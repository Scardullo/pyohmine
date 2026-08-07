#include "network.h"
#include "student.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_NET_CLIENTS 10

static int clients[MAX_NET_CLIENTS];
static pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;
static int server_fd = -1;
static pthread_t accept_thread_id;
static volatile int server_running = 0;

static void broadcast_to_clients(const char *msg){
    pthread_mutex_lock(&clients_lock);
    for(int i=0;i<MAX_NET_CLIENTS;i++){
        if(clients[i] > 0){
            write(clients[i], msg, strlen(msg));
            write(clients[i], "\n", 1);
        }
    }
    pthread_mutex_unlock(&clients_lock);
}

static void network_broadcast_cb(const char *msg){
    broadcast_to_clients(msg);
}

static void *client_thread(void *arg){
    int sock = *(int*)arg;
    free(arg);

    char buffer[256];
    ssize_t n;
    while((n = read(sock, buffer, sizeof(buffer)-1)) > 0){
        buffer[n]=0;
        printf("[client fd=%d] %s\n", sock, buffer);
    }

    close(sock);
    pthread_mutex_lock(&clients_lock);
    for(int i=0;i<MAX_NET_CLIENTS;i++){
        if(clients[i]==sock){ clients[i]=0; break; }
    }
    pthread_mutex_unlock(&clients_lock);
    return NULL;
}

static void *accept_loop(void *arg){
    (void)arg;
    while(server_running){
        int client_fd = accept(server_fd, NULL, NULL);
        if(client_fd < 0){
            if(!server_running) break;      // stopServer() closed the socket
            if(errno == EINTR) continue;
            break;
        }

        pthread_mutex_lock(&clients_lock);
        int added=0;
        for(int i=0;i<MAX_NET_CLIENTS;i++){
            if(clients[i]==0){ clients[i]=client_fd; added=1; break; }
        }
        pthread_mutex_unlock(&clients_lock);

        if(!added){
            const char *msg="Server full\n";
            write(client_fd, msg, strlen(msg));
            close(client_fd);
            continue;
        }

        int *pclient = malloc(sizeof(int));
        if(!pclient){
            pthread_mutex_lock(&clients_lock);
            for(int i=0;i<MAX_NET_CLIENTS;i++) if(clients[i]==client_fd){ clients[i]=0; break; }
            pthread_mutex_unlock(&clients_lock);
            close(client_fd);
            continue;
        }
        *pclient = client_fd;

        pthread_t tid;
        if(pthread_create(&tid, NULL, client_thread, pclient) != 0){
            free(pclient);
            pthread_mutex_lock(&clients_lock);
            for(int i=0;i<MAX_NET_CLIENTS;i++) if(clients[i]==client_fd){ clients[i]=0; break; }
            pthread_mutex_unlock(&clients_lock);
            close(client_fd);
            continue;
        }
        pthread_detach(tid);
    }
    return NULL;
}

int startServer(int port){
    if(server_running) return 0;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd < 0){ perror("socket"); server_fd=-1; return -1; }

    int opt=1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0){
        perror("bind"); close(server_fd); server_fd=-1; return -1;
    }
    if(listen(server_fd, 5) < 0){
        perror("listen"); close(server_fd); server_fd=-1; return -1;
    }

    memset(clients, 0, sizeof(clients));
    registerBroadcastCallback(network_broadcast_cb);

    server_running = 1;
    if(pthread_create(&accept_thread_id, NULL, accept_loop, NULL) != 0){
        perror("pthread_create");
        server_running = 0;
        close(server_fd); server_fd=-1;
        return -1;
    }

    printf("Broadcast server listening on port %d\n", port);
    return 0;
}

void stopServer(void){
    if(!server_running) return;
    server_running = 0;

    if(server_fd >= 0){
        shutdown(server_fd, SHUT_RDWR);   // unblocks the pending accept()
        close(server_fd);
        server_fd = -1;
    }

    pthread_join(accept_thread_id, NULL);

    pthread_mutex_lock(&clients_lock);
    for(int i=0;i<MAX_NET_CLIENTS;i++){
        if(clients[i] > 0){ close(clients[i]); clients[i]=0; }
    }
    pthread_mutex_unlock(&clients_lock);

    registerBroadcastCallback(NULL);
    printf("Broadcast server stopped.\n");
}

int isServerRunning(void){ return server_running; }

void runClientSession(const char *ip, int port){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){ perror("socket"); return; }

    struct sockaddr_in server_addr;
    memset(&server_addr,0,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((uint16_t)port);
    if(inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0){
        fprintf(stderr,"Invalid server address: %s\n", ip);
        close(sock);
        return;
    }

    if(connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        perror("connect");
        close(sock);
        return;
    }

    printf("Connected to %s:%d. Type messages and press Enter to send.\n", ip, port);
    printf("Type /quit to disconnect and return to the menu.\n");

    char buffer[256];
    while(1){
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        int max_fd = sock > STDIN_FILENO ? sock : STDIN_FILENO;

        if(select(max_fd+1, &read_fds, NULL, NULL, NULL) < 0){
            if(errno==EINTR) continue;
            perror("select");
            break;
        }

        if(FD_ISSET(sock, &read_fds)){
            int n = read(sock, buffer, sizeof(buffer)-1);
            if(n <= 0){ printf("Disconnected by server.\n"); break; }
            buffer[n]=0;
            printf("[Server] %s", buffer);
        }

        if(FD_ISSET(STDIN_FILENO, &read_fds)){
            if(!fgets(buffer,sizeof(buffer),stdin)) break;
            buffer[strcspn(buffer,"\n")]=0;
            if(strcmp(buffer,"/quit")==0) break;
            write(sock, buffer, strlen(buffer));
            write(sock, "\n", 1);
        }
    }

    close(sock);
    printf("Client session ended.\n");
}
