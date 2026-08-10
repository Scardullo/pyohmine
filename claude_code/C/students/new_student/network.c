#include "network.h"
#include "student.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_NET_CLIENTS 10
#define INBUF_SIZE 1024

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

static void sendLine(int fd, const char *fmt, ...){
    char buf[400];
    va_list ap; va_start(ap,fmt); vsnprintf(buf,sizeof(buf)-2,fmt,ap); va_end(ap);
    size_t n = strlen(buf);
    buf[n++]='\n';
    write(fd, buf, n);
}

static int containsCI(const char *hay, const char *needle){
    if(!*needle) return 1;
    size_t hn=strlen(hay), nn=strlen(needle);
    if(nn>hn) return 0;
    for(size_t i=0;i<=hn-nn;i++){
        size_t j=0;
        while(j<nn && tolower((unsigned char)hay[i+j])==tolower((unsigned char)needle[j])) j++;
        if(j==nn) return 1;
    }
    return 0;
}

// ---- remote command handlers ---------------------------------------------
// These read the shared student list directly (under student_lock) instead
// of reusing student.c's printf-based display functions, since those write
// to stdout rather than returning text a network client can consume.

static void cmdList(int fd){
    pthread_mutex_lock(&student_lock);
    if(!head){ pthread_mutex_unlock(&student_lock); sendLine(fd,"(no students)"); return; }
    for(Student *t=head;t;t=t->next){
        float avg = studentAverage(t);
        sendLine(fd,"%d\t%s\t%.2f\t%c", t->id, t->name, avg, letterGrade(avg));
    }
    pthread_mutex_unlock(&student_lock);
}

static void cmdSearch(int fd, const char *query){
    pthread_mutex_lock(&student_lock);
    int found=0;
    for(Student *t=head;t;t=t->next){
        if(containsCI(t->name,query)){
            float avg = studentAverage(t);
            sendLine(fd,"%d\t%s\t%.2f\t%c", t->id, t->name, avg, letterGrade(avg));
            found++;
        }
    }
    pthread_mutex_unlock(&student_lock);
    if(!found) sendLine(fd,"(no matches)");
}

static void cmdRange(int fd, const char *args){
    float lo=0, hi=100;
    if(sscanf(args,"%f %f",&lo,&hi)!=2){ sendLine(fd,"ERR usage: RANGE <min> <max>"); return; }
    pthread_mutex_lock(&student_lock);
    int found=0;
    for(Student *t=head;t;t=t->next){
        float avg = studentAverage(t);
        if(avg>=lo && avg<=hi){ sendLine(fd,"%d\t%s\t%.2f\t%c", t->id, t->name, avg, letterGrade(avg)); found++; }
    }
    pthread_mutex_unlock(&student_lock);
    if(!found) sendLine(fd,"(no matches)");
}

static void cmdStats(int fd){
    Student *top=getTopStudent(), *low=getLowestStudent();
    sendLine(fd,"count=%d avg=%.2f median=%.2f stddev=%.2f top=%s low=%s",
              countStudents(), getAverageGrade(), getMedianGrade(), getStdDevGrade(),
              top?top->name:"N/A", low?low->name:"N/A");
}

static void cmdAdd(int fd, char *args){
    char *comma = strrchr(args,',');
    if(!comma){ sendLine(fd,"ERR usage: ADD name,grade"); return; }
    *comma=0;
    float grade = strtof(comma+1,NULL);
    if(addStudent(args,grade)) sendLine(fd,"OK added");
    else sendLine(fd,"ERR invalid name or grade");
}

static void cmdEdit(int fd, char *args, int authenticated){
    if(!authenticated){ sendLine(fd,"ERR AUTH required"); return; }
    char *c1 = strchr(args,',');
    if(!c1){ sendLine(fd,"ERR usage: EDIT id,name,grade"); return; }
    *c1=0;
    int id = atoi(args);
    char *rest = c1+1;
    char *c2 = strrchr(rest,',');
    if(!c2){ sendLine(fd,"ERR usage: EDIT id,name,grade"); return; }
    *c2=0;
    float grade = strtof(c2+1,NULL);
    if(editStudent(id,rest,grade)) sendLine(fd,"OK edited");
    else sendLine(fd,"ERR not found or invalid");
}

static void cmdDel(int fd, const char *args, int authenticated){
    if(!authenticated){ sendLine(fd,"ERR AUTH required"); return; }
    int id = atoi(args);
    if(deleteStudentWithUndo(id)) sendLine(fd,"OK deleted");
    else sendLine(fd,"ERR not found");
}

static void handleCommand(int fd, char *line, int *authenticated){
    if(line[0]==0) return;

    char *sp = strchr(line,' ');
    size_t clen = sp ? (size_t)(sp-line) : strlen(line);
    char cmd[16];
    if(clen>=sizeof(cmd)) clen=sizeof(cmd)-1;
    memcpy(cmd,line,clen); cmd[clen]=0;
    char *args = sp ? sp+1 : line+strlen(line);
    while(*args==' ') args++;

    char up[16]; size_t i=0;
    for(; cmd[i] && i<sizeof(up)-1; i++) up[i]=(char)toupper((unsigned char)cmd[i]);
    up[i]=0;

    if(strcmp(up,"HELP")==0){
        sendLine(fd,"Commands: HELP LIST SEARCH <text> RANGE <min> <max> STATS AUTH <pw> ADD <name>,<grade> EDIT <id>,<name>,<grade> DEL <id> QUIT");
    } else if(strcmp(up,"LIST")==0){
        cmdList(fd);
    } else if(strcmp(up,"SEARCH")==0){
        cmdSearch(fd,args);
    } else if(strcmp(up,"RANGE")==0){
        cmdRange(fd,args);
    } else if(strcmp(up,"STATS")==0){
        cmdStats(fd);
    } else if(strcmp(up,"AUTH")==0){
        if(adminLogin(args)){ *authenticated=1; sendLine(fd,"OK authenticated"); }
        else sendLine(fd,"ERR bad password");
    } else if(strcmp(up,"ADD")==0){
        cmdAdd(fd,args);
    } else if(strcmp(up,"EDIT")==0){
        cmdEdit(fd,args,*authenticated);
    } else if(strcmp(up,"DEL")==0){
        cmdDel(fd,args,*authenticated);
    } else if(strcmp(up,"QUIT")==0){
        sendLine(fd,"Bye.");
    } else {
        // not a recognized command - treat as free-form chat, same as the
        // original server's behavior.
        printf("[client fd=%d] %s\n", fd, line);
        char msg[300]; snprintf(msg,sizeof(msg),"[peer %d] %s", fd, line);
        broadcast_to_clients(msg);
    }
}

static void *client_thread(void *arg){
    int sock = *(int*)arg;
    free(arg);

    int authenticated = 0;
    char inbuf[INBUF_SIZE]; size_t inlen=0;
    char chunk[256];
    ssize_t n;

    sendLine(sock,"Connected. Type HELP for a list of commands.");

    while((n = read(sock, chunk, sizeof(chunk))) > 0){
        for(ssize_t i=0;i<n;i++){
            char c = chunk[i];
            if(c=='\n'){
                if(inlen>0 && inbuf[inlen-1]=='\r') inlen--;
                inbuf[inlen]=0;
                handleCommand(sock, inbuf, &authenticated);
                inlen=0;
            } else if(inlen < sizeof(inbuf)-1){
                inbuf[inlen++]=c;
            } // else: line too long, silently drop the overflow bytes
        }
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

    printf("Command/broadcast server listening on port %d\n", port);
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

    printf("Connected to %s:%d. Type HELP to see server commands.\n", ip, port);
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
