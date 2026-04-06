#include "server.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

static int server_fd;
static pthread_t client_threads[MAX_CLIENTS];
static int running = 0;

typedef struct {
    int sock;
} ClientInfo;

static void* clientHandler(void *arg){
    ClientInfo *ci = (ClientInfo*)arg;
    char buffer[BUFFER_SIZE];

    while(1){
        memset(buffer,0,sizeof(buffer));
        int bytes = recv(ci->sock,buffer,sizeof(buffer)-1,0);
        if(bytes<=0) break;

        // simple command parser: ADD Name Grade
        if(strncmp(buffer,"ADD ",4)==0){
            char name[NAME_LEN]; float grade;
            if(sscanf(buffer+4,"%49s %f",name,&grade)==2){
                addStudent(name,grade);
                send(ci->sock,"OK\n",3,0);
            } else send(ci->sock,"ERROR\n",6,0);
        }
        else if(strncmp(buffer,"LIST",4)==0){
            pthread_mutex_lock(&student_lock);
            Student *t=head;
            while(t){
                char msg[128];
                snprintf(msg,sizeof(msg),"%d %s %.2f\n",t->id,t->name,t->grade);
                send(ci->sock,msg,strlen(msg),0);
                t=t->next;
            }
            pthread_mutex_unlock(&student_lock);
        }
        else if(strncmp(buffer,"DELETE ",7)==0){
            int id; sscanf(buffer+7,"%d",&id);
            deleteStudent(id);
            send(ci->sock,"OK\n",3,0);
        }
        else if(strncmp(buffer,"EXIT",4)==0){
            break;
        } else send(ci->sock,"UNKNOWN COMMAND\n",16,0);
    }

    close(ci->sock);
    free(ci);
    return NULL;
}

void startServer(int port){
    struct sockaddr_in addr;
    server_fd = socket(AF_INET,SOCK_STREAM,0);
    if(server_fd<0){ perror("socket"); return; }

    int opt=1;
    setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if(bind(server_fd,(struct sockaddr*)&addr,sizeof(addr))<0){ perror("bind"); return; }
    if(listen(server_fd,MAX_CLIENTS)<0){ perror("listen"); return; }

    running=1;
    printf("Server listening on port %d\n",port);

    while(running){
        int client_sock = accept(server_fd,NULL,NULL);
        if(client_sock<0) continue;

        ClientInfo *ci = malloc(sizeof(ClientInfo));
        ci->sock = client_sock;
        pthread_t tid;
        pthread_create(&tid,NULL,clientHandler,ci);
        pthread_detach(tid);
    }
}

void stopServer(){
    running=0;
    close(server_fd);
}
