#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "server.h"
#include "student.h"

static int server_fd;
static pthread_t client_threads[MAX_CLIENTS];
static int running = 0;

/* Send message to client */
static void sendMsg(int sock, const char *msg) {
    send(sock, msg, strlen(msg), 0);
}

/* Handle commands from a client */
static void *clientHandler(void *arg) {
    int sock = *(int*)arg;
    free(arg);
    char buffer[BUFFER_SIZE];

    sendMsg(sock, "Welcome to Student Server!\n");

    while(1){
        memset(buffer,0,sizeof(buffer));
        int n = recv(sock, buffer, sizeof(buffer)-1, 0);
        if(n <= 0) break;

        buffer[n] = '\0';
        char cmd[32]; sscanf(buffer,"%31s",cmd);

        if(strcmp(cmd,"ADD")==0){
            char name[NAME_LEN]; float grade;
            if(sscanf(buffer+4,"%49s %f",name,&grade)==2){
                addStudent(name,grade);
                sendMsg(sock,"Student added.\n");
            } else sendMsg(sock,"Usage: ADD <name> <grade>\n");
        }
        else if(strcmp(cmd,"LIST")==0){
            pthread_mutex_lock(&student_lock);
            Student *t=head;
            char line[128];
            while(t){
                snprintf(line,sizeof(line),"%d %s %.2f %c\n",t->id,t->name,t->grade,t->letter);
                sendMsg(sock,line);
                t=t->next;
            }
            pthread_mutex_unlock(&student_lock);
        }
        else if(strcmp(cmd,"DELETE")==0){
            int id; if(sscanf(buffer+7,"%d",&id)==1){
                if(deleteStudent(id)) sendMsg(sock,"Deleted.\n");
                else sendMsg(sock,"Not found.\n");
            } else sendMsg(sock,"Usage: DELETE <id>\n");
        }
        else if(strcmp(cmd,"EDIT")==0){
            int id; char name[NAME_LEN]; float grade;
            if(sscanf(buffer+5,"%d %49s %f",&id,name,&grade)==3){
                if(editStudent(id,name,grade)) sendMsg(sock,"Edited.\n");
                else sendMsg(sock,"Not found.\n");
            } else sendMsg(sock,"Usage: EDIT <id> <name> <grade>\n");
        }
        else if(strcmp(cmd,"SORTNAME")==0){
            sortByName(); sendMsg(sock,"Sorted by name.\n");
        }
        else if(strcmp(cmd,"SORTGRADE")==0){
            sortByGrade(); sendMsg(sock,"Sorted by grade.\n");
        }
        else if(strcmp(cmd,"EXIT")==0){
            sendMsg(sock,"Goodbye!\n"); break;
        }
        else sendMsg(sock,"Unknown command.\n");
    }

    close(sock);
    return NULL;
}

void startServer() {
    struct sockaddr_in addr;
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd<0){ perror("socket"); exit(1); }

    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=INADDR_ANY;
    addr.sin_port=htons(PORT);

    if(bind(server_fd,(struct sockaddr*)&addr,sizeof(addr))<0){ perror("bind"); exit(1); }
    if(listen(server_fd,MAX_CLIENTS)<0){ perror("listen"); exit(1); }

    running=1;
    printf("Server listening on port %d\n",PORT);

    while(running){
        struct sockaddr_in client_addr;
        socklen_t len=sizeof(client_addr);
        int *client_sock = malloc(sizeof(int));
        *client_sock = accept(server_fd,(struct sockaddr*)&client_addr,&len);
        if(*client_sock<0){ free(client_sock); continue; }
        for(int i=0;i<MAX_CLIENTS;i++){
            if(client_threads[i]==0 || pthread_tryjoin_np(client_threads[i],NULL)==0){
                pthread_create(&client_threads[i],NULL,clientHandler,client_sock);
                break;
            }
        }
    }
}

void stopServer() {
    running=0;
    close(server_fd);
    for(int i=0;i<MAX_CLIENTS;i++){
        if(client_threads[i]) pthread_cancel(client_threads[i]);
    }
    printf("Server stopped.\n");
}
