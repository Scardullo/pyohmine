#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 256

int main(){
    int sock = socket(AF_INET,SOCK_STREAM,0);
    if(sock<0){ perror("socket"); return 1; }

    struct sockaddr_in server;
    server.sin_family=AF_INET;
    server.sin_port=htons(5555);
    server.sin_addr.s_addr=inet_addr("127.0.0.1");

    if(connect(sock,(struct sockaddr*)&server,sizeof(server))<0){
        perror("connect"); return 1;
    }

    char buffer[BUFFER_SIZE];
    int n = recv(sock,buffer,sizeof(buffer)-1,0);
    if(n>0){ buffer[n]='\0'; printf("%s",buffer); }

    while(1){
        printf("> "); fflush(stdout);
        if(!fgets(buffer,sizeof(buffer),stdin)) break;
        send(sock,buffer,strlen(buffer),0);
        if(strncmp(buffer,"EXIT",4)==0) break;

        n=recv(sock,buffer,sizeof(buffer)-1,0);
        if(n>0){ buffer[n]='\0'; printf("%s",buffer); }
    }

    close(sock);
    return 0;
}
