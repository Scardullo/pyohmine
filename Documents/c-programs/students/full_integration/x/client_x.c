#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345
#define BUFFER_SIZE 256

int main(){
    int sock = socket(AF_INET,SOCK_STREAM,0);
    if(sock<0){ perror("socket"); return 1; }

    struct sockaddr_in addr;
    addr.sin_family=AF_INET;
    addr.sin_port=htons(SERVER_PORT);
    inet_pton(AF_INET,SERVER_IP,&addr.sin_addr);

    if(connect(sock,(struct sockaddr*)&addr,sizeof(addr))<0){
        perror("connect"); return 1;
    }

    char buffer[BUFFER_SIZE];
    while(1){
        printf("Command> ");
        fgets(buffer,sizeof(buffer),stdin);
        buffer[strcspn(buffer,"\n")]='\0';
        if(send(sock,buffer,strlen(buffer),0)<0){ perror("send"); break; }
        if(strncmp(buffer,"EXIT",4)==0) break;

        int bytes=recv(sock,buffer,sizeof(buffer)-1,0);
        if(bytes>0){
            buffer[bytes]='\0';
            printf("%s\n",buffer);
        }
    }

    close(sock);
    return 0;
}
