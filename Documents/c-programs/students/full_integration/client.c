#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>


#define PORT 12345
#define SERVER_IP "127.0.0.1"

int main(){
    int sock = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in server_addr = {AF_INET, htons(PORT)};
    inet_pton(AF_INET,SERVER_IP,&server_addr.sin_addr);

    if(connect(sock,(struct sockaddr*)&server_addr,sizeof(server_addr))<0){
        perror("Connect failed"); return 1;
    }

    printf("Connected to server %s:%d\n", SERVER_IP, PORT);

    fd_set read_fds;
    char buffer[128];

    while(1){
        FD_ZERO(&read_fds);
        FD_SET(sock,&read_fds);
        FD_SET(STDIN_FILENO,&read_fds);
        int max_fd = sock>STDIN_FILENO?sock:STDIN_FILENO;
        select(max_fd+1,&read_fds,NULL,NULL,NULL);

        if(FD_ISSET(sock,&read_fds)){
            int n = read(sock, buffer,sizeof(buffer)-1);
            if(n<=0){ printf("Disconnected\n"); break; }
            buffer[n]=0;
            printf("[Server] %s\n",buffer);
        }

        if(FD_ISSET(STDIN_FILENO,&read_fds)){
            fgets(buffer,sizeof(buffer),stdin);
            buffer[strcspn(buffer,"\n")]=0;
            write(sock, buffer, strlen(buffer));
        }
    }

    close(sock);
    return 0;
}
