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
}
