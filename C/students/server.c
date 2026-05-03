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

	if(strncmp(buffer,"ADD ",4)==0){
	    char name[NAME_LEN]; float grade;
	    if(sscanf(buffer+4,"%49s %f",name,&grade)==2){
		
	    }
	}
    }
}
