#ifndef SERVER_H
#define SERVER_H

#include <netinet/in.h>
#include <pthread.h>

#define PORT 5555
#define MAX_CLIENTS 16
#define BUFFER_SIZE 256

/* Starts the server and listens for clients */
void startServer();

/* Stops the server cleanly */
void stopServer();

#endif
