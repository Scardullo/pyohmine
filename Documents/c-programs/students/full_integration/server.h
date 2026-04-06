#ifndef SERVER_H
#define SERVER_H

#include "student.h"
#include <netinet/in.h>

#define SERVER_PORT 12345
#define MAX_CLIENTS 10
#define BUFFER_SIZE 256

void startServer(int port);
void stopServer();

#endif
