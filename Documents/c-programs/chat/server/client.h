#ifndef CLIENT_H
#define CLIENT_H

#include "../common/protocol.h"

typedef struct Client {
    int fd;
    char nick[MAX_NICK];
    uint8_t buf[2048];
    int buf_used;
} Client;

Client *client_create(int fd);
void client_destroy(Client *c);

#endif
