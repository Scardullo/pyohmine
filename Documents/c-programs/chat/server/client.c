#include "client.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

Client *client_create(int fd) {
    Client *c = calloc(1, sizeof(Client));
    c->fd = fd;
    strcpy(c->nick, "anon");
    return c;
}

void client_destroy(Client *c) {
    close(c->fd);
    free(c);
}
