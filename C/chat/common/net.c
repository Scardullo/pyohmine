#define _POSIX_C_SOURCE 200112L

#include "net.h"
#include "util.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int tcp_listen(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr = {0}:
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (void*)&addr, sizeof addr) < 0) die("bind");
    if (listen(fd, 64) < 0) die("listen");

    return fd;
}

int tcp_connect(const char *host, uint16_t port) {
    
}
