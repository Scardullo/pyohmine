#define _POSIX_C_SOURCE 200112L  // optional, ensures getaddrinfo is declared

#include "net.h"
#include "util.h"

#include <arpa/inet.h>   // htons, inet_pton
#include <netdb.h>       // struct addrinfo, getaddrinfo
#include <sys/socket.h>  // socket, bind, listen, connect
#include <unistd.h>      // close
#include <string.h>      // memset, memcpy
#include <stdio.h>       // perror
#include <stdlib.h>      // exit


int tcp_listen(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (void*)&addr, sizeof addr) < 0) die("bind");
    if (listen(fd, 64) < 0) die("listen");

    return fd;
}

int tcp_connect(const char *host, uint16_t port) {
    struct addrinfo hints = {0}, *res;
    char p[16];
    snprintf(p, sizeof p, "%u", port);

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, p, &hints, &res) != 0)
        die("getaddrinfo");

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) die("socket");

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0)
        die("connect");

    freeaddrinfo(res);
    return fd;
}

int send_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n <= 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}

int recv_all(int fd, void *buf, size_t len) {
    char *p = buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n <= 0) return -1;
        p += n;
        len -= n;
    }
    return 0;
}
