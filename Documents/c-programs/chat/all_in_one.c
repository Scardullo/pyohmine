/*
    chat.c — FULL single-file chat system (Linux only)

    FEATURES:
    - TCP server + client in one file
    - pthreads
    - broadcast to all clients
    - packet framing with length + type
    - endian-safe
    - clean disconnect handling
*/
#define _POSIX_C_SOURCE 200112L

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#define MAX_CLIENTS 32
#define MAX_DATA    1024
#define PORT        5555

// utilities

void err(const char *msg) {
    perror(msg);
    exit(1);
}

void trim_newline(char *s) {
    size_t n = strlen(s);
    if (n && s[n - 1] == '\n')
        s[n - 1] = 0;
}

// packet protocols

/*
    Wire format (network):
    [uint16 length][uint8 type][payload bytes]

    length = payload size INCLUDING null terminator
*/

enum {
    MSG_NAME = 1,
    MSG_CHAT = 2,
    MSG_SYS  = 3
};

typedef struct {
    uint16_t len;      // payload length (host order in memory)
    uint8_t  type;
    char     data[MAX_DATA];
} Packet;

// reliable send / recv

int send_all(int fd, const void *buf, size_t len) {
    size_t sent = 0;
    const char *p = buf;

    while (sent < len) {
        ssize_t n = write(fd, p + sent, len - sent);
        if (n <= 0)
            return -1;
        sent += n;
    }
    return 0;
}

int recv_all(int fd, void *buf, size_t len) {
    size_t recvd = 0;
    char *p = buf;

    while (recvd < len) {
        ssize_t n = read(fd, p + recvd, len - recvd);
        if (n <= 0)
            return -1;
        recvd += n;
    }
    return 0;
}

// network helpers

int tcp_listen(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) err("socket");

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0)
        err("bind");

    if (listen(fd, 16) < 0)
        err("listen");

    return fd;
}

int tcp_connect(const char *host, uint16_t port) {
    struct addrinfo hints = {0}, *res;
    char p[16];

    snprintf(p, sizeof p, "%u", port);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, p, &hints, &res) != 0)
        err("getaddrinfo");

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) err("socket");

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0)
        err("connect");

    freeaddrinfo(res);
    return fd;
}

// server implementation

typedef struct {
    int fd;
    char username[64];
} Client;

Client clients[MAX_CLIENTS];

pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;

void broadcast(Packet *pkt, int except_fd) {
    uint16_t net_len = htons(pkt->len);

    pthread_mutex_lock(&clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].fd > 0 && clients[i].fd != except_fd) {
            send_all(clients[i].fd, &net_len, 2);
            send_all(clients[i].fd, &pkt->type, 1);
            send_all(clients[i].fd, pkt->data, pkt->len);
        }
    }
    pthread_mutex_unlock(&clients_lock);
}

void *client_thread(void *arg) {
    Client *c = arg;
    Packet pkt;

    // receive username
    uint16_t netlen;
    if (recv_all(c->fd, &netlen, 2) < 0) goto done;
    pkt.len = ntohs(netlen);
    recv_all(c->fd, &pkt.type, 1);
    recv_all(c->fd, pkt.data, pkt.len);

    strncpy(c->username, pkt.data, sizeof c->username - 1);

    snprintf(pkt.data, MAX_DATA, "*** %s joined ***", c->username);
    pkt.len = strlen(pkt.data) + 1;
    pkt.type = MSG_SYS;
    broadcast(&pkt, -1);

    while (1) {
        if (recv_all(c->fd, &netlen, 2) < 0) break;
        pkt.len = ntohs(netlen);
        if (pkt.len >= MAX_DATA) break;

        recv_all(c->fd, &pkt.type, 1);
        recv_all(c->fd, pkt.data, pkt.len);

        pkt.type = MSG_CHAT;
        snprintf(pkt.data, MAX_DATA, "[%s] %s", c->username, pkt.data);
        pkt.len = strlen(pkt.data) + 1;
        broadcast(&pkt, -1);
    }

done:
    close(c->fd);

    pthread_mutex_lock(&clients_lock);
    c->fd = 0;
    pthread_mutex_unlock(&clients_lock);

    snprintf(pkt.data, MAX_DATA, "*** %s left ***", c->username);
    pkt.len = strlen(pkt.data) + 1;
    pkt.type = MSG_SYS;
    broadcast(&pkt, -1);

    return NULL;
}

void run_server(void) {
    int listenfd = tcp_listen(PORT);
    printf("Server listening on %d\n", PORT);

    while (1) {
        int fd = accept(listenfd, NULL, NULL);
        if (fd < 0) continue;

        pthread_mutex_lock(&clients_lock);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].fd == 0) {
                clients[i].fd = fd;
                pthread_t t;
                pthread_create(&t, NULL, client_thread, &clients[i]);
                pthread_detach(t);
                break;
            }
        }
        pthread_mutex_unlock(&clients_lock);
    }
}

// client implementation

static int sock;

void *recv_thread(void *arg) {
    Packet pkt;
    uint16_t netlen;

    while (1) {
        if (recv_all(sock, &netlen, 2) < 0) break;
        pkt.len = ntohs(netlen);

        recv_all(sock, &pkt.type, 1);
        recv_all(sock, pkt.data, pkt.len);

        printf("%s\n", pkt.data);
    }
    return NULL;
}

void run_client(void) {
    sock = tcp_connect("127.0.0.1", PORT);

    char username[64];
    printf("Username: ");
    fgets(username, sizeof username, stdin);
    trim_newline(username);

    Packet pkt;
    pkt.type = MSG_NAME;
    strncpy(pkt.data, username, MAX_DATA - 1);
    pkt.len = strlen(pkt.data) + 1;

    uint16_t netlen = htons(pkt.len);
    send_all(sock, &netlen, 2);
    send_all(sock, &pkt.type, 1);
    send_all(sock, pkt.data, pkt.len);

    pthread_t t;
    pthread_create(&t, NULL, recv_thread, NULL);
    pthread_detach(t);

    char line[MAX_DATA];
    while (fgets(line, sizeof line, stdin)) {
        trim_newline(line);
        pkt.type = MSG_CHAT;
        strncpy(pkt.data, line, MAX_DATA - 1);
        pkt.len = strlen(pkt.data) + 1;

        netlen = htons(pkt.len);
        send_all(sock, &netlen, 2);
        send_all(sock, &pkt.type, 1);
        send_all(sock, pkt.data, pkt.len);
    }
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s server|client\n", argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "server"))
        run_server();
    else if (!strcmp(argv[1], "client"))
        run_client();
    else
        fprintf(stderr, "unknown mode\n");

    return 0;
}
