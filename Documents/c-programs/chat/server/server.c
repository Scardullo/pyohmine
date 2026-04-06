#include "../common/net.h"
#include "../common/util.h"
#include "../common/protocol.h"
#include "client.h"

#include <sys/epoll.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_EVENTS 64
#define MAX_CLIENTS 1024

static Client *clients[MAX_CLIENTS];

static void broadcast(Packet *pkt, int except_fd) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->fd != except_fd) {
            send_all(clients[i]->fd, pkt, pkt->len + 3);
        }
    }
}

static void handle_packet(Client *c, Packet *pkt) {
    if (pkt->type == MSG_NICK) {
        safe_strncpy(c->nick, (char*)pkt->data, MAX_NICK);
        Packet out = {0};
        out.type = MSG_SYSTEM;
        snprintf((char*)out.data, MAX_PAYLOAD, "%s joined", c->nick);
        out.len = strlen((char*)out.data) + 1;
        broadcast(&out, -1);
    }
    else if (pkt->type == MSG_CHAT) {
        Packet out = {0};
        out.type = MSG_CHAT;
        snprintf((char*)out.data, MAX_PAYLOAD, "%s: %s",
                 c->nick, pkt->data);
        out.len = strlen((char*)out.data) + 1;
        broadcast(&out, c->fd);
    }
}

int main() {
    int listenfd = tcp_listen(5555);
    set_nonblocking(listenfd);

    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = listenfd };
    epoll_ctl(ep, EPOLL_CTL_ADD, listenfd, &ev);

    struct epoll_event events[MAX_EVENTS];

    printf("Chat server listening on 5555\n");

    while (1) {
        int n = epoll_wait(ep, events, MAX_EVENTS, -1);
        for (int i = 0; i < n; i++) {

            if (events[i].data.fd == listenfd) {
                int fd = accept(listenfd, NULL, NULL);
                set_nonblocking(fd);

                Client *c = client_create(fd);
                clients[fd] = c;

                struct epoll_event cev = { .events = EPOLLIN, .data.fd = fd };
                epoll_ctl(ep, EPOLL_CTL_ADD, fd, &cev);

                printf("Client connected %d\n", fd);
            }
            else {
                int fd = events[i].data.fd;
                Client *c = clients[fd];

                Packet pkt;
                if (recv_all(fd, &pkt.len, 2) < 0 ||
                    recv_all(fd, &pkt.type, 1) < 0 ||
                    recv_all(fd, pkt.data, pkt.len) < 0) {

                    printf("Client disconnected %d\n", fd);
                    epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL);
                    client_destroy(c);
                    clients[fd] = NULL;
                    continue;
                }

                handle_packet(c, &pkt);
            }
        }
    }
}
