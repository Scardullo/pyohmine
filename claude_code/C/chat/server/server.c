#include "../common/net.h"
#include "../common/util.h"
#include "../common/protocol.h"
#include "client.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#define MAX_EVENTS 64
#define MAX_CLIENTS 1024

static Client *clients[MAX_CLIENTS];

static void disconnect_client(int ep, Client *c) {
    printf("Client disconnected %d\n", c->fd);
    epoll_ctl(ep, EPOLL_CTL_DEL, c->fd, NULL);
    clients[c->fd] = NULL;
    client_destroy(c);
}

// Queues pkt for c and keeps this fd's EPOLLOUT registration in sync with
// whether data is still waiting to go out. Disconnects c on hard failure.
static void deliver(int ep, Client *c, Packet *pkt) {
    int want_write = 0;
    if (client_send(c, pkt, &want_write) < 0) {
        disconnect_client(ep, c);
        return;
    }
    if (want_write != c->epollout_registered) {
        struct epoll_event ev = {0};
        ev.data.fd = c->fd;
        ev.events = EPOLLIN | (want_write ? EPOLLOUT : 0);
        epoll_ctl(ep, EPOLL_CTL_MOD, c->fd, &ev);
        c->epollout_registered = want_write;
    }
}

static void broadcast_room(int ep, const char *room, Packet *pkt, int except_fd) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        Client *c = clients[i];
        if (c && c->fd != except_fd && strcmp(c->room, room) == 0) {
            deliver(ep, c, pkt);
        }
    }
}

static Client *find_by_nick(const char *nick) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->registered && strcmp(clients[i]->nick, nick) == 0)
            return clients[i];
    }
    return NULL;
}

static void send_system(int ep, Client *c, const char *fmt, ...) {
    Packet out = {0};
    out.type = MSG_SYSTEM;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf((char*)out.data, MAX_PAYLOAD, fmt, ap);
    va_end(ap);
    out.len = strlen((char*)out.data) + 1;
    deliver(ep, c, &out);
}

static void handle_nick(int ep, Client *c, Packet *pkt) {
    char requested[MAX_NICK];
    safe_strncpy(requested, (char*)pkt->data, MAX_NICK);

    if (requested[0] == '\0') {
        send_system(ep, c, "Nickname cannot be empty");
        return;
    }
    if (strcmp(requested, c->nick) == 0) return;

    Client *existing = find_by_nick(requested);
    if (existing && existing != c) {
        send_system(ep, c, "Nickname '%s' is already taken", requested);
        return;
    }

    char old_nick[MAX_NICK];
    safe_strncpy(old_nick, c->nick, MAX_NICK);
    int was_registered = c->registered;

    safe_strncpy(c->nick, requested, MAX_NICK);
    c->registered = 1;

    Packet out = {0};
    out.type = MSG_SYSTEM;
    if (was_registered)
        snprintf((char*)out.data, MAX_PAYLOAD, "%s is now known as %s", old_nick, c->nick);
    else
        snprintf((char*)out.data, MAX_PAYLOAD, "%s joined #%s", c->nick, c->room);
    out.len = strlen((char*)out.data) + 1;
    broadcast_room(ep, c->room, &out, -1);
}

static void handle_chat(int ep, Client *c, Packet *pkt) {
    if (!c->registered) {
        send_system(ep, c, "Set a nickname first");
        return;
    }
    Packet out = {0};
    out.type = MSG_CHAT;
    snprintf((char*)out.data, MAX_PAYLOAD, "%s: %s", c->nick, pkt->data);
    out.len = strlen((char*)out.data) + 1;
    broadcast_room(ep, c->room, &out, c->fd);
}

static void handle_priv(int ep, Client *c, Packet *pkt) {
    if (!c->registered) {
        send_system(ep, c, "Set a nickname first");
        return;
    }

    // Wire format: "<target-nick>\0<message>"
    const char *data = (char*)pkt->data;
    size_t tlen = strnlen(data, pkt->len);
    if (tlen == pkt->len) {
        send_system(ep, c, "Malformed /msg");
        return;
    }
    char target[MAX_NICK];
    safe_strncpy(target, data, MAX_NICK);
    const char *msg = data + tlen + 1;

    Client *dst = find_by_nick(target);
    if (!dst) {
        send_system(ep, c, "No such user: %s", target);
        return;
    }

    Packet out = {0};
    out.type = MSG_PRIV;
    int n = snprintf((char*)out.data, MAX_PAYLOAD, "%s", c->nick);
    size_t prefix_len = (size_t)n + 1; // include the NUL
    size_t room = MAX_PAYLOAD - prefix_len;
    size_t msg_len = strnlen(msg, room - 1);
    memcpy(out.data + prefix_len, msg, msg_len);
    out.data[prefix_len + msg_len] = '\0';
    out.len = prefix_len + msg_len + 1;
    deliver(ep, dst, &out);
}

static void handle_list(int ep, Client *c, Packet *pkt) {
    (void)pkt;
    Packet out = {0};
    out.type = MSG_SYSTEM;
    char *buf = (char*)out.data;
    int off = snprintf(buf, MAX_PAYLOAD, "Online in #%s: ", c->room);
    int first = 1;
    for (int i = 0; i < MAX_CLIENTS && off < MAX_PAYLOAD; i++) {
        Client *o = clients[i];
        if (o && o->registered && strcmp(o->room, c->room) == 0) {
            off += snprintf(buf + off, MAX_PAYLOAD - off, "%s%s", first ? "" : ", ", o->nick);
            first = 0;
        }
    }
    if (first && off < MAX_PAYLOAD) snprintf(buf + off, MAX_PAYLOAD - off, "(nobody yet)");
    out.len = strlen(buf) + 1;
    deliver(ep, c, &out);
}

static void handle_join(int ep, Client *c, Packet *pkt) {
    char newroom[MAX_ROOM];
    safe_strncpy(newroom, (char*)pkt->data, MAX_ROOM);

    if (newroom[0] == '\0') {
        send_system(ep, c, "Room name cannot be empty");
        return;
    }
    if (strcmp(newroom, c->room) == 0) {
        send_system(ep, c, "Already in #%s", c->room);
        return;
    }

    if (c->registered) {
        Packet left = {0};
        left.type = MSG_SYSTEM;
        snprintf((char*)left.data, MAX_PAYLOAD, "%s left #%s", c->nick, c->room);
        left.len = strlen((char*)left.data) + 1;
        broadcast_room(ep, c->room, &left, c->fd);
    }

    safe_strncpy(c->room, newroom, MAX_ROOM);

    if (c->registered) {
        Packet joined = {0};
        joined.type = MSG_SYSTEM;
        snprintf((char*)joined.data, MAX_PAYLOAD, "%s joined #%s", c->nick, c->room);
        joined.len = strlen((char*)joined.data) + 1;
        broadcast_room(ep, c->room, &joined, c->fd);
    }
    send_system(ep, c, "Joined #%s", c->room);
}

static void handle_packet(int ep, Client *c, Packet *pkt) {
    switch (pkt->type) {
        case MSG_NICK: handle_nick(ep, c, pkt); break;
        case MSG_CHAT: handle_chat(ep, c, pkt); break;
        case MSG_PRIV: handle_priv(ep, c, pkt); break;
        case MSG_LIST: handle_list(ep, c, pkt); break;
        case MSG_JOIN: handle_join(ep, c, pkt); break;
        default: break; // unknown type from an old/broken client - ignore
    }
}

int main() {
    setvbuf(stdout, NULL, _IOLBF, 0); // flush log lines promptly even when redirected

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
            int fd = events[i].data.fd;

            if (fd == listenfd) {
                // Level-triggered: drain every pending connection now so we
                // don't leave one queued until the next epoll_wait wakeup.
                while (1) {
                    int cfd = accept(listenfd, NULL, NULL);
                    if (cfd < 0) break; // EAGAIN (no more pending) or a transient error either way

                    if (cfd >= MAX_CLIENTS) {
                        fprintf(stderr, "Rejecting fd %d: exceeds MAX_CLIENTS\n", cfd);
                        close(cfd);
                        continue;
                    }

                    set_nonblocking(cfd);
                    Client *c = client_create(cfd);
                    clients[cfd] = c;

                    struct epoll_event cev = { .events = EPOLLIN, .data.fd = cfd };
                    epoll_ctl(ep, EPOLL_CTL_ADD, cfd, &cev);

                    printf("Client connected %d\n", cfd);
                }
                continue;
            }

            Client *c = clients[fd];
            if (!c) continue; // stale event for an fd we already closed this batch

            if (events[i].events & (EPOLLHUP | EPOLLERR)) {
                disconnect_client(ep, c);
                continue;
            }

            if (events[i].events & EPOLLOUT) {
                int want_write = 0;
                if (client_flush(c, &want_write) < 0) {
                    disconnect_client(ep, c);
                    continue;
                }
                if (want_write != c->epollout_registered) {
                    struct epoll_event mev = { .events = EPOLLIN | (want_write ? EPOLLOUT : 0), .data.fd = fd };
                    epoll_ctl(ep, EPOLL_CTL_MOD, fd, &mev);
                    c->epollout_registered = want_write;
                }
            }

            if (events[i].events & EPOLLIN) {
                if (client_fill(c) < 0) {
                    disconnect_client(ep, c);
                    continue;
                }

                Packet pkt;
                while (1) {
                    int rc = client_extract_packet(c, &pkt);
                    if (rc == 0) break; // no full packet buffered yet

                    if (rc < 0) {
                        printf("Client %d sent an oversized packet, disconnecting\n", fd);
                        disconnect_client(ep, c);
                        c = NULL;
                        break;
                    }

                    handle_packet(ep, c, &pkt);
                    if (!clients[fd]) { c = NULL; break; } // handle_packet may have disconnected us
                }
            }
        }
    }
}
