#include "client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

Client *client_create(int fd) {
    Client *c = calloc(1, sizeof(Client));
    c->fd = fd;
    strcpy(c->nick, "anon");
    strcpy(c->room, DEFAULT_ROOM);
    return c;
}

void client_destroy(Client *c) {
    close(c->fd);
    free(c);
}

int client_fill(Client *c) {
    while (c->in_used < IN_BUF_SIZE) {
        ssize_t n = recv(c->fd, c->in_buf + c->in_used, IN_BUF_SIZE - c->in_used, 0);
        if (n > 0) {
            c->in_used += (size_t)n;
            continue; // level-triggered epoll: drain until the kernel buffer is empty
        }
        if (n == 0) return -1;             // peer closed the connection
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; // no more data right now
        if (errno == EINTR) continue;
        return -1;
    }
    return 0; // in_buf full for now; caller should extract packets to free space
}

int client_extract_packet(Client *c, Packet *pkt) {
    if (c->in_used < 3) return 0;

    uint16_t netlen;
    memcpy(&netlen, c->in_buf, 2);
    uint16_t len = ntohs(netlen);
    uint8_t type = c->in_buf[2];

    if (len >= MAX_PAYLOAD) return -1; // leave room for the null terminator

    size_t needed = 3 + len;
    if (c->in_used < needed) return 0; // packet not fully buffered yet

    pkt->len = len;
    pkt->type = type;
    if (len > 0) memcpy(pkt->data, c->in_buf + 3, len);
    pkt->data[len] = '\0';

    memmove(c->in_buf, c->in_buf + needed, c->in_used - needed);
    c->in_used -= needed;
    return 1;
}

int client_flush(Client *c, int *want_write) {
    while (c->out_used > 0) {
        ssize_t n = send(c->fd, c->out_buf, c->out_used, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            return -1;
        }
        memmove(c->out_buf, c->out_buf + n, c->out_used - (size_t)n);
        c->out_used -= (size_t)n;
    }
    if (want_write) *want_write = (c->out_used > 0);
    return 0;
}

int client_send(Client *c, const Packet *pkt, int *want_write) {
    size_t needed = 3 + pkt->len;
    if (c->out_used + needed > OUT_BUF_SIZE) return -1; // slow consumer

    uint16_t netlen = htons(pkt->len);
    memcpy(c->out_buf + c->out_used, &netlen, 2);
    c->out_buf[c->out_used + 2] = pkt->type;
    if (pkt->len > 0) memcpy(c->out_buf + c->out_used + 3, pkt->data, pkt->len);
    c->out_used += needed;

    return client_flush(c, want_write);
}
