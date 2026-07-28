#ifndef CLIENT_H
#define CLIENT_H

#include "../common/protocol.h"
#include <stddef.h>
#include <stdint.h>

#define IN_BUF_SIZE  4096
#define OUT_BUF_SIZE 16384

typedef struct Client {
    int fd;
    char nick[MAX_NICK];
    char room[MAX_ROOM];
    int registered; // has a unique, user-chosen nickname (vs. the "anon" default)

    uint8_t in_buf[IN_BUF_SIZE];
    size_t  in_used;

    uint8_t out_buf[OUT_BUF_SIZE];
    size_t  out_used;

    int epollout_registered; // owned by server.c; tracks current epoll interest
} Client;

Client *client_create(int fd);
void client_destroy(Client *c);

// Pulls whatever is currently available off the socket into c->in_buf.
// Returns 0 on success (0 or more bytes may have been read), -1 if the
// peer disconnected or the socket errored.
int client_fill(Client *c);

// Extracts one complete framed packet from the front of c->in_buf, if one
// is fully buffered. pkt->data is always null-terminated on success.
// Returns 1 if a packet was extracted, 0 if more data is needed,
// -1 on a protocol violation (declared length too large) - caller should
// disconnect the client.
int client_extract_packet(Client *c, Packet *pkt);

// Queues a packet and opportunistically sends as much as the socket will
// take right now. *want_write is set to 1 if bytes remain queued (caller
// must ensure EPOLLOUT is registered for this fd) or 0 if the queue fully
// drained (caller may drop EPOLLOUT). Returns 0 on success, -1 if the
// outbound queue overflowed (slow consumer) or the socket hard-errored -
// caller should disconnect the client either way.
int client_send(Client *c, const Packet *pkt, int *want_write);

// Flushes previously queued bytes once the socket becomes writable again.
// Same *want_write / return convention as client_send.
int client_flush(Client *c, int *want_write);

#endif
