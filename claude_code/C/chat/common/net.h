#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <stddef.h>
#include "protocol.h"

int tcp_listen(uint16_t port);
int tcp_connect(const char *host, uint16_t port);

int send_all(int fd, const void *buf, size_t len);
int recv_all(int fd, void *buf, size_t len);

// Frame a Packet on the wire (length in network byte order) and send it.
// Returns 0 on success, -1 on I/O error / disconnect.
int send_packet(int fd, const Packet *pkt);

// Read one framed Packet off the wire. pkt->data is always null-terminated
// on success, so it is safe to use as a C string.
// Returns 0 on success, -1 on I/O error / disconnect, -2 if the peer
// declared a length that doesn't fit in the payload buffer (protocol error).
int recv_packet(int fd, Packet *pkt);

#endif
