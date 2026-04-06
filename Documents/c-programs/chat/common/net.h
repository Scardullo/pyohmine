#ifndef NET_H
#define NET_H

#include <stdint.h>

int tcp_listen(uint16_t port);
int tcp_connect(const char *host, uint16_t port);

int send_all(int fd, const void *buf, size_t len);
int recv_all(int fd, void *buf, size_t len);

#endif
