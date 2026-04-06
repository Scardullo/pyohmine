#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define MAX_PAYLOAD 1024
#define MAX_NICK    32

enum {
    MSG_NICK = 1,
    MSG_CHAT = 2,
    MSG_PRIV = 3,
    MSG_SYSTEM = 4
};

typedef struct {
    uint16_t len;
    uint8_t  type;
    uint8_t  data[MAX_PAYLOAD];
} __attribute__((packed)) Packet;

#endif
