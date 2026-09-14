#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define MAX_PAYLOAD 1024
#define MAX_NICK    32
#define MAX_ROOM    32
#define DEFAULT_ROOM "general"

enum {
    MSG_NICK = 1,   // client -> server: set/change nickname
    MSG_CHAT = 2,   // client -> server: chat line (broadcast to sender's room)
    MSG_PRIV = 3,   // client -> server: "target\0message"  |  server -> client: "sender\0message"
    MSG_SYSTEM = 4, // server -> client: informational/error text
    MSG_JOIN = 5,   // client -> server: switch to a room
    MSG_LIST = 6    // client -> server: request the roster of the current room
};

typedef struct {
    uint16_t len;
    uint8_t  type;
    uint8_t  data[MAX_PAYLOAD];
} __attribute__((packed)) Packet;

#endif
