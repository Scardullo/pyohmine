#include "../common/net.h"
#include "../common/util.h"
#include "../common/protocol.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

static int sock;

void *recv_thread(void *arg) {
    Packet pkt;
    while (1) {
        if (recv_all(sock, &pkt.len, 2) < 0 ||
            recv_all(sock, &pkt.type, 1) < 0 ||
            recv_all(sock, pkt.data, pkt.len) < 0)
            break;

        printf("%s\n", pkt.data);
    }
    return NULL;
}

int main() {
    sock = tcp_connect("127.0.0.1", 5555);

    char nick[64];
    printf("Nick: ");
    fgets(nick, sizeof nick, stdin);
    trim_newline(nick);

    Packet pkt = {0};
    pkt.type = MSG_NICK;
    strcpy((char*)pkt.data, nick);
    pkt.len = strlen(nick) + 1;
    send_all(sock, &pkt, pkt.len + 3);

    pthread_t t;
    pthread_create(&t, NULL, recv_thread, NULL);

    char line[1024];
    while (fgets(line, sizeof line, stdin)) {
        trim_newline(line);
        pkt.type = MSG_CHAT;
        strcpy((char*)pkt.data, line);
        pkt.len = strlen(line) + 1;
        send_all(sock, &pkt, pkt.len + 3);
    }
}
