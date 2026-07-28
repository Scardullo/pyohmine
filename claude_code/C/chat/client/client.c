#include "../common/net.h"
#include "../common/util.h"
#include "../common/protocol.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static int sock;

void *recv_thread(void *arg) {
    (void)arg;
    Packet pkt;
    while (1) {
        int rc = recv_packet(sock, &pkt);
        if (rc < 0) {
            if (rc == -2) fprintf(stderr, "Server sent an oversized packet\n");
            break;
        }

        if (pkt.type == MSG_PRIV) {
            // Wire format: "<sender-nick>\0<message>"
            size_t slen = strnlen((char*)pkt.data, pkt.len);
            const char *sender = (char*)pkt.data;
            const char *msg = (slen < pkt.len) ? (char*)pkt.data + slen + 1 : "";
            printf("[PM from %s] %s\n", sender, msg);
        } else {
            printf("%s\n", pkt.data);
        }
    }
    printf("Disconnected from server.\n");
    return NULL;
}

static void send_simple(uint8_t type, const char *text) {
    Packet pkt = {0};
    pkt.type = type;
    safe_strncpy((char*)pkt.data, text, MAX_PAYLOAD);
    pkt.len = strlen((char*)pkt.data) + 1;
    send_packet(sock, &pkt);
}

static void send_empty(uint8_t type) {
    Packet pkt = {0};
    pkt.type = type;
    pkt.len = 0;
    send_packet(sock, &pkt);
}

static void send_priv(const char *target, const char *msg) {
    Packet pkt = {0};
    pkt.type = MSG_PRIV;

    size_t tlen = strnlen(target, MAX_NICK - 1);
    memcpy(pkt.data, target, tlen);
    pkt.data[tlen] = '\0';

    size_t room = MAX_PAYLOAD - tlen - 2; // space left after "<target>\0" and the final NUL
    size_t mlen = strnlen(msg, room);
    memcpy(pkt.data + tlen + 1, msg, mlen);
    pkt.data[tlen + 1 + mlen] = '\0';

    pkt.len = tlen + 1 + mlen + 1;
    send_packet(sock, &pkt);
    printf("-> %s: %s\n", target, msg);
}

static void print_help(void) {
    printf(
        "Commands:\n"
        "  /msg <nick> <text>   send a private message\n"
        "  /list                list who's in your current room\n"
        "  /join <room>         switch rooms (default: " DEFAULT_ROOM ")\n"
        "  /nick <name>         change your nickname\n"
        "  /quit                disconnect\n"
        "  /help                show this message\n");
}

int main() {
    sock = tcp_connect("127.0.0.1", 5555);

    char nick[64];
    printf("Nick: ");
    fgets(nick, sizeof nick, stdin);
    trim_newline(nick);
    send_simple(MSG_NICK, nick);

    pthread_t t;
    pthread_create(&t, NULL, recv_thread, NULL);

    printf("Connected. Type /help for commands.\n");

    char line[1024];
    while (fgets(line, sizeof line, stdin)) {
        trim_newline(line);
        if (line[0] == '\0') continue;

        if (line[0] == '/') {
            if (strncmp(line, "/msg ", 5) == 0) {
                char *rest = line + 5;
                char *sp = strchr(rest, ' ');
                if (!sp || sp[1] == '\0') {
                    printf("Usage: /msg <nick> <message>\n");
                } else {
                    *sp = '\0';
                    send_priv(rest, sp + 1);
                }
            } else if (strcmp(line, "/list") == 0) {
                send_empty(MSG_LIST);
            } else if (strncmp(line, "/join ", 6) == 0) {
                send_simple(MSG_JOIN, line + 6);
            } else if (strncmp(line, "/nick ", 6) == 0) {
                send_simple(MSG_NICK, line + 6);
            } else if (strcmp(line, "/quit") == 0) {
                break;
            } else if (strcmp(line, "/help") == 0) {
                print_help();
            } else {
                printf("Unknown command: %s (try /help)\n", line);
            }
            continue;
        }

        send_simple(MSG_CHAT, line);
    }

    shutdown(sock, SHUT_RDWR); // wakes recv_thread's blocking recv() cleanly
    close(sock);
    return 0;
}
