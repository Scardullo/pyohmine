#define _POSIX_C_SOURCE 200112L

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PORT           5555
#define MAX_CLIENTS    64
#define MAX_NAME       32
#define MAX_ROOM       32
#define MAX_PAYLOAD    2048
#define BACKLOG        32

#define ANSI_RESET     "\033[0m"
#define ANSI_RED       "\033[31m"
#define ANSI_GREEN     "\033[32m"
#define ANSI_YELLOW    "\033[33m"
#define ANSI_BLUE      "\033[34m"
#define ANSI_MAGENTA   "\033[35m"
#define ANSI_CYAN      "\033[36m"

enum {
    PKT_HELLO = 1,
    PKT_CHAT,
    PKT_SYSTEM,
    PKT_PRIVATE,
    PKT_COMMAND,
    PKT_ROOM
};

typedef struct {
    uint16_t len;
    uint8_t  type;
    char     data[MAX_PAYLOAD];
} Packet;

typedef struct {
    int fd;
    int active;
    pthread_t thread;

    char username[MAX_NAME];
    char room[MAX_ROOM];

    time_t connected_at;
    uint64_t msgs_sent;
} Client;

static Client clients[MAX_CLIENTS];
static pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;

static volatile sig_atomic_t running = 1;

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void trim_newline(char *s) {
    size_t n = strlen(s);
    if (n && s[n - 1] == '\n')
        s[n - 1] = 0;
}

static void timestamp(char *buf, size_t sz) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    strftime(buf, sz, "%H:%M:%S", tm);
}

static void log_msg(const char *fmt, ...) {
    char tbuf[32];
    timestamp(tbuf, sizeof tbuf);

    printf(ANSI_CYAN "[%s] " ANSI_RESET, tbuf);

    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);

    printf("\n");
}

static int send_all(int fd, const void *buf, size_t len) {
    size_t sent = 0;
    const char *p = buf;

    while (sent < len) {
	ssize_t n = send(fd, p + sent, len - sent, 0);
	if (n <= 0)
	    return -1;
	sent += n;
    }

    return 0;
}

static int recv_all(int fd, void *buf, size_t len) {
    size_t recvd = 0;
    char *p = buf;

    while (recvd < len) {
	ssize_t n = recv(fd, p + recvd, len - recvd, 0);
	if (n <= 0)
		return -1;
	recvd += n;
    }

    return 0;
}

static int send_packet(int fd, uint8_t type, const char *msg) {
    Packet pkt = {0};

    pkt.type = type;
    strncpy(pkt.data, msg, sizeof(pkt.data) - 1);
    pkt.len = strlen(pkt.data) + 1;

    uint16_t netlen = htons(pkt.len);

    if (send_all(fd, &netlen, 2) < 0)
	return -1;
}
