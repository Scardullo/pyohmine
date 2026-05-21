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
