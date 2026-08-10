#include "network.h"
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_PORT 12345
#define DEFAULT_IP   "127.0.0.1"

// Standalone client binary: connects to a running server (main --port N, or
// the standalone `server` binary) and drops into the same interactive
// command session available from the menu's "Connect as Client" option.
// Usage: ./client [ip] [port]
int main(int argc, char **argv){
    const char *ip = argc > 1 ? argv[1] : DEFAULT_IP;
    int port = argc > 2 ? atoi(argv[2]) : DEFAULT_PORT;
    runClientSession(ip, port);
    return 0;
}
