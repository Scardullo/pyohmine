#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

void die(const char *msg) {
    perror(msg);
    exit(1);
}

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) die("fcntl get");
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        die("fcntl set");
}

void trim_newline(char *s) {
    size_t n = strlen(s);
    if (n && s[n-1] == '\n') s[n-1] = 0;
}

void safe_strncpy(char *dst, const char *src, size_t n) {
    strncpy(dst, src, n-1);
    dst[n-1] = 0;
}
