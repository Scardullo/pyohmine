#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>

void die(const char *msg);
void set_nonblocking(int fd);
void trim_newline(char *s);
void safe_strncpy(char *dst, const char *src, size_t n);

#endif
