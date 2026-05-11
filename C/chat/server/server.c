#include "../common/net.h"
#include "../common/util.h"
#include "../common/protocol.h"

#include <sys/epoll.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_EVENTS 64
#define MAX_CLIENTS 1024


