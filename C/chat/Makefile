C=gcc
CFLAGS=-Wall -Wextra -02 -Icommon

COMMON=common/net.o common/util.o

all: server/chatserver client/chatclient

common/net.o: common/net.c
	$(CC) $(CFLAGS) -c $< -o $@

common/util.o: common/util.c
	$(CC) $(CFLAGS) -c $< -o $@
