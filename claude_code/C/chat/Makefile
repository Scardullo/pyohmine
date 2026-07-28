CC=gcc
CFLAGS=-Wall -Wextra -O2 -Icommon

COMMON=common/net.o common/util.o

all: server/chatserver client/chatclient

common/net.o: common/net.c
	$(CC) $(CFLAGS) -c $< -o $@

common/util.o: common/util.c
	$(CC) $(CFLAGS) -c $< -o $@

server/client.o: server/client.c
	$(CC) $(CFLAGS) -c $< -o $@

server/server.o: server/server.c
	$(CC) $(CFLAGS) -c $< -o $@

server/chatserver: server/server.o server/client.o $(COMMON)
	$(CC) $^ -o $@

client/chatclient: client/client.c $(COMMON)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f server/*.o common/*.o client/*.o server/chatserver client/chatclient
