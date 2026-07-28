CC      = gcc
CFLAGS  = -Wall -Wextra -g
SQLITE  = $(shell pkg-config --cflags --libs sqlite3)
PTHREAD = -lpthread

.PHONY: all clean

all: main server client

main: main.c student.c network.c student.h network.h
	$(CC) $(CFLAGS) -o main main.c student.c network.c $(SQLITE) $(PTHREAD)

server: server.c student.c
	$(CC) $(CFLAGS) -o server server.c student.c $(SQLITE) $(PTHREAD)

client: client.c
	$(CC) $(CFLAGS) -o client client.c

clean:
	rm -f main server client
