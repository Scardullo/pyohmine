CC      = gcc
CFLAGS  = -Wall -Wextra -g
SQLITE  = $(shell pkg-config --cflags --libs sqlite3)
PTHREAD = -lpthread
MATH    = -lm

.PHONY: all clean test

all: main server client

main: main.c student.c network.c student.h network.h
	$(CC) $(CFLAGS) -o main main.c student.c network.c $(SQLITE) $(PTHREAD) $(MATH)

server: server.c student.c network.c student.h network.h server.h
	$(CC) $(CFLAGS) -o server server.c student.c network.c $(SQLITE) $(PTHREAD) $(MATH)

client: client.c network.c student.c student.h network.h
	$(CC) $(CFLAGS) -o client client.c network.c student.c $(SQLITE) $(PTHREAD) $(MATH)

test: main
	./main --test

clean:
	rm -f main server client
