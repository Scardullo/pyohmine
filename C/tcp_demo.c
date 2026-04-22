#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 9090
#define BUF_SIZE 1024

void run_server() {
    int listen_fd, conn_fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char buffer[BUF_SIZE];

    listen_fd = socket(AF_INET, SOCK_STREAM,0);
    if (listen_fd < 0) {
	perror("socket");
	exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	perror("bind");
	exit(1);
    }

    if (listen(listen_fd, 5) < 0) {
	perror("listen");
	exit(1);
    }

    printf("[SERVER] Listening on port %d...\n", PORT);

    conn_fd = accept(listen_fd, (struct sockaddr *)&addr, &addr_len);
    if (conn_fd < 0) {
	perror("accept");
	exit(1);
    }

    printf("[SERVER] Client connected\n");

    ssize_t n = recv(conn_fd, buffer, BUF_SIZE -1, 0);
    if (n > 0) {
	buffer[n] = '\0';
	printf("[SERVER] Received: %s\n", buffer);
    }




}
