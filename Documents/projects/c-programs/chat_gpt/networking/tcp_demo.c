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

    // 1. Create TCP socket
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        exit(1);
    }

    // 2. Prepare address (IP + port)
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    // 3. Bind socket to IP:PORT
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    // 4. Start listening (TCP state: LISTEN)
    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        exit(1);
    }

    printf("[SERVER] Listening on port %d...\n", PORT);

    // 5. Accept incoming connection
    conn_fd = accept(listen_fd, (struct sockaddr *)&addr, &addr_len);
    if (conn_fd < 0) {
        perror("accept");
        exit(1);
    }

    printf("[SERVER] Client connected\n");

    // 6. Receive data (TCP stream)
    ssize_t n = recv(conn_fd, buffer, BUF_SIZE - 1, 0);
    if (n > 0) {
        buffer[n] = '\0';
        printf("[SERVER] Received: %s\n", buffer);
    }

    // 7. Send response
    const char *reply = "Hello from server!";
    send(conn_fd, reply, strlen(reply), 0);

    close(conn_fd);
    close(listen_fd);
}

void run_client() {
    int sock;
    struct sockaddr_in addr;
    char buffer[BUF_SIZE];

    // 1. Create TCP socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    // 2. Server address
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    // 3. Connect (TCP handshake happens here)
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(1);
    }

    printf("[CLIENT] Connected to server\n");

    // 4. Send data
    const char *msg = "Hello from client!";
    send(sock, msg, strlen(msg), 0);

    // 5. Receive reply
    ssize_t n = recv(sock, buffer, BUF_SIZE - 1, 0);
    if (n > 0) {
        buffer[n] = '\0';
        printf("[CLIENT] Received: %s\n", buffer);
    }

    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s [server|client]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "server") == 0) {
        run_server();
    } else if (strcmp(argv[1], "client") == 0) {
        run_client();
    } else {
        fprintf(stderr, "Invalid mode\n");
        return 1;
    }

    return 0;
}
