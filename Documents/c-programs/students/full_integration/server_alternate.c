#include "student.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

#define PORT 12345
#define MAX_CLIENTS 10

static int clients[MAX_CLIENTS];
static pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;

/* Send message to all connected clients */
void broadcast_to_clients(const char *msg) {
    pthread_mutex_lock(&clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] > 0) {
            write(clients[i], msg, strlen(msg));
        }
    }
    pthread_mutex_unlock(&clients_lock);
}

void student_broadcast(const char *msg) {
    broadcast_to_clients(msg);
}

void *client_thread(void *arg) {
    int sock = *(int *)arg;
    free(arg);   // free heap copy

    char buffer[128];
    ssize_t n;

    while ((n = read(sock, buffer, sizeof(buffer))) > 0) {
        write(sock, buffer, n);
    }

    close(sock);

    /* Remove from clients[] list */
    pthread_mutex_lock(&clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] == sock) {
            clients[i] = 0;
            break;
        }
    }
    pthread_mutex_unlock(&clients_lock);

    return NULL;
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    registerBroadcastCallback(student_broadcast);

    printf("Server listening on port %d...\n", PORT);

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        /* Add client to global list */
        pthread_mutex_lock(&clients_lock);
        int added = 0;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i] == 0) {
                clients[i] = client_fd;
                added = 1;
                break;
            }
        }
        pthread_mutex_unlock(&clients_lock);

        if (!added) {
            printf("Too many clients. Rejecting connection.\n");
            close(client_fd);
            continue;
        }

        // Allocate memory to safely pass socket to thread 
        int *pclient = malloc(sizeof(int));
        if (!pclient) {
            perror("malloc");

            // remove client from list since we can't handle it
            pthread_mutex_lock(&clients_lock);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i] == client_fd) {
                    clients[i] = 0;
                    break;
                }
            }
            pthread_mutex_unlock(&clients_lock);

            close(client_fd);
            continue;
        }

        *pclient = client_fd;

        pthread_t tid;
        int rc = pthread_create(&tid, NULL, client_thread, pclient);
        if (rc != 0) {
            perror("pthread_create");

            free(pclient);  // prevent leak

            pthread_mutex_lock(&clients_lock);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i] == client_fd) {
                    clients[i] = 0;
                    break;
                }
            }
            pthread_mutex_unlock(&clients_lock);

            close(client_fd);
            continue;
        }

        pthread_detach(tid);
    }

    close(server_fd);
    return 0;
}

