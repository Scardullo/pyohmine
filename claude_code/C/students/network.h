#ifndef NETWORK_H
#define NETWORK_H

// Starts a background broadcast server on the given port. Every add/edit/
// delete/undo performed through student.c gets pushed out to connected
// clients. Returns 0 on success, -1 on failure.
int startServer(int port);

// Stops the broadcast server and disconnects any connected clients.
void stopServer(void);

int isServerRunning(void);

// Connects to a broadcast server as a client. Blocks in an interactive
// chat loop until the user types /quit or the server disconnects.
void runClientSession(const char *ip, int port);

#endif
