#ifndef NETWORK_H
#define NETWORK_H

// Starts a background command/broadcast server on the given port. Every
// add/edit/delete/undo performed anywhere (locally through the menu, or
// remotely through a connected client) gets pushed out to every connected
// client as a change notification. Returns 0 on success, -1 on failure.
//
// Wire protocol: clients send one command per line (newline-terminated).
// Recognized commands (case-insensitive):
//   HELP                          list commands
//   LIST                          list all students (id, name, avg, letter)
//   SEARCH <substring>            case-insensitive name search
//   RANGE <min> <max>             students whose average falls in [min,max]
//   STATS                         count/avg/median/stddev/top/lowest
//   AUTH <password>               authenticate this connection as admin
//                                 (note: if no admin password has ever been
//                                 set, the FIRST AUTH anyone sends - local
//                                 menu or remote - permanently becomes it;
//                                 set one locally via the menu before
//                                 exposing the server on a shared network)
//   ADD <name>,<grade>            add a student
//   EDIT <id>,<name>,<grade>      rename/regrade a student (requires AUTH)
//   DEL <id>                      delete a student (requires AUTH)
//   QUIT                          polite disconnect
// Any other line is treated as free-form chat and broadcast to every other
// connected client, same as the original server.
int startServer(int port);

// Stops the broadcast server and disconnects any connected clients.
void stopServer(void);

int isServerRunning(void);

// Connects to a broadcast server as a client. Blocks in an interactive
// chat/command loop until the user types /quit or the server disconnects.
void runClientSession(const char *ip, int port);

#endif
