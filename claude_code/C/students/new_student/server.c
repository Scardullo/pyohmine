#include "network.h"
#include "student.h"
#include "server.h"
#include <stdio.h>
#include <stdlib.h>

// Standalone command/broadcast server binary. It's a thin wrapper around the
// same network.c server the interactive menu uses (see main.c option 21),
// so this binary and the menu-driven app speak the identical wire protocol -
// unlike the original server.c/client.c, which reimplemented sockets from
// scratch and only understood raw chat, not the ADD/EDIT/DEL/LIST commands.
int main(int argc, char **argv){
    int port = SERVER_PORT;
    if(argc > 1) port = atoi(argv[1]);

    loadJSON();  // pick up a previously saved roster, if any
    printf("Loaded %d students from %s.\n", countStudents(), FILE_JSON);

    if(startServer(port) != 0){
        fprintf(stderr,"Failed to start server on port %d\n", port);
        cleanupStudentModule();
        return 1;
    }

    printf("Server running on port %d. Press Enter to stop and exit.\n", port);
    getchar();

    stopServer();
    saveJSON();
    cleanupStudentModule();
    return 0;
}
