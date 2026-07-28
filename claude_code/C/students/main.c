#include "student.h"
#include "network.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sqlite3 *db = NULL;

// ---- input helpers -------------------------------------------------------
// Centralizing input here means every menu case gets the same overflow-safe,
// re-prompt-on-bad-input behavior instead of raw scanf() calls that leave
// garbage in the stream or overflow fixed-size buffers.

static int readLine(char *buf, size_t size){
    if(!fgets(buf, (int)size, stdin)) return 0;   // EOF / read error
    buf[strcspn(buf, "\n")] = 0;
    return 1;
}

static int readInt(const char *prompt, int *out){
    char line[64];
    while(1){
        printf("%s", prompt);
        if(!readLine(line, sizeof(line))) return 0;
        char *endptr;
        long val = strtol(line, &endptr, 10);
        while(*endptr==' ') endptr++;
        if(endptr==line || *endptr!='\0'){
            printf("Please enter a valid whole number.\n");
            continue;
        }
        *out = (int)val;
        return 1;
    }
}

static int readGrade(const char *prompt, float *out){
    char line[64];
    while(1){
        printf("%s", prompt);
        if(!readLine(line, sizeof(line))) return 0;
        char *endptr;
        float val = strtof(line, &endptr);
        while(*endptr==' ') endptr++;
        if(endptr==line || *endptr!='\0'){
            printf("Please enter a valid number.\n");
            continue;
        }
        if(!isValidGrade(val)){
            printf("Grade must be between 0 and 100.\n");
            continue;
        }
        *out = val;
        return 1;
    }
}

static int readName(const char *prompt, char *buf, size_t size){
    while(1){
        printf("%s", prompt);
        if(!readLine(buf, size)) return 0;
        if(!isValidName(buf)){
            printf("Name cannot be empty or contain a comma.\n");
            continue;
        }
        return 1;
    }
}

// menu
void printMenu() {
    printf("\n=== Student Management Menu ===\n"
           "1.  Add Student\n"
           "2.  Edit Student\n"
           "3.  Delete Student\n"
           "4.  Display Students\n"
           "5.  Search by Name\n"
           "6.  Sort by Name\n"
           "7.  Sort by Grade\n"
           "8.  Show Dashboard\n"
           "9.  Undo Last Delete\n"
           "10. Save CSV\n"
           "11. Load CSV\n"
           "12. Save SQLite\n"
           "13. Load SQLite\n"
           "14. Save JSON\n"
           "15. Load JSON\n"
           "16. Start Broadcast Server\n"
           "17. Stop Broadcast Server\n"
           "18. Connect as Client\n"
           "19. Run Unit Tests\n"
           "20. Exit\n");
}

// main
int main() {
    if (sqlite3_open(FILE_SQLITE,&db)!=SQLITE_OK){
        fprintf(stderr,"Cannot open SQLite DB\n"); db=NULL;
    }

    int choice;
    char name[NAME_LEN];
    char line[64];
    float grade;
    int id;

    while(1){
        printMenu();
        if(!readInt("Choice: ", &choice)) break;   // EOF on stdin

        switch(choice){
            case 1:
                if(!readName("Name: ", name, sizeof(name))) break;
                if(!readGrade("Grade: ", &grade)) break;
                if(!addStudent(name,grade)) printf("Could not add student.\n");
                break;
            case 2:
                if(!readInt("ID to edit: ", &id)) break;
                if(!readName("New Name: ", name, sizeof(name))) break;
                if(!readGrade("New Grade: ", &grade)) break;
                if(!editStudent(id,name,grade)) printf("No student with that ID.\n");
                break;
            case 3:
                if(!readInt("ID to delete: ", &id)) break;
                if(!deleteStudentWithUndo(id)) printf("No student with that ID.\n");
                break;
            case 4:
                displayStudents();
                break;
            case 5:
                if(!readName("Name (or part of it) to search: ", name, sizeof(name))) break;
                searchByName(name);
                break;
            case 6:
                sortByName();
                break;
            case 7:
                sortByGrade();
                break;
            case 8:
                showDashboard();
                break;
            case 9:
                undoLastDelete();
                break;
            case 10:
                saveCSV();
                break;
            case 11:
                loadCSV();
                break;
            case 12:
                if(db) saveSQLite(db);
                break;
            case 13:
                if(db) loadSQLite(db);
                break;
            case 14:
                saveJSON();
                break;
            case 15:
                loadJSON();
                break;
            case 16: {
                int port = 12345;
                printf("Port to listen on [12345]: ");
                if(readLine(line,sizeof(line)) && line[0]) port = atoi(line);
                if(startServer(port)!=0) printf("Failed to start server.\n");
                break;
            }
            case 17:
                stopServer();
                break;
            case 18: {
                char ip[64] = "127.0.0.1";
                int port = 12345;
                printf("Server IP [127.0.0.1]: ");
                readLine(ip,sizeof(ip));
                if(ip[0]==0) strcpy(ip,"127.0.0.1");
                printf("Port [12345]: ");
                if(readLine(line,sizeof(line)) && line[0]) port = atoi(line);
                runClientSession(ip, port);
                break;
            }
            case 19:
                runUnitTests();
                break;
            case 20:
                stopServer();
                cleanupStudentModule();
                if(db) sqlite3_close(db);
                printf("Exiting program...\n");
                return 0;
            default:
                printf("Invalid choice!\n");
        }
    }

    stopServer();
    cleanupStudentModule();
    if(db) sqlite3_close(db);
    return 0;
}
