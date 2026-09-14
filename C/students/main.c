#include "student.h"
#include "network.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

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

static int readCourseName(const char *prompt, char *buf, size_t size){
    while(1){
        printf("%s", prompt);
        if(!readLine(buf, size)) return 0;
        if(!isValidCourseName(buf)){
            printf("Course name cannot be empty or contain a comma, colon, or pipe.\n");
            continue;
        }
        return 1;
    }
}

// ANSI "move cursor home, clear to end of screen" - keeps the terminal
// showing just the current menu or the current action's output instead of
// letting every prior screen pile up in scrollback.
static void clearScreen(void){
    printf("\033[H\033[J");
    fflush(stdout);
}

static int requireAdmin(){
    if(!isAdmin()){
        printf("Admin authentication required. Use menu option 24 to log in.\n");
        return 0;
    }
    return 1;
}

// menu
void printMenu() {
    printf("\n=== Student Management Menu ===\n"
           "1.  Add Student\n"
           "2.  Add Course to Student\n"
           "3.  Edit Student (name + primary grade)\n"
           "4.  Edit Course Grade\n"
           "5.  Remove Course [admin]\n"
           "6.  List Courses for Student\n"
           "7.  Delete Student [admin]\n"
           "8.  Display Students (paged)\n"
           "9.  Search by Name\n"
           "10. Search by Average Grade Range\n"
           "11. Sort by Name\n"
           "12. Sort by Average Grade\n"
           "13. Show Dashboard\n"
           "14. Undo Last Delete [admin]\n"
           "15. Save CSV\n"
           "16. Load CSV\n"
           "17. Save SQLite\n"
           "18. Load SQLite\n"
           "19. Save JSON\n"
           "20. Load JSON\n"
           "21. Start Command/Broadcast Server\n"
           "22. Stop Server [admin]\n"
           "23. Connect as Client\n"
           "24. Admin Login\n"
           "25. Admin Logout\n"
           "26. Run Unit Tests\n"
           "27. Exit\n");
}

static void printUsage(const char *prog){
    printf("Usage: %s [--test] [--port N] [--load-csv] [--load-json] [--help]\n"
           "  -t, --test        run the unit test suite and exit\n"
           "  -p, --port N      auto-start the command/broadcast server on port N\n"
           "  -c, --load-csv    load students.csv on startup\n"
           "  -j, --load-json   load students.json on startup\n"
           "  -h, --help        show this message\n", prog);
}

// main
int main(int argc, char **argv) {
    int autoPort = 0, autoLoadCSV = 0, autoLoadJSON = 0, testOnly = 0;

    static struct option longOpts[] = {
        {"test",      no_argument,       0, 't'},
        {"port",      required_argument, 0, 'p'},
        {"load-csv",  no_argument,       0, 'c'},
        {"load-json", no_argument,       0, 'j'},
        {"help",      no_argument,       0, 'h'},
        {0,0,0,0}
    };
    int opt;
    while((opt = getopt_long(argc, argv, "tp:cjh", longOpts, NULL)) != -1){
        switch(opt){
            case 't': testOnly = 1; break;
            case 'p': autoPort = atoi(optarg); break;
            case 'c': autoLoadCSV = 1; break;
            case 'j': autoLoadJSON = 1; break;
            case 'h': printUsage(argv[0]); return 0;
            default:  printUsage(argv[0]); return 1;
        }
    }

    if(testOnly){
        runUnitTests();
        return 0;
    }

    if (sqlite3_open(FILE_SQLITE,&db)!=SQLITE_OK){
        fprintf(stderr,"Cannot open SQLite DB\n"); db=NULL;
    }

    if(autoLoadCSV) loadCSV();
    if(autoLoadJSON) loadJSON();
    if(autoPort > 0 && startServer(autoPort)!=0)
        printf("Failed to auto-start server on port %d\n", autoPort);

    int choice;
    char name[NAME_LEN];
    char courseName[COURSE_NAME_LEN];
    char line[64];
    float grade, gradeHi;
    int id;

    while(1){
        clearScreen();
        printMenu();
        if(!readInt("Choice: ", &choice)) break;   // EOF on stdin
        clearScreen();

        switch(choice){
            case 1:
                if(!readName("Name: ", name, sizeof(name))) break;
                if(!readGrade("Grade: ", &grade)) break;
                if(!addStudent(name,grade)) printf("Could not add student.\n");
                break;
            case 2:
                if(!readInt("Student ID: ", &id)) break;
                if(!readCourseName("Course name: ", courseName, sizeof(courseName))) break;
                if(!readGrade("Grade: ", &grade)) break;
                if(!addCourse(id,courseName,grade))
                    printf("Could not add course (bad student ID, duplicate course name, or course slots full).\n");
                break;
            case 3:
                if(!readInt("ID to edit: ", &id)) break;
                if(!readName("New Name: ", name, sizeof(name))) break;
                if(!readGrade("New Grade: ", &grade)) break;
                if(!editStudent(id,name,grade)) printf("No student with that ID.\n");
                break;
            case 4:
                if(!readInt("Student ID: ", &id)) break;
                if(!readCourseName("Course name: ", courseName, sizeof(courseName))) break;
                if(!readGrade("New grade: ", &grade)) break;
                if(!editCourseGrade(id,courseName,grade)) printf("Course not found.\n");
                break;
            case 5:
                if(!requireAdmin()) break;
                if(!readInt("Student ID: ", &id)) break;
                if(!readCourseName("Course name to remove: ", courseName, sizeof(courseName))) break;
                if(!removeCourse(id,courseName)) printf("Course not found.\n");
                break;
            case 6:
                if(!readInt("Student ID: ", &id)) break;
                listCourses(id);
                break;
            case 7:
                if(!requireAdmin()) break;
                if(!readInt("ID to delete: ", &id)) break;
                if(!deleteStudentWithUndo(id)) printf("No student with that ID.\n");
                break;
            case 8: {
                int page = 1;
                while(1){
                    clearScreen();
                    displayStudents(page);
                    printf("[Enter]=next, b=back, q=stop paging: ");
                    if(!readLine(line,sizeof(line))) break;
                    if(line[0]=='q' || line[0]=='Q') break;
                    if(line[0]=='b' || line[0]=='B'){ if(page>1) page--; continue; }
                    page++;
                }
                break;
            }
            case 9:
                if(!readName("Name (or part of it) to search: ", name, sizeof(name))) break;
                searchByName(name);
                break;
            case 10:
                if(!readGrade("Minimum average: ", &grade)) break;
                if(!readGrade("Maximum average: ", &gradeHi)) break;
                searchByGradeRange(grade, gradeHi);
                break;
            case 11:
                sortByName();
                break;
            case 12:
                sortByGrade();
                break;
            case 13:
                showDashboard();
                break;
            case 14:
                if(!requireAdmin()) break;
                undoLastDelete();
                break;
            case 15:
                saveCSV();
                break;
            case 16:
                loadCSV();
                break;
            case 17:
                if(db) saveSQLite(db);
                break;
            case 18:
                if(db) loadSQLite(db);
                break;
            case 19:
                saveJSON();
                break;
            case 20:
                loadJSON();
                break;
            case 21: {
                if(isServerRunning()){
                    printf("Server is already running.\n");
                    break;
                }
                int port = 12345;
                printf("Port to listen on [12345]: ");
                if(readLine(line,sizeof(line)) && line[0]) port = atoi(line);
                if(startServer(port)!=0) printf("Failed to start server.\n");
                break;
            }
            case 22:
                if(!requireAdmin()) break;
                if(!isServerRunning()){
                    printf("Server is not running.\n");
                    break;
                }
                stopServer();
                break;
            case 23: {
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
            case 24: {
                char pw[128];
                printf("Admin password: ");
                if(!readLine(pw,sizeof(pw))) break;
                if(adminLogin(pw)) printf("Authenticated as admin.\n");
                else printf("Incorrect password.\n");
                break;
            }
            case 25:
                adminLogout();
                printf("Logged out.\n");
                break;
            case 26:
                runUnitTests();
                break;
            case 27:
                stopServer();
                cleanupStudentModule();
                if(db) sqlite3_close(db);
                printf("Exiting program...\n");
                return 0;
            default:
                printf("Invalid choice!\n");
        }

        // Option 8 already pauses per-page inside its own loop, and option 27
        // exits before reaching here. Everything else's output would otherwise
        // get wiped by the clearScreen() at the top of the next iteration
        // before the user has a chance to read it.
        if(choice != 8){
            printf("\nPress Enter to return to the menu...");
            readLine(line, sizeof(line));
        }
    }

    stopServer();
    cleanupStudentModule();
    if(db) sqlite3_close(db);
    return 0;
}
