#include "student.h"
#include "server.h"
#include <ncurses.h>
#include <pthread.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

static int running = 1;
static sqlite3 *db = NULL;

/* -------------------- Dashboard Thread -------------------- */
void* dashboardThread(void *arg){
    initscr();
    noecho();
    curs_set(FALSE);

    while(running){
        pthread_mutex_lock(&student_lock);
        clear();
        mvprintw(0,0,"=== Student Dashboard ===");
        mvprintw(1,0,"Total Students: %d",head ? 1 : 0);
        int row=3;
        Student *t=head;
        while(t && row<20){
            mvprintw(row++,0,"%d | %-20s | %.2f",t->id,t->name,t->grade);
            t=t->next;
        }
        Student *top = getTopStudent();
        Student *low = getLowestStudent();
        mvprintw(22,0,"Top: %s %.2f",top?top->name:"N/A",top?top->grade:0);
        mvprintw(23,0,"Lowest: %s %.2f",low?low->name:"N/A",low?low->grade:0);
        mvprintw(24,0,"Avg Grade: %.2f",getAverageGrade());
        pthread_mutex_unlock(&student_lock);

        refresh();
        usleep(500000);
    }

    endwin();
    return NULL;
}

/* -------------------- Menu Helpers -------------------- */
void printMenu(){
    printf("\n=== Student Management ===\n"
           "1. Add Student\n"
           "2. Edit Student\n"
           "3. Delete Student\n"
           "4. List Students\n"
           "5. Sort by Name\n"
           "6. Sort by Grade\n"
           "7. Save CSV\n"
           "8. Load CSV\n"
           "9. Save SQLite\n"
           "10. Load SQLite\n"
           "11. Exit\n");
}

/* -------------------- Main -------------------- */
int main(int argc,char **argv){
    if(sqlite3_open(FILE_SQLITE,&db)!=SQLITE_OK){
        fprintf(stderr,"Cannot open SQLite DB\n");
        db=NULL;
    }

    if(argc>1 && strcmp(argv[1],"server")==0){
        printf("Starting server mode...\n");
        startServer(SERVER_PORT);
        if(db) saveSQLite(db);
        sqlite3_close(db);
        return 0;
    }

    pthread_t dash;
    running=1;
    pthread_create(&dash,NULL,dashboardThread,NULL);

    int choice;
    char name[NAME_LEN];
    float grade;
    int id;

    while(1){
        printMenu();
        printf("Choice: ");
        if(scanf("%d",&choice)!=1){ while(getchar()!='\n'); continue; }

        switch(choice){
            case 1:
                printf("Name: "); scanf("%s",name);
                printf("Grade: "); scanf("%f",&grade);
                addStudent(name,grade);
                break;
            case 2:
                printf("ID to edit: "); scanf("%d",&id);
                printf("New Name: "); scanf("%s",name);
                printf("New Grade: "); scanf("%f",&grade);
                editStudent(id,name,grade);
                break;
            case 3:
                printf("ID to delete: "); scanf("%d",&id);
                deleteStudent(id);
                break;
            case 4:
                displayStudents();
                break;
            case 5:
                sortByName();
                break;
            case 6:
                sortByGrade();
                break;
            case 7:
                saveCSV();
                break;
            case 8:
                loadCSV();
                break;
            case 9:
                if(db) saveSQLite(db);
                break;
            case 10:
                if(db) loadSQLite(db);
                break;
            case 11:
                running=0;
                pthread_join(dash,NULL);
                freeList();
                if(db) sqlite3_close(db);
                printf("Exiting...\n");
                return 0;
            default:
                printf("Invalid choice\n");
        }
    }

    return 0;
}
