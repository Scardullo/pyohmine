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
    }
}
