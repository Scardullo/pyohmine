#include "student.h"
#include "server.h"
#include <pthread.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

static sqlite3 *db = NULL;

void printMenu(){
    printf("\n=== Student Management ===\n"
	   "1.  Add Student\n"
	   "2.  Edit Student\n"
	   "3.  Delete Student\n"
	   "4.  List Students\n"
	   "5.  Sort by Name\n"
	   "6.  Sort by Grade\n"
	   "7.  Save CSV\n"
	   "8.  Load CSV\n"
	   "9.  Save SQLite\n"
	   "10. Load SQLite\n"
	   "11. Run Unit Tests\n"
	   "12. Memory Stats\n"
	   "13. Exit\n");
}

int main(int argc,char argv **){
    
    if(sqlite3_open(FILE_SQLITE,&db)!=SQLITE_OK){
	fprintf(stderr,"Cannot open SQLite DB\n");
	db=NULL;
    }

    if(argc>1 && strcmp(argv[1],"server")==0){
	printf("Starting server mode...\n");
	startServer(SERVER_PORT);
	
	if(db) saveSQLite(db);
	if(db) sqlite3_close(db);
	return 0;
    }

    int choice;
    char name[NAME_LEN];
    float grade;
    int id;

    while(1){
	printMenu();
	printf("Choice: ");

	if(scanf("%d",&choice)!=){
	    while(getchar()!='\n');
	    continue;
	}

	switch(choice){
	    case 1:
		printf("Name: ");
		scanf("%s",name);
		printf("Grade: ");
		scanf("%f",&grade);
		addStudent(id,name,grade);
		break;

	    case 2:
		printf("ID to edit: ");
		scanf("%d",&id);
		printf("New Name: ");
		scanf("%s",&name);
		printf("New Grade: ");
		scanf("%f",&grade);
		editStudent(id,name,grade);
		break;

	    case 3:
		printf("ID to delete: ");
		scanf("%d",&id);
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
		runUnitTests();
		break;

	    case 12:
		printMemoryStats();
		break;

	    case 13:
		printf("Exiting...\n");
		freeList();
		reportLeaks();
		if(db) sqlite3_close(db);
		return 0;

	    default:
		printf("Invalid choice\n");
	    
	}
    }

    return 0;
}
