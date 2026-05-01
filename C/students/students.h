#ifndef STUDENT_H
#define STUDENT_H

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

#define NAME_LEN 50
#define FILE_CSV "students.csv"
#define FILE_JSON "students.json"
#define FILE_SQLITE "students.db"

typedef struct Student {
    int id;
    char name[NAME_LEN];
    float grade;
    struct Student *next;
} Student;

extern Student *head;
extern pthread_mutex_t student_lock;

void *student_malloc(size_t size);
void student_free(void *ptr);
void print_allocations();

int addStudent(const char *name, float grade);
int editStudent(int id, const char *name, float grade);
int deleteStudent(int id);
Student* searchById(int id);
Student* getTopStudent();
Student* getLowestStudent();
float getAverageGrade();
void displayStudents();
void freeList();

void sortByName();
void sortByGrade();

void loadCSV();
void saveCSV();
void loadJSON();
void saveJSON();
int loadSQLite(sqlite3 *db);
int saveSQLite(sqlite3 *db);

void logMessage(const char *fmt, ...);

#endif
