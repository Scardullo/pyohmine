#ifndef STUDENT_H
#define STUDENT_H

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <pthread.h>

// file names
#define FILE_CSV "students.csv"
#define FILE_JSON "students.json"
#define FILE_SQLITE "students.db"
#define NAME_LEN 50

// student struct
typedef struct Student {
    int id;
    char name[NAME_LEN];
    float grade;
    struct Student *next;
} Student;

// memory allocator
typedef struct AllocRecord {
    void *ptr;
    size_t size;
    struct AllocRecord *next;
} AllocRecord;

void *student_malloc(size_t size);
void student_free(void *ptr);
void print_allocations();
void reportLeaks();

// global variables
extern Student *head;
extern pthread_mutex_t student_lock;

// logging
void logMessage(const char *fmt, ...);

// broadcast
typedef void (*BroadcastCallback)(const char *msg);
void registerBroadcastCallback(BroadcastCallback cb);

// core CRUD
int addStudent(const char *name, float grade);
int editStudent(int id, const char *name, float grade);
int deleteStudentWithUndo(int id);
void undoLastDelete();
Student* searchById(int id);
void displayStudents();
void freeList();

// sorting
void sortByName();
void sortByGrade();

// statistics
Student* getTopStudent();
Student* getLowestStudent();
float getAverageGrade();

// csv storage
void saveCSV();
void loadCSV();

// sqlite storage
int saveSQLite(sqlite3 *db);
int loadSQLite(sqlite3 *db);

// unit test hooks
void runUnitTests();
void runUnitTestsWithAllocator();

// cleanup
void cleanupStudentModule();

#endif
