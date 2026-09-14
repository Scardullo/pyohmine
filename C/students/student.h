#ifndef STUDENT_H
#define STUDENT_H

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <pthread.h>

// file names
#define FILE_CSV     "students.csv"
#define FILE_JSON    "students.json"
#define FILE_SQLITE  "students.db"
#define FILE_ADMIN   "admin.hash"
#define NAME_LEN        50
#define COURSE_NAME_LEN 24
#define MAX_COURSES      8
#define PAGE_SIZE       10
#define HASH_TABLE_SIZE 257   // prime, keeps id % size well distributed

// a single course grade belonging to a student
typedef struct Course {
    char name[COURSE_NAME_LEN];
    float grade;
} Course;

// student struct - now holds a small fixed-size array of course grades
// instead of a single grade, so a student's "grade" is really a GPA-style
// average computed on demand.
typedef struct Student {
    int id;
    char name[NAME_LEN];
    Course courses[MAX_COURSES];
    int courseCount;
    struct Student *next;    // master list (insertion / sorted order)
    struct Student *hnext;   // id-hash bucket chain, see student.c
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
int addStudent(const char *name, float grade);          // convenience: creates a "General" course
int editStudent(int id, const char *name, float grade);  // renames + overwrites first course grade
int deleteStudentWithUndo(int id);
void undoLastDelete();
Student* searchById(int id);          // O(1) via internal hash index
void displayStudents(int page);       // page starts at 1; 0 or negative = show all
void freeList();

// courses
int addCourse(int id, const char *courseName, float grade);
int editCourseGrade(int id, const char *courseName, float grade);
int removeCourse(int id, const char *courseName);
void listCourses(int id);
float studentAverage(const Student *s);
char letterGrade(float avg);

// validation
int isValidGrade(float grade);
int isValidName(const char *name);
int isValidCourseName(const char *name);

// searching
int searchByName(const char *query);
int searchByGradeRange(float minGrade, float maxGrade);

// sorting
void sortByName();
void sortByGrade();

// statistics
Student* getTopStudent();
Student* getLowestStudent();
float getAverageGrade();
float getMedianGrade();
float getStdDevGrade();
int countStudents();
void showDashboard();

// admin authentication (very lightweight - salted FNV-1a hash, NOT
// cryptographically secure, just enough to gate destructive menu actions
// in a learning project)
int adminLogin(const char *password);
int isAdmin();
void adminLogout();

// csv storage
void saveCSV();
void loadCSV();

// json storage
void saveJSON();
void loadJSON();

// sqlite storage (relational: students + courses tables)
int saveSQLite(sqlite3 *db);
int loadSQLite(sqlite3 *db);

// unit test hooks
void runUnitTests();

// cleanup
void cleanupStudentModule();

#endif
