#ifndef STUDENT_H
#define STUDENT_H

#include <time.h>
#include <pthread.h>

#define FILE_NAME   "students.csv"
#define JSON_FILE   "students.json"
#define NAME_LEN    50

typedef struct Student {
    int id;
    char name[NAME_LEN];
    float grade;
    char letter;
    time_t created;
    struct Student *next;
} Student;

/* Global head + mutex */
extern Student *head;
extern pthread_mutex_t student_lock;

/* Core operations (thread-safe) */
void addStudent(const char *name, float grade);
int deleteStudent(int id);
int editStudent(int id, const char *newName, float newGrade);
Student* getStudentById(int id);
void listStudents();

/* Sorting */
void sortByName();
void sortByGrade();

/* Statistics */
float getAverageGrade();
Student* getTopStudent();
Student* getLowestStudent();

/* Persistence */
void saveToCSV();
void loadFromCSV();
void exportToJSON();

/* Utility */
char letterGrade(float g);

#endif
