#ifndef STUDENT_H
#define STUDENT_H

#include <time.h>

#define FILE_NAME   "students.csv"
#define JSON_FILE   "students.json"
#define BIN_FILE    "students.bin"
#define BACKUP_FILE "students.bak"
#define HISTORY_FILE "history.log"

#define NAME_LEN 50
#define MAX_UNDO 32

typedef struct Student {
    int id;
    char name[NAME_LEN];
    float grade;
    char letter;
    time_t created;
    struct Student *next;
} Student;

typedef struct Action {
    Student snapshot;
    int type; /* 1 = add, 2 = delete, 3 = edit */
} Action;

extern Student *head;

/* Core */
void addStudent();
void deleteStudent();
void editStudent();
void displayStudents();
void searchById();
void searchByName();
void freeList();

/* Sorting */
void sortStudentsByName();
void sortStudentsByGrade();

/* Statistics */
float getAverageGrade();
float getMedianGrade();
float getStdDev();
Student *getTopStudent();
Student *getLowestStudent();

/* Persistence */
void saveToCSV();
void loadFromCSV();
void saveToBinary();
void loadFromBinary();
void exportToJSON();
void backupData();
void restoreBackup();

/* Undo / Redo */
void undo();
void redo();

/* Utilities */
char letterGrade(float g);
void logAction(const char *msg);

#endif
