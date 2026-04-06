#ifndef STUDENT_H
#define STUDENT_H

#define FILE_NAME "students.csv"
#define BACKUP_FILE "students_backup.csv"
#define JSON_FILE "students.json"

typedef struct Student {
    int id;
    char name[50];
    float grade;
    struct Student *next;
} Student;

extern Student *head;

// Core functions
void loadFromCSV();
void saveToCSV();
void addStudent();
void displayStudents();
void searchById();
void searchByName();
void deleteStudent();
void editStudent();
void freeList();

// Sorting
void sortStudentsByName();
void sortStudentsByGrade();

// Statistics
float getAverageGrade();
Student *getTopStudent();
Student *getLowestStudent();

// New features
void backupData();    // ?? not found
void restoreBackup(); // ?? not found
void exportToJSON();
void undoLastDelete();

#endif
