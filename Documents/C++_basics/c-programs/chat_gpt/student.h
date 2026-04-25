#ifndef STUDENT_H
#define STUDENT_H

#define FILE_NAME "students.csv"

typedef struct Student {
    int id;
    char name[50];
    float grade;
    struct Student *next;
} Student;

extern Student *head;

// Function declarations
void loadFromCSV();
void saveToCSV();
void addStudent();
void viewStudents();
void searchById();
void searchByName();
void deleteStudent();
void editStudent();
void sortStudentsByName();
void sortStudentsByGrade();
float getAverageGrade();
Student *getTopStudent();
Student *getLowestStudent();
void freeList();

#endif
