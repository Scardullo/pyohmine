#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILE_NAME "students.txt"

typedef struct {
    int id;
    char name[50];
    float grade;
} Student;

void addStudent();
void viewStudents();
void searchStudent();
void deleteStudent();
int getNextId();

int main() {
    int choice;

    do {
        printf("\n=== Student Management System ===\n");
        printf("1. Add Student\n");
        printf("2. View Students\n");
        printf("3. Search Student by ID\n");
        printf("4. Delete Student by ID\n");
        printf("0. Exit\n");
        printf("Enter choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1: addStudent(); break;
            case 2: viewStudents(); break;
            case 3: searchStudent(); break;
            case 4: deleteStudent(); break;
            case 0: printf("Exiting...\n"); break;
            default: printf("Invalid choice!\n");
        }
    } while (choice != 0);

    return 0;
}

void addStudent() {
    FILE *fp = fopen(FILE_NAME, "a");
    if (!fp) {
        printf("Error opening file!\n");
        return;
    }

    Student s;
    s.id = getNextId();

    printf("Enter student name: ");
    getchar(); // clear newline from previous input
    fgets(s.name, sizeof(s.name), stdin);
    s.name[strcspn(s.name, "\n")] = '\0'; // remove newline

    printf("Enter grade: ");
    scanf("%f", &s.grade);

    fprintf(fp, "%d,%s,%.2f\n", s.id, s.name, s.grade);
    fclose(fp);

    printf("Student added successfully with ID: %d\n", s.id);
}

void viewStudents() {
    FILE *fp = fopen(FILE_NAME, "r");
    if (!fp) {
        printf("No records found.\n");
        return;
    }

    Student s;
    printf("\n%-5s %-20s %-5s\n", "ID", "Name", "Grade");
    printf("------------------------------------\n");

    while (fscanf(fp, "%d,%49[^,],%f\n", &s.id, s.name, &s.grade) == 3) {
        printf("%-5d %-20s %-5.2f\n", s.id, s.name, s.grade);
    }

    fclose(fp);
}

void searchStudent() {
    FILE *fp = fopen(FILE_NAME, "r");
    if (!fp) {
        printf("File not found.\n");
        return;
    }

    int id;
    printf("Enter student ID: ");
    scanf("%d", &id);

    Student s;
    int found = 0;

    while (fscanf(fp, "%d,%49[^,],%f\n", &s.id, s.name, &s.grade) == 3) {
        if (s.id == id) {
            printf("Found: %d | %s | %.2f\n", s.id, s.name, s.grade);
            found = 1;
            break;
        }
    }

    if (!found) printf("Student not found.\n");
    fclose(fp);
}

void deleteStudent() {
    FILE *fp = fopen(FILE_NAME, "r");
    if (!fp) {
        printf("File not found.\n");
        return;
    }

    FILE *temp = fopen("temp.txt", "w");
    if (!temp) {
        printf("Error creating temp file.\n");
        fclose(fp);
        return;
    }

    int id;
    printf("Enter student ID to delete: ");
    scanf("%d", &id);

    Student s;
    int deleted = 0;

    while (fscanf(fp, "%d,%49[^,],%f\n", &s.id, s.name, &s.grade) == 3) {
        if (s.id != id)
            fprintf(temp, "%d,%s,%.2f\n", s.id, s.name, s.grade);
        else
            deleted = 1;
    }

    fclose(fp);
    fclose(temp);

    remove(FILE_NAME);
    rename("temp.txt", FILE_NAME);

    if (deleted)
        printf("Student deleted successfully.\n");
    else
        printf("Student ID not found.\n");
}

int getNextId() {
    FILE *fp = fopen(FILE_NAME, "r");
    if (!fp) return 1;

    int id = 0;
    Student s;
    while (fscanf(fp, "%d,%49[^,],%f\n", &s.id, s.name, &s.grade) == 3)
        id = s.id;

    fclose(fp);
    return id + 1;
}
