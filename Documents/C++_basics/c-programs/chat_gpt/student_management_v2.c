#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILE_NAME "students.dat"

// Define student structure
typedef struct Student {
    int id;
    char name[50];
    float grade;
    struct Student *next;
} Student;

// Global head pointer for linked list
Student *head = NULL;

// Function prototypes
void loadFromFile();
void saveToFile();
void addStudent();
void viewStudents();
void searchStudent();
void deleteStudent();
int getNextId();
void freeList();

int main() {
    int choice;

    loadFromFile(); // Load existing data at startup

    do {
        printf("\n=== Student Management System v2 ===\n");
        printf("1. Add Student\n");
        printf("2. View Students\n");
        printf("3. Search Student by ID\n");
        printf("4. Delete Student by ID\n");
        printf("0. Exit and Save\n");
        printf("Enter choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1: addStudent(); break;
            case 2: viewStudents(); break;
            case 3: searchStudent(); break;
            case 4: deleteStudent(); break;
            case 0:
                saveToFile();
                printf("Data saved. Exiting...\n");
                break;
            default: printf("Invalid choice!\n");
        }
    } while (choice != 0);

    freeList();
    return 0;
}

void addStudent() {
    Student *newStudent = (Student *)malloc(sizeof(Student));
    if (!newStudent) {
        printf("Memory allocation failed!\n");
        return;
    }

    newStudent->id = getNextId();
    getchar(); // clear newline
    printf("Enter name: ");
    fgets(newStudent->name, sizeof(newStudent->name), stdin);
    newStudent->name[strcspn(newStudent->name, "\n")] = '\0';

    printf("Enter grade: ");
    scanf("%f", &newStudent->grade);

    newStudent->next = NULL;

    // Append to linked list
    if (head == NULL)
        head = newStudent;
    else {
        Student *temp = head;
        while (temp->next != NULL)
            temp = temp->next;
        temp->next = newStudent;
    }

    printf("Student added (ID: %d)\n", newStudent->id);
}

void viewStudents() {
    if (!head) {
        printf("No records to display.\n");
        return;
    }

    printf("\n%-5s %-20s %-6s\n", "ID", "Name", "Grade");
    printf("-----------------------------------\n");
    Student *temp = head;
    while (temp) {
        printf("%-5d %-20s %-6.2f\n", temp->id, temp->name, temp->grade);
        temp = temp->next;
    }
}

void searchStudent() {
    if (!head) {
        printf("No records found.\n");
        return;
    }

    int id;
    printf("Enter student ID: ");
    scanf("%d", &id);

    Student *temp = head;
    while (temp) {
        if (temp->id == id) {
            printf("Found: %d | %s | %.2f\n", temp->id, temp->name, temp->grade);
            return;
        }
        temp = temp->next;
    }

    printf("Student not found.\n");
}

void deleteStudent() {
    if (!head) {
        printf("No records found.\n");
        return;
    }

    int id;
    printf("Enter ID to delete: ");
    scanf("%d", &id);

    Student *temp = head;
    Student *prev = NULL;

    while (temp && temp->id != id) {
        prev = temp;
        temp = temp->next;
    }

    if (!temp) {
        printf("Student ID not found.\n");
        return;
    }

    if (prev == NULL)
        head = temp->next;
    else
        prev->next = temp->next;

    free(temp);
    printf("Student deleted successfully.\n");
}

int getNextId() {
    int maxId = 0;
    Student *temp = head;
    while (temp) {
        if (temp->id > maxId)
            maxId = temp->id;
        temp = temp->next;
    }
    return maxId + 1;
}

// Save linked list to binary file
void saveToFile() {
    FILE *fp = fopen(FILE_NAME, "wb");
    if (!fp) {
        printf("Error opening file for writing.\n");
        return;
    }

    Student *temp = head;
    while (temp) {
        fwrite(temp, sizeof(Student) - sizeof(Student *), 1, fp);
        temp = temp->next;
    }

    fclose(fp);
}

// Load data from binary file into linked list
void loadFromFile() {
    FILE *fp = fopen(FILE_NAME, "rb");
    if (!fp) return;

    Student buffer;
    while (fread(&buffer, sizeof(Student) - sizeof(Student *), 1, fp) == 1) {
        Student *newNode = (Student *)malloc(sizeof(Student));
        if (!newNode) break;
        *newNode = buffer;
        newNode->next = NULL;

        if (head == NULL)
            head = newNode;
        else {
            Student *temp = head;
            while (temp->next)
                temp = temp->next;
            temp->next = newNode;
        }
    }

    fclose(fp);
}

void freeList() {
    Student *temp;
    while (head) {
        temp = head;
        head = head->next;
        free(temp);
    }
}
