#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "student.h"

Student *head = NULL;

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

// ========== ADD STUDENT ==========
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

    newStudent->next = head;
    head = newStudent;

    printf("Student added successfully (ID: %d)\n", newStudent->id);
    saveToCSV();
}

// ========== VIEW ==========
void viewStudents() {
    if (!head) {
        printf("No student records found.\n");
        return;
    }

    printf("\n%-5s %-20s %-6s\n", "ID", "Name", "Grade");
    Student *temp = head;
    while (temp) {
        printf("%-5d %-20s %-6.2f\n", temp->id, temp->name, temp->grade);
        temp = temp->next;
    }
}

// ========== SEARCH BY ID ==========
void searchById() {
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

// ========== SEARCH BY NAME ==========
void searchByName() {
    getchar();
    char keyword[50];
    printf("Enter name keyword: ");
    fgets(keyword, sizeof(keyword), stdin);
    keyword[strcspn(keyword, "\n")] = '\0';

    int found = 0;
    Student *temp = head;
    while (temp) {
        if (strstr(temp->name, keyword)) {
            printf("%d | %s | %.2f\n", temp->id, temp->name, temp->grade);
            found = 1;
        }
        temp = temp->next;
    }

    if (!found)
        printf("No student names matched '%s'\n", keyword);
}

// ========== DELETE ==========
void deleteStudent() {
    int id;
    printf("Enter ID to delete: ");
    scanf("%d", &id);

    Student *temp = head, *prev = NULL;
    while (temp && temp->id != id) {
        prev = temp;
        temp = temp->next;
    }

    if (!temp) {
        printf("ID not found.\n");
        return;
    }

    if (prev)
        prev->next = temp->next;
    else
        head = temp->next;

    free(temp);
    printf("Student deleted successfully.\n");
    saveToCSV();
}

// ========== EDIT ==========
void editStudent() {
    int id;
    printf("Enter ID to edit: ");
    scanf("%d", &id);
    getchar();

    Student *temp = head;
    while (temp && temp->id != id)
        temp = temp->next;

    if (!temp) {
        printf("Student not found.\n");
        return;
    }

    printf("Editing %s (%.2f)\n", temp->name, temp->grade);

    char choice;
    printf("Change name? (y/n): ");
    scanf(" %c", &choice);
    getchar();
    if (choice == 'y' || choice == 'Y') {
        printf("Enter new name: ");
        fgets(temp->name, sizeof(temp->name), stdin);
        temp->name[strcspn(temp->name, "\n")] = '\0';
    }

    printf("Change grade? (y/n): ");
    scanf(" %c", &choice);
    if (choice == 'y' || choice == 'Y') {
        printf("Enter new grade: ");
        scanf("%f", &temp->grade);
    }

    printf("Student updated!\n");
    saveToCSV();
}

// ========== CSV SAVE / LOAD ==========
void saveToCSV() {
    FILE *fp = fopen(FILE_NAME, "w");
    if (!fp) {
        printf("Error saving file.\n");
        return;
    }

    fprintf(fp, "ID,Name,Grade\n");
    Student *temp = head;
    while (temp) {
        fprintf(fp, "%d,%s,%.2f\n", temp->id, temp->name, temp->grade);
        temp = temp->next;
    }

    fclose(fp);
}

void loadFromCSV() {
    FILE *fp = fopen(FILE_NAME, "r");
    if (!fp) return;

    char line[128];
    fgets(line, sizeof(line), fp); // Skip header

    while (fgets(line, sizeof(line), fp)) {
        Student *newNode = (Student *)malloc(sizeof(Student));
        if (sscanf(line, "%d,%49[^,],%f", &newNode->id, newNode->name, &newNode->grade) == 3) {
            newNode->next = head;
            head = newNode;
        } else {
            free(newNode);
        }
    }

    fclose(fp);
}

// ========== MERGE SORT HELPERS ==========
Student *mergeByName(Student *a, Student *b) {
    if (!a) return b;
    if (!b) return a;
    Student *result;
    if (strcmp(a->name, b->name) < 0) {
        result = a;
        result->next = mergeByName(a->next, b);
    } else {
        result = b;
        result->next = mergeByName(a, b->next);
    }
    return result;
}

Student *mergeByGrade(Student *a, Student *b) {
    if (!a) return b;
    if (!b) return a;
    Student *result;
    if (a->grade > b->grade) {
        result = a;
        result->next = mergeByGrade(a->next, b);
    } else {
        result = b;
        result->next = mergeByGrade(a, b->next);
    }
    return result;
}

void frontBackSplit(Student *source, Student **frontRef, Student **backRef) {
    Student *fast, *slow;
    if (!source || !source->next) {
        *frontRef = source;
        *backRef = NULL;
        return;
    }
    slow = source;
    fast = source->next;
    while (fast) {
        fast = fast->next;
        if (fast) {
            slow = slow->next;
            fast = fast->next;
        }
    }
    *frontRef = source;
    *backRef = slow->next;
    slow->next = NULL;
}

void mergeSort(Student **headRef, int byGrade) {
    Student *headNode = *headRef;
    if (!headNode || !headNode->next) return;

    Student *a, *b;
    frontBackSplit(headNode, &a, &b);

    mergeSort(&a, byGrade);
    mergeSort(&b, byGrade);

    *headRef = byGrade ? mergeByGrade(a, b) : mergeByName(a, b);
}

void sortStudentsByName() {
    mergeSort(&head, 0);
    printf("Students sorted by name.\n");
    saveToCSV();
}

void sortStudentsByGrade() {
    mergeSort(&head, 1);
    printf("Students sorted by grade.\n");
    saveToCSV();
}

// ========== STATISTICS ==========
float getAverageGrade() {
    if (!head) return 0.0;
    int count = 0;
    float total = 0.0;
    Student *temp = head;
    while (temp) {
        total += temp->grade;
        count++;
        temp = temp->next;
    }
    return total / count;
}

Student *getTopStudent() {
    if (!head) return NULL;
    Student *top = head, *temp = head->next;
    while (temp) {
        if (temp->grade > top->grade)
            top = temp;
        temp = temp->next;
    }
    return top;
}

Student *getLowestStudent() {
    if (!head) return NULL;
    Student *low = head, *temp = head->next;
    while (temp) {
        if (temp->grade < low->grade)
            low = temp;
        temp = temp->next;
    }
    return low;
}

// ========== CLEANUP ==========
void freeList() {
    Student *temp;
    while (head) {
        temp = head;
        head = head->next;
        free(temp);
    }
}
