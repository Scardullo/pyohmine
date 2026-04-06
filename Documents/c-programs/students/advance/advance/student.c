#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "student.h"

// global state

Student *head = NULL;

static Action undoStack[MAX_UNDO];
static Action redoStack[MAX_UNDO];
static int undoTop = 0;
static int redoTop = 0;

// internal helpers

static int getNextId(void) {
    int max = 0;
    for (Student *t = head; t; t = t->next)
        if (t->id > max) max = t->id;
    return max + 1;
}

char letterGrade(float g) {
    if (g >= 90) return 'A';
    if (g >= 80) return 'B';
    if (g >= 70) return 'C';
    if (g >= 60) return 'D';
    return 'F';
}

void logAction(const char *msg) {
    FILE *fp = fopen(HISTORY_FILE, "a");
    if (!fp) return;
    time_t now = time(NULL);
    fprintf(fp, "%s | %s", msg, ctime(&now));
    fclose(fp);
}

static void pushUndo(Student *s, int type) {
    if (undoTop == MAX_UNDO) undoTop = 0;
    undoStack[undoTop].snapshot = *s;
    undoStack[undoTop].type = type;
    undoTop++;
    redoTop = 0;
}

static Student *cloneStudent(const Student *s) {
    Student *n = malloc(sizeof(Student));
    *n = *s;
    n->next = NULL;
    return n;
}

// crud

void addStudent() {
    Student *n = malloc(sizeof(Student));
    if (!n) return;

    n->id = getNextId();
    getchar();
    printf("Name: ");
    fgets(n->name, NAME_LEN, stdin);
    n->name[strcspn(n->name, "\n")] = 0;

    printf("Grade: ");
    scanf("%f", &n->grade);

    n->letter = letterGrade(n->grade);
    n->created = time(NULL);

    n->next = head;
    head = n;

    pushUndo(n, 1);
    logAction("ADD");
    saveToCSV();
}

void displayStudents() {
    if (!head) {
        printf("No records.\n");
        return;
    }
    printf("\nID  Name                 Grade Letter\n");
    printf("------------------------------------\n");
    for (Student *t = head; t; t = t->next)
        printf("%-3d %-20s %-6.2f %c\n",
               t->id, t->name, t->grade, t->letter);
}

void searchById() {
    int id;
    printf("ID: ");
    scanf("%d", &id);
    for (Student *t = head; t; t = t->next)
        if (t->id == id) {
            printf("%d %s %.2f (%c)\n",
                   t->id, t->name, t->grade, t->letter);
            return;
        }
    printf("Not found.\n");
}

void searchByName() {
    char key[NAME_LEN];
    getchar();
    printf("Name contains: ");
    fgets(key, NAME_LEN, stdin);
    key[strcspn(key, "\n")] = 0;

    for (Student *t = head; t; t = t->next)
        if (strstr(t->name, key))
            printf("%d %s %.2f\n", t->id, t->name, t->grade);
}

void deleteStudent() {
    int id;
    printf("Delete ID: ");
    scanf("%d", &id);

    Student *t = head, *p = NULL;
    while (t && t->id != id) {
        p = t;
        t = t->next;
    }
    if (!t) {
        printf("Not found.\n");
        return;
    }

    pushUndo(t, 2);
    if (p) p->next = t->next;
    else head = t->next;

    free(t);
    logAction("DELETE");
    saveToCSV();
}

void editStudent() {
    int id;
    printf("Edit ID: ");
    scanf("%d", &id);
    getchar();

    for (Student *t = head; t; t = t->next) {
        if (t->id == id) {
            pushUndo(t, 3);

            printf("New name: ");
            fgets(t->name, NAME_LEN, stdin);
            t->name[strcspn(t->name, "\n")] = 0;

            printf("New grade: ");
            scanf("%f", &t->grade);
            t->letter = letterGrade(t->grade);

            logAction("EDIT");
            saveToCSV();
            return;
        }
    }
    printf("Not found.\n");
}

// undo / redo

void undo() {
    if (!undoTop) {
        printf("Nothing to undo.\n");
        return;
    }
    Action a = undoStack[--undoTop];
    redoStack[redoTop++] = a;

    if (a.type == 1) {
        deleteStudent();
    } else if (a.type == 2) {
        Student *n = cloneStudent(&a.snapshot);
        n->next = head;
        head = n;
    }
}

void redo() {
    if (!redoTop) {
        printf("Nothing to redo.\n");
        return;
    }
    Action a = redoStack[--redoTop];
    Student *n = cloneStudent(&a.snapshot);
    n->next = head;
    head = n;
}

// sorting

static Student *merge(Student *a, Student *b, int byGrade) {
    if (!a) return b;
    if (!b) return a;

    int cmp = byGrade
        ? (a->grade > b->grade)
        : (strcmp(a->name, b->name) < 0);

    if (cmp) {
        a->next = merge(a->next, b, byGrade);
        return a;
    }
    b->next = merge(a, b->next, byGrade);
    return b;
}

static void split(Student *src, Student **a, Student **b) {
    Student *fast = src->next, *slow = src;
    while (fast) {
        fast = fast->next;
        if (fast) {
            slow = slow->next;
            fast = fast->next;
        }
    }
    *a = src;
    *b = slow->next;
    slow->next = NULL;
}

static void mergeSort(Student **h, int byGrade) {
    if (!*h || !(*h)->next) return;
    Student *a, *b;
    split(*h, &a, &b);
    mergeSort(&a, byGrade);
    mergeSort(&b, byGrade);
    *h = merge(a, b, byGrade);
}

void sortStudentsByName() { mergeSort(&head, 0); }
void sortStudentsByGrade() { mergeSort(&head, 1); }

// statistics

float getAverageGrade() {
    float sum = 0;
    int count = 0;
    for (Student *s = head; s; s = s->next) {
        sum += s->grade;
        count++;
    }
    return count ? sum / count : 0;
}

float getMedianGrade() {
    float arr[256];
    int n = 0;
    for (Student *s = head; s; s = s->next)
        arr[n++] = s->grade;
    if (!n) return 0;

    for (int i = 0; i < n - 1; i++)
        for (int j = i + 1; j < n; j++)
            if (arr[i] > arr[j]) {
                float t = arr[i];
                arr[i] = arr[j];
                arr[j] = t;
            }

    return (n % 2)
        ? arr[n / 2]
        : (arr[n / 2 - 1] + arr[n / 2]) / 2;
}

float getStdDev() {
    float avg = getAverageGrade();
    float sum = 0;
    int count = 0;
    for (Student *s = head; s; s = s->next) {
        sum += pow(s->grade - avg, 2);
        count++;
    }
    return count ? sqrt(sum / count) : 0;
}

Student *getTopStudent() {
    if (!head) return NULL;
    Student *t = head;
    for (Student *s = head; s; s = s->next)
        if (s->grade > t->grade) t = s;
    return t;
}

Student *getLowestStudent() {
    if (!head) return NULL;
    Student *t = head;
    for (Student *s = head; s; s = s->next)
        if (s->grade < t->grade) t = s;
    return t;
}

// persistence

void saveToCSV() {
    FILE *fp = fopen(FILE_NAME, "w");
    if (!fp) return;
    fprintf(fp, "ID,Name,Grade,Letter\n");
    for (Student *s = head; s; s = s->next)
        fprintf(fp, "%d,%s,%.2f,%c\n",
                s->id, s->name, s->grade, s->letter);
    fclose(fp);
}

void loadFromCSV() {
    FILE *fp = fopen(FILE_NAME, "r");
    if (!fp) return;
    freeList();

    char line[128];
    fgets(line, sizeof line, fp);
    while (fgets(line, sizeof line, fp)) {
        Student *s = malloc(sizeof(Student));
        sscanf(line, "%d,%49[^,],%f,%c",
               &s->id, s->name, &s->grade, &s->letter);
        s->next = head;
        head = s;
    }
    fclose(fp);
}

void saveToBinary() {
    FILE *fp = fopen(BIN_FILE, "wb");
    if (!fp) return;
    for (Student *s = head; s; s = s->next)
        fwrite(s, sizeof(Student), 1, fp);
    fclose(fp);
}

void loadFromBinary() {
    FILE *fp = fopen(BIN_FILE, "rb");
    if (!fp) return;
    freeList();

    Student tmp;
    while (fread(&tmp, sizeof(Student), 1, fp)) {
        Student *s = cloneStudent(&tmp);
        s->next = head;
        head = s;
    }
    fclose(fp);
}

void exportToJSON() {
    FILE *fp = fopen(JSON_FILE, "w");
    if (!fp) return;

    fprintf(fp, "[\n");
    for (Student *s = head; s; s = s->next)
        fprintf(fp,
            "  {\"id\":%d,\"name\":\"%s\",\"grade\":%.2f}%s\n",
            s->id, s->name, s->grade,
            s->next ? "," : "");
    fprintf(fp, "]\n");
    fclose(fp);
}

void backupData() {
    saveToBinary();
    rename(BIN_FILE, BACKUP_FILE);
}

void restoreBackup() {
    rename(BACKUP_FILE, BIN_FILE);
    loadFromBinary();
}

void freeList() {
    while (head) {
        Student *t = head;
        head = head->next;
        free(t);
    }
}
