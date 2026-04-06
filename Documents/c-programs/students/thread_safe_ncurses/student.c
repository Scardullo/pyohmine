#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "student.h"

// global state 

Student *head = NULL;
pthread_mutex_t student_lock = PTHREAD_MUTEX_INITIALIZER;

// utility

char letterGrade(float g) {
    if (g >= 90) return 'A';
    if (g >= 80) return 'B';
    if (g >= 70) return 'C';
    if (g >= 60) return 'D';
    return 'F';
}

// core crud

void addStudent(const char *name, float grade) {
    Student *n = malloc(sizeof(Student));
    if (!n) return;
    n->id = 1;
    n->grade = grade;
    n->letter = letterGrade(grade);
    n->created = time(NULL);
    strncpy(n->name, name, NAME_LEN);
    n->next = NULL;

    pthread_mutex_lock(&student_lock);
    Student *t = head;
    while (t) {
        if (t->id >= n->id) n->id = t->id + 1;
        t = t->next;
    }
    n->next = head;
    head = n;
    pthread_mutex_unlock(&student_lock);
}

int deleteStudent(int id) {
    pthread_mutex_lock(&student_lock);
    Student *t = head, *prev = NULL;
    while (t && t->id != id) { prev = t; t = t->next; }
    if (!t) { pthread_mutex_unlock(&student_lock); return 0; }
    if (prev) prev->next = t->next;
    else head = t->next;
    free(t);
    pthread_mutex_unlock(&student_lock);
    return 1;
}

int editStudent(int id, const char *newName, float newGrade) {
    pthread_mutex_lock(&student_lock);
    Student *t = head;
    while (t && t->id != id) t = t->next;
    if (!t) { pthread_mutex_unlock(&student_lock); return 0; }
    strncpy(t->name, newName, NAME_LEN);
    t->grade = newGrade;
    t->letter = letterGrade(newGrade);
    pthread_mutex_unlock(&student_lock);
    return 1;
}

Student* getStudentById(int id) {
    pthread_mutex_lock(&student_lock);
    Student *t = head;
    while (t && t->id != id) t = t->next;
    pthread_mutex_unlock(&student_lock);
    return t;
}

void listStudents() {
    pthread_mutex_lock(&student_lock);
    Student *t = head;
    printf("\nID  Name                 Grade Letter\n");
    printf("------------------------------------\n");
    while (t) {
        printf("%-3d %-20s %-6.2f %c\n", t->id, t->name, t->grade, t->letter);
        t = t->next;
    }
    pthread_mutex_unlock(&student_lock);
}

// sorting

static Student* merge(Student *a, Student *b, int byGrade) {
    if (!a) return b;
    if (!b) return a;
    if ((byGrade && a->grade > b->grade) || (!byGrade && strcmp(a->name,b->name)<0)) {
        a->next = merge(a->next,b,byGrade);
        return a;
    }
    b->next = merge(a,b->next,byGrade);
    return b;
}

static void split(Student *source, Student **a, Student **b) {
    Student *fast = source->next, *slow = source;
    while (fast) { fast = fast->next; if (fast) { slow=slow->next; fast=fast->next; } }
    *a=source; *b=slow->next; slow->next=NULL;
}

static void mergeSort(Student **h, int byGrade) {
    if (!*h || !(*h)->next) return;
    Student *a,*b;
    split(*h,&a,&b);
    mergeSort(&a,byGrade);
    mergeSort(&b,byGrade);
    *h=merge(a,b,byGrade);
}

void sortByName() {
    pthread_mutex_lock(&student_lock); 
    mergeSort(&head,0); 
    pthread_mutex_unlock(&student_lock); 
}

void sortByGrade() { 
    pthread_mutex_lock(&student_lock); 
    mergeSort(&head,1); 
    pthread_mutex_unlock(&student_lock); 
}

// statistics

float getAverageGrade() {
    pthread_mutex_lock(&student_lock);
    float sum=0; int count=0;
    for (Student *t=head; t; t=t->next){ sum+=t->grade; count++; }
    pthread_mutex_unlock(&student_lock);
    return count?sum/count:0;
}

Student* getTopStudent() {
    pthread_mutex_lock(&student_lock);
    Student *top=head;
    for (Student *t=head;t;t=t->next) if(t->grade>top->grade) top=t;
    pthread_mutex_unlock(&student_lock);
    return top;
}

Student* getLowestStudent() {
    pthread_mutex_lock(&student_lock);
    Student *low=head;
    for (Student *t=head;t;t=t->next) if(t->grade<low->grade) low=t;
    pthread_mutex_unlock(&student_lock);
    return low;
}

// persistence

void saveToCSV() {
    pthread_mutex_lock(&student_lock);
    FILE *fp=fopen(FILE_NAME,"w");
    if(!fp){ pthread_mutex_unlock(&student_lock); return; }
    fprintf(fp,"ID,Name,Grade,Letter\n");
    for(Student *t=head;t;t=t->next) fprintf(fp,"%d,%s,%.2f,%c\n",t->id,t->name,t->grade,t->letter);
    fclose(fp);
    pthread_mutex_unlock(&student_lock);
}

void loadFromCSV() {
    pthread_mutex_lock(&student_lock);
    FILE *fp=fopen(FILE_NAME,"r");
    if(!fp){ pthread_mutex_unlock(&student_lock); return; }
    Student *t=head; while(t){ Student *tmp=t;t=t->next; free(tmp); } head=NULL;
    char line[128]; fgets(line,sizeof(line),fp);
    while(fgets(line,sizeof(line),fp)){
        Student *s=malloc(sizeof(Student));
        sscanf(line,"%d,%49[^,],%f,%c",&s->id,s->name,&s->grade,&s->letter);
        s->next=head; head=s;
    }
    fclose(fp);
    pthread_mutex_unlock(&student_lock);
}

void exportToJSON() {
    pthread_mutex_lock(&student_lock);
    FILE *fp=fopen(JSON_FILE,"w");
    if(!fp){ pthread_mutex_unlock(&student_lock); return; }
    fprintf(fp,"[\n");
    Student *t=head;
    while(t){
        fprintf(fp,"  {\"id\":%d,\"name\":\"%s\",\"grade\":%.2f,\"letter\":\"%c\"}%s\n",
                t->id,t->name,t->grade,t->letter,t->next ? "," : "");
        t=t->next;
    }
    fprintf(fp,"]\n");
    fclose(fp);
    pthread_mutex_unlock(&student_lock);
}
