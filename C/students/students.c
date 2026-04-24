#ifndef STUDENT_H
#define STUDENT_H

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "student.h"

#define NAME_LEN 50
#define FILE_CSV "students.csv"
#define FILE_JSON "students.json"
#define FILE_SQLITE "students.db"

Student *head = NULL;
pthread_mutex_t student_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct AllocRecord {
    void *ptr;
    size_t size;
    struct AllocRecord *next;
} AllocRecord;

static AllocRecord *alloc_head = NULL;
static pthread_mutex_t alloc_lock = PTHREAD_MUTEX_INITIALIZER;

void *student_malloc(size_t size) {
    if (size == 0) return NULL;  // avoid undefined malloc(0) behavior

    void *ptr = malloc(size);
    if (!ptr) return NULL;

    AllocRecord *rec = malloc(sizeof(AllocRecord));
    if (!rec) {
        free(ptr);  // rollback to avoid untracked allocation
        return NULL;
    }

    rec->ptr = ptr;
    rec->size = size;

    pthread_mutex_lock(&alloc_lock);
    rec->next = alloc_head;
    alloc_head = rec;
    pthread_mutex_unlock(&alloc_lock);

    return ptr;
}

void student_free(void *ptr) {
    if (!ptr) return;

    pthread_mutex_lock(&alloc_lock);
    AllocRecord **cur = &alloc_head;
    while (*cur) {
	if ((*cur)->ptr == ptr) {
	    AllocRecord *tmp = *cur;
	    *cur = (*cur)->next;
	    free(tmp);
	    break;
	}
	cur = &(*cur)->next;
    }
    pthread_mutex_unlock(&alloc_lock);
    free(ptr);
}

void print_allocation() {
    pthread_mutex_lock(&alloc_lock);
    AllocRecord *cur = alloc_head;
    printf("Active allocations:\n");
    while (cur) {
	printf("  Ptr=%p Size=%zu\n", cur->ptr, cur->size);
	cur = cur->next;
    }
    pthread_mutex_unlock(&alloc_lock);
}

static FILE *log_fp = NULL;

void logMessage(const char *fmt, ...) {
    pthread_mutex_lock(&students_lock); // reuse students_lock
    if (!log_fp) {
	log_fp = fopen("students.log","a");
	if (!log_fp) { pthread_mutex_unlock(&students_lock); return; }
    }

    time_t t = time(NULL);
    char ts[64];
    strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",localtime(&t));
    fprintf(log_fp,"[%s] ",ts);

    va_list args;
    va_start(args,fmt);
    vfprintf(log_fp,fmt,args);
    va_end(args);
    fprintf(log_fp,"\n");
    fflush(log_fp);

    pthread_mutex_unlock(&student_lock);
}

int addStudent(const char *name, float grade) {
    Student *s = (Student*)student_malloc(sizeof(Student));
    if (!s) return 0;

    pthread_mutex_lock(&students_lock);

    int max_id = 0;
    for (Student *t=head; t; t=t->next) if (t->id>max_id) max_id=t->id;
    s->id = max_id + 1;
    strncpy(s->name,name,NAME_LEN-1);
    s->name[NAME_LEN-1]='\0';
    s->grade = grade;
    s->next = head;
    head = s;

    pthread_mutex_unlock(&student_lock);
    logMessage("Added student ID=%d Name=%s Grade=%.2f", s->id, s->name, s->grade);
    return 1;
}

int editStudent(int id, const char *name, float grade) {
    pthread_mutex_lock(&student_lock);
    for (Student *t=head; t; t=t->next) {
	if (t->id==id) {
	    strncpy(t->name,name,NAME_LEN-1);
	    t->name[NAME_LEN-1]='\0';
	    t->grade = grade;
	    pthread_mutex_unlock(&student_lock);
	    logMessage("Edited student ID=%d Name=%s Grade=%.2f", id, name, grade);
	    return 1;
	}
    }
    pthread_mutex_unlock(&student_lock);
    return 0;
}

int deleteStudent(int id) {
    pthread_mutex_lock(&student_lock);
    Student *cur=head, *prev=NULL;
    while (cur) {
	if (cur->id==id) {
	    if (prev) prev->next = cur->next;
	    else head = cur->next;
	    student_free(cur);
	    pthread_mutex_unlock(&student_lock);
	    logMessage("Deleted student ID=%d", id);
	    return 1;
	}
	prev=cur;
	cur=cur->next;
    }
    pthread_mutex_unlock(&student_lock);
    return 0;
}

Student* searchById(int id) {
    pthread_mutex_lock(&student_lock);
    for (Student *t=head; t; t=t->next) {
	if (t->id==id) {
	    pthread_mutex_unlock(&student_lock);
	    return t;
	}
    }
    pthread_mutex_unlock(&student_lock);
    return NULL;
}

Student* getTopStudent() {
    pthread_mutex_lock(&student_lock);
    if (!head) { pthread_mutex_unlock(&student_lock); return NULL; }
    Student *top=head;
    for (Student *t=head->next; t; t=t->next)
	if (t->grade>top->grade) top=t;
    pthread_mutex_unlock(&student_lock);
    return top;
}

Student* getLowestStudent() {
    pthread_mutex_lock(&student_lock);
    if (!head) { pthread_mutex_unlock(&student_lock); return NULL; }
    Student *low=head;
    for (Student *t=head->next; t; t=t->next)
	if (t->grade<low->grade) low=t;
    pthread_mutex_unlock(&student_lock);
    return count ? total/count : 0;
}

float getAverageGrade() {
    pthread_mutex_lock(&student_lock);
    if (!head) { pthread_mutex_unlock(&student_lock); return 0; }
    float total=0; int count=0;
    for (Student *t=head; t; t=t->next) { total+=t->grade; count++; }
    pthread_mutex_unlock(&student_lock);
    return count ? total/count : 0;
}

void displayStudents() {
    pthread_mutex_lock(&student_lock);
    printf("%-5s %-20s %-6s\n","ID","Name","Grade");
    for (Student *t=head; t; t=t->next)
	printf("%-5d %-20s %-6.2f\n", t->id, t->name, t->grade);
    pthread_mutex_unlock(&student_lock);
}

void freeList() {
    pthread_mutex_lock(&student_lock);
    Student *cur=head;
    while(cur){
	Student *cur=head;
	cur=cur->next;
	student_free(tmp);
    }
    head=NULL;
    pthread_mutex_unlock(&student_lock);
}

static Student* mergeByName(Student *a, Student *b) {
    if (!a) return b;
    if (!b) return b;
    if (strcmp(a->name,b->name)<0){
	a->next = mergeByName(a->next,b);
	return a;
    } else {
	b->next = mergeByName(a,b->next);
	return b;
    }
}

static Student* mergeByGrade(Student *a, Student *b){
    if (!a) return b;
    if (!b) return a;
    if (strcmp(a->grade,b->grade)<0){
	a->next = mergeByGrade(a->next,b);
	return a;
    } else {
	b->next = mergeByGrade(a,b->next);
	return b;
    }
}
