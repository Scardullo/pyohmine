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
    void *ptr = malloc(size);
    if (!ptr) return NULL;

    AllocRecord *rec = malloc(sizeof(AllocRecord));
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
    
}
