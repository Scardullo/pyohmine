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
#define FILE_SQLITE "students.h"

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

