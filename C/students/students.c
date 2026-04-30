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
    pthread_mutex_lock(&student_lock); // reuse student_lock
    if (!log_fp) {
	log_fp = fopen("students.log","a");
	if (!log_fp) { pthread_mutex_unlock(&student_lock); return; }
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

    pthread_mutex_lock(&student_lock);

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
	Student *tmp=cur;
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

static void frontBackSplit(Student *source, Student **front, Student **back){
    if(!source || !source->next){ *front=source; *back=NULL; return; }
    Student *slow=source,*fast=source->next;
    while(fast){
	fast=fast->next;
	if(fast){ slow=slow->next; fast=fast->next; }
    }
    *front=source;
    *back=slow->next;
    slow->next=NULL;
}

static void mergeSort(Student **headRef,int byGrade){
    Student *h = *headRef;
    if(!h || !h->next) return;
    Student *a,*b;
    frontBackSplit(h,&a,&b);
    mergeSort(&a,byGrade);
    mergeSort(&b,byGrade);
    *headRef = byGrade ? mergeByGrade(a,b) : mergeByName(a,b);
}

void sortByName(){
    pthread_mutex_lock(&student_lock);
    mergeSort(&head,0);
    pthread_mutex_unlock(&student_lock);
    logMessage("Sorted students by name");
}

void sortByGrade(){
    pthread_mutex_lock(&student_lock);
    mergeSort(&head,1);
    pthread_mutex_unlock(&student_lock);
    logMessage("Sorted students by grade");
}

void saveCSV(){
    pthread_mutex_lock(&student_lock);
    FILE *fp = fopen(FILE_CSV,"w");
    if(!fp){ pthread_mutex_unlock(&student_lock); return; }
    fprintf(fp,"ID,Name,Grade\n");
    for(Student *t=head; t; t=t->next)
	fprintf(fp,"%d,%s,%.2f\n",t->id,t->name,t->grade);
    fclose(fp);
    pthread_mutex_unlock(&student_lock);
    logMessage("Saved students to CSV");
}

void loadCSV(){
    pthread_mutex_lock(&student_lock);
    FILE *fp=fopen(FILE_CSV,"r");
    if(!fp){ pthread_mutex_unlock(&student_lock); return; }
    freeList();
    char line[128];
    fgets(line,sizeof(line),fp); // skip header
    while(fgets(line,sizeof(line),fp)){
	Student *s=(Student*)student_malloc(sizeof(Student));
	if(sscanf(line,"%d,%49[^,],%f",&s->id,s->name,&s->grade)==3){
	    s->next=head; head=s;
	} else student_free(s);
    }
    fclose(fp);
    pthread_mutex_unlock(&student_lock);
    logMessage("Loaded students from CSV");
}

void saveJSON(){
    pthread_mutex_lock(&student_lock);
    FILE *fp=fopen(FILE_JSON,"w");
    if(!fp){ pthread_mutex_unlock(&student_lock); return; }
    fprintf(fp,"[\n");
    Student *t=head;
    while(t){
	fprintf(fp," {\"id\": %d, \"name\": \"%s\", \"grade\": %.2f}%s\n",
		t->id,t->name,t->grade,t->next ? "," : "");
	t=t->next;
    }
    fprintf(fp,"]\n");
    fclose(fp);
    pthread_mutex_unlock(&student_lock);
    logMessage("Saved students to JSON");
}


void loadJSON(){
    // Simple JSON loader placeholder
    // Full JSON parsing can be added with cJSON or manual parsing
    logMessage("JSON load not implemented, use CSV or SQLite");
}

int saveSQLite(sqlite3 *db){
    if(!db) return 0;
    pthread_mutex_lock(&student_lock);

    char *err=NULL;
    char sql[512];
    snprintf(sql,sizeof(sql),
	     "CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY, name TEXT, grade REAL);");
    if(sqlite3_exec(db,sql,0,0,&err)!=SQLITE_OK){
	fprintf(stderr,"SQLite error: %s\n",err);
	sqlite3_free(err);
	pthread_mutex_unlock(&student_lock);
	return 0;
    }

    snprintf(sql,sizeof(sql),"DELETE FROM students;");
    if(sqlite3_exec(db,sql,0,0,&err)!=SQLITE_OK){
	fprintf(stderr, "SQLite error: %s\n",err);
	sqlite3_free(err);
	pthread_mutex_unlock(&student_lock);
	return 0;
    }

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db,"INSERT INTO students (id,name,grade) VALUES (?,?,?);",-1,&stmt,0);
    for(Student *t=head;t;t=t->next){
	sqlite3_bind_int(stmt,1,t->id);
	sqlite3_bind_text(stmt,2,t->name,-1,SQLITE_TRANSIENT);
	sqlite3_bind_double(stmt,3,t->grade);
	sqlite3_step(stmt);
	sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&student_lock);
    logMessage("Saved students to SQLite");
    return 1;
}

int loadSQLite(sqlite *db){
    if(!db) return 0;
    pthread_mutex_lock(&student_lock);
    freeList();

    char *err=NULL;
    char sql[512];
    snprintf(sql,sizeof(sql),"CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY, name TEXT, grade REAL);");
    if(sqlite3_exec(db,sql,0,0,&err)!=SQLITE_OK){
	fprintf(stderr,"SQLite error: %s\n",err);
	sqlite3_free(err);
	pthread_mutex_unlock(&student_lock);
	return 0;
    }

    sqlite3_stmt *stmt;
    if(sqlite3_prepare_v2(db,"SELECT id,name,grade FROM students;",-1,&stmt,0)!=SQLITE_OK){
	pthread_mutex_unlock(&student_lock);
	return 0;
    }

    while(sqlite3_step(stmt)==SQLITE_ROW){
	Student *s=(Student*)student_malloc(sizeof(Student));
	s->id = sqlite3_column_int(stmt,0);
	const unsigned char *name = sqlite3_column_text(stmt,1);
	strncpy(s->name,(const char *)name,NAME_LEN-1);
	s->name[NAME_LEN-1]='\0';
	s->grade = (float)sqlite3_column_double(stmt,2);
	s->next = head; head=s;
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&student_lock);
    logMessage("Loaded students from SQLite");
    return 1;
}

static Student *lastDeleted = NULL;

void undoLastDelete() {
    pthread_mutex_lock(&student_lock);
    if (!lastDeleted) { pthread_mutex_unlock(&student_lock); return; }

    lastDeleted->next = head;
    head = lastDeleted;
    lastDeleted = NULL;
    pthread_mutex_unlock(&student_lock);
    logMessage("Undo last delete performed");
}

int deleteStudentWithUndo(int id) {
    pthread_mutex_lock(&student_lock);
    Student *cur=head,*prev=NULL;
    while(cur){
	if(cur->id==id){
	    if(prev) prev->next=cur->next; else head=cur->next;

	    student_free(lastDeleted);
	    lastDeleted = (Student*)student_malloc(sizeof(Student));
	    *lastDeleted = *cur;
	    lastDeleted->next = NULL;

	    student_free(cur);
	    pthread_mutex_unlock(&student_lock);
	    logMessage("Deleted student ID=%d (with undo)",id);
	    return 1;
	}
	prev=cur;
	cur=cur->next;
    }
    pthread_mutex_unlock(&student_lock);
    return 0;
}

typedef void (*BroadcastCallback)(const char *msg);
static BroadcastCallback broadcast_cb = NULL;

void registerBroadcastCallback(BroadcastCallback cb){
    broadcast_cb = cb;
}

static void broadcastMessage(const char *msg){
    if(broadcast_cb) broadcast_cb(msg);
}

int addStudentBroadcast(const char *name,float grade){
    int res = addStudent(name,grade);
    if(res){
	char msg[128];
	snprintf(msg,sizeof(msg),"Added: %s %.2f",name,grade);
	broadcastMessage(msg);
    }
    return res;
}

int editStudentBroadcast(int id,const char *name,float grade){
    int res = editStudent(id,name,grade);
    if(res){
	char msg[128];
	snprintf(msg,sizeof(msg),"Edited ID %d: %s %.2f",id,name,grade);
	broadcastMessage(msg);
    }
    return res;
}

int deleteStudentBroadcast(int id){
    int res = deleteStudentWithUndo(id);
    if(res){
	char msg[128];
	snprintf(msg,sizeof(msg),"Deleted ID %d",id);
	broadcastMessage(msg);
    }
    return res;
}

void runUnitTests(){
    printf("Running unit tests...\n");

    addStudent("Alice",90);
    addStudent("Bob",75);
    addStudent("Charlie",85);

    Student *s = searchById(1);
    if(s && strcmp(s->name,"Alice")==0) printf("PASS: searchById\n");

    editStudent(1,"AliceA",95);
    s = searchById(1);
    if(s && s->grade==95) printf("PASS: editStudent\n");

    deleteStudentWithUndo(2);
    s = searchById(2);
    if(!s) printf("PASS: deleteStudentWithUndo\n");
    undoLastDelete();
    s = searchById(2);
    if(s) printf("PASS: undoLastDelete\n");

    float avg = getAverageGrade();
    Student *top = getTopStudent();
    Student *low = getLowestStudent();
    printf("Avg: %.2f, Top: %s, Low: %s\n",avg,top?top->name:"N/A",low?low->name:"N/A");

    freeList();
    printf("Unit tests finished.\n");
}

void printMemoryStats(){
    pthread_mutex_lock(&alloc_lock);
    AllocRecord *cur = alloc_head;
    int count = 0;
    size_t total = 0;
    while(cur){
	count++;
	total += cur->size;
	cur = cur->next;
    }
    pthread_mutex_unlock(&alloc_lock);

    printf("\n=== Memory Stats ===\n");
    printf("Active allocations: %d\n", count);
    printf("Total bytes allocated: %zu\n", total);
}

void reportLeaks(){
    pthread_mutex_lock(&alloc_lock);
    if(alloc_head){
	printf("\nMemory leaks detected:\n");
	AllocRecord *cur=alloc_head;
	while(cur){
	    printf("  Leak: ptr=%p size=%zu\n",cur->ptr,cur->size);
	    cur=cur->next;
	}
    } else {
	printf("\nNo memory leaks detected.\n");
    }
    pthread_mutex_unlock(&alloc_lock);
}

void runUnitTestWithAllocator(){
    printf("Running unit tests with memory tracking...\n");

    addStudent("Alice",90);
    addStuent("Bob",80);
    addStudent("Charlie",85);

    printMemoryStats();

    deleteStudentWithUndo(2);
    undoLastDelete();

    printMemoryStats();

    freeList()
    reportLeaks();
}



