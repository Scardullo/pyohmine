#include "student.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <time.h>

// global variables
Student *head = NULL;
pthread_mutex_t student_lock = PTHREAD_MUTEX_INITIALIZER;

static Student *lastDeleted = NULL;
static AllocRecord *alloc_head = NULL;
static pthread_mutex_t alloc_lock = PTHREAD_MUTEX_INITIALIZER;

static FILE *log_fp = NULL;
typedef void (*BroadcastCallback)(const char *msg);
static BroadcastCallback broadcast_cb = NULL;

// custom memory allocator
void *student_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) return NULL;
    AllocRecord *rec = malloc(sizeof(AllocRecord));
    rec->ptr = ptr; rec->size = size;
    pthread_mutex_lock(&alloc_lock);
    rec->next = alloc_head; alloc_head = rec;
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

void print_allocations() {
    pthread_mutex_lock(&alloc_lock);
    AllocRecord *cur = alloc_head;
    printf("Active allocations:\n");
    while (cur) {
        printf("  Ptr=%p Size=%zu\n", cur->ptr, cur->size);
        cur = cur->next;
    }
    pthread_mutex_unlock(&alloc_lock);
}

void reportLeaks() {
    pthread_mutex_lock(&alloc_lock);
    if (alloc_head) {
        printf("\nMemory leaks detected:\n");
        AllocRecord *cur = alloc_head;
        while(cur){
            printf("  Leak: ptr=%p size=%zu\n", cur->ptr, cur->size);
            cur = cur->next;
        }
    } else {
        printf("\nNo memory leaks detected.\n");
    }
    pthread_mutex_unlock(&alloc_lock);
}

// logging
void logMessage(const char *fmt, ...) {
    pthread_mutex_lock(&student_lock);
    if(!log_fp) log_fp = fopen("student.log","a");
    if(!log_fp){ pthread_mutex_unlock(&student_lock); return; }
    time_t t = time(NULL);
    char ts[64]; strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",localtime(&t));
    fprintf(log_fp,"[%s] ",ts);
    va_list args; va_start(args,fmt);
    vfprintf(log_fp,fmt,args); va_end(args);
    fprintf(log_fp,"\n"); fflush(log_fp);
    pthread_mutex_unlock(&student_lock);
}

// broadcast
void registerBroadcastCallback(BroadcastCallback cb){ broadcast_cb=cb; }
static void broadcastMessage(const char *msg){ if(broadcast_cb) broadcast_cb(msg); }

// core CRUD
int addStudent(const char *name,float grade){
    Student *s = (Student*)student_malloc(sizeof(Student));
    if(!s) return 0;
    pthread_mutex_lock(&student_lock);
    int max_id = 0;
    for(Student *t=head;t;t=t->next) if(t->id>max_id) max_id=t->id;
    s->id = max_id+1;
    strncpy(s->name,name,NAME_LEN-1); s->name[NAME_LEN-1]=0;
    s->grade=grade; s->next=head; head=s;
    pthread_mutex_unlock(&student_lock);
    logMessage("Added student ID=%d Name=%s Grade=%.2f",s->id,s->name,s->grade);
    char msg[128]; snprintf(msg,sizeof(msg),"Added: %s %.2f",name,grade);
    broadcastMessage(msg);
    return 1;
}

int editStudent(int id,const char *name,float grade){
    pthread_mutex_lock(&student_lock);
    for(Student *t=head;t;t=t->next){
        if(t->id==id){
            strncpy(t->name,name,NAME_LEN-1); t->name[NAME_LEN-1]=0;
            t->grade=grade;
            pthread_mutex_unlock(&student_lock);
            logMessage("Edited student ID=%d Name=%s Grade=%.2f",id,name,grade);
            char msg[128]; snprintf(msg,sizeof(msg),"Edited ID %d: %s %.2f",id,name,grade);
            broadcastMessage(msg);
            return 1;
        }
    }
    pthread_mutex_unlock(&student_lock);
    return 0;
}

int deleteStudentWithUndo(int id){
    pthread_mutex_lock(&student_lock);
    Student *cur=head,*prev=NULL;
    while(cur){
        if(cur->id==id){
            if(prev) prev->next=cur->next; else head=cur->next;

            student_free(lastDeleted);
            lastDeleted = (Student*)student_malloc(sizeof(Student));
            *lastDeleted = *cur; lastDeleted->next=NULL;

            student_free(cur);
            pthread_mutex_unlock(&student_lock);
            logMessage("Deleted student ID=%d",id);
            char msg[128]; snprintf(msg,sizeof(msg),"Deleted ID %d",id);
            broadcastMessage(msg);
            return 1;
        }
        prev=cur; cur=cur->next;
    }
    pthread_mutex_unlock(&student_lock);
    return 0;
}

void undoLastDelete(){
    pthread_mutex_lock(&student_lock);
    if(!lastDeleted){ pthread_mutex_unlock(&student_lock); return; }
    lastDeleted->next=head; head=lastDeleted; lastDeleted=NULL;
    pthread_mutex_unlock(&student_lock);
    logMessage("Undo last delete performed");
}

// search
Student* searchById(int id){
    pthread_mutex_lock(&student_lock);
    for(Student *t=head;t;t=t->next) if(t->id==id){ pthread_mutex_unlock(&student_lock); return t; }
    pthread_mutex_unlock(&student_lock);
    return NULL;
}

// stats
Student* getTopStudent(){
    pthread_mutex_lock(&student_lock);
    if(!head){ pthread_mutex_unlock(&student_lock); return NULL; }
    Student *top=head; for(Student *t=head->next;t;t=t->next) if(t->grade>top->grade) top=t;
    pthread_mutex_unlock(&student_lock);
    return top;
}

Student* getLowestStudent(){
    pthread_mutex_lock(&student_lock);
    if(!head){ pthread_mutex_unlock(&student_lock); return NULL; }
    Student *low=head; for(Student *t=head->next;t;t=t->next) if(t->grade<low->grade) low=t;
    pthread_mutex_unlock(&student_lock);
    return low;
}

float getAverageGrade(){
    pthread_mutex_lock(&student_lock);
    if(!head){ pthread_mutex_unlock(&student_lock); return 0; }
    float total=0; int count=0;
    for(Student *t=head;t;t=t->next){ total+=t->grade; count++; }
    pthread_mutex_unlock(&student_lock);
    return count?total/count:0;
}

// display
void displayStudents(){
    pthread_mutex_lock(&student_lock);
    printf("%-5s %-20s %-6s\n","ID","Name","Grade");
    for(Student *t=head;t;t=t->next)
        printf("%-5d %-20s %-6.2f\n",t->id,t->name,t->grade);
    pthread_mutex_unlock(&student_lock);
}

// free list
void freeList(){
    pthread_mutex_lock(&student_lock);
    Student *cur=head;
    while(cur){ Student *tmp=cur; cur=cur->next; student_free(tmp); }
    head=NULL;
    pthread_mutex_unlock(&student_lock);
}

// sorting
static Student* mergeByName(Student *a, Student *b){
    if(!a) return b; if(!b) return a;
    if(strcmp(a->name,b->name)<0){ a->next=mergeByName(a->next,b); return a; }
    else { b->next=mergeByName(a,b->next); return b; }
}
static Student* mergeByGrade(Student *a, Student *b){
    if(!a) return b; if(!b) return a;
    if(a->grade>b->grade){ a->next=mergeByGrade(a->next,b); return a; }
    else { b->next=mergeByGrade(a,b->next); return b; }
}
static void frontBackSplit(Student *src, Student **f, Student **b){
    if(!src||!src->next){*f=src;*b=NULL;return;}
    Student *slow=src,*fast=src->next;
    while(fast){ fast=fast->next; if(fast){ slow=slow->next; fast=fast->next; } }
    *f=src; *b=slow->next; slow->next=NULL;
}
static void mergeSort(Student **h,int byGrade){
    if (!*h || !((*h)->next)) return;
    Student *a,*b;
    frontBackSplit(*h,&a,&b);
    mergeSort(&a,byGrade); mergeSort(&b,byGrade);
    *h=byGrade?mergeByGrade(a,b):mergeByName(a,b);
}
void sortByName(){ 
    pthread_mutex_lock(&student_lock);
    mergeSort(&head,0); 
    pthread_mutex_unlock(&student_lock); 
    logMessage("Sorted by name"); 
}

void sortByGrade(){ 
    pthread_mutex_lock(&student_lock); 
    mergeSort(&head,1); 
    pthread_mutex_unlock(&student_lock); 
    logMessage("Sorted by grade"); }

// csv storage
void saveCSV(){
    pthread_mutex_lock(&student_lock);
    FILE *fp=fopen(FILE_CSV,"w"); if(!fp){ pthread_mutex_unlock(&student_lock); return; 
    }
    fprintf(fp,"ID,Name,Grade\n");
    for(Student *t=head;t;t=t->next) fprintf(fp,"%d,%s,%.2f\n",t->id,t->name,t->grade);
    fclose(fp); pthread_mutex_unlock(&student_lock); logMessage("Saved CSV");
}
void loadCSV(){
    pthread_mutex_lock(&student_lock);
    FILE *fp=fopen(FILE_CSV,"r"); if(!fp){ pthread_mutex_unlock(&student_lock); return; 
    }
    freeList(); char line[128]; fgets(line,sizeof(line),fp);
    while(fgets(line,sizeof(line),fp)){
        Student *s=(Student*)student_malloc(sizeof(Student));
        if(sscanf(line,"%d,%49[^,],%f",&s->id,s->name,&s->grade)==3){ 
            s->next=head; head=s; 
        } else student_free(s);
    }
    fclose(fp); pthread_mutex_unlock(&student_lock); logMessage("Loaded CSV");
}

// sqlite storage
int saveSQLite(sqlite3 *db){
    if(!db) return 0;
    pthread_mutex_lock(&student_lock);
    char *err=NULL; char sql[512];
    snprintf(sql,sizeof(sql),"CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY,name TEXT,grade REAL);");
    
    if(sqlite3_exec(db,sql,0,0,&err)!=SQLITE_OK){ 
        fprintf(stderr,"%s\n",err); 
        sqlite3_free(err); 
        pthread_mutex_unlock(&student_lock); return 0; 
    }
    snprintf(sql,sizeof(sql),"DELETE FROM students;"); 
    
    if(sqlite3_exec(db,sql,0,0,&err)!=SQLITE_OK){ 
        fprintf(stderr,"%s\n",err); 
        sqlite3_free(err); 
        pthread_mutex_unlock(&student_lock); return 0; 
    }
    
    sqlite3_stmt *stmt; 
    sqlite3_prepare_v2(db,"INSERT INTO students (id,name,grade) VALUES (?,?,?);",-1,&stmt,0);
    
    for(Student *t=head;t;t=t->next){
        sqlite3_bind_int(stmt,1,t->id); sqlite3_bind_text(stmt,2,t->name,-1,SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt,3,t->grade); sqlite3_step(stmt); sqlite3_reset(stmt);
    }
    
    sqlite3_finalize(stmt); pthread_mutex_unlock(&student_lock); logMessage("Saved SQLite"); return 1;
}

int loadSQLite(sqlite3 *db){
    if(!db) return 0; pthread_mutex_lock(&student_lock); freeList();
    char *err=NULL; char sql[512];
    snprintf(sql,sizeof(sql),"CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY,name TEXT,grade REAL);");
    if(sqlite3_exec(db,sql,0,0,&err)!=SQLITE_OK){ 
        fprintf(stderr,"%s\n",err); sqlite3_free(err); 
        pthread_mutex_unlock(&student_lock); return 0; }
    sqlite3_stmt *stmt; sqlite3_prepare_v2(db,"SELECT id,name,grade FROM students;",-1,&stmt,0);
    while(sqlite3_step(stmt)==SQLITE_ROW){
        Student *s=(Student*)student_malloc(sizeof(Student));
        s->id = sqlite3_column_int(stmt,0);
        const unsigned char *name = sqlite3_column_text(stmt,1);
        strncpy(s->name,(const char*)name,NAME_LEN-1); s->name[NAME_LEN-1]=0;
        s->grade = (float)sqlite3_column_double(stmt,2);
        s->next=head; head=s;
    }
    sqlite3_finalize(stmt); pthread_mutex_unlock(&student_lock); logMessage("Loaded SQLite"); return 1;
}

// unit test
void runUnitTests(){
    printf("Running unit tests...\n");
    addStudent("Alice",90); addStudent("Bob",75); addStudent("Charlie",85);
    Student *s=searchById(1); if(s&&strcmp(s->name,"Alice")==0) printf("PASS: searchById\n");
    editStudent(1,"AliceA",95); s=searchById(1); if(s&&s->grade==95) printf("PASS: editStudent\n");
    deleteStudentWithUndo(2); s=searchById(2); if(!s) printf("PASS: deleteStudentWithUndo\n");
    undoLastDelete(); s=searchById(2); if(s) printf("PASS: undoLastDelete\n");
    printf("Avg %.2f Top %s Low %s\n",getAverageGrade(),getTopStudent()->name,getLowestStudent()->name);
    freeList(); printf("Unit tests finished.\n");
    reportLeaks();
}
