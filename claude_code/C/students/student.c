#include "student.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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

// broadcast
void registerBroadcastCallback(BroadcastCallback cb){ broadcast_cb=cb; }
static void broadcastMessage(const char *msg){ if(broadcast_cb) broadcast_cb(msg); }

// validation
int isValidGrade(float grade){
    return grade >= 0.0f && grade <= 100.0f;
}

int isValidName(const char *name){
    // reject empty names and commas, since commas would corrupt the CSV format
    return name && name[0] != '\0' && !strchr(name, ',');
}

// core CRUD
int addStudent(const char *name,float grade){
    if(!isValidName(name) || !isValidGrade(grade)) return 0;
    Student *s = (Student*)student_malloc(sizeof(Student));
    if(!s) return 0;
    pthread_mutex_lock(&student_lock);
    int max_id = 0;
    for(Student *t=head;t;t=t->next) if(t->id>max_id) max_id=t->id;
    s->id = max_id+1;
    strncpy(s->name,name,NAME_LEN-1);
    s->name[NAME_LEN-1]=0;
    s->grade=grade;
    s->next=head;
    head=s;
    pthread_mutex_unlock(&student_lock);
    logMessage("Added student ID=%d Name=%s Grade=%.2f",s->id,s->name,s->grade);
    char msg[128]; snprintf(msg, sizeof(msg), "Added: %s %.2f",name,grade);
    broadcastMessage(msg);
    return 1;
}

int editStudent(int id,const char *name,float grade){
    if(!isValidName(name) || !isValidGrade(grade)) return 0;
    pthread_mutex_lock(&student_lock);
    for(Student *t=head;t;t=t->next){
        if(t->id==id){
            strncpy(t->name,name,NAME_LEN-1); t->name[NAME_LEN-1]=0;
            t->grade=grade;
            pthread_mutex_unlock(&student_lock);
            logMessage("Edited student ID=%d Name=%s Grade=%.2f",id,name,grade);
            char msg[128];
            snprintf(msg, sizeof(msg), "Edited ID %d: %s %.2f",id,name,grade);
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
            char msg[128];
            snprintf(msg,sizeof(msg),"Deleted ID %d",id);
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
    lastDeleted->next=head;
    head=lastDeleted;
    char msg[128];
    snprintf(msg,sizeof(msg),"Undo last delete: %s restored", lastDeleted->name);
    lastDeleted=NULL;
    pthread_mutex_unlock(&student_lock);
    logMessage("%s", msg);
    broadcastMessage(msg);
}

// search
Student* searchById(int id){
    pthread_mutex_lock(&student_lock);
    for(Student *t=head;t;t=t->next)
        if (t->id==id){
            pthread_mutex_unlock(&student_lock); return t;
        }
    pthread_mutex_unlock(&student_lock);
    return NULL;
}

static int ci_contains(const char *hay, const char *needle){
    if(!*needle) return 1;
    size_t hn=strlen(hay), nn=strlen(needle);
    if(nn>hn) return 0;
    for(size_t i=0;i<=hn-nn;i++){
        size_t j=0;
        while(j<nn && tolower((unsigned char)hay[i+j])==tolower((unsigned char)needle[j])) j++;
        if(j==nn) return 1;
    }
    return 0;
}

int searchByName(const char *query){
    pthread_mutex_lock(&student_lock);
    int found=0;
    for(Student *t=head;t;t=t->next){
        if(ci_contains(t->name,query)){
            if(found==0) printf("%-5s %-20s %-6s\n","ID","Name","Grade");
            printf("%-5d %-20s %-6.2f\n",t->id,t->name,t->grade);
            found++;
        }
    }
    pthread_mutex_unlock(&student_lock);
    if(!found) printf("No students matching \"%s\"\n", query);
    return found;
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

int countStudents(){
    pthread_mutex_lock(&student_lock);
    int count=0;
    for(Student *t=head;t;t=t->next) count++;
    pthread_mutex_unlock(&student_lock);
    return count;
}

// display
void displayStudents(){
    pthread_mutex_lock(&student_lock);
    if(!head){ printf("No students yet.\n"); pthread_mutex_unlock(&student_lock); return; }
    printf("%-5s %-20s %-6s\n","ID","Name","Grade");
    for(Student *t=head;t;t=t->next)
        printf("%-5d %-20s %-6.2f\n",t->id,t->name,t->grade);
    pthread_mutex_unlock(&student_lock);
}

// on-demand stats dashboard (replaces the old always-on ncurses thread, which
// deadlocked itself: it held student_lock and then called getTopStudent() etc,
// which try to lock the same non-recursive mutex again)
void showDashboard(){
    printf("\n=== Student Dashboard ===\n");
    printf("Total Students: %d\n", countStudents());
    displayStudents();
    Student *top = getTopStudent();
    Student *low = getLowestStudent();
    printf("Top: %s %.2f\n", top?top->name:"N/A", top?top->grade:0.0f);
    printf("Lowest: %s %.2f\n", low?low->name:"N/A", low?low->grade:0.0f);
    printf("Average Grade: %.2f\n", getAverageGrade());
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
    if(!a) return b;
    if(!b) return a;
    if(strcmp(a->name,b->name)<0){ a->next=mergeByName(a->next,b); return a; }
    else { b->next=mergeByName(a,b->next); return b; }
}
static Student* mergeByGrade(Student *a, Student *b){
    if(!a) return b;
    if(!b) return a;
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
    // freeList() takes student_lock itself, so it must run before we take the
    // lock here - locking it twice from the same thread deadlocks since
    // student_lock is a plain (non-recursive) mutex.
    FILE *fp=fopen(FILE_CSV,"r");
    if(!fp) return;
    freeList();
    pthread_mutex_lock(&student_lock);
    char line[128]; fgets(line,sizeof(line),fp);
    while(fgets(line,sizeof(line),fp)){
        Student *s=(Student*)student_malloc(sizeof(Student));
        if(sscanf(line,"%d,%49[^,],%f",&s->id,s->name,&s->grade)==3){
            s->next=head; head=s;
        } else student_free(s);
    }
    fclose(fp); pthread_mutex_unlock(&student_lock); logMessage("Loaded CSV");
}

// json storage (hand-rolled reader/writer - no external JSON library available)
void saveJSON(){
    pthread_mutex_lock(&student_lock);
    FILE *fp=fopen(FILE_JSON,"w");
    if(!fp){ pthread_mutex_unlock(&student_lock); return; }
    fprintf(fp,"{\n  \"students\": [\n");
    int first=1;
    for(Student *t=head;t;t=t->next){
        if(!first) fprintf(fp,",\n");
        first=0;
        fprintf(fp,"    {\"id\": %d, \"name\": \"", t->id);
        for(const char *c=t->name; *c; c++){
            if(*c=='"' || *c=='\\') fputc('\\',fp);
            fputc(*c,fp);
        }
        fprintf(fp,"\", \"grade\": %.2f}", t->grade);
    }
    fprintf(fp,"\n  ]\n}\n");
    fclose(fp);
    pthread_mutex_unlock(&student_lock);
    logMessage("Saved JSON");
}

static char *readWholeFile(const char *path){
    FILE *fp=fopen(path,"r");
    if(!fp) return NULL;
    fseek(fp,0,SEEK_END);
    long size=ftell(fp);
    if(size<0){ fclose(fp); return NULL; }
    fseek(fp,0,SEEK_SET);
    char *buf=malloc((size_t)size+1);
    if(!buf){ fclose(fp); return NULL; }
    size_t n=fread(buf,1,(size_t)size,fp);
    buf[n]=0;
    fclose(fp);
    return buf;
}

static int jsonExtractInt(const char *obj,const char *key,int *out){
    char pattern[32]; snprintf(pattern,sizeof(pattern),"\"%s\"",key);
    const char *p=strstr(obj,pattern);
    if(!p) return 0;
    p=strchr(p+strlen(pattern),':');
    if(!p) return 0;
    p++;
    while(*p==' '||*p=='\t') p++;
    *out=(int)strtol(p,NULL,10);
    return 1;
}

static int jsonExtractFloat(const char *obj,const char *key,float *out){
    char pattern[32]; snprintf(pattern,sizeof(pattern),"\"%s\"",key);
    const char *p=strstr(obj,pattern);
    if(!p) return 0;
    p=strchr(p+strlen(pattern),':');
    if(!p) return 0;
    p++;
    while(*p==' '||*p=='\t') p++;
    *out=strtof(p,NULL);
    return 1;
}

static int jsonExtractString(const char *obj,const char *key,char *out,size_t outsize){
    char pattern[32]; snprintf(pattern,sizeof(pattern),"\"%s\"",key);
    const char *p=strstr(obj,pattern);
    if(!p) return 0;
    p=strchr(p+strlen(pattern),':');
    if(!p) return 0;
    p++;
    while(*p==' '||*p=='\t') p++;
    if(*p!='"') return 0;
    p++;
    size_t i=0;
    while(*p && *p!='"' && i<outsize-1){
        if(*p=='\\' && *(p+1)) p++;
        out[i++]=*p++;
    }
    out[i]=0;
    return 1;
}

void loadJSON(){
    char *buf = readWholeFile(FILE_JSON);
    if(!buf) return;

    char *arr = strstr(buf,"\"students\"");
    if(!arr){ free(buf); return; }
    arr = strchr(arr,'[');
    if(!arr){ free(buf); return; }

    // freeList() takes student_lock itself; must run before we lock below.
    freeList();
    pthread_mutex_lock(&student_lock);

    char *p = arr+1;
    while(*p){
        while(*p && *p!='{' && *p!=']') p++;
        if(*p==']' || !*p) break;

        char *start=p;
        int depth=0, inStr=0;
        while(*p){
            if(inStr){
                if(*p=='\\' && *(p+1)) p++;
                else if(*p=='"') inStr=0;
            } else {
                if(*p=='"') inStr=1;
                else if(*p=='{') depth++;
                else if(*p=='}'){ depth--; if(depth==0){ p++; break; } }
            }
            p++;
        }
        size_t len = (size_t)(p-start);
        char *obj = malloc(len+1);
        memcpy(obj,start,len); obj[len]=0;

        int id; float grade; char name[NAME_LEN];
        int ok_id = jsonExtractInt(obj,"id",&id);
        int ok_grade = jsonExtractFloat(obj,"grade",&grade);
        int ok_name = jsonExtractString(obj,"name",name,sizeof(name));
        if(ok_id && ok_grade && ok_name){
            Student *s=(Student*)student_malloc(sizeof(Student));
            s->id=id;
            strncpy(s->name,name,NAME_LEN-1); s->name[NAME_LEN-1]=0;
            s->grade=grade;
            s->next=head; head=s;
        }
        free(obj);
    }
    pthread_mutex_unlock(&student_lock);
    free(buf);
    logMessage("Loaded JSON");
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
    if(sqlite3_prepare_v2(db,"INSERT INTO students (id,name,grade) VALUES (?,?,?);",-1,&stmt,0)!=SQLITE_OK){
        fprintf(stderr,"sqlite3_prepare_v2 failed: %s\n", sqlite3_errmsg(db));
        pthread_mutex_unlock(&student_lock); return 0;
    }

    for(Student *t=head;t;t=t->next){
        sqlite3_bind_int(stmt,1,t->id); sqlite3_bind_text(stmt,2,t->name,-1,SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt,3,t->grade); sqlite3_step(stmt); sqlite3_reset(stmt);
    }

    sqlite3_finalize(stmt); pthread_mutex_unlock(&student_lock); logMessage("Saved SQLite"); return 1;
}

int loadSQLite(sqlite3 *db){
    if(!db) return 0;
    // freeList() takes student_lock itself; must run before we lock below.
    freeList();
    pthread_mutex_lock(&student_lock);
    char *err=NULL; char sql[512];
    snprintf(sql,sizeof(sql),"CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY,name TEXT,grade REAL);");
    if(sqlite3_exec(db,sql,0,0,&err)!=SQLITE_OK){
        fprintf(stderr,"%s\n",err); sqlite3_free(err);
        pthread_mutex_unlock(&student_lock); return 0; }
    sqlite3_stmt *stmt;
    if(sqlite3_prepare_v2(db,"SELECT id,name,grade FROM students;",-1,&stmt,0)!=SQLITE_OK){
        fprintf(stderr,"sqlite3_prepare_v2 failed: %s\n", sqlite3_errmsg(db));
        pthread_mutex_unlock(&student_lock); return 0;
    }
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

// cleanup
void cleanupStudentModule(){
    freeList();
    student_free(lastDeleted);
    lastDeleted = NULL;
    pthread_mutex_lock(&student_lock);
    if(log_fp){ fclose(log_fp); log_fp=NULL; }
    pthread_mutex_unlock(&student_lock);
}

// unit test
void runUnitTests(){
    printf("Running unit tests...\n");
    addStudent("Alice",90); addStudent("Bob",75); addStudent("Charlie",85);
    Student *s=searchById(1); if(s&&strcmp(s->name,"Alice")==0) printf("PASS: searchById\n");
    editStudent(1,"AliceA",95); s=searchById(1); if(s&&s->grade==95) printf("PASS: editStudent\n");
    if(!addStudent("BadGrade",150)) printf("PASS: addStudent rejects out-of-range grade\n");
    if(!addStudent("",50)) printf("PASS: addStudent rejects empty name\n");
    if(countStudents()==3) printf("PASS: countStudents\n");
    if(searchByName("ali")==1) printf("PASS: searchByName (case-insensitive substring)\n");
    deleteStudentWithUndo(2); s=searchById(2); if(!s) printf("PASS: deleteStudentWithUndo\n");
    undoLastDelete(); s=searchById(2); if(s) printf("PASS: undoLastDelete\n");
    printf("Avg %.2f Top %s Low %s\n",getAverageGrade(),getTopStudent()->name,getLowestStudent()->name);
    freeList(); printf("Unit tests finished.\n");
    reportLeaks();
}
