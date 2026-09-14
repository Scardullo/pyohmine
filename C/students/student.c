#include "student.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <time.h>
#include <math.h>
#include <strings.h>

// global variables
Student *head = NULL;
pthread_mutex_t student_lock = PTHREAD_MUTEX_INITIALIZER;

static Student *lastDeleted = NULL;
static AllocRecord *alloc_head = NULL;
static pthread_mutex_t alloc_lock = PTHREAD_MUTEX_INITIALIZER;

static FILE *log_fp = NULL;
typedef void (*BroadcastCallback)(const char *msg);
static BroadcastCallback broadcast_cb = NULL;

// monotonically increasing id counter. The original version recomputed
// max(id)+1 on every add, which meant a deleted top-id student's id could be
// silently reused. Tracking it explicitly avoids that and makes addStudent
// O(1) instead of O(n).
static int nextIdCounter = 0;

// ---------------------------------------------------------------------
// id -> Student* hash index. The master list (head/next) stays the source
// of truth for ordering (insertion order, or sorted order after
// sortByName/sortByGrade); this table is a secondary index purely so
// searchById / deleteStudentWithUndo can find a node in O(1) average
// instead of walking the whole list. Every function that mutates the list
// must keep this table in sync. All ht* helpers assume the caller already
// holds student_lock.
// ---------------------------------------------------------------------
static Student *hashTable[HASH_TABLE_SIZE];

static unsigned hashId(int id){
    return ((unsigned)id) % HASH_TABLE_SIZE;
}
static void htInsert(Student *s){
    unsigned b = hashId(s->id);
    s->hnext = hashTable[b];
    hashTable[b] = s;
}
static void htRemove(Student *s){
    unsigned b = hashId(s->id);
    Student **cur = &hashTable[b];
    while(*cur){
        if(*cur == s){ *cur = s->hnext; return; }
        cur = &(*cur)->hnext;
    }
}
static Student *htFind(int id){
    for(Student *s = hashTable[hashId(id)]; s; s = s->hnext)
        if(s->id == id) return s;
    return NULL;
}
static void htClear(){
    memset(hashTable, 0, sizeof(hashTable));
}

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

int isValidCourseName(const char *name){
    // ':' and '|' are the CSV course-field separators, so course names can't use them
    return name && name[0] != '\0' && !strchr(name, ',') && !strchr(name, ':') && !strchr(name, '|');
}

// courses ------------------------------------------------------------------
float studentAverage(const Student *s){
    if(!s || s->courseCount == 0) return 0.0f;
    float total = 0;
    for(int i=0;i<s->courseCount;i++) total += s->courses[i].grade;
    return total / s->courseCount;
}

char letterGrade(float avg){
    if(avg >= 90) return 'A';
    if(avg >= 80) return 'B';
    if(avg >= 70) return 'C';
    if(avg >= 60) return 'D';
    return 'F';
}

int addCourse(int id, const char *courseName, float grade){
    if(!isValidCourseName(courseName) || !isValidGrade(grade)) return 0;
    pthread_mutex_lock(&student_lock);
    Student *s = htFind(id);
    if(!s || s->courseCount >= MAX_COURSES){ pthread_mutex_unlock(&student_lock); return 0; }
    for(int i=0;i<s->courseCount;i++)
        if(strcasecmp(s->courses[i].name, courseName)==0){ pthread_mutex_unlock(&student_lock); return 0; }
    strncpy(s->courses[s->courseCount].name, courseName, COURSE_NAME_LEN-1);
    s->courses[s->courseCount].name[COURSE_NAME_LEN-1]=0;
    s->courses[s->courseCount].grade = grade;
    s->courseCount++;
    pthread_mutex_unlock(&student_lock);
    logMessage("Added course '%s'=%.2f to student ID=%d", courseName, grade, id);
    char msg[128]; snprintf(msg,sizeof(msg),"ID %d: added course %s (%.2f)", id, courseName, grade);
    broadcastMessage(msg);
    return 1;
}

int editCourseGrade(int id, const char *courseName, float grade){
    if(!isValidGrade(grade)) return 0;
    pthread_mutex_lock(&student_lock);
    Student *s = htFind(id);
    if(!s){ pthread_mutex_unlock(&student_lock); return 0; }
    for(int i=0;i<s->courseCount;i++){
        if(strcasecmp(s->courses[i].name, courseName)==0){
            s->courses[i].grade = grade;
            pthread_mutex_unlock(&student_lock);
            logMessage("Edited course '%s' of student ID=%d to %.2f", courseName, id, grade);
            char msg[128]; snprintf(msg,sizeof(msg),"ID %d: course %s now %.2f", id, courseName, grade);
            broadcastMessage(msg);
            return 1;
        }
    }
    pthread_mutex_unlock(&student_lock);
    return 0;
}

int removeCourse(int id, const char *courseName){
    pthread_mutex_lock(&student_lock);
    Student *s = htFind(id);
    if(!s){ pthread_mutex_unlock(&student_lock); return 0; }
    for(int i=0;i<s->courseCount;i++){
        if(strcasecmp(s->courses[i].name, courseName)==0){
            for(int j=i;j<s->courseCount-1;j++) s->courses[j]=s->courses[j+1];
            s->courseCount--;
            pthread_mutex_unlock(&student_lock);
            logMessage("Removed course '%s' from student ID=%d", courseName, id);
            return 1;
        }
    }
    pthread_mutex_unlock(&student_lock);
    return 0;
}

void listCourses(int id){
    pthread_mutex_lock(&student_lock);
    Student *s = htFind(id);
    if(!s){ pthread_mutex_unlock(&student_lock); printf("No student with that ID.\n"); return; }
    if(s->courseCount==0){ printf("%s has no courses yet.\n", s->name); pthread_mutex_unlock(&student_lock); return; }
    printf("Courses for %s (ID %d):\n", s->name, s->id);
    for(int i=0;i<s->courseCount;i++)
        printf("  %-24s %.2f\n", s->courses[i].name, s->courses[i].grade);
    float avg = studentAverage(s);
    printf("  Average: %.2f (%c)\n", avg, letterGrade(avg));
    pthread_mutex_unlock(&student_lock);
}

// core CRUD ------------------------------------------------------------------
int addStudent(const char *name,float grade){
    if(!isValidName(name) || !isValidGrade(grade)) return 0;
    Student *s = (Student*)student_malloc(sizeof(Student));
    if(!s) return 0;
    pthread_mutex_lock(&student_lock);
    s->id = ++nextIdCounter;
    strncpy(s->name,name,NAME_LEN-1);
    s->name[NAME_LEN-1]=0;
    s->courseCount = 1;
    strncpy(s->courses[0].name,"General",COURSE_NAME_LEN-1);
    s->courses[0].name[COURSE_NAME_LEN-1]=0;
    s->courses[0].grade = grade;
    s->next=head;
    head=s;
    htInsert(s);
    pthread_mutex_unlock(&student_lock);
    logMessage("Added student ID=%d Name=%s Grade=%.2f",s->id,s->name,grade);
    char msg[128]; snprintf(msg, sizeof(msg), "Added: %s %.2f",name,grade);
    broadcastMessage(msg);
    return 1;
}

int editStudent(int id,const char *name,float grade){
    // renames the student and overwrites their first course's grade
    // (creating a "General" course if they don't have one yet). Per-course
    // edits should go through editCourseGrade() instead.
    if(!isValidName(name) || !isValidGrade(grade)) return 0;
    pthread_mutex_lock(&student_lock);
    Student *s = htFind(id);
    if(!s){ pthread_mutex_unlock(&student_lock); return 0; }
    strncpy(s->name,name,NAME_LEN-1); s->name[NAME_LEN-1]=0;
    if(s->courseCount==0){
        strncpy(s->courses[0].name,"General",COURSE_NAME_LEN-1);
        s->courses[0].name[COURSE_NAME_LEN-1]=0;
        s->courseCount=1;
    }
    s->courses[0].grade=grade;
    pthread_mutex_unlock(&student_lock);
    logMessage("Edited student ID=%d Name=%s Grade=%.2f",id,name,grade);
    char msg[128];
    snprintf(msg, sizeof(msg), "Edited ID %d: %s %.2f",id,name,grade);
    broadcastMessage(msg);
    return 1;
}

int deleteStudentWithUndo(int id){
    pthread_mutex_lock(&student_lock);
    if(!htFind(id)){ pthread_mutex_unlock(&student_lock); return 0; }   // fail fast, O(1)
    Student *cur=head,*prev=NULL;
    while(cur){
        if(cur->id==id){
            if(prev) prev->next=cur->next; else head=cur->next;
            htRemove(cur);

            student_free(lastDeleted);
            lastDeleted = (Student*)student_malloc(sizeof(Student));
            *lastDeleted = *cur; lastDeleted->next=NULL; lastDeleted->hnext=NULL;

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
    htInsert(lastDeleted);
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
    Student *s = htFind(id);
    pthread_mutex_unlock(&student_lock);
    return s;
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

static void printStudentRow(const Student *t){
    float avg = studentAverage(t);
    printf("%-5d %-20s %-5d %-7.2f %-6c\n", t->id, t->name, t->courseCount, avg, letterGrade(avg));
}
static void printStudentHeader(void){
    printf("%-5s %-20s %-5s %-7s %-6s\n","ID","Name","Crs#","Avg","Grd");
}

int searchByName(const char *query){
    pthread_mutex_lock(&student_lock);
    int found=0;
    for(Student *t=head;t;t=t->next){
        if(ci_contains(t->name,query)){
            if(found==0) printStudentHeader();
            printStudentRow(t);
            found++;
        }
    }
    pthread_mutex_unlock(&student_lock);
    if(!found) printf("No students matching \"%s\"\n", query);
    return found;
}

int searchByGradeRange(float minGrade, float maxGrade){
    pthread_mutex_lock(&student_lock);
    int found=0;
    for(Student *t=head;t;t=t->next){
        float avg = studentAverage(t);
        if(avg>=minGrade && avg<=maxGrade){
            if(found==0) printStudentHeader();
            printStudentRow(t);
            found++;
        }
    }
    pthread_mutex_unlock(&student_lock);
    if(!found) printf("No students with average in [%.2f, %.2f]\n", minGrade, maxGrade);
    return found;
}

// stats
Student* getTopStudent(){
    pthread_mutex_lock(&student_lock);
    if(!head){ pthread_mutex_unlock(&student_lock); return NULL; }
    Student *top=head; for(Student *t=head->next;t;t=t->next) if(studentAverage(t)>studentAverage(top)) top=t;
    pthread_mutex_unlock(&student_lock);
    return top;
}

Student* getLowestStudent(){
    pthread_mutex_lock(&student_lock);
    if(!head){ pthread_mutex_unlock(&student_lock); return NULL; }
    Student *low=head; for(Student *t=head->next;t;t=t->next) if(studentAverage(t)<studentAverage(low)) low=t;
    pthread_mutex_unlock(&student_lock);
    return low;
}

float getAverageGrade(){
    pthread_mutex_lock(&student_lock);
    if(!head){ pthread_mutex_unlock(&student_lock); return 0; }
    float total=0; int count=0;
    for(Student *t=head;t;t=t->next){ total+=studentAverage(t); count++; }
    pthread_mutex_unlock(&student_lock);
    return count?total/count:0;
}

static int cmpFloat(const void *a, const void *b){
    float fa=*(const float*)a, fb=*(const float*)b;
    return (fa>fb)-(fa<fb);
}

float getMedianGrade(){
    pthread_mutex_lock(&student_lock);
    int n=0; for(Student *t=head;t;t=t->next) n++;
    if(n==0){ pthread_mutex_unlock(&student_lock); return 0; }
    float *avgs = malloc(sizeof(float)*(size_t)n);
    int i=0; for(Student *t=head;t;t=t->next) avgs[i++]=studentAverage(t);
    pthread_mutex_unlock(&student_lock);
    qsort(avgs,(size_t)n,sizeof(float),cmpFloat);
    float median = (n%2) ? avgs[n/2] : (avgs[n/2-1]+avgs[n/2])/2.0f;
    free(avgs);
    return median;
}

float getStdDevGrade(){
    pthread_mutex_lock(&student_lock);
    int n=0; float total=0;
    for(Student *t=head;t;t=t->next){ total+=studentAverage(t); n++; }
    if(n==0){ pthread_mutex_unlock(&student_lock); return 0; }
    float mean = total/n;
    float sumSq=0;
    for(Student *t=head;t;t=t->next){ float d=studentAverage(t)-mean; sumSq+=d*d; }
    pthread_mutex_unlock(&student_lock);
    return sqrtf(sumSq/n);
}

int countStudents(){
    pthread_mutex_lock(&student_lock);
    int count=0;
    for(Student *t=head;t;t=t->next) count++;
    pthread_mutex_unlock(&student_lock);
    return count;
}

// display
void displayStudents(int page){
    pthread_mutex_lock(&student_lock);
    if(!head){ printf("No students yet.\n"); pthread_mutex_unlock(&student_lock); return; }

    int total=0; for(Student *t=head;t;t=t->next) total++;

    int start=0, end=total;
    if(page>0){
        start=(page-1)*PAGE_SIZE;
        end = start+PAGE_SIZE; if(end>total) end=total;
        if(start>=total){ printf("No more students (only %d total).\n", total); pthread_mutex_unlock(&student_lock); return; }
    }

    printStudentHeader();
    int i=0;
    for(Student *t=head;t;t=t->next,i++){
        if(i<start || i>=end) continue;
        printStudentRow(t);
    }
    if(page>0){
        int totalPages = (total + PAGE_SIZE - 1)/PAGE_SIZE;
        printf("-- page %d of %d (%d students total) --\n", page, totalPages, total);
    }
    pthread_mutex_unlock(&student_lock);
}

// on-demand stats dashboard (replaces the old always-on ncurses thread, which
// deadlocked itself: it held student_lock and then called getTopStudent() etc,
// which try to lock the same non-recursive mutex again)
void showDashboard(){
    printf("\n=== Student Dashboard ===\n");
    printf("Total Students: %d\n", countStudents());
    displayStudents(0);
    Student *top = getTopStudent();
    Student *low = getLowestStudent();
    printf("Top: %s %.2f\n", top?top->name:"N/A", top?studentAverage(top):0.0f);
    printf("Lowest: %s %.2f\n", low?low->name:"N/A", low?studentAverage(low):0.0f);
    printf("Average: %.2f  Median: %.2f  StdDev: %.2f\n", getAverageGrade(), getMedianGrade(), getStdDevGrade());

    // ASCII histogram of letter-grade distribution
    int buckets[5]={0,0,0,0,0}; // A B C D F
    pthread_mutex_lock(&student_lock);
    for(Student *t=head;t;t=t->next){
        switch(letterGrade(studentAverage(t))){
            case 'A': buckets[0]++; break;
            case 'B': buckets[1]++; break;
            case 'C': buckets[2]++; break;
            case 'D': buckets[3]++; break;
            default:  buckets[4]++; break;
        }
    }
    pthread_mutex_unlock(&student_lock);
    const char *labels="ABCDF";
    printf("Grade distribution:\n");
    for(int i=0;i<5;i++){
        printf("  %c | ", labels[i]);
        for(int j=0;j<buckets[i];j++) putchar('#');
        printf(" (%d)\n", buckets[i]);
    }
}

// free list
void freeList(){
    pthread_mutex_lock(&student_lock);
    Student *cur=head;
    while(cur){ Student *tmp=cur; cur=cur->next; student_free(tmp); }
    head=NULL;
    htClear();
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
    if(studentAverage(a)>studentAverage(b)){ a->next=mergeByGrade(a->next,b); return a; }
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
// note: sorting only relinks ->next pointers; the hash table indexes by
// pointer identity so it stays valid without a rebuild.
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

// admin authentication -------------------------------------------------
// NOT cryptographically secure - a salted FNV-1a hash is enough to gate
// destructive menu actions in a learning project without storing the
// password in plaintext. Do not reuse this pattern for anything real.
static int admin_authenticated = 0;
#define ADMIN_SALT "student-cli-salt-v1"

static unsigned long long fnv1a(const char *s){
    unsigned long long h = 1469598103934665603ULL;
    for(; *s; s++){ h ^= (unsigned char)*s; h *= 1099511628211ULL; }
    return h;
}

int adminLogin(const char *password){
    if(!password) return 0;
    char salted[300];
    snprintf(salted,sizeof(salted),"%s%s",ADMIN_SALT,password);
    unsigned long long h = fnv1a(salted);

    FILE *fp = fopen(FILE_ADMIN,"r");
    if(!fp){
        // first run: whatever password is entered becomes the admin password
        fp = fopen(FILE_ADMIN,"w");
        if(!fp) return 0;
        fprintf(fp,"%llx\n",h);
        fclose(fp);
        admin_authenticated = 1;
        logMessage("Admin password set for the first time");
        return 1;
    }
    unsigned long long stored=0;
    if(fscanf(fp,"%llx",&stored)!=1) stored=0;
    fclose(fp);
    if(stored==h){ admin_authenticated=1; logMessage("Admin login succeeded"); return 1; }
    logMessage("Admin login failed");
    return 0;
}
int isAdmin(){ return admin_authenticated; }
void adminLogout(){ admin_authenticated=0; }

// csv storage ------------------------------------------------------------
// format: ID,Name,course1:grade1|course2:grade2|...
void saveCSV(){
    pthread_mutex_lock(&student_lock);
    FILE *fp=fopen(FILE_CSV,"w"); if(!fp){ pthread_mutex_unlock(&student_lock); return; }
    fprintf(fp,"ID,Name,Courses\n");
    for(Student *t=head;t;t=t->next){
        fprintf(fp,"%d,%s,",t->id,t->name);
        for(int i=0;i<t->courseCount;i++)
            fprintf(fp,"%s%s:%.2f", i?"|":"", t->courses[i].name, t->courses[i].grade);
        fprintf(fp,"\n");
    }
    fclose(fp); pthread_mutex_unlock(&student_lock); logMessage("Saved CSV");
}

static void parseCoursesField(Student *s, char *field){
    s->courseCount = 0;
    char *saveptr=NULL;
    char *tok = strtok_r(field,"|",&saveptr);
    while(tok && s->courseCount < MAX_COURSES){
        char *colon = strchr(tok,':');
        if(colon){
            *colon=0;
            strncpy(s->courses[s->courseCount].name,tok,COURSE_NAME_LEN-1);
            s->courses[s->courseCount].name[COURSE_NAME_LEN-1]=0;
            s->courses[s->courseCount].grade = strtof(colon+1,NULL);
            s->courseCount++;
        }
        tok = strtok_r(NULL,"|",&saveptr);
    }
}

void loadCSV(){
    // freeList() takes student_lock itself, so it must run before we take the
    // lock here - locking it twice from the same thread deadlocks since
    // student_lock is a plain (non-recursive) mutex.
    FILE *fp=fopen(FILE_CSV,"r");
    if(!fp) return;
    freeList();
    pthread_mutex_lock(&student_lock);
    nextIdCounter = 0;
    char line[1024];
    fgets(line,sizeof(line),fp); // header
    while(fgets(line,sizeof(line),fp)){
        line[strcspn(line,"\n")]=0;
        char *p=line;
        char *idStr=strsep(&p,",");
        char *nameStr=strsep(&p,",");
        char *coursesStr=p; // remainder (may itself be NULL/empty)
        if(!idStr || !nameStr) continue;
        Student *s=(Student*)student_malloc(sizeof(Student));
        s->id = atoi(idStr);
        strncpy(s->name,nameStr,NAME_LEN-1); s->name[NAME_LEN-1]=0;
        if(coursesStr && *coursesStr) parseCoursesField(s,coursesStr); else s->courseCount=0;
        s->next=head; head=s;
        htInsert(s);
        if(s->id > nextIdCounter) nextIdCounter = s->id;
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
        fprintf(fp,"\", \"courses\": [");
        for(int i=0;i<t->courseCount;i++){
            fprintf(fp,"%s{\"name\": \"", i?", ":"");
            for(const char *c=t->courses[i].name; *c; c++){
                if(*c=='"' || *c=='\\') fputc('\\',fp);
                fputc(*c,fp);
            }
            fprintf(fp,"\", \"grade\": %.2f}", t->courses[i].grade);
        }
        fprintf(fp,"]}");
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

// scans forward from *pp for the next balanced {...} object; used both for
// the top-level "students" array and for each student's nested "courses"
// array. Returns a malloc'd copy of the object text, or NULL once it hits
// the array's closing ']' (or end of string) with nothing left to parse.
static char *nextJsonObject(char **pp){
    char *p=*pp;
    while(*p && *p!='{' && *p!=']') p++;
    if(*p!='{'){ *pp=p; return NULL; }
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
    size_t len=(size_t)(p-start);
    char *obj=malloc(len+1);
    memcpy(obj,start,len); obj[len]=0;
    *pp=p;
    return obj;
}

static void parseCoursesArray(Student *s, char *coursesArr){
    s->courseCount=0;
    if(!coursesArr) return;
    char *p=coursesArr;
    char *cobj;
    while(s->courseCount < MAX_COURSES && (cobj=nextJsonObject(&p))!=NULL){
        char cname[COURSE_NAME_LEN]; float cgrade;
        int ok_n = jsonExtractString(cobj,"name",cname,sizeof(cname));
        int ok_g = jsonExtractFloat(cobj,"grade",&cgrade);
        if(ok_n && ok_g){
            strncpy(s->courses[s->courseCount].name,cname,COURSE_NAME_LEN-1);
            s->courses[s->courseCount].name[COURSE_NAME_LEN-1]=0;
            s->courses[s->courseCount].grade=cgrade;
            s->courseCount++;
        }
        free(cobj);
    }
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
    nextIdCounter = 0;

    char *p = arr+1;
    char *obj;
    while((obj=nextJsonObject(&p))!=NULL){
        int id; char name[NAME_LEN];
        int ok_id = jsonExtractInt(obj,"id",&id);
        int ok_name = jsonExtractString(obj,"name",name,sizeof(name));
        if(ok_id && ok_name){
            Student *s=(Student*)student_malloc(sizeof(Student));
            s->id=id;
            strncpy(s->name,name,NAME_LEN-1); s->name[NAME_LEN-1]=0;
            char *carr = strstr(obj,"\"courses\"");
            if(carr) carr = strchr(carr,'[');
            parseCoursesArray(s, carr ? carr+1 : NULL);
            s->next=head; head=s;
            htInsert(s);
            if(s->id > nextIdCounter) nextIdCounter = s->id;
        }
        free(obj);
    }
    pthread_mutex_unlock(&student_lock);
    free(buf);
    logMessage("Loaded JSON");
}

// sqlite storage -----------------------------------------------------------
// relational: a students table plus a courses table keyed by student_id.
int saveSQLite(sqlite3 *db){
    if(!db) return 0;
    pthread_mutex_lock(&student_lock);
    char *err=NULL;

    const char *ddl =
        "CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY, name TEXT);"
        "CREATE TABLE IF NOT EXISTS courses (student_id INTEGER, name TEXT, grade REAL);";
    if(sqlite3_exec(db,ddl,0,0,&err)!=SQLITE_OK){
        fprintf(stderr,"%s\n",err); sqlite3_free(err);
        pthread_mutex_unlock(&student_lock); return 0;
    }
    if(sqlite3_exec(db,"BEGIN TRANSACTION; DELETE FROM students; DELETE FROM courses;",0,0,&err)!=SQLITE_OK){
        fprintf(stderr,"%s\n",err); sqlite3_free(err);
        pthread_mutex_unlock(&student_lock); return 0;
    }

    sqlite3_stmt *stmtS, *stmtC;
    if(sqlite3_prepare_v2(db,"INSERT INTO students (id,name) VALUES (?,?);",-1,&stmtS,0)!=SQLITE_OK ||
       sqlite3_prepare_v2(db,"INSERT INTO courses (student_id,name,grade) VALUES (?,?,?);",-1,&stmtC,0)!=SQLITE_OK){
        fprintf(stderr,"sqlite3_prepare_v2 failed: %s\n", sqlite3_errmsg(db));
        sqlite3_exec(db,"ROLLBACK;",0,0,0);
        pthread_mutex_unlock(&student_lock); return 0;
    }

    for(Student *t=head;t;t=t->next){
        sqlite3_bind_int(stmtS,1,t->id); sqlite3_bind_text(stmtS,2,t->name,-1,SQLITE_TRANSIENT);
        sqlite3_step(stmtS); sqlite3_reset(stmtS);
        for(int i=0;i<t->courseCount;i++){
            sqlite3_bind_int(stmtC,1,t->id);
            sqlite3_bind_text(stmtC,2,t->courses[i].name,-1,SQLITE_TRANSIENT);
            sqlite3_bind_double(stmtC,3,t->courses[i].grade);
            sqlite3_step(stmtC); sqlite3_reset(stmtC);
        }
    }

    sqlite3_finalize(stmtS); sqlite3_finalize(stmtC);
    sqlite3_exec(db,"COMMIT;",0,0,&err);
    pthread_mutex_unlock(&student_lock); logMessage("Saved SQLite"); return 1;
}

int loadSQLite(sqlite3 *db){
    if(!db) return 0;
    // freeList() takes student_lock itself; must run before we lock below.
    freeList();
    pthread_mutex_lock(&student_lock);
    nextIdCounter = 0;
    char *err=NULL;
    const char *ddl =
        "CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY, name TEXT);"
        "CREATE TABLE IF NOT EXISTS courses (student_id INTEGER, name TEXT, grade REAL);";
    if(sqlite3_exec(db,ddl,0,0,&err)!=SQLITE_OK){
        fprintf(stderr,"%s\n",err); sqlite3_free(err);
        pthread_mutex_unlock(&student_lock); return 0;
    }

    sqlite3_stmt *stmt;
    if(sqlite3_prepare_v2(db,"SELECT id,name FROM students;",-1,&stmt,0)!=SQLITE_OK){
        fprintf(stderr,"sqlite3_prepare_v2 failed: %s\n", sqlite3_errmsg(db));
        pthread_mutex_unlock(&student_lock); return 0;
    }
    while(sqlite3_step(stmt)==SQLITE_ROW){
        Student *s=(Student*)student_malloc(sizeof(Student));
        s->id = sqlite3_column_int(stmt,0);
        const unsigned char *name = sqlite3_column_text(stmt,1);
        strncpy(s->name,(const char*)name,NAME_LEN-1); s->name[NAME_LEN-1]=0;
        s->courseCount=0;
        s->next=head; head=s;
        htInsert(s);
        if(s->id > nextIdCounter) nextIdCounter = s->id;
    }
    sqlite3_finalize(stmt);

    sqlite3_stmt *cstmt;
    if(sqlite3_prepare_v2(db,"SELECT name,grade FROM courses WHERE student_id=?;",-1,&cstmt,0)==SQLITE_OK){
        for(Student *t=head;t;t=t->next){
            sqlite3_bind_int(cstmt,1,t->id);
            while(t->courseCount<MAX_COURSES && sqlite3_step(cstmt)==SQLITE_ROW){
                const unsigned char *cname = sqlite3_column_text(cstmt,0);
                strncpy(t->courses[t->courseCount].name,(const char*)cname,COURSE_NAME_LEN-1);
                t->courses[t->courseCount].name[COURSE_NAME_LEN-1]=0;
                t->courses[t->courseCount].grade=(float)sqlite3_column_double(cstmt,1);
                t->courseCount++;
            }
            sqlite3_reset(cstmt);
        }
        sqlite3_finalize(cstmt);
    }

    pthread_mutex_unlock(&student_lock); logMessage("Loaded SQLite"); return 1;
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
    Student *s=searchById(1); if(s&&strcmp(s->name,"Alice")==0) printf("PASS: searchById (hash lookup)\n");
    editStudent(1,"AliceA",95); s=searchById(1); if(s&&s->courses[0].grade==95) printf("PASS: editStudent\n");
    if(!addStudent("BadGrade",150)) printf("PASS: addStudent rejects out-of-range grade\n");
    if(!addStudent("",50)) printf("PASS: addStudent rejects empty name\n");
    if(countStudents()==3) printf("PASS: countStudents\n");
    if(searchByName("ali")==1) printf("PASS: searchByName (case-insensitive substring)\n");

    if(addCourse(2,"Math",80)) printf("PASS: addCourse\n");
    if(!addCourse(2,"Math",70)) printf("PASS: addCourse rejects duplicate course name\n");
    if(editCourseGrade(2,"math",88)) printf("PASS: editCourseGrade (case-insensitive match)\n");
    s=searchById(2);
    if(s && fabsf(studentAverage(s) - ((75.0f+88.0f)/2.0f)) < 0.01f) printf("PASS: studentAverage over multiple courses\n");
    if(letterGrade(95)=='A' && letterGrade(55)=='F') printf("PASS: letterGrade thresholds\n");
    if(removeCourse(2,"Math")) printf("PASS: removeCourse\n");

    if(searchByGradeRange(90,100)>=1) printf("PASS: searchByGradeRange\n");

    deleteStudentWithUndo(2); s=searchById(2); if(!s) printf("PASS: deleteStudentWithUndo\n");
    undoLastDelete(); s=searchById(2); if(s) printf("PASS: undoLastDelete\n");

    float med = getMedianGrade(), sd = getStdDevGrade();
    printf("Avg %.2f Median %.2f StdDev %.2f Top %s Low %s\n",
           getAverageGrade(), med, sd, getTopStudent()->name, getLowestStudent()->name);

    if(adminLogin("unit-test-password")) printf("PASS: adminLogin\n");
    if(isAdmin()) printf("PASS: isAdmin reflects successful login\n");
    adminLogout();
    if(!isAdmin()) printf("PASS: adminLogout clears state\n");

    freeList(); printf("Unit tests finished.\n");
    reportLeaks();
}
