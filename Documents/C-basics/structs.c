#include <stdio.h>
#include <string.h>
#include <stdbool.h>


typedef struct{
    char name[50];
    int age;
    float gpa;
    bool fulltime;
}Students;

void printstudent(Students student);  // <- this has to be after struct but before main()

int main() {

    // struct = A custom container that holds multiple
    //          pieces of related information.
    //          Similar to Objects in other languages

    Students student1 = {"Danny", 30, 2.5, false};
    Students student2 = {"Anthony", 32, 2.7, false};
    Students student3 = {"Patrick", 21, 3.5, true};
    Students student4 = {0};  // <- put a zero to clear out previous memory 
                              //    if you want to assign values later
    strncpy(student4.name, "Sandy", sizeof(student4.name)-1);
    student4.name[49] = '\0';
    //strcpy(student4.name, "Sandy");
    
    student4.age = 27; 
    student4.gpa = 4.0;
    student4.fulltime   = true; 
    
    printstudent(student1);
    printstudent(student2);
    printstudent(student3);
    printstudent(student4);

    return 0;
}

void printstudent(Students student){
    printf("%s\n", student.name);
    printf("%d\n", student.age);
    printf("%.2f\n", student.gpa);
    printf("%s\n", (student.fulltime) ? "Fulltime" : "Part time");
    printf("\n");
}
