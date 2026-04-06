#include <stdio.h>
#include <string.h>

int main() {

    int age = 0;            // you can declare variables in C
    float gpa = 0.0f;       // without assigning a value.
    char grade = '\0';      // "\0" is a null terminator
    char name[30] = "";     // <- when declaring array without assigning
                            //    must specify size "30"
    printf("Enter age: ");      
    scanf("%d", &age);

    printf("Enter gpa: ");
    scanf("%f", &gpa);

    printf("Enter grade: ");
    scanf(" %c", &grade);   // <- puting a space before " %"  
                            //    tells C to skip over the "\n"
                            //    thats in the input buffer

    getchar();              // <- this is used to clear "\n" from input buffer
    printf("Enter full name: ");
    //scanf("%s", &name);               // <- scanf()  cant read whitespace
                                        //    so it cant read full name
    //fgets(name, 30, stdin);           // <- note the size is needed. 
                                        //    In this case "30"
    fgets(name, sizeof(name), stdin);   // <- sizeof() instead of assigning length.
    name[strlen(name) - 1] = '\0';      //    fgets() reads whole line including "\n"
                                        //    so "strlen()" is used here to fix this
                                        // otherwise there would be a blank line
                                        // after printing value of name
    printf("\n");
    printf("*********************\n");                        
    printf("name:  %s\n", name);
    printf("age:   %d\n", age);
    printf("gpa:   %.2f\n", gpa);
    printf("grade: %c\n", grade);

    

    return 0;

}