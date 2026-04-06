#include <stdio.h>
#include <stdbool.h>

void hello(char name[], int age);     // <- function prototype
bool agecheck(int age);               // <- function prototype

int main() {

    // function prototype = Provides the compiler w/ info about a functions:
    //                      name, return type, and parameters before its actual definition.
    //                      Enables type checking and allows functions to be used before
    //                      they're defined.
    //                      Improves readability, organization, and helps prevent errors.

    hello("Anthony", 42);

    if(agecheck(30)){
        printf("access granted");
    }
    else{
        printf("access denied");
    }


    return 0;
}

void hello(char name[], int age){      
    printf("Hello %s\n", name);
    printf("You are %d years old\n", age);
}

bool agecheck(int age){
    //return age >= 16;   // does same as following if()
    if(age >= 16){
        return true;
    }
    else{
        return false;
    }
}