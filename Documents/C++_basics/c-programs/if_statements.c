#include <stdio.h>
#include <stdbool.h>
#include <string.h>

int main() {

    int age = 0;
    bool student = true;
    char name[50] = "";

    printf("Enter your name: ");
    fgets(name, sizeof(name), stdin);
    name[strlen(name) - 1] = '\0';

    printf("Enter age: ");
    scanf("%d", &age);

    if(strlen(name) == 0){
        printf("User Error");
    }
    else{
        printf("Hello %s\n", name);
    }

    if(age >= 70){
        printf("you are a senior");
    }
    else if(age >= 18){
        printf("you are an adult");
    }
    else if(age < 0){
        printf("you are an Invalid");
    }    
    else if(age == 0){
        printf("you are a newborn");
    }
    else{
        printf("you are a child");
    }

    printf("\n");

    if(student == true){
        printf("Student access allowed");
    }
    else{
        printf("access denied");
    }

    return 0;
}