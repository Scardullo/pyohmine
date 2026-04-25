#include <stdio.h>

int add(int age);

int main() {

    int age = 25;
    add(age);

    printf("%d", age);


    return 0;
}

int add(int age){
    age+= 2;
}