#include <stdio.h>

// variable scope = variables can share the same name if 
//                  they are in different scopes {}

//int result = 0;   // in C try to avoid global variables 
                    // because they are hard to debug

int add(int x, int y){
    int result = x + y;
    return result;
}

int subtract(int x, int y){
    int result = x - y;
    return result;
}


int main() {

    int x = 5;
    int y = 6;

    //int result = add(3,4);
    int result = subtract(x,y);
    printf("%d", result);
 
    return 0;
}