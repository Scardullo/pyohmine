#include <iostream>

int mynum = 3; // <- global

void printnum();

int main() {

    // Local Variables = declared inside a function or block {}
    // Global Variables = declared outside of all functions

    int mynum = 1;  // <- local
    printnum();
    std::cout << mynum << '\n';
    std::cout << ::mynum << '\n'; // <- "::mynum" scope resolution operator
                                  //              calls global variable '3'
                                  
    return 0;
}

void printnum(){
    int mynum = 2;
    std::cout << mynum << '\n';
}

