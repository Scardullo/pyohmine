#include <iostream>

int main() {

    // sizeof() = determines the size in bytes of a:
    //            variable, data type, class, objects, etc.

    std::string name = "anthony";
    double gpa = 2.5;
    char grade = 'F';
    bool student = true;
    char grades[] = {'A', 'B', 'C', 'D', 'F'};
    std::string students[] = {"Arch", "Ubuntu", "Fedora", "OpenSUSE"};

    std::cout << sizeof(name) << " bytes\n";
    std::cout << sizeof(grades)/sizeof(grades[0]) << " elements\n";   // finds how many elements 
    std::cout << sizeof(grades)/sizeof(char) << " elements\n";        // in array
    std::cout << sizeof(students)/sizeof(std::string) << " elements\n";        


    return 0;
}