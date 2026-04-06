#include <iostream>

int main() {

    char grade;

    std::cout << "Enter Grade: ";
    std::cin >> grade;

    switch(grade){
        case 'A':
            std::cout << "100 -90";
            break;
        case 'B':
            std::cout << "89- 80";
            break;
        case 'C':
            std::cout << "79 -70";
            break;
        // ..............
        // ..............
        default:
            std::cout << "Only Letters A - F";
    }

    return 0;
}