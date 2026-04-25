#include <iostream>

int main() {

    // switch = alternative to using many "else if" statements
    //          compare one value against matching cases
    
    int month;
    std::cout << "Enter the month (1-12): ";
    std::cin >> month;

    switch(month){
        case 1:
            std::cout << "January";
            break;
        case 2:
            std::cout << "Feabuary";
            break;
        case 3:
            std::cout << "March";
            break;
        // ...................
        // ...................
        default:
            std::cout << "Enter only Numbers 1-12";

    }

    return 0;
}