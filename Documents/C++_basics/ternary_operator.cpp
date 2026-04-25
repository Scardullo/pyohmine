#include <iostream>

int main() {

    // ternary operator ?: = replacement to an if/else statement
    // condition ? expression1 : expression2;

    //int grade = 75;

    //if(grade >= 60) {
    //    std::cout << "Pass";
    //}
    //else{
    //    std::cout << "Fail";
    //}
    
    int number;
    int grade;
    
    std::cout << "Enter grade percentage (number only): ";
    std::cin >> grade;
    grade >= 60 ? std::cout << "Pass \n" : std::cout << "Fail \n";
    
    std::cout << "Enter a number: ";
    std::cin >>  number;
    number % 2 == 1 ? std::cout << "ODD" : std::cout << "EVEN";

    bool power = true;
    power ? std::cout << "ON" : std::cout << "OFF";


    return 0;
}