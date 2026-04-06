#include <iostream>

int main() 
{

    double temp;
    char unit;

    std::cout << "********** temp conversion ************\n";
    std::cout << "F = Fahrenheit\n";
    std::cout << "C = Celsius\n";
    std::cout << "Enter 'F' or 'C': ";
    std::cin >> unit;

    if(unit == 'F' || unit == 'f'){
        std::cout << "Enter temperature in Celsius: ";
        std::cin >> temp;

        temp = (1.8 * temp) + 32.0;
        std::cout << "Temperature is : " << temp << "F\n";

    }
    else if(unit == 'C' || unit == 'c'){
        std::cout << "Enter temperature in Fahrenheit: ";
        std::cin >> temp;

        temp = (temp - 32) / 1.8;
        std::cout << "Temperature is: " << temp << "C\n";
    }
    else{
        std::cout << "Please enter only C or F";
    }

    std::cout << "***************************************\n";

    return 0;
}