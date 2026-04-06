#include <iostream>

int main() 
{
    int age;

    std::cout << "Enter age: ";
    std::cin >> age;

    
    if(age >= 65){
        std::cout << "Senior";
    }
    else if(age >= 18){
        std::cout << "Adult";
    }
    else if(age < 0){
        std::cout << "Invalid";
    }
    else{
        std::cout << "Minor";
    }

    return 0;
}