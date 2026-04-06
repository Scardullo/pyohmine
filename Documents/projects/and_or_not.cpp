#include <iostream>

int main() 
{
    // && = AND
    // || = OR
    // !  = NOT

    int temp;
    bool sunny = true;

    std::cout << "Enter Temp: ";
    std::cin >> temp;

    if(temp > 0 && temp < 30){
        std::cout << "Temp good\n";
    }
    else if(temp <= 0 || temp > 30){
        std::cout << "Temp bad\n";
    }
    
    if(!sunny){  // <- if(sunny)  <- bool true
        std::cout << "It's cloudy";
    }
    else{
        std::cout << "It's sunny";
    }

    return 0;
}