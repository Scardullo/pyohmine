#include <iostream>

int main() {

    // array = a data structure that can hold multiple values
    //         values are accessed by an index number
    //         "kind of like a variable that hold multiple values"

    std::string car[] = {"Corvette", "Mustang", "Camry"};

    car[2] = "Camaro"; 

    std::cout << car[1] << '\n';
    std::cout << car[0] << '\n';

    std::string distros[3]; // if declaring an array must set size

    distros[0] = "Arch";
    distros[1] = "Ubuntu";
    distros[2] = "Fedora";

    std::cout << distros[0] << '\n'; 

    double prices[] = {5.00, 7.50, 9.99, 15.00};

    std::cout << prices[0] << '\n';
    std::cout << prices[1] << '\n';
    std::cout << prices[2] << '\n';
    std::cout << prices[3] << '\n';

    return 0;
}