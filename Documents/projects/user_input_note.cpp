#include <iostream>

// cout << (insertion operator)
// cin >> (extraction operator)

int main() {

    std::string name;
    int age;

    std::cout << "whats your age?";
    std::cin >> age;

    std::cout << "Whats your full name?";
    std::getline(std::cin >> std::ws, name);  // <- getline after cin  
                                              //    so use "std::ws"
    std::cout << "Hello " << name << '\n';
    std::cout << "Your are " << age << " years old";

    return 0;
}