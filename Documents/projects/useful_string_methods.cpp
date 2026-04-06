#include <iostream>

int main() {

    std::string name;

    std::cout << "Enter name: ";
    std::getline(std::cin, name);
    
    std::cout << name.at(0) << '\n';

    name.insert(3, "@");

    std::cout << name.find('t') << '\n';

    name.erase(0, 3);

    //name.clear(); // <- clears name

    //std::cout << "Hello ";

    name.append("@gmail.com");

    std::cout << "username: " << name;

    if(name.empty()){
        std::cout << "User Error";
    }
    else if(name.length() > 50){
        std::cout << "Error len";    
    }
    else{
        std::cout << "Welcome " << name;
    }
    return 0;
}