#include <iostream>

void unixos(std::string, double);

int main() 
{

    std::string user = "anthony";
    std::string name = "Arch Linux";
    double version = 7.1;
    double version2 = 7.2;

    unixos(user, version);
    std::cout << "\n";
    unixos(name, version2);

    return 0;
}

// function can be defined after main if 
// declared before main ^ 

void unixos(std::string x, double y){
    std::cout << "...starting unix os 7.1.7 " << x << '\n';
    std::cout << "...loading intiramfs " << x << '\n';
    std::cout << "...GRUB bootloader " << x << '\n';
    std::cout << "... STD Version: " << y << '\n';
}