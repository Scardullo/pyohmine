#include <iostream>

void unixcode();
void unixcode(std::string distro1);
void unixcode(std::string distro2, std::string distro3);

int main() {

    unixcode("Arch Linux");
    unixcode("Ubuntu", "Fedora");

    return 0;
}

void unixcode(){
    std::cout << "..loading unixcode\n";
}
void unixcode(std::string distro1){
    std::cout << "Distro1: " << distro1 << " GNU/Linux\n";
}

void unixcode(std::string distro2, std::string distro3){
    std::cout << "Distro2: " << distro2 << " Distro3: " << distro3 << '\n';
}