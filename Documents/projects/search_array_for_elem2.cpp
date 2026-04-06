#include <iostream>

int searchArray(std::string array[], int size, std::string element);

int main() {

    std::string distros[] = {"Arch", "Ubuntu", "Debian", "Fedora", "OpenSuse"};
    int size = sizeof(distros)/sizeof(distros[0]);
    int index;
    std::string mydistro;

    std::cout << "Enter element to search for: " << '\n';
    std::getline(std::cin, mydistro);

    index = searchArray(distros, size, mydistro);

    if(index != -1){
        std::cout << mydistro << " is at index " << index;
    }
    else{
        std::cout << mydistro << " is not in the array ";
    }

    return 0;
}

int searchArray(std::string array[], int size, std::string element){

    for(int i = 0; i < size; i++){
        if(array[i] == element){
            return i;
        }
    }
    return -1;
}