#include <iostream>

int main() {

    std::string distros[] = {"Arch", "Ubuntu", "Fedora", "OpenSuse"};

    std::cout << distros[0] << '\n';
    std::cout << distros[1] << '\n';
    std::cout << distros[2] << '\n';

    std::cout << '\n';

    for(int x = 0; x < 3; x++){
        std::cout << distros[x] << '\n';
    }

    std::cout << '\n';

    // by using sizeof like this you can add or take away from array 
    // instead of having to change the for loop
    for(int i = 0; i < sizeof(distros)/sizeof(std::string); i++){             
        std::cout << distros[i] << '\n';
    }

    std::cout << '\n';

    char grades[] = {'A', 'B', 'C', 'D', 'F'};

    for(int y = 0; y < sizeof(grades)/sizeof(char); y++){             
        std::cout << grades[y] << '\n';
    }


    return 0;
}