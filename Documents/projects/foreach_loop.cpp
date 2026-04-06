#include <iostream>

int main() {

    // foreach loop = loop that eases the traversal over an
    // iterable data set

    std::string distros[] = {"Arch", "Ubuntu", "Fedora", "OpenSuse", "Bazzite"};

    for(int i = 0; i < sizeof(distros)/sizeof(std::string); i++){  // standard for loop           
        std::cout << distros[i] << '\n';                           // more flexibility 
    }

    for(std::string distro : distros ){         // for each loop
        std::cout << distro << '\n';            // less syntax but only 
    }                                           // from begging to end

    int grades[] = {99, 87, 73, 84};

    for(int grade : grades){
        std::cout << grade << '\n';
    }

    return 0;
}