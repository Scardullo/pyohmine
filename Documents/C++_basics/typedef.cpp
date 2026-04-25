#include <iostream>
#include <vector>

    // typedef = reserved keyword used to create an additional name
    //           (alias) for another data type.
    //           New identifier for an existing type
    //           Helps with readability and reduces typos
    // using   = works like typedef only backwards

//typedef std::vector<std::pair<std::string, int>> pairlist_t

//typedef std::string text_t;
//typedef int num_t;

using text_t = std::string;
using num_t = int;

int main() {

    text_t firstname = "anthony";
    num_t age = 41; 

    std::cout << firstname << '\n';
    std::cout << age << '\n';
    //pairlist_t pairlist;

    return 0;
}