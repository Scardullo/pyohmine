#include <iostream>

std::string concatStrings(std::string string1, std::string string2);

int main(){

    std::string firstname = "anthony";
    std::string lastname = "scardullo";
    std::string fullname = concatStrings(firstname, lastname);

    std::cout << "Hello " << fullname; 


    return 0;
}

std::string concatStrings(std::string string1, std::string string2){
    return string1 + " " + string2;
}
