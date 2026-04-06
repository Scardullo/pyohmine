#include <iostream>

int main() {

    bool power = true;
    power ? std::cout << "ON" : std::cout << "OFF";
    //std::cout << (power ? "ON" : "OFF");  // <- could also do
                                            //    it like this


    return 0;
    
}