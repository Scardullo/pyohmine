#include <iostream>
#include <ctime>

int main()
{

    srand(time(0));
    int randNum = rand() % 5 + 1;

    switch(randNum){
        case 1: std::cout << "Linux";
                break;
        case 2: std::cout << "python";
                break;
        case 3: std::cout << "Unix";
                break;
        case 4: std::cout << "C++";
                break;
        case 5: std::cout << "FreeBSD";
                break;
    }

    return 0;
}