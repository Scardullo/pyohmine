#include <iostream>
#include <ctime>

int main()
{
    // pseudo-randow = NOT truly random (but close)

    srand(time(NULL));

    int num = (rand() % 7) + 1;  // to get rand num between 
    int num2 = (rand() % 7) + 1;
    int num3 = (rand() % 7) + 1;
                                // 1 and 7 "+1" to get rid of 0
    std::cout << num << '\n';
    std::cout << num2 << '\n';
    std::cout << num3 << '\n';

    return 0;
}