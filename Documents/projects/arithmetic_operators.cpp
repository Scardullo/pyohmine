#include <iostream>

int main() {

    int students = 20;

    //students = students + 2;
    students+=2;
    students++;  // use ++ if only adding 1

    //students = students - 2;
    students-=2;
    students--;
    
    //students = students * 2;
    students*=2;

    //students = students / 2;
    //students/=3;  <-- this would need "double students"
    //                  because of decimal result

    int remainder = students % 3;

    std::cout << remainder;
    //std::cout << remainder;

    // arithmetic follows order of operations ((), *, /, +, - )

    return 0;
}