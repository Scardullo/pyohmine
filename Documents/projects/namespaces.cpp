#include <iostream>

namespace first{
    int x = 1;
}

namespace second{
    int x = 2;
}

int main() {
    using namespace second; // uses "second" not "main"

    std::cout << x << '\n';

    int x = 0;

    std::cout << x << "\n";
    std::cout << first::x;  // to use "first" namespace

    return 0;
}