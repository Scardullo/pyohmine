#include <iostream>

int main() {
    using std::cout;     // could do this instead
    using std::string;   // of "namespace std"

    string name = "anthony";  // <-

    cout << "hello " << name; // <-

    return 0;
}