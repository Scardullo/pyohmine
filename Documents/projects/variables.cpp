#include <iostream>

int main() {
 
    int x; // declaration
    x = 5; //assignment
    int y = 7; 
    int sum = x + y;

    // integer (whole number)
    int age = 21;
    int year = 2023;
    int days = 7.5; // <- The decimal would be truncated

    //double (decimal)
    double price = 10.99;
    double gpa = 2.5;
    double temp = 25.1;

    // single character
    char grade = 'A';
    char initial = 'C';
    char currency = '$';

    // boolean
    bool student = true;
    bool power = true;
    bool ForSale = false;

    //strings (objects that represent text)
    std::string name = "anthony";
    std::string os = "linux 2025 gnu"; // <- note numbers treated diff ??
    std::string distro = "Arch";

    std::cout << days << '\n';
    std::cout << temp << '\n';
    std::cout << x << '\n';
    std::cout << y << '\n';
    std::cout << sum << '\n';
    std::cout << "start " << os << '\n';
    std::cout << "Hello " << name << " Welcome to Arch";

    return 0;
}
