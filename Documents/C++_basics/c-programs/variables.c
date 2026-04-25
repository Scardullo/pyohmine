#include <stdio.h>
#include <stdbool.h>

int main() {

    // variable = reusable container
    // int = whole numbers (4 bytes)
    // float = single-precision decimal number (4 bytes)
    // double = double-precision decimal number (8 bytes)
    // char = single character (1 byte)
    // char[] = array of characters (size varies)
    // bool = true or false (1 byte) requires <stdbool.h> 

    int age = 41;
    int year = 2025;
    int quantity = 4;

    float gpa = 2.5;
    float price = 19.99;
    float temp = -10.1;

    double pi = 3.14159256788;
    double e = 2.718281782549;

    char grade = 'A';
    char symbol = '&';

    char distro[] = "Arch Linux";       // no strings in C
    char user[] = "anthony";            // strings are stored
    char email[] = "anthony@gmail.com"; // in arrays

    bool online = true;
    //bool online = 1; // <- '1' is true   '0' is false
    bool systemd = false;

    printf("You are %d years old\n", age);
    printf("The year is %d\n", year);
    printf("Order %d x items\n", quantity);

    printf("gpa is %f\n", gpa);
    printf("The price is $%.2f\n", price); // <- %.2f for only 2 
    printf("Temp is %f degrees\n", temp);  //    places after decimal

    printf("The value of pi is %.5lf\n", pi);   // <- %lf "long float"
    printf("The value of e is %.7lf\n", e);
    
    printf("Your grade is %c\n", grade);
    printf("Bash symbol is %c\n", symbol);

    printf("Distro is %s\n", distro);
    printf("Username is : %s\n", user);
    printf("Your email is %s\n", email);

    printf("%d", online);
    
    if(online){
        printf("...online\n");
    }
    else{
        printf("...offline\n");
    }

    if(systemd){
        printf("systemd bootloader");
    }
    else{
        printf("Grub bootloader");
    }

    return 0;
}