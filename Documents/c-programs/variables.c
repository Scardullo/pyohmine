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
    
    // unsigned int   src;      // 4 bytes (source IP)
    // unsigned int   dst;      // 4 bytes (destination IP)
    // unsigned char  zero;     // 1 byte (must be 0)
    // unsigned char  proto;    // 1 byte (IP protocol, TCP = 6)
    // unsigned short tcp_len;  // 2 bytes (TCP length)

    // unsigned short htype;    // 2 bytes (hardware type)
    // unsigned short ptype;    // 2 bytes (protocol type)
    // unsigned char  hlen;     // 1 byte  (hardware address length)
    // unsigned char  plen;     // 1 byte  (protocol address length)
    // unsigned short oper;     // 2 bytes (operation: request/reply)
    // unsigned char  sha[6];   // 6 bytes (sender MAC)
    // unsigned char  spa[4];   // 4 bytes (sender IP)
    // unsigned char  tha[6];   // 6 bytes (target MAC)
    // unsigned char  tpa[4];   // 4 bytes (target IP)



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
