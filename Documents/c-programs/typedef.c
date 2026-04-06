#include <stdio.h>

typedef int number;
typedef char string[50];
typedef char Initials[3];

int main() {

    // typedef = reserved keyword that gives an existing datatype a "nickname"
    //           Helps simplify complex types and improves readability

    //           typedef existing_type new_name;

    int x = 3;
    int y = 4;
    number z = x + y;

    string name = "Arch linux";  // remeber to not use "[]" when using the keyword
                                 // because the array size is declared with the typedef
    char user1[] = "AS";         
    char user2[] = "BN";         
    Initials user3 = "DM";       //                     ''
    Initials user4 = "CA";       //                     ''

    printf("%d\n", z);

    printf("%s\n", name);
    printf("%s\n", user1);
    printf("%s\n", user2);
    printf("%s\n", user3);
    printf("%s\n", user4);

    return 0;
}