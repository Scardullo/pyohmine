#include <stdio.h>
#include <stdlib.h>

int main() {
    char input[50];
    char *end;
    long value;

    printf("Enter a number: ");
    fgets(input, sizeof(input), stdin);

    value = strtol(input, &end, 10);   
                                       
    if (end == input) {
        printf("Invalid number!\n");
    } else {
        printf("You entered: %ld\n", value);
    }

    return 0;
}

// long strtol(const char *str, char **endptr, int base); <- USAGE  




/*It converts a string (like "123") into an integer value (123),
and it also lets you:

Detect invalid input (unlike atoi())

Handle different number bases (decimal, hex, binary, etc.)

Find where the number ends in the string*/
