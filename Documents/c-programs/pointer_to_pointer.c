#include <stdio.h>

int main() {
    char c = 'A';        // normal char
    char *p = &c;        // pointer to char
    char **pp = &p;      // pointer to pointer to char

    printf("c: %c\n", c);        // A
    printf("*p: %c\n", *p);      // A
    printf("**pp: %c\n", **pp);  // A
}
