#include <stdio.h>
#include <stdlib.h>

int main() {
    char line[50];
    int age;

    printf("Enter your age: ");
    fgets(line, sizeof(line), stdin);       // Safe input (reads entire line)

    // Option 1: Using atoi()
    age = atoi(line);                       // Convert string to int (no error check)
    printf("Using atoi(): %d\n", age);

    // Option 2: Using sscanf()
    sscanf(line, "%d", &age);               // Extract int from string (formatted)
    printf("Using sscanf(): %d\n", age);    // sscanf() = reads string from memory

    return 0;
}
