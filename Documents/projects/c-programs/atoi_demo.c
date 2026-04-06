#include <stdio.h>
#include <stdlib.h>   // atoi()

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <number_string>\n", argv[0]);
        return 1;
    }

    // argv[1] is a C string (char *)
    printf("Input string: \"%s\"\n", argv[1]);

    // Convert string to integer
    int value = atoi(argv[1]);

    printf("After atoi(): %d\n", value);

    return 0;
}
