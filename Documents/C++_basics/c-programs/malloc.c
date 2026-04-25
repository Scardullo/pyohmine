#include <stdio.h>
#include <stdlib.h>

int main() {

    // malloc() = A function in C that dynamically allocates
    //            a specified number of bytes in memory

    int number = 0;
    printf("Enter the number of grades: ");
    scanf("%d", &number);
    
    char *grades = malloc(number * sizeof(char));   // until now our arrays have
                                                    // been fixed in size, but what
                                                    // if we dont know the size we need 
                                                    // until after the program is running
    if(grades == NULL){                       // <- if we dereference a NULL pointer it can
        printf("Memory Allocation Failed\n"); // cause a 'segmentation fault'
        return 1; // <- exit code because of NULL meaning there was a problem
    }

    for(int i = 0; i < number; i++){
        printf("Enter Grade #%d: ", i + 1);
        scanf(" %c", &grades[i]);
    }

    for(int i = 0; i < number; i++){
        printf("%c ", grades[i]);
    }


    free(grades);   // returning the "rented" space back to the OS
    grades = NULL;  // avoids "dangling pointers" which is 
                    // we dont want a pointer in our program that 
                    // points to memory we are not using anymore
                    // if we dereference a NULL pointer it can
                    // cause a 'segmentation fault'


    return 0;
}