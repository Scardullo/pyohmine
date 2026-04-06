#include <stdio.h>

int main() {

    // array = A fixed-size collection of elements of the same data type
    //         (Similar to a variable, but it holds more than 1 value)
    //         Each value in an array ic called an "element"         

    int numbers[] = {10, 20, 30, 40, 50};
    char grades[] = {'A', 'B', 'C', 'D', 'F'};
    char name[] = "anthony";

    numbers[0] = 100;

    printf("%d\n", numbers[0]);
    printf("%c\n", grades[2]);
    printf("%c\n", name[3]);
    printf("--------------------------\n");


    for(int i = 0; i < sizeof(grades); i++){
        printf("%c\n", grades[i]);
    }

    printf("--------------------------\n");
    //--------------------------------------------------------------------------------
    printf("%d\n", sizeof(numbers));        // <- 20 divided by
    printf("%d\n", sizeof(numbers[0]));     // <-  4 gives the amount of elements             

    int size = sizeof(numbers) / sizeof(numbers[0]);  // <- this does same as latter
                                                      //    and stores it in a variable
    for(int i = 0; i < size; i++){
        printf("%d\n", numbers[i]);
    }

    /*                                      
    for(int i = 0; i < 5; i++){
        printf("%d ", numbers[i]);
    }
    */
    //----------------------------------------------------------------------------------
    printf("----------------------------\n");

    for(int i = 0; i < sizeof(name); i++){
        printf("%c ", name[i]);
    }

    return 0;
}