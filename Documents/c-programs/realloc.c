#include <stdio.h>
#include <stdlib.h>

int main() {

    // realloc() = Reallocation.
    //             Resize previously allocated memory
    //             realloc(ptr, bytes)

    int number = 0;
    printf("Enter the number of prices: ");
    scanf("%d", &number);

    float *prices = malloc(number * sizeof(float));

    if(prices == NULL){
        printf("Memory allocation failed!\n");
        return 1;
    }

    for(int i = 0; i < number; i++){
        printf("Enter price #%d: ", i + 1);
        scanf("%f", &prices[i]);
    }

    int newNumber = 0;
    printf("Enter a new number of prices: ");
    scanf("%d", &newNumber);

    float *temp = realloc(prices, newNumber * sizeof(float));

    if(temp == NULL){
        printf("Could not reallocate memory!\n");
    }
    else{
        prices = temp;
        temp = NULL;   // <- this is only if you plan on reusing "temp"

        for(int i = number; i < newNumber; i++){ // <- if the original nummber was 5
            printf("Enter price #%d: ", i + 1);  //    then we would start at 5 and go 
            scanf("%f", &prices[i]);             //    to the "newNumber".
        }                                        //    if the "newNumber" is less, the 
                                                 //    realloc() shrinks the list "Resize"
        for(int i = 0; i < newNumber; i++){
            printf("$%.2f \n", prices[i]);
        }

    }

    free(prices);
    prices = NULL;


    return 0;
}