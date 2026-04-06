#include <stdio.h>
#include <stdlib.h>

int main() {

    // calloc() = Cintiguous Allocation
    //            Allocates memory dynamically and sets all allocted bytes to 0.
    //            malloc() is faster, but calloc() leads to less bugs
    //            calloc(#, size)

    int number = 0;
    printf("Enter the number of players: ");
    scanf("%d", &number);

    //int *scores = malloc(number * sizeof(int)); // <- with this there were garbage values
    int *scores = calloc(number, sizeof(int));    // <- with this they were all "0"'s

    if(scores == NULL){
        printf("memory allocation Failed!");
        return 1;
    }

    for(int i = 0; i < number; i++){
        printf("Enter score #%d: ", i + 1);  // <- "+ 1" because user could be confused
        scanf("%d", &scores[i]);             //          entering at a "0"

    }
    for(int i = 0; i < number; i++){
        printf("%d ", scores[i]);
    }

    free(scores);
    scores = NULL;


    return 0;
}