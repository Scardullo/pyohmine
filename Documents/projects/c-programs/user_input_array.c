#include <stdio.h>

int main() {

    
    int grades[] = {100, 90, 80 ,70 ,60};
    int scores[5] = {0};


    for(int i = 0; i < 5; i++){
        printf("Enter a score: ");
        scanf("%d", &scores[i]);
    }

    for(int i = 0; i < 5; i++){
        printf("%d ", scores[i]);
    }

    return 0;
}