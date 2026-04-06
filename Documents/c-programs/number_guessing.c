#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {

    srand(time(NULL));

    int guess = 0;
    int tries = 0;
    int min = 10;
    int max = 100;
    int answer = (rand() % (max - min + 1)) + min;

    printf(" %d", answer);

    do{
        printf("Guess a # b/t %d - %d: ", min, max);
        scanf("%d", &guess);
        tries++;

        if(guess + 30 < answer){
            printf("much higher\n");
        }
        else if(guess - 30 > answer){
            printf("much lower\n");
        }
        else if(guess < answer){
            printf("higher\n");
        }
        else{
            printf("lower\n");
        }

    }while(guess != answer);

    printf("The answer is %d\n", answer);
    printf("It took you %d tries", tries);


    return 0;
}