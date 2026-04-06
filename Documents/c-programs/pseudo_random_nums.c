#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {

    // Pseudo-random = Appear random but are determined by a
    //                 mathmatical formula that uses a seed value
    //                 to generate a predictable sequence of numbers.
    //                 advanced: Mersenne Twister or /dev/random

    srand(time(NULL));

    printf("%d\n", rand());
    printf("%d\n", RAND_MAX);       // <- "RAND_MAX" finds maximum random value

    int min = 2;
    int max = 10;

    int min2 = 50;
    int max2 = 100;

    int randomNum = (rand() % 8) + 1;       // <- using modulo the range of numbers 
                                            //    is the possible remainder(s)
                                            //    the "+ 1" is to exempt the number 0

    int randNum = (rand() % max) + min;
    
    int randNum2 = (rand() % (max2 - min2 + 1)) + min2;     // <- this is formula needed
    int randNum3 = (rand() % (max2 - min2 + 1)) + min2;     // <- to create a 
    int randNum4 = (rand() % (max2 - min2 + 1)) + min2;     // <- pseudo-random number


    
    printf("%d\n", randomNum);
    printf("%d\n", randNum);
    printf("%d %d %d\n", randNum2, randNum3, randNum4);                

    return 0;
}