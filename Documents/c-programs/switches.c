#include <stdio.h>

int main() {

    // switch = an alternative to using
    //          many if-else statements more
    //          efficent with fixed integer values

    int dayofweek = 0;
    //char dayofweek = '\0';

    printf("Enter #(1 - 7) for day of week: ");
    //printf("Enter (M, T, W, R, F, S, or U) for day of week: ");
    scanf("%d", &dayofweek);
    //scanf("%c", &dayofweek);

    switch(dayofweek){
        case 1:
            printf("Monday");
            break;
        case 2:
            printf("Tuesday");
            break;
        case 3:
            printf("Wednesday");
            break;
        case 4:
            printf("Thursday");
            break;
        case 5:
            printf("Friday");
            break;
        case 6:
            printf("Saturday");
            break;
        case 7:
            printf("Sunday");
            break;
        default:
            printf("User Error");
        
    }


    return 0;
}