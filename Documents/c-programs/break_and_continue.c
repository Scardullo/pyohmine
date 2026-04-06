#include <stdio.h>

int main() {

    // break = break out of a loop (STOP)
    // continue = skip iteration of a loop (SKIP)

    
    for(int i = 1; i <= 10; i++){

        if(i == 4){
            continue;
        }
        else if(i == 8){
            break;
        }
        
        printf("%d\n", i);
    }

    return 0;
}