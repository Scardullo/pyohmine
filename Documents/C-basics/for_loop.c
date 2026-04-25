#include <stdio.h>
#include <unistd.h>

int main() {

    // for loop = Repeat some code a limited # of times
    //            for(Initialization; Condition; Update)

    for(int i = 0; i < 10; i++){    // 0 to 9
        printf("%d\n", i);
    }

    printf("\n");

    for(int i = 1; i <= 10; i++){   // 1 to 10
        printf("%d\n", i);
    }

    printf("\n");

    for(int i = 1; i <= 10; i+=2){   // 1 3 5 7 9 
        printf("%d\n", i);
    }

    printf("\n");
    
    for(int i = 2; i <= 10; i+=2){   // 2 4 6 8 10
        printf("%d\n", i);
    }

    printf("\n");

    for(int i = 10; i >= 1; i-=1){   // 10 to 1
        sleep(1);
        printf("%d\n", i);
    }
    printf("program terminated");

    return 0;
}