#include <stdio.h>
#include <string.h>
#include <stdbool.h>

int main() {

    bool running = true;
    char response = '\0';
    //int num = 0;
    //char name[50] = "";

    while(running){
        printf("system running\n");
        printf("continue: (Y/N)\n");
        scanf(" %c", &response);

        if(response != 'Y' && response != 'y'){
            running = false;
        }
    }

    printf("system powering off\n");

    // ---------------------------------------------

    /*
    while(num <= 0){                                    // with "while" loop you 
        printf("Enter a number greater than 0: ");      // can only enter loop
        scanf("%d", &num);                              // if condition is true
    }
    */

    /*
    do{
        printf("Enter a number greater than 0: ");      // a "do while" loop checks the
        scanf(" %d", &num);                             // condition at the end so 
        printf("You Entered: %d\n", num);               // you can enter the loop even if the
    }while(num <= 0);                                   // condition is not true
    */
    
    // ----------------------------------------------

    /*
    printf("Enter your name: ");
    fgets(name, sizeof(name), stdin);
    name[strlen(name) - 1] = '\0';

    while(strlen(name) == 0){
        printf("User Error");
        fgets(name, sizeof(name), stdin);
        name[strlen(name) - 1] = '\0';
    }

    printf("Hello %s", name);
    */

    return 0;
}