#include <stdio.h>
#include <stdbool.h>

int main() {

    // AND = &&     OR = ||    NOT = !

    int temp = 0;
    bool sunny = true;
    
    if(temp > 0 && temp < 30){
        printf("The temp is good\n");
    }
    else{
        printf("The temp is bad\n");
    }

    // the following does same as latter
    // using the OR  " || " operator
    
    if(temp <= 0 || temp >= 30){
        printf("The temp is bad\n");
    }
    else{
        printf("The temp is good\n");
    }

    if(sunny){
        printf("It is sunny\n");
    }
    else{
        printf("Its is cloudy\n");
    }

    // the following does the same as the latter
    // using th NOT " ! " operator

    if(!sunny){
        printf("It is cloudy\n");
    }
    else{
        printf("It is sunny\n");
    }


    return 0;
}