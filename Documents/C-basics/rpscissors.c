#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int getComputerChoice();
int getUserChoice();
void checkWinner(int userchoice, int compchoice);

int main() {

    srand(time(NULL));

    int userchoice = getUserChoice();
    int compchoice = getComputerChoice();

    switch(userchoice){
        case 1:
            printf("You chose: ----> Rock\n");
            break;
        case 2:
            printf("You chose: ----> Paper\n");
            break;
        case 3:
            printf("You chose: ----> Scissors\n");
            break;
        default:
            printf("User Error\n");
    }

    switch(compchoice){
        case 1:
            printf("Computer choice: Rock\n");
            break;
        case 2:
            printf("Computer Choice: Paper\n");
            break;
        case 3:
            printf("Computer Choice: Scissors\n");
            break;
    }

    checkWinner(userchoice, compchoice);

    return 0;
}

int getComputerChoice(){
    return (rand() % 3) + 1;
}

int getUserChoice(){
    int choice = 0;

    while(1){
        printf("Choose an option\n");
        printf("1. Rock\n");
        printf("2. Paper\n");
        printf("3. Scissors\n");
        printf("Enter your choice: ");

        if(scanf("%d", &choice) != 1){
            // invalid input
            printf("Invalid input! Please enter a number.\n");

            // clear input buffer
            int c;
            while((c = getchar()) != '\n' && c != EOF);

            continue;
        }

        if(choice >= 1 && choice <= 3){
            break;
        }

        printf("Please enter 1, 2, or 3.\n");
    }

    return choice;
}


void checkWinner(int userchoice, int compchoice){
    
    if(userchoice == compchoice){
        printf("It's a Tie!");
    }
    else if(userchoice == 1 && compchoice == 3){
        printf("You Win!");
    }
    else if(userchoice == 2 && compchoice == 1){
        printf("You Win!");
    }
    else if(userchoice == 3 && compchoice == 2){
        printf("You Win!");
    }
    else{
        printf("You Lose");
    }

    /* The following does the same as the latter
    
    if(userchoice == compchoice){
        printf("It's a Tie!");
    }
    else if((userchoice == 1 && compchoice == 3) || 
            (userchoice == 2 && compchoice == 1) ||
            (userchoice == 3 && compchoice == 2)){
        printf("You Win");
    }
    else{
        printf("You Lose");
    }
    */
      

}
