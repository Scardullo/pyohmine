#include <stdio.h>

void checkBalance(float balance);
float deposit();
float withdraw(float balance);

int main() {

    int choice = 0;
    float balance = 0.0f;

    printf("********** ATM ************");

    do{
        printf("\nSelect an Option:\n");
        printf("\n1. Check Balance\n");
        printf("2. Make Deposit\n");
        printf("3. Make Withdrawl\n");
        printf("4. Exit\n");
        printf("\nEnter Choice: ");
        scanf("%d", &choice);

        switch(choice){
            case 1:
                checkBalance(balance);
                break;
            case 2:
                balance += deposit();
                break;
            case 3:
                balance -= withdraw(balance);
                break;
            case 4:
                printf("Thank You!");
                break;
            default:
                printf("\nUser Error\n");
        }

    }while(choice != 4);


    return 0;
}

void checkBalance(float balance){
    printf("\n Your current balance is: $%.2f\n", balance);
    
}

float deposit(){
    float amount = 0.0f;

    printf("\nEnter amount to deposit: $");
    scanf("%f", &amount);

    if(amount < 0){
        printf("User Error");
        return 0.0f;
    }
    else{
        printf("Succesfully deposited $%.2f\n", amount);
        return amount;
    }
}

float withdraw(float balance){
    float amount = 0.0f;

    printf("\nEnter the amount to withdrawl: $");
    scanf("%f", &amount);

    if(amount < 0){
        printf("User Error");
        return 0.0f;
    }
    else if(amount > balance){
        printf("Insufficient Funds\n");
        printf("Balance: $%.2f", balance);
        return 0.0f;
    }
    else{
        printf("Successfully Withdrew $%.2f\n", amount);
        return amount;
    }
}