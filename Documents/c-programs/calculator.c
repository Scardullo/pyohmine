#include <stdio.h>

int main() {

    char operator = '\0';
    double num1 = 0.0;
    double num2 = 0.0;
    double result = 0.0;

    printf("Enter first number: ");
    scanf("%lf", &num1);

    printf("Enter ( + - * /): ");
    scanf(" %c", &operator);        // <- remeber the space " %c" to clear
                                    //    the "\n" in input buffer
    printf("Enter second number: ");
    scanf("%lf", &num2);

    switch(operator){
        case '+':
            result = num1 + num2;
            break;
        case '-':
            result = num1 - num2;
            break;
        case '*':
            result = num1 * num2;
            break;
        case '/':
            if(num2 == 0){
                printf("zeroDivsionError\n");
            }
            else{
            result = num1 / num2;          
            }
            break;
        default:
            printf("User Error\n");
    }

    printf("Result: %.4lf", result);

    return 0;
}