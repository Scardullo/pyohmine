#include <stdio.h>
#include <stdbool.h>

int main() {

    float price = 10.00;
    bool student = true;    // 10% discount
    bool staff = true;     // 20% discount

    // student = $9
    // staff = $8
    // student + senior = $7

    if(student){
        if(staff){
            printf("student discount is 10%\n");
            printf("staff discount is 20%\n");
            price = price * 0.7;
        }
        else{
            printf("student discount of 10%\n");
            price *= 0.9;
        }
;
    }
    else{
        if(staff){
            printf("staff discount is 20%\n");
            price = price * 0.8;
        }
        
    }
    

    printf("Total price is : $%.2f\n", price);

    return 0;
}