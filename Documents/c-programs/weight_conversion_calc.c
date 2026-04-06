#include <stdio.h>

int main() {

    int choice = 0;
    float pounds = 0.0f;
    float kilograms = 0.0f;

    printf("Weight Conversion Calculator\n");
    printf("1. Kilograms to pounds\n");
    printf("2. pounds to kilograms\n");
    printf("Enter choice (1 or 2): ");
    scanf("%d", &choice);

    if(choice == 1){
        // kilo to lbs
        printf("Enter weight in kilograms: ");
        scanf("%f", &kilograms);
        pounds = kilograms * 2.20462;
        printf("%.2f kilograms is equal to %.2f pounds\n", kilograms, pounds);
    }
    else if(choice == 2){
        // lbs to kilo
        printf("Enter weight in pounds: ");
        scanf("%f", &pounds);
        kilograms = pounds / 2.20462;
        printf("%.2f pounds is equal to %.2f kilograms\n", pounds, kilograms);
    }
    else{
        printf("Invalid Choice!");
    }


    return 0;
}