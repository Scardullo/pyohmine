#include <stdio.h>

// format specifiers can set the width , precision, and flags

int main() {

    int age = 25;
    float price = 19.99;
    double pi = 3.141591823;
    char currency = '$';
    char name[] = "anthony";

    printf("\n");

    printf("%d\n", age);
    printf("%f\n", price);
    printf("%lf\n", pi);
    printf("%c\n", currency);
    printf("%s\n", name);

    int num1 = 1;
    int num2 = 10;
    int num3 = 100;

    printf("%-3d\n", num1);
    printf("%-3d\n", num2);
    printf("%-3d\n", num3);

    printf("\n");

    printf("%3d\n", num1);
    printf("%3d\n", num2);
    printf("%3d\n", num3);

    printf("\n");

    printf("%03d\n", num1);
    printf("%03d\n", num2);
    printf("%03d\n", num3);

    printf("\n");

    int neg_num = -100;
    int pos_num = 100;

    printf("%+d\n", neg_num);   // <-  "+" adds + or - in front 
    printf("%+d\n", pos_num);   //      of num to show if pos or neg

    printf("\n");

    float price1 = 19.99;
    float price2 = 1.50;
    float price3 = -100.00;

    printf("%f\n", price1);     // default behavior of C is to 
    printf("%f\n", price2);     // place 6 digits after decimal
    printf("%f\n", price3);

    printf("\n");

    printf("%.2f\n", price1);   //  <- ".(n)" to specify digits
    printf("%.2f\n", price2);   //       after decimal
    printf("%.2f\n", price3);   // if this was ".1(n)" output 
                                // gets rounded ex. 19.99 = 20.0
    printf("\n");
    printf("%.1f\n", price1);   // ".1(n)" 19.99 = 20.0 (rounded)

    printf("\n");
    printf("%7.2f\n", price1);  // the "7" here is the min width
    printf("%7.2f\n", price2);  
    printf("%7.2f\n", price3);

    return 0;
}