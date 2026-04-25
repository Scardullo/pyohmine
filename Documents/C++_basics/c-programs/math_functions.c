#include <math.h>
#include <stdio.h>
#include <stdlib.h>

int main() {

    //int x = 9;
    //float x = 3.99;
    float x = 45;
    float y = 3.14;
    float z = 3.14;

    //x = sqrt(x);
    //x = pow(x, 2);
    //x = floor(x);
    //x = abs(x);
    //x = log(x);
    //x = sin(x);
    //x = cos(x);
    x = tan(x);
    y = round(y);
    z = ceil(z);

    printf("%f", x);
    printf("\n");
    printf("%.2f", y);
    printf("\n");
    printf("%.2f", z);


    return 0;
}