#include <stdio.h>
#include <stdbool.h>

int getmax(int x, int y){

    if(x >= y){
        return x;
    }
    else{
        return y;
    }
}

bool agecheck(int age){

    if(age >= 18){
        return true;
    }
    else{
        return false;
    }
}

int square(int num){
    int result = num * num;
    //return num * num;     // <- does same
    return result;
}

double cube(double num){
    return num * num * num;
}

int main() {

    int max = getmax(5,3);

    printf("%d\n", max);

    int age = 21;

    if(agecheck(age)){
        printf("access granted\n");
    }
    else{
        printf("access denied\n");
    }

    //int x = 2 * 2;
    //int y = 3 * 3;
    //int z = 4 * 4;

    double a = cube(2.1);
    double b = cube(3.2);
    double c = cube(4.3);

    int x = square(2);
    int y = square(3);
    int z = square(4);


    printf("%d\n", x);
    printf("%d\n", y);
    printf("%d\n", z);

    printf("%lf\n", a);
    printf("%lf\n", b);
    printf("%lf\n", c);

    return 0;
}