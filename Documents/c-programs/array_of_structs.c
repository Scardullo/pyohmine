#include <stdio.h>

typedef struct{
    char model[25];
    int year;
    int price;
}Car;

int main() {

    // array of structs = Array where each element contains a struct {}
    //                    Helps organize and group together related data


    Car cars[]= {{"Mustang", 2025, 32000},
                 {"Corvette", 2026, 68000},
                 {"Challenger", 2024, 29000}};



    int number = sizeof(cars) / sizeof(cars[0]);

    for(int i = 0; i < number; i++){
        printf("%s %d $%d\n", cars[i].model, cars[i].year, cars[i].price);
    }

    return 0;
}