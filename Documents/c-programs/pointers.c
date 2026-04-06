#include <stdio.h>

void birthday(int* age);

int main() {

    // pointer = A variable that stores the memory address of another variable.
    //           Benefit: They help avoid wasting memory by allowing you to pass
    //           the address of a large data structure instead of copying the entire data.

    int age = 27;
    int *pAge = &age;  // <- wouldnt need this if passing "&age" into the function below

    birthday(pAge);    // <- either of these 
    //birthday(&age);  //    two work the same

    printf("You are %d years old", age);

    return 0;
}

void birthday(int* age){
    // C uses pass-by-value, but passing a pointer simulates pass-by-reference
    (*age)++;  // <- by adding parenthesis we are forcing operator precedence,
}              //    without them we would dereference first, then increment the pointer
	       //    which would keep age at 27
