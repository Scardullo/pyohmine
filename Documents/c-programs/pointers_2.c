#include <stdio.h>

int main() {
    int age = 27;
    int *pAge = &age;

    int a = (*pAge)++;  // post-increment
    int b = ++(*pAge);  // pre-increment

    printf("After post-increment:\n");
    printf("a = %d, age = %d\n", a, age);

    printf("After pre-increment:\n");
    printf("b = %d, age = %d\n", b, age);

    return 0;
}
