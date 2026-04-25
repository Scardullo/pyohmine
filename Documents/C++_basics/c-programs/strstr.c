#include <stdio.h>
#include <string.h>

int main () {

    char name[] = "Anthony Scardullo";
    char keyword[] = "car";

    char *result = strstr(name, keyword);

    if (result)
        printf("Found at: %s\n", result);
    else
        printf("Not found\n");

}