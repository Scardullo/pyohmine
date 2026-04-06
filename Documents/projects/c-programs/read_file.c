#include <stdio.h>

int main() {

    FILE *pFile = fopen("/home/anthony/Documents/input.txt", "r");
    char buffer[1024] = {0};

    if(pFile == NULL){
        printf("User Error\n");
        return 1;
    }

    while(fgets(buffer, sizeof(buffer), pFile) != NULL){  // <- NULL is when there is nothing
        printf("%s", buffer);                              //    left to read in the file
    }


    fclose(pFile);

    return 0;
}