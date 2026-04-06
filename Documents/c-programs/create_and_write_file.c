#include <stdio.h>

int main() {

    FILE *pFile = fopen("/home/anthony/Documents/output.txt", "w");

    char text[] = "Arch linux\nLinux/GNU";

    if(pFile == NULL){
        printf("User Error\n");
        return 1;
    }

    fprintf(pFile, "%s", text);
    printf("File Written\n");

    fclose(pFile);

    return 0;
}