#include <stdio.h>
#include <string.h>

int main() {

    char names[4][25] = {0};    // <- if an array is going to be empty when
                                // declared, both col and row need to be set
    
    for(int i = 0; i < sizeof(names) / sizeof(names[0]); i++){
        printf("Enter a name: ");
        fgets(names[i], sizeof(names[i]), stdin);
        names[i][strlen(names[i]) - 1] = '\0';
    }

    for(int i = 0; i < sizeof(names) / sizeof(names[0]); i++){
        printf("%s\n", names[i]);
    }

    char fruits[][10] = {"linux-lts",
                         "unix", 
                         "archlinux", 
                         "linux", 
                         "kernel"};

    int size = sizeof(fruits) / sizeof(fruits[0]);

    fruits[1][0] = 'U';
    
    for(int i = 0; i < size; i++){
        printf("%s\n", fruits[i]);
    }


    return 0;
}