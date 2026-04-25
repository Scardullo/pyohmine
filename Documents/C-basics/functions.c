#include <stdio.h>
#include <string.h>

void bootloader(char x[], float y){

    printf("start %s\n", x);
    printf("load initramfs\n");
    printf("load kernel %.2f\n", y);
    printf("start OS\n");
    printf("start zshell\n");

}

int main() {

    char boot[50] = "";
    float kernel = 0.0;

    printf("Enter GRUB or systemd: ");
    fgets(boot, sizeof(boot), stdin);
    boot[strlen(boot) -1] = '\0';

    printf("Enter kernel version: ");
    scanf("%f", &kernel);

    bootloader(boot, kernel);

    return 0;
}