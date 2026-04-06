#include <stdio.h>
#include <string.h>

int main() {

    char item[50] = "";
    float price = 0.0f;
    int quantity = 0;
    char currency = '$';
    float total = 0.0f;

    printf("Enter item: ");
    fgets(item, sizeof(item), stdin);
    item[strlen(item) - 1] = '\0';

    printf("price?: ");
    scanf("%f", &price);

    printf("Quantity?: ");
    scanf("%d", &quantity);

    total = price * quantity;

    printf("\nPurchased: %d %s/s\n", quantity, item);
    printf("Total: %c%.2f", currency, total);

    return 0;
}