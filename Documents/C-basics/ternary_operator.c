#include <stdio.h>
#include <stdbool.h>

int main() {

    // ternary operator = shorthand for if-else statements

    // (condition) ? value_if_true : value_if_false;

    bool online = true;

    int num = 8;

    int x = 9;
    int y = 7;
    int max = (x > y) ? x : y;

    int age = 21;

    int hours = 11;
    int minutes = 3;

    printf("%s", (online) ? "online\n" : "offline\n");

    printf("%d is %s", num, (num % 2 == 0) ? "even\n" : "odd\n");

    printf("%d", max);

    printf("%s", (age > 18) ? "adult\n" : "child\n");

    printf("%02d:%02d %s", hours, minutes, (hours < 12) ? "AM" : "PM");
        //   ^    ^  "%02d" adds 0 for padding: prints "11:03" not "11: 3"

    return 0;
}