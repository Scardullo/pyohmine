#include <stdio.h>


enum days{
    SUNDAY = 1, MONDAY = 2, TUESDAY = 3, WEDNESDAY = 4,
    THURSDAY = 5, FRIDAY = 6, SATURDAY = 7
};

typedef enum{       // <- if you use typedef you dont have to use "enum" in main()
    SUN = 1, MON = 2, TUE = 3, WED = 4,
    THU = 5, FRI = 6, SAT = 7
}day; // <- goes down here instead


int main() {

    // enum = A user-defined data type that consists
    //        of a set of named integer constants.
    //        Benefit: Replaces numbers with readable names
    // SUNDAY = 0;
    // MONDAY = 1;
    // TUESDAY = 2;

    enum days today = WEDNESDAY;
    
    day tomorrow = SAT;

    if(today == SUNDAY || today == SATURDAY){
        printf("Its the weekend\n");
    }
    else{
        printf("Its a weekday\n");
    }

    printf("%d\n", today);
    printf("%d\n", tomorrow);


    return 0;
}