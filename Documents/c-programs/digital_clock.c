#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>

int main() {

    time_t rawtime = 0;  // time_t is UNIX Epoch (UTC Jan 1st 1970)
    struct tm *pTime = NULL;
    bool running = true;

    printf("DIGITAL CLOCK\n");

    while(running){

        time(&rawtime);

        pTime = localtime(&rawtime);

        printf("%02d:%02d:%02d\n", pTime->tm_hour, pTime->tm_min, pTime->tm_sec); 
            //  ^ carriage return     // ^ shortcut to:   printf("%d:%d:%d", (*pTime).tm_hour);
            //  ^ not working
        
            sleep(1);
    }


    return 0;
}