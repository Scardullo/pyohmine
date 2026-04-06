#include <stdio.h>
#include <ctype.h>

int main() {

    char questions[][100] = {"Largest Planet ?",
                             "Hottest Planet ?",
                             "Most Moons ?",
                             "Most Famous ?"};

    char options[][100]= {"A. Jupiter\nB. Saturn\nC. Uranus\nD. Neptune",
                          "A. Mercury\nB. Venus\nC. Pluto\nD. Mars",
                          "A. Jupiter\nB. Earth\nC. Earth\nD. Saturn",
                          "A. Saturn\nB. Earth\nC. Alaska\nD. Venus"};

    char answerkey[] = {'A', 'B', 'D', 'B'};

    int questionCount = sizeof(questions) / sizeof(questions[0]);

    char guess = '\0';
    int score = 0;

    for(int i = 0; i < questionCount; i++){
        printf("%s\n", questions[i]);
        printf("\n%s\n", options[i]);
        printf("Enter Choice: ");
        scanf(" %c", &guess);

        guess = toupper(guess); // <- converts lower case to upper

        if(guess == answerkey[i]){
            printf("Correct\n");
            score++;
        }
        else{
            printf("Wrong\n");
        }
  
    }

    printf("\nScore: %d out of %d\n", score, questionCount);

    return 0;

}