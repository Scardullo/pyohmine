#include <iostream>
#include <ctime>

char getUserChoice();
char getComputerChoice();
void showChoice(char choice);
void chooseWinner(char player, char computer);


int main() {

    char player;
    char computer;
    
    player = getUserChoice();
    std::cout << "Your choice: ";
    showChoice(player);

    computer = getComputerChoice();
    std::cout << "Computers Choice: ";
    showChoice(computer);

    chooseWinner(player, computer);

    return 0;
}

char getUserChoice(){

    char player;
    std::cout << "         Rock Paper Scissors\n";
    do{
        std::cout << "Choose a letter\n";
        std::cout << "*****************************************\n";
        std::cout << "'r' for rock\n";
        std::cout << "'p' for paper\n";
        std::cout << "'s' for scissors\n";
        std::cin >> player;
    }while(player != 'r' && player != 'p' && player != 's');

    return player;
}

char getComputerChoice(){

    srand(time(0));
    int num = rand() % 3 + 1;

    switch(num){
        case 1: return 'r';
        case 2: return 'p';
        case 3: return 's';
    }
    return 0;
}

void showChoice(char choice){

    switch(choice){
        case 'r': std::cout << "Rock\n";
                  break;
        case 'p': std::cout << "Paper\n";
                  break;
        case 's': std::cout << "Scissors\n";
                  break;
    } 

}

void chooseWinner(char player, char computer){

    switch(player){
        case 'r': if(computer == 'r'){
                      std::cout << "Its a tie!\n";
                  }
                  else if(computer == 'p'){
                      std::cout << "You lose!\n";
                  }
                  else{
                      std::cout << "You Win";
                  }
                  break;
    }

    switch(player){
        case 'p': if(computer == 'r'){
                      std::cout << "You Wim!\n";
                  }
                  else if(computer == 'p'){
                      std::cout << "Its a Tie!\n";
                  }
                  else{
                      std::cout << "You Lose";
                  }
                  break;
    }

    switch(player){
        case 's': if(computer == 'r'){
                      std::cout << "You Lose!\n";
                  }
                  else if(computer == 'p'){
                      std::cout << "You Win!\n";
                  }
                  else{
                      std::cout << "Its a Tie";
                  }
                  break;
    }
}