#include <iostream>
#include <iomanip>

void showbalance(double balance);
double deposit();
double withdraw(double balance);

int main() {

    double balance = 200.00;
    int choice = 0;
    do{
        std::cout << "********* ATM ***********\n";
        std::cout << "Enter option: \n";
        std::cout << "1. Show Balance\n";
        std::cout << "2. Deposit\n";
        std::cout << "3. Withdraw\n";
        std::cout << "4. Exit\n";
        std::cin >> choice;
        
        std::cin.clear();   // <- resets error flags when stdin fails to interpret input
        fflush(stdin);      // <- clears input buffer (theres a '\n' character in input buffer)

        switch(choice){
            case 1: showbalance(balance);
                    break;
            case 2: balance += deposit();
                    showbalance(balance);
                    break;
            case 3: balance -= withdraw(balance);
                    showbalance(balance);
                    break;
            case 4: std::cout << "Thank You\n";
                    break;
            default: std::cout << "Invalid Option\n";
        }
    }while(choice != 4);

    return 0;
}

void showbalance(double balance){
        std::cout << "Balance: $" << std::setprecision(2) << std::fixed << balance << '\n';
}

double deposit(){
    double amount = 0;

    std::cout << "Enter deposit: ";
    std::cin >> amount;

    if(amount > 0){
        return amount;
    }
    else{
        std::cout << "Invalid amount: ";
        return 0;
    }   
}

double withdraw(double balance){
    
    double amount = 0;
    
    std::cout << "Enter amount to Withdrawl: ";
    std::cin >> amount;

    if(amount > balance){
        std::cout << "Insufficient Funds\n";
        return 0;
    }
    else if(amount < 0){
        std::cout << "Invalid\n";
        return 0;
    }
    else{
        return amount;
    }
    
}