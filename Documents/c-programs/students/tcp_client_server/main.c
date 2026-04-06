#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include "student.h"

void drawMenu(WINDOW *win,int highlight){
    char *choices[]={"Add Student","List Students","Delete Student","Edit Student","Sort by Name","Sort by Grade","Export JSON","Exit"};
    int n=8;
    box(win,0,0);
    for(int i=0;i<n;i++){
        if(highlight==i+1) wattron(win,A_REVERSE);
        mvwprintw(win,i+1,2,"%d. %s",i+1,choices[i]);
        wattroff(win,A_REVERSE);
    }
    wrefresh(win);
}

int main(){
    initscr(); noecho(); cbreak();
    int startx=0,starty=0,width=40,height=15;
    WINDOW *menuwin=newwin(height,width,starty,startx);
    keypad(menuwin,TRUE);
    int choice=0,highlight=1;

    loadFromCSV();

    while(1){
        drawMenu(menuwin,highlight);
        int c=wgetch(menuwin);
        switch(c){
            case KEY_UP: if(highlight>1) highlight--; break;
            case KEY_DOWN: if(highlight<8) highlight++; break;
            case 10:
                choice=highlight;
                if(choice==1){
                    char name[NAME_LEN]; float grade;
                    echo();
                    mvprintw(20,0,"Name: "); getnstr(name,NAME_LEN-1);
                    mvprintw(21,0,"Grade: "); scanw("%f",&grade);
                    noecho();
                    addStudent(name,grade);
                    mvprintw(22,0,"Added student."); clrtoeol(); refresh();
                } else if(choice==2){
                    clear();
                    listStudents();
                    printw("\nPress any key to return...");
                    getch();
                } else if(choice==3){
                    int id; echo(); mvprintw(20,0,"Delete ID: "); scanw("%d",&id); noecho();
                    if(deleteStudent(id)) mvprintw(21,0,"Deleted."); else mvprintw(21,0,"Not found.");
                    clrtoeol(); refresh();
                } else if(choice==4){
                    int id; char name[NAME_LEN]; float grade;
                    echo();
                    mvprintw(20,0,"ID to edit: "); scanw("%d",&id);
                    mvprintw(21,0,"New name: "); getnstr(name,NAME_LEN-1);
                    mvprintw(22,0,"New grade: "); scanw("%f",&grade); noecho();
                    if(editStudent(id,name,grade)) mvprintw(23,0,"Edited."); else mvprintw(23,0,"Not found.");
                    clrtoeol(); refresh();
                } else if(choice==5){ sortByName(); mvprintw(20,0,"Sorted by name."); clrtoeol(); refresh(); }
                else if(choice==6){ sortByGrade(); mvprintw(20,0,"Sorted by grade."); clrtoeol(); refresh(); }
                else if(choice==7){ exportToJSON(); mvprintw(20,0,"Exported JSON."); clrtoeol(); refresh(); }
                else if(choice==8){ break; }
        }
    }

    saveToCSV();
    endwin();
    return 0;
}
