#include <stdio.h>
#include <stdlib.h>
#include "student.h"

void menu() {
    printf("\n==== Student Management System v6 ===="
           "\n1. Add Student"
           "\n2. Display Students"
           "\n3. Search Student by ID"
           "\n4. Search Student by Name"
           "\n5. Edit Student"
           "\n6. Delete Student"
           "\n7. Sort by Name"
           "\n8. Sort by Grade"
           "\n9. Show Stats"
           "\n10. Save to File"
           "\n11. Load from File"
           "\n12. Export to JSON"
           "\n13. Undo Last Delete"
           "\n14. Exit"
           "\n====================================\n");
}

void showStats() {
    if (!head) {
        printf("No student records found.\n");
        return;
    }
    float avg = getAverageGrade();
    Student *top = getTopStudent();
    Student *low = getLowestStudent();

    printf("\nAverage Grade: %.2f\n", avg);
    if (top) printf("Top Student: %s (%.2f)\n", top->name, top->grade);
    if (low) printf("Lowest Student: %s (%.2f)\n", low->name, low->grade);
}

int main() {
    loadFromCSV(); // load saved data at startup
    int choice;

    do {
        menu();
        printf("Enter your choice: ");
        if (scanf("%d", &choice) != 1) {
            printf("Invalid input! Please enter a number.\n");
            while (getchar() != '\n'); // clear input buffer
            continue;
        }

        switch (choice) {
            case 1: addStudent(); break;
            case 2: displayStudents(); break;
            case 3: searchById(); break;
            case 4: searchByName(); break;
            case 5: editStudent(); break;
            case 6: deleteStudent(); break;
            case 7: sortStudentsByName(); break;
            case 8: sortStudentsByGrade(); break;
            case 9: showStats(); break;
            case 10: saveToCSV(); break;
            case 11: loadFromCSV(); break;
            case 12: exportToJSON(); break;
            case 13: undoLastDelete(); break;
            case 14:
                printf("Exiting program... Goodbye!\n");
                saveToCSV();
                freeList();
                break;
            default:
                printf("Invalid choice. Please try again.\n");
        }

    } while (choice != 14);

    return 0;
}
