#include <stdio.h>
#include <stdlib.h>
#include "student.h"

int main() {
    int choice;
    loadFromCSV();

    do {
        printf("\n=== Student Management System v5 ===\n");
        printf("1. Add Student\n");
        printf("2. View Students\n");
        printf("3. Search by ID\n");
        printf("4. Search by Name\n");
        printf("5. Delete Student\n");
        printf("6. Edit Student\n");
        printf("7. Sort by Name\n");
        printf("8. Sort by Grade\n");
        printf("9. Statistics\n");
        printf("0. Exit\n");
        printf("Enter choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1: addStudent(); break;
            case 2: viewStudents(); break;
            case 3: searchById(); break;
            case 4: searchByName(); break;
            case 5: deleteStudent(); break;
            case 6: editStudent(); break;
            case 7: sortStudentsByName(); break;
            case 8: sortStudentsByGrade(); break;
            case 9: {
                float avg = getAverageGrade();
                Student *top = getTopStudent();
                Student *low = getLowestStudent();
                printf("\n--- Statistics ---\n");
                printf("Average Grade: %.2f\n", avg);
                if (top) printf("Top Student: %s (%.2f)\n", top->name, top->grade);
                if (low) printf("Lowest Student: %s (%.2f)\n", low->name, low->grade);
                break;
            }
            case 0:
                printf("Goodbye!\n");
                saveToCSV();
                break;
            default:
                printf("Invalid choice!\n");
        }
    } while (choice != 0);

    freeList();
    return 0;
}
