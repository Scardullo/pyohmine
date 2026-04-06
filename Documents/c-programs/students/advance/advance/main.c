#include <stdio.h>
#include "student.h"

void menu() {
    printf(
        "\n==== Student Management System ====\n"
        "1. Add Student\n"
        "2. Display Students\n"
        "3. Search by ID\n"
        "4. Search by Name\n"
        "5. Edit Student\n"
        "6. Delete Student\n"
        "7. Sort by Name\n"
        "8. Sort by Grade\n"
        "9. Statistics\n"
        "10. Save CSV\n"
        "11. Load CSV\n"
        "12. Export JSON\n"
        "13. Save Binary\n"
        "14. Load Binary\n"
        "15. Backup\n"
        "16. Restore\n"
        "17. Undo\n"
        "18. Redo\n"
        "19. Exit\n"
        "Choice: "
    );
}

int main() {
    int c;
    loadFromCSV();

    do {
        menu();
        scanf("%d", &c);
        switch (c) {
            case 1: addStudent(); break;
            case 2: displayStudents(); break;
            case 3: searchById(); break;
            case 4: searchByName(); break;
            case 5: editStudent(); break;
            case 6: deleteStudent(); break;
            case 7: sortStudentsByName(); break;
            case 8: sortStudentsByGrade(); break;
            case 9:
                printf("Avg: %.2f\n", getAverageGrade());
                printf("Median: %.2f\n", getMedianGrade());
                printf("StdDev: %.2f\n", getStdDev());
                if (getTopStudent())
                    printf("Top: %s\n", getTopStudent()->name);
                if (getLowestStudent())
                    printf("Low: %s\n", getLowestStudent()->name);
                break;
            case 10: saveToCSV(); break;
            case 11: loadFromCSV(); break;
            case 12: exportToJSON(); break;
            case 13: saveToBinary(); break;
            case 14: loadFromBinary(); break;
            case 15: backupData(); break;
            case 16: restoreBackup(); break;
            case 17: undo(); break;
            case 18: redo(); break;
        }
    } while (c != 19);

    freeList();
    return 0;
}
