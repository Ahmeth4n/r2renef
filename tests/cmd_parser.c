#include <stdio.h>
#include <string.h>

int main(){ 
    char str[] = "renef://spawn/io.byterialab.moduletest";

    char *first = strtok(str, "://");   // "renef"
    char *second = strtok(NULL, "/"); // "spawn"
    char *third = strtok(NULL, "/"); // "spawn"

    printf("renef part: %s\n", first);
    printf("event: %s\n", second);
    printf("package or pid: %s\n", third);
    
    return 0;
}