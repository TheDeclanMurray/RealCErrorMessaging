#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char* type = argv[1];
    if (type == NULL) {
        printf("Usage: %s <type>\n", argv[0]);
        printf("Types: segfault_deref, segfault_rec, buserror, trap, works_somehow\n");
        return 1;
    } else if(strcmp(type, "segfault_deref") == 0) {
        /* Segmentation fault by dereferencing NULL pointer */
        int *p = NULL;
        *p = 42;
    } else if(strcmp(type, "segfault_rec") == 0) {
        /* Segmentation fault by infinite recursion */
        main(argc, argv);
    } else if(strcmp(type, "buserror") == 0) {
        /* Bus error by writing to read-only memory */
        char * str = "Segmentation Fault!";
        str[0] = 's';
    } else if(strcmp(type, "trap") == 0) {
        /* "Trace trap" by double free */
        char * s = malloc(sizeof(char) * 10);
        free(s);
        free(s);
    } else if(strcmp(type, "segfault_outofbounds") == 0) {
        /* This code does not always cause a segfault, but is still undefined behavior */
        char * s = malloc(sizeof(char) * 10);
        s[120000000] = 'a';
        printf("%c\n", s[120000000]); 
        free(s);
    } else {
        printf("Unknown type: %s\n", type);
        printf("Types: segfault_deref, segfault_rec, buserror, trap, works_somehow\n");
        return 1;
    }
    return 0;
}