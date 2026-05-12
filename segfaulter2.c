#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


int main(int argc, char **argv);

void deref(){
/* Segmentation fault by dereferencing NULL pointer */
        int *p = NULL;
        *p = 42;
}

void rec(int argc, char **argv);

void rec_help(int argc, char **argv){
    rec(argc, argv);
}

void rec(int argc, char **argv){
/* Segmentation fault by infinite recursion */
    rec_help(argc, argv);
}

void bus_hardware(){
/* Bus error by writing to read-only memory */
// sometimes a bus error on some computers 
        char * str = "Segmentation Fault!";
        str[0] = 's';

}

void twofree (){
        /* "Trace trap" by double free */
        char * s = malloc(sizeof(char) * 10);
        free(s);
        free(s);
}

void bounds () {
        /* This code does not always cause a segfault, but is still undefined behavior */
        char * s = malloc(sizeof(char) * 10);
        s[10] = 'a';
        free(s);
}

void bus() {
    const char *path = "busdemo.tmp";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror("open"); return; }

    if (ftruncate(fd, 4096) != 0) { perror("ftruncate 1"); return; }

    char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) { perror("mmap"); return; }

    if (ftruncate(fd, 0) != 0) { perror("ftruncate 2"); return; }

    volatile char c = p[0];   // usually SIGBUS here
    (void)c;

    munmap(p, 4096);
    close(fd);
    return;
}

// write to protected memory
void wonprot(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) return;

    char *buf = mmap(NULL, page, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        perror("mmap");
        return;
    }

    if (mprotect(buf, page, PROT_NONE) != 0) {
        perror("mprotect");
        munmap(buf, page);
        return;
    }

    buf[0] = 'x';   // should raise SIGSEGV
    munmap(buf, page);
}

int main(int argc, char **argv) {
    char* type = argv[1];
    if (type == NULL) {
        printf("Usage: %s <type>\n", argv[0]);
        printf("Types: deref, rec, bus, 2free, bounds, wonprot\n");
        return 1;
    } else if(strcmp(type, "deref") == 0) {
        deref();
    } else if(strcmp(type, "rec") == 0) {
        rec(argc, argv);
    } else if(strcmp(type, "bus") == 0) {
        bus();
    } else if(strcmp(type, "2free") == 0) {
        twofree();
    } else if(strcmp(type, "bounds") == 0) {
        bounds();
    } else if(strcmp(type, "wonprot") == 0){
        wonprot();
    } else if (strcmp(type, "next") == 0){

    } else {
        printf("Unknown type: %s\n", type);
        printf("Types: deref, rec, bus, 2free, bounds, wonprot\n");
        return 1;
    }
    return 0;
}