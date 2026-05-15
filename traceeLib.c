#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <execinfo.h>
#include <errno.h>
#include <ucontext.h>
#include <inttypes.h>

#include "trace_symbolizer.h"
#include "memHelper.h"

uintptr_t pending_addr;

typedef struct {
    void  *mapping;      // start of full mapping (guard + usable)
    void  *stack_bottom; // lowest usable address
    size_t stack_size;   // usable stack bytes
    size_t total_size;    // total mapping bytes
} recovery_stack_t;

// recovery stack vars
static stack_t ss;
static recovery_stack_t g_rs;
static int g_rs_ready = 0;
static ucontext_t g_recovery_uc;
static ucontext_t g_handler_uc;

static void recovery_entry(void);
void secondary_stack_handler(int signal, siginfo_t *info, void *ctx);
void segfault_handler(int signal, siginfo_t *info, void *ctx);

int allocate_recovery_stack(recovery_stack_t *out, size_t usable_size) {
    if (!out || usable_size == 0) return -1;

    long pagesz = sysconf(_SC_PAGESIZE);
    if (pagesz <= 0) return -2;

    size_t page = (size_t)pagesz;
    size_t rounded = (usable_size + page - 1) & ~(page - 1);
    size_t total = rounded + page;

    // map new mem to act as our stack for recovery purposes
    void *mem = mmap(NULL, total, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return -3;

    if (mprotect(mem, page, PROT_NONE) != 0) {
        munmap(mem, total);
        return -4;
    }

    out->mapping = mem;
    out->stack_bottom = (char *)mem + page;
    out->stack_size = rounded;
    out->total_size = total;
    return 0;
}

static int setup_recovery_context(void) {
    if (getcontext(&g_recovery_uc) == -1) return -1;

    g_recovery_uc.uc_stack.ss_sp = g_rs.stack_bottom;
    g_recovery_uc.uc_stack.ss_size = g_rs.stack_size;
    g_recovery_uc.uc_stack.ss_flags = 0;
    g_recovery_uc.uc_link = NULL;

    makecontext(&g_recovery_uc, recovery_entry, 0);
    return 0;
}

__attribute__((constructor)) void init(void)
{
    // allocate the recovery stack for overflow errors
    if (allocate_recovery_stack(&g_rs, 1 << 20) != 0) {
        perror("allocate recovery stack");
        exit(EXIT_FAILURE);
    }
    g_rs_ready = 1;

    // create another context to switch to 
    if (setup_recovery_context() != 0) {
        perror("setup_recovery_context");
        _exit(EXIT_FAILURE);
    }

    ss.ss_sp = malloc(SIGSTKSZ);
    if (ss.ss_sp == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) == -1) {
        perror("sigaltstack");
        exit(EXIT_FAILURE);
    }

    struct sigaction sa;

    // settup signal handlers
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segfault_handler;
    sa.sa_flags = SA_SIGINFO;   // main stack
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        perror("sigaction SIGSEGV");
        exit(EXIT_FAILURE);
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = secondary_stack_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;   // alternate stack
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        perror("sigaction SIGUSR1");
        exit(EXIT_FAILURE);
    }
}


// when code finishes
// node this does not run when we exit()
__attribute__((destructor))
void fini(void) {
    // runs after main() returns, before process exits
    printf("Program exiting!\n");

    // disable the extra stack space
    stack_t disable = {0}; 
    disable.ss_flags = SS_DISABLE; 
    sigaltstack(&disable, NULL); 

    // free memory that the lib allocated
    free(ss.ss_sp); 
    ss.ss_sp = NULL;

    // get the mem leaks
    // this function is not fully opperational, there is something in our code that allocates but does not free
    // check_memory_leaks();
}

static void recovery_entry(void) {
    // minimal function to handle stack overflows
    write(STDERR_FILENO, "Stack Overflow Related to: ", 36);
    print_location((void*) pending_addr);
    _exit(EXIT_FAILURE); 
}

void secondary_stack_handler(int signal, siginfo_t *info, void *ctx){
    // signal handler for stack overflows
    swapcontext(&g_handler_uc, &g_recovery_uc);
    _exit(EXIT_FAILURE);
}

void segfault_handler(int signal, siginfo_t *info, void *ctx){
    // printf("Real Erros Handling Seg Fault\n");
    intptr_t seg_fault_address = (intptr_t)(info->si_addr);

    // do the trace using the real malloc
    set_disable_tracking(1);
    printf("Stack Trace:\n");
    if (!print_stack()){
        printf("Failed, trying mem location:\n");
        if (print_location((void*) pending_addr) != 0){
            printf("Location Print Also Failed.\n");
        }
    }
    set_disable_tracking(0);

    // give info
    if(seg_fault_address == 0){
        printf("Null Pointer Dereference Error\n");
    } 

    _exit(EXIT_FAILURE);
}