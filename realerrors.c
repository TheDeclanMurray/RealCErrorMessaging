#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <inttypes.h>
#include <execinfo.h>
#include <sys/resource.h>


// #include <sys/siginfo.h>

#include "symaddr.h"

#define BUF_SIZE 2048
#define MAX_STRARR_LEN 8

#define NUMBER 0
#define STRING 1
#define STRARR 2
#define POINTER 3

#define RDI regs.rdi
#define RSI regs.rsi
#define RDX regs.rdx
#define R10 regs.r10
#define R8  regs.r8
#define R9  regs.r9 

#define ENDER "STR_END"
#define LOG_FILE 0

// used to pass a list of pointers between functions
typedef struct {
    uint64_t data[MAX_STRARR_LEN];
    size_t    length;
} uint64_array_t;

char child_process_name[128] = "\0";

int main(int argc, char** argv) {
    // Call fork to create a child process
    pid_t child_pid = fork();
    if(child_pid == -1) {
        perror("fork failed");
        exit(2);
    }

    // get command
    char* cmd = argv[1];
    strcpy(child_process_name, argv[1]);

    // create NULL terminated list of args
    char* args[argc];
    for(int i = 1; i < argc; i++){
        args[i-1] = argv[i];
    }
    args[argc - 1] = NULL;

    // If this is the child, ask to be traced
    if(child_pid == 0) {
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace traceme failed");
            exit(2);
        }

        // Stop the process so the tracer can catch it
        raise(SIGSTOP);

        // attatch tracee Library 
        setenv("LD_PRELOAD", "traceeLib.so", 1); 


        // run the args
        if(execvp(cmd, args)) {
            perror("execvp failed");
            exit(2);
        }

    } else {
        // Wait for the child to stop

        // Redirect ALL printf() to log for the tracer
        if (LOG_FILE){
            FILE *logfile = freopen("syscall_trace.log", "w", stdout);
            if (!logfile) {
                perror("Failed to open logfile");
                exit(2);
            }
            setvbuf(stdout, NULL, _IONBF, 0);  // Disable buffering for real-time logging
        }

        // track child status
        int status;
        int result;
        do {
            result = waitpid(child_pid, &status, 0);
            if(result != child_pid) {
                perror("waitpid failed");
                exit(2);
            }
        } while(!WIFSTOPPED(status));

        // We are now attached to the child process
        if (LOG_FILE) printf("Attached!\n");

        // loop vars
        bool running = true;
        int last_signal = 0;

        // Now repeatedly resume and trace the program
        while(running) {
            // Continue the process, delivering the last signal we received (if any)
            if(ptrace(PTRACE_SYSCALL, child_pid, NULL, last_signal) == -1) {
                perror("ptrace CONT failed");
                exit(2);
            }

            // No signal to send yet
            last_signal = 0;

            // Wait for the child to stop again
            if(waitpid(child_pid, &status, 0) != child_pid) {
                perror("waitpid failed");
                exit(2);
            }

            if(WIFEXITED(status)) {
                printf("User Program exited with status %d\n", WEXITSTATUS(status));
                running = false;
            } else if(WIFSIGNALED(status)) {
                int sig = WTERMSIG(status);
                printf("User Program terminated with signal %d (%s)\n", sig, strsignal(sig));
                running = false;
            } else if(WIFSTOPPED(status)) {
                // Get the signal delivered to the child
                last_signal = WSTOPSIG(status);

                if(last_signal == SIGSEGV){
                    if (LOG_FILE) printf("signal is SIGSEGV\n");
                    // handle segfault
                    
                    siginfo_t info;
                    ptrace(PTRACE_GETSIGINFO, child_pid, 0, &info);
                    uintptr_t faultingMemAddress = (uintptr_t) info.si_addr;

                    if(faultingMemAddress == 0){
                        if (LOG_FILE) printf("Null Pointer Deref\n");
                        continue;
                    }

                    if (LOG_FILE) printf("Faulting memory address: %p\n", (void *) faultingMemAddress);

                    // read maps to get perms
                    char buf[256];
                    snprintf(buf, 256, "/proc/%d/maps", child_pid);
                    FILE *fp = fopen(buf, "r");
                    if (!fp) return 0;
                    uintptr_t stack_start, stack_end;
                    uintptr_t start, end;
                    char perms[5];
                    char name[256];
                    char line[1024];
                    while (fgets(line, sizeof(line), fp)) {
                        // printf("%s", line);
                        strcpy(name, "Anonomous Memory (Likely Malloc or MMAP, posible Guard Page)");
                        sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*u %255[^\n]", &start, &end, perms, name);
                        if (faultingMemAddress >= start && faultingMemAddress < end){
                            if (LOG_FILE) printf("Incorrect Memory Access happened in %s\n", name);
                            printf("File Permissions are %s\n", perms);
                        }

                        if (strcmp(name, "[stack]")){
                            stack_start = start;
                            stack_end = end;
                        }
                    }
                    fclose(fp);

                    if (LOG_FILE) printf("stack Addr Range: %p - %p\n", (void*) stack_start, (void*) stack_end);

                    // get register info
                    struct user_regs_struct regs;
                    uintptr_t rip;
                    if (ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) == -1) {
                        perror("ptrace(GETREGS) failed");
                    } else {
                        rip = (uintptr_t)regs.rip;
                        if (LOG_FILE) printf("RIP: %p\n", (void *)rip);
                    }

                    // seg fault types
                    switch (info.si_code)
                    {
                    case SEGV_MAPERR:
                        // address not mapped at all
                        if (faultingMemAddress < stack_start && faultingMemAddress /* > stack_start - 0x10000 */){
                            // likely a stack overflow, fault just below the stack
                            if (LOG_FILE) printf("Stack Overflow\n");

                            // get tracee lib variable location
                            uintptr_t slot = get_tracee_symbol_addr(child_pid, "traceeLib.so", "./traceeLib.so", "pending_addr");
                            if (!slot) {
                                fprintf(stderr, "failed to resolve symbol address\n");
                            } else {
                                // put rip info into the tracee var location
                                if (ptrace(PTRACE_POKEDATA, child_pid, (void *)slot, (void *)rip) == -1) {
                                    perror("ptrace(POKEDATA) failed");
                                }
                            }
                            last_signal = SIGUSR1;
                            continue;
                        } else {
                            printf("Access to Unmapped Memory. TBD\n");
                        }
                        break;
                    case SEGV_ACCERR:
                        // perms error rwxp
                        if (faultingMemAddress == rip){
                            // failed on attempt to executre code in memory
                            if (perms[2] == 'x'){
                                printf("Address Space has Execute Permisions, IDK Cause of Problem\n");
                            } else {
                                printf("Code attempted to execute code by jumping to memory with execution permisons disallowed.\n");
                            }
                        } else {
                            // read or write error
                            if (perms[1] == 'w'){
                                if (perms[0] == 'r'){
                                    printf("Address space is Readable and Writable, IDK cause of Problem\n");
                                } else{
                                    printf("Address Space is Not Readable\n");
                                }
                            } else {
                                // TODO: see why this is inconsistant
                                if (perms[0] == 'r'){
                                    printf("Address Space is Not Writable\n");
                                } else {
                                    printf("Address Space is Not Readable or Writeable\n");
                                }
                            }
                        }
                        break;
                    default:
                        break;
                    }
                        
                    continue;
                }

                if (last_signal == SIGBUS){
                    printf("User Program hit a Bus Error\n");
                    
                    siginfo_t si;
                    if (ptrace(PTRACE_GETSIGINFO, child_pid, 0, &si) == -1) {
                        perror("PTRACE_GETSIGINFO");
                        exit(EXIT_FAILURE);
                    }

                    // if (si.si_signo == SIGBUS) {
                    //     if (__linux__){
                    //         printf("  fault address: %p\n", si.si_addr);
                    //     } else{
                    //         printf("  signal stop: signo=%d si_code=%d\n", si.si_signo, si.si_code);
                    //     }
                    // }

                    // add sig handler for SIGBUS with custom user info
                    last_signal = SIGSEGV;

                    continue;
                }

                // If the signal was a SIGTRAP, we stopped because of a system call
                if(last_signal == SIGTRAP) {
                    // Read register state from the child process
                    struct user_regs_struct regs;
                    if(ptrace(PTRACE_GETREGS, child_pid, NULL, &regs)) {
                        perror("ptrace GETREGS failed");
                        exit(2);
                    }

                    // Get the system call number
                    size_t syscall_num = regs.orig_rax;
                    
                    
                    // clear sys_call_args for next run
                    // for (int i = 0; i < 7; i++){
                    //     strcpy(sys_call_args[i], ENDER);
                    // }

                    // handle each system call number used
                    switch (syscall_num) {
                        case 0:
                            // strcpy(syscall_name, "read");
                            // strcpy(sys_call_args[0], syscall_name);
                            // cstr(child_pid, RDI, NUMBER, sys_call_args[1]);
                            // cstr(child_pid, RSI, POINTER, sys_call_args[2]);
                            // cstr(child_pid, RDX, NUMBER, sys_call_args[3]);
                            // outputType = NUMBER;
                            break;
                        default:
                            // printf("Unknown syscall Number: %zu\n", syscall_num);
                            break;
                    }
                }
                last_signal = 0;
            }
        }
    }
    return 0;
}
