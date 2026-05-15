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

#include "symaddr.h"

// gloable variables for testing
#define LOG_FILE 0

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
        // TODO add to end of preload
        // Note this may override LD_PRELOAD
        // TODO: add this to the existing list of Preloaded libs
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
                    
                    // get memory access address
                    siginfo_t info;
                    ptrace(PTRACE_GETSIGINFO, child_pid, 0, &info);
                    uintptr_t faultingMemAddress = (uintptr_t) info.si_addr;

                    // this is a Null Pointer Deref
                    if(faultingMemAddress == 0){
                        if (LOG_FILE) printf("Null Pointer Deref\n");
                        // rest of code does not pertain to this error, continue
                        continue;
                    }

                    if (LOG_FILE) printf("Faulting memory address: %p\n", (void *) faultingMemAddress);

                    // read maps to get perms
                    char buf[256];
                    snprintf(buf, 256, "/proc/%d/maps", child_pid);
                    FILE *fp = fopen(buf, "r");
                    if (!fp) return 0;

                    // vars to fill
                    uintptr_t stack_start, stack_end;
                    uintptr_t start, end;
                    char perms[5];
                    char name[256];
                    char line[1024];
                    while (fgets(line, sizeof(line), fp)) {
                        // get the details about particular memory locations
                        strcpy(name, "Anonomous Memory (Likely Malloc or MMAP, posible Guard Page)");
                        sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*u %255[^\n]", &start, &end, perms, name);
                        if (faultingMemAddress >= start && faultingMemAddress < end){
                            // if the memory access happened in a partiular section 
                            if (LOG_FILE) printf("Incorrect Memory Access happened in %s\n", name);
                            printf("File Permissions are %s\n", perms);
                            continue;
                        }

                        if (strcmp(name, "[stack]")){
                            stack_start = start;
                            stack_end = end;
                        }
                    }
                    fclose(fp);

                    if (LOG_FILE) printf("Stack Addr Range: %p - %p\n", (void*) stack_start, (void*) stack_end);

                    // get rip register info
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

                            // set a particular signal to run a handler in its own stack
                            last_signal = SIGUSR1;
                            continue;
                        } else {
                            // relivent info for non segfaults is above
                        }
                        break;
                    case SEGV_ACCERR:
                        // perms error rwxp
                        if (faultingMemAddress == rip){
                            // failed on attempt to executre code in memory
                            if (perms[2] == 'x'){
                                printf("Address Space does has Execute Permisions, IDK Cause of Problem.\n");
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

                    // add sig handler for SIGBUS with custom user info
                    last_signal = SIGSEGV;

                    continue;
                }
                last_signal = 0;
            }
        }
    }
    return 0;
}
