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

// #include <sys/siginfo.h>

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

// used to pass a list of pointers between functions
typedef struct {
    uint64_t data[MAX_STRARR_LEN];
    size_t    length;
} uint64_array_t;

char child_process_name[128] = "\0";

// print the file and line of a given address 
void trace_maddr(void *addr){
    char cmd[256];

    // get the name of the binary process run
    // char path[64];
    // ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);
    // if (n < 0) {
    //     perror("readlink");
    //     return;
    // }
    // path[n] = '\0';

    if (strlen(child_process_name) == 0){
        printf("child_process_name not set\n");
        return;
    }

    // command line call to get line numbers
    snprintf(cmd, sizeof(cmd), "addr2line -f -e %s %p", child_process_name, addr);
    system(cmd);
}

void print_stack(void) {
    void *buf[64];
    int n = backtrace(buf, 64);
    char **syms = backtrace_symbols(buf, n);

    if (!syms) {
        perror("backtrace_symbols");
        return;
    }

    // only the stack trace the user cars about
    for (int i = 0; i < n; i++) {
        // printf("%s\n", syms[i]);
        trace_maddr(buf[i]);
        // printf("%p\n", buf[i]);
    }

    free(syms);
}



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

        // run the args
        if(execvp(cmd, args)) {
            perror("execvp failed");
            exit(2);
        }

    } else {
        // Wait for the child to stop

        // Redirect ALL printf() to log for the tracer
        FILE *logfile = freopen("syscall_trace.log", "w", stdout);
        if (!logfile) {
            perror("Failed to open logfile");
            exit(2);
        }
        setvbuf(stdout, NULL, _IONBF, 0);  // Disable buffering for real-time logging

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
        printf("Attached!\n");

        // loop vars
        bool running = true;
        int last_signal = 0;
        // bool at_entry = true;
        // char sys_call_args[7][BUF_SIZE];
        // int outputType = POINTER;
        // char syscall_name[64];

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
                printf("Child exited with status %d\n", WEXITSTATUS(status));
                running = false;
            } else if(WIFSIGNALED(status)) {
                int sig = WTERMSIG(status);
                printf("Child terminated with signal %d (%s)\n", sig, strsignal(sig));
                running = false;
            } else if(WIFSTOPPED(status)) {
                // Get the signal delivered to the child
                last_signal = WSTOPSIG(status);

                if(last_signal == SIGSEGV){
                    printf("signal is SIGSEGV\n");
                    // handle segfault
                    
                    siginfo_t info;
                    ptrace(PTRACE_GETSIGINFO, child_pid, 0, &info);
                    printf("faulting memory address: %p\n", info.si_addr);

                    // trace_maddr(info.si_addr);
                    print_stack();
                    // if addres 0 user is derefrencing a pointer


                    // kill child proccess
                    kill(child_pid, SIGTERM); 
                    running = false;
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
                  
