#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

#include <fcntl.h>
#include <unistd.h>

static void redirect_output(const char *path) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) {
        perror("open");
        _exit(1);
    }

    if (dup2(fd, STDOUT_FILENO) < 0) {
        perror("dup2 stdout");
        _exit(1);
    }

    if (dup2(fd, STDERR_FILENO) < 0) {
        perror("dup2 stderr");
        _exit(1);
    }

    close(fd);
}

static long long ns_diff(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) * 1000000000LL + (b.tv_nsec - a.tv_nsec);
}

static long long run_once(char *const argv[]) {
    struct timespec start, end;
    pid_t pid;

    clock_gettime(CLOCK_MONOTONIC, &start);

    pid = fork();

    if (pid == 0) {
        redirect_output("run.log");
        execvp(argv[0], argv);
    }

    if (waitpid(pid, NULL, 0) < 0) {
        perror("waitpid");
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    return ns_diff(start, end);
}

int main(void) {
    const int iters = 1000;

    char *args[] = {"deref", "rec","bus", "2free", "bounds", "wonprot", "control"};
    int vol[] = {1000, 10000, 100000, 1000000};

    printf("| Run Type | Volume  | avg with (ms) | avg without (ms) | overhead (ms) | Slowdown %% |\n");
    printf("| -------- | ------- | ------------- | ---------------- | ------------- | ---------- |\n");

    for( int j = 0; j < 7; j++){
        for( int v= 0; v < 4; v++){
            long long total_with = 0;
            long long total_without = 0;
            char vol_str[16];
            snprintf(vol_str, sizeof(vol_str), "%d", vol[v]);

            char *with_prog[] = {"./realerrors", "./testSuite", args[j], vol_str, NULL};
            char *without_prog[] = {"./testSuite", args[j], vol_str, NULL};

            // warm up cache
            for (int i = 0; i < 20; i++) {
                run_once(with_prog);
                run_once(without_prog);
            }

            for (int i = 0; i < iters; i++) {
                long long t1 = run_once(with_prog);
                long long t2 = run_once(without_prog);

                if (t1 < 0 || t2 < 0) {
                    return 1;
                }

                total_with += t1;
                total_without += t2;
            }

            int ns2ms = 1000000;
            double avg_with = (double)total_with / iters / ns2ms;
            double avg_without = (double)total_without / iters / ns2ms;
            double overhead = avg_with - avg_without;
            double percent = ((avg_with - avg_without)/avg_without) * 100;

            printf("| %-8s | %-7d | %-14.2f | %-16.2f | %-13.2f | %-10.2f |\n",
                args[j], vol[v],
                avg_with, avg_without,
                overhead, percent);
            // printf("Test Results for     %s at vol: %d\n", args[j], vol[v]);
            // printf("avg with wrapper:    %.0f ns\n", avg_with);
            // printf("avg without wrapper: %.0f ns\n", avg_without);
            // printf("overhead:            %.0f ns\n", overhead);
            // printf("Percentage           %.2f\n\n", percent);
        }
    }

    return 0;
}