#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void die_usage(void) {
    fprintf(stderr, "Usage: accheck-test-exec <path>\n");
    _exit(2);
}

int main(int argc, char *argv[]) {
    if (argc != 2) die_usage();

    if (setuid(getuid()) != 0) {
        fprintf(stderr, "setuid drop failed: %s\n", strerror(errno));
        return 2;
    }

    const int EXEC_FAIL = 254;

    pid_t pid = fork();
    if (pid < 0) {
        printf("DENIED\n");
        return 0;
    }

    if (pid == 0) {
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) {
            dup2(dn, STDOUT_FILENO);
            dup2(dn, STDERR_FILENO);
        }

        char *const av[] = { argv[1], NULL };
        execv(argv[1], av);
        _exit(EXEC_FAIL);
    }

    int st;
    if (waitpid(pid, &st, 0) < 0) {
        printf("DENIED\n");
        return 0;
    }

    if (WIFEXITED(st) && WEXITSTATUS(st) == EXEC_FAIL) {
        printf("DENIED\n");
    } else {
        printf("ALLOWED\n");
    }
    return 0;
}
