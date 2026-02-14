#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void die_usage(void) {
    fprintf(stderr, "Usage: accheck-helper <user> <read|write|execute> <path>\n");
    exit(2);
}

static void drop_to_user(struct passwd *pw) {
    // Set groups first, then gid, then uid
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
        fprintf(stderr, "initgroups failed: %s\n", strerror(errno));
        exit(2);
    }
    if (setgid(pw->pw_gid) != 0) {
        fprintf(stderr, "setgid failed: %s\n", strerror(errno));
        exit(2);
    }
    if (setuid(pw->pw_uid) != 0) {
        fprintf(stderr, "setuid failed: %s\n", strerror(errno));
        exit(2);
    }

    if (geteuid() != pw->pw_uid || getegid() != pw->pw_gid) {
        fprintf(stderr, "Privilege drop verification failed\n");
        exit(2);
    }
}

static int kernel_read_check(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

static int kernel_write_check(const char *path) {
    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

static int kernel_exec_check(const char *path) {
    const int EXEC_FAIL = 254;

    pid_t pid = fork();
    if (pid < 0) return 0;

    if (pid == 0) {
        // Child: silence output
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) {
            dup2(dn, STDOUT_FILENO);
            dup2(dn, STDERR_FILENO);
        }

        char *const argv[] = { (char *)path, NULL };
        execv(path, argv);
        _exit(EXEC_FAIL);
    }

    int st;
    if (waitpid(pid, &st, 0) < 0) return 0;

    if (WIFEXITED(st) && WEXITSTATUS(st) == EXEC_FAIL) {
        return 0; // exec() failed (likely EACCES or similar)
    }
    return 1; // exec() succeeded (program ran, even if it later exited nonzero)
}

int main(int argc, char *argv[]) {
    if (argc != 4) die_usage();

    const char *user = argv[1];
    const char *op   = argv[2];
    const char *path = argv[3];

    if (geteuid() != 0) {
        fprintf(stderr, "accheck-helper must be installed setuid-root\n");
        return 2;
    }

    struct passwd *pw = getpwnam(user);
    if (!pw) {
        fprintf(stderr, "unknown user: %s\n", user);
        return 2;
    }

    drop_to_user(pw);

    int ok = 0;
    if (strcmp(op, "read") == 0) ok = kernel_read_check(path);
    else if (strcmp(op, "write") == 0) ok = kernel_write_check(path);
    else if (strcmp(op, "execute") == 0) ok = kernel_exec_check(path);
    else die_usage();

    printf("%s\n", ok ? "ALLOWED" : "DENIED");
    return 0;
}
