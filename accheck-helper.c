#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <user> <read/write/execute> <path>\n", argv[0]);
        return 1;
    }

    struct passwd *pw = getpwnam(argv[1]);
    if (!pw) {
        fprintf(stderr, "User %s not found\n", argv[1]);
        return 1;
    }

    // Switch identity to target user [cite: 1084-1085]
    if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
        perror("Failed to drop privileges");
        return 1;
    }

    FILE *f;
    if (strcmp(argv[2], "read") == 0) {
        f = fopen(argv[3], "r");
    } else if (strcmp(argv[2], "write") == 0) {
        f = fopen(argv[3], "a");
    } else if (strcmp(argv[2], "execute") == 0) {
        if (access(argv[3], X_OK) == 0) {
            printf("KERNEL RESULT: ALLOW\n");
            return 0;
        } else f = NULL;
    }

    if (f) {
        printf("KERNEL RESULT: ALLOW\n");
        fclose(f);
    } else {
        printf("KERNEL RESULT: DENY (Error: %s)\n", strerror(errno));
    }
    return 0;
}
