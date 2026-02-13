#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc != 4) return 1;
    struct passwd *pw = getpwnam(argv[1]);
    if (!pw) return 1;

    // Drop privileges to target user
    if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
        perror("Privilege drop failed");
        return 1;
    }

    int success = 0;
    if (strcmp(argv[2], "read") == 0) {
        FILE *f = fopen(argv[3], "r");
        if (f) { success = 1; fclose(f); }
    } else if (strcmp(argv[2], "write") == 0) {
        FILE *f = fopen(argv[3], "a");
        if (f) { success = 1; fclose(f); }
    } else if (strcmp(argv[2], "execute") == 0) {
        if (access(argv[3], X_OK) == 0) success = 1;
    }

    printf("KERNEL RESULT: %s\n", success ? "ALLOW" : "DENY");
    return 0;
}
