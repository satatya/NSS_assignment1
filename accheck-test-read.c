#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void die_usage(void) {
    fprintf(stderr, "Usage: accheck-test-read <path>\n");
    _exit(2);
}

int main(int argc, char *argv[]) {
    if (argc != 2) die_usage();

    // Drop setuid root privileges permanently to invoking user
    if (setuid(getuid()) != 0) {
        fprintf(stderr, "setuid drop failed: %s\n", strerror(errno));
        return 2;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        printf("DENIED\n");
        return 0;
    }

    close(fd);
    printf("ALLOWED\n");
    return 0;
}
