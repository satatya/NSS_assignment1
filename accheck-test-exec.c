#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) return 1;
    setuid(getuid()); // Explicitly drop privileges [cite: 1097]
    if (access(argv[1], X_OK) == 0) {
        printf("Execute Success\n");
    } else {
        printf("Execute Failed: %s\n", strerror(errno));
    }
    return 0;
}
