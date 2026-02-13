#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) return 1;
    setuid(getuid()); // Explicitly drop privileges [cite: 1097]
    FILE *f = fopen(argv[1], "a");
    if (f) {
        printf("Write Success\n");
        fclose(f);
    } else {
        printf("Write Failed: %s\n", strerror(errno));
    }
    return 0;
}
