#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) return 1;

    // Drop privileges to the real user who invoked the script [cite: 1097]
    setuid(getuid());

    FILE *f = fopen(argv[1], "r");
    if (f) {
        printf("Read Success\n");
        fclose(f);
    } else {
        printf("Read Failed: %s\n", strerror(errno));
    }
    return 0;
}
