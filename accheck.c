#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <user> <read/write/execute> <path>\n", argv[0]);
        return 1;
    }

    char *target_user = argv[1];
    char *op_str = argv[2];
    char *path = argv[3];
    struct stat sb;

    if (stat(path, &sb) == -1) {
        perror("stat failed");
        return 1;
    }

    struct passwd *pw = getpwnam(target_user);
    if (!pw) {
        fprintf(stderr, "User %s not found.\n", target_user);
        return 1;
    }

    // Required reasoning output
    printf("Reasoning for user : %s (UID : %u)\n", target_user, pw->pw_uid);
    printf("File Owner UID: %u | File Group GID : %u\n", sb.st_uid, sb.st_gid);
    printf("Traditional Mode : %o\n", sb.st_mode & 0777);

    int allowed = 0;
    char *reason = "Denied by default logic";

    // 1. ROOT CHECK
    if (pw->pw_uid == 0) {
        allowed = 1; reason = "User is root (super-user)"; goto result;
    }

    // 2. OWNER CHECK
    if (pw->pw_uid == sb.st_uid) {
        int bit = (strcmp(op_str, "read") == 0) ? S_IRUSR : 
                  (strcmp(op_str, "write") == 0) ? S_IWUSR : S_IXUSR;
        if (sb.st_mode & bit) { allowed = 1; reason = "Match in Owner bits"; }
        else { reason = "User is owner, but bits deny access"; }
        goto result;
    }

    // 3. GROUP CHECK
    int g_bit = (strcmp(op_str, "read") == 0) ? S_IRGRP : 
                (strcmp(op_str, "write") == 0) ? S_IWGRP : S_IXGRP;
    if (pw->pw_gid == sb.st_gid) {
        if (sb.st_mode & g_bit) { allowed = 1; reason = "Match in Group bits"; }
        goto result;
    }

    // 4. OTHER/EVERYONE CHECK
    int o_bit = (strcmp(op_str, "read") == 0) ? S_IROTH : 
                (strcmp(op_str, "write") == 0) ? S_IWOTH : S_IXOTH;
    if (sb.st_mode & o_bit) {
        allowed = 1;
        reason = "Applied Other/Everyone permission bits";
    }

result:
    printf("PREDICTION: %s\nREASON: %s\n", allowed ? "ALLOW" : "DENY", reason);
    return 0;
}
