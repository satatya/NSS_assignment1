#include <sys/types.h>
#include <sys/stat.h>
#include <sys/acl.h>
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

    // Fixed scope: Define these at the top
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

    // Mandatory reasoning output
    printf("Reasoning for user : %s (UID : %u)\n", target_user, pw->pw_uid);
    printf("Reasoning for %s on %s (%s)\n", target_user, path, op_str);
    printf("File Owner UID: %u | File Group GID : %u\n", sb.st_uid, sb.st_gid);
    printf("Traditional Mode : %o\n", sb.st_mode & 0777);

    int allowed = 0;
    char *reason = "Denied by default";

    // 1. Root Check
    if (pw->pw_uid == 0) {
        allowed = 1; reason = "User is root"; goto result;
    }

    // 2. Owner Check
    if (pw->pw_uid == sb.st_uid) {
        int bit = (strcmp(op_str, "read") == 0) ? S_IRUSR : 
                  (strcmp(op_str, "write") == 0) ? S_IWUSR : S_IXUSR;
        if (sb.st_mode & bit) { allowed = 1; reason = "Owner bits allow access"; }
        goto result;
    }

    // 3. ACL & Mask Check (FreeBSD Logic)
    acl_t acl = acl_get_file(path, ACL_TYPE_ACCESS);
    if (acl) {
        acl_entry_t entry;
        int id = ACL_FIRST_ENTRY;
        int mask = 0x7, user_perms = 0, found = 0;
        int req = (strcmp(op_str, "read") == 0) ? ACL_READ :
                  (strcmp(op_str, "write") == 0) ? ACL_WRITE : ACL_EXECUTE;

        while (acl_get_entry(acl, id, &entry) == 1) {
            id = ACL_NEXT_ENTRY;
            acl_tag_t tag;
            acl_get_tag_type(entry, &tag);
            acl_permset_t ps;
            acl_get_permset(entry, &ps);

            if (tag == ACL_MASK) {
                mask = 0;
                if (acl_get_perm(ps, ACL_READ)) mask |= ACL_READ;
                if (acl_get_perm(ps, ACL_WRITE)) mask |= ACL_WRITE;
                if (acl_get_perm(ps, ACL_EXECUTE)) mask |= ACL_EXECUTE;
            } else if (tag == ACL_USER) {
                uid_t *uid = (uid_t *)acl_get_qualifier(entry);
                if (*uid == pw->pw_uid) {
                    found = 1;
                    if (acl_get_perm(ps, req)) user_perms = 1;
                }
                acl_free(uid);
            }
        }
        if (found) {
            if (user_perms && (mask & req)) { allowed = 1; reason = "ACL User entry allowed (within mask)"; }
            else { reason = "ACL or Mask denied access"; }
            acl_free(acl); goto result;
        }
        acl_free(acl);
    }

    // 4. Group & Other Check
    int g_bit = (strcmp(op_str, "read") == 0) ? S_IRGRP : 
                (strcmp(op_str, "write") == 0) ? S_IWGRP : S_IXGRP;
    if (pw->pw_gid == sb.st_gid && (sb.st_mode & g_bit)) {
        allowed = 1; reason = "Group bits match";
    } else {
        int o_bit = (strcmp(op_str, "read") == 0) ? S_IROTH : 
                    (strcmp(op_str, "write") == 0) ? S_IWOTH : S_IXOTH;
        if (sb.st_mode & o_bit) { allowed = 1; reason = "Other bits match"; }
    }

result:
    printf("PREDICTION: %s\nREASON: %s\n", allowed ? "ALLOW" : "DENY", reason);
    return 0;
}
