#include <sys/types.h>
#include <sys/acl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
// #include <sys/acl.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>

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

    printf("Reasoning for user : %s (UID : %u)\n", target_user, pw->pw_uid);
    printf("File Owner UID: %u | File Group GID : %u\n", sb.st_uid, sb.st_gid);
    printf("Traditional Mode : %o\n", sb.st_mode & 0777);

    int allowed = 0;
    char *final_reason = "Denied by default";

    if (pw->pw_uid == 0) {
        allowed = 1;
        final_reason = "User is root";
        goto result;
    }

    if (pw->pw_uid == sb.st_uid) {
        int mode_bit = (strcmp(op_str, "read") == 0) ? S_IRUSR : 
                       (strcmp(op_str, "write") == 0) ? S_IWUSR : S_IXUSR;
        if (sb.st_mode & mode_bit) {
            allowed = 1;
            final_reason = "Match in Owner bits";
        }
        goto result;
    }

    acl_t acl = acl_get_file(path, ACL_TYPE_ACCESS);
    if (acl != NULL) {
        acl_entry_t entry;
        int entry_id = ACL_FIRST_ENTRY;
        int mask = 0x7, user_perms = 0, found_user = 0;
        int req_bit = (strcmp(op_str, "read") == 0) ? ACL_READ :
                      (strcmp(op_str, "write") == 0) ? ACL_WRITE : ACL_EXECUTE;

        while (acl_get_entry(acl, entry_id, &entry) == 1) {
            entry_id = ACL_NEXT_ENTRY;
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
                uid_t *id = (uid_t *)acl_get_qualifier(entry);
                if (*id == pw->pw_uid) {
                    found_user = 1;
                    if (acl_get_perm(ps, req_bit)) user_perms = 1;
                }
                acl_free(id);
            }
        }
        if (found_user) {
            if (user_perms && (mask & req_bit)) {
                allowed = 1;
                final_reason = "Allowed by User ACL (constrained by Mask)";
            }
            acl_free(acl);
            goto result;
        }
        acl_free(acl);
    }

    int grp_bit = (strcmp(op_str, "read") == 0) ? S_IRGRP : 
                  (strcmp(op_str, "write") == 0) ? S_IWGRP : S_IXGRP;
    if (pw->pw_gid == sb.st_gid && (sb.st_mode & grp_bit)) {
        allowed = 1;
        final_reason = "Match in Group bits";
    }

result:
    printf("PREDICTION: %s\nREASON: %s\n", allowed ? "ALLOW" : "DENY", final_reason);
    return 0;
}
