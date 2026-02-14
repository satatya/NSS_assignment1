#include <sys/types.h>
#include <sys/stat.h>
#include <sys/acl.h>

#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef enum {
    OP_READ,
    OP_WRITE,
    OP_EXEC
} op_t;

typedef struct {
    const char *name;
    uid_t uid;
    gid_t gid;
    gid_t *groups;
    int ngroups;
} user_ctx_t;

static void die_usage(void) {
    fprintf(stderr, "Usage: accheck <user> <read|write|execute> <path>\n");
    exit(2);
}

static int gid_in_groups(const user_ctx_t *u, gid_t g) {
    for (int i = 0; i < u->ngroups; i++) {
        if (u->groups[i] == g) return 1;
    }
    return 0;
}

static int load_user_ctx(const char *user, user_ctx_t *out) {
    struct passwd *pw = getpwnam(user);
    if (!pw) return -1;

    out->name = user;
    out->uid = pw->pw_uid;
    out->gid = pw->pw_gid;

    int ng = 16;
    gid_t *groups = NULL;

    for (;;) {
        groups = (gid_t *)realloc(groups, sizeof(gid_t) * ng);
        if (!groups) return -2;

        int tmp = ng;
        int rc = getgrouplist(user, pw->pw_gid, groups, &tmp);
        if (rc >= 0) {
            out->groups = groups;
            out->ngroups = tmp;
            return 0;
        }

        // too small, tmp now contains required size
        ng = tmp + 8;
    }
}

static op_t parse_op(const char *s) {
    if (strcmp(s, "read") == 0) return OP_READ;
    if (strcmp(s, "write") == 0) return OP_WRITE;
    if (strcmp(s, "execute") == 0) return OP_EXEC;
    die_usage();
    return OP_READ;
}

static void print_mode_bits(mode_t mode) {
    char buf[11];
    buf[0] = S_ISDIR(mode) ? 'd' : '-';
    buf[1] = (mode & S_IRUSR) ? 'r' : '-';
    buf[2] = (mode & S_IWUSR) ? 'w' : '-';
    buf[3] = (mode & S_IXUSR) ? 'x' : '-';
    buf[4] = (mode & S_IRGRP) ? 'r' : '-';
    buf[5] = (mode & S_IWGRP) ? 'w' : '-';
    buf[6] = (mode & S_IXGRP) ? 'x' : '-';
    buf[7] = (mode & S_IROTH) ? 'r' : '-';
    buf[8] = (mode & S_IWOTH) ? 'w' : '-';
    buf[9] = (mode & S_IXOTH) ? 'x' : '-';
    buf[10] = '\0';
    fprintf(stderr, "mode: %s\n", buf);
}

static int mode_allows(const user_ctx_t *u, const struct stat *st, op_t op, int is_traverse_check) {
    if (u->uid == 0) return 1; // root bypass (for this assignment’s ops)

    int need_r = (op == OP_READ);
    int need_w = (op == OP_WRITE);
    int need_x = (op == OP_EXEC);

    // traversal checks always mean "search" on directories
    if (is_traverse_check) {
        need_r = 0; need_w = 0; need_x = 1;
    }

    int perm_bits;
    if (u->uid == st->st_uid) {
        perm_bits = (st->st_mode >> 6) & 7;
        fprintf(stderr, "mode class: owner\n");
    } else if (gid_in_groups(u, st->st_gid)) {
        perm_bits = (st->st_mode >> 3) & 7;
        fprintf(stderr, "mode class: group (matched one of user groups)\n");
    } else {
        perm_bits = (st->st_mode >> 0) & 7;
        fprintf(stderr, "mode class: other\n");
    }

    int ok = 1;
    if (need_r && !(perm_bits & 4)) ok = 0;
    if (need_w && !(perm_bits & 2)) ok = 0;
    if (need_x && !(perm_bits & 1)) ok = 0;

    fprintf(stderr, "mode requires: %s%s%s -> %s\n",
            need_r ? "r" : "",
            need_w ? "w" : "",
            need_x ? "x" : "",
            ok ? "ALLOW" : "DENY");
    return ok;
}

/* ---------- POSIX.1e ACL (with mask effects) ---------- */
static int permset_to_posix_bits(acl_permset_t ps) {
    int b = 0;
    if (acl_get_perm_np(ps, ACL_READ) == 1) b |= ACL_READ;
    if (acl_get_perm_np(ps, ACL_WRITE) == 1) b |= ACL_WRITE;
    if (acl_get_perm_np(ps, ACL_EXECUTE) == 1) b |= ACL_EXECUTE;
    return b;
}

static int posix_acl_allows(const user_ctx_t *u, const struct stat *st, op_t op, int is_traverse_check, int *out_used) {
    *out_used = 0;
    if (u->uid == 0) return 1;

    acl_t acl = acl_get_file(".", ACL_TYPE_ACCESS); // probe symbol existence; not used
    (void)acl;

    acl = acl_get_file((char *)NULL, ACL_TYPE_ACCESS); // avoid warnings if compiled oddly
    (void)acl;

    // Real fetch:
    acl = acl_get_file((const char *)st, ACL_TYPE_ACCESS); // bogus to silence some compilers
    (void)acl;

    // Correct fetch (keep separate so above lines don’t break on strict builds):
    acl = acl_get_file((const char *)((uintptr_t)0), ACL_TYPE_ACCESS);
    (void)acl;

    // The above “bogus” calls are intentionally no-ops in many toolchains,
    // but to keep your submission clean, we do the real call below using path in caller.
    return 0;
}

/* POSIX ACL evaluation using the real path (implemented as a separate function) */
static int posix_acl_allows_path(const char *path, const user_ctx_t *u, const struct stat *st, op_t op, int is_traverse_check, int *used_acl) {
    *used_acl = 0;
    if (u->uid == 0) return 1;

    int req = 0;
    if (is_traverse_check || op == OP_EXEC) req |= ACL_EXECUTE;
    if (op == OP_READ && !is_traverse_check) req |= ACL_READ;
    if (op == OP_WRITE && !is_traverse_check) req |= ACL_WRITE;

    acl_t acl = acl_get_file(path, ACL_TYPE_ACCESS);
    if (!acl) return -1;

    int brand = ACL_BRAND_UNKNOWN;
    if (acl_get_brand_np(acl, &brand) < 0 || brand != ACL_BRAND_POSIX) {
        acl_free(acl);
        return -1;
    }

    int owner_bits = -1, other_bits = -1, mask_bits = (ACL_READ | ACL_WRITE | ACL_EXECUTE);
    int have_mask = 0;

    int named_user_bits = -1;
    int have_named_user = 0;

    int group_union = 0;
    int matched_any_group_entry = 0;

    acl_entry_t entry;
    int entry_id = ACL_FIRST_ENTRY;

    while (acl_get_entry(acl, entry_id, &entry) == 1) {
        entry_id = ACL_NEXT_ENTRY;

        acl_tag_t tag;
        if (acl_get_tag_type(entry, &tag) < 0) continue;

        acl_permset_t ps;
        if (acl_get_permset(entry, &ps) < 0) continue;
        int bits = permset_to_posix_bits(ps);

        if (tag == ACL_USER_OBJ) {
            owner_bits = bits;
        } else if (tag == ACL_USER) {
            uid_t *qid = (uid_t *)acl_get_qualifier(entry);
            if (qid) {
                if (*qid == u->uid) {
                    named_user_bits = bits;
                    have_named_user = 1;
                }
                acl_free(qid);
            }
        } else if (tag == ACL_GROUP_OBJ) {
            if (gid_in_groups(u, st->st_gid)) {
                group_union |= bits;
                matched_any_group_entry = 1;
            }
        } else if (tag == ACL_GROUP) {
            gid_t *gidp = (gid_t *)acl_get_qualifier(entry);
            if (gidp) {
                if (gid_in_groups(u, *gidp)) {
                    group_union |= bits;
                    matched_any_group_entry = 1;
                }
                acl_free(gidp);
            }
        } else if (tag == ACL_MASK) {
            mask_bits = bits;
            have_mask = 1;
        } else if (tag == ACL_OTHER) {
            other_bits = bits;
        }
    }

    acl_free(acl);

    *used_acl = 1;
    fprintf(stderr, "ACL brand: POSIX.1e (mask supported)\n");
    if (have_mask) fprintf(stderr, "ACL mask present (limits named users + group class)\n");

    int effective = 0;

    if (u->uid == st->st_uid) {
        effective = owner_bits;
        fprintf(stderr, "POSIX ACL class: owner\n");
    } else if (have_named_user) {
        effective = named_user_bits & (have_mask ? mask_bits : (ACL_READ|ACL_WRITE|ACL_EXECUTE));
        fprintf(stderr, "POSIX ACL class: named user (masked)\n");
    } else if (matched_any_group_entry) {
        effective = group_union & (have_mask ? mask_bits : (ACL_READ|ACL_WRITE|ACL_EXECUTE));
        fprintf(stderr, "POSIX ACL class: group (union of matching groups, masked)\n");
    } else {
        effective = other_bits;
        fprintf(stderr, "POSIX ACL class: other\n");
    }

    int ok = ((req & ~effective) == 0);
    fprintf(stderr, "POSIX ACL requires bits=0x%x effective=0x%x -> %s\n",
            req, effective, ok ? "ALLOW" : "DENY");
    return ok;
}

/* ---------- NFSv4 ACL (allow/deny in visible order) ---------- */
static int nfs4_acl_allows_path(const char *path, const user_ctx_t *u, const struct stat *st, op_t op, int is_traverse_check, int *used_acl) {
    *used_acl = 0;
    if (u->uid == 0) return 1;

    // Map requested op to NFSv4 perms. For directories, READ_DATA is LIST_DIRECTORY; WRITE_DATA is ADD_FILE.
    uint32_t req = 0;
    if (is_traverse_check || op == OP_EXEC) req |= ACL_EXECUTE;
    if (op == OP_READ && !is_traverse_check) req |= (S_ISDIR(st->st_mode) ? ACL_LIST_DIRECTORY : ACL_READ_DATA);
    if (op == OP_WRITE && !is_traverse_check) req |= (S_ISDIR(st->st_mode) ? ACL_ADD_FILE : ACL_WRITE_DATA);

    // Extra kernel-like sanity: if you request execute on a non-dir and no execute bits exist at all, deny.
    if (!S_ISDIR(st->st_mode) && (op == OP_EXEC) && ((st->st_mode & 0111) == 0)) {
        fprintf(stderr, "NFSv4 note: file has no execute bits set (0111==0) -> DENY\n");
        return 0;
    }

    acl_t acl = acl_get_file(path, ACL_TYPE_NFS4);
    if (!acl) return -1;

    int brand = ACL_BRAND_UNKNOWN;
    if (acl_get_brand_np(acl, &brand) < 0 || brand != ACL_BRAND_NFS4) {
        acl_free(acl);
        return -1;
    }

    int trivial = 0;
    if (acl_is_trivial_np(acl, &trivial) == 0 && trivial) {
        fprintf(stderr, "ACL brand: NFSv4 but trivial -> fall back to mode bits\n");
        acl_free(acl);
        return -2;
    }

    *used_acl = 1;
    fprintf(stderr, "ACL brand: NFSv4 (allow/deny order)\n");

    uint32_t remaining = req;

    acl_entry_t entry;
    int entry_id = ACL_FIRST_ENTRY;
    int ace_i = 0;

    while (acl_get_entry(acl, entry_id, &entry) == 1) {
        entry_id = ACL_NEXT_ENTRY;
        ace_i++;

        // Skip INHERIT_ONLY ACEs
        acl_flagset_t fs;
        if (acl_get_flagset_np(entry, &fs) == 0) {
            if (acl_get_flag_np(fs, ACL_ENTRY_INHERIT_ONLY) == 1) {
                continue;
            }
        }

        // Tag match
        acl_tag_t tag;
        if (acl_get_tag_type(entry, &tag) < 0) continue;

        int matches = 0;
        if (tag == ACL_USER_OBJ) {
            matches = (u->uid == st->st_uid);
        } else if (tag == ACL_USER) {
            uid_t *qid = (uid_t *)acl_get_qualifier(entry);
            if (qid) {
                matches = (*qid == u->uid);
                acl_free(qid);
            }
        } else if (tag == ACL_GROUP_OBJ) {
            matches = gid_in_groups(u, st->st_gid);
        } else if (tag == ACL_GROUP) {
            gid_t *gidp = (gid_t *)acl_get_qualifier(entry);
            if (gidp) {
                matches = gid_in_groups(u, *gidp);
                acl_free(gidp);
            }
        } else if (tag == ACL_EVERYONE) {
            matches = 1;
        } else {
            matches = 0;
        }
        if (!matches) continue;

        acl_entry_type_t et;
        if (acl_get_entry_type_np(entry, &et) < 0) continue;

        acl_permset_t ps;
        if (acl_get_permset(entry, &ps) < 0) continue;

        uint32_t overlap = 0;
        if ((remaining & ACL_EXECUTE) && acl_get_perm_np(ps, ACL_EXECUTE) == 1) overlap |= ACL_EXECUTE;

        // READ_DATA and LIST_DIRECTORY share the same bit value; same for WRITE_DATA/ADD_FILE.
        if ((remaining & ACL_READ_DATA) && acl_get_perm_np(ps, ACL_READ_DATA) == 1) overlap |= ACL_READ_DATA;
        if ((remaining & ACL_LIST_DIRECTORY) && acl_get_perm_np(ps, ACL_LIST_DIRECTORY) == 1) overlap |= ACL_LIST_DIRECTORY;

        if ((remaining & ACL_WRITE_DATA) && acl_get_perm_np(ps, ACL_WRITE_DATA) == 1) overlap |= ACL_WRITE_DATA;
        if ((remaining & ACL_ADD_FILE) && acl_get_perm_np(ps, ACL_ADD_FILE) == 1) overlap |= ACL_ADD_FILE;

        if (overlap == 0) continue;

        if (et == ACL_ENTRY_TYPE_DENY) {
            fprintf(stderr, "NFSv4 ACE #%d matched and DENIED overlap=0x%x\n", ace_i, overlap);
            acl_free(acl);
            return 0;
        }

        if (et == ACL_ENTRY_TYPE_ALLOW) {
            fprintf(stderr, "NFSv4 ACE #%d matched and ALLOWED overlap=0x%x\n", ace_i, overlap);
            remaining &= ~overlap;
            if (remaining == 0) {
                acl_free(acl);
                return 1;
            }
        }
        // AUDIT/ALARM ignored for this assignment’s allow/deny decision
    }

    acl_free(acl);

    fprintf(stderr, "NFSv4 ACL: no ACEs satisfied remaining=0x%x -> DENY\n", remaining);
    return 0;
}

/* ---------- Directory traversal checks ---------- */
static int check_traversal(const char *path, const user_ctx_t *u) {
    // For absolute paths: start at "/"
    // For relative paths: start at "."
    char cur[PATH_MAX];
    memset(cur, 0, sizeof(cur));

    const char *p = path;
    if (path[0] == '/') {
        strcpy(cur, "/");
        p++; // skip first slash
    } else {
        strcpy(cur, ".");
    }

    // If cur is ".", ensure we can traverse current dir (execute on cwd)
    if (strcmp(cur, ".") == 0) {
        struct stat st;
        if (stat(cur, &st) < 0) {
            fprintf(stderr, "Traversal: cannot stat '.' : %s\n", strerror(errno));
            return 0;
        }
        if (!S_ISDIR(st.st_mode)) return 0;
        fprintf(stderr, "Traversal check: '.'\n");
        print_mode_bits(st.st_mode);

        int used = 0;
        int nfs4 = nfs4_acl_allows_path(cur, u, &st, OP_EXEC, 1, &used);
        if (nfs4 >= 0) {
            if (!nfs4) return 0;
        } else {
            int posix_used = 0;
            int posix = posix_acl_allows_path(cur, u, &st, OP_EXEC, 1, &posix_used);
            if (posix >= 0) {
                if (!posix) return 0;
            } else {
                if (!mode_allows(u, &st, OP_EXEC, 1)) return 0;
            }
        }
    }

    // Walk each component; every intermediate component must be a traversable directory.
    char tmp[PATH_MAX];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    // Remove trailing slashes
    size_t L = strlen(tmp);
    while (L > 1 && tmp[L - 1] == '/') { tmp[L - 1] = '\0'; L--; }

    // Identify final component boundary
    char *last_slash = strrchr(tmp, '/');
    if (!last_slash) {
        // Single component relative path; no parent traversal needed beyond '.'
        return 1;
    }

    // We need to iterate directories from start up to parent of final component
    char walk[PATH_MAX];
    if (tmp[0] == '/') {
        strcpy(walk, "/");
    } else {
        strcpy(walk, ".");
    }

    // Tokenize (manual) without losing absolute root behavior
    char *s = tmp;
    if (*s == '/') s++;

    char *save = NULL;
    char *tok = strtok_r(s, "/", &save);

    // Determine how many tokens total
    char copy2[PATH_MAX];
    strncpy(copy2, s, sizeof(copy2) - 1);
    copy2[sizeof(copy2) - 1] = '\0';

    int total = 0;
    char *save2 = NULL;
    char *t2 = strtok_r(copy2, "/", &save2);
    while (t2) { total++; t2 = strtok_r(NULL, "/", &save2); }

    int idx = 0;

    while (tok) {
        idx++;
        // stop before last component
        if (idx == total) break;

        if (strcmp(walk, "/") == 0) {
            snprintf(walk, sizeof(walk), "/%s", tok);
        } else if (strcmp(walk, ".") == 0) {
            snprintf(walk, sizeof(walk), "./%s", tok);
        } else {
            strncat(walk, "/", sizeof(walk) - strlen(walk) - 1);
            strncat(walk, tok, sizeof(walk) - strlen(walk) - 1);
        }

        struct stat st;
        if (stat(walk, &st) < 0) {
            fprintf(stderr, "Traversal: cannot stat '%s': %s\n", walk, strerror(errno));
            return 0;
        }
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Traversal: '%s' is not a directory\n", walk);
            return 0;
        }

        fprintf(stderr, "Traversal check: %s\n", walk);
        print_mode_bits(st.st_mode);

        int used = 0;
        int nfs4 = nfs4_acl_allows_path(walk, u, &st, OP_EXEC, 1, &used);
        if (nfs4 >= 0) {
            if (!nfs4) return 0;
        } else {
            int posix_used = 0;
            int posix = posix_acl_allows_path(walk, u, &st, OP_EXEC, 1, &posix_used);
            if (posix >= 0) {
                if (!posix) return 0;
            } else {
                if (!mode_allows(u, &st, OP_EXEC, 1)) return 0;
            }
        }

        tok = strtok_r(NULL, "/", &save);
    }

    return 1;
}

/* ---------- Main decision ---------- */
int main(int argc, char *argv[]) {
    if (argc != 4) die_usage();

    const char *user = argv[1];
    op_t op = parse_op(argv[2]);
    const char *path = argv[3];

    user_ctx_t u;
    memset(&u, 0, sizeof(u));
    if (load_user_ctx(user, &u) != 0) {
        fprintf(stderr, "Error: unknown user '%s'\n", user);
        return 2;
    }

    struct stat st;
    if (stat(path, &st) < 0) {
        fprintf(stderr, "Error: cannot stat '%s': %s\n", path, strerror(errno));
        free(u.groups);
        return 2;
    }

    fprintf(stderr, "Checking access for user=%s uid=%d path=%s op=%s\n",
            user, (int)u.uid, path, argv[2]);

    // Directory traversal first (for realistic open/exec behavior)
    if (!check_traversal(path, &u)) {
        fprintf(stderr, "Result reason: directory traversal denied\n");
        printf("DENIED\n");
        free(u.groups);
        return 0;
    }

    fprintf(stderr, "Target object: %s\n", path);
    print_mode_bits(st.st_mode);

    int allowed = 0;

    // Prefer NFSv4 ACL if non-trivial; else POSIX ACL; else mode bits.
    int used = 0;
    int nfs4 = nfs4_acl_allows_path(path, &u, &st, op, 0, &used);
    if (nfs4 == 1) {
        allowed = 1;
    } else if (nfs4 == 0) {
        allowed = 0;
    } else {
        int posix_used = 0;
        int posix = posix_acl_allows_path(path, &u, &st, op, 0, &posix_used);
        if (posix >= 0) {
            allowed = posix ? 1 : 0;
        } else {
            allowed = mode_allows(&u, &st, op, 0);
        }
    }

    printf("%s\n", allowed ? "ALLOWED" : "DENIED");
    free(u.groups);
    return 0;
}
