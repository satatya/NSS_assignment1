# NSS2 Assignment 1 — Access Control Reasoning & Validation on FreeBSD  
**Subject:** Networks and Systems Security II (NSS2)  
**Name:** Satatya De  
**Roll:** MT25084  
**Program:** M.Tech CSE (1st Year)  

---

## 1) Project Overview

This assignment studies **how FreeBSD decides file access** by building a small toolchain that shows:

1) **Predictor — `accheck`**  
   A reasoning engine that *predicts* whether a user should be allowed to perform an operation (`read/write/execute`) on a path.  
   It prints the decision plus the reasoning (mode bits, ACL brand, matched class, traversal checks).

2) **Validator — `accheck-helper` (setuid-root)**  
   A validator that shows **kernel truth** by adopting the target identity (UID/GID/groups) and then attempting the real operation.
   The kernel decision (success/failure) is the ground truth.

3) **Security Test Suite — `accheck-test-read/write/exec` (setuid-root)**  
   Demonstrates the secure "drop-early" pattern: the program starts setuid-root but immediately drops privileges to the real invoking user,
   then attempts the operation.

The key learning is:  
> **Reasoning is not enforcement.** `accheck` explains, `accheck-helper` verifies.

---

## 2) Compliance Note (Important)

Per A1 rule: **no bash/assembly for permission checking inside the code**.

- The C programs do **not** use `system()`, `popen()`, or shelling out to `ls/getfacl`.
- No inline assembly is used for checking permissions.
- Decisions are derived using **C system calls / FreeBSD APIs**:  
  `stat(2)`, `getpwnam(3)`, `getgrouplist(3)`, ACL APIs like `acl_get_file(3)`, and real kernel enforcement via `open(2)` / `execve(2)` in the helper.



---

## 3) Files in the Submission

My submission directory contains:

- `accheck.c` — predictor (reasoning engine)
- `accheck-helper.c` — validator (setuid-root, kernel truth)
- `accheck-test-read.c` — setuid-root test (drops privilege, then read)
- `accheck-test-write.c` — setuid-root test (drops privilege, then write/append)
- `accheck-test-exec.c` — setuid-root test (drops privilege, then execute/search)
- `Makefile` — builds all targets
- `README.md` — this document

---

## 4) Build Instructions

### 4.1 Compile
```sh
make clean
make
```

### 4.2 SetUID configuration (Mandatory, run as root)

These binaries must be setuid-root for identity switching and controlled tests:
```sh
chown root:wheel accheck-helper accheck-test-read accheck-test-write accheck-test-exec
chmod 4755 accheck-helper accheck-test-read accheck-test-write accheck-test-exec
```

---

## 5) Usage

### 5.1 Predictor: accheck
```sh
./accheck <user> <read|write|execute> <path>
```

Examples:
```sh
./accheck bob read /srv/testlab/secret.txt 2>&1
./accheck bob write /srv/testlab/secret.txt 2>&1
./accheck bob execute /srv/testlab/runme.sh 2>&1
```

Tip: `2>&1` keeps the reasoning output together (useful for screenshots).

### 5.2 Validator: accheck-helper
```sh
./accheck-helper <user> <read|write|execute> <path>
```

Examples:
```sh
./accheck-helper bob read /srv/testlab/secret.txt
./accheck-helper bob write /srv/testlab/secret.txt
```

### 5.3 Drop-early test suite

Run these as an unprivileged user (example: bob):
```sh
su - bob
cd /path/to/repo
./accheck-test-read  /srv/testlab/secret.txt
./accheck-test-write /srv/testlab/secret.txt
./accheck-test-exec  /srv/testlab/runme.sh
exit
```

---

## 6) Test Scenarios (at least 3)

### Scenario A — NFSv4 ACL override on a 640 file

**Goal:** Show ACL can grant access even when mode bits would deny.

**Setup (root):**
```sh
mkdir -p /srv/testlab
echo "TOP SECRET" > /srv/testlab/secret.txt
chown alice:labgroup /srv/testlab/secret.txt
chmod 640 /srv/testlab/secret.txt

# Give bob explicit read via NFSv4 ACL
setfacl -m u:bob:r:allow /srv/testlab/secret.txt
```

**Observe:**
```sh
./accheck bob read  /srv/testlab/secret.txt 2>&1
./accheck bob write /srv/testlab/secret.txt 2>&1
./accheck-helper bob read  /srv/testlab/secret.txt
./accheck-helper bob write /srv/testlab/secret.txt
```

**Expected result:**

- **Read:** ALLOWED (ACL allow)
- **Write:** DENIED

This demonstrates the ACL layer and why the helper is the final authority.

---

### Scenario B — Directory traversal restriction beats file ACL

**Goal:** Show that even if a file ACL allows read, the directory must be traversable.

**Setup (root):**
```sh
mkdir -p /srv/testlab/notraverse
echo "INSIDE" > /srv/testlab/notraverse/inside.txt
chown -R alice:labgroup /srv/testlab/notraverse
chmod 700 /srv/testlab/notraverse

# Even if bob is allowed on the file...
setfacl -m u:bob:r:allow /srv/testlab/notraverse/inside.txt
```

**Observe:**
```sh
./accheck bob read /srv/testlab/notraverse/inside.txt 2>&1
./accheck-helper bob read /srv/testlab/notraverse/inside.txt
```

**Expected result:**  
Both tools show DENIED, with `accheck` explicitly identifying which parent directory blocks traversal.

---

### Scenario C — Privilege-drop execution test (drop-early pattern)

**Goal:** Show a setuid-root program can drop privileges and then behave like the real user.

**Setup (root):**
```sh
printf "#!/bin/sh\necho RUN_OK\n" > /srv/testlab/runme.sh
chown alice:labgroup /srv/testlab/runme.sh
chmod 755 /srv/testlab/runme.sh
```

**Observe (as bob):**
```sh
su - bob
cd /path/to/repo
./accheck-test-exec /srv/testlab/runme.sh
exit
```

**Expected result:**  
`accheck-test-exec` prints ALLOWED (because bob can execute/search due to 755).  
**Key point:** it does NOT rely on "root powers" after dropping privileges.

---

### Scenario D (extra) — Supplementary group access via mode bits

**Goal:** Show group membership affects access via the group bits.

**Setup (root):**
```sh
pw groupadd projgrp
pw groupmod projgrp -m bob

echo "GROUP DATA" > /srv/testlab/groupfile.txt
chown alice:projgrp /srv/testlab/groupfile.txt
chmod 640 /srv/testlab/groupfile.txt
```

**Observe:**
```sh
./accheck bob read /srv/testlab/groupfile.txt 2>&1
./accheck-helper bob read /srv/testlab/groupfile.txt
```

**Expected result:**  
Both show ALLOWED due to group match.

---

## 7) Error Cases Handled (3 examples)

**Unknown user**  
If the username is invalid, `getpwnam()` fails and the program exits cleanly with an error.

**Invalid path / stat failure**  
If the path doesn't exist (or cannot be stated), `stat()` fails and the program prints the OS error (errno) and exits safely.

**Invalid operation argument**  
Only `read`, `write`, `execute` are accepted. Any other string triggers a usage message and a non-zero exit.

---

## 8) What this assignment demonstrates (short takeaway)

- **Mode bits** are only one layer of access control.
- **NFSv4 ACLs** can override mode-bit expectations.
- **Directory traversal** (search permission) is required regardless of file ACLs.
- A **setuid-root program** becomes safe when it drops privileges early, letting the kernel enforce normal policy.

---

## 9) Quick Submission Checklist

- ✓ `make clean && make` builds all binaries
- ✓ setuid set on: `accheck-helper` and `accheck-test-*`
- ✓ I have screenshots for:
  - `secret.txt` ACL + read allowed, write denied (predictor + helper)
  - traversal denial (predictor + helper)
  - priv-drop exec test as bob
  - (optional) supplementary group scenario
