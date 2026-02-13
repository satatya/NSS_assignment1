# Access Control Reasoning and Validation (NSS Assignment 1)

## Project Overview
This project explores the mechanics of Unix access control by implementing a two-part system:
1. **The Predictor (`accheck`)**: A metadata-driven engine that reasons about file access based on traditional Unix permission bits (Owner/Group/Other).
2. **The Validator (`accheck-helper`)**: A security-conscious tool that validates those predictions by attempting real file operations after dropping root privileges to match a target user's identity.

The system is specifically designed to handle and highlight discrepancies between **Traditional Unix Permissions** and modern **NFSv4 ACLs** on FreeBSD.

---

## Technical Features
* **Metadata Extraction**: Uses `stat(2)` to retrieve UIDs, GIDs, and mode bits.
* **Identity Management**: Uses `getpwnam(3)` to resolve usernames and `setuid(2)`/`setgid(2)` for privilege management.
* **Secure Privilege Dropping**: Standalone test programs demonstrate that a process cannot regain root "powers" once privileges are dropped.

---

## Build & Installation

### Compilation
The project includes a `Makefile` that uses pattern rules for efficient building.
```bash
make clean
make
```

### Security Configuration (Mandatory)

The validator and test suite must be owned by `root` and have the **SetUID** bit enabled to allow identity switching during validation.
```bash
# Run as root
chown root accheck-helper accheck-test-read accheck-test-write accheck-test-exec
chmod 4755 accheck-helper accheck-test-read accheck-test-write accheck-test-exec
```

---

## Testing Scenarios & Results

### 1. Traditional Logic (Predictor)

**Scenario**: Testing an outsider's access to a file with `640` permissions.

* **Setup**: File owned by `alice:labgroup` with mode `640`.
* **Action**: `./accheck charlie read secret.txt`
* **Result**: `PREDICTION: DENY`.
* **Reasoning**: Charlie (UID 1004) is not the owner (UID 1002) and is not in the group. The "Other" bits are `0`, resulting in a denial.

### 2. Kernel Validation (The NFSv4 ACL Case)

**Scenario**: Verifying access when a specific NFSv4 ACL overrides traditional bits.

* **Setup**: Grant user `bob` read access via `setfacl -m u:bob:r:allow secret.txt`.
* **Action**: Compare `./accheck bob read` vs `./accheck-helper bob read`.
* **Result**:
  * **accheck**: `PREDICTION: DENY` (sees only traditional bits).
  * **accheck-helper**: `KERNEL RESULT: ALLOW` (kernel respects the ACL).

* **Significance**: This demonstrates that while the predictor is useful for reasoning, the validator is the "source of truth" as it uses actual kernel logic.

### 3. Privilege Dropping Verification

**Scenario**: Ensuring a SetUID-root program cannot "cheat" the system after dropping privileges.

* **Action**: Run `./accheck-test-read secret.txt` as user `charlie`.
* **Result**: `Permission denied`.
* **Reasoning**: Even though the binary has the SetUID bit, the code calls `setuid(getuid())` immediately, forcing it to follow Charlie's restricted permissions.

---

## Error Handling

* **Non-existent Path**: Reports "stat failed: No such file or directory" via `perror`.
* **Unknown User**: Reports "User [name] not found" if `getpwnam()` returns NULL.
* **Invalid Operations**: Rejects strings other than "read", "write", or "execute".

---

## Author
* **Name**: Satatya De
* **Roll Number**: MT25084
* **System**: FreeBSD 15.0-CURRENT
