CC = cc
CFLAGS = -Wall
TARGETS = accheck accheck-helper accheck-test-read accheck-test-write accheck-test-exec

all: $(TARGETS)

accheck: accheck.c
	$(CC) $(CFLAGS) accheck.c -o accheck

accheck-helper: accheck-helper.c
	$(CC) $(CFLAGS) accheck-helper.c -o accheck-helper

accheck-test-read: accheck-test-read.c
	$(CC) $(CFLAGS) accheck-test-read.c -o accheck-test-read

accheck-test-write: accheck-test-write.c
	$(CC) $(CFLAGS) accheck-test-write.c -o accheck-test-write

accheck-test-exec: accheck-test-exec.c
	$(CC) $(CFLAGS) accheck-test-exec.c -o accheck-test-exec

clean:
	rm -f $(TARGETS)

# Note: After running 'make', you must manually run 'chmod 4755' on the helper and test binaries as root.
