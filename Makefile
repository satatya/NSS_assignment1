CC=cc
CFLAGS=-Wall -Wextra -O2

all: accheck accheck-helper accheck-test-read accheck-test-write accheck-test-exec

accheck: accheck.c
	$(CC) $(CFLAGS) -o accheck accheck.c

accheck-helper: accheck-helper.c
	$(CC) $(CFLAGS) -o accheck-helper accheck-helper.c

accheck-test-read: accheck-test-read.c
	$(CC) $(CFLAGS) -o accheck-test-read accheck-test-read.c

accheck-test-write: accheck-test-write.c
	$(CC) $(CFLAGS) -o accheck-test-write accheck-test-write.c

accheck-test-exec: accheck-test-exec.c
	$(CC) $(CFLAGS) -o accheck-test-exec accheck-test-exec.c

clean:
	rm -f accheck accheck-helper accheck-test-read accheck-test-write accheck-test-exec
