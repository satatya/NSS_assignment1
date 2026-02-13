CC = cc
CFLAGS = -Wall
# We try to link posix1e; if it fails, we assume it's in libc
LDFLAGS = -lposix1e
TARGETS = accheck accheck-helper accheck-test-read accheck-test-write accheck-test-exec

all: $(TARGETS)

accheck: accheck.c
	$(CC) $(CFLAGS) accheck.c -o accheck $(LDFLAGS) || $(CC) $(CFLAGS) accheck.c -o accheck

accheck-helper: accheck-helper.c
	$(CC) $(CFLAGS) accheck-helper.c -o accheck-helper

accheck-test-%: accheck-test-%.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGETS)
