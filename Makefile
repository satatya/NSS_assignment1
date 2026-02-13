CC = cc
CFLAGS = -Wall
LIBS = -lposix1e
TARGETS = accheck accheck-helper accheck-test-read accheck-test-write accheck-test-exec

all: $(TARGETS)

accheck: accheck.c
	$(CC) $(CFLAGS) accheck.c -o accheck $(LIBS)

accheck-helper: accheck-helper.c
	$(CC) $(CFLAGS) accheck-helper.c -o accheck-helper

accheck-test-%: accheck-test-%.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGETS)
