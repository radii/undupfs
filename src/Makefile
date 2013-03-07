CFLAGS := -O2 -g -W -Wall -Wno-sign-compare $(shell pkg-config fuse --cflags)
LDFLAGS := $(shell pkg-config fuse --libs) -lssl

targets := undup-fuse undupfs-debug

all: $(targets)

%.o: %.c shared.h Makefile
	$(CC) $(CFLAGS) -c $< -o $@

undup-fuse: undup-fuse.o undup-core.o util.o bloom.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

undupfs-debug: undup-debug.o undup-core.o util.o bloom.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

bloom: bloom.c util.o
	$(CC) $(CFLAGS) $(LDFLAGS) -DMAIN -o bloom bloom.c util.o

clean:
	rm -f *.o
	rm -f $(targets)
