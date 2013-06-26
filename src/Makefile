CFLAGS := -O2 -g -W -Wall -Wno-sign-compare -Wno-unused-parameter -pthread $(shell pkg-config fuse --cflags)
LDFLAGS := $(shell pkg-config fuse --libs) -lssl

targets := undup-fuse undupfs-debug

all: $(targets)

%.o: %.c bloom.h core.h shared.h undupfs.h Makefile
	$(CC) $(CFLAGS) -c $< -o $@

undup-fuse: undup-fuse.o undup-core.o util.o bloom.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

undupfs-debug: undup-debug.o undup-core.o util.o bloom.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

bloom: bloom.c util.o undup-core.o
	$(CC) $(CFLAGS) $(LDFLAGS) -DMAIN -o bloom bloom.c util.o undup-core.o

install: all
	cp undupfs-debug undup-fuse mkfs.undup /usr/local/bin

clean:
	rm -f *.o
	rm -f $(targets)
