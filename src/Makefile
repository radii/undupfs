CFLAGS := -O2 -g -W -Wall -Wno-sign-compare -Wno-unused-parameter -pthread $(shell pkg-config fuse --cflags) -D_BSD_SOURCE=1 -D_GNU_SOURCE=1
LDFLAGS := $(shell pkg-config fuse --libs)

targets := undup-fuse undupfs-debug

bloom_objs := util.o sha512.o undup-core.o

all: $(targets)

%.o: %.c bloom.h core.h shared.h undupfs.h sha512.h Makefile
	$(CC) $(CFLAGS) -c $< -o $@

undup-fuse: undup-fuse.o undup-core.o util.o bloom.o sha512.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

undupfs-debug: undup-debug.o undup-core.o util.o bloom.o sha512.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

bloom: bloom.c $(bloom_objs)
	$(CC) $(CFLAGS) $(LDFLAGS) -DMAIN -o bloom bloom.c $(bloom_objs)

install: all
	cp undupfs-debug undup-fuse mkfs.undup /usr/local/bin

clean:
	rm -f *.o
	rm -f $(targets) bloom
