CFLAGS := -O2 -g -Wall $(shell pkg-config fuse --cflags)
LDFLAGS := $(shell pkg-config fuse --libs) -lssl

targets = undup-fuse

all: $(targets)

undup-fuse.o: undup-fuse.c shared.h

undup-fuse: undup-fuse.o util.o bloom.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

bloom: bloom.c util.o
	$(CC) $(CFLAGS) $(LDFLAGS) -DMAIN -o bloom bloom.c util.o

clean:
	rm -f *.o
	rm -f $(targets)
