CFLAGS := -g -Wall $(shell pkg-config fuse --cflags)
LDFLAGS := $(shell pkg-config fuse --libs) -lssl

targets = undup-fuse

all: $(targets)

undup-fuse: undup-fuse.o util.o
	$(CC) $(CFLAGS) $(LDFLAGS) undup-fuse.o util.o -o undup-fuse

clean:
	rm -f *.o
	rm -f $(targets)
