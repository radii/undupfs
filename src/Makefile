CFLAGS := -Wall $(shell pkg-config fuse --cflags)
LDFLAGS := $(shell pkg-config fuse --libs) -lssl

targets = undup-fuse

all: $(targets)

clean:
	rm -f *.o
	rm -f $(targets)
