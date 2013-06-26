#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <endian.h>

struct sha512_ctx {
	uint64_t state[8];
	uint64_t count[2];
	uint8_t buf[128];
	uint64_t W[80];
};

void sha512_init(struct sha512_ctx *);
void sha512_update(struct sha512_ctx *, const uint8_t *, unsigned int);
void sha512_final(struct sha512_ctx *, uint8_t *, unsigned int);

static inline uint64_t cpu_to_be64(uint64_t x)
{
	return htobe64(x);
}

static inline uint64_t be64_to_cpu(uint64_t x)
{
	return be64toh(x);
}

#endif
