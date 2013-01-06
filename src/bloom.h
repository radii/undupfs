#ifndef BLOOM_H_
#define BLOOM_H_

#include "shared.h"

struct bloom_params {
    int size;     // bits in the bloom filter
    int bytesize; // ceil(size / 8)
    int nbit;     // number of bits set per input key
    int keylen;   // length of key, in bytes
    int bitperf;  // bits consumed per F_i
};

struct bloom_params *bloom_setup(int sz, int nb, int kl);

void bloom_init(struct bloom_params *p, u8 *b);

int bloom_insert(struct bloom_params *p, u8 *b, u8 *key);

int bloom_test(struct bloom_params *p, u8 *b, u8 *key);

#endif /* BLOOM_H_ */
