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

/*
 * Set up a cohort of Bloom filters.  bloom_setup initializes shared state and
 * validates the settings.
 *
 * @sz: size of the Bloom bitarray, in bits.
 * @nb: number of bits set per key inserted into filter.
 * @kl: length of input keys, in bytes.
 */
struct bloom_params *bloom_setup(int sz, int nb, int kl);

/*
 * Initialize a single filter given the established settings.
 *
 * @b: bitarray to initialize.  Must be of the appropriate size.
 */
void bloom_init(struct bloom_params *p, u8 *b);

/* Insert KEY into filter B.
 *
 * Returns 1 if the key collided with existing entries (that is, all of the bits
 * set due to B were already set).  Returns 0 if B caused a bit to be set.
 */
int bloom_insert(struct bloom_params *p, u8 *b, const u8 *key);

/* Check if KEY is present in filter B.
 *
 * Returns 1 if KEY may have been inserted (all of the bits set due to KEY are
 * set).  Returns 0 if KEY was not inserted.
 */
int bloom_present(struct bloom_params *p, const u8 *b, const u8 *key);

/* Dump debug info about bloom filter B under params P to F.
 */
void bloom_dump(struct bloom_params *p, const u8 *b, FILE *f);

/* Returns weight (number of bits set) of bloom filter B.
 */
int bloom_weight(struct bloom_params *p, const u8 *b);

#endif /* BLOOM_H_ */
