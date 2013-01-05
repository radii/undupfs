/*
 * bloom.c: implementation of Bloom filters for undup-fuse
 *
 * Copyright (C) 2013 Andrew Isaacson <adi@hexapodia.org>
 *
 * This program is free software, licensed under the terms of the GNU GPL
 * version 3.  See the file COPYING for more information.
 */

#include <stdio.h>
#include <stdlib.h>

#include "bloom.h"

/*
 * Theory of operation.  This implementation is tuned to the scenario that we
 * have many (1M or more) filters set up with the same parameters.  Therefore
 * it's important that the parameters be stored separately from the bit array,
 * and there's no explicit linkage between them.
 *
 * The parameters are stroed in a `struct bloom_params` which is returned from
 * bloom_setup().  Each filter bitarray is initialized by a call to bloom_init.
 *
 * Keys are assumed to be a hash output, and are assumed to be a random
 * selection from {0,1}^N.  Bits from the key are used directly as inputs to the
 * Bloom filter function, rather than being hashed as in a general purpose Bloom
 * filter implementaiton.
 *
 * Keys are inserted into a filter by calling bloom_insert().
 *
 * Key presence is tested by calling bloom_test().
 */

/*
 * Set up a cohort of Bloom filters.  bloom_setup initializes shared state and
 * validates the settings.
 *
 * @sz: size of the Bloom bitarray, in bits.
 * @nb: number of bits set per key inserted into filter.
 * @kl: length of input keys, in bytes.
 */
struct bloom_params *bloom_setup(int sz, int nb, int kl)
{
    struct bloom_params *p = calloc(sizeof *p, 1);

    if (!p) return p;

    p->size = sz;
    p->bytesize = sz / 8 + !!(sz % 8);
    ASSERT(p->bytesize * 8 >= sz);
    p->nbit = nb;
    p->keylen = kl;

    return p;
}

/*
 * Initialize a single filter given the established settings.
 *
 * @b: bitarray to initialize.  Must be of the appropriate size.
 */
void bloom_init(struct bloom_params *p, u8 *b)
{
    memset(b, 0, p->bytesize);
}

int bloom_insert(struct bloom_params *p, u8 *b, u8 *key)
{
    int i;

    for (i=0; i<p->nbit; i++) {
        int b = 
    }
}

int bloom_test(struct bloom_params *p, u8 *b, u8 *key)
{
}

#ifdef MAIN
int main(void)
{
    printf("running Bloom filter tests\n");
    return 0;
}
#endif
