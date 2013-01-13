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
#include <string.h>

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

static int log2_ceil(int x)
{
    int r = 1;
    while (1 << r < x)
        r++;
    return r;
}

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
    p->bitperf = log2_ceil(sz);

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


/*
 * Extracts NBIT bits from bit array A starting at bit position POS.
 * Both bits an bytes are indexed big-endian:
 *    \ bitindex|            11 1111
 *  val\        |0123 4567 8901 2345
 *  ------------+-------------------
 *  0x11 0x2f   |0001 0001 0010 1111
 *  extracting:
 *  4 @ 0      = 0001      = 0x01
 *  6 @ 0      = 0001 00   = 0x08
 *  8 @ 0      = 0001 0001 = 0x11
 *  12 @ 0     = 0001 0001 0010 = 0x112
 *  8 @ 4      = 0001 0010 = 0x12
 *  8 @ 2      = 01 0001 00 = 0x44
 *  
 * Values are returned right-justified, so if 4 bits valued 0010 are extracted,
 * the return value is 0x00000002.
 */
static u32 get_bits(u8 *a, int pos, int nbit)
{
    u64 r = 0;
    int i;
    u32 mask = (1LL << nbit) - 1;
    int shift, base = 0;

    ASSERT(nbit <= 32);

    /* pos n shift      input   output
     * --- - -----  --------- --------
     *  0  1  7     1000 0000 00000001
     *  0  2  6     1100 0000 00000011
     *  1  1  6     0100 0000 00000001
     *  2  1  5     0010 0000 00000001
     *  ...
     *  7  1  0     0000 0001 00000001
     *  ...
     *  5  4        0000 0111 00001110
     */
    shift = ((8 - nbit - (pos % 8)) + 4 * 8) % 8;

    if (pos % 8 > 0) {
        r = a[pos/8];
        nbit -= (8 - (pos % 8));
        base = 1;
    }

    for(i = 0; i < nbit; i+= 8) {
        r = (r << 8) | a[(pos + i) / 8 + base];
    }
    return (r >> shift) & mask;
}

static u32 get_bit(u8 *a, int pos)
{
    return 1 & (a[pos / 8] >> (7 - pos % 8));
}

/*
 * Sets the Xth bit of B.  Returns the previous value of the bit.
 */
static int set_bit(u8 *b, int x)
{
    int i = x / 8;
    int j = 7 - x % 8;
    int m = 1 << j;
    int r = (b[i] & m) != 0;

    b[i] |= m;
    return r;
}

/* Insert KEY into filter B.
 *
 * Returns 1 if the key collided with existing entries (that is, all of the bits
 * set due to B were already set).  Returns 0 if B caused a bit to be set.
 */
int bloom_insert(struct bloom_params *p, u8 *b, u8 *key)
{
    int i, did_collide = 1;

    for (i=0; i<p->nbit; i++) {
        int x = get_bits(key, i * p->bitperf, p->bitperf) % p->size;
        did_collide &= set_bit(b, x);
    }
    return did_collide;
}

/* Check if KEY is present in filter B.
 *
 * Returns 1 if KEY may have been inserted (all of the bits set due to KEY are
 * set).  Returns 0 if KEY was not inserted.
 */
int bloom_present(struct bloom_params *p, u8 *b, u8 *key)
{
    int i;
    for (i=0; i<p->nbit; i++) {
        int x = get_bits(key, i * p->bitperf, p->bitperf) % p->size;
        if (get_bit(b, x) == 0)
            return 0;
    }
    return 1;
}

#ifdef MAIN

int o_verbose = 0;
FILE *f_debug = NULL;

int main(void)
{
    printf("running Bloom filter tests\n");
    printf("testing get_bits ..."); fflush(stdout);
    {
        int ntest = 0;
        u8 a[] = { 0x12, 0x34, 0x55, 0x66, 0x77, 0xff, 0xab };

        ASSERT(get_bits(a, 0, 8)  ==       0x12); ntest++;
        ASSERT(get_bits(a, 0, 4)  ==        0x1); ntest++;
        ASSERT(get_bits(a, 4, 4)  ==        0x2); ntest++;
        ASSERT(get_bits(a, 5, 4)  ==        0x4); ntest++;
        ASSERT(get_bits(a, 5, 8)  ==       0x46); ntest++;
        ASSERT(get_bits(a, 0, 32) == 0x12345566); ntest++;
        ASSERT(get_bits(a, 1, 32) == 0x2468aacc); ntest++;
        ASSERT(get_bits(a, 2, 32) == 0x48d15599); ntest++;

        u8 b[] = { 0xff, 0x18, 0x33 };
        ASSERT(get_bits(b,  0, 1) == 1); ntest++;
        ASSERT(get_bits(b,  1, 1) == 1); ntest++;
        ASSERT(get_bits(b,  2, 1) == 1); ntest++;
        ASSERT(get_bits(b,  3, 1) == 1); ntest++;
        ASSERT(get_bits(b,  7, 1) == 1); ntest++;
        ASSERT(get_bits(b,  8, 1) == 0); ntest++;
        ASSERT(get_bits(b,  9, 1) == 0); ntest++;
        ASSERT(get_bits(b, 10, 1) == 0); ntest++;
        ASSERT(get_bits(b, 11, 1) == 1); ntest++;
        ASSERT(get_bits(b, 12, 1) == 1); ntest++;
        ASSERT(get_bits(b, 13, 1) == 0); ntest++;
        ASSERT(get_bits(b, 16, 1) == 0); ntest++;
        ASSERT(get_bits(b, 17, 1) == 0); ntest++;
        ASSERT(get_bits(b, 18, 1) == 1); ntest++;
        ASSERT(get_bits(b, 19, 1) == 1); ntest++;
        printf(" passed %d tests\n", ntest);
    }

    printf("testing get_bit ..."); fflush(stdout);
    {
        int ntest = 0;
        u8 a[] = { 0xff, 0x18, 0x33 };
        ASSERT(get_bit(a,  0) == 1); ntest++;
        ASSERT(get_bit(a,  1) == 1); ntest++;
        ASSERT(get_bit(a,  2) == 1); ntest++;
        ASSERT(get_bit(a,  3) == 1); ntest++;
        ASSERT(get_bit(a,  7) == 1); ntest++;
        ASSERT(get_bit(a,  8) == 0); ntest++;
        ASSERT(get_bit(a,  9) == 0); ntest++;
        ASSERT(get_bit(a, 10) == 0); ntest++;
        ASSERT(get_bit(a, 11) == 1); ntest++;
        ASSERT(get_bit(a, 12) == 1); ntest++;
        ASSERT(get_bit(a, 13) == 0); ntest++;
        ASSERT(get_bit(a, 16) == 0); ntest++;
        ASSERT(get_bit(a, 17) == 0); ntest++;
        ASSERT(get_bit(a, 18) == 1); ntest++;
        ASSERT(get_bit(a, 19) == 1); ntest++;
        printf(" passed %d tests\n", ntest);
    }

    printf("testing set_bit ..."); fflush(stdout);
    {
        int ntest = 0;
        u8 a[10] = { 0 };

        ASSERT(set_bit(a, 0) == 0);
        ASSERT(a[0] == 0x80); ntest++;
        ASSERT(set_bit(a, 1) == 0);
        ASSERT(a[0] == 0xc0); ntest++;
        ASSERT(set_bit(a, 7) == 0);
        ASSERT(a[0] == 0xc1); ntest++;
        ASSERT(set_bit(a, 8) == 0);
        ASSERT(a[1] == 0x80); ntest++;
        ASSERT(set_bit(a, 8) == 1); ntest++;
        ASSERT(set_bit(a, 20) == 0);
        ASSERT(a[2] == 0x08); ntest++;

        printf(" passed %d test\n", ntest);
    }
    printf("testing bloom_insert ..."); fflush(stdout);
    {
        int ntest = 0;
    }

    return 0;
}
#endif
