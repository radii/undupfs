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
 * The parameters are stored in a `struct bloom_params` which is returned from
 * bloom_setup().  Each filter bitarray is initialized by a call to bloom_init.
 *
 * Keys are assumed to be a hash output, and are assumed to be a random
 * selection from {0,1}^N.  Bits from the key are used directly as inputs to the
 * Bloom filter function, rather than being hashed as in a general purpose Bloom
 * filter implementaiton.
 *
 * Keys are inserted into a filter by calling bloom_insert().
 *
 * Key presence is tested by calling bloom_present().
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
 * Both bits and bytes are indexed big-endian:
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
static u32 get_bits(const u8 *a, int pos, int nbit)
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

static u32 get_bit(const u8 *a, int pos)
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
int bloom_insert(struct bloom_params *p, u8 *b, const u8 *key)
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
int bloom_present(struct bloom_params *p, const u8 *b, const u8 *key)
{
    int i;
    for (i=0; i<p->nbit; i++) {
        int x = get_bits(key, i * p->bitperf, p->bitperf) % p->size;
        if (get_bit(b, x) == 0)
            return 0;
    }
    return 1;
}

int bloom_weight(struct bloom_params *p, const u8 *b)
{
    int i, w;
    const u8 t[] = {
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
    };

    for (i=w=0; i<p->bytesize; i++) {
        w += t[b[i]];
    }
    return w;
}

void bloom_dump(struct bloom_params *p, const u8 *b, FILE *f, const u8 *key)
{
    int i;
    int w = bloom_weight(p, b);
    int m = -1;

    if (key) {
        m = 0;
        for (i=0; i<p->nbit; i++) {
            int x = get_bits(key, i * p->bitperf, p->bitperf) % p->size;
            if (get_bit(b, x) == 0)
                m++;
        }
        m = p->nbit - m;
    }

    fprintf(f, "%p weight %d/%d (%.2f%%) m=%d/%d %02x%02x%02x%02x\n",
            b, w, p->size, 100.0 * w / p->size, m, p->nbit,
            key[0], key[1], key[2], key[3]);
    for (i=0; i<p->bytesize; i++) {
        fprintf(f, "%02x%s", b[i], (i % 16 == 15) ? "\n" : "  " + (i % 8 != 7));
    }
    fprintf(f, "\n");
}

#ifdef MAIN

#include <openssl/sha.h>

int o_verbose = 0;
FILE *f_debug = NULL;

static int hexnibble(int x)
{
    if (x >= '0' && x <= '9')
        return x - '0';
    if (x >= 'a' && x <= 'f')
        return x - 'a' + 10;
    if (x >= 'A' && x <= 'F')
        return x - 'A' + 10;
    ASSERT(0 == 1);
    return 0;
}

static void hex2bytes(u8 *b, const char *p)
{
    int i;

    for(i=0; p[i] && p[i+1]; i+=2) {
        b[i/2] = hexnibble(p[i]) << 4 | hexnibble(p[i+1]);
    }
    ASSERT(p[i] == '\0');
}

static void hash(void *h, const void *buf, int n)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buf, n);
    SHA256_Final(h, &ctx);
}

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

        printf(" passed %d tests\n", ntest);
    }
    printf("testing bloom_insert ..."); fflush(stdout);
    {
        int ntest = 0;
        int hashsz = 32; // SHA256
        int bitsperhash = 7;
        u8 h[10][32];
        struct bloom_params *p;
        u8 *b;
        int x, i;
        int fp = 0;

        hex2bytes(h[0], "9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa");
        hex2bytes(h[1], "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865");
        hex2bytes(h[2], "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3");
        hex2bytes(h[3], "1121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2");
        hex2bytes(h[4], "7de1555df0c2700329e815b93b32c571c3ea54dc967b89e81ab73b9972b72d1d");
        hex2bytes(h[5], "f0b5c2c2211c8d67ed15e75e656c7862d086e9245420892a7de62cd9ec582a06");
        hex2bytes(h[6], "06e9d52c1720fca412803e3b07c4b228ff113e303f4c7ab94665319d832bbfb7");
        hex2bytes(h[7], "10159baf262b43a92d95db59dae1f72c645127301661e0a3ce4e38b295a97c58");
        hex2bytes(h[8], "aa67a169b0bba217aa0aa88a65346920c84c42447c36ba5f7ea65f422c1fe5d8");
        hex2bytes(h[9], "2e6d31a5983a91251bfae5aefa1c0a19d8ba3cf601d0e8a706b4cfa9661a6b8a");

        ASSERT(h[0][0] == 0x9a); ntest++;
        ASSERT(h[0][31] == 0xaa); ntest++;
        ASSERT(h[1][0] == 0x43); ntest++;
        ASSERT(h[1][31] == 0x65); ntest++;

        p = bloom_setup(1024, bitsperhash, hashsz);
        b = malloc(p->bytesize); // XXX

        ASSERT(b);

        bloom_init(p, b);
        bloom_insert(p, b, h[0]);
        ASSERT(bloom_weight(p, b) == bitsperhash); ntest++;
        bloom_insert(p, b, h[0]);
        ASSERT(bloom_weight(p, b) == bitsperhash); ntest++;
        bloom_insert(p, b, h[1]);
        ASSERT(bloom_weight(p, b) > 2 * bitsperhash - 2);
        ASSERT(bloom_weight(p, b) < 2 * bitsperhash + 1); ntest++;
        bloom_insert(p, b, h[1]);
        ASSERT(bloom_weight(p, b) > 2 * bitsperhash - 2);
        ASSERT(bloom_weight(p, b) < 2 * bitsperhash + 1); ntest++;

        ASSERT(bloom_present(p, b, h[2]) == 0); ntest++;

        bloom_insert(p, b, h[2]);
        ASSERT(bloom_weight(p, b) > 3 * bitsperhash - 2);
        ASSERT(bloom_weight(p, b) < 3 * bitsperhash + 1); ntest++;

        ASSERT(bloom_present(p, b, h[2]) == 1); ntest++;

        x = bloom_weight(p, b);
        bloom_insert(p, b, h[2]);
        ASSERT(x == bloom_weight(p, b));

        ASSERT(bloom_present(p, b, h[3]) == 0); ntest++;
        bloom_insert(p, b, h[3]);
        ASSERT(bloom_present(p, b, h[3]) == 1); ntest++;
        ASSERT(bloom_weight(p, b) > 4 * bitsperhash - 2);
        ASSERT(bloom_weight(p, b) < 4 * bitsperhash + 1); ntest++;

        ASSERT(bloom_present(p, b, h[4]) == 0); ntest++;
        bloom_insert(p, b, h[4]);
        ASSERT(bloom_present(p, b, h[4]) == 1); ntest++;
        ASSERT(bloom_weight(p, b) > 5 * bitsperhash - 2);
        ASSERT(bloom_weight(p, b) < 5 * bitsperhash + 1); ntest++;

        ASSERT(bloom_present(p, b, h[5]) == 0); ntest++;
        bloom_insert(p, b, h[5]);
        ASSERT(bloom_present(p, b, h[5]) == 1); ntest++;
        ASSERT(bloom_weight(p, b) > 6 * bitsperhash - 2);
        ASSERT(bloom_weight(p, b) < 6 * bitsperhash + 1); ntest++;

        ASSERT(bloom_present(p, b, h[6]) == 0); ntest++;
        bloom_insert(p, b, h[6]);
        ASSERT(bloom_present(p, b, h[6]) == 1); ntest++;
        ASSERT(bloom_weight(p, b) > 7 * bitsperhash - 2);
        ASSERT(bloom_weight(p, b) < 7 * bitsperhash + 1); ntest++;

        ASSERT(bloom_present(p, b, h[7]) == 0); ntest++;
        bloom_insert(p, b, h[7]);
        ASSERT(bloom_present(p, b, h[7]) == 1); ntest++;
        ASSERT(bloom_weight(p, b) > 8 * bitsperhash - 2);
        ASSERT(bloom_weight(p, b) < 8 * bitsperhash + 1); ntest++;

        ASSERT(bloom_present(p, b, h[8]) == 0); ntest++;
        bloom_insert(p, b, h[8]);
        ASSERT(bloom_present(p, b, h[8]) == 1); ntest++;
        ASSERT(bloom_weight(p, b) > 9 * bitsperhash - 3);
        ASSERT(bloom_weight(p, b) < 9 * bitsperhash + 1); ntest++;

        ASSERT(bloom_present(p, b, h[9]) == 0); ntest++;
        bloom_insert(p, b, h[9]);
        ASSERT(bloom_present(p, b, h[9]) == 1); ntest++;
        ASSERT(bloom_weight(p, b) > 10 * bitsperhash - 3);
        ASSERT(bloom_weight(p, b) < 10 * bitsperhash + 1); ntest++;

        fp = 0;
        for (i=0; i<300; i++) {
            char a[10];
            u8 g[32];
            int collided, before, after;

            snprintf(a, sizeof a, "%d", i);
            hash(g, a, sizeof(a));
            before = bloom_present(p, b, g);
            collided = bloom_insert(p, b, g);
            after = bloom_present(p, b, g);
            ASSERT(after);
            ASSERT(before == collided);
            fp += collided;
            ntest++;
        }
        ASSERT(fp < 50);
        ASSERT(fp > 1);
        ntest++;

        printf(" passed %d tests\n", ntest);
    }

    return 0;
}
#endif
