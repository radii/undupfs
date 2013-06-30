/*
 * undup-debug: debug commands for undupfs
 *
 * Copyright (C) 2013 Andrew Isaacson <adi@hexapodia.org>
 *
 * This program is free software, licensed under the terms of the GNU GPL
 * version 3.  See the file COPYING for more information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "myfts.h"

#include "shared.h"
#include "core.h"
#include "undupfs.h"
#include "bloom.h"

static void usage(const char *cmd) __attribute__((noreturn));

static void usage(const char *cmd)
{
    fprintf(stderr, "Usage: %s -[v] cmd /path/to/file\n", cmd);
    fprintf(stderr, "Valid values for cmd include:\n");
    fprintf(stderr, "  dumpstub /path/to/undupfs/stubfile\n");
    fprintf(stderr, "  dumpbucket /path/to/.undupfs/undup.dat\n");
    fprintf(stderr, "  gccheck /path/to/undupfs\n");
    fprintf(stderr, "  hashbench\n");
    fprintf(stderr, "  hashunit\n");
    die("");
}

int o_verbose = 0;
FILE *f_debug = NULL;
FILE *f_stats = NULL;

struct undup_state *debug_init(const char *basedir)
{
    char fname[PATH_MAX];
    int fd, n, ver;
    off_t flen;
    struct stat st;
    struct undup_hdr hdr;
    int filtersz0 = 1024;
    int filtersz1 = filtersz0 * 20;
    int bitcount = 7;
    int bitcount1 = 3;
    struct undup_state *state;

    char *f = getenv("UNDUP_DEBUG");
    if (f) {
        if (!strcmp(f, "stderr"))
            f_debug = stderr;
        else
            f_debug = fopen(f, "w");
    }
    f = getenv("UNDUP_STATS");
    if (f) {
        f_stats = fopen(f, "w");
    }
    n = snprintf(fname, sizeof fname, "%s/.undupfs/undup.dat", basedir);
    if (n > sizeof fname) return NULL;
    if ((fd = open(fname, O_RDWR)) == -1)
        die("%s: %s\n", fname, strerror(errno));
    if (fstat(fd, &st) == -1)
        die("fstat: %s\n", strerror(errno));
    flen = st.st_size;
    n = read(fd, &hdr, sizeof hdr);
    if (n != sizeof hdr)
        die("unable to read header, got %d errno = %d (%s)\n",
            n, errno, strerror(errno));
    if (hdr.magic != UNDUPFS_MAGIC)
        die("bad magic: 0x%08x\n", hdr.magic);
    ver = hdr.version;
    if (ver != 0x01)
        die("%s: Unknown version: 0x%04x\n", hdr.version);
    if (hdr.flags != 0)
        die("%s: Unknown flags: 0x%04x\n", hdr.flags);
    if (hdr.len != 0)
        die("%s: corrupt len: %08x\n", hdr.len);

    state = calloc(sizeof *state, 1);
    if (!state) die("malloc: %s\n", strerror(errno));
    state->basedir   = strdup(basedir);
    state->blksz     = HASH_BLOCK;
    state->blkshift  = 12;
    state->fd        = fd;
    state->bucketlen = flen;
    state->hashblock = malloc(HASH_BLOCK);
    state->hbpos     = 0;
    state->nblooms   = 0;
    state->bloomscale = 128;

    ASSERT(1 << state->blkshift == state->blksz);

    // if ver == 1
    state->hashsz    = 32;

    state->bp0 = bloom_setup(filtersz0, bitcount, state->hashsz);
    state->bp1 = bloom_setup(filtersz1, bitcount1, state->hashsz);

    bucket_validate(state);

    debug("undup_init done, base=%s len=%lld\n",
          state->basedir, (long long)flen);

    return state;
}

static int dumpstub(int argc, char **argv)
{
    struct stub *stub;
    struct undup_state *state;
    char *fname;
    off_t i, nhash;

    fname = argv[1];
    state = debug_init(argv[0]);
    if (!state) die("%s: %s\n", argv[0], strerror(errno));
    stub = stub_open(state, fname, O_RDONLY);
    if (!stub) die("%s: %s\n", fname, strerror(errno));
    printf("%s: magic 0x%x version %d flags 0x%x len %lld (%.1f MiB)\n",
            fname, stub->hdr.magic, stub->hdr.version, stub->hdr.flags,
            stub->hdr.len, stub->hdr.len / 1024. / 1024);

    nhash = stub->hdr.len / state->blksz + !!(stub->hdr.len % state->blksz);

    printf("dumping %d hashes:\n", (int)nhash);

    for (i=0; i<nhash; i++) {
        int n;
        u8 hash[state->hashsz];
        off_t pos = sizeof(stub->hdr) + i * state->hashsz;

        if ((n = pread(stub->fd, hash, state->hashsz, pos)) == -1)
            die("pread(%d, %p, %d, %lld): %s\n",
                    stub->fd, hash, state->hashsz,
                    (long long)pos, strerror(errno));

        if (n < state->hashsz)
            die("%s: early EOF at %lld (got %d of %d)\n",
                    fname, (long long)pos, n, state->hashsz);

        printf("%-8lld ", (long long)i);
        print_hash(stdout, hash, state->hashsz);
        printf("\n");
    }

    return 0;
}

static int dumpbucket(int argc, char **argv)
{
    struct undup_state *state;

    state = debug_init(argv[0]);
    if (!state) die("%s: %s\n", argv[0], strerror(errno));

    printf("%s hashsz=%d blksz=%d fd=%d len=%lld\n",
            state->basedir, state->hashsz, state->blksz,
            state->fd, (long long)state->bucketlen);

    dumptocs(stdout, state);
    return 0;
}

/* compute how many data blocks are in the given bucket.  The layout is
 * +--------+----+----+----+----+----------+----+----+----+----+----------+
 * | header | d0 | d1 | d2 | d3 | h0h1h2h3 | d4 | d5 | d6 | d7 | h4h5h6h7 |
 * +--------+----+----+----+----+----------+----+----+----+----+----------+
 * where d0 is data block 0 and h0 is the hash of d0.
 *
 * so the number of datablocks is the byte length, minus the header, divided
 * by the block size, divided by (N+1) and then multiplied by N to account
 * for the hashblocks.  Then add on any remainder to account for not-yet-hashed
 * blocks.  For 4k blocks with 32 byte (256 bit) hashes, N = 4096 / 32 = 128.
 */
static u64 bucket_nblock(struct undup_state *state)
{
    u64 blkbytes = state->bucketlen - sizeof(struct undup_hdr);
    u64 numblk = blkbytes / state->blksz;
    int hashperblk = state->blksz / state->hashsz;
    u64 leftover = blkbytes % (state->blksz * (hashperblk + 1));
    u64 numdatablk = numblk / (hashperblk + 1) * hashperblk;

    return numdatablk + leftover / state->blksz;
}

u64 blknum_offset(struct undup_state *state, off_t off)
{
    u64 offbytes = off - sizeof(struct undup_hdr);
    u64 numblk = offbytes / state->blksz;
    int hashperblk = state->blksz / state->hashsz;
    u64 leftover = offbytes % (state->blksz * (hashperblk + 1));
    u64 numdatablk = numblk / (hashperblk + 1) * hashperblk;

    return numdatablk + leftover / state->blksz;
}

struct gcstats {
    u64 numblk;
    u64 ncount;
    u8 *count;
    u8 *hash;
};

static void u8_saturating_add(u8 *x, int delta)
{
    int a = *x + delta;
    if (a > 255)
        *x = 255;
    else if (a < 0)
        *x = 0;
    else
        *x = a;
}

/* Threadsafe implementation of bsearch(3).
 *
 * Similar to bsearch(3) from <stdlib.h> except that the compar() helper
 * function takes an argument `arg' to allow the caller to pass per-instance
 * data in.
 *
 * Compare the qsort(3) versus qsort_r(3) functions.
 */
void *bsearch_r(const void *key, const void *base,
        size_t nmemb, size_t size,
        int (*compar)(const void *, const void *, void *), void *arg)
{
    const unsigned char *b = base;
    size_t n = 0, m = nmemb - 1;
    int r;
    const void *p;

    p = b + m * size;
    r = (*compar)(key, p, arg);
    if (r == 0)
        return (void *)p;
    else if (r > 0)
        return NULL;

    p = b;
    r = (*compar)(key, p, arg);
    if (r == 0)
        return (void *)p;
    else if (r < 0)
        return NULL;

    while (m - n > 1) {
        size_t i = n + (m - n) / 2;
        p = b + i * size;

        r = (*compar)(key, p, arg);

        if (r == 0)
            return (void *)p;
        else if (r > 0)
            n = i;
        else if (r < 0)
            m = i;
    }
    return NULL;
}

static int hash_compar(const void *a, const void *b, void *arg)
{
    struct undup_state *state = arg;

    return memcmp(a, b, state->hashsz);
}

static off_t blkidx_search(struct undup_state *state, struct gcstats *gc, u8 *hash)
{
    u8 *p;

    p = bsearch_r(hash, gc->hash, gc->ncount, state->hashsz, hash_compar, state);
    if (!p) return -1;
    return (p - gc->hash) / state->hashsz;
}

static int gccount_one(struct undup_state *state, struct gcstats *gc,
        struct stub *stub, char *fname)
{
    u64 nhash;
    int i;

    nhash = stub->hdr.len / state->blksz + !!(stub->hdr.len % state->blksz);

    printf("counting %d hashes from %s:\n", (int)nhash, fname);

    for (i=0; i<nhash; i++) {
        int n;
        off_t blkidx;
        u8 hash[state->hashsz];
        off_t pos = sizeof(stub->hdr) + i * state->hashsz;

        if ((n = pread(stub->fd, hash, state->hashsz, pos)) == -1)
            die("pread(%d, %p, %d, %lld): %s\n",
                    stub->fd, hash, state->hashsz,
                    (long long)pos, strerror(errno));

        if (n == 0)
            return 0;
        if (n < state->hashsz)
            die("%s: early EOF at %lld (got %d of %d)\n",
                    fname, (long long)pos, n, state->hashsz);
        if (lookup_special(state, hash, 0, 0))
            continue;
        blkidx = blkidx_search(state, gc, hash);
        if (blkidx == -1) {
            die("Search for %02x%02x%02x%02x failed\n",
                    hash[0], hash[1], hash[2], hash[3]);
        }
        u8_saturating_add(&gc->count[blkidx], 1);
        gc->numblk++;

        if (i % 1000 == 0) {
            printf("%d %d\r", i, (int)blkidx);
            fflush(stdout);
        }
    }
    printf("\n");
    return 0;
}

static int gccheck(int argc, char **argv)
{
    struct undup_state *state;
    struct stub *stub;
    char *paths[2] = { argv[0], 0 };
    FTS *fts;
    FTSENT *e;
    char undup_path[PATH_MAX];
    struct gcstats *gcstats;
    int histogram[256] = { 0 };
    int i, n, nblk, hashperblk;
    u64 nhash;
    off_t blkpos;

    snprintf(undup_path, PATH_MAX, "%s/.undupfs", argv[0]);

    state = debug_init(argv[0]);
    if (!state) die("%s: %s\n", argv[0], strerror(errno));

    gcstats = calloc(sizeof *gcstats, 1);
    if (!gcstats) die("malloc failed\n");
    nhash = bucket_nblock(state);
    gcstats->ncount = nhash;
    gcstats->count = calloc(nhash, 1);
    if (!gcstats->count)
        die("malloc(%lld) failed\n", bucket_nblock(state));
    gcstats->hash = calloc(nhash, state->hashsz);
    if (!gcstats->hash)
        die("malloc(%lld) failed\n", nhash * state->hashsz);

    hashperblk = state->blksz / state->hashsz;
    nblk = nhash / hashperblk;
    printf("reading %d hashes (tail %lld) total %d.\n", (int)nblk * hashperblk,
            (nhash - nblk * hashperblk), (int)nhash);
    for (i=0; i<nblk; i++) {
        off_t blkpos = HASH_BLOCK * ((i + 1) * (hashperblk + 1));
        u8 *p = gcstats->hash + i * HASH_BLOCK;
        n = pread(state->fd, p, HASH_BLOCK, blkpos);
        if (n != HASH_BLOCK) {
            die("pread(%d, %p, %lld, %lld) = %d (%s)\n",
                    state->fd, gcstats->hash, HASH_BLOCK, (u64)blkpos, n, strerror(errno));
        }
    }
    for (i = nblk * hashperblk, blkpos = HASH_BLOCK * (1 + (nblk * (hashperblk + 1)));
         blkpos < state->bucketlen;
         i++, blkpos += HASH_BLOCK) {
        u8 buf[HASH_BLOCK];
        u8 *p = gcstats->hash + i * state->hashsz;

        n = pread(state->fd, buf, HASH_BLOCK, blkpos);
        if (n != HASH_BLOCK) {
            die("pread(%d, %p, %lld, %lld) = %d (%s)\n",
                    state->fd, buf, HASH_BLOCK, blkpos, n, strerror(errno));
        }
        do_hash(p, state->hashsz, buf, n);
    }

    qsort_r(gcstats->hash, nhash, state->hashsz, hash_compar, state);

    fts = fts_open(paths, FTS_XDEV, NULL);
    if (!fts) die("fts_open(%s): %s\n", argv[0], strerror(errno));

    while ((e = fts_read(fts)) != NULL) {
        if (!strcmp(e->fts_name, ".undupfs") &&
                !strcmp(e->fts_path, undup_path)) {
            fts_set(fts, e, FTS_SKIP);
        }
        if (e->fts_info == FTS_F) {
            stub = stub_open(state, e->fts_path, O_RDONLY);
            if (!stub) die("%s: %s\n", e->fts_path, strerror(errno));
            gccount_one(state, gcstats, stub, e->fts_path);
            stub_close(state, stub);
        }
    }
    for (i=0; i<gcstats->ncount; i++) {
        histogram[gcstats->count[i]]++;
    }
    for (n = 255; n > 0; n--)
        if (histogram[n] > 0) break;
    n = (n / 8 + !!(n % 8)) * 8;
    for (i=0; i<n; i++) {
        printf("%7d%s", histogram[i], i % 8 == 7 ? "\n" : " ");
    }
    printf("%d unused blocks (%.0f%%)\n",
            histogram[0], histogram[0] * 100. / gcstats->ncount);
    printf("%lld blocks stored, %lld blocks used, %.0f%% saved\n",
            gcstats->ncount, gcstats->numblk,
            100 - gcstats->ncount * 100. / gcstats->numblk);

    fts_close(fts);
    return 0;
}

static int hashbench(int argc, char **argv)
{
    double t0, t1, t;
    int i;
    int n = 10240;
    int buflen = 4096;
    int nmb = n * buflen / 1024 / 1024;
    char *buf = malloc(buflen);
    int hashsz = 32;
    u8 hash[hashsz];
    int residue = 0;

    memset(buf, 1, buflen);
    t0 = rtc();
    for (i=0; i<n; i++) {
        *(int *)buf = i;
        do_hash(hash, hashsz, buf, buflen);
        residue += hash[0];
    }
    t1 = rtc();

    t = t1 - t0;
    printf("%d MB in %.3f sec %.1f MB/sec %.2f nsec/byte r=%d\n",
            nmb, t, nmb / t, t * 1e9 / (nmb * 1024 * 1024), residue);
    return 0;
}

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

static int hashunit(int argc, char **argv)
{
    char buf[4096];
    int hashsz = 32;
    u8 h[hashsz], g[hashsz];
    int ntest = 0;
    int buflen;

    /* standard test vector */
    buflen = snprintf(buf, sizeof buf, "hello, world\n");
    hex2bytes(h, "f65f341b35981fda842b09b2c8af9bcd");
    do_hash(g, hashsz, buf, buflen);
    ASSERT(memcmp(g, h, sizeof(g)) == 0); ntest++;

    /* zero length test vector */
    buflen = 0;
    hex2bytes(h, "cf83e1357eefb8bdf1542850d66d8007");
    do_hash(g, hashsz, buf, buflen);
    ASSERT(memcmp(g, h, sizeof(g)) == 0); ntest++;

    printf("hash unit tests passed %d tests\n", ntest);
    return 0;
}

struct {
    const char *name;
    int (*func)(int, char **);
} cmds[] = {
    { "dumpstub", dumpstub },
    { "dumpbucket", dumpbucket },
    { "gccheck", gccheck },
    { "hashbench", hashbench },
    { "hashunit", hashunit },
    { 0, 0 }
};

void version(void)
{
    fprintf(stderr, "undupfs-debug version 0.1 (2013-06-29)\n");
    exit(0);
}

int main(int argc, char **argv)
{
    int c, i;

    if (argc > 1 && (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version")))
        version();
    while ((c = getopt(argc, argv, "hv")) != EOF)  {
        switch(c) {
        case 'h':
            usage(argv[0]);
        case 'v':
            o_verbose++;
            break;
        default:
            fprintf(stderr, "Unknown option '%c'\n", c);
            usage(argv[0]);
        }
    }

    if (argc - optind < 2)
        usage(argv[0]);

    for (i=0; cmds[i].name; i++) {
        if (!strcmp(argv[optind], cmds[i].name))
            return (cmds[i].func)(argc - optind - 1, &argv[optind + 1]);
    }

    fprintf(stderr, "Unknown command '%s'\n", argv[optind]);
    usage(argv[0]);
}
