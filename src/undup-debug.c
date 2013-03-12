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
    int filtersz1 = filtersz0 * 4;
    int bitcount = 7;
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
    state->hashsz    = 32; // SHA256

    state->bp0 = bloom_setup(filtersz0, bitcount, state->hashsz);
    state->bp1 = bloom_setup(filtersz1, bitcount, state->hashsz);

    bucket_validate(state);

    debug("undup_init done, base=%s len=%lld\n",
          state->basedir, (long long)flen);

    return state;
}

void print_hash(FILE *f, const u8 *buf, int n)
{
    int i;

    for (i=0; i<n; i++)
        fprintf(f, "%02x", buf[i]);
}

static int dumpstub(int argc, char **argv)
{
    struct stub *stub;
    struct undup_state *state;
    char *fname;
    int len;
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
            die("%s: early EOF at %lld (got %d of %d0\n",
                    fname, (long long)pos, n, state->hashsz);

        printf("%-8lld ", (long long)i);
        print_hash(stdout, hash, state->hashsz);
        printf("\n");
    }

    return 0;
}

static int dumpbucket(int argc, char **argv)
{
    int i, j, n;
    u8 buf[HASH_BLOCK];
    struct undup_state *state;
    int nhash, ntoc;
    struct stat st;
    off_t flen, blkpos;
    
    state = debug_init(argv[0]);
    if (!state) die("%s: %s\n", argv[0], strerror(errno));

    nhash = HASH_BLOCK / state->hashsz;

    printf("%s hashsz=%d blksz=%d fd=%d len=%lld\n",
            state->basedir, state->hashsz, state->blksz,
            (long long)state->bucketlen);

    for (i=0; ; i++) {
        blkpos = (off_t)HASH_BLOCK * ((i + 1) * (nhash + 1));

        n = pread(state->fd, buf, HASH_BLOCK, blkpos);
        if (n == 0) break;
        if (n == -1) die("dumpbucket: pread: %s\n", strerror(errno));
        if (n < HASH_BLOCK)
            die("dumpbucket: short read: %d at %lld\n", n, (long long)blkpos);

        printf("TOC %d at %lld (0x%llx):\n", i,
                (long long)blkpos, (long long)blkpos);
        for (j=0; j<nhash; j++) {
            printf("%-8lld ", i * nhash + j);
            print_hash(stdout, buf + j * state->hashsz, state->hashsz);
            printf("\n");
        }
    }
    ntoc = i - 1;
    if (fstat(state->fd, &st) == -1)
        die("fstat: %s\n", strerror(errno));
    flen = st.st_size;

    blkpos = (off_t)HASH_BLOCK * ((ntoc + 1) * (nhash + 1));
    if (blkpos + HASH_BLOCK < flen) {
        int nbyte = flen - (blkpos + HASH_BLOCK);
        int nblock = nbyte / HASH_BLOCK;

        printf("%d blocks (%d bytes) remaining after TOC %d\n",
                nblock, nbyte, ntoc);
        for (i = 0; i < nblock; i ++) {
            off_t pos = blkpos + i * HASH_BLOCK;
            u8 hash[state->hashsz];
            int blknum = (ntoc + 1) * nhash + i;

            n = pread(state->fd, buf, HASH_BLOCK, pos);
            if (n == 0) break;
            if (n == -1) die("dumpbucket: pread: %s\n", strerror(errno));
            if (n < HASH_BLOCK)
                die("dumpbucket: short read: %d at %lld\n", n, (long long)pos);
            do_hash(hash, buf, n);
            printf("%-8lld ", (long long)blknum);
            print_hash(stdout, hash, state->hashsz);
            printf("\n");
        }
    }
    return 0;
}

struct {
    const char *name;
    int (*func)(int, char **);
} cmds[] = {
    { "dumpstub", dumpstub },
    { "dumpbucket", dumpbucket },
    { 0, 0 }
};

int main(int argc, char **argv)
{
    int c, i;

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
