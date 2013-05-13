/*
 * undup-fuse: a deduplicating filesystem using FUSE.
 *
 * Copyright (C) 2012-2013 Andrew Isaacson <adi@hexapodia.org>
 *
 * This program is free software, licensed under the terms of the GNU GPL
 * version 3.  See the file COPYING for more information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <pthread.h>

#include <openssl/sha.h>

#include "shared.h"
#include "core.h"
#include "undupfs.h"
#include "bloom.h"

void state_rdlock(struct undup_state *state)
{
    int e;

    if ((e = pthread_rwlock_rdlock(&state->lock)) != 0)
        die("pthread_rwlock_rdlock: %s\n", strerror(e));
}

void state_wrlock(struct undup_state *state)
{
    int e;

    if ((e = pthread_rwlock_wrlock(&state->lock)) != 0)
        die("pthread_rwlock_wrlock: %s\n", strerror(e));
}

void state_unlock(struct undup_state *state)
{
    int e;

    if ((e = pthread_rwlock_unlock(&state->lock)) != 0)
        die("pthread_rwlock_unlock: %s\n", strerror(e));
}

int stub_refresh(struct undup_state *state, struct stub *stub)
{
    int n;

    n = pread(stub->fd, &stub->hdr, sizeof(stub->hdr), 0);
    if (n == -1) {
        debug("stub_refresh(stub=%p fd=%d) pread errno=%d (%s)\n",
                stub, stub->fd, errno, strerror(errno));
        return -1;
    }
    if (n < sizeof(stub->hdr)) {
        errno = EIO;
        return -1;
    }
    debug("stub_refresh %p fd=%d magic=0x%x version=%d flags=0x%x len=%lld\n",
            stub, stub->fd, stub->hdr.magic, stub->hdr.version,
            stub->hdr.flags, (long long)stub->hdr.len);
    return 0;
}

struct stub *stub_open(struct undup_state *state, const char *stubpath, int rdwr)
{
    struct stub *stub = calloc(sizeof *stub, 1);
    int e;

    if (!stub) {
       errno = ENOMEM;
       return NULL;
    }

    ASSERT(rdwr == O_RDONLY || rdwr == O_RDWR || rdwr == O_WRONLY);

    stub->fd = open(stubpath, O_RDWR);
    if (stub->fd == -1)
        goto err;
    if (stub_refresh(state, stub) == -1)
        goto err;
    debug("stub_open(%s) = %p fd=%d magic=0x%x version=%d flags=0x%x len=%lld\n",
            stubpath, stub, stub->fd, stub->hdr.magic, stub->hdr.version,
            stub->hdr.flags, (long long)stub->hdr.len);
    return stub;
err:
    e = errno;
    close(stub->fd);
    free(stub);
    errno = e;
    return NULL;
}

int stub_close(struct undup_state *state, struct stub *stub)
{
    int n, e;

    debug("stub_close(%p) fd=%d\n", stub, stub->fd);
    n = close(stub->fd);
    e = errno;
    free(stub);
    return n == -1 ? -e : 0;
}

int stub_update_len(struct stub *stub, off_t newlen, int do_trunc)
{
    int n;

    debug("stub_update_len %p len=%lld newlen=%lld trunc=%d\n",
          stub, (long long)stub->hdr.len, (long long)newlen, do_trunc);

    if (do_trunc == 0 && newlen <= stub->hdr.len)
        return 0;

    stub->hdr.len = newlen;
    n = pwrite(stub->fd, &stub->hdr.len, sizeof(stub->hdr.len),
               offsetof(struct undup_hdr, len));
    if (n == -1)
        return -1;
    if (n < sizeof(stub->hdr.len)) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int stub_get_hash(struct undup_state *state, struct stub *stub, off_t off, u8 *hash)
{
    off_t hashpos;
    int n;
   
    hashpos = UNDUP_HDR_SIZE + (off >> state->blkshift) * state->hashsz;
    n = pread(stub->fd, hash, state->hashsz, hashpos);
    if (n == -1)
        return -1;
    if (n < state->hashsz) {
        errno = EIO;
        verbose("got %d bytes (needed %d) at %lld\n",
                n, state->hashsz, (long long)hashpos);
        return -1;
    }
    return 0;
}

void print_hash(FILE *f, const u8 *buf, int n)
{
    int i;

    for (i=0; i<n; i++)
        fprintf(f, "%02x", buf[i]);
}

int dumptocs(FILE *f, struct undup_state *state)
{
    int i, j, n; 
    u8 buf[HASH_BLOCK]; 
    struct stat st; 
    int ntoc, nhash;
    off_t flen, blkpos; 
    u8 b0[state->bp0->bytesize];
    u8 b1[state->bp1->bytesize];

    nhash = HASH_BLOCK / state->hashsz; 

    bloom_init(state->bp0, b0);
    bloom_init(state->bp1, b1);

    for (i=0; ; i++) {
        blkpos = (off_t)HASH_BLOCK * ((i + 1) * (nhash + 1));

        n = pread(state->fd, buf, HASH_BLOCK, blkpos);
        if (n == 0) break;
        if (n == -1) die("dumpbucket: pread: %s\n", strerror(errno));
        if (n < HASH_BLOCK)
            die("dumpbucket: short read: %d at %lld\n", n, (long long)blkpos);

        fprintf(f, "TOC %d at %lld (0x%llx):\n", i,
                (long long)blkpos, (long long)blkpos);
        for (j=0; j<nhash; j++) {
            u8 *p = buf + j * state->hashsz;

            bloom_insert(state->bp0, b0, p);
            bloom_insert(state->bp1, b1, p);

            fprintf(f, "%-8lld ", (long long)i * nhash + j);
            print_hash(f, p, state->hashsz);
            fprintf(f, "\n");
        }
        bloom_dump(state->bp0, b0, f, buf);
        bloom_init(state->bp0, b0);

        fprintf(f, "b1 at %d:\n", i);
        bloom_dump(state->bp1, b1, f, buf);

        if (i % state->bloomscale == state->bloomscale - 1) {
            fprintf(f, "b1 at %d:\n", i);
            bloom_dump(state->bp1, b1, f, buf);
            bloom_init(state->bp1, b1);
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

        fprintf(f, "%d blocks (%d bytes) remaining after TOC %d\n",
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
            fprintf(f, "%-8lld ", (long long)blknum);
            print_hash(f, hash, state->hashsz);
            fprintf(f, "\n");
        }
    }
    return ntoc;
}

static void dump_tables(struct undup_state *state, const u8 *hash)
{
    if (f_debug == NULL) return;

    dumptocs(f_debug, state);
}

static void dump_blooms(struct undup_state *state, const u8 *hash)
{
    int i;

    if (f_debug == NULL) return;

    for (i=0; i<state->nblooms; i++) {
        debug("bloom0[%d] = %p\n", i, state->bloom0[i]);
        if (state->bloom0[i])
            bloom_dump(state->bp0, state->bloom0[i], f_debug, hash);
    }
    for (i=0; i<state->nblooms / state->bloomscale; i++) {
        debug("bloom1[%d] = %p\n", i, state->bloom1[i]);
        if (state->bloom1[i])
            bloom_dump(state->bp1, state->bloom1[i], f_debug, hash);
    }
    fflush(f_debug);
}

static int event_counts[COUNT_MAX], event_counts_prev[COUNT_MAX];
static double event_times[COUNT_MAX], event_times_prev[COUNT_MAX];
static u64 event_values[COUNT_MAX], event_values_prev[COUNT_MAX];

void count_event(int event, double elapsed, int value)
{
    if (!f_stats) return;
    ASSERT(event > 0 && event < COUNT_MAX);
    event_counts[event]++;
    event_times[event] += elapsed;
    event_values[event] += value;
}

void count_print_stats(struct undup_state *state, FILE *f)
{
    int i, n, w;
    int c[COUNT_MAX];
    double t[COUNT_MAX];
    u64 v[COUNT_MAX];

    for (i=0; i<COUNT_MAX; i++) {
        c[i] = event_counts[i] - event_counts_prev[i];
        t[i] = event_times[i] - event_times_prev[i];
        v[i] = event_values[i] - event_values_prev[i];
    }

    fprintf(f, "read:  %.2f elapsed %d total %.2f µs/event %.2f MB/sec\n",
            t[COUNT_READ],
            c[COUNT_READ],
            t[COUNT_READ] * 1e6 / c[COUNT_READ],
            v[COUNT_READ] / t[COUNT_READ] / 1024 / 1024);
    fprintf(f, "write: %.2f elapsed %d total %.2f µs/event %.2f MB/sec\n",
            t[COUNT_WRITE],
            c[COUNT_WRITE],
            t[COUNT_WRITE] * 1e6 / c[COUNT_WRITE],
            v[COUNT_WRITE] / t[COUNT_WRITE] / 1024 / 1024);
    fprintf(f, "bloom0: %d query, %d hit, %d false positive, %.0f%% fp rate\n",
            c[COUNT_BLOOM_QUERY0],
            c[COUNT_BLOOM_HIT0],
            c[COUNT_BLOOM_FP0],
            c[COUNT_BLOOM_FP0] * 100.0 /
            (c[COUNT_BLOOM_HIT0] + c[COUNT_BLOOM_FP0]));
    fprintf(f, "bloom1: %d query, %d hit, %d false positive, %.0f%% fp rate\n",
            c[COUNT_BLOOM_QUERY1],
            c[COUNT_BLOOM_HIT1],
            c[COUNT_BLOOM_FP1],
            c[COUNT_BLOOM_FP1] * 100.0 /
            (c[COUNT_BLOOM_HIT1] + c[COUNT_BLOOM_FP1]));
    for (i=n=w=0; i<state->nblooms; i++) {
        if (state->bloom0[i]) {
            n++;
            w += bloom_weight(state->bp0, state->bloom0[i]);
        }
    }
    fprintf(f, "bloom0: %d/%d tables, %d bits set (%.0f%%)\n",
            n, state->nblooms, w,
            w * 100.0 / (state->nblooms * state->bp0->size));
    for (i=n=w=0; i<state->nblooms / state->bloomscale; i++) {
        if (state->bloom1[i]) {
            n++;
            w += bloom_weight(state->bp1, state->bloom1[i]);
        }
    }
    fprintf(f, "bloom1: %d/%d tables, %d bits set (%.0f%%)\n",
            n, state->nblooms / state->bloomscale, w,
            w * 100.0 / (state->nblooms / state->bloomscale * state->bp1->size));

    memcpy(event_times_prev, event_times, sizeof event_times);
    memcpy(event_counts_prev, event_counts, sizeof event_counts);
    memcpy(event_values_prev, event_values, sizeof event_values);
}

/*
 * Find HASH in the bucket.  If found, fill in FD and OFF and return 1.
 * If not found, return 0.  On error, return -1 with errno set.
 */
static int lookup_hash(struct undup_state *state, const u8 *hash, int *fd, off_t *off)
{
    int h, i, j, n;
    char buf[HASH_BLOCK];
    off_t blkpos;
    int hashsz = state->hashsz;
    int nhash = HASH_BLOCK / hashsz;

    for (h = 0; ; h++) {
        int nbloom1 = state->nblooms / state->bloomscale;

        count_event(COUNT_BLOOM_QUERY1, 0, 1);
        if (h < nbloom1 &&
                state->bloom1 &&
                state->bloom1[h] &&
                !bloom_present(state->bp1, state->bloom1[h], hash)) {
            debug("%02x%02x%02x%02x bloom1 %d/%d miss\n",
                    hash[0], hash[1], hash[2], hash[3], h, nbloom1);
            continue;
        }
        for (i = h * state->bloomscale; i < (h + 1) * state->bloomscale ; i++) {
            count_event(COUNT_BLOOM_QUERY0, 0, 1);
            if (i < state->nblooms &&
                    state->bloom0[i] &&
                    !bloom_present(state->bp0, state->bloom0[i], hash)) {
                debug("%02x%02x%02x%02x bloom0 %d/%d miss\n",
                        hash[0], hash[1], hash[2], hash[3], i, state->nblooms);
                continue;
            } else {
                debug("%02x%02x%02x%02x bloom %d/%d possible\n",
                        hash[0], hash[1], hash[2], hash[3], i, state->nblooms);
            }

            blkpos = HASH_BLOCK * ((i + 1) * (nhash + 1));
            n = pread(state->fd, buf, HASH_BLOCK, blkpos);
            debug("lookup_hash pos=%lld n=%d\n", (long long)blkpos, n);
            if (n == 0)
                goto out;
            if (n == -1)
                return -1;
            if (n < HASH_BLOCK) {
                errno = EIO;
                return -1;
            }

            if (i >= state->nblooms || !state->bloom0[i]) {
                int newn = i + 1;
                int i1 = i / state->bloomscale;
                int newn1 = newn / state->bloomscale + 2;

                u8 **newblooms0 = realloc(state->bloom0, newn * sizeof *state->bloom0);
                u8 **newblooms1 = 0;
                u8 *newbloom0 = malloc(state->bp0->bytesize); // XXX
                u8 *newbloom1 = 0;

                if (!state->bloom1 ||
                        i1 > state->nblooms / state->bloomscale ||
                        !state->bloom1[i1]) {
                    newblooms1 = realloc(state->bloom1,
                            newn1 * sizeof *state->bloom1);
                    newbloom1 = malloc(state->bp1->bytesize); // XXX
                    if (!newblooms1 || !newbloom1)
                        goto free_error;
                }

                if (!newblooms0 || !newbloom0) {
free_error:
                    free(newblooms0);
                    free(newbloom0);
                    free(newblooms1);
                    free(newbloom1);
                } else {
                    for (j = state->nblooms; j < i; j++)
                        newblooms0[j] = NULL;
                    if (newblooms1) {
                        for (j = nbloom1; j < newn1; j++) {
                            newblooms1[j] = NULL;
                        }
                    }
                    newblooms0[i] = newbloom0;
                    bloom_init(state->bp0, newblooms0[i]);
                    state->bloom0 = newblooms0;
                    if (newblooms1) {
                        newblooms1[i1] = newbloom1;
                        bloom_init(state->bp1, newblooms1[i1]);
                        state->bloom1 = newblooms1;
                    }
                    state->nblooms = newn;
                    for (j = 0; j < nhash; j++) {
                        void *p = buf + j * state->hashsz;
                        u8 *b = p;
                        debug("insert i=%d j=%d %02x%02x%02x%02x\n",
                                i, j, b[0], b[1], b[2], b[3]);
                        bloom_insert(state->bp0, state->bloom0[i], p);
                        bloom_insert(state->bp1, state->bloom1[i1], p);
                    }
                }
                dump_blooms(state, hash);
            }

            for (j = 0; j < nhash; j++) {
                debug("%02x%02x%02x%02x <> %02x%02x%02x%02x\n",
                        hash[0], hash[1], hash[2], hash[3],
                        (u8)(buf+j*hashsz)[0], (u8)(buf+j*hashsz)[1],
                        (u8)(buf+j*hashsz)[2], (u8)(buf+j*hashsz)[3]);
                if (!memcmp(buf + (j * hashsz), hash, hashsz)) {
                    *fd = state->fd;
                    *off = HASH_BLOCK * (1 + j + (i * (1 + nhash)));
                    count_event(COUNT_BLOOM_HIT0, 0, 1);
                    count_event(COUNT_BLOOM_HIT1, 0, 1);
                    return 1;
                }
            }
            count_event(COUNT_BLOOM_FP0, 0, 1);
        }
        count_event(COUNT_BLOOM_FP1, 0, 1);
    }
out:
    for (j = 0; j < state->hbpos / hashsz; j++) {
        debug("%02x%02x%02x%02x <> %02x%02x%02x%02x\n",
              (u8)hash[0], (u8)hash[1], (u8)hash[2], (u8)hash[3],
              (u8)(state->hashblock+j*hashsz)[0],
              (u8)(state->hashblock+j*hashsz)[1],
              (u8)(state->hashblock+j*hashsz)[2],
              (u8)(state->hashblock+j*hashsz)[3]);
        if (!memcmp(state->hashblock + (j * hashsz), hash, hashsz)) {
            *fd = state->fd;
            *off = HASH_BLOCK * (1 + j + (i * (1 + nhash)));
            return 1;
        }
    }
    return 0;
}

void count_maybe_dump(struct undup_state *state, double t)
{
    static double last_t;
    double t0, t1;

    if (!f_stats) return;
    if (t < last_t + 1) return;

    t0 = rtc();

    last_t = t;

    fprintf(f_stats, "%.3f\n", t);
    count_print_stats(state, f_stats);
    fflush(f_stats);
    t1 = rtc();
    fprintf(f_stats, "stats output took %.6f\n", t1 - t0);
}

int stub_read(struct undup_state *state, struct stub *stub, void *buf, size_t size, off_t offset)
{
    int tot, n, m, ret;
    off_t datapos = -1;
    int datafd = -1;
    u8 hash[HASH_MAX];

    debug("stub_read(%p, %d, %lld len=%lld)\n", stub,
            (int)size, (long long)offset, (long long)stub->hdr.len);

    if (offset >= stub->hdr.len)
        return 0;

    if (offset + size > stub->hdr.len && offset <= stub->hdr.len) {
        size = stub->hdr.len - offset;
    }

    tot = 0;
    while (size > 0) {
        state_rdlock(state);
        ret = stub_get_hash(state, stub, offset, hash);
        if (ret != -1)
            ret = lookup_hash(state, hash, &datafd, &datapos);
        state_unlock(state);
        debug("lookup got %d %d %lld\n", ret, datafd, (long long)datapos);
        if (ret == -1)
            return -1;
        if (ret == 0) {
            state_wrlock(state);
            dump_tables(state, hash);
            dump_blooms(state, hash);
            state_unlock(state);
            errno = EIO;
            return -1;
        }
        m = size > state->blksz ? state->blksz : size;
        debug("pread(%d, %p, %d, %lld)\n", datafd, buf, m, (long long)datapos);
        n = pread(datafd, buf, m, datapos);
        if (n == -1)
            return -1;
        if (n < m) {
            errno = EIO;
            return -1;
        }
        size -= n;
        buf += n;
        offset += n;
        tot += n;
    }

    return tot;
}

static int all_zeros(u8 *buf, int n)
{
    int i;

    for (i=0; i<n; i++)
        if (buf[i] != 0) return 0;
    return 1;
}

/*
 * Validate the bucket described by STATE.  This includes adjusting fields
 * such as state->bucketlen so that future blocks go to the right place,
 * but it does not validate block hashes in the bucket.
 *
 * The following system is used to recover from a partially written tail
 * segment.
 *  - for each data block in the segment, check if it is all 0s.
 *  - if nonzero, hash it and store the hash in state->hashblock.
 *  - adjust bucketlen and hbpos to the last non-zero data block.
 */
int bucket_validate(struct undup_state *state)
{
    int chunksz = state->blksz * (1 + (state->blksz / state->hashsz));
    int ntailbyte = (state->bucketlen - state->blksz) % chunksz;
    int ntailblk = ntailbyte / state->blksz;
    int i, n, nzero;
    u8 buf[state->blksz], *hash;

    debug("bucket_validate len=%lld hbpos=%d (%d bytes in tail = %d blocks) %d blocks total%s\n",
            (long long)state->bucketlen, state->hbpos, ntailbyte, ntailblk, 0,
            ntailbyte % state->blksz == 0 ? "" : " (MISALIGNED)");

    if (ntailbyte == 0) return 0;

    for (i = nzero = 0; ; i++) {
        off_t pos = state->bucketlen - ntailbyte + i * state->blksz;

        n = pread(state->fd, buf, state->blksz, pos);
        if (n == 0) break;
        if (n == -1)
            die("bucket_validate: pread(%d, %lld) = %d (%d '%s')\n",
                    state->blksz, (long long)pos, n, errno, strerror(errno));
        if (all_zeros(buf, state->blksz))
            nzero++;
        else
            nzero = 0;
        hash = &state->hashblock[i * state->hashsz];
        do_hash(hash, buf, n);
    }

    state->hbpos = i * state->hashsz;

    debug("bucket_validate hbpos=%d i=%d\n", state->hbpos, i);

    return 0;
}

/*
 * Writes the block BLK to file STUBFD at offset BLKOFF with hash HASH.
 * BLK must be of size state->blksz, BLKOFF must be naturally aligned,
 * and HASH must be the hash of BLK.
 *
 * Since STUBFD is a "stub file" (see DESIGN for details), and we have already
 * established that HASH is not present in the bucket, a write consists of
 *  - write BLOCK and HASH to the bucket.
 *  - write HASH to the appropriate spot in the stub file.
 *  - update undup_hdr.len if necessary.
 *
 * returns 0 on success, or -errno on failure.
 */
int stub_write_block(struct undup_state *state, struct stub *stub,
                     off_t blkoff, const u8 *blk, int blklen, u8 *hash)
{
    off_t hashidx = blkoff >> state->blkshift;
    off_t hashpos = sizeof(struct undup_hdr) + hashidx * state->hashsz;
    int n;

    ASSERT((blkoff & (state->blksz-1)) == 0);

    debug("write_block off=%lld hash=%02x%02x%02x%02x\n",
          (long long)blkoff, hash[0], hash[1], hash[2], hash[3]);

    memcpy(state->hashblock + state->hbpos, hash, state->hashsz);
    state->hbpos += state->hashsz;
    n = pwrite(state->fd, blk, state->blksz, state->bucketlen);
    if (n == -1)
        return -errno;
    if (n < state->blksz)
        return -EIO;
    state->bucketlen += state->blksz;
    ASSERT(state->hbpos <= state->blksz);
    if (state->hbpos == state->blksz) {
        n = pwrite(state->fd, state->hashblock, state->blksz, state->bucketlen);
        if (n == -1)
            return -errno;
        if (n < state->blksz)
            return -EIO;
        state->hbpos = 0;
        state->bucketlen += state->blksz;
    }
    n = pwrite(stub->fd, hash, state->hashsz, hashpos);
    if (n == -1)
        return -errno;
    if (n < state->hashsz)
        return -EIO;

    return 0;
}

void do_hash(void *hash, const void *buf, int n)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buf, n);
    SHA256_Final(hash, &ctx);
}

int stub_write(struct undup_state *state, struct stub *stub, const void *buf, size_t n, off_t off)
{
    u8 hash[HASH_MAX];
    int ret = 0;
    int datafd = -1;
    off_t datapos = -1;

    ASSERT(n == HASH_BLOCK);

    do_hash(hash, buf, n);

    state_wrlock(state);

    ret = lookup_hash(state, hash, &datafd, &datapos);
    debug("lookup_hash got %d %d %lld n=%d\n",
          ret, datafd, (long long)datapos, (int)n);
    if (ret == -1)
        goto out;
    if (ret == 0) {
        // not found, write new block to bucket, write hash to stubfile
        ret = stub_write_block(state, stub, off, buf, state->blksz, hash);
        goto out;
    } else {
        off_t hashidx = off >> state->blkshift;
        off_t hashpos = sizeof(struct undup_hdr) + hashidx * state->hashsz;

        // found; optionally read+verify data, write hash
        ret = pwrite(stub->fd, hash, state->hashsz, hashpos);
        if (ret == -1)
            goto out;
        if (ret < state->hashsz) {
            errno = EIO;
            goto out;
        }
    }
out:
    state_unlock(state);
    return ret;
}
