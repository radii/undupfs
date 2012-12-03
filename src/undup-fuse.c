/*
 * undup-fuse: a deduplicating filesystem using FUSE.
 *
 * Copyright (C) 2012 Andrew Isaacson <adi@hexapodia.org>
 *
 * This program is free software, licensed under the terms of the GNU GPL
 * version 3.  See the file COPYING for more information.
 */

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>

#include <openssl/sha.h>

#include "undupfs.h"

struct undup_state {
    char *basedir;
    int hashsz;      // the size of a single hash
    int blksz;       // the size of a block (power of 2)
    int blkshift;    // the shift for a block (log_2(blksz))
    int fd;          // filedescriptor to bucketfile
    off_t bucketlen; // length of bucketfile
    char *hashblock; // in-progress block of hashes
    int hbpos;       // current position in hashblock
};

static struct undup_state *state;

static void die(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(1);
}

#define ASSERT(cond_) do { if (!(cond_)) die("%s:%d: ASSERT failed: %s\n", \
                                        __FILE__, __LINE__, #cond_); } while(0)

static int o_verbose = 0;
static FILE *f_debug = NULL;

static void verbose(char *fmt, ...)
{
    va_list ap;

    if (!o_verbose) return;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static void debug(char *fmt, ...)
{
    va_list ap;

    if (!f_debug) return;

    va_start(ap, fmt);
    vfprintf(f_debug, fmt, ap);
    va_end(ap);
    fflush(f_debug);
}

/*
 * Find HASH in the bucket.  If found, fill in FD and OFF and return 1.
 * If not found, return 0.  On error, return -1 with errno set.
 */
static int lookup_hash(const char *hash, int *fd, off_t *off)
{
    int i, j, n;
    char buf[HASH_BLOCK];
    off_t blkpos;
    int hashsz = state->hashsz;
    int nhash = HASH_BLOCK / hashsz;

    for (i = 0; ; i++) {
        blkpos = (off_t)HASH_BLOCK * ((1 + i) * nhash + 1);
        n = pread(state->fd, buf, HASH_BLOCK, blkpos);
        debug("lookup_hash pos=%lld n=%d\n", (long long)blkpos, n);
        if (n == 0)
            return 0;
        if (n == -1)
            return -1;
        if (n < HASH_BLOCK) {
            errno = EIO;
            return -1;
        }
        for (j = 0; j < nhash; j++) {
            if (!memcmp(buf + (j * hashsz), hash, hashsz)) {
                *fd = state->fd;
                *off = HASH_BLOCK * (1 + j + (i * (1 + nhash)));
                return 1;
            }
        }
    }
    return 0;
}

static int undup_getattr(const char *path, struct stat *stbuf)
{
    char b[PATH_MAX+1];
    int n, err, fd;
    struct undup_hdr hdr;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    debug("getattr path=%s b=%s\n", path, b);

    n = stat(b, stbuf);
    if (n == -1)
        return -errno;

    if (S_ISDIR(stbuf->st_mode))
        return 0;

    fd = open(b, O_RDONLY);
    if (fd == -1)
        return -errno;

    n = pread(fd, &hdr, sizeof(hdr), 0);
    if (n == -1)
        goto out;
    if (n < sizeof(hdr)) {
        errno = -EIO;
        goto out;
    }
    stbuf->st_size = hdr.len;

    close(fd);
    return 0;
out:
    err = errno;
    close(fd);
    return -err;
}

static int undup_opendir(const char *path, struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    int n;
    DIR *dp;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    dp = opendir(b);
    if (dp == NULL)
        return -EIO;
    fi->fh = (long)(void *)dp;

    return 0;
}

static int undup_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    int n, err = 0;
    DIR *dp;
    struct dirent *de;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    dp = (DIR *)(void *)fi->fh;

    debug("readdir path=%s off=%lld b=%s dp=%p\n",
          path, (long long)offset, b, dp);

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        if (!strcmp(de->d_name, ".undupfs"))
            continue;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0)) {
            err = errno ? errno : EIO;
            break;
        }
    }

    closedir(dp);
    return -err;
}

static int undup_mkdir(const char *path, mode_t mode)
{
    char b[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;
    return n == -1 ? -errno : n;
}

static int undup_unlink(const char *path)
{
    char b[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;
    return n == -1 ? -errno : n;
}

static int undup_rmdir(const char *path)
{
    char b[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;
    return n == -1 ? -errno : n;
}

static int undup_rename(const char *from, const char *to)
{
    char b[PATH_MAX+1], c[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, from);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    n = snprintf(c, PATH_MAX, "%s/%s", state->basedir, to);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    n = rename(b, c);
    return n == -1 ? -errno : n;
}

static int undup_truncate(const char *path, off_t size)
{
    char b[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    return n == -1 ? -errno : 0;
}

static int undup_open(const char *path, struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    n = open(b, fi->flags);
    return n == -1 ? -errno : 0;
}

static int undup_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    int n, fd;
    struct undup_hdr hdr;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    debug("create path=%s mode=0%o\n", path, mode);

    fd = creat(b, mode);
    if (fd == -1)
        return -errno;

    fi->fh = fd;

    hdr.magic = UNDUPFS_MAGIC;
    hdr.version = 1;
    hdr.flags = 0;
    hdr.len = 0;

    n = write(fd, &hdr, sizeof(hdr));
    if (n == -1)
        return -errno;

    return 0;
}

static int undup_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    char hash[HASH_MAX];
    int n, m, err, ret;
    off_t hashpos, datapos = -1;
    int fd, datafd = -1;
    int tot;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    fd = open(b, O_RDONLY);
    if (fd == -1)
        return -errno;

    tot = 0;
    while (size > 0) {
        hashpos = UNDUP_HDR_SIZE + (offset >> state->blkshift) * state->hashsz;
        n = pread(fd, hash, state->hashsz, hashpos);
        if (n == -1)
            goto out;
        if (n < state->hashsz) {
            errno = EIO;
            verbose("got %d bytes (needed %d) at %lld (%s)\n",
                    n, state->hashsz, (long long)hashpos, path);
            goto out;
        }
        ret = lookup_hash(hash, &datafd, &datapos);
        debug("loookup got %d %d %lld\n", ret, datafd, datapos);
        if (ret == -1)
            goto out;
        if (ret == 0) {
            errno = EIO;
            goto out;
        }
        m = size > state->blksz ? state->blksz : size;
        n = pread(datafd, buf, m, datapos);
        if (n == -1)
            goto out;
        if (n < m) {
            errno = -EIO;
            goto out;
        }
        size -= n;
        buf += n;
        offset += n;
        tot += n;
    }

    return tot;
out:
    err = errno;
    close(fd);
    return -err;
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
static int write_block(int stubfd, off_t blkoff, const char *blk, char *hash)
{
    off_t hashidx = blkoff >> state->blkshift;
    off_t hashpos = sizeof(struct undup_hdr) + hashidx * state->hashsz;
    int n;

    ASSERT((blkoff & (state->blksz-1)) == 0);

    memcpy(state->hashblock + state->hbpos, hash, state->hashsz);
    state->hbpos += state->hashsz;
    n = pwrite(state->fd, blk, state->blksz, state->bucketlen);
    if (n == -1)
        return -errno;
    if (n < state->blksz)
        return -EIO;
    state->bucketlen += state->blksz;
    if (state->hbpos == state->blksz) {
        n = pwrite(state->fd, state->hashblock, state->blksz, state->bucketlen);
        if (n == -1)
            return -errno;
        if (n < state->blksz)
            return -EIO;
        state->hbpos = 0;
        state->bucketlen += state->blksz;
    }
    n = pwrite(stubfd, hash, state->hashsz, hashpos);
    if (n == -1)
        return -errno;
    if (n < state->hashsz)
        return -EIO;

    return 0;
}

static void do_hash(void *hash, const char *buf, int n)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buf, n);
    SHA256_Final(hash, &ctx);
}

static int undup_write(const char *path, const char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    int i, n, fd, ret;
    char hash[HASH_MAX];
    int datafd = -1;
    off_t datapos = -1;

    ASSERT((size % HASH_BLOCK) == 0);
    ASSERT((offset % HASH_BLOCK) == 0);

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    debug("write path=%s size=%d offset=%lld\n", path, (int)size,
          (long long)offset);
    fd = open(b, O_RDWR);
    if (fd == -1)
        return -errno;

    for (i = 0; i < size; i += state->blksz) {
        n = size - i;
        if (n > state->blksz) n = state->blksz;
        do_hash(hash, buf + i, n);
        ret = lookup_hash(hash, &datafd, &datapos);
        debug("loookup_hash got %d %d %lld\n", ret, datafd, datapos);
        if (ret == -1)
            goto out;
        if (ret == 0) {
            // not found, write new block to bucket, write hash to stubfile
            ret = write_block(fd, offset, buf + i, hash);
            goto out;
        } else {
            off_t hashidx = offset >> state->blkshift;
            off_t hashpos = sizeof(struct undup_hdr) + hashidx * state->hashsz;

            // found; optionally read+verify data, write hash
            n = pwrite(fd, hash, state->hashsz, hashpos);
            if (n == -1)
                goto out;
            if (n < state->hashsz) {
                errno = -EIO;
                goto out;
            }

        }
    }

    //calculate hashes
    //lookup hashes in bucket
    //if present, write hashes
    //if not present, write blocks to bucket and write hashes
    //update length as necessary

out:
    return n == -1 ? -errno : n;
}

static struct fuse_operations undup_oper = {
    .getattr            = undup_getattr,
    .readdir            = undup_readdir,
    .opendir            = undup_opendir,
    .mkdir              = undup_mkdir,
    .unlink             = undup_unlink,
    .rmdir              = undup_rmdir,
    .truncate           = undup_truncate,
    .open               = undup_open,
    .create             = undup_create,
    .read               = undup_read,
    .write              = undup_write,
    .rename             = undup_rename,
};

static int undup_init(const char *basedir)
{
    char fname[PATH_MAX];
    int fd, n, ver;
    off_t flen;
    struct stat st;
    struct undup_hdr hdr;

    char *f = getenv("UNDUP_DEBUG");
    if (f) {
        f_debug = fopen(f, "w");
    }
    n = snprintf(fname, sizeof fname, "%s/.undupfs/undup.dat", basedir);
    if (n > sizeof fname) return -ENAMETOOLONG;
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

    ASSERT(1 << state->blkshift == state->blksz);

    // if ver == 1
    state->hashsz    = 32; // SHA256

    debug("undup_init done, base=%s len=%lld\n",
          state->basedir, (long long)flen);

    return 0;
}

void usage(const char *cmd)
{
    die("Usage: %s -[vd] undupdir mountpoint\n", cmd);
}

int main(int argc, char **argv)
{
    if (argc < 3)
        usage(argv[0]);
    undup_init(argv[argc-2]);
    argv[argc-2] = argv[argc-1];
    argv[argc-1] = NULL;
    argc--;
    return fuse_main(argc, argv, &undup_oper, state);
}
