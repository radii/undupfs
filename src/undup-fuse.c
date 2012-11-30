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

#include "undupfs.h"

struct undup_state {
    char *basedir;
    int hashsz;
    int blksz;
    int blkshift;
    int fd;
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

static int o_verbose = 0;

static void verbose(char *fmt, ...)
{
    va_list ap;

    if (!o_verbose) return;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
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
        blkpos = (1 + i) * (1 + nhash);
        n = pread(state->fd, buf, HASH_BLOCK, blkpos);
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
    off_t flen;
    struct undup_hdr hdr;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    fd = open(b, O_RDONLY);
    if (fd == -1)
        return -errno;

    n = fstat(fd, stbuf);
    if (n == -1)
        goto out;
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

    dp = opendir(b);
    if (dp == NULL)
        return -errno;

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
    return n == -1 ? -errno : n;
}

static int undup_open(const char *path, struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    n = open(path, fi->flags);
    return n == -1 ? -errno : 0;
}

static int undup_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    char hash[HASH_MAX];
    int n, m, err, ret;
    off_t hashpos, datapos;
    int fd, datafd;
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

static int undup_write(const char *path, const char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    //calculate hashes
    //lookup hashes in bucket
    //if present, write hashes
    //if not present, write blocks to bucket and write hashes
    //update length as necessary

    return n == -1 ? -errno : n;
}

static struct fuse_operations undup_oper = {
    .getattr            = undup_getattr,
    .readdir            = undup_readdir,
    .mkdir              = undup_mkdir,
    .unlink             = undup_unlink,
    .rmdir              = undup_rmdir,
    .truncate           = undup_truncate,
    .open               = undup_open,
    .read               = undup_read,
    .write              = undup_write,
    .rename             = undup_rename,
};

int main(int argc, char **argv)
{
    return fuse_main(argc, argv, &undup_oper, NULL);
}
