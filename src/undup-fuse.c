/*
 * undup-fuse: a deduplicating filesystem using FUSE.
 *
 * Copyright (C) 2012-2013 Andrew Isaacson <adi@hexapodia.org>
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
#include <sys/time.h>

#include <pthread.h>

#include <openssl/sha.h>

#include "core.h"
#include "shared.h"
#include "undupfs.h"
#include "bloom.h"

static struct undup_state *state;

int o_verbose = 0;
FILE *f_debug = NULL;
FILE *f_stats = NULL;

static int undup_getattr(const char *path, struct stat *stbuf)
{
    char b[PATH_MAX+1];
    int n;
    struct stub *stub;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    debug("getattr path=%s b=%s\n", path, b);

    n = stat(b, stbuf);
    if (n == -1)
        return -errno;

    if (S_ISDIR(stbuf->st_mode))
        return 0;

    stub = stub_open(state, b, O_RDONLY);
    if (stub == NULL)
        return -errno;

    stbuf->st_size = stub->hdr.len;

    stub_close(state, stub);
    return 0;
}

static int undup_chown(const char *path, uid_t uid, gid_t gid)
{
    char b[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    debug("chown path=%s b=%s uid=%d gid=%d\n", path, b, uid, gid);

    n = chown(b, uid, gid);
    return n < 0 ? -errno : 0;
}

static int undup_chmod(const char *path, mode_t mode)
{
    char b[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    debug("chmod path=%s b=%s mode=0%o\n", path, b, mode);

    n = chmod(b, mode);

    return n < 0 ? -errno : 0;
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

    debug("mkdir(%s, 0%o)\n", path, mode);

    n = mkdir(b, mode);
    return n == -1 ? -errno : n;
}

static int undup_unlink(const char *path)
{
    char b[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    verbose("unlink(%s)\n", path);

    n = unlink(b);

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

static int undup_readlink(const char *path, char *buf, size_t size)
{
    char b[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    /* XXX probably only handles relative links.  Need to handle
     *  - absolute links
     *  - correctly truncating ../../.. at root
     */
    debug("readlink(%s, %p, %d)\n", b, buf, (int)size);
    n = readlink(b, buf, size);
    return n == -1 ? -errno : n;
}

static int undup_symlink(const char *oldpath, const char *newpath)
{
    char b[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, newpath);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    debug("symlink(%s, %s)\n", oldpath, b);
    n = symlink(oldpath, b);
    return n == -1 ? -errno : n;
}

static int undup_link(const char *from, const char *to)
{
    char b[PATH_MAX+1], c[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, from);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    n = snprintf(c, PATH_MAX, "%s/%s", state->basedir, to);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    debug("link(%s, %s)\n", b, c);
    n = link(b, c);
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

    debug("rename(%s, %s)\n", b, c);
    n = rename(b, c);
    return n == -1 ? -errno : n;
}

static int undup_truncate(const char *path, off_t size)
{
    char b[PATH_MAX+1];
    int n, ret;
    struct stub *stub;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    debug("truncate(%s, %lld)\n", b, (long long)size);

    if (n == -1)
       return -errno;

    stub = stub_open(state, b, O_RDWR);
    if (!stub)
        return -errno;

    ret = stub_update_len(stub, size, 1);
    stub_close(state, stub);
    return ret;
}

static int undup_open(const char *path, struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    int n, openmode;
    struct stub *stub;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    debug("open(%s, flags=0x%x)\n", path, fi->flags);

    if ((fi->flags & O_ACCMODE) == O_RDWR)
        openmode = O_RDWR;
    else if ((fi->flags & O_ACCMODE) == O_RDONLY)
        openmode = O_RDONLY;
    else if ((fi->flags & O_ACCMODE) == O_WRONLY)
        openmode = O_WRONLY;
    else {
        debug("open failing with flags 0x%x\n", fi->flags);
        return -EINVAL;
    }

    stub = stub_open(state, b, openmode);
    if (!stub)
        return -errno;

    fi->fh = (intptr_t)stub;
    return 0;
}

static int undup_release(const char *path, struct fuse_file_info *fi)
{
    int n;
    struct stub *stub = (struct stub *)fi->fh;

    debug("undup_release(%s fi=%p stub=%p)\n", path, fi, stub);

    n = stub_close(state, stub);
    fi->fh = 0;

    return n < 0 ? -errno : n;
}

static int undup_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    int n, fd;
    struct undup_hdr hdr;
    struct stub *stub;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    debug("create path=%s mode=0%o\n", path, mode);

    fd = creat(b, mode);
    if (fd == -1)
        return -errno;

    hdr.magic = UNDUPFS_MAGIC;
    hdr.version = 1;
    hdr.flags = 0;
    hdr.len = 0;

    n = write(fd, &hdr, sizeof(hdr));
    if (n == -1)
        return -errno;

    if (close(fd) == -1)
        debug("undup_create: close(%d): %d (%s)\n", fd, errno, strerror(errno));
    // XXX whatta hack, do a stub_create() or something
    stub = stub_open(state, b, O_RDWR);
    if (!stub)
        return -errno;

    fi->fh = (intptr_t)stub;

    return 0;
}

static int undup_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    int n, ret;
    struct stub *stub;
    double t0, t1;

    t0 = rtc();

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    stub = (struct stub *)fi->fh;
    if (!stub)
        return -EIO;

    debug("undup_read off=%lld size=%d path=%s len=%lld\n",
          (long long)offset, (int)size, path, (long long)stub->hdr.len);

    ret = stub_read(state, stub, buf, size, offset);
    debug("undup_read return %d errno=%d\n", ret, errno);
    t1 = rtc();
    count_event(COUNT_READ, t1 - t0, size);
    state_wrlock(state);
    count_maybe_dump(state, t1);
    state_unlock(state);
    return ret;
}

static int undup_write(const char *path, const char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    int i, n, ret = 0;
    struct stub *stub;
    u8 *fillbuf = NULL;
    size_t nwrite = 0;
    off_t orig_offset = offset;
    double t0, t1;

    t0 = rtc();

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    stub = (struct stub *)fi->fh;
    debug("undup_write path=%s size=%d offset=%lld fi=%p flags=%x stub=%p\n",
            path, (int)size, (long long)offset, fi, fi ? (int)fi->flags : 0, stub);
    if (!stub)
        return -EIO;

    if ((i = offset % state->blksz) > 0) {
        off_t blkoff = offset - i;

        debug("  offset fill i=%d off=%lld blkoff=%lld\n", i, (long long)offset,
                (long long)blkoff);
        fillbuf = malloc(state->blksz);
        if (!fillbuf) {
            ret = -ENOMEM;
            goto out_close;
        }
        ret = stub_read(state, stub, fillbuf, state->blksz, blkoff);
        if (ret == -1)
            goto out_close;

        n = state->blksz - i;
        if (n > size) n = size;
        memcpy(fillbuf + i, buf, n);
        if (i + n < state->blksz && ret < state->blksz) {
            int m = i + n;
            if (m < ret) m = ret;
            memset(fillbuf + m, 0, state->blksz - m);
        }

        debug("  prefix write i=%d n=%d blkoff=%lld offset=%lld\n",
                i, n, (long long)blkoff, (long long)offset);
        ret = stub_write(state, stub, fillbuf, state->blksz, blkoff);
        if (ret == -1) {
            goto out_close;
        }
        offset = offset + n;
        size -= n;
        buf += n;
        nwrite += n;
        debug("  end prefix nwrite=%d n=%d off=%lld\n", (int)nwrite, n,
                (long long)offset);
    }

    for (i = 0; i + state->blksz <= size; i += state->blksz) {
        n = size - i;
        if (n > state->blksz) n = state->blksz;
        debug("  write block i=%d n=%d nwrite=%d offset=%lld\n",
                i, n, (int)nwrite, (long long)offset);
        stub_write(state, stub, buf + i, n, offset + i);
        nwrite += n;
        debug("  end block nwrite=%d n=%d\n", (int)nwrite, n);
    }
    if (i < size) {
        off_t blkoff = offset + i;

        ASSERT(i < state->blksz);
        debug("  tail write i=%d offset=%lld blkoff=%lld size=%d\n",
                i, (long long)offset, (long long)blkoff, (int)size);
        if (!fillbuf) fillbuf = malloc(state->blksz);
        if (!fillbuf) {
            ret = -ENOMEM;
            goto out;
        }

        ret = stub_read(state, stub, fillbuf, state->blksz, blkoff);
        if (ret < 0) {
            debug("stub_read failed! write bail.\n");
            goto out;
        }
        if (ret < state->blksz) {
            /*
             * less than full buffer was read (probably 0 due to read-past-eof)
             * so fill out the rest of the buffer with NUL.
             */
            memset(fillbuf + ret, state->blksz - ret, 0);
        }

        n = size - i;
        ASSERT(n < state->blksz);
        memcpy(fillbuf, buf + i, n);
        if (n < state->blksz)
            memset(fillbuf + n, 0, state->blksz - n);
        ret = stub_write(state, stub, fillbuf, state->blksz, blkoff);
        if (ret == -1) {
            goto out;
        }
        nwrite += n;
        debug("  end tail nwrite=%d n=%d off=%lld\n", (int)nwrite, n,
                (long long)offset);
    }
out:
    if (stub_refresh(state, stub) == -1) {
        ret = -1;
    } else {
        stub_update_len(stub, orig_offset + nwrite, 0);
    }
out_close:
    free(fillbuf);
    t1 = rtc();
    count_event(COUNT_WRITE, t1 - t0, size);
    count_maybe_dump(state, t1);
    debug("undup_write ret=%d n=%d errno=%d\n", ret, n, errno);
    return ret == -1 ? -errno : ret < 0 ? ret : n;
}

static struct fuse_operations undup_oper = {
    .getattr            = undup_getattr,
    .chown              = undup_chown,
    .chmod              = undup_chmod,
    .readdir            = undup_readdir,
    .opendir            = undup_opendir,
    .mkdir              = undup_mkdir,
    .unlink             = undup_unlink,
    .rmdir              = undup_rmdir,
    .readlink           = undup_readlink,
    .symlink            = undup_symlink,
    .link               = undup_link,
    .truncate           = undup_truncate,
    .open               = undup_open,
    .release            = undup_release,
    .create             = undup_create,
    .read               = undup_read,
    .write              = undup_write,
    .rename             = undup_rename,
};

static int undup_init(const char *basedir)
{
    char fname[PATH_MAX];
    int fd, n, ver, e;
    off_t flen;
    struct stat st;
    struct undup_hdr hdr;
    int filtersz0 = 1024;
    int filtersz1 = filtersz0 * 20;
    int bitcount = 7;
    int bitcount1 = 3;

    char *f = getenv("UNDUP_DEBUG");
    if (f) {
        o_verbose = 1;
        f_debug = fopen(f, "w");
    }
    f = getenv("UNDUP_STATS");
    if (f) {
        f_stats = fopen(f, "w");
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
    state->nblooms   = 0;
    state->bloomscale = 128;

    ASSERT(1 << state->blkshift == state->blksz);

    // if ver == 1
    state->hashsz    = 32; // SHA256

    state->bp0 = bloom_setup(filtersz0, bitcount, state->hashsz);
    state->bp1 = bloom_setup(filtersz1, bitcount1, state->hashsz);

    if ((e = pthread_rwlock_init(&state->lock, 0)) != 0)
        die("pthread_rwlock_init: %s\n", strerror(e));

    bucket_validate(state);

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
