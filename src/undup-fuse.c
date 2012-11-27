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

static int undup_getattr(const char *path, struct stat *stbuf)
{
    char b[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;

    n = stat(b, stbuf);
    return n == -1 ? -errno : n;
}

static int undup_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    int n;
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
        if (filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
    return 0;
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
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;
    return n == -1 ? -errno : n;
}

static int undup_write(const char *path, const char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi)
{
    char b[PATH_MAX+1];
    int n;

    n = snprintf(b, PATH_MAX, "%s/%s", state->basedir, path);
    if (n > PATH_MAX)
        return -ENAMETOOLONG;
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
