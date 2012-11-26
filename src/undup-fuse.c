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
}

static int undup_truncate(const char *path, off_t size)
{
}

static int undup_open(const char *path, struct fuse_file_info *fi)
{
}

static int undup_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi)
{
}

static int undup_write(const char *path, const char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi)
{
}

static struct fuse_operations undup_oper = {
    .getattr            = undup_getattr,
    .truncate           = undup_truncate,
    .open               = undup_open,
    .read               = undup_read,
    .write              = undup_write,
};

int main(int argc, char **argv)
{
    return fuse_main(argc, argv, &undup_oper, NULL);
}
