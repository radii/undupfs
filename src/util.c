/*
 * util.c - shared utility functions for undup-fuse
 *
 * Copyright (C) 2012-2013 Andrew Isaacson <adi@hexapodia.org>
 *
 * This program is free software, licensed under the terms of the GNU GPL
 * version 3.  See the file COPYING for more information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <sys/time.h>
#include <pthread.h>

#include "shared.h"

void die(char *fmt, ...)
{
    va_list ap, ap2;

    va_copy(ap, ap2);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (f_debug) {
        va_start(ap, fmt);
        vfprintf(f_debug, fmt, ap);
        va_end(ap);
    }
    *(int *)0 = 42;
    exit(1);
}

double rtc(void)
{
    struct timeval tv;

    gettimeofday(&tv, 0);
    return tv.tv_sec + tv.tv_usec / 1e6;
}

void verbose(char *fmt, ...)
{
    va_list ap;

    fprintf(f_debug, "[%9.3f] %u ", rtc(), (u32)pthread_self());
    va_start(ap, fmt);
    vfprintf(f_debug, fmt, ap);
    va_end(ap);
    fflush(f_debug);
}

void debug(char *fmt, ...)
{
    va_list ap;

    if (!f_debug) return;

    fprintf(f_debug, "[%9.3f] %u ", rtc(), (u32)pthread_self());
    va_start(ap, fmt);
    vfprintf(f_debug, fmt, ap);
    va_end(ap);
    fflush(f_debug);
}
