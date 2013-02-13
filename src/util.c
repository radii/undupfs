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

#include "shared.h"

void die(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
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

    if (!o_verbose) return;

    fprintf(f_debug, "[%9.3f] ", rtc());
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void debug(char *fmt, ...)
{
    va_list ap;

    if (!f_debug) return;

    fprintf(f_debug, "[%9.3f] ", rtc());
    va_start(ap, fmt);
    vfprintf(f_debug, fmt, ap);
    va_end(ap);
    fflush(f_debug);
}

int event_counts[COUNT_MAX];
double event_times[COUNT_MAX];
u64 event_values[COUNT_MAX];

void count_event(int event, double elapsed, int value)
{
    ASSERT(event > 0 && event < COUNT_MAX);
    event_counts[event]++;
    event_times[event] += elapsed;
    event_values[event] += value;
}

void count_stats(FILE *f)
{
    fprintf(f, "read:  %.2f elapsed %d total %.2f µs/event %.2f MB/sec\n",
            event_times[COUNT_READ],
            event_counts[COUNT_READ],
            event_counts[COUNT_READ] / event_times[COUNT_READ],
            event_values[COUNT_READ] / event_times[COUNT_READ] / 1024 / 1024);
    fprintf(f, "write: %.2f elapsed %d total %.2f µs/event %.2f MB/sec\n",
            event_times[COUNT_WRITE],
            event_counts[COUNT_WRITE],
            event_counts[COUNT_WRITE] / event_times[COUNT_WRITE],
            event_values[COUNT_WRITE] / event_times[COUNT_WRITE] / 1024 / 1024);
}
