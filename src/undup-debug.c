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

#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/time.h>

#include "shared.h"
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

static int dumpstub(int argc, char **argv)
{
    int i;

    for (i=0; i<argc; i++) {
        printf(">%s<\n", argv[i]);
    }
    return 0;
}

static int dumpbucket(int argc, char **argv)
{
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

int o_verbose = 0;
FILE *f_debug = NULL;
FILE *f_stats = NULL;

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
        printf("%s %s\n", cmds[i].name, argv[optind]);
        if (!strcmp(argv[optind], cmds[i].name))
            return (cmds[i].func)(argc - optind - 1, &argv[optind + 1]);
    }

    fprintf(stderr, "Unknown command '%s'\n", argv[optind]);
    usage(argv[0]);
}
