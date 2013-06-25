#ifndef SHARED_H_
#define SHARED_H_

#include <stdio.h>

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;

#define ASSERT(cond_) do { if (!(cond_)) die("%s:%d: ASSERT failed: %s\n", \
                                        __FILE__, __LINE__, #cond_); } while(0)

/* util.c */

void die(char *fmt, ...) __attribute__((noreturn));
double rtc(void);

extern int o_verbose;
extern FILE *f_debug;

void verbose(char *fmt, ...) __attribute__((format (printf, 1, 2)));
void debug(char *fmt, ...) __attribute__((format (printf, 1, 2)));

void count_event(int event, double elapsed, int val);
void count_stats(FILE *f);

enum {
    COUNT_WRITE         = 1,
    COUNT_READ,
    COUNT_BLOOM_QUERY0,
    COUNT_BLOOM_HIT0,
    COUNT_BLOOM_FP0,
    COUNT_BLOOM_QUERY1,
    COUNT_BLOOM_HIT1,
    COUNT_BLOOM_FP1,
    COUNT_MAX
};

#endif /* SHARED_H_ */
