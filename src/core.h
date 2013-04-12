#ifndef UNDUP_CORE_H
#define UNDUP_CORE_H

#include "shared.h"
#include "undupfs.h"
#include "bloom.h"

struct undup_state {
    char *basedir;
    int hashsz;      // the size of a single hash
    int blksz;       // the size of a block (power of 2)
    int blkshift;    // the shift for a block (log_2(blksz))
    int fd;          // filedescriptor to bucketfile
    off_t bucketlen; // length of bucketfile
    u8 *hashblock;   // in-progress block of hashes
    int hbpos;       // current position in hashblock
    struct bloom_params *bp0;
    struct bloom_params *bp1;
    u8 **bloom0;
    u8 **bloom1;
    int nblooms;
    int bloomscale;
    pthread_rwlock_t lock;
};

extern FILE *f_debug;
extern FILE *f_stats;

struct stub *stub_open(struct undup_state *state, const char *stubpath, int rw);

int stub_close(struct undup_state *state, struct stub *stub);
int stub_read(struct undup_state *state, struct stub *stub, void *buf, size_t size, off_t offset);
int stub_write(struct undup_state *state, struct stub *stub, const void *buf, size_t n, off_t off);

int stub_refresh(struct undup_state *state, struct stub *stub);

void count_maybe_dump(struct undup_state *state, double t);

int bucket_validate(struct undup_state *state);
int stub_update_len(struct stub *stub, off_t newlen);
void do_hash(void *hash, const void *buf, int n);
int dumptocs(FILE *f, struct undup_state *state);
void print_hash(FILE *f, const u8 *buf, int n);

void state_rdlock(struct undup_state *state);
void state_wrlock(struct undup_state *state);
void state_unlock(struct undup_state *state);

#endif // UNDUP_CORE_H
