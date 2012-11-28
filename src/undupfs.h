#ifndef UNDUPFS_H_
#define UNDUPFS_H_

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;

struct undup_hdr {
    u32 magic;
    u16 version;
    u16 flags;
    u64 len;
};

#define UNDUPFS_MAGIC 0x55444653
#define UNDUPFS_VERSION 1

#define UNDUPFS_DIRECT_CONTENT 0x01

#define HASH_MAX (512 / 8) /* SHA-512 */
#define HASH_BLOCK 4096

#define UNDUP_HDR_SIZE sizeof(struct undup_hdr)

#endif /* UNDUPFS_H_ */
