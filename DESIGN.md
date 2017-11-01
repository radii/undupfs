== OVERVIEW ==

An undupfs mount is layered on another filesystem, such as ext4, called the
"host filesystem".  The following example may be instructive:

    mount -t undupfs /var/data.undupfs /data

In this example, `/data` is the "undupfs mount" and `/var/data.undupfs` is the
"host directory".

== Hash and block sizes ==

The block size for undupfs is 4 KiB.  The hash size is 256 bits (32 bytes).
The hash function used is SHA512 truncated to 32 bytes.

== METADATA ==

File metadata such as owner, permissions, mtime, atime are drawn from the inode
on the host directory.  Following our example, `/data/hello.txt` will be
represented by a stub file `/var/data.undupfs/hello.txt`.

== TOC ==

The stub file in the host directory is used to store undupfs metadata and, for
short files, file content.  All fields are stored big endian.  The stub file
begins with a header:

    struct undup_hdr {
        u32 magic;      // UDFS = 0x55 0x44 0x46 0x53
        u16 version_hash; // 0x1 = V1_SHA512
        u16 flags;
        u64 len;
    };

The following flag bits are present in the flags field:

    #define UNDUP_DIRECT_CONTENT 0x0001

Stub files with DIRECT_CONTENT set contain `len` bytes of user data immediately
after the `undup_hdr`.

Non-DIRECT stub files have $ceil(`len` / 4096)$ hashes starting after the
`undup_hdr`.

== CONTENT STORAGE ==

File content is stored in 4 KiB blocks in one or more *bucket* files under the
`.undupfs` subdirectory of the host directory.

A bucket file consists of a header followed by zero or more segments.  A
completed segment consists of 4096 / 32 = 128 blocks of data, followed by a
block of data hashes (32 bytes each) called a TOC.  A final, "incomplete",
segment may contain 1 to 127 data blocks without a TOC.

Upon initialization, the implementation reads all of the TOC blocks and
constructs appropriate in-memory data structures to find a data block given
a hash value.
