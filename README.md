## undupfs 0.1 - deduplicating layered filesystem

`undupfs` provides deduplicating storage.  Files with overlapping content can be
stored without wasting space on duplicated data.  This can be particularly
useful for storing multiple VM images, especially in a space-constrained
environment like a laptop SSD.  For example, 10 VMs with Debian installed can
transparently share storage.  Since deduplication trades off increased
nonlocality of reference for decreased space consumption, it is especially well
suited to SSD storage.

#### Getting Started

0. Install fuse and its development prerequisites (`sudo apt-get install
libfuse-dev`) and ensure that your user is permitted to mount new fuse
filesystems (generally, give membership in the `fuse` group).
1. Build and install `undupfs`.  This will put the binaries in `/usr/local/bin`.

        cd undupfs/src && make && sudo make install

2. Create a new undupfs filesystem.

        mkdir -p ~/.undup/vms ~/vms
        mkfs.undup ~/.undup/vms

3. Mount the new filesystem on the desired location.

        undup-fuse ~/.undup/vms ~/vms

4. Move, copy, or write new files to the newly mounted undupfs filesystem.
5. When done, unmount the undupfs filesystem.

        fusermount -u ~/vms

#### Future Work

1. garbage collection.
2. "pivoted parallel Bloom filter test" to speed up Bloom queries.
3. partition blocks into multiple buckets for improved liveness probabilities.
4. online dedup of an existing folder.
