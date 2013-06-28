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

3. Mount the new filesystem on the desired location.  Depending on your
application, using `-o allow_other` or `-o allow_root` may be required.

        undup-fuse ~/.undup/vms ~/vms

4. Move, copy, or write new files to the newly mounted undupfs filesystem.
5. When done, unmount the undupfs filesystem.

        fusermount -u ~/vms

#### Space Savings

Storing three 20GiB Debian VM images in an undupfs, with each VM containing a
distinct set of installed packages, results in significant space savings:

```
% cp --sparse=always *.img /tmp/sparse
% cp -v --sparse=always *.img ~/vms
‘deb1.img’ -> ‘/home/adi/vms/deb1.img’
‘deb2.img’ -> ‘/home/adi/vms/deb2.img’
‘deb3.img’ -> ‘/home/adi/vms/deb3.img’
% du -sk ~/.undup/vms
6428448 /home/adi/.undup/vms
% (cd /tmp/sparse; du -skc *.img)
4880116 deb1.img
2311256 deb2.img
3035764 deb3.img
10227136        total
```

The undup backing store -- including block storage and metadata -- takes
6.2 GiB, while sparse copies of the source files take 9.8 GiB, giving a savings
of 37% due to deduplication.

#### Performance

The performance of undupfs depends on the amount of data stored.  With 5GB
of unique data stored, undupfs 0.1 can accept writes at about 18 MB/sec on a
2.13 GHz Core i7 640L.  With 10GB stored, the write speed drops to about 15
MB/sec.

Reading from undupfs runs at about 200 MB/sec on a fast SSD.  Read performance
does not change very much with amount of data stored.

Do not attempt to run undupfs on a spinning disk.  Performance will be
extremely poor.

#### Compatibility

The `undupfs` system will store any file type, but it is designed with a
specific use case in mind:  disk images from virtualization software.  Any disk
image format that maintains 4KiB alignment will enable deduplication.

##### kvm

`undupfs` is primarily tested using `kvm` and `libvirt`, `virt-manager`, and
`virt-viewer` on Debian unstable, amd64, 3.8 and newer kernels.  The `raw` disk
image type works fine.  Run undup-fuse with the `-o allow_other` option since
Debian's libvirt has kvm run as a different user.

```
ii  qemu-kvm     1.1.2+dfsg-5 amd64 Full virtualization on x86 hardware
ii  virt-manager 0.9.4-2      all   desktop application for managing virtual mac
ii  virt-viewer  0.5.4-1      amd64 Displaying the graphical console of a virtua
```

##### qemu

Not tested, but should work since `kvm` uses `qemu` underpinnings.  Both `raw`
and `qcow2` images should support deduplication.

##### virtualbox

Not tested, but should work.  If you try it and it works, please get in touch!

##### Xen

Xen does not store VM images on a Linux filesystem, so Xen cannot use FUSE
filesystems, so undupfs cannot help with Xen.

##### VMware Workstation/Player

Not tested, but should work.  If you try it and it works, please get in touch!
Some `.vmdk` files from older versions of VMware products may have
non-4k-aligned guest partitions which will defeat deduplication, but modern
images (created using 2008 or later releases of Workstation or Fusion) should
be properly aligned.

##### Other hypervisors

Proprietary hypervisors such as VMware ESX/ESXi and Microsoft Hyper-V do not
store VM images on a Linux filesystem and cannot use FUSE, so undupfs cannot
help with them.

#### Future Work

Features:

1. garbage collection.
2. online dedup of an existing folder.

Performance improvements:

1. partition blocks into multiple buckets for improved liveness probabilities.
2. "pivoted parallel Bloom filter test" to speed up Bloom queries.
3. hash lookaside cache to speed up clone-style workloads.
