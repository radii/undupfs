undupfs - deduplicating layered filesystem

This FUSE driver provides deduplicating storage.  Files with the same content
can be stored with reduced space consumption.  This can be especially useful
for storing multiple VM images, especially in space-constrained environments
like SSDs.  For example, 10 VMs with Debian installed can transparently share
storage.  Since deduplication trades off increased nonlocality of reference
for decreased space consumption, it is especially well suited to SSD storage.
