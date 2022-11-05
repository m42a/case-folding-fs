# case-folding-fs
A case-insensitive FUSE filesystem.

`case-folding-fs` mounts over an existing directory and provides case-insensitive lookup within it (using Unicode case-folding).  This is mainly useful for running scripts written on Mac OS or Windows that assume the filesystem is case-insensitive.

### Build instructions

In the checkout directory:
```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target case-folding-fs
```

### Usage instructions

Run `build/case-folding-fs path/goes/here` to mount over a particular directory.  To unmount it, run `fusermount3 -u path/goes/here`.  To mount it for running a single command, use the provided `build/case-folding-wrap.sh` script.  For example, if you want to run `/foo/command.py` in the directory `/bar/data`, and you built the program in `~/case-folding-fs/build`, do
```sh
cd /bar/data
~/case-folding-fs/build/case-folding-wrap.sh python /foo/command.py arg1 arg2 arg3
```

This will mount `case-folding-fs` over `/bar/data`, run `python /foo/command.py arg1 arg2 arg3`, and then unmount it.

### Why should I use this instead of [ciopfs](https://www.brain-dump.org/projects/ciopfs/)?

* It mounts over the existing directory instead of having to use a separate mountpoint.
* It allows you to use an existing directory tree, instead of requiring the directory be prepared while mounted.
* When unmounted, all files retain their original name.  ciopfs names the underlying files in lowercase and keeps the original name in an extended file attribute.

## Why shouldn't I use this?

* It's slow.
  * It can open, read, and close a 1MiB file about 3000 times a second, in contrast to the native performance of 5000 times per second.
  * It can open, read, and close a 2 byte file about 50000 times a second, in contrast to the native performance of 750000 times per second (a 15x difference!).
* If you have 2 files with the same folded name, only one will be accessible (and which one it is is determined by the order that the underlying filesystem reports the files).
* Since it caches the entire directory tree, it will use a lot of memory if the tree is large and deeply nested.
* Since it caches the entire directory tree, if you modify the underlying filesystem while it is mounted it won't notice those changes.
