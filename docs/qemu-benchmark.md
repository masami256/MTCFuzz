
# Prepare

```
mkdir qemu-bench
cd qemu-bench/
```


## Building buildroot

```
git clone https://gitlab.com/buildroot.org/buildroot/
cd buildroot
git checkout fcde5363aa35220a1f201159a05de652ec6f811f
```

## Configuration

Create default configuration.

```
make qemu_riscv64_virt_defconfig
```

Run menuconfig.

```
make menuconfig
```

Set following setting.

```
Kernel -> [] Linux Kernel
Filesystem images -> [*] cpio the root filesystem (for use as an initial RAM filesystem)
Filesystem images -> cpio the root filesystem (for use as an initial RAM filesystem) -> Compression method -> gzip
Filesystem images -> [*] tar the root filesystem
Target Packages -> Debugging, profiling and benchmark -> [*] rt-tests 
```

## Build

```
make -j$(nproc)
```

# Building QEMU

```
cd qemu-bench/
```

```
git clone https://github.com/qemu/qemu.git
cd qemu
git checkout 9027aa63959c0a6cdfe53b2a610aaec98764a2da
```

```
mkdir build
cd build
../configure
make
```

# Building Linux kernel

```
git clone https://github.com/torvalds/linux.git
cd linux
git checkout v6.17
```

# Configuration

```
make ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- defconfig
```

# Build

```
make ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- -j$(nproc)
```

# Run tests

## test on normal qemu

Start qemu.

```
./run-qemu normal
```

Login as root then run following command.

```
mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576 hostshare /mnt
cd /mnt
```

Then run test.

```
./run-test normal
```

## test on customized qemu

Start qemu.

```
./run-qemu custom
```

Login as root then run following command.

```
mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576 hostshare /mnt
cd /mnt
```

Start logging from another terminal.

```
/home/build/projects/srcs/qemu-bench/qemu/scripts/qmp/qmp-shell /tmp/qemu-mtcfuzz.sock
(QEMU) mtcfuzz-trace-start filename=/tmp/test.log
```

Then run test.

```
./run-test.sh custom
```

