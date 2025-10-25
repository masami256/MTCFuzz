# Download

```
git clone https://github.com/qemu/qemu.git
cd qemu
git checkout 9027aa63959c0a6cdfe53b2a610aaec98764a2da
```

# Apply patch

```
git am /home/build/projects/mtcfuzz/patches/qemu/0001-Add-trace-function.patch
```

# Build

```
mkdir build
cd build
../configure
make
```