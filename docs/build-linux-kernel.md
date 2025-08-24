# Download

```
git clone git@github.com:torvalds/linux.git
cd linux
git checkout 19272b37aa4f83ca52bdf9c16d5d81bdd1354494
```

# Configuration

```
make ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- defconfig
```

```
./scripts/config -e DEBUG_INFO
./scripts/config -e DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT
```

```
make ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- oldconfig
```

# Build

```
make ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- -j$(nproc)
```
