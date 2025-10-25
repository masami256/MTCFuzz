# Download

```
git clone https://github.com/riscv-software-src/opensbi.git
cd opensbi
git checkout bd613dd92113f683052acfb23d9dc8ba60029e0a
```

# Build

```
make CROSS_COMPILE=riscv64-linux-gnu- clean
make CROSS_COMPILE=riscv64-linux-gnu- PLATFORM_RISCV_XLEN=64 PLATFORM=generic 
```