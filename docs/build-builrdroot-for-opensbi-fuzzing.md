# Download source

```
git clone https://gitlab.com/buildroot.org/buildroot/
cd buildroot
git checkout fcde5363aa35220a1f201159a05de652ec6f811f
```

# Apply patch

```
git am <path/to/0001-dropbear-Allow-empty-password-login.patch>
```

# Configuration

```
make qemu_riscv64_virt_defconfig
```

```
Kernel -> [] Linux Kernel
Target packages -> Miscellaneous -> [*] haveged
Target packages -> Networking applications -> [*] iproute2
Target packages -> Networking applications -> [*] dropbear
Target packages -> Networking applications -> dropbear -> [*] client programs
Target packages -> Networking applications -> dropbear -> [*] disable reverse DNS lookups
Target packages -> Networking applications -> dropbear -> [*] optimize for size
Filesystem images -> [*] cpio the root filesystem (for use as an initial RAM filesystem)
Filesystem images -> cpio the root filesystem (for use as an initial RAM filesystem) -> Compression method -> gzip
Filesystem images -> [*] tar the root filesystem
```

# Build

```
make -j$(nproc)
```
