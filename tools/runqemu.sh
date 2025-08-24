#!/bin/bash

fuzztype="sbi"

if [ $# -eq 1 ]; then
    fuzztype=$1
fi

if [ "$1" = "sbi" ]; then
    /home/build/projects/srcs/qemu/build/qemu-system-riscv64 \
        -machine virt \
        -nographic \
        -smp 1 \
        -bios /home/build/projects/srcs/opensbi/build/platform/generic/firmware/fw_jump.bin \
        -kernel /home/build/projects/srcs/linux/arch/riscv/boot/Image \
        -append "root=/dev/vda ro console=ttyS0 nokaslr oops=panic panic_on_warn=1 panic_on_oops=1" \
        -object rng-random,filename=/dev/urandom,id=rng0 \
        -device virtio-rng-device,rng=rng0 \
        -initrd /home/build/projects/srcs/buildroot/output/images/rootfs.cpio.gz \
        -netdev user,id=net0,host=10.0.2.2,hostfwd=tcp::10022-:22 \
        -device virtio-net-device,netdev=net0 \
        -m 2048 \
        -fsdev local,id=fsdev0,path=/home/build/projects/mtcfuzz,security_model=none \
        -device virtio-9p-device,fsdev=fsdev0,mount_tag=hostshare \
        -drive file=/home/build/projects/mtcfuzz/work/fuzz-snapshot.qcow2,if=none,format=qcow2,id=snapshot0 \
        -qmp unix:/tmp/qemu-mtcfuzz.sock,server,nowait \
        $*
elif [ "$1" = "optee" ]; then
    cd work/bin
    /home/build/projects/srcs/qemu/build/qemu-system-aarch64 \
        -machine virt,acpi=off,secure=on,mte=off,gic-version=3,virtualization=false \
        -bios /home/build/projects/mtcfuzz/work/bin/bl1.bin \
        -kernel /home/build/projects/mtcfuzz/work/bin/Image \
        -append "console=ttyAMA0,115200 keep_bootcon root=/dev/vda2 nokaslr oops=panic panic_on_warn=1 panic_on_oops=1" \
        -nographic \
        -drive file=/home/build/projects/mtcfuzz/work/fuzz-snapshot.qcow2,if=none,format=qcow2,id=snapshot0 \
        -netdev user,id=net0,host=10.0.2.2,hostfwd=tcp::10022-:22 \
        -device virtio-net-device,netdev=net0 \
        -smp 2 \
        -m 2048 \
        -qmp unix:/tmp/qemu-mtcfuzz.sock,server,nowait \
        -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-device,rng=rng0 \
        -initrd /home/build/projects/srcs/optee/out/bin/rootfs.cpio.uboot \
        -cpu max,sme=on,pauth-impdef=on \
        -d unimp \
        -semihosting-config enable=on,target=native
fi

