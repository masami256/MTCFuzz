#!/bin/bash

usage() {
    if [ $# != 1 ]; then
        echo "[*]Usage $0 <normal|custom>"
        echo "  normal: run default qemu build"
        echo "  custom: run custom qemu by MTCFuzz"
        exit 1
    fi
}

qemu=""
if [ "$1" = "normal" ]; then
    qemu="/home/build/projects/srcs/qemu-bench/qemu/build/qemu-system-riscv64"
elif [ "$1" = "custom" ]; then
    qemu="/home/build/projects/srcs/qemu/build/qemu-system-riscv64"
else
  usage
fi

qmpshell="/home/build/projects/srcs/qemu-bench/qemu/scripts/qmp/qmp-shell"

"${qemu}" \
    -machine virt \
    -nographic \
    -smp 1 \
    -bios /home/build/projects/srcs/qemu-bench/buildroot/output/images/fw_jump.bin \
    -kernel /home/build/projects/srcs/qemu-bench/linux/arch/riscv/boot/Image \
    -append "root=/dev/vda ro console=ttyS0 nokaslr oops=panic panic_on_warn=1 panic_on_oops=1" \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-device,rng=rng0 \
    -initrd /home/build/projects/srcs/qemu-bench/buildroot/output/images/rootfs.cpio.gz \
    -m 2048 \
    -drive file=/home/build/projects/mtcfuzz/work/fuzz-snapshot.qcow2,if=none,format=qcow2,id=snapshot0 \
    -netdev user,id=net0 \
    -device virtio-net-device,netdev=net0 \
    -fsdev local,id=fsdev0,path=/home/build/projects/mtcfuzz/tests/qemu-bench,security_model=none \
    -device virtio-9p-device,fsdev=fsdev0,mount_tag=hostshare \
    -qmp unix:/tmp/qemu-mtcfuzz.sock,server,nowait
