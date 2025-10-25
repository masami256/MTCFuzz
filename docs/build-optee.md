# Download, Build, and Test run

```
mkdir optee
cd optee
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml
repo sync -j4 --no-clone-bundle
cd buildroot
git am /home/build/projects/mtcfuzz/patches/optee/buildroot/0001-dropbear-Allow-empty-password-login.patch
cd ../build
git am /home/build/projects/mtcfuzz/patches/optee/build/0001-common.mk-Add-dropbear-package.patch
git am /home/build/projects/mtcfuzz/patches/optee/build/0001-kconfigs-Enable-debug-info-options-to-qemu.conf.patch
git am /home/build/projects/mtcfuzz/patches/optee/build/0001-Add-kernel-parameters-for-fuzzing.patch
git am /home/build/projects/mtcfuzz/patches/optee/build/0001-Set-BOOTDELAY-parameter-to-0.patch
git am /home/build/projects/mtcfuzz/patches/optee/build/0001-Enable-buildroot-debug-option.patch

cd ../optee_test
git am /home/build/projects/mtcfuzz/patches/optee/optee_test/0001-add-test.patch
git am /home/build/projects/mtcfuzz/patches/optee/optee_test/0001-Add-xtest-fuzz-1001.patch
git am /home/build/projects/mtcfuzz/patches/optee/optee_test/0001-host-xtest-Add-debug-support-function.patch

cd ../build
make -j$(nproc) toolchains
make DEBUG=1 -j$(nproc)
make run DEBUG=1 CFG_CORE_ASLR=n CFG_TA_ASLR=n -j$(nproc)
```

# Build for fTPM test

Goto build directory then apply following patch before build.

```
git am /home/build/projects/mtcfuzz/patches/optee/ftpm/0001-Enable-Linux-IMA-feature.patch
```

Build with higher log level.

```
make run DEBUG=1 CFG_CORE_ASLR=n CFG_TA_ASLR=n -j$(nproc)
```
