#pragma once

#define SBI_FUZZ_IOCTL_EXEC_ECALL         _IOWR('s', 0x10, struct sbi_data)

struct ecall_result {
    long error;
    long value;
};

struct sbi_data {
    unsigned long eid;
    unsigned long fid;
    unsigned long a0;
    unsigned long a1;
    unsigned long a2;
    unsigned long a3;
    unsigned long a4;
    unsigned long a5;
    struct ecall_result ret;
};
