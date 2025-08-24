#include "sbi_ecall.h"
#include "sbi_fuzz.h"

unsigned long sbi_get_spec_version(int fd, struct sbi_data *p)
{
    long ret;

    ret = ioctl(fd, SBI_FUZZ_IOCTL_EXEC_ECALL, p);
    if (ret < 0) {
        perror("ioctl");
        return ret;
    }

    return 0;
}