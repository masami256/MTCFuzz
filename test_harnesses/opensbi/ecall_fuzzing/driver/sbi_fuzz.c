#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/gfp.h> 
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/dma-mapping.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <asm/sbi.h>

#define SBI_FUZZ_DEVICE_NAME "sbi_fuzz"
#define SBI_FUZZ_DEVICE_MINOR 243

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

#define SBI_FUZZ_IOCTL_EXEC_ECALL         _IOWR('s', 0x10, struct sbi_data)

unsigned long sbi_spec_version = SBI_EXT_BASE_GET_SPEC_VERSION;

static long sb_fuzz_exec_ecall(unsigned long arg)
{
    struct sbi_data data;
    struct sbiret ret;

    if (copy_from_user(&data, (void __user *) arg, sizeof(data))) {
        pr_warn("%s: copy_from_user: Failed to copy data from user\n", __func__);
        return -EFAULT;
    }
    
    ret = sbi_ecall(data.eid, data.fid,
        data.a0, data.a1,
        data.a2, data.a3,
        data.a4, data.a5);
    
    data.ret.error = ret.error;
    data.ret.value = ret.value;

    pr_info("%s: ecall result: EID: 0x%lx, FID: 0x%lx, a0: 0x%lx, a1: 0x%lx, a2: 0x%lx, a3: 0x%lx, a4: 0x%lx, a5: 0x%lx, error: 0x%lx, value: 0x%lx\n",
        __func__, data.eid, data.fid, data.a0, data.a1, data.a2, data.a3, data.a4, data.a5,
    data.ret.error, data.ret.value);
    
    if (copy_to_user((void __user *) arg, &data, sizeof(data))) {
        pr_warn("%s: copy_to_user: Failed to copy data to user\n", __func__);
        return -EFAULT;
    }

    return 0;
}

static long sbi_fuzz_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
    long r = -EINVAL;

    switch (ioctl) {
        case SBI_FUZZ_IOCTL_EXEC_ECALL:
            r = sb_fuzz_exec_ecall(arg);
            break;
        default:
            pr_warn("%s: Unknown ioctl %ud\n", __func__, ioctl);
            break;
    }

    pr_debug("========================================\n");
    return r;
}

static int sbi_fuzz_release(struct inode *inode, struct file *filp)
{
    return 0;
}

static struct file_operations sbi_fuzz_chardev_fops = {
    .unlocked_ioctl     = sbi_fuzz_ioctl,
    .compat_ioctl       = sbi_fuzz_ioctl,
    .release        = sbi_fuzz_release,
    .llseek         = noop_llseek,
};

static struct miscdevice sbi_fuzz_chardev = {
    .minor      = SBI_FUZZ_DEVICE_MINOR,
    .name       = SBI_FUZZ_DEVICE_NAME,
    .fops       = &sbi_fuzz_chardev_fops,
};

static int __init sbi_fuzz_init(void) 
{
    int ret;

    ret = misc_register(&sbi_fuzz_chardev);
    if (ret < 0) {
        pr_warn("%s: Failed to create fuzzing driver\n", __func__);
        return ret;
    }
    pr_debug("%s: Fuzzing device file created\n", __func__);

    return 0;
}

static void __exit sbi_fuzz_exit(void) 
{
    unregister_chrdev(SBI_FUZZ_DEVICE_MINOR, SBI_FUZZ_DEVICE_NAME);

    pr_debug("%s: Fuzzing driver is closed\n", __func__);
}

module_init(sbi_fuzz_init);
module_exit(sbi_fuzz_exit);
MODULE_LICENSE("GPL");

