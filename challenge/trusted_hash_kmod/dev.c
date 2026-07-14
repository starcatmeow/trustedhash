#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

#include "dev.h"
#include "cmd.h"

static char log_prefix[] = "trusted_hash:dev.c";

static int dev_open(struct inode *inode, struct file *file) {
    return 0;
}

static int dev_release(struct inode *inode, struct file *file) {
    return 0;
}

static long dev_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case IOCTL_CREATE_SESSION:
            return create_session((struct trusted_hash_create_session __user *)arg);
        case IOCTL_ACTIVATE_CREDENTIAL:
            return activate_credential((struct trusted_hash_activate_credential __user *)arg);
        case IOCTL_TRUSTED_HASH:
            return trusted_hash((struct trusted_hash_request __user *)arg);
        case IOCTL_CANCEL_SESSION:
            return cancel_session((struct trusted_hash_cancel_session __user *)arg);
        default:
            pr_debug("Unknown ioctl command: %u\n", cmd);
            return -EINVAL;
    }
    return 0;
}

static int major;
static struct class *cls;
static struct device *dev;
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = dev_open,
    .release = dev_release,
    .unlocked_ioctl = dev_unlocked_ioctl,
};

int init_dev(void) {
    major = register_chrdev(0, TRUSTED_HASH_DEVICE_NAME, &fops);
    if (major < 0) {
        pr_err("%s: Failed to register character device: %d\n", log_prefix, major);
        return major;
    }
    pr_debug("Registered character device with major number %d\n", major);

    cls = class_create(TRUSTED_HASH_DEVICE_NAME);
    if (IS_ERR(cls)) {
        int rc = PTR_ERR(cls);

        pr_err("%s: Failed to create device class: %d\n", log_prefix, rc);
        cls = NULL;
        unregister_chrdev(major, TRUSTED_HASH_DEVICE_NAME);
        major = 0;
        return rc;
    }

    dev = device_create(cls, NULL, MKDEV(major, 0), NULL, TRUSTED_HASH_DEVICE_NAME);
    if (IS_ERR(dev)) {
        int rc = PTR_ERR(dev);

        pr_err("%s: Failed to create device node: %d\n", log_prefix, rc);
        dev = NULL;
        class_destroy(cls);
        cls = NULL;
        unregister_chrdev(major, TRUSTED_HASH_DEVICE_NAME);
        major = 0;
        return rc;
    }

    return 0;
}

void cleanup_dev(void) {
    if (!IS_ERR_OR_NULL(dev)) {
        device_destroy(cls, MKDEV(major, 0));
        dev = NULL;
    }
    if (!IS_ERR_OR_NULL(cls)) {
        class_destroy(cls);
        cls = NULL;
    }
    if (major > 0) {
        unregister_chrdev(major, TRUSTED_HASH_DEVICE_NAME);
        major = 0;
    }
}
