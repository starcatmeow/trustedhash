#define pr_fmt(fmt) "%s: " fmt, KBUILD_MODNAME

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include "cmd.h"
#include "dev.h"

MODULE_DESCRIPTION("Trusted Hash Kernel Module");
MODULE_AUTHOR("starcatmeow");
MODULE_LICENSE("Dual MIT/GPL");

static int trusted_hash_init(void) {
    int rc = init_module_identity();

    if (rc)
        return rc;

    rc = init_dev();

    if (rc) {
        cleanup_module_identity();
        return rc;
    }

    pr_info("Trusted Hash Kernel Module initialized\n");
    return 0;
}

static void trusted_hash_exit(void) {
    cleanup_dev();
    cleanup_sessions();
    cleanup_module_identity();
    pr_info("Trusted Hash Kernel Module exited\n");
}

module_init(trusted_hash_init);
module_exit(trusted_hash_exit);
