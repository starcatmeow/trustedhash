#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/tpm.h>
#include <asm/uaccess.h>

#include "dev.h"

// https://github.com/tpm2-software/tpm2-tools/blob/da0793c81ce55c0d0dcaf41f79839988fb50f2fb/tools/tpm2_getekcertificate.c#L84
#define TPM_RSA_EK_CERT_NV_INDEX 0x01C00002
#define TPM_RSA_EK_HANDLE 0x81010001
#define TRUSTED_HASH_TPM_PRIVATE_MAX_SIZE 4096

struct session {
    u8 key_auth[TRUSTED_HASH_KEY_AUTH_SIZE];
    u32 pcr_mask;
    u32 srk_handle;
    u32 ak_handle;
    u32 decrypt_key_handle;
    u16 decrypt_private_size;
    u8 decrypt_private[TRUSTED_HASH_TPM_PRIVATE_MAX_SIZE];
    u16 decrypt_public_size;
    u8 decrypt_public[TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE];
    u8 pcr_digest[32];
    u8 policy_digest[32];
    bool activated;
};

long create_session(struct trusted_hash_create_session __user *user_req);
long activate_credential(struct trusted_hash_activate_credential __user *user_req);
long trusted_hash(struct trusted_hash_request __user *user_req);
long cancel_session(struct trusted_hash_cancel_session __user *user_req);
int init_module_identity(void);
void cleanup_module_identity(void);
void cleanup_sessions(void);
