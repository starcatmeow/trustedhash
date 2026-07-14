/* SPDX-License-Identifier: MIT */
#ifndef TRUSTED_HASH_UAPI_H
#define TRUSTED_HASH_UAPI_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

#define TRUSTED_HASH_DEVICE_NAME "trusted_hash"
#define TRUSTED_HASH_IOC_MAGIC 'R'

#define TRUSTED_HASH_CHALLENGE_SIZE 32
#define TRUSTED_HASH_KEY_AUTH_SIZE 32
#define TRUSTED_HASH_EK_CERT_MAX_SIZE 2048
#define TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE 2048
#define TRUSTED_HASH_TPM_NAME_MAX_SIZE 64
#define TRUSTED_HASH_TPM_ATTEST_MAX_SIZE 2048
#define TRUSTED_HASH_TPM_SIGNATURE_MAX_SIZE 2048
#define TRUSTED_HASH_MODULE_SIGNER_PUBLIC_MAX_SIZE 512
#define TRUSTED_HASH_MODULE_SIGNER_SIGNATURE_MAX_SIZE 512
#define TRUSTED_HASH_CREDENTIAL_BLOB_MAX_SIZE 1024
#define TRUSTED_HASH_SECRET_MAX_SIZE 1024
#define TRUSTED_HASH_CREDENTIAL_MAX_SIZE 1024
#define TRUSTED_HASH_ENCRYPTED_BLOB_MAX_SIZE 4096
#define TRUSTED_HASH_RESULT_SIZE 32

#define TRUSTED_HASH_MODULE_SIGNER_PCR 14
#define TRUSTED_HASH_DEFAULT_PCR_MASK ((1u << 0) | (1u << 2) | (1u << 4) | (1u << 7) | (1u << 11) | (1u << TRUSTED_HASH_MODULE_SIGNER_PCR))
#define TRUSTED_HASH_MODULE_SIGNER_PCR_MASK TRUSTED_HASH_DEFAULT_PCR_MASK

struct trusted_hash_create_session {
	__u8 challenge[TRUSTED_HASH_CHALLENGE_SIZE];
	__u32 pcr_mask;

	__u32 session_id;

	__u16 ek_cert_size;
	__u8 ek_cert[TRUSTED_HASH_EK_CERT_MAX_SIZE];

	__u16 ek_public_size;
	__u8 ek_public[TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE];

	__u16 ak_public_size;
	__u8 ak_public[TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE];

	__u16 ak_name_size;
	__u8 ak_name[TRUSTED_HASH_TPM_NAME_MAX_SIZE];

	__u16 decrypt_key_public_size;
	__u8 decrypt_key_public[TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE];

	__u16 decrypt_key_name_size;
	__u8 decrypt_key_name[TRUSTED_HASH_TPM_NAME_MAX_SIZE];

	__u16 pcr_digest_size;
	__u8 pcr_digest[32];

	__u16 policy_digest_size;
	__u8 policy_digest[32];

	__u16 certify_info_size;
	__u8 certify_info[TRUSTED_HASH_TPM_ATTEST_MAX_SIZE];

	__u16 certify_signature_size;
	__u8 certify_signature[TRUSTED_HASH_TPM_SIGNATURE_MAX_SIZE];

	__u16 module_signer_public_size;
	__u8 module_signer_public[TRUSTED_HASH_MODULE_SIGNER_PUBLIC_MAX_SIZE];

	__u16 module_signer_name_size;
	__u8 module_signer_name[TRUSTED_HASH_TPM_NAME_MAX_SIZE];

	__u16 module_signature_size;
	__u8 module_signature[TRUSTED_HASH_MODULE_SIGNER_SIGNATURE_MAX_SIZE];
} __attribute__((packed));

struct trusted_hash_activate_credential {
	__u32 session_id;

	__u16 credential_blob_size;
	__u8 credential_blob[TRUSTED_HASH_CREDENTIAL_BLOB_MAX_SIZE];

	__u16 secret_size;
	__u8 secret[TRUSTED_HASH_SECRET_MAX_SIZE];

	__u16 credential_size;
	__u8 credential[TRUSTED_HASH_CREDENTIAL_MAX_SIZE];
} __attribute__((packed));

struct trusted_hash_request {
	__u32 session_id;

	__u16 encrypted_blob_size;
	__u8 encrypted_blob[TRUSTED_HASH_ENCRYPTED_BLOB_MAX_SIZE];

	__u8 result[TRUSTED_HASH_RESULT_SIZE];
} __attribute__((packed));

struct trusted_hash_cancel_session {
	__u32 session_id;
} __attribute__((packed));

#define IOCTL_CREATE_SESSION \
	_IOWR(TRUSTED_HASH_IOC_MAGIC, 0, struct trusted_hash_create_session)
#define IOCTL_ACTIVATE_CREDENTIAL \
	_IOWR(TRUSTED_HASH_IOC_MAGIC, 1, struct trusted_hash_activate_credential)
#define IOCTL_TRUSTED_HASH \
	_IOWR(TRUSTED_HASH_IOC_MAGIC, 2, struct trusted_hash_request)
#define IOCTL_CANCEL_SESSION \
	_IOW(TRUSTED_HASH_IOC_MAGIC, 3, struct trusted_hash_cancel_session)

#endif
