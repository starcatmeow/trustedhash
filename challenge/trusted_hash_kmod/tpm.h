#include <linux/tpm.h>
#include <crypto/sha2.h>

#define TPM_CC_NV_ReadPublic 0x00000169
#define TPM2_CC_READ_PUBLIC 0x00000173

struct tpm2_resp_auth_area {
    __be16 auth_size;
    u8 auth_data[];
} __packed;

int tpm2_nv_readpublic(struct tpm_chip *chip, u32 nv_index, u16 *data_size);

int tpm2_nv_read(struct tpm_chip *chip, u32 nv_index, u16 size, u8 *data);

int tpm2_readpublic(struct tpm_chip *chip, u32 handle,
		    u8 *public, u16 public_max, u16 *public_size,
		    u8 *name, u16 name_max, u16 *name_size);

int tpm2_createprimary_srk(struct tpm_chip *chip, u32 *handle,
			   u8 *public, u16 public_max, u16 *public_size,
			   u8 *name, u16 name_max, u16 *name_size);

int tpm2_create_ak(struct tpm_chip *chip, u32 parent_handle,
		   u8 *out_private, u16 out_private_max, u16 *out_private_size,
		   u8 *out_public, u16 out_public_max, u16 *out_public_size);

int tpm2_create_module_signer(struct tpm_chip *chip, u32 parent_handle,
			      const u8 *auth, u16 auth_size,
			      u8 *out_private, u16 out_private_max,
			      u16 *out_private_size,
			      u8 *out_public, u16 out_public_max,
			      u16 *out_public_size);

int tpm2_create_sealed_secret(struct tpm_chip *chip, u32 parent_handle,
			      const u8 *policy_digest, u16 policy_digest_size,
			      const u8 *secret, u16 secret_size,
			      u8 *out_private, u16 out_private_max,
			      u16 *out_private_size,
			      u8 *out_public, u16 out_public_max,
			      u16 *out_public_size);

int tpm2_create_decrypt_key(struct tpm_chip *chip, u32 parent_handle,
			    const u8 *auth, u16 auth_size,
			    const u8 *policy_digest, u16 policy_digest_size,
			    const u8 *outside_info, u16 outside_info_size,
			    u8 *out_private, u16 out_private_max,
			    u16 *out_private_size,
			    u8 *out_public, u16 out_public_max,
			    u16 *out_public_size,
			    u8 *creation_hash, u16 creation_hash_max,
			    u16 *creation_hash_size,
			    u8 *creation_ticket, u16 creation_ticket_max,
			    u16 *creation_ticket_size);

int tpm2_load(struct tpm_chip *chip, u32 parent_handle,
	      const u8 *in_private, u16 in_private_size,
	      const u8 *in_public, u16 in_public_size,
	      u32 *handle, u8 *name, u16 name_max, u16 *name_size);

int tpm2_certify_creation(struct tpm_chip *chip, u32 signing_handle,
			  u32 object_handle, const u8 *qualifying_data,
			  u16 qualifying_data_size, const u8 *creation_hash,
			  u16 creation_hash_size, const u8 *creation_ticket,
			  u16 creation_ticket_size, u8 *certify_info,
			  u16 certify_info_max, u16 *certify_info_size,
			  u8 *signature, u16 signature_max,
			  u16 *signature_size);

int tpm2_sign(struct tpm_chip *chip, u32 signing_handle,
	      const u8 *auth, u16 auth_size,
	      const u8 digest[SHA256_DIGEST_SIZE],
	      u8 *signature, u16 signature_max, u16 *signature_size);

int tpm2_unseal(struct tpm_chip *chip, u32 item_handle, u32 policy_session,
		u8 *secret, u16 secret_max, u16 *secret_size);

int tpm2_evict_control_owner(struct tpm_chip *chip, u32 object_handle,
			     u32 persistent_handle);

int tpm2_pcr_extend_sha256(struct tpm_chip *chip, u32 pcr_index,
			   const u8 digest[SHA256_DIGEST_SIZE]);

int trusted_hash_tpm2_flush_context(struct tpm_chip *chip, u32 handle);

int tpm2_start_policy_session(struct tpm_chip *chip, u32 *session_handle,
			      u8 *nonce_tpm, u16 nonce_tpm_max,
			      u16 *nonce_tpm_size);

int tpm2_policy_secret_endorsement(struct tpm_chip *chip, u32 policy_session);

int tpm2_policy_pcr(struct tpm_chip *chip, u32 policy_session,
		    const u8 *pcr_digest, u16 pcr_digest_size,
		    const u8 *pcr_selection, u16 pcr_selection_size);

int tpm2_policy_authvalue(struct tpm_chip *chip, u32 policy_session);

int tpm2_activate_credential(struct tpm_chip *chip, u32 activate_handle,
			     u32 key_handle, u32 key_policy_session,
			     const u8 *credential_blob,
			     u16 credential_blob_size,
			     const u8 *secret, u16 secret_size,
			     u8 *credential, u16 credential_max,
			     u16 *credential_size);

int tpm2_rsa_decrypt(struct tpm_chip *chip, u32 key_handle,
		     const u8 *key_name, u16 key_name_size,
		     u32 policy_session, const u8 *nonce_tpm,
		     u16 nonce_tpm_size, const u8 *key_auth,
		     u16 key_auth_size, const u8 *ciphertext,
		     u16 ciphertext_size, u8 *plaintext,
		     u16 plaintext_max, u16 *plaintext_size);
