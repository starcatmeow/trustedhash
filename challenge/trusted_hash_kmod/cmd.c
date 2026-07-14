#include <linux/device.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <crypto/sha2.h>

#include "cmd.h"
#include "tpm.h"

static DEFINE_XARRAY_ALLOC1(sessions);
static DEFINE_MUTEX(sessions_lock);
static DEFINE_MUTEX(module_identity_lock);

#define TRUSTED_HASH_PCR_MAX 23
#define TRUSTED_HASH_PCR_SELECT_SIZE 3
#define TRUSTED_HASH_TPM_CREATION_HASH_MAX_SIZE 128
#define TRUSTED_HASH_TPM_CREATION_TICKET_MAX_SIZE 128
#define TRUSTED_HASH_MODULE_TRANSCRIPT_LABEL "trusted_hash_module_signer_v1"
#define TRUSTED_HASH_MODULE_PCR_DIGEST "trusted_hash module signer is kernel-owned"
#define TRUSTED_HASH_MODULE_SIGNER_HANDLE 0x81010020
#define TRUSTED_HASH_MODULE_SECRET_HANDLE 0x81010021
#define TPM2_CC_POLICY_PCR 0x0000017f
#define TPM2_CC_POLICY_AUTHVALUE 0x0000016b

struct module_identity {
	u32 srk_handle;
	u32 signer_handle;
	u16 signer_public_size;
	u8 signer_public[TRUSTED_HASH_MODULE_SIGNER_PUBLIC_MAX_SIZE];
	u16 signer_name_size;
	u8 signer_name[TRUSTED_HASH_TPM_NAME_MAX_SIZE];
	bool ready;
};

static char log_prefix[] = "trusted_hash:cmd.c";
static struct module_identity module_identity;
static u8 module_signer_auth[TRUSTED_HASH_KEY_AUTH_SIZE];

static void free_session(struct session *sess)
{
	kfree_sensitive(sess);
}

static struct tpm_chip *trusted_hash_default_tpm(void)
{
	struct tpm_chip *tpm = tpm_default_chip();

	if (!tpm)
		pr_err("%s: No default TPM chip is available\n", log_prefix
	);

	return tpm;
}

static void flush_session_handles(struct tpm_chip *tpm, struct session *sess)
{
	int rc;

	if (sess->decrypt_key_handle) {
		rc = trusted_hash_tpm2_flush_context(tpm, sess->decrypt_key_handle);
		if (rc)
			pr_warn("%s: Failed to flush decrypt key 0x%08x: %d\n", log_prefix
			,
				sess->decrypt_key_handle, rc);
		sess->decrypt_key_handle = 0;
	}
	if (sess->ak_handle) {
		rc = trusted_hash_tpm2_flush_context(tpm, sess->ak_handle);
		if (rc)
			pr_warn("%s: Failed to flush AK 0x%08x: %d\n", log_prefix
			,
				sess->ak_handle, rc);
		sess->ak_handle = 0;
	}
	if (sess->srk_handle) {
		rc = trusted_hash_tpm2_flush_context(tpm, sess->srk_handle);
		if (rc)
			pr_warn("%s: Failed to flush SRK 0x%08x: %d\n", log_prefix
			,
				sess->srk_handle, rc);
		sess->srk_handle = 0;
	}
}

static void destroy_session(struct tpm_chip *tpm, struct session *sess)
{
	if (!sess)
		return;

	if (tpm)
		flush_session_handles(tpm, sess);
	free_session(sess);
}

static void cleanup_sessions_with_tpm(struct tpm_chip *tpm)
{
	struct session *sess;
	unsigned long index;

	xa_for_each(&sessions, index, sess) {
		xa_erase(&sessions, index);
		destroy_session(tpm, sess);
	}
}

static void put_be16(u8 *dst, u16 value)
{
	*dst++ = value >> 8;
	*dst = value;
}

static void put_be32(u8 *dst, u32 value)
{
	*dst++ = value >> 24;
	*dst++ = value >> 16;
	*dst++ = value >> 8;
	*dst = value;
}

static void transcript_update(struct sha256_ctx *ctx, const u8 *data, u32 size)
{
	u8 be32[4];

	put_be32(be32, size);
	sha256_update(ctx, be32, sizeof(be32));
	if (size)
		sha256_update(ctx, data, size);
	memzero_explicit(be32, sizeof(be32));
}

static int build_pcr_selection(u32 pcr_mask, u8 selection[10])
{
	u8 select[TRUSTED_HASH_PCR_SELECT_SIZE] = {};
	int pcr;

	if (pcr_mask & ~GENMASK(TRUSTED_HASH_PCR_MAX, 0))
		return -EINVAL;

	for (pcr = 0; pcr <= TRUSTED_HASH_PCR_MAX; pcr++) {
		if (pcr_mask & BIT(pcr))
			select[pcr / 8] |= BIT(pcr % 8);
	}

	put_be32(&selection[0], 1); /* TPML_PCR_SELECTION.count */
	put_be16(&selection[4], TPM_ALG_SHA256);
	selection[6] = TRUSTED_HASH_PCR_SELECT_SIZE;
	memcpy(&selection[7], select, TRUSTED_HASH_PCR_SELECT_SIZE);

	return 0;
}

static int compute_pcr_digest(struct tpm_chip *tpm, u32 pcr_mask, u8 out[32])
{
	struct sha256_ctx ctx;
	struct tpm_digest digest = {
		.alg_id = TPM_ALG_SHA256,
	};
	int pcr;
	int rc;

	if (!pcr_mask)
		return -EINVAL;

	sha256_init(&ctx);
	for (pcr = 0; pcr <= TRUSTED_HASH_PCR_MAX; pcr++) {
		if (!(pcr_mask & BIT(pcr)))
			continue;

		memset(&digest.digest, 0, sizeof(digest.digest));
		rc = tpm_pcr_read(tpm, pcr, &digest);
		if (rc) {
			pr_err("%s: Failed to read PCR %d: %d\n", log_prefix
			, pcr, rc);
			return rc;
		}

		sha256_update(&ctx, digest.digest, SHA256_DIGEST_SIZE);
	}
	sha256_final(&ctx, out);

	return 0;
}

static void compute_policy_digest(const u8 pcr_digest[32], u32 pcr_mask, u8 out[32])
{
	struct sha256_ctx ctx;
	u8 policy[SHA256_DIGEST_SIZE] = {};
	u8 cc[4];
	u8 selection[10];

	build_pcr_selection(pcr_mask, selection);

	put_be32(cc, TPM2_CC_POLICY_PCR);
	sha256_init(&ctx);
	sha256_update(&ctx, policy, sizeof(policy));
	sha256_update(&ctx, cc, sizeof(cc));
	sha256_update(&ctx, selection, sizeof(selection));
	sha256_update(&ctx, pcr_digest, SHA256_DIGEST_SIZE);
	sha256_final(&ctx, out);

	put_be32(cc, TPM2_CC_POLICY_AUTHVALUE);
	sha256_init(&ctx);
	sha256_update(&ctx, out, SHA256_DIGEST_SIZE);
	sha256_update(&ctx, cc, sizeof(cc));
	sha256_final(&ctx, out);
}

static void compute_policy_pcr_digest(const u8 pcr_digest[32], u32 pcr_mask,
				      u8 out[32])
{
	struct sha256_ctx ctx;
	u8 policy[SHA256_DIGEST_SIZE] = {};
	u8 cc[4];
	u8 selection[10];

	build_pcr_selection(pcr_mask, selection);

	put_be32(cc, TPM2_CC_POLICY_PCR);
	sha256_init(&ctx);
	sha256_update(&ctx, policy, sizeof(policy));
	sha256_update(&ctx, cc, sizeof(cc));
	sha256_update(&ctx, selection, sizeof(selection));
	sha256_update(&ctx, pcr_digest, SHA256_DIGEST_SIZE);
	sha256_final(&ctx, out);
}

static void compute_module_signer_digest(
	struct trusted_hash_create_session *req,
	const u8 challenge[TRUSTED_HASH_CHALLENGE_SIZE],
	u8 out[SHA256_DIGEST_SIZE])
{
	struct sha256_ctx ctx;
	u8 pcr_mask_be[4];

	put_be32(pcr_mask_be, req->pcr_mask);
	sha256_init(&ctx);
	transcript_update(&ctx, TRUSTED_HASH_MODULE_TRANSCRIPT_LABEL,
			  sizeof(TRUSTED_HASH_MODULE_TRANSCRIPT_LABEL) - 1);
	transcript_update(&ctx, challenge, TRUSTED_HASH_CHALLENGE_SIZE);
	transcript_update(&ctx, pcr_mask_be, sizeof(pcr_mask_be));
	transcript_update(&ctx, req->pcr_digest, req->pcr_digest_size);
	transcript_update(&ctx, req->policy_digest, req->policy_digest_size);
	transcript_update(&ctx, req->ak_name, req->ak_name_size);
	transcript_update(&ctx, req->decrypt_key_name, req->decrypt_key_name_size);
	transcript_update(&ctx, req->ak_public, req->ak_public_size);
	transcript_update(&ctx, req->decrypt_key_public,
			  req->decrypt_key_public_size);
	transcript_update(&ctx, req->certify_info, req->certify_info_size);
	transcript_update(&ctx, req->certify_signature,
			  req->certify_signature_size);
	transcript_update(&ctx, req->module_signer_name,
			  req->module_signer_name_size);
	sha256_final(&ctx, out);

	memzero_explicit(pcr_mask_be, sizeof(pcr_mask_be));
}

static int sign_module_transcript(struct tpm_chip *tpm,
				  struct trusted_hash_create_session *req,
				  const u8 challenge[TRUSTED_HASH_CHALLENGE_SIZE])
{
	u8 digest[SHA256_DIGEST_SIZE];
	int rc;

	mutex_lock(&module_identity_lock);
	if (!module_identity.ready) {
		rc = -ENODEV;
		goto out;
	}

	req->module_signer_public_size = module_identity.signer_public_size;
	memcpy(req->module_signer_public, module_identity.signer_public,
	       module_identity.signer_public_size);
	req->module_signer_name_size = module_identity.signer_name_size;
	memcpy(req->module_signer_name, module_identity.signer_name,
	       module_identity.signer_name_size);

	compute_module_signer_digest(req, challenge, digest);
	rc = tpm2_sign(tpm, module_identity.signer_handle,
		       module_signer_auth, sizeof(module_signer_auth),
		       digest, req->module_signature,
		       TRUSTED_HASH_MODULE_SIGNER_SIGNATURE_MAX_SIZE,
		       &req->module_signature_size);
out:
	mutex_unlock(&module_identity_lock);
	memzero_explicit(digest, sizeof(digest));
	return rc;
}

int init_module_identity(void)
{
	struct tpm_chip *tpm;
	u8 *private = NULL;
	u8 *secret_private = NULL;
	u8 *secret_public = NULL;
	u8 *srk_public = NULL;
	u8 *srk_name = NULL;
	u8 pcr_digest[SHA256_DIGEST_SIZE];
	u8 policy_digest[SHA256_DIGEST_SIZE];
	u8 selection[10];
	struct sha256_ctx ctx;
	u16 private_size = 0;
	u16 secret_private_size = 0;
	u16 secret_public_size = 0;
	u16 srk_public_size = 0;
	u16 srk_name_size = 0;
	u32 srk_handle = 0;
	u32 secret_handle = 0;
	u32 policy_session = 0;
	bool signer_exists;
	bool secret_exists;
	bool signer_persisted = false;
	bool secret_persisted = false;
	int rc;
	int signer_rc;
	int secret_rc;

	private = kzalloc(TRUSTED_HASH_TPM_PRIVATE_MAX_SIZE, GFP_KERNEL);
	secret_private = kzalloc(TRUSTED_HASH_TPM_PRIVATE_MAX_SIZE, GFP_KERNEL);
	secret_public = kzalloc(TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE, GFP_KERNEL);
	srk_public = kzalloc(TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE, GFP_KERNEL);
	srk_name = kzalloc(TRUSTED_HASH_TPM_NAME_MAX_SIZE, GFP_KERNEL);
	if (!private || !secret_private || !secret_public ||
	    !srk_public || !srk_name) {
		rc = -ENOMEM;
		goto out_free;
	}

	mutex_lock(&module_identity_lock);
	if (module_identity.ready) {
		rc = 0;
		goto out_unlock;
	}

	tpm = trusted_hash_default_tpm();
	if (!tpm) {
		rc = -ENODEV;
		goto out_unlock;
	}

	rc = build_pcr_selection(TRUSTED_HASH_MODULE_SIGNER_PCR_MASK,
				 selection);
	if (rc)
		goto out_put_tpm;
	rc = compute_pcr_digest(tpm, TRUSTED_HASH_MODULE_SIGNER_PCR_MASK,
				pcr_digest);
	if (rc)
		goto out_put_tpm;
	compute_policy_pcr_digest(pcr_digest,
				  TRUSTED_HASH_MODULE_SIGNER_PCR_MASK,
				  policy_digest);

	signer_rc = tpm2_readpublic(tpm, TRUSTED_HASH_MODULE_SIGNER_HANDLE,
				    module_identity.signer_public,
				    TRUSTED_HASH_MODULE_SIGNER_PUBLIC_MAX_SIZE,
				    &module_identity.signer_public_size,
				    module_identity.signer_name,
				    TRUSTED_HASH_TPM_NAME_MAX_SIZE,
				    &module_identity.signer_name_size);
	secret_rc = tpm2_readpublic(tpm, TRUSTED_HASH_MODULE_SECRET_HANDLE,
				    secret_public,
				    TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE,
				    &secret_public_size,
				    srk_name, TRUSTED_HASH_TPM_NAME_MAX_SIZE,
				    &srk_name_size);
	signer_exists = signer_rc == 0;
	secret_exists = secret_rc == 0;

	if (signer_exists != secret_exists) {
		pr_err("%s: Inconsistent module signer TPM state: signer=%d secret=%d\n", log_prefix
		,
		       signer_exists, secret_exists);
		rc = -EIO;
		goto out_put_tpm;
	}

	if (signer_exists) {
		rc = tpm2_start_policy_session(tpm, &policy_session,
					       NULL, 0, NULL);
		if (rc) {
			pr_err("%s: Failed to start module signer policy session: %d\n", log_prefix
			,
			       rc);
			goto out_put_tpm;
		}
		rc = tpm2_policy_pcr(tpm, policy_session,
				     pcr_digest, sizeof(pcr_digest),
				     selection, sizeof(selection));
		if (rc) {
			pr_err("%s: Failed to authorize module signer PCR policy: %d\n", log_prefix
			,
			       rc);
			goto out_flush_policy;
		}
		rc = tpm2_unseal(tpm, TRUSTED_HASH_MODULE_SECRET_HANDLE,
				 policy_session, module_signer_auth,
				 sizeof(module_signer_auth), &private_size);
		if (rc) {
			pr_err("%s: Failed to unseal module signer auth: %d\n", log_prefix
			, rc);
			goto out_flush_policy;
		}
		if (private_size != sizeof(module_signer_auth)) {
			pr_err("%s: Unexpected module signer auth size: %u\n", log_prefix
			,
			       private_size);
			rc = -EIO;
			goto out_flush_policy;
		}
		policy_session = 0;
		module_identity.signer_handle = TRUSTED_HASH_MODULE_SIGNER_HANDLE;
		module_identity.ready = true;
		pr_info("%s: restored persistent handle 0x%08x\n",
			log_prefix
		, TRUSTED_HASH_MODULE_SIGNER_HANDLE);
		goto extend_pcr;
	}

	rc = tpm_get_random(tpm, module_signer_auth,
			    sizeof(module_signer_auth));
	if (rc != sizeof(module_signer_auth)) {
		pr_err("%s: Failed to generate module signer authorization: %d\n", log_prefix
		, rc);
		rc = rc < 0 ? rc : -EIO;
		goto out_put_tpm;
	}

	rc = tpm2_createprimary_srk(tpm, &srk_handle,
				    srk_public, TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE,
				    &srk_public_size,
				    srk_name, TRUSTED_HASH_TPM_NAME_MAX_SIZE,
				    &srk_name_size);
	if (rc) {
		pr_err("%s: Failed to create module signer SRK: %d\n", log_prefix
		, rc);
		goto out_put_tpm;
	}
	module_identity.srk_handle = srk_handle;

	rc = tpm2_create_module_signer(tpm, srk_handle,
				       module_signer_auth,
				       sizeof(module_signer_auth),
				       private, TRUSTED_HASH_TPM_PRIVATE_MAX_SIZE,
				       &private_size,
				       module_identity.signer_public,
				       TRUSTED_HASH_MODULE_SIGNER_PUBLIC_MAX_SIZE,
				       &module_identity.signer_public_size);
	if (rc) {
		pr_err("%s: Failed to create module signer key: %d\n", log_prefix
		, rc);
		goto out_flush_srk;
	}

	rc = tpm2_load(tpm, srk_handle, private, private_size,
		       module_identity.signer_public,
		       module_identity.signer_public_size,
		       &module_identity.signer_handle,
		       module_identity.signer_name,
		       TRUSTED_HASH_TPM_NAME_MAX_SIZE,
		       &module_identity.signer_name_size);
	if (rc) {
		pr_err("%s: Failed to load module signer key: %d\n", log_prefix
		, rc);
		goto out_flush_srk;
	}

	rc = tpm2_evict_control_owner(tpm, module_identity.signer_handle,
				      TRUSTED_HASH_MODULE_SIGNER_HANDLE);
	if (rc) {
		pr_err("%s: Failed to persist module signer key: %d\n", log_prefix
		, rc);
		goto out_flush_signer;
	}
	signer_persisted = true;

	rc = tpm2_create_sealed_secret(tpm, srk_handle,
				       policy_digest, sizeof(policy_digest),
				       module_signer_auth,
				       sizeof(module_signer_auth),
				       secret_private,
				       TRUSTED_HASH_TPM_PRIVATE_MAX_SIZE,
				       &secret_private_size,
				       secret_public,
				       TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE,
				       &secret_public_size);
	if (rc) {
		pr_err("%s: Failed to create sealed module signer auth: %d\n", log_prefix
		, rc);
		goto out_flush_signer;
	}

	rc = tpm2_load(tpm, srk_handle, secret_private, secret_private_size,
		       secret_public, secret_public_size,
		       &secret_handle, srk_name,
		       TRUSTED_HASH_TPM_NAME_MAX_SIZE, &srk_name_size);
	if (rc) {
		pr_err("%s: Failed to load sealed module signer auth: %d\n", log_prefix
		, rc);
		goto out_flush_signer;
	}

	rc = tpm2_evict_control_owner(tpm, secret_handle,
				      TRUSTED_HASH_MODULE_SECRET_HANDLE);
	if (rc) {
		pr_err("%s: Failed to persist sealed module signer auth: %d\n", log_prefix
		, rc);
		goto out_flush_secret;
	}
	secret_persisted = true;

	rc = trusted_hash_tpm2_flush_context(tpm, secret_handle);
	if (rc) {
		pr_err("%s: Failed to flush sealed module signer auth transient: %d\n", log_prefix
		,
		       rc);
		goto out_flush_signer;
	}
	secret_handle = 0;

	rc = trusted_hash_tpm2_flush_context(tpm, module_identity.signer_handle);
	if (rc) {
		pr_err("%s: Failed to flush module signer transient: %d\n", log_prefix
		, rc);
		goto out_flush_srk;
	}
	module_identity.signer_handle = TRUSTED_HASH_MODULE_SIGNER_HANDLE;

extend_pcr:
	sha256_init(&ctx);
	sha256_update(&ctx, TRUSTED_HASH_MODULE_PCR_DIGEST,
		      sizeof(TRUSTED_HASH_MODULE_PCR_DIGEST) - 1);
	sha256_final(&ctx, pcr_digest);
	rc = tpm2_pcr_extend_sha256(tpm, TRUSTED_HASH_MODULE_SIGNER_PCR,
				    pcr_digest);
	if (rc) {
		pr_err("%s: Failed to extend module signer PCR %u: %d\n", log_prefix
		,
		       TRUSTED_HASH_MODULE_SIGNER_PCR, rc);
		goto out_flush_srk;
	}

	if (srk_handle) {
		rc = trusted_hash_tpm2_flush_context(tpm, srk_handle);
		if (rc) {
			pr_err("%s: Failed to flush module signer SRK: %d\n", log_prefix
			, rc);
			goto out_flush_signer;
		}
		srk_handle = 0;
	}
	module_identity.srk_handle = 0;
	module_identity.ready = true;
	pr_info("%s: initialized with PCR mask 0x%08x and ratchet PCR %u\n",
		log_prefix
	, TRUSTED_HASH_MODULE_SIGNER_PCR_MASK,
		TRUSTED_HASH_MODULE_SIGNER_PCR);
	goto out_put_tpm;

out_flush_secret:
	if (secret_handle)
		trusted_hash_tpm2_flush_context(tpm, secret_handle);
	secret_handle = 0;
out_flush_signer:
	if (module_identity.signer_handle &&
	    module_identity.signer_handle != TRUSTED_HASH_MODULE_SIGNER_HANDLE)
		trusted_hash_tpm2_flush_context(tpm, module_identity.signer_handle);
	module_identity.signer_handle = 0;
out_flush_srk:
	if (module_identity.srk_handle)
		trusted_hash_tpm2_flush_context(tpm, module_identity.srk_handle);
	module_identity.srk_handle = 0;
out_flush_policy:
	if (policy_session)
		trusted_hash_tpm2_flush_context(tpm, policy_session);
	policy_session = 0;
out_put_tpm:
	if (rc && secret_persisted)
		tpm2_evict_control_owner(tpm, TRUSTED_HASH_MODULE_SECRET_HANDLE,
					  TRUSTED_HASH_MODULE_SECRET_HANDLE);
	if (rc && signer_persisted)
		tpm2_evict_control_owner(tpm, TRUSTED_HASH_MODULE_SIGNER_HANDLE,
					  TRUSTED_HASH_MODULE_SIGNER_HANDLE);
	put_device(&tpm->dev);
out_unlock:
	if (rc)
		memset(&module_identity, 0, sizeof(module_identity));
	mutex_unlock(&module_identity_lock);
out_free:
	kfree_sensitive(private);
	kfree_sensitive(secret_private);
	kfree_sensitive(secret_public);
	kfree_sensitive(srk_public);
	kfree_sensitive(srk_name);
	memzero_explicit(pcr_digest, sizeof(pcr_digest));
	memzero_explicit(policy_digest, sizeof(policy_digest));
	return rc;
}

long create_session(struct trusted_hash_create_session __user *user_req)
{
	struct trusted_hash_create_session *req;
	u8 challenge[TRUSTED_HASH_CHALLENGE_SIZE];
	u8 selection[10];
	u8 creation_hash[TRUSTED_HASH_TPM_CREATION_HASH_MAX_SIZE];
	u8 creation_ticket[TRUSTED_HASH_TPM_CREATION_TICKET_MAX_SIZE];
	u8 *ak_private = NULL;
	u8 *decrypt_private = NULL;
	struct session *sess;
	struct tpm_chip *tpm;
	u16 ak_private_size = 0;
	u16 creation_hash_size = 0;
	u16 creation_ticket_size = 0;
	u16 decrypt_private_size = 0;
	u32 pcr_mask;
	u32 session_id;
	bool sessions_locked = false;
	int rc;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	if (copy_from_user(req, user_req, sizeof(*req))) {
		rc = -EFAULT;
		goto err_free_req;
	}

	if (!req->pcr_mask)
		req->pcr_mask = TRUSTED_HASH_DEFAULT_PCR_MASK;
	pcr_mask = req->pcr_mask;
	memcpy(challenge, req->challenge, sizeof(challenge));

	rc = build_pcr_selection(pcr_mask, selection);
	if (rc)
		goto err_free_req;

	memset(req, 0, sizeof(*req));
	memcpy(req->challenge, challenge, sizeof(challenge));
	req->pcr_mask = pcr_mask;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess) {
		rc = -ENOMEM;
		goto err_free_req;
	}
	ak_private = kzalloc(TRUSTED_HASH_TPM_PRIVATE_MAX_SIZE, GFP_KERNEL);
	decrypt_private = kzalloc(TRUSTED_HASH_TPM_PRIVATE_MAX_SIZE, GFP_KERNEL);
	if (!ak_private || !decrypt_private) {
		rc = -ENOMEM;
		goto err_free_session;
	}

	sess->pcr_mask = pcr_mask;

	mutex_lock(&sessions_lock);
	sessions_locked = true;

	tpm = trusted_hash_default_tpm();
	if (!tpm) {
		rc = -ENODEV;
		goto err_free_session;
	}
	cleanup_sessions_with_tpm(tpm);

	rc = tpm_get_random(tpm, sess->key_auth, sizeof(sess->key_auth));
	if (rc != sizeof(sess->key_auth)) {
		pr_err("%s: Failed to generate key authorization: %d\n", log_prefix
		, rc);
		rc = rc < 0 ? rc : -EIO;
		goto err_put_tpm;
	}

	rc = tpm2_nv_readpublic(tpm, TPM_RSA_EK_CERT_NV_INDEX,
				&req->ek_cert_size);
	if (rc) {
		pr_err("%s: Failed to read EK certificate public area: %d\n", log_prefix
		, rc);
		goto err_put_tpm;
	}

	if (req->ek_cert_size > TRUSTED_HASH_EK_CERT_MAX_SIZE) {
		pr_err("%s: EK certificate is too large: %u\n", log_prefix
		, req->ek_cert_size);
		rc = -EOVERFLOW;
		goto err_put_tpm;
	}

	rc = tpm2_nv_read(tpm, TPM_RSA_EK_CERT_NV_INDEX, req->ek_cert_size,
			  req->ek_cert);
	if (rc) {
		pr_err("%s: Failed to read EK certificate: %d\n", log_prefix
		, rc);
		goto err_put_tpm;
	}

	rc = tpm2_readpublic(tpm, TPM_RSA_EK_HANDLE,
			     req->ek_public, TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE,
			     &req->ek_public_size,
			     req->ak_name, TRUSTED_HASH_TPM_NAME_MAX_SIZE,
			     &req->ak_name_size);
	if (rc) {
		pr_err("%s: Failed to read EK public: %d\n", log_prefix
		, rc);
		goto err_put_tpm;
	}
	req->ak_name_size = 0;

	rc = compute_pcr_digest(tpm, sess->pcr_mask, sess->pcr_digest);
	if (rc)
		goto err_put_tpm;
	compute_policy_digest(sess->pcr_digest, sess->pcr_mask, sess->policy_digest);

	rc = tpm2_createprimary_srk(tpm, &sess->srk_handle,
				    req->decrypt_key_public,
				    TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE,
				    &req->decrypt_key_public_size,
				    req->decrypt_key_name,
				    TRUSTED_HASH_TPM_NAME_MAX_SIZE,
				    &req->decrypt_key_name_size);
	if (rc) {
		pr_err("%s: Failed to create SRK primary: %d\n", log_prefix
		, rc);
		goto err_put_tpm;
	}
	req->decrypt_key_public_size = 0;
	req->decrypt_key_name_size = 0;

	rc = tpm2_create_ak(tpm, sess->srk_handle,
			    ak_private, TRUSTED_HASH_TPM_PRIVATE_MAX_SIZE,
			    &ak_private_size,
			    req->ak_public, TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE,
			    &req->ak_public_size);
	if (rc) {
		pr_err("%s: Failed to create AK: %d\n", log_prefix
		, rc);
		goto err_put_tpm;
	}

	rc = tpm2_load(tpm, sess->srk_handle,
		       ak_private, ak_private_size,
		       req->ak_public, req->ak_public_size,
		       &sess->ak_handle,
		       req->ak_name, TRUSTED_HASH_TPM_NAME_MAX_SIZE,
		       &req->ak_name_size);
	if (rc) {
		pr_err("%s: Failed to load AK: %d\n", log_prefix
		, rc);
		goto err_put_tpm;
	}

	rc = tpm2_create_decrypt_key(tpm, sess->srk_handle,
				     sess->key_auth, sizeof(sess->key_auth),
				     sess->policy_digest, SHA256_DIGEST_SIZE,
				     challenge, sizeof(challenge),
				     decrypt_private,
				     TRUSTED_HASH_TPM_PRIVATE_MAX_SIZE,
				     &decrypt_private_size,
				     req->decrypt_key_public,
				     TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE,
				     &req->decrypt_key_public_size,
				     creation_hash, sizeof(creation_hash),
				     &creation_hash_size,
				     creation_ticket, sizeof(creation_ticket),
				     &creation_ticket_size);
	if (rc) {
		pr_err("%s: Failed to create decrypt key: %d\n", log_prefix
		, rc);
		goto err_put_tpm;
	}
	sess->decrypt_private_size = decrypt_private_size;
	memcpy(sess->decrypt_private, decrypt_private, decrypt_private_size);
	sess->decrypt_public_size = req->decrypt_key_public_size;
	memcpy(sess->decrypt_public, req->decrypt_key_public,
	       req->decrypt_key_public_size);

	rc = tpm2_load(tpm, sess->srk_handle,
		       decrypt_private, decrypt_private_size,
		       req->decrypt_key_public, req->decrypt_key_public_size,
		       &sess->decrypt_key_handle,
		       req->decrypt_key_name, TRUSTED_HASH_TPM_NAME_MAX_SIZE,
		       &req->decrypt_key_name_size);
	if (rc) {
		pr_err("%s: Failed to load decrypt key: %d\n", log_prefix
		, rc);
		goto err_put_tpm;
	}

	rc = tpm2_certify_creation(tpm, sess->ak_handle,
				   sess->decrypt_key_handle,
				   challenge, sizeof(challenge),
				   creation_hash, creation_hash_size,
				   creation_ticket, creation_ticket_size,
				   req->certify_info,
				   TRUSTED_HASH_TPM_ATTEST_MAX_SIZE,
				   &req->certify_info_size,
				   req->certify_signature,
				   TRUSTED_HASH_TPM_SIGNATURE_MAX_SIZE,
				   &req->certify_signature_size);
	if (rc) {
		pr_err("%s: Failed to certify decrypt-key creation with AK: %d\n", log_prefix
		, rc);
		goto err_put_tpm;
	}

	req->pcr_digest_size = SHA256_DIGEST_SIZE;
	memcpy(req->pcr_digest, sess->pcr_digest, SHA256_DIGEST_SIZE);
	req->policy_digest_size = SHA256_DIGEST_SIZE;
	memcpy(req->policy_digest, sess->policy_digest, SHA256_DIGEST_SIZE);

	/*
	 * Keep TPM transient pressure low before signing with the persistent
	 * module signer. Some TPMs account a persistent signing key as a loaded
	 * object for TPM2_Sign, and at this point SRK+AK+decrypt-key can already
	 * fill the object slots.
	 */
	rc = trusted_hash_tpm2_flush_context(tpm, sess->decrypt_key_handle);
	if (rc) {
		pr_err("%s: Failed to flush decrypt-key transient: %d\n", log_prefix
		, rc);
		goto err_put_tpm;
	}
	sess->decrypt_key_handle = 0;
	rc = trusted_hash_tpm2_flush_context(tpm, sess->srk_handle);
	if (rc) {
		pr_err("%s: Failed to flush SRK transient: %d\n", log_prefix
		, rc);
		goto err_put_tpm;
	}
	sess->srk_handle = 0;

	rc = sign_module_transcript(tpm, req, challenge);
	if (rc) {
		pr_err("%s: Failed to sign create-session transcript with module signer: %d\n", log_prefix
		,
		       rc);
		goto err_put_tpm;
	}

	rc = xa_alloc(&sessions, &session_id, sess, xa_limit_32b, GFP_KERNEL);
	if (rc) {
		pr_err("%s: Failed to allocate session ID: %d\n", log_prefix
		, rc);
		goto err_put_tpm;
	}

	req->session_id = session_id;
	req->pcr_mask = sess->pcr_mask;

	kfree_sensitive(ak_private);
	kfree_sensitive(decrypt_private);

	if (copy_to_user(user_req, req, sizeof(*req))) {
		xa_erase(&sessions, session_id);
		destroy_session(tpm, sess);
		mutex_unlock(&sessions_lock);
		put_device(&tpm->dev);
		rc = -EFAULT;
		goto err_free_req;
	}

	mutex_unlock(&sessions_lock);
	put_device(&tpm->dev);
	pr_debug("Created session with ID %u\n", session_id);
	kfree_sensitive(req);
	return 0;

err_put_tpm:
	flush_session_handles(tpm, sess);
	put_device(&tpm->dev);
err_free_session:
	if (sessions_locked)
		mutex_unlock(&sessions_lock);
	free_session(sess);
	kfree_sensitive(ak_private);
	kfree_sensitive(decrypt_private);
err_free_req:
	kfree_sensitive(req);
	return rc;
}

long activate_credential(struct trusted_hash_activate_credential __user *user_req)
{
	struct trusted_hash_activate_credential *req;
	struct session *sess;
	struct tpm_chip *tpm;
	u32 policy_session = 0;
	bool sessions_locked = false;
	int rc = 0;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	if (copy_from_user(req, user_req, sizeof(*req))) {
		rc = -EFAULT;
		goto out;
	}

	if (req->credential_blob_size > TRUSTED_HASH_CREDENTIAL_BLOB_MAX_SIZE ||
	    req->secret_size > TRUSTED_HASH_SECRET_MAX_SIZE) {
		rc = -EINVAL;
		goto out;
	}

	mutex_lock(&sessions_lock);
	sessions_locked = true;

	sess = xa_load(&sessions, req->session_id);
	if (!sess) {
		rc = -ENOENT;
		goto out;
	}

	if (!sess->ak_handle) {
		rc = -EINVAL;
		goto out;
	}

	tpm = trusted_hash_default_tpm();
	if (!tpm) {
		rc = -ENODEV;
		goto out;
	}

	rc = tpm2_start_policy_session(tpm, &policy_session, NULL, 0, NULL);
	if (rc) {
		pr_err("%s: Failed to start EK policy session: %d\n", log_prefix
		, rc);
		goto put_tpm;
	}

	rc = tpm2_policy_secret_endorsement(tpm, policy_session);
	if (rc) {
		pr_err("%s: Failed to authorize endorsement policy: %d\n", log_prefix
		, rc);
		goto flush_policy;
	}

	rc = tpm2_activate_credential(tpm, sess->ak_handle,
				      TPM_RSA_EK_HANDLE, policy_session,
				      req->credential_blob,
				      req->credential_blob_size,
				      req->secret, req->secret_size,
				      req->credential,
				      TRUSTED_HASH_CREDENTIAL_MAX_SIZE,
				      &req->credential_size);
	if (rc) {
		pr_err("%s: Failed to activate credential: %d\n", log_prefix
		, rc);
		goto flush_policy;
	}
	policy_session = 0;
	sess->activated = true;

flush_policy:
	if (policy_session)
		trusted_hash_tpm2_flush_context(tpm, policy_session);
put_tpm:
	put_device(&tpm->dev);
	if (rc)
		goto out;

	if (copy_to_user(user_req, req, sizeof(*req)))
		rc = -EFAULT;

out:
	if (sessions_locked)
		mutex_unlock(&sessions_lock);
	kfree_sensitive(req);
	return rc;
}

long trusted_hash(struct trusted_hash_request __user *user_req)
{
	struct trusted_hash_request *req;
	struct session *sess = NULL;
	struct tpm_chip *tpm = NULL;
	u8 selection[10];
	u8 policy_nonce_tpm[32];
	u8 *plaintext = NULL;
	u8 *srk_public = NULL;
	u8 *srk_name = NULL;
	u8 *decrypt_name = NULL;
	struct sha256_ctx hash_ctx;
	u32 policy_session = 0;
	u16 plaintext_size = 0;
	u16 policy_nonce_tpm_size = 0;
	u16 srk_public_size = 0;
	u16 srk_name_size = 0;
	u16 decrypt_name_size = 0;
	bool sessions_locked = false;
	int rc = 0;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	if (copy_from_user(req, user_req, sizeof(*req))) {
		rc = -EFAULT;
		goto out;
	}

	if (req->encrypted_blob_size > TRUSTED_HASH_ENCRYPTED_BLOB_MAX_SIZE) {
		rc = -EINVAL;
		goto out;
	}

	plaintext = kzalloc(TRUSTED_HASH_ENCRYPTED_BLOB_MAX_SIZE, GFP_KERNEL);
	srk_public = kzalloc(TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE, GFP_KERNEL);
	srk_name = kzalloc(TRUSTED_HASH_TPM_NAME_MAX_SIZE, GFP_KERNEL);
	decrypt_name = kzalloc(TRUSTED_HASH_TPM_NAME_MAX_SIZE, GFP_KERNEL);
	if (!plaintext || !srk_public || !srk_name || !decrypt_name) {
		rc = -ENOMEM;
		goto out;
	}

	mutex_lock(&sessions_lock);
	sessions_locked = true;

	sess = xa_erase(&sessions, req->session_id);
	if (!sess) {
		rc = -ENOENT;
		goto out;
	}

	tpm = trusted_hash_default_tpm();
	if (!tpm) {
		rc = -ENODEV;
		goto out;
	}

	if (!sess->activated) {
		rc = -EACCES;
		goto out;
	}

	rc = build_pcr_selection(sess->pcr_mask, selection);
	if (rc)
		goto out;

	rc = tpm2_createprimary_srk(tpm, &sess->srk_handle,
				    srk_public, TRUSTED_HASH_TPM_PUBLIC_MAX_SIZE,
				    &srk_public_size,
				    srk_name, TRUSTED_HASH_TPM_NAME_MAX_SIZE,
				    &srk_name_size);
	if (rc) {
		pr_err("%s: Failed to recreate SRK primary for decrypt: %d\n", log_prefix
		, rc);
		goto out;
	}

	rc = tpm2_load(tpm, sess->srk_handle,
		       sess->decrypt_private, sess->decrypt_private_size,
		       sess->decrypt_public, sess->decrypt_public_size,
		       &sess->decrypt_key_handle,
		       decrypt_name, TRUSTED_HASH_TPM_NAME_MAX_SIZE,
		       &decrypt_name_size);
	if (rc) {
		pr_err("%s: Failed to reload decrypt key: %d\n", log_prefix
		, rc);
		goto out;
	}

	rc = tpm2_start_policy_session(tpm, &policy_session,
				       policy_nonce_tpm,
				       sizeof(policy_nonce_tpm),
				       &policy_nonce_tpm_size);
	if (rc) {
		pr_err("%s: Failed to start decrypt policy session: %d\n", log_prefix
		, rc);
		goto out;
	}

	rc = tpm2_policy_pcr(tpm, policy_session,
			     sess->pcr_digest, SHA256_DIGEST_SIZE,
			     selection, sizeof(selection));
	if (rc) {
		pr_err("%s: Failed to authorize decrypt PCR policy: %d\n", log_prefix
		, rc);
		goto out;
	}

	rc = tpm2_policy_authvalue(tpm, policy_session);
	if (rc) {
		pr_err("%s: Failed to authorize decrypt authValue policy: %d\n", log_prefix
		, rc);
		goto out;
	}

	rc = tpm2_rsa_decrypt(tpm, sess->decrypt_key_handle,
			      decrypt_name, decrypt_name_size,
			      policy_session,
			      policy_nonce_tpm, policy_nonce_tpm_size,
			      sess->key_auth, sizeof(sess->key_auth),
			      req->encrypted_blob, req->encrypted_blob_size,
			      plaintext, TRUSTED_HASH_ENCRYPTED_BLOB_MAX_SIZE,
			      &plaintext_size);
	if (rc) {
		pr_err("%s: Failed to decrypt trusted hash blob: %d\n", log_prefix
		, rc);
		goto out;
	}
	policy_session = 0;

	sha256_init(&hash_ctx);
	sha256_update(&hash_ctx, plaintext, plaintext_size);
	sha256_final(&hash_ctx, req->result);

	if (copy_to_user(user_req, req, sizeof(*req)))
		rc = -EFAULT;

out:
	if (policy_session && tpm)
		trusted_hash_tpm2_flush_context(tpm, policy_session);
	if (sess) {
		if (tpm)
			destroy_session(tpm, sess);
		else
			free_session(sess);
	}
	if (tpm)
		put_device(&tpm->dev);
	if (sessions_locked)
		mutex_unlock(&sessions_lock);
	kfree_sensitive(plaintext);
	kfree_sensitive(srk_public);
	kfree_sensitive(srk_name);
	kfree_sensitive(decrypt_name);
	kfree_sensitive(req);
	return rc;
}

long cancel_session(struct trusted_hash_cancel_session __user *user_req)
{
	struct trusted_hash_cancel_session req;
	struct session *sess;
	struct tpm_chip *tpm;

	if (copy_from_user(&req, user_req, sizeof(req)))
		return -EFAULT;

	mutex_lock(&sessions_lock);
	sess = xa_erase(&sessions, req.session_id);
	if (!sess) {
		mutex_unlock(&sessions_lock);
		return -ENOENT;
	}

	tpm = trusted_hash_default_tpm();
	if (tpm) {
		destroy_session(tpm, sess);
		put_device(&tpm->dev);
	} else {
		free_session(sess);
	}

	mutex_unlock(&sessions_lock);
	return 0;
}

void cleanup_sessions(void)
{
	struct tpm_chip *tpm;

	mutex_lock(&sessions_lock);
	tpm = trusted_hash_default_tpm();
	if (tpm) {
		cleanup_sessions_with_tpm(tpm);
		put_device(&tpm->dev);
	} else {
		cleanup_sessions_with_tpm(NULL);
	}
	xa_destroy(&sessions);
	mutex_unlock(&sessions_lock);
}

void cleanup_module_identity(void)
{
	struct tpm_chip *tpm;

	mutex_lock(&module_identity_lock);
	if (!module_identity.signer_handle && !module_identity.srk_handle) {
		memset(&module_identity, 0, sizeof(module_identity));
		mutex_unlock(&module_identity_lock);
		return;
	}

	tpm = trusted_hash_default_tpm();
	if (tpm) {
		if (module_identity.signer_handle &&
		    module_identity.signer_handle != TRUSTED_HASH_MODULE_SIGNER_HANDLE)
			trusted_hash_tpm2_flush_context(tpm,
							module_identity.signer_handle);
		if (module_identity.srk_handle)
			trusted_hash_tpm2_flush_context(tpm,
							module_identity.srk_handle);
		put_device(&tpm->dev);
	}
	memset(&module_identity, 0, sizeof(module_identity));
	mutex_unlock(&module_identity_lock);
}
