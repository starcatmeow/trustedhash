#include "dev.h"
#include "tpm.h"
#include <linux/random.h>
#include <linux/unaligned.h>
#include <crypto/sha2.h>
#include <crypto/utils.h>

static char log_prefix[] = "trusted_hash:tpm.c";

/*
 * TPM2 command wrapper layer.
 *
 * This file is intentionally boring: it builds TPM2 command buffers, sends
 * them through the kernel TPM transport, and bounds-checks the TPM response
 * fields copied back to trusted_hash callers. It is not part of the intended
 * challenge solution.
 *
 * Public tpm2_* helpers are named after the TPM2 command they issue. Helpers
 * with extra suffixes such as _srk, _ak, _decrypt_key, or _endorsement are
 * fixed-template/fixed-hierarchy specializations of that named TPM2 command.
 */

#define TPM_ALG_RSA 0x0001
#define TPM_ALG_KEYEDHASH 0x0008
#define TPM_ALG_RSASSA 0x0014
#define TPM_ALG_OAEP 0x0017
#define TPM2_CC_ACTIVATE_CREDENTIAL 0x00000147
#define TPM2_CC_EVICT_CONTROL 0x00000120
#define TPM2_CC_FLUSH_CONTEXT 0x00000165
#define TPM2_CC_POLICY_PCR 0x0000017f
#define TPM2_CC_POLICY_SECRET 0x00000151
#define TPM2_CC_POLICY_AUTHVALUE 0x0000016b
#define TPM2_CC_RSA_DECRYPT 0x00000159
#define TPM2_CC_SIGN 0x0000015d
#define TPM2_CC_UNSEAL 0x0000015e
#define TPM2_CC_PCR_EXTEND 0x00000182
#define TPM2_CC_START_AUTH_SESSION 0x00000176
#define TPM2_CC_CERTIFY_CREATION 0x0000014a
#define TPM2_RC_SUCCESS 0x00000000
#define TPM2_RH_ENDORSEMENT 0x4000000b
#define TPM2_RH_NULL 0x40000007
#define TPM2_RH_OWNER 0x40000001
#define TPM_ST_HASHCHECK 0x8024
#define TPM2_SE_POLICY 0x01
#define TPMA_SESSION_CONTINUESESSION 0x01
#define TPM_RSA_KEY_BITS 2048
#define TPM_AES_KEY_BITS 128
#define TPM_SHA256_BLOCK_SIZE 64

static void put_be32_local(u8 *dst, u32 value)
{
    *dst++ = value >> 24;
    *dst++ = value >> 16;
    *dst++ = value >> 8;
    *dst = value;
}

static void put_be16_local(u8 *dst, u16 value)
{
    *dst++ = value >> 8;
    *dst = value;
}

static void hmac_sha256_4(const u8 *key, u16 key_size,
                          const u8 *data1, u16 data1_size,
                          const u8 *data2, u16 data2_size,
                          const u8 *data3, u16 data3_size,
                          const u8 *data4, u16 data4_size,
                          u8 out[SHA256_DIGEST_SIZE])
{
    struct sha256_ctx ctx;
    u8 block[TPM_SHA256_BLOCK_SIZE] = {};
    u8 inner[SHA256_DIGEST_SIZE];
    u8 ipad[TPM_SHA256_BLOCK_SIZE];
    u8 opad[TPM_SHA256_BLOCK_SIZE];
    int i;

    if (key_size > sizeof(block)) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_size);
        sha256_final(&ctx, block);
    } else {
        memcpy(block, key, key_size);
    }

    for (i = 0; i < TPM_SHA256_BLOCK_SIZE; i++) {
        ipad[i] = block[i] ^ 0x36;
        opad[i] = block[i] ^ 0x5c;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, ipad, sizeof(ipad));
    sha256_update(&ctx, data1, data1_size);
    sha256_update(&ctx, data2, data2_size);
    sha256_update(&ctx, data3, data3_size);
    sha256_update(&ctx, data4, data4_size);
    sha256_final(&ctx, inner);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, sizeof(opad));
    sha256_update(&ctx, inner, sizeof(inner));
    sha256_final(&ctx, out);

    memzero_explicit(block, sizeof(block));
    memzero_explicit(inner, sizeof(inner));
    memzero_explicit(ipad, sizeof(ipad));
    memzero_explicit(opad, sizeof(opad));
}

static void sha256_u32_update(struct sha256_ctx *ctx, u32 value)
{
    u8 be32[4];

    put_be32_local(be32, value);
    sha256_update(ctx, be32, sizeof(be32));
    memzero_explicit(be32, sizeof(be32));
}

static int require_bytes(u32 response_len, u32 offset, u32 len)
{
    if (offset > response_len || len > response_len - offset)
        return -EIO;
    return 0;
}

static int normalize_tpm_rc(int rc)
{
    return rc > 0 ? -EIO : rc;
}

int trusted_hash_tpm2_flush_context(struct tpm_chip *chip, u32 handle)
{
    int rc;
    struct tpm_buf buf;

    rc = tpm_buf_init(&buf, TPM2_ST_NO_SESSIONS, TPM2_CC_FLUSH_CONTEXT);
    if (rc)
        return rc;

    tpm_buf_append_u32(&buf, handle);

    rc = tpm_try_get_ops(chip);
    if (rc)
        goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_FlushContext");
    if (rc)
        rc = normalize_tpm_rc(rc);

    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_nv_readpublic(struct tpm_chip *chip, u32 nv_index, u16 *data_size) {
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;
    u32 response_len;
    u32 offset = TPM_HEADER_SIZE;
    u32 public_end;
    u16 public_size;
    u16 auth_policy_digest_size;

    rc = tpm_buf_init(&buf, TPM2_ST_NO_SESSIONS, TPM_CC_NV_ReadPublic);
    if (rc) return rc;

    // handle area
    tpm_buf_append_u32(&buf, nv_index); // nv index

    rc = tpm_try_get_ops(chip);
	if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_NV_ReadPublic");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_NO_SESSIONS) {
        pr_err("%s: Unexpected TPM2_NV_ReadPublic response tag 0x%04x\n", log_prefix,
               be16_to_cpu(header->tag));
        rc = -EIO;
        goto put_ops;
    }

    response_len = be32_to_cpu(header->length);
    if (require_bytes(response_len, offset, sizeof(__be16))) {
        rc = -EIO;
        goto put_ops;
    }
    public_size = get_unaligned_be16(&buf.data[offset]);
    offset += sizeof(__be16);
    if (require_bytes(response_len, offset, public_size)) {
        rc = -EIO;
        goto put_ops;
    }
    public_end = offset + public_size;

    if (require_bytes(public_end, offset, sizeof(__be32) + sizeof(__be16) +
                      sizeof(__be32) + sizeof(__be16))) {
        rc = -EIO;
        goto put_ops;
    }
    offset += sizeof(__be32); /* nvIndex */
    offset += sizeof(__be16); /* nameAlg */
    offset += sizeof(__be32); /* attributes */

    auth_policy_digest_size = get_unaligned_be16(&buf.data[offset]);
    offset += sizeof(__be16);
    if (auth_policy_digest_size != 0) {
        pr_err("%s: Unexpected auth policy digest size %d in TPM2_NV_ReadPublic\n", log_prefix,
               (int)auth_policy_digest_size);
        rc = -EIO;
        goto put_ops;
    }
    if (require_bytes(public_end, offset, sizeof(__be16))) {
        rc = -EIO;
        goto put_ops;
    }
    *data_size = get_unaligned_be16(&buf.data[offset]);
    offset += sizeof(__be16);
    if (offset != public_end) {
        rc = -EIO;
        goto put_ops;
    }
    rc = 0;
put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_nv_read(struct tpm_chip *chip, u32 nv_index, u16 size, u8 *data) {
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;
    u32 response_len;
    u32 parameter_size;
    u32 parameter_end;
    u32 offset = TPM_HEADER_SIZE;
    u16 returned_size;

    rc = tpm_buf_init(&buf, TPM2_ST_SESSIONS, TPM2_CC_NV_READ);
    if (rc) return rc;

    // handle area
    tpm_buf_append_u32(&buf, nv_index); // auth handle
    tpm_buf_append_u32(&buf, nv_index); // nv index

    // auth area
    tpm_buf_append_empty_auth(&buf, TPM2_RS_PW);

    // param area
    tpm_buf_append_u16(&buf, size); // size
    tpm_buf_append_u16(&buf, 0); // offset

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_NV_Read");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_SESSIONS) {
        pr_err("%s: Unexpected TPM2_NV_Read response tag 0x%04x\n", log_prefix,
               be16_to_cpu(header->tag));
        rc = -EIO;
        goto put_ops;
    }

    response_len = be32_to_cpu(header->length);
    if (require_bytes(response_len, offset, sizeof(__be32))) {
        rc = -EIO;
        goto put_ops;
    }
    parameter_size = get_unaligned_be32(&buf.data[offset]);
    offset += sizeof(__be32);
    if (require_bytes(response_len, offset, parameter_size)) {
        rc = -EIO;
        goto put_ops;
    }
    parameter_end = offset + parameter_size;

    if (require_bytes(response_len, offset, sizeof(__be16))) {
        rc = -EIO;
        goto put_ops;
    }
    returned_size = get_unaligned_be16(&buf.data[offset]);
    offset += sizeof(__be16);
    if (returned_size != size) {
        pr_err("%s: Unexpected TPM2_NV_Read data size %d, expected %d\n", log_prefix,
               (int)returned_size, size);
        rc = -EIO;
        goto put_ops;
    }

    if (require_bytes(response_len, offset, returned_size)) {
        rc = -EIO;
        goto put_ops;
    }
    memcpy(data, &buf.data[offset], returned_size);
    offset += returned_size;
    if (offset != parameter_end) {
        rc = -EIO;
        goto put_ops;
    }

    rc = 0;
put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_readpublic(struct tpm_chip *chip, u32 handle,
                    u8 *public, u16 public_max, u16 *public_size,
                    u8 *name, u16 name_max, u16 *name_size) {
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;
    u32 response_len;
    u32 offset = TPM_HEADER_SIZE;
    u16 field_size;

    rc = tpm_buf_init(&buf, TPM2_ST_NO_SESSIONS, TPM2_CC_READ_PUBLIC);
    if (rc) return rc;

    tpm_buf_append_u32(&buf, handle);

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_ReadPublic");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_NO_SESSIONS) {
        pr_err("%s: Unexpected TPM2_ReadPublic response tag 0x%04x\n", log_prefix,
               be16_to_cpu(header->tag));
        rc = -EIO;
        goto put_ops;
    }

    response_len = be32_to_cpu(header->length);
    if (require_bytes(response_len, offset, sizeof(__be16))) {
        rc = -EIO;
        goto put_ops;
    }

    field_size = get_unaligned_be16(&buf.data[offset]);
    if (field_size + sizeof(__be16) > public_max ||
        require_bytes(response_len, offset, field_size + sizeof(__be16))) {
        rc = -EOVERFLOW;
        goto put_ops;
    }
    memcpy(public, &buf.data[offset], field_size + sizeof(__be16));
    *public_size = field_size + sizeof(__be16);
    offset += field_size + sizeof(__be16);

    if (require_bytes(response_len, offset, sizeof(__be16))) {
        rc = -EIO;
        goto put_ops;
    }
    field_size = get_unaligned_be16(&buf.data[offset]);
    offset += sizeof(__be16);
    if (field_size > name_max || require_bytes(response_len, offset, field_size)) {
        rc = -EOVERFLOW;
        goto put_ops;
    }
    memcpy(name, &buf.data[offset], field_size);
    *name_size = field_size;
    offset += field_size;

    /*
     * qualifiedName follows. We do not need it for the verifier-visible API,
     * but sanity-check that it is structurally present.
     */
    if (require_bytes(response_len, offset, sizeof(__be16))) {
        rc = -EIO;
        goto put_ops;
    }

    rc = 0;
put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

static void append_rsa_storage_parent_template(struct tpm_buf *template)
{
    tpm_buf_append_u16(template, TPM_ALG_RSA);
    tpm_buf_append_u16(template, TPM_ALG_SHA256);
    tpm_buf_append_u32(template, TPM2_OA_FIXED_TPM |
                                 TPM2_OA_FIXED_PARENT |
                                 TPM2_OA_SENSITIVE_DATA_ORIGIN |
                                 TPM2_OA_USER_WITH_AUTH |
                                 TPM2_OA_NO_DA |
                                 TPM2_OA_RESTRICTED |
                                 TPM2_OA_DECRYPT);

    /* authPolicy */
    tpm_buf_append_u16(template, 0);

    /* TPMS_RSA_PARMS.symmetric = AES-128-CFB */
    tpm_buf_append_u16(template, TPM_ALG_AES);
    tpm_buf_append_u16(template, TPM_AES_KEY_BITS);
    tpm_buf_append_u16(template, TPM_ALG_CFB);

    /* scheme = TPM_ALG_NULL */
    tpm_buf_append_u16(template, TPM_ALG_NULL);

    tpm_buf_append_u16(template, TPM_RSA_KEY_BITS);
    tpm_buf_append_u32(template, 0); /* default exponent */

    /* unique.rsa */
    tpm_buf_append_u16(template, 0);
}

static void append_null_symmetric(struct tpm_buf *template)
{
    tpm_buf_append_u16(template, TPM_ALG_NULL);
}

static void append_rsa_scheme_hash(struct tpm_buf *template, u16 scheme)
{
    tpm_buf_append_u16(template, scheme);
    tpm_buf_append_u16(template, TPM_ALG_SHA256);
}

static void append_rsa_common_tail(struct tpm_buf *template)
{
    tpm_buf_append_u16(template, TPM_RSA_KEY_BITS);
    tpm_buf_append_u32(template, 0);
    tpm_buf_append_u16(template, 0);
}

static void append_rsa_ak_template(struct tpm_buf *template)
{
    tpm_buf_append_u16(template, TPM_ALG_RSA);
    tpm_buf_append_u16(template, TPM_ALG_SHA256);
    tpm_buf_append_u32(template, TPM2_OA_FIXED_TPM |
                                 TPM2_OA_FIXED_PARENT |
                                 TPM2_OA_SENSITIVE_DATA_ORIGIN |
                                 TPM2_OA_USER_WITH_AUTH |
                                 TPM2_OA_RESTRICTED |
                                 TPM2_OA_SIGN);
    tpm_buf_append_u16(template, 0);
    append_null_symmetric(template);
    append_rsa_scheme_hash(template, TPM_ALG_RSASSA);
    append_rsa_common_tail(template);
}

static void append_rsa_module_signer_template(struct tpm_buf *template)
{
    tpm_buf_append_u16(template, TPM_ALG_RSA);
    tpm_buf_append_u16(template, TPM_ALG_SHA256);
    tpm_buf_append_u32(template, TPM2_OA_FIXED_TPM |
                                 TPM2_OA_FIXED_PARENT |
                                 TPM2_OA_SENSITIVE_DATA_ORIGIN |
                                 TPM2_OA_USER_WITH_AUTH |
                                 TPM2_OA_SIGN);
    tpm_buf_append_u16(template, 0);
    append_null_symmetric(template);
    append_rsa_scheme_hash(template, TPM_ALG_RSASSA);
    append_rsa_common_tail(template);
}

static void append_rsa_decrypt_template(struct tpm_buf *template,
                                        const u8 *policy_digest,
                                        u16 policy_digest_size)
{
    tpm_buf_append_u16(template, TPM_ALG_RSA);
    tpm_buf_append_u16(template, TPM_ALG_SHA256);
    tpm_buf_append_u32(template, TPM2_OA_FIXED_TPM |
                                 TPM2_OA_FIXED_PARENT |
                                 TPM2_OA_SENSITIVE_DATA_ORIGIN |
                                 TPM2_OA_NO_DA |
                                 TPM2_OA_DECRYPT);
    tpm_buf_append_u16(template, policy_digest_size);
    tpm_buf_append(template, policy_digest, policy_digest_size);
    append_null_symmetric(template);
    append_rsa_scheme_hash(template, TPM_ALG_OAEP);
    append_rsa_common_tail(template);
}

static void append_keyedhash_sealed_template(struct tpm_buf *template,
                                             const u8 *policy_digest,
                                             u16 policy_digest_size)
{
    tpm_buf_append_u16(template, TPM_ALG_KEYEDHASH);
    tpm_buf_append_u16(template, TPM_ALG_SHA256);
    tpm_buf_append_u32(template, TPM2_OA_FIXED_TPM |
                                 TPM2_OA_FIXED_PARENT |
                                 TPM2_OA_ADMIN_WITH_POLICY |
                                 TPM2_OA_NO_DA);
    tpm_buf_append_u16(template, policy_digest_size);
    tpm_buf_append(template, policy_digest, policy_digest_size);
    tpm_buf_append_u16(template, TPM_ALG_NULL);
    tpm_buf_append_u16(template, 0);
}

static int skip_tpm2b(struct tpm_buf *buf, u32 response_len, u32 *offset)
{
    u16 size;

    if (require_bytes(response_len, *offset, sizeof(__be16)))
        return -EIO;

    size = get_unaligned_be16(&buf->data[*offset]);
    *offset += sizeof(__be16);
    if (require_bytes(response_len, *offset, size))
        return -EIO;

    *offset += size;
    return 0;
}

static int copy_tpm2b(struct tpm_buf *buf, u32 response_len, u32 *offset,
                     u8 *out, u16 out_max, u16 *out_size, bool include_size)
{
    u32 start = *offset;
    u16 size;

    if (require_bytes(response_len, *offset, sizeof(__be16)))
        return -EIO;

    size = get_unaligned_be16(&buf->data[*offset]);
    *offset += sizeof(__be16);
    if (require_bytes(response_len, *offset, size))
        return -EIO;

    if (include_size) {
        if (size + sizeof(__be16) > out_max)
            return -EOVERFLOW;
        memcpy(out, &buf->data[start], size + sizeof(__be16));
        *out_size = size + sizeof(__be16);
    } else {
        if (size > out_max)
            return -EOVERFLOW;
        memcpy(out, &buf->data[*offset], size);
        *out_size = size;
    }

    *offset += size;
    return 0;
}

static void append_empty_session(struct tpm_buf *buf, u32 handle, u8 attrs)
{
    tpm_buf_append_u32(buf, handle);
    tpm_buf_append_u16(buf, 0);
    tpm_buf_append_u8(buf, attrs);
    tpm_buf_append_u16(buf, 0);
}

static void append_hmac_session(struct tpm_buf *buf, u32 handle,
                                const u8 *nonce, u16 nonce_size, u8 attrs,
                                const u8 *hmac, u16 hmac_size)
{
    tpm_buf_append_u32(buf, handle);
    tpm_buf_append_u16(buf, nonce_size);
    if (nonce_size)
        tpm_buf_append(buf, nonce, nonce_size);
    tpm_buf_append_u8(buf, attrs);
    tpm_buf_append_u16(buf, hmac_size);
    if (hmac_size)
        tpm_buf_append(buf, hmac, hmac_size);
}

static void append_password_auth(struct tpm_buf *buf, const u8 *auth,
                                 u16 auth_size)
{
    tpm_buf_append_u32(buf, 4 + 2 + 1 + 2 + auth_size);
    tpm_buf_append_u32(buf, TPM2_RS_PW);
    tpm_buf_append_u16(buf, 0);
    tpm_buf_append_u8(buf, 0);
    tpm_buf_append_u16(buf, auth_size);
    if (auth_size)
        tpm_buf_append(buf, auth, auth_size);
}

static void append_two_empty_sessions(struct tpm_buf *buf, u32 first_handle,
                                      u32 second_handle)
{
    tpm_buf_append_u32(buf, 18);
    append_empty_session(buf, first_handle, 0);
    append_empty_session(buf, second_handle, 0);
}

static int copy_tpmt_signature(struct tpm_buf *buf, u32 response_len,
                               u32 *offset, u8 *signature,
                               u16 signature_max, u16 *signature_size)
{
    u32 start = *offset;
    u16 sig_alg;
    u16 rsa_sig_size;

    if (require_bytes(response_len, *offset, 2 * sizeof(__be16)))
        return -EIO;

    sig_alg = get_unaligned_be16(&buf->data[*offset]);
    *offset += sizeof(__be16);
    if (sig_alg != TPM_ALG_RSASSA)
        return -EOPNOTSUPP;

    *offset += sizeof(__be16); /* hashAlg */
    if (require_bytes(response_len, *offset, sizeof(__be16)))
        return -EIO;

    rsa_sig_size = get_unaligned_be16(&buf->data[*offset]);
    *offset += sizeof(__be16);
    if (require_bytes(response_len, *offset, rsa_sig_size))
        return -EIO;

    *offset += rsa_sig_size;
    if (*offset - start > signature_max)
        return -EOVERFLOW;

    memcpy(signature, &buf->data[start], *offset - start);
    *signature_size = *offset - start;
    return 0;
}

static int copy_creation_ticket(struct tpm_buf *buf, u32 response_len,
                                u32 *offset, u8 *ticket, u16 ticket_max,
                                u16 *ticket_size)
{
    u32 start = *offset;
    int rc;

    if (require_bytes(response_len, *offset, sizeof(__be16) + sizeof(__be32)))
        return -EIO;

    *offset += sizeof(__be16) + sizeof(__be32);
    rc = skip_tpm2b(buf, response_len, offset);
    if (rc)
        return rc;

    if (!ticket || !ticket_size)
        return 0;

    if (*offset - start > ticket_max)
        return -EOVERFLOW;

    memcpy(ticket, &buf->data[start], *offset - start);
    *ticket_size = *offset - start;
    return 0;
}

int tpm2_createprimary_srk(struct tpm_chip *chip, u32 *handle,
                           u8 *public, u16 public_max, u16 *public_size,
                           u8 *name, u16 name_max, u16 *name_size)
{
    int rc;
    struct tpm_buf buf;
    struct tpm_buf template;
    struct tpm_header *header;
    u32 response_len;
    u32 parameter_size;
    u32 parameter_end;
    u32 offset = TPM_HEADER_SIZE;

    rc = tpm_buf_init(&buf, TPM2_ST_SESSIONS, TPM2_CC_CREATE_PRIMARY);
    if (rc) return rc;

    rc = tpm_buf_init_sized(&template);
    if (rc) goto out_buf;
    append_rsa_storage_parent_template(&template);

    tpm_buf_append_u32(&buf, TPM2_RH_OWNER);
    tpm_buf_append_empty_auth(&buf, TPM2_RS_PW);

    /* inSensitive: TPMS_SENSITIVE_CREATE with empty userAuth and data */
    tpm_buf_append_u16(&buf, 4);
    tpm_buf_append_u16(&buf, 0);
    tpm_buf_append_u16(&buf, 0);

    tpm_buf_append(&buf, template.data, template.length);
    tpm_buf_destroy(&template);

    /* outsideInfo */
    tpm_buf_append_u16(&buf, 0);

    /* creationPCR */
    tpm_buf_append_u32(&buf, 0);

    rc = tpm_try_get_ops(chip);
    if (rc) goto out_buf;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_CreatePrimary(SRK)");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_SESSIONS) {
        rc = -EIO;
        goto put_ops;
    }

    response_len = be32_to_cpu(header->length);
    if (require_bytes(response_len, offset, sizeof(__be32))) {
        rc = -EIO;
        goto put_ops;
    }
    *handle = get_unaligned_be32(&buf.data[offset]);
    offset += sizeof(__be32);

    if (require_bytes(response_len, offset, sizeof(__be32))) {
        rc = -EIO;
        goto put_ops;
    }
    parameter_size = get_unaligned_be32(&buf.data[offset]);
    offset += sizeof(__be32);
    parameter_end = offset + parameter_size;
    if (parameter_end > response_len) {
        rc = -EIO;
        goto put_ops;
    }

    rc = copy_tpm2b(&buf, response_len, &offset, public, public_max,
                    public_size, true);
    if (rc) goto flush_handle;

    rc = skip_tpm2b(&buf, response_len, &offset); /* creationData */
    if (rc) goto flush_handle;
    rc = skip_tpm2b(&buf, response_len, &offset); /* creationHash */
    if (rc) goto flush_handle;

    /* creationTicket: tag + hierarchy + TPM2B_DIGEST */
    if (require_bytes(response_len, offset, sizeof(__be16) + sizeof(__be32))) {
        rc = -EIO;
        goto flush_handle;
    }
    offset += sizeof(__be16) + sizeof(__be32);
    rc = skip_tpm2b(&buf, response_len, &offset);
    if (rc) goto flush_handle;

    rc = copy_tpm2b(&buf, response_len, &offset, name, name_max, name_size,
                    false);
    if (rc) goto flush_handle;

    if (offset != parameter_end) {
        rc = -EIO;
        goto flush_handle;
    }

    rc = 0;
    goto put_ops;

flush_handle:
    tpm2_flush_context(chip, *handle);
    *handle = 0;
put_ops:
    tpm_put_ops(chip);
out_buf:
    tpm_buf_destroy(&buf);
    return rc;
}

static int tpm2_create_with_template(struct tpm_chip *chip, u32 parent_handle,
                                     const u8 *auth, u16 auth_size,
                                     const u8 *sensitive_data,
                                     u16 sensitive_data_size,
                                     struct tpm_buf *public_template,
                                     const u8 *outside_info,
                                     u16 outside_info_size,
                                     u8 *out_private, u16 out_private_max,
                                     u16 *out_private_size,
                                     u8 *out_public, u16 out_public_max,
                                     u16 *out_public_size,
                                     u8 *creation_hash,
                                     u16 creation_hash_max,
                                     u16 *creation_hash_size,
                                     u8 *creation_ticket,
                                     u16 creation_ticket_max,
                                     u16 *creation_ticket_size)
{
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;
    u32 response_len;
    u32 parameter_size;
    u32 parameter_end;
    u32 offset = TPM_HEADER_SIZE;

    rc = tpm_buf_init(&buf, TPM2_ST_SESSIONS, TPM2_CC_CREATE);
    if (rc) return rc;

    tpm_buf_append_u32(&buf, parent_handle);
    tpm_buf_append_empty_auth(&buf, TPM2_RS_PW);

    tpm_buf_append_u16(&buf, sizeof(__be16) + auth_size +
                             sizeof(__be16) + sensitive_data_size);
    tpm_buf_append_u16(&buf, auth_size);
    if (auth_size)
        tpm_buf_append(&buf, auth, auth_size);
    tpm_buf_append_u16(&buf, sensitive_data_size);
    if (sensitive_data_size)
        tpm_buf_append(&buf, sensitive_data, sensitive_data_size);

    tpm_buf_append(&buf, public_template->data, public_template->length);
    tpm_buf_append_u16(&buf, outside_info_size);
    if (outside_info_size)
        tpm_buf_append(&buf, outside_info, outside_info_size);
    tpm_buf_append_u32(&buf, 0);

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_Create");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_SESSIONS) {
        rc = -EIO;
        goto put_ops;
    }

    response_len = be32_to_cpu(header->length);
    if (require_bytes(response_len, offset, sizeof(__be32))) {
        rc = -EIO;
        goto put_ops;
    }
    parameter_size = get_unaligned_be32(&buf.data[offset]);
    offset += sizeof(__be32);
    parameter_end = offset + parameter_size;
    if (parameter_end > response_len) {
        rc = -EIO;
        goto put_ops;
    }

    rc = copy_tpm2b(&buf, response_len, &offset, out_private,
                    out_private_max, out_private_size, true);
    if (rc) goto put_ops;
    rc = copy_tpm2b(&buf, response_len, &offset, out_public,
                    out_public_max, out_public_size, true);
    if (rc) goto put_ops;

    rc = skip_tpm2b(&buf, response_len, &offset); /* creationData */
    if (rc) goto put_ops;

    if (creation_hash && creation_hash_size) {
        rc = copy_tpm2b(&buf, response_len, &offset, creation_hash,
                        creation_hash_max, creation_hash_size, true);
    } else {
        rc = skip_tpm2b(&buf, response_len, &offset);
    }
    if (rc) goto put_ops;

    if (creation_ticket && creation_ticket_size)
        rc = copy_creation_ticket(&buf, response_len, &offset,
                                  creation_ticket, creation_ticket_max,
                                  creation_ticket_size);
    else
        rc = copy_creation_ticket(&buf, response_len, &offset,
                                  NULL, 0, NULL);
    if (rc) goto put_ops;

    if (offset != parameter_end) {
        rc = -EIO;
        goto put_ops;
    }

    rc = 0;
put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_create_ak(struct tpm_chip *chip, u32 parent_handle,
                   u8 *out_private, u16 out_private_max, u16 *out_private_size,
                   u8 *out_public, u16 out_public_max, u16 *out_public_size)
{
    int rc;
    struct tpm_buf template;

    rc = tpm_buf_init_sized(&template);
    if (rc) return rc;
    append_rsa_ak_template(&template);
    rc = tpm2_create_with_template(chip, parent_handle, NULL, 0, NULL, 0, &template,
                                   NULL, 0,
                                   out_private, out_private_max,
                                   out_private_size, out_public,
                                   out_public_max, out_public_size,
                                   NULL, 0, NULL, NULL, 0, NULL);
    tpm_buf_destroy(&template);
    return rc;
}

int tpm2_create_module_signer(struct tpm_chip *chip, u32 parent_handle,
                              const u8 *auth, u16 auth_size,
                              u8 *out_private, u16 out_private_max,
                              u16 *out_private_size,
                              u8 *out_public, u16 out_public_max,
                              u16 *out_public_size)
{
    int rc;
    struct tpm_buf template;

    rc = tpm_buf_init_sized(&template);
    if (rc) return rc;
    append_rsa_module_signer_template(&template);
    rc = tpm2_create_with_template(chip, parent_handle, auth, auth_size,
                                   NULL, 0,
                                   &template, NULL, 0,
                                   out_private, out_private_max,
                                   out_private_size, out_public,
                                   out_public_max, out_public_size,
                                   NULL, 0, NULL, NULL, 0, NULL);
    tpm_buf_destroy(&template);
    return rc;
}

int tpm2_create_sealed_secret(struct tpm_chip *chip, u32 parent_handle,
                              const u8 *policy_digest, u16 policy_digest_size,
                              const u8 *secret, u16 secret_size,
                              u8 *out_private, u16 out_private_max,
                              u16 *out_private_size,
                              u8 *out_public, u16 out_public_max,
                              u16 *out_public_size)
{
    int rc;
    struct tpm_buf template;

    rc = tpm_buf_init_sized(&template);
    if (rc) return rc;
    append_keyedhash_sealed_template(&template, policy_digest,
                                     policy_digest_size);
    rc = tpm2_create_with_template(chip, parent_handle, NULL, 0,
                                   secret, secret_size,
                                   &template, NULL, 0,
                                   out_private, out_private_max,
                                   out_private_size, out_public,
                                   out_public_max, out_public_size,
                                   NULL, 0, NULL, NULL, 0, NULL);
    tpm_buf_destroy(&template);
    return rc;
}

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
                            u16 *creation_ticket_size)
{
    int rc;
    struct tpm_buf template;

    rc = tpm_buf_init_sized(&template);
    if (rc) return rc;
    append_rsa_decrypt_template(&template, policy_digest, policy_digest_size);
    rc = tpm2_create_with_template(chip, parent_handle, auth, auth_size,
                                   NULL, 0,
                                   &template, outside_info,
                                   outside_info_size,
                                   out_private, out_private_max,
                                   out_private_size, out_public,
                                   out_public_max, out_public_size,
                                   creation_hash, creation_hash_max,
                                   creation_hash_size, creation_ticket,
                                   creation_ticket_max,
                                   creation_ticket_size);
    tpm_buf_destroy(&template);
    return rc;
}

int tpm2_load(struct tpm_chip *chip, u32 parent_handle,
              const u8 *in_private, u16 in_private_size,
              const u8 *in_public, u16 in_public_size,
              u32 *handle, u8 *name, u16 name_max, u16 *name_size)
{
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;
    u32 response_len;
    u32 parameter_size;
    u32 parameter_end;
    u32 offset = TPM_HEADER_SIZE;

    rc = tpm_buf_init(&buf, TPM2_ST_SESSIONS, TPM2_CC_LOAD);
    if (rc) return rc;

    tpm_buf_append_u32(&buf, parent_handle);
    tpm_buf_append_empty_auth(&buf, TPM2_RS_PW);
    tpm_buf_append(&buf, in_private, in_private_size);
    tpm_buf_append(&buf, in_public, in_public_size);

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_Load");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_SESSIONS) {
        rc = -EIO;
        goto put_ops;
    }

    response_len = be32_to_cpu(header->length);
    if (require_bytes(response_len, offset, sizeof(__be32))) {
        rc = -EIO;
        goto put_ops;
    }
    *handle = get_unaligned_be32(&buf.data[offset]);
    offset += sizeof(__be32);

    if (require_bytes(response_len, offset, sizeof(__be32))) {
        rc = -EIO;
        goto put_ops;
    }
    parameter_size = get_unaligned_be32(&buf.data[offset]);
    offset += sizeof(__be32);
    parameter_end = offset + parameter_size;
    if (parameter_end > response_len) {
        rc = -EIO;
        goto put_ops;
    }

    rc = copy_tpm2b(&buf, response_len, &offset, name, name_max, name_size,
                    false);
    if (rc) goto flush_handle;

    if (offset != parameter_end) {
        rc = -EIO;
        goto flush_handle;
    }

    rc = 0;
    goto put_ops;

flush_handle:
    tpm2_flush_context(chip, *handle);
    *handle = 0;
put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_certify_creation(struct tpm_chip *chip, u32 signing_handle,
                          u32 object_handle, const u8 *qualifying_data,
                          u16 qualifying_data_size, const u8 *creation_hash,
                          u16 creation_hash_size, const u8 *creation_ticket,
                          u16 creation_ticket_size, u8 *certify_info,
                          u16 certify_info_max, u16 *certify_info_size,
                          u8 *signature, u16 signature_max,
                          u16 *signature_size)
{
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;
    u32 response_len;
    u32 parameter_size;
    u32 parameter_end;
    u32 offset = TPM_HEADER_SIZE;

    rc = tpm_buf_init(&buf, TPM2_ST_SESSIONS, TPM2_CC_CERTIFY_CREATION);
    if (rc) return rc;

    tpm_buf_append_u32(&buf, signing_handle);
    tpm_buf_append_u32(&buf, object_handle);
    tpm_buf_append_empty_auth(&buf, TPM2_RS_PW);

    tpm_buf_append_u16(&buf, qualifying_data_size);
    if (qualifying_data_size)
        tpm_buf_append(&buf, qualifying_data, qualifying_data_size);

    tpm_buf_append(&buf, creation_hash, creation_hash_size);
    tpm_buf_append_u16(&buf, TPM_ALG_NULL);
    tpm_buf_append(&buf, creation_ticket, creation_ticket_size);

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_CertifyCreation");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_SESSIONS) {
        rc = -EIO;
        goto put_ops;
    }

    response_len = be32_to_cpu(header->length);
    if (require_bytes(response_len, offset, sizeof(__be32))) {
        rc = -EIO;
        goto put_ops;
    }
    parameter_size = get_unaligned_be32(&buf.data[offset]);
    offset += sizeof(__be32);
    parameter_end = offset + parameter_size;
    if (parameter_end > response_len) {
        rc = -EIO;
        goto put_ops;
    }

    rc = copy_tpm2b(&buf, response_len, &offset, certify_info,
                    certify_info_max, certify_info_size, true);
    if (rc) goto put_ops;

    rc = copy_tpmt_signature(&buf, response_len, &offset, signature,
                             signature_max, signature_size);
    if (rc) goto put_ops;

    if (offset != parameter_end) {
        rc = -EIO;
        goto put_ops;
    }

    rc = 0;
put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_sign(struct tpm_chip *chip, u32 signing_handle,
              const u8 *auth, u16 auth_size,
              const u8 digest[SHA256_DIGEST_SIZE],
              u8 *signature, u16 signature_max, u16 *signature_size)
{
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;
    u32 response_len;
    u32 parameter_size;
    u32 parameter_end;
    u32 offset = TPM_HEADER_SIZE;

    rc = tpm_buf_init(&buf, TPM2_ST_SESSIONS, TPM2_CC_SIGN);
    if (rc) return rc;

    tpm_buf_append_u32(&buf, signing_handle);
    append_password_auth(&buf, auth, auth_size);

    tpm_buf_append_u16(&buf, SHA256_DIGEST_SIZE);
    tpm_buf_append(&buf, digest, SHA256_DIGEST_SIZE);
    append_rsa_scheme_hash(&buf, TPM_ALG_RSASSA);
    tpm_buf_append_u16(&buf, TPM_ST_HASHCHECK);
    tpm_buf_append_u32(&buf, TPM2_RH_NULL);
    tpm_buf_append_u16(&buf, 0);

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_Sign");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_SESSIONS) {
        rc = -EIO;
        goto put_ops;
    }

    response_len = be32_to_cpu(header->length);
    if (require_bytes(response_len, offset, sizeof(__be32))) {
        rc = -EIO;
        goto put_ops;
    }
    parameter_size = get_unaligned_be32(&buf.data[offset]);
    offset += sizeof(__be32);
    parameter_end = offset + parameter_size;
    if (parameter_end > response_len) {
        rc = -EIO;
        goto put_ops;
    }

    rc = copy_tpmt_signature(&buf, response_len, &offset, signature,
                             signature_max, signature_size);
    if (rc)
        goto put_ops;

    if (offset != parameter_end) {
        rc = -EIO;
        goto put_ops;
    }

    rc = 0;
put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_unseal(struct tpm_chip *chip, u32 item_handle, u32 policy_session,
                u8 *secret, u16 secret_max, u16 *secret_size)
{
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;
    u32 response_len;
    u32 parameter_size;
    u32 parameter_end;
    u32 offset = TPM_HEADER_SIZE;

    rc = tpm_buf_init(&buf, TPM2_ST_SESSIONS, TPM2_CC_UNSEAL);
    if (rc) return rc;

    tpm_buf_append_u32(&buf, item_handle);
    tpm_buf_append_u32(&buf, 9);
    append_empty_session(&buf, policy_session, 0);

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_Unseal");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_SESSIONS) {
        rc = -EIO;
        goto put_ops;
    }

    response_len = be32_to_cpu(header->length);
    if (require_bytes(response_len, offset, sizeof(__be32))) {
        rc = -EIO;
        goto put_ops;
    }
    parameter_size = get_unaligned_be32(&buf.data[offset]);
    offset += sizeof(__be32);
    parameter_end = offset + parameter_size;
    if (parameter_end > response_len) {
        rc = -EIO;
        goto put_ops;
    }

    rc = copy_tpm2b(&buf, response_len, &offset, secret, secret_max,
                    secret_size, false);
    if (rc)
        goto put_ops;

    if (offset != parameter_end) {
        rc = -EIO;
        goto put_ops;
    }

    rc = 0;
put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_evict_control_owner(struct tpm_chip *chip, u32 object_handle,
                             u32 persistent_handle)
{
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;

    rc = tpm_buf_init(&buf, TPM2_ST_SESSIONS, TPM2_CC_EVICT_CONTROL);
    if (rc) return rc;

    tpm_buf_append_u32(&buf, TPM2_RH_OWNER);
    tpm_buf_append_u32(&buf, object_handle);
    tpm_buf_append_empty_auth(&buf, TPM2_RS_PW);
    tpm_buf_append_u32(&buf, persistent_handle);

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_EvictControl(owner)");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    rc = be16_to_cpu(header->tag) == TPM2_ST_SESSIONS ? 0 : -EIO;

put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_pcr_extend_sha256(struct tpm_chip *chip, u32 pcr_index,
                           const u8 digest[SHA256_DIGEST_SIZE])
{
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;

    rc = tpm_buf_init(&buf, TPM2_ST_SESSIONS, TPM2_CC_PCR_EXTEND);
    if (rc) return rc;

    tpm_buf_append_u32(&buf, pcr_index);
    tpm_buf_append_empty_auth(&buf, TPM2_RS_PW);
    tpm_buf_append_u32(&buf, 1);
    tpm_buf_append_u16(&buf, TPM_ALG_SHA256);
    tpm_buf_append(&buf, digest, SHA256_DIGEST_SIZE);

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_PCR_Extend");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    rc = be16_to_cpu(header->tag) == TPM2_ST_SESSIONS ? 0 : -EIO;

put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_start_policy_session(struct tpm_chip *chip, u32 *session_handle,
                              u8 *nonce_tpm, u16 nonce_tpm_max,
                              u16 *nonce_tpm_size)
{
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;
    u8 nonce[16];
    u32 response_len;
    u32 offset = TPM_HEADER_SIZE;

    get_random_bytes(nonce, sizeof(nonce));

    rc = tpm_buf_init(&buf, TPM2_ST_NO_SESSIONS, TPM2_CC_START_AUTH_SESSION);
    if (rc) return rc;

    tpm_buf_append_u32(&buf, TPM2_RH_NULL);
    tpm_buf_append_u32(&buf, TPM2_RH_NULL);
    tpm_buf_append_u16(&buf, sizeof(nonce));
    tpm_buf_append(&buf, nonce, sizeof(nonce));
    tpm_buf_append_u16(&buf, 0);
    tpm_buf_append_u8(&buf, TPM2_SE_POLICY);
    tpm_buf_append_u16(&buf, TPM_ALG_NULL);
    tpm_buf_append_u16(&buf, TPM_ALG_SHA256);

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_StartAuthSession(policy)");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_NO_SESSIONS) {
        rc = -EIO;
        goto put_ops;
    }

    response_len = be32_to_cpu(header->length);
    if (require_bytes(response_len, offset, sizeof(__be32))) {
        rc = -EIO;
        goto put_ops;
    }
    *session_handle = get_unaligned_be32(&buf.data[offset]);
    offset += sizeof(__be32);

    if (nonce_tpm && nonce_tpm_size)
        rc = copy_tpm2b(&buf, response_len, &offset, nonce_tpm,
                        nonce_tpm_max, nonce_tpm_size, false);
    else
        rc = skip_tpm2b(&buf, response_len, &offset); /* nonceTPM */
    if (rc)
        goto flush_session;

    rc = 0;
    goto put_ops;

flush_session:
    tpm2_flush_context(chip, *session_handle);
    *session_handle = 0;
put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_policy_secret_endorsement(struct tpm_chip *chip, u32 policy_session)
{
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;
    u32 response_len;
    u32 parameter_size;
    u32 parameter_end;
    u32 offset = TPM_HEADER_SIZE;

    rc = tpm_buf_init(&buf, TPM2_ST_SESSIONS, TPM2_CC_POLICY_SECRET);
    if (rc) return rc;

    tpm_buf_append_u32(&buf, TPM2_RH_ENDORSEMENT);
    tpm_buf_append_u32(&buf, policy_session);
    tpm_buf_append_empty_auth(&buf, TPM2_RS_PW);
    tpm_buf_append_u16(&buf, 0);
    tpm_buf_append_u16(&buf, 0);
    tpm_buf_append_u16(&buf, 0);
    tpm_buf_append_u32(&buf, 0);

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_PolicySecret(endorsement)");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_SESSIONS) {
        rc = -EIO;
        goto put_ops;
    }

    response_len = be32_to_cpu(header->length);
    if (require_bytes(response_len, offset, sizeof(__be32))) {
        rc = -EIO;
        goto put_ops;
    }
    parameter_size = get_unaligned_be32(&buf.data[offset]);
    offset += sizeof(__be32);
    parameter_end = offset + parameter_size;
    if (parameter_end > response_len) {
        rc = -EIO;
        goto put_ops;
    }

    rc = skip_tpm2b(&buf, response_len, &offset); /* timeout */
    if (rc) goto put_ops;

    if (require_bytes(response_len, offset, sizeof(__be16) + sizeof(__be32))) {
        rc = -EIO;
        goto put_ops;
    }
    offset += sizeof(__be16) + sizeof(__be32);
    rc = skip_tpm2b(&buf, response_len, &offset); /* policyTicket.digest */
    if (rc) goto put_ops;

    if (offset != parameter_end) {
        rc = -EIO;
        goto put_ops;
    }

    rc = 0;
put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_policy_pcr(struct tpm_chip *chip, u32 policy_session,
                    const u8 *pcr_digest, u16 pcr_digest_size,
                    const u8 *pcr_selection, u16 pcr_selection_size)
{
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;

    rc = tpm_buf_init(&buf, TPM2_ST_NO_SESSIONS, TPM2_CC_POLICY_PCR);
    if (rc) return rc;

    tpm_buf_append_u32(&buf, policy_session);
    tpm_buf_append_u16(&buf, pcr_digest_size);
    if (pcr_digest_size)
        tpm_buf_append(&buf, pcr_digest, pcr_digest_size);
    tpm_buf_append(&buf, pcr_selection, pcr_selection_size);

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_PolicyPCR");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_NO_SESSIONS)
        rc = -EIO;
    else
        rc = 0;

put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_policy_authvalue(struct tpm_chip *chip, u32 policy_session)
{
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;

    rc = tpm_buf_init(&buf, TPM2_ST_NO_SESSIONS, TPM2_CC_POLICY_AUTHVALUE);
    if (rc) return rc;

    tpm_buf_append_u32(&buf, policy_session);

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_PolicyAuthValue");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_NO_SESSIONS)
        rc = -EIO;
    else
        rc = 0;

put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_activate_credential(struct tpm_chip *chip, u32 activate_handle,
                             u32 key_handle, u32 key_policy_session,
                             const u8 *credential_blob,
                             u16 credential_blob_size,
                             const u8 *secret, u16 secret_size,
                             u8 *credential, u16 credential_max,
                             u16 *credential_size)
{
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;
    u32 response_len;
    u32 parameter_size;
    u32 parameter_end;
    u32 offset = TPM_HEADER_SIZE;

    rc = tpm_buf_init(&buf, TPM2_ST_SESSIONS, TPM2_CC_ACTIVATE_CREDENTIAL);
    if (rc) return rc;

    tpm_buf_append_u32(&buf, activate_handle);
    tpm_buf_append_u32(&buf, key_handle);
    append_two_empty_sessions(&buf, TPM2_RS_PW, key_policy_session);
    tpm_buf_append(&buf, credential_blob, credential_blob_size);
    tpm_buf_append(&buf, secret, secret_size);

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_ActivateCredential");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_SESSIONS) {
        rc = -EIO;
        goto put_ops;
    }

    response_len = be32_to_cpu(header->length);
    if (require_bytes(response_len, offset, sizeof(__be32))) {
        rc = -EIO;
        goto put_ops;
    }
    parameter_size = get_unaligned_be32(&buf.data[offset]);
    offset += sizeof(__be32);
    parameter_end = offset + parameter_size;
    if (parameter_end > response_len) {
        rc = -EIO;
        goto put_ops;
    }

    rc = copy_tpm2b(&buf, response_len, &offset, credential,
                    credential_max, credential_size, false);
    if (rc) goto put_ops;

    if (offset != parameter_end) {
        rc = -EIO;
        goto put_ops;
    }

    rc = 0;
put_ops:
    tpm_put_ops(chip);
out:
    tpm_buf_destroy(&buf);
    return rc;
}

int tpm2_rsa_decrypt(struct tpm_chip *chip, u32 key_handle,
                     const u8 *key_name, u16 key_name_size,
                     u32 policy_session, const u8 *nonce_tpm,
                     u16 nonce_tpm_size, const u8 *key_auth,
                     u16 key_auth_size, const u8 *ciphertext,
                     u16 ciphertext_size, u8 *plaintext,
                     u16 plaintext_max, u16 *plaintext_size)
{
    int rc;
    struct tpm_buf buf;
    struct tpm_header *header;
    struct sha256_ctx hash_ctx;
    u8 attrs = 0;
    u8 be16[2];
    u8 be32[4];
    u8 cp_hash[SHA256_DIGEST_SIZE];
    u8 rp_hash[SHA256_DIGEST_SIZE];
    u8 hmac[SHA256_DIGEST_SIZE];
    u8 response_hmac[SHA256_DIGEST_SIZE];
    u8 expected_response_hmac[SHA256_DIGEST_SIZE];
    u8 nonce_caller[16];
    u8 response_nonce[64];
    u16 response_nonce_size = 0;
    u16 response_hmac_size = 0;
    u8 response_attrs;
    u32 response_len;
    u32 parameter_size;
    u32 parameter_start;
    u32 parameter_end;
    u32 offset = TPM_HEADER_SIZE;

    rc = tpm_buf_init(&buf, TPM2_ST_SESSIONS, TPM2_CC_RSA_DECRYPT);
    if (rc) return rc;

    get_random_bytes(nonce_caller, sizeof(nonce_caller));

    sha256_init(&hash_ctx);
    put_be32_local(be32, TPM2_CC_RSA_DECRYPT);
    sha256_update(&hash_ctx, be32, sizeof(be32));
    sha256_update(&hash_ctx, key_name, key_name_size);
    put_be16_local(be16, ciphertext_size);
    sha256_update(&hash_ctx, be16, sizeof(be16));
    sha256_update(&hash_ctx, ciphertext, ciphertext_size);
    put_be16_local(be16, TPM_ALG_OAEP);
    sha256_update(&hash_ctx, be16, sizeof(be16));
    put_be16_local(be16, TPM_ALG_SHA256);
    sha256_update(&hash_ctx, be16, sizeof(be16));
    put_be16_local(be16, 0);
    sha256_update(&hash_ctx, be16, sizeof(be16));
    sha256_final(&hash_ctx, cp_hash);

    hmac_sha256_4(key_auth, key_auth_size,
                  cp_hash, sizeof(cp_hash),
                  nonce_caller, sizeof(nonce_caller),
                  nonce_tpm, nonce_tpm_size,
                  &attrs, sizeof(attrs),
                  hmac);

    tpm_buf_append_u32(&buf, key_handle);
    tpm_buf_append_u32(&buf, 4 + 2 + sizeof(nonce_caller) + 1 + 2 +
                             sizeof(hmac));
    append_hmac_session(&buf, policy_session,
                        nonce_caller, sizeof(nonce_caller),
                        attrs, hmac, sizeof(hmac));
    tpm_buf_append_u16(&buf, ciphertext_size);
    tpm_buf_append(&buf, ciphertext, ciphertext_size);
    append_rsa_scheme_hash(&buf, TPM_ALG_OAEP);
    tpm_buf_append_u16(&buf, 0); /* label */

    rc = tpm_try_get_ops(chip);
    if (rc) goto out;

    rc = tpm_transmit_cmd(chip, &buf, 0, "TPM2_RSA_Decrypt");
    if (rc) {
        rc = normalize_tpm_rc(rc);
        goto put_ops;
    }

    header = (struct tpm_header *)buf.data;
    if (be16_to_cpu(header->tag) != TPM2_ST_SESSIONS) {
        rc = -EIO;
        goto put_ops;
    }

    response_len = be32_to_cpu(header->length);
    if (require_bytes(response_len, offset, sizeof(__be32))) {
        rc = -EIO;
        goto put_ops;
    }
    parameter_size = get_unaligned_be32(&buf.data[offset]);
    offset += sizeof(__be32);
    parameter_start = offset;
    parameter_end = offset + parameter_size;
    if (parameter_end > response_len) {
        rc = -EIO;
        goto put_ops;
    }

    rc = copy_tpm2b(&buf, response_len, &offset, plaintext,
                    plaintext_max, plaintext_size, false);
    if (rc) goto put_ops;

    if (offset != parameter_end) {
        rc = -EIO;
        goto put_ops;
    }

    rc = copy_tpm2b(&buf, response_len, &offset, response_nonce,
                    sizeof(response_nonce), &response_nonce_size, false);
    if (rc) goto put_ops;

    if (require_bytes(response_len, offset, sizeof(response_attrs))) {
        rc = -EIO;
        goto put_ops;
    }
    response_attrs = buf.data[offset++];

    rc = copy_tpm2b(&buf, response_len, &offset, response_hmac,
                    sizeof(response_hmac), &response_hmac_size, false);
    if (rc) goto put_ops;

    if (response_hmac_size != sizeof(response_hmac)) {
        rc = -EIO;
        goto put_ops;
    }

    if (offset != response_len) {
        rc = -EIO;
        goto put_ops;
    }

    sha256_init(&hash_ctx);
    sha256_u32_update(&hash_ctx, TPM2_RC_SUCCESS);
    sha256_u32_update(&hash_ctx, TPM2_CC_RSA_DECRYPT);
    sha256_update(&hash_ctx, &buf.data[parameter_start], parameter_size);
    sha256_final(&hash_ctx, rp_hash);

    hmac_sha256_4(key_auth, key_auth_size,
                  rp_hash, sizeof(rp_hash),
                  response_nonce, response_nonce_size,
                  nonce_caller, sizeof(nonce_caller),
                  &response_attrs, sizeof(response_attrs),
                  expected_response_hmac);

    if (crypto_memneq(response_hmac, expected_response_hmac,
                      sizeof(response_hmac))) {
        rc = -EIO;
        goto put_ops;
    }

    rc = 0;
put_ops:
    tpm_put_ops(chip);
out:
    memzero_explicit(cp_hash, sizeof(cp_hash));
    memzero_explicit(rp_hash, sizeof(rp_hash));
    memzero_explicit(hmac, sizeof(hmac));
    memzero_explicit(response_hmac, sizeof(response_hmac));
    memzero_explicit(expected_response_hmac, sizeof(expected_response_hmac));
    memzero_explicit(nonce_caller, sizeof(nonce_caller));
    memzero_explicit(response_nonce, sizeof(response_nonce));
    tpm_buf_destroy(&buf);
    return rc;
}
