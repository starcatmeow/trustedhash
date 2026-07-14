use crate::config::Config;
use crate::crypto::{
    verify_certify_signature, verify_ek_certificate, verify_tpm_rsassa_sha256_signature,
};
use crate::pcr::{check_pcr_digest_baseline, compute_policy_digest};
use crate::tpm::{
    parse_certify_creation_attest, parse_rsa_tpm2b_public, tpm_name_from_public, RsaPublicInfo,
    TPMA_OBJECT_DECRYPT, TPMA_OBJECT_FIXED_PARENT, TPMA_OBJECT_FIXED_TPM, TPMA_OBJECT_NO_DA,
    TPMA_OBJECT_RESTRICTED, TPMA_OBJECT_SENSITIVE_DATA_ORIGIN, TPMA_OBJECT_SIGN_ENCRYPT,
    TPMA_OBJECT_USER_WITH_AUTH, TPM_ALG_NULL, TPM_ALG_OAEP, TPM_ALG_RSASSA, TPM_ALG_SHA256,
    TPM_RSA_DEFAULT_EXPONENT, TPM_RSA_KEY_BITS, TPM_RSA_MODULUS_SIZE,
};
use crate::Result;
use trusted_hash_common::{module_signer_transcript, CreateSessionResponse};

pub(crate) fn verify_create_session_attestation(
    create: &CreateSessionResponse,
    challenge: &[u8],
    config: &Config,
) -> Result<()> {
    verify_pcr_claims(create, config)?;
    verify_ek_claims(create, config)?;
    verify_ak_name_binding(create)?;
    verify_certified_decrypt_key(create, challenge)?;
    verify_module_signer(create, challenge, config)?;
    Ok(())
}

fn verify_pcr_claims(create: &CreateSessionResponse, config: &Config) -> Result<()> {
    if create.pcr_mask != config.pcr_mask {
        return Err(format!(
            "A returned PCR mask 0x{:08x}, expected 0x{:08x}",
            create.pcr_mask, config.pcr_mask
        )
        .into());
    }
    if create.pcr_digest.len() != 32 {
        return Err(format!("unexpected PCR digest size {}", create.pcr_digest.len()).into());
    }
    check_pcr_digest_baseline(
        &create.pcr_digest,
        config.expected_pcr_digest.as_deref(),
        config.allow_current_pcr_digest,
    )?;
    if create.policy_digest.len() != 32 {
        return Err(format!(
            "unexpected policy digest size {}",
            create.policy_digest.len()
        )
        .into());
    }
    let expected_policy_digest = compute_policy_digest(create.pcr_mask, &create.pcr_digest)?;
    if create.policy_digest != expected_policy_digest {
        return Err("returned policy digest does not match B-side PCR policy computation".into());
    }
    Ok(())
}

fn verify_ek_claims(create: &CreateSessionResponse, config: &Config) -> Result<()> {
    let root_ca = config
        .ek_root_ca
        .as_ref()
        .ok_or("EK root CA is required; use --ek-root-ca")?;
    verify_ek_certificate(create, root_ca, config.ek_issuer.as_ref())
}

fn verify_ak_name_binding(create: &CreateSessionResponse) -> Result<()> {
    let ak_public = parse_rsa_tpm2b_public(&create.ak_public, "AK public")?;
    verify_ak_public(&ak_public)?;
    let ak_name = tpm_name_from_public(&create.ak_public, "AK public")?;
    if ak_name != create.ak_name {
        return Err("AK public area does not match returned AK name".into());
    }
    Ok(())
}

fn verify_ak_attributes(attributes: u32) -> Result<()> {
    let required = TPMA_OBJECT_FIXED_TPM
        | TPMA_OBJECT_FIXED_PARENT
        | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
        | TPMA_OBJECT_USER_WITH_AUTH
        | TPMA_OBJECT_RESTRICTED
        | TPMA_OBJECT_SIGN_ENCRYPT;
    if attributes & required != required {
        return Err(format!(
            "AK is missing required attributes: attrs=0x{attributes:08x}, required=0x{required:08x}"
        )
        .into());
    }
    if attributes & TPMA_OBJECT_DECRYPT != 0 {
        return Err(format!("AK has forbidden decrypt attribute: attrs=0x{attributes:08x}").into());
    }
    Ok(())
}

fn verify_ak_public(public: &RsaPublicInfo<'_>) -> Result<()> {
    if public.name_alg != TPM_ALG_SHA256 {
        return Err(format!("AK uses unsupported nameAlg 0x{:04x}", public.name_alg).into());
    }
    verify_ak_attributes(public.object_attributes)?;
    if !public.auth_policy.is_empty() {
        return Err("AK authPolicy must be empty".into());
    }
    if public.symmetric_alg != TPM_ALG_NULL {
        return Err(format!(
            "AK uses unexpected symmetric algorithm 0x{:04x}",
            public.symmetric_alg
        )
        .into());
    }
    if public.rsa_scheme != TPM_ALG_RSASSA || public.rsa_scheme_hash != Some(TPM_ALG_SHA256) {
        return Err(format!(
            "AK uses unexpected RSA scheme 0x{:04x}/{:?}",
            public.rsa_scheme, public.rsa_scheme_hash
        )
        .into());
    }
    verify_rsa_key_material(public, "AK")
}

fn verify_certified_decrypt_key(create: &CreateSessionResponse, challenge: &[u8]) -> Result<()> {
    let decrypt_public = parse_rsa_tpm2b_public(&create.decrypt_key_public, "decrypt key public")?;
    verify_decrypt_key_public(&decrypt_public, &create.policy_digest)?;
    verify_decrypt_key_name_binding(&create.decrypt_key_public, &create.decrypt_key_name)?;

    let attest =
        parse_certify_creation_attest(&create.certify_info, challenge, &create.decrypt_key_name)?;
    verify_certify_signature(&create.ak_public, attest, &create.certify_signature)?;
    Ok(())
}

fn verify_module_signer(
    create: &CreateSessionResponse,
    challenge: &[u8],
    config: &Config,
) -> Result<()> {
    let signer_public =
        parse_rsa_tpm2b_public(&create.module_signer_public, "module signer public")?;
    verify_module_signer_public(&signer_public)?;

    let public_name = tpm_name_from_public(&create.module_signer_public, "module signer public")?;
    if public_name != create.module_signer_name {
        return Err("module signer public area does not match returned module signer name".into());
    }

    let expected_name = config
        .expected_module_signer_name
        .as_ref()
        .ok_or("module signer baseline is required; use --expected-module-signer-name or --learn-pcr-digest")?;
    if &create.module_signer_name != expected_name {
        return Err("module signer name does not match configured baseline".into());
    }

    let transcript = module_signer_transcript(create, challenge);
    verify_tpm_rsassa_sha256_signature(
        &create.module_signer_public,
        &transcript,
        &create.module_signature,
        "module signer",
    )
}

fn verify_module_signer_public(public: &RsaPublicInfo<'_>) -> Result<()> {
    if public.name_alg != TPM_ALG_SHA256 {
        return Err(format!(
            "module signer uses unsupported nameAlg 0x{:04x}",
            public.name_alg
        )
        .into());
    }
    let expected = TPMA_OBJECT_FIXED_TPM
        | TPMA_OBJECT_FIXED_PARENT
        | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
        | TPMA_OBJECT_USER_WITH_AUTH
        | TPMA_OBJECT_SIGN_ENCRYPT;
    if public.object_attributes != expected {
        return Err(format!(
            "module signer attributes do not match kernel template: attrs=0x{:08x}, expected=0x{expected:08x}",
            public.object_attributes
        )
        .into());
    }
    if !public.auth_policy.is_empty() {
        return Err("module signer authPolicy must be empty".into());
    }
    if public.symmetric_alg != TPM_ALG_NULL {
        return Err(format!(
            "module signer uses unexpected symmetric algorithm 0x{:04x}",
            public.symmetric_alg
        )
        .into());
    }
    if public.rsa_scheme != TPM_ALG_RSASSA || public.rsa_scheme_hash != Some(TPM_ALG_SHA256) {
        return Err(format!(
            "module signer uses unexpected RSA scheme 0x{:04x}/{:?}",
            public.rsa_scheme, public.rsa_scheme_hash
        )
        .into());
    }
    verify_rsa_key_material(public, "module signer")
}

fn verify_decrypt_key_attributes(attributes: u32) -> Result<()> {
    let expected = TPMA_OBJECT_FIXED_TPM
        | TPMA_OBJECT_FIXED_PARENT
        | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
        | TPMA_OBJECT_NO_DA
        | TPMA_OBJECT_DECRYPT;
    if attributes != expected {
        return Err(format!(
            "decrypt key attributes do not match kernel template: attrs=0x{attributes:08x}, expected=0x{expected:08x}"
        )
        .into());
    }
    Ok(())
}

fn verify_decrypt_key_public(
    public: &RsaPublicInfo<'_>,
    expected_policy_digest: &[u8],
) -> Result<()> {
    if public.name_alg != TPM_ALG_SHA256 {
        return Err(format!(
            "decrypt key uses unsupported nameAlg 0x{:04x}",
            public.name_alg
        )
        .into());
    }
    verify_decrypt_key_attributes(public.object_attributes)?;
    if public.auth_policy != expected_policy_digest {
        return Err("decrypt key authPolicy does not match returned PCR policy digest".into());
    }
    if public.symmetric_alg != TPM_ALG_NULL {
        return Err(format!(
            "decrypt key uses unexpected symmetric algorithm 0x{:04x}",
            public.symmetric_alg
        )
        .into());
    }
    if public.rsa_scheme != TPM_ALG_OAEP || public.rsa_scheme_hash != Some(TPM_ALG_SHA256) {
        return Err(format!(
            "decrypt key uses unexpected RSA scheme 0x{:04x}/{:?}",
            public.rsa_scheme, public.rsa_scheme_hash
        )
        .into());
    }
    verify_rsa_key_material(public, "decrypt key")
}

fn verify_rsa_key_material(public: &RsaPublicInfo<'_>, label: &str) -> Result<()> {
    if public.key_bits != TPM_RSA_KEY_BITS {
        return Err(format!("{label} uses {} RSA bits", public.key_bits).into());
    }
    if public.exponent != TPM_RSA_DEFAULT_EXPONENT {
        return Err(format!("{label} uses exponent {}", public.exponent).into());
    }
    if public.modulus.len() != TPM_RSA_MODULUS_SIZE {
        return Err(format!(
            "{label} modulus has {} bytes, expected {}",
            public.modulus.len(),
            TPM_RSA_MODULUS_SIZE
        )
        .into());
    }
    Ok(())
}

fn verify_decrypt_key_name_binding(
    decrypt_key_public: &[u8],
    certified_decrypt_key_name: &[u8],
) -> Result<()> {
    let public_name = tpm_name_from_public(decrypt_key_public, "decrypt key public")?;
    if public_name != certified_decrypt_key_name {
        return Err("decrypt key public area does not match certified decrypt key name".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RunMode};
    use crate::tpm::TPM_ALG_RSA;
    use std::path::PathBuf;

    #[test]
    fn ak_public_must_be_restricted_attestation_key() {
        let attrs = TPMA_OBJECT_FIXED_TPM
            | TPMA_OBJECT_FIXED_PARENT
            | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
            | TPMA_OBJECT_USER_WITH_AUTH
            | TPMA_OBJECT_SIGN_ENCRYPT;
        let ak_public = fake_rsa_public(attrs, &[], TPM_ALG_NULL, TPM_ALG_RSASSA, 0x11);
        let mut create = fake_create_response_with_ak(ak_public);

        let err = verify_ak_name_binding(&create)
            .expect_err("ordinary non-restricted signing key must be rejected as an AK");
        assert!(err
            .to_string()
            .contains("AK is missing required attributes"));

        create.ak_public = fake_decrypt_public(&[0x41; 32], 0x22);
        create.ak_name = tpm_name_from_public(&create.ak_public, "AK public").unwrap();
        let err = verify_ak_name_binding(&create)
            .expect_err("decrypt-capable key must be rejected as an AK");
        assert!(err
            .to_string()
            .contains("AK is missing required attributes"));
    }

    #[test]
    fn restricted_ak_public_is_accepted() {
        let attrs = TPMA_OBJECT_FIXED_TPM
            | TPMA_OBJECT_FIXED_PARENT
            | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
            | TPMA_OBJECT_USER_WITH_AUTH
            | TPMA_OBJECT_RESTRICTED
            | TPMA_OBJECT_SIGN_ENCRYPT;
        let ak_public = fake_rsa_public(attrs, &[], TPM_ALG_NULL, TPM_ALG_RSASSA, 0x11);
        let create = fake_create_response_with_ak(ak_public);

        verify_ak_name_binding(&create).unwrap();
    }

    #[test]
    fn decrypt_public_name_must_match_certified_name() {
        let policy = [0x41; 32];
        let certified_public = fake_decrypt_public(&policy, 0x11);
        let substituted_public = fake_decrypt_public(&policy, 0x22);

        let certified_name = tpm_name_from_public(&certified_public, "certified public").unwrap();
        let substituted_name =
            tpm_name_from_public(&substituted_public, "substituted public").unwrap();
        assert_ne!(certified_name, substituted_name);

        let substituted = parse_rsa_tpm2b_public(&substituted_public, "substituted public")
            .expect("substituted public parses");
        verify_decrypt_key_public(&substituted, &policy).unwrap();
        let err = verify_decrypt_key_name_binding(&substituted_public, &certified_name)
            .expect_err("substituted public must not match certified name");
        assert!(err
            .to_string()
            .contains("decrypt key public area does not match certified decrypt key name"));
    }

    #[test]
    fn decrypt_key_must_not_allow_user_auth() {
        let policy = [0x41; 32];
        let attrs = TPMA_OBJECT_FIXED_TPM
            | TPMA_OBJECT_FIXED_PARENT
            | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
            | TPMA_OBJECT_NO_DA
            | TPMA_OBJECT_USER_WITH_AUTH
            | TPMA_OBJECT_DECRYPT;
        let public = fake_rsa_public(attrs, &policy, TPM_ALG_NULL, TPM_ALG_OAEP, 0x11);
        let parsed = parse_rsa_tpm2b_public(&public, "decrypt key public").unwrap();

        let err = verify_decrypt_key_public(&parsed, &policy)
            .expect_err("decrypt key with userWithAuth must be rejected");
        assert!(err
            .to_string()
            .contains("decrypt key attributes do not match kernel template"));
    }

    #[test]
    fn kernel_template_decrypt_key_is_accepted() {
        let policy = [0x41; 32];
        let public = fake_decrypt_public(&policy, 0x11);
        let parsed = parse_rsa_tpm2b_public(&public, "decrypt key public").unwrap();

        verify_decrypt_key_public(&parsed, &policy).unwrap();
    }

    #[test]
    fn module_signer_baseline_is_required() {
        let mut create = fake_create_response_with_ak(fake_module_signer_public(0x33));
        create.module_signer_public = fake_module_signer_public(0x44);
        create.module_signer_name =
            tpm_name_from_public(&create.module_signer_public, "module signer public").unwrap();

        let err = verify_module_signer(&create, &[0u8; 32], &fake_config(None))
            .expect_err("module signer baseline must be configured");
        assert!(err
            .to_string()
            .contains("module signer baseline is required"));
    }

    #[test]
    fn module_signer_name_must_match_baseline() {
        let mut create = fake_create_response_with_ak(fake_module_signer_public(0x33));
        create.module_signer_public = fake_module_signer_public(0x44);
        create.module_signer_name =
            tpm_name_from_public(&create.module_signer_public, "module signer public").unwrap();

        let err = verify_module_signer(&create, &[0u8; 32], &fake_config(Some(vec![0x41; 34])))
            .expect_err("wrong module signer baseline must be rejected");
        assert!(err
            .to_string()
            .contains("module signer name does not match configured baseline"));
    }

    fn fake_decrypt_public(auth_policy: &[u8; 32], modulus_byte: u8) -> Vec<u8> {
        let attrs = TPMA_OBJECT_FIXED_TPM
            | TPMA_OBJECT_FIXED_PARENT
            | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
            | TPMA_OBJECT_NO_DA
            | TPMA_OBJECT_DECRYPT;
        fake_rsa_public(attrs, auth_policy, TPM_ALG_NULL, TPM_ALG_OAEP, modulus_byte)
    }

    fn fake_module_signer_public(modulus_byte: u8) -> Vec<u8> {
        let attrs = TPMA_OBJECT_FIXED_TPM
            | TPMA_OBJECT_FIXED_PARENT
            | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
            | TPMA_OBJECT_USER_WITH_AUTH
            | TPMA_OBJECT_SIGN_ENCRYPT;
        fake_rsa_public(attrs, &[], TPM_ALG_NULL, TPM_ALG_RSASSA, modulus_byte)
    }

    fn fake_rsa_public(
        attrs: u32,
        auth_policy: &[u8],
        symmetric_alg: u16,
        rsa_scheme: u16,
        modulus_byte: u8,
    ) -> Vec<u8> {
        let modulus = vec![modulus_byte; TPM_RSA_MODULUS_SIZE];
        let mut area = Vec::new();
        area.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
        area.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        area.extend_from_slice(&attrs.to_be_bytes());
        area.extend_from_slice(&(auth_policy.len() as u16).to_be_bytes());
        area.extend_from_slice(auth_policy);
        area.extend_from_slice(&symmetric_alg.to_be_bytes());
        area.extend_from_slice(&rsa_scheme.to_be_bytes());
        area.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        area.extend_from_slice(&TPM_RSA_KEY_BITS.to_be_bytes());
        area.extend_from_slice(&0u32.to_be_bytes());
        area.extend_from_slice(&(modulus.len() as u16).to_be_bytes());
        area.extend_from_slice(&modulus);

        let mut public = Vec::new();
        public.extend_from_slice(&(area.len() as u16).to_be_bytes());
        public.extend_from_slice(&area);
        public
    }

    fn fake_create_response_with_ak(ak_public: Vec<u8>) -> CreateSessionResponse {
        let ak_name = tpm_name_from_public(&ak_public, "AK public").unwrap();
        CreateSessionResponse {
            session_id: 0,
            pcr_mask: 0,
            ek_cert: Vec::new(),
            ek_public: Vec::new(),
            ak_public,
            ak_name,
            decrypt_key_public: Vec::new(),
            decrypt_key_name: Vec::new(),
            pcr_digest: Vec::new(),
            policy_digest: Vec::new(),
            certify_info: Vec::new(),
            certify_signature: Vec::new(),
            module_signer_public: Vec::new(),
            module_signer_name: Vec::new(),
            module_signature: Vec::new(),
        }
    }

    fn fake_config(expected_module_signer_name: Option<Vec<u8>>) -> Config {
        Config {
            addr: "127.0.0.1:31337".to_string(),
            pcr_profile: "custom".to_string(),
            pcr_mask: 0,
            expected_pcr_digest: None,
            expected_module_signer_name,
            allow_current_pcr_digest: false,
            mode: RunMode::CreateOnly,
            write_pcr_config: None::<PathBuf>,
            ek_root_ca: None::<PathBuf>,
            ek_issuer: None::<PathBuf>,
        }
    }
}
