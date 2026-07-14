use crate::tpm::{TPM2_CC_POLICY_AUTHVALUE, TPM2_CC_POLICY_PCR, TPM_ALG_SHA256};
use crate::util::{hex_lower, openssl_sha256};
use crate::Result;
use trusted_hash_common::DEFAULT_PCR_MASK;

pub(crate) const PCR_MAX: u8 = 23;
pub(crate) const PCR_SELECT_SIZE: usize = 3;
pub(crate) const PCR7_SECURE_BOOT: u8 = 7;
pub(crate) const PCR_PROFILE_HARD: &str = "hard";
pub(crate) const PCR_PROFILE_NO_SECURE_BOOT_CERT: &str = "no-secure-boot-cert";
pub(crate) const PCR_PROFILE_CUSTOM: &str = "custom";

pub(crate) fn compute_policy_digest(pcr_mask: u32, pcr_digest: &[u8]) -> Result<Vec<u8>> {
    let selection = build_pcr_selection(pcr_mask)?;
    let mut pcr_policy_input = Vec::with_capacity(32 + 4 + selection.len() + pcr_digest.len());
    pcr_policy_input.extend_from_slice(&[0u8; 32]);
    pcr_policy_input.extend_from_slice(&TPM2_CC_POLICY_PCR.to_be_bytes());
    pcr_policy_input.extend_from_slice(&selection);
    pcr_policy_input.extend_from_slice(pcr_digest);
    let pcr_policy = openssl_sha256(&pcr_policy_input)?;

    let mut auth_policy_input = Vec::with_capacity(32 + 4);
    auth_policy_input.extend_from_slice(&pcr_policy);
    auth_policy_input.extend_from_slice(&TPM2_CC_POLICY_AUTHVALUE.to_be_bytes());
    openssl_sha256(&auth_policy_input)
}

pub(crate) fn build_pcr_selection(pcr_mask: u32) -> Result<[u8; 10]> {
    if pcr_mask == 0 || (pcr_mask >> (PCR_MAX + 1)) != 0 {
        return Err(format!("invalid PCR mask 0x{pcr_mask:08x}").into());
    }

    let mut selection = [0u8; 10];
    selection[..4].copy_from_slice(&1u32.to_be_bytes());
    selection[4..6].copy_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    selection[6] = PCR_SELECT_SIZE as u8;
    for pcr in 0..=PCR_MAX {
        if pcr_mask & (1u32 << pcr) != 0 {
            let pcr = pcr as usize;
            selection[7 + pcr / 8] |= 1u8 << (pcr % 8);
        }
    }
    Ok(selection)
}

pub(crate) fn check_pcr_digest_baseline(
    reported: &[u8],
    expected: Option<&[u8]>,
    allow_current: bool,
) -> Result<()> {
    if let Some(expected) = expected {
        if expected.len() != 32 {
            return Err(format!("expected PCR digest has invalid size {}", expected.len()).into());
        }
        if reported != expected {
            return Err(format!(
                "PCR digest does not match expected baseline: got {}, expected {}",
                hex_lower(reported),
                hex_lower(expected)
            )
            .into());
        }
        return Ok(());
    }

    if allow_current {
        eprintln!(
            "warning: accepting current PCR digest without a baseline; do not use this in challenge production"
        );
        Ok(())
    } else {
        Err(format!(
            "missing --expected-pcr-digest for PCR baseline enforcement; current digest is {}",
            hex_lower(reported)
        )
        .into())
    }
}

pub(crate) fn resolve_pcr_policy(
    profile: Option<&str>,
    raw_mask: Option<u32>,
) -> Result<(String, u32)> {
    match (profile, raw_mask) {
        (None, None) => Ok((PCR_PROFILE_HARD.to_string(), DEFAULT_PCR_MASK)),
        (Some(PCR_PROFILE_CUSTOM), None) => Err("--pcr-profile custom requires --pcr-mask".into()),
        (Some(PCR_PROFILE_CUSTOM), Some(mask)) => {
            validate_pcr_mask(mask)?;
            Ok((PCR_PROFILE_CUSTOM.to_string(), mask))
        }
        (Some(profile), None) => Ok((profile.to_string(), pcr_profile_mask(profile)?)),
        (Some(profile), Some(mask)) => {
            let expected = pcr_profile_mask(profile)?;
            if mask != expected {
                return Err(format!(
                    "PCR mask 0x{mask:08x} does not match profile {profile} (expected 0x{expected:08x}); use --pcr-profile custom for an explicit custom policy"
                )
                .into());
            }
            Ok((profile.to_string(), mask))
        }
        (None, Some(mask)) => match known_pcr_profile_for_mask(mask) {
            Some(profile) => Ok((profile.to_string(), mask)),
            None => Err(format!(
                "unknown PCR mask 0x{mask:08x}; use --pcr-profile custom --pcr-mask 0x{mask:08x} for an explicit custom policy"
            )
            .into()),
        },
    }
}

fn pcr_profile_mask(profile: &str) -> Result<u32> {
    match profile {
        PCR_PROFILE_HARD => Ok(DEFAULT_PCR_MASK),
        PCR_PROFILE_NO_SECURE_BOOT_CERT => Ok(DEFAULT_PCR_MASK & !(1u32 << PCR7_SECURE_BOOT)),
        _ => Err(format!("unknown PCR profile: {profile}").into()),
    }
}

fn known_pcr_profile_for_mask(mask: u32) -> Option<&'static str> {
    if mask == DEFAULT_PCR_MASK {
        Some(PCR_PROFILE_HARD)
    } else if mask == DEFAULT_PCR_MASK & !(1u32 << PCR7_SECURE_BOOT) {
        Some(PCR_PROFILE_NO_SECURE_BOOT_CERT)
    } else {
        None
    }
}

fn validate_pcr_mask(mask: u32) -> Result<()> {
    build_pcr_selection(mask)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pcr_policy_is_hard_profile() {
        let (profile, mask) = resolve_pcr_policy(None, None).unwrap();
        assert_eq!(profile, PCR_PROFILE_HARD);
        assert_eq!(mask, DEFAULT_PCR_MASK);
    }

    #[test]
    fn secure_boot_cert_profile_drops_pcr7() {
        let (_, mask) = resolve_pcr_policy(Some(PCR_PROFILE_NO_SECURE_BOOT_CERT), None).unwrap();
        assert_eq!(mask, DEFAULT_PCR_MASK & !(1u32 << PCR7_SECURE_BOOT));
        assert_eq!(mask & (1u32 << PCR7_SECURE_BOOT), 0);
    }

    #[test]
    fn raw_unknown_mask_fails_closed() {
        let err = resolve_pcr_policy(None, Some(1u32 << 6)).unwrap_err();
        assert!(err.to_string().contains("unknown PCR mask"));
    }

    #[test]
    fn custom_profile_accepts_explicit_mask() {
        let (profile, mask) =
            resolve_pcr_policy(Some(PCR_PROFILE_CUSTOM), Some(1u32 << 6)).unwrap();
        assert_eq!(profile, PCR_PROFILE_CUSTOM);
        assert_eq!(mask, 1u32 << 6);
    }

    #[test]
    fn named_profile_rejects_mismatched_mask() {
        let err = resolve_pcr_policy(Some(PCR_PROFILE_HARD), Some(1u32 << 6)).unwrap_err();
        assert!(err.to_string().contains("does not match profile hard"));
    }

    #[test]
    fn pcr_digest_baseline_requires_expected_digest_by_default() {
        let err = check_pcr_digest_baseline(&[0x11; 32], None, false).unwrap_err();
        assert!(err.to_string().contains("missing --expected-pcr-digest"));
    }

    #[test]
    fn pcr_digest_baseline_rejects_mismatch() {
        let err = check_pcr_digest_baseline(&[0x11; 32], Some(&[0x22; 32]), false).unwrap_err();
        assert!(err.to_string().contains("does not match expected baseline"));
    }

    #[test]
    fn pcr_digest_baseline_accepts_match() {
        check_pcr_digest_baseline(&[0x11; 32], Some(&[0x11; 32]), false).unwrap();
    }
}
