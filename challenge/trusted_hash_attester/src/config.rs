use crate::pcr::resolve_pcr_policy;
use crate::util::{hex_lower, parse_hex, parse_u32};
use crate::Result;
use std::env;
use std::fs;
use std::path::PathBuf;
use trusted_hash_common::DEFAULT_ATTESTER_ADDR;

const DEV_ESCAPE_ENV: &str = "TRUSTED_HASH_ATTESTER_DEV_ESCAPES";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum RunMode {
    LearnPcrDigest,
    CreateOnly,
    Full,
}

pub(crate) struct Config {
    pub(crate) addr: String,
    pub(crate) pcr_profile: String,
    pub(crate) pcr_mask: u32,
    pub(crate) expected_pcr_digest: Option<Vec<u8>>,
    pub(crate) expected_module_signer_name: Option<Vec<u8>>,
    pub(crate) allow_current_pcr_digest: bool,
    pub(crate) mode: RunMode,
    pub(crate) write_pcr_config: Option<PathBuf>,
    pub(crate) ek_root_ca: Option<PathBuf>,
    pub(crate) ek_issuer: Option<PathBuf>,
}

impl Config {
    pub(crate) fn from_args() -> Result<Self> {
        let args = env::args().skip(1).collect::<Vec<_>>();
        let file_config = match arg_value(&args, "--config")? {
            Some(path) => parse_pcr_config(&fs::read_to_string(path)?)?,
            None => PcrConfig::default(),
        };

        let mut addr = DEFAULT_ATTESTER_ADDR.to_string();
        let mut pcr_profile = file_config.pcr_profile;
        let mut pcr_mask = file_config.pcr_mask;
        let mut expected_pcr_digest = file_config.expected_pcr_digest;
        let mut expected_module_signer_name = file_config.expected_module_signer_name;
        let mut allow_current_pcr_digest = false;
        let mut learn_pcr_digest = false;
        let mut write_pcr_config = None;
        let mut ek_root_ca = None;
        let mut ek_issuer = None;
        let mut create_only = false;

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--config" => {
                    let _ = args.next().ok_or("--config requires a value")?;
                }
                "--addr" => {
                    addr = args.next().ok_or("--addr requires a value")?;
                }
                "--pcr-profile" => {
                    pcr_profile = Some(args.next().ok_or("--pcr-profile requires a value")?);
                }
                "--pcr-mask" => {
                    let value = args.next().ok_or("--pcr-mask requires a value")?;
                    pcr_mask = Some(parse_u32(&value)?);
                }
                "--expected-pcr-digest" => {
                    let value = args
                        .next()
                        .ok_or("--expected-pcr-digest requires a value")?;
                    expected_pcr_digest = Some(parse_expected_pcr_digest(&value)?);
                }
                "--expected-module-signer-name" => {
                    let value = args
                        .next()
                        .ok_or("--expected-module-signer-name requires a value")?;
                    expected_module_signer_name = Some(parse_expected_module_signer_name(&value)?);
                }
                "--allow-current-pcr-digest" => {
                    allow_current_pcr_digest = true;
                }
                "--learn-pcr-digest" => {
                    learn_pcr_digest = true;
                }
                "--write-pcr-config" => {
                    write_pcr_config = Some(PathBuf::from(
                        args.next().ok_or("--write-pcr-config requires a value")?,
                    ));
                }
                "--ek-root-ca" => {
                    ek_root_ca = Some(PathBuf::from(
                        args.next().ok_or("--ek-root-ca requires a value")?,
                    ));
                }
                "--ek-issuer" => {
                    ek_issuer = Some(PathBuf::from(
                        args.next().ok_or("--ek-issuer requires a value")?,
                    ));
                }
                "--create-only" => {
                    create_only = true;
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => return Err(format!("unknown argument: {arg}").into()),
            }
        }

        let dev_escape_env = env::var(DEV_ESCAPE_ENV).ok();
        validate_development_escapes(allow_current_pcr_digest, dev_escape_env.as_deref())?;

        let mode = match (learn_pcr_digest, create_only) {
            (true, true) => {
                return Err("--learn-pcr-digest and --create-only are mutually exclusive".into())
            }
            (true, false) => RunMode::LearnPcrDigest,
            (false, true) => RunMode::CreateOnly,
            (false, false) => RunMode::Full,
        };

        let (pcr_profile, pcr_mask) = resolve_pcr_policy(pcr_profile.as_deref(), pcr_mask)?;
        Ok(Self {
            addr,
            pcr_profile,
            pcr_mask,
            expected_pcr_digest,
            expected_module_signer_name,
            allow_current_pcr_digest,
            mode,
            write_pcr_config,
            ek_root_ca,
            ek_issuer,
        })
    }
}

pub(crate) fn write_pcr_config(
    path: &PathBuf,
    profile: &str,
    digest: &[u8],
    module_signer_name: &[u8],
) -> Result<()> {
    let contents = format!(
        "# trusted-hash attester baseline\npcr_profile={profile}\nexpected_pcr_digest={}\nexpected_module_signer_name={}\n",
        hex_lower(digest),
        hex_lower(module_signer_name)
    );
    fs::write(path, contents)?;
    Ok(())
}

fn validate_development_escapes(
    allow_current_pcr_digest: bool,
    env_value: Option<&str>,
) -> Result<()> {
    if !allow_current_pcr_digest {
        return Ok(());
    }

    if dev_escapes_enabled(env_value) {
        return Ok(());
    }

    Err(format!(
        "--allow-current-pcr-digest requires {DEV_ESCAPE_ENV}=1; this flag is for development smoke tests only"
    )
    .into())
}

fn dev_escapes_enabled(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

#[derive(Debug, Default)]
struct PcrConfig {
    pcr_profile: Option<String>,
    pcr_mask: Option<u32>,
    expected_pcr_digest: Option<Vec<u8>>,
    expected_module_signer_name: Option<Vec<u8>>,
}

fn arg_value(args: &[String], name: &str) -> Result<Option<String>> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == name {
            return Ok(Some(
                iter.next()
                    .ok_or_else(|| format!("{name} requires a value"))?
                    .to_string(),
            ));
        }
    }
    Ok(None)
}

fn parse_pcr_config(contents: &str) -> Result<PcrConfig> {
    let mut config = PcrConfig::default();

    for (line_index, line) in contents.lines().enumerate() {
        let line_number = line_index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid config line {line_number}: missing '='"))?;
        let key = key.trim();
        let value = strip_config_quotes(value.trim());
        match key {
            "pcr_profile" => {
                if config.pcr_profile.is_some() {
                    return Err(format!("duplicate pcr_profile on line {line_number}").into());
                }
                config.pcr_profile = Some(value.to_string());
            }
            "pcr_mask" => {
                if config.pcr_mask.is_some() {
                    return Err(format!("duplicate pcr_mask on line {line_number}").into());
                }
                config.pcr_mask = Some(parse_u32(value)?);
            }
            "expected_pcr_digest" => {
                if config.expected_pcr_digest.is_some() {
                    return Err(
                        format!("duplicate expected_pcr_digest on line {line_number}").into(),
                    );
                }
                config.expected_pcr_digest = Some(parse_expected_pcr_digest(value)?);
            }
            "expected_module_signer_name" => {
                if config.expected_module_signer_name.is_some() {
                    return Err(format!(
                        "duplicate expected_module_signer_name on line {line_number}"
                    )
                    .into());
                }
                config.expected_module_signer_name =
                    Some(parse_expected_module_signer_name(value)?);
            }
            _ => return Err(format!("unknown config key on line {line_number}: {key}").into()),
        }
    }

    Ok(config)
}

fn strip_config_quotes(value: &str) -> &str {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn parse_expected_pcr_digest(value: &str) -> Result<Vec<u8>> {
    let digest = parse_hex(value)?;
    if digest.len() != 32 {
        return Err(format!(
            "--expected-pcr-digest must decode to 32 bytes, got {}",
            digest.len()
        )
        .into());
    }
    Ok(digest)
}

fn parse_expected_module_signer_name(value: &str) -> Result<Vec<u8>> {
    let name = parse_hex(value)?;
    if name.len() != 34 {
        return Err(format!(
            "--expected-module-signer-name must decode to a 34-byte TPM SHA256 Name, got {}",
            name.len()
        )
        .into());
    }
    Ok(name)
}

fn print_help() {
    println!(
        "trusted-hash-attester [--config PATH] [--addr HOST:PORT] [--pcr-profile hard|no-secure-boot-cert|custom] [--pcr-mask MASK] [--expected-pcr-digest HEX] [--expected-module-signer-name HEX] [--learn-pcr-digest|--allow-current-pcr-digest] [--write-pcr-config PATH] [--ek-root-ca PEM] [--ek-issuer PEM] [--create-only]"
    );
    println!("development escape flags require {DEV_ESCAPE_ENV}=1: --allow-current-pcr-digest");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcr::PCR_PROFILE_HARD;

    #[test]
    fn expected_pcr_digest_parses_hex_with_prefix() {
        let digest = parse_expected_pcr_digest(&format!("0x{}", "ab".repeat(32))).unwrap();
        assert_eq!(digest, vec![0xab; 32]);
    }

    #[test]
    fn expected_pcr_digest_rejects_wrong_size() {
        let err = parse_expected_pcr_digest("abcd").unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn expected_module_signer_name_rejects_wrong_size() {
        let err = parse_expected_module_signer_name("abcd").unwrap_err();
        assert!(err.to_string().contains("34-byte"));
    }

    #[test]
    fn pcr_config_parses_profile_digest_and_module_signer_name() {
        let config = parse_pcr_config(&format!(
            "# comment\npcr_profile = \"{}\"\nexpected_pcr_digest = {}\nexpected_module_signer_name = {}\n",
            PCR_PROFILE_HARD,
            "cd".repeat(32),
            "00".to_string() + &"ef".repeat(33)
        ))
        .unwrap();
        assert_eq!(config.pcr_profile.as_deref(), Some(PCR_PROFILE_HARD));
        assert_eq!(config.expected_pcr_digest, Some(vec![0xcd; 32]));
        assert_eq!(
            config.expected_module_signer_name,
            Some({
                let mut name = vec![0x00];
                name.extend(vec![0xef; 33]);
                name
            })
        );
        assert_eq!(config.pcr_mask, None);
    }

    #[test]
    fn pcr_config_rejects_unknown_key() {
        let err = parse_pcr_config("surprise=true\n").unwrap_err();
        assert!(err.to_string().contains("unknown config key"));
    }

    #[test]
    fn development_escapes_require_env_opt_in() {
        let err = validate_development_escapes(true, Some("0")).unwrap_err();
        assert!(err.to_string().contains("--allow-current-pcr-digest"));
    }

    #[test]
    fn development_escapes_accept_explicit_env_opt_in() {
        validate_development_escapes(true, Some("1")).unwrap();
        validate_development_escapes(true, Some("yes")).unwrap();
    }
}
