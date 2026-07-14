use crate::config::{write_pcr_config, Config, RunMode};
use crate::crypto::{encrypt_with_decrypt_key, make_credential};
use crate::util::hex_lower;
use crate::verify::verify_create_session_attestation;
use crate::Result;
use std::env;
use std::net::TcpStream;
use std::time::Duration;
use trusted_hash_common::{
    expect_ok, random_challenge, read_response, write_request, ActivateCredentialRequest,
    CancelSessionRequest, CreateSessionRequest, CreateSessionResponse, Request, Response,
    TrustedHashRequest,
};

const AGENT_IO_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) fn run(config: Config) -> Result<()> {
    let mut stream = TcpStream::connect(&config.addr)?;
    stream.set_read_timeout(Some(AGENT_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(AGENT_IO_TIMEOUT))?;
    let created = CreatedSession::request(&mut stream, &config)?;
    created.print_summary(&config);

    let session_id = created.session_id();
    let result = match config.mode {
        RunMode::LearnPcrDigest => created.learn_pcr_digest(&mut stream, &config),
        RunMode::CreateOnly => created
            .verify(&config)
            .and_then(|attested| attested.cancel(&mut stream)),
        RunMode::Full => created
            .verify(&config)
            .and_then(|attested| attested.activate(&mut stream))
            .and_then(|activated| activated.trusted_hash(&mut stream)),
    };

    if result.is_err() {
        cancel_session_best_effort(&mut stream, session_id);
    }

    result
}

struct CreatedSession {
    challenge: [u8; 32],
    evidence: CreateSessionResponse,
}

struct AttestedSession {
    evidence: CreateSessionResponse,
}

struct ActivatedSession {
    evidence: CreateSessionResponse,
}

impl CreatedSession {
    fn request(stream: &mut TcpStream, config: &Config) -> Result<Self> {
        let challenge = random_challenge()?;
        write_request(
            stream,
            &Request::CreateSession(CreateSessionRequest {
                challenge,
                pcr_mask: config.pcr_mask,
            }),
        )?;

        let evidence = match expect_ok(read_response(stream)?)? {
            Response::CreateSession(resp) => resp,
            _ => return Err("unexpected create_session response type".into()),
        };

        Ok(Self {
            challenge,
            evidence,
        })
    }

    fn session_id(&self) -> u32 {
        self.evidence.session_id
    }

    fn print_summary(&self, config: &Config) {
        let create = &self.evidence;
        println!("session_id={}", create.session_id);
        println!("pcr_profile={}", config.pcr_profile);
        println!("pcr_mask=0x{:08x}", create.pcr_mask);
        println!("ek_cert_size={}", create.ek_cert.len());
        println!("ek_public_size={}", create.ek_public.len());
        println!("ak_public_size={}", create.ak_public.len());
        println!("ak_name_size={}", create.ak_name.len());
        println!(
            "decrypt_key_public_size={}",
            create.decrypt_key_public.len()
        );
        println!("decrypt_key_name_size={}", create.decrypt_key_name.len());
        println!("pcr_digest_size={}", create.pcr_digest.len());
        println!("pcr_digest_hex={}", hex_lower(&create.pcr_digest));
        println!("policy_digest_size={}", create.policy_digest.len());
        println!("policy_digest_hex={}", hex_lower(&create.policy_digest));
        println!("certify_info_size={}", create.certify_info.len());
        println!("certify_signature_size={}", create.certify_signature.len());
        println!(
            "module_signer_public_size={}",
            create.module_signer_public.len()
        );
        println!(
            "module_signer_name_size={}",
            create.module_signer_name.len()
        );
        println!(
            "module_signer_name_hex={}",
            hex_lower(&create.module_signer_name)
        );
        println!("module_signature_size={}", create.module_signature.len());
    }

    fn learn_pcr_digest(self, stream: &mut TcpStream, config: &Config) -> Result<()> {
        println!(
            "expected_pcr_digest_arg=--expected-pcr-digest {}",
            hex_lower(&self.evidence.pcr_digest)
        );
        println!(
            "expected_module_signer_name_arg=--expected-module-signer-name {}",
            hex_lower(&self.evidence.module_signer_name)
        );
        if let Some(path) = &config.write_pcr_config {
            write_pcr_config(
                path,
                &config.pcr_profile,
                &self.evidence.pcr_digest,
                &self.evidence.module_signer_name,
            )?;
            println!("wrote_pcr_config={}", path.display());
        }
        cancel_session(stream, self.evidence.session_id)
    }

    fn verify(self, config: &Config) -> Result<AttestedSession> {
        verify_create_session_attestation(&self.evidence, &self.challenge, config)?;
        Ok(AttestedSession {
            evidence: self.evidence,
        })
    }
}

impl AttestedSession {
    fn cancel(self, stream: &mut TcpStream) -> Result<()> {
        cancel_session(stream, self.evidence.session_id)
    }

    fn activate(self, stream: &mut TcpStream) -> Result<ActivatedSession> {
        let credential_secret = random_challenge()?.to_vec();
        let (credential_blob, secret) = make_credential(
            &self.evidence.ek_public,
            &self.evidence.ak_name,
            &credential_secret,
        )?;
        write_request(
            stream,
            &Request::ActivateCredential(ActivateCredentialRequest {
                session_id: self.evidence.session_id,
                credential_blob,
                secret,
            }),
        )?;

        let activated = match expect_ok(read_response(stream)?)? {
            Response::ActivateCredential(resp) => resp,
            _ => return Err("unexpected activate_credential response type".into()),
        };

        if activated.credential != credential_secret {
            return Err("activate_credential round trip failed".into());
        }

        Ok(ActivatedSession {
            evidence: self.evidence,
        })
    }
}

impl ActivatedSession {
    fn trusted_hash(self, stream: &mut TcpStream) -> Result<()> {
        let flag = env::var("CTF_FLAG").unwrap_or_else(|_| "ctf{local-placeholder}".to_string());
        let encrypted_blob =
            encrypt_with_decrypt_key(&self.evidence.decrypt_key_public, flag.as_bytes())?;
        write_request(
            stream,
            &Request::TrustedHash(TrustedHashRequest {
                session_id: self.evidence.session_id,
                encrypted_blob,
            }),
        )?;

        let hash = match expect_ok(read_response(stream)?)? {
            Response::TrustedHash(resp) => resp,
            _ => return Err("unexpected trusted_hash response type".into()),
        };

        println!("trusted_hash_result={}", hex_lower(&hash.result));
        Ok(())
    }
}

fn cancel_session(stream: &mut TcpStream, session_id: u32) -> Result<()> {
    write_request(
        stream,
        &Request::CancelSession(CancelSessionRequest { session_id }),
    )?;

    match expect_ok(read_response(stream)?)? {
        Response::CancelSession => Ok(()),
        _ => Err("unexpected cancel_session response type".into()),
    }
}

fn cancel_session_best_effort(stream: &mut TcpStream, session_id: u32) {
    if let Err(err) = cancel_session(stream, session_id) {
        eprintln!("warning: failed to cancel session {session_id}: {err}");
    }
}
