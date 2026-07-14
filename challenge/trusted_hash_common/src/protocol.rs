use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};

pub const DEFAULT_AGENT_ADDR: &str = "0.0.0.0:31337";
pub const DEFAULT_ATTESTER_ADDR: &str = "127.0.0.1:31337";

pub const CHALLENGE_SIZE: usize = 32;
pub const EK_CERT_MAX_SIZE: usize = 2048;
pub const TPM_PUBLIC_MAX_SIZE: usize = 2048;
pub const TPM_NAME_MAX_SIZE: usize = 64;
pub const TPM_ATTEST_MAX_SIZE: usize = 2048;
pub const TPM_SIGNATURE_MAX_SIZE: usize = 2048;
pub const MODULE_SIGNER_PUBLIC_MAX_SIZE: usize = 512;
pub const MODULE_SIGNER_SIGNATURE_MAX_SIZE: usize = 512;
pub const CREDENTIAL_BLOB_MAX_SIZE: usize = 1024;
pub const SECRET_MAX_SIZE: usize = 1024;
pub const CREDENTIAL_MAX_SIZE: usize = 1024;
pub const ENCRYPTED_BLOB_MAX_SIZE: usize = 4096;
pub const TRUSTED_HASH_RESULT_SIZE: usize = 32;
pub const MAX_FRAME_SIZE: usize = 64 * 1024;
pub const ERROR_MESSAGE_MAX_SIZE: usize = 4096;
pub const ROOT_PASSWORD_MAX_SIZE: usize = 256;
pub const MODULE_SIGNER_TRANSCRIPT_LABEL: &[u8] = b"trusted_hash_module_signer_v1";

pub const MODULE_SIGNER_PCR: u32 = 14;

pub const DEFAULT_PCR_MASK: u32 =
    (1 << 0) | (1 << 2) | (1 << 4) | (1 << 7) | (1 << 11) | (1 << MODULE_SIGNER_PCR);
pub const MODULE_SIGNER_PCR_MASK: u32 = DEFAULT_PCR_MASK;

#[derive(Debug, Clone)]
pub struct CreateSessionRequest {
    pub challenge: [u8; CHALLENGE_SIZE],
    pub pcr_mask: u32,
}

#[derive(Debug, Clone)]
pub struct CreateSessionResponse {
    pub session_id: u32,
    pub pcr_mask: u32,
    pub ek_cert: Vec<u8>,
    pub ek_public: Vec<u8>,
    pub ak_public: Vec<u8>,
    pub ak_name: Vec<u8>,
    pub decrypt_key_public: Vec<u8>,
    pub decrypt_key_name: Vec<u8>,
    pub pcr_digest: Vec<u8>,
    pub policy_digest: Vec<u8>,
    pub certify_info: Vec<u8>,
    pub certify_signature: Vec<u8>,
    pub module_signer_public: Vec<u8>,
    pub module_signer_name: Vec<u8>,
    pub module_signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ActivateCredentialRequest {
    pub session_id: u32,
    pub credential_blob: Vec<u8>,
    pub secret: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ActivateCredentialResponse {
    pub credential: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TrustedHashRequest {
    pub session_id: u32,
    pub encrypted_blob: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TrustedHashResponse {
    pub result: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CancelSessionRequest {
    pub session_id: u32,
}

#[derive(Debug, Clone)]
pub struct SetRootPasswordRequest {
    pub password: String,
}

#[derive(Debug, Clone)]
pub enum Request {
    CreateSession(CreateSessionRequest),
    ActivateCredential(ActivateCredentialRequest),
    TrustedHash(TrustedHashRequest),
    CancelSession(CancelSessionRequest),
    SetRootPassword(SetRootPasswordRequest),
}

#[derive(Debug, Clone)]
pub enum Response {
    CreateSession(CreateSessionResponse),
    ActivateCredential(ActivateCredentialResponse),
    TrustedHash(TrustedHashResponse),
    CancelSession,
    SetRootPassword,
    Error { code: i32, message: String },
}

#[derive(Debug)]
pub enum ProtocolError {
    Io(io::Error),
    InvalidMessage(String),
    MessageTooLarge(usize),
    RemoteError { code: i32, message: String },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::InvalidMessage(msg) => write!(f, "invalid message: {msg}"),
            Self::MessageTooLarge(size) => write!(f, "message too large: {size}"),
            Self::RemoteError { code, message } => write!(f, "remote error {code}: {message}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<io::Error> for ProtocolError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for ProtocolError {
    fn from(err: serde_json::Error) -> Self {
        Self::InvalidMessage(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

pub fn read_request(stream: &mut impl Read) -> Result<Request> {
    let body = read_frame(stream)?;
    decode_request(&body)
}

pub fn write_request(stream: &mut impl Write, req: &Request) -> Result<()> {
    write_frame(stream, &encode_request(req)?)
}

pub fn read_response(stream: &mut impl Read) -> Result<Response> {
    let body = read_frame(stream)?;
    decode_response(&body)
}

pub fn write_response(stream: &mut impl Write, resp: &Response) -> Result<()> {
    write_frame(stream, &encode_response(resp)?)
}

pub fn expect_ok(resp: Response) -> Result<Response> {
    match resp {
        Response::Error { code, message } => Err(ProtocolError::RemoteError { code, message }),
        other => Ok(other),
    }
}

pub fn random_challenge() -> io::Result<[u8; CHALLENGE_SIZE]> {
    let mut challenge = [0; CHALLENGE_SIZE];
    File::open("/dev/urandom")?.read_exact(&mut challenge)?;
    Ok(challenge)
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireRequest {
    CreateSession {
        challenge: String,
        pcr_mask: u32,
    },
    ActivateCredential {
        session_id: u32,
        credential_blob: String,
        secret: String,
    },
    TrustedHash {
        session_id: u32,
        encrypted_blob: String,
    },
    CancelSession {
        session_id: u32,
    },
    SetRootPassword {
        password: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WireResponse {
    CreateSession {
        session_id: u32,
        pcr_mask: u32,
        ek_cert: String,
        ek_public: String,
        ak_public: String,
        ak_name: String,
        decrypt_key_public: String,
        decrypt_key_name: String,
        pcr_digest: String,
        policy_digest: String,
        certify_info: String,
        certify_signature: String,
        module_signer_public: String,
        module_signer_name: String,
        module_signature: String,
    },
    ActivateCredential {
        credential: String,
    },
    TrustedHash {
        result: String,
    },
    CancelSession,
    SetRootPassword,
    Error {
        code: i32,
        message: String,
    },
}

fn encode_request(req: &Request) -> Result<Vec<u8>> {
    let wire = match req {
        Request::CreateSession(req) => WireRequest::CreateSession {
            challenge: encode_bytes(&req.challenge, CHALLENGE_SIZE)?,
            pcr_mask: req.pcr_mask,
        },
        Request::ActivateCredential(req) => WireRequest::ActivateCredential {
            session_id: req.session_id,
            credential_blob: encode_bytes(&req.credential_blob, CREDENTIAL_BLOB_MAX_SIZE)?,
            secret: encode_bytes(&req.secret, SECRET_MAX_SIZE)?,
        },
        Request::TrustedHash(req) => WireRequest::TrustedHash {
            session_id: req.session_id,
            encrypted_blob: encode_bytes(&req.encrypted_blob, ENCRYPTED_BLOB_MAX_SIZE)?,
        },
        Request::CancelSession(req) => WireRequest::CancelSession {
            session_id: req.session_id,
        },
        Request::SetRootPassword(req) => WireRequest::SetRootPassword {
            password: req.password.clone(),
        },
    };
    Ok(serde_json::to_vec(&wire)?)
}

fn decode_request(body: &[u8]) -> Result<Request> {
    match serde_json::from_slice(body)? {
        WireRequest::CreateSession {
            challenge,
            pcr_mask,
        } => Ok(Request::CreateSession(CreateSessionRequest {
            challenge: decode_array(&challenge)?,
            pcr_mask,
        })),
        WireRequest::ActivateCredential {
            session_id,
            credential_blob,
            secret,
        } => Ok(Request::ActivateCredential(ActivateCredentialRequest {
            session_id,
            credential_blob: decode_bytes(&credential_blob, CREDENTIAL_BLOB_MAX_SIZE)?,
            secret: decode_bytes(&secret, SECRET_MAX_SIZE)?,
        })),
        WireRequest::TrustedHash {
            session_id,
            encrypted_blob,
        } => Ok(Request::TrustedHash(TrustedHashRequest {
            session_id,
            encrypted_blob: decode_bytes(&encrypted_blob, ENCRYPTED_BLOB_MAX_SIZE)?,
        })),
        WireRequest::CancelSession { session_id } => {
            Ok(Request::CancelSession(CancelSessionRequest { session_id }))
        }
        WireRequest::SetRootPassword { password } => {
            if password.len() > ROOT_PASSWORD_MAX_SIZE {
                return Err(ProtocolError::MessageTooLarge(password.len()));
            }
            Ok(Request::SetRootPassword(SetRootPasswordRequest {
                password,
            }))
        }
    }
}

fn encode_response(resp: &Response) -> Result<Vec<u8>> {
    let wire = match resp {
        Response::Error { code, message } => {
            if message.len() > ERROR_MESSAGE_MAX_SIZE {
                return Err(ProtocolError::MessageTooLarge(message.len()));
            }
            WireResponse::Error {
                code: *code,
                message: message.clone(),
            }
        }
        Response::CreateSession(resp) => WireResponse::CreateSession {
            session_id: resp.session_id,
            pcr_mask: resp.pcr_mask,
            ek_cert: encode_bytes(&resp.ek_cert, EK_CERT_MAX_SIZE)?,
            ek_public: encode_bytes(&resp.ek_public, TPM_PUBLIC_MAX_SIZE)?,
            ak_public: encode_bytes(&resp.ak_public, TPM_PUBLIC_MAX_SIZE)?,
            ak_name: encode_bytes(&resp.ak_name, TPM_NAME_MAX_SIZE)?,
            decrypt_key_public: encode_bytes(&resp.decrypt_key_public, TPM_PUBLIC_MAX_SIZE)?,
            decrypt_key_name: encode_bytes(&resp.decrypt_key_name, TPM_NAME_MAX_SIZE)?,
            pcr_digest: encode_bytes(&resp.pcr_digest, 32)?,
            policy_digest: encode_bytes(&resp.policy_digest, 32)?,
            certify_info: encode_bytes(&resp.certify_info, TPM_ATTEST_MAX_SIZE)?,
            certify_signature: encode_bytes(&resp.certify_signature, TPM_SIGNATURE_MAX_SIZE)?,
            module_signer_public: encode_bytes(
                &resp.module_signer_public,
                MODULE_SIGNER_PUBLIC_MAX_SIZE,
            )?,
            module_signer_name: encode_bytes(&resp.module_signer_name, TPM_NAME_MAX_SIZE)?,
            module_signature: encode_bytes(
                &resp.module_signature,
                MODULE_SIGNER_SIGNATURE_MAX_SIZE,
            )?,
        },
        Response::ActivateCredential(resp) => WireResponse::ActivateCredential {
            credential: encode_bytes(&resp.credential, CREDENTIAL_MAX_SIZE)?,
        },
        Response::TrustedHash(resp) => WireResponse::TrustedHash {
            result: encode_bytes(&resp.result, TRUSTED_HASH_RESULT_SIZE)?,
        },
        Response::CancelSession => WireResponse::CancelSession,
        Response::SetRootPassword => WireResponse::SetRootPassword,
    };
    Ok(serde_json::to_vec(&wire)?)
}

fn decode_response(body: &[u8]) -> Result<Response> {
    match serde_json::from_slice(body)? {
        WireResponse::Error { code, message } => Ok(Response::Error { code, message }),
        WireResponse::CreateSession {
            session_id,
            pcr_mask,
            ek_cert,
            ek_public,
            ak_public,
            ak_name,
            decrypt_key_public,
            decrypt_key_name,
            pcr_digest,
            policy_digest,
            certify_info,
            certify_signature,
            module_signer_public,
            module_signer_name,
            module_signature,
        } => Ok(Response::CreateSession(CreateSessionResponse {
            session_id,
            pcr_mask,
            ek_cert: decode_bytes(&ek_cert, EK_CERT_MAX_SIZE)?,
            ek_public: decode_bytes(&ek_public, TPM_PUBLIC_MAX_SIZE)?,
            ak_public: decode_bytes(&ak_public, TPM_PUBLIC_MAX_SIZE)?,
            ak_name: decode_bytes(&ak_name, TPM_NAME_MAX_SIZE)?,
            decrypt_key_public: decode_bytes(&decrypt_key_public, TPM_PUBLIC_MAX_SIZE)?,
            decrypt_key_name: decode_bytes(&decrypt_key_name, TPM_NAME_MAX_SIZE)?,
            pcr_digest: decode_bytes(&pcr_digest, 32)?,
            policy_digest: decode_bytes(&policy_digest, 32)?,
            certify_info: decode_bytes(&certify_info, TPM_ATTEST_MAX_SIZE)?,
            certify_signature: decode_bytes(&certify_signature, TPM_SIGNATURE_MAX_SIZE)?,
            module_signer_public: decode_bytes(
                &module_signer_public,
                MODULE_SIGNER_PUBLIC_MAX_SIZE,
            )?,
            module_signer_name: decode_bytes(&module_signer_name, TPM_NAME_MAX_SIZE)?,
            module_signature: decode_bytes(&module_signature, MODULE_SIGNER_SIGNATURE_MAX_SIZE)?,
        })),
        WireResponse::ActivateCredential { credential } => {
            Ok(Response::ActivateCredential(ActivateCredentialResponse {
                credential: decode_bytes(&credential, CREDENTIAL_MAX_SIZE)?,
            }))
        }
        WireResponse::TrustedHash { result } => Ok(Response::TrustedHash(TrustedHashResponse {
            result: decode_array::<TRUSTED_HASH_RESULT_SIZE>(&result)?.to_vec(),
        })),
        WireResponse::CancelSession => Ok(Response::CancelSession),
        WireResponse::SetRootPassword => Ok(Response::SetRootPassword),
    }
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut len_buf = [0; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(ProtocolError::MessageTooLarge(len));
    }
    let mut body = vec![0; len];
    stream.read_exact(&mut body)?;
    Ok(body)
}

fn write_frame(stream: &mut impl Write, body: &[u8]) -> Result<()> {
    if body.len() > MAX_FRAME_SIZE {
        return Err(ProtocolError::MessageTooLarge(body.len()));
    }
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn encode_bytes(bytes: &[u8], max_len: usize) -> Result<String> {
    if bytes.len() > max_len {
        return Err(ProtocolError::MessageTooLarge(bytes.len()));
    }
    Ok(BASE64.encode(bytes))
}

fn decode_bytes(value: &str, max_len: usize) -> Result<Vec<u8>> {
    let bytes = BASE64
        .decode(value)
        .map_err(|err| ProtocolError::InvalidMessage(format!("invalid base64: {err}")))?;
    if bytes.len() > max_len {
        return Err(ProtocolError::InvalidMessage("byte field too large".into()));
    }
    Ok(bytes)
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes = decode_bytes(value, N)?;
    bytes
        .try_into()
        .map_err(|_| ProtocolError::InvalidMessage("fixed byte field has wrong size".into()))
}

pub fn module_signer_transcript(create: &CreateSessionResponse, challenge: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    transcript_field(&mut out, MODULE_SIGNER_TRANSCRIPT_LABEL);
    transcript_field(&mut out, challenge);
    transcript_field(&mut out, &create.pcr_mask.to_be_bytes());
    transcript_field(&mut out, &create.pcr_digest);
    transcript_field(&mut out, &create.policy_digest);
    transcript_field(&mut out, &create.ak_name);
    transcript_field(&mut out, &create.decrypt_key_name);
    transcript_field(&mut out, &create.ak_public);
    transcript_field(&mut out, &create.decrypt_key_public);
    transcript_field(&mut out, &create.certify_info);
    transcript_field(&mut out, &create.certify_signature);
    transcript_field(&mut out, &create.module_signer_name);
    out
}

fn transcript_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_session_request_round_trips_as_json() {
        let encoded = encode_request(&Request::CancelSession(CancelSessionRequest {
            session_id: 0x1234_5678,
        }))
        .unwrap();
        assert_eq!(
            std::str::from_utf8(&encoded).unwrap(),
            r#"{"type":"cancel_session","session_id":305419896}"#
        );

        match decode_request(&encoded).unwrap() {
            Request::CancelSession(req) => assert_eq!(req.session_id, 0x1234_5678),
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[test]
    fn binary_fields_are_base64_in_json() {
        let encoded = encode_request(&Request::TrustedHash(TrustedHashRequest {
            session_id: 7,
            encrypted_blob: b"flag ciphertext".to_vec(),
        }))
        .unwrap();
        assert_eq!(
            std::str::from_utf8(&encoded).unwrap(),
            r#"{"type":"trusted_hash","session_id":7,"encrypted_blob":"ZmxhZyBjaXBoZXJ0ZXh0"}"#
        );
    }

    #[test]
    fn set_root_password_request_round_trips_as_json() {
        let encoded = encode_request(&Request::SetRootPassword(SetRootPasswordRequest {
            password: "abcd1234".to_string(),
        }))
        .unwrap();
        assert_eq!(
            std::str::from_utf8(&encoded).unwrap(),
            r#"{"type":"set_root_password","password":"abcd1234"}"#
        );

        match decode_request(&encoded).unwrap() {
            Request::SetRootPassword(req) => assert_eq!(req.password, "abcd1234"),
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[test]
    fn cancel_session_response_round_trips() {
        let encoded = encode_response(&Response::CancelSession).unwrap();

        match decode_response(&encoded).unwrap() {
            Response::CancelSession => {}
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn set_root_password_response_round_trips() {
        let encoded = encode_response(&Response::SetRootPassword).unwrap();

        match decode_response(&encoded).unwrap() {
            Response::SetRootPassword => {}
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn read_frame_rejects_oversized_declared_length() {
        let mut frame = &((MAX_FRAME_SIZE as u32 + 1).to_be_bytes())[..];
        match read_frame(&mut frame).unwrap_err() {
            ProtocolError::MessageTooLarge(size) => assert_eq!(size, MAX_FRAME_SIZE + 1),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn write_frame_rejects_oversized_body() {
        let body = vec![0u8; MAX_FRAME_SIZE + 1];
        let mut out = Vec::new();
        match write_frame(&mut out, &body).unwrap_err() {
            ProtocolError::MessageTooLarge(size) => assert_eq!(size, MAX_FRAME_SIZE + 1),
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(out.is_empty());
    }

    #[test]
    fn encode_request_rejects_oversized_trusted_hash_blob() {
        let req = Request::TrustedHash(TrustedHashRequest {
            session_id: 7,
            encrypted_blob: vec![0u8; ENCRYPTED_BLOB_MAX_SIZE + 1],
        });

        match encode_request(&req).unwrap_err() {
            ProtocolError::MessageTooLarge(size) => {
                assert_eq!(size, ENCRYPTED_BLOB_MAX_SIZE + 1)
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn encode_response_rejects_oversized_error_message() {
        let resp = Response::Error {
            code: -1,
            message: "x".repeat(ERROR_MESSAGE_MAX_SIZE + 1),
        };

        match encode_response(&resp).unwrap_err() {
            ProtocolError::MessageTooLarge(size) => {
                assert_eq!(size, ERROR_MESSAGE_MAX_SIZE + 1)
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
