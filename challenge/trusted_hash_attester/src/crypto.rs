use crate::tpm::{rsa_public_pem_from_tpm2b_public, BytesCursor, TPM_ALG_RSASSA, TPM_ALG_SHA256};
use crate::util::{hex_lower, temp_work_dir};
use crate::Result;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use trusted_hash_common::CreateSessionResponse;

pub(crate) fn encrypt_with_decrypt_key(public: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let tmp_dir = temp_work_dir("trusted-hash-encrypt")?;

    let public_path = tmp_dir.join("decrypt.pem");
    let plaintext_path = tmp_dir.join("plaintext.bin");
    let ciphertext_path = tmp_dir.join("ciphertext.bin");

    fs::write(&public_path, rsa_public_pem_from_tpm2b_public(public)?)?;
    fs::write(&plaintext_path, plaintext)?;

    let output = Command::new("openssl")
        .arg("pkeyutl")
        .arg("-encrypt")
        .arg("-pubin")
        .arg("-inkey")
        .arg(&public_path)
        .arg("-in")
        .arg(&plaintext_path)
        .arg("-out")
        .arg(&ciphertext_path)
        .arg("-pkeyopt")
        .arg("rsa_padding_mode:oaep")
        .arg("-pkeyopt")
        .arg("rsa_oaep_md:sha256")
        .arg("-pkeyopt")
        .arg("rsa_mgf1_md:sha256")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "openssl pkeyutl failed: {stderr}; saved inputs in {}",
            tmp_dir.display()
        )
        .into());
    }

    let ciphertext = fs::read(&ciphertext_path)?;
    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(ciphertext)
}

pub(crate) fn make_credential(
    ek_public: &[u8],
    ak_name: &[u8],
    credential: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let tmp_dir = temp_work_dir("trusted-hash-makecredential")?;

    let ek_public_path = tmp_dir.join("ek.pem");
    let output_path = tmp_dir.join("credential.blob");

    fs::write(
        &ek_public_path,
        rsa_public_pem_from_tpm2b_public(ek_public)?,
    )?;
    let ak_name_hex = hex_lower(ak_name);

    let mut child = Command::new("tpm2_makecredential")
        .arg("-T")
        .arg("none")
        .arg("-G")
        .arg("rsa")
        .arg("-u")
        .arg(&ek_public_path)
        .arg("-s")
        .arg("-")
        .arg("-n")
        .arg(&ak_name_hex)
        .arg("-o")
        .arg(&output_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    child
        .stdin
        .as_mut()
        .ok_or("failed to open tpm2_makecredential stdin")?
        .write_all(credential)?;

    let output = child.wait_with_output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("tpm2_makecredential failed: {stderr}").into());
    }

    let blob = fs::read(&output_path)?;
    match split_makecredential_blob(&blob) {
        Ok(split) => {
            let _ = fs::remove_dir_all(&tmp_dir);
            Ok(split)
        }
        Err(err) => Err(format!(
            "{err}; saved makecredential output in {}",
            tmp_dir.display()
        )
        .into()),
    }
}

pub(crate) fn verify_ek_certificate(
    create: &CreateSessionResponse,
    root_ca: &PathBuf,
    issuer: Option<&PathBuf>,
) -> Result<()> {
    let tmp_dir = temp_work_dir("trusted-hash-verify-ek")?;
    let ek_cert_path = tmp_dir.join("ek.der");
    let ek_cert_pem_path = tmp_dir.join("ek.pem");
    let cert_public_path = tmp_dir.join("ek-cert.pem");
    let cert_public_der_path = tmp_dir.join("ek-cert.spki.der");
    let tpm_public_path = tmp_dir.join("ek-tpm.pem");
    let tpm_public_der_path = tmp_dir.join("ek-tpm.spki.der");

    fs::write(&ek_cert_path, &create.ek_cert)?;
    let output = Command::new("openssl")
        .arg("x509")
        .arg("-inform")
        .arg("DER")
        .arg("-in")
        .arg(&ek_cert_path)
        .arg("-out")
        .arg(&ek_cert_pem_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to convert EK certificate to PEM: {stderr}; saved inputs in {}",
            tmp_dir.display()
        )
        .into());
    }

    let mut command = Command::new("openssl");
    command.arg("verify").arg("-CAfile").arg(root_ca);
    if let Some(issuer) = issuer {
        command.arg("-untrusted").arg(issuer);
    }
    command.arg(&ek_cert_pem_path);

    let output = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "EK certificate verification failed: {stderr}; saved inputs in {}",
            tmp_dir.display()
        )
        .into());
    }

    let output = Command::new("openssl")
        .arg("x509")
        .arg("-in")
        .arg(&ek_cert_pem_path)
        .arg("-pubkey")
        .arg("-noout")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to extract EK certificate public key: {stderr}; saved inputs in {}",
            tmp_dir.display()
        )
        .into());
    }
    fs::write(&cert_public_path, &output.stdout)?;
    fs::write(
        &tpm_public_path,
        rsa_public_pem_from_tpm2b_public(&create.ek_public)?,
    )?;
    openssl_public_key_der(&cert_public_path, &cert_public_der_path, &tmp_dir)?;
    openssl_public_key_der(&tpm_public_path, &tpm_public_der_path, &tmp_dir)?;

    let cert_public_der = fs::read(&cert_public_der_path)?;
    let tpm_public_der = fs::read(&tpm_public_der_path)?;
    if cert_public_der != tpm_public_der {
        return Err(format!(
            "EK certificate public key does not match TPM EK public area; saved inputs in {}",
            tmp_dir.display()
        )
        .into());
    }

    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(())
}

pub(crate) fn verify_certify_signature(
    ak_public: &[u8],
    attest: &[u8],
    certify_signature: &[u8],
) -> Result<()> {
    verify_tpm_rsassa_sha256_signature(ak_public, attest, certify_signature, "certify")
}

pub(crate) fn verify_tpm_rsassa_sha256_signature(
    public: &[u8],
    message: &[u8],
    signature: &[u8],
    label: &str,
) -> Result<()> {
    let mut cursor = BytesCursor::new(signature);
    let sig_alg = cursor.take_u16()?;
    if sig_alg != TPM_ALG_RSASSA {
        return Err(format!("unsupported {label} signature algorithm 0x{sig_alg:04x}").into());
    }
    let hash_alg = cursor.take_u16()?;
    if hash_alg != TPM_ALG_SHA256 {
        return Err(format!("unsupported {label} signature hash 0x{hash_alg:04x}").into());
    }
    let signature = cursor.take_tpm2b()?;
    cursor.finish()?;

    let tmp_dir = temp_work_dir(&format!("trusted-hash-verify-{label}"))?;
    let public_path = tmp_dir.join("public.pem");
    let message_path = tmp_dir.join("message.bin");
    let signature_path = tmp_dir.join("signature.bin");

    fs::write(&public_path, rsa_public_pem_from_tpm2b_public(public)?)?;
    fs::write(&message_path, message)?;
    fs::write(&signature_path, signature)?;

    let output = Command::new("openssl")
        .arg("dgst")
        .arg("-sha256")
        .arg("-verify")
        .arg(&public_path)
        .arg("-signature")
        .arg(&signature_path)
        .arg(&message_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "openssl {label} signature verification failed: {stderr}; saved inputs in {}",
            tmp_dir.display()
        )
        .into());
    }

    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(())
}

fn openssl_public_key_der(
    public_pem: &PathBuf,
    public_der: &PathBuf,
    tmp_dir: &PathBuf,
) -> Result<()> {
    let output = Command::new("openssl")
        .arg("pkey")
        .arg("-pubin")
        .arg("-in")
        .arg(public_pem)
        .arg("-outform")
        .arg("DER")
        .arg("-out")
        .arg(public_der)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "failed to canonicalize public key: {stderr}; saved inputs in {}",
            tmp_dir.display()
        )
        .into());
    }
    Ok(())
}

fn split_makecredential_blob(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let blob = strip_tss2_private_header(blob)?;
    if blob.len() < 2 {
        return Err(format!("makecredential output is too short ({})", blob.len()).into());
    }

    let credential_size = u16::from_be_bytes([blob[0], blob[1]]) as usize;
    let credential_end = credential_size + 2;
    if credential_end > blob.len() || blob.len() < credential_end + 2 {
        return Err(format!(
            "makecredential output has invalid TPM2B_ID_OBJECT size: len={}, first16={}",
            blob.len(),
            hex_lower(&blob[..blob.len().min(16)])
        )
        .into());
    }

    let secret_size = u16::from_be_bytes([blob[credential_end], blob[credential_end + 1]]) as usize;
    let secret_end = credential_end + 2 + secret_size;
    if secret_end != blob.len() {
        return Err(format!(
            "makecredential output has trailing or truncated encrypted secret: len={}, credential_size={}, secret_size={}, first16={}",
            blob.len(),
            credential_size,
            secret_size,
            hex_lower(&blob[..blob.len().min(16)])
        )
        .into());
    }

    Ok((
        blob[..credential_end].to_vec(),
        blob[credential_end..secret_end].to_vec(),
    ))
}

fn strip_tss2_private_header(blob: &[u8]) -> Result<&[u8]> {
    const TSS2_PRIVATE_MAGIC: &[u8; 4] = &[0xba, 0xdc, 0xc0, 0xde];
    const TSS2_PRIVATE_VERSION_1: &[u8; 4] = &[0, 0, 0, 1];

    if blob.len() >= 8 && &blob[..4] == TSS2_PRIVATE_MAGIC && &blob[4..8] == TSS2_PRIVATE_VERSION_1
    {
        Ok(&blob[8..])
    } else if blob.starts_with(TSS2_PRIVATE_MAGIC) {
        Err(format!(
            "unsupported tpm2-tools private blob header: first8={}",
            hex_lower(&blob[..blob.len().min(8)])
        )
        .into())
    } else {
        Ok(blob)
    }
}
