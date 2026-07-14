use crate::Result;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn parse_u32(value: &str) -> Result<u32> {
    if let Some(hex) = value.strip_prefix("0x") {
        Ok(u32::from_str_radix(hex, 16)?)
    } else {
        Ok(value.parse()?)
    }
}

pub(crate) fn parse_hex(value: &str) -> Result<Vec<u8>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() % 2 != 0 {
        return Err("hex string must have an even number of digits".into());
    }

    let mut out = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex digit: {}", byte as char).into()),
    }
}

pub(crate) fn openssl_sha256(data: &[u8]) -> Result<Vec<u8>> {
    let tmp_dir = temp_work_dir("trusted-hash-sha256")?;
    let input_path = tmp_dir.join("input.bin");
    fs::write(&input_path, data)?;

    let output = Command::new("openssl")
        .arg("dgst")
        .arg("-sha256")
        .arg("-binary")
        .arg(&input_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "openssl sha256 failed: {stderr}; saved input in {}",
            tmp_dir.display()
        )
        .into());
    }

    let digest = output.stdout;
    let _ = fs::remove_dir_all(&tmp_dir);
    if digest.len() != 32 {
        return Err(format!("openssl sha256 returned {} bytes", digest.len()).into());
    }
    Ok(digest)
}

pub(crate) fn temp_work_dir(prefix: &str) -> Result<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let tmp_dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    fs::create_dir(&tmp_dir)?;
    Ok(tmp_dir)
}
