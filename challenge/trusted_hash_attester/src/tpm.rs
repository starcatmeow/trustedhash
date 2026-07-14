use crate::util::openssl_sha256;
use crate::Result;

pub(crate) const TPM_ALG_RSA: u16 = 0x0001;
pub(crate) const TPM_ALG_SHA256: u16 = 0x000b;
pub(crate) const TPM_ALG_NULL: u16 = 0x0010;
pub(crate) const TPM_ALG_RSASSA: u16 = 0x0014;
pub(crate) const TPM_ALG_OAEP: u16 = 0x0017;
pub(crate) const TPMA_OBJECT_FIXED_TPM: u32 = 1 << 1;
pub(crate) const TPMA_OBJECT_FIXED_PARENT: u32 = 1 << 4;
pub(crate) const TPMA_OBJECT_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
pub(crate) const TPMA_OBJECT_USER_WITH_AUTH: u32 = 1 << 6;
pub(crate) const TPMA_OBJECT_NO_DA: u32 = 1 << 10;
pub(crate) const TPMA_OBJECT_RESTRICTED: u32 = 1 << 16;
pub(crate) const TPMA_OBJECT_DECRYPT: u32 = 1 << 17;
pub(crate) const TPMA_OBJECT_SIGN_ENCRYPT: u32 = 1 << 18;
pub(crate) const TPM2_CC_POLICY_AUTHVALUE: u32 = 0x0000_016b;
pub(crate) const TPM2_CC_POLICY_PCR: u32 = 0x0000_017f;
pub(crate) const TPM_GENERATED_VALUE: u32 = 0xff544347;
pub(crate) const TPM_ST_ATTEST_CREATION: u16 = 0x801a;
pub(crate) const TPM_RSA_KEY_BITS: u16 = 2048;
pub(crate) const TPM_RSA_MODULUS_SIZE: usize = 256;
pub(crate) const TPM_RSA_DEFAULT_EXPONENT: u32 = 65537;

pub(crate) struct RsaPublicInfo<'a> {
    pub(crate) public_area: &'a [u8],
    pub(crate) name_alg: u16,
    pub(crate) object_attributes: u32,
    pub(crate) auth_policy: &'a [u8],
    pub(crate) symmetric_alg: u16,
    pub(crate) rsa_scheme: u16,
    pub(crate) rsa_scheme_hash: Option<u16>,
    pub(crate) key_bits: u16,
    pub(crate) modulus: &'a [u8],
    pub(crate) exponent: u32,
}

pub(crate) fn parse_rsa_tpm2b_public<'a>(
    public: &'a [u8],
    label: &'static str,
) -> Result<RsaPublicInfo<'a>> {
    let mut cursor = BytesCursor::new(public);
    let public_size = cursor.take_u16()? as usize;
    let public_start = cursor.offset;
    let public_end = cursor.offset + public_size;
    if public_end != public.len() {
        return Err(format!("{label} has invalid TPM2B_PUBLIC size").into());
    }

    let public_type = cursor.take_u16()?;
    if public_type != TPM_ALG_RSA {
        return Err(format!("{label} is not an RSA TPMT_PUBLIC").into());
    }

    let name_alg = cursor.take_u16()?;
    let object_attributes = cursor.take_u32()?;
    let auth_policy = cursor.take_tpm2b()?;

    let symmetric_alg = cursor.take_u16()?;
    match symmetric_alg {
        0x0006 => {
            let _key_bits = cursor.take_u16()?;
            let _mode = cursor.take_u16()?;
        }
        TPM_ALG_NULL => {}
        alg => return Err(format!("{label} uses unsupported symmetric alg 0x{alg:04x}").into()),
    }

    let rsa_scheme = cursor.take_u16()?;
    let rsa_scheme_hash = match rsa_scheme {
        TPM_ALG_NULL => None,
        _ => Some(cursor.take_u16()?),
    };

    let key_bits = cursor.take_u16()?;
    let exponent = match cursor.take_u32()? {
        0 => TPM_RSA_DEFAULT_EXPONENT,
        value => value,
    };
    let modulus = cursor.take_tpm2b()?;
    cursor.finish_at(public_end)?;

    Ok(RsaPublicInfo {
        public_area: &public[public_start..public_end],
        name_alg,
        object_attributes,
        auth_policy,
        symmetric_alg,
        rsa_scheme,
        rsa_scheme_hash,
        key_bits,
        modulus,
        exponent,
    })
}

pub(crate) fn tpm_name_from_public(public: &[u8], label: &'static str) -> Result<Vec<u8>> {
    let parsed = parse_rsa_tpm2b_public(public, label)?;
    if parsed.name_alg != TPM_ALG_SHA256 {
        return Err(format!("{label} uses unsupported nameAlg 0x{:04x}", parsed.name_alg).into());
    }

    let mut name = TPM_ALG_SHA256.to_be_bytes().to_vec();
    name.extend_from_slice(&openssl_sha256(parsed.public_area)?);
    Ok(name)
}

pub(crate) fn parse_certify_creation_attest<'a>(
    certify_info: &'a [u8],
    challenge: &[u8],
    decrypt_key_name: &[u8],
) -> Result<&'a [u8]> {
    let mut outer = BytesCursor::new(certify_info);
    let attest_size = outer.take_u16()? as usize;
    let attest = outer.take_bytes(attest_size)?;
    outer.finish()?;

    let mut cursor = BytesCursor::new(attest);
    let magic = cursor.take_u32()?;
    if magic != TPM_GENERATED_VALUE {
        return Err(format!("unexpected TPMS_ATTEST magic 0x{magic:08x}").into());
    }
    let attest_type = cursor.take_u16()?;
    if attest_type != TPM_ST_ATTEST_CREATION {
        return Err(format!("unexpected TPMS_ATTEST type 0x{attest_type:04x}").into());
    }

    let _qualified_signer = cursor.take_tpm2b()?;
    let extra_data = cursor.take_tpm2b()?;
    if extra_data != challenge {
        return Err("CertifyCreation extraData does not match attester challenge".into());
    }

    cursor.skip(17)?; /* TPMS_CLOCK_INFO */
    let _firmware_version = cursor.take_u64()?;

    let object_name = cursor.take_tpm2b()?;
    if object_name != decrypt_key_name {
        return Err("CertifyCreation objectName does not match decrypt key name".into());
    }
    let _creation_hash = cursor.take_tpm2b()?;
    cursor.finish()?;

    Ok(attest)
}

pub(crate) fn rsa_public_pem_from_tpm2b_public(public: &[u8]) -> Result<String> {
    let parsed = parse_rsa_tpm2b_public(public, "TPM public")?;

    let rsa_public = der_sequence(&[
        der_integer_positive(parsed.modulus),
        der_integer_positive(&parsed.exponent.to_be_bytes()),
    ]);
    let algorithm = der_sequence(&[der_oid_rsa_encryption(), der_null()]);
    let spki = der_sequence(&[algorithm, der_bit_string(&rsa_public)]);
    Ok(format!(
        "-----BEGIN PUBLIC KEY-----\n{}-----END PUBLIC KEY-----\n",
        pem_base64(&spki)
    ))
}

pub(crate) struct BytesCursor<'a> {
    bytes: &'a [u8],
    pub(crate) offset: usize,
}

impl<'a> BytesCursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn take_u16(&mut self) -> Result<u16> {
        let bytes = self.take_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn take_u32(&mut self) -> Result<u32> {
        let bytes = self.take_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(crate) fn take_u64(&mut self) -> Result<u64> {
        let bytes = self.take_bytes(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(crate) fn take_tpm2b(&mut self) -> Result<&'a [u8]> {
        let size = self.take_u16()? as usize;
        self.take_bytes(size)
    }

    pub(crate) fn take_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.offset + len > self.bytes.len() {
            return Err("short TPM public field".into());
        }
        let out = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(out)
    }

    pub(crate) fn skip(&mut self, len: usize) -> Result<()> {
        self.take_bytes(len).map(|_| ())
    }

    pub(crate) fn finish_at(&self, expected: usize) -> Result<()> {
        if self.offset == expected {
            Ok(())
        } else {
            Err("trailing TPM public bytes".into())
        }
    }

    pub(crate) fn finish(&self) -> Result<()> {
        self.finish_at(self.bytes.len())
    }
}

fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = parts.iter().flatten().copied().collect();
    der_tlv(0x30, &body)
}

fn der_integer_positive(value: &[u8]) -> Vec<u8> {
    let first_non_zero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len().saturating_sub(1));
    let mut body = value[first_non_zero..].to_vec();
    if body.first().copied().unwrap_or(0) & 0x80 != 0 {
        body.insert(0, 0);
    }
    der_tlv(0x02, &body)
}

fn der_oid_rsa_encryption() -> Vec<u8> {
    der_tlv(
        0x06,
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
    )
}

fn der_null() -> Vec<u8> {
    der_tlv(0x05, &[])
}

fn der_bit_string(value: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(value.len() + 1);
    body.push(0);
    body.extend_from_slice(value);
    der_tlv(0x03, &body)
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else {
        let len = (body.len() as u32).to_be_bytes();
        let first = len
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(len.len() - 1);
        out.push(0x80 | (len.len() - first) as u8);
        out.extend_from_slice(&len[first..]);
    }
    out.extend_from_slice(body);
    out
}

fn pem_base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut line_len = 0usize;

    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;
        let chars = [
            TABLE[((n >> 18) & 0x3f) as usize] as char,
            TABLE[((n >> 12) & 0x3f) as usize] as char,
            if chunk.len() > 1 {
                TABLE[((n >> 6) & 0x3f) as usize] as char
            } else {
                '='
            },
            if chunk.len() > 2 {
                TABLE[(n & 0x3f) as usize] as char
            } else {
                '='
            },
        ];
        for ch in chars {
            out.push(ch);
            line_len += 1;
            if line_len == 64 {
                out.push('\n');
                line_len = 0;
            }
        }
    }

    if line_len != 0 {
        out.push('\n');
    }
    out
}
