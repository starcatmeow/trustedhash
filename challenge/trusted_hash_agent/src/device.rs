use std::fs::File;
use std::io;
use std::mem;
use std::os::fd::AsRawFd;
use trusted_hash_common::{
    ActivateCredentialRequest, ActivateCredentialResponse, CancelSessionRequest,
    CreateSessionRequest, CreateSessionResponse, TrustedHashRequest, TrustedHashResponse,
    CHALLENGE_SIZE, CREDENTIAL_BLOB_MAX_SIZE, CREDENTIAL_MAX_SIZE, EK_CERT_MAX_SIZE,
    ENCRYPTED_BLOB_MAX_SIZE, MODULE_SIGNER_PUBLIC_MAX_SIZE, MODULE_SIGNER_SIGNATURE_MAX_SIZE,
    SECRET_MAX_SIZE, TPM_ATTEST_MAX_SIZE, TPM_NAME_MAX_SIZE, TPM_PUBLIC_MAX_SIZE,
    TPM_SIGNATURE_MAX_SIZE, TRUSTED_HASH_RESULT_SIZE,
};

pub const DEVICE_PATH: &str = "/dev/trusted_hash";

const IOC_MAGIC: u8 = b'R';
const IOC_NRBITS: u64 = 8;
const IOC_TYPEBITS: u64 = 8;
const IOC_SIZEBITS: u64 = 14;
const IOC_NRSHIFT: u64 = 0;
const IOC_TYPESHIFT: u64 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u64 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u64 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_READ: u64 = 2;
const IOC_WRITE: u64 = 1;

#[repr(C, packed)]
#[derive(Clone)]
struct CreateSessionIoctl {
    challenge: [u8; CHALLENGE_SIZE],
    pcr_mask: u32,
    session_id: u32,
    ek_cert_size: u16,
    ek_cert: [u8; EK_CERT_MAX_SIZE],
    ek_public_size: u16,
    ek_public: [u8; TPM_PUBLIC_MAX_SIZE],
    ak_public_size: u16,
    ak_public: [u8; TPM_PUBLIC_MAX_SIZE],
    ak_name_size: u16,
    ak_name: [u8; TPM_NAME_MAX_SIZE],
    decrypt_key_public_size: u16,
    decrypt_key_public: [u8; TPM_PUBLIC_MAX_SIZE],
    decrypt_key_name_size: u16,
    decrypt_key_name: [u8; TPM_NAME_MAX_SIZE],
    pcr_digest_size: u16,
    pcr_digest: [u8; 32],
    policy_digest_size: u16,
    policy_digest: [u8; 32],
    certify_info_size: u16,
    certify_info: [u8; TPM_ATTEST_MAX_SIZE],
    certify_signature_size: u16,
    certify_signature: [u8; TPM_SIGNATURE_MAX_SIZE],
    module_signer_public_size: u16,
    module_signer_public: [u8; MODULE_SIGNER_PUBLIC_MAX_SIZE],
    module_signer_name_size: u16,
    module_signer_name: [u8; TPM_NAME_MAX_SIZE],
    module_signature_size: u16,
    module_signature: [u8; MODULE_SIGNER_SIGNATURE_MAX_SIZE],
}

#[repr(C, packed)]
#[derive(Clone)]
struct ActivateCredentialIoctl {
    session_id: u32,
    credential_blob_size: u16,
    credential_blob: [u8; CREDENTIAL_BLOB_MAX_SIZE],
    secret_size: u16,
    secret: [u8; SECRET_MAX_SIZE],
    credential_size: u16,
    credential: [u8; CREDENTIAL_MAX_SIZE],
}

#[repr(C, packed)]
#[derive(Clone)]
struct TrustedHashIoctl {
    session_id: u32,
    encrypted_blob_size: u16,
    encrypted_blob: [u8; ENCRYPTED_BLOB_MAX_SIZE],
    result: [u8; TRUSTED_HASH_RESULT_SIZE],
}

#[repr(C, packed)]
#[derive(Clone, Default)]
struct CancelSessionIoctl {
    session_id: u32,
}

macro_rules! impl_zero_default {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl Default for $ty {
                fn default() -> Self {
                    // These are C ioctl payloads made only of integer and byte-array fields.
                    unsafe { mem::zeroed() }
                }
            }
        )+
    };
}

impl_zero_default!(
    CreateSessionIoctl,
    ActivateCredentialIoctl,
    TrustedHashIoctl,
);

pub struct TrustedHashDevice {
    file: File,
}

impl TrustedHashDevice {
    pub fn open(path: &str) -> io::Result<Self> {
        Ok(Self {
            file: File::options().read(true).write(true).open(path)?,
        })
    }

    pub fn create_session(&self, req: CreateSessionRequest) -> io::Result<CreateSessionResponse> {
        let mut ioctl_req = CreateSessionIoctl::default();
        ioctl_req.challenge = req.challenge;
        ioctl_req.pcr_mask = req.pcr_mask;
        unsafe_ioctl(
            self.file.as_raw_fd(),
            ioctl_create_session(),
            &mut ioctl_req,
        )?;
        create_session_from_ioctl(&ioctl_req)
    }

    pub fn activate_credential(
        &self,
        req: ActivateCredentialRequest,
    ) -> io::Result<ActivateCredentialResponse> {
        if req.credential_blob.len() > CREDENTIAL_BLOB_MAX_SIZE
            || req.secret.len() > SECRET_MAX_SIZE
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "activate request too large",
            ));
        }

        let mut ioctl_req = ActivateCredentialIoctl::default();
        ioctl_req.session_id = req.session_id;
        ioctl_req.credential_blob_size = req.credential_blob.len() as u16;
        ioctl_req.credential_blob[..req.credential_blob.len()]
            .copy_from_slice(&req.credential_blob);
        ioctl_req.secret_size = req.secret.len() as u16;
        ioctl_req.secret[..req.secret.len()].copy_from_slice(&req.secret);
        unsafe_ioctl(
            self.file.as_raw_fd(),
            ioctl_activate_credential(),
            &mut ioctl_req,
        )?;

        let credential = slice_field_checked(
            &ioctl_req.credential,
            ioctl_req.credential_size,
            "credential",
        )?;
        Ok(ActivateCredentialResponse { credential })
    }

    pub fn trusted_hash(&self, req: TrustedHashRequest) -> io::Result<TrustedHashResponse> {
        if req.encrypted_blob.len() > ENCRYPTED_BLOB_MAX_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "encrypted blob too large",
            ));
        }

        let mut ioctl_req = TrustedHashIoctl::default();
        ioctl_req.session_id = req.session_id;
        ioctl_req.encrypted_blob_size = req.encrypted_blob.len() as u16;
        ioctl_req.encrypted_blob[..req.encrypted_blob.len()].copy_from_slice(&req.encrypted_blob);
        unsafe_ioctl(self.file.as_raw_fd(), ioctl_trusted_hash(), &mut ioctl_req)?;

        Ok(TrustedHashResponse {
            result: ioctl_req.result.to_vec(),
        })
    }

    pub fn cancel_session(&self, req: CancelSessionRequest) -> io::Result<()> {
        let mut ioctl_req = CancelSessionIoctl {
            session_id: req.session_id,
        };
        unsafe_ioctl(
            self.file.as_raw_fd(),
            ioctl_cancel_session(),
            &mut ioctl_req,
        )
    }
}

fn create_session_from_ioctl(req: &CreateSessionIoctl) -> io::Result<CreateSessionResponse> {
    Ok(CreateSessionResponse {
        session_id: req.session_id,
        pcr_mask: req.pcr_mask,
        ek_cert: slice_field_checked(&req.ek_cert, req.ek_cert_size, "ek_cert")?,
        ek_public: slice_field_checked(&req.ek_public, req.ek_public_size, "ek_public")?,
        ak_public: slice_field_checked(&req.ak_public, req.ak_public_size, "ak_public")?,
        ak_name: slice_field_checked(&req.ak_name, req.ak_name_size, "ak_name")?,
        decrypt_key_public: slice_field_checked(
            &req.decrypt_key_public,
            req.decrypt_key_public_size,
            "decrypt_key_public",
        )?,
        decrypt_key_name: slice_field_checked(
            &req.decrypt_key_name,
            req.decrypt_key_name_size,
            "decrypt_key_name",
        )?,
        pcr_digest: slice_field_checked(&req.pcr_digest, req.pcr_digest_size, "pcr_digest")?,
        policy_digest: slice_field_checked(
            &req.policy_digest,
            req.policy_digest_size,
            "policy_digest",
        )?,
        certify_info: slice_field_checked(
            &req.certify_info,
            req.certify_info_size,
            "certify_info",
        )?,
        certify_signature: slice_field_checked(
            &req.certify_signature,
            req.certify_signature_size,
            "certify_signature",
        )?,
        module_signer_public: slice_field_checked(
            &req.module_signer_public,
            req.module_signer_public_size,
            "module_signer_public",
        )?,
        module_signer_name: slice_field_checked(
            &req.module_signer_name,
            req.module_signer_name_size,
            "module_signer_name",
        )?,
        module_signature: slice_field_checked(
            &req.module_signature,
            req.module_signature_size,
            "module_signature",
        )?,
    })
}

fn slice_field_checked<const N: usize>(
    data: &[u8; N],
    size: u16,
    field: &'static str,
) -> io::Result<Vec<u8>> {
    let len = usize::from(size);
    if len > N {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{field} size too large"),
        ));
    }
    Ok(data[..len].to_vec())
}

fn ioctl_create_session() -> u64 {
    iowr(0, mem::size_of::<CreateSessionIoctl>())
}

fn ioctl_activate_credential() -> u64 {
    iowr(1, mem::size_of::<ActivateCredentialIoctl>())
}

fn ioctl_trusted_hash() -> u64 {
    iowr(2, mem::size_of::<TrustedHashIoctl>())
}

fn ioctl_cancel_session() -> u64 {
    iow(3, mem::size_of::<CancelSessionIoctl>())
}

fn iow(nr: u8, size: usize) -> u64 {
    (IOC_WRITE << IOC_DIRSHIFT)
        | ((IOC_MAGIC as u64) << IOC_TYPESHIFT)
        | ((nr as u64) << IOC_NRSHIFT)
        | ((size as u64) << IOC_SIZESHIFT)
}

fn iowr(nr: u8, size: usize) -> u64 {
    ((IOC_READ | IOC_WRITE) << IOC_DIRSHIFT)
        | ((IOC_MAGIC as u64) << IOC_TYPESHIFT)
        | ((nr as u64) << IOC_NRSHIFT)
        | ((size as u64) << IOC_SIZESHIFT)
}

fn unsafe_ioctl<T>(fd: i32, request: u64, data: &mut T) -> io::Result<()> {
    let rc = unsafe { ioctl(fd, request, data as *mut T as *mut std::ffi::c_void) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

extern "C" {
    fn ioctl(fd: i32, request: u64, ...) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_field_checked_rejects_oversized_ioctl_size() {
        let data = [0u8; 4];
        let err = slice_field_checked(&data, 5, "field").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("field size too large"));
    }

    #[test]
    fn create_session_from_ioctl_rejects_oversized_response_size() {
        let mut req = CreateSessionIoctl::default();
        req.ak_name_size = TPM_NAME_MAX_SIZE as u16 + 1;

        let err = create_session_from_ioctl(&req).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("ak_name size too large"));
    }

    #[test]
    fn create_session_ioctl_fits_linux_size_bits() {
        assert!(mem::size_of::<CreateSessionIoctl>() < (1usize << IOC_SIZEBITS));
    }
}
