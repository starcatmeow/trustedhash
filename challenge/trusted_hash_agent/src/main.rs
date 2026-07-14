use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

mod device;

use device::{TrustedHashDevice, DEVICE_PATH};
use trusted_hash_common::{read_request, write_response, Request, Response, DEFAULT_AGENT_ADDR};

const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(15);
const ROOT_PASSWORD_FUSE: &str = "/var/lib/trusted-hash-agent/root-pass-provision-complete";
const ROOT_PASSWORD_STATE_DIR: &str = "/var/lib/trusted-hash-agent";

fn main() -> io::Result<()> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_AGENT_ADDR.to_string());
    let listener = TcpListener::bind(&addr)?;
    let device_lock = Arc::new(Mutex::new(()));
    eprintln!("trusted-hash-agent listening on {addr}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let device_lock = Arc::clone(&device_lock);
                thread::spawn(move || {
                    if let Err(err) = handle_client(stream, device_lock) {
                        eprintln!("client error: {err}");
                    }
                });
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }

    Ok(())
}

fn handle_client(mut stream: TcpStream, device_lock: Arc<Mutex<()>>) -> io::Result<()> {
    stream.set_read_timeout(Some(CLIENT_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CLIENT_IO_TIMEOUT))?;

    loop {
        let request = match read_request(&mut stream) {
            Ok(request) => request,
            Err(err) => {
                if let trusted_hash_common::ProtocolError::Io(io_err) = &err {
                    if io_err.kind() == io::ErrorKind::UnexpectedEof {
                        return Ok(());
                    }
                }
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }
        };

        let dev = match TrustedHashDevice::open(DEVICE_PATH) {
            Ok(dev) => dev,
            Err(err) => {
                write_response(&mut stream, &error_response(err))
                    .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;
                continue;
            }
        };

        let response = {
            let _guard = device_lock
                .lock()
                .map_err(|_| io::Error::other("device lock poisoned"))?;
            dispatch(&dev, request)
        };
        write_response(&mut stream, &response)
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;
    }
}

fn provision_root_password(password: &str) -> io::Result<()> {
    if password.is_empty() || password.contains('\n') || password.contains('\r') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid root password",
        ));
    }
    if fs::metadata(ROOT_PASSWORD_FUSE).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "root password provisioner is fused",
        ));
    }

    let mut child = Command::new("/run/current-system/sw/bin/chpasswd")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::other("failed to open chpasswd stdin"))?;
        writeln!(stdin, "root:{password}")?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "chpasswd failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let mut fuse = fs::File::create(ROOT_PASSWORD_FUSE)?;
    fuse.write_all(b"1\n")?;
    fuse.sync_all()?;
    fs::File::open(ROOT_PASSWORD_STATE_DIR)?.sync_all()?;
    sync_filesystems()?;
    Ok(())
}

fn sync_filesystems() -> io::Result<()> {
    let output = Command::new("/run/current-system/sw/bin/sync")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "sync failed: {}",
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn dispatch(dev: &TrustedHashDevice, request: Request) -> Response {
    match request {
        Request::CreateSession(req) => match dev.create_session(req) {
            Ok(resp) => Response::CreateSession(resp),
            Err(err) => error_response(err),
        },
        Request::ActivateCredential(req) => match dev.activate_credential(req) {
            Ok(resp) => Response::ActivateCredential(resp),
            Err(err) => error_response(err),
        },
        Request::TrustedHash(req) => match dev.trusted_hash(req) {
            Ok(resp) => Response::TrustedHash(resp),
            Err(err) => error_response(err),
        },
        Request::CancelSession(req) => match dev.cancel_session(req) {
            Ok(()) => Response::CancelSession,
            Err(err) => error_response(err),
        },
        Request::SetRootPassword(req) => match provision_root_password(&req.password) {
            Ok(()) => Response::SetRootPassword,
            Err(err) => error_response(err),
        },
    }
}

fn error_response(err: io::Error) -> Response {
    Response::Error {
        code: err.raw_os_error().unwrap_or(-1),
        message: err.to_string(),
    }
}
