use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_tungstenite::connect_async;
use trusted_hash_common::{
    expect_ok, read_response, write_request, Request, SetRootPasswordRequest,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_JS: &str = include_str!("../static/app.js");
const PROFILE_HARD: &str = "hard";
const PROFILE_RELAXED: &str = "no-secure-boot-cert";
const VM_RECORD_FILE: &str = "portal-vm.json";
const ROOT_PASSWORD_DIGEST_FILE: &str = "root-password.digest";
const SSH_PORT: u16 = 2222;
const AGENT_PORT: u16 = 31337;
const VNC_PORT: u16 = 5900;
const VNC_WEBSOCKET_PORT: u16 = 5700;
const VM_ID: &str = "vm";
const DEFAULT_VM_DIR: &str = "/var/lib/trusted-hash/vm";
const DEFAULT_WORK_DIR: &str = "/var/lib/trusted-hash/portal";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VmEndpoint {
    host: String,
    port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VncEndpoint {
    host: String,
    display: u16,
    port: u16,
    #[serde(default)]
    websocket_port: u16,
    password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VmPorts {
    ssh: VmEndpoint,
    trusted_hash_agent: VmEndpoint,
    vnc: VncEndpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VmStartResponse {
    vm_id: String,
    status: String,
    ports: VmPorts,
    pcr_profiles: BTreeMap<String, String>,
    ek_root_ca_pem: String,
    ek_issuer_pem: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PortalState {
    vm: Option<VmStartResponse>,
    phase: String,
    attester: AttesterView,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttesterView {
    running: bool,
    last_ok: bool,
    last_started_unix: Option<u64>,
    last_finished_unix: Option<u64>,
    profile: Option<String>,
    stages: Vec<AttesterStage>,
    output_tail: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttesterStage {
    name: String,
    status: String,
    detail: Option<String>,
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    state: Arc<Mutex<RuntimeState>>,
}

#[derive(Debug, Clone)]
struct RuntimeState {
    portal: PortalState,
    public_child: Option<u32>,
    runtime_loops_started: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedVm {
    vm: VmStartResponse,
    public_child: Option<u32>,
}

#[derive(Debug, Serialize)]
struct PortalStartResponse {
    state: PortalState,
    credentials: OneTimeCredentials,
}

#[derive(Debug, Serialize)]
struct OneTimeCredentials {
    root_password: String,
    vnc_password: String,
}

#[derive(Debug, Deserialize)]
struct RestartRequest {
    root_password: String,
}

#[derive(Debug, Serialize)]
struct RestartResponse {
    state: PortalState,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Arc::new(Config::from_env()?);
    fs::create_dir_all(&config.work_dir)?;
    if let Some(parent) = config.vm_dir.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut runtime = RuntimeState {
        portal: PortalState {
            vm: None,
            phase: "not_created".to_string(),
            attester: AttesterView {
                running: false,
                last_ok: false,
                last_started_unix: None,
                last_finished_unix: None,
                profile: None,
                stages: Vec::new(),
                output_tail: Vec::new(),
            },
            error: None,
        },
        public_child: None,
        runtime_loops_started: false,
    };
    if let Err(err) = restore_existing_vm(&config, &mut runtime) {
        portal_log(format!("restore_existing_vm failed: {err}"));
        runtime.portal.phase = "failed".to_string();
        runtime.portal.error = Some(format!("failed to restore VM state: {err}"));
    }

    let state = Arc::new(Mutex::new(runtime));
    if state.lock().unwrap().portal.vm.is_some() {
        start_runtime_loops(config.clone(), state.clone());
    }

    let addr = config.addr.clone();
    let app_state = AppState {
        config: config.clone(),
        state: state.clone(),
    };
    portal_log(format!("trusted_hash_portal listening on {addr}"));
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, router(app_state))
        .with_graceful_shutdown(shutdown_signal(config, state))
        .await?;
    Ok(())
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/static/app.js", get(app_js_handler))
        .route("/novnc", get(novnc_index_handler))
        .route("/novnc/*path", get(novnc_asset_handler))
        .route("/vnc-websocket", get(vnc_websocket_handler))
        .route("/api/state", get(state_handler))
        .route("/api/start", post(start_handler))
        .route("/api/restart", post(restart_handler))
        .with_state(state)
}

async fn shutdown_signal(config: Arc<Config>, state: Arc<Mutex<RuntimeState>>) {
    wait_for_shutdown_signal().await;
    let pid = state.lock().unwrap().public_child;
    let _ = stop_child(pid);
    let _ = stop_pid_file(&config.vm_dir(), "public-qemu.pid");
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn index_handler() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn app_js_handler() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )
        .body(Body::from(APP_JS))
        .unwrap()
}

async fn novnc_index_handler(AxumState(app): AxumState<AppState>) -> Response {
    serve_novnc_asset(&app.config.novnc_root, "vnc.html").await
}

async fn novnc_asset_handler(
    AxumPath(path): AxumPath<String>,
    AxumState(app): AxumState<AppState>,
) -> Response {
    serve_novnc_asset(&app.config.novnc_root, &path).await
}

async fn vnc_websocket_handler(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(proxy_vnc_websocket)
}

async fn proxy_vnc_websocket(socket: WebSocket) {
    let upstream = connect_async("ws://127.0.0.1:5700/").await;
    let Ok((upstream, _)) = upstream else {
        return;
    };
    let (mut client_tx, mut client_rx) = socket.split();
    let (mut upstream_tx, mut upstream_rx) = upstream.split();

    let client_to_upstream = async {
        while let Some(message) = client_rx.next().await {
            let Ok(message) = message else {
                break;
            };
            let upstream_message = match message {
                Message::Text(text) => tokio_tungstenite::tungstenite::Message::Text(text),
                Message::Binary(bytes) => tokio_tungstenite::tungstenite::Message::Binary(bytes),
                Message::Ping(bytes) => tokio_tungstenite::tungstenite::Message::Ping(bytes),
                Message::Pong(bytes) => tokio_tungstenite::tungstenite::Message::Pong(bytes),
                Message::Close(frame) => {
                    let frame =
                        frame.map(
                            |frame| tokio_tungstenite::tungstenite::protocol::CloseFrame {
                                code: frame.code.into(),
                                reason: frame.reason,
                            },
                        );
                    let _ = upstream_tx
                        .send(tokio_tungstenite::tungstenite::Message::Close(frame))
                        .await;
                    break;
                }
            };
            if upstream_tx.send(upstream_message).await.is_err() {
                break;
            }
        }
    };

    let upstream_to_client = async {
        while let Some(message) = upstream_rx.next().await {
            let Ok(message) = message else {
                break;
            };
            let client_message = match message {
                tokio_tungstenite::tungstenite::Message::Text(text) => Message::Text(text),
                tokio_tungstenite::tungstenite::Message::Binary(bytes) => Message::Binary(bytes),
                tokio_tungstenite::tungstenite::Message::Ping(bytes) => Message::Ping(bytes),
                tokio_tungstenite::tungstenite::Message::Pong(bytes) => Message::Pong(bytes),
                tokio_tungstenite::tungstenite::Message::Close(frame) => {
                    let frame = frame.map(|frame| axum::extract::ws::CloseFrame {
                        code: frame.code.into(),
                        reason: frame.reason,
                    });
                    let _ = client_tx.send(Message::Close(frame)).await;
                    break;
                }
                tokio_tungstenite::tungstenite::Message::Frame(_) => continue,
            };
            if client_tx.send(client_message).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = client_to_upstream => {}
        _ = upstream_to_client => {}
    }
}

async fn state_handler(AxumState(app): AxumState<AppState>) -> Response {
    let state = app.state.lock().unwrap().portal.clone();
    (StatusCode::OK, Json(state)).into_response()
}

async fn start_handler(AxumState(app): AxumState<AppState>) -> Response {
    portal_log("api/start requested");
    {
        let guard = app.state.lock().unwrap();
        if guard.portal.phase == "creating" {
            return (StatusCode::OK, Json(guard.portal.clone())).into_response();
        }
        if guard.portal.vm.is_some() {
            return json_error(
                StatusCode::CONFLICT,
                "VM already exists for this environment",
            );
        }
    }

    {
        let mut guard = app.state.lock().unwrap();
        guard.portal.phase = "creating".to_string();
        guard.portal.error = None;
    }

    let config = app.config.clone();
    let state = app.state.clone();
    let result = tokio::task::spawn_blocking(move || create_vm(&config, &state)).await;
    match result {
        Ok(Ok(credentials)) => {
            portal_log("api/start completed");
            start_runtime_loops(app.config, app.state.clone());
            let state = app.state.lock().unwrap().portal.clone();
            (
                StatusCode::OK,
                Json(PortalStartResponse { state, credentials }),
            )
                .into_response()
        }
        Ok(Err(err)) => {
            portal_log(format!("api/start failed: {err}"));
            let mut guard = app.state.lock().unwrap();
            guard.portal.phase = "failed".to_string();
            guard.portal.error = Some(err.to_string());
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(guard.portal.clone()),
            )
                .into_response()
        }
        Err(err) => {
            portal_log(format!("api/start task failed: {err}"));
            let mut guard = app.state.lock().unwrap();
            guard.portal.phase = "failed".to_string();
            guard.portal.error = Some(err.to_string());
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(guard.portal.clone()),
            )
                .into_response()
        }
    }
}

async fn restart_handler(
    AxumState(app): AxumState<AppState>,
    Json(body): Json<RestartRequest>,
) -> Response {
    portal_log("api/restart requested");
    let config = app.config.clone();
    let state = app.state.clone();
    let result =
        tokio::task::spawn_blocking(move || restart_vm(&config, &state, &body.root_password)).await;
    match result {
        Ok(Ok(())) => {
            portal_log("api/restart completed");
            let state = app.state.lock().unwrap().portal.clone();
            (StatusCode::OK, Json(RestartResponse { state })).into_response()
        }
        Ok(Err(err)) => {
            portal_log(format!("api/restart failed: {err}"));
            let mut guard = app.state.lock().unwrap();
            guard.portal.phase = "failed".to_string();
            guard.portal.error = Some(err.to_string());
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(guard.portal.clone()),
            )
                .into_response()
        }
        Err(err) => {
            portal_log(format!("api/restart task failed: {err}"));
            let mut guard = app.state.lock().unwrap();
            guard.portal.phase = "failed".to_string();
            guard.portal.error = Some(err.to_string());
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(guard.portal.clone()),
            )
                .into_response()
        }
    }
}

async fn serve_novnc_asset(root: &Path, raw_path: &str) -> Response {
    let Some(path) = safe_asset_path(root, raw_path) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid noVNC asset path");
    };

    match tokio::fs::read(&path).await {
        Ok(contents) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type_for_path(&path))
            .body(Body::from(contents))
            .unwrap(),
        Err(_) => json_error(
            StatusCode::NOT_FOUND,
            format!(
                "noVNC asset not found; set TH_NOVNC_ROOT to a noVNC installation containing {}",
                raw_path
            ),
        ),
    }
}

fn safe_asset_path(root: &Path, raw_path: &str) -> Option<PathBuf> {
    let relative = raw_path.trim_start_matches('/');
    let mut path = PathBuf::from(root);
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(path)
}

fn content_type_for_path(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("gif") => "image/gif",
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

fn create_vm(config: &Config, state: &Arc<Mutex<RuntimeState>>) -> Result<OneTimeCredentials> {
    portal_log("create_vm: begin");
    let root_password = random_hex(32)?;
    let vnc_password = random_hex(8)?;
    let vm_dir = config.vm_dir();
    portal_log(format!(
        "create_vm: release_dir={} vm_dir={} scripts_dir={} attester_bin={}",
        config.release_dir.display(),
        vm_dir.display(),
        config.scripts_dir.display(),
        config.attester_bin.display()
    ));
    if vm_dir.exists() {
        return Err("VM directory already exists; reopen the platform environment to reset".into());
    }
    run_status_logged(
        "create-vm",
        Command::new(config.scripts_dir.join("create-vm"))
            .arg(&config.release_dir)
            .arg(&vm_dir),
    )?;
    portal_log("create_vm: create-vm script completed");
    fs::write(vm_dir.join("vnc-passwd.txt"), format!("{vnc_password}\n"))?;
    portal_log(format!(
        "create_vm: wrote VNC password file at {}",
        vm_dir.join("vnc-passwd.txt").display()
    ));

    portal_log("create_vm: starting private/provision VM");
    let private_child = spawn_qemu(config, &vm_dir, "provision", "private")?;
    let private_pid = private_child.id();
    portal_log(format!("create_vm: private/provision VM pid={private_pid}"));
    write_pid(&vm_dir, "private-qemu.pid", private_pid)?;
    let init_result = (|| {
        portal_log(format!(
            "create_vm: waiting for private agent on 127.0.0.1:{AGENT_PORT}"
        ));
        wait_for_tcp("127.0.0.1", AGENT_PORT, Duration::from_secs(180))?;
        portal_log("create_vm: private agent TCP port is reachable");
        let mut pcr_profiles = BTreeMap::new();
        for profile in [PROFILE_HARD, PROFILE_RELAXED] {
            let out = config.work_dir.join(format!("pcr-{profile}.conf"));
            portal_log(format!(
                "create_vm: capturing initial PCR profile {profile}"
            ));
            capture_profile(
                config,
                &vm_dir,
                profile,
                &format!("127.0.0.1:{AGENT_PORT}"),
                &out,
            )?;
            portal_log(format!(
                "create_vm: captured PCR profile {profile} into {}",
                out.display()
            ));
            pcr_profiles.insert(profile.to_string(), fs::read_to_string(out)?);
        }
        portal_log("create_vm: provisioning one-time root password through agent");
        provision_root_password(&root_password)?;
        portal_log("create_vm: root password provisioned");
        Result::<BTreeMap<String, String>>::Ok(pcr_profiles)
    })();
    portal_log(format!(
        "create_vm: stopping private/provision VM pid={private_pid}"
    ));
    let _ = stop_child(Some(private_pid));
    let pcr_profiles = init_result?;

    portal_log("create_vm: starting public VM");
    let public_child = spawn_qemu(config, &vm_dir, "public", "public")?;
    let public_pid = public_child.id();
    portal_log(format!("create_vm: public VM pid={public_pid}"));
    write_pid(&vm_dir, "public-qemu.pid", public_pid)?;
    portal_log(format!(
        "create_vm: waiting for public agent on 127.0.0.1:{AGENT_PORT}"
    ));
    wait_for_tcp("127.0.0.1", AGENT_PORT, Duration::from_secs(180))?;
    portal_log("create_vm: public agent TCP port is reachable");

    let vm = VmStartResponse {
        vm_id: VM_ID.to_string(),
        status: "ready".to_string(),
        ports: VmPorts {
            ssh: VmEndpoint {
                host: "127.0.0.1".to_string(),
                port: SSH_PORT,
            },
            trusted_hash_agent: VmEndpoint {
                host: "127.0.0.1".to_string(),
                port: AGENT_PORT,
            },
            vnc: VncEndpoint {
                host: "127.0.0.1".to_string(),
                display: 0,
                port: VNC_PORT,
                websocket_port: VNC_WEBSOCKET_PORT,
                password: None,
            },
        },
        pcr_profiles,
        ek_root_ca_pem: fs::read_to_string(vm_dir.join("ca/swtpm-localca-rootca-cert.pem"))?,
        ek_issuer_pem: fs::read_to_string(vm_dir.join("ca/issuercert.pem"))?,
    };
    write_vm_material(config, &vm)?;
    write_password_digest(config, &root_password)?;
    save_vm_record(config, &vm, Some(public_pid))?;
    portal_log(format!(
        "create_vm: persisted VM material in {} and record in {}",
        config.work_dir.display(),
        vm_dir.join(VM_RECORD_FILE).display()
    ));
    {
        let mut guard = state.lock().unwrap();
        guard.portal.vm = Some(vm);
        guard.portal.phase = "ready".to_string();
        guard.portal.error = None;
        guard.public_child = Some(public_pid);
    }

    portal_log("create_vm: ready");
    Ok(OneTimeCredentials {
        root_password,
        vnc_password,
    })
}

fn restart_vm(
    config: &Config,
    state: &Arc<Mutex<RuntimeState>>,
    root_password: &str,
) -> Result<()> {
    portal_log("restart_vm: begin");
    if !password_matches(config, root_password)? {
        return Err("root password confirmation failed".into());
    }
    let old_pid = {
        let mut guard = state.lock().unwrap();
        guard.portal.phase = "restarting".to_string();
        guard.public_child.take()
    };
    portal_log(format!(
        "restart_vm: stopping old public VM pid={old_pid:?}"
    ));
    stop_child(old_pid)?;
    let vm_dir = config.vm_dir();
    portal_log("restart_vm: starting public VM");
    let public_child = spawn_qemu(config, &vm_dir, "public", "public")?;
    let public_pid = public_child.id();
    portal_log(format!("restart_vm: public VM pid={public_pid}"));
    write_pid(&vm_dir, "public-qemu.pid", public_pid)?;
    portal_log(format!(
        "restart_vm: waiting for public agent on 127.0.0.1:{AGENT_PORT}"
    ));
    wait_for_tcp("127.0.0.1", AGENT_PORT, Duration::from_secs(180))?;
    portal_log("restart_vm: public agent TCP port is reachable");

    let mut guard = state.lock().unwrap();
    guard.public_child = Some(public_pid);
    guard.portal.phase = "ready".to_string();
    guard.portal.error = None;
    portal_log("restart_vm: ready");
    Ok(())
}

fn spawn_qemu(config: &Config, vm_dir: &Path, mode: &str, label: &str) -> Result<Child> {
    let log_path = vm_dir.join(format!("{label}-qemu.log"));
    portal_log(format!(
        "spawn_qemu: label={label} mode={mode} log={}",
        log_path.display()
    ));
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let mut command = Command::new("setsid");
    command
        .arg(config.scripts_dir.join("start-vm"))
        .arg(vm_dir)
        .env("TRUSTED_HASH_QEMU_MONITOR", "none")
        .env("TRUSTED_HASH_VM_MODE", mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    portal_log(format!(
        "spawn_qemu: command={} TRUSTED_HASH_QEMU_MONITOR=none TRUSTED_HASH_VM_MODE={mode}",
        command_summary(&command)
    ));
    let mut child = command.spawn()?;
    if let Some(stdout) = child.stdout.take() {
        spawn_output_logger(stdout, log.try_clone()?, format!("{label}/start-vm stdout"));
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_output_logger(stderr, log, format!("{label}/start-vm stderr"));
    }
    portal_log(format!(
        "spawn_qemu: started label={label} mode={mode} pid={}",
        child.id()
    ));
    Ok(child)
}

fn capture_profile(
    config: &Config,
    vm_dir: &Path,
    profile: &str,
    addr: &str,
    out: &Path,
) -> Result<()> {
    run_status_logged(
        &format!("initial-attester profile={profile}"),
        Command::new(&config.attester_bin)
            .arg("--addr")
            .arg(addr)
            .arg("--pcr-profile")
            .arg(profile)
            .arg("--learn-pcr-digest")
            .arg("--write-pcr-config")
            .arg(out)
            .arg("--ek-root-ca")
            .arg(vm_dir.join("ca/swtpm-localca-rootca-cert.pem"))
            .arg("--ek-issuer")
            .arg(vm_dir.join("ca/issuercert.pem")),
    )
}

fn provision_root_password(root_password: &str) -> Result<()> {
    portal_log(format!(
        "provision_root_password: connecting to 127.0.0.1:{AGENT_PORT}"
    ));
    let mut stream = TcpStream::connect(("127.0.0.1", AGENT_PORT))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    write_request(
        &mut stream,
        &Request::SetRootPassword(SetRootPasswordRequest {
            password: root_password.to_string(),
        }),
    )?;
    match expect_ok(read_response(&mut stream)?)? {
        trusted_hash_common::Response::SetRootPassword => {
            portal_log("provision_root_password: agent accepted root password update");
            Ok(())
        }
        other => Err(format!("unexpected set-root-password response: {other:?}").into()),
    }
}

fn start_runtime_loops(config: Arc<Config>, state: Arc<Mutex<RuntimeState>>) {
    {
        let mut guard = state.lock().unwrap();
        if guard.runtime_loops_started {
            return;
        }
        guard.runtime_loops_started = true;
    }
    portal_log(format!(
        "runtime_loop: started, interval_secs={}",
        config.test_interval_secs
    ));
    std::thread::spawn(move || loop {
        if state.lock().unwrap().portal.vm.is_none() {
            portal_log("runtime_loop: stopping because VM state is empty");
            return;
        }
        run_attester_once(&config, &state);
        std::thread::sleep(Duration::from_secs(config.test_interval_secs));
    });
}

fn run_attester_once(config: &Config, state: &Arc<Mutex<RuntimeState>>) {
    if state.lock().unwrap().portal.vm.is_none() {
        return;
    }
    portal_log("periodic-attester: begin");
    let profile_path = config.work_dir.join("pcr-hard.conf");
    let root_ca = config.work_dir.join("swtpm-localca-rootca-cert.pem");
    let issuer = config.work_dir.join("issuercert.pem");

    {
        let mut guard = state.lock().unwrap();
        guard.portal.attester.running = true;
        guard.portal.attester.last_started_unix = Some(now_unix());
        guard.portal.attester.profile = Some("hard".to_string());
        guard.portal.attester.stages = default_stages();
        guard.portal.attester.output_tail.clear();
    }

    let mut command = Command::new(&config.attester_bin);
    command
        .arg("--addr")
        .arg(format!("127.0.0.1:{AGENT_PORT}"))
        .arg("--config")
        .arg(profile_path)
        .arg("--ek-root-ca")
        .arg(root_ca)
        .arg("--ek-issuer")
        .arg(issuer)
        .env("CTF_FLAG", &config.flag);
    portal_log(format!(
        "periodic-attester: command={} env=CTF_FLAG=<redacted>",
        command_summary(&command)
    ));
    let output = command.output();

    let mut guard = state.lock().unwrap();
    guard.portal.attester.running = false;
    guard.portal.attester.last_finished_unix = Some(now_unix());
    match output {
        Ok(output) => {
            log_command_output("periodic-attester", &output);
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            guard.portal.attester.output_tail = tail_lines(&text, 40);
            guard.portal.attester.last_ok = output.status.success();
            guard.portal.attester.stages = parse_attester_stages(&text, output.status.success());
            if output.status.success() {
                guard.portal.error = None;
                portal_log("periodic-attester: completed successfully");
            } else {
                guard.portal.error = Some(format!("attester failed with {}", output.status));
                portal_log(format!("periodic-attester: failed with {}", output.status));
            }
        }
        Err(err) => {
            portal_log(format!("periodic-attester: spawn failed: {err}"));
            guard.portal.attester.last_ok = false;
            guard.portal.attester.output_tail = vec![err.to_string()];
            guard.portal.attester.stages = vec![AttesterStage {
                name: "spawn attester".to_string(),
                status: "fail".to_string(),
                detail: Some(err.to_string()),
            }];
            guard.portal.error = Some(err.to_string());
        }
    }
}

fn restore_existing_vm(config: &Config, runtime: &mut RuntimeState) -> Result<()> {
    let record_path = config.vm_dir().join(VM_RECORD_FILE);
    if !record_path.exists() {
        portal_log(format!(
            "restore_existing_vm: no existing record at {}",
            record_path.display()
        ));
        return Ok(());
    }
    portal_log(format!(
        "restore_existing_vm: restoring record from {}",
        record_path.display()
    ));
    let persisted: PersistedVm = serde_json::from_slice(&fs::read(record_path)?)?;
    write_vm_material(config, &persisted.vm)?;
    runtime.portal.vm = Some(persisted.vm);
    runtime.portal.phase = "ready".to_string();
    runtime.portal.error = None;
    runtime.public_child = fs::read_to_string(config.vm_dir().join("public-qemu.pid"))
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .or(persisted.public_child);
    portal_log(format!(
        "restore_existing_vm: restored public_child={:?}",
        runtime.public_child
    ));
    Ok(())
}

fn save_vm_record(config: &Config, vm: &VmStartResponse, public_child: Option<u32>) -> Result<()> {
    let record = PersistedVm {
        vm: vm.clone(),
        public_child,
    };
    fs::write(
        config.vm_dir().join(VM_RECORD_FILE),
        serde_json::to_vec_pretty(&record)?,
    )?;
    Ok(())
}

fn write_vm_material(config: &Config, vm: &VmStartResponse) -> Result<()> {
    fs::create_dir_all(&config.work_dir)?;
    fs::write(
        config.work_dir.join("pcr-hard.conf"),
        vm.pcr_profiles
            .get(PROFILE_HARD)
            .ok_or("VM response missed hard PCR profile")?,
    )?;
    fs::write(
        config.work_dir.join("pcr-no-secure-boot-cert.conf"),
        vm.pcr_profiles
            .get(PROFILE_RELAXED)
            .ok_or("VM response missed no-secure-boot-cert PCR profile")?,
    )?;
    fs::write(
        config.work_dir.join("swtpm-localca-rootca-cert.pem"),
        &vm.ek_root_ca_pem,
    )?;
    fs::write(config.work_dir.join("issuercert.pem"), &vm.ek_issuer_pem)?;
    Ok(())
}

fn write_password_digest(config: &Config, password: &str) -> Result<()> {
    let path = config.work_dir.join(ROOT_PASSWORD_DIGEST_FILE);
    fs::write(&path, password_digest(password))?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn password_matches(config: &Config, password: &str) -> Result<bool> {
    let expected = fs::read_to_string(config.work_dir.join(ROOT_PASSWORD_DIGEST_FILE))?;
    Ok(expected == password_digest(password))
}

fn password_digest(password: &str) -> String {
    use sha2::{Digest, Sha256};
    hex_lower(&Sha256::digest(password.as_bytes()))
}

fn random_hex(byte_len: usize) -> Result<String> {
    let mut file = fs::File::open("/dev/urandom")?;
    let mut bytes = vec![0u8; byte_len];
    file.read_exact(&mut bytes)?;
    Ok(hex_lower(&bytes))
}

fn parse_attester_stages(text: &str, success: bool) -> Vec<AttesterStage> {
    let mut seen = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            seen.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    [
        ("create session", "session_id"),
        ("PCR quote", "pcr_digest_hex"),
        ("module signer", "module_signer_name_hex"),
        ("trusted hash", "trusted_hash_result"),
    ]
    .into_iter()
    .map(|(name, key)| AttesterStage {
        name: name.to_string(),
        status: if seen.contains_key(key) {
            "ok"
        } else if success {
            "ok"
        } else {
            "fail"
        }
        .to_string(),
        detail: seen.get(key).cloned(),
    })
    .collect()
}

fn default_stages() -> Vec<AttesterStage> {
    [
        "create session",
        "PCR quote",
        "module signer",
        "trusted hash",
    ]
    .into_iter()
    .map(|name| AttesterStage {
        name: name.to_string(),
        status: "running".to_string(),
        detail: None,
    })
    .collect()
}

fn tail_lines(text: &str, count: usize) -> Vec<String> {
    let lines = text.lines().map(str::to_string).collect::<Vec<_>>();
    let start = lines.len().saturating_sub(count);
    lines[start..].to_vec()
}

fn run_status_logged(label: &str, command: &mut Command) -> Result<()> {
    portal_log(format!("{label}: command={}", command_summary(command)));
    let output = command.output()?;
    log_command_output(label, &output);
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "command failed: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

fn log_command_output(label: &str, output: &std::process::Output) {
    portal_log(format!("{label}: exit_status={}", output.status));
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        portal_log(format!("{label}: stdout: {line}"));
    }
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        portal_log(format!("{label}: stderr: {line}"));
    }
}

fn spawn_output_logger<R>(reader: R, mut log: fs::File, label: String)
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let reader = BufReader::new(reader);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    let _ = writeln!(log, "{line}");
                    portal_log(format!("{label}: {line}"));
                }
                Err(err) => {
                    portal_log(format!("{label}: read failed: {err}"));
                    break;
                }
            }
        }
        portal_log(format!("{label}: closed"));
    });
}

fn command_summary(command: &Command) -> String {
    let mut parts = vec![command.get_program().to_string_lossy().into_owned()];
    parts.extend(
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned()),
    );
    parts.join(" ")
}

fn portal_log(message: impl AsRef<str>) {
    eprintln!("[trusted-hash-portal {}] {}", now_unix(), message.as_ref());
}

fn write_pid(vm_dir: &Path, name: &str, pid: u32) -> Result<()> {
    fs::write(vm_dir.join(name), format!("{pid}\n"))?;
    Ok(())
}

fn stop_pid_file(vm_dir: &Path, name: &str) -> Result<()> {
    let pid = fs::read_to_string(vm_dir.join(name))
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok());
    stop_child(pid)
}

fn stop_child(pid: Option<u32>) -> Result<()> {
    if let Some(pid) = pid {
        signal_process_group(pid, libc::SIGTERM)?;
        std::thread::sleep(Duration::from_secs(2));
        if process_group_exists(pid)? {
            signal_process_group(pid, libc::SIGKILL)?;
        }
        reap_child(pid, Duration::from_secs(5))?;
    }
    Ok(())
}

fn signal_process_group(pid: u32, signal: libc::c_int) -> Result<()> {
    let pgid = -(pid as libc::pid_t);
    let rc = unsafe { libc::kill(pgid, signal) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(err.into())
}

fn process_group_exists(pid: u32) -> Result<bool> {
    let pgid = -(pid as libc::pid_t);
    let rc = unsafe { libc::kill(pgid, 0) };
    if rc == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(false);
    }
    Err(err.into())
}

fn reap_child(pid: u32, timeout: Duration) -> Result<()> {
    let started = SystemTime::now();
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
        if rc == pid as libc::pid_t || rc == -1 {
            if rc == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ECHILD) {
                    return Err(err.into());
                }
            }
            return Ok(());
        }
        if started.elapsed()? >= timeout {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_tcp(host: &str, port: u16, timeout: Duration) -> Result<()> {
    let started = SystemTime::now();
    loop {
        if std::net::TcpStream::connect((host, port)).is_ok() {
            return Ok(());
        }
        if started.elapsed()? > timeout {
            return Err(format!("timed out waiting for {host}:{port}").into());
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn json_error(status: StatusCode, error: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: error.into(),
        }),
    )
        .into_response()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone)]
struct Config {
    addr: String,
    flag: String,
    release_dir: PathBuf,
    vm_dir: PathBuf,
    scripts_dir: PathBuf,
    attester_bin: PathBuf,
    novnc_root: PathBuf,
    work_dir: PathBuf,
    test_interval_secs: u64,
}

impl Config {
    fn from_env() -> Result<Self> {
        Ok(Self {
            addr: env_value("TH_PORTAL_ADDR", "0.0.0.0:8080"),
            flag: env_required("FLAG")?,
            release_dir: PathBuf::from(env_value("TH_RELEASE_DIR", "/opt/trusted-hash-release")),
            vm_dir: PathBuf::from(DEFAULT_VM_DIR),
            scripts_dir: PathBuf::from(env_value(
                "TH_SCRIPTS_DIR",
                "/opt/trusted-hash/challenge/scripts",
            )),
            attester_bin: PathBuf::from(env_value("TH_ATTESTER_BIN", "trusted-hash-attester")),
            novnc_root: PathBuf::from(env_value("TH_NOVNC_ROOT", "/usr/share/novnc")),
            work_dir: PathBuf::from(DEFAULT_WORK_DIR),
            test_interval_secs: env_value("TH_TEST_INTERVAL_SECONDS", "30").parse()?,
        })
    }

    fn vm_dir(&self) -> PathBuf {
        self.vm_dir.clone()
    }
}

fn env_value(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_required(name: &str) -> Result<String> {
    env::var(name).map_err(|_| format!("missing required environment variable {name}").into())
}
