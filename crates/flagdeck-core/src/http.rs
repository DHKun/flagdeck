#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::too_many_lines
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use flagdeck_adapter_host::{
    AdapterHost, AdapterHostConfig, AdapterWorker, ControlTransport, HostError,
};
use flagdeck_adapter_protocol::{JsonRpcRequest, RequestMetadata};
use flagdeck_domain::{
    ADAPTER_PROTOCOL, Artifact, ArtifactId, BodyState, ConnectionMetadata, ExportPolicy,
    HttpMessage, HttpSource, MessageDirection, MessageId, OrderedValue, ProjectId,
    ProxyCaptureMode, ProxySession, ProxySessionId, ProxySessionState, RepresentationKind, ScopeId,
    Sensitivity, TargetScope, Timestamp,
};
use flagdeck_storage::WorkspaceLayout;
use flagdeck_storage::{ArtifactWriteRequest, HttpMessageFilter, ProjectStore, StorageError};
use native_tls::TlsConnector;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use ts_rs::TS;
use uuid::Uuid;

const PROXY_READY_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_EVENT_LINE_BYTES: usize = 1024 * 1024;
const MAX_HTTP_BODY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HTTP_HEAD_BYTES: usize = 1024 * 1024;
const CHROME: &str = "/usr/bin/google-chrome-stable";
const CERTUTIL: &str = "/usr/bin/certutil";
const OPENSSL: &str = "/usr/bin/openssl";
const SETSID: &str = "/usr/bin/setsid";

#[derive(Debug, Error)]
pub enum HttpWorkbenchError {
    #[error("an HTTP proxy session is already active")]
    ActiveProxy,
    #[error("the HTTP proxy session is unavailable")]
    NoActiveProxy,
    #[error("the HTTP workbench request is invalid")]
    InvalidRequest,
    #[error("the HTTP target is outside the saved scope")]
    ScopeViolation,
    #[error("the HTTP worker failed its runtime contract")]
    WorkerContract,
    #[error("the project CA or browser trust store failed validation")]
    TrustStore,
    #[error("HTTP adapter host failed")]
    AdapterHost(#[from] HostError),
    #[error("HTTP storage operation failed")]
    Storage(#[from] StorageError),
    #[error("HTTP workbench I/O failed")]
    Io(#[from] std::io::Error),
    #[error("HTTP event JSON failed validation")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StartProxyRequest {
    pub project_id: ProjectId,
    pub scope_id: ScopeId,
    pub capture_mode: ProxyCaptureMode,
    pub ssl_insecure: bool,
    pub launch_browser: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StopProxyRequest {
    pub project_id: ProjectId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct HttpHistoryPageRequest {
    pub project_id: ProjectId,
    pub cursor: Option<String>,
    pub limit: usize,
    pub query: Option<String>,
    pub source: Option<HttpSource>,
    pub direction: Option<MessageDirection>,
    pub host: Option<String>,
    pub status_code: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct HttpHistoryPage {
    pub items: Vec<HttpMessage>,
    pub next_cursor: Option<String>,
    pub imported_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct GetHttpMessageRequest {
    pub project_id: ProjectId,
    pub message_id: MessageId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct RepeatHttpRequest {
    pub project_id: ProjectId,
    pub scope_id: ScopeId,
    pub parent_message_id: MessageId,
    pub method: String,
    pub path: String,
    pub headers: Vec<OrderedValue>,
    pub body: Vec<u8>,
    pub ssl_insecure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct RepeatHttpResult {
    pub request: HttpMessage,
    pub response: HttpMessage,
    pub serialized_request_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct DiffHttpMessagesRequest {
    pub project_id: ProjectId,
    pub left_message_id: MessageId,
    pub right_message_id: MessageId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ValueDifference {
    pub name: String,
    pub left: Vec<String>,
    pub right: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct HttpBodyDiff {
    pub kind: String,
    pub left_sha256: String,
    pub right_sha256: String,
    #[ts(type = "number")]
    pub left_length: u64,
    #[ts(type = "number")]
    pub right_length: u64,
    pub text_changes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct HttpMessageDiff {
    pub headers: Vec<ValueDifference>,
    pub parameters: Vec<ValueDifference>,
    pub body: HttpBodyDiff,
    #[ts(type = "number | null")]
    pub duration_delta_millis: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CreateSqlmapRequestFileRequest {
    pub project_id: ProjectId,
    pub message_id: MessageId,
    pub confirm_sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SendRawHttp1Request {
    pub project_id: ProjectId,
    pub scope_id: ScopeId,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub ssl_insecure: bool,
    pub wire_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SendRawHttp1Result {
    pub request: HttpMessage,
    pub response: HttpMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct OpenHttpBrowserPreviewRequest {
    pub project_id: ProjectId,
    pub message_id: MessageId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct OpenHttpBrowserPreviewResult {
    pub url: String,
}

struct ActiveProxy {
    session: ProxySession,
    worker: AdapterWorker,
    events_file: PathBuf,
    capture_root: PathBuf,
    chrome_process_group: Option<i32>,
    last_event_sequence: u64,
}

pub struct HttpWorkbench {
    active: AsyncMutex<Option<ActiveProxy>>,
    worker_source_root: PathBuf,
}

impl Default for HttpWorkbench {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpWorkbench {
    #[must_use]
    pub fn new() -> Self {
        Self::with_worker_source(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../workers/mitmproxy"),
        )
    }

    #[must_use]
    pub fn with_worker_source(worker_source_root: PathBuf) -> Self {
        Self {
            active: AsyncMutex::new(None),
            worker_source_root,
        }
    }

    pub async fn start_proxy(
        &self,
        store: Arc<ProjectStore>,
        scope: TargetScope,
        request: &StartProxyRequest,
    ) -> Result<ProxySession, HttpWorkbenchError> {
        if store.project_id() != &request.project_id
            || scope.project_id != request.project_id
            || scope.scope_id != request.scope_id
        {
            return Err(HttpWorkbenchError::InvalidRequest);
        }
        let mut active = self.active.lock().await;
        if active.is_some() {
            return Err(HttpWorkbenchError::ActiveProxy);
        }
        let session_id = ProxySessionId::new();
        let mut session = ProxySession {
            proxy_session_id: session_id.clone(),
            project_id: request.project_id.clone(),
            scope_id: request.scope_id.clone(),
            state: ProxySessionState::Starting,
            capture_mode: request.capture_mode,
            listen_host: "127.0.0.1".to_owned(),
            listen_port: None,
            worker_pid: None,
            systemd_unit: None,
            cgroup_path: None,
            invocation_id: Some(format!("proxy-{}", session_id.0)),
            ca_sha256: None,
            chrome_pid: None,
            ssl_insecure: request.ssl_insecure,
            created_at: Timestamp::now(),
            ready_at: None,
            stopped_at: None,
            error_summary: None,
        };
        store.save_proxy_session(&session)?;

        let layout = store.layout();
        let session_runtime = layout.runtime.join(format!("proxy-{}", session_id.0));
        create_private_directory(&session_runtime)?;
        let worker_root = prepare_proxy_worker(&self.worker_source_root, layout)?;
        let launched =
            launch_proxy_worker(layout, &session_runtime, &worker_root, request, &session_id).await;
        let (worker, listen_port, proxy_pid, events_file, capture_root) = match launched {
            Ok(value) => value,
            Err(error) => {
                session.state = ProxySessionState::Failed;
                session.stopped_at = Some(Timestamp::now());
                session.error_summary = Some(error.to_string());
                store.save_proxy_session(&session)?;
                return Err(error);
            }
        };
        let started = (|| {
            let ca_path = wait_for_project_ca(&layout.mitm_confdir)?;
            let ca_sha256 = certificate_sha256(&ca_path)?;
            let nss_database = initialize_project_nss(
                &layout.browser_home,
                &request.project_id,
                &ca_path,
                &ca_sha256,
            )?;
            let chrome_process_group = if request.launch_browser {
                Some(launch_project_chrome(
                    &layout.browser_home,
                    &layout.browser_profile,
                    listen_port,
                    scope_explicitly_includes_loopback(&scope),
                )?)
            } else {
                None
            };
            Ok::<_, HttpWorkbenchError>((ca_sha256, nss_database, chrome_process_group))
        })();

        let (ca_sha256, _nss_database, chrome_process_group) = match started {
            Ok(value) => value,
            Err(error) => {
                let _ = worker.shutdown().await;
                session.state = ProxySessionState::Failed;
                session.stopped_at = Some(Timestamp::now());
                session.error_summary = Some(error.to_string());
                store.save_proxy_session(&session)?;
                return Err(error);
            }
        };
        session.state = ProxySessionState::Ready;
        session.listen_port = Some(listen_port);
        session.worker_pid = Some(proxy_pid);
        session.ca_sha256 = Some(ca_sha256);
        session.chrome_pid = chrome_process_group;
        session.ready_at = Some(Timestamp::now());
        store.save_proxy_session(&session)?;
        *active = Some(ActiveProxy {
            session: session.clone(),
            worker,
            events_file,
            capture_root,
            chrome_process_group,
            last_event_sequence: 0,
        });
        Ok(session)
    }

    pub async fn stop_proxy(
        &self,
        store: Arc<ProjectStore>,
        project_id: &ProjectId,
    ) -> Result<ProxySession, HttpWorkbenchError> {
        let mut active_lock = self.active.lock().await;
        let mut active = active_lock
            .take()
            .ok_or(HttpWorkbenchError::NoActiveProxy)?;
        if &active.session.project_id != project_id || store.project_id() != project_id {
            *active_lock = Some(active);
            return Err(HttpWorkbenchError::InvalidRequest);
        }
        active.session.state = ProxySessionState::Stopping;
        store.save_proxy_session(&active.session)?;
        let imported = sync_active_proxy(&mut active, &store).await?;
        let _ = adapter_call(
            &mut active.worker,
            "shutdown",
            &active.session.proxy_session_id,
            json!({}),
        )
        .await;
        let worker_result = active.worker.shutdown().await;
        if let Some(process_group) = active.chrome_process_group {
            stop_process_group(process_group);
        }
        let imported_after = ingest_proxy_events(
            &store,
            &active.session,
            &active.events_file,
            &active.capture_root,
        )?;
        active.session.stopped_at = Some(Timestamp::now());
        active.session.chrome_pid = None;
        if worker_result.is_ok() {
            active.session.state = ProxySessionState::Stopped;
            active.session.error_summary = None;
        } else {
            active.session.state = ProxySessionState::Failed;
            active.session.error_summary = Some(format!(
                "proxy shutdown failed after importing {} messages",
                imported.saturating_add(imported_after)
            ));
        }
        store.save_proxy_session(&active.session)?;
        Ok(active.session)
    }

    pub async fn active_session(&self, project_id: &ProjectId) -> Option<ProxySession> {
        self.active
            .lock()
            .await
            .as_ref()
            .filter(|active| &active.session.project_id == project_id)
            .map(|active| active.session.clone())
    }

    pub async fn ingest_active(
        &self,
        store: &ProjectStore,
        project_id: &ProjectId,
    ) -> Result<usize, HttpWorkbenchError> {
        let mut active = self.active.lock().await;
        let Some(active) = active
            .as_mut()
            .filter(|active| &active.session.project_id == project_id)
        else {
            return Ok(0);
        };
        sync_active_proxy(active, store).await
    }

    pub async fn open_browser_preview(
        &self,
        store: &ProjectStore,
        message: &HttpMessage,
    ) -> Result<OpenHttpBrowserPreviewResult, HttpWorkbenchError> {
        let active = self.active.lock().await;
        let active = active
            .as_ref()
            .filter(|active| {
                active.session.project_id == message.project_id
                    && active.session.state == ProxySessionState::Ready
                    && active.chrome_process_group.is_some()
            })
            .ok_or(HttpWorkbenchError::NoActiveProxy)?;
        let content_type = header_value(&message.headers, "content-type").unwrap_or_default();
        if message.direction != MessageDirection::Response
            || !content_type
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/html"))
        {
            return Err(HttpWorkbenchError::InvalidRequest);
        }
        let scope = store.target_scope(&active.session.scope_id)?;
        if !scope.exact_hosts.iter().any(|host| host == &message.host)
            || !scope
                .ports
                .iter()
                .any(|range| range.start <= message.port && message.port <= range.end)
            || !scope.schemes.iter().any(|scheme| scheme == &message.scheme)
        {
            return Err(HttpWorkbenchError::ScopeViolation);
        }
        let url = format!("{}://{}{}", message.scheme, message.authority, message.path);
        let parsed = url::Url::parse(&url).map_err(|_| HttpWorkbenchError::InvalidRequest)?;
        if parsed.host_str() != Some(message.host.as_str()) {
            return Err(HttpWorkbenchError::ScopeViolation);
        }
        let proxy_port = active
            .session
            .listen_port
            .ok_or(HttpWorkbenchError::WorkerContract)?;
        let mut command = Command::new(CHROME);
        command
            .arg(format!(
                "--user-data-dir={}",
                store.layout().browser_profile.display()
            ))
            .arg(format!("--proxy-server=http://127.0.0.1:{proxy_port}"))
            .arg("--no-first-run")
            .arg(&url)
            .env_clear()
            .env("HOME", &store.layout().browser_home)
            .env("LANG", "C.UTF-8")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if scope_explicitly_includes_loopback(&scope) {
            command.arg("--proxy-bypass-list=<-loopback>");
        }
        apply_desktop_environment(&mut command);
        command.spawn()?;
        Ok(OpenHttpBrowserPreviewResult { url })
    }

    pub fn has_active(&self) -> bool {
        self.active
            .try_lock()
            .map_or(true, |active| active.is_some())
    }
}

fn prepare_proxy_worker(
    source_root: &Path,
    layout: &WorkspaceLayout,
) -> Result<PathBuf, HttpWorkbenchError> {
    let source_root = fs::canonicalize(source_root)?;
    if source_root.join(".venv/bin/mitmdump").is_file() {
        return Ok(source_root);
    }
    for required in ["pyproject.toml", "uv.lock", "flagdeck_worker_addon.py"] {
        if !source_root.join(required).is_file() {
            return Err(HttpWorkbenchError::WorkerContract);
        }
    }
    if !source_root.join("src/flagdeck_mitm/adapter.py").is_file() {
        return Err(HttpWorkbenchError::WorkerContract);
    }
    let destination = layout.runtime.join("mitmproxy-worker-1.0.0");
    create_private_directory(&destination)?;
    if destination.join("pyproject.toml").exists() {
        if fs::read(destination.join("uv.lock"))? != fs::read(source_root.join("uv.lock"))? {
            return Err(HttpWorkbenchError::WorkerContract);
        }
    } else {
        for name in ["pyproject.toml", "uv.lock", "flagdeck_worker_addon.py"] {
            copy_private_file(&source_root.join(name), &destination.join(name))?;
        }
        copy_private_tree(&source_root.join("src"), &destination.join("src"))?;
    }
    if !destination.join(".venv/bin/mitmdump").is_file() {
        let uv = find_uv_program().ok_or(HttpWorkbenchError::WorkerContract)?;
        let version = Command::new(&uv)
            .arg("--version")
            .env_clear()
            .stdin(Stdio::null())
            .output()?;
        if !version.status.success()
            || !String::from_utf8_lossy(&version.stdout).contains("uv 0.11.26")
        {
            return Err(HttpWorkbenchError::WorkerContract);
        }
        let mut command = Command::new(uv);
        command
            .args(["sync", "--project"])
            .arg(&destination)
            .args(["--locked", "--python", "3.12.13"])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for name in [
            "HOME",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        if !command.status()?.success() {
            return Err(HttpWorkbenchError::WorkerContract);
        }
    }
    let python = fs::canonicalize(destination.join(".venv/bin/python"))?;
    let mut permissions = fs::metadata(&python)?.permissions();
    permissions.set_mode(permissions.mode() & !0o022);
    fs::set_permissions(python, permissions)?;
    let output = Command::new(destination.join(".venv/bin/mitmdump"))
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout).contains("Mitmproxy: 12.2.3")
    {
        return Err(HttpWorkbenchError::WorkerContract);
    }
    fs::canonicalize(destination).map_err(Into::into)
}

fn copy_private_tree(source: &Path, destination: &Path) -> Result<(), HttpWorkbenchError> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(HttpWorkbenchError::WorkerContract);
    }
    create_private_directory(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_symlink() {
            return Err(HttpWorkbenchError::WorkerContract);
        }
        if metadata.is_dir() {
            copy_private_tree(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            copy_private_file(&source_path, &destination_path)?;
        } else {
            return Err(HttpWorkbenchError::WorkerContract);
        }
    }
    Ok(())
}

fn copy_private_file(source: &Path, destination: &Path) -> Result<(), HttpWorkbenchError> {
    if destination.exists() || !fs::symlink_metadata(source)?.is_file() {
        return Err(HttpWorkbenchError::WorkerContract);
    }
    fs::copy(source, destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn find_uv_program() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("FLAGDECK_UV_PROGRAM") {
        let path = PathBuf::from(explicit);
        if path.is_absolute() && path.is_file() {
            return Some(path);
        }
    }
    std::env::var_os("PATH").and_then(|value| {
        std::env::split_paths(&value)
            .map(|directory| directory.join("uv"))
            .find(|path| path.is_file())
    })
}

fn proxy_adapter_host(worker_root: &Path) -> Result<AdapterHost, HttpWorkbenchError> {
    let worker_root = fs::canonicalize(worker_root)?;
    let python = worker_root.join(".venv/bin/python");
    let mut config = AdapterHostConfig::new(python, &worker_root);
    config.arguments = vec![
        worker_root
            .join("src/flagdeck_mitm/adapter.py")
            .to_string_lossy()
            .into_owned(),
    ];
    config.control_transport = ControlTransport::UnixSocketPair;
    config.request_timeout = PROXY_READY_TIMEOUT;
    AdapterHost::new(config).map_err(Into::into)
}

async fn launch_proxy_worker(
    layout: &WorkspaceLayout,
    session_runtime: &Path,
    worker_root: &Path,
    request: &StartProxyRequest,
    session_id: &ProxySessionId,
) -> Result<(AdapterWorker, u16, i32, PathBuf, PathBuf), HttpWorkbenchError> {
    let host = proxy_adapter_host(worker_root)?;
    let mut last_error = HttpWorkbenchError::WorkerContract;
    for attempt in 0..5 {
        let listen_port = select_loopback_port()?;
        let attempt_root = session_runtime.join(format!("attempt-{attempt}"));
        let capture_root = attempt_root.join("proxy-staging");
        create_private_directory(&capture_root)?;
        let events_file = attempt_root.join("events.jsonl");
        let mut worker = match host.spawn() {
            Ok(worker) => worker,
            Err(error) => {
                last_error = error.into();
                continue;
            }
        };
        let result = async {
            adapter_call(
                &mut worker,
                "initialize",
                session_id,
                json!({
                    "protocol": ADAPTER_PROTOCOL,
                    "project_id": request.project_id.0,
                    "project_root": layout.root,
                    "capabilities": ["http.proxy", "http.streaming_capture"],
                    "permissions": {
                        "network": ["scope-bound"],
                        "project_artifacts": "write-staging-only",
                        "secrets": "none"
                    }
                }),
            )
            .await?;
            let result = adapter_call(
                &mut worker,
                "start",
                session_id,
                json!({
                    "listen_host": "127.0.0.1",
                    "listen_port": listen_port,
                    "confdir": layout.mitm_confdir,
                    "capture_root": capture_root,
                    "events_file": events_file,
                    "capture_mode": capture_mode_value(request.capture_mode),
                    "ssl_insecure": request.ssl_insecure
                }),
            )
            .await?;
            let proxy_pid = result
                .get("proxy_pid")
                .and_then(Value::as_i64)
                .and_then(|value| i32::try_from(value).ok())
                .filter(|value| *value > 1)
                .ok_or(HttpWorkbenchError::WorkerContract)?;
            verify_listener_ownership(proxy_pid, listen_port)?;
            Ok::<_, HttpWorkbenchError>(proxy_pid)
        }
        .await;
        match result {
            Ok(proxy_pid) => {
                return Ok((worker, listen_port, proxy_pid, events_file, capture_root));
            }
            Err(error) => {
                last_error = error;
                let _ = worker.shutdown().await;
            }
        }
    }
    Err(last_error)
}

async fn adapter_call(
    worker: &mut AdapterWorker,
    method: &str,
    session_id: &ProxySessionId,
    params: Value,
) -> Result<Value, HttpWorkbenchError> {
    let deadline = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HttpWorkbenchError::WorkerContract)?
        .as_millis()
        .saturating_add(PROXY_READY_TIMEOUT.as_millis());
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_owned(),
        id: Uuid::new_v4().to_string(),
        method: method.to_owned(),
        metadata: RequestMetadata {
            core_job_id: session_id.0.clone(),
            adapter_job_id: Some(session_id.0.clone()),
            idempotency_key: format!("{}-{method}", session_id.0),
            deadline_unix_millis: deadline.to_string(),
        },
        params,
    };
    let response = worker.request(&request).await?;
    response.result.ok_or(HttpWorkbenchError::WorkerContract)
}

fn capture_mode_value(mode: ProxyCaptureMode) -> &'static str {
    match mode {
        ProxyCaptureMode::PassThrough => "pass-through",
        ProxyCaptureMode::EvidenceStrict => "evidence-strict",
    }
}

fn select_loopback_port() -> Result<u16, HttpWorkbenchError> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn verify_listener_ownership(pid: i32, port: u16) -> Result<(), HttpWorkbenchError> {
    let mut connected = false;
    for _ in 0..20 {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}")
                .parse()
                .map_err(|_| HttpWorkbenchError::WorkerContract)?,
            Duration::from_millis(100),
        )
        .is_ok()
        {
            connected = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !connected || !process_owns_listener(pid, port)? {
        return Err(HttpWorkbenchError::WorkerContract);
    }
    Ok(())
}

fn process_owns_listener(pid: i32, port: u16) -> Result<bool, HttpWorkbenchError> {
    let expected_port = format!("{port:04X}");
    let table = fs::read_to_string("/proc/net/tcp")?;
    let inodes = table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.len() > 9
                && fields[1].starts_with("0100007F:")
                && fields[1].ends_with(&expected_port)
                && fields[3] == "0A")
                .then(|| fields[9].to_owned())
        })
        .collect::<Vec<_>>();
    if inodes.is_empty() {
        return Ok(false);
    }
    let descriptors = fs::read_dir(format!("/proc/{pid}/fd"))?;
    for descriptor in descriptors {
        if let Ok(target) = fs::read_link(descriptor?.path()) {
            let target = target.to_string_lossy();
            if inodes
                .iter()
                .any(|inode| target == format!("socket:[{inode}]"))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn wait_for_project_ca(confdir: &Path) -> Result<PathBuf, HttpWorkbenchError> {
    let ca = confdir.join("mitmproxy-ca-cert.pem");
    for _ in 0..100 {
        if ca.is_file() && fs::metadata(&ca)?.len() > 0 {
            return Ok(ca);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(HttpWorkbenchError::TrustStore)
}

fn certificate_sha256(path: &Path) -> Result<String, HttpWorkbenchError> {
    let output = Command::new(OPENSSL)
        .args(["x509", "-in"])
        .arg(path)
        .args(["-outform", "DER"])
        .env_clear()
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() || output.stdout.is_empty() {
        return Err(HttpWorkbenchError::TrustStore);
    }
    Ok(format!("{:x}", Sha256::digest(output.stdout)))
}

fn initialize_project_nss(
    browser_home: &Path,
    project_id: &ProjectId,
    ca_path: &Path,
    ca_sha256: &str,
) -> Result<PathBuf, HttpWorkbenchError> {
    let database = browser_home.join(".local/share/pki/nssdb");
    create_private_directory(&database)?;
    let database_arg = format!("sql:{}", database.display());
    if !database.join("cert9.db").is_file() {
        checked_command(
            CERTUTIL,
            &["-N", "-d", &database_arg, "--empty-password"],
            Some(browser_home),
        )?;
    }
    let nickname = format!("FlagDeck {}", project_id.0);
    let _ = Command::new(CERTUTIL)
        .args(["-D", "-d", &database_arg, "-n", &nickname])
        .env_clear()
        .env("HOME", browser_home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let status = Command::new(CERTUTIL)
        .args([
            "-A",
            "-d",
            &database_arg,
            "-n",
            &nickname,
            "-t",
            "C,,",
            "-i",
        ])
        .arg(ca_path)
        .env_clear()
        .env("HOME", browser_home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(HttpWorkbenchError::TrustStore);
    }
    let output = Command::new(CERTUTIL)
        .args(["-L", "-d", &database_arg, "-n", &nickname, "-a"])
        .env_clear()
        .env("HOME", browser_home)
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() || output.stdout.is_empty() {
        return Err(HttpWorkbenchError::TrustStore);
    }
    let verified_path = browser_home.join(".flagdeck-imported-ca.pem");
    fs::write(&verified_path, &output.stdout)?;
    fs::set_permissions(&verified_path, fs::Permissions::from_mode(0o600))?;
    let verified = certificate_sha256(&verified_path)?;
    fs::remove_file(verified_path)?;
    if verified != ca_sha256 {
        return Err(HttpWorkbenchError::TrustStore);
    }
    Ok(database)
}

fn checked_command(
    program: &str,
    arguments: &[&str],
    home: Option<&Path>,
) -> Result<(), HttpWorkbenchError> {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(home) = home {
        command.env("HOME", home);
    }
    if !command.status()?.success() {
        return Err(HttpWorkbenchError::TrustStore);
    }
    Ok(())
}

fn launch_project_chrome(
    browser_home: &Path,
    browser_profile: &Path,
    proxy_port: u16,
    include_loopback: bool,
) -> Result<i32, HttpWorkbenchError> {
    create_private_directory(browser_home)?;
    create_private_directory(browser_profile)?;
    let mut command = Command::new(SETSID);
    command
        .arg(CHROME)
        .arg(format!("--user-data-dir={}", browser_profile.display()))
        .arg(format!("--proxy-server=http://127.0.0.1:{proxy_port}"))
        .args([
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
        ])
        .env_clear()
        .env("HOME", browser_home)
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if include_loopback {
        command.arg("--proxy-bypass-list=<-loopback>");
    }
    apply_desktop_environment(&mut command);
    let child = command.spawn()?;
    let process_group =
        i32::try_from(child.id()).map_err(|_| HttpWorkbenchError::WorkerContract)?;
    for _ in 0..40 {
        if killpg(Pid::from_raw(process_group), None::<Signal>).is_ok() {
            return Ok(process_group);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(HttpWorkbenchError::WorkerContract)
}

fn apply_desktop_environment(command: &mut Command) {
    for name in [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
}

fn stop_process_group(process_group: i32) {
    let group = Pid::from_raw(process_group);
    let _ = killpg(group, Signal::SIGTERM);
    std::thread::sleep(Duration::from_millis(500));
    let _ = killpg(group, Signal::SIGKILL);
}

fn scope_explicitly_includes_loopback(scope: &TargetScope) -> bool {
    scope.exact_hosts.iter().any(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    }) || scope
        .cidrs
        .iter()
        .any(|cidr| cidr.starts_with("127.") || cidr.eq_ignore_ascii_case("::1/128"))
}

fn create_private_directory(path: &Path) -> Result<(), HttpWorkbenchError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(HttpWorkbenchError::WorkerContract);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

async fn sync_active_proxy(
    active: &mut ActiveProxy,
    store: &ProjectStore,
) -> Result<usize, HttpWorkbenchError> {
    let mut imported = 0;
    for _ in 0..1_000 {
        let result = adapter_call(
            &mut active.worker,
            "snapshot",
            &active.session.proxy_session_id,
            json!({"after_sequence": active.last_event_sequence}),
        )
        .await?;
        let events = result
            .get("events")
            .and_then(Value::as_array)
            .ok_or(HttpWorkbenchError::WorkerContract)?;
        imported +=
            ingest_proxy_event_values(store, &active.session, events, &active.capture_root)?;
        let last_sequence = result
            .get("last_sequence")
            .and_then(Value::as_u64)
            .filter(|sequence| *sequence >= active.last_event_sequence)
            .ok_or(HttpWorkbenchError::WorkerContract)?;
        active.last_event_sequence = last_sequence;
        if result.get("has_more").and_then(Value::as_bool) != Some(true) {
            return Ok(imported);
        }
    }
    Err(HttpWorkbenchError::WorkerContract)
}

#[derive(Debug, Deserialize)]
struct ProxyHttpEvent {
    event: String,
    #[serde(rename = "sequence")]
    _sequence: u64,
    timestamp_unix_ns: u128,
    flow_id: String,
    direction: String,
    method: Option<String>,
    status_code: Option<u16>,
    scheme: String,
    host: String,
    port: u16,
    authority: String,
    path: String,
    http_version: String,
    headers: Vec<OrderedValue>,
    trailers: Vec<OrderedValue>,
    query: Vec<OrderedValue>,
    form: Vec<OrderedValue>,
    body_state: String,
    declared_length: Option<u64>,
    actual_length: u64,
    captured_length: u64,
    content_encoding: Option<String>,
    body_path: Option<String>,
    body_sha256: Option<String>,
    duration_millis: Option<u64>,
    connection: ConnectionMetadata,
    representation_kind: String,
    serializer_version: String,
}

fn ingest_proxy_events(
    store: &ProjectStore,
    session: &ProxySession,
    events_file: &Path,
    capture_root: &Path,
) -> Result<usize, HttpWorkbenchError> {
    if !events_file.is_file() {
        return Ok(0);
    }
    let reader = BufReader::new(File::open(events_file)?);
    let mut imported = 0;
    for line in reader.lines() {
        let line = line?;
        if line.len() > MAX_EVENT_LINE_BYTES {
            return Err(HttpWorkbenchError::WorkerContract);
        }
        let value: Value = serde_json::from_str(&line)?;
        if value.get("event").and_then(Value::as_str) != Some("http_message") {
            continue;
        }
        imported += ingest_proxy_event_values(store, session, &[value], capture_root)?;
    }
    Ok(imported)
}

fn ingest_proxy_event_values(
    store: &ProjectStore,
    session: &ProxySession,
    values: &[Value],
    capture_root: &Path,
) -> Result<usize, HttpWorkbenchError> {
    let mut imported = 0;
    for value in values {
        let event: ProxyHttpEvent = serde_json::from_value(value.clone())?;
        if event.event != "http_message"
            || event.representation_kind != "semantic"
            || event.flow_id.is_empty()
            || event.flow_id.len() > 96
        {
            return Err(HttpWorkbenchError::WorkerContract);
        }
        let direction = match event.direction.as_str() {
            "request" => MessageDirection::Request,
            "response" => MessageDirection::Response,
            _ => return Err(HttpWorkbenchError::WorkerContract),
        };
        let stable_key = format!(
            "flagdeck://proxy/{}/{}/{}",
            session.proxy_session_id.0, event.flow_id, event.direction
        );
        let message_id =
            MessageId(Uuid::new_v5(&Uuid::NAMESPACE_URL, stable_key.as_bytes()).to_string());
        if store.http_message(&message_id).is_ok() {
            continue;
        }
        let sensitivity = message_sensitivity(&event.headers);
        let body_artifact_id =
            import_captured_body(store, &message_id, &event, capture_root, sensitivity)?;
        let redacted_view = redacted_http_view(
            event.method.as_deref(),
            event.status_code,
            &event.headers,
            &event.host,
            &event.path,
        );
        let message = HttpMessage {
            message_id,
            project_id: session.project_id.clone(),
            exchange_id: Some(format!("{}:{}", session.proxy_session_id.0, event.flow_id)),
            parent_message_id: None,
            source: HttpSource::Proxy,
            representation_kind: RepresentationKind::Semantic,
            method: event.method,
            status_code: event.status_code,
            scheme: event.scheme,
            host: event.host.to_ascii_lowercase(),
            port: event.port,
            authority: event.authority,
            path: event.path,
            http_version: event.http_version,
            headers: event.headers,
            trailers: event.trailers,
            query: event.query,
            form: event.form,
            body_inline: None,
            body_artifact_id,
            wire_artifact_id: None,
            serializer_version: event.serializer_version,
            body_state: parse_body_state(&event.body_state)?,
            declared_length: event.declared_length,
            actual_length: event.actual_length,
            content_encoding: event.content_encoding,
            decoded_preview_state: "not_requested:limit=8388608,ratio=100".to_owned(),
            direction,
            observed_at: Timestamp(event.timestamp_unix_ns.to_string()),
            duration_millis: event.duration_millis,
            connection: event.connection,
            sensitivity,
            redacted_view,
        };
        store.save_http_message(&message)?;
        imported += 1;
    }
    Ok(imported)
}

fn import_captured_body(
    store: &ProjectStore,
    message_id: &MessageId,
    event: &ProxyHttpEvent,
    capture_root: &Path,
    sensitivity: Sensitivity,
) -> Result<Option<ArtifactId>, HttpWorkbenchError> {
    let Some(path) = event.body_path.as_deref() else {
        return Ok(None);
    };
    let path = fs::canonicalize(path)?;
    let capture_root = fs::canonicalize(capture_root)?;
    if !path.starts_with(&capture_root) || !path.is_file() {
        return Err(HttpWorkbenchError::WorkerContract);
    }
    let expected_hash = event
        .body_sha256
        .as_ref()
        .filter(|hash| hash.len() == 64)
        .cloned()
        .ok_or(HttpWorkbenchError::WorkerContract)?;
    let artifact = store.commit_artifact(
        &ArtifactWriteRequest {
            logical_name: format!("http-body-{}.bin", message_id.0),
            mime: "application/octet-stream".to_owned(),
            sensitivity,
            export_policy: if sensitivity == Sensitivity::Normal {
                ExportPolicy::Include
            } else {
                ExportPolicy::ConfirmSensitive
            },
            source_job_id: None,
            source_message_id: Some(message_id.clone()),
            expected_size: Some(event.captured_length),
            expected_sha256: Some(expected_hash),
        },
        File::open(path)?,
    )?;
    Ok(Some(artifact.artifact_id))
}

fn parse_body_state(value: &str) -> Result<BodyState, HttpWorkbenchError> {
    match value {
        "complete" => Ok(BodyState::Complete),
        "streamed_complete" => Ok(BodyState::StreamedComplete),
        "truncated" => Ok(BodyState::Truncated),
        "missing" => Ok(BodyState::Missing),
        "capture_failed" => Ok(BodyState::CaptureFailed),
        _ => Err(HttpWorkbenchError::WorkerContract),
    }
}

fn message_sensitivity(headers: &[OrderedValue]) -> Sensitivity {
    if headers.iter().any(|header| {
        matches!(
            header.name.to_ascii_lowercase().as_str(),
            "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key"
        )
    }) {
        Sensitivity::SensitiveEvidence
    } else {
        Sensitivity::Normal
    }
}

fn redacted_http_view(
    method: Option<&str>,
    status: Option<u16>,
    headers: &[OrderedValue],
    host: &str,
    path: &str,
) -> String {
    let mut lines = vec![format!(
        "{} {}{} {}",
        method.unwrap_or("RESPONSE"),
        host,
        path,
        status.map_or_else(String::new, |value| value.to_string())
    )];
    lines.extend(headers.iter().map(|header| {
        if matches!(
            header.name.to_ascii_lowercase().as_str(),
            "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key"
        ) {
            format!("{}: <redacted>", header.name)
        } else {
            format!("{}: {}", header.name, header.value)
        }
    }));
    lines.join("\n")
}

pub(crate) async fn list_history(
    workbench: &HttpWorkbench,
    store: Arc<ProjectStore>,
    request: &HttpHistoryPageRequest,
) -> Result<HttpHistoryPage, HttpWorkbenchError> {
    let imported_events = workbench.ingest_active(&store, &request.project_id).await?;
    let filter = HttpMessageFilter {
        query: request.query.clone(),
        source: request.source,
        direction: request.direction,
        host: request.host.clone(),
        status_code: request.status_code,
    };
    let (items, next_cursor) =
        store.list_http_messages(request.limit, request.cursor.as_deref(), &filter)?;
    Ok(HttpHistoryPage {
        items,
        next_cursor,
        imported_events,
    })
}

pub(crate) fn repeat_http_message(
    store: &ProjectStore,
    scope: &TargetScope,
    request: &RepeatHttpRequest,
) -> Result<RepeatHttpResult, HttpWorkbenchError> {
    if request.body.len() as u64 > MAX_HTTP_BODY_BYTES {
        return Err(HttpWorkbenchError::InvalidRequest);
    }
    let parent = store.http_message(&request.parent_message_id)?;
    if parent.project_id != request.project_id
        || parent.direction != MessageDirection::Request
        || parent.representation_kind != RepresentationKind::Semantic
        || scope.scope_id != request.scope_id
    {
        return Err(HttpWorkbenchError::InvalidRequest);
    }
    let (wire, normalized_headers) = serialize_semantic_request(
        &request.method,
        &request.path,
        &parent.authority,
        &request.headers,
        &request.body,
    )?;
    let mut connection = connect_scoped(
        scope,
        &parent.scheme,
        &parent.host,
        parent.port,
        request.ssl_insecure,
    )?;
    let exchange_id = Uuid::new_v4().to_string();
    let started = Instant::now();
    connection.stream.write_all(&wire)?;
    connection.stream.flush()?;
    let parsed = read_http_response(&mut connection.stream)?;
    let duration = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let sensitivity = message_sensitivity(&normalized_headers);
    let request_message_id = MessageId::new();
    let (request_inline, request_artifact) = persist_semantic_body(
        store,
        &request_message_id,
        &request.body,
        sensitivity,
        "repeater-request-body",
    )?;
    let request_message = HttpMessage {
        message_id: request_message_id,
        project_id: request.project_id.clone(),
        exchange_id: Some(exchange_id.clone()),
        parent_message_id: Some(request.parent_message_id.clone()),
        source: HttpSource::Repeater,
        representation_kind: RepresentationKind::Semantic,
        method: Some(request.method.clone()),
        status_code: None,
        scheme: parent.scheme.clone(),
        host: parent.host.clone(),
        port: parent.port,
        authority: parent.authority.clone(),
        path: request.path.clone(),
        http_version: "HTTP/1.1".to_owned(),
        headers: normalized_headers.clone(),
        trailers: Vec::new(),
        query: query_values(&request.path),
        form: Vec::new(),
        body_inline: request_inline,
        body_artifact_id: request_artifact,
        wire_artifact_id: None,
        serializer_version: "flagdeck.semantic-http1/1".to_owned(),
        body_state: if request.body.is_empty() {
            BodyState::Missing
        } else {
            BodyState::Complete
        },
        declared_length: (!request.body.is_empty())
            .then(|| u64::try_from(request.body.len()).unwrap_or(u64::MAX)),
        actual_length: u64::try_from(request.body.len()).unwrap_or(u64::MAX),
        content_encoding: header_value(&normalized_headers, "content-encoding"),
        decoded_preview_state: "not_requested:limit=8388608,ratio=100".to_owned(),
        direction: MessageDirection::Request,
        observed_at: Timestamp::now(),
        duration_millis: None,
        connection: ConnectionMetadata {
            client_address: None,
            server_address: Some(connection.peer.to_string()),
            tls: connection.tls,
            tls_version: None,
            certificate_sha256: None,
        },
        sensitivity,
        redacted_view: redacted_http_view(
            Some(&request.method),
            None,
            &normalized_headers,
            &parent.host,
            &request.path,
        ),
    };
    store.save_http_message(&request_message)?;

    let response_message_id = MessageId::new();
    let response_sensitivity = message_sensitivity(&parsed.headers);
    let (response_inline, response_artifact) = persist_semantic_body(
        store,
        &response_message_id,
        &parsed.body,
        response_sensitivity,
        "repeater-response-body",
    )?;
    let response_message = HttpMessage {
        message_id: response_message_id,
        project_id: request.project_id.clone(),
        exchange_id: Some(exchange_id),
        parent_message_id: None,
        source: HttpSource::Repeater,
        representation_kind: RepresentationKind::Semantic,
        method: None,
        status_code: Some(parsed.status_code),
        scheme: parent.scheme,
        host: parent.host.clone(),
        port: parent.port,
        authority: parent.authority,
        path: request.path.clone(),
        http_version: parsed.http_version,
        headers: parsed.headers.clone(),
        trailers: parsed.trailers,
        query: query_values(&request.path),
        form: Vec::new(),
        body_inline: response_inline,
        body_artifact_id: response_artifact,
        wire_artifact_id: None,
        serializer_version: "flagdeck.semantic-http1/1".to_owned(),
        body_state: parsed.body_state,
        declared_length: parsed.declared_length,
        actual_length: u64::try_from(parsed.body.len()).unwrap_or(u64::MAX),
        content_encoding: header_value(&parsed.headers, "content-encoding"),
        decoded_preview_state: "not_requested:limit=8388608,ratio=100".to_owned(),
        direction: MessageDirection::Response,
        observed_at: Timestamp::now(),
        duration_millis: Some(duration),
        connection: ConnectionMetadata {
            client_address: None,
            server_address: Some(connection.peer.to_string()),
            tls: connection.tls,
            tls_version: None,
            certificate_sha256: None,
        },
        sensitivity: response_sensitivity,
        redacted_view: redacted_http_view(
            None,
            Some(parsed.status_code),
            &parsed.headers,
            &parent.host,
            &request.path,
        ),
    };
    store.save_http_message(&response_message)?;
    Ok(RepeatHttpResult {
        request: request_message,
        response: response_message,
        serialized_request_sha256: format!("{:x}", Sha256::digest(&wire)),
    })
}

pub(crate) fn diff_http_messages(
    store: &ProjectStore,
    request: &DiffHttpMessagesRequest,
) -> Result<HttpMessageDiff, HttpWorkbenchError> {
    let left = store.http_message(&request.left_message_id)?;
    let right = store.http_message(&request.right_message_id)?;
    if left.project_id != request.project_id || right.project_id != request.project_id {
        return Err(HttpWorkbenchError::InvalidRequest);
    }
    let left_body = message_body(store, &left)?;
    let right_body = message_body(store, &right)?;
    let left_text = std::str::from_utf8(&left_body).ok();
    let right_text = std::str::from_utf8(&right_body).ok();
    let text_changes = match (left_text, right_text) {
        (Some(left), Some(right)) => text_line_changes(left, right),
        _ => Vec::new(),
    };
    Ok(HttpMessageDiff {
        headers: value_differences(&left.headers, &right.headers),
        parameters: value_differences(
            &left
                .query
                .iter()
                .chain(&left.form)
                .cloned()
                .collect::<Vec<_>>(),
            &right
                .query
                .iter()
                .chain(&right.form)
                .cloned()
                .collect::<Vec<_>>(),
        ),
        body: HttpBodyDiff {
            kind: if left_text.is_some() && right_text.is_some() {
                "text".to_owned()
            } else {
                "binary_digest".to_owned()
            },
            left_sha256: format!("{:x}", Sha256::digest(&left_body)),
            right_sha256: format!("{:x}", Sha256::digest(&right_body)),
            left_length: u64::try_from(left_body.len()).unwrap_or(u64::MAX),
            right_length: u64::try_from(right_body.len()).unwrap_or(u64::MAX),
            text_changes,
        },
        duration_delta_millis: match (left.duration_millis, right.duration_millis) {
            (Some(left), Some(right)) => Some(
                i64::try_from(right)
                    .unwrap_or(i64::MAX)
                    .saturating_sub(i64::try_from(left).unwrap_or(i64::MAX)),
            ),
            _ => None,
        },
    })
}

pub(crate) fn create_sqlmap_request_file(
    store: &ProjectStore,
    request: &CreateSqlmapRequestFileRequest,
) -> Result<Artifact, HttpWorkbenchError> {
    let message = store.http_message(&request.message_id)?;
    if message.project_id != request.project_id
        || message.direction != MessageDirection::Request
        || message.representation_kind != RepresentationKind::Semantic
        || (message.sensitivity != Sensitivity::Normal && !request.confirm_sensitive)
    {
        return Err(HttpWorkbenchError::InvalidRequest);
    }
    let body = message_body(store, &message)?;
    let (wire, _) = serialize_semantic_request(
        message.method.as_deref().unwrap_or("GET"),
        &message.path,
        &message.authority,
        &message.headers,
        &body,
    )?;
    let sensitivity = message.sensitivity;
    store
        .commit_artifact(
            &ArtifactWriteRequest {
                logical_name: format!("sqlmap-request-{}.txt", message.message_id.0),
                mime: "application/http; msgtype=request".to_owned(),
                sensitivity,
                export_policy: if sensitivity == Sensitivity::Normal {
                    ExportPolicy::Include
                } else {
                    ExportPolicy::ConfirmSensitive
                },
                source_job_id: None,
                source_message_id: Some(message.message_id),
                expected_size: Some(u64::try_from(wire.len()).unwrap_or(u64::MAX)),
                expected_sha256: Some(format!("{:x}", Sha256::digest(&wire))),
            },
            wire.as_slice(),
        )
        .map_err(Into::into)
}

pub(crate) fn send_raw_http1(
    store: &ProjectStore,
    scope: &TargetScope,
    request: &SendRawHttp1Request,
) -> Result<SendRawHttp1Result, HttpWorkbenchError> {
    if request.wire_bytes.is_empty()
        || request.wire_bytes.len() as u64 > MAX_HTTP_BODY_BYTES
        || request.host.trim() != request.host
        || request.host.is_empty()
    {
        return Err(HttpWorkbenchError::InvalidRequest);
    }
    let scheme = if request.tls { "https" } else { "http" };
    let mut connection = connect_scoped(
        scope,
        scheme,
        &request.host,
        request.port,
        request.ssl_insecure,
    )?;
    let started = Instant::now();
    connection.stream.write_all(&request.wire_bytes)?;
    connection.stream.flush()?;
    let response_wire = read_raw_bounded(&mut connection.stream)?;
    let duration = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let exchange_id = Uuid::new_v4().to_string();
    let (method, path, request_headers) = best_effort_request_metadata(&request.wire_bytes);
    let sensitivity = raw_sensitivity(&request.wire_bytes);
    let request_message_id = MessageId::new();
    let request_wire_artifact = commit_wire_artifact(
        store,
        &request_message_id,
        "raw-http1-request",
        &request.wire_bytes,
        sensitivity,
    )?;
    let request_message = HttpMessage {
        message_id: request_message_id,
        project_id: request.project_id.clone(),
        exchange_id: Some(exchange_id.clone()),
        parent_message_id: None,
        source: HttpSource::Repeater,
        representation_kind: RepresentationKind::RawHttp1,
        method,
        status_code: None,
        scheme: scheme.to_owned(),
        host: request.host.to_ascii_lowercase(),
        port: request.port,
        authority: authority(&request.host, request.port, request.tls),
        path: path.clone(),
        http_version: "HTTP/1.x raw".to_owned(),
        headers: request_headers.clone(),
        trailers: Vec::new(),
        query: query_values(&path),
        form: Vec::new(),
        body_inline: None,
        body_artifact_id: None,
        wire_artifact_id: Some(request_wire_artifact),
        serializer_version: "flagdeck.raw-http1/1".to_owned(),
        body_state: BodyState::Missing,
        declared_length: None,
        actual_length: 0,
        content_encoding: None,
        decoded_preview_state: "raw_wire_only".to_owned(),
        direction: MessageDirection::Request,
        observed_at: Timestamp::now(),
        duration_millis: None,
        connection: ConnectionMetadata {
            client_address: None,
            server_address: Some(connection.peer.to_string()),
            tls: connection.tls,
            tls_version: None,
            certificate_sha256: None,
        },
        sensitivity,
        redacted_view: redacted_http_view(None, None, &request_headers, &request.host, &path),
    };
    store.save_http_message(&request_message)?;

    let (status_code, response_headers) = best_effort_response_metadata(&response_wire);
    let response_sensitivity = raw_sensitivity(&response_wire);
    let response_message_id = MessageId::new();
    let response_wire_artifact = commit_wire_artifact(
        store,
        &response_message_id,
        "raw-http1-response",
        &response_wire,
        response_sensitivity,
    )?;
    let response_message = HttpMessage {
        message_id: response_message_id,
        project_id: request.project_id.clone(),
        exchange_id: Some(exchange_id),
        parent_message_id: None,
        source: HttpSource::Repeater,
        representation_kind: RepresentationKind::RawHttp1,
        method: None,
        status_code,
        scheme: scheme.to_owned(),
        host: request.host.to_ascii_lowercase(),
        port: request.port,
        authority: authority(&request.host, request.port, request.tls),
        path,
        http_version: "HTTP/1.x raw".to_owned(),
        headers: response_headers.clone(),
        trailers: Vec::new(),
        query: Vec::new(),
        form: Vec::new(),
        body_inline: None,
        body_artifact_id: None,
        wire_artifact_id: Some(response_wire_artifact),
        serializer_version: "flagdeck.raw-http1/1".to_owned(),
        body_state: BodyState::Missing,
        declared_length: None,
        actual_length: 0,
        content_encoding: None,
        decoded_preview_state: "raw_wire_only".to_owned(),
        direction: MessageDirection::Response,
        observed_at: Timestamp::now(),
        duration_millis: Some(duration),
        connection: ConnectionMetadata {
            client_address: None,
            server_address: Some(connection.peer.to_string()),
            tls: connection.tls,
            tls_version: None,
            certificate_sha256: None,
        },
        sensitivity: response_sensitivity,
        redacted_view: redacted_http_view(
            None,
            status_code,
            &response_headers,
            &request.host,
            "raw-response",
        ),
    };
    store.save_http_message(&response_message)?;
    Ok(SendRawHttp1Result {
        request: request_message,
        response: response_message,
    })
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

struct ScopedConnection {
    stream: Box<dyn ReadWrite>,
    peer: SocketAddr,
    tls: bool,
}

fn connect_scoped(
    scope: &TargetScope,
    scheme: &str,
    host: &str,
    port: u16,
    ssl_insecure: bool,
) -> Result<ScopedConnection, HttpWorkbenchError> {
    let host = host.to_ascii_lowercase();
    if !matches!(scheme, "http" | "https")
        || !scope.schemes.iter().any(|value| value == scheme)
        || !scope.exact_hosts.iter().any(|value| value == &host)
        || !scope
            .ports
            .iter()
            .any(|range| range.start <= port && port <= range.end)
        || scope.dns_change_policy != "deny"
    {
        return Err(HttpWorkbenchError::ScopeViolation);
    }
    let expected = scope
        .dns_snapshots
        .iter()
        .rev()
        .find(|snapshot| snapshot.host == host)
        .ok_or(HttpWorkbenchError::ScopeViolation)?
        .addresses
        .iter()
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|_| HttpWorkbenchError::ScopeViolation)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let current = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| HttpWorkbenchError::ScopeViolation)?
        .map(|address| address.ip())
        .collect::<BTreeSet<_>>();
    if current.is_empty() || current != expected {
        return Err(HttpWorkbenchError::ScopeViolation);
    }
    let mut connected = None;
    for address in &expected {
        let socket = SocketAddr::new(*address, port);
        if let Ok(stream) = TcpStream::connect_timeout(&socket, Duration::from_secs(5)) {
            connected = Some(stream);
            break;
        }
    }
    let stream = connected.ok_or(HttpWorkbenchError::ScopeViolation)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let peer = stream.peer_addr()?;
    if !expected.contains(&peer.ip()) {
        return Err(HttpWorkbenchError::ScopeViolation);
    }
    if scheme == "https" {
        let mut builder = TlsConnector::builder();
        builder.danger_accept_invalid_certs(ssl_insecure);
        let connector = builder
            .build()
            .map_err(|_| HttpWorkbenchError::WorkerContract)?;
        let tls = connector
            .connect(&host, stream)
            .map_err(|_| HttpWorkbenchError::WorkerContract)?;
        Ok(ScopedConnection {
            stream: Box::new(tls),
            peer,
            tls: true,
        })
    } else {
        Ok(ScopedConnection {
            stream: Box::new(stream),
            peer,
            tls: false,
        })
    }
}

fn serialize_semantic_request(
    method: &str,
    path: &str,
    authority: &str,
    headers: &[OrderedValue],
    body: &[u8],
) -> Result<(Vec<u8>, Vec<OrderedValue>), HttpWorkbenchError> {
    if !valid_http_token(method)
        || path.is_empty()
        || path.len() > 64 * 1024
        || (!path.starts_with('/') && path != "*")
        || path.contains(['\r', '\n', '\0'])
        || authority.is_empty()
        || authority.contains(['\r', '\n', '\0'])
    {
        return Err(HttpWorkbenchError::InvalidRequest);
    }
    let mut normalized = Vec::new();
    for header in headers {
        if !valid_http_token(&header.name)
            || header.value.contains(['\r', '\n', '\0'])
            || header.value.len() > 64 * 1024
        {
            return Err(HttpWorkbenchError::InvalidRequest);
        }
        if matches!(
            header.name.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "transfer-encoding" | "connection"
        ) {
            continue;
        }
        normalized.push(header.clone());
    }
    normalized.push(OrderedValue {
        name: "Host".to_owned(),
        value: authority.to_owned(),
    });
    if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        normalized.push(OrderedValue {
            name: "Content-Length".to_owned(),
            value: body.len().to_string(),
        });
    }
    normalized.push(OrderedValue {
        name: "Connection".to_owned(),
        value: "close".to_owned(),
    });
    let header_bytes = normalized
        .iter()
        .try_fold(Vec::new(), |mut output, header| {
            output.extend_from_slice(header.name.as_bytes());
            output.extend_from_slice(b": ");
            output.extend_from_slice(header.value.as_bytes());
            output.extend_from_slice(b"\r\n");
            Ok::<_, HttpWorkbenchError>(output)
        })?;
    let capacity = method
        .len()
        .saturating_add(path.len())
        .saturating_add(header_bytes.len())
        .saturating_add(body.len())
        .saturating_add(32);
    let mut wire = Vec::with_capacity(capacity);
    write!(&mut wire, "{method} {path} HTTP/1.1\r\n")?;
    wire.extend_from_slice(&header_bytes);
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(body);
    Ok((wire, normalized))
}

fn valid_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

struct ParsedHttpResponse {
    http_version: String,
    status_code: u16,
    headers: Vec<OrderedValue>,
    trailers: Vec<OrderedValue>,
    body: Vec<u8>,
    body_state: BodyState,
    declared_length: Option<u64>,
}

fn read_http_response(
    stream: &mut Box<dyn ReadWrite>,
) -> Result<ParsedHttpResponse, HttpWorkbenchError> {
    let mut bytes = Vec::new();
    let head_end = loop {
        if let Some(index) = find_bytes(&bytes, b"\r\n\r\n") {
            break index + 4;
        }
        if bytes.len() >= MAX_HTTP_HEAD_BYTES {
            return Err(HttpWorkbenchError::WorkerContract);
        }
        let mut chunk = [0_u8; 8192];
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(HttpWorkbenchError::WorkerContract);
        }
        bytes.extend_from_slice(&chunk[..read]);
    };
    let head = std::str::from_utf8(&bytes[..head_end - 4])
        .map_err(|_| HttpWorkbenchError::WorkerContract)?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(HttpWorkbenchError::WorkerContract)?;
    let mut status_parts = status_line.splitn(3, ' ');
    let http_version = status_parts
        .next()
        .filter(|value| value.starts_with("HTTP/"))
        .ok_or(HttpWorkbenchError::WorkerContract)?
        .to_owned();
    let status_code = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| (100..=599).contains(value))
        .ok_or(HttpWorkbenchError::WorkerContract)?;
    let headers = parse_header_lines(lines)?;
    let declared_length =
        header_value(&headers, "content-length").and_then(|value| value.parse::<u64>().ok());
    let chunked = header_values(&headers, "transfer-encoding")
        .iter()
        .any(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
        });
    let mut transfer_body = bytes.split_off(head_end);
    loop {
        let complete = if chunked {
            chunked_transfer_complete(&transfer_body)
        } else if let Some(length) = declared_length {
            u64::try_from(transfer_body.len()).unwrap_or(u64::MAX) >= length
        } else {
            false
        };
        if complete {
            break;
        }
        if u64::try_from(transfer_body.len()).unwrap_or(u64::MAX) > MAX_HTTP_BODY_BYTES {
            return Err(HttpWorkbenchError::WorkerContract);
        }
        let mut chunk = vec![0_u8; 64 * 1024];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => transfer_body.extend_from_slice(&chunk[..read]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let (body, trailers, body_state) = if chunked {
        let (body, trailers, complete) = decode_chunked(&transfer_body)?;
        (
            body,
            trailers,
            if complete {
                BodyState::StreamedComplete
            } else {
                BodyState::Truncated
            },
        )
    } else if let Some(length) = declared_length {
        let expected = usize::try_from(length).map_err(|_| HttpWorkbenchError::WorkerContract)?;
        let complete = transfer_body.len() >= expected;
        transfer_body.truncate(expected.min(transfer_body.len()));
        (
            transfer_body,
            Vec::new(),
            if complete {
                BodyState::Complete
            } else {
                BodyState::Truncated
            },
        )
    } else {
        let state = if transfer_body.is_empty() {
            BodyState::Missing
        } else {
            BodyState::Complete
        };
        (transfer_body, Vec::new(), state)
    };
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > MAX_HTTP_BODY_BYTES {
        return Err(HttpWorkbenchError::WorkerContract);
    }
    Ok(ParsedHttpResponse {
        http_version,
        status_code,
        headers,
        trailers,
        body,
        body_state,
        declared_length,
    })
}

fn parse_header_lines<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> Result<Vec<OrderedValue>, HttpWorkbenchError> {
    lines
        .map(|line| {
            let (name, value) = line
                .split_once(':')
                .ok_or(HttpWorkbenchError::WorkerContract)?;
            if !valid_http_token(name) || value.contains(['\r', '\n', '\0']) {
                return Err(HttpWorkbenchError::WorkerContract);
            }
            Ok(OrderedValue {
                name: name.to_owned(),
                value: value.trim_start().to_owned(),
            })
        })
        .collect()
}

fn decode_chunked(input: &[u8]) -> Result<(Vec<u8>, Vec<OrderedValue>, bool), HttpWorkbenchError> {
    let mut cursor = 0;
    let mut body = Vec::new();
    loop {
        let Some(line_end_relative) = find_bytes(&input[cursor..], b"\r\n") else {
            return Ok((body, Vec::new(), false));
        };
        let line_end = cursor + line_end_relative;
        let size_text = std::str::from_utf8(&input[cursor..line_end])
            .map_err(|_| HttpWorkbenchError::WorkerContract)?
            .split(';')
            .next()
            .ok_or(HttpWorkbenchError::WorkerContract)?
            .trim();
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| HttpWorkbenchError::WorkerContract)?;
        cursor = line_end + 2;
        if size == 0 {
            let Some(trailer_end_relative) = find_bytes(&input[cursor..], b"\r\n\r\n") else {
                if input.get(cursor..cursor + 2) == Some(b"\r\n") {
                    return Ok((body, Vec::new(), true));
                }
                return Ok((body, Vec::new(), false));
            };
            let trailer_end = cursor + trailer_end_relative;
            let trailer_text = std::str::from_utf8(&input[cursor..trailer_end])
                .map_err(|_| HttpWorkbenchError::WorkerContract)?;
            let trailers = if trailer_text.is_empty() {
                Vec::new()
            } else {
                parse_header_lines(trailer_text.split("\r\n"))?
            };
            return Ok((body, trailers, true));
        }
        let data_end = cursor
            .checked_add(size)
            .ok_or(HttpWorkbenchError::WorkerContract)?;
        if data_end + 2 > input.len() {
            return Ok((body, Vec::new(), false));
        }
        body.extend_from_slice(&input[cursor..data_end]);
        if body.len() as u64 > MAX_HTTP_BODY_BYTES || &input[data_end..data_end + 2] != b"\r\n" {
            return Err(HttpWorkbenchError::WorkerContract);
        }
        cursor = data_end + 2;
    }
}

fn chunked_transfer_complete(input: &[u8]) -> bool {
    decode_chunked(input).is_ok_and(|(_, _, complete)| complete)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn header_values(headers: &[OrderedValue], name: &str) -> Vec<String> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.clone())
        .collect()
}

fn header_value(headers: &[OrderedValue], name: &str) -> Option<String> {
    headers
        .iter()
        .rev()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.clone())
}

fn query_values(path: &str) -> Vec<OrderedValue> {
    path.split_once('?').map_or_else(Vec::new, |(_, query)| {
        url::form_urlencoded::parse(query.as_bytes())
            .map(|(name, value)| OrderedValue {
                name: name.into_owned(),
                value: value.into_owned(),
            })
            .collect()
    })
}

fn persist_semantic_body(
    store: &ProjectStore,
    message_id: &MessageId,
    body: &[u8],
    sensitivity: Sensitivity,
    logical_prefix: &str,
) -> Result<(Option<Vec<u8>>, Option<ArtifactId>), HttpWorkbenchError> {
    if body.is_empty() {
        return Ok((None, None));
    }
    if body.len() <= flagdeck_domain::MAX_INLINE_BODY_BYTES {
        return Ok((Some(body.to_vec()), None));
    }
    let artifact = store.commit_artifact(
        &ArtifactWriteRequest {
            logical_name: format!("{logical_prefix}-{}.bin", message_id.0),
            mime: "application/octet-stream".to_owned(),
            sensitivity,
            export_policy: if sensitivity == Sensitivity::Normal {
                ExportPolicy::Include
            } else {
                ExportPolicy::ConfirmSensitive
            },
            source_job_id: None,
            source_message_id: Some(message_id.clone()),
            expected_size: Some(u64::try_from(body.len()).unwrap_or(u64::MAX)),
            expected_sha256: Some(format!("{:x}", Sha256::digest(body))),
        },
        body,
    )?;
    Ok((None, Some(artifact.artifact_id)))
}

pub(crate) fn message_body(
    store: &ProjectStore,
    message: &HttpMessage,
) -> Result<Vec<u8>, HttpWorkbenchError> {
    if let Some(body) = &message.body_inline {
        return Ok(body.clone());
    }
    if let Some(artifact_id) = &message.body_artifact_id {
        return store
            .read_artifact_bounded(artifact_id, MAX_HTTP_BODY_BYTES)
            .map_err(Into::into);
    }
    if message.representation_kind == RepresentationKind::RawHttp1
        && let Some(artifact_id) = &message.wire_artifact_id
    {
        return store
            .read_artifact_bounded(artifact_id, MAX_HTTP_BODY_BYTES)
            .map_err(Into::into);
    }
    Ok(Vec::new())
}

fn value_differences(left: &[OrderedValue], right: &[OrderedValue]) -> Vec<ValueDifference> {
    let group = |values: &[OrderedValue]| {
        let mut grouped = BTreeMap::<String, Vec<String>>::new();
        for value in values {
            grouped
                .entry(value.name.to_ascii_lowercase())
                .or_default()
                .push(value.value.clone());
        }
        grouped
    };
    let left = group(left);
    let right = group(right);
    left.keys()
        .chain(right.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|name| {
            let left_values = left.get(&name).cloned().unwrap_or_default();
            let right_values = right.get(&name).cloned().unwrap_or_default();
            (left_values != right_values).then_some(ValueDifference {
                name,
                left: left_values,
                right: right_values,
            })
        })
        .collect()
}

fn text_line_changes(left: &str, right: &str) -> Vec<String> {
    if left == right {
        return Vec::new();
    }
    let left_lines = left.lines().collect::<Vec<_>>();
    let right_lines = right.lines().collect::<Vec<_>>();
    let mut changes = Vec::new();
    for index in 0..left_lines.len().max(right_lines.len()).min(200) {
        match (left_lines.get(index), right_lines.get(index)) {
            (Some(left), Some(right)) if left == right => {}
            (Some(left), Some(right)) => {
                changes.push(format!("- {left}"));
                changes.push(format!("+ {right}"));
            }
            (Some(left), None) => changes.push(format!("- {left}")),
            (None, Some(right)) => changes.push(format!("+ {right}")),
            (None, None) => {}
        }
    }
    changes
}

fn read_raw_bounded(stream: &mut Box<dyn ReadWrite>) -> Result<Vec<u8>, HttpWorkbenchError> {
    let mut output = Vec::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                output.extend_from_slice(&buffer[..read]);
                if output.len() as u64 > MAX_HTTP_BODY_BYTES {
                    return Err(HttpWorkbenchError::WorkerContract);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(output)
}

fn best_effort_request_metadata(bytes: &[u8]) -> (Option<String>, String, Vec<OrderedValue>) {
    let head = find_bytes(bytes, b"\r\n\r\n").map_or(bytes, |index| &bytes[..index]);
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    let method = parts
        .next()
        .filter(|value| valid_http_token(value))
        .map(str::to_owned);
    let path = parts
        .next()
        .filter(|value| value.len() <= 64 * 1024)
        .unwrap_or("/")
        .to_owned();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, value)| valid_http_token(name) && !value.contains('\0'))
        .map(|(name, value)| OrderedValue {
            name: name.to_owned(),
            value: value.trim_start().to_owned(),
        })
        .collect();
    (method, path, headers)
}

fn best_effort_response_metadata(bytes: &[u8]) -> (Option<u16>, Vec<OrderedValue>) {
    let head = find_bytes(bytes, b"\r\n\r\n").map_or(bytes, |index| &bytes[..index]);
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| (100..=599).contains(value));
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, value)| valid_http_token(name) && !value.contains('\0'))
        .map(|(name, value)| OrderedValue {
            name: name.to_owned(),
            value: value.trim_start().to_owned(),
        })
        .collect();
    (status, headers)
}

fn raw_sensitivity(bytes: &[u8]) -> Sensitivity {
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    if [
        "authorization:",
        "proxy-authorization:",
        "cookie:",
        "set-cookie:",
        "x-api-key:",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        Sensitivity::SensitiveEvidence
    } else {
        Sensitivity::Normal
    }
}

fn commit_wire_artifact(
    store: &ProjectStore,
    message_id: &MessageId,
    prefix: &str,
    bytes: &[u8],
    sensitivity: Sensitivity,
) -> Result<ArtifactId, HttpWorkbenchError> {
    let artifact = store.commit_artifact(
        &ArtifactWriteRequest {
            logical_name: format!("{prefix}-{}.http", message_id.0),
            mime: "application/octet-stream".to_owned(),
            sensitivity,
            export_policy: if sensitivity == Sensitivity::Normal {
                ExportPolicy::Include
            } else {
                ExportPolicy::ConfirmSensitive
            },
            source_job_id: None,
            source_message_id: Some(message_id.clone()),
            expected_size: Some(u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
            expected_sha256: Some(format!("{:x}", Sha256::digest(bytes))),
        },
        bytes,
    )?;
    Ok(artifact.artifact_id)
}

fn authority(host: &str, port: u16, tls: bool) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if (tls && port == 443) || (!tls && port == 80) {
        host
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::mpsc;
    use std::thread;

    use flagdeck_domain::{DnsResolutionSnapshot, NetworkClass, PortRange, RedirectPolicy};
    use flagdeck_storage::OpenMode;

    use super::*;

    #[test]
    fn loopback_bypass_requires_explicit_loopback_host_or_cidr() {
        let mut scope: TargetScope = serde_json::from_value(json!({
            "scope_id": ScopeId::new(),
            "project_id": ProjectId::new(),
            "schemes": ["http"],
            "exact_hosts": ["example.test"],
            "wildcard_subdomains": [],
            "cidrs": [],
            "ports": [{"start": 80, "end": 80}],
            "redirect_policy": "deny",
            "dns_change_policy": "deny",
            "dns_snapshots": [],
            "network_class": "internet",
            "created_at": "1",
            "updated_at": "1"
        }))
        .unwrap();
        assert!(!scope_explicitly_includes_loopback(&scope));
        scope.exact_hosts = vec!["127.0.0.1".to_owned()];
        assert!(scope_explicitly_includes_loopback(&scope));
    }

    #[test]
    fn sensitive_headers_are_redacted_from_search_view() {
        let headers = vec![
            OrderedValue {
                name: "Authorization".to_owned(),
                value: "Bearer secret".to_owned(),
            },
            OrderedValue {
                name: "Accept".to_owned(),
                value: "text/plain".to_owned(),
            },
        ];
        let view = redacted_http_view(Some("GET"), None, &headers, "example.test", "/");
        assert!(view.contains("Authorization: <redacted>"));
        assert!(!view.contains("Bearer secret"));
        assert!(view.contains("Accept: text/plain"));
    }

    #[tokio::test]
    async fn real_proxy_uses_dynamic_port_ca_nss_and_persists_history() {
        let target = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let target_port = target.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut connection, _) = target.accept().unwrap();
            let mut request = [0_u8; 4096];
            let _ = connection.read(&mut request).unwrap();
            connection
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\nConnection: close\r\n\r\nR4 proxy body",
                )
                .unwrap();
        });
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("workspaces");
        let (store, summary) = ProjectStore::create(&root, "R4 proxy fixture").unwrap();
        assert_eq!(store.mode(), OpenMode::ReadWrite);
        let scope = TargetScope {
            scope_id: ScopeId::new(),
            project_id: summary.project_id.clone(),
            schemes: vec!["http".to_owned()],
            exact_hosts: vec!["127.0.0.1".to_owned()],
            wildcard_subdomains: Vec::new(),
            cidrs: Vec::new(),
            ports: vec![PortRange {
                start: target_port,
                end: target_port,
            }],
            redirect_policy: RedirectPolicy::Deny,
            dns_change_policy: "deny".to_owned(),
            dns_snapshots: vec![DnsResolutionSnapshot {
                host: "127.0.0.1".to_owned(),
                addresses: vec!["127.0.0.1".to_owned()],
                resolved_at: Timestamp::now(),
                peer_address: None,
                rebinding_action: "deny".to_owned(),
            }],
            network_class: NetworkClass::Loopback,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        };
        store.save_target_scope(&scope).unwrap();
        let store = Arc::new(store);
        let workbench = HttpWorkbench::new();
        let launch_browser = std::env::var_os("FLAGDECK_TEST_CHROME").is_some();
        let session = workbench
            .start_proxy(
                Arc::clone(&store),
                scope.clone(),
                &StartProxyRequest {
                    project_id: summary.project_id.clone(),
                    scope_id: scope.scope_id,
                    capture_mode: ProxyCaptureMode::PassThrough,
                    ssl_insecure: false,
                    launch_browser,
                },
            )
            .await
            .unwrap();
        let proxy_port = session.listen_port.unwrap();
        assert_ne!(proxy_port, target_port);
        assert_eq!(session.ca_sha256.as_deref().unwrap().len(), 64);
        assert_eq!(session.chrome_pid.is_some(), launch_browser);
        assert!(
            store
                .layout()
                .browser_home
                .join(".local/share/pki/nssdb/cert9.db")
                .is_file()
        );
        let output = Command::new("/usr/bin/curl")
            .args([
                "--silent",
                "--show-error",
                "--noproxy",
                "",
                "--proxy",
                &format!("http://127.0.0.1:{proxy_port}"),
                &format!("http://127.0.0.1:{target_port}/r4"),
            ])
            .env_clear()
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"R4 proxy body");
        server.join().unwrap();
        assert_eq!(
            workbench
                .ingest_active(&store, &summary.project_id)
                .await
                .unwrap(),
            2
        );
        workbench
            .stop_proxy(Arc::clone(&store), &summary.project_id)
            .await
            .unwrap();
        let (messages, _) = store
            .list_http_messages(10, None, &HttpMessageFilter::default())
            .unwrap();
        assert_eq!(messages.len(), 2);
        assert!(messages.iter().all(|message| {
            message.source == HttpSource::Proxy
                && message.representation_kind == RepresentationKind::Semantic
        }));
        let response = messages
            .iter()
            .find(|message| message.direction == MessageDirection::Response)
            .unwrap();
        assert_eq!(response.status_code, Some(200));
        assert_eq!(response.actual_length, 13);
        assert!(response.body_artifact_id.is_some());
    }

    #[test]
    fn semantic_serializer_preserves_duplicates_and_owns_framing_headers() {
        let (wire, headers) = serialize_semantic_request(
            "POST",
            "/submit?q=1",
            "example.test",
            &[
                OrderedValue {
                    name: "X-Duplicate".to_owned(),
                    value: "one".to_owned(),
                },
                OrderedValue {
                    name: "X-Duplicate".to_owned(),
                    value: "two".to_owned(),
                },
                OrderedValue {
                    name: "Content-Length".to_owned(),
                    value: "999".to_owned(),
                },
                OrderedValue {
                    name: "Transfer-Encoding".to_owned(),
                    value: "chunked".to_owned(),
                },
            ],
            b"abc",
        )
        .unwrap();
        let wire = String::from_utf8(wire).unwrap();
        assert!(wire.starts_with("POST /submit?q=1 HTTP/1.1\r\n"));
        assert_eq!(wire.matches("X-Duplicate:").count(), 2);
        assert!(wire.contains("Content-Length: 3\r\n"));
        assert!(!wire.contains("Content-Length: 999"));
        assert!(!wire.contains("Transfer-Encoding"));
        assert!(wire.ends_with("\r\n\r\nabc"));
        assert_eq!(header_values(&headers, "x-duplicate"), ["one", "two"]);
        assert!(
            serialize_semantic_request("GET\r\nInjected: yes", "/", "example.test", &[], &[],)
                .is_err()
        );
    }

    #[test]
    fn repeater_diff_sqlmap_and_raw_http1_keep_contract_boundaries() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (raw_sender, raw_receiver) = mpsc::sync_channel(1);
        let server = thread::spawn(move || {
            let (mut repeater, _) = listener.accept().unwrap();
            let mut request = [0_u8; 8192];
            let read = repeater.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..read]).contains("X-Edit: yes"));
            repeater
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\nX-End: yes\r\n\r\n",
                )
                .unwrap();
            drop(repeater);

            let (mut raw, _) = listener.accept().unwrap();
            let mut captured = Vec::new();
            let mut buffer = [0_u8; 8192];
            let read = raw.read(&mut buffer).unwrap();
            captured.extend_from_slice(&buffer[..read]);
            raw_sender.send(captured).unwrap();
            raw.write_all(
                b"HTTP/1.1 201 Created\r\nContent-Length: 3\r\nConnection: close\r\n\r\nraw",
            )
            .unwrap();
        });
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("workspaces");
        let (store, summary) = ProjectStore::create(&root, "HTTP fixture").unwrap();
        let scope = TargetScope {
            scope_id: ScopeId::new(),
            project_id: summary.project_id.clone(),
            schemes: vec!["http".to_owned()],
            exact_hosts: vec!["127.0.0.1".to_owned()],
            wildcard_subdomains: Vec::new(),
            cidrs: Vec::new(),
            ports: vec![PortRange {
                start: port,
                end: port,
            }],
            redirect_policy: RedirectPolicy::Deny,
            dns_change_policy: "deny".to_owned(),
            dns_snapshots: vec![DnsResolutionSnapshot {
                host: "127.0.0.1".to_owned(),
                addresses: vec!["127.0.0.1".to_owned()],
                resolved_at: Timestamp::now(),
                peer_address: None,
                rebinding_action: "deny".to_owned(),
            }],
            network_class: NetworkClass::Loopback,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        };
        store.save_target_scope(&scope).unwrap();
        let parent = HttpMessage {
            message_id: MessageId::new(),
            project_id: summary.project_id.clone(),
            exchange_id: Some("fixture-parent".to_owned()),
            parent_message_id: None,
            source: HttpSource::Proxy,
            representation_kind: RepresentationKind::Semantic,
            method: Some("GET".to_owned()),
            status_code: None,
            scheme: "http".to_owned(),
            host: "127.0.0.1".to_owned(),
            port,
            authority: format!("127.0.0.1:{port}"),
            path: "/old?a=1".to_owned(),
            http_version: "HTTP/1.1".to_owned(),
            headers: vec![OrderedValue {
                name: "X-Old".to_owned(),
                value: "value".to_owned(),
            }],
            trailers: Vec::new(),
            query: vec![OrderedValue {
                name: "a".to_owned(),
                value: "1".to_owned(),
            }],
            form: Vec::new(),
            body_inline: None,
            body_artifact_id: None,
            wire_artifact_id: None,
            serializer_version: "mitmproxy.semantic/12.2.3".to_owned(),
            body_state: BodyState::Missing,
            declared_length: None,
            actual_length: 0,
            content_encoding: None,
            decoded_preview_state: "not_requested".to_owned(),
            direction: MessageDirection::Request,
            observed_at: Timestamp::now(),
            duration_millis: None,
            connection: ConnectionMetadata {
                client_address: None,
                server_address: Some(format!("127.0.0.1:{port}")),
                tls: false,
                tls_version: None,
                certificate_sha256: None,
            },
            sensitivity: Sensitivity::Normal,
            redacted_view: "GET 127.0.0.1 /old?a=1".to_owned(),
        };
        store.save_http_message(&parent).unwrap();
        let repeated = repeat_http_message(
            &store,
            &scope,
            &RepeatHttpRequest {
                project_id: summary.project_id.clone(),
                scope_id: scope.scope_id.clone(),
                parent_message_id: parent.message_id.clone(),
                method: "POST".to_owned(),
                path: "/new?a=2".to_owned(),
                headers: vec![OrderedValue {
                    name: "X-Edit".to_owned(),
                    value: "yes".to_owned(),
                }],
                body: b"payload".to_vec(),
                ssl_insecure: false,
            },
        )
        .unwrap();
        assert_eq!(
            repeated.request.parent_message_id.as_ref(),
            Some(&parent.message_id)
        );
        assert_eq!(repeated.response.status_code, Some(200));
        assert_eq!(
            repeated.response.body_inline.as_deref(),
            Some(b"hello".as_slice())
        );
        assert_eq!(
            repeated.response.trailers,
            vec![OrderedValue {
                name: "X-End".to_owned(),
                value: "yes".to_owned()
            }]
        );
        let diff = diff_http_messages(
            &store,
            &DiffHttpMessagesRequest {
                project_id: summary.project_id.clone(),
                left_message_id: parent.message_id.clone(),
                right_message_id: repeated.request.message_id.clone(),
            },
        )
        .unwrap();
        assert!(
            diff.headers
                .iter()
                .any(|difference| difference.name == "x-edit")
        );
        assert!(
            diff.parameters
                .iter()
                .any(|difference| difference.name == "a")
        );
        assert_eq!(diff.body.kind, "text");
        let sqlmap = create_sqlmap_request_file(
            &store,
            &CreateSqlmapRequestFileRequest {
                project_id: summary.project_id.clone(),
                message_id: repeated.request.message_id.clone(),
                confirm_sensitive: false,
            },
        )
        .unwrap();
        let sqlmap_bytes = store
            .read_artifact_bounded(&sqlmap.artifact_id, MAX_HTTP_BODY_BYTES)
            .unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&sqlmap_bytes)),
            repeated.serialized_request_sha256
        );

        let raw_wire = format!(
            "GET /raw HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Duplicate: one\r\nX-Duplicate: two\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let raw = send_raw_http1(
            &store,
            &scope,
            &SendRawHttp1Request {
                project_id: summary.project_id,
                scope_id: scope.scope_id.clone(),
                host: "127.0.0.1".to_owned(),
                port,
                tls: false,
                ssl_insecure: false,
                wire_bytes: raw_wire.clone(),
            },
        )
        .unwrap();
        assert_eq!(raw_receiver.recv().unwrap(), raw_wire);
        assert_eq!(raw.response.status_code, Some(201));
        assert_eq!(
            raw.request.representation_kind,
            RepresentationKind::RawHttp1
        );
        assert!(raw.request.wire_artifact_id.is_some());
        assert!(raw.response.wire_artifact_id.is_some());
        server.join().unwrap();
    }

    #[test]
    #[ignore = "release gate provisions a 190 MiB private worker environment"]
    fn bundled_worker_source_provisions_locked_private_environment() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("bundled-worker");
        create_private_directory(&source).unwrap();
        let workspace_source =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../workers/mitmproxy");
        for name in ["pyproject.toml", "uv.lock", "flagdeck_worker_addon.py"] {
            copy_private_file(&workspace_source.join(name), &source.join(name)).unwrap();
        }
        copy_private_tree(&workspace_source.join("src"), &source.join("src")).unwrap();
        let root = temporary.path().join("workspaces");
        let (store, _) = ProjectStore::create(&root, "provision fixture").unwrap();
        let installed = prepare_proxy_worker(&source, store.layout()).unwrap();
        assert!(installed.join(".venv/bin/mitmdump").is_file());
        assert!(installed.join(".venv/bin/flagdeck-mitm-worker").is_file());
        assert_eq!(
            fs::metadata(fs::canonicalize(installed.join(".venv/bin/python")).unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o022,
            0
        );
    }
}
