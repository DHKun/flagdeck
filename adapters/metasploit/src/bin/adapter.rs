#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use flagdeck_adapter_protocol::{
    AdapterDescription, JSON_RPC_VERSION, JsonRpcError, JsonRpcRequest, JsonRpcResponse,
};
use flagdeck_domain::{ADAPTER_PROTOCOL, MAX_CONTROL_FRAME_BYTES, RiskLevel};
use flagdeck_metasploit_adapter::{
    ADAPTER_ID, ADAPTER_VERSION, HttpsMessagePackTransport, MsfError, MsfRpcClient, RpcTransport,
    redact_transcript, value_as_str, value_to_json,
};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::Uid;
use rmpv::Value;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const MSFRPCD: &str = "/opt/metasploit-framework/embedded/framework/msfrpcd";
const TOKEN_TIMEOUT_SECONDS: u16 = 300;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const READY_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_TRANSCRIPT_BYTES: usize = 256 * 1024;

type RpcClient = MsfRpcClient<HttpsMessagePackTransport>;

#[derive(Debug, Default)]
struct Ownership {
    jobs: BTreeSet<String>,
    consoles: BTreeSet<String>,
    sessions: BTreeSet<String>,
    execution_uuids: BTreeSet<String>,
}

struct Lifecycle {
    project_id: String,
    workspace: String,
    port: u16,
    certificate_sha256: String,
    supervisor: String,
    unit: Option<String>,
    direct_child: Option<Child>,
    rpc: RpcClient,
    ownership: Ownership,
}

struct AdapterState {
    project_id: Option<String>,
    root: Option<PathBuf>,
    launcher: Option<PathBuf>,
    lifecycle: Option<Lifecycle>,
}

impl AdapterState {
    fn new() -> Self {
        Self {
            project_id: None,
            root: None,
            launcher: None,
            lifecycle: None,
        }
    }

    fn dispatch(&mut self, request: &JsonRpcRequest) -> Result<JsonValue, AdapterFailure> {
        match request.method.as_str() {
            "initialize" => self.initialize(&request.params),
            "describe" => Self::describe(),
            "health" => self.health(),
            "start_lifecycle" => self.start_lifecycle(),
            "status" => self.status(),
            "search_modules" => self.search_modules(&request.params),
            "module_options" => self.module_options(&request.params),
            "execute_module" => self.execute_module(&request.params),
            "list_jobs" => self.list_jobs(),
            "stop_job" => self.stop_job(&request.params),
            "create_console" => self.create_console(),
            "read_console" => self.read_console(&request.params),
            "write_console" => self.write_console(&request.params),
            "destroy_console" => self.destroy_console(&request.params),
            "list_sessions" => self.list_sessions(),
            "session_command" => self.session_command(&request.params),
            "stop_session" => self.stop_session(&request.params),
            "shutdown" => self.shutdown(&request.params),
            _ => Err(AdapterFailure::InvalidRequest),
        }
    }

    fn initialize(&mut self, params: &JsonValue) -> Result<JsonValue, AdapterFailure> {
        if self.project_id.is_some() || self.lifecycle.is_some() {
            return Err(AdapterFailure::LifecycleConflict);
        }
        let project_id = required_string(params, "project_id", 64)?;
        Uuid::parse_str(project_id).map_err(|_| AdapterFailure::InvalidRequest)?;
        let root = absolute_private_directory(required_string(params, "workspace_root", 4096)?)?;
        let launcher = PathBuf::from(required_string(params, "launcher_path", 4096)?);
        let launcher = fs::canonicalize(launcher).map_err(|_| AdapterFailure::Runtime)?;
        let metadata = fs::metadata(&launcher).map_err(|_| AdapterFailure::Runtime)?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o022 != 0 {
            return Err(AdapterFailure::Runtime);
        }
        self.project_id = Some(project_id.to_owned());
        self.root = Some(root);
        self.launcher = Some(launcher);
        Ok(json!({
            "adapter_id": ADAPTER_ID,
            "adapter_version": ADAPTER_VERSION,
            "protocol": ADAPTER_PROTOCOL,
            "project_id": project_id,
        }))
    }

    fn describe() -> Result<JsonValue, AdapterFailure> {
        let description = AdapterDescription {
            adapter_id: ADAPTER_ID.to_owned(),
            adapter_version: ADAPTER_VERSION.to_owned(),
            protocol: ADAPTER_PROTOCOL.to_owned(),
            methods: vec![
                "start_lifecycle",
                "status",
                "search_modules",
                "module_options",
                "execute_module",
                "list_jobs",
                "stop_job",
                "create_console",
                "read_console",
                "write_console",
                "destroy_console",
                "list_sessions",
                "session_command",
                "stop_session",
                "shutdown",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            risk_level: RiskLevel::L3,
            input_schema_sha256: sha256(b"flagdeck.metasploit.input/1"),
            output_schema_sha256: sha256(b"flagdeck.metasploit.output/1"),
            ui_schema_sha256: sha256(b"flagdeck.metasploit.ui/1"),
            capabilities: vec!["exploit_framework", "console", "sessions"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            metadata: BTreeMap::from([
                ("rpc".to_owned(), "standard-messagepack-tls".to_owned()),
                ("listener".to_owned(), "dynamic-loopback".to_owned()),
                ("execution_replay".to_owned(), "disabled".to_owned()),
            ]),
        };
        serde_json::to_value(description).map_err(|_| AdapterFailure::Runtime)
    }

    fn health(&self) -> Result<JsonValue, AdapterFailure> {
        let metadata = fs::metadata(MSFRPCD).map_err(|_| AdapterFailure::Runtime)?;
        if !metadata.is_file() {
            return Err(AdapterFailure::Runtime);
        }
        Ok(json!({
            "healthy": true,
            "msfrpcd_path": MSFRPCD,
            "msfrpcd_sha256": sha256_file(Path::new(MSFRPCD))?,
            "lifecycle_active": self.lifecycle.is_some(),
        }))
    }

    fn start_lifecycle(&mut self) -> Result<JsonValue, AdapterFailure> {
        if self.lifecycle.is_some() {
            return Err(AdapterFailure::LifecycleConflict);
        }
        let project_id = self
            .project_id
            .clone()
            .ok_or(AdapterFailure::Uninitialized)?;
        let root = self.root.clone().ok_or(AdapterFailure::Uninitialized)?;
        let launcher = self.launcher.clone().ok_or(AdapterFailure::Uninitialized)?;
        let framework_config_root = framework_config_root()?;
        for directory in [root.join("home"), root.join("config"), root.join("runtime")] {
            fs::create_dir_all(&directory).map_err(|_| AdapterFailure::Runtime)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| AdapterFailure::Runtime)?;
        }
        let mut last_error = AdapterFailure::Runtime;
        for _ in 0..5 {
            let port = reserve_dynamic_port()?;
            let mut credential = random_credential()?;
            let username_length = usize::from(u16::from_be_bytes([credential[4], credential[5]]));
            let password_length = usize::from(u16::from_be_bytes([credential[6], credential[7]]));
            let password_start = 8 + username_length;
            let username = String::from_utf8(credential[8..password_start].to_vec())
                .map_err(|_| AdapterFailure::Runtime)?;
            let password = String::from_utf8(
                credential[password_start..password_start + password_length].to_vec(),
            )
            .map_err(|_| AdapterFailure::Runtime)?;
            match launch_msfrpcd(&root, &framework_config_root, &launcher, port, &credential) {
                Ok(process) => {
                    credential.zeroize();
                    match ready_rpc(port, &username, &password) {
                        Ok(mut rpc) => {
                            let workspace = format!("flagdeck_{}", project_id.replace('-', ""));
                            let setup = (|| {
                                let version = rpc.framework_version()?;
                                rpc.ensure_workspace(&workspace)?;
                                let certificate_sha256 = rpc
                                    .transport()
                                    .certificate_sha256()
                                    .ok_or(AdapterFailure::Runtime)?
                                    .to_owned();
                                Ok::<_, AdapterFailure>((version, certificate_sha256))
                            })();
                            let (version, certificate_sha256) = match setup {
                                Ok(value) => value,
                                Err(error) => {
                                    last_error = error;
                                    stop_process(&process);
                                    continue;
                                }
                            };
                            self.lifecycle = Some(Lifecycle {
                                project_id: project_id.clone(),
                                workspace: workspace.clone(),
                                port,
                                certificate_sha256: certificate_sha256.clone(),
                                supervisor: process.supervisor,
                                unit: process.unit,
                                direct_child: process.direct_child,
                                rpc,
                                ownership: Ownership::default(),
                            });
                            return Ok(json!({
                                "state": "ready",
                                "project_id": project_id,
                                "workspace": workspace,
                                "port": port,
                                "certificate_sha256": certificate_sha256,
                                "framework_version": version,
                                "supervisor": self.lifecycle.as_ref().map(|value| value.supervisor.clone()),
                            }));
                        }
                        Err(error) => {
                            last_error = error;
                            stop_process(&process);
                        }
                    }
                }
                Err(error) => {
                    credential.zeroize();
                    last_error = error;
                }
            }
        }
        Err(last_error)
    }

    fn status(&mut self) -> Result<JsonValue, AdapterFailure> {
        let Some(lifecycle) = self.lifecycle.as_mut() else {
            return Ok(json!({"state": "stopped"}));
        };
        let sessions = lifecycle.rpc.call_readonly("session.list", &[])?;
        refresh_managed_sessions(&mut lifecycle.ownership, &sessions);
        let session_count = sessions.as_map().map_or(0, Vec::len);
        Ok(json!({
            "state": "ready",
            "project_id": lifecycle.project_id,
            "workspace": lifecycle.workspace,
            "port": lifecycle.port,
            "certificate_sha256": lifecycle.certificate_sha256,
            "supervisor": lifecycle.supervisor,
            "managed_jobs": lifecycle.ownership.jobs.len(),
            "managed_consoles": lifecycle.ownership.consoles.len(),
            "managed_sessions": lifecycle.ownership.sessions.len(),
            "active_sessions": session_count,
            "reauth_count": lifecycle.rpc.reauth_count,
            "readonly_replay_count": lifecycle.rpc.readonly_replay_count,
        }))
    }

    fn search_modules(&mut self, params: &JsonValue) -> Result<JsonValue, AdapterFailure> {
        let query = required_string(params, "query", 512)?;
        let modules = self.lifecycle_mut()?.rpc.search_modules(query)?;
        serde_json::to_value(modules).map_err(|_| AdapterFailure::Runtime)
    }

    fn module_options(&mut self, params: &JsonValue) -> Result<JsonValue, AdapterFailure> {
        let module_type = required_string(params, "module_type", 32)?;
        let fullname = required_string(params, "fullname", 512)?;
        let options = self
            .lifecycle_mut()?
            .rpc
            .module_options(module_type, fullname)?;
        serde_json::to_value(options).map_err(|_| AdapterFailure::Runtime)
    }

    fn execute_module(&mut self, params: &JsonValue) -> Result<JsonValue, AdapterFailure> {
        let module_type = required_string(params, "module_type", 32)?;
        let fullname = required_string(params, "fullname", 512)?;
        let options: BTreeMap<String, JsonValue> = serde_json::from_value(
            params
                .get("options")
                .cloned()
                .ok_or(AdapterFailure::InvalidRequest)?,
        )
        .map_err(|_| AdapterFailure::InvalidRequest)?;
        let before = session_ids(&mut self.lifecycle_mut()?.rpc)?;
        let receipt = self
            .lifecycle_mut()?
            .rpc
            .execute_module(module_type, fullname, &options)?;
        let lifecycle = self.lifecycle_mut()?;
        if let Some(job_id) = &receipt.job_id {
            lifecycle.ownership.jobs.insert(job_id.clone());
        }
        if let Some(execution_uuid) = &receipt.uuid {
            lifecycle
                .ownership
                .execution_uuids
                .insert(execution_uuid.clone());
        }
        thread::sleep(Duration::from_millis(100));
        let after = session_ids(&mut lifecycle.rpc).unwrap_or_default();
        lifecycle
            .ownership
            .sessions
            .extend(after.difference(&before).cloned());
        serde_json::to_value(receipt).map_err(|_| AdapterFailure::Runtime)
    }

    fn list_jobs(&mut self) -> Result<JsonValue, AdapterFailure> {
        let lifecycle = self.lifecycle_mut()?;
        let value = lifecycle.rpc.call_readonly("job.list", &[])?;
        Ok(json!({
            "items": value_to_json(&value)?,
            "managed_ids": lifecycle.ownership.jobs,
        }))
    }

    fn stop_job(&mut self, params: &JsonValue) -> Result<JsonValue, AdapterFailure> {
        let id = required_string(params, "job_id", 128)?;
        let lifecycle = self.lifecycle_mut()?;
        if !lifecycle.ownership.jobs.contains(id) {
            return Err(AdapterFailure::Ownership);
        }
        let result = lifecycle
            .rpc
            .call_execution("job.stop", &[Value::from(id)])?;
        lifecycle.ownership.jobs.remove(id);
        Ok(value_to_json(&result)?)
    }

    fn create_console(&mut self) -> Result<JsonValue, AdapterFailure> {
        let lifecycle = self.lifecycle_mut()?;
        let value = lifecycle.rpc.call_execution("console.create", &[])?;
        let json = value_to_json(&value)?;
        let id = json
            .get("id")
            .and_then(JsonValue::as_str)
            .ok_or(AdapterFailure::Runtime)?;
        lifecycle.ownership.consoles.insert(id.to_owned());
        Ok(json)
    }

    fn read_console(&mut self, params: &JsonValue) -> Result<JsonValue, AdapterFailure> {
        let id = required_string(params, "console_id", 128)?;
        let lifecycle = self.lifecycle_mut()?;
        require_owned(&lifecycle.ownership.consoles, id)?;
        let value = lifecycle
            .rpc
            .call_execution("console.read", &[Value::from(id)])?;
        let mut json = value_to_json(&value)?;
        if let Some(data) = json.get_mut("data") {
            let raw = data.as_str().unwrap_or_default();
            if raw.len() > MAX_TRANSCRIPT_BYTES {
                return Err(AdapterFailure::ResponseBound);
            }
            json["redacted"] = JsonValue::String(redact_transcript(raw));
        }
        Ok(json)
    }

    fn write_console(&mut self, params: &JsonValue) -> Result<JsonValue, AdapterFailure> {
        let id = required_string(params, "console_id", 128)?;
        let command = required_string(params, "command", 16 * 1024)?;
        let lifecycle = self.lifecycle_mut()?;
        require_owned(&lifecycle.ownership.consoles, id)?;
        let result = lifecycle.rpc.call_execution(
            "console.write",
            &[
                Value::from(id),
                Value::from(format!("{}\n", command.trim_end())),
            ],
        )?;
        Ok(value_to_json(&result)?)
    }

    fn destroy_console(&mut self, params: &JsonValue) -> Result<JsonValue, AdapterFailure> {
        let id = required_string(params, "console_id", 128)?;
        let lifecycle = self.lifecycle_mut()?;
        require_owned(&lifecycle.ownership.consoles, id)?;
        let result = lifecycle
            .rpc
            .call_execution("console.destroy", &[Value::from(id)])?;
        lifecycle.ownership.consoles.remove(id);
        Ok(value_to_json(&result)?)
    }

    fn list_sessions(&mut self) -> Result<JsonValue, AdapterFailure> {
        let lifecycle = self.lifecycle_mut()?;
        let value = lifecycle.rpc.call_readonly("session.list", &[])?;
        refresh_managed_sessions(&mut lifecycle.ownership, &value);
        Ok(json!({
            "items": value_to_json(&value)?,
            "managed_ids": lifecycle.ownership.sessions,
        }))
    }

    fn session_command(&mut self, params: &JsonValue) -> Result<JsonValue, AdapterFailure> {
        let id = required_string(params, "session_id", 128)?;
        let command = required_string(params, "command", 16 * 1024)?;
        let lifecycle = self.lifecycle_mut()?;
        require_owned(&lifecycle.ownership.sessions, id)?;
        let session_type = session_type(&mut lifecycle.rpc, id)?;
        let (write_method, read_method) = if session_type.contains("meterpreter") {
            ("session.meterpreter_write", "session.meterpreter_read")
        } else {
            ("session.shell_write", "session.shell_read")
        };
        lifecycle.rpc.call_execution(
            write_method,
            &[
                Value::from(id),
                Value::from(format!("{}\n", command.trim_end())),
            ],
        )?;
        thread::sleep(Duration::from_millis(100));
        let result = lifecycle
            .rpc
            .call_execution(read_method, &[Value::from(id)])?;
        let mut json = value_to_json(&result)?;
        let raw = json
            .get("data")
            .and_then(JsonValue::as_str)
            .unwrap_or_default();
        if raw.len() > MAX_TRANSCRIPT_BYTES {
            return Err(AdapterFailure::ResponseBound);
        }
        json["redacted"] = JsonValue::String(redact_transcript(raw));
        Ok(json)
    }

    fn stop_session(&mut self, params: &JsonValue) -> Result<JsonValue, AdapterFailure> {
        let id = required_string(params, "session_id", 128)?;
        let lifecycle = self.lifecycle_mut()?;
        require_owned(&lifecycle.ownership.sessions, id)?;
        let result = lifecycle
            .rpc
            .call_execution("session.stop", &[Value::from(id)])?;
        lifecycle.ownership.sessions.remove(id);
        Ok(value_to_json(&result)?)
    }

    fn shutdown(&mut self, params: &JsonValue) -> Result<JsonValue, AdapterFailure> {
        let terminate_sessions = params
            .get("terminate_sessions")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false);
        let Some(mut lifecycle) = self.lifecycle.take() else {
            return Ok(json!({"state": "stopped"}));
        };
        let sessions = lifecycle.rpc.call_readonly("session.list", &[])?;
        refresh_managed_sessions(&mut lifecycle.ownership, &sessions);
        let active = session_ids_from_value(&sessions)?;
        if !active.is_empty() && !terminate_sessions {
            self.lifecycle = Some(lifecycle);
            return Err(AdapterFailure::ActiveSessions);
        }
        if terminate_sessions {
            for id in active.intersection(&lifecycle.ownership.sessions) {
                let _ = lifecycle
                    .rpc
                    .call_execution("session.stop", &[Value::from(id.as_str())]);
            }
        }
        for id in lifecycle.ownership.consoles.clone() {
            let _ = lifecycle
                .rpc
                .call_execution("console.destroy", &[Value::from(id.as_str())]);
        }
        for id in lifecycle.ownership.jobs.clone() {
            let _ = lifecycle
                .rpc
                .call_execution("job.stop", &[Value::from(id.as_str())]);
        }
        let _ = lifecycle.rpc.logout();
        stop_lifecycle_process(&mut lifecycle)?;
        Ok(json!({"state": "stopped"}))
    }

    fn lifecycle_mut(&mut self) -> Result<&mut Lifecycle, AdapterFailure> {
        self.lifecycle.as_mut().ok_or(AdapterFailure::NoLifecycle)
    }
}

#[derive(Debug)]
enum AdapterFailure {
    InvalidRequest,
    Uninitialized,
    NoLifecycle,
    LifecycleConflict,
    ActiveSessions,
    Ownership,
    ResponseBound,
    Runtime,
    Rpc(String),
}

impl From<MsfError> for AdapterFailure {
    fn from(value: MsfError) -> Self {
        Self::Rpc(value.to_string())
    }
}

impl AdapterFailure {
    fn rpc_error(&self) -> JsonRpcError {
        let (code, message) = match self {
            Self::InvalidRequest => (-32602, "invalid request"),
            Self::Uninitialized => (-32010, "adapter is uninitialized"),
            Self::NoLifecycle => (-32011, "Metasploit lifecycle is stopped"),
            Self::LifecycleConflict => (-32012, "project lifecycle is already bound"),
            Self::ActiveSessions => (-32013, "active sessions require confirmed termination"),
            Self::Ownership => (-32014, "external object operation was denied"),
            Self::ResponseBound => (-32015, "response exceeded its bound"),
            Self::Runtime | Self::Rpc(_) => (-32020, "Metasploit adapter operation failed"),
        };
        JsonRpcError {
            code,
            message: message.to_owned(),
            redacted_data: match self {
                Self::Rpc(error) => Some(error.clone()),
                _ => None,
            },
        }
    }
}

struct LaunchedProcess {
    supervisor: String,
    unit: Option<String>,
    direct_child: Option<Child>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Metasploit adapter stopped: {error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), String> {
    let _ = env::var_os("FLAGDECK_ADAPTER_FD");
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    let mut state = AdapterState::new();
    loop {
        let request = match read_request(&mut input) {
            Ok(Some(value)) => value,
            Ok(None) => break,
            Err(error) => return Err(error),
        };
        let response = match state.dispatch(&request) {
            Ok(result) => JsonRpcResponse {
                jsonrpc: JSON_RPC_VERSION.to_owned(),
                id: request.id,
                result: Some(result),
                error: None,
            },
            Err(error) => JsonRpcResponse {
                jsonrpc: JSON_RPC_VERSION.to_owned(),
                id: request.id,
                result: None,
                error: Some(error.rpc_error()),
            },
        };
        write_response(&mut output, &response)?;
    }
    if let Some(mut lifecycle) = state.lifecycle.take() {
        let _ = lifecycle.rpc.logout();
        let _ = stop_lifecycle_process(&mut lifecycle);
    }
    Ok(())
}

fn read_request(stream: &mut impl Read) -> Result<Option<JsonRpcRequest>, String> {
    let mut length = [0_u8; 4];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(_) => return Err("adapter control read failed".to_owned()),
    }
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| "invalid frame")?;
    if length == 0 || length > MAX_CONTROL_FRAME_BYTES {
        return Err("adapter control frame exceeded bound".to_owned());
    }
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .map_err(|_| "adapter control read failed")?;
    let request: JsonRpcRequest =
        serde_json::from_slice(&payload).map_err(|_| "invalid request")?;
    if request.jsonrpc != JSON_RPC_VERSION || request.metadata.validate().is_err() {
        return Err("invalid request metadata".to_owned());
    }
    Ok(Some(request))
}

fn write_response(stream: &mut impl Write, response: &JsonRpcResponse) -> Result<(), String> {
    let payload = serde_json::to_vec(response).map_err(|_| "response serialization failed")?;
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        return Err("response exceeded control bound".to_owned());
    }
    let length = u32::try_from(payload.len()).map_err(|_| "response length failed")?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(&payload))
        .and_then(|()| stream.flush())
        .map_err(|_| "adapter control write failed".to_owned())
}

fn launch_msfrpcd(
    root: &Path,
    framework_config_root: &Path,
    launcher: &Path,
    port: u16,
    credential: &[u8],
) -> Result<LaunchedProcess, AdapterFailure> {
    let socket_root = private_runtime_socket_directory()?;
    let socket_path = socket_root.join("credential.sock");
    let listener = UnixListener::bind(&socket_path).map_err(|_| AdapterFailure::Runtime)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|_| AdapterFailure::Runtime)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| AdapterFailure::Runtime)?;
    let unit = format!("flagdeck-msf-{}", Uuid::new_v4());
    let mut command = Command::new(SYSTEMD_RUN);
    command
        .args(["--user", "--collect", "--service-type=exec"])
        .arg(format!("--unit={unit}"))
        .arg("--property=KillMode=control-group")
        .arg("--property=LimitCORE=0")
        .arg("--property=NoNewPrivileges=yes")
        .arg("--property=MemoryMax=1073741824")
        .arg("--property=TasksMax=256")
        .arg("--property=CPUQuota=200%")
        .arg("--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6")
        .arg(format!(
            "--property=LoadCredential=flagdeck.msf-rpc:{}",
            socket_path.display()
        ))
        .arg(launcher)
        .args([
            "--channel",
            "systemd-credential",
            "--source",
            "flagdeck.msf-rpc",
            "--home",
        ])
        .arg(root.join("home"))
        .arg("--config-root")
        .arg(framework_config_root)
        .arg("--port")
        .arg(port.to_string())
        .arg("--token-timeout")
        .arg(TOKEN_TIMEOUT_SECONDS.to_string())
        .env_clear()
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    apply_user_bus_environment(&mut command);
    if let Ok(mut child) = command.spawn() {
        if serve_credential(&listener, credential, &mut child).is_ok()
            && child.wait().is_ok_and(|status| status.success())
            && wait_for_systemd_ready(&unit, port).is_ok()
        {
            let _ = fs::remove_file(&socket_path);
            let _ = fs::remove_dir(&socket_root);
            return Ok(LaunchedProcess {
                supervisor: "systemd_user_service".to_owned(),
                unit: Some(unit),
                direct_child: None,
            });
        }
        let _ = child.kill();
        let _ = child.wait();
        let mut stop = Command::new(SYSTEMCTL);
        stop.args(["--user", "stop", &unit]).env_clear();
        apply_user_bus_environment(&mut stop);
        let _ = stop.status();
    }
    let _ = fs::remove_file(&socket_path);
    let _ = fs::remove_dir(&socket_root);
    let socket_root = private_runtime_socket_directory()?;
    let socket_path = socket_root.join("credential.sock");
    let listener = UnixListener::bind(&socket_path).map_err(|_| AdapterFailure::Runtime)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|_| AdapterFailure::Runtime)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| AdapterFailure::Runtime)?;
    let mut child = Command::new(launcher)
        .args(["--channel", "direct-socket", "--source"])
        .arg(&socket_path)
        .arg("--home")
        .arg(root.join("home"))
        .arg("--config-root")
        .arg(framework_config_root)
        .arg("--port")
        .arg(port.to_string())
        .arg("--token-timeout")
        .arg(TOKEN_TIMEOUT_SECONDS.to_string())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| AdapterFailure::Runtime)?;
    serve_credential(&listener, credential, &mut child)?;
    let _ = fs::remove_file(&socket_path);
    let _ = fs::remove_dir(&socket_root);
    wait_for_port(port, READY_TIMEOUT)?;
    Ok(LaunchedProcess {
        supervisor: "pgid_fallback".to_owned(),
        unit: None,
        direct_child: Some(child),
    })
}

fn serve_credential(
    listener: &UnixListener,
    credential: &[u8],
    child: &mut Child,
) -> Result<(), AdapterFailure> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let peer =
                    getsockopt(&stream, PeerCredentials).map_err(|_| AdapterFailure::Runtime)?;
                if peer.uid() != Uid::current().as_raw() {
                    return Err(AdapterFailure::Runtime);
                }
                stream
                    .write_all(credential)
                    .map_err(|_| AdapterFailure::Runtime)?;
                stream.flush().map_err(|_| AdapterFailure::Runtime)?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if child
                    .try_wait()
                    .map_err(|_| AdapterFailure::Runtime)?
                    .is_some()
                    || Instant::now() >= deadline
                {
                    return Err(AdapterFailure::Runtime);
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return Err(AdapterFailure::Runtime),
        }
    }
}

fn ready_rpc(port: u16, username: &str, password: &str) -> Result<RpcClient, AdapterFailure> {
    let deadline = Instant::now() + READY_TIMEOUT;
    let mut last = AdapterFailure::Runtime;
    while Instant::now() < deadline {
        match HttpsMessagePackTransport::connect("127.0.0.1", port, REQUEST_TIMEOUT).and_then(
            |transport| MsfRpcClient::new(transport, username.to_owned(), password.to_owned()),
        ) {
            Ok(mut rpc) => match rpc.login() {
                Ok(()) => return Ok(rpc),
                Err(error) => last = AdapterFailure::Rpc(error.to_string()),
            },
            Err(error) => last = AdapterFailure::Rpc(error.to_string()),
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(last)
}

fn wait_for_systemd_ready(unit: &str, port: u16) -> Result<(), AdapterFailure> {
    let deadline = Instant::now() + READY_TIMEOUT;
    while Instant::now() < deadline {
        let mut show = Command::new(SYSTEMCTL);
        show.args([
            "--user",
            "show",
            unit,
            "--property=MainPID",
            "--property=ActiveState",
        ])
        .env_clear();
        apply_user_bus_environment(&mut show);
        let output = show.output().map_err(|_| AdapterFailure::Runtime)?;
        let text = String::from_utf8_lossy(&output.stdout);
        let pid = text
            .lines()
            .find_map(|line| line.strip_prefix("MainPID="))
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);
        if text.contains("ActiveState=active") && pid > 0 && listener_owned_by_pid(pid, port) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(AdapterFailure::Runtime)
}

fn listener_owned_by_pid(pid: u32, port: u16) -> bool {
    let mut inodes = BTreeSet::new();
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    for entry in entries.flatten() {
        if let Ok(target) = fs::read_link(entry.path()) {
            let text = target.to_string_lossy();
            if let Some(inode) = text
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
            {
                inodes.insert(inode.to_owned());
            }
        }
    }
    let expected = format!(":{port:04X}");
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = fs::read_to_string(table) {
            for line in text.lines().skip(1) {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if fields.len() > 9
                    && fields[3] == "0A"
                    && fields[1].ends_with(&expected)
                    && inodes.contains(fields[9])
                {
                    return true;
                }
            }
        }
    }
    false
}

fn wait_for_port(port: u16, timeout: Duration) -> Result<(), AdapterFailure> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(
            &SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into(),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(AdapterFailure::Runtime)
}

fn stop_lifecycle_process(lifecycle: &mut Lifecycle) -> Result<(), AdapterFailure> {
    if let Some(unit) = &lifecycle.unit {
        let mut stop = Command::new(SYSTEMCTL);
        stop.args(["--user", "stop", unit]).env_clear();
        apply_user_bus_environment(&mut stop);
        let status = stop.status().map_err(|_| AdapterFailure::Runtime)?;
        if !status.success() {
            return Err(AdapterFailure::Runtime);
        }
    }
    if let Some(child) = lifecycle.direct_child.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(
            &SocketAddrV4::new(Ipv4Addr::LOCALHOST, lifecycle.port).into(),
            Duration::from_millis(50),
        )
        .is_err()
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(AdapterFailure::Runtime)
}

fn stop_process(process: &LaunchedProcess) {
    if let Some(unit) = &process.unit {
        let mut stop = Command::new(SYSTEMCTL);
        stop.args(["--user", "stop", unit]).env_clear();
        apply_user_bus_environment(&mut stop);
        let _ = stop.status();
    }
    if let Some(child) = &process.direct_child {
        let _ = Command::new("/usr/bin/kill")
            .arg(child.id().to_string())
            .env_clear()
            .status();
    }
}

fn session_ids(rpc: &mut RpcClient) -> Result<BTreeSet<String>, AdapterFailure> {
    let value = rpc.call_readonly("session.list", &[])?;
    session_ids_from_value(&value)
}

fn session_ids_from_value(value: &Value) -> Result<BTreeSet<String>, AdapterFailure> {
    let map = value.as_map().ok_or(AdapterFailure::Runtime)?;
    Ok(map
        .iter()
        .filter_map(|(key, _)| value_as_str(key).map(ToOwned::to_owned))
        .collect())
}

fn session_type(rpc: &mut RpcClient, id: &str) -> Result<String, AdapterFailure> {
    let value = rpc.call_readonly("session.list", &[])?;
    let sessions = value.as_map().ok_or(AdapterFailure::Runtime)?;
    let details = sessions
        .iter()
        .find(|(key, _)| value_as_str(key) == Some(id))
        .and_then(|(_, value)| value.as_map())
        .ok_or(AdapterFailure::Ownership)?;
    Ok(details
        .iter()
        .find(|(key, _)| value_as_str(key) == Some("type"))
        .and_then(|(_, value)| value_as_str(value))
        .unwrap_or("shell")
        .to_owned())
}

fn refresh_managed_sessions(ownership: &mut Ownership, sessions: &Value) {
    let Some(sessions) = sessions.as_map() else {
        return;
    };
    for (id, details) in sessions {
        let Some(id) = value_as_str(id) else {
            continue;
        };
        let Some(details) = details.as_map() else {
            continue;
        };
        let owned = details.iter().any(|(key, value)| {
            matches!(value_as_str(key), Some("exploit_uuid" | "uuid"))
                && value_as_str(value).is_some_and(|uuid| ownership.execution_uuids.contains(uuid))
        });
        if owned {
            ownership.sessions.insert(id.to_owned());
        }
    }
}

fn reserve_dynamic_port() -> Result<u16, AdapterFailure> {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| AdapterFailure::Runtime)?;
    listener
        .local_addr()
        .map(|value| value.port())
        .map_err(|_| AdapterFailure::Runtime)
}

fn random_credential() -> Result<Vec<u8>, AdapterFailure> {
    let mut random = [0_u8; 40];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(|_| AdapterFailure::Runtime)?;
    let username = format!("fd_{}", hex(&random[..6]));
    let password = hex(&random[6..]);
    let mut payload = Vec::with_capacity(8 + username.len() + password.len());
    payload.extend_from_slice(b"FDM1");
    payload.extend_from_slice(
        &u16::try_from(username.len())
            .map_err(|_| AdapterFailure::Runtime)?
            .to_be_bytes(),
    );
    payload.extend_from_slice(
        &u16::try_from(password.len())
            .map_err(|_| AdapterFailure::Runtime)?
            .to_be_bytes(),
    );
    payload.extend_from_slice(username.as_bytes());
    payload.extend_from_slice(password.as_bytes());
    random.zeroize();
    Ok(payload)
}

fn required_string<'a>(
    params: &'a JsonValue,
    key: &str,
    limit: usize,
) -> Result<&'a str, AdapterFailure> {
    let value = params
        .get(key)
        .and_then(JsonValue::as_str)
        .ok_or(AdapterFailure::InvalidRequest)?;
    if value.is_empty() || value.len() > limit || value.contains('\0') {
        return Err(AdapterFailure::InvalidRequest);
    }
    Ok(value)
}

fn private_runtime_socket_directory() -> Result<PathBuf, AdapterFailure> {
    let runtime = PathBuf::from(format!("/run/user/{}", Uid::current().as_raw()));
    if !runtime.is_dir() {
        return Err(AdapterFailure::Runtime);
    }
    let directory = runtime.join(format!(
        "fd-msf-{}-{}",
        std::process::id(),
        &Uuid::new_v4().simple().to_string()[..8]
    ));
    fs::create_dir(&directory).map_err(|_| AdapterFailure::Runtime)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|_| AdapterFailure::Runtime)?;
    Ok(directory)
}

fn framework_config_root() -> Result<PathBuf, AdapterFailure> {
    let user = nix::unistd::User::from_uid(Uid::current())
        .map_err(|_| AdapterFailure::Runtime)?
        .ok_or(AdapterFailure::Runtime)?;
    let root = fs::canonicalize(user.dir.join(".msf4")).map_err(|_| AdapterFailure::Runtime)?;
    let metadata = fs::metadata(&root).map_err(|_| AdapterFailure::Runtime)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o022 != 0 {
        return Err(AdapterFailure::Runtime);
    }
    Ok(root)
}

fn apply_user_bus_environment(command: &mut Command) {
    let runtime = format!("/run/user/{}", Uid::current().as_raw());
    command
        .env("XDG_RUNTIME_DIR", &runtime)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={runtime}/bus"),
        )
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8");
}

fn absolute_private_directory(value: &str) -> Result<PathBuf, AdapterFailure> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(AdapterFailure::InvalidRequest);
    }
    fs::create_dir_all(&path).map_err(|_| AdapterFailure::Runtime)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .map_err(|_| AdapterFailure::Runtime)?;
    fs::canonicalize(path).map_err(|_| AdapterFailure::Runtime)
}

fn require_owned(values: &BTreeSet<String>, id: &str) -> Result<(), AdapterFailure> {
    if values.contains(id) {
        Ok(())
    } else {
        Err(AdapterFailure::Ownership)
    }
}

fn sha256_file(path: &Path) -> Result<String, AdapterFailure> {
    let mut file = File::open(path).map_err(|_| AdapterFailure::Runtime)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| AdapterFailure::Runtime)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn hex(value: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(TABLE[usize::from(byte >> 4)]));
        output.push(char::from(TABLE[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_have_256_bits_and_no_argv_metacharacters() {
        let mut credential = random_credential().unwrap();
        let username_length = usize::from(u16::from_be_bytes([credential[4], credential[5]]));
        let password_length = usize::from(u16::from_be_bytes([credential[6], credential[7]]));
        assert!(username_length >= 8);
        assert_eq!(password_length, 68);
        assert!(
            credential[8..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        );
        credential.zeroize();
        assert!(credential.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn required_strings_are_bounded_and_nul_free() {
        assert_eq!(required_string(&json!({"x": "ok"}), "x", 2).unwrap(), "ok");
        assert!(required_string(&json!({"x": "bad\0"}), "x", 10).is_err());
        assert!(required_string(&json!({"x": "long"}), "x", 3).is_err());
    }

    #[test]
    fn late_sessions_map_back_to_owned_execution_uuid() {
        let mut ownership = Ownership::default();
        ownership.execution_uuids.insert("owned-uuid".to_owned());
        let sessions = Value::Map(vec![(
            Value::from("7"),
            Value::Map(vec![
                (Value::from("type"), Value::from("meterpreter")),
                (Value::from("exploit_uuid"), Value::from("owned-uuid")),
            ]),
        )]);
        refresh_managed_sessions(&mut ownership, &sessions);
        assert!(ownership.sessions.contains("7"));
    }
}
