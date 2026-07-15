#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(target_os = "macos")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use flagdeck_domain::{CommandSpec, SecretTransport, SupervisorBackend, Validate};
use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
#[cfg(target_os = "macos")]
use nix::unistd::getpgid;
use nix::unistd::{Pid, Uid};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::process::Child;
use tokio::task::JoinHandle;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum ExecPolicyError {
    #[error("domain command contract rejected: {0}")]
    Domain(String),
    #[error("program path must resolve to a trusted regular file")]
    ProgramPath,
    #[error("program owner is outside the root/current-user allowlist")]
    ProgramOwner,
    #[error("program is group/world writable")]
    ProgramWritable,
    #[error("program SHA-256 differs from CommandSpec")]
    ProgramHash,
    #[error("environment key is outside the CommandSpec allowlist")]
    EnvironmentKey,
    #[error("argument or environment contains NUL")]
    EmbeddedNul,
    #[error("argv secret transport requires an explicit L3 exception")]
    ArgvException,
    #[error("secret transport requires the audited credential launcher")]
    CredentialLauncherRequired,
    #[error("managed process ownership evidence changed")]
    OwnershipMismatch,
    #[error("managed process cleanup exceeded its deadline")]
    CleanupDeadline,
    #[error("I/O validation failed")]
    Io(#[from] std::io::Error),
    #[error("managed process launch failed")]
    Spawn,
    #[error("managed process identity is invalid")]
    ProcessIdentity,
    #[error("credential channel input failed validation")]
    CredentialInput,
    #[error("credential channel peer identity failed validation")]
    CredentialPeer,
    #[error("credential channel exceeded its deadline")]
    CredentialTimeout,
    #[error("credential channel task failed")]
    CredentialTask,
}

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const ENV: &str = "/usr/bin/env";
#[cfg(target_os = "linux")]
const SETSID: &str = "/usr/bin/setsid";
#[cfg(target_os = "linux")]
const PRLIMIT: &str = "/usr/bin/prlimit";
const SYSTEMD_UNIT_PREFIX: &str = "flagdeck-alpha";
const START_IDENTITY_TIMEOUT: Duration = Duration::from_secs(3);
const CLEANUP_DEADLINE: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
pub const MAX_CREDENTIAL_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorPolicy {
    pub preferred_backend: SupervisorBackend,
    pub fallback_backend: SupervisorBackend,
    pub kill_mode: String,
    pub limit_core_bytes: u64,
    pub no_new_privileges: bool,
    pub memory_max_bytes: u64,
    pub tasks_max: u32,
    pub cpu_quota_percent: u16,
    pub signal_grace_millis: u64,
    pub cleanup_deadline_millis: u64,
    pub stdout_stderr_channel_chunks: usize,
    pub stdout_stderr_chunk_bytes: usize,
    pub preview_limit_bytes: usize,
}

impl Default for SupervisorPolicy {
    fn default() -> Self {
        Self {
            preferred_backend: SupervisorBackend::SystemdUserService,
            fallback_backend: SupervisorBackend::PgidFallback,
            kill_mode: "control-group".to_owned(),
            limit_core_bytes: 0,
            no_new_privileges: true,
            memory_max_bytes: 256 * 1024 * 1024,
            tasks_max: 64,
            cpu_quota_percent: 100,
            signal_grace_millis: 2000,
            cleanup_deadline_millis: 5000,
            stdout_stderr_channel_chunks: 64,
            stdout_stderr_chunk_bytes: 8 * 1024,
            preview_limit_bytes: 256 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialChannel {
    SystemdLoadCredentialFromUnixSocket,
    DirectOneShotUnixSocket,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPolicy {
    pub preferred_channel: CredentialChannel,
    pub fallback_channel: CredentialChannel,
    pub same_uid_proc_environment_exposure: bool,
    pub same_uid_systemd_credential_copy_exposure: bool,
    pub unit_metadata_contains_secret_literal: bool,
}

impl Default for SecretPolicy {
    fn default() -> Self {
        Self {
            preferred_channel: CredentialChannel::SystemdLoadCredentialFromUnixSocket,
            fallback_channel: CredentialChannel::DirectOneShotUnixSocket,
            same_uid_proc_environment_exposure: true,
            same_uid_systemd_credential_copy_exposure: true,
            unit_metadata_contains_secret_literal: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialDelivery {
    pub credential_id: String,
    pub peer_pid: Option<i32>,
    pub peer_uid: u32,
    pub peer_gid: u32,
    pub bytes_sent: usize,
    pub source_removed: bool,
}

pub struct OneShotCredentialServer {
    credential_id: String,
    socket_path: PathBuf,
    delivery: Option<JoinHandle<Result<CredentialDelivery, ExecPolicyError>>>,
}

impl std::fmt::Debug for OneShotCredentialServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OneShotCredentialServer")
            .field("credential_id", &self.credential_id)
            .field("socket_path", &self.socket_path)
            .field("active", &self.delivery.is_some())
            .finish()
    }
}

impl OneShotCredentialServer {
    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub fn systemd_load_credential_property(&self) -> String {
        format!(
            "LoadCredential={}:{}",
            self.credential_id,
            self.socket_path.display()
        )
    }

    pub async fn wait(mut self) -> Result<CredentialDelivery, ExecPolicyError> {
        let delivery = self
            .delivery
            .take()
            .ok_or(ExecPolicyError::CredentialTask)?;
        delivery
            .await
            .map_err(|_| ExecPolicyError::CredentialTask)?
    }
}

impl Drop for OneShotCredentialServer {
    fn drop(&mut self) {
        if let Some(delivery) = self.delivery.take() {
            delivery.abort();
        }
        let _ = fs::remove_file(&self.socket_path);
    }
}

pub fn start_one_shot_credential(
    runtime_directory: &Path,
    credential_id: &str,
    payload: Vec<u8>,
    deadline: Duration,
) -> Result<OneShotCredentialServer, ExecPolicyError> {
    validate_credential_id(credential_id)?;
    if payload.is_empty() || payload.len() > MAX_CREDENTIAL_BYTES || deadline.is_zero() {
        return Err(ExecPolicyError::CredentialInput);
    }
    let runtime = validate_private_runtime_directory(runtime_directory)?;
    let socket_path = runtime.join(format!("credential-{}.sock", Uuid::new_v4().simple()));
    if socket_path.as_os_str().as_bytes().len() >= 104 {
        return Err(ExecPolicyError::CredentialInput);
    }
    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    let task_path = socket_path.clone();
    let task_id = credential_id.to_owned();
    let delivery = tokio::spawn(async move {
        deliver_one_shot_credential(
            listener,
            task_path,
            task_id,
            Zeroizing::new(payload),
            deadline,
        )
        .await
    });
    Ok(OneShotCredentialServer {
        credential_id: credential_id.to_owned(),
        socket_path,
        delivery: Some(delivery),
    })
}

async fn deliver_one_shot_credential(
    listener: UnixListener,
    socket_path: PathBuf,
    credential_id: String,
    payload: Zeroizing<Vec<u8>>,
    deadline: Duration,
) -> Result<CredentialDelivery, ExecPolicyError> {
    let result = async {
        let (mut stream, _) = tokio::time::timeout(deadline, listener.accept())
            .await
            .map_err(|_| ExecPolicyError::CredentialTimeout)??;
        let peer = stream.peer_cred()?;
        if peer.uid() != Uid::current().as_raw() {
            return Err(ExecPolicyError::CredentialPeer);
        }
        stream.write_all(&payload).await?;
        stream.shutdown().await?;
        Ok(CredentialDelivery {
            credential_id,
            peer_pid: peer.pid(),
            peer_uid: peer.uid(),
            peer_gid: peer.gid(),
            bytes_sent: payload.len(),
            source_removed: false,
        })
    }
    .await;
    drop(listener);
    let removal = fs::remove_file(&socket_path);
    match result {
        Ok(mut evidence) => {
            if let Err(error) = removal {
                return Err(ExecPolicyError::Io(error));
            }
            evidence.source_removed = !socket_path.exists();
            Ok(evidence)
        }
        Err(error) => {
            let _ = removal;
            Err(error)
        }
    }
}

fn validate_credential_id(value: &str) -> Result<(), ExecPolicyError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ExecPolicyError::CredentialInput);
    }
    Ok(())
}

fn validate_private_runtime_directory(path: &Path) -> Result<PathBuf, ExecPolicyError> {
    if !path.is_absolute() {
        return Err(ExecPolicyError::CredentialInput);
    }
    let original = fs::symlink_metadata(path)?;
    if original.file_type().is_symlink() {
        return Err(ExecPolicyError::CredentialInput);
    }
    let canonical = fs::canonicalize(path)?;
    let metadata = fs::metadata(&canonical)?;
    if !metadata.is_dir()
        || metadata.uid() != Uid::current().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ExecPolicyError::CredentialInput);
    }
    Ok(canonical)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCommand {
    pub canonical_program: PathBuf,
    pub argv: Vec<String>,
    pub environment: Vec<(String, String)>,
    pub cwd: PathBuf,
    pub program_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedProcessIdentity {
    pub supervisor_backend: SupervisorBackend,
    pub wrapper_pid: i32,
    pub pid: Option<i32>,
    pub process_group_id: Option<i32>,
    pub process_start_ticks: Option<u64>,
    pub systemd_unit: Option<String>,
    pub cgroup_path: Option<String>,
    pub invocation_id: Option<String>,
    pub target_program: String,
    pub ownership_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationResult {
    pub supervisor_backend: SupervisorBackend,
    pub accepted: bool,
    pub ownership_verified: bool,
    pub cleanup_verified: bool,
    pub residual_processes: u32,
    pub duration_millis: u64,
    pub signals_sent: Vec<String>,
    pub unit_collected: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedExecutionResult {
    pub supervisor_backend: SupervisorBackend,
    pub wrapper_pid: i32,
    pub pid: Option<i32>,
    pub process_group_id: Option<i32>,
    pub process_start_ticks: Option<u64>,
    pub systemd_unit: Option<String>,
    pub cgroup_path: Option<String>,
    pub invocation_id: Option<String>,
    pub ownership_verified: bool,
    pub cleanup_verified: bool,
    pub residual_processes: u32,
    pub exit_code: Option<i32>,
    pub exit_reason: String,
    pub timed_out: bool,
    pub duration_millis: u64,
    pub cancellation: Option<CancellationResult>,
}

enum ManagedState {
    Systemd,
    Pgid(Child),
    Completed(std::process::ExitStatus),
}

pub struct ManagedExecution {
    identity: ManagedProcessIdentity,
    state: ManagedState,
    started: Instant,
    timeout: Duration,
    stop_grace: Duration,
}

impl ManagedExecution {
    #[must_use]
    pub fn identity(&self) -> &ManagedProcessIdentity {
        &self.identity
    }

    pub async fn wait(self) -> Result<ManagedExecutionResult, ExecPolicyError> {
        match self.state {
            ManagedState::Systemd => {
                wait_systemd(self.identity, self.started, self.timeout, self.stop_grace).await
            }
            ManagedState::Pgid(child) => {
                wait_pgid(
                    child,
                    self.identity,
                    self.started,
                    self.timeout,
                    self.stop_grace,
                )
                .await
            }
            ManagedState::Completed(status) => Ok(completed_result(
                self.identity,
                status,
                self.started.elapsed(),
            )),
        }
    }
}

pub fn validate_command(spec: &CommandSpec) -> Result<ValidatedCommand, ExecPolicyError> {
    spec.validate()
        .map_err(|error| ExecPolicyError::Domain(error.to_string()))?;
    if spec.secret_transport == SecretTransport::ArgvException
        && !matches!(spec.risk_level, flagdeck_domain::RiskLevel::L3)
    {
        return Err(ExecPolicyError::ArgvException);
    }
    if !matches!(
        spec.secret_transport,
        SecretTransport::None | SecretTransport::ArgvException
    ) {
        return Err(ExecPolicyError::CredentialLauncherRequired);
    }
    let canonical_program = validate_program(Path::new(&spec.program), &spec.tool_sha256)?;
    let program_sha256 = spec.tool_sha256.clone();
    if spec
        .argv_exec
        .iter()
        .chain(spec.env_exec.keys())
        .chain(spec.env_exec.values())
        .any(|value| value.contains('\0'))
    {
        return Err(ExecPolicyError::EmbeddedNul);
    }
    let allowlist: BTreeSet<_> = spec.environment_allowlist.iter().collect();
    if spec.env_exec.keys().any(|key| !allowlist.contains(key)) {
        return Err(ExecPolicyError::EnvironmentKey);
    }
    let cwd = fs::canonicalize(&spec.cwd)?;
    if !cwd.is_dir() {
        return Err(ExecPolicyError::ProgramPath);
    }
    Ok(ValidatedCommand {
        canonical_program,
        argv: spec.argv_exec.clone(),
        environment: spec
            .env_exec
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        cwd,
        program_sha256,
    })
}

pub fn validate_program(program: &Path, expected_sha256: &str) -> Result<PathBuf, ExecPolicyError> {
    if !program.is_absolute() {
        return Err(ExecPolicyError::ProgramPath);
    }
    let canonical_program = fs::canonicalize(program)?;
    let metadata = fs::metadata(&canonical_program)?;
    if !metadata.is_file() {
        return Err(ExecPolicyError::ProgramPath);
    }
    let current_uid = Uid::current().as_raw();
    if metadata.uid() != 0 && metadata.uid() != current_uid {
        return Err(ExecPolicyError::ProgramOwner);
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(ExecPolicyError::ProgramWritable);
    }
    if sha256_file(&canonical_program)? != expected_sha256 {
        return Err(ExecPolicyError::ProgramHash);
    }
    Ok(canonical_program)
}

pub async fn start_managed(
    spec: &CommandSpec,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<ManagedExecution, ExecPolicyError> {
    let backend = if systemd_user_available().await {
        SupervisorBackend::SystemdUserService
    } else {
        SupervisorBackend::PgidFallback
    };
    start_managed_with_backend(spec, stdout_path, stderr_path, backend).await
}

pub async fn start_managed_with_backend(
    spec: &CommandSpec,
    stdout_path: &Path,
    stderr_path: &Path,
    backend: SupervisorBackend,
) -> Result<ManagedExecution, ExecPolicyError> {
    let validated = validate_command(spec)?;
    validate_output_path(&validated.cwd, stdout_path)?;
    validate_output_path(&validated.cwd, stderr_path)?;
    create_private_output(stdout_path)?;
    create_private_output(stderr_path)?;
    match backend {
        SupervisorBackend::SystemdUserService => {
            start_systemd(spec, &validated, stdout_path, stderr_path).await
        }
        SupervisorBackend::PgidFallback => {
            start_pgid(spec, &validated, stdout_path, stderr_path).await
        }
    }
}

pub async fn execute_managed(
    spec: &CommandSpec,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<ManagedExecutionResult, ExecPolicyError> {
    start_managed(spec, stdout_path, stderr_path)
        .await?
        .wait()
        .await
}

pub async fn execute_managed_with_backend(
    spec: &CommandSpec,
    stdout_path: &Path,
    stderr_path: &Path,
    backend: SupervisorBackend,
) -> Result<ManagedExecutionResult, ExecPolicyError> {
    start_managed_with_backend(spec, stdout_path, stderr_path, backend)
        .await?
        .wait()
        .await
}

pub async fn systemd_user_available() -> bool {
    if !Path::new(SYSTEMD_RUN).is_file() || !Path::new(SYSTEMCTL).is_file() {
        return false;
    }
    tokio::process::Command::new(SYSTEMCTL)
        .args(["--user", "show-environment"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|status| status.success())
}

async fn start_systemd(
    spec: &CommandSpec,
    validated: &ValidatedCommand,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<ManagedExecution, ExecPolicyError> {
    let unit = systemd_unit_name(spec)?;
    let limits = &spec.resource_limits;
    let mut properties = vec![
        "KillMode=control-group".to_owned(),
        format!("LimitCORE={}", limits.core_dump_bytes),
        "NoNewPrivileges=yes".to_owned(),
        format!("MemoryMax={}", limits.memory_max_bytes),
        format!("TasksMax={}", limits.tasks_max),
        format!("CPUQuota={}%", limits.cpu_quota_percent),
        format!("TimeoutStopSec={}ms", spec.stop_grace_millis),
        "UMask=0077".to_owned(),
        "RemainAfterExit=yes".to_owned(),
        "CollectMode=inactive-or-failed".to_owned(),
        format!("WorkingDirectory={}", validated.cwd.display()),
        format!("StandardOutput=append:{}", stdout_path.display()),
        format!("StandardError=append:{}", stderr_path.display()),
    ];
    if spec.network_isolation == "loopback-systemd-primary-pgid-input-gate" {
        properties.push("IPAddressDeny=any".to_owned());
        properties.push("IPAddressAllow=localhost".to_owned());
    }
    let mut command = tokio::process::Command::new(SYSTEMD_RUN);
    command.args(["--user", "--quiet", "--service-type=exec"]);
    command.arg(format!("--unit={unit}"));
    for property in properties {
        command.arg(format!("--property={property}"));
    }
    command.arg("--").args([ENV, "-i"]);
    append_environment(&mut command, &validated.environment);
    command
        .arg(&validated.canonical_program)
        .args(&validated.argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let started = Instant::now();
    let mut launcher = command.spawn().map_err(|_| ExecPolicyError::Spawn)?;
    let wrapper_pid = launcher
        .id()
        .and_then(|value| i32::try_from(value).ok())
        .ok_or(ExecPolicyError::ProcessIdentity)?;
    let status = launcher.wait().await.map_err(|_| ExecPolicyError::Spawn)?;
    if !status.success() {
        return Err(ExecPolicyError::Spawn);
    }
    let properties = wait_unit_identity(&unit, START_IDENTITY_TIMEOUT).await?;
    let invocation_id = required_property(&properties, "InvocationID")?.to_owned();
    let pid = positive_property(&properties, "ExecMainPID")
        .or_else(|| positive_property(&properties, "MainPID"));
    let process_start_ticks =
        pid.and_then(|value| read_proc_stat(value).ok().map(|stat| stat.start_ticks));
    let cgroup_path = properties
        .get("ControlGroup")
        .filter(|value| !value.is_empty())
        .cloned()
        .or_else(|| inferred_unit_cgroup(&unit, &properties));
    Ok(ManagedExecution {
        identity: ManagedProcessIdentity {
            supervisor_backend: SupervisorBackend::SystemdUserService,
            wrapper_pid,
            pid,
            process_group_id: None,
            process_start_ticks,
            systemd_unit: Some(unit),
            cgroup_path,
            invocation_id: Some(invocation_id),
            target_program: validated.canonical_program.display().to_string(),
            ownership_verified: true,
        },
        state: ManagedState::Systemd,
        started,
        timeout: Duration::from_millis(spec.timeout_millis),
        stop_grace: stop_grace(spec.stop_grace_millis),
    })
}

#[cfg(target_os = "linux")]
async fn start_pgid(
    spec: &CommandSpec,
    validated: &ValidatedCommand,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<ManagedExecution, ExecPolicyError> {
    let stdout = OpenOptions::new().append(true).open(stdout_path)?;
    let stderr = OpenOptions::new().append(true).open(stderr_path)?;
    let mut command = tokio::process::Command::new(PRLIMIT);
    command
        .args(["--core=0:0", "--", SETSID, ENV, "-i"])
        .env_clear();
    append_environment(&mut command, &validated.environment);
    command
        .arg(&validated.canonical_program)
        .args(&validated.argv)
        .current_dir(&validated.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true);
    let started = Instant::now();
    let mut child = command.spawn().map_err(|_| ExecPolicyError::Spawn)?;
    let wrapper_pid = child
        .id()
        .and_then(|value| i32::try_from(value).ok())
        .ok_or(ExecPolicyError::ProcessIdentity)?;
    let start_state = wait_pgid_identity(&mut child, wrapper_pid, START_IDENTITY_TIMEOUT).await?;
    let (process_group_id, process_start_ticks, state) = match start_state {
        PgidStartState::Running(stat) => (
            Some(stat.pgid),
            Some(stat.start_ticks),
            ManagedState::Pgid(child),
        ),
        PgidStartState::Completed(status) => {
            (Some(wrapper_pid), None, ManagedState::Completed(status))
        }
    };
    Ok(ManagedExecution {
        identity: ManagedProcessIdentity {
            supervisor_backend: SupervisorBackend::PgidFallback,
            wrapper_pid,
            pid: Some(wrapper_pid),
            process_group_id,
            process_start_ticks,
            systemd_unit: None,
            cgroup_path: None,
            invocation_id: None,
            target_program: validated.canonical_program.display().to_string(),
            ownership_verified: true,
        },
        state,
        started,
        timeout: Duration::from_millis(spec.timeout_millis),
        stop_grace: stop_grace(spec.stop_grace_millis),
    })
}

#[cfg(target_os = "macos")]
async fn start_pgid(
    spec: &CommandSpec,
    validated: &ValidatedCommand,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<ManagedExecution, ExecPolicyError> {
    let stdout = OpenOptions::new().append(true).open(stdout_path)?;
    let stderr = OpenOptions::new().append(true).open(stderr_path)?;
    let mut command = tokio::process::Command::new(&validated.canonical_program);
    command.as_std_mut().process_group(0);
    command
        .args(&validated.argv)
        .current_dir(&validated.cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true);
    for (name, value) in &validated.environment {
        command.env(name, value);
    }
    let started = Instant::now();
    let mut child = command.spawn().map_err(|_| ExecPolicyError::Spawn)?;
    let wrapper_pid = child
        .id()
        .and_then(|value| i32::try_from(value).ok())
        .ok_or(ExecPolicyError::ProcessIdentity)?;
    let start_state = wait_pgid_identity(&mut child, wrapper_pid, START_IDENTITY_TIMEOUT).await?;
    let state = match start_state {
        PgidStartState::Running => ManagedState::Pgid(child),
        PgidStartState::Completed(status) => ManagedState::Completed(status),
    };
    Ok(ManagedExecution {
        identity: ManagedProcessIdentity {
            supervisor_backend: SupervisorBackend::PgidFallback,
            wrapper_pid,
            pid: Some(wrapper_pid),
            process_group_id: Some(wrapper_pid),
            process_start_ticks: None,
            systemd_unit: None,
            cgroup_path: None,
            invocation_id: None,
            target_program: validated.canonical_program.display().to_string(),
            ownership_verified: true,
        },
        state,
        started,
        timeout: Duration::from_millis(spec.timeout_millis),
        stop_grace: stop_grace(spec.stop_grace_millis),
    })
}

async fn wait_systemd(
    identity: ManagedProcessIdentity,
    started: Instant,
    timeout: Duration,
    stop_grace: Duration,
) -> Result<ManagedExecutionResult, ExecPolicyError> {
    let unit = identity
        .systemd_unit
        .as_deref()
        .ok_or(ExecPolicyError::ProcessIdentity)?;
    let deadline = started + timeout;
    loop {
        let properties = systemctl_show(unit).await?;
        if properties
            .get("LoadState")
            .is_some_and(|value| value == "not-found")
            && cgroup_process_count(identity.cgroup_path.as_deref())? == 0
        {
            return Ok(result_from_identity(
                identity,
                None,
                "unit_collected_after_external_stop".to_owned(),
                false,
                started.elapsed(),
                true,
                0,
                None,
            ));
        }
        verify_systemd_properties(&identity, &properties)?;
        let sub_state = properties.get("SubState").map_or("", String::as_str);
        let active_state = properties.get("ActiveState").map_or("", String::as_str);
        if matches!(sub_state, "exited" | "dead" | "failed")
            || matches!(active_state, "inactive" | "failed")
        {
            let exit_code = systemd_exit_code(&properties);
            let exit_reason = systemd_exit_reason(&properties, exit_code);
            let cleanup = collect_systemd_unit(&identity, Duration::from_secs(1)).await;
            let residual = cgroup_process_count(identity.cgroup_path.as_deref())?;
            return Ok(result_from_identity(
                identity,
                exit_code,
                exit_reason,
                false,
                started.elapsed(),
                cleanup && residual == 0,
                residual,
                None,
            ));
        }
        if Instant::now() >= deadline {
            let cancellation = cancel_managed(&identity, stop_grace).await?;
            return Ok(result_from_identity(
                identity,
                None,
                "timeout".to_owned(),
                true,
                started.elapsed(),
                cancellation.cleanup_verified,
                cancellation.residual_processes,
                Some(cancellation),
            ));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn wait_pgid(
    mut child: Child,
    identity: ManagedProcessIdentity,
    started: Instant,
    timeout: Duration,
    stop_grace: Duration,
) -> Result<ManagedExecutionResult, ExecPolicyError> {
    use std::os::unix::process::ExitStatusExt;

    if let Ok(status) = tokio::time::timeout(timeout, child.wait()).await {
        let status = status.map_err(|_| ExecPolicyError::Spawn)?;
        let exit_code = status.code();
        let exit_reason = if let Some(code) = exit_code {
            format!("exit_code:{code}")
        } else if let Some(signal) = status.signal() {
            format!("signal:{signal}")
        } else {
            "status_unavailable".to_owned()
        };
        let residual = pgid_process_count(
            identity
                .process_group_id
                .ok_or(ExecPolicyError::ProcessIdentity)?,
        )?;
        Ok(result_from_identity(
            identity,
            exit_code,
            exit_reason,
            false,
            started.elapsed(),
            residual == 0,
            residual,
            None,
        ))
    } else {
        let cancellation = cancel_managed(&identity, stop_grace).await?;
        let _ = child.wait().await;
        Ok(result_from_identity(
            identity,
            None,
            "timeout".to_owned(),
            true,
            started.elapsed(),
            cancellation.cleanup_verified,
            cancellation.residual_processes,
            Some(cancellation),
        ))
    }
}

pub async fn cancel_managed(
    identity: &ManagedProcessIdentity,
    grace: Duration,
) -> Result<CancellationResult, ExecPolicyError> {
    match identity.supervisor_backend {
        SupervisorBackend::SystemdUserService => cancel_systemd(identity, grace).await,
        SupervisorBackend::PgidFallback => cancel_pgid(identity, grace).await,
    }
}

async fn cancel_systemd(
    identity: &ManagedProcessIdentity,
    grace: Duration,
) -> Result<CancellationResult, ExecPolicyError> {
    let started = Instant::now();
    let deadline = started + CLEANUP_DEADLINE;
    let unit = identity
        .systemd_unit
        .as_deref()
        .ok_or(ExecPolicyError::ProcessIdentity)?;
    let properties = systemctl_show(unit).await?;
    verify_systemd_properties(identity, &properties)?;
    let mut signals = Vec::new();
    if cgroup_process_count(identity.cgroup_path.as_deref())? > 0 {
        systemctl_kill(unit, "SIGINT").await?;
        signals.push("SIGINT".to_owned());
        wait_cgroup_empty(identity.cgroup_path.as_deref(), started + grace).await?;
    }
    if cgroup_process_count(identity.cgroup_path.as_deref())? > 0 {
        let properties = systemctl_show(unit).await?;
        verify_systemd_properties(identity, &properties)?;
        systemctl_kill(unit, "SIGTERM").await?;
        signals.push("SIGTERM".to_owned());
        wait_cgroup_empty(identity.cgroup_path.as_deref(), started + grace + grace).await?;
    }
    if cgroup_process_count(identity.cgroup_path.as_deref())? > 0 {
        let properties = systemctl_show(unit).await?;
        verify_systemd_properties(identity, &properties)?;
        systemctl_kill(unit, "SIGKILL").await?;
        signals.push("SIGKILL".to_owned());
    }
    wait_cgroup_empty(identity.cgroup_path.as_deref(), deadline).await?;
    let unit_collected =
        collect_systemd_unit(identity, deadline.saturating_duration_since(Instant::now())).await;
    let residual = cgroup_process_count(identity.cgroup_path.as_deref())?;
    Ok(CancellationResult {
        supervisor_backend: SupervisorBackend::SystemdUserService,
        accepted: true,
        ownership_verified: true,
        cleanup_verified: residual == 0 && unit_collected && started.elapsed() <= CLEANUP_DEADLINE,
        residual_processes: residual,
        duration_millis: millis(started.elapsed()),
        signals_sent: signals,
        unit_collected: Some(unit_collected),
    })
}

async fn cancel_pgid(
    identity: &ManagedProcessIdentity,
    grace: Duration,
) -> Result<CancellationResult, ExecPolicyError> {
    let started = Instant::now();
    let deadline = started + CLEANUP_DEADLINE;
    verify_pgid_identity(identity)?;
    let pgid = identity
        .process_group_id
        .ok_or(ExecPolicyError::ProcessIdentity)?;
    let mut signals = Vec::new();
    if pgid_process_count(pgid)? > 0 {
        send_group_signal(pgid, Signal::SIGINT)?;
        signals.push("SIGINT".to_owned());
        wait_pgid_empty(pgid, started + grace).await?;
    }
    if pgid_process_count(pgid)? > 0 {
        verify_pgid_identity(identity)?;
        send_group_signal(pgid, Signal::SIGTERM)?;
        signals.push("SIGTERM".to_owned());
        wait_pgid_empty(pgid, started + grace + grace).await?;
    }
    if pgid_process_count(pgid)? > 0 {
        verify_pgid_identity(identity)?;
        send_group_signal(pgid, Signal::SIGKILL)?;
        signals.push("SIGKILL".to_owned());
    }
    wait_pgid_empty(pgid, deadline).await?;
    let residual = pgid_process_count(pgid)?;
    Ok(CancellationResult {
        supervisor_backend: SupervisorBackend::PgidFallback,
        accepted: true,
        ownership_verified: true,
        cleanup_verified: residual == 0 && started.elapsed() <= CLEANUP_DEADLINE,
        residual_processes: residual,
        duration_millis: millis(started.elapsed()),
        signals_sent: signals,
        unit_collected: None,
    })
}

#[cfg(target_os = "linux")]
fn verify_pgid_identity(identity: &ManagedProcessIdentity) -> Result<(), ExecPolicyError> {
    let pid = identity.pid.ok_or(ExecPolicyError::ProcessIdentity)?;
    let expected_pgid = identity
        .process_group_id
        .ok_or(ExecPolicyError::ProcessIdentity)?;
    let expected_start = identity
        .process_start_ticks
        .ok_or(ExecPolicyError::ProcessIdentity)?;
    let stat = read_proc_stat(pid).map_err(|_| ExecPolicyError::OwnershipMismatch)?;
    if stat.state == 'Z' || stat.pgid != expected_pgid || stat.start_ticks != expected_start {
        return Err(ExecPolicyError::OwnershipMismatch);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_pgid_identity(identity: &ManagedProcessIdentity) -> Result<(), ExecPolicyError> {
    let pid = identity.pid.ok_or(ExecPolicyError::ProcessIdentity)?;
    let expected_pgid = identity
        .process_group_id
        .ok_or(ExecPolicyError::ProcessIdentity)?;
    if pid != expected_pgid
        || getpgid(Some(Pid::from_raw(pid))).map_err(|_| ExecPolicyError::OwnershipMismatch)?
            != Pid::from_raw(expected_pgid)
    {
        return Err(ExecPolicyError::OwnershipMismatch);
    }
    Ok(())
}

fn send_group_signal(pgid: i32, signal: Signal) -> Result<(), ExecPolicyError> {
    match killpg(Pid::from_raw(pgid), signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(_) => Err(ExecPolicyError::Spawn),
    }
}

async fn wait_pgid_empty(pgid: i32, deadline: Instant) -> Result<(), ExecPolicyError> {
    while Instant::now() < deadline {
        if pgid_process_count(pgid)? == 0 {
            return Ok(());
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    Ok(())
}

async fn wait_cgroup_empty(cgroup: Option<&str>, deadline: Instant) -> Result<(), ExecPolicyError> {
    while Instant::now() < deadline {
        if cgroup_process_count(cgroup)? == 0 {
            return Ok(());
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    Ok(())
}

async fn collect_systemd_unit(identity: &ManagedProcessIdentity, timeout: Duration) -> bool {
    let Some(unit) = identity.systemd_unit.as_deref() else {
        return false;
    };
    let _ = systemctl_status(&["stop", unit]).await;
    let _ = systemctl_status(&["reset-failed", unit]).await;
    let deadline = Instant::now() + timeout.min(Duration::from_secs(1));
    while Instant::now() < deadline {
        if systemctl_show(unit).await.is_ok_and(|properties| {
            properties
                .get("LoadState")
                .is_some_and(|value| value == "not-found")
        }) {
            return true;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    false
}

fn result_from_identity(
    identity: ManagedProcessIdentity,
    exit_code: Option<i32>,
    exit_reason: String,
    timed_out: bool,
    duration: Duration,
    cleanup_verified: bool,
    residual_processes: u32,
    cancellation: Option<CancellationResult>,
) -> ManagedExecutionResult {
    ManagedExecutionResult {
        supervisor_backend: identity.supervisor_backend,
        wrapper_pid: identity.wrapper_pid,
        pid: identity.pid,
        process_group_id: identity.process_group_id,
        process_start_ticks: identity.process_start_ticks,
        systemd_unit: identity.systemd_unit,
        cgroup_path: identity.cgroup_path,
        invocation_id: identity.invocation_id,
        ownership_verified: identity.ownership_verified,
        cleanup_verified,
        residual_processes,
        exit_code,
        exit_reason,
        timed_out,
        duration_millis: millis(duration),
        cancellation,
    }
}

fn completed_result(
    identity: ManagedProcessIdentity,
    status: std::process::ExitStatus,
    duration: Duration,
) -> ManagedExecutionResult {
    use std::os::unix::process::ExitStatusExt;

    let exit_code = status.code();
    let exit_reason = if let Some(code) = exit_code {
        format!("exit_code:{code}")
    } else if let Some(signal) = status.signal() {
        format!("signal:{signal}")
    } else {
        "status_unavailable".to_owned()
    };
    result_from_identity(
        identity,
        exit_code,
        exit_reason,
        false,
        duration,
        true,
        0,
        None,
    )
}

fn append_environment(command: &mut tokio::process::Command, environment: &[(String, String)]) {
    for (name, value) in environment {
        command.arg(format!("{name}={value}"));
    }
}

fn validate_output_path(cwd: &Path, output: &Path) -> Result<(), ExecPolicyError> {
    if output.file_name().is_none() {
        return Err(ExecPolicyError::ProgramPath);
    }
    // Compare canonical parents so pre-created log files (launch banners) are accepted.
    let parent = output.parent().ok_or(ExecPolicyError::ProgramPath)?;
    let canonical_cwd = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let canonical_parent = if parent.exists() {
        fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf())
    } else {
        parent.to_path_buf()
    };
    if canonical_parent != canonical_cwd {
        return Err(ExecPolicyError::ProgramPath);
    }
    if output.exists() {
        let metadata = fs::metadata(output)?;
        if !metadata.is_file() {
            return Err(ExecPolicyError::ProgramPath);
        }
    }
    Ok(())
}

fn create_private_output(path: &Path) -> Result<(), ExecPolicyError> {
    // Allow pre-seeded launch banners: keep existing private log files.
    if path.is_file() {
        let metadata = fs::metadata(path)?;
        if metadata.mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        return Ok(());
    }
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn systemd_unit_name(spec: &CommandSpec) -> Result<String, ExecPolicyError> {
    let unit_suffix = spec.command_spec_id.0.replace('-', "");
    if unit_suffix.len() < 20 || !unit_suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ExecPolicyError::ProcessIdentity);
    }
    Ok(format!(
        "{SYSTEMD_UNIT_PREFIX}-{}.service",
        &unit_suffix[..20]
    ))
}

async fn wait_unit_identity(
    unit: &str,
    timeout: Duration,
) -> Result<BTreeMap<String, String>, ExecPolicyError> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let properties = systemctl_show(unit).await?;
        if properties
            .get("LoadState")
            .is_some_and(|value| value == "loaded")
            && properties
                .get("InvocationID")
                .is_some_and(|value| !value.is_empty())
            && positive_property(&properties, "ExecMainPID").is_some()
        {
            return Ok(properties);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    Err(ExecPolicyError::ProcessIdentity)
}

#[cfg(target_os = "linux")]
enum PgidStartState {
    Running(ProcStat),
    Completed(std::process::ExitStatus),
}

#[cfg(target_os = "linux")]
async fn wait_pgid_identity(
    child: &mut Child,
    pid: i32,
    timeout: Duration,
) -> Result<PgidStartState, ExecPolicyError> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(stat) = read_proc_stat(pid)
            && stat.state != 'Z'
            && stat.pgid == pid
            && stat.sid == pid
        {
            return Ok(PgidStartState::Running(stat));
        }
        if let Some(status) = child.try_wait().map_err(|_| ExecPolicyError::Spawn)? {
            return Ok(PgidStartState::Completed(status));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    Err(ExecPolicyError::ProcessIdentity)
}

#[cfg(target_os = "macos")]
enum PgidStartState {
    Running,
    Completed(std::process::ExitStatus),
}

#[cfg(target_os = "macos")]
async fn wait_pgid_identity(
    child: &mut Child,
    pid: i32,
    timeout: Duration,
) -> Result<PgidStartState, ExecPolicyError> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if getpgid(Some(Pid::from_raw(pid))).is_ok_and(|pgid| pgid.as_raw() == pid) {
            return Ok(PgidStartState::Running);
        }
        if let Some(status) = child.try_wait().map_err(|_| ExecPolicyError::Spawn)? {
            return Ok(PgidStartState::Completed(status));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    Err(ExecPolicyError::ProcessIdentity)
}

async fn systemctl_show(unit: &str) -> Result<BTreeMap<String, String>, ExecPolicyError> {
    let output = tokio::process::Command::new(SYSTEMCTL)
        .args(["--user", "show", unit, "--all", "--no-pager"])
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|_| ExecPolicyError::Spawn)?;
    let mut properties = BTreeMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some((key, value)) = line.split_once('=') {
            properties.insert(key.to_owned(), value.to_owned());
        }
    }
    Ok(properties)
}

async fn systemctl_kill(unit: &str, signal: &str) -> Result<(), ExecPolicyError> {
    systemctl_status(&[
        "kill",
        "--kill-whom=all",
        &format!("--signal={signal}"),
        unit,
    ])
    .await
}

async fn systemctl_status(arguments: &[&str]) -> Result<(), ExecPolicyError> {
    let status = tokio::process::Command::new(SYSTEMCTL)
        .arg("--user")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|_| ExecPolicyError::Spawn)?;
    if status.success() {
        Ok(())
    } else {
        Err(ExecPolicyError::Spawn)
    }
}

fn verify_systemd_properties(
    identity: &ManagedProcessIdentity,
    properties: &BTreeMap<String, String>,
) -> Result<(), ExecPolicyError> {
    let unit = identity
        .systemd_unit
        .as_deref()
        .ok_or(ExecPolicyError::ProcessIdentity)?;
    let invocation = identity
        .invocation_id
        .as_deref()
        .ok_or(ExecPolicyError::ProcessIdentity)?;
    if !unit.starts_with(SYSTEMD_UNIT_PREFIX)
        || properties.get("Id").map(String::as_str) != Some(unit)
        || properties.get("InvocationID").map(String::as_str) != Some(invocation)
        || !properties
            .get("ExecStart")
            .is_some_and(|value| value.contains(&identity.target_program))
    {
        return Err(ExecPolicyError::OwnershipMismatch);
    }
    Ok(())
}

fn inferred_unit_cgroup(unit: &str, properties: &BTreeMap<String, String>) -> Option<String> {
    let slice = properties.get("Slice")?.trim_end_matches(".slice");
    if slice != "app" {
        return None;
    }
    Some(format!(
        "/user.slice/user-{}.slice/user@{}.service/app.slice/{unit}",
        Uid::current().as_raw(),
        Uid::current().as_raw()
    ))
}

fn required_property<'a>(
    properties: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, ExecPolicyError> {
    properties
        .get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or(ExecPolicyError::ProcessIdentity)
}

fn positive_property(properties: &BTreeMap<String, String>, key: &str) -> Option<i32> {
    properties
        .get(key)
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|value| *value > 0)
}

fn systemd_exit_code(properties: &BTreeMap<String, String>) -> Option<i32> {
    let code = properties.get("ExecMainCode")?.parse::<i32>().ok()?;
    let status = properties.get("ExecMainStatus")?.parse::<i32>().ok()?;
    (code == 1).then_some(status)
}

fn systemd_exit_reason(properties: &BTreeMap<String, String>, exit_code: Option<i32>) -> String {
    if let Some(code) = exit_code {
        return format!("exit_code:{code}");
    }
    let code = properties
        .get("ExecMainCode")
        .map_or("unknown", String::as_str);
    let status = properties
        .get("ExecMainStatus")
        .map_or("unknown", String::as_str);
    let result = properties.get("Result").map_or("unknown", String::as_str);
    format!("systemd:{result}:code={code}:status={status}")
}

fn cgroup_process_count(cgroup: Option<&str>) -> Result<u32, ExecPolicyError> {
    let Some(cgroup) = cgroup else {
        return Ok(0);
    };
    let path = Path::new("/sys/fs/cgroup")
        .join(cgroup.trim_start_matches('/'))
        .join("cgroup.procs");
    if !path.exists() {
        return Ok(0);
    }
    let count = fs::read_to_string(path)?.split_whitespace().count();
    u32::try_from(count).map_err(|_| ExecPolicyError::ProcessIdentity)
}

#[cfg(target_os = "linux")]
fn pgid_process_count(pgid: i32) -> Result<u32, ExecPolicyError> {
    let mut count = 0_u32;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(process_id) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
        else {
            continue;
        };
        if read_proc_stat(process_id).is_ok_and(|stat| stat.pgid == pgid && stat.state != 'Z') {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

#[cfg(target_os = "macos")]
fn pgid_process_count(pgid: i32) -> Result<u32, ExecPolicyError> {
    match killpg(Pid::from_raw(pgid), None::<Signal>) {
        Ok(()) | Err(Errno::EPERM) => Ok(1),
        Err(Errno::ESRCH) => Ok(0),
        Err(_) => Err(ExecPolicyError::ProcessIdentity),
    }
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
struct ProcStat {
    state: char,
    pgid: i32,
    sid: i32,
    start_ticks: u64,
}

fn read_proc_stat(pid: i32) -> Result<ProcStat, std::io::Error> {
    let value = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = value.rfind(") ").ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed /proc stat")
    })?;
    let fields = value[end + 2..].split_whitespace().collect::<Vec<_>>();
    if fields.len() <= 19 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "short /proc stat",
        ));
    }
    Ok(ProcStat {
        state: fields[0]
            .chars()
            .next()
            .ok_or_else(|| std::io::Error::other("missing process state"))?,
        pgid: fields[2]
            .parse()
            .map_err(|_| std::io::Error::other("invalid process group"))?,
        sid: fields[3]
            .parse()
            .map_err(|_| std::io::Error::other("invalid session"))?,
        start_ticks: fields[19]
            .parse()
            .map_err(|_| std::io::Error::other("invalid process start"))?,
    })
}

fn stop_grace(value: u64) -> Duration {
    Duration::from_millis(value.min(2_000))
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        hasher.update(&buffer[..length]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use flagdeck_domain::{CommandSpecId, ResourceLimits, RiskLevel};
    use tokio::io::AsyncReadExt;

    use super::*;

    fn fixture_spec(program: &str, arguments: Vec<String>) -> CommandSpec {
        CommandSpec {
            command_spec_id: CommandSpecId::new(),
            tool_id: "fixture".to_owned(),
            tool_version: "system".to_owned(),
            tool_sha256: sha256_file(Path::new(program)).unwrap(),
            program: program.to_owned(),
            argv_exec: arguments.clone(),
            argv_redacted: arguments,
            env_exec: BTreeMap::from([("LANG".to_owned(), "C.UTF-8".to_owned())]),
            env_redacted: BTreeMap::from([("LANG".to_owned(), "C.UTF-8".to_owned())]),
            secret_transport: SecretTransport::None,
            secret_inputs: Vec::new(),
            cwd: "/tmp".to_owned(),
            environment_allowlist: vec!["LANG".to_owned()],
            timeout_millis: 1000,
            stop_grace_millis: 100,
            expected_outputs: Vec::new(),
            risk_level: RiskLevel::L0,
            scope_id: None,
            sandbox_profile: "systemd-default".to_owned(),
            resource_limits: ResourceLimits::default(),
            network_isolation: "none".to_owned(),
        }
    }

    #[test]
    fn accepted_r0_supervisor_and_secret_defaults_are_frozen() {
        let supervisor = SupervisorPolicy::default();
        assert_eq!(supervisor.cleanup_deadline_millis, 5000);
        assert_eq!(supervisor.signal_grace_millis, 2000);
        assert_eq!(supervisor.stdout_stderr_channel_chunks, 64);
        assert_eq!(supervisor.stdout_stderr_chunk_bytes, 8192);
        let secret = SecretPolicy::default();
        assert_eq!(
            secret.preferred_channel,
            CredentialChannel::SystemdLoadCredentialFromUnixSocket
        );
        assert!(secret.same_uid_proc_environment_exposure);
        assert!(!secret.unit_metadata_contains_secret_literal);
    }

    #[test]
    fn one_shot_credential_is_private_uid_bound_and_removed() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let secret = format!("flagdeck-r3-secret-{}", Uuid::new_v4());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let server = start_one_shot_credential(
                temporary.path(),
                "flagdeck.r3-test",
                secret.as_bytes().to_vec(),
                Duration::from_secs(1),
            )
            .unwrap();
            let socket_path = server.socket_path().to_path_buf();
            let property = server.systemd_load_credential_property();
            assert!(property.contains("flagdeck.r3-test"));
            assert!(property.contains(socket_path.to_str().unwrap()));
            assert!(!property.contains(&secret));
            assert!(!format!("{server:?}").contains(&secret));
            let metadata = fs::symlink_metadata(&socket_path).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o077, 0);

            let mut stream = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            let delivery = server.wait().await.unwrap();
            assert_eq!(received, secret.as_bytes());
            assert_eq!(delivery.peer_uid, Uid::current().as_raw());
            assert_eq!(delivery.bytes_sent, secret.len());
            assert!(delivery.source_removed);
            assert!(!socket_path.exists());
            assert!(tokio::net::UnixStream::connect(&socket_path).await.is_err());
            for entry in fs::read_dir(temporary.path()).unwrap() {
                let bytes = fs::read(entry.unwrap().path()).unwrap_or_default();
                assert!(
                    !bytes
                        .windows(secret.len())
                        .any(|part| part == secret.as_bytes())
                );
            }
        });
    }

    #[test]
    fn credential_timeout_cleans_source_and_rejects_unsafe_inputs() {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert!(matches!(
                start_one_shot_credential(
                    temporary.path(),
                    "../unsafe",
                    vec![1],
                    Duration::from_secs(1)
                ),
                Err(ExecPolicyError::CredentialInput)
            ));
            let server = start_one_shot_credential(
                temporary.path(),
                "timeout",
                vec![7; MAX_CREDENTIAL_BYTES],
                Duration::from_millis(20),
            )
            .unwrap();
            let path = server.socket_path().to_path_buf();
            assert!(matches!(
                server.wait().await,
                Err(ExecPolicyError::CredentialTimeout)
            ));
            assert!(!path.exists());
        });
    }

    #[test]
    fn command_requires_hash_path_and_environment_allowlist() {
        let accepted =
            validate_command(&fixture_spec("/usr/bin/true", vec!["--help".to_owned()])).unwrap();
        assert_eq!(accepted.canonical_program, Path::new("/usr/bin/true"));
        let mut wrong_hash = fixture_spec("/usr/bin/true", vec!["--help".to_owned()]);
        wrong_hash.tool_sha256 = "0".repeat(64);
        assert!(matches!(
            validate_command(&wrong_hash),
            Err(ExecPolicyError::ProgramHash)
        ));
        let mut extra_environment = fixture_spec("/usr/bin/true", Vec::new());
        extra_environment
            .env_exec
            .insert("SSH_AUTH_SOCK".to_owned(), "/tmp/agent".to_owned());
        extra_environment
            .env_redacted
            .insert("SSH_AUTH_SOCK".to_owned(), "/tmp/agent".to_owned());
        assert!(matches!(
            validate_command(&extra_environment),
            Err(ExecPolicyError::EnvironmentKey)
        ));
        let mut secret_environment = fixture_spec("/usr/bin/true", Vec::new());
        secret_environment.secret_transport = SecretTransport::Environment;
        secret_environment
            .environment_allowlist
            .push("TOKEN".to_owned());
        secret_environment
            .env_exec
            .insert("TOKEN".to_owned(), "secret".to_owned());
        secret_environment
            .env_redacted
            .insert("TOKEN".to_owned(), "<redacted>".to_owned());
        assert!(matches!(
            validate_command(&secret_environment),
            Err(ExecPolicyError::CredentialLauncherRequired)
        ));
    }

    #[test]
    fn pgid_backend_executes_with_private_file_logs() {
        let temporary = tempfile::tempdir().unwrap();
        let mut spec = fixture_spec("/usr/bin/true", vec!["--help".to_owned()]);
        spec.cwd = temporary.path().display().to_string();
        let stdout = temporary.path().join("stdout.log");
        let stderr = temporary.path().join("stderr.log");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime
            .block_on(execute_managed_with_backend(
                &spec,
                &stdout,
                &stderr,
                SupervisorBackend::PgidFallback,
            ))
            .unwrap();
        assert_eq!(result.exit_code, Some(0));
        assert!(!result.timed_out);
        assert_eq!(result.process_group_id, result.pid);
        assert!(result.ownership_verified);
        assert!(result.cleanup_verified);
        assert_eq!(
            fs::metadata(stdout).unwrap().permissions().mode() & 0o077,
            0
        );
        assert_eq!(
            fs::metadata(stderr).unwrap().permissions().mode() & 0o077,
            0
        );
    }

    #[test]
    fn pgid_cancel_verifies_identity_and_cleans_within_five_seconds() {
        let temporary = tempfile::tempdir().unwrap();
        let mut spec = fixture_spec("/usr/bin/sleep", vec!["30".to_owned()]);
        spec.cwd = temporary.path().display().to_string();
        spec.timeout_millis = 60_000;
        let stdout = temporary.path().join("stdout.log");
        let stderr = temporary.path().join("stderr.log");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let execution = start_managed_with_backend(
                &spec,
                &stdout,
                &stderr,
                SupervisorBackend::PgidFallback,
            )
            .await
            .unwrap();
            let identity = execution.identity().clone();
            let mut tampered = identity.clone();
            tampered.process_start_ticks = tampered.process_start_ticks.map(|value| value + 1);
            assert!(matches!(
                cancel_managed(&tampered, Duration::from_millis(50)).await,
                Err(ExecPolicyError::OwnershipMismatch)
            ));
            let cancel = cancel_managed(&identity, Duration::from_millis(50))
                .await
                .unwrap();
            assert!(cancel.cleanup_verified);
            assert_eq!(cancel.residual_processes, 0);
            assert!(cancel.duration_millis <= 5000);
            let result = execution.wait().await.unwrap();
            assert_ne!(result.exit_reason, "exit_code:0");
        });
    }

    #[test]
    fn systemd_cancel_verifies_invocation_and_cleans_cgroup() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        if !runtime.block_on(systemd_user_available()) {
            return;
        }
        let temporary = tempfile::tempdir().unwrap();
        let mut spec = fixture_spec("/usr/bin/sleep", vec!["30".to_owned()]);
        spec.cwd = temporary.path().display().to_string();
        spec.timeout_millis = 60_000;
        let stdout = temporary.path().join("stdout.log");
        let stderr = temporary.path().join("stderr.log");
        runtime.block_on(async {
            let execution = start_managed_with_backend(
                &spec,
                &stdout,
                &stderr,
                SupervisorBackend::SystemdUserService,
            )
            .await
            .unwrap();
            let identity = execution.identity().clone();
            assert!(identity.invocation_id.is_some());
            assert!(identity.cgroup_path.is_some());
            let mut tampered = identity.clone();
            tampered.invocation_id = Some("0".repeat(32));
            assert!(matches!(
                cancel_managed(&tampered, Duration::from_millis(50)).await,
                Err(ExecPolicyError::OwnershipMismatch)
            ));
            let waiter = tokio::spawn(execution.wait());
            let cancel = cancel_managed(&identity, Duration::from_millis(50))
                .await
                .unwrap();
            assert!(cancel.cleanup_verified);
            assert_eq!(cancel.residual_processes, 0);
            assert!(cancel.unit_collected.is_some_and(|value| value));
            assert!(cancel.duration_millis <= 5000);
            let result = waiter.await.unwrap().unwrap();
            assert_ne!(result.exit_code, Some(0));
        });
    }
}
