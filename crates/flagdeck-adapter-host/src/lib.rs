#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::struct_field_names
)]

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flagdeck_adapter_protocol::{
    JSON_RPC_VERSION, JsonRpcRequest, JsonRpcResponse, ProtocolError, encode_frame,
};
use flagdeck_domain::MAX_CONTROL_FRAME_BYTES;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Pid, Uid, dup};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const PRLIMIT: &str = "/usr/bin/prlimit";
const SETSID: &str = "/usr/bin/setsid";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_STDERR_LIMIT: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum HostError {
    #[error("adapter executable or working directory failed validation")]
    InvalidRuntimePath,
    #[error("adapter executable owner is outside the trusted allowlist")]
    InvalidOwner,
    #[error("adapter executable is group/world writable")]
    WritableExecutable,
    #[error("adapter process could not be started")]
    Spawn,
    #[error("adapter control I/O failed")]
    Io(#[from] std::io::Error),
    #[error("adapter control frame failed validation")]
    Protocol(#[from] ProtocolError),
    #[error("adapter response exceeded its deadline")]
    ResponseTimeout,
    #[error("adapter process exited during a request (code {code:?})")]
    WorkerCrashed { code: Option<i32> },
    #[error("adapter returned a response for a different request")]
    MismatchedResponse,
    #[error("adapter returned an invalid JSON-RPC response")]
    InvalidResponse,
    #[error("adapter stderr collector failed")]
    StderrCollector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterHostConfig {
    pub program: PathBuf,
    pub arguments: Vec<String>,
    pub cwd: PathBuf,
    pub request_timeout: Duration,
    pub stderr_limit_bytes: usize,
    pub control_transport: ControlTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlTransport {
    Stdio,
    UnixSocketPair,
}

impl AdapterHostConfig {
    #[must_use]
    pub fn new(program: impl Into<PathBuf>, cwd: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            cwd: cwd.into(),
            request_timeout: DEFAULT_TIMEOUT,
            stderr_limit_bytes: DEFAULT_STDERR_LIMIT,
            control_transport: ControlTransport::Stdio,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StderrEvidence {
    pub bytes_seen: u64,
    pub bytes_hashed: u64,
    pub truncated: bool,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct AdapterHost {
    config: AdapterHostConfig,
    canonical_program: PathBuf,
    canonical_cwd: PathBuf,
}

impl AdapterHost {
    pub fn new(config: AdapterHostConfig) -> Result<Self, HostError> {
        let canonical_program = validate_program(&config.program)?;
        let canonical_cwd =
            fs::canonicalize(&config.cwd).map_err(|_| HostError::InvalidRuntimePath)?;
        if !canonical_cwd.is_dir()
            || config.request_timeout.is_zero()
            || config.stderr_limit_bytes == 0
        {
            return Err(HostError::InvalidRuntimePath);
        }
        Ok(Self {
            config,
            canonical_program,
            canonical_cwd,
        })
    }

    pub fn spawn(&self) -> Result<AdapterWorker, HostError> {
        let mut command = Command::new(SETSID);
        command
            .arg(PRLIMIT)
            .arg("--core=0:0")
            .arg("--")
            .arg(&self.canonical_program)
            .args(&self.config.arguments)
            .current_dir(&self.canonical_cwd)
            .env_clear()
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let socket_pair = if self.config.control_transport == ControlTransport::UnixSocketPair {
            let (parent, child) = StdUnixStream::pair().map_err(HostError::Io)?;
            let inherited = dup(&child).map_err(|_| HostError::Spawn)?;
            command
                .env("FLAGDECK_ADAPTER_FD", inherited.as_raw_fd().to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null());
            Some((parent, child, inherited))
        } else {
            command.stdin(Stdio::piped()).stdout(Stdio::piped());
            None
        };
        let mut child = command.spawn().map_err(|_| HostError::Spawn)?;
        let child_id = child.id().ok_or(HostError::Spawn)?;
        let (reader, writer): (
            Box<dyn AsyncRead + Send + Unpin>,
            Box<dyn AsyncWrite + Send + Unpin>,
        ) = if let Some((parent, child_socket, inherited)) = socket_pair {
            drop(child_socket);
            drop(inherited);
            parent.set_nonblocking(true).map_err(HostError::Io)?;
            let socket = UnixStream::from_std(parent).map_err(HostError::Io)?;
            let (reader, writer) = socket.into_split();
            (Box::new(reader), Box::new(writer))
        } else {
            let stdin = child.stdin.take().ok_or(HostError::Spawn)?;
            let stdout = child.stdout.take().ok_or(HostError::Spawn)?;
            (Box::new(stdout), Box::new(stdin))
        };
        let stderr = child.stderr.take().ok_or(HostError::Spawn)?;
        let stderr_limit = self.config.stderr_limit_bytes;
        let stderr_task = tokio::spawn(async move { collect_stderr(stderr, stderr_limit).await });
        Ok(AdapterWorker {
            child,
            writer,
            reader,
            process_group: i32::try_from(child_id).ok(),
            request_timeout: self.config.request_timeout,
            stderr_task: Some(stderr_task),
        })
    }
}

pub struct AdapterWorker {
    child: Child,
    writer: Box<dyn AsyncWrite + Send + Unpin>,
    reader: Box<dyn AsyncRead + Send + Unpin>,
    process_group: Option<i32>,
    request_timeout: Duration,
    stderr_task: Option<JoinHandle<Result<StderrEvidence, std::io::Error>>>,
}

impl AdapterWorker {
    pub async fn request(
        &mut self,
        request: &JsonRpcRequest,
    ) -> Result<JsonRpcResponse, HostError> {
        if request.jsonrpc != JSON_RPC_VERSION {
            return Err(HostError::InvalidResponse);
        }
        request.metadata.validate()?;
        let request_timeout = effective_request_timeout(request, self.request_timeout)?;
        let frame = encode_frame(request)?;
        let response = timeout(request_timeout, async {
            self.writer.write_all(&frame).await?;
            self.writer.flush().await?;
            read_response(&mut self.reader).await
        })
        .await;

        let response = match response {
            Ok(Ok(value)) => value,
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(self.crash_error().await);
            }
            Ok(Err(error)) => return Err(HostError::Io(error)),
            Err(_) => {
                self.kill_process_group(Signal::SIGKILL);
                let _ = self.child.wait().await;
                return Err(HostError::ResponseTimeout);
            }
        };
        if response.jsonrpc != JSON_RPC_VERSION || response.id != request.id {
            return Err(HostError::MismatchedResponse);
        }
        if response.result.is_some() == response.error.is_some() {
            return Err(HostError::InvalidResponse);
        }
        Ok(response)
    }

    #[must_use]
    pub fn process_id(&self) -> Option<u32> {
        self.child.id()
    }

    pub async fn shutdown(mut self) -> Result<StderrEvidence, HostError> {
        let _ = self.writer.shutdown().await;
        if self.child.try_wait()?.is_none()
            && timeout(Duration::from_secs(3), self.child.wait())
                .await
                .is_err()
        {
            self.kill_process_group(Signal::SIGTERM);
            if timeout(Duration::from_secs(1), self.child.wait())
                .await
                .is_err()
            {
                self.kill_process_group(Signal::SIGKILL);
                let _ = self.child.wait().await;
            }
        }
        self.stderr_evidence().await
    }

    async fn crash_error(&mut self) -> HostError {
        let code = match timeout(Duration::from_secs(1), self.child.wait()).await {
            Ok(Ok(status)) => status.code(),
            _ => None,
        };
        HostError::WorkerCrashed { code }
    }

    async fn stderr_evidence(&mut self) -> Result<StderrEvidence, HostError> {
        let task = self.stderr_task.take().ok_or(HostError::StderrCollector)?;
        task.await
            .map_err(|_| HostError::StderrCollector)?
            .map_err(HostError::Io)
    }

    fn kill_process_group(&self, signal: Signal) {
        if let Some(process_group) = self.process_group {
            let _ = killpg(Pid::from_raw(process_group), signal);
        }
    }
}

fn effective_request_timeout(
    request: &JsonRpcRequest,
    configured: Duration,
) -> Result<Duration, HostError> {
    let deadline = request
        .metadata
        .deadline_unix_millis
        .parse::<u128>()
        .map_err(|_| HostError::InvalidResponse)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HostError::InvalidResponse)?
        .as_millis();
    if deadline <= now {
        return Err(HostError::ResponseTimeout);
    }
    let remaining = u64::try_from(deadline - now).unwrap_or(u64::MAX);
    Ok(configured.min(Duration::from_millis(remaining)))
}

async fn read_response(
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<JsonRpcResponse, std::io::Error> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length).await?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid frame length")
    })?;
    if length == 0 || length > MAX_CONTROL_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "control frame exceeded its bound",
        ));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

async fn collect_stderr(
    mut reader: impl AsyncRead + Unpin,
    limit: usize,
) -> Result<StderrEvidence, std::io::Error> {
    let mut digest = Sha256::new();
    let mut bytes_seen = 0_u64;
    let mut bytes_hashed = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        bytes_seen = bytes_seen.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        let remaining = limit.saturating_sub(usize::try_from(bytes_hashed).unwrap_or(usize::MAX));
        let accepted = read.min(remaining);
        digest.update(&buffer[..accepted]);
        bytes_hashed = bytes_hashed.saturating_add(u64::try_from(accepted).unwrap_or(u64::MAX));
    }
    Ok(StderrEvidence {
        bytes_seen,
        bytes_hashed,
        truncated: bytes_seen > bytes_hashed,
        sha256: format!("{:x}", digest.finalize()),
    })
}

fn validate_program(program: &Path) -> Result<PathBuf, HostError> {
    if !program.is_absolute() {
        return Err(HostError::InvalidRuntimePath);
    }
    let canonical = fs::canonicalize(program).map_err(|_| HostError::InvalidRuntimePath)?;
    let metadata = fs::metadata(&canonical).map_err(|_| HostError::InvalidRuntimePath)?;
    if !metadata.is_file() {
        return Err(HostError::InvalidRuntimePath);
    }
    let current_uid = Uid::current().as_raw();
    if metadata.uid() != 0 && metadata.uid() != current_uid {
        return Err(HostError::InvalidOwner);
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(HostError::WritableExecutable);
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use flagdeck_adapter_protocol::{JsonRpcRequest, RequestMetadata};
    use serde_json::{Value, json};

    use super::*;

    fn request(method: &str, id: &str) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: JSON_RPC_VERSION.to_owned(),
            id: id.to_owned(),
            method: method.to_owned(),
            metadata: RequestMetadata {
                core_job_id: "core-r3".to_owned(),
                adapter_job_id: None,
                idempotency_key: format!("idem-{id}"),
                deadline_unix_millis: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
                    .saturating_add(5_000)
                    .to_string(),
            },
            params: Value::Null,
        }
    }

    fn fixture_host(stderr_limit: usize) -> AdapterHost {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let script = root.join("tests/fixtures/r3/adapter_worker.py");
        let mut config = AdapterHostConfig::new(PathBuf::from("/usr/bin/python3"), &root);
        config.arguments = vec![script.to_string_lossy().into_owned()];
        config.stderr_limit_bytes = stderr_limit;
        AdapterHost::new(config).unwrap()
    }

    #[tokio::test]
    async fn worker_crash_is_isolated_and_next_worker_is_healthy() {
        let host = fixture_host(1024);
        let mut crashed = host.spawn().unwrap();
        let error = crashed
            .request(&request("crash", "crash-1"))
            .await
            .unwrap_err();
        assert!(matches!(error, HostError::WorkerCrashed { code: Some(23) }));
        let crash_stderr = crashed.shutdown().await.unwrap();
        assert!(crash_stderr.bytes_seen > 0);

        let mut healthy = host.spawn().unwrap();
        let response = healthy
            .request(&request("health", "health-1"))
            .await
            .unwrap();
        assert_eq!(response.result, Some(json!({"healthy": true})));
        let evidence = healthy.shutdown().await.unwrap();
        assert_eq!(evidence.bytes_seen, 0);
    }

    #[tokio::test]
    async fn stderr_flood_is_consumed_with_bounded_evidence() {
        let host = fixture_host(1024);
        let mut worker = host.spawn().unwrap();
        let response = worker
            .request(&request("stderr_flood", "flood-1"))
            .await
            .unwrap();
        assert_eq!(response.result, Some(json!({"written": 131_072})));
        let evidence = worker.shutdown().await.unwrap();
        assert_eq!(evidence.bytes_seen, 131_072);
        assert_eq!(evidence.bytes_hashed, 1024);
        assert!(evidence.truncated);
    }

    #[tokio::test]
    async fn expired_request_is_rejected_before_worker_io() {
        let host = fixture_host(1024);
        let mut worker = host.spawn().unwrap();
        let mut expired = request("health", "expired-1");
        expired.metadata.deadline_unix_millis = "1".to_owned();
        assert!(matches!(
            worker.request(&expired).await,
            Err(HostError::ResponseTimeout)
        ));
        let evidence = worker.shutdown().await.unwrap();
        assert_eq!(evidence.bytes_seen, 0);
    }

    #[tokio::test]
    async fn inherited_socket_pair_carries_adapter_frames() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let script = root.join("tests/fixtures/r3/adapter_worker.py");
        let mut config = AdapterHostConfig::new(PathBuf::from("/usr/bin/python3"), &root);
        config.arguments = vec![script.to_string_lossy().into_owned()];
        config.control_transport = ControlTransport::UnixSocketPair;
        let host = AdapterHost::new(config).unwrap();
        let mut worker = host.spawn().unwrap();
        let response = worker
            .request(&request("health", "socket-health-1"))
            .await
            .unwrap();
        assert_eq!(response.result, Some(json!({"healthy": true})));
        assert!(worker.process_id().is_some());
        let evidence = worker.shutdown().await.unwrap();
        assert_eq!(evidence.bytes_seen, 0);
    }
}
