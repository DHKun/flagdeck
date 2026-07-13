#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ts_rs::TS;
use uuid::Uuid;

pub const CONTRACT_VERSION: u32 = 6;
pub const ADAPTER_PROTOCOL: &str = "flagdeck.adapter.v1";
pub const MAX_CONTROL_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_INLINE_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds {maximum} bytes")]
    TooLarge { field: &'static str, maximum: usize },
    #[error("invalid identifier for {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid state transition: {from} -> {to}")]
    InvalidTransition { from: String, to: String },
    #[error("invalid absolute program path")]
    InvalidProgramPath,
    #[error("command contains an unredacted executable secret")]
    ExecutableSecretPersisted,
    #[error("invalid port range")]
    InvalidPortRange,
}

pub trait Validate {
    fn validate(&self) -> Result<(), DomainError>;
}

macro_rules! id_type {
    ($name:ident, $field:literal) => {
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Serialize,
            Deserialize,
            JsonSchema,
            TS,
        )]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4().to_string())
            }

            pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
                let value = value.into();
                Uuid::parse_str(&value)
                    .map_err(|_| DomainError::InvalidIdentifier { field: $field })?;
                Ok(Self(value))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl Validate for $name {
            fn validate(&self) -> Result<(), DomainError> {
                Self::parse(self.0.clone()).map(|_| ())
            }
        }
    };
}

id_type!(ProjectId, "project_id");
id_type!(ScopeId, "scope_id");
id_type!(MessageId, "message_id");
id_type!(CommandSpecId, "command_spec_id");
id_type!(JobId, "job_id");
id_type!(DiscoveryId, "discovery_id");
id_type!(ArtifactId, "artifact_id");
id_type!(AdapterEntityId, "adapter_entity_id");
id_type!(DictionaryId, "dictionary_id");
id_type!(ProxySessionId, "proxy_session_id");
id_type!(AuditEventId, "audit_event_id");
id_type!(IntruderCampaignId, "intruder_campaign_id");
id_type!(IntruderAttemptId, "intruder_attempt_id");
id_type!(StateChainRunId, "state_chain_run_id");

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema, TS)]
#[serde(transparent)]
pub struct Timestamp(pub String);

impl Timestamp {
    #[must_use]
    pub fn from_unix_millis(value: u128) -> Self {
        Self(value.to_string())
    }

    #[must_use]
    pub fn now() -> Self {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        Self::from_unix_millis(millis)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum Sensitivity {
    Normal,
    SensitiveEvidence,
    Credential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum RiskLevel {
    L0,
    L1,
    L2,
    L3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct OrderedValue {
    pub name: String,
    pub value: String,
}

impl Validate for OrderedValue {
    fn validate(&self) -> Result<(), DomainError> {
        validate_nonempty("name", &self.name, 64 * 1024)?;
        validate_size("value", &self.value, 1024 * 1024)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum NetworkClass {
    Loopback,
    Private,
    Internet,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum RedirectPolicy {
    Deny,
    SameOrigin,
    InScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl Validate for PortRange {
    fn validate(&self) -> Result<(), DomainError> {
        if self.start == 0 || self.end == 0 || self.start > self.end {
            return Err(DomainError::InvalidPortRange);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct DnsResolutionSnapshot {
    pub host: String,
    pub addresses: Vec<String>,
    pub resolved_at: Timestamp,
    pub peer_address: Option<String>,
    pub rebinding_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TargetScope {
    pub scope_id: ScopeId,
    pub project_id: ProjectId,
    pub schemes: Vec<String>,
    pub exact_hosts: Vec<String>,
    pub wildcard_subdomains: Vec<String>,
    pub cidrs: Vec<String>,
    pub ports: Vec<PortRange>,
    pub redirect_policy: RedirectPolicy,
    pub dns_change_policy: String,
    pub dns_snapshots: Vec<DnsResolutionSnapshot>,
    pub network_class: NetworkClass,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl Validate for TargetScope {
    fn validate(&self) -> Result<(), DomainError> {
        self.scope_id.validate()?;
        self.project_id.validate()?;
        if self.schemes.is_empty() {
            return Err(DomainError::Empty { field: "schemes" });
        }
        for scheme in &self.schemes {
            if !matches!(scheme.as_str(), "http" | "https") {
                return Err(DomainError::InvalidIdentifier { field: "scheme" });
            }
        }
        for port in &self.ports {
            port.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum HttpSource {
    Proxy,
    Repeater,
    Import,
    Tool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum RepresentationKind {
    Semantic,
    RawHttp1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum BodyState {
    Complete,
    StreamedComplete,
    Truncated,
    Missing,
    CaptureFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum MessageDirection {
    Request,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ConnectionMetadata {
    pub client_address: Option<String>,
    pub server_address: Option<String>,
    pub tls: bool,
    pub tls_version: Option<String>,
    pub certificate_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct HttpMessage {
    pub message_id: MessageId,
    pub project_id: ProjectId,
    #[serde(default)]
    pub exchange_id: Option<String>,
    pub parent_message_id: Option<MessageId>,
    pub source: HttpSource,
    pub representation_kind: RepresentationKind,
    pub method: Option<String>,
    #[serde(default)]
    pub status_code: Option<u16>,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub path: String,
    pub http_version: String,
    pub headers: Vec<OrderedValue>,
    pub trailers: Vec<OrderedValue>,
    pub query: Vec<OrderedValue>,
    pub form: Vec<OrderedValue>,
    pub body_inline: Option<Vec<u8>>,
    pub body_artifact_id: Option<ArtifactId>,
    pub wire_artifact_id: Option<ArtifactId>,
    pub serializer_version: String,
    pub body_state: BodyState,
    #[ts(type = "number | null")]
    pub declared_length: Option<u64>,
    #[ts(type = "number")]
    pub actual_length: u64,
    pub content_encoding: Option<String>,
    pub decoded_preview_state: String,
    pub direction: MessageDirection,
    pub observed_at: Timestamp,
    #[ts(type = "number | null")]
    pub duration_millis: Option<u64>,
    pub connection: ConnectionMetadata,
    pub sensitivity: Sensitivity,
    pub redacted_view: String,
}

impl Validate for HttpMessage {
    fn validate(&self) -> Result<(), DomainError> {
        self.message_id.validate()?;
        self.project_id.validate()?;
        if let Some(exchange_id) = &self.exchange_id {
            validate_nonempty("exchange_id", exchange_id, 128)?;
            if exchange_id.contains('\0') {
                return Err(DomainError::InvalidIdentifier {
                    field: "exchange_id",
                });
            }
        }
        if let Some(body) = &self.body_inline
            && body.len() > MAX_INLINE_BODY_BYTES
        {
            return Err(DomainError::TooLarge {
                field: "body_inline",
                maximum: MAX_INLINE_BODY_BYTES,
            });
        }
        if self.representation_kind == RepresentationKind::RawHttp1
            && self.wire_artifact_id.is_none()
        {
            return Err(DomainError::Empty {
                field: "wire_artifact_id",
            });
        }
        if self
            .status_code
            .is_some_and(|status| !(100..=599).contains(&status))
        {
            return Err(DomainError::InvalidIdentifier {
                field: "status_code",
            });
        }
        for value in self.headers.iter().chain(&self.trailers) {
            value.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ProxyCaptureMode {
    PassThrough,
    EvidenceStrict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ProxySessionState {
    Starting,
    Ready,
    Stopping,
    Stopped,
    Failed,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ProxySession {
    pub proxy_session_id: ProxySessionId,
    pub project_id: ProjectId,
    pub scope_id: ScopeId,
    pub state: ProxySessionState,
    pub capture_mode: ProxyCaptureMode,
    pub listen_host: String,
    pub listen_port: Option<u16>,
    pub worker_pid: Option<i32>,
    pub systemd_unit: Option<String>,
    pub cgroup_path: Option<String>,
    pub invocation_id: Option<String>,
    pub ca_sha256: Option<String>,
    pub chrome_pid: Option<i32>,
    pub ssl_insecure: bool,
    pub created_at: Timestamp,
    pub ready_at: Option<Timestamp>,
    pub stopped_at: Option<Timestamp>,
    pub error_summary: Option<String>,
}

impl Validate for ProxySession {
    fn validate(&self) -> Result<(), DomainError> {
        self.proxy_session_id.validate()?;
        self.project_id.validate()?;
        self.scope_id.validate()?;
        if self.listen_host != "127.0.0.1" || self.listen_port == Some(0) {
            return Err(DomainError::InvalidIdentifier {
                field: "proxy_listener",
            });
        }
        if let Some(fingerprint) = &self.ca_sha256
            && (fingerprint.len() != 64
                || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(DomainError::InvalidIdentifier { field: "ca_sha256" });
        }
        if let Some(error) = &self.error_summary {
            validate_size("error_summary", error, 4096)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum SecretTransport {
    None,
    Stdin,
    InheritedFd,
    ProtectedFile,
    Environment,
    ArgvException,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SecretInputLifecycle {
    pub identifier: String,
    pub transport: SecretTransport,
    pub destroy_after_open: bool,
    #[ts(type = "number | null")]
    pub lifetime_millis: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ResourceLimits {
    #[ts(type = "number")]
    pub memory_max_bytes: u64,
    pub tasks_max: u32,
    pub cpu_quota_percent: u16,
    #[ts(type = "number")]
    pub core_dump_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_max_bytes: 256 * 1024 * 1024,
            tasks_max: 64,
            cpu_quota_percent: 100,
            core_dump_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CommandSpec {
    pub command_spec_id: CommandSpecId,
    pub tool_id: String,
    pub tool_version: String,
    pub tool_sha256: String,
    pub program: String,
    #[serde(skip_serializing, skip_deserializing, default)]
    #[schemars(skip)]
    #[ts(skip)]
    pub argv_exec: Vec<String>,
    pub argv_redacted: Vec<String>,
    #[serde(skip_serializing, skip_deserializing, default)]
    #[schemars(skip)]
    #[ts(skip)]
    pub env_exec: BTreeMap<String, String>,
    pub env_redacted: BTreeMap<String, String>,
    pub secret_transport: SecretTransport,
    pub secret_inputs: Vec<SecretInputLifecycle>,
    pub cwd: String,
    pub environment_allowlist: Vec<String>,
    #[ts(type = "number")]
    pub timeout_millis: u64,
    #[ts(type = "number")]
    pub stop_grace_millis: u64,
    pub expected_outputs: Vec<String>,
    pub risk_level: RiskLevel,
    pub scope_id: Option<ScopeId>,
    pub sandbox_profile: String,
    pub resource_limits: ResourceLimits,
    pub network_isolation: String,
}

impl Validate for CommandSpec {
    fn validate(&self) -> Result<(), DomainError> {
        self.command_spec_id.validate()?;
        if !self.program.starts_with('/') || self.program.contains('\0') {
            return Err(DomainError::InvalidProgramPath);
        }
        if self.argv_redacted.iter().any(|value| value.contains('\0')) {
            return Err(DomainError::ExecutableSecretPersisted);
        }
        if self.argv_exec.len() != self.argv_redacted.len() {
            return Err(DomainError::ExecutableSecretPersisted);
        }
        if self.secret_transport != SecretTransport::ArgvException
            && self.argv_exec != self.argv_redacted
        {
            return Err(DomainError::ExecutableSecretPersisted);
        }
        if self.secret_transport != SecretTransport::Environment
            && self.env_exec != self.env_redacted
        {
            return Err(DomainError::ExecutableSecretPersisted);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Queued,
    Starting,
    Running,
    Stopping,
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
    Interrupted,
}

impl Display for ExecutionStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Queued => "queued",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::Interrupted => "interrupted",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ImportStatus {
    Pending,
    Importing,
    Imported,
    ParserFailed,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum SupervisorBackend {
    SystemdUserService,
    PgidFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct Job {
    pub job_id: JobId,
    pub parent_job_id: Option<JobId>,
    pub command_spec_id: CommandSpecId,
    pub execution_status: ExecutionStatus,
    pub import_status: ImportStatus,
    pub created_at: Timestamp,
    pub started_at: Option<Timestamp>,
    pub stopped_at: Option<Timestamp>,
    pub pid: Option<i32>,
    pub process_group_id: Option<i32>,
    #[serde(default)]
    #[ts(type = "number | null")]
    pub process_start_ticks: Option<u64>,
    pub exit_code: Option<i32>,
    pub exit_reason: Option<String>,
    pub systemd_unit: Option<String>,
    pub cgroup_path: Option<String>,
    pub invocation_id: Option<String>,
    pub supervisor_backend: Option<SupervisorBackend>,
    #[serde(default)]
    pub ownership_verified: bool,
    #[serde(default)]
    pub cleanup_verified: bool,
    #[serde(default)]
    pub residual_processes: u32,
    #[serde(default)]
    #[ts(type = "number | null")]
    pub cancel_duration_millis: Option<u64>,
    pub stdout_artifact_id: Option<ArtifactId>,
    pub stderr_artifact_id: Option<ArtifactId>,
    pub retry_count: u32,
    pub source_job_id: Option<JobId>,
}

impl Job {
    pub fn transition(&mut self, next: ExecutionStatus) -> Result<(), DomainError> {
        let allowed = matches!(
            (self.execution_status, next),
            (
                ExecutionStatus::Queued,
                ExecutionStatus::Starting | ExecutionStatus::Stopping | ExecutionStatus::Cancelled,
            ) | (
                ExecutionStatus::Starting,
                ExecutionStatus::Running
                    | ExecutionStatus::Stopping
                    | ExecutionStatus::Cancelled
                    | ExecutionStatus::Failed
                    | ExecutionStatus::Interrupted,
            ) | (
                ExecutionStatus::Running,
                ExecutionStatus::Stopping
                    | ExecutionStatus::Succeeded
                    | ExecutionStatus::Failed
                    | ExecutionStatus::TimedOut
                    | ExecutionStatus::Cancelled
                    | ExecutionStatus::Interrupted,
            ) | (
                ExecutionStatus::Stopping,
                ExecutionStatus::Cancelled | ExecutionStatus::Failed | ExecutionStatus::Interrupted,
            )
        );
        if !allowed {
            return Err(DomainError::InvalidTransition {
                from: self.execution_status.to_string(),
                to: next.to_string(),
            });
        }
        self.execution_status = next;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum DiscoveryKind {
    Url,
    Path,
    Parameter,
    Service,
    Fingerprint,
    Host,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct Discovery {
    pub discovery_id: DiscoveryId,
    pub project_id: ProjectId,
    pub kind: DiscoveryKind,
    pub raw_value: String,
    pub canonical_value: String,
    pub canonical_key: String,
    pub first_seen_at: Timestamp,
    pub last_seen_at: Timestamp,
    pub status: String,
    pub manual_labels: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ArtifactState {
    Staging,
    Committed,
    Corrupt,
    Orphaned,
}

impl Display for ArtifactState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Staging => "staging",
            Self::Committed => "committed",
            Self::Corrupt => "corrupt",
            Self::Orphaned => "orphaned",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum IntegrityState {
    Pending,
    Verified,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ExportPolicy {
    Include,
    ConfirmSensitive,
    ExcludeCredential,
    ExcludeRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct Artifact {
    pub artifact_id: ArtifactId,
    pub relative_path: String,
    pub logical_name: String,
    pub blob_relative_path: Option<String>,
    pub sha256: Option<String>,
    #[ts(type = "number | null")]
    pub size: Option<u64>,
    pub mime: String,
    pub source_job_id: Option<JobId>,
    pub source_message_id: Option<MessageId>,
    pub sensitivity: Sensitivity,
    pub state: ArtifactState,
    pub created_at: Timestamp,
    pub integrity: IntegrityState,
    pub export_policy: ExportPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct DictionaryIndex {
    pub dictionary_id: DictionaryId,
    pub project_id: ProjectId,
    pub artifact_id: ArtifactId,
    pub name: String,
    pub sha256: String,
    #[ts(type = "number")]
    pub size: u64,
    #[ts(type = "number")]
    pub term_count: u64,
    pub created_at: Timestamp,
}

impl Validate for DictionaryIndex {
    fn validate(&self) -> Result<(), DomainError> {
        self.dictionary_id.validate()?;
        self.project_id.validate()?;
        self.artifact_id.validate()?;
        validate_nonempty("dictionary_name", &self.name, 256)?;
        if self.sha256.len() != 64 || !self.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(DomainError::InvalidIdentifier {
                field: "dictionary_sha256",
            });
        }
        Ok(())
    }
}

impl Validate for Artifact {
    fn validate(&self) -> Result<(), DomainError> {
        self.artifact_id.validate()?;
        validate_nonempty("logical_name", &self.logical_name, 4096)?;
        if self.relative_path.starts_with('/') || self.relative_path.contains("..") {
            return Err(DomainError::InvalidIdentifier {
                field: "relative_path",
            });
        }
        if self.state == ArtifactState::Committed
            && (self.sha256.is_none() || self.blob_relative_path.is_none() || self.size.is_none())
        {
            return Err(DomainError::Empty {
                field: "committed artifact metadata",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum AdapterOwnership {
    Managed,
    External,
    Imported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AdapterEntity {
    pub adapter_entity_id: AdapterEntityId,
    pub project_id: Option<ProjectId>,
    pub adapter_id: String,
    pub adapter_version: String,
    pub protocol_version: String,
    pub entity_kind: String,
    pub external_id: String,
    pub parent_entity_id: Option<AdapterEntityId>,
    pub source_job_id: Option<JobId>,
    pub ownership: AdapterOwnership,
    pub state_schema_version: u32,
    pub summary_json: String,
    pub snapshot_artifact_id: Option<ArtifactId>,
    pub sensitivity: Sensitivity,
    pub redacted_view: String,
    pub created_at: Timestamp,
    pub synced_at: Timestamp,
    pub terminated_at: Option<Timestamp>,
}

impl Validate for AdapterEntity {
    fn validate(&self) -> Result<(), DomainError> {
        self.adapter_entity_id.validate()?;
        if let Some(project_id) = &self.project_id {
            project_id.validate()?;
        }
        validate_nonempty("adapter_id", &self.adapter_id, 128)?;
        validate_nonempty("entity_kind", &self.entity_kind, 128)?;
        validate_nonempty("external_id", &self.external_id, 512)?;
        validate_size("summary_json", &self.summary_json, 1024 * 1024)?;
        validate_size("redacted_view", &self.redacted_view, 256 * 1024)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AuditEvent {
    pub audit_event_id: AuditEventId,
    pub project_id: ProjectId,
    pub adapter_id: Option<String>,
    pub action: String,
    pub risk_level: RiskLevel,
    pub outcome: String,
    pub target_summary: String,
    pub details_json: String,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum IntruderAttackMode {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum IntruderCampaignKind {
    Intruder,
    Upload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum IntruderCampaignState {
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PayloadLocation {
    ByteRange,
    Path,
    Header,
    Query,
    Form,
    MultipartName,
    MultipartFilename,
    MultipartBody,
    MultipartContentType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PayloadPosition {
    pub location: PayloadLocation,
    pub name: Option<String>,
    pub occurrence: usize,
    pub start: Option<usize>,
    pub end: Option<usize>,
}

impl Validate for PayloadPosition {
    fn validate(&self) -> Result<(), DomainError> {
        if self.location == PayloadLocation::ByteRange {
            let (Some(start), Some(end)) = (self.start, self.end) else {
                return Err(DomainError::InvalidIdentifier {
                    field: "payload_byte_range",
                });
            };
            if start >= end || self.name.is_some() {
                return Err(DomainError::InvalidIdentifier {
                    field: "payload_byte_range",
                });
            }
        } else {
            let Some(name) = &self.name else {
                return Err(DomainError::Empty {
                    field: "payload_position_name",
                });
            };
            validate_nonempty("payload_position_name", name, 4096)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct IntruderCampaign {
    pub intruder_campaign_id: IntruderCampaignId,
    pub project_id: ProjectId,
    pub scope_id: ScopeId,
    pub parent_message_id: MessageId,
    pub campaign_kind: IntruderCampaignKind,
    pub attack_mode: IntruderAttackMode,
    pub state: IntruderCampaignState,
    pub positions: Vec<PayloadPosition>,
    pub dictionary_ids: Vec<DictionaryId>,
    pub global_rate_per_second: u32,
    pub target_rate_per_second: u32,
    #[ts(type = "number")]
    pub total_attempts: u64,
    #[ts(type = "number")]
    pub next_ordinal: u64,
    #[ts(type = "number")]
    pub completed_attempts: u64,
    #[ts(type = "number")]
    pub failed_attempts: u64,
    pub state_macro_json: Option<String>,
    pub created_at: Timestamp,
    pub started_at: Option<Timestamp>,
    pub stopped_at: Option<Timestamp>,
    pub error_summary: Option<String>,
}

impl Validate for IntruderCampaign {
    fn validate(&self) -> Result<(), DomainError> {
        self.intruder_campaign_id.validate()?;
        self.project_id.validate()?;
        self.scope_id.validate()?;
        self.parent_message_id.validate()?;
        if self.positions.is_empty() || self.positions.len() > 16 {
            return Err(DomainError::InvalidIdentifier {
                field: "payload_positions",
            });
        }
        for position in &self.positions {
            position.validate()?;
        }
        if self.dictionary_ids.len() > 16
            || (self.campaign_kind == IntruderCampaignKind::Intruder
                && self.dictionary_ids.is_empty())
        {
            return Err(DomainError::InvalidIdentifier {
                field: "payload_dictionaries",
            });
        }
        for dictionary_id in &self.dictionary_ids {
            dictionary_id.validate()?;
        }
        if self.global_rate_per_second == 0
            || self.target_rate_per_second == 0
            || self.total_attempts == 0
            || self.next_ordinal > self.total_attempts
            || self.completed_attempts.saturating_add(self.failed_attempts) > self.total_attempts
        {
            return Err(DomainError::InvalidIdentifier {
                field: "intruder_limits",
            });
        }
        if let Some(value) = &self.state_macro_json {
            validate_size("state_macro_json", value, 256 * 1024)?;
        }
        if let Some(value) = &self.error_summary {
            validate_size("intruder_error", value, 4096)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum IntruderAttemptState {
    Succeeded,
    RequestFailed,
    MacroFailed,
    VerificationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct IntruderAttempt {
    pub intruder_attempt_id: IntruderAttemptId,
    pub intruder_campaign_id: IntruderCampaignId,
    pub project_id: ProjectId,
    #[ts(type = "number")]
    pub ordinal: u64,
    pub payload_sha256: Vec<String>,
    pub payload_preview: Vec<String>,
    pub state: IntruderAttemptState,
    pub request_message_id: Option<MessageId>,
    pub response_message_id: Option<MessageId>,
    pub response_status: Option<u16>,
    #[ts(type = "number | null")]
    pub response_length: Option<u64>,
    #[ts(type = "number | null")]
    pub duration_millis: Option<u64>,
    pub evidence_artifact_id: Option<ArtifactId>,
    pub state_chain_run_id: Option<StateChainRunId>,
    pub verification_summary: Option<String>,
    pub error_summary: Option<String>,
    pub created_at: Timestamp,
}

impl Validate for IntruderAttempt {
    fn validate(&self) -> Result<(), DomainError> {
        self.intruder_attempt_id.validate()?;
        self.intruder_campaign_id.validate()?;
        self.project_id.validate()?;
        if self.payload_sha256.is_empty()
            || self.payload_sha256.iter().any(|value| {
                value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(DomainError::InvalidIdentifier {
                field: "payload_sha256",
            });
        }
        for value in &self.payload_preview {
            validate_size("payload_preview", value, 256)?;
        }
        if let Some(value) = &self.verification_summary {
            validate_size("verification_summary", value, 4096)?;
        }
        if let Some(value) = &self.error_summary {
            validate_size("attempt_error", value, 4096)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StateChainStepEvidence {
    pub name: String,
    pub request_message_id: Option<MessageId>,
    pub response_message_id: Option<MessageId>,
    pub outcome: String,
    pub extracted_variables: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StateChainRun {
    pub state_chain_run_id: StateChainRunId,
    pub project_id: ProjectId,
    pub intruder_attempt_id: IntruderAttemptId,
    pub steps: Vec<StateChainStepEvidence>,
    pub created_at: Timestamp,
}

impl Validate for StateChainRun {
    fn validate(&self) -> Result<(), DomainError> {
        self.state_chain_run_id.validate()?;
        self.project_id.validate()?;
        self.intruder_attempt_id.validate()?;
        if self.steps.is_empty() || self.steps.len() > 32 {
            return Err(DomainError::InvalidIdentifier {
                field: "state_chain_steps",
            });
        }
        for step in &self.steps {
            validate_nonempty("state_chain_step", &step.name, 256)?;
            validate_nonempty("state_chain_outcome", &step.outcome, 64)?;
            if step.extracted_variables.len() > 32 {
                return Err(DomainError::InvalidIdentifier {
                    field: "state_chain_variables",
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum UploadMutationKind {
    ExtensionCase,
    DoubleExtension,
    TrailingCharacter,
    ContentType,
    FilenameEncoding,
    MagicBytes,
    ImagePolyglot,
    ExtraFormField,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MultipartPart {
    pub ordinal: usize,
    pub opening_line_ending: Vec<u8>,
    pub raw_headers: Vec<u8>,
    pub header_body_separator: Vec<u8>,
    pub body: Vec<u8>,
    pub boundary_prefix: Vec<u8>,
    pub name: Option<Vec<u8>>,
    pub filename: Option<Vec<u8>>,
    pub content_type: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MultipartDocument {
    pub boundary: Vec<u8>,
    pub preamble: Vec<u8>,
    pub parts: Vec<MultipartPart>,
    pub closing_suffix: Vec<u8>,
}

impl Validate for MultipartDocument {
    fn validate(&self) -> Result<(), DomainError> {
        if self.boundary.is_empty()
            || self.boundary.len() > 200
            || self
                .boundary
                .iter()
                .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
            || self.parts.is_empty()
            || self.parts.len() > 1024
        {
            return Err(DomainError::InvalidIdentifier {
                field: "multipart_document",
            });
        }
        for (ordinal, part) in self.parts.iter().enumerate() {
            if part.ordinal != ordinal
                || !matches!(part.opening_line_ending.as_slice(), b"\r\n" | b"\n")
                || !matches!(part.header_body_separator.as_slice(), b"\r\n\r\n" | b"\n\n")
                || !matches!(part.boundary_prefix.as_slice(), b"\r\n" | b"\n")
            {
                return Err(DomainError::InvalidIdentifier {
                    field: "multipart_part",
                });
            }
        }
        Ok(())
    }
}

impl Validate for AuditEvent {
    fn validate(&self) -> Result<(), DomainError> {
        self.audit_event_id.validate()?;
        self.project_id.validate()?;
        validate_nonempty("audit_action", &self.action, 256)?;
        validate_nonempty("audit_outcome", &self.outcome, 64)?;
        validate_size("target_summary", &self.target_summary, 4096)?;
        validate_size("details_json", &self.details_json, 256 * 1024)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ProjectSummary {
    pub project_id: ProjectId,
    pub name: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub read_only: bool,
    pub schema_version: u32,
}

impl Validate for ProjectSummary {
    fn validate(&self) -> Result<(), DomainError> {
        self.project_id.validate()?;
        validate_nonempty("name", &self.name, 256)
    }
}

fn validate_nonempty(field: &'static str, value: &str, maximum: usize) -> Result<(), DomainError> {
    if value.trim().is_empty() {
        return Err(DomainError::Empty { field });
    }
    validate_size(field, value, maximum)
}

fn validate_size(field: &'static str, value: &str, maximum: usize) -> Result<(), DomainError> {
    if value.len() > maximum {
        return Err(DomainError::TooLarge { field, maximum });
    }
    Ok(())
}

#[must_use]
pub fn typescript_declarations() -> String {
    let config = ts_rs::Config::from_env();
    macro_rules! declaration {
        ($type:ty) => {
            <$type as TS>::decl(&config)
        };
    }
    let declarations = [
        declaration!(ProjectId),
        declaration!(ScopeId),
        declaration!(MessageId),
        declaration!(CommandSpecId),
        declaration!(JobId),
        declaration!(DiscoveryId),
        declaration!(ArtifactId),
        declaration!(AdapterEntityId),
        declaration!(DictionaryId),
        declaration!(ProxySessionId),
        declaration!(AuditEventId),
        declaration!(IntruderCampaignId),
        declaration!(IntruderAttemptId),
        declaration!(StateChainRunId),
        declaration!(Timestamp),
        declaration!(Sensitivity),
        declaration!(RiskLevel),
        declaration!(OrderedValue),
        declaration!(NetworkClass),
        declaration!(RedirectPolicy),
        declaration!(PortRange),
        declaration!(DnsResolutionSnapshot),
        declaration!(TargetScope),
        declaration!(HttpSource),
        declaration!(RepresentationKind),
        declaration!(BodyState),
        declaration!(MessageDirection),
        declaration!(ConnectionMetadata),
        declaration!(HttpMessage),
        declaration!(ProxyCaptureMode),
        declaration!(ProxySessionState),
        declaration!(ProxySession),
        declaration!(SecretTransport),
        declaration!(SecretInputLifecycle),
        declaration!(ResourceLimits),
        declaration!(CommandSpec),
        declaration!(ExecutionStatus),
        declaration!(ImportStatus),
        declaration!(SupervisorBackend),
        declaration!(Job),
        declaration!(DiscoveryKind),
        declaration!(Discovery),
        declaration!(ArtifactState),
        declaration!(IntegrityState),
        declaration!(ExportPolicy),
        declaration!(Artifact),
        declaration!(DictionaryIndex),
        declaration!(AdapterOwnership),
        declaration!(AdapterEntity),
        declaration!(AuditEvent),
        declaration!(IntruderAttackMode),
        declaration!(IntruderCampaignKind),
        declaration!(IntruderCampaignState),
        declaration!(PayloadLocation),
        declaration!(PayloadPosition),
        declaration!(IntruderCampaign),
        declaration!(IntruderAttemptState),
        declaration!(IntruderAttempt),
        declaration!(StateChainStepEvidence),
        declaration!(StateChainRun),
        declaration!(UploadMutationKind),
        declaration!(MultipartPart),
        declaration!(MultipartDocument),
        declaration!(ProjectSummary),
    ];
    declarations
        .map(|declaration| format!("export {declaration}"))
        .join("\n\n")
}

pub fn contract_schemas() -> Result<BTreeMap<&'static str, serde_json::Value>, serde_json::Error> {
    Ok(BTreeMap::from([
        (
            "target-scope",
            serde_json::to_value(schemars::schema_for!(TargetScope))?,
        ),
        (
            "http-message",
            serde_json::to_value(schemars::schema_for!(HttpMessage))?,
        ),
        (
            "command-spec",
            serde_json::to_value(schemars::schema_for!(CommandSpec))?,
        ),
        ("job", serde_json::to_value(schemars::schema_for!(Job))?),
        (
            "discovery",
            serde_json::to_value(schemars::schema_for!(Discovery))?,
        ),
        (
            "artifact",
            serde_json::to_value(schemars::schema_for!(Artifact))?,
        ),
        (
            "adapter-entity",
            serde_json::to_value(schemars::schema_for!(AdapterEntity))?,
        ),
        (
            "intruder-campaign",
            serde_json::to_value(schemars::schema_for!(IntruderCampaign))?,
        ),
        (
            "intruder-attempt",
            serde_json::to_value(schemars::schema_for!(IntruderAttempt))?,
        ),
        (
            "state-chain-run",
            serde_json::to_value(schemars::schema_for!(StateChainRun))?,
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_job() -> Job {
        Job {
            job_id: JobId::new(),
            parent_job_id: None,
            command_spec_id: CommandSpecId::new(),
            execution_status: ExecutionStatus::Queued,
            import_status: ImportStatus::Pending,
            created_at: Timestamp::now(),
            started_at: None,
            stopped_at: None,
            pid: None,
            process_group_id: None,
            process_start_ticks: None,
            exit_code: None,
            exit_reason: None,
            systemd_unit: None,
            cgroup_path: None,
            invocation_id: None,
            supervisor_backend: None,
            ownership_verified: false,
            cleanup_verified: false,
            residual_processes: 0,
            cancel_duration_millis: None,
            stdout_artifact_id: None,
            stderr_artifact_id: None,
            retry_count: 0,
            source_job_id: None,
        }
    }

    #[test]
    fn identifiers_require_uuid() {
        assert!(ProjectId::parse("not-a-uuid").is_err());
        assert!(ProjectId::parse(ProjectId::new().0).is_ok());
    }

    #[test]
    fn job_state_machine_separates_execution_and_import() {
        let mut job = sample_job();
        job.transition(ExecutionStatus::Starting).unwrap();
        job.transition(ExecutionStatus::Running).unwrap();
        job.transition(ExecutionStatus::Succeeded).unwrap();
        job.import_status = ImportStatus::ParserFailed;
        assert_eq!(job.execution_status, ExecutionStatus::Succeeded);
        assert_eq!(job.import_status, ImportStatus::ParserFailed);
        assert!(job.transition(ExecutionStatus::Running).is_err());
    }

    #[test]
    fn command_serialization_excludes_executable_secrets() {
        let command = CommandSpec {
            command_spec_id: CommandSpecId::new(),
            tool_id: "fixture".to_owned(),
            tool_version: "1".to_owned(),
            tool_sha256: "a".repeat(64),
            program: "/usr/bin/true".to_owned(),
            argv_exec: vec!["secret".to_owned()],
            argv_redacted: vec!["<redacted>".to_owned()],
            env_exec: BTreeMap::from([("LANG".to_owned(), "C.UTF-8".to_owned())]),
            env_redacted: BTreeMap::from([("LANG".to_owned(), "C.UTF-8".to_owned())]),
            secret_transport: SecretTransport::ArgvException,
            secret_inputs: Vec::new(),
            cwd: "/tmp".to_owned(),
            environment_allowlist: Vec::new(),
            timeout_millis: 1000,
            stop_grace_millis: 100,
            expected_outputs: Vec::new(),
            risk_level: RiskLevel::L3,
            scope_id: None,
            sandbox_profile: "none".to_owned(),
            resource_limits: ResourceLimits::default(),
            network_isolation: "input-gate-and-audit".to_owned(),
        };
        let encoded = serde_json::to_string(&command).unwrap();
        assert!(!encoded.contains("\"TOKEN\":\"secret\""));
        assert!(!encoded.contains("\"secret\""));
        assert!(!encoded.contains("argv_exec"));
        assert!(!encoded.contains("env_exec"));
    }

    #[test]
    fn schemas_cover_all_frozen_contracts() {
        let schemas = contract_schemas().unwrap();
        assert_eq!(schemas.len(), 10);
        assert!(schemas.values().all(|value| value["$schema"].is_string()));
        for name in [
            "target-scope",
            "http-message",
            "command-spec",
            "job",
            "discovery",
            "artifact",
            "adapter-entity",
            "intruder-campaign",
            "intruder-attempt",
            "state-chain-run",
        ] {
            assert!(schemas.contains_key(name), "missing schema {name}");
        }
        let typescript = typescript_declarations();
        for name in [
            "TargetScope",
            "HttpMessage",
            "CommandSpec",
            "Job",
            "Discovery",
            "Artifact",
            "AdapterEntity",
            "IntruderCampaign",
            "IntruderAttempt",
            "StateChainRun",
            "MultipartDocument",
            "UploadMutationKind",
        ] {
            assert!(typescript.contains(name), "missing declaration {name}");
        }
    }

    #[test]
    fn multipart_document_validates_round_trip_shape() {
        let document = MultipartDocument {
            boundary: b"BOUND".to_vec(),
            preamble: Vec::new(),
            parts: vec![MultipartPart {
                ordinal: 0,
                opening_line_ending: b"\r\n".to_vec(),
                raw_headers: b"Content-Disposition: form-data; name=\"a\"".to_vec(),
                header_body_separator: b"\r\n\r\n".to_vec(),
                body: b"value".to_vec(),
                boundary_prefix: b"\r\n".to_vec(),
                name: Some(b"a".to_vec()),
                filename: None,
                content_type: None,
            }],
            closing_suffix: b"\r\n".to_vec(),
        };
        assert!(document.validate().is_ok());
    }

    #[test]
    fn intruder_campaign_rejects_zero_rate() {
        let campaign = sample_campaign(0, 1);
        assert!(campaign.validate().is_err());
    }

    #[test]
    fn intruder_campaign_accepts_valid_limits() {
        let campaign = sample_campaign(10, 5);
        assert!(campaign.validate().is_ok());
    }

    fn sample_campaign(global_rate: u32, target_rate: u32) -> IntruderCampaign {
        IntruderCampaign {
            intruder_campaign_id: IntruderCampaignId::new(),
            project_id: ProjectId::new(),
            scope_id: ScopeId::new(),
            parent_message_id: MessageId::new(),
            campaign_kind: IntruderCampaignKind::Intruder,
            attack_mode: IntruderAttackMode::Sniper,
            state: IntruderCampaignState::Queued,
            positions: vec![PayloadPosition {
                location: PayloadLocation::ByteRange,
                name: None,
                occurrence: 0,
                start: Some(0),
                end: Some(4),
            }],
            dictionary_ids: vec![DictionaryId::new()],
            global_rate_per_second: global_rate,
            target_rate_per_second: target_rate,
            total_attempts: 4,
            next_ordinal: 0,
            completed_attempts: 0,
            failed_attempts: 0,
            state_macro_json: None,
            created_at: Timestamp::now(),
            started_at: None,
            stopped_at: None,
            error_summary: None,
        }
    }
}
