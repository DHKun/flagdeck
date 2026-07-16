#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::too_many_lines
)]

mod catalog_api;
mod external;
mod http;
mod intruder;
mod metasploit;
mod payloads;

pub use catalog_api::{
    CatalogCategoryDto, CatalogFormFieldDto, CatalogSnapshot, CatalogToolDto, EnsureTargetRequest,
    RunCatalogToolRequest, WordlistDto,
};
pub use external::{ExternalLauncherHealthDto, ExternalLauncherId, LaunchExternalRequest};
pub use http::*;
pub use intruder::*;
pub use metasploit::*;
pub use payloads::{
    ListPayloadsRequest, PayloadEntryDto, PayloadFormat, PayloadPage, PayloadPreview,
    PayloadSourceHealthDto, PreviewPayloadRequest,
};

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::net::{IpAddr, ToSocketAddrs};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use flagdeck_cli_adapters::{
    AdapterError, CatalogError, ExpectedOutput, OutputRole, ParsedHttpResponse,
    PreparedToolCommand, ToolCatalog, ToolId, ToolManifest, manifest, materialize_discoveries,
    parse_output, prepare_catalog_command, prepare_command, registry, write_wordlist,
};
use flagdeck_domain::{
    Artifact, ArtifactId, BodyState, CommandSpec, ConnectionMetadata, DictionaryId,
    DictionaryIndex, Discovery, DnsResolutionSnapshot, ExecutionStatus, ExportPolicy, HttpMessage,
    HttpSource, ImportStatus, IntruderCampaign, Job, JobId, MessageDirection, MessageId,
    MultipartDocument, NetworkClass, OrderedValue, PortRange, ProjectId, ProjectSummary,
    ProxySession, RedirectPolicy, RepresentationKind, ScopeId, Sensitivity, SupervisorBackend,
    TargetScope, Timestamp, Validate,
};
use flagdeck_exec::{
    CancellationResult, ExecPolicyError, ManagedExecutionResult, ManagedProcessIdentity,
    SecretPolicy, SupervisorPolicy, cancel_managed, start_managed, validate_program,
};
use flagdeck_storage::{
    ArtifactWriteRequest, JobImportRecord, MAX_DICTIONARY_TERM_BYTES, MAX_DICTIONARY_TERMS,
    OpenMode, PREVIEW_READ_LIMIT, ProjectExportEvidence, ProjectImportEvidence, ProjectStore,
    RecoveryReport, StorageError, StorageHealth, StoredJob, list_projects,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Notify;
use ts_rs::TS;
use url::Url;

pub const MAX_PROJECT_PAGE: usize = 100;
pub const MAX_NOTE_BYTES: usize = 1024 * 1024;
pub const MAX_DICTIONARY_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_JOB_LOG_PREVIEW_BYTES: usize = 64 * 1024;
pub const MAX_JOB_FILE_PREVIEW_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("another project is already active")]
    ActiveProject,
    #[error("active tool jobs must finish before closing the project")]
    ActiveJobs,
    #[error("no project is active")]
    NoActiveProject,
    #[error("request project does not match the active project")]
    ProjectMismatch,
    #[error("request validation failed")]
    InvalidRequest,
    #[error("target is outside the saved scope")]
    ScopeViolation,
    #[error("tool integrity or execution policy failed")]
    ToolUnavailable,
    #[error("job is no longer active")]
    JobNotActive,
    #[error("managed cancellation failed")]
    CancellationFailed,
    #[error("HTTP workbench operation failed: {0}")]
    Http(#[from] HttpWorkbenchError),
    #[error("Metasploit workbench operation failed: {0}")]
    Metasploit(#[from] MetasploitError),
    #[error("Intruder workbench operation failed: {0}")]
    Intruder(#[from] IntruderError),
    #[error("external launcher operation failed: {0}")]
    ExternalLauncher(#[from] external::ExternalLauncherError),
    #[error("payload browser operation failed: {0}")]
    PayloadBrowser(#[from] payloads::PayloadBrowserError),
    #[error("sensitive binary preview requires a future explicit reveal flow")]
    SensitivePreviewDenied,
    #[error("credential persistence is disabled")]
    CredentialPersistenceDenied,
    #[error("Core state lock failed")]
    StateLock,
    #[error("storage operation failed: {0}")]
    Storage(#[from] StorageError),
    #[error("adapter operation failed: {0}")]
    Adapter(#[from] AdapterError),
    #[error("execution operation failed: {0}")]
    Exec(#[from] ExecPolicyError),
    #[error("Core I/O operation failed")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CommandError {
    pub code: String,
    pub message: String,
}

impl From<CoreError> for CommandError {
    fn from(error: CoreError) -> Self {
        let (code, message) = match error {
            CoreError::ActiveProject => ("active_project", "Another project is already active"),
            CoreError::ActiveJobs => ("active_jobs", "Active tool jobs are still running"),
            CoreError::NoActiveProject => ("no_active_project", "No project is active"),
            CoreError::ProjectMismatch => (
                "project_mismatch",
                "The request does not match the active project",
            ),
            CoreError::InvalidRequest => ("invalid_request", "Request validation failed"),
            CoreError::ScopeViolation => (
                "scope_violation",
                "The target is outside the saved scope or its DNS snapshot changed",
            ),
            CoreError::ToolUnavailable => (
                "tool_unavailable",
                "The selected tool failed its integrity or health policy",
            ),
            CoreError::JobNotActive => ("job_not_active", "The job is no longer active"),
            CoreError::CancellationFailed => {
                ("cancellation_failed", "Managed job cancellation failed")
            }
            CoreError::SensitivePreviewDenied => (
                "sensitive_preview_denied",
                "Sensitive binary preview requires an explicit reveal flow",
            ),
            CoreError::CredentialPersistenceDenied => (
                "credential_persistence_denied",
                "Credential persistence is disabled",
            ),
            CoreError::StateLock => ("state_lock", "Core state is temporarily unavailable"),
            CoreError::Http(_) => ("http_workbench_error", "HTTP workbench operation failed"),
            CoreError::Metasploit(MetasploitError::ScopeViolation) => (
                "scope_violation",
                "The Metasploit target is outside the saved TargetScope",
            ),
            CoreError::Metasploit(MetasploitError::ConfirmationRequired) => (
                "l3_confirmation_required",
                "The exact L3 confirmation phrase is required",
            ),
            CoreError::Metasploit(MetasploitError::ActiveSessions) => (
                "active_sessions",
                "Active sessions require confirmed termination",
            ),
            CoreError::Metasploit(_) => (
                "metasploit_workbench_error",
                "Metasploit workbench operation failed",
            ),
            CoreError::Intruder(IntruderError::ConfirmationRequired) => (
                "l3_confirmation_required",
                "The exact L3 upload execution confirmation phrase is required",
            ),
            CoreError::Intruder(IntruderError::AlreadyActive) => (
                "intruder_already_active",
                "The Intruder campaign is already running",
            ),
            CoreError::Intruder(IntruderError::InvalidState) => (
                "intruder_invalid_state",
                "The Intruder campaign cannot transition from its current state",
            ),
            CoreError::Intruder(IntruderError::Multipart) => (
                "intruder_multipart_error",
                "Multipart parsing or mutation failed",
            ),
            CoreError::Intruder(IntruderError::InvalidRequest) => (
                "intruder_invalid_request",
                "The Intruder or upload request failed validation",
            ),
            CoreError::Intruder(_) => (
                "intruder_workbench_error",
                "Intruder workbench operation failed",
            ),
            CoreError::ExternalLauncher(external::ExternalLauncherError::ConfirmationRequired) => (
                "l3_confirmation_required",
                "The exact external launcher L3 confirmation phrase is required",
            ),
            CoreError::ExternalLauncher(external::ExternalLauncherError::Integrity) => (
                "tool_unavailable",
                "The external launcher failed its integrity or permission policy",
            ),
            CoreError::ExternalLauncher(_) => (
                "external_launcher_error",
                "External launcher operation failed",
            ),
            CoreError::PayloadBrowser(payloads::PayloadBrowserError::SourceUnavailable) => (
                "payload_source_unavailable",
                "The payload source failed its ownership or permission policy",
            ),
            CoreError::PayloadBrowser(payloads::PayloadBrowserError::NotFound) => {
                ("payload_not_found", "The payload entry was not found")
            }
            CoreError::PayloadBrowser(_) => {
                ("payload_browser_error", "Payload browser operation failed")
            }
            CoreError::Storage(StorageError::WriterLocked) => {
                ("writer_locked", "The project already has an active writer")
            }
            CoreError::Storage(StorageError::ReadOnly) => {
                ("read_only", "The project is open read-only")
            }
            CoreError::Storage(_) => ("storage_error", "Storage operation failed"),
            CoreError::Adapter(_) => ("adapter_error", "Tool adapter operation failed"),
            CoreError::Exec(_) => ("execution_error", "Managed execution failed"),
            CoreError::Io(_) => ("io_error", "Core file operation failed"),
        };
        Self {
            code: code.to_owned(),
            message: message.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CreateProjectRequest {
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ProjectOpenMode {
    ReadWrite,
    ReadOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct OpenProjectRequest {
    pub project_id: ProjectId,
    pub mode: ProjectOpenMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ProjectPageRequest {
    pub cursor: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ProjectPage {
    pub items: Vec<ProjectSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CreateNoteRequest {
    pub project_id: ProjectId,
    pub logical_name: String,
    pub content: String,
    pub sensitivity: Sensitivity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PreviewMode {
    Text,
    Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PreviewArtifactRequest {
    pub project_id: ProjectId,
    pub artifact_id: ArtifactId,
    #[ts(type = "number")]
    pub offset: u64,
    pub limit: usize,
    pub mode: PreviewMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArtifactPreview {
    pub artifact_id: ArtifactId,
    pub mode: PreviewMode,
    pub content: String,
    pub bytes_returned: usize,
    #[ts(type = "number")]
    pub next_offset: u64,
    pub eof: bool,
    pub redacted: bool,
    pub sensitivity: Sensitivity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArtifactPageRequest {
    pub project_id: ProjectId,
    pub cursor: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ArtifactPage {
    pub items: Vec<Artifact>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CreateScopeRequest {
    pub project_id: ProjectId,
    pub base_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ProjectContextRequest {
    pub project_id: ProjectId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ScopePage {
    pub items: Vec<TargetScope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum AlphaTool {
    Curl,
    Dddd,
    Ffuf,
    Arjun,
    Fscan,
    Gobuster,
    Wafw00f,
}

impl From<AlphaTool> for ToolId {
    fn from(value: AlphaTool) -> Self {
        match value {
            AlphaTool::Curl => Self::Curl,
            AlphaTool::Dddd => Self::Dddd,
            AlphaTool::Ffuf => Self::Ffuf,
            AlphaTool::Arjun => Self::Arjun,
            AlphaTool::Fscan => Self::Fscan,
            AlphaTool::Gobuster => Self::Gobuster,
            AlphaTool::Wafw00f => Self::Wafw00f,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct RunToolRequest {
    pub project_id: ProjectId,
    pub scope_id: ScopeId,
    pub tool: AlphaTool,
    pub target_url: String,
    pub wordlist_terms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct JobView {
    pub job: Job,
    pub tool_id: String,
    pub command_preview: String,
    pub network_isolation: String,
    pub parser_id: Option<String>,
    pub parser_version: Option<String>,
    pub parser_error: Option<String>,
    pub discovery_count: usize,
    pub http_message_count: usize,
}

impl From<StoredJob> for JobView {
    fn from(value: StoredJob) -> Self {
        let command_preview = format_command_preview(&value.command_spec);
        let (parser_id, parser_version, parser_error, discovery_count, http_message_count) =
            value.import.map_or((None, None, None, 0, 0), |record| {
                (
                    Some(record.parser_id),
                    Some(record.parser_version),
                    record.error_summary,
                    record.discovery_count,
                    record.http_message_count,
                )
            });
        Self {
            job: value.job,
            tool_id: value.command_spec.tool_id,
            command_preview,
            network_isolation: value.command_spec.network_isolation,
            parser_id,
            parser_version,
            parser_error,
            discovery_count,
            http_message_count,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct JobPageRequest {
    pub project_id: ProjectId,
    pub cursor: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct JobPage {
    pub items: Vec<JobView>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct DeleteJobRequest {
    pub project_id: ProjectId,
    pub job_id: JobId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct DeleteJobResult {
    pub job_id: JobId,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ClearJobsRequest {
    pub project_id: ProjectId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ClearJobsResult {
    pub deleted: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum JobLogStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PreviewJobLogRequest {
    pub project_id: ProjectId,
    pub job_id: JobId,
    pub stream: JobLogStream,
    #[ts(type = "number")]
    pub offset: u64,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct JobLogPreview {
    pub job_id: JobId,
    pub stream: JobLogStream,
    pub content: String,
    pub bytes_returned: usize,
    #[ts(type = "number")]
    pub next_offset: u64,
    pub eof: bool,
}

/// Read a sidecar result file from a job scan directory (e.g. ffuf-output.json).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PreviewJobFileRequest {
    pub project_id: ProjectId,
    pub job_id: JobId,
    /// Basename only; must match a safe allowlist pattern.
    pub filename: String,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct JobFilePreview {
    pub job_id: JobId,
    pub filename: String,
    pub content: String,
    pub bytes_returned: usize,
    pub found: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct DiscoveryPageRequest {
    pub project_id: ProjectId,
    pub cursor: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct DiscoveryPage {
    pub items: Vec<Discovery>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ToolHealthDto {
    pub tool: AlphaTool,
    pub name: String,
    pub pack_id: String,
    pub pack_name: String,
    pub pack_version: String,
    pub category: String,
    pub summary: String,
    pub integration_mode: String,
    pub distribution: String,
    pub license: String,
    pub homepage: String,
    pub resolution_source: String,
    pub path: String,
    pub version: String,
    pub sha256: String,
    pub risk_level: String,
    pub health_strategy: String,
    pub parser_id: String,
    pub parser_version: String,
    pub fixture_manifest: String,
    pub adapter_type: String,
    pub capabilities: Vec<String>,
    pub permissions: Vec<String>,
    pub network_policy: String,
    #[ts(type = "number")]
    pub memory_max_bytes: u64,
    pub tasks_max: u32,
    pub cpu_quota_percent: u16,
    #[ts(type = "number")]
    pub timeout_millis: u64,
    pub runtime_fingerprint: String,
    pub healthy: bool,
    pub detail: String,
    pub side_effect_free_help: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ToolPackHealthDto {
    pub pack_id: String,
    pub name: String,
    pub version: String,
    pub platform: String,
    pub description: String,
    pub tools_ready: usize,
    pub tools_total: usize,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct RunToolResult {
    pub job: JobView,
    pub artifacts: Vec<Artifact>,
    pub discoveries_imported: usize,
    pub http_messages_imported: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CancelJobRequest {
    pub project_id: ProjectId,
    pub job_id: JobId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CancelJobResult {
    pub job_id: JobId,
    pub accepted: bool,
    pub pending_identity: bool,
    pub cleanup_verified: bool,
    pub residual_processes: u32,
    #[ts(type = "number | null")]
    pub duration_millis: Option<u64>,
    pub signals_sent: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CancelAllJobsResult {
    pub requested: usize,
    pub results: Vec<CancelJobResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CreateDictionaryRequest {
    pub project_id: ProjectId,
    pub name: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct DictionaryPage {
    pub items: Vec<DictionaryIndex>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SearchDictionaryRequest {
    pub project_id: ProjectId,
    pub dictionary_id: DictionaryId,
    pub prefix: String,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct DictionarySearchResult {
    pub dictionary_id: DictionaryId,
    pub terms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ExportProjectRequest {
    pub project_id: ProjectId,
    pub confirm_sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ExportProjectResult {
    pub archive_name: String,
    pub sha256: String,
    #[ts(type = "number")]
    pub size: u64,
    pub file_count: usize,
    pub included_artifacts: usize,
    pub excluded_artifacts: usize,
    pub created_at: Timestamp,
}

impl From<ProjectExportEvidence> for ExportProjectResult {
    fn from(value: ProjectExportEvidence) -> Self {
        Self {
            archive_name: value.archive_name,
            sha256: value.sha256,
            size: value.size,
            file_count: value.file_count,
            included_artifacts: value.included_artifacts,
            excluded_artifacts: value.excluded_artifacts,
            created_at: value.created_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ImportPackage {
    pub archive_name: String,
    #[ts(type = "number")]
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ImportPackagePage {
    pub items: Vec<ImportPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ImportProjectRequest {
    pub archive_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ImportProjectResult {
    pub project: ProjectSummary,
    pub archive_sha256: String,
    #[ts(type = "number")]
    pub archive_size: u64,
    pub file_count: usize,
    #[ts(type = "number")]
    pub extracted_bytes: u64,
}

impl From<ProjectImportEvidence> for ImportProjectResult {
    fn from(value: ProjectImportEvidence) -> Self {
        Self {
            project: value.project,
            archive_sha256: value.archive_sha256,
            archive_size: value.archive_size,
            file_count: value.file_count,
            extracted_bytes: value.extracted_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct RecoveryStatusDto {
    #[ts(type = "number")]
    pub interrupted_jobs: u64,
    #[ts(type = "number")]
    pub interrupted_imports: u64,
    #[ts(type = "number")]
    pub interrupted_proxy_sessions: u64,
    #[ts(type = "number")]
    pub staging_committed: u64,
    #[ts(type = "number")]
    pub staging_orphaned: u64,
    #[ts(type = "number")]
    pub committed_corrupt: u64,
    #[ts(type = "number")]
    pub temporary_files_removed: u64,
}

impl From<RecoveryReport> for RecoveryStatusDto {
    fn from(value: RecoveryReport) -> Self {
        Self {
            interrupted_jobs: value.interrupted_jobs,
            interrupted_imports: value.interrupted_imports,
            interrupted_proxy_sessions: value.interrupted_proxy_sessions,
            staging_committed: value.staging_committed,
            staging_orphaned: value.staging_orphaned,
            committed_corrupt: value.committed_corrupt,
            temporary_files_removed: value.temporary_files_removed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StorageHealthDto {
    pub sqlite_version: String,
    pub sqlite_version_number: i32,
    pub minimum_safe_version: i32,
    pub quick_check: String,
    pub fts5_available: bool,
    pub schema_version: u32,
    pub read_only: bool,
    pub query_only: bool,
    pub writer_queue_capacity: usize,
}

impl From<StorageHealth> for StorageHealthDto {
    fn from(value: StorageHealth) -> Self {
        Self {
            sqlite_version: value.sqlite_version,
            sqlite_version_number: value.sqlite_version_number,
            minimum_safe_version: value.minimum_safe_version,
            quick_check: value.quick_check,
            fts5_available: value.fts5_available,
            schema_version: value.schema_version,
            read_only: value.read_only,
            query_only: value.query_only,
            writer_queue_capacity: value.writer_queue_capacity,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SecurityBaselineDto {
    pub preferred_supervisor: String,
    pub fallback_supervisor: String,
    #[ts(type = "number")]
    pub memory_max_bytes: u64,
    pub tasks_max: u32,
    pub cpu_quota_percent: u16,
    #[ts(type = "number")]
    pub cleanup_deadline_millis: u64,
    pub log_channel_bytes: usize,
    pub preferred_credential_channel: String,
    pub same_uid_environment_exposure: bool,
    pub same_uid_credential_copy_exposure: bool,
}

impl Default for SecurityBaselineDto {
    fn default() -> Self {
        let supervisor = SupervisorPolicy::default();
        let secret = SecretPolicy::default();
        Self {
            preferred_supervisor: "systemd_user_service".to_owned(),
            fallback_supervisor: "pgid_fallback".to_owned(),
            memory_max_bytes: supervisor.memory_max_bytes,
            tasks_max: supervisor.tasks_max,
            cpu_quota_percent: supervisor.cpu_quota_percent,
            cleanup_deadline_millis: supervisor.cleanup_deadline_millis,
            log_channel_bytes: supervisor.stdout_stderr_channel_chunks
                * supervisor.stdout_stderr_chunk_bytes,
            preferred_credential_channel: "systemd_load_credential_from_unix_socket".to_owned(),
            same_uid_environment_exposure: secret.same_uid_proc_environment_exposure,
            same_uid_credential_copy_exposure: secret.same_uid_systemd_credential_copy_exposure,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AppStatus {
    pub application_version: String,
    pub contract_version: u32,
    pub active_project: Option<ProjectSummary>,
    pub storage: Option<StorageHealthDto>,
    pub recovery: Option<RecoveryStatusDto>,
    pub active_jobs: usize,
    pub security: SecurityBaselineDto,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CoreEvent {
    #[ts(type = "number")]
    pub sequence: u64,
    pub kind: String,
    pub project_id: Option<ProjectId>,
}

pub struct CoreService {
    workspaces_root: PathBuf,
    active: Mutex<Option<Arc<ProjectStore>>>,
    active_runs: Arc<AtomicUsize>,
    active_executions: Mutex<HashMap<JobId, Arc<ActiveExecution>>>,
    event_sequence: AtomicU64,
    http_workbench: HttpWorkbench,
    metasploit_workbench: MetasploitWorkbench,
    intruder_workbench: IntruderWorkbench,
}

impl CoreService {
    #[must_use]
    pub fn new(workspaces_root: impl Into<PathBuf>) -> Self {
        Self::with_http_worker_source(workspaces_root, None)
    }

    #[must_use]
    pub fn with_http_worker_source(
        workspaces_root: impl Into<PathBuf>,
        worker_source_root: Option<PathBuf>,
    ) -> Self {
        Self::with_resource_paths(workspaces_root, worker_source_root, None, None)
    }

    #[must_use]
    pub fn with_resource_paths(
        workspaces_root: impl Into<PathBuf>,
        worker_source_root: Option<PathBuf>,
        metasploit_adapter: Option<PathBuf>,
        metasploit_launcher: Option<PathBuf>,
    ) -> Self {
        Self::with_bundled_resources(
            workspaces_root,
            worker_source_root,
            None,
            metasploit_adapter,
            metasploit_launcher,
        )
    }

    #[must_use]
    pub fn with_bundled_resources(
        workspaces_root: impl Into<PathBuf>,
        worker_source_root: Option<PathBuf>,
        uv_program: Option<PathBuf>,
        metasploit_adapter: Option<PathBuf>,
        metasploit_launcher: Option<PathBuf>,
    ) -> Self {
        Self {
            workspaces_root: workspaces_root.into(),
            active: Mutex::new(None),
            active_runs: Arc::new(AtomicUsize::new(0)),
            active_executions: Mutex::new(HashMap::new()),
            event_sequence: AtomicU64::new(0),
            http_workbench: worker_source_root.map_or_else(HttpWorkbench::new, |source| {
                HttpWorkbench::with_worker_source_and_uv(source, uv_program)
            }),
            metasploit_workbench: MetasploitWorkbench::new(metasploit_adapter, metasploit_launcher),
            intruder_workbench: IntruderWorkbench::new(),
        }
    }

    pub fn status(&self) -> Result<AppStatus, CoreError> {
        let active = self.lock_active()?;
        let (active_project, storage, recovery) =
            active.as_ref().map_or(Ok((None, None, None)), |store| {
                Ok::<_, CoreError>((
                    Some(store.summary()?),
                    Some(StorageHealthDto::from(store.health()?)),
                    Some(RecoveryStatusDto::from(store.recovery_report().clone())),
                ))
            })?;
        Ok(AppStatus {
            application_version: env!("CARGO_PKG_VERSION").to_owned(),
            contract_version: flagdeck_domain::CONTRACT_VERSION,
            active_project,
            storage,
            recovery,
            active_jobs: self.active_runs.load(Ordering::SeqCst),
            security: SecurityBaselineDto::default(),
        })
    }

    #[must_use]
    pub fn exit_requires_metasploit_shutdown(&self) -> bool {
        self.metasploit_workbench.has_active()
    }

    #[must_use]
    pub fn exit_requires_intruder_shutdown(&self) -> bool {
        self.intruder_workbench.has_active()
    }

    pub fn create_project(
        &self,
        request: &CreateProjectRequest,
    ) -> Result<ProjectSummary, CoreError> {
        validate_project_name(&request.name)?;
        let mut active = self.lock_active()?;
        if active.is_some() {
            return Err(CoreError::ActiveProject);
        }
        let (store, summary) = ProjectStore::create(&self.workspaces_root, &request.name)?;
        *active = Some(Arc::new(store));
        Ok(summary)
    }

    pub fn list_projects(&self, request: &ProjectPageRequest) -> Result<ProjectPage, CoreError> {
        if request.limit == 0 || request.limit > MAX_PROJECT_PAGE {
            return Err(CoreError::InvalidRequest);
        }
        let offset = request
            .cursor
            .as_deref()
            .map(str::parse::<usize>)
            .transpose()
            .map_err(|_| CoreError::InvalidRequest)?
            .unwrap_or(0);
        let projects = list_projects(&self.workspaces_root)?;
        let items = projects
            .iter()
            .skip(offset)
            .take(request.limit)
            .cloned()
            .collect::<Vec<_>>();
        let next = offset + items.len();
        Ok(ProjectPage {
            items,
            next_cursor: (next < projects.len()).then(|| next.to_string()),
        })
    }

    pub fn open_project(&self, request: &OpenProjectRequest) -> Result<ProjectSummary, CoreError> {
        request
            .project_id
            .validate()
            .map_err(|_| CoreError::InvalidRequest)?;
        let mut active = self.lock_active()?;
        if active.is_some() {
            return Err(CoreError::ActiveProject);
        }
        let mode = match request.mode {
            ProjectOpenMode::ReadWrite => OpenMode::ReadWrite,
            ProjectOpenMode::ReadOnly => OpenMode::ReadOnly,
        };
        let store = ProjectStore::open(&self.workspaces_root, &request.project_id, mode)?;
        let summary = store.summary()?;
        *active = Some(Arc::new(store));
        Ok(summary)
    }

    pub fn close_project(&self) -> Result<(), CoreError> {
        let mut active = self.lock_active()?;
        if self.active_runs.load(Ordering::SeqCst) > 0
            || self.http_workbench.has_active()
            || self.metasploit_workbench.has_active()
            || self.intruder_workbench.has_active()
        {
            return Err(CoreError::ActiveJobs);
        }
        active.take().ok_or(CoreError::NoActiveProject)?;
        Ok(())
    }

    pub fn create_note(&self, request: CreateNoteRequest) -> Result<Artifact, CoreError> {
        if request.content.len() > MAX_NOTE_BYTES
            || request.logical_name.trim().is_empty()
            || request.logical_name.len() > 256
        {
            return Err(CoreError::InvalidRequest);
        }
        if request.sensitivity == Sensitivity::Credential {
            return Err(CoreError::CredentialPersistenceDenied);
        }
        self.with_active(&request.project_id, |store| {
            let write_request = ArtifactWriteRequest {
                logical_name: request.logical_name,
                mime: "text/plain; charset=utf-8".to_owned(),
                sensitivity: request.sensitivity,
                export_policy: if request.sensitivity == Sensitivity::Normal {
                    ExportPolicy::Include
                } else {
                    ExportPolicy::ConfirmSensitive
                },
                source_job_id: None,
                source_message_id: None,
                expected_size: Some(
                    u64::try_from(request.content.len()).map_err(|_| CoreError::InvalidRequest)?,
                ),
                expected_sha256: None,
            };
            store
                .commit_artifact(&write_request, request.content.as_bytes())
                .map_err(Into::into)
        })
    }

    pub fn preview_artifact(
        &self,
        request: PreviewArtifactRequest,
    ) -> Result<ArtifactPreview, CoreError> {
        if request.limit == 0 || request.limit > PREVIEW_READ_LIMIT {
            return Err(CoreError::InvalidRequest);
        }
        self.with_active(&request.project_id, |store| {
            let artifact = store.artifact(&request.artifact_id)?;
            if request.mode == PreviewMode::Hex && artifact.sensitivity != Sensitivity::Normal {
                return Err(CoreError::SensitivePreviewDenied);
            }
            let bytes =
                store.read_artifact_range(&request.artifact_id, request.offset, request.limit)?;
            let bytes_returned = bytes.len();
            let next_offset = request
                .offset
                .checked_add(u64::try_from(bytes_returned).map_err(|_| CoreError::InvalidRequest)?)
                .ok_or(CoreError::InvalidRequest)?;
            let size = artifact.size.unwrap_or(0);
            let content = match request.mode {
                PreviewMode::Text => redact_and_escape_text(&bytes),
                PreviewMode::Hex => hex_preview(&bytes),
            };
            Ok(ArtifactPreview {
                artifact_id: request.artifact_id,
                mode: request.mode,
                content,
                bytes_returned,
                next_offset,
                eof: next_offset >= size,
                redacted: request.mode == PreviewMode::Text,
                sensitivity: artifact.sensitivity,
            })
        })
    }

    pub fn list_artifacts(&self, request: &ArtifactPageRequest) -> Result<ArtifactPage, CoreError> {
        if request.limit == 0 || request.limit > 100 {
            return Err(CoreError::InvalidRequest);
        }
        self.with_active(&request.project_id, |store| {
            let (items, next_cursor) =
                store.list_artifacts(request.limit, request.cursor.as_deref())?;
            Ok(ArtifactPage { items, next_cursor })
        })
    }

    pub fn create_scope(&self, request: &CreateScopeRequest) -> Result<TargetScope, CoreError> {
        let origin = parse_http_url(&request.base_url)?;
        let host = origin
            .host_str()
            .ok_or(CoreError::InvalidRequest)?
            .to_ascii_lowercase();
        let port = origin
            .port_or_known_default()
            .ok_or(CoreError::InvalidRequest)?;
        let addresses = resolve_addresses(&host, port)?;
        let now = Timestamp::now();
        let scope = TargetScope {
            scope_id: ScopeId::new(),
            project_id: request.project_id.clone(),
            schemes: vec![origin.scheme().to_owned()],
            exact_hosts: vec![host.clone()],
            wildcard_subdomains: Vec::new(),
            cidrs: Vec::new(),
            ports: vec![PortRange {
                start: port,
                end: port,
            }],
            redirect_policy: RedirectPolicy::Deny,
            dns_change_policy: "deny".to_owned(),
            dns_snapshots: vec![DnsResolutionSnapshot {
                host,
                addresses: addresses.iter().map(ToString::to_string).collect(),
                resolved_at: now.clone(),
                peer_address: None,
                rebinding_action: "deny".to_owned(),
            }],
            network_class: network_class(&addresses),
            created_at: now.clone(),
            updated_at: now,
        };
        self.with_active(&request.project_id, |store| {
            store.save_target_scope(&scope)?;
            Ok(scope)
        })
    }

    pub fn list_scopes(&self, project_id: &ProjectId) -> Result<ScopePage, CoreError> {
        self.with_active(project_id, |store| {
            Ok(ScopePage {
                items: store.list_target_scopes()?,
            })
        })
    }

    pub async fn start_http_proxy(
        &self,
        request: &StartProxyRequest,
    ) -> Result<ProxySession, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        let scope = store.target_scope(&request.scope_id)?;
        self.http_workbench
            .start_proxy(store, scope, request)
            .await
            .map_err(Into::into)
    }

    pub async fn stop_http_proxy(
        &self,
        request: &StopProxyRequest,
    ) -> Result<ProxySession, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        self.http_workbench
            .stop_proxy(store, &request.project_id)
            .await
            .map_err(Into::into)
    }

    pub async fn http_proxy_status(
        &self,
        project_id: &ProjectId,
    ) -> Result<Option<ProxySession>, CoreError> {
        let _ = self.project_store(project_id, false)?;
        Ok(self.http_workbench.active_session(project_id).await)
    }

    pub async fn list_http_history(
        &self,
        request: &HttpHistoryPageRequest,
    ) -> Result<HttpHistoryPage, CoreError> {
        let store = self.project_store(&request.project_id, false)?;
        list_history(&self.http_workbench, store, request)
            .await
            .map_err(Into::into)
    }

    pub fn get_http_message(
        &self,
        request: &GetHttpMessageRequest,
    ) -> Result<HttpMessage, CoreError> {
        self.with_active(&request.project_id, |store| {
            store.http_message(&request.message_id).map_err(Into::into)
        })
    }

    pub fn repeat_http(&self, request: &RepeatHttpRequest) -> Result<RepeatHttpResult, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        let scope = store.target_scope(&request.scope_id)?;
        repeat_http_message(&store, &scope, request).map_err(Into::into)
    }

    pub fn diff_http(
        &self,
        request: &DiffHttpMessagesRequest,
    ) -> Result<HttpMessageDiff, CoreError> {
        let store = self.project_store(&request.project_id, false)?;
        diff_http_messages(&store, request).map_err(Into::into)
    }

    pub fn create_sqlmap_request(
        &self,
        request: &CreateSqlmapRequestFileRequest,
    ) -> Result<Artifact, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        create_sqlmap_request_file(&store, request).map_err(Into::into)
    }

    pub fn send_raw_http1(
        &self,
        request: &SendRawHttp1Request,
    ) -> Result<SendRawHttp1Result, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        let scope = store.target_scope(&request.scope_id)?;
        send_raw_http1(&store, &scope, request).map_err(Into::into)
    }

    pub fn start_intruder(
        &self,
        request: &StartIntruderRequest,
    ) -> Result<IntruderCampaign, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        self.intruder_workbench
            .start_intruder(store, request)
            .map_err(Into::into)
    }

    pub fn start_upload_campaign(
        &self,
        request: &StartUploadCampaignRequest,
    ) -> Result<IntruderCampaign, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        self.intruder_workbench
            .start_upload(store, request)
            .map_err(Into::into)
    }

    pub fn cancel_intruder_campaign(
        &self,
        request: &CampaignRequest,
    ) -> Result<IntruderCampaign, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        self.intruder_workbench
            .cancel(&store, request)
            .map_err(Into::into)
    }

    pub fn resume_intruder_campaign(
        &self,
        request: &CampaignRequest,
    ) -> Result<IntruderCampaign, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        self.intruder_workbench
            .resume(store, request)
            .map_err(Into::into)
    }

    pub fn list_intruder_campaigns(
        &self,
        request: &ListIntruderCampaignsRequest,
    ) -> Result<IntruderCampaignPage, CoreError> {
        let store = self.project_store(&request.project_id, false)?;
        self.intruder_workbench
            .list_campaigns(&store, request)
            .map_err(Into::into)
    }

    pub fn list_intruder_attempts(
        &self,
        request: &IntruderAttemptPageRequest,
    ) -> Result<IntruderAttemptPage, CoreError> {
        let store = self.project_store(&request.project_id, false)?;
        self.intruder_workbench
            .list_attempts(&store, request)
            .map_err(Into::into)
    }

    pub fn parse_multipart_message(
        &self,
        request: &ParseMultipartRequest,
    ) -> Result<MultipartDocument, CoreError> {
        let store = self.project_store(&request.project_id, false)?;
        self.intruder_workbench
            .parse_multipart(&store, request)
            .map_err(Into::into)
    }

    pub async fn open_http_browser_preview(
        &self,
        request: &OpenHttpBrowserPreviewRequest,
    ) -> Result<OpenHttpBrowserPreviewResult, CoreError> {
        let store = self.project_store(&request.project_id, false)?;
        let message = store.http_message(&request.message_id)?;
        self.http_workbench
            .open_browser_preview(&store, &message)
            .await
            .map_err(Into::into)
    }

    pub async fn start_metasploit(
        &self,
        request: &StartMetasploitRequest,
    ) -> Result<MetasploitStatus, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        self.metasploit_workbench
            .start(&store, request)
            .await
            .map_err(Into::into)
    }

    pub async fn metasploit_status(
        &self,
        project_id: &ProjectId,
    ) -> Result<MetasploitStatus, CoreError> {
        let _ = self.project_store(project_id, false)?;
        self.metasploit_workbench
            .status(project_id)
            .await
            .map_err(Into::into)
    }

    pub async fn stop_metasploit(
        &self,
        request: &StopMetasploitRequest,
    ) -> Result<MetasploitStatus, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        self.metasploit_workbench
            .stop(&store, request)
            .await
            .map_err(Into::into)
    }

    pub async fn search_metasploit_modules(
        &self,
        request: &SearchMetasploitModulesRequest,
    ) -> Result<Vec<MetasploitModuleSummary>, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        self.metasploit_workbench
            .search_modules(&store, request)
            .await
            .map_err(Into::into)
    }

    pub async fn get_metasploit_options(
        &self,
        request: &GetMetasploitOptionsRequest,
    ) -> Result<Vec<MetasploitModuleOption>, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        self.metasploit_workbench
            .module_options(&store, request)
            .await
            .map_err(Into::into)
    }

    pub async fn execute_metasploit_module(
        &self,
        request: &ExecuteMetasploitModuleRequest,
    ) -> Result<MetasploitExecutionResult, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        let scope = store.target_scope(&request.scope_id)?;
        self.metasploit_workbench
            .execute_module(&store, &scope, request)
            .await
            .map_err(Into::into)
    }

    pub async fn list_metasploit_entities(
        &self,
        project_id: &ProjectId,
    ) -> Result<MetasploitEntityPage, CoreError> {
        let store = self.project_store(project_id, true)?;
        self.metasploit_workbench
            .sync_entities(&store, project_id)
            .await
            .map_err(Into::into)
    }

    pub async fn create_metasploit_console(
        &self,
        project_id: &ProjectId,
    ) -> Result<flagdeck_domain::AdapterEntity, CoreError> {
        let store = self.project_store(project_id, true)?;
        self.metasploit_workbench
            .create_console(&store, project_id)
            .await
            .map_err(Into::into)
    }

    pub async fn stop_metasploit_entity(
        &self,
        request: &StopMetasploitEntityRequest,
    ) -> Result<flagdeck_domain::AdapterEntity, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        self.metasploit_workbench
            .stop_entity(&store, request)
            .await
            .map_err(Into::into)
    }

    pub async fn metasploit_console_command(
        &self,
        request: &MetasploitConsoleCommandRequest,
    ) -> Result<MetasploitTranscriptResult, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        self.metasploit_workbench
            .console_command(&store, request)
            .await
            .map_err(Into::into)
    }

    pub async fn metasploit_session_command(
        &self,
        request: &MetasploitSessionCommandRequest,
    ) -> Result<MetasploitTranscriptResult, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        self.metasploit_workbench
            .session_command(&store, request)
            .await
            .map_err(Into::into)
    }

    pub fn list_jobs(&self, request: &JobPageRequest) -> Result<JobPage, CoreError> {
        if request.limit == 0 || request.limit > 100 {
            return Err(CoreError::InvalidRequest);
        }
        self.with_active(&request.project_id, |store| {
            let (items, next_cursor) = store.list_jobs(request.limit, request.cursor.as_deref())?;
            Ok(JobPage {
                items: items.into_iter().map(Into::into).collect(),
                next_cursor,
            })
        })
    }

    pub fn delete_job(&self, request: &DeleteJobRequest) -> Result<DeleteJobResult, CoreError> {
        request
            .job_id
            .validate()
            .map_err(|_| CoreError::InvalidRequest)?;
        let store = self.project_store(&request.project_id, true)?;
        let stored = store.job(&request.job_id)?;
        if is_active_execution_status(stored.job.execution_status)
            || self
                .active_executions
                .lock()
                .map_err(|_| CoreError::StateLock)?
                .contains_key(&request.job_id)
        {
            return Err(CoreError::ActiveJobs);
        }
        let deleted = store.delete_job(&request.job_id)?;
        if deleted {
            let scan_dir = store.layout().scans.join(&request.job_id.0);
            if scan_dir.is_dir() {
                let _ = fs::remove_dir_all(&scan_dir);
            }
        }
        Ok(DeleteJobResult {
            job_id: request.job_id.clone(),
            deleted,
        })
    }

    pub fn clear_jobs(&self, request: &ClearJobsRequest) -> Result<ClearJobsResult, CoreError> {
        let store = self.project_store(&request.project_id, true)?;
        // Refuse while any job is still active in-memory or running in DB.
        if self.active_runs.load(Ordering::SeqCst) > 0
            || !self
                .active_executions
                .lock()
                .map_err(|_| CoreError::StateLock)?
                .is_empty()
        {
            return Err(CoreError::ActiveJobs);
        }
        let (items, _) = store.list_jobs(100, None)?;
        if items
            .iter()
            .any(|item| is_active_execution_status(item.job.execution_status))
        {
            return Err(CoreError::ActiveJobs);
        }
        let scan_root = store.layout().scans.clone();
        let deleted = store.clear_jobs()?;
        if scan_root.is_dir()
            && let Ok(entries) = fs::read_dir(&scan_root)
        {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let _ = fs::remove_dir_all(path);
                }
            }
        }
        Ok(ClearJobsResult { deleted })
    }

    pub fn preview_job_log(
        &self,
        request: &PreviewJobLogRequest,
    ) -> Result<JobLogPreview, CoreError> {
        if request.limit == 0 || request.limit > MAX_JOB_LOG_PREVIEW_BYTES {
            return Err(CoreError::InvalidRequest);
        }
        self.with_active(&request.project_id, |store| {
            let stored = store.job(&request.job_id)?;
            let filename = match request.stream {
                JobLogStream::Stdout => "stdout.log",
                JobLogStream::Stderr => "stderr.log",
            };
            let path = store.layout().scans.join(&request.job_id.0).join(filename);
            let mut file = match File::options()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(JobLogPreview {
                        job_id: request.job_id.clone(),
                        stream: request.stream,
                        content: String::new(),
                        bytes_returned: 0,
                        next_offset: request.offset,
                        eof: stored.job.stopped_at.is_some(),
                    });
                }
                Err(error) => return Err(error.into()),
            };
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(CoreError::InvalidRequest);
            }
            if request.offset > metadata.len() {
                return Err(CoreError::InvalidRequest);
            }
            let remaining = metadata.len() - request.offset;
            let read_length = usize::try_from(remaining.min(request.limit as u64))
                .map_err(|_| CoreError::InvalidRequest)?;
            file.seek(SeekFrom::Start(request.offset))?;
            let mut bytes = vec![0_u8; read_length];
            file.read_exact(&mut bytes)?;
            let next_offset = request.offset + read_length as u64;
            Ok(JobLogPreview {
                job_id: request.job_id.clone(),
                stream: request.stream,
                content: String::from_utf8_lossy(&bytes).into_owned(),
                bytes_returned: read_length,
                next_offset,
                eof: stored.job.stopped_at.is_some() && next_offset == metadata.len(),
            })
        })
    }

    pub fn preview_job_file(
        &self,
        request: &PreviewJobFileRequest,
    ) -> Result<JobFilePreview, CoreError> {
        if request.limit == 0 || request.limit > MAX_JOB_FILE_PREVIEW_BYTES {
            return Err(CoreError::InvalidRequest);
        }
        let filename = request.filename.trim();
        if !is_safe_job_sidecar_filename(filename) {
            return Err(CoreError::InvalidRequest);
        }
        self.with_active(&request.project_id, |store| {
            let _stored = store.job(&request.job_id)?;
            let path = store.layout().scans.join(&request.job_id.0).join(filename);
            let mut file = match File::options()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(JobFilePreview {
                        job_id: request.job_id.clone(),
                        filename: filename.to_owned(),
                        content: String::new(),
                        bytes_returned: 0,
                        found: false,
                    });
                }
                Err(error) => return Err(error.into()),
            };
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(CoreError::InvalidRequest);
            }
            let read_length = usize::try_from(metadata.len().min(request.limit as u64))
                .map_err(|_| CoreError::InvalidRequest)?;
            let mut bytes = vec![0_u8; read_length];
            file.read_exact(&mut bytes)?;
            Ok(JobFilePreview {
                job_id: request.job_id.clone(),
                filename: filename.to_owned(),
                content: String::from_utf8_lossy(&bytes).into_owned(),
                bytes_returned: read_length,
                found: true,
            })
        })
    }

    pub fn list_discoveries(
        &self,
        request: &DiscoveryPageRequest,
    ) -> Result<DiscoveryPage, CoreError> {
        if request.limit == 0 || request.limit > 100 {
            return Err(CoreError::InvalidRequest);
        }
        self.with_active(&request.project_id, |store| {
            let (items, next_cursor) =
                store.list_discoveries(request.limit, request.cursor.as_deref())?;
            Ok(DiscoveryPage { items, next_cursor })
        })
    }

    pub fn create_dictionary(
        &self,
        request: CreateDictionaryRequest,
    ) -> Result<DictionaryIndex, CoreError> {
        if request.name.trim().is_empty()
            || request.name.trim() != request.name
            || request.name.len() > 256
            || request.content.is_empty()
            || request.content.len() > MAX_DICTIONARY_INPUT_BYTES
        {
            return Err(CoreError::InvalidRequest);
        }
        let terms = normalize_dictionary_terms(&request.content)?;
        let mut canonical = terms.join("\n");
        canonical.push('\n');
        self.with_active(&request.project_id, |store| {
            if store.mode() == OpenMode::ReadOnly {
                return Err(CoreError::Storage(StorageError::ReadOnly));
            }
            let artifact = store.commit_artifact(
                &ArtifactWriteRequest {
                    logical_name: format!("dictionary-{}.txt", request.name),
                    mime: "text/plain; charset=utf-8".to_owned(),
                    sensitivity: Sensitivity::Normal,
                    export_policy: ExportPolicy::Include,
                    source_job_id: None,
                    source_message_id: None,
                    expected_size: Some(
                        u64::try_from(canonical.len()).map_err(|_| CoreError::InvalidRequest)?,
                    ),
                    expected_sha256: None,
                },
                canonical.as_bytes(),
            )?;
            let index = DictionaryIndex {
                dictionary_id: DictionaryId::new(),
                project_id: request.project_id.clone(),
                artifact_id: artifact.artifact_id,
                name: request.name,
                sha256: artifact.sha256.ok_or(CoreError::InvalidRequest)?,
                size: artifact.size.ok_or(CoreError::InvalidRequest)?,
                term_count: u64::try_from(terms.len()).map_err(|_| CoreError::InvalidRequest)?,
                created_at: Timestamp::now(),
            };
            store.index_dictionary(&index, &terms)?;
            Ok(index)
        })
    }

    pub fn list_dictionaries(&self, project_id: &ProjectId) -> Result<DictionaryPage, CoreError> {
        self.with_active(project_id, |store| {
            Ok(DictionaryPage {
                items: store.list_dictionaries()?,
            })
        })
    }

    pub fn search_dictionary(
        &self,
        request: &SearchDictionaryRequest,
    ) -> Result<DictionarySearchResult, CoreError> {
        self.with_active(&request.project_id, |store| {
            Ok(DictionarySearchResult {
                dictionary_id: request.dictionary_id.clone(),
                terms: store.search_dictionary(
                    &request.dictionary_id,
                    &request.prefix,
                    request.limit,
                )?,
            })
        })
    }

    pub fn export_project(
        &self,
        request: &ExportProjectRequest,
    ) -> Result<ExportProjectResult, CoreError> {
        if self.active_runs.load(Ordering::SeqCst) > 0 {
            return Err(CoreError::ActiveJobs);
        }
        let store = self.project_store(&request.project_id, true)?;
        Ok(store.export_project(request.confirm_sensitive)?.into())
    }

    pub fn list_import_packages(&self) -> Result<ImportPackagePage, CoreError> {
        let inbox = self.ensure_import_inbox()?;
        let mut items = Vec::new();
        for entry in fs::read_dir(inbox)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !valid_archive_name(&name) {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.permissions().mode().trailing_zeros() >= 6
            {
                items.push(ImportPackage {
                    archive_name: name,
                    size: metadata.len(),
                });
            }
        }
        items.sort_by(|left, right| left.archive_name.cmp(&right.archive_name));
        items.truncate(100);
        Ok(ImportPackagePage { items })
    }

    pub fn import_project(
        &self,
        request: &ImportProjectRequest,
    ) -> Result<ImportProjectResult, CoreError> {
        if self.active_runs.load(Ordering::SeqCst) > 0 || !valid_archive_name(&request.archive_name)
        {
            return Err(CoreError::InvalidRequest);
        }
        let inbox = self.ensure_import_inbox()?;
        let archive = inbox.join(&request.archive_name);
        Ok(ProjectStore::import_project_archive(&self.workspaces_root, &archive)?.into())
    }

    fn ensure_import_inbox(&self) -> Result<PathBuf, CoreError> {
        fs::create_dir_all(&self.workspaces_root)?;
        fs::set_permissions(&self.workspaces_root, fs::Permissions::from_mode(0o700))?;
        let inbox = self.workspaces_root.join(".imports");
        match fs::symlink_metadata(&inbox) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(CoreError::InvalidRequest),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&inbox)?;
            }
            Err(error) => return Err(error.into()),
        }
        fs::set_permissions(&inbox, fs::Permissions::from_mode(0o700))?;
        Ok(inbox)
    }

    pub fn tool_health(&self) -> Result<Vec<ToolHealthDto>, CoreError> {
        let registry = registry()?;
        let pack_name = registry.pack.name;
        let pack_version = registry.pack.version;
        registry
            .tools
            .into_iter()
            .map(|tool| {
                let alpha_tool = alpha_tool_from_id(&tool.id)?;
                let integrity = tool_integrity_matches(&tool);
                let marker_ok = integrity && health_marker_matches(&tool);
                Ok(ToolHealthDto {
                    tool: alpha_tool,
                    name: tool.name,
                    pack_id: tool.pack_id,
                    pack_name: pack_name.clone(),
                    pack_version: pack_version.clone(),
                    category: tool.category,
                    summary: tool.summary,
                    integration_mode: tool.integration_mode,
                    distribution: tool.distribution,
                    license: tool.license,
                    homepage: tool.homepage,
                    resolution_source: tool.resolution_source.clone(),
                    path: tool.path,
                    version: tool.version,
                    sha256: tool.sha256,
                    risk_level: tool.risk_level,
                    health_strategy: tool.health_strategy,
                    parser_id: tool.parser_id,
                    parser_version: tool.parser_version,
                    fixture_manifest: tool.fixture_manifest,
                    adapter_type: tool.adapter_type,
                    capabilities: tool.capabilities,
                    permissions: tool.permissions,
                    network_policy: tool.network_policy,
                    memory_max_bytes: tool.memory_max_bytes,
                    tasks_max: tool.tasks_max,
                    cpu_quota_percent: tool.cpu_quota_percent,
                    timeout_millis: tool.timeout_millis,
                    runtime_fingerprint: tool.runtime_fingerprint,
                    healthy: marker_ok,
                    detail: if marker_ok {
                        format!("ready via {}", tool.resolution_source)
                    } else if tool.resolution_source == "missing" {
                        "tool is not installed".to_owned()
                    } else if integrity {
                        "version marker check failed".to_owned()
                    } else {
                        "integrity check failed".to_owned()
                    },
                    side_effect_free_help: tool.side_effect_free_help,
                })
            })
            .collect()
    }

    pub fn tool_pack_health(&self) -> Result<Vec<ToolPackHealthDto>, CoreError> {
        let registry = registry()?;
        let tools_total = registry.tools.len();
        let tools_ready = registry
            .tools
            .iter()
            .filter(|tool| tool_integrity_matches(tool) && health_marker_matches(tool))
            .count();
        let state = match tools_ready {
            ready if ready == tools_total => "ready",
            0 => "missing",
            _ => "partial",
        };
        let recon = ToolPackHealthDto {
            pack_id: registry.pack.id,
            name: registry.pack.name,
            version: registry.pack.version,
            platform: registry.pack.platform,
            description: registry.pack.description,
            tools_ready,
            tools_total,
            state: state.to_owned(),
        };
        let external_registry = external::registry()?;
        let external_health = external::health()?;
        let external_total = external_health.len();
        let external_ready = external_health.iter().filter(|item| item.healthy).count();
        let external_state = match external_ready {
            ready if ready == external_total => "ready",
            0 => "missing",
            _ => "partial",
        };
        let compatibility = ToolPackHealthDto {
            pack_id: external_registry.pack.id,
            name: external_registry.pack.name,
            version: external_registry.pack.version,
            platform: external_registry.pack.platform,
            description: external_registry.pack.description,
            tools_ready: external_ready,
            tools_total: external_total,
            state: external_state.to_owned(),
        };
        Ok(vec![recon, compatibility])
    }

    pub fn external_launcher_health(
        &self,
        request: &ProjectContextRequest,
    ) -> Result<Vec<ExternalLauncherHealthDto>, CoreError> {
        self.project_store(&request.project_id, false)?;
        Ok(external::health()?)
    }

    pub fn payload_source_health(
        &self,
        request: &ProjectContextRequest,
    ) -> Result<Vec<PayloadSourceHealthDto>, CoreError> {
        self.project_store(&request.project_id, false)?;
        Ok(payloads::source_health()?)
    }

    pub fn list_payloads(&self, request: &ListPayloadsRequest) -> Result<PayloadPage, CoreError> {
        self.project_store(&request.project_id, false)?;
        Ok(payloads::list(request)?)
    }

    pub fn preview_payload(
        &self,
        request: &PreviewPayloadRequest,
    ) -> Result<PayloadPreview, CoreError> {
        self.project_store(&request.project_id, false)?;
        Ok(payloads::preview(request)?)
    }

    pub fn launch_external(
        self: &Arc<Self>,
        request: &LaunchExternalRequest,
    ) -> Result<JobView, CoreError> {
        let target = parse_http_url(&request.target_url)?;
        let store = self.project_store(&request.project_id, true)?;
        let scope = store.target_scope(&request.scope_id)?;
        validate_target_against_scope(&scope, &target)?;
        let manifest = external::manifest(request.launcher)?;
        let expected_confirmation = format!(
            "LAUNCH EXTERNAL {} {}",
            request.launcher.as_str(),
            request.scope_id.0
        );
        let allowed = request.confirmation == expected_confirmation;
        store.save_audit_event(&flagdeck_domain::AuditEvent {
            audit_event_id: flagdeck_domain::AuditEventId::new(),
            project_id: request.project_id.clone(),
            adapter_id: Some(format!("external.{}", request.launcher.as_str())),
            action: "external.launch".to_owned(),
            risk_level: flagdeck_domain::RiskLevel::L3,
            outcome: if allowed { "allowed" } else { "denied" }.to_owned(),
            target_summary: target.to_string(),
            details_json: serde_json::json!({
                "launcher": request.launcher.as_str(),
                "program_sha256": manifest.program_sha256,
                "capability": manifest.capability,
                "network_policy": manifest.network_policy,
            })
            .to_string(),
            created_at: Timestamp::now(),
        })?;
        if !allowed {
            return Err(external::ExternalLauncherError::ConfirmationRequired.into());
        }

        let (store, run_guard) = self.begin_run(&request.project_id)?;
        let job_id = JobId::new();
        let job_directory = create_job_directory(store.layout().scans.as_path(), &job_id)?;
        let command = external::prepare_command(&manifest, &request.scope_id, &job_directory)?;
        store.save_command_spec(&command)?;
        let job = Job {
            job_id: job_id.clone(),
            parent_job_id: None,
            command_spec_id: command.command_spec_id.clone(),
            execution_status: ExecutionStatus::Queued,
            import_status: ImportStatus::Skipped,
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
        };
        store.save_job(&job)?;
        let control = Arc::new(ActiveExecution::new(command.stop_grace_millis));
        self.active_executions
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .insert(job_id, Arc::clone(&control));
        let queued = PreparedExternalRun {
            store,
            command,
            job,
            control,
            stdout_path: job_directory.join("stdout.log"),
            stderr_path: job_directory.join("stderr.log"),
            detach_gui: false,
            _run_guard: run_guard,
        };
        let view = JobView::from(queued.store.job(&queued.job.job_id)?);
        let core = Arc::clone(self);
        tokio::spawn(async move {
            let _ = core.execute_external_launch(queued).await;
        });
        Ok(view)
    }

    async fn execute_external_launch(&self, queued: PreparedExternalRun) -> Result<(), CoreError> {
        let job_id = queued.job.job_id.clone();
        let result = self.execute_external_launch_inner(queued).await;
        let cleanup = self
            .active_executions
            .lock()
            .map_err(|_| CoreError::StateLock)
            .map(|mut active| {
                active.remove(&job_id);
            });
        result.and(cleanup)
    }

    async fn execute_external_launch_inner(
        &self,
        mut queued: PreparedExternalRun,
    ) -> Result<(), CoreError> {
        let job_id = queued.job.job_id.clone();
        queued
            .job
            .transition(ExecutionStatus::Starting)
            .map_err(|_| CoreError::InvalidRequest)?;
        queued.job.started_at = Some(Timestamp::now());
        queued.store.save_job(&queued.job)?;

        write_launch_banner(
            &queued.stdout_path,
            &queued.stderr_path,
            &queued.command,
            queued.detach_gui,
        )?;

        if queued.detach_gui {
            run_detached_gui(&mut queued).await?;
        } else {
            // Catalog CLI uses a direct spawn/wait path so short-lived tools still leave logs
            // even when systemd identity probes race with quick exits.
            run_catalog_cli(&mut queued).await?;
        }

        let stdout = commit_existing_file(
            &queued.store,
            &queued.stdout_path,
            &format!("external-{}-stdout.log", job_id.0),
            "text/plain; charset=utf-8",
            Sensitivity::SensitiveEvidence,
            &job_id,
        )?;
        let stderr = commit_existing_file(
            &queued.store,
            &queued.stderr_path,
            &format!("external-{}-stderr.log", job_id.0),
            "text/plain; charset=utf-8",
            Sensitivity::SensitiveEvidence,
            &job_id,
        )?;
        queued.job.stdout_artifact_id = stdout.map(|artifact| artifact.artifact_id);
        queued.job.stderr_artifact_id = stderr.map(|artifact| artifact.artifact_id);
        queued.store.save_job(&queued.job)?;
        Ok(())
    }

    pub fn list_catalog(&self) -> Result<CatalogSnapshot, CoreError> {
        let catalog = ToolCatalog::load_default().map_err(|e| map_catalog_error(&e))?;
        Ok(CatalogSnapshot {
            tools_root: catalog.paths.tools_root.display().to_string(),
            wordlists_root: catalog.paths.wordlists_root.display().to_string(),
            categories: catalog
                .categories
                .iter()
                .map(|category| CatalogCategoryDto {
                    id: category.id.clone(),
                    name: category.name.clone(),
                    summary: category.summary.clone(),
                    order: category.order,
                })
                .collect(),
            tools: catalog
                .tool_views()
                .into_iter()
                .map(|view| CatalogToolDto {
                    id: view.id,
                    name: view.name,
                    category: view.category,
                    category_name: view.category_name,
                    summary: view.summary,
                    usage: view.usage,
                    mode: view.mode,
                    featured: view.featured,
                    available: view.available,
                    binary_path: view.binary_path,
                    detail: view.detail,
                    icon: view.icon,
                    accent: view.accent,
                    needs_target: view.needs_target,
                    fields: view
                        .fields
                        .into_iter()
                        .map(|field| CatalogFormFieldDto {
                            id: field.id,
                            field_type: field.field_type,
                            label: field.label,
                            required: field.required,
                            default_value: field.default,
                            from: field.from,
                            options: field.options,
                            hint: field.hint,
                        })
                        .collect(),
                })
                .collect(),
            wordlists: catalog
                .wordlist_views()
                .into_iter()
                .map(|view| WordlistDto {
                    id: view.id,
                    name: view.name,
                    path: view.path,
                    available: view.available,
                    tags: view.tags,
                })
                .collect(),
        })
    }

    pub fn ensure_target_scope(
        &self,
        request: &EnsureTargetRequest,
    ) -> Result<TargetScope, CoreError> {
        let base_url = normalize_scope_base_url(&request.base_url)?;
        let target = parse_http_url(&base_url)?;
        let store = self.project_store(&request.project_id, true)?;
        for scope in store.list_target_scopes()? {
            if validate_target_against_scope(&scope, &target).is_ok() {
                return Ok(scope);
            }
        }
        self.create_scope(&CreateScopeRequest {
            project_id: request.project_id.clone(),
            base_url,
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn start_catalog_tool(
        self: &Arc<Self>,
        request: RunCatalogToolRequest,
    ) -> Result<JobView, CoreError> {
        request
            .project_id
            .validate()
            .map_err(|_| CoreError::InvalidRequest)?;
        if request.tool_id.is_empty() || request.tool_id.len() > 128 {
            return Err(CoreError::InvalidRequest);
        }
        let catalog = ToolCatalog::load_default().map_err(|e| map_catalog_error(&e))?;
        let tool = catalog
            .tool(&request.tool_id)
            .ok_or(CoreError::ToolUnavailable)?;

        let mut form = request.form.clone();
        for field in &tool.form.fields {
            if field.from == "target_url" && !request.target_url.is_empty() {
                form.entry(field.id.clone())
                    .or_insert_with(|| request.target_url.clone());
            }
            if !field.default.is_empty() {
                form.entry(field.id.clone())
                    .or_insert_with(|| field.default.clone());
            }
        }

        // Scope only when the tool actually needs a network target.
        let scope_seed = form
            .get("url")
            .cloned()
            .filter(|value| !value.is_empty())
            .or_else(|| form.get("target").cloned().filter(|v| !v.is_empty()))
            .or_else(|| form.get("host").cloned().filter(|v| !v.is_empty()))
            .or_else(|| (!request.target_url.is_empty()).then(|| request.target_url.clone()));

        let scope = if let Some(seed) = &scope_seed {
            let scope = self.ensure_target_scope(&EnsureTargetRequest {
                project_id: request.project_id.clone(),
                base_url: seed.clone(),
            })?;
            if let Ok(base) = normalize_scope_base_url(seed) {
                let target = parse_http_url(&base)?;
                validate_target_against_scope(&scope, &target)?;
            }
            scope
        } else {
            let store = self.project_store(&request.project_id, true)?;
            if let Some(scope) = store.list_target_scopes()?.into_iter().next() {
                scope
            } else {
                self.create_scope(&CreateScopeRequest {
                    project_id: request.project_id.clone(),
                    base_url: "http://127.0.0.1/".to_owned(),
                })?
            }
        };

        let (store, run_guard) = self.begin_run(&request.project_id)?;
        let job_id = JobId::new();
        let job_directory = create_job_directory(store.layout().scans.as_path(), &job_id)?;
        let prepared = prepare_catalog_command(
            &catalog,
            &request.tool_id,
            &scope.scope_id,
            &form,
            &job_directory,
        )
        .map_err(|e| map_catalog_error(&e))?;

        let command = prepared.spec;
        store.save_command_spec(&command)?;

        let job = Job {
            job_id: job_id.clone(),
            parent_job_id: None,
            command_spec_id: command.command_spec_id.clone(),
            execution_status: ExecutionStatus::Queued,
            import_status: ImportStatus::Skipped,
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
        };
        store.save_job(&job)?;
        let control = Arc::new(ActiveExecution::new(command.stop_grace_millis));
        self.active_executions
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .insert(job_id, Arc::clone(&control));

        // Classic GUI windows detach after a short probe; long-running servers
        // (npm run dev, etc.) set catalog `detach = false` so cancel stays available.
        let detach_gui = prepared.detach;
        let queued = PreparedExternalRun {
            store,
            command,
            job,
            control,
            stdout_path: prepared.stdout_path,
            stderr_path: prepared.stderr_path,
            detach_gui,
            _run_guard: run_guard,
        };
        let view = JobView::from(queued.store.job(&queued.job.job_id)?);
        let core = Arc::clone(self);
        tokio::spawn(async move {
            let _ = core.execute_external_launch(queued).await;
        });
        Ok(view)
    }

    pub fn start_tool(self: &Arc<Self>, request: RunToolRequest) -> Result<JobView, CoreError> {
        let queued = self.prepare_tool_run(request)?;
        let view = JobView::from(queued.store.job(&queued.job.job_id)?);
        let core = Arc::clone(self);
        tokio::spawn(async move {
            let _ = core.execute_tool_run(queued).await;
        });
        Ok(view)
    }

    pub async fn run_tool(&self, request: RunToolRequest) -> Result<RunToolResult, CoreError> {
        let queued = self.prepare_tool_run(request)?;
        self.execute_tool_run(queued).await
    }

    fn prepare_tool_run(&self, request: RunToolRequest) -> Result<PreparedRun, CoreError> {
        let target = parse_http_url(&request.target_url)?;
        let (store, run_guard) = self.begin_run(&request.project_id)?;
        let scope = store.target_scope(&request.scope_id)?;
        validate_target_against_scope(&scope, &target)?;
        let tool_id = ToolId::from(request.tool);
        let tool_manifest = manifest(tool_id)?;
        if !tool_integrity_matches(&tool_manifest) || !health_marker_matches(&tool_manifest) {
            return Err(CoreError::ToolUnavailable);
        }
        let job_id = JobId::new();
        let job_directory = create_job_directory(store.layout().scans.as_path(), &job_id)?;
        let wordlist = if matches!(tool_id, ToolId::Ffuf | ToolId::Arjun | ToolId::Gobuster) {
            let path = job_directory.join("wordlist.txt");
            write_wordlist(tool_id, &request.wordlist_terms, &path)?;
            Some(path)
        } else {
            if !request.wordlist_terms.is_empty() {
                return Err(CoreError::InvalidRequest);
            }
            None
        };
        let mut prepared = prepare_command(
            tool_id,
            &request.scope_id,
            &target,
            &job_directory,
            wordlist.as_deref(),
        )?;
        if scope.network_class == NetworkClass::Loopback {
            "loopback-systemd-primary-pgid-input-gate"
                .clone_into(&mut prepared.spec.network_isolation);
        }
        store.save_command_spec(&prepared.spec)?;
        let now = Timestamp::now();
        let job = Job {
            job_id: job_id.clone(),
            parent_job_id: None,
            command_spec_id: prepared.spec.command_spec_id.clone(),
            execution_status: ExecutionStatus::Queued,
            import_status: ImportStatus::Pending,
            created_at: now,
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
        };
        store.save_job(&job)?;
        let control = Arc::new(ActiveExecution::new(prepared.spec.stop_grace_millis));
        self.active_executions
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .insert(job_id, Arc::clone(&control));
        Ok(PreparedRun {
            store,
            request,
            prepared,
            job,
            control,
            _run_guard: run_guard,
        })
    }

    async fn execute_tool_run(&self, queued: PreparedRun) -> Result<RunToolResult, CoreError> {
        let job_id = queued.job.job_id.clone();
        let result = self.execute_tool_run_inner(queued).await;
        self.active_executions
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .remove(&job_id);
        result
    }

    async fn execute_tool_run_inner(
        &self,
        queued: PreparedRun,
    ) -> Result<RunToolResult, CoreError> {
        let PreparedRun {
            store,
            request,
            prepared,
            mut job,
            control,
            _run_guard,
        } = queued;
        let job_id = job.job_id.clone();
        job.transition(ExecutionStatus::Starting)
            .map_err(|_| CoreError::InvalidRequest)?;
        job.started_at = Some(Timestamp::now());
        store.save_job(&job)?;

        if control.cancel_requested.load(Ordering::SeqCst) {
            job.transition(ExecutionStatus::Cancelled)
                .map_err(|_| CoreError::InvalidRequest)?;
            job.stopped_at = Some(Timestamp::now());
            job.exit_reason = Some("cancelled_before_launch".to_owned());
            job.cleanup_verified = true;
            job.import_status = ImportStatus::Skipped;
            let record = terminal_import_record(
                &job,
                &prepared,
                Vec::new(),
                0,
                0,
                Some("cancelled before process launch".to_owned()),
            );
            store.complete_import(&job, &record, &[], &[])?;
            return run_result(&store, &job_id, Vec::new());
        }

        let execution =
            start_managed(&prepared.spec, &prepared.stdout_path, &prepared.stderr_path).await;
        let execution_error = execution.is_err();
        if let Ok(execution) = execution {
            let identity = execution.identity().clone();
            set_active_identity(&control, &identity)?;
            apply_process_identity(&mut job, &identity);
            if control.cancel_requested.load(Ordering::SeqCst) {
                job.transition(ExecutionStatus::Stopping)
                    .map_err(|_| CoreError::InvalidRequest)?;
                store.save_job(&job)?;
                let _ = drive_cancellation(&control).await?;
            } else {
                job.transition(ExecutionStatus::Running)
                    .map_err(|_| CoreError::InvalidRequest)?;
                store.save_job(&job)?;
            }
            let result = execution.wait().await?;
            let cancellation = if control.cancel_requested.load(Ordering::SeqCst) {
                drive_cancellation(&control).await?
            } else {
                result.cancellation.clone()
            };
            apply_execution_result(
                &mut job,
                &result,
                control.cancel_requested.load(Ordering::SeqCst),
                cancellation.as_ref(),
            )?;
        } else {
            job.exit_reason = Some("managed_execution_policy_error".to_owned());
            job.stopped_at = Some(Timestamp::now());
            job.transition(ExecutionStatus::Failed)
                .map_err(|_| CoreError::InvalidRequest)?;
        }
        store.save_job(&job)?;

        let committed = commit_run_artifacts(&store, &prepared, &job_id)?;
        job.stdout_artifact_id
            .clone_from(&committed.stdout_artifact_id);
        job.stderr_artifact_id
            .clone_from(&committed.stderr_artifact_id);
        store.save_job(&job)?;
        let source_artifact_ids = committed
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.clone())
            .collect::<Vec<_>>();

        if execution_error || job.execution_status != ExecutionStatus::Succeeded {
            job.import_status = ImportStatus::Skipped;
            let record = terminal_import_record(
                &job,
                &prepared,
                source_artifact_ids,
                0,
                0,
                Some("process execution did not succeed".to_owned()),
            );
            store.complete_import(&job, &record, &[], &[])?;
            return run_result(&store, &job_id, committed.artifacts);
        }

        job.import_status = ImportStatus::Importing;
        let importing = JobImportRecord {
            job_id: job_id.clone(),
            parser_id: prepared.manifest.parser_id.clone(),
            parser_version: prepared.manifest.parser_version.clone(),
            import_status: ImportStatus::Importing,
            discovery_count: 0,
            http_message_count: 0,
            source_artifact_ids: source_artifact_ids.clone(),
            error_summary: None,
            completed_at: None,
        };
        store.write_import_state(&job, &importing)?;

        let parsed = match parse_output(&prepared) {
            Ok(parsed) => parsed,
            Err(error) => {
                persist_parser_failure(
                    &store,
                    &mut job,
                    &prepared,
                    source_artifact_ids,
                    error.to_string(),
                )?;
                return run_result(&store, &job_id, committed.artifacts);
            }
        };
        let observed_at = Timestamp::now();
        let discoveries =
            materialize_discoveries(&request.project_id, parsed.discoveries, &observed_at);
        let http_messages = parsed
            .http_response
            .map(|response| {
                build_http_message(
                    &request.project_id,
                    &prepared,
                    &committed,
                    response,
                    observed_at.clone(),
                )
            })
            .transpose()?
            .into_iter()
            .collect::<Vec<_>>();
        job.import_status = ImportStatus::Imported;
        let record = terminal_import_record(
            &job,
            &prepared,
            source_artifact_ids,
            discoveries.len(),
            http_messages.len(),
            None,
        );
        store.complete_import(&job, &record, &discoveries, &http_messages)?;
        run_result(&store, &job_id, committed.artifacts)
    }

    pub async fn cancel_job(
        &self,
        request: &CancelJobRequest,
    ) -> Result<CancelJobResult, CoreError> {
        request
            .job_id
            .validate()
            .map_err(|_| CoreError::InvalidRequest)?;
        let store = self.project_store(&request.project_id, true)?;
        let control = self
            .active_executions
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .get(&request.job_id)
            .cloned()
            .ok_or(CoreError::JobNotActive)?;
        control.cancel_requested.store(true, Ordering::SeqCst);
        let has_identity = control
            .identity
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .is_some();
        if has_identity {
            let mut job = store.job(&request.job_id)?.job;
            if matches!(
                job.execution_status,
                ExecutionStatus::Queued | ExecutionStatus::Starting | ExecutionStatus::Running
            ) {
                job.transition(ExecutionStatus::Stopping)
                    .map_err(|_| CoreError::InvalidRequest)?;
                store.save_job(&job)?;
            }
        }
        let cancellation = drive_cancellation(&control).await?;
        Ok(cancel_job_result(request.job_id.clone(), cancellation))
    }

    pub async fn cancel_all_jobs(
        &self,
        project_id: &ProjectId,
    ) -> Result<CancelAllJobsResult, CoreError> {
        self.project_store(project_id, true)?;
        let job_ids = self
            .active_executions
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut results = Vec::with_capacity(job_ids.len());
        for job_id in &job_ids {
            results.push(
                self.cancel_job(&CancelJobRequest {
                    project_id: project_id.clone(),
                    job_id: job_id.clone(),
                })
                .await?,
            );
        }
        Ok(CancelAllJobsResult {
            requested: job_ids.len(),
            results,
        })
    }

    #[must_use]
    pub fn next_event(&self, kind: impl Into<String>, project_id: Option<ProjectId>) -> CoreEvent {
        CoreEvent {
            sequence: self.event_sequence.fetch_add(1, Ordering::SeqCst) + 1,
            kind: kind.into(),
            project_id,
        }
    }

    fn with_active<T, F>(&self, project_id: &ProjectId, operation: F) -> Result<T, CoreError>
    where
        F: FnOnce(&ProjectStore) -> Result<T, CoreError>,
    {
        project_id
            .validate()
            .map_err(|_| CoreError::InvalidRequest)?;
        let active = self.lock_active()?;
        let store = Arc::clone(active.as_ref().ok_or(CoreError::NoActiveProject)?);
        if store.project_id() != project_id {
            return Err(CoreError::ProjectMismatch);
        }
        drop(active);
        operation(&store)
    }

    fn project_store(
        &self,
        project_id: &ProjectId,
        writable: bool,
    ) -> Result<Arc<ProjectStore>, CoreError> {
        project_id
            .validate()
            .map_err(|_| CoreError::InvalidRequest)?;
        let active = self.lock_active()?;
        let store = Arc::clone(active.as_ref().ok_or(CoreError::NoActiveProject)?);
        if store.project_id() != project_id {
            return Err(CoreError::ProjectMismatch);
        }
        if writable && store.mode() == OpenMode::ReadOnly {
            return Err(CoreError::Storage(StorageError::ReadOnly));
        }
        Ok(store)
    }

    fn begin_run(
        &self,
        project_id: &ProjectId,
    ) -> Result<(Arc<ProjectStore>, ActiveRunGuard), CoreError> {
        let store = self.project_store(project_id, true)?;
        self.active_runs.fetch_add(1, Ordering::SeqCst);
        Ok((
            store,
            ActiveRunGuard {
                counter: Arc::clone(&self.active_runs),
            },
        ))
    }

    fn lock_active(&self) -> Result<MutexGuard<'_, Option<Arc<ProjectStore>>>, CoreError> {
        self.active.lock().map_err(|_| CoreError::StateLock)
    }

    #[cfg(test)]
    fn seed_http_message(&self, message: &HttpMessage) {
        let active = self.lock_active().unwrap();
        active.as_ref().unwrap().save_http_message(message).unwrap();
    }

    #[cfg(test)]
    fn audit_events_for_test(&self, limit: usize) -> Vec<flagdeck_domain::AuditEvent> {
        let active = self.lock_active().unwrap();
        active.as_ref().unwrap().list_audit_events(limit).unwrap()
    }
}

struct ActiveRunGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ActiveRunGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

struct ActiveExecution {
    identity: Mutex<Option<ManagedProcessIdentity>>,
    cancel_requested: AtomicBool,
    cancel_started: AtomicBool,
    cancel_failed: AtomicBool,
    cancel_result: Mutex<Option<CancellationResult>>,
    cancel_finished: Notify,
    stop_grace: Duration,
}

impl ActiveExecution {
    fn new(stop_grace_millis: u64) -> Self {
        Self {
            identity: Mutex::new(None),
            cancel_requested: AtomicBool::new(false),
            cancel_started: AtomicBool::new(false),
            cancel_failed: AtomicBool::new(false),
            cancel_result: Mutex::new(None),
            cancel_finished: Notify::new(),
            stop_grace: Duration::from_millis(stop_grace_millis.min(2_000)),
        }
    }
}

struct PreparedRun {
    store: Arc<ProjectStore>,
    request: RunToolRequest,
    prepared: PreparedToolCommand,
    job: Job,
    control: Arc<ActiveExecution>,
    _run_guard: ActiveRunGuard,
}

struct PreparedExternalRun {
    store: Arc<ProjectStore>,
    command: CommandSpec,
    job: Job,
    control: Arc<ActiveExecution>,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    /// GUI tools: spawn detached outside systemd so DISPLAY/XAUTHORITY work.
    detach_gui: bool,
    _run_guard: ActiveRunGuard,
}

struct CommittedRunArtifacts {
    artifacts: Vec<Artifact>,
    role_artifacts: Vec<(OutputRole, Artifact)>,
    stdout_artifact_id: Option<ArtifactId>,
    stderr_artifact_id: Option<ArtifactId>,
}

fn normalize_dictionary_terms(content: &str) -> Result<Vec<String>, CoreError> {
    let mut seen = BTreeSet::new();
    let mut terms = Vec::new();
    for line in content.lines() {
        let term = line.trim();
        if term.is_empty() {
            continue;
        }
        if term.len() > MAX_DICTIONARY_TERM_BYTES || term.contains('\0') {
            return Err(CoreError::InvalidRequest);
        }
        if seen.insert(term.to_owned()) {
            terms.push(term.to_owned());
        }
        if terms.len() > MAX_DICTIONARY_TERMS {
            return Err(CoreError::InvalidRequest);
        }
    }
    if terms.is_empty() {
        return Err(CoreError::InvalidRequest);
    }
    Ok(terms)
}

fn valid_archive_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.ends_with(".flagdeck.zip")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn map_catalog_error(error: &CatalogError) -> CoreError {
    match error {
        CatalogError::NotFound | CatalogError::BinaryMissing => CoreError::ToolUnavailable,
        CatalogError::InvalidInput | CatalogError::Url(_) => CoreError::InvalidRequest,
        CatalogError::Invalid(_) | CatalogError::Toml(_) | CatalogError::Io(_) => {
            CoreError::Adapter(AdapterError::InvalidInput)
        }
    }
}

fn is_safe_job_sidecar_filename(filename: &str) -> bool {
    if filename.is_empty() || filename.len() > 128 {
        return false;
    }
    if filename.contains('/') || filename.contains('\\') || filename.contains("..") {
        return false;
    }
    // Allow names like ffuf-output.json, dddd-output.jsonl, fscan-output.txt
    filename
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        && filename.contains('.')
}

fn is_active_execution_status(status: ExecutionStatus) -> bool {
    matches!(
        status,
        ExecutionStatus::Queued
            | ExecutionStatus::Starting
            | ExecutionStatus::Running
            | ExecutionStatus::Stopping
    )
}

fn append_job_log(path: &Path, text: &str) -> Result<(), CoreError> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok(())
}

fn write_launch_banner(
    stdout_path: &Path,
    stderr_path: &Path,
    command: &CommandSpec,
    detach_gui: bool,
) -> Result<(), CoreError> {
    let argv = command.argv_exec.join(" ");
    let banner = format!(
        "=== FlagDeck launch ===\n\
         tool_id: {}\n\
         program: {}\n\
         argv: {}\n\
         cwd: {}\n\
         mode: {}\n\
         timeout_ms: {}\n\
         started_at: {}\n\
         =======================\n",
        command.tool_id,
        command.program,
        argv,
        command.cwd,
        if detach_gui {
            "detached_gui"
        } else {
            "managed_cli"
        },
        command.timeout_millis,
        Timestamp::now().0
    );
    append_job_log(stdout_path, &banner)?;
    append_job_log(stderr_path, &banner)?;
    // Surface missing GUI session early in the log pane.
    if detach_gui {
        let display = command
            .env_exec
            .get("DISPLAY")
            .cloned()
            .unwrap_or_else(|| "(unset)".to_owned());
        let xauth = command
            .env_exec
            .get("XAUTHORITY")
            .cloned()
            .unwrap_or_else(|| "(unset)".to_owned());
        append_job_log(
            stdout_path,
            &format!("[flagdeck] gui env DISPLAY={display} XAUTHORITY={xauth}\n"),
        )?;
    }
    Ok(())
}

fn open_job_log_file(path: &Path) -> Result<fs::File, CoreError> {
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok(file)
}

fn spawn_catalog_process(
    command: &CommandSpec,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<std::process::Child, CoreError> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let stdout = open_job_log_file(stdout_path)?;
    let stderr = open_job_log_file(stderr_path)?;
    let mut process = Command::new(&command.program);
    process
        .args(&command.argv_exec)
        .current_dir(&command.cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    for (key, value) in &command.env_exec {
        process.env(key, value);
    }
    process.process_group(0);
    process.spawn().map_err(CoreError::Io)
}

async fn run_catalog_cli(queued: &mut PreparedExternalRun) -> Result<(), CoreError> {
    queued
        .job
        .transition(ExecutionStatus::Running)
        .map_err(|_| CoreError::InvalidRequest)?;
    queued.store.save_job(&queued.job)?;

    let mut child =
        match spawn_catalog_process(&queued.command, &queued.stdout_path, &queued.stderr_path) {
            Ok(child) => child,
            Err(error) => {
                let detail = format!("[flagdeck] cli spawn failed: {error}\n");
                append_job_log(&queued.stderr_path, &detail)?;
                append_job_log(&queued.stdout_path, &detail)?;
                queued.job.exit_reason = Some(format!("cli_spawn_failed:{error}"));
                queued.job.stopped_at = Some(Timestamp::now());
                queued
                    .job
                    .transition(ExecutionStatus::Failed)
                    .map_err(|_| CoreError::InvalidRequest)?;
                return Ok(());
            }
        };

    let pid = i32::try_from(child.id()).unwrap_or_default();
    queued.job.pid = Some(pid);
    queued.job.process_group_id = Some(pid);
    queued.job.ownership_verified = true;
    queued.job.supervisor_backend = Some(SupervisorBackend::PgidFallback);
    let identity = ManagedProcessIdentity {
        supervisor_backend: SupervisorBackend::PgidFallback,
        wrapper_pid: pid,
        pid: Some(pid),
        process_group_id: Some(pid),
        process_start_ticks: None,
        systemd_unit: None,
        cgroup_path: None,
        invocation_id: None,
        target_program: queued.command.program.clone(),
        ownership_verified: true,
    };
    set_active_identity(&queued.control, &identity)?;
    queued.store.save_job(&queued.job)?;
    append_job_log(
        &queued.stdout_path,
        &format!("[flagdeck] process started pid={pid}\n"),
    )?;

    let timeout = Duration::from_millis(queued.command.timeout_millis.max(1_000));
    let wait_result =
        tokio::time::timeout(timeout, tokio::task::spawn_blocking(move || child.wait())).await;

    match wait_result {
        Ok(Ok(Ok(status))) => {
            let code = status.code();
            append_job_log(
                &queued.stdout_path,
                &format!("\n[flagdeck] finished exit={code:?} status={status}\n"),
            )?;
            queued.job.exit_code = code;
            queued.job.exit_reason = Some(format!("exit:{status}"));
            queued.job.stopped_at = Some(Timestamp::now());
            queued.job.cleanup_verified = true;
            if status.success() {
                queued
                    .job
                    .transition(ExecutionStatus::Succeeded)
                    .map_err(|_| CoreError::InvalidRequest)?;
            } else {
                queued
                    .job
                    .transition(ExecutionStatus::Failed)
                    .map_err(|_| CoreError::InvalidRequest)?;
            }
        }
        Ok(Ok(Err(error))) => {
            append_job_log(
                &queued.stderr_path,
                &format!("[flagdeck] wait failed: {error}\n"),
            )?;
            queued.job.exit_reason = Some(format!("wait_failed:{error}"));
            queued.job.stopped_at = Some(Timestamp::now());
            queued
                .job
                .transition(ExecutionStatus::Failed)
                .map_err(|_| CoreError::InvalidRequest)?;
        }
        Ok(Err(_)) => {
            append_job_log(
                &queued.stderr_path,
                "[flagdeck] internal join error while waiting for process\n",
            )?;
            queued.job.exit_reason = Some("wait_join_error".to_owned());
            queued.job.stopped_at = Some(Timestamp::now());
            queued
                .job
                .transition(ExecutionStatus::Failed)
                .map_err(|_| CoreError::InvalidRequest)?;
        }
        Err(_) => {
            append_job_log(
                &queued.stdout_path,
                &format!(
                    "\n[flagdeck] timed out after {} ms; sending SIGKILL to process group\n",
                    timeout.as_millis()
                ),
            )?;
            if pid > 1 {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            queued.job.exit_reason = Some(format!("timeout_ms:{}", timeout.as_millis()));
            queued.job.stopped_at = Some(Timestamp::now());
            queued.job.cleanup_verified = true;
            queued
                .job
                .transition(ExecutionStatus::TimedOut)
                .map_err(|_| CoreError::InvalidRequest)?;
        }
    }
    queued.store.save_job(&queued.job)?;
    Ok(())
}

async fn run_detached_gui(queued: &mut PreparedExternalRun) -> Result<(), CoreError> {
    queued
        .job
        .transition(ExecutionStatus::Running)
        .map_err(|_| CoreError::InvalidRequest)?;
    queued.store.save_job(&queued.job)?;

    let mut child =
        match spawn_catalog_process(&queued.command, &queued.stdout_path, &queued.stderr_path) {
            Ok(child) => child,
            Err(error) => {
                let detail = format!("[flagdeck] gui spawn failed: {error}\n");
                append_job_log(&queued.stderr_path, &detail)?;
                append_job_log(&queued.stdout_path, &detail)?;
                queued.job.exit_reason = Some(format!("gui_spawn_failed:{error}"));
                queued.job.stopped_at = Some(Timestamp::now());
                queued
                    .job
                    .transition(ExecutionStatus::Failed)
                    .map_err(|_| CoreError::InvalidRequest)?;
                return Ok(());
            }
        };

    let pid = i32::try_from(child.id()).unwrap_or_default();
    queued.job.pid = Some(pid);
    queued.job.process_group_id = Some(pid);
    queued.store.save_job(&queued.job)?;
    append_job_log(
        &queued.stdout_path,
        &format!("[flagdeck] gui process spawned pid={pid}\n"),
    )?;

    // Give the UI a moment to crash with a visible error if DISPLAY/Xauth is wrong.
    tokio::time::sleep(Duration::from_millis(1800)).await;
    match child.try_wait() {
        Ok(Some(status)) => {
            let code = status.code();
            append_job_log(
                &queued.stdout_path,
                &format!("[flagdeck] gui exited early code={code:?} status={status}\n"),
            )?;
            queued.job.exit_code = code;
            queued.job.exit_reason = Some(format!("gui_exited_early:{status}"));
            queued.job.stopped_at = Some(Timestamp::now());
            queued.job.cleanup_verified = true;
            if status.success() {
                queued
                    .job
                    .transition(ExecutionStatus::Succeeded)
                    .map_err(|_| CoreError::InvalidRequest)?;
            } else {
                queued
                    .job
                    .transition(ExecutionStatus::Failed)
                    .map_err(|_| CoreError::InvalidRequest)?;
            }
        }
        Ok(None) => {
            append_job_log(
                &queued.stdout_path,
                &format!(
                    "[flagdeck] gui still running after probe; detaching pid={pid}\n\
                     [flagdeck] 独立窗口应已打开。此任务标记为成功，进程不再由 FlagDeck 等待。\n"
                ),
            )?;
            // Reap zombies without blocking the Tokio runtime / tests.
            std::thread::Builder::new()
                .name(format!("flagdeck-gui-reaper-{pid}"))
                .spawn(move || {
                    let _ = child.wait();
                })
                .ok();
            queued.job.exit_reason = Some(format!("gui_detached_pid_{pid}"));
            queued.job.stopped_at = Some(Timestamp::now());
            queued.job.cleanup_verified = true;
            queued
                .job
                .transition(ExecutionStatus::Succeeded)
                .map_err(|_| CoreError::InvalidRequest)?;
        }
        Err(error) => {
            append_job_log(
                &queued.stderr_path,
                &format!("[flagdeck] gui wait error: {error}\n"),
            )?;
            queued.job.exit_reason = Some(format!("gui_wait_error:{error}"));
            queued.job.stopped_at = Some(Timestamp::now());
            queued
                .job
                .transition(ExecutionStatus::Failed)
                .map_err(|_| CoreError::InvalidRequest)?;
        }
    }
    queued.store.save_job(&queued.job)?;
    Ok(())
}

/// Accept full http(s) URL or bare host/IP/CIDR-ish target for scope registration.
fn normalize_scope_base_url(value: &str) -> Result<String, CoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidRequest);
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let _ = parse_http_url(trimmed)?;
        return Ok(trimmed.to_owned());
    }
    // Strip path-like noise: "1.2.3.4/24" is ok for display scope host side;
    // create_scope expects a URL — wrap as http://host/
    let host = trimmed.split('/').next().unwrap_or(trimmed);
    if host.is_empty() || host.contains(' ') {
        return Err(CoreError::InvalidRequest);
    }
    let synthesized = format!("http://{host}/");
    let _ = parse_http_url(&synthesized)?;
    Ok(synthesized)
}

fn parse_http_url(value: &str) -> Result<Url, CoreError> {
    if value.is_empty() || value.len() > 4096 || value.trim() != value {
        return Err(CoreError::InvalidRequest);
    }
    let url = Url::parse(value).map_err(|_| CoreError::InvalidRequest)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(CoreError::InvalidRequest);
    }
    Ok(url)
}

fn resolve_addresses(host: &str, port: u16) -> Result<Vec<IpAddr>, CoreError> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|_| CoreError::ScopeViolation)?
        .map(|address| address.ip())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(CoreError::ScopeViolation);
    }
    Ok(addresses)
}

fn network_class(addresses: &[IpAddr]) -> NetworkClass {
    if addresses.iter().all(IpAddr::is_loopback) {
        return NetworkClass::Loopback;
    }
    let private = addresses
        .iter()
        .filter(|address| is_private(address))
        .count();
    if private == addresses.len() {
        NetworkClass::Private
    } else if private == 0 {
        NetworkClass::Internet
    } else {
        NetworkClass::Mixed
    }
}

fn is_private(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => value.is_private() || value.is_link_local() || value.is_loopback(),
        IpAddr::V6(value) => {
            value.is_unique_local() || value.is_unicast_link_local() || value.is_loopback()
        }
    }
}

fn validate_target_against_scope(scope: &TargetScope, target: &Url) -> Result<(), CoreError> {
    let host = target
        .host_str()
        .ok_or(CoreError::ScopeViolation)?
        .to_ascii_lowercase();
    let port = target
        .port_or_known_default()
        .ok_or(CoreError::ScopeViolation)?;
    if !scope.schemes.iter().any(|scheme| scheme == target.scheme())
        || !scope.exact_hosts.iter().any(|value| value == &host)
        || !scope
            .ports
            .iter()
            .any(|range| range.start <= port && port <= range.end)
        || scope.dns_change_policy != "deny"
    {
        return Err(CoreError::ScopeViolation);
    }
    let expected = scope
        .dns_snapshots
        .iter()
        .rev()
        .find(|snapshot| snapshot.host == host)
        .ok_or(CoreError::ScopeViolation)?
        .addresses
        .iter()
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|_| CoreError::ScopeViolation)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let current = resolve_addresses(&host, port)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if expected != current {
        return Err(CoreError::ScopeViolation);
    }
    Ok(())
}

fn create_job_directory(scans: &Path, job_id: &JobId) -> Result<PathBuf, CoreError> {
    let directory = scans.join(&job_id.0);
    fs::create_dir(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    for name in ["home", "tmp", "xdg-config"] {
        let child = directory.join(name);
        fs::create_dir(&child)?;
        fs::set_permissions(child, fs::Permissions::from_mode(0o700))?;
    }
    Ok(fs::canonicalize(directory)?)
}

fn alpha_tool_from_id(value: &str) -> Result<AlphaTool, CoreError> {
    match value {
        "curl" => Ok(AlphaTool::Curl),
        "dddd" => Ok(AlphaTool::Dddd),
        "ffuf" => Ok(AlphaTool::Ffuf),
        "arjun" => Ok(AlphaTool::Arjun),
        "fscan" => Ok(AlphaTool::Fscan),
        "gobuster" => Ok(AlphaTool::Gobuster),
        "wafw00f" => Ok(AlphaTool::Wafw00f),
        _ => Err(CoreError::InvalidRequest),
    }
}

fn tool_integrity_matches(tool: &ToolManifest) -> bool {
    !tool.path.is_empty() && validate_program(Path::new(&tool.path), &tool.sha256).is_ok()
}

fn health_marker_matches(tool: &ToolManifest) -> bool {
    if tool.path.is_empty() {
        return false;
    }
    if tool.health_argv.is_empty() {
        return true;
    }
    Command::new(&tool.path)
        .args(&tool.health_argv)
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| {
            let mut evidence = output.stdout;
            evidence.extend_from_slice(&output.stderr);
            String::from_utf8_lossy(&evidence).contains(&tool.health_version_marker)
        })
}

fn set_active_identity(
    control: &ActiveExecution,
    identity: &ManagedProcessIdentity,
) -> Result<(), CoreError> {
    *control.identity.lock().map_err(|_| CoreError::StateLock)? = Some(identity.clone());
    Ok(())
}

async fn drive_cancellation(
    control: &ActiveExecution,
) -> Result<Option<CancellationResult>, CoreError> {
    if !control.cancel_requested.load(Ordering::SeqCst) {
        return Ok(None);
    }
    let identity = control
        .identity
        .lock()
        .map_err(|_| CoreError::StateLock)?
        .clone();
    let Some(identity) = identity else {
        return Ok(None);
    };
    if control
        .cancel_started
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        if let Ok(result) = cancel_managed(&identity, control.stop_grace).await {
            *control
                .cancel_result
                .lock()
                .map_err(|_| CoreError::StateLock)? = Some(result.clone());
            control.cancel_finished.notify_waiters();
            return Ok(Some(result));
        }
        control.cancel_failed.store(true, Ordering::SeqCst);
        control.cancel_finished.notify_waiters();
        return Err(CoreError::CancellationFailed);
    }
    loop {
        let notified = control.cancel_finished.notified();
        if let Some(result) = control
            .cancel_result
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .clone()
        {
            return Ok(Some(result));
        }
        if control.cancel_failed.load(Ordering::SeqCst) {
            return Err(CoreError::CancellationFailed);
        }
        notified.await;
    }
}

fn cancel_job_result(job_id: JobId, cancellation: Option<CancellationResult>) -> CancelJobResult {
    cancellation.map_or(
        CancelJobResult {
            job_id: job_id.clone(),
            accepted: true,
            pending_identity: true,
            cleanup_verified: false,
            residual_processes: 0,
            duration_millis: None,
            signals_sent: Vec::new(),
        },
        |result| CancelJobResult {
            job_id,
            accepted: result.accepted,
            pending_identity: false,
            cleanup_verified: result.cleanup_verified,
            residual_processes: result.residual_processes,
            duration_millis: Some(result.duration_millis),
            signals_sent: result.signals_sent,
        },
    )
}

fn apply_process_identity(job: &mut Job, identity: &ManagedProcessIdentity) {
    job.pid = identity.pid.or(Some(identity.wrapper_pid));
    job.process_group_id = identity.process_group_id;
    job.process_start_ticks = identity.process_start_ticks;
    job.systemd_unit.clone_from(&identity.systemd_unit);
    job.cgroup_path.clone_from(&identity.cgroup_path);
    job.invocation_id.clone_from(&identity.invocation_id);
    job.supervisor_backend = Some(identity.supervisor_backend);
    job.ownership_verified = identity.ownership_verified;
}

fn apply_execution_result(
    job: &mut Job,
    result: &ManagedExecutionResult,
    cancel_requested: bool,
    cancellation: Option<&CancellationResult>,
) -> Result<(), CoreError> {
    job.pid = result.pid.or(Some(result.wrapper_pid));
    job.process_group_id = result.process_group_id;
    job.process_start_ticks = result.process_start_ticks;
    job.exit_code = result.exit_code;
    job.exit_reason = Some(if cancel_requested {
        format!("cancelled:{}", result.exit_reason)
    } else {
        result.exit_reason.clone()
    });
    job.systemd_unit.clone_from(&result.systemd_unit);
    job.cgroup_path.clone_from(&result.cgroup_path);
    job.invocation_id.clone_from(&result.invocation_id);
    job.supervisor_backend = Some(result.supervisor_backend);
    job.ownership_verified = result.ownership_verified;
    job.cleanup_verified =
        cancellation.map_or(result.cleanup_verified, |value| value.cleanup_verified);
    job.residual_processes =
        cancellation.map_or(result.residual_processes, |value| value.residual_processes);
    job.cancel_duration_millis = cancellation.map(|value| value.duration_millis);
    job.stopped_at = Some(Timestamp::now());
    let terminal = if cancel_requested {
        ExecutionStatus::Cancelled
    } else if result.timed_out {
        ExecutionStatus::TimedOut
    } else if result.exit_code == Some(0) {
        ExecutionStatus::Succeeded
    } else {
        ExecutionStatus::Failed
    };
    job.transition(terminal)
        .map_err(|_| CoreError::InvalidRequest)
}

fn commit_run_artifacts(
    store: &ProjectStore,
    prepared: &PreparedToolCommand,
    job_id: &JobId,
) -> Result<CommittedRunArtifacts, CoreError> {
    let mut artifacts = Vec::new();
    let mut role_artifacts = Vec::new();
    let stdout = commit_existing_file(
        store,
        &prepared.stdout_path,
        &format!("{}-stdout.log", prepared.manifest.id),
        if prepared.manifest.id == "curl" {
            "application/json"
        } else {
            "text/plain; charset=utf-8"
        },
        Sensitivity::SensitiveEvidence,
        job_id,
    )?;
    if let Some(artifact) = &stdout {
        artifacts.push(artifact.clone());
    }
    let stderr = commit_existing_file(
        store,
        &prepared.stderr_path,
        &format!("{}-stderr.log", prepared.manifest.id),
        "text/plain; charset=utf-8",
        Sensitivity::SensitiveEvidence,
        job_id,
    )?;
    if let Some(artifact) = &stderr {
        artifacts.push(artifact.clone());
    }
    for output in &prepared.outputs {
        if let Some(artifact) = commit_expected_output(store, output, job_id)? {
            role_artifacts.push((output.role, artifact.clone()));
            artifacts.push(artifact);
        }
    }
    if let Some(wordlist) = &prepared.input_wordlist
        && let Some(artifact) = commit_existing_file(
            store,
            wordlist,
            &format!("{}-wordlist.txt", prepared.manifest.id),
            "text/plain; charset=utf-8",
            Sensitivity::SensitiveEvidence,
            job_id,
        )?
    {
        artifacts.push(artifact);
    }
    Ok(CommittedRunArtifacts {
        stdout_artifact_id: stdout.map(|artifact| artifact.artifact_id),
        stderr_artifact_id: stderr.map(|artifact| artifact.artifact_id),
        artifacts,
        role_artifacts,
    })
}

fn commit_expected_output(
    store: &ProjectStore,
    output: &ExpectedOutput,
    job_id: &JobId,
) -> Result<Option<Artifact>, CoreError> {
    commit_existing_file(
        store,
        &output.path,
        &output.logical_name,
        &output.mime,
        output.sensitivity,
        job_id,
    )
}

fn commit_existing_file(
    store: &ProjectStore,
    path: &Path,
    logical_name: &str,
    mime: &str,
    sensitivity: Sensitivity,
    job_id: &JobId,
) -> Result<Option<Artifact>, CoreError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return Err(CoreError::InvalidRequest),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let request = ArtifactWriteRequest {
        logical_name: logical_name.to_owned(),
        mime: mime.to_owned(),
        sensitivity,
        export_policy: if sensitivity == Sensitivity::Normal {
            ExportPolicy::Include
        } else {
            ExportPolicy::ConfirmSensitive
        },
        source_job_id: Some(job_id.clone()),
        source_message_id: None,
        expected_size: Some(metadata.len()),
        expected_sha256: None,
    };
    Ok(Some(store.commit_artifact(&request, File::open(path)?)?))
}

fn terminal_import_record(
    job: &Job,
    prepared: &PreparedToolCommand,
    source_artifact_ids: Vec<ArtifactId>,
    discovery_count: usize,
    http_message_count: usize,
    error_summary: Option<String>,
) -> JobImportRecord {
    JobImportRecord {
        job_id: job.job_id.clone(),
        parser_id: prepared.manifest.parser_id.clone(),
        parser_version: prepared.manifest.parser_version.clone(),
        import_status: job.import_status,
        discovery_count,
        http_message_count,
        source_artifact_ids,
        error_summary,
        completed_at: Some(Timestamp::now()),
    }
}

fn persist_parser_failure(
    store: &ProjectStore,
    job: &mut Job,
    prepared: &PreparedToolCommand,
    source_artifact_ids: Vec<ArtifactId>,
    error_summary: String,
) -> Result<(), CoreError> {
    job.import_status = ImportStatus::ParserFailed;
    let record = terminal_import_record(
        job,
        prepared,
        source_artifact_ids,
        0,
        0,
        Some(error_summary),
    );
    store.complete_import(job, &record, &[], &[])?;
    Ok(())
}

fn run_result(
    store: &ProjectStore,
    job_id: &JobId,
    artifacts: Vec<Artifact>,
) -> Result<RunToolResult, CoreError> {
    let job = JobView::from(store.job(job_id)?);
    Ok(RunToolResult {
        discoveries_imported: job.discovery_count,
        http_messages_imported: job.http_message_count,
        job,
        artifacts,
    })
}

fn build_http_message(
    project_id: &ProjectId,
    prepared: &PreparedToolCommand,
    committed: &CommittedRunArtifacts,
    response: ParsedHttpResponse,
    observed_at: Timestamp,
) -> Result<HttpMessage, CoreError> {
    let body_artifact_id = committed
        .role_artifacts
        .iter()
        .find(|(role, _)| *role == response.body_role)
        .map(|(_, artifact)| artifact.artifact_id.clone())
        .ok_or(CoreError::InvalidRequest)?;
    let host = response
        .url
        .host_str()
        .ok_or(CoreError::InvalidRequest)?
        .to_owned();
    let authority = response
        .url
        .origin()
        .ascii_serialization()
        .split_once("://")
        .map(|(_, value)| value.to_owned())
        .ok_or(CoreError::InvalidRequest)?;
    let sensitive = response.headers.iter().any(|header| {
        matches!(
            header.name.to_ascii_lowercase().as_str(),
            "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key"
        )
    });
    let mut view = format!("HTTP/{} {}\n", response.http_version, response.status_code);
    for header in &response.headers {
        let _ = writeln!(view, "{}: {}", header.name, header.value);
    }
    let redacted_view = format!(
        "{}\n<body: {} bytes archived>",
        redact_and_escape_text(view.as_bytes()),
        response.actual_length
    );
    let query = response
        .url
        .query_pairs()
        .map(|(name, value)| OrderedValue {
            name: name.into_owned(),
            value: value.into_owned(),
        })
        .collect();
    Ok(HttpMessage {
        message_id: MessageId::new(),
        project_id: project_id.clone(),
        exchange_id: None,
        parent_message_id: None,
        source: HttpSource::Tool,
        representation_kind: RepresentationKind::Semantic,
        method: Some("GET".to_owned()),
        status_code: Some(response.status_code),
        scheme: response.url.scheme().to_owned(),
        host,
        port: response.remote_port,
        authority,
        path: response.url.path().to_owned(),
        http_version: response.http_version,
        headers: response.headers,
        trailers: Vec::new(),
        query,
        form: Vec::new(),
        body_inline: response.inline_body,
        body_artifact_id: Some(body_artifact_id),
        wire_artifact_id: None,
        serializer_version: format!(
            "{}/{}",
            prepared.manifest.parser_id, prepared.manifest.parser_version
        ),
        body_state: BodyState::Complete,
        declared_length: response.declared_length,
        actual_length: response.actual_length,
        content_encoding: response.content_encoding,
        decoded_preview_state: "not_decoded".to_owned(),
        direction: MessageDirection::Response,
        observed_at,
        duration_millis: response.duration_millis,
        connection: ConnectionMetadata {
            client_address: None,
            server_address: response
                .remote_ip
                .map(|address| format!("{address}:{}", response.remote_port)),
            tls: response.url.scheme() == "https",
            tls_version: None,
            certificate_sha256: None,
        },
        sensitivity: if sensitive {
            Sensitivity::SensitiveEvidence
        } else {
            Sensitivity::Normal
        },
        redacted_view,
    })
}

fn validate_project_name(name: &str) -> Result<(), CoreError> {
    if name.trim().is_empty() || name.len() > 256 || name.contains(['\0', '\n', '\r', '/', '\\']) {
        return Err(CoreError::InvalidRequest);
    }
    Ok(())
}

fn format_command_preview(spec: &CommandSpec) -> String {
    let mut preview = spec.program.clone();
    for argument in &spec.argv_redacted {
        preview.push(' ');
        preview.push_str(
            &serde_json::to_string(argument).unwrap_or_else(|_| "\"<invalid>\"".to_owned()),
        );
    }
    preview
}

#[must_use]
pub fn redact_and_escape_text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut output = String::with_capacity(text.len());
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            output.push('\n');
        }
        output.push_str(&redact_line(line));
    }
    output
        .chars()
        .map(|character| {
            if character.is_control() && !matches!(character, '\n' | '\t') {
                format!("\\u{{{:04x}}}", u32::from(character))
            } else {
                character.to_string()
            }
        })
        .collect()
}

fn redact_line(line: &str) -> String {
    if let Some((name, _)) = line.split_once(':')
        && matches!(
            name.trim().to_ascii_lowercase().as_str(),
            "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key"
        )
    {
        return format!("{}: <redacted>", name.trim());
    }
    let mut redacted = line.to_owned();
    for key in ["token=", "password=", "passwd=", "api_key=", "apikey="] {
        redact_assignment(&mut redacted, key);
    }
    redacted
}

fn redact_assignment(value: &mut String, key: &str) {
    let mut search_from = 0;
    while search_from < value.len() {
        let lowercase = value[search_from..].to_ascii_lowercase();
        let Some(relative_start) = lowercase.find(key) else {
            break;
        };
        let start = search_from + relative_start;
        let value_start = start + key.len();
        let value_end = value[value_start..]
            .find(['&', ';', ' ', '\t'])
            .map_or(value.len(), |offset| value_start + offset);
        value.replace_range(value_start..value_end, "<redacted>");
        search_from = value_start + "<redacted>".len();
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 3);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[must_use]
pub fn typescript_declarations() -> String {
    let config = ts_rs::Config::from_env();
    macro_rules! declaration {
        ($type:ty) => {
            format!("export {}", <$type as TS>::decl(&config))
        };
    }
    [
        declaration!(CommandError),
        declaration!(CreateProjectRequest),
        declaration!(ProjectOpenMode),
        declaration!(OpenProjectRequest),
        declaration!(ProjectPageRequest),
        declaration!(ProjectPage),
        declaration!(CreateNoteRequest),
        declaration!(PreviewMode),
        declaration!(PreviewArtifactRequest),
        declaration!(ArtifactPreview),
        declaration!(ArtifactPageRequest),
        declaration!(ArtifactPage),
        declaration!(CreateScopeRequest),
        declaration!(ProjectContextRequest),
        declaration!(ScopePage),
        declaration!(StartProxyRequest),
        declaration!(StopProxyRequest),
        declaration!(HttpHistoryPageRequest),
        declaration!(HttpHistoryPage),
        declaration!(GetHttpMessageRequest),
        declaration!(RepeatHttpRequest),
        declaration!(RepeatHttpResult),
        declaration!(DiffHttpMessagesRequest),
        declaration!(ValueDifference),
        declaration!(HttpBodyDiff),
        declaration!(HttpMessageDiff),
        declaration!(CreateSqlmapRequestFileRequest),
        declaration!(SendRawHttp1Request),
        declaration!(SendRawHttp1Result),
        declaration!(OpenHttpBrowserPreviewRequest),
        declaration!(OpenHttpBrowserPreviewResult),
        declaration!(MetasploitLifecycleState),
        declaration!(MetasploitStatus),
        declaration!(StartMetasploitRequest),
        declaration!(StopMetasploitRequest),
        declaration!(SearchMetasploitModulesRequest),
        declaration!(MetasploitModuleSummary),
        declaration!(MetasploitModuleOption),
        declaration!(GetMetasploitOptionsRequest),
        declaration!(MetasploitExecutionKind),
        declaration!(ExecuteMetasploitModuleRequest),
        declaration!(MetasploitExecutionResult),
        declaration!(MetasploitEntityPage),
        declaration!(MetasploitEntityRequest),
        declaration!(StopMetasploitEntityRequest),
        declaration!(MetasploitConsoleCommandRequest),
        declaration!(MetasploitSessionCommandRequest),
        declaration!(TokenSource),
        declaration!(TokenExtractor),
        declaration!(StateMacroStep),
        declaration!(StateMacro),
        declaration!(StartIntruderRequest),
        declaration!(CampaignRequest),
        declaration!(IntruderCampaignPage),
        declaration!(IntruderAttemptPageRequest),
        declaration!(IntruderAttemptPage),
        declaration!(ListIntruderCampaignsRequest),
        declaration!(ParseMultipartRequest),
        declaration!(UploadVerificationMode),
        declaration!(UploadVerification),
        declaration!(StartUploadCampaignRequest),
        declaration!(MetasploitTranscriptResult),
        declaration!(ExternalLauncherId),
        declaration!(ExternalLauncherHealthDto),
        declaration!(LaunchExternalRequest),
        declaration!(PayloadFormat),
        declaration!(PayloadSourceHealthDto),
        declaration!(PayloadEntryDto),
        declaration!(ListPayloadsRequest),
        declaration!(PayloadPage),
        declaration!(PreviewPayloadRequest),
        declaration!(PayloadPreview),
        declaration!(AlphaTool),
        declaration!(RunToolRequest),
        declaration!(CatalogCategoryDto),
        declaration!(CatalogFormFieldDto),
        declaration!(CatalogToolDto),
        declaration!(WordlistDto),
        declaration!(CatalogSnapshot),
        declaration!(RunCatalogToolRequest),
        declaration!(EnsureTargetRequest),
        declaration!(JobView),
        declaration!(JobPageRequest),
        declaration!(JobPage),
        declaration!(DeleteJobRequest),
        declaration!(DeleteJobResult),
        declaration!(ClearJobsRequest),
        declaration!(ClearJobsResult),
        declaration!(JobLogStream),
        declaration!(PreviewJobLogRequest),
        declaration!(JobLogPreview),
        declaration!(PreviewJobFileRequest),
        declaration!(JobFilePreview),
        declaration!(DiscoveryPageRequest),
        declaration!(DiscoveryPage),
        declaration!(ToolHealthDto),
        declaration!(ToolPackHealthDto),
        declaration!(RunToolResult),
        declaration!(CancelJobRequest),
        declaration!(CancelJobResult),
        declaration!(CancelAllJobsResult),
        declaration!(CreateDictionaryRequest),
        declaration!(DictionaryPage),
        declaration!(SearchDictionaryRequest),
        declaration!(DictionarySearchResult),
        declaration!(ExportProjectRequest),
        declaration!(ExportProjectResult),
        declaration!(ImportPackage),
        declaration!(ImportPackagePage),
        declaration!(ImportProjectRequest),
        declaration!(ImportProjectResult),
        declaration!(RecoveryStatusDto),
        declaration!(StorageHealthDto),
        declaration!(SecurityBaselineDto),
        declaration!(AppStatus),
        declaration!(CoreEvent),
    ]
    .join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureProcess(std::process::Child);

    impl Drop for FixtureProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn service() -> (tempfile::TempDir, CoreService) {
        let temporary = tempfile::tempdir().unwrap();
        let service = CoreService::new(temporary.path().join("workspaces"));
        (temporary, service)
    }

    #[test]
    fn project_lifecycle_uses_ids_and_explicit_read_only_mode() {
        let (_temporary, core) = service();
        let created = core
            .create_project(&CreateProjectRequest {
                name: "R1 shell".to_owned(),
            })
            .unwrap();
        assert!(!created.read_only);
        assert!(matches!(
            core.create_project(&CreateProjectRequest {
                name: "second".to_owned()
            }),
            Err(CoreError::ActiveProject)
        ));
        core.close_project().unwrap();
        let opened = core
            .open_project(&OpenProjectRequest {
                project_id: created.project_id,
                mode: ProjectOpenMode::ReadOnly,
            })
            .unwrap();
        assert!(opened.read_only);
        assert!(core.status().unwrap().storage.unwrap().query_only);
    }

    #[test]
    fn note_preview_is_project_bound_redacted_and_data_only() {
        let (_temporary, core) = service();
        let project = core
            .create_project(&CreateProjectRequest {
                name: "Preview".to_owned(),
            })
            .unwrap();
        let hostile = "Authorization: Bearer secret\n<script>window.__PWNED__=1</script>\ntoken=abc123\nvisible\u{0000}control";
        let artifact = core
            .create_note(CreateNoteRequest {
                project_id: project.project_id.clone(),
                logical_name: "hostile.txt".to_owned(),
                content: hostile.to_owned(),
                sensitivity: Sensitivity::SensitiveEvidence,
            })
            .unwrap();
        let preview = core
            .preview_artifact(PreviewArtifactRequest {
                project_id: project.project_id.clone(),
                artifact_id: artifact.artifact_id.clone(),
                offset: 0,
                limit: PREVIEW_READ_LIMIT,
                mode: PreviewMode::Text,
            })
            .unwrap();
        assert!(preview.content.contains("<script>"));
        assert!(!preview.content.contains("Bearer secret"));
        assert!(!preview.content.contains("abc123"));
        assert!(preview.content.contains("\\u{0000}"));
        assert!(matches!(
            core.preview_artifact(PreviewArtifactRequest {
                project_id: project.project_id,
                artifact_id: artifact.artifact_id,
                offset: 0,
                limit: 32,
                mode: PreviewMode::Hex,
            }),
            Err(CoreError::SensitivePreviewDenied)
        ));
    }

    #[test]
    fn project_binding_and_credential_persistence_are_enforced() {
        let (_temporary, core) = service();
        let project = core
            .create_project(&CreateProjectRequest {
                name: "Boundary".to_owned(),
            })
            .unwrap();
        assert!(matches!(
            core.create_note(CreateNoteRequest {
                project_id: ProjectId::new(),
                logical_name: "wrong.txt".to_owned(),
                content: "value".to_owned(),
                sensitivity: Sensitivity::Normal,
            }),
            Err(CoreError::ProjectMismatch)
        ));
        assert!(matches!(
            core.create_note(CreateNoteRequest {
                project_id: project.project_id,
                logical_name: "credential.txt".to_owned(),
                content: "secret".to_owned(),
                sensitivity: Sensitivity::Credential,
            }),
            Err(CoreError::CredentialPersistenceDenied)
        ));
    }

    #[test]
    fn pagination_and_events_are_bounded_and_monotonic() {
        let (_temporary, core) = service();
        let project = core
            .create_project(&CreateProjectRequest {
                name: "Pages".to_owned(),
            })
            .unwrap();
        for index in 0..3 {
            core.create_note(CreateNoteRequest {
                project_id: project.project_id.clone(),
                logical_name: format!("note-{index}.txt"),
                content: format!("value-{index}"),
                sensitivity: Sensitivity::Normal,
            })
            .unwrap();
        }
        let first = core
            .list_artifacts(&ArtifactPageRequest {
                project_id: project.project_id.clone(),
                cursor: None,
                limit: 2,
            })
            .unwrap();
        assert_eq!(first.items.len(), 2);
        assert!(first.next_cursor.is_some());
        let second = core
            .list_artifacts(&ArtifactPageRequest {
                project_id: project.project_id.clone(),
                cursor: first.next_cursor,
                limit: 2,
            })
            .unwrap();
        assert_eq!(second.items.len(), 1);
        assert!(second.next_cursor.is_none());
        let one = core.next_event("project_changed", Some(project.project_id.clone()));
        let two = core.next_event("artifact_committed", Some(project.project_id));
        assert_eq!(two.sequence, one.sequence + 1);
    }

    #[test]
    fn generated_ipc_types_cover_all_commands() {
        let declarations = typescript_declarations();
        for name in [
            "AppStatus",
            "CreateProjectRequest",
            "OpenProjectRequest",
            "CreateNoteRequest",
            "PreviewArtifactRequest",
            "ArtifactPageRequest",
            "CommandError",
            "CreateScopeRequest",
            "ExternalLauncherHealthDto",
            "LaunchExternalRequest",
            "ListPayloadsRequest",
            "PreviewPayloadRequest",
            "RunToolRequest",
            "JobPageRequest",
            "PreviewJobLogRequest",
            "DiscoveryPageRequest",
            "ToolHealthDto",
            "ToolPackHealthDto",
            "CancelJobRequest",
            "CancelAllJobsResult",
            "CreateDictionaryRequest",
            "SearchDictionaryRequest",
            "ExportProjectRequest",
            "ImportPackagePage",
            "ImportProjectRequest",
        ] {
            assert!(declarations.contains(name));
        }
    }

    #[test]
    fn dictionary_is_canonicalized_indexed_and_prefix_searchable() {
        let (_temporary, core) = service();
        let project = core
            .create_project(&CreateProjectRequest {
                name: "Dictionary".to_owned(),
            })
            .unwrap();
        let dictionary = core
            .create_dictionary(CreateDictionaryRequest {
                project_id: project.project_id.clone(),
                name: "paths".to_owned(),
                content: " admin\napi\nadmin\n assets \n\n".to_owned(),
            })
            .unwrap();
        assert_eq!(dictionary.term_count, 3);
        let page = core.list_dictionaries(&project.project_id).unwrap();
        assert_eq!(page.items, vec![dictionary.clone()]);
        let search = core
            .search_dictionary(&SearchDictionaryRequest {
                project_id: project.project_id,
                dictionary_id: dictionary.dictionary_id,
                prefix: "a".to_owned(),
                limit: 10,
            })
            .unwrap();
        assert_eq!(search.terms, ["admin", "api", "assets"]);
    }

    #[test]
    fn project_package_uses_fixed_private_inbox_and_roundtrips() {
        let (temporary, source) = service();
        let project = source
            .create_project(&CreateProjectRequest {
                name: "Portable".to_owned(),
            })
            .unwrap();
        source
            .create_note(CreateNoteRequest {
                project_id: project.project_id.clone(),
                logical_name: "evidence.txt".to_owned(),
                content: "portable evidence".to_owned(),
                sensitivity: Sensitivity::Normal,
            })
            .unwrap();
        let exported = source
            .export_project(&ExportProjectRequest {
                project_id: project.project_id.clone(),
                confirm_sensitive: false,
            })
            .unwrap();
        let source_archive = temporary
            .path()
            .join("workspaces")
            .join(&project.project_id.0)
            .join("exports")
            .join(&exported.archive_name);

        let destination_root = temporary.path().join("imported-workspaces");
        let destination = CoreService::new(&destination_root);
        assert!(destination.list_import_packages().unwrap().items.is_empty());
        let inbox_archive = destination_root
            .join(".imports")
            .join(&exported.archive_name);
        fs::copy(source_archive, &inbox_archive).unwrap();
        fs::set_permissions(&inbox_archive, fs::Permissions::from_mode(0o600)).unwrap();
        let packages = destination.list_import_packages().unwrap();
        assert_eq!(packages.items.len(), 1);
        assert_eq!(packages.items[0].archive_name, exported.archive_name);
        assert!(matches!(
            destination.import_project(&ImportProjectRequest {
                archive_name: "../escape.flagdeck.zip".to_owned(),
            }),
            Err(CoreError::InvalidRequest)
        ));
        let imported = destination
            .import_project(&ImportProjectRequest {
                archive_name: exported.archive_name,
            })
            .unwrap();
        assert_eq!(imported.project.project_id, project.project_id);
        destination
            .open_project(&OpenProjectRequest {
                project_id: project.project_id.clone(),
                mode: ProjectOpenMode::ReadWrite,
            })
            .unwrap();
        let artifacts = destination
            .list_artifacts(&ArtifactPageRequest {
                project_id: project.project_id,
                cursor: None,
                limit: 10,
            })
            .unwrap();
        assert_eq!(artifacts.items.len(), 1);
    }

    #[test]
    fn exact_origin_scope_checks_port_and_dns_snapshot() {
        let (_temporary, core) = service();
        let project = core
            .create_project(&CreateProjectRequest {
                name: "Scope".to_owned(),
            })
            .unwrap();
        let scope = core
            .create_scope(&CreateScopeRequest {
                project_id: project.project_id,
                base_url: "http://127.0.0.1:38001/".to_owned(),
            })
            .unwrap();
        assert_eq!(scope.network_class, NetworkClass::Loopback);
        validate_target_against_scope(
            &scope,
            &Url::parse("http://127.0.0.1:38001/search").unwrap(),
        )
        .unwrap();
        assert!(
            validate_target_against_scope(
                &scope,
                &Url::parse("http://127.0.0.1:38002/search").unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn tool_health_reports_all_seven_binaries_portably() {
        let (_temporary, core) = service();
        let health = core.tool_health().unwrap();
        assert_eq!(health.len(), 7);
        let ready = health.iter().filter(|tool| tool.healthy).count();
        for tool in &health {
            if tool.healthy {
                assert!(tool.path.starts_with('/'));
                assert_ne!(tool.resolution_source, "missing");
                assert_eq!(tool.detail, format!("ready via {}", tool.resolution_source));
            } else {
                assert!(matches!(
                    tool.detail.as_str(),
                    "tool is not installed"
                        | "version marker check failed"
                        | "integrity check failed"
                ));
            }
        }
        let dddd = health
            .iter()
            .find(|tool| tool.tool == AlphaTool::Dddd)
            .unwrap();
        assert_eq!(dddd.health_strategy, "static-go-build-metadata-and-sha256");
        let fscan = health
            .iter()
            .find(|tool| tool.tool == AlphaTool::Fscan)
            .unwrap();
        assert_eq!(fscan.adapter_type, "declarative-cli");
        assert_eq!(fscan.network_policy, "input-gate-and-audit");
        assert!(
            fscan
                .capabilities
                .iter()
                .any(|item| item == "service_discovery")
        );
        assert!(!dddd.side_effect_free_help);
        assert!(health.iter().all(|tool| tool.pack_id == "flagdeck-recon"));
        let packs = core.tool_pack_health().unwrap();
        assert_eq!(packs.len(), 2);
        assert_eq!(packs[0].tools_ready, ready);
        assert_eq!(packs[0].tools_total, 7);
        assert_eq!(
            packs[0].state,
            match ready {
                0 => "missing",
                7 => "ready",
                _ => "partial",
            }
        );
    }

    #[test]
    #[ignore = "requires a compatible curl binary and managed process supervisor"]
    fn managed_job_logs_support_bounded_incremental_preview() {
        let temporary = tempfile::tempdir().unwrap();
        let core = Arc::new(CoreService::new(temporary.path().join("workspaces")));
        let project = core
            .create_project(&CreateProjectRequest {
                name: "Live logs".to_owned(),
            })
            .unwrap();
        let scope = core
            .create_scope(&CreateScopeRequest {
                project_id: project.project_id.clone(),
                base_url: "http://127.0.0.1:1/".to_owned(),
            })
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let job = runtime.block_on(async {
            let started = core
                .start_tool(RunToolRequest {
                    project_id: project.project_id.clone(),
                    scope_id: scope.scope_id,
                    tool: AlphaTool::Curl,
                    target_url: "http://127.0.0.1:1/".to_owned(),
                    wordlist_terms: Vec::new(),
                })
                .unwrap();
            for _ in 0..250 {
                let stored = core
                    .project_store(&project.project_id, false)
                    .unwrap()
                    .job(&started.job.job_id)
                    .unwrap();
                if stored.job.stopped_at.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            started.job.job_id
        });
        let first = core
            .preview_job_log(&PreviewJobLogRequest {
                project_id: project.project_id.clone(),
                job_id: job.clone(),
                stream: JobLogStream::Stderr,
                offset: 0,
                limit: 32,
            })
            .unwrap();
        assert!(first.bytes_returned <= 32);
        let second = core
            .preview_job_log(&PreviewJobLogRequest {
                project_id: project.project_id,
                job_id: job,
                stream: JobLogStream::Stderr,
                offset: first.next_offset,
                limit: MAX_JOB_LOG_PREVIEW_BYTES,
            })
            .unwrap();
        assert!(second.next_offset >= first.next_offset);
        assert!(second.eof);
    }

    #[test]
    fn preview_job_file_reads_sidecar_and_rejects_path_escape() {
        let temporary = tempfile::tempdir().unwrap();
        let core = CoreService::new(temporary.path().join("workspaces"));
        let project = core
            .create_project(&CreateProjectRequest {
                name: "Job file preview".to_owned(),
            })
            .unwrap();
        let store = core.project_store(&project.project_id, true).unwrap();
        let job_id = JobId::new();
        let directory = create_job_directory(&store.layout().scans, &job_id).unwrap();
        fs::write(
            directory.join("ffuf-output.json"),
            br#"{"results":[{"url":"http://x/a","status":200}]}"#,
        )
        .unwrap();
        let wordlist = directory.join("wordlist.txt");
        write_wordlist(ToolId::Ffuf, &["admin".to_owned()], &wordlist).unwrap();
        let mut prepared = prepare_command(
            ToolId::Ffuf,
            &ScopeId::new(),
            &Url::parse("http://127.0.0.1:38001/").unwrap(),
            &directory,
            Some(&wordlist),
        )
        .unwrap();
        if prepared.spec.program.is_empty() {
            prepared.spec.program = "/opt/flagdeck-test/bin/ffuf".to_owned();
        }
        store.save_command_spec(&prepared.spec).unwrap();
        let now = Timestamp::now();
        let job = Job {
            job_id: job_id.clone(),
            parent_job_id: None,
            command_spec_id: prepared.spec.command_spec_id.clone(),
            execution_status: ExecutionStatus::Succeeded,
            import_status: ImportStatus::Pending,
            created_at: now.clone(),
            started_at: Some(now.clone()),
            stopped_at: Some(now),
            pid: None,
            process_group_id: None,
            process_start_ticks: None,
            exit_code: Some(0),
            exit_reason: Some("exit_code:0".to_owned()),
            systemd_unit: None,
            cgroup_path: None,
            invocation_id: None,
            supervisor_backend: None,
            ownership_verified: true,
            cleanup_verified: true,
            residual_processes: 0,
            cancel_duration_millis: None,
            stdout_artifact_id: None,
            stderr_artifact_id: None,
            retry_count: 0,
            source_job_id: None,
        };
        store.save_job(&job).unwrap();

        let preview = core
            .preview_job_file(&PreviewJobFileRequest {
                project_id: project.project_id.clone(),
                job_id: job_id.clone(),
                filename: "ffuf-output.json".to_owned(),
                limit: 4096,
            })
            .unwrap();
        assert!(preview.found);
        assert!(preview.content.contains("http://x/a"));

        let missing = core
            .preview_job_file(&PreviewJobFileRequest {
                project_id: project.project_id.clone(),
                job_id: job_id.clone(),
                filename: "nope.json".to_owned(),
                limit: 4096,
            })
            .unwrap();
        assert!(!missing.found);

        assert!(matches!(
            core.preview_job_file(&PreviewJobFileRequest {
                project_id: project.project_id,
                job_id,
                filename: "../escape.json".to_owned(),
                limit: 4096,
            }),
            Err(CoreError::InvalidRequest)
        ));
    }

    #[test]
    fn exit_zero_with_corrupted_output_persists_parser_failed_independently() {
        let temporary = tempfile::tempdir().unwrap();
        let (store, project) =
            ProjectStore::create(&temporary.path().join("workspaces"), "Parser state").unwrap();
        let job_id = JobId::new();
        let directory = create_job_directory(&store.layout().scans, &job_id).unwrap();
        let wordlist = directory.join("wordlist.txt");
        write_wordlist(ToolId::Ffuf, &["admin".to_owned()], &wordlist).unwrap();
        let mut prepared = prepare_command(
            ToolId::Ffuf,
            &ScopeId::new(),
            &Url::parse("http://127.0.0.1:38001/").unwrap(),
            &directory,
            Some(&wordlist),
        )
        .unwrap();
        if prepared.spec.program.is_empty() {
            prepared.spec.program = "/opt/flagdeck-test/bin/ffuf".to_owned();
        }
        fs::write(directory.join("ffuf-output.json"), b"{corrupted").unwrap();
        store.save_command_spec(&prepared.spec).unwrap();
        let now = Timestamp::now();
        let mut job = Job {
            job_id: job_id.clone(),
            parent_job_id: None,
            command_spec_id: prepared.spec.command_spec_id.clone(),
            execution_status: ExecutionStatus::Succeeded,
            import_status: ImportStatus::Importing,
            created_at: now.clone(),
            started_at: Some(now.clone()),
            stopped_at: Some(now),
            pid: Some(123),
            process_group_id: Some(123),
            process_start_ticks: Some(1),
            exit_code: Some(0),
            exit_reason: Some("exit_code:0".to_owned()),
            systemd_unit: None,
            cgroup_path: None,
            invocation_id: None,
            supervisor_backend: Some(flagdeck_domain::SupervisorBackend::PgidFallback),
            ownership_verified: true,
            cleanup_verified: false,
            residual_processes: 0,
            cancel_duration_millis: None,
            stdout_artifact_id: None,
            stderr_artifact_id: None,
            retry_count: 0,
            source_job_id: None,
        };
        let importing = JobImportRecord {
            job_id: job_id.clone(),
            parser_id: prepared.manifest.parser_id.clone(),
            parser_version: prepared.manifest.parser_version.clone(),
            import_status: ImportStatus::Importing,
            discovery_count: 0,
            http_message_count: 0,
            source_artifact_ids: Vec::new(),
            error_summary: None,
            completed_at: None,
        };
        store.write_import_state(&job, &importing).unwrap();
        let parser_error = parse_output(&prepared).unwrap_err();
        persist_parser_failure(
            &store,
            &mut job,
            &prepared,
            Vec::new(),
            parser_error.to_string(),
        )
        .unwrap();
        let stored = store.job(&job_id).unwrap();
        assert_eq!(stored.job.execution_status, ExecutionStatus::Succeeded);
        assert_eq!(stored.job.exit_code, Some(0));
        assert_eq!(stored.job.import_status, ImportStatus::ParserFailed);
        assert!(stored.import.unwrap().error_summary.is_some());
        assert_eq!(store.project_id(), &project.project_id);
    }

    #[test]
    #[ignore = "requires the R2 Tool Pack and a systemd user manager"]
    fn vertical_alpha_runs_four_real_tools_and_survives_restart() {
        let temporary = tempfile::tempdir().unwrap();
        let ready = temporary.path().join("ready.json");
        let requests = temporary.path().join("requests.jsonl");
        let server_script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/r2/target_server.py");
        let child = Command::new("/usr/bin/python3")
            .arg(server_script)
            .args(["--ready-file", ready.to_str().unwrap()])
            .args(["--log-file", requests.to_str().unwrap()])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let _fixture = FixtureProcess(child);
        for _ in 0..250 {
            if ready.is_file() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let ready_value: serde_json::Value =
            serde_json::from_slice(&fs::read(&ready).unwrap()).unwrap();
        let base_url = ready_value["url"].as_str().unwrap().to_owned();
        let workspaces = temporary.path().join("workspaces");
        let core = CoreService::new(&workspaces);
        let project = core
            .create_project(&CreateProjectRequest {
                name: "R2 vertical Alpha".to_owned(),
            })
            .unwrap();
        let scope = core
            .create_scope(&CreateScopeRequest {
                project_id: project.project_id.clone(),
                base_url: base_url.clone(),
            })
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let cases = [
            (AlphaTool::Curl, format!("{base_url}/"), Vec::new()),
            (AlphaTool::Dddd, base_url.clone(), Vec::new()),
            (
                AlphaTool::Ffuf,
                base_url.clone(),
                vec![
                    "admin".to_owned(),
                    "api".to_owned(),
                    "redirect".to_owned(),
                    "missing-r2".to_owned(),
                ],
            ),
            (
                AlphaTool::Arjun,
                format!("{base_url}/search"),
                vec!["debug".to_owned(), "id".to_owned(), "unused".to_owned()],
            ),
        ];
        for (tool, target_url, wordlist_terms) in cases {
            let expected_http_messages = usize::from(tool == AlphaTool::Curl);
            let result = runtime
                .block_on(core.run_tool(RunToolRequest {
                    project_id: project.project_id.clone(),
                    scope_id: scope.scope_id.clone(),
                    tool,
                    target_url,
                    wordlist_terms,
                }))
                .unwrap();
            assert_eq!(result.job.job.execution_status, ExecutionStatus::Succeeded);
            assert_eq!(result.job.job.import_status, ImportStatus::Imported);
            assert_eq!(result.http_messages_imported, expected_http_messages);
            assert!(!result.artifacts.is_empty());
        }
        core.close_project().unwrap();
        drop(core);

        let restarted = CoreService::new(&workspaces);
        restarted
            .open_project(&OpenProjectRequest {
                project_id: project.project_id.clone(),
                mode: ProjectOpenMode::ReadWrite,
            })
            .unwrap();
        let jobs = restarted
            .list_jobs(&JobPageRequest {
                project_id: project.project_id.clone(),
                cursor: None,
                limit: 100,
            })
            .unwrap();
        assert_eq!(jobs.items.len(), 4);
        assert!(jobs.items.iter().all(|item| {
            item.job.execution_status == ExecutionStatus::Succeeded
                && item.job.import_status == ImportStatus::Imported
                && item.job.supervisor_backend
                    == Some(flagdeck_domain::SupervisorBackend::SystemdUserService)
                && item.network_isolation == "loopback-systemd-primary-pgid-input-gate"
        }));
        let discoveries = restarted
            .list_discoveries(&DiscoveryPageRequest {
                project_id: project.project_id,
                cursor: None,
                limit: 100,
            })
            .unwrap();
        assert!(discoveries.items.len() >= 7);
        let request_log = fs::read_to_string(requests).unwrap();
        assert!(request_log.lines().all(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|value| value["client"].as_str().map(str::to_owned))
                .as_deref()
                == Some("127.0.0.1")
        }));
    }

    #[test]
    #[ignore = "requires a compatible curl binary and systemd user manager"]
    fn background_job_cancel_cleans_owned_systemd_cgroup() {
        let temporary = tempfile::tempdir().unwrap();
        let ready = temporary.path().join("ready.json");
        let requests = temporary.path().join("requests.jsonl");
        let server_script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/r2/target_server.py");
        let child = Command::new("/usr/bin/python3")
            .arg(server_script)
            .args(["--ready-file", ready.to_str().unwrap()])
            .args(["--log-file", requests.to_str().unwrap()])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let _fixture = FixtureProcess(child);
        for _ in 0..250 {
            if ready.is_file() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let ready_value: serde_json::Value =
            serde_json::from_slice(&fs::read(&ready).unwrap()).unwrap();
        let base_url = ready_value["url"].as_str().unwrap().to_owned();
        let core = Arc::new(CoreService::new(temporary.path().join("workspaces")));
        let project = core
            .create_project(&CreateProjectRequest {
                name: "R3 cancellation".to_owned(),
            })
            .unwrap();
        let scope = core
            .create_scope(&CreateScopeRequest {
                project_id: project.project_id.clone(),
                base_url: base_url.clone(),
            })
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let queued = core
                .start_tool(RunToolRequest {
                    project_id: project.project_id.clone(),
                    scope_id: scope.scope_id,
                    tool: AlphaTool::Curl,
                    target_url: format!("{base_url}/slow"),
                    wordlist_terms: Vec::new(),
                })
                .unwrap();
            let running = loop {
                let stored = core
                    .list_jobs(&JobPageRequest {
                        project_id: project.project_id.clone(),
                        cursor: None,
                        limit: 100,
                    })
                    .unwrap()
                    .items
                    .into_iter()
                    .find(|item| item.job.job_id == queued.job.job_id)
                    .unwrap();
                if stored.job.execution_status == ExecutionStatus::Running {
                    break stored;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            };
            assert!(running.job.invocation_id.is_some());
            assert!(running.job.cgroup_path.is_some());
            assert!(running.job.ownership_verified);
            let cancelled = core
                .cancel_job(&CancelJobRequest {
                    project_id: project.project_id.clone(),
                    job_id: queued.job.job_id.clone(),
                })
                .await
                .unwrap();
            assert!(cancelled.accepted);
            assert!(cancelled.cleanup_verified);
            assert_eq!(cancelled.residual_processes, 0);
            assert!(
                cancelled
                    .duration_millis
                    .is_some_and(|value| value <= 5_000)
            );
            loop {
                let status = core.status().unwrap();
                if status.active_jobs == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let terminal = core
                .list_jobs(&JobPageRequest {
                    project_id: project.project_id.clone(),
                    cursor: None,
                    limit: 100,
                })
                .unwrap()
                .items
                .into_iter()
                .find(|item| item.job.job_id == queued.job.job_id)
                .unwrap();
            assert_eq!(terminal.job.execution_status, ExecutionStatus::Cancelled);
            assert_eq!(terminal.job.import_status, ImportStatus::Skipped);
            assert!(terminal.job.cleanup_verified);
            assert_eq!(terminal.job.residual_processes, 0);
        });
    }

    #[test]
    fn command_errors_do_not_expose_storage_context() {
        let error = CommandError::from(CoreError::Storage(StorageError::InvalidLayout(
            "/private/workspace/path".to_owned(),
        )));
        assert_eq!(error.code, "storage_error");
        assert_eq!(error.message, "Storage operation failed");
        assert!(!error.message.contains("/private"));
    }

    struct LoopbackFixture {
        port: u16,
        connections: Arc<AtomicUsize>,
        off_scope: Arc<AtomicUsize>,
        stored: Arc<Mutex<Vec<u8>>>,
    }

    fn find_seq(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
        haystack
            .get(from..)?
            .windows(needle.len())
            .position(|window| window == needle)
            .map(|index| index + from)
    }

    fn extract_uploaded_file(body: &[u8]) -> Vec<u8> {
        let Some(name) = find_seq(body, b"filename=", 0) else {
            return Vec::new();
        };
        let Some(header_end) = find_seq(body, b"\r\n\r\n", name) else {
            return Vec::new();
        };
        let start = header_end + 4;
        let end = find_seq(body, b"\r\n--", start).unwrap_or(body.len());
        body[start..end].to_vec()
    }

    fn spawn_loopback_fixture() -> LoopbackFixture {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let off_scope = Arc::new(AtomicUsize::new(0));
        let stored = Arc::new(Mutex::new(Vec::new()));
        let token_counter = Arc::new(AtomicUsize::new(0));
        let thread_connections = Arc::clone(&connections);
        let thread_off_scope = Arc::clone(&off_scope);
        let thread_stored = Arc::clone(&stored);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                thread_connections.fetch_add(1, Ordering::SeqCst);
                if stream
                    .peer_addr()
                    .is_ok_and(|peer| !peer.ip().is_loopback())
                {
                    thread_off_scope.fetch_add(1, Ordering::SeqCst);
                }
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }
                let mut fields = request_line.split_whitespace();
                let method = fields.next().unwrap_or_default().to_owned();
                let path = fields.next().unwrap_or_default().to_owned();
                let mut content_length = 0usize;
                let mut csrf = String::new();
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap_or(0) == 0 {
                        break;
                    }
                    if header == "\r\n" || header == "\n" {
                        break;
                    }
                    let lower = header.to_ascii_lowercase();
                    if let Some(value) = lower.strip_prefix("content-length:") {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                    if lower.starts_with("x-csrf:") {
                        csrf = header["x-csrf:".len()..].trim().to_owned();
                    }
                }
                let mut request_body = vec![0u8; content_length];
                let _ = std::io::Read::read_exact(&mut reader, &mut request_body);
                let (status, body): (&str, Vec<u8>) = match (method.as_str(), path.as_str()) {
                    ("GET", "/token") => {
                        let sequence = token_counter.fetch_add(1, Ordering::SeqCst);
                        (
                            "200 OK",
                            format!("<input name=\"csrf\" value=\"TOKEN-{sequence}\">")
                                .into_bytes(),
                        )
                    }
                    ("POST", "/upload") => {
                        if csrf.starts_with("TOKEN-") {
                            *thread_stored.lock().unwrap() = extract_uploaded_file(&request_body);
                            ("200 OK", br#"{"path":"/files/stored"}"#.to_vec())
                        } else {
                            ("403 Forbidden", b"missing csrf".to_vec())
                        }
                    }
                    ("GET", "/files/stored") => ("200 OK", thread_stored.lock().unwrap().clone()),
                    ("POST", "/search") => ("200 OK", request_body.clone()),
                    _ => ("404 Not Found", b"not found".to_vec()),
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = std::io::Write::write_all(&mut stream, head.as_bytes());
                let _ = std::io::Write::write_all(&mut stream, &body);
                let _ = std::io::Write::flush(&mut stream);
                drop(reader);
                drop(stream);
            }
        });
        LoopbackFixture {
            port,
            connections,
            off_scope,
            stored,
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn loopback_request(
        project_id: &ProjectId,
        port: u16,
        method: &str,
        path: &str,
        headers: Vec<OrderedValue>,
        body: Vec<u8>,
    ) -> HttpMessage {
        let has_body = !body.is_empty();
        HttpMessage {
            message_id: MessageId::new(),
            project_id: project_id.clone(),
            exchange_id: None,
            parent_message_id: None,
            source: HttpSource::Import,
            representation_kind: RepresentationKind::Semantic,
            method: Some(method.to_owned()),
            status_code: None,
            scheme: "http".to_owned(),
            host: "127.0.0.1".to_owned(),
            port,
            authority: format!("127.0.0.1:{port}"),
            path: path.to_owned(),
            http_version: "HTTP/1.1".to_owned(),
            headers,
            trailers: Vec::new(),
            query: Vec::new(),
            form: Vec::new(),
            body_inline: has_body.then(|| body.clone()),
            body_artifact_id: None,
            wire_artifact_id: None,
            serializer_version: "flagdeck.semantic-http1/1".to_owned(),
            body_state: if has_body {
                BodyState::Complete
            } else {
                BodyState::Missing
            },
            declared_length: has_body.then_some(body.len() as u64),
            actual_length: body.len() as u64,
            content_encoding: None,
            decoded_preview_state: "not_requested".to_owned(),
            direction: MessageDirection::Request,
            observed_at: Timestamp::now(),
            duration_millis: None,
            connection: ConnectionMetadata {
                client_address: None,
                server_address: None,
                tls: false,
                tls_version: None,
                certificate_sha256: None,
            },
            sensitivity: Sensitivity::Normal,
            redacted_view: String::new(),
        }
    }

    fn await_campaign(
        core: &CoreService,
        project_id: &ProjectId,
        id: &flagdeck_domain::IntruderCampaignId,
    ) -> IntruderCampaign {
        for _ in 0..200 {
            let page = core
                .list_intruder_campaigns(&ListIntruderCampaignsRequest {
                    project_id: project_id.clone(),
                    limit: 50,
                })
                .unwrap();
            if let Some(found) = page
                .items
                .into_iter()
                .find(|campaign| &campaign.intruder_campaign_id == id)
                && matches!(
                    found.state,
                    flagdeck_domain::IntruderCampaignState::Completed
                        | flagdeck_domain::IntruderCampaignState::Failed
                )
            {
                return found;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("campaign did not reach a terminal state");
    }

    #[test]
    fn external_launch_requires_exact_l3_phrase_and_records_both_outcomes() {
        let (_temporary, core) = service();
        let core = Arc::new(core);
        let project = core
            .create_project(&CreateProjectRequest {
                name: "R7 external launch audit".to_owned(),
            })
            .unwrap();
        let scope = core
            .create_scope(&CreateScopeRequest {
                project_id: project.project_id.clone(),
                base_url: "http://127.0.0.1:9/".to_owned(),
            })
            .unwrap();
        let request = LaunchExternalRequest {
            project_id: project.project_id.clone(),
            scope_id: scope.scope_id.clone(),
            launcher: ExternalLauncherId::Shiro,
            target_url: "http://127.0.0.1:9/".to_owned(),
            confirmation: "wrong phrase".to_owned(),
        };
        assert!(matches!(
            core.launch_external(&request),
            Err(CoreError::ExternalLauncher(
                external::ExternalLauncherError::ConfirmationRequired
            ))
        ));

        let exact = LaunchExternalRequest {
            confirmation: format!("LAUNCH EXTERNAL shiro {}", scope.scope_id.0),
            ..request
        };
        assert!(matches!(
            core.launch_external(&exact),
            Err(CoreError::ExternalLauncher(
                external::ExternalLauncherError::Integrity
            ))
        ));
        let audit = core.audit_events_for_test(10);
        assert!(audit.iter().any(|event| {
            event.action == "external.launch"
                && event.outcome == "denied"
                && event.risk_level == flagdeck_domain::RiskLevel::L3
                && event.adapter_id.as_deref() == Some("external.shiro")
        }));
        assert!(audit.iter().any(|event| {
            event.action == "external.launch"
                && event.outcome == "allowed"
                && event.risk_level == flagdeck_domain::RiskLevel::L3
                && event.adapter_id.as_deref() == Some("external.shiro")
        }));
        assert_eq!(core.active_runs.load(Ordering::SeqCst), 0);
        assert!(core.active_executions.lock().unwrap().is_empty());
    }

    #[test]
    fn upload_execution_verification_requires_exact_confirmation_and_audits() {
        let (_temporary, core) = service();
        let project = core
            .create_project(&CreateProjectRequest {
                name: "R6 l3".to_owned(),
            })
            .unwrap();
        let scope = core
            .create_scope(&CreateScopeRequest {
                project_id: project.project_id.clone(),
                base_url: "http://127.0.0.1:9/".to_owned(),
            })
            .unwrap();
        let upload_body =
            b"--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php echo 1;?>\r\n--X--\r\n".to_vec();
        let upload_message = loopback_request(
            &project.project_id,
            9,
            "POST",
            "/upload",
            vec![OrderedValue {
                name: "Content-Type".to_owned(),
                value: "multipart/form-data; boundary=X".to_owned(),
            }],
            upload_body,
        );
        core.seed_http_message(&upload_message);
        let verification = UploadVerification {
            mode: UploadVerificationMode::Execution,
            path_extractor: Some(TokenExtractor {
                variable: "path".to_owned(),
                source: TokenSource::ResponseBody,
                header_name: None,
                prefix: b"\"path\":\"".to_vec(),
                suffix: b"\"".to_vec(),
                maximum_length: 256,
            }),
            expected_execution_marker: Some(b"flagdeck-executed-42".to_vec()),
        };
        let base = StartUploadCampaignRequest {
            project_id: project.project_id.clone(),
            scope_id: scope.scope_id.clone(),
            parent_message_id: upload_message.message_id.clone(),
            part_ordinal: 0,
            mutations: vec![flagdeck_domain::UploadMutationKind::MagicBytes],
            global_rate_per_second: 50,
            target_rate_per_second: 50,
            state_macro: None,
            verification: verification.clone(),
            confirmation: Some("wrong phrase".to_owned()),
        };
        let denied = core.start_upload_campaign(&base);
        assert!(matches!(
            denied,
            Err(CoreError::Intruder(IntruderError::ConfirmationRequired))
        ));
        let audit = core.audit_events_for_test(10);
        assert!(audit.iter().any(|event| {
            event.action == "upload.execution_verification"
                && event.outcome == "denied"
                && event.risk_level == flagdeck_domain::RiskLevel::L3
                && event
                    .details_json
                    .contains("85c3bcca56b787172263d3f8aea27349b7330f756a4e58f31d186e74e680ddcf")
                && !event.details_json.contains("flagdeck-executed-42")
        }));

        let phrase = format!("VERIFY UPLOAD EXECUTION {}", upload_message.message_id.0);
        let allowed = StartUploadCampaignRequest {
            confirmation: Some(phrase),
            ..base
        };
        // The exact phrase clears the L3 gate; the campaign then runs (and fails to reach
        // the unroutable port), but the allowed audit event is recorded synchronously.
        let _ = core.start_upload_campaign(&allowed);
        let audit = core.audit_events_for_test(10);
        assert!(audit.iter().any(|event| {
            event.action == "upload.execution_verification"
                && event.outcome == "allowed"
                && event.risk_level == flagdeck_domain::RiskLevel::L3
                && event
                    .details_json
                    .contains("85c3bcca56b787172263d3f8aea27349b7330f756a4e58f31d186e74e680ddcf")
                && !event.details_json.contains("flagdeck-executed-42")
        }));
    }

    #[test]
    fn loopback_upload_chain_verifies_and_intruder_modes_run() {
        let fixture = spawn_loopback_fixture();
        let (_temporary, core) = service();
        let project = core
            .create_project(&CreateProjectRequest {
                name: "R6 loopback".to_owned(),
            })
            .unwrap();
        let scope = core
            .create_scope(&CreateScopeRequest {
                project_id: project.project_id.clone(),
                base_url: format!("http://127.0.0.1:{}/", fixture.port),
            })
            .unwrap();
        let dictionary = core
            .create_dictionary(CreateDictionaryRequest {
                project_id: project.project_id.clone(),
                name: "words".to_owned(),
                content: "alpha\nbravo\ncharlie\ndelta\n".to_owned(),
            })
            .unwrap();

        // Stateful upload chain: refresh CSRF, upload a mutated file, verify by retrieval.
        let token_message = loopback_request(
            &project.project_id,
            fixture.port,
            "GET",
            "/token",
            Vec::new(),
            Vec::new(),
        );
        core.seed_http_message(&token_message);
        let upload_body =
            b"--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php echo 1;?>\r\n--X--\r\n".to_vec();
        let upload_message = loopback_request(
            &project.project_id,
            fixture.port,
            "POST",
            "/upload",
            vec![
                OrderedValue {
                    name: "Content-Type".to_owned(),
                    value: "multipart/form-data; boundary=X".to_owned(),
                },
                OrderedValue {
                    name: "X-CSRF".to_owned(),
                    value: "{{csrf}}".to_owned(),
                },
            ],
            upload_body,
        );
        core.seed_http_message(&upload_message);
        let state_macro = StateMacro {
            steps: vec![StateMacroStep {
                name: "refresh-csrf".to_owned(),
                message_id: token_message.message_id.clone(),
                extractors: vec![TokenExtractor {
                    variable: "csrf".to_owned(),
                    source: TokenSource::ResponseBody,
                    header_name: None,
                    prefix: b"value=\"".to_vec(),
                    suffix: b"\"".to_vec(),
                    maximum_length: 64,
                }],
            }],
        };
        let upload = core
            .start_upload_campaign(&StartUploadCampaignRequest {
                project_id: project.project_id.clone(),
                scope_id: scope.scope_id.clone(),
                parent_message_id: upload_message.message_id.clone(),
                part_ordinal: 0,
                mutations: vec![flagdeck_domain::UploadMutationKind::MagicBytes],
                global_rate_per_second: 50,
                target_rate_per_second: 50,
                state_macro: Some(state_macro),
                verification: UploadVerification {
                    mode: UploadVerificationMode::SafeRetrieval,
                    path_extractor: Some(TokenExtractor {
                        variable: "path".to_owned(),
                        source: TokenSource::ResponseBody,
                        header_name: None,
                        prefix: b"\"path\":\"".to_vec(),
                        suffix: b"\"".to_vec(),
                        maximum_length: 256,
                    }),
                    expected_execution_marker: None,
                },
                confirmation: None,
            })
            .unwrap();
        let terminal = await_campaign(&core, &project.project_id, &upload.intruder_campaign_id);
        assert_eq!(
            terminal.state,
            flagdeck_domain::IntruderCampaignState::Completed
        );
        let attempts = core
            .list_intruder_attempts(&IntruderAttemptPageRequest {
                project_id: project.project_id.clone(),
                intruder_campaign_id: upload.intruder_campaign_id.clone(),
                cursor: None,
                limit: 50,
            })
            .unwrap();
        assert_eq!(attempts.items.len(), 1);
        let attempt = &attempts.items[0];
        assert_eq!(
            attempt.state,
            flagdeck_domain::IntruderAttemptState::Succeeded
        );
        assert!(
            attempt
                .verification_summary
                .as_deref()
                .is_some_and(|summary| summary.starts_with("safe_retrieval_verified")),
            "unexpected summary {:?}",
            attempt.verification_summary
        );
        assert!(attempt.state_chain_run_id.is_some());
        let expected_stored = format!(
            "GIF89aFLAGDECK_SAFE_UPLOAD\ncampaign={}\nattempt=0\n",
            upload.intruder_campaign_id.0
        );
        let stored = fixture.stored.lock().unwrap();
        assert_eq!(stored.as_slice(), expected_stored.as_bytes());
        assert!(
            !stored
                .windows(b"<?php echo 1;?>".len())
                .any(|window| window == b"<?php echo 1;?>")
        );
        drop(stored);

        // Sniper intruder over a form field with the full dictionary.
        let search_message = loopback_request(
            &project.project_id,
            fixture.port,
            "POST",
            "/search",
            vec![OrderedValue {
                name: "Content-Type".to_owned(),
                value: "application/x-www-form-urlencoded".to_owned(),
            }],
            b"q=seed".to_vec(),
        );
        core.seed_http_message(&search_message);
        let sniper = core
            .start_intruder(&StartIntruderRequest {
                project_id: project.project_id.clone(),
                scope_id: scope.scope_id.clone(),
                parent_message_id: search_message.message_id.clone(),
                attack_mode: flagdeck_domain::IntruderAttackMode::Sniper,
                positions: vec![flagdeck_domain::PayloadPosition {
                    location: flagdeck_domain::PayloadLocation::Form,
                    name: Some("q".to_owned()),
                    occurrence: 0,
                    start: None,
                    end: None,
                }],
                dictionary_ids: vec![dictionary.dictionary_id.clone()],
                global_rate_per_second: 8,
                target_rate_per_second: 8,
                state_macro: None,
            })
            .unwrap();
        let sniper_start = std::time::Instant::now();
        let sniper_terminal =
            await_campaign(&core, &project.project_id, &sniper.intruder_campaign_id);
        assert_eq!(
            sniper_terminal.state,
            flagdeck_domain::IntruderCampaignState::Completed
        );
        assert_eq!(sniper_terminal.total_attempts, 4);
        assert_eq!(sniper_terminal.completed_attempts, 4);
        // Global rate limit of 8/s across four attempts imposes a measurable floor.
        assert!(sniper_start.elapsed() >= Duration::from_millis(250));
        let sniper_attempts = core
            .list_intruder_attempts(&IntruderAttemptPageRequest {
                project_id: project.project_id.clone(),
                intruder_campaign_id: sniper.intruder_campaign_id.clone(),
                cursor: None,
                limit: 50,
            })
            .unwrap();
        assert_eq!(sniper_attempts.items.len(), 4);
        let ordinals: Vec<u64> = sniper_attempts
            .items
            .iter()
            .map(|attempt| attempt.ordinal)
            .collect();
        assert_eq!(ordinals, vec![0, 1, 2, 3]);

        // Out-of-scope parent is rejected before any socket is opened.
        let connections_before = fixture.connections.load(Ordering::SeqCst);
        let off_scope_message = loopback_request(
            &project.project_id,
            fixture.port + 1,
            "POST",
            "/search",
            vec![OrderedValue {
                name: "Content-Type".to_owned(),
                value: "application/x-www-form-urlencoded".to_owned(),
            }],
            b"q=seed".to_vec(),
        );
        core.seed_http_message(&off_scope_message);
        let rejected = core.start_intruder(&StartIntruderRequest {
            project_id: project.project_id.clone(),
            scope_id: scope.scope_id.clone(),
            parent_message_id: off_scope_message.message_id.clone(),
            attack_mode: flagdeck_domain::IntruderAttackMode::Sniper,
            positions: vec![flagdeck_domain::PayloadPosition {
                location: flagdeck_domain::PayloadLocation::Form,
                name: Some("q".to_owned()),
                occurrence: 0,
                start: None,
                end: None,
            }],
            dictionary_ids: vec![dictionary.dictionary_id.clone()],
            global_rate_per_second: 8,
            target_rate_per_second: 8,
            state_macro: None,
        });
        assert!(matches!(
            rejected,
            Err(CoreError::Intruder(IntruderError::InvalidRequest))
        ));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            fixture.connections.load(Ordering::SeqCst),
            connections_before,
            "an out-of-scope campaign opened a connection"
        );
        assert_eq!(
            fixture.off_scope.load(Ordering::SeqCst),
            0,
            "a non-loopback peer connected"
        );
    }

    fn self_rss_kib() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status.lines().find_map(|line| {
                    line.strip_prefix("VmRSS:").and_then(|value| {
                        value
                            .split_whitespace()
                            .next()
                            .and_then(|kib| kib.parse().ok())
                    })
                })
            })
            .unwrap_or(0)
    }

    // Rate-limit, stop/resume and memory evidence for the R6 gate. Ignored by default;
    // driven by `mise run r6-intruder-evidence`, which pins FLAGDECK_R6_EVIDENCE.
    #[test]
    #[ignore = "R6 performance evidence gate"]
    fn r6_intruder_performance_gate() {
        let fixture = spawn_loopback_fixture();
        let (_temporary, core) = service();
        let project = core
            .create_project(&CreateProjectRequest {
                name: "R6 evidence".to_owned(),
            })
            .unwrap();
        let scope = core
            .create_scope(&CreateScopeRequest {
                project_id: project.project_id.clone(),
                base_url: format!("http://127.0.0.1:{}/", fixture.port),
            })
            .unwrap();
        let terms = (0..12)
            .map(|index| format!("term{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let dictionary = core
            .create_dictionary(CreateDictionaryRequest {
                project_id: project.project_id.clone(),
                name: "evidence".to_owned(),
                content: format!("{terms}\n"),
            })
            .unwrap();
        let search_message = loopback_request(
            &project.project_id,
            fixture.port,
            "POST",
            "/search",
            vec![OrderedValue {
                name: "Content-Type".to_owned(),
                value: "application/x-www-form-urlencoded".to_owned(),
            }],
            b"q=seed".to_vec(),
        );
        core.seed_http_message(&search_message);

        let target_rate = 8u32;
        let rss_before = self_rss_kib();
        let started = std::time::Instant::now();
        let campaign = core
            .start_intruder(&StartIntruderRequest {
                project_id: project.project_id.clone(),
                scope_id: scope.scope_id.clone(),
                parent_message_id: search_message.message_id.clone(),
                attack_mode: flagdeck_domain::IntruderAttackMode::Sniper,
                positions: vec![flagdeck_domain::PayloadPosition {
                    location: flagdeck_domain::PayloadLocation::Form,
                    name: Some("q".to_owned()),
                    occurrence: 0,
                    start: None,
                    end: None,
                }],
                dictionary_ids: vec![dictionary.dictionary_id.clone()],
                global_rate_per_second: target_rate,
                target_rate_per_second: target_rate,
                state_macro: None,
            })
            .unwrap();

        // Cancel mid-flight to exercise pause, then resume and confirm continuity.
        std::thread::sleep(Duration::from_millis(500));
        let paused = core
            .cancel_intruder_campaign(&CampaignRequest {
                project_id: project.project_id.clone(),
                intruder_campaign_id: campaign.intruder_campaign_id.clone(),
            })
            .unwrap();
        assert_eq!(paused.state, flagdeck_domain::IntruderCampaignState::Paused);
        // Wait for the worker thread to observe cancellation and release the slot.
        std::thread::sleep(Duration::from_millis(200));
        let resumed_from = core
            .list_intruder_campaigns(&ListIntruderCampaignsRequest {
                project_id: project.project_id.clone(),
                limit: 10,
            })
            .unwrap()
            .items
            .into_iter()
            .find(|item| item.intruder_campaign_id == campaign.intruder_campaign_id)
            .unwrap()
            .next_ordinal;
        core.resume_intruder_campaign(&CampaignRequest {
            project_id: project.project_id.clone(),
            intruder_campaign_id: campaign.intruder_campaign_id.clone(),
        })
        .unwrap();
        let terminal = await_campaign(&core, &project.project_id, &campaign.intruder_campaign_id);
        let elapsed = started.elapsed();
        let rss_after = self_rss_kib();
        assert_eq!(
            terminal.state,
            flagdeck_domain::IntruderCampaignState::Completed
        );
        assert_eq!(terminal.total_attempts, 12);
        assert_eq!(terminal.completed_attempts, 12);

        let attempts = core
            .list_intruder_attempts(&IntruderAttemptPageRequest {
                project_id: project.project_id.clone(),
                intruder_campaign_id: campaign.intruder_campaign_id.clone(),
                cursor: None,
                limit: 50,
            })
            .unwrap();
        let mut ordinals: Vec<u64> = attempts.items.iter().map(|a| a.ordinal).collect();
        ordinals.sort_unstable();
        assert_eq!(
            ordinals,
            (0..12).collect::<Vec<_>>(),
            "duplicate or missing ordinals"
        );

        let measured_rate = 12.0 / elapsed.as_secs_f64();
        // Global rate limiting keeps throughput at or under the target (with slack).
        assert!(
            measured_rate <= f64::from(target_rate) * 1.6,
            "measured rate {measured_rate} exceeded target {target_rate}"
        );

        let evidence = serde_json::json!({
            "scenario": "r6-intruder-upload",
            "attack_mode": "sniper",
            "total_attempts": terminal.total_attempts,
            "completed_attempts": terminal.completed_attempts,
            "target_rate_per_second": target_rate,
            "measured_rate_per_second": (measured_rate * 1000.0).round() / 1000.0,
            "elapsed_millis": u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            "resume_from_ordinal": resumed_from,
            "ordinals_unique": true,
            "rss_before_kib": rss_before,
            "rss_after_kib": rss_after,
            "rss_delta_kib": rss_after.saturating_sub(rss_before),
        });
        if let Some(path) = std::env::var_os("FLAGDECK_R6_EVIDENCE") {
            let path = PathBuf::from(path);
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            fs::write(&path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
        }
    }
}
