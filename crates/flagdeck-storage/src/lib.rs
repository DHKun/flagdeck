#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use flagdeck_domain::{
    AdapterEntity, Artifact, ArtifactId, ArtifactState, AuditEvent, CommandSpec, DictionaryId,
    DictionaryIndex, Discovery, DiscoveryId, ExportPolicy, HttpMessage, HttpSource, IntegrityState,
    IntruderAttempt, IntruderAttemptId, IntruderCampaign, IntruderCampaignId, Job,
    MessageDirection, MessageId, ProjectId, ProjectSummary, ProxySession, ProxySessionId,
    Sensitivity, StateChainRun, TargetScope, Timestamp, Validate,
};
use fs2::FileExt;
use nix::sys::stat::{Mode, umask};
use rusqlite::backup::Backup;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

pub const SCHEMA_VERSION: u32 = 6;
pub const MIN_SAFE_SQLITE_VERSION: i32 = 3_051_003;
pub const WRITER_QUEUE_CAPACITY: usize = 32;
pub const PREVIEW_READ_LIMIT: usize = 64 * 1024;
pub const MAX_ARCHIVE_FILES: usize = 4096;
pub const MAX_ARCHIVE_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_ARCHIVE_FILE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_ARCHIVE_COMPRESSION_RATIO: u64 = 100;
pub const MAX_ARCHIVE_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_DICTIONARY_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_DICTIONARY_TERMS: usize = 100_000;
pub const MAX_DICTIONARY_TERM_BYTES: usize = 512;

const MIGRATION_V1: &str = r"
CREATE TABLE schema_migrations(
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    application_version TEXT NOT NULL
) STRICT;
CREATE TABLE projects(
    project_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;
CREATE TABLE target_scopes(
    scope_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;
CREATE TABLE http_messages(
    message_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    parent_message_id TEXT,
    body_artifact_id TEXT,
    wire_artifact_id TEXT,
    direction TEXT NOT NULL,
    body_state TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    observed_at TEXT NOT NULL
) STRICT;
CREATE TABLE command_specs(
    command_spec_id TEXT PRIMARY KEY,
    tool_id TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    tool_sha256 TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    payload_json TEXT NOT NULL
) STRICT;
CREATE TABLE jobs(
    job_id TEXT PRIMARY KEY,
    parent_job_id TEXT,
    command_spec_id TEXT NOT NULL REFERENCES command_specs(command_spec_id),
    execution_status TEXT NOT NULL,
    import_status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    stopped_at TEXT,
    payload_json TEXT NOT NULL
) STRICT;
CREATE INDEX jobs_execution_status_idx ON jobs(execution_status);
CREATE TABLE discoveries(
    discovery_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    kind TEXT NOT NULL,
    raw_value TEXT NOT NULL,
    canonical_value TEXT NOT NULL,
    canonical_key TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    UNIQUE(project_id, canonical_key)
) STRICT;
CREATE TABLE discovery_observations(
    observation_id TEXT PRIMARY KEY,
    discovery_id TEXT NOT NULL REFERENCES discoveries(discovery_id),
    source_job_id TEXT,
    observed_at TEXT NOT NULL,
    raw_value TEXT NOT NULL
) STRICT;
CREATE TABLE artifacts(
    artifact_id TEXT PRIMARY KEY,
    relative_path TEXT NOT NULL,
    logical_name TEXT NOT NULL,
    staging_relative_path TEXT,
    blob_relative_path TEXT,
    sha256 TEXT,
    size INTEGER,
    mime TEXT NOT NULL,
    source_job_id TEXT,
    source_message_id TEXT,
    sensitivity TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    integrity TEXT NOT NULL,
    export_policy TEXT NOT NULL,
    payload_json TEXT NOT NULL
) STRICT;
CREATE INDEX artifacts_state_idx ON artifacts(state);
CREATE INDEX artifacts_sha256_idx ON artifacts(sha256);
CREATE TABLE adapter_entities(
    adapter_entity_id TEXT PRIMARY KEY,
    project_id TEXT,
    adapter_id TEXT NOT NULL,
    entity_kind TEXT NOT NULL,
    external_id TEXT NOT NULL,
    ownership TEXT NOT NULL,
    state_schema_version INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    synced_at TEXT NOT NULL,
    terminated_at TEXT,
    UNIQUE(project_id, adapter_id, entity_kind, external_id)
) STRICT;
CREATE VIRTUAL TABLE search_fts USING fts5(
    entity_type UNINDEXED,
    entity_id UNINDEXED,
    content,
    tokenize='unicode61 remove_diacritics 2'
);
";

const MIGRATION_V2: &str = r"
CREATE TABLE job_imports(
    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id) ON DELETE CASCADE,
    parser_id TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    import_status TEXT NOT NULL,
    discovery_count INTEGER NOT NULL,
    http_message_count INTEGER NOT NULL,
    source_artifact_ids_json TEXT NOT NULL,
    error_summary TEXT,
    completed_at TEXT,
    payload_json TEXT NOT NULL
) STRICT;
CREATE INDEX jobs_created_idx ON jobs(created_at DESC,job_id DESC);
CREATE INDEX discoveries_last_seen_idx ON discoveries(last_seen_at DESC,discovery_id DESC);
CREATE INDEX discovery_observations_source_idx ON discovery_observations(source_job_id,observed_at DESC);
CREATE UNIQUE INDEX discovery_observations_dedup_idx ON discovery_observations(discovery_id,source_job_id,raw_value);
";

const MIGRATION_V3: &str = r"
CREATE TABLE dictionaries(
    dictionary_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
    name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    term_count INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    UNIQUE(project_id,name)
) STRICT;
CREATE TABLE dictionary_terms(
    dictionary_id TEXT NOT NULL REFERENCES dictionaries(dictionary_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    term TEXT NOT NULL,
    normalized_term TEXT NOT NULL,
    PRIMARY KEY(dictionary_id,ordinal)
) STRICT;
CREATE INDEX dictionaries_created_idx ON dictionaries(created_at DESC,dictionary_id DESC);
CREATE INDEX dictionary_terms_prefix_idx ON dictionary_terms(dictionary_id,normalized_term,ordinal);
";

const MIGRATION_V4: &str = r"
ALTER TABLE http_messages ADD COLUMN exchange_id TEXT;
ALTER TABLE http_messages ADD COLUMN source TEXT;
ALTER TABLE http_messages ADD COLUMN representation_kind TEXT;
ALTER TABLE http_messages ADD COLUMN method TEXT;
ALTER TABLE http_messages ADD COLUMN status_code INTEGER;
ALTER TABLE http_messages ADD COLUMN scheme TEXT;
ALTER TABLE http_messages ADD COLUMN host TEXT;
ALTER TABLE http_messages ADD COLUMN port INTEGER;
ALTER TABLE http_messages ADD COLUMN path TEXT;
ALTER TABLE http_messages ADD COLUMN actual_length INTEGER;
ALTER TABLE http_messages ADD COLUMN duration_millis INTEGER;
ALTER TABLE http_messages ADD COLUMN sensitivity TEXT;
UPDATE http_messages SET
    exchange_id=json_extract(payload_json,'$.exchange_id'),
    source=json_extract(payload_json,'$.source'),
    representation_kind=json_extract(payload_json,'$.representation_kind'),
    method=json_extract(payload_json,'$.method'),
    status_code=json_extract(payload_json,'$.status_code'),
    scheme=json_extract(payload_json,'$.scheme'),
    host=json_extract(payload_json,'$.host'),
    port=json_extract(payload_json,'$.port'),
    path=json_extract(payload_json,'$.path'),
    actual_length=json_extract(payload_json,'$.actual_length'),
    duration_millis=json_extract(payload_json,'$.duration_millis'),
    sensitivity=json_extract(payload_json,'$.sensitivity');
CREATE INDEX http_messages_observed_idx ON http_messages(observed_at DESC,message_id DESC);
CREATE INDEX http_messages_exchange_idx ON http_messages(project_id,exchange_id,direction);
CREATE INDEX http_messages_history_idx ON http_messages(project_id,source,direction,host,status_code,observed_at DESC);
DELETE FROM search_fts WHERE entity_type='http_message';
INSERT INTO search_fts(entity_type,entity_id,content)
SELECT 'http_message',message_id,json_extract(payload_json,'$.redacted_view')
FROM http_messages;
CREATE TABLE proxy_sessions(
    proxy_session_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    scope_id TEXT NOT NULL REFERENCES target_scopes(scope_id),
    state TEXT NOT NULL,
    listen_port INTEGER,
    created_at TEXT NOT NULL,
    ready_at TEXT,
    stopped_at TEXT,
    payload_json TEXT NOT NULL
) STRICT;
CREATE INDEX proxy_sessions_project_state_idx ON proxy_sessions(project_id,state,created_at DESC);
";

const MIGRATION_V5: &str = r"
CREATE INDEX adapter_entities_project_kind_idx
ON adapter_entities(project_id,adapter_id,entity_kind,synced_at DESC,adapter_entity_id DESC);
CREATE TABLE audit_events(
    audit_event_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    adapter_id TEXT,
    action TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    outcome TEXT NOT NULL,
    target_summary TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
) STRICT;
CREATE INDEX audit_events_project_created_idx
ON audit_events(project_id,created_at DESC,audit_event_id DESC);
";

const MIGRATION_V6: &str = r"
CREATE TABLE intruder_campaigns(
    intruder_campaign_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    scope_id TEXT NOT NULL REFERENCES target_scopes(scope_id),
    parent_message_id TEXT NOT NULL REFERENCES http_messages(message_id),
    campaign_kind TEXT NOT NULL,
    attack_mode TEXT NOT NULL,
    state TEXT NOT NULL,
    total_attempts INTEGER NOT NULL,
    next_ordinal INTEGER NOT NULL,
    completed_attempts INTEGER NOT NULL,
    failed_attempts INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    stopped_at TEXT,
    payload_json TEXT NOT NULL
) STRICT;
CREATE INDEX intruder_campaigns_project_state_idx
ON intruder_campaigns(project_id,state,created_at DESC,intruder_campaign_id DESC);
CREATE TABLE intruder_attempts(
    intruder_attempt_id TEXT PRIMARY KEY,
    intruder_campaign_id TEXT NOT NULL REFERENCES intruder_campaigns(intruder_campaign_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    ordinal INTEGER NOT NULL,
    state TEXT NOT NULL,
    response_status INTEGER,
    response_length INTEGER,
    duration_millis INTEGER,
    created_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    UNIQUE(intruder_campaign_id,ordinal)
) STRICT;
CREATE INDEX intruder_attempts_campaign_ordinal_idx
ON intruder_attempts(intruder_campaign_id,ordinal);
CREATE TABLE state_chain_runs(
    state_chain_run_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    intruder_attempt_id TEXT NOT NULL REFERENCES intruder_attempts(intruder_attempt_id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
) STRICT;
CREATE INDEX state_chain_runs_attempt_idx ON state_chain_runs(intruder_attempt_id);
";

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("workspace is already held by a writer")]
    WriterLocked,
    #[error("operation requires a writable project")]
    ReadOnly,
    #[error("workspace layout or permission contract failed: {0}")]
    InvalidLayout(String),
    #[error("domain contract rejected: {0}")]
    Domain(String),
    #[error("artifact size differs from the declared size")]
    SizeMismatch,
    #[error("artifact SHA-256 differs from the expected hash")]
    HashMismatch,
    #[error("artifact does not exist or is not committed")]
    ArtifactNotFound,
    #[error("artifact preview request exceeds 64 KiB")]
    PreviewTooLarge,
    #[error("injected commit interruption after {0}")]
    InjectedFault(&'static str),
    #[error("single writer queue stopped")]
    WriterStopped,
    #[error("single writer response type mismatch")]
    WriterType,
    #[error("sensitive evidence requires explicit export confirmation")]
    SensitiveExportConfirmationRequired,
    #[error("project archive violates the import contract: {0}")]
    InvalidArchive(String),
    #[error("project archive exceeds a bounded import limit")]
    ArchiveLimit,
    #[error("the imported project already exists")]
    ProjectExists,
    #[error("I/O failure")]
    Io(#[from] std::io::Error),
    #[error("SQLite failure")]
    Sqlite(#[from] rusqlite::Error),
    #[error("JSON failure")]
    Json(#[from] serde_json::Error),
    #[error("TOML serialization failure")]
    TomlSerialize(#[from] toml::ser::Error),
    #[error("TOML parsing failure")]
    TomlParse(#[from] toml::de::Error),
    #[error("ZIP archive failure")]
    Zip(#[from] zip::result::ZipError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveLimits {
    pub maximum_files: usize,
    pub maximum_total_bytes: u64,
    pub maximum_file_bytes: u64,
    pub maximum_compression_ratio: u64,
    pub maximum_manifest_bytes: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            maximum_files: MAX_ARCHIVE_FILES,
            maximum_total_bytes: MAX_ARCHIVE_TOTAL_BYTES,
            maximum_file_bytes: MAX_ARCHIVE_FILE_BYTES,
            maximum_compression_ratio: MAX_ARCHIVE_COMPRESSION_RATIO,
            maximum_manifest_bytes: MAX_ARCHIVE_MANIFEST_BYTES,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectArchiveEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub sensitivity: Sensitivity,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectArchiveExclusion {
    pub artifact_id: String,
    pub logical_name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectArchiveManifest {
    pub format: String,
    pub format_version: u32,
    pub contract_version: u32,
    pub schema_version: u32,
    pub project_id: ProjectId,
    pub project_name: String,
    pub created_at: Timestamp,
    pub sensitive_evidence_confirmed: bool,
    pub entries: Vec<ProjectArchiveEntry>,
    pub exclusions: Vec<ProjectArchiveExclusion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectExportEvidence {
    pub archive_name: String,
    pub sha256: String,
    pub size: u64,
    pub file_count: usize,
    pub included_artifacts: usize,
    pub excluded_artifacts: usize,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectImportEvidence {
    pub project: ProjectSummary,
    pub archive_sha256: String,
    pub archive_size: u64,
    pub file_count: usize,
    pub extracted_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    ReadWrite,
    ReadOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockMetadata {
    pub instance_id: String,
    pub pid: u32,
    pub process_start_ticks: u64,
    pub hostname: String,
    pub acquired_at: Timestamp,
}

#[derive(Debug, Clone)]
pub struct WorkspaceLayout {
    pub root: PathBuf,
    pub database: PathBuf,
    pub lock: PathBuf,
    pub blobs: PathBuf,
    pub artifacts: PathBuf,
    pub scans: PathBuf,
    pub notes: PathBuf,
    pub exports: PathBuf,
    pub backups: PathBuf,
    pub runtime: PathBuf,
    pub tmp: PathBuf,
    pub browser_home: PathBuf,
    pub browser_profile: PathBuf,
    pub mitm_confdir: PathBuf,
    pub metasploit: PathBuf,
}

impl WorkspaceLayout {
    #[must_use]
    pub fn for_project(workspaces_root: &Path, project_id: &ProjectId) -> Self {
        Self::for_root(workspaces_root.join(&project_id.0))
    }

    #[must_use]
    fn for_root(root: PathBuf) -> Self {
        Self {
            database: root.join("project.sqlite"),
            lock: root.join(".flagdeck.lock"),
            blobs: root.join("blobs/sha256"),
            artifacts: root.join("artifacts"),
            scans: root.join("scans"),
            notes: root.join("notes"),
            exports: root.join("exports"),
            backups: root.join("backups"),
            runtime: root.join("runtime"),
            tmp: root.join("tmp"),
            browser_home: root.join("browser-home"),
            browser_profile: root.join("browser-profile"),
            mitm_confdir: root.join("mitm-confdir"),
            metasploit: root.join("metasploit"),
            root,
        }
    }

    fn create(&self) -> Result<(), StorageError> {
        create_private_dir(&self.root)?;
        for directory in [
            &self.blobs,
            &self.artifacts,
            &self.scans,
            &self.notes,
            &self.exports,
            &self.backups,
            &self.runtime,
            &self.tmp,
            &self.browser_home,
            &self.browser_profile,
            &self.mitm_confdir,
            &self.metasploit,
        ] {
            create_private_dir(directory)?;
        }
        sync_directory(&self.root)?;
        Ok(())
    }

    pub fn verify(&self) -> Result<(), StorageError> {
        for directory in [
            &self.root,
            &self.blobs,
            &self.artifacts,
            &self.scans,
            &self.notes,
            &self.exports,
            &self.backups,
            &self.runtime,
            &self.tmp,
            &self.browser_home,
            &self.browser_profile,
            &self.mitm_confdir,
            &self.metasploit,
        ] {
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(StorageError::InvalidLayout(directory.display().to_string()));
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(StorageError::InvalidLayout(format!(
                    "{} mode {:o}",
                    directory.display(),
                    metadata.permissions().mode() & 0o777
                )));
            }
        }
        if self.database.exists() && fs::metadata(&self.database)?.permissions().mode() & 0o077 != 0
        {
            return Err(StorageError::InvalidLayout(
                self.database.display().to_string(),
            ));
        }
        Ok(())
    }
}

struct WorkspaceLock {
    file: File,
}

impl WorkspaceLock {
    fn acquire(path: &Path) -> Result<Self, StorageError> {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                StorageError::WriterLocked
            } else {
                StorageError::Io(error)
            }
        })?;
        let metadata = LockMetadata {
            instance_id: Uuid::new_v4().to_string(),
            pid: std::process::id(),
            process_start_ticks: current_process_start_ticks().unwrap_or(0),
            hostname: fs::read_to_string("/etc/hostname")
                .unwrap_or_else(|_| "unknown".to_owned())
                .trim()
                .to_owned(),
            acquired_at: Timestamp::now(),
        };
        file.set_len(0)?;
        file.write_all(&serde_json::to_vec_pretty(&metadata)?)?;
        file.sync_all()?;
        Ok(Self { file })
    }
}

impl Drop for WorkspaceLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

type WriteResult = Result<Box<dyn Any + Send>, StorageError>;
type WriteOperation = Box<dyn FnOnce(&mut Connection) -> WriteResult + Send>;

enum WriterCommand {
    Execute(WriteOperation, SyncSender<WriteResult>),
    Shutdown,
}

struct WriterRuntime {
    sender: SyncSender<WriterCommand>,
    join: Option<JoinHandle<()>>,
}

impl WriterRuntime {
    fn start(database: PathBuf) -> Result<Self, StorageError> {
        let (sender, receiver) = sync_channel(WRITER_QUEUE_CAPACITY);
        let (ready_sender, ready_receiver) = sync_channel(1);
        let join = thread::spawn(move || writer_loop(&database, &receiver, &ready_sender));
        ready_receiver
            .recv()
            .map_err(|_| StorageError::WriterStopped)??;
        Ok(Self {
            sender,
            join: Some(join),
        })
    }

    fn call<T, F>(&self, operation: F) -> Result<T, StorageError>
    where
        T: Any + Send,
        F: FnOnce(&mut Connection) -> Result<T, StorageError> + Send + 'static,
    {
        let (response_sender, response_receiver) = sync_channel(1);
        let erased: WriteOperation = Box::new(move |connection| {
            operation(connection).map(|value| Box::new(value) as Box<dyn Any + Send>)
        });
        self.sender
            .send(WriterCommand::Execute(erased, response_sender))
            .map_err(|_| StorageError::WriterStopped)?;
        let value = response_receiver
            .recv()
            .map_err(|_| StorageError::WriterStopped)??;
        value
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| StorageError::WriterType)
    }
}

impl Drop for WriterRuntime {
    fn drop(&mut self) {
        let _ = self.sender.send(WriterCommand::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn writer_loop(
    database: &Path,
    receiver: &Receiver<WriterCommand>,
    ready: &SyncSender<Result<(), StorageError>>,
) {
    let mut connection = match open_writer_connection(database) {
        Ok(connection) => {
            let _ = ready.send(Ok(()));
            connection
        }
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    while let Ok(command) = receiver.recv() {
        match command {
            WriterCommand::Execute(operation, response) => {
                let _ = response.send(operation(&mut connection));
            }
            WriterCommand::Shutdown => break,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobImportRecord {
    pub job_id: flagdeck_domain::JobId,
    pub parser_id: String,
    pub parser_version: String,
    pub import_status: flagdeck_domain::ImportStatus,
    pub discovery_count: usize,
    pub http_message_count: usize,
    pub source_artifact_ids: Vec<ArtifactId>,
    pub error_summary: Option<String>,
    pub completed_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredJob {
    pub job: Job,
    pub command_spec: CommandSpec,
    pub import: Option<JobImportRecord>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpMessageFilter {
    pub query: Option<String>,
    pub source: Option<HttpSource>,
    pub direction: Option<MessageDirection>,
    pub host: Option<String>,
    pub status_code: Option<u16>,
}

pub struct ProjectStore {
    project_id: ProjectId,
    mode: OpenMode,
    layout: WorkspaceLayout,
    _lock: Option<WorkspaceLock>,
    writer: Option<WriterRuntime>,
    recovery: RecoveryReport,
}

impl ProjectStore {
    pub fn create(
        workspaces_root: &Path,
        name: &str,
    ) -> Result<(Self, ProjectSummary), StorageError> {
        set_private_process_defaults();
        validate_project_name(name)?;
        create_private_dir(workspaces_root)?;
        let project_id = ProjectId::new();
        let layout = WorkspaceLayout::for_project(workspaces_root, &project_id);
        layout.create()?;
        let lock = WorkspaceLock::acquire(&layout.lock)?;
        let mut connection = open_writer_connection(&layout.database)?;
        run_migrations(&mut connection, &layout, false)?;
        let now = Timestamp::now();
        connection.execute(
            "INSERT INTO projects(project_id,name,created_at,updated_at) VALUES(?1,?2,?3,?3)",
            params![project_id.0, name, now.0],
        )?;
        drop(connection);
        let writer = WriterRuntime::start(layout.database.clone())?;
        let summary = ProjectSummary {
            project_id: project_id.clone(),
            name: name.to_owned(),
            created_at: now.clone(),
            updated_at: now,
            read_only: false,
            schema_version: SCHEMA_VERSION,
        };
        Ok((
            Self {
                project_id,
                mode: OpenMode::ReadWrite,
                layout,
                _lock: Some(lock),
                writer: Some(writer),
                recovery: RecoveryReport::default(),
            },
            summary,
        ))
    }

    pub fn open(
        workspaces_root: &Path,
        project_id: &ProjectId,
        mode: OpenMode,
    ) -> Result<Self, StorageError> {
        set_private_process_defaults();
        project_id
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        let root = fs::canonicalize(workspaces_root)?;
        let layout = WorkspaceLayout::for_project(&root, project_id);
        let canonical_project = fs::canonicalize(&layout.root)?;
        if canonical_project.parent() != Some(root.as_path()) {
            return Err(StorageError::InvalidLayout(
                canonical_project.display().to_string(),
            ));
        }
        layout.verify()?;
        match mode {
            OpenMode::ReadWrite => {
                let lock = WorkspaceLock::acquire(&layout.lock)?;
                let existed = layout.database.exists();
                let mut connection = open_writer_connection(&layout.database)?;
                run_migrations(&mut connection, &layout, existed)?;
                let recovery = recover_database_and_files(&mut connection, &layout)?;
                drop(connection);
                let writer = WriterRuntime::start(layout.database.clone())?;
                Ok(Self {
                    project_id: project_id.clone(),
                    mode,
                    layout,
                    _lock: Some(lock),
                    writer: Some(writer),
                    recovery,
                })
            }
            OpenMode::ReadOnly => {
                let connection = open_reader_connection(&layout.database)?;
                assert_schema_current(&connection)?;
                drop(connection);
                Ok(Self {
                    project_id: project_id.clone(),
                    mode,
                    layout,
                    _lock: None,
                    writer: None,
                    recovery: RecoveryReport::default(),
                })
            }
        }
    }

    #[must_use]
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    #[must_use]
    pub fn mode(&self) -> OpenMode {
        self.mode
    }

    #[must_use]
    pub fn layout(&self) -> &WorkspaceLayout {
        &self.layout
    }

    #[must_use]
    pub fn recovery_report(&self) -> &RecoveryReport {
        &self.recovery
    }

    pub fn summary(&self) -> Result<ProjectSummary, StorageError> {
        let connection = open_reader_connection(&self.layout.database)?;
        connection
            .query_row(
                "SELECT project_id,name,created_at,updated_at FROM projects WHERE project_id=?1",
                [&self.project_id.0],
                |row| {
                    Ok(ProjectSummary {
                        project_id: ProjectId(row.get(0)?),
                        name: row.get(1)?,
                        created_at: Timestamp(row.get(2)?),
                        updated_at: Timestamp(row.get(3)?),
                        read_only: self.mode == OpenMode::ReadOnly,
                        schema_version: SCHEMA_VERSION,
                    })
                },
            )
            .map_err(Into::into)
    }

    pub fn health(&self) -> Result<StorageHealth, StorageError> {
        let connection = open_reader_connection(&self.layout.database)?;
        let quick_check: String =
            connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        let sqlite_version = rusqlite::version().to_owned();
        let sqlite_version_number = rusqlite::version_number();
        let fts_count: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='search_fts'",
            [],
            |row| row.get(0),
        )?;
        let query_only: i64 = connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
        Ok(StorageHealth {
            sqlite_version,
            sqlite_version_number,
            minimum_safe_version: MIN_SAFE_SQLITE_VERSION,
            quick_check,
            fts5_available: fts_count == 1,
            schema_version: connection.query_row("PRAGMA user_version", [], |row| row.get(0))?,
            read_only: self.mode == OpenMode::ReadOnly,
            query_only: query_only == 1,
            writer_queue_capacity: WRITER_QUEUE_CAPACITY,
        })
    }

    pub fn commit_artifact<R: Read>(
        &self,
        request: &ArtifactWriteRequest,
        reader: R,
    ) -> Result<Artifact, StorageError> {
        self.commit_artifact_with_fault(request, reader, CommitFault::None)
    }

    pub fn commit_artifact_with_fault<R: Read>(
        &self,
        request: &ArtifactWriteRequest,
        mut reader: R,
        fault: CommitFault,
    ) -> Result<Artifact, StorageError> {
        validate_artifact_request(request)?;
        let writer = self.writable_writer()?;
        let artifact_id = ArtifactId::new();
        let staging_relative = format!("tmp/{}.staging", artifact_id.0);
        let relative_path = format!("artifacts/{}.json", artifact_id.0);
        let staging_path = self.layout.root.join(&staging_relative);
        ensure_descendant(&self.layout.root, &staging_path)?;
        let created_at = Timestamp::now();
        let initial = Artifact {
            artifact_id: artifact_id.clone(),
            relative_path: relative_path.clone(),
            logical_name: request.logical_name.clone(),
            blob_relative_path: None,
            sha256: None,
            size: None,
            mime: request.mime.clone(),
            source_job_id: request.source_job_id.clone(),
            source_message_id: request.source_message_id.clone(),
            sensitivity: request.sensitivity,
            state: ArtifactState::Staging,
            created_at: created_at.clone(),
            integrity: IntegrityState::Pending,
            export_policy: request.export_policy,
        };
        let initial_json = serde_json::to_string(&initial)?;
        let insert = initial.clone();
        let staging_for_insert = staging_relative.clone();
        writer.call(move |connection| {
            insert_artifact_row(
                connection,
                &insert,
                Some(&staging_for_insert),
                &initial_json,
            )?;
            Ok(())
        })?;

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&staging_path)?;
        let mut hasher = Sha256::new();
        let mut size = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let length = reader.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            file.write_all(&buffer[..length])?;
            hasher.update(&buffer[..length]);
            size = size
                .checked_add(u64::try_from(length).map_err(|_| StorageError::SizeMismatch)?)
                .ok_or(StorageError::SizeMismatch)?;
        }
        file.sync_all()?;
        drop(file);
        let sha256 = format!("{:x}", hasher.finalize());
        if request
            .expected_size
            .is_some_and(|expected| expected != size)
        {
            return Err(StorageError::SizeMismatch);
        }
        if request
            .expected_sha256
            .as_ref()
            .is_some_and(|expected| expected != &sha256)
        {
            return Err(StorageError::HashMismatch);
        }
        let blob_relative = format!("blobs/sha256/{}/{}", &sha256[..2], sha256);
        let blob_path = self.layout.root.join(&blob_relative);
        ensure_descendant(&self.layout.root, &blob_path)?;
        let metadata_artifact = Artifact {
            blob_relative_path: Some(blob_relative.clone()),
            sha256: Some(sha256.clone()),
            size: Some(size),
            ..initial.clone()
        };
        let metadata_json = serde_json::to_string(&metadata_artifact)?;
        let artifact_for_staging = artifact_id.clone();
        let blob_for_staging = blob_relative.clone();
        let sha_for_staging = sha256.clone();
        let size_for_staging = i64::try_from(size).map_err(|_| StorageError::SizeMismatch)?;
        writer.call(move |connection| {
            connection.execute(
                "UPDATE artifacts SET blob_relative_path=?2,sha256=?3,size=?4,payload_json=?5 WHERE artifact_id=?1 AND state='staging'",
                params![artifact_for_staging.0, blob_for_staging, sha_for_staging, size_for_staging, metadata_json],
            )?;
            Ok(())
        })?;
        if fault == CommitFault::AfterFileSync {
            return Err(StorageError::InjectedFault("file fsync"));
        }

        let blob_parent = blob_path
            .parent()
            .ok_or_else(|| StorageError::InvalidLayout("blob path lacks parent".to_owned()))?;
        create_private_dir(blob_parent)?;
        if blob_path.exists() {
            if sha256_file(&blob_path)? != sha256 || fs::metadata(&blob_path)?.len() != size {
                return Err(StorageError::HashMismatch);
            }
            fs::remove_file(&staging_path)?;
        } else {
            fs::rename(&staging_path, &blob_path)?;
            fs::set_permissions(&blob_path, fs::Permissions::from_mode(0o600))?;
        }
        sync_directory(blob_parent)?;
        if fault == CommitFault::AfterRename {
            return Err(StorageError::InjectedFault("blob rename"));
        }

        let committed = Artifact {
            state: ArtifactState::Committed,
            integrity: IntegrityState::Verified,
            ..metadata_artifact
        };
        write_artifact_manifest(&self.layout, &committed)?;
        let committed_json = serde_json::to_string(&committed)?;
        let committed_for_db = committed.clone();
        writer.call(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute(
                "UPDATE artifacts SET staging_relative_path=NULL,state='committed',integrity='verified',payload_json=?2 WHERE artifact_id=?1 AND state='staging'",
                params![committed_for_db.artifact_id.0, committed_json],
            )?;
            transaction.commit()?;
            Ok(())
        })?;
        Ok(committed)
    }

    pub fn artifact(&self, artifact_id: &ArtifactId) -> Result<Artifact, StorageError> {
        artifact_id
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        let connection = open_reader_connection(&self.layout.database)?;
        let payload: Option<String> = connection
            .query_row(
                "SELECT payload_json FROM artifacts WHERE artifact_id=?1",
                [&artifact_id.0],
                |row| row.get(0),
            )
            .optional()?;
        let payload = payload.ok_or(StorageError::ArtifactNotFound)?;
        Ok(serde_json::from_str(&payload)?)
    }

    pub fn read_artifact_range(
        &self,
        artifact_id: &ArtifactId,
        offset: u64,
        limit: usize,
    ) -> Result<Vec<u8>, StorageError> {
        if limit > PREVIEW_READ_LIMIT {
            return Err(StorageError::PreviewTooLarge);
        }
        let artifact = self.artifact(artifact_id)?;
        if artifact.state != ArtifactState::Committed {
            return Err(StorageError::ArtifactNotFound);
        }
        let relative = artifact
            .blob_relative_path
            .ok_or(StorageError::ArtifactNotFound)?;
        let path = self.layout.root.join(relative);
        ensure_descendant(&self.layout.root, &path)?;
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut output = vec![0_u8; limit];
        let length = file.read(&mut output)?;
        output.truncate(length);
        Ok(output)
    }

    pub fn read_artifact_bounded(
        &self,
        artifact_id: &ArtifactId,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, StorageError> {
        if maximum_bytes == 0 || maximum_bytes > 64 * 1024 * 1024 {
            return Err(StorageError::PreviewTooLarge);
        }
        let artifact = self.artifact(artifact_id)?;
        if artifact.state != ArtifactState::Committed {
            return Err(StorageError::ArtifactNotFound);
        }
        let size = artifact.size.ok_or(StorageError::ArtifactNotFound)?;
        if size > maximum_bytes {
            return Err(StorageError::PreviewTooLarge);
        }
        let relative = artifact
            .blob_relative_path
            .ok_or(StorageError::ArtifactNotFound)?;
        let path = self.layout.root.join(relative);
        ensure_descendant(&self.layout.root, &path)?;
        let bytes = fs::read(path)?;
        if u64::try_from(bytes.len()).ok() != Some(size) {
            return Err(StorageError::SizeMismatch);
        }
        Ok(bytes)
    }

    pub fn list_artifacts(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<(Vec<Artifact>, Option<String>), StorageError> {
        if limit == 0 || limit > 100 {
            return Err(StorageError::Domain(
                "artifact page limit must be 1..=100".to_owned(),
            ));
        }
        let (cursor_time, cursor_id) = cursor
            .map(parse_artifact_cursor)
            .transpose()?
            .unwrap_or_else(|| ("~".to_owned(), "~".to_owned()));
        let connection = open_reader_connection(&self.layout.database)?;
        let mut statement = connection.prepare(
            "SELECT payload_json,created_at,artifact_id FROM artifacts
             WHERE state IN ('committed','corrupt')
               AND (created_at < ?1 OR (created_at = ?1 AND artifact_id < ?2))
             ORDER BY created_at DESC,artifact_id DESC LIMIT ?3",
        )?;
        let sql_limit = i64::try_from(limit + 1)
            .map_err(|_| StorageError::Domain("page limit overflow".to_owned()))?;
        let mut rows = statement
            .query_map(params![cursor_time, cursor_id, sql_limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let next_cursor = if has_more {
            rows.last()
                .map(|(_, created_at, artifact_id)| format!("{created_at}:{artifact_id}"))
        } else {
            None
        };
        let artifacts = rows
            .into_iter()
            .map(|(payload, _, _)| serde_json::from_str(&payload).map_err(Into::into))
            .collect::<Result<Vec<_>, StorageError>>()?;
        Ok((artifacts, next_cursor))
    }

    pub fn index_dictionary(
        &self,
        index: &DictionaryIndex,
        terms: &[String],
    ) -> Result<(), StorageError> {
        index
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        if index.project_id != self.project_id
            || terms.is_empty()
            || terms.len() > MAX_DICTIONARY_TERMS
            || index.term_count
                != u64::try_from(terms.len()).map_err(|_| StorageError::ArchiveLimit)?
            || index.size > MAX_DICTIONARY_BYTES
            || terms.iter().any(|term| {
                term.is_empty()
                    || term.len() > MAX_DICTIONARY_TERM_BYTES
                    || term.contains(['\0', '\n', '\r'])
                    || term.trim() != term
            })
        {
            return Err(StorageError::Domain(
                "dictionary index contract failed".to_owned(),
            ));
        }
        let artifact = self.artifact(&index.artifact_id)?;
        if artifact.state != ArtifactState::Committed
            || artifact.sha256.as_deref() != Some(&index.sha256)
            || artifact.size != Some(index.size)
        {
            return Err(StorageError::HashMismatch);
        }
        let value = index.clone();
        let terms = terms.to_vec();
        self.writable_writer()?.call(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let payload = serde_json::to_string(&value)?;
            transaction.execute(
                "INSERT INTO dictionaries(dictionary_id,project_id,artifact_id,name,sha256,size,term_count,created_at,payload_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    value.dictionary_id.0,
                    value.project_id.0,
                    value.artifact_id.0,
                    value.name,
                    value.sha256,
                    i64::try_from(value.size).map_err(|_| StorageError::ArchiveLimit)?,
                    i64::try_from(value.term_count).map_err(|_| StorageError::ArchiveLimit)?,
                    value.created_at.0,
                    payload,
                ],
            )?;
            let mut statement = transaction.prepare(
                "INSERT INTO dictionary_terms(dictionary_id,ordinal,term,normalized_term) VALUES(?1,?2,?3,?4)",
            )?;
            for (ordinal, term) in terms.iter().enumerate() {
                statement.execute(params![
                    value.dictionary_id.0,
                    i64::try_from(ordinal).map_err(|_| StorageError::ArchiveLimit)?,
                    term,
                    term.to_lowercase(),
                ])?;
            }
            drop(statement);
            transaction.commit()?;
            Ok(())
        })
    }

    pub fn list_dictionaries(&self) -> Result<Vec<DictionaryIndex>, StorageError> {
        let connection = open_reader_connection(&self.layout.database)?;
        let mut statement = connection.prepare(
            "SELECT payload_json FROM dictionaries WHERE project_id=?1 ORDER BY created_at DESC,dictionary_id DESC LIMIT 100",
        )?;
        statement
            .query_map([&self.project_id.0], |row| row.get::<_, String>(0))?
            .map(|value| {
                value
                    .map_err(StorageError::from)
                    .and_then(|payload| serde_json::from_str(&payload).map_err(Into::into))
            })
            .collect()
    }

    pub fn search_dictionary(
        &self,
        dictionary_id: &DictionaryId,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<String>, StorageError> {
        dictionary_id
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        if prefix.is_empty()
            || prefix.len() > MAX_DICTIONARY_TERM_BYTES
            || prefix.contains(['\0', '\n', '\r'])
            || limit == 0
            || limit > 100
        {
            return Err(StorageError::Domain(
                "dictionary search contract failed".to_owned(),
            ));
        }
        let lower = prefix.to_lowercase();
        let upper = format!("{lower}\u{10ffff}");
        let sql_limit = i64::try_from(limit).map_err(|_| StorageError::ArchiveLimit)?;
        let connection = open_reader_connection(&self.layout.database)?;
        let mut statement = connection.prepare(
            "SELECT term FROM dictionary_terms
             WHERE dictionary_id=?1 AND normalized_term>=?2 AND normalized_term<?3
             ORDER BY normalized_term,ordinal LIMIT ?4",
        )?;
        statement
            .query_map(params![dictionary_id.0, lower, upper, sql_limit], |row| {
                row.get::<_, String>(0)
            })?
            .map(|value| value.map_err(Into::into))
            .collect()
    }

    pub fn save_target_scope(&self, scope: &TargetScope) -> Result<(), StorageError> {
        scope
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        let value = scope.clone();
        let payload = serde_json::to_string(&value)?;
        self.writable_writer()?.call(move |connection| {
            connection.execute(
                "INSERT INTO target_scopes(scope_id,project_id,payload_json,created_at,updated_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(scope_id) DO UPDATE SET payload_json=excluded.payload_json,updated_at=excluded.updated_at",
                params![value.scope_id.0, value.project_id.0, payload, value.created_at.0, value.updated_at.0],
            )?;
            Ok(())
        })
    }

    pub fn target_scope(
        &self,
        scope_id: &flagdeck_domain::ScopeId,
    ) -> Result<TargetScope, StorageError> {
        scope_id
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        let connection = open_reader_connection(&self.layout.database)?;
        let payload = connection
            .query_row(
                "SELECT payload_json FROM target_scopes WHERE scope_id=?1 AND project_id=?2",
                params![scope_id.0, self.project_id.0],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::Domain("target scope does not exist".to_owned()))?;
        Ok(serde_json::from_str(&payload)?)
    }

    pub fn list_target_scopes(&self) -> Result<Vec<TargetScope>, StorageError> {
        let connection = open_reader_connection(&self.layout.database)?;
        let mut statement = connection.prepare(
            "SELECT payload_json FROM target_scopes WHERE project_id=?1 ORDER BY updated_at DESC,scope_id DESC LIMIT 100",
        )?;
        statement
            .query_map([&self.project_id.0], |row| row.get::<_, String>(0))?
            .map(|value| {
                value
                    .map_err(StorageError::from)
                    .and_then(|payload| serde_json::from_str(&payload).map_err(Into::into))
            })
            .collect()
    }

    pub fn save_http_message(&self, message: &HttpMessage) -> Result<(), StorageError> {
        message
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        let value = message.clone();
        self.writable_writer()?.call(move |connection| {
            upsert_http_message(connection, &value)?;
            Ok(())
        })
    }

    pub fn http_message(&self, message_id: &MessageId) -> Result<HttpMessage, StorageError> {
        message_id
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        let connection = open_reader_connection(&self.layout.database)?;
        let payload = connection
            .query_row(
                "SELECT payload_json FROM http_messages WHERE project_id=?1 AND message_id=?2",
                params![self.project_id.0, message_id.0],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::Domain("HTTP message does not exist".to_owned()))?;
        Ok(serde_json::from_str(&payload)?)
    }

    pub fn list_http_messages(
        &self,
        limit: usize,
        cursor: Option<&str>,
        filter: &HttpMessageFilter,
    ) -> Result<(Vec<HttpMessage>, Option<String>), StorageError> {
        if limit == 0 || limit > 100 {
            return Err(StorageError::Domain(
                "HTTP history page limit must be 1..=100".to_owned(),
            ));
        }
        let (cursor_time, cursor_id) = cursor
            .map(parse_http_message_cursor)
            .transpose()?
            .unwrap_or_else(|| ("~".to_owned(), "~".to_owned()));
        let query = filter
            .query
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if query.is_some_and(|value| value.len() > 1024 || value.contains('\0')) {
            return Err(StorageError::Domain(
                "invalid HTTP history query".to_owned(),
            ));
        }
        let host = filter
            .host
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase);
        if host
            .as_deref()
            .is_some_and(|value| value.len() > 253 || value.contains(['\0', '/', '\\']))
        {
            return Err(StorageError::Domain("invalid HTTP history host".to_owned()));
        }
        let source = filter.source.map(|value| enum_json(&value)).transpose()?;
        let direction = filter
            .direction
            .map(|value| enum_json(&value))
            .transpose()?;
        let status_code = filter.status_code.map(i64::from);
        let fts_query = query.map(fts_literal_query);
        let sql_limit = i64::try_from(limit + 1)
            .map_err(|_| StorageError::Domain("page limit overflow".to_owned()))?;
        let connection = open_reader_connection(&self.layout.database)?;
        let mut statement = connection.prepare(
            "SELECT h.payload_json,h.observed_at,h.message_id
             FROM http_messages h
             WHERE h.project_id=?1
               AND (h.observed_at < ?2 OR (h.observed_at = ?2 AND h.message_id < ?3))
               AND (?4 IS NULL OR h.source=?4)
               AND (?5 IS NULL OR h.direction=?5)
               AND (?6 IS NULL OR h.host=?6)
               AND (?7 IS NULL OR h.status_code=?7)
               AND (?8 IS NULL OR EXISTS(
                   SELECT 1 FROM search_fts f
                   WHERE f.entity_type='http_message'
                     AND f.entity_id=h.message_id
                     AND f.content MATCH ?8
               ))
             ORDER BY h.observed_at DESC,h.message_id DESC LIMIT ?9",
        )?;
        let mut rows = statement
            .query_map(
                params![
                    self.project_id.0,
                    cursor_time,
                    cursor_id,
                    source,
                    direction,
                    host,
                    status_code,
                    fts_query,
                    sql_limit
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let next_cursor = has_more.then(|| {
            rows.last()
                .map(|(_, observed_at, message_id)| format!("{observed_at}:{message_id}"))
        });
        let items = rows
            .into_iter()
            .map(|(payload, _, _)| serde_json::from_str(&payload).map_err(Into::into))
            .collect::<Result<Vec<_>, StorageError>>()?;
        Ok((items, next_cursor.flatten()))
    }

    pub fn save_proxy_session(&self, session: &ProxySession) -> Result<(), StorageError> {
        session
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        if session.project_id != self.project_id {
            return Err(StorageError::Domain(
                "proxy session belongs to another project".to_owned(),
            ));
        }
        let value = session.clone();
        self.writable_writer()?.call(move |connection| {
            upsert_proxy_session(connection, &value)?;
            Ok(())
        })
    }

    pub fn proxy_session(&self, session_id: &ProxySessionId) -> Result<ProxySession, StorageError> {
        session_id
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        let connection = open_reader_connection(&self.layout.database)?;
        let payload = connection
            .query_row(
                "SELECT payload_json FROM proxy_sessions WHERE project_id=?1 AND proxy_session_id=?2",
                params![self.project_id.0, session_id.0],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::Domain("proxy session does not exist".to_owned()))?;
        Ok(serde_json::from_str(&payload)?)
    }

    pub fn list_proxy_sessions(&self) -> Result<Vec<ProxySession>, StorageError> {
        let connection = open_reader_connection(&self.layout.database)?;
        let mut statement = connection.prepare(
            "SELECT payload_json FROM proxy_sessions WHERE project_id=?1 ORDER BY created_at DESC,proxy_session_id DESC LIMIT 100",
        )?;
        statement
            .query_map([&self.project_id.0], |row| row.get::<_, String>(0))?
            .map(|value| {
                value
                    .map_err(StorageError::from)
                    .and_then(|payload| serde_json::from_str(&payload).map_err(Into::into))
            })
            .collect()
    }

    pub fn save_command_spec(&self, spec: &CommandSpec) -> Result<(), StorageError> {
        spec.validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        let value = spec.clone();
        let payload = serde_json::to_string(&value)?;
        self.writable_writer()?.call(move |connection| {
            connection.execute(
                "INSERT OR REPLACE INTO command_specs(command_spec_id,tool_id,tool_version,tool_sha256,risk_level,payload_json) VALUES(?1,?2,?3,?4,?5,?6)",
                params![value.command_spec_id.0, value.tool_id, value.tool_version, value.tool_sha256, enum_json(&value.risk_level)?, payload],
            )?;
            Ok(())
        })
    }

    pub fn save_job(&self, job: &Job) -> Result<(), StorageError> {
        let value = job.clone();
        self.writable_writer()?.call(move |connection| {
            upsert_job_row(connection, &value)?;
            Ok(())
        })
    }

    pub fn job(&self, job_id: &flagdeck_domain::JobId) -> Result<StoredJob, StorageError> {
        job_id
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        let connection = open_reader_connection(&self.layout.database)?;
        connection
            .query_row(
                "SELECT j.payload_json,c.payload_json,i.payload_json
                 FROM jobs j
                 JOIN command_specs c ON c.command_spec_id=j.command_spec_id
                 LEFT JOIN job_imports i ON i.job_id=j.job_id
                 WHERE j.job_id=?1",
                [&job_id.0],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(job, command_spec, import)| -> Result<StoredJob, StorageError> {
                    Ok(StoredJob {
                        job: serde_json::from_str(&job)?,
                        command_spec: serde_json::from_str(&command_spec)?,
                        import: import
                            .map(|payload| serde_json::from_str(&payload))
                            .transpose()?,
                    })
                },
            )
            .transpose()?
            .ok_or_else(|| StorageError::Domain("job does not exist".to_owned()))
    }

    pub fn list_jobs(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<(Vec<StoredJob>, Option<String>), StorageError> {
        if limit == 0 || limit > 100 {
            return Err(StorageError::Domain(
                "job page limit must be 1..=100".to_owned(),
            ));
        }
        let (cursor_time, cursor_id) = cursor
            .map(parse_job_cursor)
            .transpose()?
            .unwrap_or_else(|| ("~".to_owned(), "~".to_owned()));
        let connection = open_reader_connection(&self.layout.database)?;
        let mut statement = connection.prepare(
            "SELECT j.payload_json,j.created_at,j.job_id,c.payload_json,i.payload_json
             FROM jobs j
             JOIN command_specs c ON c.command_spec_id=j.command_spec_id
             LEFT JOIN job_imports i ON i.job_id=j.job_id
             WHERE j.created_at < ?1 OR (j.created_at = ?1 AND j.job_id < ?2)
             ORDER BY j.created_at DESC,j.job_id DESC LIMIT ?3",
        )?;
        let sql_limit = i64::try_from(limit + 1)
            .map_err(|_| StorageError::Domain("page limit overflow".to_owned()))?;
        let mut rows = statement
            .query_map(params![cursor_time, cursor_id, sql_limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let next_cursor = has_more
            .then(|| {
                rows.last()
                    .map(|(_, created_at, job_id, _, _)| format!("{created_at}:{job_id}"))
            })
            .flatten();
        let items = rows
            .into_iter()
            .map(|(job, _, _, command_spec, import)| {
                Ok(StoredJob {
                    job: serde_json::from_str(&job)?,
                    command_spec: serde_json::from_str(&command_spec)?,
                    import: import
                        .map(|payload| serde_json::from_str(&payload))
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;
        Ok((items, next_cursor))
    }

    pub fn save_discovery(&self, discovery: &Discovery) -> Result<(), StorageError> {
        let value = discovery.clone();
        self.writable_writer()?.call(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            upsert_discovery(&transaction, &value, None)?;
            transaction.commit()?;
            Ok(())
        })
    }

    pub fn save_discoveries(&self, discoveries: Vec<Discovery>) -> Result<(), StorageError> {
        if discoveries.is_empty()
            || discoveries.len() > 100_000
            || discoveries
                .iter()
                .any(|discovery| discovery.project_id != self.project_id)
        {
            return Err(StorageError::Domain(
                "discovery batch must contain 1..=100000 project-bound rows".to_owned(),
            ));
        }
        for discovery in &discoveries {
            validate_discovery_payload(discovery)?;
        }
        self.writable_writer()?.call(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let existing: i64 = transaction.query_row(
                "SELECT count(*) FROM discoveries WHERE project_id=?1",
                [&discoveries[0].project_id.0],
                |row| row.get(0),
            )?;
            let unique_keys = discoveries
                .iter()
                .map(|discovery| discovery.canonical_key.as_str())
                .collect::<HashSet<_>>()
                .len()
                == discoveries.len();
            if existing == 0 && unique_keys {
                let mut insert = transaction.prepare(
                    "INSERT INTO discoveries(discovery_id,project_id,kind,raw_value,canonical_value,canonical_key,first_seen_at,last_seen_at,payload_json)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                )?;
                let mut search = transaction.prepare(
                    "INSERT INTO search_fts(entity_type,entity_id,content) VALUES('discovery',?1,?2)",
                )?;
                for discovery in &discoveries {
                    let payload = serde_json::to_string(discovery)?;
                    insert.execute(params![
                        discovery.discovery_id.0,
                        discovery.project_id.0,
                        enum_json(&discovery.kind)?,
                        discovery.raw_value,
                        discovery.canonical_value,
                        discovery.canonical_key,
                        discovery.first_seen_at.0,
                        discovery.last_seen_at.0,
                        payload
                    ])?;
                    search.execute(params![discovery.discovery_id.0, discovery.canonical_value])?;
                }
            } else {
                for discovery in &discoveries {
                    upsert_discovery(&transaction, discovery, None)?;
                }
            }
            transaction.commit()?;
            Ok(())
        })
    }

    pub fn list_discoveries(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<(Vec<Discovery>, Option<String>), StorageError> {
        if limit == 0 || limit > 100 {
            return Err(StorageError::Domain(
                "discovery page limit must be 1..=100".to_owned(),
            ));
        }
        let (cursor_time, cursor_id) = cursor
            .map(parse_discovery_cursor)
            .transpose()?
            .unwrap_or_else(|| ("~".to_owned(), "~".to_owned()));
        let connection = open_reader_connection(&self.layout.database)?;
        let mut statement = connection.prepare(
            "SELECT payload_json,last_seen_at,discovery_id FROM discoveries
             WHERE project_id=?1
               AND (last_seen_at < ?2 OR (last_seen_at = ?2 AND discovery_id < ?3))
             ORDER BY last_seen_at DESC,discovery_id DESC LIMIT ?4",
        )?;
        let sql_limit = i64::try_from(limit + 1)
            .map_err(|_| StorageError::Domain("page limit overflow".to_owned()))?;
        let mut rows = statement
            .query_map(
                params![self.project_id.0, cursor_time, cursor_id, sql_limit],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let next_cursor = if has_more {
            rows.last()
                .map(|(_, observed_at, discovery_id)| format!("{observed_at}:{discovery_id}"))
        } else {
            None
        };
        let items = rows
            .into_iter()
            .map(|(payload, _, _)| serde_json::from_str(&payload).map_err(Into::into))
            .collect::<Result<Vec<_>, StorageError>>()?;
        Ok((items, next_cursor))
    }

    pub fn write_import_state(
        &self,
        job: &Job,
        record: &JobImportRecord,
    ) -> Result<(), StorageError> {
        validate_import_record(job, record)?;
        let job = job.clone();
        let record = record.clone();
        self.writable_writer()?.call(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            upsert_job_row(&transaction, &job)?;
            upsert_import_row(&transaction, &record)?;
            transaction.commit()?;
            Ok(())
        })
    }

    pub fn complete_import(
        &self,
        job: &Job,
        record: &JobImportRecord,
        discoveries: &[Discovery],
        http_messages: &[HttpMessage],
    ) -> Result<(), StorageError> {
        validate_import_record(job, record)?;
        if discoveries.len() != record.discovery_count
            || http_messages.len() != record.http_message_count
            || discoveries
                .iter()
                .any(|item| item.project_id != self.project_id)
            || http_messages
                .iter()
                .any(|item| item.project_id != self.project_id)
        {
            return Err(StorageError::Domain("invalid import result".to_owned()));
        }
        for message in http_messages {
            message
                .validate()
                .map_err(|error| StorageError::Domain(error.to_string()))?;
        }
        let job = job.clone();
        let record = record.clone();
        let discoveries = discoveries.to_vec();
        let http_messages = http_messages.to_vec();
        self.writable_writer()?.call(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            upsert_job_row(&transaction, &job)?;
            upsert_import_row(&transaction, &record)?;
            for discovery in &discoveries {
                upsert_discovery(&transaction, discovery, Some(&job.job_id))?;
            }
            for message in &http_messages {
                upsert_http_message(&transaction, message)?;
            }
            transaction.commit()?;
            Ok(())
        })
    }

    pub fn save_adapter_entity(&self, entity: &AdapterEntity) -> Result<(), StorageError> {
        entity
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        if entity.project_id.as_ref() != Some(&self.project_id) {
            return Err(StorageError::Domain(
                "adapter entity belongs to another project".to_owned(),
            ));
        }
        let value = entity.clone();
        let payload = serde_json::to_string(&value)?;
        self.writable_writer()?.call(move |connection| {
            connection.execute(
                "INSERT OR REPLACE INTO adapter_entities(adapter_entity_id,project_id,adapter_id,entity_kind,external_id,ownership,state_schema_version,payload_json,created_at,synced_at,terminated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![value.adapter_entity_id.0, value.project_id.map(|id| id.0), value.adapter_id, value.entity_kind, value.external_id, enum_json(&value.ownership)?, value.state_schema_version, payload, value.created_at.0, value.synced_at.0, value.terminated_at.map(|time| time.0)],
            )?;
            Ok(())
        })
    }

    pub fn adapter_entity(
        &self,
        adapter_entity_id: &flagdeck_domain::AdapterEntityId,
    ) -> Result<AdapterEntity, StorageError> {
        adapter_entity_id
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        let connection = open_reader_connection(&self.layout.database)?;
        let payload = connection
            .query_row(
                "SELECT payload_json FROM adapter_entities WHERE project_id=?1 AND adapter_entity_id=?2",
                params![self.project_id.0, adapter_entity_id.0],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::Domain("adapter entity does not exist".to_owned()))?;
        Ok(serde_json::from_str(&payload)?)
    }

    pub fn list_adapter_entities(
        &self,
        adapter_id: &str,
        entity_kind: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AdapterEntity>, StorageError> {
        if adapter_id.is_empty() || adapter_id.len() > 128 || limit == 0 || limit > 500 {
            return Err(StorageError::Domain(
                "invalid adapter entity query".to_owned(),
            ));
        }
        let connection = open_reader_connection(&self.layout.database)?;
        let limit = i64::try_from(limit).map_err(|_| StorageError::ArchiveLimit)?;
        let mut statement = connection.prepare(
            "SELECT payload_json FROM adapter_entities
             WHERE project_id=?1 AND adapter_id=?2 AND (?3 IS NULL OR entity_kind=?3)
             ORDER BY synced_at DESC,adapter_entity_id DESC LIMIT ?4",
        )?;
        statement
            .query_map(
                params![self.project_id.0, adapter_id, entity_kind, limit],
                |row| row.get::<_, String>(0),
            )?
            .map(|value| {
                value
                    .map_err(StorageError::from)
                    .and_then(|payload| serde_json::from_str(&payload).map_err(Into::into))
            })
            .collect()
    }

    pub fn save_audit_event(&self, event: &AuditEvent) -> Result<(), StorageError> {
        event
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        if event.project_id != self.project_id {
            return Err(StorageError::Domain(
                "audit event belongs to another project".to_owned(),
            ));
        }
        let value = event.clone();
        let payload = serde_json::to_string(&value)?;
        self.writable_writer()?.call(move |connection| {
            connection.execute(
                "INSERT INTO audit_events(audit_event_id,project_id,adapter_id,action,risk_level,outcome,target_summary,details_json,created_at,payload_json)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    value.audit_event_id.0,
                    value.project_id.0,
                    value.adapter_id,
                    value.action,
                    enum_json(&value.risk_level)?,
                    value.outcome,
                    value.target_summary,
                    value.details_json,
                    value.created_at.0,
                    payload,
                ],
            )?;
            Ok(())
        })
    }

    pub fn list_audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>, StorageError> {
        if limit == 0 || limit > 500 {
            return Err(StorageError::Domain("invalid audit query".to_owned()));
        }
        let connection = open_reader_connection(&self.layout.database)?;
        let limit = i64::try_from(limit).map_err(|_| StorageError::ArchiveLimit)?;
        let mut statement = connection.prepare(
            "SELECT payload_json FROM audit_events WHERE project_id=?1
             ORDER BY created_at DESC,audit_event_id DESC LIMIT ?2",
        )?;
        statement
            .query_map(params![self.project_id.0, limit], |row| {
                row.get::<_, String>(0)
            })?
            .map(|value| {
                value
                    .map_err(StorageError::from)
                    .and_then(|payload| serde_json::from_str(&payload).map_err(Into::into))
            })
            .collect()
    }

    pub fn save_intruder_campaign(&self, campaign: &IntruderCampaign) -> Result<(), StorageError> {
        campaign
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        if campaign.project_id != self.project_id {
            return Err(StorageError::Domain(
                "intruder campaign belongs to another project".to_owned(),
            ));
        }
        let value = campaign.clone();
        let payload = serde_json::to_string(&value)?;
        let total_attempts = integer_from_u64(value.total_attempts)?;
        let next_ordinal = integer_from_u64(value.next_ordinal)?;
        let completed_attempts = integer_from_u64(value.completed_attempts)?;
        let failed_attempts = integer_from_u64(value.failed_attempts)?;
        self.writable_writer()?.call(move |connection| {
            connection.execute(
                "INSERT INTO intruder_campaigns(intruder_campaign_id,project_id,scope_id,parent_message_id,campaign_kind,attack_mode,state,total_attempts,next_ordinal,completed_attempts,failed_attempts,created_at,started_at,stopped_at,payload_json)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
                 ON CONFLICT(intruder_campaign_id) DO UPDATE SET state=excluded.state,next_ordinal=excluded.next_ordinal,completed_attempts=excluded.completed_attempts,failed_attempts=excluded.failed_attempts,started_at=excluded.started_at,stopped_at=excluded.stopped_at,payload_json=excluded.payload_json",
                params![
                    value.intruder_campaign_id.0,
                    value.project_id.0,
                    value.scope_id.0,
                    value.parent_message_id.0,
                    enum_json(&value.campaign_kind)?,
                    enum_json(&value.attack_mode)?,
                    enum_json(&value.state)?,
                    total_attempts,
                    next_ordinal,
                    completed_attempts,
                    failed_attempts,
                    value.created_at.0,
                    value.started_at.map(|time| time.0),
                    value.stopped_at.map(|time| time.0),
                    payload,
                ],
            )?;
            Ok(())
        })
    }

    pub fn intruder_campaign(
        &self,
        campaign_id: &IntruderCampaignId,
    ) -> Result<IntruderCampaign, StorageError> {
        campaign_id
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        let connection = open_reader_connection(&self.layout.database)?;
        let payload = connection
            .query_row(
                "SELECT payload_json FROM intruder_campaigns WHERE project_id=?1 AND intruder_campaign_id=?2",
                params![self.project_id.0, campaign_id.0],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::Domain("intruder campaign does not exist".to_owned()))?;
        Ok(serde_json::from_str(&payload)?)
    }

    pub fn list_intruder_campaigns(
        &self,
        limit: usize,
    ) -> Result<Vec<IntruderCampaign>, StorageError> {
        if limit == 0 || limit > 500 {
            return Err(StorageError::Domain(
                "invalid intruder campaign query".to_owned(),
            ));
        }
        let connection = open_reader_connection(&self.layout.database)?;
        let limit = i64::try_from(limit).map_err(|_| StorageError::ArchiveLimit)?;
        let mut statement = connection.prepare(
            "SELECT payload_json FROM intruder_campaigns WHERE project_id=?1
             ORDER BY created_at DESC,intruder_campaign_id DESC LIMIT ?2",
        )?;
        statement
            .query_map(params![self.project_id.0, limit], |row| {
                row.get::<_, String>(0)
            })?
            .map(|value| {
                value
                    .map_err(StorageError::from)
                    .and_then(|payload| serde_json::from_str(&payload).map_err(Into::into))
            })
            .collect()
    }

    pub fn save_intruder_attempt(&self, attempt: &IntruderAttempt) -> Result<(), StorageError> {
        attempt
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        if attempt.project_id != self.project_id {
            return Err(StorageError::Domain(
                "intruder attempt belongs to another project".to_owned(),
            ));
        }
        let value = attempt.clone();
        let payload = serde_json::to_string(&value)?;
        let ordinal = integer_from_u64(value.ordinal)?;
        let response_length = value.response_length.map(integer_from_u64).transpose()?;
        let duration_millis = value.duration_millis.map(integer_from_u64).transpose()?;
        self.writable_writer()?.call(move |connection| {
            connection.execute(
                "INSERT INTO intruder_attempts(intruder_attempt_id,intruder_campaign_id,project_id,ordinal,state,response_status,response_length,duration_millis,created_at,payload_json)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
                 ON CONFLICT(intruder_attempt_id) DO UPDATE SET state=excluded.state,response_status=excluded.response_status,response_length=excluded.response_length,duration_millis=excluded.duration_millis,payload_json=excluded.payload_json",
                params![
                    value.intruder_attempt_id.0,
                    value.intruder_campaign_id.0,
                    value.project_id.0,
                    ordinal,
                    enum_json(&value.state)?,
                    value.response_status,
                    response_length,
                    duration_millis,
                    value.created_at.0,
                    payload,
                ],
            )?;
            Ok(())
        })
    }

    pub fn intruder_attempt(
        &self,
        attempt_id: &IntruderAttemptId,
    ) -> Result<IntruderAttempt, StorageError> {
        attempt_id
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        let connection = open_reader_connection(&self.layout.database)?;
        let payload = connection
            .query_row(
                "SELECT payload_json FROM intruder_attempts WHERE project_id=?1 AND intruder_attempt_id=?2",
                params![self.project_id.0, attempt_id.0],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::Domain("intruder attempt does not exist".to_owned()))?;
        Ok(serde_json::from_str(&payload)?)
    }

    pub fn list_intruder_attempts(
        &self,
        campaign_id: &IntruderCampaignId,
        limit: usize,
        cursor: Option<u64>,
    ) -> Result<Vec<IntruderAttempt>, StorageError> {
        if limit == 0 || limit > 500 {
            return Err(StorageError::Domain(
                "invalid intruder attempt query".to_owned(),
            ));
        }
        let connection = open_reader_connection(&self.layout.database)?;
        let limit = i64::try_from(limit).map_err(|_| StorageError::ArchiveLimit)?;
        let cursor = cursor.map(integer_from_u64).transpose()?.unwrap_or(-1);
        let mut statement = connection.prepare(
            "SELECT payload_json FROM intruder_attempts
             WHERE project_id=?1 AND intruder_campaign_id=?2 AND ordinal>?3
             ORDER BY ordinal ASC LIMIT ?4",
        )?;
        statement
            .query_map(
                params![self.project_id.0, campaign_id.0, cursor, limit],
                |row| row.get::<_, String>(0),
            )?
            .map(|value| {
                value
                    .map_err(StorageError::from)
                    .and_then(|payload| serde_json::from_str(&payload).map_err(Into::into))
            })
            .collect()
    }

    pub fn save_state_chain_run(&self, run: &StateChainRun) -> Result<(), StorageError> {
        run.validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        if run.project_id != self.project_id {
            return Err(StorageError::Domain(
                "state chain run belongs to another project".to_owned(),
            ));
        }
        let value = run.clone();
        let payload = serde_json::to_string(&value)?;
        self.writable_writer()?.call(move |connection| {
            connection.execute(
                "INSERT OR REPLACE INTO state_chain_runs(state_chain_run_id,project_id,intruder_attempt_id,created_at,payload_json) VALUES(?1,?2,?3,?4,?5)",
                params![value.state_chain_run_id.0, value.project_id.0, value.intruder_attempt_id.0, value.created_at.0, payload],
            )?;
            Ok(())
        })
    }

    pub fn state_chain_run(
        &self,
        run_id: &flagdeck_domain::StateChainRunId,
    ) -> Result<StateChainRun, StorageError> {
        run_id
            .validate()
            .map_err(|error| StorageError::Domain(error.to_string()))?;
        let connection = open_reader_connection(&self.layout.database)?;
        let payload = connection
            .query_row(
                "SELECT payload_json FROM state_chain_runs WHERE project_id=?1 AND state_chain_run_id=?2",
                params![self.project_id.0, run_id.0],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StorageError::Domain("state chain run does not exist".to_owned()))?;
        Ok(serde_json::from_str(&payload)?)
    }

    pub fn dictionary_terms_page(
        &self,
        dictionary_id: &DictionaryId,
        offset: u64,
        limit: usize,
    ) -> Result<Vec<String>, StorageError> {
        if limit == 0 || limit > 1024 {
            return Err(StorageError::Domain(
                "invalid dictionary stream page".to_owned(),
            ));
        }
        let connection = open_reader_connection(&self.layout.database)?;
        let offset = integer_from_u64(offset)?;
        let limit = i64::try_from(limit).map_err(|_| StorageError::ArchiveLimit)?;
        let mut statement = connection.prepare(
            "SELECT term FROM dictionary_terms WHERE dictionary_id=?1
             ORDER BY ordinal ASC LIMIT ?2 OFFSET ?3",
        )?;
        statement
            .query_map(params![dictionary_id.0, limit, offset], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn create_database_snapshot(&self) -> Result<SnapshotEvidence, StorageError> {
        let writer = self.writable_writer()?;
        let destination = self.layout.backups.join(format!(
            "project-v{}-{}.sqlite",
            SCHEMA_VERSION,
            Timestamp::now().0
        ));
        let destination_for_writer = destination.clone();
        writer.call(move |connection| {
            let mut target = Connection::open(&destination_for_writer)?;
            let backup = Backup::new(connection, &mut target)?;
            backup.run_to_completion(64, Duration::from_millis(1), None)?;
            drop(backup);
            drop(target);
            fs::set_permissions(&destination_for_writer, fs::Permissions::from_mode(0o600))?;
            Ok(())
        })?;
        let sha256 = sha256_file(&destination)?;
        Ok(SnapshotEvidence {
            relative_path: destination
                .strip_prefix(&self.layout.root)
                .map_err(|_| StorageError::InvalidLayout(destination.display().to_string()))?
                .to_string_lossy()
                .into_owned(),
            size: fs::metadata(&destination)?.len(),
            sha256,
        })
    }

    pub fn export_project(
        &self,
        confirm_sensitive: bool,
    ) -> Result<ProjectExportEvidence, StorageError> {
        let writer = self.writable_writer()?;
        let export_id = Uuid::new_v4().to_string();
        let snapshot = self.layout.tmp.join(format!("export-{export_id}.sqlite"));
        let snapshot_for_writer = snapshot.clone();
        writer.call(move |connection| {
            let mut target = Connection::open(&snapshot_for_writer)?;
            let backup = Backup::new(connection, &mut target)?;
            backup.run_to_completion(64, Duration::from_millis(1), None)?;
            drop(backup);
            drop(target);
            fs::set_permissions(&snapshot_for_writer, fs::Permissions::from_mode(0o600))?;
            Ok(())
        })?;
        let result = self.export_snapshot(&snapshot, confirm_sensitive, &export_id);
        let _ = fs::remove_file(&snapshot);
        result
    }

    fn export_snapshot(
        &self,
        snapshot: &Path,
        confirm_sensitive: bool,
        export_id: &str,
    ) -> Result<ProjectExportEvidence, StorageError> {
        let summary = project_summary_from_database(snapshot, false)?;
        let artifacts = all_committed_artifacts(snapshot)?;
        if !confirm_sensitive
            && artifacts
                .iter()
                .any(|artifact| artifact.export_policy == ExportPolicy::ConfirmSensitive)
        {
            return Err(StorageError::SensitiveExportConfirmationRequired);
        }
        let mut sources = BTreeMap::<String, ArchiveSource>::new();
        insert_archive_source(
            &mut sources,
            ProjectArchiveEntry {
                path: "project.sqlite".to_owned(),
                size: fs::metadata(snapshot)?.len(),
                sha256: sha256_file(snapshot)?,
                sensitivity: Sensitivity::SensitiveEvidence,
                kind: "database".to_owned(),
            },
            snapshot.to_path_buf(),
        )?;
        let mut exclusions = Vec::new();
        let mut included_artifacts = 0_usize;
        for artifact in artifacts {
            let include = match artifact.export_policy {
                ExportPolicy::Include => true,
                ExportPolicy::ConfirmSensitive => confirm_sensitive,
                ExportPolicy::ExcludeCredential | ExportPolicy::ExcludeRuntime => false,
            };
            if !include {
                exclusions.push(ProjectArchiveExclusion {
                    artifact_id: artifact.artifact_id.0,
                    logical_name: artifact.logical_name,
                    reason: enum_json(&artifact.export_policy)?,
                });
                continue;
            }
            let blob_relative = artifact
                .blob_relative_path
                .as_ref()
                .ok_or(StorageError::ArtifactNotFound)?;
            validate_archive_payload_path(blob_relative)?;
            let blob = self.layout.root.join(blob_relative);
            let blob_size = fs::metadata(&blob)?.len();
            let blob_sha = sha256_file(&blob)?;
            if artifact.size != Some(blob_size) || artifact.sha256.as_deref() != Some(&blob_sha) {
                return Err(StorageError::HashMismatch);
            }
            insert_archive_source(
                &mut sources,
                ProjectArchiveEntry {
                    path: blob_relative.clone(),
                    size: blob_size,
                    sha256: blob_sha,
                    sensitivity: artifact.sensitivity,
                    kind: "blob".to_owned(),
                },
                blob,
            )?;
            validate_archive_payload_path(&artifact.relative_path)?;
            let metadata_path = self.layout.root.join(&artifact.relative_path);
            insert_archive_source(
                &mut sources,
                ProjectArchiveEntry {
                    path: artifact.relative_path,
                    size: fs::metadata(&metadata_path)?.len(),
                    sha256: sha256_file(&metadata_path)?,
                    sensitivity: artifact.sensitivity,
                    kind: "artifact_manifest".to_owned(),
                },
                metadata_path,
            )?;
            included_artifacts = included_artifacts.saturating_add(1);
        }
        let created_at = Timestamp::now();
        let entries = sources
            .values()
            .map(|source| source.entry.clone())
            .collect::<Vec<_>>();
        let manifest = ProjectArchiveManifest {
            format: "flagdeck.project-export".to_owned(),
            format_version: 1,
            contract_version: flagdeck_domain::CONTRACT_VERSION,
            schema_version: SCHEMA_VERSION,
            project_id: summary.project_id,
            project_name: summary.name,
            created_at: created_at.clone(),
            sensitive_evidence_confirmed: confirm_sensitive,
            entries,
            exclusions,
        };
        let archive_name = format!(
            "flagdeck-{}-{}-{}.flagdeck.zip",
            self.project_id.0,
            created_at.0,
            &export_id[..8]
        );
        let final_path = self.layout.exports.join(&archive_name);
        let temporary = self.layout.exports.join(format!(".{archive_name}.partial"));
        let write_result = write_project_archive(&temporary, &manifest, &sources);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        let verified = validate_project_archive(&temporary, ArchiveLimits::default())?;
        if verified.manifest != manifest {
            let _ = fs::remove_file(&temporary);
            return Err(StorageError::InvalidArchive(
                "written manifest changed during verification".to_owned(),
            ));
        }
        fs::rename(&temporary, &final_path)?;
        fs::set_permissions(&final_path, fs::Permissions::from_mode(0o600))?;
        sync_directory(&self.layout.exports)?;
        Ok(ProjectExportEvidence {
            archive_name,
            sha256: sha256_file(&final_path)?,
            size: fs::metadata(&final_path)?.len(),
            file_count: manifest.entries.len() + 1,
            included_artifacts,
            excluded_artifacts: manifest.exclusions.len(),
            created_at,
        })
    }

    pub fn import_project_archive(
        workspaces_root: &Path,
        archive_path: &Path,
    ) -> Result<ProjectImportEvidence, StorageError> {
        let archive_metadata = fs::symlink_metadata(archive_path)?;
        if !archive_metadata.is_file()
            || archive_metadata.file_type().is_symlink()
            || archive_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(StorageError::InvalidArchive(
                "archive must be a private regular file".to_owned(),
            ));
        }
        create_private_dir(workspaces_root)?;
        if archive_metadata.uid() != fs::metadata(workspaces_root)?.uid() {
            return Err(StorageError::InvalidArchive(
                "archive owner differs from workspace owner".to_owned(),
            ));
        }
        let validated = validate_project_archive(archive_path, ArchiveLimits::default())?;
        let target = workspaces_root.join(&validated.manifest.project_id.0);
        if target.exists() {
            return Err(StorageError::ProjectExists);
        }
        let staging = workspaces_root.join(format!(".import-{}", Uuid::new_v4()));
        let layout = WorkspaceLayout::for_root(staging.clone());
        layout.create()?;
        let extraction = extract_project_archive(archive_path, &validated, &layout);
        if let Err(error) = extraction {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
        validate_imported_database(&layout.database, &validated.manifest)?;
        sync_directory(&layout.root)?;
        fs::rename(&staging, &target)?;
        sync_directory(workspaces_root)?;
        let project = match ProjectStore::open(
            workspaces_root,
            &validated.manifest.project_id,
            OpenMode::ReadWrite,
        ) {
            Ok(store) => store.summary()?,
            Err(error) => {
                let _ = fs::remove_dir_all(&target);
                return Err(error);
            }
        };
        Ok(ProjectImportEvidence {
            project,
            archive_sha256: validated.archive_sha256,
            archive_size: archive_metadata.len(),
            file_count: validated.file_count,
            extracted_bytes: validated.total_bytes,
        })
    }

    fn writable_writer(&self) -> Result<&WriterRuntime, StorageError> {
        if self.mode == OpenMode::ReadOnly {
            return Err(StorageError::ReadOnly);
        }
        self.writer.as_ref().ok_or(StorageError::WriterStopped)
    }
}

#[derive(Debug, Clone)]
struct ArchiveSource {
    entry: ProjectArchiveEntry,
    source: PathBuf,
}

struct ValidatedArchive {
    manifest: ProjectArchiveManifest,
    manifest_bytes: Vec<u8>,
    archive_sha256: String,
    file_count: usize,
    total_bytes: u64,
}

fn insert_archive_source(
    sources: &mut BTreeMap<String, ArchiveSource>,
    entry: ProjectArchiveEntry,
    source: PathBuf,
) -> Result<(), StorageError> {
    if let Some(existing) = sources.get_mut(&entry.path) {
        if existing.entry.sha256 != entry.sha256 || existing.entry.size != entry.size {
            return Err(StorageError::HashMismatch);
        }
        existing.entry.sensitivity = most_sensitive(existing.entry.sensitivity, entry.sensitivity);
        return Ok(());
    }
    validate_archive_payload_path(&entry.path)?;
    sources.insert(entry.path.clone(), ArchiveSource { entry, source });
    Ok(())
}

const fn most_sensitive(left: Sensitivity, right: Sensitivity) -> Sensitivity {
    match (left, right) {
        (Sensitivity::Credential, _) | (_, Sensitivity::Credential) => Sensitivity::Credential,
        (Sensitivity::SensitiveEvidence, _) | (_, Sensitivity::SensitiveEvidence) => {
            Sensitivity::SensitiveEvidence
        }
        (Sensitivity::Normal, Sensitivity::Normal) => Sensitivity::Normal,
    }
}

fn project_summary_from_database(
    database: &Path,
    read_only: bool,
) -> Result<ProjectSummary, StorageError> {
    let connection = open_reader_connection(database)?;
    let mut statement = connection.prepare(
        "SELECT project_id,name,created_at,updated_at FROM projects ORDER BY project_id LIMIT 2",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok(ProjectSummary {
                project_id: ProjectId(row.get(0)?),
                name: row.get(1)?,
                created_at: Timestamp(row.get(2)?),
                updated_at: Timestamp(row.get(3)?),
                read_only,
                schema_version: SCHEMA_VERSION,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != 1 {
        return Err(StorageError::InvalidArchive(
            "database must contain exactly one project".to_owned(),
        ));
    }
    rows.into_iter()
        .next()
        .ok_or_else(|| StorageError::InvalidArchive("project row is missing".to_owned()))
}

fn all_committed_artifacts(database: &Path) -> Result<Vec<Artifact>, StorageError> {
    let connection = open_reader_connection(database)?;
    let mut statement = connection.prepare(
        "SELECT payload_json FROM artifacts WHERE state='committed' ORDER BY artifact_id",
    )?;
    statement
        .query_map([], |row| row.get::<_, String>(0))?
        .map(|value| {
            value
                .map_err(StorageError::from)
                .and_then(|payload| serde_json::from_str(&payload).map_err(Into::into))
        })
        .collect()
}

fn write_project_archive(
    path: &Path,
    manifest: &ProjectArchiveManifest,
    sources: &BTreeMap<String, ArchiveSource>,
) -> Result<(), StorageError> {
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o600);
    for (name, source) in sources {
        writer.start_file(name, options)?;
        let mut input = File::open(&source.source)?;
        let copied = std::io::copy(&mut input, &mut writer)?;
        if copied != source.entry.size {
            return Err(StorageError::SizeMismatch);
        }
    }
    let manifest_bytes = toml::to_string_pretty(manifest)?.into_bytes();
    if u64::try_from(manifest_bytes.len()).map_err(|_| StorageError::ArchiveLimit)?
        > MAX_ARCHIVE_MANIFEST_BYTES
    {
        return Err(StorageError::ArchiveLimit);
    }
    writer.start_file("project.toml", options)?;
    writer.write_all(&manifest_bytes)?;
    let output = writer.finish()?;
    output.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn validate_project_archive(
    path: &Path,
    limits: ArchiveLimits,
) -> Result<ValidatedArchive, StorageError> {
    if limits.maximum_files == 0
        || limits.maximum_total_bytes == 0
        || limits.maximum_file_bytes == 0
        || limits.maximum_compression_ratio == 0
        || limits.maximum_manifest_bytes == 0
    {
        return Err(StorageError::ArchiveLimit);
    }
    let archive_sha256 = sha256_file(path)?;
    let mut archive = ZipArchive::new(File::open(path)?)?;
    if archive.is_empty() || archive.len() > limits.maximum_files {
        return Err(StorageError::ArchiveLimit);
    }
    let mut metadata = BTreeMap::<String, (u64, u64)>::new();
    let mut manifest_bytes = None;
    let mut total_bytes = 0_u64;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let name = validate_zip_entry(&file)?;
        if metadata.contains_key(&name) {
            return Err(StorageError::InvalidArchive(
                "duplicate archive entry".to_owned(),
            ));
        }
        if file.size() > limits.maximum_file_bytes {
            return Err(StorageError::ArchiveLimit);
        }
        total_bytes = total_bytes
            .checked_add(file.size())
            .ok_or(StorageError::ArchiveLimit)?;
        if total_bytes > limits.maximum_total_bytes {
            return Err(StorageError::ArchiveLimit);
        }
        let compressed = file.compressed_size();
        if (compressed == 0 && file.size() > 0)
            || (compressed > 0
                && file.size() > compressed.saturating_mul(limits.maximum_compression_ratio))
        {
            return Err(StorageError::ArchiveLimit);
        }
        if name == "project.toml" {
            if file.size() > limits.maximum_manifest_bytes {
                return Err(StorageError::ArchiveLimit);
            }
            let capacity = usize::try_from(file.size()).map_err(|_| StorageError::ArchiveLimit)?;
            let mut bytes = Vec::with_capacity(capacity);
            file.read_to_end(&mut bytes)?;
            manifest_bytes = Some(bytes);
        }
        metadata.insert(name, (file.size(), compressed));
    }
    let manifest_bytes = manifest_bytes
        .ok_or_else(|| StorageError::InvalidArchive("project.toml is missing".to_owned()))?;
    let manifest: ProjectArchiveManifest = toml::from_slice(&manifest_bytes)?;
    validate_archive_manifest(&manifest, &metadata)?;
    for entry in &manifest.entries {
        let mut file = archive.by_name(&entry.path)?;
        let mut hasher = Sha256::new();
        let copied = copy_with_hash(&mut file, std::io::sink(), &mut hasher)?;
        if copied != entry.size || format!("{:x}", hasher.finalize()) != entry.sha256 {
            return Err(StorageError::HashMismatch);
        }
    }
    Ok(ValidatedArchive {
        manifest,
        manifest_bytes,
        archive_sha256,
        file_count: archive.len(),
        total_bytes,
    })
}

fn validate_zip_entry(file: &zip::read::ZipFile<'_, File>) -> Result<String, StorageError> {
    if file.is_dir() || file.is_symlink() || file.encrypted() {
        return Err(StorageError::InvalidArchive(
            "directories, symlinks, and encrypted entries are rejected".to_owned(),
        ));
    }
    let name = file.name().to_owned();
    let enclosed = file
        .enclosed_name()
        .ok_or_else(|| StorageError::InvalidArchive("archive path escapes its root".to_owned()))?;
    if name.is_empty()
        || name.contains(['\\', '\0'])
        || enclosed.as_os_str().to_string_lossy() != name
        || enclosed
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(StorageError::InvalidArchive(
            "archive path is not canonical".to_owned(),
        ));
    }
    Ok(name)
}

fn validate_archive_manifest(
    manifest: &ProjectArchiveManifest,
    metadata: &BTreeMap<String, (u64, u64)>,
) -> Result<(), StorageError> {
    manifest
        .project_id
        .validate()
        .map_err(|error| StorageError::InvalidArchive(error.to_string()))?;
    if manifest.format != "flagdeck.project-export"
        || manifest.format_version != 1
        || manifest.contract_version != flagdeck_domain::CONTRACT_VERSION
        || manifest.schema_version != SCHEMA_VERSION
        || manifest.project_name.trim().is_empty()
        || manifest.project_name.len() > 256
        || manifest.entries.is_empty()
        || manifest.entries.len() + 1 != metadata.len()
    {
        return Err(StorageError::InvalidArchive(
            "manifest header contract failed".to_owned(),
        ));
    }
    let mut names = BTreeSet::new();
    let mut database_entries = 0_usize;
    for entry in &manifest.entries {
        validate_archive_payload_path(&entry.path)?;
        let expected_kind = archive_entry_kind(&entry.path)?;
        let Some((size, _)) = metadata.get(&entry.path) else {
            return Err(StorageError::InvalidArchive(
                "manifest entry is missing from ZIP".to_owned(),
            ));
        };
        if !names.insert(entry.path.clone())
            || *size != entry.size
            || entry.kind != expected_kind
            || entry.sha256.len() != 64
            || !entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(StorageError::InvalidArchive(
                "manifest entry contract failed".to_owned(),
            ));
        }
        if entry.path == "project.sqlite" {
            database_entries += 1;
        }
    }
    if database_entries != 1
        || metadata
            .keys()
            .any(|name| name != "project.toml" && !names.contains(name))
    {
        return Err(StorageError::InvalidArchive(
            "archive contains an unmanifested entry".to_owned(),
        ));
    }
    Ok(())
}

fn validate_archive_payload_path(path: &str) -> Result<(), StorageError> {
    archive_entry_kind(path).map(|_| ())
}

fn archive_entry_kind(path: &str) -> Result<String, StorageError> {
    if path == "project.sqlite" {
        return Ok("database".to_owned());
    }
    if let Some(value) = path.strip_prefix("blobs/sha256/") {
        let mut parts = value.split('/');
        let prefix = parts.next().unwrap_or_default();
        let digest = parts.next().unwrap_or_default();
        if parts.next().is_none()
            && prefix.len() == 2
            && digest.len() == 64
            && digest.starts_with(prefix)
            && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Ok("blob".to_owned());
        }
    }
    if let Some(value) = path.strip_prefix("artifacts/")
        && let Some(identifier) = value.strip_suffix(".json")
        && ArtifactId::parse(identifier).is_ok()
    {
        return Ok("artifact_manifest".to_owned());
    }
    Err(StorageError::InvalidArchive(
        "manifest path is outside the export allowlist".to_owned(),
    ))
}

fn extract_project_archive(
    archive_path: &Path,
    validated: &ValidatedArchive,
    layout: &WorkspaceLayout,
) -> Result<(), StorageError> {
    write_private_bytes(&layout.root.join("project.toml"), &validated.manifest_bytes)?;
    let mut archive = ZipArchive::new(File::open(archive_path)?)?;
    for entry in &validated.manifest.entries {
        validate_archive_payload_path(&entry.path)?;
        let destination = layout.root.join(&entry.path);
        ensure_descendant(&layout.root, &destination)?;
        let parent = destination.parent().ok_or_else(|| {
            StorageError::InvalidLayout("archive destination lacks parent".to_owned())
        })?;
        create_private_dir(parent)?;
        let mut source = archive.by_name(&entry.path)?;
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&destination)?;
        let mut hasher = Sha256::new();
        let copied = copy_with_hash(&mut source, &mut output, &mut hasher)?;
        output.sync_all()?;
        drop(output);
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
        if copied != entry.size || format!("{:x}", hasher.finalize()) != entry.sha256 {
            return Err(StorageError::HashMismatch);
        }
        sync_directory(parent)?;
    }
    Ok(())
}

fn validate_imported_database(
    database: &Path,
    manifest: &ProjectArchiveManifest,
) -> Result<(), StorageError> {
    let connection = open_reader_connection(database)?;
    let quick_check: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if quick_check != "ok" || version != manifest.schema_version {
        return Err(StorageError::InvalidArchive(
            "database integrity or schema check failed".to_owned(),
        ));
    }
    drop(connection);
    let project = project_summary_from_database(database, false)?;
    if project.project_id != manifest.project_id || project.name != manifest.project_name {
        return Err(StorageError::InvalidArchive(
            "database project identity differs from manifest".to_owned(),
        ));
    }
    Ok(())
}

fn copy_with_hash<R: Read, W: Write>(
    reader: &mut R,
    mut writer: W,
    hasher: &mut Sha256,
) -> Result<u64, StorageError> {
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let length = reader.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        writer.write_all(&buffer[..length])?;
        hasher.update(&buffer[..length]);
        copied = copied
            .checked_add(u64::try_from(length).map_err(|_| StorageError::ArchiveLimit)?)
            .ok_or(StorageError::ArchiveLimit)?;
    }
    Ok(copied)
}

fn write_private_bytes(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn upsert_job_row(connection: &Connection, job: &Job) -> Result<(), StorageError> {
    let payload = serde_json::to_string(job)?;
    connection.execute(
        "INSERT INTO jobs(job_id,parent_job_id,command_spec_id,execution_status,import_status,created_at,started_at,stopped_at,payload_json)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
         ON CONFLICT(job_id) DO UPDATE SET
           parent_job_id=excluded.parent_job_id,
           command_spec_id=excluded.command_spec_id,
           execution_status=excluded.execution_status,
           import_status=excluded.import_status,
           started_at=excluded.started_at,
           stopped_at=excluded.stopped_at,
           payload_json=excluded.payload_json",
        params![
            job.job_id.0,
            job.parent_job_id.as_ref().map(|id| &id.0),
            job.command_spec_id.0,
            job.execution_status.to_string(),
            enum_json(&job.import_status)?,
            job.created_at.0,
            job.started_at.as_ref().map(|time| &time.0),
            job.stopped_at.as_ref().map(|time| &time.0),
            payload
        ],
    )?;
    Ok(())
}

fn upsert_http_message(connection: &Connection, message: &HttpMessage) -> Result<(), StorageError> {
    if message.redacted_view.len() > 1024 * 1024 {
        return Err(StorageError::Domain(
            "HTTP message search view exceeds one MiB".to_owned(),
        ));
    }
    let payload = serde_json::to_string(message)?;
    let actual_length = i64::try_from(message.actual_length)
        .map_err(|_| StorageError::Domain("HTTP message length overflow".to_owned()))?;
    let duration_millis = message
        .duration_millis
        .map(i64::try_from)
        .transpose()
        .map_err(|_| StorageError::Domain("HTTP duration overflow".to_owned()))?;
    connection.execute(
        "INSERT INTO http_messages(message_id,project_id,exchange_id,parent_message_id,body_artifact_id,wire_artifact_id,direction,body_state,source,representation_kind,method,status_code,scheme,host,port,path,actual_length,duration_millis,sensitivity,payload_json,observed_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)
         ON CONFLICT(message_id) DO UPDATE SET
           exchange_id=excluded.exchange_id,
           parent_message_id=excluded.parent_message_id,
           body_artifact_id=excluded.body_artifact_id,
           wire_artifact_id=excluded.wire_artifact_id,
           direction=excluded.direction,
           body_state=excluded.body_state,
           source=excluded.source,
           representation_kind=excluded.representation_kind,
           method=excluded.method,
           status_code=excluded.status_code,
           scheme=excluded.scheme,
           host=excluded.host,
           port=excluded.port,
           path=excluded.path,
           actual_length=excluded.actual_length,
           duration_millis=excluded.duration_millis,
           sensitivity=excluded.sensitivity,
           payload_json=excluded.payload_json,
           observed_at=excluded.observed_at",
        params![
            message.message_id.0,
            message.project_id.0,
            message.exchange_id,
            message.parent_message_id.as_ref().map(|id| &id.0),
            message.body_artifact_id.as_ref().map(|id| &id.0),
            message.wire_artifact_id.as_ref().map(|id| &id.0),
            enum_json(&message.direction)?,
            enum_json(&message.body_state)?,
            enum_json(&message.source)?,
            enum_json(&message.representation_kind)?,
            message.method,
            message.status_code.map(i64::from),
            message.scheme,
            message.host,
            i64::from(message.port),
            message.path,
            actual_length,
            duration_millis,
            enum_json(&message.sensitivity)?,
            payload,
            message.observed_at.0
        ],
    )?;
    connection.execute(
        "DELETE FROM search_fts WHERE entity_type='http_message' AND entity_id=?1",
        [&message.message_id.0],
    )?;
    connection.execute(
        "INSERT INTO search_fts(entity_type,entity_id,content) VALUES('http_message',?1,?2)",
        params![message.message_id.0, message.redacted_view],
    )?;
    Ok(())
}

fn upsert_proxy_session(
    connection: &Connection,
    session: &ProxySession,
) -> Result<(), StorageError> {
    let payload = serde_json::to_string(session)?;
    connection.execute(
        "INSERT INTO proxy_sessions(proxy_session_id,project_id,scope_id,state,listen_port,created_at,ready_at,stopped_at,payload_json)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
         ON CONFLICT(proxy_session_id) DO UPDATE SET
           state=excluded.state,
           listen_port=excluded.listen_port,
           ready_at=excluded.ready_at,
           stopped_at=excluded.stopped_at,
           payload_json=excluded.payload_json",
        params![
            session.proxy_session_id.0,
            session.project_id.0,
            session.scope_id.0,
            enum_json(&session.state)?,
            session.listen_port.map(i64::from),
            session.created_at.0,
            session.ready_at.as_ref().map(|time| &time.0),
            session.stopped_at.as_ref().map(|time| &time.0),
            payload
        ],
    )?;
    Ok(())
}

fn upsert_import_row(
    connection: &Connection,
    record: &JobImportRecord,
) -> Result<(), StorageError> {
    let payload = serde_json::to_string(record)?;
    let source_artifacts = serde_json::to_string(&record.source_artifact_ids)?;
    let discovery_count = i64::try_from(record.discovery_count)
        .map_err(|_| StorageError::Domain("discovery count overflow".to_owned()))?;
    let http_message_count = i64::try_from(record.http_message_count)
        .map_err(|_| StorageError::Domain("HTTP message count overflow".to_owned()))?;
    connection.execute(
        "INSERT INTO job_imports(job_id,parser_id,parser_version,import_status,discovery_count,http_message_count,source_artifact_ids_json,error_summary,completed_at,payload_json)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
         ON CONFLICT(job_id) DO UPDATE SET
           parser_id=excluded.parser_id,
           parser_version=excluded.parser_version,
           import_status=excluded.import_status,
           discovery_count=excluded.discovery_count,
           http_message_count=excluded.http_message_count,
           source_artifact_ids_json=excluded.source_artifact_ids_json,
           error_summary=excluded.error_summary,
           completed_at=excluded.completed_at,
           payload_json=excluded.payload_json",
        params![
            record.job_id.0,
            record.parser_id,
            record.parser_version,
            enum_json(&record.import_status)?,
            discovery_count,
            http_message_count,
            source_artifacts,
            record.error_summary,
            record.completed_at.as_ref().map(|time| &time.0),
            payload
        ],
    )?;
    Ok(())
}

fn upsert_discovery(
    transaction: &Transaction<'_>,
    incoming: &Discovery,
    source_job_id: Option<&flagdeck_domain::JobId>,
) -> Result<Discovery, StorageError> {
    validate_discovery_payload(incoming)?;
    let existing = transaction
        .query_row(
            "SELECT payload_json FROM discoveries WHERE project_id=?1 AND canonical_key=?2",
            params![incoming.project_id.0, incoming.canonical_key],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let stored = if let Some(payload) = existing {
        let mut value: Discovery = serde_json::from_str(&payload)?;
        value.raw_value.clone_from(&incoming.raw_value);
        value.canonical_value.clone_from(&incoming.canonical_value);
        value.last_seen_at.clone_from(&incoming.last_seen_at);
        value
    } else {
        incoming.clone()
    };
    let payload = serde_json::to_string(&stored)?;
    transaction.execute(
        "INSERT INTO discoveries(discovery_id,project_id,kind,raw_value,canonical_value,canonical_key,first_seen_at,last_seen_at,payload_json)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
         ON CONFLICT(project_id,canonical_key) DO UPDATE SET
           raw_value=excluded.raw_value,
           canonical_value=excluded.canonical_value,
           last_seen_at=excluded.last_seen_at,
           payload_json=excluded.payload_json",
        params![
            stored.discovery_id.0,
            stored.project_id.0,
            enum_json(&stored.kind)?,
            stored.raw_value,
            stored.canonical_value,
            stored.canonical_key,
            stored.first_seen_at.0,
            stored.last_seen_at.0,
            payload
        ],
    )?;
    transaction.execute(
        "DELETE FROM search_fts WHERE entity_type='discovery' AND entity_id=?1",
        [&stored.discovery_id.0],
    )?;
    transaction.execute(
        "INSERT INTO search_fts(entity_type,entity_id,content) VALUES('discovery',?1,?2)",
        params![stored.discovery_id.0, stored.canonical_value],
    )?;
    if let Some(source_job_id) = source_job_id {
        transaction.execute(
            "INSERT OR IGNORE INTO discovery_observations(observation_id,discovery_id,source_job_id,observed_at,raw_value) VALUES(?1,?2,?3,?4,?5)",
            params![
                Uuid::new_v4().to_string(),
                stored.discovery_id.0,
                source_job_id.0,
                incoming.last_seen_at.0,
                incoming.raw_value
            ],
        )?;
    }
    Ok(stored)
}

fn validate_discovery_payload(incoming: &Discovery) -> Result<(), StorageError> {
    incoming
        .discovery_id
        .validate()
        .map_err(|error| StorageError::Domain(error.to_string()))?;
    incoming
        .project_id
        .validate()
        .map_err(|error| StorageError::Domain(error.to_string()))?;
    if incoming.raw_value.len() > 1024 * 1024
        || incoming.canonical_value.is_empty()
        || incoming.canonical_value.len() > 1024 * 1024
        || incoming.canonical_key.len() != 64
        || !incoming
            .canonical_key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(StorageError::Domain("invalid discovery".to_owned()));
    }
    Ok(())
}

fn validate_import_record(job: &Job, record: &JobImportRecord) -> Result<(), StorageError> {
    if job.job_id != record.job_id
        || job.import_status != record.import_status
        || record.parser_id.is_empty()
        || record.parser_id.len() > 256
        || record.parser_version.is_empty()
        || record.parser_version.len() > 64
        || record
            .error_summary
            .as_ref()
            .is_some_and(|value| value.len() > 1024)
    {
        return Err(StorageError::Domain("invalid import record".to_owned()));
    }
    let terminal = matches!(
        record.import_status,
        flagdeck_domain::ImportStatus::Imported
            | flagdeck_domain::ImportStatus::ParserFailed
            | flagdeck_domain::ImportStatus::Skipped
    );
    if terminal != record.completed_at.is_some() {
        return Err(StorageError::Domain("invalid import completion".to_owned()));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactWriteRequest {
    pub logical_name: String,
    pub mime: String,
    pub sensitivity: Sensitivity,
    pub export_policy: ExportPolicy,
    pub source_job_id: Option<flagdeck_domain::JobId>,
    pub source_message_id: Option<MessageId>,
    pub expected_size: Option<u64>,
    pub expected_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitFault {
    None,
    AfterFileSync,
    AfterRename,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryReport {
    pub interrupted_jobs: u64,
    pub interrupted_imports: u64,
    pub interrupted_proxy_sessions: u64,
    pub interrupted_campaigns: u64,
    pub staging_committed: u64,
    pub staging_orphaned: u64,
    pub committed_corrupt: u64,
    pub temporary_files_removed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageHealth {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotEvidence {
    pub relative_path: String,
    pub size: u64,
    pub sha256: String,
}

pub fn list_projects(workspaces_root: &Path) -> Result<Vec<ProjectSummary>, StorageError> {
    if !workspaces_root.exists() {
        return Ok(Vec::new());
    }
    let mut projects = Vec::new();
    for entry in fs::read_dir(workspaces_root)? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        if !metadata.is_dir() || metadata.is_symlink() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().into_owned();
        let Ok(project_id) = ProjectId::parse(id) else {
            continue;
        };
        let layout = WorkspaceLayout::for_project(workspaces_root, &project_id);
        if !layout.database.is_file() {
            continue;
        }
        let connection = open_reader_connection(&layout.database)?;
        if let Some(summary) = connection
            .query_row(
                "SELECT project_id,name,created_at,updated_at FROM projects WHERE project_id=?1",
                [&project_id.0],
                |row| {
                    Ok(ProjectSummary {
                        project_id: ProjectId(row.get(0)?),
                        name: row.get(1)?,
                        created_at: Timestamp(row.get(2)?),
                        updated_at: Timestamp(row.get(3)?),
                        read_only: false,
                        schema_version: SCHEMA_VERSION,
                    })
                },
            )
            .optional()?
        {
            projects.push(summary);
        }
    }
    projects.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    Ok(projects)
}

fn set_private_process_defaults() {
    umask(Mode::from_bits_truncate(0o077));
}

fn validate_project_name(name: &str) -> Result<(), StorageError> {
    if name.trim().is_empty() || name.len() > 256 || name.contains(['\0', '\n', '\r']) {
        return Err(StorageError::Domain("invalid project name".to_owned()));
    }
    Ok(())
}

fn validate_artifact_request(request: &ArtifactWriteRequest) -> Result<(), StorageError> {
    if request.logical_name.trim().is_empty()
        || request.logical_name.len() > 4096
        || request.logical_name.contains(['\0', '/', '\\'])
        || request.mime.trim().is_empty()
        || request.mime.len() > 256
    {
        return Err(StorageError::Domain("invalid artifact metadata".to_owned()));
    }
    if let Some(hash) = &request.expected_sha256
        && (hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(StorageError::Domain("invalid expected SHA-256".to_owned()));
    }
    Ok(())
}

fn parse_artifact_cursor(cursor: &str) -> Result<(String, String), StorageError> {
    let (created_at, artifact_id) = cursor
        .split_once(':')
        .ok_or_else(|| StorageError::Domain("invalid artifact cursor".to_owned()))?;
    if created_at.is_empty() || ArtifactId::parse(artifact_id).is_err() {
        return Err(StorageError::Domain("invalid artifact cursor".to_owned()));
    }
    Ok((created_at.to_owned(), artifact_id.to_owned()))
}

fn parse_job_cursor(cursor: &str) -> Result<(String, String), StorageError> {
    parse_entity_cursor(cursor, |value| flagdeck_domain::JobId::parse(value).is_ok())
}

fn parse_discovery_cursor(cursor: &str) -> Result<(String, String), StorageError> {
    parse_entity_cursor(cursor, |value| DiscoveryId::parse(value).is_ok())
}

fn parse_http_message_cursor(cursor: &str) -> Result<(String, String), StorageError> {
    parse_entity_cursor(cursor, |value| MessageId::parse(value).is_ok())
}

fn fts_literal_query(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn parse_entity_cursor(
    cursor: &str,
    valid_identifier: impl FnOnce(String) -> bool,
) -> Result<(String, String), StorageError> {
    let (timestamp, identifier) = cursor
        .split_once(':')
        .ok_or_else(|| StorageError::Domain("invalid page cursor".to_owned()))?;
    if timestamp.is_empty() || !valid_identifier(identifier.to_owned()) {
        return Err(StorageError::Domain("invalid page cursor".to_owned()));
    }
    Ok((timestamp.to_owned(), identifier.to_owned()))
}

fn create_private_dir(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(StorageError::InvalidLayout(path.display().to_string()));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(StorageError::InvalidLayout(path.display().to_string()));
            }
        }
        Err(error) => return Err(StorageError::Io(error)),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), StorageError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn ensure_descendant(root: &Path, path: &Path) -> Result<(), StorageError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| StorageError::InvalidLayout(path.display().to_string()))?;
    if relative.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(StorageError::InvalidLayout(path.display().to_string()));
    }
    Ok(())
}

fn open_writer_connection(path: &Path) -> Result<Connection, StorageError> {
    let connection = Connection::open(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    configure_writer(&connection)?;
    Ok(connection)
}

fn configure_writer(connection: &Connection) -> Result<(), StorageError> {
    if rusqlite::version_number() < MIN_SAFE_SQLITE_VERSION {
        return Err(StorageError::InvalidLayout(format!(
            "SQLite {} below minimum {}",
            rusqlite::version_number(),
            MIN_SAFE_SQLITE_VERSION
        )));
    }
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA foreign_keys=ON;
         PRAGMA trusted_schema=OFF;
         PRAGMA wal_autocheckpoint=0;",
    )?;
    Ok(())
}

fn open_reader_connection(path: &Path) -> Result<Connection, StorageError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys=ON;
         PRAGMA trusted_schema=OFF;
         PRAGMA query_only=ON;",
    )?;
    Ok(connection)
}

fn run_migrations(
    connection: &mut Connection,
    layout: &WorkspaceLayout,
    existed: bool,
) -> Result<(), StorageError> {
    let mut version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(StorageError::InvalidLayout(format!(
            "database schema {version} is newer than {SCHEMA_VERSION}"
        )));
    }
    if version == SCHEMA_VERSION {
        assert_schema_current(connection)?;
        return Ok(());
    }
    if existed && fs::metadata(&layout.database).is_ok_and(|metadata| metadata.len() > 0) {
        let backup_path = layout.backups.join(format!(
            "pre-migration-v{version}-{}.sqlite",
            Timestamp::now().0
        ));
        let mut destination = Connection::open(&backup_path)?;
        let backup = Backup::new(connection, &mut destination)?;
        backup.run_to_completion(64, Duration::from_millis(1), None)?;
        drop(backup);
        drop(destination);
        fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))?;
    }
    for (target_version, migration) in [
        (1, MIGRATION_V1),
        (2, MIGRATION_V2),
        (3, MIGRATION_V3),
        (4, MIGRATION_V4),
        (5, MIGRATION_V5),
        (6, MIGRATION_V6),
    ] {
        if version < target_version {
            apply_migration(connection, migration, target_version)?;
            version = target_version;
        }
    }
    assert_schema_current(connection)
}

fn apply_migration(
    connection: &mut Connection,
    sql: &str,
    target_version: u32,
) -> Result<(), StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(sql)?;
    transaction.execute(
        "INSERT INTO schema_migrations(version,applied_at,application_version) VALUES(?1,?2,?3)",
        params![
            target_version,
            Timestamp::now().0,
            env!("CARGO_PKG_VERSION")
        ],
    )?;
    transaction.pragma_update(None, "user_version", target_version)?;
    transaction.commit()?;
    Ok(())
}

fn assert_schema_current(connection: &Connection) -> Result<(), StorageError> {
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != SCHEMA_VERSION {
        return Err(StorageError::InvalidLayout(format!(
            "schema version {version}, expected {SCHEMA_VERSION}"
        )));
    }
    let fts5: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='search_fts'",
        [],
        |row| row.get(0),
    )?;
    if fts5 != 1 {
        return Err(StorageError::InvalidLayout("FTS5 gate failed".to_owned()));
    }
    let imports: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='job_imports'",
        [],
        |row| row.get(0),
    )?;
    if imports != 1 {
        return Err(StorageError::InvalidLayout(
            "job import schema gate failed".to_owned(),
        ));
    }
    let audit_events: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='audit_events'",
        [],
        |row| row.get(0),
    )?;
    if audit_events != 1 {
        return Err(StorageError::InvalidLayout(
            "audit event schema gate failed".to_owned(),
        ));
    }
    let proxy_sessions: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='proxy_sessions'",
        [],
        |row| row.get(0),
    )?;
    if proxy_sessions != 1 {
        return Err(StorageError::InvalidLayout(
            "proxy session schema gate failed".to_owned(),
        ));
    }
    let intruder_campaigns: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='intruder_campaigns'",
        [],
        |row| row.get(0),
    )?;
    if intruder_campaigns != 1 {
        return Err(StorageError::InvalidLayout(
            "intruder campaign schema gate failed".to_owned(),
        ));
    }
    Ok(())
}

fn recover_database_and_files(
    connection: &mut Connection,
    layout: &WorkspaceLayout,
) -> Result<RecoveryReport, StorageError> {
    let mut report = RecoveryReport::default();
    let now = Timestamp::now();
    report.interrupted_jobs = u64::try_from(connection.execute(
        "UPDATE jobs SET execution_status='interrupted',stopped_at=?1,payload_json=json_set(payload_json,'$.execution_status','interrupted','$.stopped_at',?1) WHERE execution_status IN ('starting','running','stopping')",
        [&now.0],
    )?)
    .unwrap_or(0);
    report.interrupted_imports = u64::try_from(connection.execute(
        "UPDATE jobs SET import_status='parser_failed',payload_json=json_set(payload_json,'$.import_status','parser_failed') WHERE import_status='importing'",
        [],
    )?)
    .unwrap_or(0);
    report.interrupted_proxy_sessions = u64::try_from(connection.execute(
        "UPDATE proxy_sessions SET state='interrupted',stopped_at=?1,payload_json=json_set(payload_json,'$.state','interrupted','$.stopped_at',?1,'$.error_summary','proxy session interrupted during restart recovery') WHERE state IN ('starting','ready','stopping')",
        [&now.0],
    )?)
    .unwrap_or(0);
    report.interrupted_campaigns = u64::try_from(connection.execute(
        "UPDATE intruder_campaigns SET state='interrupted',stopped_at=?1,payload_json=json_set(payload_json,'$.state','interrupted','$.stopped_at',?1,'$.error_summary','intruder campaign interrupted during restart recovery') WHERE state IN ('queued','running')",
        [&now.0],
    )?)
    .unwrap_or(0);
    connection.execute(
        "UPDATE job_imports SET import_status='parser_failed',error_summary='import interrupted during restart recovery',completed_at=?1,payload_json=json_set(payload_json,'$.import_status','parser_failed','$.error_summary','import interrupted during restart recovery','$.completed_at',?1) WHERE import_status='importing'",
        [&now.0],
    )?;

    let staging_rows = {
        let mut statement = connection.prepare(
            "SELECT artifact_id,staging_relative_path,blob_relative_path,sha256,size,payload_json FROM artifacts WHERE state='staging'",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (artifact_id, staging, blob, sha256, size, payload) in staging_rows {
        let size = size.and_then(|value| u64::try_from(value).ok());
        let recoverable = blob.as_ref().zip(sha256.as_ref()).zip(size).is_some_and(
            |((relative, expected_hash), expected_size)| {
                let path = layout.root.join(relative);
                path.is_file()
                    && fs::metadata(&path).is_ok_and(|metadata| metadata.len() == expected_size)
                    && sha256_file(&path).is_ok_and(|actual| &actual == expected_hash)
            },
        );
        if recoverable {
            let mut artifact: Artifact = serde_json::from_str(&payload)?;
            artifact.state = ArtifactState::Committed;
            artifact.integrity = IntegrityState::Verified;
            connection.execute(
                "UPDATE artifacts SET staging_relative_path=NULL,state='committed',integrity='verified',payload_json=?2 WHERE artifact_id=?1",
                params![artifact_id, serde_json::to_string(&artifact)?],
            )?;
            write_artifact_manifest(layout, &artifact)?;
            report.staging_committed += 1;
        } else {
            if let Some(relative) = staging {
                let path = layout.root.join(relative);
                if path.is_file() {
                    fs::remove_file(path)?;
                    report.temporary_files_removed += 1;
                }
            }
            connection.execute(
                "UPDATE artifacts SET state='orphaned',integrity='failed',payload_json=json_set(payload_json,'$.state','orphaned','$.integrity','failed') WHERE artifact_id=?1",
                [artifact_id],
            )?;
            report.staging_orphaned += 1;
        }
    }
    let committed_rows = {
        let mut statement = connection.prepare(
            "SELECT artifact_id,blob_relative_path,sha256,size FROM artifacts WHERE state='committed'",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (artifact_id, blob, hash, size) in committed_rows {
        let size = size.and_then(|value| u64::try_from(value).ok());
        let valid = blob.as_ref().zip(hash.as_ref()).zip(size).is_some_and(
            |((relative, expected_hash), expected_size)| {
                let path = layout.root.join(relative);
                path.is_file()
                    && fs::metadata(&path).is_ok_and(|metadata| metadata.len() == expected_size)
                    && sha256_file(&path).is_ok_and(|actual| &actual == expected_hash)
            },
        );
        if !valid {
            connection.execute(
                "UPDATE artifacts SET state='corrupt',integrity='failed',payload_json=json_set(payload_json,'$.state','corrupt','$.integrity','failed') WHERE artifact_id=?1",
                [artifact_id],
            )?;
            report.committed_corrupt += 1;
        }
    }
    for entry in fs::read_dir(&layout.tmp)? {
        let path = entry?.path();
        if path.is_file() {
            fs::remove_file(path)?;
            report.temporary_files_removed += 1;
        }
    }
    Ok(report)
}

fn insert_artifact_row(
    connection: &Connection,
    artifact: &Artifact,
    staging_relative: Option<&str>,
    payload: &str,
) -> Result<(), StorageError> {
    let size = artifact
        .size
        .map(i64::try_from)
        .transpose()
        .map_err(|_| StorageError::SizeMismatch)?;
    connection.execute(
        "INSERT INTO artifacts(artifact_id,relative_path,logical_name,staging_relative_path,blob_relative_path,sha256,size,mime,source_job_id,source_message_id,sensitivity,state,created_at,integrity,export_policy,payload_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
        params![artifact.artifact_id.0, artifact.relative_path, artifact.logical_name, staging_relative, artifact.blob_relative_path, artifact.sha256, size, artifact.mime, artifact.source_job_id.as_ref().map(|id| &id.0), artifact.source_message_id.as_ref().map(|id| &id.0), enum_json(&artifact.sensitivity)?, artifact.state.to_string(), artifact.created_at.0, enum_json(&artifact.integrity)?, enum_json(&artifact.export_policy)?, payload],
    )?;
    Ok(())
}

fn write_artifact_manifest(
    layout: &WorkspaceLayout,
    artifact: &Artifact,
) -> Result<(), StorageError> {
    let path = layout.root.join(&artifact.relative_path);
    ensure_descendant(&layout.root, &path)?;
    let temporary = layout
        .tmp
        .join(format!("{}.manifest", artifact.artifact_id.0));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(artifact)?)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    sync_directory(&layout.artifacts)
}

fn enum_json<T: Serialize>(value: &T) -> Result<String, StorageError> {
    let encoded = serde_json::to_string(value)?;
    Ok(encoded.trim_matches('"').to_owned())
}

fn integer_from_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::Domain("integer overflow".to_owned()))
}

fn sha256_file(path: &Path) -> Result<String, StorageError> {
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

fn current_process_start_ticks() -> Result<u64, StorageError> {
    let value = fs::read_to_string("/proc/self/stat")?;
    let end = value
        .rfind(") ")
        .ok_or_else(|| StorageError::InvalidLayout("malformed /proc/self/stat".to_owned()))?;
    value[end + 2..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| StorageError::InvalidLayout("short /proc/self/stat".to_owned()))?
        .parse()
        .map_err(|_| StorageError::InvalidLayout("invalid process start ticks".to_owned()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use flagdeck_domain::{
        BodyState, CommandSpecId, ConnectionMetadata, DnsResolutionSnapshot, ExecutionStatus,
        HttpSource, ImportStatus, JobId, MessageDirection, NetworkClass, PortRange,
        ProxyCaptureMode, ProxySession, ProxySessionId, ProxySessionState, RedirectPolicy,
        RepresentationKind, ResourceLimits, RiskLevel, ScopeId, SecretTransport, TargetScope,
    };
    use tempfile::TempDir;

    use super::*;

    fn create_store() -> (TempDir, ProjectStore, ProjectSummary) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("workspaces");
        let (store, summary) = ProjectStore::create(&root, "R1 fixture").unwrap();
        (temporary, store, summary)
    }

    fn artifact_request() -> ArtifactWriteRequest {
        ArtifactWriteRequest {
            logical_name: "note.txt".to_owned(),
            mime: "text/plain".to_owned(),
            sensitivity: Sensitivity::Normal,
            export_policy: ExportPolicy::Include,
            source_job_id: None,
            source_message_id: None,
            expected_size: Some(12),
            expected_sha256: None,
        }
    }

    fn command_spec() -> CommandSpec {
        CommandSpec {
            command_spec_id: CommandSpecId::new(),
            tool_id: "fixture".to_owned(),
            tool_version: "1".to_owned(),
            tool_sha256: "0".repeat(64),
            program: "/usr/bin/true".to_owned(),
            argv_exec: Vec::new(),
            argv_redacted: Vec::new(),
            env_exec: BTreeMap::new(),
            env_redacted: BTreeMap::new(),
            secret_transport: SecretTransport::None,
            secret_inputs: Vec::new(),
            cwd: "/tmp".to_owned(),
            environment_allowlist: Vec::new(),
            timeout_millis: 1000,
            stop_grace_millis: 100,
            expected_outputs: Vec::new(),
            risk_level: RiskLevel::L0,
            scope_id: None,
            sandbox_profile: "test".to_owned(),
            resource_limits: ResourceLimits::default(),
            network_isolation: "none".to_owned(),
        }
    }

    fn http_message(
        project_id: &ProjectId,
        observed_at: &str,
        source: HttpSource,
        host: &str,
        status_code: u16,
        redacted_view: &str,
    ) -> HttpMessage {
        HttpMessage {
            message_id: MessageId::new(),
            project_id: project_id.clone(),
            exchange_id: Some(format!("exchange-{observed_at}")),
            parent_message_id: None,
            source,
            representation_kind: RepresentationKind::Semantic,
            method: Some("GET".to_owned()),
            status_code: Some(status_code),
            scheme: "https".to_owned(),
            host: host.to_owned(),
            port: 443,
            authority: host.to_owned(),
            path: "/history".to_owned(),
            http_version: "1.1".to_owned(),
            headers: Vec::new(),
            trailers: Vec::new(),
            query: Vec::new(),
            form: Vec::new(),
            body_inline: None,
            body_artifact_id: None,
            wire_artifact_id: None,
            serializer_version: "flagdeck.semantic-http1/1".to_owned(),
            body_state: BodyState::Missing,
            declared_length: None,
            actual_length: 0,
            content_encoding: None,
            decoded_preview_state: "not_requested".to_owned(),
            direction: MessageDirection::Response,
            observed_at: Timestamp(observed_at.to_owned()),
            duration_millis: Some(10),
            connection: ConnectionMetadata {
                client_address: None,
                server_address: None,
                tls: true,
                tls_version: Some("TLSv1.3".to_owned()),
                certificate_sha256: None,
            },
            sensitivity: Sensitivity::Normal,
            redacted_view: redacted_view.to_owned(),
        }
    }

    fn write_test_zip(path: &Path, entries: &[(&str, &[u8], u32, CompressionMethod)]) {
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        let mut writer = ZipWriter::new(file);
        for (name, bytes, mode, compression) in entries {
            let options = SimpleFileOptions::default()
                .compression_method(*compression)
                .unix_permissions(*mode);
            writer.start_file(*name, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().sync_all().unwrap();
    }

    #[test]
    fn project_layout_database_and_lock_contract_pass() {
        let (_temporary, store, summary) = create_store();
        assert_eq!(summary.schema_version, SCHEMA_VERSION);
        assert_eq!(summary.schema_version, 6);
        store.layout().verify().unwrap();
        let health = store.health().unwrap();
        assert!(health.sqlite_version_number >= MIN_SAFE_SQLITE_VERSION);
        assert!(health.fts5_available);
        assert_eq!(health.quick_check, "ok");
        assert!(!health.read_only);
        assert_eq!(
            fs::metadata(&store.layout().database)
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }

    #[test]
    fn http_history_is_paged_structured_and_redacted_fts_searchable() {
        let (_temporary, store, summary) = create_store();
        let first = http_message(
            &summary.project_id,
            "1",
            HttpSource::Proxy,
            "alpha.test",
            200,
            "GET alpha.test /history needle <redacted>",
        );
        let second = http_message(
            &summary.project_id,
            "2",
            HttpSource::Repeater,
            "beta.test",
            404,
            "GET beta.test /history replay",
        );
        let third = http_message(
            &summary.project_id,
            "3",
            HttpSource::Proxy,
            "alpha.test",
            413,
            "GET alpha.test /history body-too-large",
        );
        for message in [&first, &second, &third] {
            store.save_http_message(message).unwrap();
        }

        let empty_filter = HttpMessageFilter::default();
        let (page, cursor) = store.list_http_messages(2, None, &empty_filter).unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].message_id, third.message_id);
        assert_eq!(page[1].message_id, second.message_id);
        let (tail, final_cursor) = store
            .list_http_messages(2, cursor.as_deref(), &empty_filter)
            .unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].message_id, first.message_id);
        assert!(final_cursor.is_none());

        let searchable = HttpMessageFilter {
            query: Some("needle".to_owned()),
            source: Some(HttpSource::Proxy),
            direction: Some(MessageDirection::Response),
            host: Some("ALPHA.TEST".to_owned()),
            status_code: Some(200),
        };
        let (matches, cursor) = store.list_http_messages(10, None, &searchable).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].message_id, first.message_id);
        assert!(cursor.is_none());

        let secret_filter = HttpMessageFilter {
            query: Some("actual-secret-value".to_owned()),
            ..HttpMessageFilter::default()
        };
        assert!(
            store
                .list_http_messages(10, None, &secret_filter)
                .unwrap()
                .0
                .is_empty()
        );
        assert_eq!(store.http_message(&second.message_id).unwrap(), second);
    }

    #[test]
    fn active_proxy_session_recovers_to_interrupted() {
        let (temporary, store, summary) = create_store();
        let root = temporary.path().join("workspaces");
        let scope = TargetScope {
            scope_id: ScopeId::new(),
            project_id: summary.project_id.clone(),
            schemes: vec!["http".to_owned()],
            exact_hosts: vec!["127.0.0.1".to_owned()],
            wildcard_subdomains: Vec::new(),
            cidrs: Vec::new(),
            ports: vec![PortRange {
                start: 38_001,
                end: 38_001,
            }],
            redirect_policy: RedirectPolicy::Deny,
            dns_change_policy: "deny".to_owned(),
            dns_snapshots: vec![DnsResolutionSnapshot {
                host: "127.0.0.1".to_owned(),
                addresses: vec!["127.0.0.1".to_owned()],
                resolved_at: Timestamp("1".to_owned()),
                peer_address: Some("127.0.0.1".to_owned()),
                rebinding_action: "pinned".to_owned(),
            }],
            network_class: NetworkClass::Loopback,
            created_at: Timestamp("1".to_owned()),
            updated_at: Timestamp("1".to_owned()),
        };
        store.save_target_scope(&scope).unwrap();
        let session = ProxySession {
            proxy_session_id: ProxySessionId::new(),
            project_id: summary.project_id.clone(),
            scope_id: scope.scope_id,
            state: ProxySessionState::Ready,
            capture_mode: ProxyCaptureMode::PassThrough,
            listen_host: "127.0.0.1".to_owned(),
            listen_port: Some(38_001),
            worker_pid: Some(42),
            systemd_unit: None,
            cgroup_path: None,
            invocation_id: None,
            ca_sha256: Some("a".repeat(64)),
            chrome_pid: None,
            ssl_insecure: false,
            created_at: Timestamp("1".to_owned()),
            ready_at: Some(Timestamp("2".to_owned())),
            stopped_at: None,
            error_summary: None,
        };
        let session_id = session.proxy_session_id.clone();
        store.save_proxy_session(&session).unwrap();
        drop(store);

        let recovered =
            ProjectStore::open(&root, &summary.project_id, OpenMode::ReadWrite).unwrap();
        assert_eq!(recovered.recovery_report().interrupted_proxy_sessions, 1);
        let session = recovered.proxy_session(&session_id).unwrap();
        assert_eq!(session.state, ProxySessionState::Interrupted);
        assert!(session.stopped_at.is_some());
        assert_eq!(
            session.error_summary.as_deref(),
            Some("proxy session interrupted during restart recovery")
        );
    }

    #[test]
    fn one_thousand_http_messages_survive_restart_and_cursor_paging() {
        let (temporary, store, summary) = create_store();
        let root = temporary.path().join("workspaces");
        for ordinal in 0..1_000 {
            let message = http_message(
                &summary.project_id,
                &format!("{ordinal:04}"),
                HttpSource::Proxy,
                "history.test",
                200,
                &format!("GET history.test /message/{ordinal}"),
            );
            store.save_http_message(&message).unwrap();
        }
        drop(store);
        let reopened = ProjectStore::open(&root, &summary.project_id, OpenMode::ReadWrite).unwrap();
        let mut cursor = None;
        let mut total = 0;
        loop {
            let (page, next) = reopened
                .list_http_messages(100, cursor.as_deref(), &HttpMessageFilter::default())
                .unwrap();
            total += page.len();
            cursor = next;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(total, 1_000);
    }

    #[test]
    fn second_writer_is_rejected_and_read_only_has_no_writer() {
        let (temporary, store, summary) = create_store();
        let root = temporary.path().join("workspaces");
        assert!(matches!(
            ProjectStore::open(&root, &summary.project_id, OpenMode::ReadWrite),
            Err(StorageError::WriterLocked)
        ));
        let read_only = ProjectStore::open(&root, &summary.project_id, OpenMode::ReadOnly).unwrap();
        assert!(read_only.health().unwrap().query_only);
        assert!(matches!(
            read_only.commit_artifact(&artifact_request(), "hello world!".as_bytes()),
            Err(StorageError::ReadOnly)
        ));
        drop(store);
    }

    #[test]
    fn artifact_commit_is_hashed_atomic_private_and_snapshot_uses_backup() {
        let (_temporary, store, _summary) = create_store();
        let artifact = store
            .commit_artifact(&artifact_request(), "hello world!".as_bytes())
            .unwrap();
        assert_eq!(artifact.state, ArtifactState::Committed);
        assert_eq!(artifact.size, Some(12));
        let bytes = store
            .read_artifact_range(&artifact.artifact_id, 0, PREVIEW_READ_LIMIT)
            .unwrap();
        assert_eq!(bytes, b"hello world!");
        let blob = store
            .layout()
            .root
            .join(artifact.blob_relative_path.as_ref().unwrap());
        assert_eq!(fs::metadata(blob).unwrap().permissions().mode() & 0o077, 0);
        let manifest = store.layout().root.join(&artifact.relative_path);
        assert_eq!(
            fs::metadata(manifest).unwrap().permissions().mode() & 0o077,
            0
        );
        let snapshot = store.create_database_snapshot().unwrap();
        assert_eq!(snapshot.sha256.len(), 64);
        assert!(store.layout().root.join(snapshot.relative_path).is_file());
    }

    #[test]
    fn recovery_handles_both_interrupted_artifact_commit_windows() {
        let (temporary, store, summary) = create_store();
        let root = temporary.path().join("workspaces");
        assert!(matches!(
            store.commit_artifact_with_fault(
                &artifact_request(),
                "hello world!".as_bytes(),
                CommitFault::AfterFileSync
            ),
            Err(StorageError::InjectedFault("file fsync"))
        ));
        drop(store);
        let recovered =
            ProjectStore::open(&root, &summary.project_id, OpenMode::ReadWrite).unwrap();
        assert_eq!(recovered.recovery_report().staging_orphaned, 1);
        assert!(
            fs::read_dir(&recovered.layout().tmp)
                .unwrap()
                .next()
                .is_none()
        );
        assert!(matches!(
            recovered.commit_artifact_with_fault(
                &artifact_request(),
                "hello world!".as_bytes(),
                CommitFault::AfterRename
            ),
            Err(StorageError::InjectedFault("blob rename"))
        ));
        drop(recovered);
        let recovered =
            ProjectStore::open(&root, &summary.project_id, OpenMode::ReadWrite).unwrap();
        assert_eq!(recovered.recovery_report().staging_committed, 1);
    }

    #[test]
    fn running_jobs_recover_to_interrupted() {
        let (temporary, store, summary) = create_store();
        let root = temporary.path().join("workspaces");
        let spec = command_spec();
        store.save_command_spec(&spec).unwrap();
        let job = Job {
            job_id: JobId::new(),
            parent_job_id: None,
            command_spec_id: spec.command_spec_id,
            execution_status: ExecutionStatus::Running,
            import_status: ImportStatus::Pending,
            created_at: Timestamp::now(),
            started_at: Some(Timestamp::now()),
            stopped_at: None,
            pid: Some(123),
            process_group_id: Some(123),
            process_start_ticks: Some(1),
            exit_code: None,
            exit_reason: None,
            systemd_unit: Some("fixture.service".to_owned()),
            cgroup_path: Some("/fixture".to_owned()),
            invocation_id: Some("fixture".to_owned()),
            supervisor_backend: Some(flagdeck_domain::SupervisorBackend::SystemdUserService),
            ownership_verified: true,
            cleanup_verified: false,
            residual_processes: 0,
            cancel_duration_millis: None,
            stdout_artifact_id: None,
            stderr_artifact_id: None,
            retry_count: 0,
            source_job_id: None,
        };
        store.save_job(&job).unwrap();
        drop(store);
        let recovered =
            ProjectStore::open(&root, &summary.project_id, OpenMode::ReadWrite).unwrap();
        assert_eq!(recovered.recovery_report().interrupted_jobs, 1);
    }

    #[test]
    fn import_state_observations_and_discovery_dedup_are_atomic() {
        let (_temporary, store, summary) = create_store();
        let spec = command_spec();
        store.save_command_spec(&spec).unwrap();
        let now = Timestamp::now();
        let mut job = Job {
            job_id: JobId::new(),
            parent_job_id: None,
            command_spec_id: spec.command_spec_id,
            execution_status: ExecutionStatus::Succeeded,
            import_status: ImportStatus::Importing,
            created_at: now.clone(),
            started_at: Some(now.clone()),
            stopped_at: Some(now.clone()),
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
            cleanup_verified: true,
            residual_processes: 0,
            cancel_duration_millis: None,
            stdout_artifact_id: None,
            stderr_artifact_id: None,
            retry_count: 0,
            source_job_id: None,
        };
        let mut record = JobImportRecord {
            job_id: job.job_id.clone(),
            parser_id: "fixture.parser".to_owned(),
            parser_version: "1".to_owned(),
            import_status: ImportStatus::Importing,
            discovery_count: 0,
            http_message_count: 0,
            source_artifact_ids: Vec::new(),
            error_summary: None,
            completed_at: None,
        };
        store.write_import_state(&job, &record).unwrap();
        let discovery = Discovery {
            discovery_id: DiscoveryId::new(),
            project_id: summary.project_id,
            kind: flagdeck_domain::DiscoveryKind::Path,
            raw_value: "/admin".to_owned(),
            canonical_value: "/admin".to_owned(),
            canonical_key: "a".repeat(64),
            first_seen_at: now.clone(),
            last_seen_at: now.clone(),
            status: "active".to_owned(),
            manual_labels: Vec::new(),
        };
        let duplicate = Discovery {
            discovery_id: DiscoveryId::new(),
            ..discovery.clone()
        };
        job.import_status = ImportStatus::Imported;
        record.import_status = ImportStatus::Imported;
        record.discovery_count = 2;
        record.completed_at = Some(Timestamp::now());
        store
            .complete_import(&job, &record, &[discovery, duplicate], &[])
            .unwrap();
        let (discoveries, cursor) = store.list_discoveries(100, None).unwrap();
        assert_eq!(discoveries.len(), 1);
        assert!(cursor.is_none());
        assert_eq!(store.job(&job.job_id).unwrap().import, Some(record));
        let connection = open_reader_connection(&store.layout().database).unwrap();
        let observations: i64 = connection
            .query_row("SELECT count(*) FROM discovery_observations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(observations, 1);
    }

    #[test]
    fn discovery_batches_are_project_bound_and_atomic() {
        let (_temporary, store, summary) = create_store();
        let now = Timestamp::now();
        let rows = (0..3)
            .map(|index| Discovery {
                discovery_id: DiscoveryId::new(),
                project_id: summary.project_id.clone(),
                kind: flagdeck_domain::DiscoveryKind::Path,
                raw_value: format!("/batch-{index}"),
                canonical_value: format!("/batch-{index}"),
                canonical_key: format!("{index:064x}"),
                first_seen_at: now.clone(),
                last_seen_at: now.clone(),
                status: "active".to_owned(),
                manual_labels: Vec::new(),
            })
            .collect();
        store.save_discoveries(rows).unwrap();
        assert_eq!(store.list_discoveries(100, None).unwrap().0.len(), 3);
        assert!(store.save_discoveries(Vec::new()).is_err());
    }

    #[test]
    fn importing_jobs_recover_to_parser_failed() {
        let (temporary, store, summary) = create_store();
        let root = temporary.path().join("workspaces");
        let spec = command_spec();
        store.save_command_spec(&spec).unwrap();
        let now = Timestamp::now();
        let job = Job {
            job_id: JobId::new(),
            parent_job_id: None,
            command_spec_id: spec.command_spec_id,
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
            cleanup_verified: true,
            residual_processes: 0,
            cancel_duration_millis: None,
            stdout_artifact_id: None,
            stderr_artifact_id: None,
            retry_count: 0,
            source_job_id: None,
        };
        let record = JobImportRecord {
            job_id: job.job_id.clone(),
            parser_id: "fixture.parser".to_owned(),
            parser_version: "1".to_owned(),
            import_status: ImportStatus::Importing,
            discovery_count: 0,
            http_message_count: 0,
            source_artifact_ids: Vec::new(),
            error_summary: None,
            completed_at: None,
        };
        store.write_import_state(&job, &record).unwrap();
        let job_id = job.job_id;
        drop(store);
        let recovered =
            ProjectStore::open(&root, &summary.project_id, OpenMode::ReadWrite).unwrap();
        assert_eq!(recovered.recovery_report().interrupted_imports, 1);
        let stored = recovered.job(&job_id).unwrap();
        assert_eq!(stored.job.execution_status, ExecutionStatus::Succeeded);
        assert_eq!(stored.job.import_status, ImportStatus::ParserFailed);
        assert_eq!(
            stored.import.unwrap().error_summary.as_deref(),
            Some("import interrupted during restart recovery")
        );
    }

    #[test]
    fn dictionary_index_is_private_bounded_and_prefix_searchable() {
        let (_temporary, store, summary) = create_store();
        let body = b"admin\napi\nalpha\n";
        let artifact = store
            .commit_artifact(
                &ArtifactWriteRequest {
                    logical_name: "paths.txt".to_owned(),
                    mime: "text/plain; charset=utf-8".to_owned(),
                    sensitivity: Sensitivity::Normal,
                    export_policy: ExportPolicy::Include,
                    source_job_id: None,
                    source_message_id: None,
                    expected_size: Some(u64::try_from(body.len()).unwrap()),
                    expected_sha256: None,
                },
                body.as_slice(),
            )
            .unwrap();
        let dictionary = DictionaryIndex {
            dictionary_id: DictionaryId::new(),
            project_id: summary.project_id,
            artifact_id: artifact.artifact_id,
            name: "paths".to_owned(),
            sha256: artifact.sha256.unwrap(),
            size: artifact.size.unwrap(),
            term_count: 3,
            created_at: Timestamp::now(),
        };
        store
            .index_dictionary(
                &dictionary,
                &["admin".to_owned(), "api".to_owned(), "alpha".to_owned()],
            )
            .unwrap();
        assert_eq!(store.list_dictionaries().unwrap(), vec![dictionary.clone()]);
        assert_eq!(
            store
                .search_dictionary(&dictionary.dictionary_id, "a", 10)
                .unwrap(),
            vec!["admin", "alpha", "api"]
        );
        assert!(
            store
                .search_dictionary(&dictionary.dictionary_id, "", 10)
                .is_err()
        );
    }

    fn request_message(project_id: &ProjectId, host: &str) -> HttpMessage {
        let mut message = http_message(project_id, "1", HttpSource::Repeater, host, 200, "req");
        message.direction = MessageDirection::Request;
        message.status_code = None;
        message.method = Some("POST".to_owned());
        message
    }

    fn loopback_scope(project_id: &ProjectId) -> TargetScope {
        TargetScope {
            scope_id: ScopeId::new(),
            project_id: project_id.clone(),
            schemes: vec!["https".to_owned()],
            exact_hosts: vec!["127.0.0.1".to_owned()],
            wildcard_subdomains: Vec::new(),
            cidrs: Vec::new(),
            ports: vec![PortRange {
                start: 443,
                end: 443,
            }],
            redirect_policy: RedirectPolicy::Deny,
            dns_change_policy: "deny".to_owned(),
            dns_snapshots: Vec::new(),
            network_class: NetworkClass::Loopback,
            created_at: Timestamp("1".to_owned()),
            updated_at: Timestamp("1".to_owned()),
        }
    }

    fn queued_campaign(
        project_id: &ProjectId,
        scope_id: &ScopeId,
        parent: &MessageId,
    ) -> IntruderCampaign {
        IntruderCampaign {
            intruder_campaign_id: IntruderCampaignId::new(),
            project_id: project_id.clone(),
            scope_id: scope_id.clone(),
            parent_message_id: parent.clone(),
            campaign_kind: flagdeck_domain::IntruderCampaignKind::Intruder,
            attack_mode: flagdeck_domain::IntruderAttackMode::Sniper,
            state: flagdeck_domain::IntruderCampaignState::Queued,
            positions: vec![flagdeck_domain::PayloadPosition {
                location: flagdeck_domain::PayloadLocation::ByteRange,
                name: None,
                occurrence: 0,
                start: Some(0),
                end: Some(4),
            }],
            dictionary_ids: vec![DictionaryId::new()],
            global_rate_per_second: 10,
            target_rate_per_second: 5,
            total_attempts: 3,
            next_ordinal: 1,
            completed_attempts: 1,
            failed_attempts: 0,
            state_macro_json: None,
            created_at: Timestamp("1".to_owned()),
            started_at: Some(Timestamp("2".to_owned())),
            stopped_at: None,
            error_summary: None,
        }
    }

    #[test]
    fn campaign_attempt_statechain_persist_and_recover_to_interrupted() {
        let (temporary, store, summary) = create_store();
        let scope = loopback_scope(&summary.project_id);
        store.save_target_scope(&scope).unwrap();
        let parent = request_message(&summary.project_id, "127.0.0.1");
        store.save_http_message(&parent).unwrap();
        let campaign = queued_campaign(&summary.project_id, &scope.scope_id, &parent.message_id);
        store.save_intruder_campaign(&campaign).unwrap();
        let mut attempt = IntruderAttempt {
            intruder_attempt_id: IntruderAttemptId::new(),
            intruder_campaign_id: campaign.intruder_campaign_id.clone(),
            project_id: summary.project_id.clone(),
            ordinal: 0,
            payload_sha256: vec!["a".repeat(64)],
            payload_preview: vec!["preview".to_owned()],
            state: flagdeck_domain::IntruderAttemptState::Succeeded,
            request_message_id: None,
            response_message_id: None,
            response_status: Some(200),
            response_length: Some(12),
            duration_millis: Some(7),
            evidence_artifact_id: None,
            state_chain_run_id: None,
            verification_summary: None,
            error_summary: None,
            created_at: Timestamp("3".to_owned()),
        };
        store.save_intruder_attempt(&attempt).unwrap();
        let run = StateChainRun {
            state_chain_run_id: flagdeck_domain::StateChainRunId::new(),
            project_id: summary.project_id.clone(),
            intruder_attempt_id: attempt.intruder_attempt_id.clone(),
            steps: vec![flagdeck_domain::StateChainStepEvidence {
                name: "csrf".to_owned(),
                request_message_id: None,
                response_message_id: None,
                outcome: "succeeded".to_owned(),
                extracted_variables: vec!["token".to_owned()],
            }],
            created_at: Timestamp("4".to_owned()),
        };
        store.save_state_chain_run(&run).unwrap();
        attempt.state_chain_run_id = Some(run.state_chain_run_id.clone());
        attempt.verification_summary = Some("state chain completed".to_owned());
        store.save_intruder_attempt(&attempt).unwrap();

        let mut duplicate_ordinal = attempt.clone();
        duplicate_ordinal.intruder_attempt_id = IntruderAttemptId::new();
        assert!(matches!(
            store.save_intruder_attempt(&duplicate_ordinal),
            Err(StorageError::Sqlite(_))
        ));
        drop(store);

        let reopened = ProjectStore::open(
            &temporary.path().join("workspaces"),
            &summary.project_id,
            OpenMode::ReadWrite,
        )
        .unwrap();
        assert_eq!(reopened.recovery_report().interrupted_campaigns, 1);
        let recovered = reopened
            .intruder_campaign(&campaign.intruder_campaign_id)
            .unwrap();
        assert_eq!(
            recovered.state,
            flagdeck_domain::IntruderCampaignState::Interrupted
        );
        assert_eq!(recovered.next_ordinal, 1);
        let attempts = reopened
            .list_intruder_attempts(&campaign.intruder_campaign_id, 10, None)
            .unwrap();
        assert_eq!(attempts, vec![attempt.clone()]);
        let recovered_attempt = reopened
            .intruder_attempt(&attempt.intruder_attempt_id)
            .unwrap();
        assert_eq!(recovered_attempt.response_status, Some(200));
        assert_eq!(
            recovered_attempt.state_chain_run_id,
            Some(run.state_chain_run_id.clone())
        );
        assert_eq!(
            reopened.state_chain_run(&run.state_chain_run_id).unwrap(),
            run
        );
    }

    #[test]
    fn dictionary_terms_page_streams_without_full_load() {
        let (_temporary, store, summary) = create_store();
        let body = b"a0\na1\na2\na3\na4\n";
        let artifact = store
            .commit_artifact(
                &ArtifactWriteRequest {
                    logical_name: "stream.txt".to_owned(),
                    mime: "text/plain".to_owned(),
                    sensitivity: Sensitivity::Normal,
                    export_policy: ExportPolicy::Include,
                    source_job_id: None,
                    source_message_id: None,
                    expected_size: Some(u64::try_from(body.len()).unwrap()),
                    expected_sha256: None,
                },
                body.as_slice(),
            )
            .unwrap();
        let dictionary = DictionaryIndex {
            dictionary_id: DictionaryId::new(),
            project_id: summary.project_id,
            artifact_id: artifact.artifact_id,
            name: "stream".to_owned(),
            sha256: artifact.sha256.unwrap(),
            size: artifact.size.unwrap(),
            term_count: 5,
            created_at: Timestamp::now(),
        };
        let terms = ["a0", "a1", "a2", "a3", "a4"].map(str::to_owned).to_vec();
        store.index_dictionary(&dictionary, &terms).unwrap();
        assert_eq!(
            store
                .dictionary_terms_page(&dictionary.dictionary_id, 0, 2)
                .unwrap(),
            vec!["a0", "a1"]
        );
        assert_eq!(
            store
                .dictionary_terms_page(&dictionary.dictionary_id, 2, 2)
                .unwrap(),
            vec!["a2", "a3"]
        );
        assert_eq!(
            store
                .dictionary_terms_page(&dictionary.dictionary_id, 4, 2)
                .unwrap(),
            vec!["a4"]
        );
    }

    #[test]
    fn backup_manifest_export_import_roundtrip_preserves_hashes_and_index() {
        let (temporary, store, summary) = create_store();
        let body = b"admin\napi\n";
        let artifact = store
            .commit_artifact(
                &ArtifactWriteRequest {
                    logical_name: "exported-paths.txt".to_owned(),
                    mime: "text/plain".to_owned(),
                    sensitivity: Sensitivity::Normal,
                    export_policy: ExportPolicy::Include,
                    source_job_id: None,
                    source_message_id: None,
                    expected_size: Some(u64::try_from(body.len()).unwrap()),
                    expected_sha256: None,
                },
                body.as_slice(),
            )
            .unwrap();
        let dictionary = DictionaryIndex {
            dictionary_id: DictionaryId::new(),
            project_id: summary.project_id.clone(),
            artifact_id: artifact.artifact_id.clone(),
            name: "exported-paths".to_owned(),
            sha256: artifact.sha256.clone().unwrap(),
            size: artifact.size.unwrap(),
            term_count: 2,
            created_at: Timestamp::now(),
        };
        store
            .index_dictionary(&dictionary, &["admin".to_owned(), "api".to_owned()])
            .unwrap();
        let export = store.export_project(false).unwrap();
        let archive = store.layout().exports.join(&export.archive_name);
        assert_eq!(sha256_file(&archive).unwrap(), export.sha256);
        assert_eq!(
            fs::metadata(&archive).unwrap().permissions().mode() & 0o077,
            0
        );
        let import_root = temporary.path().join("imported-workspaces");
        let imported = ProjectStore::import_project_archive(&import_root, &archive).unwrap();
        assert_eq!(imported.project.project_id, summary.project_id);
        assert_eq!(imported.archive_sha256, export.sha256);
        let reopened = ProjectStore::open(
            &import_root,
            &imported.project.project_id,
            OpenMode::ReadWrite,
        )
        .unwrap();
        assert_eq!(
            reopened.list_dictionaries().unwrap(),
            vec![dictionary.clone()]
        );
        assert_eq!(
            reopened
                .search_dictionary(&dictionary.dictionary_id, "ap", 10)
                .unwrap(),
            vec!["api"]
        );
        assert_eq!(
            reopened
                .read_artifact_range(&artifact.artifact_id, 0, body.len())
                .unwrap(),
            body
        );
        assert!(matches!(
            ProjectStore::import_project_archive(&import_root, &archive),
            Err(StorageError::ProjectExists)
        ));
    }

    #[test]
    fn sensitive_export_requires_explicit_confirmation() {
        let (_temporary, store, _summary) = create_store();
        let mut request = artifact_request();
        request.sensitivity = Sensitivity::SensitiveEvidence;
        request.export_policy = ExportPolicy::ConfirmSensitive;
        store
            .commit_artifact(&request, b"hello world!".as_slice())
            .unwrap();
        assert!(matches!(
            store.export_project(false),
            Err(StorageError::SensitiveExportConfirmationRequired)
        ));
        let confirmed = store.export_project(true).unwrap();
        assert_eq!(confirmed.included_artifacts, 1);
    }

    #[test]
    fn archive_preflight_rejects_zip_slip_symlink_limits_ratio_and_hash_failure() {
        let temporary = tempfile::tempdir().unwrap();
        let zip_slip = temporary.path().join("zip-slip.zip");
        write_test_zip(
            &zip_slip,
            &[("../escape", b"x", 0o600, CompressionMethod::Stored)],
        );
        assert!(matches!(
            validate_project_archive(&zip_slip, ArchiveLimits::default()),
            Err(StorageError::InvalidArchive(_))
        ));
        assert!(!temporary.path().join("escape").exists());

        let symlink = temporary.path().join("symlink.zip");
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&symlink)
            .unwrap();
        let mut writer = ZipWriter::new(file);
        writer
            .add_symlink(
                "project.toml",
                "target",
                SimpleFileOptions::default().unix_permissions(0o777),
            )
            .unwrap();
        writer.finish().unwrap().sync_all().unwrap();
        assert!(matches!(
            validate_project_archive(&symlink, ArchiveLimits::default()),
            Err(StorageError::InvalidArchive(_))
        ));

        let bounded = temporary.path().join("bounded.zip");
        write_test_zip(
            &bounded,
            &[
                ("one", b"12", 0o600, CompressionMethod::Stored),
                ("two", b"34", 0o600, CompressionMethod::Stored),
            ],
        );
        assert!(matches!(
            validate_project_archive(
                &bounded,
                ArchiveLimits {
                    maximum_files: 1,
                    ..ArchiveLimits::default()
                }
            ),
            Err(StorageError::ArchiveLimit)
        ));
        assert!(matches!(
            validate_project_archive(
                &bounded,
                ArchiveLimits {
                    maximum_total_bytes: 3,
                    ..ArchiveLimits::default()
                }
            ),
            Err(StorageError::ArchiveLimit)
        ));

        let compressed = temporary.path().join("compressed.zip");
        let zeros = vec![0_u8; 128 * 1024];
        write_test_zip(
            &compressed,
            &[(
                "project.toml",
                zeros.as_slice(),
                0o600,
                CompressionMethod::Deflated,
            )],
        );
        assert!(matches!(
            validate_project_archive(
                &compressed,
                ArchiveLimits {
                    maximum_compression_ratio: 2,
                    ..ArchiveLimits::default()
                }
            ),
            Err(StorageError::ArchiveLimit)
        ));

        let (_source_root, store, _summary) = create_store();
        store
            .commit_artifact(&artifact_request(), b"hello world!".as_slice())
            .unwrap();
        let export = store.export_project(false).unwrap();
        let valid = store.layout().exports.join(export.archive_name);
        let tampered = temporary.path().join("tampered.zip");
        let mut input = ZipArchive::new(File::open(valid).unwrap()).unwrap();
        let output = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&tampered)
            .unwrap();
        let mut writer = ZipWriter::new(output);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o600);
        for index in 0..input.len() {
            let mut source = input.by_index(index).unwrap();
            let name = source.name().to_owned();
            let mut bytes = Vec::new();
            source.read_to_end(&mut bytes).unwrap();
            if name.starts_with("blobs/") && !bytes.is_empty() {
                bytes[0] ^= 1;
            }
            writer.start_file(name, options).unwrap();
            writer.write_all(&bytes).unwrap();
        }
        writer.finish().unwrap().sync_all().unwrap();
        assert!(matches!(
            validate_project_archive(&tampered, ArchiveLimits::default()),
            Err(StorageError::HashMismatch)
        ));
    }

    #[test]
    fn version_one_database_migrates_to_version_six_with_backup() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("workspaces");
        create_private_dir(&root).unwrap();
        let project_id = ProjectId::new();
        let layout = WorkspaceLayout::for_project(&root, &project_id);
        layout.create().unwrap();
        let mut connection = open_writer_connection(&layout.database).unwrap();
        apply_migration(&mut connection, MIGRATION_V1, 1).unwrap();
        run_migrations(&mut connection, &layout, true).unwrap();
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(version, 6);
        for table in [
            "intruder_campaigns",
            "intruder_attempts",
            "state_chain_runs",
        ] {
            let exists: i64 = connection
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "missing table {table}");
        }
        assert!(fs::read_dir(&layout.backups).unwrap().next().is_some());
    }

    #[test]
    fn adapter_entities_and_l3_audit_survive_restart() {
        let (temporary, store, summary) = create_store();
        let now = Timestamp::now();
        let entity = AdapterEntity {
            adapter_entity_id: flagdeck_domain::AdapterEntityId::new(),
            project_id: Some(summary.project_id.clone()),
            adapter_id: "metasploit".to_owned(),
            adapter_version: "1.0.0".to_owned(),
            protocol_version: flagdeck_domain::ADAPTER_PROTOCOL.to_owned(),
            entity_kind: "session".to_owned(),
            external_id: "1".to_owned(),
            parent_entity_id: None,
            source_job_id: None,
            ownership: flagdeck_domain::AdapterOwnership::Managed,
            state_schema_version: 1,
            summary_json: r#"{"state":"active"}"#.to_owned(),
            snapshot_artifact_id: None,
            sensitivity: Sensitivity::SensitiveEvidence,
            redacted_view: "managed session 1".to_owned(),
            created_at: now.clone(),
            synced_at: now.clone(),
            terminated_at: None,
        };
        store.save_adapter_entity(&entity).unwrap();
        let event = AuditEvent {
            audit_event_id: flagdeck_domain::AuditEventId::new(),
            project_id: summary.project_id.clone(),
            adapter_id: Some("metasploit".to_owned()),
            action: "metasploit.session.command".to_owned(),
            risk_level: flagdeck_domain::RiskLevel::L3,
            outcome: "allowed".to_owned(),
            target_summary: "session 1".to_owned(),
            details_json: r#"{"command_sha256":"00"}"#.to_owned(),
            created_at: now,
        };
        store.save_audit_event(&event).unwrap();
        drop(store);
        let reopened = ProjectStore::open(
            &temporary.path().join("workspaces"),
            &summary.project_id,
            OpenMode::ReadWrite,
        )
        .unwrap();
        assert_eq!(
            reopened
                .adapter_entity(&entity.adapter_entity_id)
                .unwrap()
                .external_id,
            "1"
        );
        assert_eq!(
            reopened
                .list_adapter_entities("metasploit", Some("session"), 10)
                .unwrap(),
            vec![entity]
        );
        assert_eq!(reopened.list_audit_events(10).unwrap(), vec![event]);
    }

    #[test]
    fn failed_migration_transaction_rolls_back() {
        let temporary = tempfile::tempdir().unwrap();
        let database = temporary.path().join("migration.sqlite");
        let mut connection = open_writer_connection(&database).unwrap();
        let result = apply_migration(
            &mut connection,
            "CREATE TABLE partial(id INTEGER); THIS IS INVALID SQL;",
            1,
        );
        assert!(result.is_err());
        let partial: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='partial'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(partial, 0);
        assert_eq!(version, 0);
    }

    #[test]
    fn private_directory_creation_rejects_a_symlink() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target");
        let link = temporary.path().join("workspace-link");
        fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();
        assert!(matches!(
            create_private_dir(&link),
            Err(StorageError::InvalidLayout(_))
        ));
    }
}
