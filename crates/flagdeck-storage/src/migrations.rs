//! `SQLite` 迁移：V1 到 V6 的 DDL 常量、迁移执行器与 schema 版本闸门。
//! 从原本单文件的 storage crate 里析出，把「库结构」这一关注点集中到一处。
//! `SCHEMA_VERSION` 仍在 crate 根（被多处引用），这里经 `crate::SCHEMA_VERSION` 使用。

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use flagdeck_domain::Timestamp;
use rusqlite::backup::Backup;
use rusqlite::{Connection, TransactionBehavior, params};

use crate::{SCHEMA_VERSION, StorageError, WorkspaceLayout};

pub(crate) const MIGRATION_V1: &str = r"
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

pub(crate) fn run_migrations(
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

pub(crate) fn apply_migration(
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

pub(crate) fn assert_schema_current(connection: &Connection) -> Result<(), StorageError> {
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
