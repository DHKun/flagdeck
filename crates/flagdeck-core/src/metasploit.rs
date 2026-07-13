#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flagdeck_adapter_host::{AdapterHost, AdapterHostConfig, AdapterWorker, HostError};
use flagdeck_adapter_protocol::{
    AdapterPermissions, InitializeParams, JSON_RPC_VERSION, JsonRpcRequest, RequestMetadata,
};
use flagdeck_domain::{
    ADAPTER_PROTOCOL, AdapterEntity, AdapterEntityId, AdapterOwnership, Artifact, ArtifactId,
    AuditEvent, AuditEventId, ExportPolicy, ProjectId, RiskLevel, Sensitivity, TargetScope,
    Timestamp, Validate,
};
use flagdeck_storage::{ArtifactWriteRequest, ProjectStore, StorageError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use thiserror::Error;
use tokio::sync::Mutex;
use ts_rs::TS;
use uuid::Uuid;

const ADAPTER_ID: &str = "metasploit";
const ADAPTER_VERSION: &str = "1.0.0";
const ENTITY_SCHEMA_VERSION: u32 = 1;
const MAX_MODULE_QUERY_BYTES: usize = 512;
const MAX_OPTION_COUNT: usize = 256;
const MAX_OPTION_VALUE_BYTES: usize = 64 * 1024;
const MAX_CONSOLE_COMMAND_BYTES: usize = 16 * 1024;

#[derive(Debug, Error)]
pub enum MetasploitError {
    #[error("Metasploit Adapter is unavailable")]
    Unavailable,
    #[error("a Metasploit lifecycle is already active")]
    AlreadyActive,
    #[error("no Metasploit lifecycle is active")]
    Inactive,
    #[error("the active Metasploit lifecycle belongs to another project")]
    ProjectMismatch,
    #[error("Metasploit request failed validation")]
    InvalidRequest,
    #[error("Metasploit target is outside TargetScope")]
    ScopeViolation,
    #[error("L3 confirmation is missing or invalid")]
    ConfirmationRequired,
    #[error("active sessions require confirmed termination")]
    ActiveSessions,
    #[error("Adapter response failed validation")]
    AdapterContract,
    #[error("Adapter rejected the request: {0}")]
    AdapterRejected(String),
    #[error("Adapter host failed: {0}")]
    Host(#[from] HostError),
    #[error("storage failed: {0}")]
    Storage(#[from] StorageError),
    #[error("I/O failed")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum MetasploitLifecycleState {
    Stopped,
    Ready,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MetasploitStatus {
    pub state: MetasploitLifecycleState,
    pub project_id: Option<ProjectId>,
    pub workspace: Option<String>,
    pub listen_port: Option<u16>,
    pub certificate_sha256: Option<String>,
    pub framework_version: Option<String>,
    pub supervisor: Option<String>,
    pub managed_jobs: usize,
    pub managed_consoles: usize,
    pub managed_sessions: usize,
    pub active_sessions: usize,
    pub isolation_level: String,
}

impl MetasploitStatus {
    fn stopped() -> Self {
        Self {
            state: MetasploitLifecycleState::Stopped,
            project_id: None,
            workspace: None,
            listen_port: None,
            certificate_sha256: None,
            framework_version: None,
            supervisor: None,
            managed_jobs: 0,
            managed_consoles: 0,
            managed_sessions: 0,
            active_sessions: 0,
            isolation_level: "input_scope_gate_and_audit".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StartMetasploitRequest {
    pub project_id: ProjectId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StopMetasploitRequest {
    pub project_id: ProjectId,
    pub confirmation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SearchMetasploitModulesRequest {
    pub project_id: ProjectId,
    pub query: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MetasploitModuleSummary {
    pub module_type: String,
    pub fullname: String,
    pub name: String,
    pub rank: String,
    pub disclosure_date: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MetasploitModuleOption {
    pub name: String,
    pub option_type: String,
    pub required: bool,
    pub advanced: bool,
    #[ts(type = "unknown | null")]
    pub default: Option<Value>,
    pub description: String,
    pub enums: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct GetMetasploitOptionsRequest {
    pub project_id: ProjectId,
    pub module_type: String,
    pub fullname: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum MetasploitExecutionKind {
    Check,
    Run,
    Exploit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ExecuteMetasploitModuleRequest {
    pub project_id: ProjectId,
    pub scope_id: flagdeck_domain::ScopeId,
    pub module_type: String,
    pub fullname: String,
    pub execution_kind: MetasploitExecutionKind,
    #[ts(type = "Record<string, unknown>")]
    pub options: BTreeMap<String, Value>,
    pub confirmation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MetasploitExecutionResult {
    pub job_entity: Option<AdapterEntity>,
    pub execution_uuid: Option<String>,
    pub audit_event: AuditEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MetasploitEntityPage {
    pub items: Vec<AdapterEntity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MetasploitEntityRequest {
    pub project_id: ProjectId,
    pub external_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StopMetasploitEntityRequest {
    pub project_id: ProjectId,
    pub entity_kind: String,
    pub external_id: String,
    pub confirmation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MetasploitConsoleCommandRequest {
    pub project_id: ProjectId,
    pub console_id: String,
    pub command: String,
    pub confirmation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MetasploitSessionCommandRequest {
    pub project_id: ProjectId,
    pub session_id: String,
    pub command: String,
    pub confirmation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MetasploitTranscriptResult {
    pub entity: AdapterEntity,
    pub artifact: Artifact,
    pub redacted: String,
}

struct ActiveMetasploit {
    project_id: ProjectId,
    worker: AdapterWorker,
    status: MetasploitStatus,
    lifecycle_entity_id: AdapterEntityId,
}

pub struct MetasploitWorkbench {
    adapter_program: Option<PathBuf>,
    launcher_program: Option<PathBuf>,
    active: Mutex<Option<ActiveMetasploit>>,
}

impl MetasploitWorkbench {
    #[must_use]
    pub fn new(adapter_program: Option<PathBuf>, launcher_program: Option<PathBuf>) -> Self {
        Self {
            adapter_program,
            launcher_program,
            active: Mutex::new(None),
        }
    }

    pub fn has_active(&self) -> bool {
        self.active.try_lock().map_or(true, |value| value.is_some())
    }

    pub async fn start(
        &self,
        store: &ProjectStore,
        request: &StartMetasploitRequest,
    ) -> Result<MetasploitStatus, MetasploitError> {
        request
            .project_id
            .validate()
            .map_err(|_| MetasploitError::InvalidRequest)?;
        let mut active = self.active.lock().await;
        if active.is_some() {
            return Err(MetasploitError::AlreadyActive);
        }
        let adapter_program = canonical_executable(
            self.adapter_program
                .as_deref()
                .ok_or(MetasploitError::Unavailable)?,
        )?;
        let launcher_program = canonical_executable(
            self.launcher_program
                .as_deref()
                .ok_or(MetasploitError::Unavailable)?,
        )?;
        let runtime_root = store.layout().metasploit.join("runtime");
        fs::create_dir_all(&runtime_root)?;
        set_private_directory(&runtime_root)?;
        let mut config = AdapterHostConfig::new(adapter_program, &runtime_root);
        config.request_timeout = Duration::from_secs(40);
        let host = AdapterHost::new(config)?;
        let mut worker = host.spawn()?;
        let description =
            adapter_call(&mut worker, "describe", &request.project_id, json!({})).await?;
        validate_description(&description)?;
        let initialize = InitializeParams {
            protocol: ADAPTER_PROTOCOL.to_owned(),
            project_id: request.project_id.clone(),
            capabilities: vec![
                "exploit_framework".to_owned(),
                "console".to_owned(),
                "sessions".to_owned(),
            ],
            permissions: AdapterPermissions {
                network: vec!["dynamic_loopback_rpc".to_owned()],
                project_artifacts: "write_sensitive".to_owned(),
                secrets: "runtime_memory_only".to_owned(),
            },
        };
        initialize
            .validate()
            .map_err(|_| MetasploitError::AdapterContract)?;
        adapter_call(
            &mut worker,
            "initialize",
            &request.project_id,
            json!({
                "project_id": request.project_id,
                "workspace_root": store.layout().metasploit,
                "launcher_path": launcher_program,
                "protocol_initialize": initialize,
            }),
        )
        .await?;
        let result = match adapter_call(
            &mut worker,
            "start_lifecycle",
            &request.project_id,
            json!({}),
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                let _ = worker.shutdown().await;
                return Err(error);
            }
        };
        let status = parse_status(&result, &request.project_id)?;
        let lifecycle = entity(
            &request.project_id,
            "lifecycle",
            &request.project_id.0,
            None,
            Sensitivity::SensitiveEvidence,
            &result,
            "Metasploit RPC lifecycle ready",
        )?;
        store.save_adapter_entity(&lifecycle)?;
        audit(
            store,
            &request.project_id,
            "metasploit.lifecycle.start",
            RiskLevel::L0,
            "allowed",
            "127.0.0.1 dynamic RPC",
            &json!({
                "certificate_sha256": status.certificate_sha256,
                "supervisor": status.supervisor,
                "isolation_level": status.isolation_level,
            }),
        )?;
        *active = Some(ActiveMetasploit {
            project_id: request.project_id.clone(),
            worker,
            status: status.clone(),
            lifecycle_entity_id: lifecycle.adapter_entity_id,
        });
        Ok(status)
    }

    pub async fn status(
        &self,
        project_id: &ProjectId,
    ) -> Result<MetasploitStatus, MetasploitError> {
        let mut active = self.active.lock().await;
        let Some(active) = active.as_mut() else {
            return Ok(MetasploitStatus::stopped());
        };
        ensure_project(active, project_id)?;
        let value = adapter_call(&mut active.worker, "status", project_id, json!({})).await?;
        active.status = parse_status(&value, project_id)?;
        Ok(active.status.clone())
    }

    pub async fn stop(
        &self,
        store: &ProjectStore,
        request: &StopMetasploitRequest,
    ) -> Result<MetasploitStatus, MetasploitError> {
        let mut guard = self.active.lock().await;
        let Some(active) = guard.as_mut() else {
            return Ok(MetasploitStatus::stopped());
        };
        ensure_project(active, &request.project_id)?;
        let status_value =
            adapter_call(&mut active.worker, "status", &request.project_id, json!({})).await?;
        let current = parse_status(&status_value, &request.project_id)?;
        let terminate_sessions = current.active_sessions > 0;
        if terminate_sessions
            && request.confirmation.as_deref() != Some("TERMINATE ACTIVE SESSIONS")
        {
            audit(
                store,
                &request.project_id,
                "metasploit.lifecycle.stop",
                RiskLevel::L3,
                "denied",
                "active sessions",
                &json!({"reason": "confirmation_required"}),
            )?;
            return Err(MetasploitError::ActiveSessions);
        }
        adapter_call(
            &mut active.worker,
            "shutdown",
            &request.project_id,
            json!({"terminate_sessions": terminate_sessions}),
        )
        .await?;
        let mut stopped_entity = store.adapter_entity(&active.lifecycle_entity_id)?;
        stopped_entity.terminated_at = Some(Timestamp::now());
        stopped_entity.synced_at = Timestamp::now();
        "Metasploit RPC lifecycle stopped".clone_into(&mut stopped_entity.redacted_view);
        store.save_adapter_entity(&stopped_entity)?;
        audit(
            store,
            &request.project_id,
            "metasploit.lifecycle.stop",
            if terminate_sessions {
                RiskLevel::L3
            } else {
                RiskLevel::L0
            },
            "allowed",
            "managed lifecycle",
            &json!({"terminated_sessions": terminate_sessions}),
        )?;
        let active = guard.take().ok_or(MetasploitError::Inactive)?;
        let _ = active.worker.shutdown().await?;
        Ok(MetasploitStatus::stopped())
    }

    pub async fn search_modules(
        &self,
        store: &ProjectStore,
        request: &SearchMetasploitModulesRequest,
    ) -> Result<Vec<MetasploitModuleSummary>, MetasploitError> {
        if request.query.len() > MAX_MODULE_QUERY_BYTES {
            return Err(MetasploitError::InvalidRequest);
        }
        let mut active = self.active.lock().await;
        let active = active.as_mut().ok_or(MetasploitError::Inactive)?;
        ensure_project(active, &request.project_id)?;
        let value = adapter_call(
            &mut active.worker,
            "search_modules",
            &request.project_id,
            json!({"query": request.query}),
        )
        .await?;
        let modules: Vec<MetasploitModuleSummary> =
            serde_json::from_value(value.clone()).map_err(|_| MetasploitError::AdapterContract)?;
        for module in &modules {
            let snapshot =
                serde_json::to_value(module).map_err(|_| MetasploitError::AdapterContract)?;
            store.save_adapter_entity(&entity(
                &request.project_id,
                "module",
                &format!("{}/{}", module.module_type, module.fullname),
                None,
                Sensitivity::Normal,
                &snapshot,
                &format!("{} — {}", module.fullname, module.name),
            )?)?;
        }
        Ok(modules)
    }

    pub async fn module_options(
        &self,
        store: &ProjectStore,
        request: &GetMetasploitOptionsRequest,
    ) -> Result<Vec<MetasploitModuleOption>, MetasploitError> {
        validate_module_identity(&request.module_type, &request.fullname)?;
        let mut active = self.active.lock().await;
        let active = active.as_mut().ok_or(MetasploitError::Inactive)?;
        ensure_project(active, &request.project_id)?;
        let value = adapter_call(
            &mut active.worker,
            "module_options",
            &request.project_id,
            json!({
                "module_type": request.module_type,
                "fullname": request.fullname,
            }),
        )
        .await?;
        let options: Vec<MetasploitModuleOption> =
            serde_json::from_value(value.clone()).map_err(|_| MetasploitError::AdapterContract)?;
        if options.len() > MAX_OPTION_COUNT {
            return Err(MetasploitError::AdapterContract);
        }
        store.save_adapter_entity(&entity(
            &request.project_id,
            "module_options",
            &format!("{}/{}", request.module_type, request.fullname),
            None,
            Sensitivity::Normal,
            &value,
            &format!("{} options", request.fullname),
        )?)?;
        Ok(options)
    }

    pub async fn execute_module(
        &self,
        store: &ProjectStore,
        scope: &TargetScope,
        request: &ExecuteMetasploitModuleRequest,
    ) -> Result<MetasploitExecutionResult, MetasploitError> {
        validate_module_identity(&request.module_type, &request.fullname)?;
        validate_options(scope, &request.options)?;
        let expected = format!("EXECUTE {}/{}", request.module_type, request.fullname);
        if request.confirmation != expected {
            let event = audit(
                store,
                &request.project_id,
                "metasploit.module.execute",
                RiskLevel::L3,
                "denied",
                &target_summary(&request.options),
                &json!({"reason": "confirmation_required", "module": request.fullname}),
            )?;
            drop(event);
            return Err(MetasploitError::ConfirmationRequired);
        }
        let redacted_options = redact_options(&request.options);
        let mut active = self.active.lock().await;
        let active = active.as_mut().ok_or(MetasploitError::Inactive)?;
        ensure_project(active, &request.project_id)?;
        let value = adapter_call(
            &mut active.worker,
            "execute_module",
            &request.project_id,
            json!({
                "module_type": request.module_type,
                "fullname": request.fullname,
                "execution_kind": request.execution_kind,
                "options": request.options,
                "automatic_replay": false,
            }),
        )
        .await?;
        let job_id = value
            .get("job_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let execution_uuid = value
            .get("uuid")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let job_entity = if let Some(job_id) = job_id {
            let summary = json!({
                "job_id": job_id,
                "execution_uuid": execution_uuid,
                "module_type": request.module_type,
                "module": request.fullname,
                "execution_kind": request.execution_kind,
                "options": redacted_options,
                "automatic_replay": false,
                "state": "running",
            });
            let entity = entity(
                &request.project_id,
                "job",
                &job_id,
                None,
                Sensitivity::SensitiveEvidence,
                &summary,
                &format!("Metasploit Job {job_id}: {}", request.fullname),
            )?;
            store.save_adapter_entity(&entity)?;
            Some(entity)
        } else {
            None
        };
        let event = audit(
            store,
            &request.project_id,
            "metasploit.module.execute",
            RiskLevel::L3,
            "allowed",
            &target_summary(&request.options),
            &json!({
                "module_type": request.module_type,
                "module": request.fullname,
                "execution_kind": request.execution_kind,
                "options": redacted_options,
                "automatic_replay": false,
                "job_id": job_entity.as_ref().map(|value| value.external_id.clone()),
                "execution_uuid": execution_uuid,
            }),
        )?;
        Ok(MetasploitExecutionResult {
            job_entity,
            execution_uuid,
            audit_event: event,
        })
    }

    pub async fn sync_entities(
        &self,
        store: &ProjectStore,
        project_id: &ProjectId,
    ) -> Result<MetasploitEntityPage, MetasploitError> {
        let mut active = self.active.lock().await;
        let active = active.as_mut().ok_or(MetasploitError::Inactive)?;
        ensure_project(active, project_id)?;
        for (method, kind) in [("list_jobs", "job"), ("list_sessions", "session")] {
            let value = adapter_call(&mut active.worker, method, project_id, json!({})).await?;
            let managed = value
                .get("managed_ids")
                .and_then(Value::as_array)
                .ok_or(MetasploitError::AdapterContract)?;
            let items = value
                .get("items")
                .and_then(Value::as_object)
                .ok_or(MetasploitError::AdapterContract)?;
            for id in managed.iter().filter_map(Value::as_str) {
                let summary = items
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| json!({"state": "ended"}));
                store.save_adapter_entity(&entity(
                    project_id,
                    kind,
                    id,
                    None,
                    Sensitivity::SensitiveEvidence,
                    &summary,
                    &format!("Metasploit {kind} {id}"),
                )?)?;
            }
        }
        Ok(MetasploitEntityPage {
            items: store.list_adapter_entities(ADAPTER_ID, None, 500)?,
        })
    }

    pub async fn create_console(
        &self,
        store: &ProjectStore,
        project_id: &ProjectId,
    ) -> Result<AdapterEntity, MetasploitError> {
        let mut active = self.active.lock().await;
        let active = active.as_mut().ok_or(MetasploitError::Inactive)?;
        ensure_project(active, project_id)?;
        let value =
            adapter_call(&mut active.worker, "create_console", project_id, json!({})).await?;
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .ok_or(MetasploitError::AdapterContract)?;
        let entity = entity(
            project_id,
            "console",
            id,
            None,
            Sensitivity::SensitiveEvidence,
            &value,
            &format!("Metasploit Console {id}"),
        )?;
        store.save_adapter_entity(&entity)?;
        Ok(entity)
    }

    pub async fn stop_entity(
        &self,
        store: &ProjectStore,
        request: &StopMetasploitEntityRequest,
    ) -> Result<AdapterEntity, MetasploitError> {
        if !matches!(request.entity_kind.as_str(), "job" | "console" | "session")
            || request.external_id.is_empty()
            || request.external_id.len() > 128
            || request.confirmation
                != format!(
                    "STOP {} {}",
                    request.entity_kind.to_ascii_uppercase(),
                    request.external_id
                )
        {
            return Err(MetasploitError::ConfirmationRequired);
        }
        let method = match request.entity_kind.as_str() {
            "job" => "stop_job",
            "console" => "destroy_console",
            "session" => "stop_session",
            _ => return Err(MetasploitError::InvalidRequest),
        };
        let params = match request.entity_kind.as_str() {
            "job" => json!({"job_id": request.external_id}),
            "console" => json!({"console_id": request.external_id}),
            "session" => json!({"session_id": request.external_id}),
            _ => return Err(MetasploitError::InvalidRequest),
        };
        let mut active = self.active.lock().await;
        let active = active.as_mut().ok_or(MetasploitError::Inactive)?;
        ensure_project(active, &request.project_id)?;
        adapter_call(&mut active.worker, method, &request.project_id, params).await?;
        let stable = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!(
                "flagdeck:{}:{ADAPTER_ID}:{}:{}",
                request.project_id, request.entity_kind, request.external_id
            )
            .as_bytes(),
        );
        let id = AdapterEntityId::parse(stable.to_string())
            .map_err(|_| MetasploitError::AdapterContract)?;
        let mut entity = store.adapter_entity(&id)?;
        entity.terminated_at = Some(Timestamp::now());
        entity.synced_at = Timestamp::now();
        entity.redacted_view = format!(
            "Metasploit {} {} stopped",
            request.entity_kind, request.external_id
        );
        store.save_adapter_entity(&entity)?;
        audit(
            store,
            &request.project_id,
            &format!("metasploit.{}.stop", request.entity_kind),
            if request.entity_kind == "session" {
                RiskLevel::L3
            } else {
                RiskLevel::L2
            },
            "allowed",
            &request.external_id,
            &json!({"ownership": "managed"}),
        )?;
        Ok(entity)
    }

    pub async fn console_command(
        &self,
        store: &ProjectStore,
        request: &MetasploitConsoleCommandRequest,
    ) -> Result<MetasploitTranscriptResult, MetasploitError> {
        validate_command(&request.command)?;
        if request.confirmation != format!("CONSOLE {}", request.console_id) {
            return Err(MetasploitError::ConfirmationRequired);
        }
        let mut active = self.active.lock().await;
        let active = active.as_mut().ok_or(MetasploitError::Inactive)?;
        ensure_project(active, &request.project_id)?;
        adapter_call(
            &mut active.worker,
            "write_console",
            &request.project_id,
            json!({"console_id": request.console_id, "command": request.command}),
        )
        .await?;
        let value = adapter_call(
            &mut active.worker,
            "read_console",
            &request.project_id,
            json!({"console_id": request.console_id}),
        )
        .await?;
        transcript_result(
            store,
            &request.project_id,
            "console",
            &request.console_id,
            &request.command,
            &value,
        )
    }

    pub async fn session_command(
        &self,
        store: &ProjectStore,
        request: &MetasploitSessionCommandRequest,
    ) -> Result<MetasploitTranscriptResult, MetasploitError> {
        validate_command(&request.command)?;
        if request.confirmation != format!("SESSION {}", request.session_id) {
            return Err(MetasploitError::ConfirmationRequired);
        }
        let mut active = self.active.lock().await;
        let active = active.as_mut().ok_or(MetasploitError::Inactive)?;
        ensure_project(active, &request.project_id)?;
        let value = adapter_call(
            &mut active.worker,
            "session_command",
            &request.project_id,
            json!({"session_id": request.session_id, "command": request.command}),
        )
        .await?;
        transcript_result(
            store,
            &request.project_id,
            "session",
            &request.session_id,
            &request.command,
            &value,
        )
    }
}

fn transcript_result(
    store: &ProjectStore,
    project_id: &ProjectId,
    kind: &str,
    external_id: &str,
    command: &str,
    value: &Value,
) -> Result<MetasploitTranscriptResult, MetasploitError> {
    let raw = value
        .get("data")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let redacted = value
        .get("redacted")
        .and_then(Value::as_str)
        .unwrap_or("[sensitive transcript saved]")
        .to_owned();
    let request = ArtifactWriteRequest {
        logical_name: format!("metasploit-{kind}-{external_id}-transcript.txt"),
        mime: "text/plain; charset=utf-8".to_owned(),
        sensitivity: Sensitivity::SensitiveEvidence,
        export_policy: ExportPolicy::ConfirmSensitive,
        source_job_id: None,
        source_message_id: None,
        expected_size: Some(u64::try_from(raw.len()).map_err(|_| MetasploitError::InvalidRequest)?),
        expected_sha256: None,
    };
    let artifact = store.commit_artifact(&request, raw.as_bytes())?;
    let summary = json!({
        "state": "active",
        "last_command_sha256": format!("{:x}", sha2::Sha256::digest(command.as_bytes())),
        "transcript_artifact_id": artifact.artifact_id,
        "redacted": redacted,
    });
    let mut entity = entity(
        project_id,
        kind,
        external_id,
        Some(artifact.artifact_id.clone()),
        Sensitivity::SensitiveEvidence,
        &summary,
        &redacted,
    )?;
    entity.snapshot_artifact_id = Some(artifact.artifact_id.clone());
    store.save_adapter_entity(&entity)?;
    audit(
        store,
        project_id,
        &format!("metasploit.{kind}.command"),
        RiskLevel::L3,
        "allowed",
        external_id,
        &json!({
            "command_sha256": format!("{:x}", sha2::Sha256::digest(command.as_bytes())),
            "artifact_id": artifact.artifact_id,
        }),
    )?;
    Ok(MetasploitTranscriptResult {
        entity,
        artifact,
        redacted,
    })
}

async fn adapter_call(
    worker: &mut AdapterWorker,
    method: &str,
    project_id: &ProjectId,
    params: Value,
) -> Result<Value, MetasploitError> {
    let request_id = Uuid::new_v4().to_string();
    let deadline = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MetasploitError::AdapterContract)?
        .as_millis()
        .saturating_add(45_000)
        .to_string();
    let response = worker
        .request(&JsonRpcRequest {
            jsonrpc: JSON_RPC_VERSION.to_owned(),
            id: request_id.clone(),
            method: method.to_owned(),
            metadata: RequestMetadata {
                core_job_id: format!("msf-{}", project_id.0),
                adapter_job_id: None,
                idempotency_key: format!("{method}-{request_id}"),
                deadline_unix_millis: deadline,
            },
            params,
        })
        .await?;
    if let Some(error) = response.error {
        return Err(match error.code {
            -32013 => MetasploitError::ActiveSessions,
            -32014 => MetasploitError::InvalidRequest,
            _ => error.redacted_data.map_or(
                MetasploitError::AdapterContract,
                MetasploitError::AdapterRejected,
            ),
        });
    }
    response.result.ok_or(MetasploitError::AdapterContract)
}

fn parse_status(
    value: &Value,
    project_id: &ProjectId,
) -> Result<MetasploitStatus, MetasploitError> {
    let state = match value.get("state").and_then(Value::as_str) {
        Some("ready") => MetasploitLifecycleState::Ready,
        Some("stopped") => MetasploitLifecycleState::Stopped,
        _ => return Err(MetasploitError::AdapterContract),
    };
    if state == MetasploitLifecycleState::Stopped {
        return Ok(MetasploitStatus::stopped());
    }
    if value.get("project_id").and_then(Value::as_str) != Some(project_id.0.as_str()) {
        return Err(MetasploitError::ProjectMismatch);
    }
    let framework_version = value
        .get("framework_version")
        .and_then(|version| version.get("version"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    Ok(MetasploitStatus {
        state,
        project_id: Some(project_id.clone()),
        workspace: value
            .get("workspace")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        listen_port: value
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok()),
        certificate_sha256: value
            .get("certificate_sha256")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        framework_version,
        supervisor: value
            .get("supervisor")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        managed_jobs: value
            .get("managed_jobs")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0),
        managed_consoles: value
            .get("managed_consoles")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0),
        managed_sessions: value
            .get("managed_sessions")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0),
        active_sessions: value
            .get("active_sessions")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0),
        isolation_level: "input_scope_gate_and_audit".to_owned(),
    })
}

fn validate_description(value: &Value) -> Result<(), MetasploitError> {
    let capabilities = value
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or(MetasploitError::AdapterContract)?;
    let expected_capabilities = ["exploit_framework", "console", "sessions"];
    if value.get("adapter_id").and_then(Value::as_str) != Some(ADAPTER_ID)
        || value.get("adapter_version").and_then(Value::as_str) != Some(ADAPTER_VERSION)
        || value.get("protocol").and_then(Value::as_str) != Some(ADAPTER_PROTOCOL)
        || value.get("risk_level").and_then(Value::as_str) != Some("l3")
        || expected_capabilities.iter().any(|expected| {
            !capabilities
                .iter()
                .filter_map(Value::as_str)
                .any(|actual| actual == *expected)
        })
    {
        return Err(MetasploitError::AdapterContract);
    }
    for (field, contract) in [
        (
            "input_schema_sha256",
            b"flagdeck.metasploit.input/1".as_slice(),
        ),
        (
            "output_schema_sha256",
            b"flagdeck.metasploit.output/1".as_slice(),
        ),
        ("ui_schema_sha256", b"flagdeck.metasploit.ui/1".as_slice()),
    ] {
        let expected = format!("{:x}", sha2::Sha256::digest(contract));
        if value.get(field).and_then(Value::as_str) != Some(expected.as_str()) {
            return Err(MetasploitError::AdapterContract);
        }
    }
    Ok(())
}

fn entity(
    project_id: &ProjectId,
    kind: &str,
    external_id: &str,
    artifact_id: Option<ArtifactId>,
    sensitivity: Sensitivity,
    summary: &Value,
    redacted_view: &str,
) -> Result<AdapterEntity, MetasploitError> {
    let now = Timestamp::now();
    let stable = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("flagdeck:{project_id}:{ADAPTER_ID}:{kind}:{external_id}").as_bytes(),
    );
    let value = AdapterEntity {
        adapter_entity_id: AdapterEntityId::parse(stable.to_string())
            .map_err(|_| MetasploitError::AdapterContract)?,
        project_id: Some(project_id.clone()),
        adapter_id: ADAPTER_ID.to_owned(),
        adapter_version: ADAPTER_VERSION.to_owned(),
        protocol_version: ADAPTER_PROTOCOL.to_owned(),
        entity_kind: kind.to_owned(),
        external_id: external_id.to_owned(),
        parent_entity_id: None,
        source_job_id: None,
        ownership: AdapterOwnership::Managed,
        state_schema_version: ENTITY_SCHEMA_VERSION,
        summary_json: serde_json::to_string(summary)
            .map_err(|_| MetasploitError::AdapterContract)?,
        snapshot_artifact_id: artifact_id,
        sensitivity,
        redacted_view: redacted_view.chars().take(256 * 1024).collect(),
        created_at: now.clone(),
        synced_at: now,
        terminated_at: None,
    };
    value
        .validate()
        .map_err(|_| MetasploitError::AdapterContract)?;
    Ok(value)
}

fn audit(
    store: &ProjectStore,
    project_id: &ProjectId,
    action: &str,
    risk_level: RiskLevel,
    outcome: &str,
    target_summary: &str,
    details: &Value,
) -> Result<AuditEvent, MetasploitError> {
    let event = AuditEvent {
        audit_event_id: AuditEventId::new(),
        project_id: project_id.clone(),
        adapter_id: Some(ADAPTER_ID.to_owned()),
        action: action.to_owned(),
        risk_level,
        outcome: outcome.to_owned(),
        target_summary: target_summary.chars().take(4096).collect(),
        details_json: serde_json::to_string(&details)
            .map_err(|_| MetasploitError::AdapterContract)?,
        created_at: Timestamp::now(),
    };
    store.save_audit_event(&event)?;
    Ok(event)
}

fn validate_module_identity(module_type: &str, fullname: &str) -> Result<(), MetasploitError> {
    let types = [
        "exploit",
        "auxiliary",
        "post",
        "payload",
        "encoder",
        "nop",
        "evasion",
    ];
    if !types.contains(&module_type)
        || fullname.is_empty()
        || fullname.len() > 512
        || fullname.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
    {
        return Err(MetasploitError::InvalidRequest);
    }
    Ok(())
}

fn validate_options(
    scope: &TargetScope,
    options: &BTreeMap<String, Value>,
) -> Result<(), MetasploitError> {
    if options.len() > MAX_OPTION_COUNT {
        return Err(MetasploitError::InvalidRequest);
    }
    for (name, value) in options {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || serde_json::to_vec(value)
                .map_err(|_| MetasploitError::InvalidRequest)?
                .len()
                > MAX_OPTION_VALUE_BYTES
        {
            return Err(MetasploitError::InvalidRequest);
        }
        let upper = name.to_ascii_uppercase();
        match upper.as_str() {
            "RHOST" | "RHOSTS" => {
                let targets = value.as_str().ok_or(MetasploitError::InvalidRequest)?;
                for target in
                    targets.split(|character: char| character == ',' || character.is_whitespace())
                {
                    if target.is_empty() {
                        continue;
                    }
                    if target.contains('/')
                        || target.contains('-')
                        || target.contains(':') && target.parse::<IpAddr>().is_err()
                    {
                        return Err(MetasploitError::ScopeViolation);
                    }
                    if !host_in_scope(scope, target) {
                        return Err(MetasploitError::ScopeViolation);
                    }
                }
            }
            "RPORT" => {
                let port = json_u16(value).ok_or(MetasploitError::InvalidRequest)?;
                if !scope
                    .ports
                    .iter()
                    .any(|range| range.start <= port && port <= range.end)
                {
                    return Err(MetasploitError::ScopeViolation);
                }
            }
            "TARGETURI" => {
                let path = value.as_str().ok_or(MetasploitError::InvalidRequest)?;
                if !path.starts_with('/') || path.contains('\r') || path.contains('\n') {
                    return Err(MetasploitError::InvalidRequest);
                }
            }
            "LHOST" => {
                let address = value
                    .as_str()
                    .and_then(|text| text.parse::<IpAddr>().ok())
                    .ok_or(MetasploitError::InvalidRequest)?;
                if !address.is_loopback() {
                    return Err(MetasploitError::ScopeViolation);
                }
            }
            "LPORT" => {
                json_u16(value).ok_or(MetasploitError::InvalidRequest)?;
            }
            "PROXIES" => {
                let proxy = value.as_str().ok_or(MetasploitError::InvalidRequest)?;
                if !proxy.is_empty() && !proxy.contains("127.0.0.1") && !proxy.contains("localhost")
                {
                    return Err(MetasploitError::ScopeViolation);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn host_in_scope(scope: &TargetScope, target: &str) -> bool {
    let normalized = target.trim_matches(['[', ']']).to_ascii_lowercase();
    if scope
        .exact_hosts
        .iter()
        .any(|host| host.eq_ignore_ascii_case(&normalized))
    {
        return true;
    }
    let Ok(address) = normalized.parse::<IpAddr>() else {
        return false;
    };
    scope.dns_snapshots.iter().any(|snapshot| {
        snapshot
            .addresses
            .iter()
            .filter_map(|value| value.parse::<IpAddr>().ok())
            .any(|candidate| candidate == address)
    })
}

fn json_u16(value: &Value) -> Option<u16> {
    value
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| *value > 0)
        .or_else(|| {
            value
                .as_str()?
                .parse::<u16>()
                .ok()
                .filter(|value| *value > 0)
        })
}

fn redact_options(options: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    options
        .iter()
        .map(|(key, value)| {
            let upper = key.to_ascii_uppercase();
            let sensitive = [
                "PASS", "PASSWORD", "TOKEN", "COOKIE", "AUTH", "SECRET", "KEY",
            ]
            .iter()
            .any(|needle| upper.contains(needle));
            (
                key.clone(),
                if sensitive {
                    Value::String("[REDACTED]".to_owned())
                } else {
                    value.clone()
                },
            )
        })
        .collect()
}

fn target_summary(options: &BTreeMap<String, Value>) -> String {
    let mut parts = Vec::new();
    for key in ["RHOST", "RHOSTS", "RPORT", "TARGETURI", "LHOST", "LPORT"] {
        if let Some(value) = options.get(key) {
            parts.push(format!("{key}={value}"));
        }
    }
    parts.join(" ")
}

fn validate_command(command: &str) -> Result<(), MetasploitError> {
    if command.trim().is_empty()
        || command.len() > MAX_CONSOLE_COMMAND_BYTES
        || command.contains('\0')
        || command.contains('\r')
    {
        return Err(MetasploitError::InvalidRequest);
    }
    Ok(())
}

fn ensure_project(
    active: &ActiveMetasploit,
    project_id: &ProjectId,
) -> Result<(), MetasploitError> {
    if &active.project_id == project_id {
        Ok(())
    } else {
        Err(MetasploitError::ProjectMismatch)
    }
}

fn canonical_executable(path: &Path) -> Result<PathBuf, MetasploitError> {
    if !path.is_absolute() {
        return Err(MetasploitError::Unavailable);
    }
    let path = fs::canonicalize(path)?;
    path.is_file()
        .then_some(path)
        .ok_or(MetasploitError::Unavailable)
}

fn set_private_directory(path: &Path) -> Result<(), MetasploitError> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::time::Duration;

    use flagdeck_domain::{
        DnsResolutionSnapshot, NetworkClass, PortRange, RedirectPolicy, ScopeId,
    };

    use super::*;

    fn scope() -> TargetScope {
        let now = Timestamp::now();
        TargetScope {
            scope_id: ScopeId::new(),
            project_id: ProjectId::new(),
            schemes: vec!["http".to_owned()],
            exact_hosts: vec!["challenge.local".to_owned()],
            wildcard_subdomains: vec![],
            cidrs: vec![],
            ports: vec![PortRange {
                start: 8080,
                end: 8080,
            }],
            redirect_policy: RedirectPolicy::Deny,
            dns_change_policy: "deny".to_owned(),
            dns_snapshots: vec![DnsResolutionSnapshot {
                host: "challenge.local".to_owned(),
                addresses: vec!["127.0.0.1".to_owned()],
                resolved_at: now.clone(),
                peer_address: Some("127.0.0.1".to_owned()),
                rebinding_action: "deny".to_owned(),
            }],
            network_class: NetworkClass::Loopback,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    #[test]
    fn execution_options_enforce_scope_ports_and_loopback_listener() {
        let scope = scope();
        let allowed = BTreeMap::from([
            ("RHOSTS".to_owned(), json!("127.0.0.1")),
            ("RPORT".to_owned(), json!(8080)),
            ("TARGETURI".to_owned(), json!("/app")),
            ("LHOST".to_owned(), json!("127.0.0.1")),
        ]);
        assert!(validate_options(&scope, &allowed).is_ok());
        let mut denied = allowed.clone();
        denied.insert("RHOSTS".to_owned(), json!("192.0.2.10"));
        assert!(matches!(
            validate_options(&scope, &denied),
            Err(MetasploitError::ScopeViolation)
        ));
        denied = allowed;
        denied.insert("RPORT".to_owned(), json!(4444));
        assert!(matches!(
            validate_options(&scope, &denied),
            Err(MetasploitError::ScopeViolation)
        ));
    }

    #[test]
    fn sensitive_options_are_redacted_before_audit() {
        let options = BTreeMap::from([
            ("RHOSTS".to_owned(), json!("127.0.0.1")),
            ("PASSWORD".to_owned(), json!("hunter2")),
        ]);
        let redacted = redact_options(&options);
        assert_eq!(redacted["PASSWORD"], "[REDACTED]");
        assert!(
            !serde_json::to_string(&redacted)
                .unwrap()
                .contains("hunter2")
        );
    }

    #[test]
    fn module_and_command_inputs_are_structural() {
        assert!(validate_module_identity("exploit", "linux/http/example").is_ok());
        assert!(validate_module_identity("exploit", "../escape").is_err());
        assert!(validate_command("whoami").is_ok());
        assert!(validate_command("bad\rcommand").is_err());
    }

    #[tokio::test]
    #[ignore = "requires local Metasploit 6.4.135 and systemd user manager"]
    async fn real_loopback_lifecycle_gate() {
        let adapter = std::env::var_os("FLAGDECK_R5_ADAPTER")
            .map(PathBuf::from)
            .unwrap();
        let launcher = std::env::var_os("FLAGDECK_R5_LAUNCHER")
            .map(PathBuf::from)
            .unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let (store, project) = ProjectStore::create(temporary.path(), "R5 real gate").unwrap();
        let workbench = MetasploitWorkbench::new(Some(adapter), Some(launcher));
        let ready = workbench
            .start(
                &store,
                &StartMetasploitRequest {
                    project_id: project.project_id.clone(),
                },
            )
            .await
            .unwrap();
        assert_eq!(ready.state, MetasploitLifecycleState::Ready);
        assert!(ready.listen_port.is_some_and(|port| port > 0));
        assert_eq!(ready.certificate_sha256.as_deref().map(str::len), Some(64));
        assert!(
            ready
                .framework_version
                .as_deref()
                .is_some_and(|value| value.starts_with("6.4"))
        );
        let modules = workbench
            .search_modules(
                &store,
                &SearchMetasploitModulesRequest {
                    project_id: project.project_id.clone(),
                    query: "http_version".to_owned(),
                },
            )
            .await
            .unwrap();
        assert!(
            modules
                .iter()
                .any(|module| module.fullname.contains("http_version"))
        );
        let port = ready.listen_port.unwrap();
        workbench
            .stop(
                &store,
                &StopMetasploitRequest {
                    project_id: project.project_id,
                    confirmation: None,
                },
            )
            .await
            .unwrap();
        assert!(
            TcpStream::connect_timeout(
                &SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into(),
                Duration::from_millis(100),
            )
            .is_err()
        );
        let database = fs::read(store.layout().database.clone()).unwrap();
        assert!(
            !database
                .windows(b"MSF_RPC_PASS".len())
                .any(|value| value == b"MSF_RPC_PASS")
        );
        assert!(
            !database
                .windows(b"auth.login".len())
                .any(|value| value == b"auth.login")
        );
    }

    #[tokio::test]
    #[ignore = "ten-run local Metasploit performance evidence gate"]
    async fn real_loopback_ten_run_performance_gate() {
        let adapter = PathBuf::from(std::env::var_os("FLAGDECK_R5_ADAPTER").unwrap());
        let launcher = PathBuf::from(std::env::var_os("FLAGDECK_R5_LAUNCHER").unwrap());
        let evidence = PathBuf::from(std::env::var_os("FLAGDECK_R5_EVIDENCE").unwrap());
        let temporary = tempfile::tempdir().unwrap();
        let (store, project) = ProjectStore::create(temporary.path(), "R5 performance").unwrap();
        let workbench = MetasploitWorkbench::new(Some(adapter.clone()), Some(launcher.clone()));
        let mut start_millis = Vec::new();
        let mut rss_kib = Vec::new();
        for _ in 0..10 {
            let started = std::time::Instant::now();
            let ready = workbench
                .start(
                    &store,
                    &StartMetasploitRequest {
                        project_id: project.project_id.clone(),
                    },
                )
                .await
                .unwrap();
            start_millis.push(u64::try_from(started.elapsed().as_millis()).unwrap());
            let port = ready.listen_port.unwrap();
            rss_kib.push(listener_rss_kib(port).unwrap());
            workbench
                .stop(
                    &store,
                    &StopMetasploitRequest {
                        project_id: project.project_id.clone(),
                        confirmation: None,
                    },
                )
                .await
                .unwrap();
            assert!(
                TcpStream::connect_timeout(
                    &SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into(),
                    Duration::from_millis(100),
                )
                .is_err()
            );
        }
        let mut ordered = start_millis.clone();
        ordered.sort_unstable();
        let result = json!({
            "status": "PASS",
            "runs": 10,
            "start_millis": start_millis,
            "start_p50_millis": ordered[4],
            "start_p95_millis": ordered[9],
            "msfrpcd_rss_kib": rss_kib,
            "msfrpcd_rss_p95_kib": *rss_kib.iter().max().unwrap(),
            "adapter_bytes": fs::metadata(&adapter).unwrap().len(),
            "launcher_bytes": fs::metadata(&launcher).unwrap().len(),
            "adapter_sha256": hash_file(&adapter),
            "launcher_sha256": hash_file(&launcher),
            "framework": "6.4.135",
            "rpc": "standard-messagepack-tls",
            "credential_transport": "systemd-load-credential-from-one-shot-unix-socket",
            "project_id": project.project_id,
            "generated_at": Timestamp::now(),
        });
        fs::create_dir_all(evidence.parent().unwrap()).unwrap();
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&evidence)
            .unwrap();
        writeln!(file, "{}", serde_json::to_string_pretty(&result).unwrap()).unwrap();
        file.sync_all().unwrap();
        fs::set_permissions(evidence, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn listener_rss_kib(port: u16) -> Option<u64> {
        let expected = format!(":{port:04X}");
        let inode = ["/proc/net/tcp", "/proc/net/tcp6"]
            .iter()
            .find_map(|table| {
                fs::read_to_string(table)
                    .ok()?
                    .lines()
                    .skip(1)
                    .find_map(|line| {
                        let fields = line.split_whitespace().collect::<Vec<_>>();
                        (fields.len() > 9 && fields[3] == "0A" && fields[1].ends_with(&expected))
                            .then(|| fields[9].to_owned())
                    })
            })?;
        for process in fs::read_dir("/proc").ok()?.flatten() {
            if !process
                .file_name()
                .to_string_lossy()
                .bytes()
                .all(|byte| byte.is_ascii_digit())
            {
                continue;
            }
            let Ok(descriptors) = fs::read_dir(process.path().join("fd")) else {
                continue;
            };
            if descriptors.flatten().any(|descriptor| {
                fs::read_link(descriptor.path())
                    .is_ok_and(|target| target.to_string_lossy() == format!("socket:[{inode}]"))
            }) {
                return fs::read_to_string(process.path().join("status"))
                    .ok()?
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("VmRSS:")?
                            .split_whitespace()
                            .next()?
                            .parse()
                            .ok()
                    });
            }
        }
        None
    }

    fn hash_file(path: &Path) -> String {
        format!("{:x}", sha2::Sha256::digest(fs::read(path).unwrap()))
    }
}
