#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::too_many_lines
)]

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use flagdeck_domain::{
    Artifact, DictionaryId, ExportPolicy, HttpMessage, IntruderAttackMode, IntruderAttempt,
    IntruderAttemptId, IntruderAttemptState, IntruderCampaign, IntruderCampaignId,
    IntruderCampaignKind, IntruderCampaignState, MessageDirection, MessageId, MultipartDocument,
    MultipartPart, OrderedValue, PayloadLocation, PayloadPosition, ProjectId, RiskLevel, ScopeId,
    Sensitivity, StateChainRun, StateChainRunId, StateChainStepEvidence, TargetScope, Timestamp,
    UploadMutationKind, Validate,
};
use flagdeck_storage::{ArtifactWriteRequest, ProjectStore, StorageError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use ts_rs::TS;

use crate::http::{RepeatHttpRequest, RepeatHttpResult, message_body, repeat_http_message};

type MacroVariables = BTreeMap<String, Vec<u8>>;
type StateMacroOutcome = (MacroVariables, Option<StateChainRunId>);
type PartHeaderFields = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);

const MAX_INTRUDER_ATTEMPTS: u64 = 100_000;
const MAX_RATE_PER_SECOND: u32 = 10_000;
const MAX_MULTIPART_BYTES: usize = 64 * 1024 * 1024;
const DICTIONARY_PAGE_SIZE: usize = 256;

#[derive(Debug, Error)]
pub enum IntruderError {
    #[error("invalid Intruder or upload request")]
    InvalidRequest,
    #[error("the campaign is already active")]
    AlreadyActive,
    #[error("the campaign cannot transition from its current state")]
    InvalidState,
    #[error("the exact L3 confirmation phrase is required")]
    ConfirmationRequired,
    #[error("multipart parsing or mutation failed")]
    Multipart,
    #[error("Intruder state lock failed")]
    StateLock,
    #[error("HTTP execution failed")]
    Http(#[from] crate::http::HttpWorkbenchError),
    #[error("storage failed")]
    Storage(#[from] StorageError),
    #[error("JSON failed")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum TokenSource {
    ResponseBody,
    ResponseHeader,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TokenExtractor {
    pub variable: String,
    pub source: TokenSource,
    pub header_name: Option<String>,
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub maximum_length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StateMacroStep {
    pub name: String,
    pub message_id: MessageId,
    pub extractors: Vec<TokenExtractor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StateMacro {
    pub steps: Vec<StateMacroStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StartIntruderRequest {
    pub project_id: ProjectId,
    pub scope_id: ScopeId,
    pub parent_message_id: MessageId,
    pub attack_mode: IntruderAttackMode,
    pub positions: Vec<PayloadPosition>,
    pub dictionary_ids: Vec<DictionaryId>,
    pub global_rate_per_second: u32,
    pub target_rate_per_second: u32,
    pub state_macro: Option<StateMacro>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CampaignRequest {
    pub project_id: ProjectId,
    pub intruder_campaign_id: IntruderCampaignId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct IntruderCampaignPage {
    pub items: Vec<IntruderCampaign>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct IntruderAttemptPageRequest {
    pub project_id: ProjectId,
    pub intruder_campaign_id: IntruderCampaignId,
    #[ts(type = "number | null")]
    pub cursor: Option<u64>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct IntruderAttemptPage {
    pub items: Vec<IntruderAttempt>,
    #[ts(type = "number | null")]
    pub next_cursor: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ListIntruderCampaignsRequest {
    pub project_id: ProjectId,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ParseMultipartRequest {
    pub project_id: ProjectId,
    pub message_id: MessageId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum UploadVerificationMode {
    None,
    SafeRetrieval,
    Execution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct UploadVerification {
    pub mode: UploadVerificationMode,
    pub path_extractor: Option<TokenExtractor>,
    pub expected_execution_marker: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StartUploadCampaignRequest {
    pub project_id: ProjectId,
    pub scope_id: ScopeId,
    pub parent_message_id: MessageId,
    pub part_ordinal: usize,
    pub mutations: Vec<UploadMutationKind>,
    pub global_rate_per_second: u32,
    pub target_rate_per_second: u32,
    pub state_macro: Option<StateMacro>,
    pub verification: UploadVerification,
    pub confirmation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CampaignExecutionConfig {
    Intruder {
        state_macro: Option<StateMacro>,
    },
    Upload {
        part_ordinal: usize,
        mutations: Vec<UploadMutationKind>,
        state_macro: Option<StateMacro>,
        verification: UploadVerification,
    },
}

#[derive(Default)]
struct ActiveCampaigns {
    campaigns: Mutex<HashMap<IntruderCampaignId, Arc<AtomicBool>>>,
    next_global: Mutex<Option<Instant>>,
    next_target: Mutex<HashMap<String, Instant>>,
}

#[derive(Default)]
pub struct IntruderWorkbench {
    active: Arc<ActiveCampaigns>,
}

impl IntruderWorkbench {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn has_active(&self) -> bool {
        self.active
            .campaigns
            .lock()
            .is_ok_and(|campaigns| !campaigns.is_empty())
    }

    pub fn list_campaigns(
        &self,
        store: &ProjectStore,
        request: &ListIntruderCampaignsRequest,
    ) -> Result<IntruderCampaignPage, IntruderError> {
        if store.project_id() != &request.project_id || request.limit == 0 || request.limit > 500 {
            return Err(IntruderError::InvalidRequest);
        }
        Ok(IntruderCampaignPage {
            items: store.list_intruder_campaigns(request.limit)?,
        })
    }

    pub fn list_attempts(
        &self,
        store: &ProjectStore,
        request: &IntruderAttemptPageRequest,
    ) -> Result<IntruderAttemptPage, IntruderError> {
        if store.project_id() != &request.project_id || request.limit == 0 || request.limit > 500 {
            return Err(IntruderError::InvalidRequest);
        }
        let items = store.list_intruder_attempts(
            &request.intruder_campaign_id,
            request.limit,
            request.cursor,
        )?;
        let next_cursor = (items.len() == request.limit)
            .then(|| items.last().map(|attempt| attempt.ordinal))
            .flatten();
        Ok(IntruderAttemptPage { items, next_cursor })
    }

    pub fn parse_multipart(
        &self,
        store: &ProjectStore,
        request: &ParseMultipartRequest,
    ) -> Result<MultipartDocument, IntruderError> {
        let message = store.http_message(&request.message_id)?;
        if message.project_id != request.project_id
            || message.direction != MessageDirection::Request
        {
            return Err(IntruderError::InvalidRequest);
        }
        let body = message_body(store, &message)?;
        parse_multipart_message(&message, &body)
    }

    pub fn start_intruder(
        &self,
        store: Arc<ProjectStore>,
        request: &StartIntruderRequest,
    ) -> Result<IntruderCampaign, IntruderError> {
        validate_common_request(
            request.global_rate_per_second,
            request.target_rate_per_second,
            &request.positions,
        )?;
        validate_state_macro(request.state_macro.as_ref())?;
        let parent = validate_parent(&store, &request.project_id, &request.parent_message_id)?;
        let scope = store.target_scope(&request.scope_id)?;
        validate_parent_scope(&parent, &scope)?;
        let counts = dictionary_counts(&store, &request.dictionary_ids)?;
        let total_attempts = attempt_count(request.attack_mode, request.positions.len(), &counts)?;
        let config = CampaignExecutionConfig::Intruder {
            state_macro: request.state_macro.clone(),
        };
        let campaign = IntruderCampaign {
            intruder_campaign_id: IntruderCampaignId::new(),
            project_id: request.project_id.clone(),
            scope_id: request.scope_id.clone(),
            parent_message_id: request.parent_message_id.clone(),
            campaign_kind: IntruderCampaignKind::Intruder,
            attack_mode: request.attack_mode,
            state: IntruderCampaignState::Queued,
            positions: request.positions.clone(),
            dictionary_ids: request.dictionary_ids.clone(),
            global_rate_per_second: request.global_rate_per_second,
            target_rate_per_second: request.target_rate_per_second,
            total_attempts,
            next_ordinal: 0,
            completed_attempts: 0,
            failed_attempts: 0,
            state_macro_json: Some(serde_json::to_string(&config)?),
            created_at: Timestamp::now(),
            started_at: None,
            stopped_at: None,
            error_summary: None,
        };
        store.save_intruder_campaign(&campaign)?;
        self.spawn(store, campaign.clone())?;
        Ok(campaign)
    }

    pub fn start_upload(
        &self,
        store: Arc<ProjectStore>,
        request: &StartUploadCampaignRequest,
    ) -> Result<IntruderCampaign, IntruderError> {
        let positions = vec![PayloadPosition {
            location: PayloadLocation::MultipartBody,
            name: Some(request.part_ordinal.to_string()),
            occurrence: request.part_ordinal,
            start: None,
            end: None,
        }];
        validate_common_request(
            request.global_rate_per_second,
            request.target_rate_per_second,
            &positions,
        )?;
        validate_state_macro(request.state_macro.as_ref())?;
        if request.mutations.is_empty() || request.mutations.len() > 32 {
            return Err(IntruderError::InvalidRequest);
        }
        let parent = validate_parent(&store, &request.project_id, &request.parent_message_id)?;
        let scope = store.target_scope(&request.scope_id)?;
        validate_parent_scope(&parent, &scope)?;
        let body = message_body(&store, &parent)?;
        let document = parse_multipart_message(&parent, &body)?;
        file_part_ordinal(&document, request.part_ordinal)?;
        validate_verification(&request.verification)?;
        if request.verification.mode == UploadVerificationMode::Execution {
            let expected = format!("VERIFY UPLOAD EXECUTION {}", parent.message_id.0);
            if request.confirmation.as_deref() != Some(expected.as_str()) {
                save_upload_audit(
                    &store,
                    &request.project_id,
                    RiskLevel::L3,
                    "denied",
                    &parent,
                    &request.verification,
                )?;
                return Err(IntruderError::ConfirmationRequired);
            }
            save_upload_audit(
                &store,
                &request.project_id,
                RiskLevel::L3,
                "allowed",
                &parent,
                &request.verification,
            )?;
        }
        let config = CampaignExecutionConfig::Upload {
            part_ordinal: request.part_ordinal,
            mutations: request.mutations.clone(),
            state_macro: request.state_macro.clone(),
            verification: request.verification.clone(),
        };
        let total_attempts =
            u64::try_from(request.mutations.len()).map_err(|_| IntruderError::InvalidRequest)?;
        let campaign = IntruderCampaign {
            intruder_campaign_id: IntruderCampaignId::new(),
            project_id: request.project_id.clone(),
            scope_id: request.scope_id.clone(),
            parent_message_id: request.parent_message_id.clone(),
            campaign_kind: IntruderCampaignKind::Upload,
            attack_mode: IntruderAttackMode::Sniper,
            state: IntruderCampaignState::Queued,
            positions,
            dictionary_ids: Vec::new(),
            global_rate_per_second: request.global_rate_per_second,
            target_rate_per_second: request.target_rate_per_second,
            total_attempts,
            next_ordinal: 0,
            completed_attempts: 0,
            failed_attempts: 0,
            state_macro_json: Some(serde_json::to_string(&config)?),
            created_at: Timestamp::now(),
            started_at: None,
            stopped_at: None,
            error_summary: None,
        };
        store.save_intruder_campaign(&campaign)?;
        self.spawn(store, campaign.clone())?;
        Ok(campaign)
    }

    pub fn cancel(
        &self,
        store: &ProjectStore,
        request: &CampaignRequest,
    ) -> Result<IntruderCampaign, IntruderError> {
        let cancellation = self
            .active
            .campaigns
            .lock()
            .map_err(|_| IntruderError::StateLock)?
            .get(&request.intruder_campaign_id)
            .cloned()
            .ok_or(IntruderError::InvalidState)?;
        cancellation.store(true, Ordering::SeqCst);
        let mut campaign = store.intruder_campaign(&request.intruder_campaign_id)?;
        if campaign.project_id != request.project_id {
            return Err(IntruderError::InvalidRequest);
        }
        campaign.state = IntruderCampaignState::Paused;
        campaign.stopped_at = Some(Timestamp::now());
        store.save_intruder_campaign(&campaign)?;
        Ok(campaign)
    }

    pub fn resume(
        &self,
        store: Arc<ProjectStore>,
        request: &CampaignRequest,
    ) -> Result<IntruderCampaign, IntruderError> {
        let mut campaign = store.intruder_campaign(&request.intruder_campaign_id)?;
        if campaign.project_id != request.project_id
            || !matches!(
                campaign.state,
                IntruderCampaignState::Paused | IntruderCampaignState::Interrupted
            )
            || campaign.next_ordinal >= campaign.total_attempts
        {
            return Err(IntruderError::InvalidState);
        }
        if self
            .active
            .campaigns
            .lock()
            .map_err(|_| IntruderError::StateLock)?
            .contains_key(&campaign.intruder_campaign_id)
        {
            return Err(IntruderError::AlreadyActive);
        }
        campaign.state = IntruderCampaignState::Queued;
        campaign.stopped_at = None;
        campaign.error_summary = None;
        store.save_intruder_campaign(&campaign)?;
        self.spawn(store, campaign.clone())?;
        Ok(campaign)
    }

    fn spawn(
        &self,
        store: Arc<ProjectStore>,
        campaign: IntruderCampaign,
    ) -> Result<(), IntruderError> {
        let cancellation = Arc::new(AtomicBool::new(false));
        {
            let mut active = self
                .active
                .campaigns
                .lock()
                .map_err(|_| IntruderError::StateLock)?;
            if active
                .insert(
                    campaign.intruder_campaign_id.clone(),
                    Arc::clone(&cancellation),
                )
                .is_some()
            {
                return Err(IntruderError::AlreadyActive);
            }
        }
        let shared = Arc::clone(&self.active);
        let campaign_id = campaign.intruder_campaign_id.clone();
        thread::Builder::new()
            .name(format!("flagdeck-intruder-{}", campaign_id.0))
            .spawn(move || {
                if let Err(error) = run_campaign(&shared, &store, campaign, &cancellation)
                    && let Ok(mut failed) = store.intruder_campaign(&campaign_id)
                {
                    failed.state = IntruderCampaignState::Failed;
                    failed.stopped_at = Some(Timestamp::now());
                    failed.error_summary = Some(error.to_string());
                    let _ = store.save_intruder_campaign(&failed);
                }
                if let Ok(mut active) = shared.campaigns.lock() {
                    active.remove(&campaign_id);
                }
            })
            .map_err(|_| IntruderError::StateLock)?;
        Ok(())
    }
}

fn validate_common_request(
    global_rate: u32,
    target_rate: u32,
    positions: &[PayloadPosition],
) -> Result<(), IntruderError> {
    if global_rate == 0
        || target_rate == 0
        || global_rate > MAX_RATE_PER_SECOND
        || target_rate > MAX_RATE_PER_SECOND
        || positions.is_empty()
        || positions.len() > 16
    {
        return Err(IntruderError::InvalidRequest);
    }
    for position in positions {
        position
            .validate()
            .map_err(|_| IntruderError::InvalidRequest)?;
    }
    Ok(())
}

fn validate_parent(
    store: &ProjectStore,
    project_id: &ProjectId,
    message_id: &MessageId,
) -> Result<HttpMessage, IntruderError> {
    let parent = store.http_message(message_id)?;
    if &parent.project_id != project_id
        || parent.direction != MessageDirection::Request
        || parent.method.is_none()
    {
        return Err(IntruderError::InvalidRequest);
    }
    Ok(parent)
}

fn validate_parent_scope(parent: &HttpMessage, scope: &TargetScope) -> Result<(), IntruderError> {
    if !scope.schemes.iter().any(|scheme| scheme == &parent.scheme)
        || !scope.exact_hosts.iter().any(|host| host == &parent.host)
        || !scope
            .ports
            .iter()
            .any(|range| range.start <= parent.port && parent.port <= range.end)
    {
        return Err(IntruderError::InvalidRequest);
    }
    Ok(())
}

fn dictionary_counts(
    store: &ProjectStore,
    dictionary_ids: &[DictionaryId],
) -> Result<Vec<u64>, IntruderError> {
    let dictionaries = store.list_dictionaries()?;
    let mut counts = Vec::with_capacity(dictionary_ids.len());
    for dictionary_id in dictionary_ids {
        let dictionary = dictionaries
            .iter()
            .find(|item| &item.dictionary_id == dictionary_id)
            .ok_or(IntruderError::InvalidRequest)?;
        if dictionary.term_count == 0 {
            return Err(IntruderError::InvalidRequest);
        }
        counts.push(dictionary.term_count);
    }
    Ok(counts)
}

fn attempt_count(
    mode: IntruderAttackMode,
    position_count: usize,
    dictionary_counts: &[u64],
) -> Result<u64, IntruderError> {
    let positions = u64::try_from(position_count).map_err(|_| IntruderError::InvalidRequest)?;
    let total = match mode {
        IntruderAttackMode::Sniper => {
            if dictionary_counts.len() != 1 {
                return Err(IntruderError::InvalidRequest);
            }
            positions.saturating_mul(dictionary_counts[0])
        }
        IntruderAttackMode::BatteringRam => {
            if dictionary_counts.len() != 1 {
                return Err(IntruderError::InvalidRequest);
            }
            dictionary_counts[0]
        }
        IntruderAttackMode::Pitchfork => {
            if dictionary_counts.len() != position_count {
                return Err(IntruderError::InvalidRequest);
            }
            *dictionary_counts
                .iter()
                .min()
                .ok_or(IntruderError::InvalidRequest)?
        }
        IntruderAttackMode::ClusterBomb => {
            if dictionary_counts.len() != position_count {
                return Err(IntruderError::InvalidRequest);
            }
            dictionary_counts
                .iter()
                .try_fold(1_u64, |total, count| total.checked_mul(*count))
                .ok_or(IntruderError::InvalidRequest)?
        }
    };
    if total == 0 || total > MAX_INTRUDER_ATTEMPTS {
        return Err(IntruderError::InvalidRequest);
    }
    Ok(total)
}

fn validate_state_macro(state_macro: Option<&StateMacro>) -> Result<(), IntruderError> {
    let Some(state_macro) = state_macro else {
        return Ok(());
    };
    if state_macro.steps.is_empty() || state_macro.steps.len() > 16 {
        return Err(IntruderError::InvalidRequest);
    }
    for step in &state_macro.steps {
        if step.name.trim().is_empty() || step.name.len() > 256 || step.extractors.len() > 16 {
            return Err(IntruderError::InvalidRequest);
        }
        for extractor in &step.extractors {
            validate_extractor(extractor)?;
        }
    }
    Ok(())
}

fn validate_extractor(extractor: &TokenExtractor) -> Result<(), IntruderError> {
    if extractor.variable.is_empty()
        || extractor.variable.len() > 64
        || !extractor
            .variable
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || extractor.maximum_length == 0
        || extractor.maximum_length > 4096
        || (extractor.source == TokenSource::ResponseBody && extractor.prefix.is_empty())
        || (extractor.source == TokenSource::ResponseHeader
            && extractor.header_name.as_deref().is_none_or(str::is_empty))
    {
        return Err(IntruderError::InvalidRequest);
    }
    Ok(())
}

fn validate_verification(verification: &UploadVerification) -> Result<(), IntruderError> {
    match verification.mode {
        UploadVerificationMode::None => {
            if verification.path_extractor.is_some()
                || verification.expected_execution_marker.is_some()
            {
                return Err(IntruderError::InvalidRequest);
            }
        }
        UploadVerificationMode::SafeRetrieval => {
            validate_extractor(
                verification
                    .path_extractor
                    .as_ref()
                    .ok_or(IntruderError::InvalidRequest)?,
            )?;
            if verification.expected_execution_marker.is_some() {
                return Err(IntruderError::InvalidRequest);
            }
        }
        UploadVerificationMode::Execution => {
            validate_extractor(
                verification
                    .path_extractor
                    .as_ref()
                    .ok_or(IntruderError::InvalidRequest)?,
            )?;
            let marker = verification
                .expected_execution_marker
                .as_deref()
                .ok_or(IntruderError::InvalidRequest)?;
            if marker.is_empty()
                || marker.len() > 256
                || marker
                    .iter()
                    .any(|byte| matches!(*byte, 0..=8 | 11 | 12 | 14..=31 | 127))
            {
                return Err(IntruderError::InvalidRequest);
            }
        }
    }
    Ok(())
}

fn save_upload_audit(
    store: &ProjectStore,
    project_id: &ProjectId,
    risk_level: RiskLevel,
    outcome: &str,
    parent: &HttpMessage,
    verification: &UploadVerification,
) -> Result<(), IntruderError> {
    let marker_sha256 = verification
        .expected_execution_marker
        .as_deref()
        .map(|marker| format!("{:x}", Sha256::digest(marker)));
    store.save_audit_event(&flagdeck_domain::AuditEvent {
        audit_event_id: flagdeck_domain::AuditEventId::new(),
        project_id: project_id.clone(),
        adapter_id: None,
        action: "upload.execution_verification".to_owned(),
        risk_level,
        outcome: outcome.to_owned(),
        target_summary: format!(
            "{}://{}:{}{}",
            parent.scheme, parent.host, parent.port, parent.path
        ),
        details_json: serde_json::json!({
            "parent_message_id": parent.message_id.0,
            "expected_execution_marker_sha256": marker_sha256,
        })
        .to_string(),
        created_at: Timestamp::now(),
    })?;
    Ok(())
}

fn run_campaign(
    shared: &ActiveCampaigns,
    store: &ProjectStore,
    mut campaign: IntruderCampaign,
    cancellation: &AtomicBool,
) -> Result<(), IntruderError> {
    let config: CampaignExecutionConfig = serde_json::from_str(
        campaign
            .state_macro_json
            .as_deref()
            .ok_or(IntruderError::InvalidRequest)?,
    )?;
    let parent = validate_parent(store, &campaign.project_id, &campaign.parent_message_id)?;
    let scope = store.target_scope(&campaign.scope_id)?;
    validate_parent_scope(&parent, &scope)?;
    let base_body = message_body(store, &parent)?;
    let counts = if campaign.campaign_kind == IntruderCampaignKind::Intruder {
        dictionary_counts(store, &campaign.dictionary_ids)?
    } else {
        Vec::new()
    };
    let mut dictionary_cache = DictionaryCache::default();
    campaign.state = IntruderCampaignState::Running;
    campaign.started_at.get_or_insert_with(Timestamp::now);
    campaign.stopped_at = None;
    store.save_intruder_campaign(&campaign)?;

    while campaign.next_ordinal < campaign.total_attempts {
        if cancellation.load(Ordering::SeqCst) {
            campaign.state = IntruderCampaignState::Paused;
            campaign.stopped_at = Some(Timestamp::now());
            store.save_intruder_campaign(&campaign)?;
            return Ok(());
        }
        throttle(
            shared,
            &format!("{}:{}", parent.host, parent.port),
            campaign.global_rate_per_second,
            campaign.target_rate_per_second,
        )?;
        let ordinal = campaign.next_ordinal;
        let execution = match &config {
            CampaignExecutionConfig::Intruder { state_macro } => {
                let payloads = payloads_for_ordinal(
                    store,
                    &mut dictionary_cache,
                    campaign.attack_mode,
                    &campaign.dictionary_ids,
                    &counts,
                    campaign.positions.len(),
                    ordinal,
                )?;
                execute_attempt(
                    store,
                    &campaign,
                    &scope,
                    &parent,
                    &base_body,
                    payloads,
                    state_macro.as_ref(),
                    None,
                    None,
                    ordinal,
                )
            }
            CampaignExecutionConfig::Upload {
                part_ordinal,
                mutations,
                state_macro,
                verification,
            } => {
                let mutation_index =
                    usize::try_from(ordinal).map_err(|_| IntruderError::InvalidRequest)?;
                let mutation = *mutations
                    .get(mutation_index)
                    .ok_or(IntruderError::InvalidRequest)?;
                execute_upload_attempt(
                    store,
                    &campaign,
                    &scope,
                    &parent,
                    &base_body,
                    *part_ordinal,
                    mutation,
                    state_macro.as_ref(),
                    verification,
                    ordinal,
                )
            }
        };
        match execution {
            Ok(()) => campaign.completed_attempts = campaign.completed_attempts.saturating_add(1),
            Err(error) => {
                campaign.failed_attempts = campaign.failed_attempts.saturating_add(1);
                campaign.error_summary = Some(error.to_string());
            }
        }
        campaign.next_ordinal = ordinal.saturating_add(1);
        store.save_intruder_campaign(&campaign)?;
    }
    campaign.state = IntruderCampaignState::Completed;
    campaign.stopped_at = Some(Timestamp::now());
    store.save_intruder_campaign(&campaign)?;
    Ok(())
}

fn throttle(
    shared: &ActiveCampaigns,
    target: &str,
    global_rate: u32,
    target_rate: u32,
) -> Result<(), IntruderError> {
    let now = Instant::now();
    let global_interval = Duration::from_secs_f64(1.0 / f64::from(global_rate));
    let target_interval = Duration::from_secs_f64(1.0 / f64::from(target_rate));
    let global_ready = {
        let mut next = shared
            .next_global
            .lock()
            .map_err(|_| IntruderError::StateLock)?;
        let ready = next.unwrap_or(now).max(now);
        *next = Some(ready + global_interval);
        ready
    };
    let target_ready = {
        let mut targets = shared
            .next_target
            .lock()
            .map_err(|_| IntruderError::StateLock)?;
        let ready = targets.get(target).copied().unwrap_or(now).max(now);
        targets.insert(target.to_owned(), ready + target_interval);
        ready
    };
    let ready = global_ready.max(target_ready);
    if ready > now {
        thread::sleep(ready.duration_since(now));
    }
    Ok(())
}

#[derive(Default)]
struct DictionaryCache {
    pages: HashMap<DictionaryId, (u64, Vec<String>)>,
}

impl DictionaryCache {
    fn term(
        &mut self,
        store: &ProjectStore,
        dictionary_id: &DictionaryId,
        ordinal: u64,
    ) -> Result<Vec<u8>, IntruderError> {
        let page_size =
            u64::try_from(DICTIONARY_PAGE_SIZE).map_err(|_| IntruderError::InvalidRequest)?;
        let page_start = (ordinal / page_size) * page_size;
        let reload = self
            .pages
            .get(dictionary_id)
            .is_none_or(|(start, _)| *start != page_start);
        if reload {
            let terms =
                store.dictionary_terms_page(dictionary_id, page_start, DICTIONARY_PAGE_SIZE)?;
            self.pages
                .insert(dictionary_id.clone(), (page_start, terms));
        }
        let index = usize::try_from(ordinal.saturating_sub(page_start))
            .map_err(|_| IntruderError::InvalidRequest)?;
        self.pages
            .get(dictionary_id)
            .and_then(|(_, terms)| terms.get(index))
            .map(|term| term.as_bytes().to_vec())
            .ok_or(IntruderError::InvalidRequest)
    }
}

fn payloads_for_ordinal(
    store: &ProjectStore,
    cache: &mut DictionaryCache,
    mode: IntruderAttackMode,
    dictionary_ids: &[DictionaryId],
    counts: &[u64],
    position_count: usize,
    ordinal: u64,
) -> Result<Vec<Option<Vec<u8>>>, IntruderError> {
    let mut payloads = vec![None; position_count];
    match mode {
        IntruderAttackMode::Sniper => {
            let count = counts[0];
            let position =
                usize::try_from(ordinal / count).map_err(|_| IntruderError::InvalidRequest)?;
            payloads[position] = Some(cache.term(store, &dictionary_ids[0], ordinal % count)?);
        }
        IntruderAttackMode::BatteringRam => {
            let payload = cache.term(store, &dictionary_ids[0], ordinal)?;
            payloads.fill(Some(payload));
        }
        IntruderAttackMode::Pitchfork => {
            for (index, dictionary_id) in dictionary_ids.iter().enumerate() {
                payloads[index] = Some(cache.term(store, dictionary_id, ordinal)?);
            }
        }
        IntruderAttackMode::ClusterBomb => {
            let mut remainder = ordinal;
            for index in (0..position_count).rev() {
                let term_ordinal = remainder % counts[index];
                remainder /= counts[index];
                payloads[index] = Some(cache.term(store, &dictionary_ids[index], term_ordinal)?);
            }
        }
    }
    Ok(payloads)
}

#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
fn execute_attempt(
    store: &ProjectStore,
    campaign: &IntruderCampaign,
    scope: &TargetScope,
    parent: &HttpMessage,
    base_body: &[u8],
    payloads: Vec<Option<Vec<u8>>>,
    state_macro: Option<&StateMacro>,
    prebuilt_body: Option<Vec<u8>>,
    upload_verification: Option<(&UploadVerification, Vec<u8>)>,
    ordinal: u64,
) -> Result<(), IntruderError> {
    let attempt_id = IntruderAttemptId::new();
    let applied = payloads.iter().flatten().cloned().collect::<Vec<_>>();
    let payload_sha256 = applied
        .iter()
        .map(|payload| format!("{:x}", Sha256::digest(payload)))
        .collect::<Vec<_>>();
    let payload_preview = applied
        .iter()
        .map(|payload| preview_bytes(payload))
        .collect();
    let mut attempt = IntruderAttempt {
        intruder_attempt_id: attempt_id.clone(),
        intruder_campaign_id: campaign.intruder_campaign_id.clone(),
        project_id: campaign.project_id.clone(),
        ordinal,
        payload_sha256,
        payload_preview,
        state: IntruderAttemptState::RequestFailed,
        request_message_id: None,
        response_message_id: None,
        response_status: None,
        response_length: None,
        duration_millis: None,
        evidence_artifact_id: None,
        state_chain_run_id: None,
        verification_summary: None,
        error_summary: None,
        created_at: Timestamp::now(),
    };
    store.save_intruder_attempt(&attempt)?;
    let variables = match execute_state_macro(store, campaign, scope, &attempt_id, state_macro) {
        Ok((variables, run_id)) => {
            attempt.state_chain_run_id = run_id;
            variables
        }
        Err(error) => {
            attempt.state = IntruderAttemptState::MacroFailed;
            attempt.error_summary = Some(error.to_string());
            store.save_intruder_attempt(&attempt)?;
            return Err(error);
        }
    };
    let mut path = substitute_string(&parent.path, &variables)?;
    let mut headers = parent
        .headers
        .iter()
        .map(|header| {
            Ok(OrderedValue {
                name: header.name.clone(),
                value: substitute_string(&header.value, &variables)?,
            })
        })
        .collect::<Result<Vec<_>, IntruderError>>()?;
    let mut body = substitute_bytes(prebuilt_body.as_deref().unwrap_or(base_body), &variables)?;
    if prebuilt_body.is_none() {
        if campaign
            .positions
            .iter()
            .any(|position| is_multipart_location(position.location))
        {
            if !campaign
                .positions
                .iter()
                .all(|position| is_multipart_location(position.location))
            {
                return Err(IntruderError::InvalidRequest);
            }
            body = apply_multipart_positions(parent, &campaign.positions, &payloads, &body)?;
        } else {
            apply_payload_positions(
                &campaign.positions,
                &payloads,
                &mut path,
                &mut headers,
                &mut body,
            )?;
        }
    }
    let result = repeat_http_message(
        store,
        scope,
        &RepeatHttpRequest {
            project_id: campaign.project_id.clone(),
            scope_id: campaign.scope_id.clone(),
            parent_message_id: parent.message_id.clone(),
            method: parent.method.clone().ok_or(IntruderError::InvalidRequest)?,
            path,
            headers,
            body,
            ssl_insecure: false,
        },
    );
    match result {
        Ok(result) => {
            populate_attempt_response(&mut attempt, &result);
            attempt.state = IntruderAttemptState::Succeeded;
            if let Some((verification, expected)) = upload_verification {
                verify_upload(
                    store,
                    campaign,
                    scope,
                    parent,
                    &result,
                    verification,
                    &expected,
                    &mut attempt,
                )?;
            }
            let evidence = commit_attempt_evidence(store, &attempt)?;
            attempt.evidence_artifact_id = Some(evidence.artifact_id);
            store.save_intruder_attempt(&attempt)?;
            Ok(())
        }
        Err(error) => {
            attempt.error_summary = Some(error.to_string());
            store.save_intruder_attempt(&attempt)?;
            Err(error.into())
        }
    }
}

fn populate_attempt_response(attempt: &mut IntruderAttempt, result: &RepeatHttpResult) {
    attempt.request_message_id = Some(result.request.message_id.clone());
    attempt.response_message_id = Some(result.response.message_id.clone());
    attempt.response_status = result.response.status_code;
    attempt.response_length = Some(result.response.actual_length);
    attempt.duration_millis = result.response.duration_millis;
}

#[allow(clippy::too_many_arguments)]
fn execute_upload_attempt(
    store: &ProjectStore,
    campaign: &IntruderCampaign,
    scope: &TargetScope,
    parent: &HttpMessage,
    base_body: &[u8],
    part_ordinal: usize,
    mutation: UploadMutationKind,
    state_macro: Option<&StateMacro>,
    verification: &UploadVerification,
    ordinal: u64,
) -> Result<(), IntruderError> {
    let mut document = parse_multipart_message(parent, base_body)?;
    prepare_upload_mutation(
        &mut document,
        &campaign.intruder_campaign_id,
        part_ordinal,
        mutation,
        verification.mode,
        ordinal,
    )?;
    let expected_body = document
        .parts
        .get(part_ordinal)
        .ok_or(IntruderError::Multipart)?
        .body
        .clone();
    let body = serialize_multipart(&document)?;
    execute_attempt(
        store,
        campaign,
        scope,
        parent,
        base_body,
        vec![Some(format!("{mutation:?}").into_bytes())],
        state_macro,
        Some(body),
        Some((verification, expected_body)),
        ordinal,
    )
}

fn commit_attempt_evidence(
    store: &ProjectStore,
    attempt: &IntruderAttempt,
) -> Result<Artifact, IntruderError> {
    let bytes = serde_json::to_vec_pretty(attempt)?;
    Ok(store.commit_artifact(
        &ArtifactWriteRequest {
            logical_name: format!("intruder-attempt-{}.json", attempt.intruder_attempt_id.0),
            mime: "application/json".to_owned(),
            sensitivity: Sensitivity::SensitiveEvidence,
            export_policy: ExportPolicy::ConfirmSensitive,
            source_job_id: None,
            source_message_id: attempt.response_message_id.clone(),
            expected_size: Some(
                u64::try_from(bytes.len()).map_err(|_| IntruderError::InvalidRequest)?,
            ),
            expected_sha256: Some(format!("{:x}", Sha256::digest(&bytes))),
        },
        bytes.as_slice(),
    )?)
}

fn preview_bytes(bytes: &[u8]) -> String {
    let length = bytes.len().min(64);
    String::from_utf8_lossy(&bytes[..length])
        .chars()
        .flat_map(char::escape_default)
        .take(256)
        .collect()
}

fn execute_state_macro(
    store: &ProjectStore,
    campaign: &IntruderCampaign,
    scope: &TargetScope,
    attempt_id: &IntruderAttemptId,
    state_macro: Option<&StateMacro>,
) -> Result<StateMacroOutcome, IntruderError> {
    let Some(state_macro) = state_macro else {
        return Ok((BTreeMap::new(), None));
    };
    let mut variables = BTreeMap::new();
    let mut evidence = Vec::with_capacity(state_macro.steps.len());
    for step in &state_macro.steps {
        let template = validate_parent(store, &campaign.project_id, &step.message_id)?;
        validate_parent_scope(&template, scope)?;
        let body = substitute_bytes(&message_body(store, &template)?, &variables)?;
        let headers = template
            .headers
            .iter()
            .map(|header| {
                Ok(OrderedValue {
                    name: header.name.clone(),
                    value: substitute_string(&header.value, &variables)?,
                })
            })
            .collect::<Result<Vec<_>, IntruderError>>()?;
        let result = repeat_http_message(
            store,
            scope,
            &RepeatHttpRequest {
                project_id: campaign.project_id.clone(),
                scope_id: campaign.scope_id.clone(),
                parent_message_id: template.message_id.clone(),
                method: template
                    .method
                    .clone()
                    .ok_or(IntruderError::InvalidRequest)?,
                path: substitute_string(&template.path, &variables)?,
                headers,
                body,
                ssl_insecure: false,
            },
        )?;
        let response_body = message_body(store, &result.response)?;
        let mut extracted = Vec::new();
        for extractor in &step.extractors {
            let value = extract_token(extractor, &result.response, &response_body)?;
            variables.insert(extractor.variable.clone(), value);
            extracted.push(extractor.variable.clone());
        }
        evidence.push(StateChainStepEvidence {
            name: step.name.clone(),
            request_message_id: Some(result.request.message_id),
            response_message_id: Some(result.response.message_id),
            outcome: "succeeded".to_owned(),
            extracted_variables: extracted,
        });
    }
    let run = StateChainRun {
        state_chain_run_id: StateChainRunId::new(),
        project_id: campaign.project_id.clone(),
        intruder_attempt_id: attempt_id.clone(),
        steps: evidence,
        created_at: Timestamp::now(),
    };
    store.save_state_chain_run(&run)?;
    Ok((variables, Some(run.state_chain_run_id)))
}

fn extract_token(
    extractor: &TokenExtractor,
    response: &HttpMessage,
    response_body: &[u8],
) -> Result<Vec<u8>, IntruderError> {
    let source = match extractor.source {
        TokenSource::ResponseBody => response_body.to_vec(),
        TokenSource::ResponseHeader => response
            .headers
            .iter()
            .find(|header| {
                extractor
                    .header_name
                    .as_ref()
                    .is_some_and(|name| header.name.eq_ignore_ascii_case(name))
            })
            .map(|header| header.value.as_bytes().to_vec())
            .ok_or(IntruderError::InvalidRequest)?,
    };
    let start = if extractor.prefix.is_empty() {
        0
    } else {
        find_bytes(&source, &extractor.prefix)
            .map(|index| index + extractor.prefix.len())
            .ok_or(IntruderError::InvalidRequest)?
    };
    let remainder = source.get(start..).ok_or(IntruderError::InvalidRequest)?;
    let length = if extractor.suffix.is_empty() {
        remainder.len().min(extractor.maximum_length)
    } else {
        find_bytes(remainder, &extractor.suffix).ok_or(IntruderError::InvalidRequest)?
    };
    if length == 0 || length > extractor.maximum_length {
        return Err(IntruderError::InvalidRequest);
    }
    Ok(remainder[..length].to_vec())
}

fn substitute_string(
    value: &str,
    variables: &BTreeMap<String, Vec<u8>>,
) -> Result<String, IntruderError> {
    let bytes = substitute_bytes(value.as_bytes(), variables)?;
    String::from_utf8(bytes).map_err(|_| IntruderError::InvalidRequest)
}

fn substitute_bytes(
    value: &[u8],
    variables: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, IntruderError> {
    let mut output = value.to_vec();
    for (name, replacement) in variables {
        let marker = format!("{{{{{name}}}}}").into_bytes();
        output = replace_all_bytes(&output, &marker, replacement)?;
    }
    if output.len() > MAX_MULTIPART_BYTES {
        return Err(IntruderError::InvalidRequest);
    }
    Ok(output)
}

fn apply_payload_positions(
    positions: &[PayloadPosition],
    payloads: &[Option<Vec<u8>>],
    path: &mut String,
    headers: &mut [OrderedValue],
    body: &mut Vec<u8>,
) -> Result<(), IntruderError> {
    if positions.len() != payloads.len() {
        return Err(IntruderError::InvalidRequest);
    }
    let mut byte_ranges = Vec::new();
    for (position, payload) in positions.iter().zip(payloads) {
        let Some(payload) = payload else {
            continue;
        };
        match position.location {
            PayloadLocation::ByteRange => byte_ranges.push((
                position.start.ok_or(IntruderError::InvalidRequest)?,
                position.end.ok_or(IntruderError::InvalidRequest)?,
                payload.clone(),
            )),
            PayloadLocation::Path => {
                *path = replace_occurrence_string(
                    path,
                    position
                        .name
                        .as_deref()
                        .ok_or(IntruderError::InvalidRequest)?,
                    position.occurrence,
                    &percent_encode(payload),
                )?;
            }
            PayloadLocation::Header => replace_header_occurrence(
                headers,
                position
                    .name
                    .as_deref()
                    .ok_or(IntruderError::InvalidRequest)?,
                position.occurrence,
                payload,
            )?,
            PayloadLocation::Query => {
                *path = replace_query_value(
                    path,
                    position
                        .name
                        .as_deref()
                        .ok_or(IntruderError::InvalidRequest)?,
                    position.occurrence,
                    payload,
                )?;
            }
            PayloadLocation::Form => {
                *body = replace_form_value(
                    body,
                    position
                        .name
                        .as_deref()
                        .ok_or(IntruderError::InvalidRequest)?,
                    position.occurrence,
                    payload,
                )?;
            }
            PayloadLocation::MultipartName
            | PayloadLocation::MultipartFilename
            | PayloadLocation::MultipartBody
            | PayloadLocation::MultipartContentType => {
                return Err(IntruderError::InvalidRequest);
            }
        }
    }
    byte_ranges.sort_by_key(|entry| Reverse(entry.0));
    let mut previous_start = usize::MAX;
    for (start, end, payload) in byte_ranges {
        if end > body.len() || end > previous_start || start >= end {
            return Err(IntruderError::InvalidRequest);
        }
        body.splice(start..end, payload);
        previous_start = start;
    }
    if body.len() > MAX_MULTIPART_BYTES {
        return Err(IntruderError::InvalidRequest);
    }
    Ok(())
}

fn replace_header_occurrence(
    headers: &mut [OrderedValue],
    name: &str,
    occurrence: usize,
    payload: &[u8],
) -> Result<(), IntruderError> {
    let value = String::from_utf8(payload.to_vec()).map_err(|_| IntruderError::InvalidRequest)?;
    if value.contains(['\r', '\n', '\0']) {
        return Err(IntruderError::InvalidRequest);
    }
    let header = headers
        .iter_mut()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .nth(occurrence)
        .ok_or(IntruderError::InvalidRequest)?;
    header.value = value;
    Ok(())
}

fn replace_query_value(
    path: &str,
    name: &str,
    occurrence: usize,
    payload: &[u8],
) -> Result<String, IntruderError> {
    let Some((base, query)) = path.split_once('?') else {
        return Err(IntruderError::InvalidRequest);
    };
    let replaced = replace_parameter_value(query.as_bytes(), name, occurrence, payload)?;
    Ok(format!("{base}?{}", String::from_utf8_lossy(&replaced)))
}

fn replace_form_value(
    body: &[u8],
    name: &str,
    occurrence: usize,
    payload: &[u8],
) -> Result<Vec<u8>, IntruderError> {
    replace_parameter_value(body, name, occurrence, payload)
}

fn replace_parameter_value(
    bytes: &[u8],
    name: &str,
    occurrence: usize,
    payload: &[u8],
) -> Result<Vec<u8>, IntruderError> {
    let mut seen = 0_usize;
    let mut output = Vec::with_capacity(bytes.len() + payload.len());
    for (index, pair) in bytes.split(|byte| *byte == b'&').enumerate() {
        if index > 0 {
            output.push(b'&');
        }
        let equals = pair.iter().position(|byte| *byte == b'=');
        let key = equals.map_or(pair, |position| &pair[..position]);
        if key == name.as_bytes() && seen == occurrence {
            output.extend_from_slice(key);
            output.push(b'=');
            output.extend_from_slice(percent_encode(payload).as_bytes());
            seen = seen.saturating_add(1);
            continue;
        }
        if key == name.as_bytes() {
            seen = seen.saturating_add(1);
        }
        output.extend_from_slice(pair);
    }
    if seen <= occurrence {
        return Err(IntruderError::InvalidRequest);
    }
    Ok(output)
}

fn replace_occurrence_string(
    value: &str,
    needle: &str,
    occurrence: usize,
    replacement: &str,
) -> Result<String, IntruderError> {
    if needle.is_empty() {
        return Err(IntruderError::InvalidRequest);
    }
    let (start, matched) = value
        .match_indices(needle)
        .nth(occurrence)
        .ok_or(IntruderError::InvalidRequest)?;
    let mut output = String::with_capacity(value.len() + replacement.len());
    output.push_str(&value[..start]);
    output.push_str(replacement);
    output.push_str(&value[start + matched.len()..]);
    Ok(output)
}

fn percent_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 3);
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push('%');
            let _ = write!(encoded, "{byte:02X}");
        }
    }
    encoded
}

const GIF_MAGIC: &[u8] = b"GIF89a";
const GIF_POLYGLOT_HEADER: &[u8] = b"GIF89a\x01\x00\x01\x00\x80\x00\x00";

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn find_bytes_from(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let slice = haystack.get(from..)?;
    find_bytes(slice, needle).map(|index| index + from)
}

fn replace_all_bytes(
    source: &[u8],
    needle: &[u8],
    replacement: &[u8],
) -> Result<Vec<u8>, IntruderError> {
    if needle.is_empty() {
        return Ok(source.to_vec());
    }
    let mut output = Vec::with_capacity(source.len());
    let mut cursor = 0;
    while cursor < source.len() {
        if let Some(index) = find_bytes_from(source, needle, cursor) {
            output.extend_from_slice(&source[cursor..index]);
            output.extend_from_slice(replacement);
            cursor = index + needle.len();
        } else {
            output.extend_from_slice(&source[cursor..]);
            break;
        }
        if output.len() > MAX_MULTIPART_BYTES {
            return Err(IntruderError::InvalidRequest);
        }
    }
    Ok(output)
}

const fn is_multipart_location(location: PayloadLocation) -> bool {
    matches!(
        location,
        PayloadLocation::MultipartName
            | PayloadLocation::MultipartFilename
            | PayloadLocation::MultipartBody
            | PayloadLocation::MultipartContentType
    )
}

fn multipart_boundary(parent: &HttpMessage) -> Result<Vec<u8>, IntruderError> {
    let content_type = parent
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
        .ok_or(IntruderError::Multipart)?;
    extract_boundary(content_type.value.as_bytes())
}

fn extract_boundary(content_type: &[u8]) -> Result<Vec<u8>, IntruderError> {
    let lower = content_type.to_ascii_lowercase();
    let marker = b"boundary=";
    let index = find_bytes(&lower, marker).ok_or(IntruderError::Multipart)?;
    let rest = content_type
        .get(index + marker.len()..)
        .ok_or(IntruderError::Multipart)?;
    let boundary = if rest.first() == Some(&b'"') {
        let inner = &rest[1..];
        let end = find_bytes(inner, b"\"").ok_or(IntruderError::Multipart)?;
        inner[..end].to_vec()
    } else {
        let end = rest
            .iter()
            .position(|byte| matches!(byte, b';' | b' ' | b'\t'))
            .unwrap_or(rest.len());
        rest[..end].to_vec()
    };
    if boundary.is_empty()
        || boundary.len() > 200
        || boundary
            .iter()
            .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(IntruderError::Multipart);
    }
    Ok(boundary)
}

fn parse_multipart_message(
    parent: &HttpMessage,
    body: &[u8],
) -> Result<MultipartDocument, IntruderError> {
    let boundary = multipart_boundary(parent)?;
    parse_multipart(&boundary, body)
}

fn read_line_ending(bytes: &[u8]) -> Result<(Vec<u8>, usize), IntruderError> {
    if bytes.starts_with(b"\r\n") {
        Ok((b"\r\n".to_vec(), 2))
    } else if bytes.starts_with(b"\n") {
        Ok((b"\n".to_vec(), 1))
    } else {
        Err(IntruderError::Multipart)
    }
}

fn find_header_separator(bytes: &[u8]) -> Result<(usize, Vec<u8>), IntruderError> {
    let crlf = find_bytes(bytes, b"\r\n\r\n");
    let lf = find_bytes(bytes, b"\n\n");
    match (crlf, lf) {
        (Some(crlf), Some(lf)) => {
            if crlf <= lf {
                Ok((crlf, b"\r\n\r\n".to_vec()))
            } else {
                Ok((lf, b"\n\n".to_vec()))
            }
        }
        (Some(crlf), None) => Ok((crlf, b"\r\n\r\n".to_vec())),
        (None, Some(lf)) => Ok((lf, b"\n\n".to_vec())),
        (None, None) => Err(IntruderError::Multipart),
    }
}

fn parse_multipart(boundary: &[u8], body: &[u8]) -> Result<MultipartDocument, IntruderError> {
    if body.len() > MAX_MULTIPART_BYTES {
        return Err(IntruderError::Multipart);
    }
    let mut dash = Vec::with_capacity(boundary.len() + 2);
    dash.extend_from_slice(b"--");
    dash.extend_from_slice(boundary);
    let first = find_bytes(body, &dash).ok_or(IntruderError::Multipart)?;
    let preamble = body[..first].to_vec();
    let mut parts = Vec::new();
    let mut cursor = first;
    let closing_suffix;
    loop {
        if body.get(cursor..cursor + dash.len()) != Some(dash.as_slice()) {
            return Err(IntruderError::Multipart);
        }
        let after = cursor + dash.len();
        if body.get(after..after + 2) == Some(b"--".as_slice()) {
            closing_suffix = body.get(after + 2..).unwrap_or_default().to_vec();
            break;
        }
        let rest = body.get(after..).ok_or(IntruderError::Multipart)?;
        let (opening_line_ending, opening_len) = read_line_ending(rest)?;
        let header_start = after + opening_len;
        let header_region = body.get(header_start..).ok_or(IntruderError::Multipart)?;
        let (separator_offset, header_body_separator) = find_header_separator(header_region)?;
        let raw_headers = header_region[..separator_offset].to_vec();
        let body_start = header_start + separator_offset + header_body_separator.len();
        let (part_body, boundary_prefix, next_cursor) =
            find_next_delimiter(body, body_start, &dash)?;
        let (name, filename, content_type) = parse_part_headers(&raw_headers);
        parts.push(MultipartPart {
            ordinal: parts.len(),
            opening_line_ending,
            raw_headers,
            header_body_separator,
            body: part_body,
            boundary_prefix,
            name,
            filename,
            content_type,
        });
        if parts.len() > 1024 {
            return Err(IntruderError::Multipart);
        }
        cursor = next_cursor;
    }
    let document = MultipartDocument {
        boundary: boundary.to_vec(),
        preamble,
        parts,
        closing_suffix,
    };
    document.validate().map_err(|_| IntruderError::Multipart)?;
    Ok(document)
}

fn find_next_delimiter(
    body: &[u8],
    body_start: usize,
    dash: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, usize), IntruderError> {
    let mut search = body_start;
    loop {
        let delimiter = find_bytes_from(body, dash, search).ok_or(IntruderError::Multipart)?;
        if delimiter >= 2 && &body[delimiter - 2..delimiter] == b"\r\n" {
            return Ok((
                body[body_start..delimiter - 2].to_vec(),
                b"\r\n".to_vec(),
                delimiter,
            ));
        }
        if delimiter >= 1 && body[delimiter - 1] == b'\n' {
            return Ok((
                body[body_start..delimiter - 1].to_vec(),
                b"\n".to_vec(),
                delimiter,
            ));
        }
        search = delimiter + dash.len();
    }
}

fn split_header_lines(raw: &[u8]) -> Vec<Vec<u8>> {
    raw.split(|byte| *byte == b'\n')
        .map(|line| {
            line.strip_suffix(b"\r")
                .map_or_else(|| line.to_vec(), <[u8]>::to_vec)
        })
        .collect()
}

fn parse_part_headers(raw: &[u8]) -> PartHeaderFields {
    let mut name = None;
    let mut filename = None;
    let mut content_type = None;
    for line in split_header_lines(raw) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with(b"content-disposition:") {
            name = extract_quoted_param(&line, b"name");
            filename = extract_quoted_param(&line, b"filename");
        } else if lower.starts_with(b"content-type:") {
            content_type = line
                .get("content-type:".len()..)
                .map(|value| trim_ascii(value).to_vec());
        }
    }
    (name, filename, content_type)
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

fn extract_quoted_param(line: &[u8], param: &[u8]) -> Option<Vec<u8>> {
    let lower = line.to_ascii_lowercase();
    let mut marker = param.to_ascii_lowercase();
    marker.extend_from_slice(b"=\"");
    let index = find_bytes(&lower, &marker)?;
    let value_start = index + marker.len();
    let inner = line.get(value_start..)?;
    let end = find_bytes(inner, b"\"")?;
    Some(inner[..end].to_vec())
}

fn header_eol(separator: &[u8]) -> &'static [u8] {
    if separator == b"\r\n\r\n" {
        b"\r\n"
    } else {
        b"\n"
    }
}

fn serialize_multipart(document: &MultipartDocument) -> Result<Vec<u8>, IntruderError> {
    document.validate().map_err(|_| IntruderError::Multipart)?;
    let mut output = document.preamble.clone();
    for part in &document.parts {
        output.extend_from_slice(b"--");
        output.extend_from_slice(&document.boundary);
        output.extend_from_slice(&part.opening_line_ending);
        output.extend_from_slice(&part.raw_headers);
        output.extend_from_slice(&part.header_body_separator);
        output.extend_from_slice(&part.body);
        output.extend_from_slice(&part.boundary_prefix);
    }
    output.extend_from_slice(b"--");
    output.extend_from_slice(&document.boundary);
    output.extend_from_slice(b"--");
    output.extend_from_slice(&document.closing_suffix);
    if output.len() > MAX_MULTIPART_BYTES {
        return Err(IntruderError::Multipart);
    }
    Ok(output)
}

fn header_safe(value: &[u8]) -> bool {
    !value
        .iter()
        .any(|byte| matches!(byte, b'\r' | b'\n' | 0 | b'"'))
}

fn replace_quoted_param(
    raw: &mut Vec<u8>,
    param: &[u8],
    value: &[u8],
) -> Result<(), IntruderError> {
    if !header_safe(value) {
        return Err(IntruderError::Multipart);
    }
    let lower = raw.to_ascii_lowercase();
    let mut marker = param.to_ascii_lowercase();
    marker.extend_from_slice(b"=\"");
    let index = find_bytes(&lower, &marker).ok_or(IntruderError::Multipart)?;
    let value_start = index + marker.len();
    let inner = raw.get(value_start..).ok_or(IntruderError::Multipart)?;
    let end = find_bytes(inner, b"\"").ok_or(IntruderError::Multipart)?;
    let mut output = raw[..value_start].to_vec();
    output.extend_from_slice(value);
    output.extend_from_slice(&raw[value_start + end..]);
    *raw = output;
    Ok(())
}

fn set_content_type(part: &mut MultipartPart, value: &[u8]) -> Result<(), IntruderError> {
    if !header_safe(value) {
        return Err(IntruderError::Multipart);
    }
    let eol = header_eol(&part.header_body_separator);
    let lower = part.raw_headers.to_ascii_lowercase();
    if let Some(index) = find_bytes(&lower, b"content-type:") {
        let value_start = index + "content-type:".len();
        let rest = part
            .raw_headers
            .get(value_start..)
            .ok_or(IntruderError::Multipart)?;
        let line_end = find_bytes(rest, b"\n").map_or(rest.len(), |newline| {
            if newline > 0 && rest[newline - 1] == b'\r' {
                newline - 1
            } else {
                newline
            }
        });
        let mut output = part.raw_headers[..value_start].to_vec();
        output.push(b' ');
        output.extend_from_slice(value);
        output.extend_from_slice(&part.raw_headers[value_start + line_end..]);
        part.raw_headers = output;
    } else {
        part.raw_headers.extend_from_slice(eol);
        part.raw_headers.extend_from_slice(b"Content-Type: ");
        part.raw_headers.extend_from_slice(value);
    }
    part.content_type = Some(value.to_vec());
    Ok(())
}

fn apply_multipart_positions(
    parent: &HttpMessage,
    positions: &[PayloadPosition],
    payloads: &[Option<Vec<u8>>],
    body: &[u8],
) -> Result<Vec<u8>, IntruderError> {
    if positions.len() != payloads.len() {
        return Err(IntruderError::InvalidRequest);
    }
    let boundary = multipart_boundary(parent)?;
    let mut document = parse_multipart(&boundary, body)?;
    for (position, payload) in positions.iter().zip(payloads) {
        let Some(payload) = payload else {
            continue;
        };
        let part = document
            .parts
            .get_mut(position.occurrence)
            .ok_or(IntruderError::InvalidRequest)?;
        match position.location {
            PayloadLocation::MultipartName => {
                replace_quoted_param(&mut part.raw_headers, b"name", payload)?;
                part.name = Some(payload.clone());
            }
            PayloadLocation::MultipartFilename => {
                replace_quoted_param(&mut part.raw_headers, b"filename", payload)?;
                part.filename = Some(payload.clone());
            }
            PayloadLocation::MultipartContentType => set_content_type(part, payload)?,
            PayloadLocation::MultipartBody => part.body.clone_from(payload),
            _ => return Err(IntruderError::InvalidRequest),
        }
    }
    serialize_multipart(&document)
}

fn file_part_ordinal(
    document: &MultipartDocument,
    part_ordinal: usize,
) -> Result<usize, IntruderError> {
    if document
        .parts
        .get(part_ordinal)
        .and_then(|part| part.filename.as_ref())
        .is_none()
    {
        return Err(IntruderError::InvalidRequest);
    }
    Ok(part_ordinal)
}

fn prepare_upload_mutation(
    document: &mut MultipartDocument,
    campaign_id: &IntruderCampaignId,
    part_ordinal: usize,
    mutation: UploadMutationKind,
    verification_mode: UploadVerificationMode,
    attempt_ordinal: u64,
) -> Result<(), IntruderError> {
    let ordinal = file_part_ordinal(document, part_ordinal)?;
    if verification_mode != UploadVerificationMode::Execution {
        let marker = format!(
            "FLAGDECK_SAFE_UPLOAD\ncampaign={}\nattempt={attempt_ordinal}\n",
            campaign_id.0
        );
        document
            .parts
            .get_mut(ordinal)
            .ok_or(IntruderError::Multipart)?
            .body = marker.into_bytes();
    }
    mutate_upload(document, ordinal, mutation)
}

fn mutate_upload(
    document: &mut MultipartDocument,
    part_ordinal: usize,
    mutation: UploadMutationKind,
) -> Result<(), IntruderError> {
    let ordinal = file_part_ordinal(document, part_ordinal)?;
    if mutation == UploadMutationKind::ExtraFormField {
        return add_extra_form_field(document, ordinal);
    }
    let part = document
        .parts
        .get_mut(ordinal)
        .ok_or(IntruderError::Multipart)?;
    match mutation {
        UploadMutationKind::ExtensionCase => {
            let filename = current_filename(part)?;
            set_part_filename(part, &toggle_extension_case(&filename)?)?;
        }
        UploadMutationKind::DoubleExtension => {
            let filename = current_filename(part)?;
            set_part_filename(part, &double_extension(&filename)?)?;
        }
        UploadMutationKind::TrailingCharacter => {
            let filename = current_filename(part)?;
            let mut mutated = filename.clone();
            mutated.push(b' ');
            set_part_filename(part, &mutated)?;
        }
        UploadMutationKind::FilenameEncoding => {
            let filename = current_filename(part)?;
            set_part_filename(part, &encode_filename(&filename)?)?;
        }
        UploadMutationKind::ContentType => set_content_type(part, b"image/jpeg")?,
        UploadMutationKind::MagicBytes => {
            let mut mutated = GIF_MAGIC.to_vec();
            mutated.extend_from_slice(&part.body);
            part.body = mutated;
        }
        UploadMutationKind::ImagePolyglot => {
            let mut mutated = GIF_POLYGLOT_HEADER.to_vec();
            mutated.extend_from_slice(&part.body);
            part.body = mutated;
            set_content_type(part, b"image/gif")?;
        }
        UploadMutationKind::ExtraFormField => unreachable!(),
    }
    if document
        .parts
        .iter()
        .map(|part| part.body.len())
        .sum::<usize>()
        > MAX_MULTIPART_BYTES
    {
        return Err(IntruderError::Multipart);
    }
    Ok(())
}

fn current_filename(part: &MultipartPart) -> Result<Vec<u8>, IntruderError> {
    part.filename
        .clone()
        .or_else(|| extract_quoted_param(&part.raw_headers, b"filename"))
        .ok_or(IntruderError::Multipart)
}

fn set_part_filename(part: &mut MultipartPart, filename: &[u8]) -> Result<(), IntruderError> {
    replace_quoted_param(&mut part.raw_headers, b"filename", filename)?;
    part.filename = Some(filename.to_vec());
    Ok(())
}

fn split_extension(filename: &[u8]) -> Result<(usize, &[u8]), IntruderError> {
    let dot = filename
        .iter()
        .rposition(|byte| *byte == b'.')
        .ok_or(IntruderError::Multipart)?;
    if dot == 0 || dot + 1 >= filename.len() {
        return Err(IntruderError::Multipart);
    }
    Ok((dot, &filename[dot + 1..]))
}

fn toggle_extension_case(filename: &[u8]) -> Result<Vec<u8>, IntruderError> {
    let (dot, extension) = split_extension(filename)?;
    let mut output = filename[..=dot].to_vec();
    for (index, byte) in extension.iter().enumerate() {
        if index % 2 == 0 {
            output.push(byte.to_ascii_uppercase());
        } else {
            output.push(byte.to_ascii_lowercase());
        }
    }
    Ok(output)
}

fn double_extension(filename: &[u8]) -> Result<Vec<u8>, IntruderError> {
    let (dot, extension) = split_extension(filename)?;
    let mut output = filename[..dot].to_vec();
    output.extend_from_slice(b".jpg.");
    output.extend_from_slice(extension);
    Ok(output)
}

fn encode_filename(filename: &[u8]) -> Result<Vec<u8>, IntruderError> {
    let (dot, extension) = split_extension(filename)?;
    let mut output = filename[..dot].to_vec();
    output.extend_from_slice(b"%2e");
    output.extend_from_slice(extension);
    Ok(output)
}

fn add_extra_form_field(
    document: &mut MultipartDocument,
    reference_ordinal: usize,
) -> Result<(), IntruderError> {
    let reference = document
        .parts
        .get(reference_ordinal)
        .ok_or(IntruderError::Multipart)?;
    let opening_line_ending = reference.opening_line_ending.clone();
    let header_body_separator = reference.header_body_separator.clone();
    let boundary_prefix = reference.boundary_prefix.clone();
    let mut raw_headers = Vec::new();
    raw_headers.extend_from_slice(b"Content-Disposition: form-data; name=\"flagdeck_extra\"");
    let part = MultipartPart {
        ordinal: document.parts.len(),
        opening_line_ending,
        raw_headers,
        header_body_separator,
        body: b"1".to_vec(),
        boundary_prefix,
        name: Some(b"flagdeck_extra".to_vec()),
        filename: None,
        content_type: None,
    };
    document.parts.push(part);
    Ok(())
}

fn execution_marker_matches(retrieved: &[u8], expected_marker: &[u8]) -> bool {
    retrieved == expected_marker
}

#[allow(clippy::too_many_arguments)]
fn verify_upload(
    store: &ProjectStore,
    campaign: &IntruderCampaign,
    scope: &TargetScope,
    parent: &HttpMessage,
    upload_result: &RepeatHttpResult,
    verification: &UploadVerification,
    expected_body: &[u8],
    attempt: &mut IntruderAttempt,
) -> Result<(), IntruderError> {
    let execution = match verification.mode {
        UploadVerificationMode::None => return Ok(()),
        UploadVerificationMode::SafeRetrieval => false,
        UploadVerificationMode::Execution => true,
    };
    let extractor = verification
        .path_extractor
        .as_ref()
        .ok_or(IntruderError::InvalidRequest)?;
    let response_body = message_body(store, &upload_result.response)?;
    let Ok(path) = extract_token(extractor, &upload_result.response, &response_body) else {
        attempt.state = IntruderAttemptState::VerificationFailed;
        attempt.verification_summary = Some("upload_path_not_returned".to_owned());
        return Ok(());
    };
    let Some(path) = normalize_retrieval_path(&path, parent) else {
        attempt.state = IntruderAttemptState::VerificationFailed;
        attempt.verification_summary = Some("upload_path_invalid".to_owned());
        return Ok(());
    };
    let retrieval = repeat_http_message(
        store,
        scope,
        &RepeatHttpRequest {
            project_id: campaign.project_id.clone(),
            scope_id: campaign.scope_id.clone(),
            parent_message_id: parent.message_id.clone(),
            method: "GET".to_owned(),
            path,
            headers: Vec::new(),
            body: Vec::new(),
            ssl_insecure: false,
        },
    )?;
    let status = retrieval.response.status_code.unwrap_or(0);
    if !(200..300).contains(&status) {
        attempt.state = IntruderAttemptState::VerificationFailed;
        attempt.verification_summary = Some(format!("artifact_not_retrievable:status={status}"));
        return Ok(());
    }
    let retrieved = message_body(store, &retrieval.response)?;
    let retrieved_hash = format!("{:x}", Sha256::digest(&retrieved));
    let expected_hash = format!("{:x}", Sha256::digest(expected_body));
    if execution {
        let expected_marker = verification
            .expected_execution_marker
            .as_deref()
            .ok_or(IntruderError::InvalidRequest)?;
        if execution_marker_matches(&retrieved, expected_marker) {
            attempt.verification_summary = Some(format!(
                "execution_verified:retrieved_sha256={retrieved_hash}"
            ));
        } else if retrieved_hash == expected_hash {
            attempt.state = IntruderAttemptState::VerificationFailed;
            attempt.verification_summary = Some("source_returned_not_executed".to_owned());
        } else {
            attempt.state = IntruderAttemptState::VerificationFailed;
            attempt.verification_summary = Some("execution_not_confirmed".to_owned());
        }
    } else if retrieved_hash == expected_hash {
        attempt.verification_summary =
            Some(format!("safe_retrieval_verified:sha256={retrieved_hash}"));
    } else {
        attempt.state = IntruderAttemptState::VerificationFailed;
        attempt.verification_summary = Some("content_replaced_pseudo_success".to_owned());
    }
    Ok(())
}

fn normalize_retrieval_path(path: &[u8], parent: &HttpMessage) -> Option<String> {
    let path = std::str::from_utf8(path).ok()?.trim();
    if path.is_empty() || path.contains(['\r', '\n', '\0']) {
        return None;
    }
    if let Some(rest) = path
        .strip_prefix("http://")
        .or_else(|| path.strip_prefix("https://"))
    {
        let (authority, absolute) = rest
            .split_once('/')
            .map_or((rest, String::from("/")), |(authority, tail)| {
                (authority, format!("/{tail}"))
            });
        let host = authority.split(['@', ':']).next().unwrap_or(authority);
        if !host.eq_ignore_ascii_case(&parent.host) {
            return None;
        }
        return Some(absolute);
    }
    if path.starts_with('/') {
        Some(path.to_owned())
    } else {
        Some(format!("/{path}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = b"--X\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php echo 1;?>\r\n--X--\r\n";

    fn parse_fixture(raw: &[u8]) -> MultipartDocument {
        parse_multipart(b"X", raw).expect("fixture parses")
    }

    #[test]
    fn multipart_round_trips_crlf_exactly() {
        let document = parse_fixture(FIXTURE);
        assert_eq!(document.parts.len(), 2);
        assert_eq!(document.parts[0].name.as_deref(), Some(b"field".as_slice()));
        assert_eq!(
            document.parts[1].filename.as_deref(),
            Some(b"shell.php".as_slice())
        );
        assert_eq!(
            document.parts[1].content_type.as_deref(),
            Some(b"application/x-php".as_slice())
        );
        assert_eq!(document.parts[1].body, b"<?php echo 1;?>");
        assert_eq!(serialize_multipart(&document).unwrap(), FIXTURE);
    }

    #[test]
    fn multipart_round_trips_lf_preamble_epilogue_and_binary() {
        let raw = b"lead\n--Y\nContent-Disposition: form-data; name=\"a\"\n\nfirst\n--Y\nContent-Disposition: form-data; name=\"a\"\n\n\x00\x01\xff\n--Y--\ntail";
        let document = parse_multipart(b"Y", raw).unwrap();
        // the newline preceding the first delimiter stays in the preamble for exact bytes.
        assert_eq!(document.preamble, b"lead\n");
        assert_eq!(document.closing_suffix, b"\ntail");
        assert_eq!(document.parts.len(), 2);
        // duplicate field name preserved by ordinal.
        assert_eq!(document.parts[0].name.as_deref(), Some(b"a".as_slice()));
        assert_eq!(document.parts[1].name.as_deref(), Some(b"a".as_slice()));
        assert_eq!(document.parts[1].body, b"\x00\x01\xff");
        assert_eq!(serialize_multipart(&document).unwrap(), raw);
    }

    #[test]
    fn boundary_extracted_from_quoted_and_unquoted_headers() {
        assert_eq!(
            extract_boundary(b"multipart/form-data; boundary=X").unwrap(),
            b"X"
        );
        assert_eq!(
            extract_boundary(b"multipart/form-data; boundary=\"a b\"; charset=utf-8").unwrap(),
            b"a b"
        );
        assert_eq!(
            extract_boundary(b"multipart/form-data; BOUNDARY=Zed").unwrap(),
            b"Zed"
        );
        assert!(extract_boundary(b"application/json").is_err());
    }

    fn mutate_and_reparse(mutation: UploadMutationKind) -> MultipartDocument {
        let mut document = parse_fixture(FIXTURE);
        mutate_upload(&mut document, 1, mutation).unwrap();
        let serialized = serialize_multipart(&document).unwrap();
        let reparsed = parse_multipart(b"X", &serialized).unwrap();
        // the untouched text field is always preserved byte for byte.
        assert_eq!(reparsed.parts[0].body, b"value");
        assert_eq!(reparsed.parts[0].name.as_deref(), Some(b"field".as_slice()));
        reparsed
    }

    #[test]
    fn extension_case_mutation_toggles_extension() {
        let document = mutate_and_reparse(UploadMutationKind::ExtensionCase);
        assert_eq!(
            document.parts[1].filename.as_deref(),
            Some(b"shell.PhP".as_slice())
        );
        assert_eq!(document.parts[1].body, b"<?php echo 1;?>");
    }

    #[test]
    fn double_extension_mutation_inserts_benign_segment() {
        let document = mutate_and_reparse(UploadMutationKind::DoubleExtension);
        assert_eq!(
            document.parts[1].filename.as_deref(),
            Some(b"shell.jpg.php".as_slice())
        );
    }

    #[test]
    fn trailing_character_mutation_appends_space() {
        let document = mutate_and_reparse(UploadMutationKind::TrailingCharacter);
        assert_eq!(
            document.parts[1].filename.as_deref(),
            Some(b"shell.php ".as_slice())
        );
    }

    #[test]
    fn filename_encoding_mutation_percent_encodes_dot() {
        let document = mutate_and_reparse(UploadMutationKind::FilenameEncoding);
        assert_eq!(
            document.parts[1].filename.as_deref(),
            Some(b"shell%2ephp".as_slice())
        );
    }

    #[test]
    fn content_type_mutation_masquerades_as_image() {
        let document = mutate_and_reparse(UploadMutationKind::ContentType);
        assert_eq!(
            document.parts[1].content_type.as_deref(),
            Some(b"image/jpeg".as_slice())
        );
        assert_eq!(
            document.parts[1].filename.as_deref(),
            Some(b"shell.php".as_slice())
        );
    }

    #[test]
    fn magic_bytes_mutation_prepends_gif_header() {
        let document = mutate_and_reparse(UploadMutationKind::MagicBytes);
        assert!(document.parts[1].body.starts_with(GIF_MAGIC));
        assert!(document.parts[1].body.ends_with(b"<?php echo 1;?>"));
    }

    #[test]
    fn image_polyglot_mutation_sets_header_and_content_type() {
        let document = mutate_and_reparse(UploadMutationKind::ImagePolyglot);
        assert!(document.parts[1].body.starts_with(GIF_POLYGLOT_HEADER));
        assert_eq!(
            document.parts[1].content_type.as_deref(),
            Some(b"image/gif".as_slice())
        );
    }

    #[test]
    fn safe_upload_modes_replace_script_body_before_mutation() {
        let campaign_id = IntruderCampaignId::new();
        for (mode, mutation, prefix) in [
            (
                UploadVerificationMode::None,
                UploadMutationKind::MagicBytes,
                GIF_MAGIC,
            ),
            (
                UploadVerificationMode::SafeRetrieval,
                UploadMutationKind::ImagePolyglot,
                GIF_POLYGLOT_HEADER,
            ),
        ] {
            let mut document = parse_fixture(FIXTURE);
            prepare_upload_mutation(&mut document, &campaign_id, 1, mutation, mode, 7).unwrap();
            let body = &document.parts[1].body;
            let expected_marker = format!(
                "FLAGDECK_SAFE_UPLOAD\ncampaign={}\nattempt=7\n",
                campaign_id.0
            );
            assert_eq!(body, &[prefix, expected_marker.as_bytes()].concat());
            assert!(find_bytes(body, b"<?php echo 1;?>").is_none());
        }

        let mut execution = parse_fixture(FIXTURE);
        prepare_upload_mutation(
            &mut execution,
            &campaign_id,
            1,
            UploadMutationKind::MagicBytes,
            UploadVerificationMode::Execution,
            7,
        )
        .unwrap();
        assert_eq!(
            execution.parts[1].body,
            [GIF_MAGIC, b"<?php echo 1;?>"].concat()
        );

        let document = parse_fixture(FIXTURE);
        assert!(file_part_ordinal(&document, 0).is_err());
    }

    #[test]
    fn execution_verification_requires_the_exact_expected_marker() {
        assert!(execution_marker_matches(
            b"flagdeck-executed-42",
            b"flagdeck-executed-42"
        ));
        assert!(!execution_marker_matches(
            b"<html>ordinary page mentions FLAGDECK-EXEC</html>",
            b"flagdeck-executed-42"
        ));
    }

    #[test]
    fn extra_form_field_mutation_appends_part() {
        let document = mutate_and_reparse(UploadMutationKind::ExtraFormField);
        assert_eq!(document.parts.len(), 3);
        assert_eq!(
            document.parts[2].name.as_deref(),
            Some(b"flagdeck_extra".as_slice())
        );
        // the original file part is preserved.
        assert_eq!(
            document.parts[1].filename.as_deref(),
            Some(b"shell.php".as_slice())
        );
    }

    #[test]
    fn attempt_counts_cover_four_modes() {
        assert_eq!(
            attempt_count(IntruderAttackMode::Sniper, 2, &[10]).unwrap(),
            20
        );
        assert_eq!(
            attempt_count(IntruderAttackMode::BatteringRam, 3, &[7]).unwrap(),
            7
        );
        assert_eq!(
            attempt_count(IntruderAttackMode::Pitchfork, 2, &[5, 8]).unwrap(),
            5
        );
        assert_eq!(
            attempt_count(IntruderAttackMode::ClusterBomb, 2, &[3, 4]).unwrap(),
            12
        );
        assert!(attempt_count(IntruderAttackMode::Sniper, 1, &[1, 2]).is_err());
        assert!(attempt_count(IntruderAttackMode::Pitchfork, 2, &[3]).is_err());
    }

    #[test]
    fn extract_token_reads_prefix_and_suffix() {
        let response = sample_response();
        let extractor = TokenExtractor {
            variable: "csrf".to_owned(),
            source: TokenSource::ResponseBody,
            header_name: None,
            prefix: b"name=\"token\" value=\"".to_vec(),
            suffix: b"\"".to_vec(),
            maximum_length: 64,
        };
        let body = b"<input name=\"token\" value=\"abc123\">";
        let value = extract_token(&extractor, &response, body).unwrap();
        assert_eq!(value, b"abc123");
    }

    #[test]
    fn replace_all_bytes_replaces_every_occurrence() {
        let out = replace_all_bytes(b"a{{x}}b{{x}}c", b"{{x}}", b"Z").unwrap();
        assert_eq!(out, b"aZbZc");
    }

    #[test]
    fn normalize_retrieval_path_rejects_off_host_absolute_url() {
        let parent = sample_response();
        assert_eq!(
            normalize_retrieval_path(b"/uploads/a.php", &parent).as_deref(),
            Some("/uploads/a.php")
        );
        assert_eq!(
            normalize_retrieval_path(b"http://example.test/x", &parent).as_deref(),
            Some("/x")
        );
        assert!(normalize_retrieval_path(b"http://evil.test/x", &parent).is_none());
    }

    fn sample_response() -> HttpMessage {
        HttpMessage {
            message_id: MessageId::new(),
            project_id: ProjectId::new(),
            exchange_id: None,
            parent_message_id: None,
            source: flagdeck_domain::HttpSource::Repeater,
            representation_kind: flagdeck_domain::RepresentationKind::Semantic,
            method: None,
            status_code: Some(200),
            scheme: "http".to_owned(),
            host: "example.test".to_owned(),
            port: 80,
            authority: "example.test".to_owned(),
            path: "/".to_owned(),
            http_version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
            trailers: Vec::new(),
            query: Vec::new(),
            form: Vec::new(),
            body_inline: None,
            body_artifact_id: None,
            wire_artifact_id: None,
            serializer_version: "flagdeck.semantic-http1/1".to_owned(),
            body_state: flagdeck_domain::BodyState::Complete,
            declared_length: None,
            actual_length: 0,
            content_encoding: None,
            decoded_preview_state: "not_requested".to_owned(),
            direction: MessageDirection::Response,
            observed_at: Timestamp::now(),
            duration_millis: None,
            connection: flagdeck_domain::ConnectionMetadata {
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
}
