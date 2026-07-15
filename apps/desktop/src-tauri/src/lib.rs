#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value,
    clippy::too_many_lines
)]

use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use flagdeck_core::{
    AppStatus, ArtifactPage, ArtifactPageRequest, ArtifactPreview, CampaignRequest,
    CancelAllJobsResult, CancelJobRequest, CancelJobResult, CatalogSnapshot, ClearJobsRequest,
    ClearJobsResult, CommandError, CoreError, CoreEvent, CoreService, CreateDictionaryRequest,
    CreateNoteRequest, CreateProjectRequest, CreateScopeRequest, CreateSqlmapRequestFileRequest,
    DeleteJobRequest, DeleteJobResult, DictionaryPage, DictionarySearchResult,
    DiffHttpMessagesRequest, DiscoveryPage, DiscoveryPageRequest, EnsureTargetRequest,
    ExecuteMetasploitModuleRequest, ExportProjectRequest, ExportProjectResult,
    ExternalLauncherHealthDto, GetHttpMessageRequest, GetMetasploitOptionsRequest, HttpHistoryPage,
    HttpHistoryPageRequest, HttpMessageDiff, ImportPackagePage, ImportProjectRequest,
    ImportProjectResult, IntruderAttemptPage, IntruderAttemptPageRequest, IntruderCampaignPage,
    JobLogPreview, JobPage, JobPageRequest, JobView, LaunchExternalRequest,
    ListIntruderCampaignsRequest, ListPayloadsRequest, MetasploitConsoleCommandRequest,
    MetasploitEntityPage, MetasploitExecutionResult, MetasploitModuleOption,
    MetasploitModuleSummary, MetasploitSessionCommandRequest, MetasploitStatus,
    MetasploitTranscriptResult, OpenHttpBrowserPreviewRequest, OpenHttpBrowserPreviewResult,
    OpenProjectRequest, ParseMultipartRequest, PayloadPage, PayloadPreview, PayloadSourceHealthDto,
    PreviewArtifactRequest, PreviewJobLogRequest, PreviewPayloadRequest, ProjectContextRequest,
    ProjectPage, ProjectPageRequest, RepeatHttpRequest, RepeatHttpResult, RunCatalogToolRequest,
    RunToolRequest, ScopePage, SearchDictionaryRequest, SearchMetasploitModulesRequest,
    SendRawHttp1Request, SendRawHttp1Result, StartIntruderRequest, StartMetasploitRequest,
    StartProxyRequest, StartUploadCampaignRequest, StopMetasploitEntityRequest,
    StopMetasploitRequest, StopProxyRequest, ToolHealthDto, ToolPackHealthDto,
};
use flagdeck_domain::{
    AdapterEntity, Artifact, DictionaryIndex, HttpMessage, IntruderCampaign, MultipartDocument,
    ProjectId, ProjectSummary, ProxySession, TargetScope,
};
use nix::sys::resource::{Resource, setrlimit};
use nix::sys::stat::{Mode, umask};
use tauri::webview::{NewWindowResponse, WebviewWindowBuilder};
use tauri::{AppHandle, Emitter, Manager, State, Url, WebviewUrl, WebviewWindow};

const SECURITY_PROBE_ENV: &str = "FLAGDECK_SECURITY_PROBE";
const WORKSPACES_ROOT_ENV: &str = "FLAGDECK_WORKSPACES_ROOT";

fn runtime_error() -> CommandError {
    CommandError {
        code: "runtime_error".to_owned(),
        message: "Core operation could not be completed".to_owned(),
    }
}

async fn run_core<T, F>(operation: F) -> Result<T, CommandError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, CoreError> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(operation)
        .await
        .map_err(|_| runtime_error())?
        .map_err(Into::into)
}

fn emit_core_event(
    app: &AppHandle,
    core: &CoreService,
    kind: &str,
    project_id: Option<ProjectId>,
) -> CoreEvent {
    let event = core.next_event(kind, project_id);
    let _ = app.emit("flagdeck://core-event", &event);
    event
}

#[tauri::command]
async fn app_status(state: State<'_, Arc<CoreService>>) -> Result<AppStatus, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.status()).await
}

#[tauri::command]
async fn create_project(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: CreateProjectRequest,
) -> Result<ProjectSummary, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let summary = run_core(move || worker.create_project(&request)).await?;
    emit_core_event(
        &app,
        &core,
        "project_created",
        Some(summary.project_id.clone()),
    );
    Ok(summary)
}

#[tauri::command]
async fn list_projects(
    state: State<'_, Arc<CoreService>>,
    request: ProjectPageRequest,
) -> Result<ProjectPage, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.list_projects(&request)).await
}

#[tauri::command]
async fn open_project(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: OpenProjectRequest,
) -> Result<ProjectSummary, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let summary = run_core(move || worker.open_project(&request)).await?;
    emit_core_event(
        &app,
        &core,
        "project_opened",
        Some(summary.project_id.clone()),
    );
    Ok(summary)
}

#[tauri::command]
async fn close_project(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
) -> Result<CoreEvent, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    run_core(move || worker.close_project()).await?;
    Ok(emit_core_event(&app, &core, "project_closed", None))
}

#[tauri::command]
async fn create_note(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: CreateNoteRequest,
) -> Result<Artifact, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let artifact = run_core(move || worker.create_note(request)).await?;
    emit_core_event(&app, &core, "artifact_committed", Some(project_id));
    Ok(artifact)
}

#[tauri::command]
async fn preview_artifact(
    state: State<'_, Arc<CoreService>>,
    request: PreviewArtifactRequest,
) -> Result<ArtifactPreview, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.preview_artifact(request)).await
}

#[tauri::command]
async fn list_artifacts(
    state: State<'_, Arc<CoreService>>,
    request: ArtifactPageRequest,
) -> Result<ArtifactPage, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.list_artifacts(&request)).await
}

#[tauri::command]
async fn create_scope(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: CreateScopeRequest,
) -> Result<TargetScope, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let scope = run_core(move || worker.create_scope(&request)).await?;
    emit_core_event(&app, &core, "scope_saved", Some(project_id));
    Ok(scope)
}

#[tauri::command]
async fn list_scopes(
    state: State<'_, Arc<CoreService>>,
    request: ProjectContextRequest,
) -> Result<ScopePage, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.list_scopes(&request.project_id)).await
}

#[tauri::command]
async fn tool_health(
    state: State<'_, Arc<CoreService>>,
) -> Result<Vec<ToolHealthDto>, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.tool_health()).await
}

#[tauri::command]
async fn list_catalog(state: State<'_, Arc<CoreService>>) -> Result<CatalogSnapshot, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.list_catalog()).await
}

#[tauri::command]
async fn ensure_target(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: EnsureTargetRequest,
) -> Result<flagdeck_domain::TargetScope, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let scope = run_core(move || worker.ensure_target_scope(&request)).await?;
    emit_core_event(&app, &core, "scope_saved", Some(project_id));
    Ok(scope)
}

#[tauri::command]
async fn run_catalog_tool(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: RunCatalogToolRequest,
) -> Result<JobView, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let job = run_core(move || worker.start_catalog_tool(request)).await?;
    emit_core_event(&app, &core, "job_started", Some(project_id));
    Ok(job)
}

#[tauri::command]
async fn delete_job(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: DeleteJobRequest,
) -> Result<DeleteJobResult, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let result = run_core(move || worker.delete_job(&request)).await?;
    emit_core_event(&app, &core, "job_deleted", Some(project_id));
    Ok(result)
}

#[tauri::command]
async fn clear_jobs(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: ClearJobsRequest,
) -> Result<ClearJobsResult, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let result = run_core(move || worker.clear_jobs(&request)).await?;
    emit_core_event(&app, &core, "jobs_cleared", Some(project_id));
    Ok(result)
}

#[tauri::command]
async fn tool_pack_health(
    state: State<'_, Arc<CoreService>>,
) -> Result<Vec<ToolPackHealthDto>, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.tool_pack_health()).await
}

#[tauri::command]
async fn preview_job_log(
    state: State<'_, Arc<CoreService>>,
    request: PreviewJobLogRequest,
) -> Result<JobLogPreview, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.preview_job_log(&request)).await
}

#[tauri::command]
async fn external_launcher_health(
    state: State<'_, Arc<CoreService>>,
    request: ProjectContextRequest,
) -> Result<Vec<ExternalLauncherHealthDto>, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.external_launcher_health(&request)).await
}

#[tauri::command]
async fn payload_source_health(
    state: State<'_, Arc<CoreService>>,
    request: ProjectContextRequest,
) -> Result<Vec<PayloadSourceHealthDto>, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.payload_source_health(&request)).await
}

#[tauri::command]
async fn list_payloads(
    state: State<'_, Arc<CoreService>>,
    request: ListPayloadsRequest,
) -> Result<PayloadPage, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.list_payloads(&request)).await
}

#[tauri::command]
async fn preview_payload(
    state: State<'_, Arc<CoreService>>,
    request: PreviewPayloadRequest,
) -> Result<PayloadPreview, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.preview_payload(&request)).await
}

#[tauri::command]
async fn launch_external(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: LaunchExternalRequest,
) -> Result<JobView, CommandError> {
    let core = Arc::clone(state.inner());
    let project_id = request.project_id.clone();
    let result = core.launch_external(&request).map_err(CommandError::from)?;
    emit_core_event(&app, &core, "job_queued", Some(project_id));
    Ok(result)
}

#[tauri::command]
async fn run_tool(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: RunToolRequest,
) -> Result<JobView, CommandError> {
    let core = Arc::clone(state.inner());
    let project_id = request.project_id.clone();
    let result = core.start_tool(request).map_err(CommandError::from)?;
    emit_core_event(&app, &core, "job_queued", Some(project_id));
    Ok(result)
}

#[tauri::command]
async fn cancel_job(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: CancelJobRequest,
) -> Result<CancelJobResult, CommandError> {
    let core = Arc::clone(state.inner());
    let project_id = request.project_id.clone();
    let result = core
        .cancel_job(&request)
        .await
        .map_err(CommandError::from)?;
    emit_core_event(&app, &core, "job_cancelled", Some(project_id));
    Ok(result)
}

#[tauri::command]
async fn cancel_all_jobs(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: ProjectContextRequest,
) -> Result<CancelAllJobsResult, CommandError> {
    let core = Arc::clone(state.inner());
    let project_id = request.project_id;
    let result = core
        .cancel_all_jobs(&project_id)
        .await
        .map_err(CommandError::from)?;
    emit_core_event(&app, &core, "jobs_cancelled", Some(project_id));
    Ok(result)
}

#[tauri::command]
async fn list_jobs(
    state: State<'_, Arc<CoreService>>,
    request: JobPageRequest,
) -> Result<JobPage, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.list_jobs(&request)).await
}

#[tauri::command]
async fn list_discoveries(
    state: State<'_, Arc<CoreService>>,
    request: DiscoveryPageRequest,
) -> Result<DiscoveryPage, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.list_discoveries(&request)).await
}

#[tauri::command]
async fn create_dictionary(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: CreateDictionaryRequest,
) -> Result<DictionaryIndex, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let dictionary = run_core(move || worker.create_dictionary(request)).await?;
    emit_core_event(&app, &core, "dictionary_indexed", Some(project_id));
    Ok(dictionary)
}

#[tauri::command]
async fn list_dictionaries(
    state: State<'_, Arc<CoreService>>,
    request: ProjectContextRequest,
) -> Result<DictionaryPage, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.list_dictionaries(&request.project_id)).await
}

#[tauri::command]
async fn search_dictionary(
    state: State<'_, Arc<CoreService>>,
    request: SearchDictionaryRequest,
) -> Result<DictionarySearchResult, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.search_dictionary(&request)).await
}

#[tauri::command]
async fn export_project(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: ExportProjectRequest,
) -> Result<ExportProjectResult, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let result = run_core(move || worker.export_project(&request)).await?;
    emit_core_event(&app, &core, "project_exported", Some(project_id));
    Ok(result)
}

#[tauri::command]
async fn list_import_packages(
    state: State<'_, Arc<CoreService>>,
) -> Result<ImportPackagePage, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.list_import_packages()).await
}

#[tauri::command]
async fn import_project(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: ImportProjectRequest,
) -> Result<ImportProjectResult, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let result = run_core(move || worker.import_project(&request)).await?;
    emit_core_event(
        &app,
        &core,
        "project_imported",
        Some(result.project.project_id.clone()),
    );
    Ok(result)
}

#[tauri::command]
async fn start_http_proxy(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: StartProxyRequest,
) -> Result<ProxySession, CommandError> {
    let core = Arc::clone(state.inner());
    let project_id = request.project_id.clone();
    let session = core
        .start_http_proxy(&request)
        .await
        .map_err(CommandError::from)?;
    emit_core_event(&app, &core, "http_proxy_ready", Some(project_id));
    Ok(session)
}

#[tauri::command]
async fn stop_http_proxy(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: StopProxyRequest,
) -> Result<ProxySession, CommandError> {
    let core = Arc::clone(state.inner());
    let project_id = request.project_id.clone();
    let session = core
        .stop_http_proxy(&request)
        .await
        .map_err(CommandError::from)?;
    emit_core_event(&app, &core, "http_proxy_stopped", Some(project_id));
    Ok(session)
}

#[tauri::command]
async fn http_proxy_status(
    state: State<'_, Arc<CoreService>>,
    request: ProjectContextRequest,
) -> Result<Option<ProxySession>, CommandError> {
    state
        .http_proxy_status(&request.project_id)
        .await
        .map_err(Into::into)
}

#[tauri::command]
async fn list_http_history(
    state: State<'_, Arc<CoreService>>,
    request: HttpHistoryPageRequest,
) -> Result<HttpHistoryPage, CommandError> {
    state.list_http_history(&request).await.map_err(Into::into)
}

#[tauri::command]
async fn get_http_message(
    state: State<'_, Arc<CoreService>>,
    request: GetHttpMessageRequest,
) -> Result<HttpMessage, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.get_http_message(&request)).await
}

#[tauri::command]
async fn repeat_http(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: RepeatHttpRequest,
) -> Result<RepeatHttpResult, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let result = run_core(move || worker.repeat_http(&request)).await?;
    emit_core_event(&app, &core, "http_repeated", Some(project_id));
    Ok(result)
}

#[tauri::command]
async fn diff_http(
    state: State<'_, Arc<CoreService>>,
    request: DiffHttpMessagesRequest,
) -> Result<HttpMessageDiff, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.diff_http(&request)).await
}

#[tauri::command]
async fn create_sqlmap_request(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: CreateSqlmapRequestFileRequest,
) -> Result<Artifact, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let artifact = run_core(move || worker.create_sqlmap_request(&request)).await?;
    emit_core_event(&app, &core, "sqlmap_request_created", Some(project_id));
    Ok(artifact)
}

#[tauri::command]
async fn send_raw_http1(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: SendRawHttp1Request,
) -> Result<SendRawHttp1Result, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let result = run_core(move || worker.send_raw_http1(&request)).await?;
    emit_core_event(&app, &core, "raw_http1_sent", Some(project_id));
    Ok(result)
}

#[tauri::command]
async fn open_http_browser_preview(
    state: State<'_, Arc<CoreService>>,
    request: OpenHttpBrowserPreviewRequest,
) -> Result<OpenHttpBrowserPreviewResult, CommandError> {
    state
        .open_http_browser_preview(&request)
        .await
        .map_err(Into::into)
}

#[tauri::command]
async fn start_intruder(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: StartIntruderRequest,
) -> Result<IntruderCampaign, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let campaign = run_core(move || worker.start_intruder(&request)).await?;
    emit_core_event(&app, &core, "intruder_started", Some(project_id));
    Ok(campaign)
}

#[tauri::command]
async fn start_upload_campaign(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: StartUploadCampaignRequest,
) -> Result<IntruderCampaign, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let campaign = run_core(move || worker.start_upload_campaign(&request)).await?;
    emit_core_event(&app, &core, "upload_campaign_started", Some(project_id));
    Ok(campaign)
}

#[tauri::command]
async fn cancel_intruder_campaign(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: CampaignRequest,
) -> Result<IntruderCampaign, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let campaign = run_core(move || worker.cancel_intruder_campaign(&request)).await?;
    emit_core_event(&app, &core, "intruder_cancelled", Some(project_id));
    Ok(campaign)
}

#[tauri::command]
async fn resume_intruder_campaign(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: CampaignRequest,
) -> Result<IntruderCampaign, CommandError> {
    let core = Arc::clone(state.inner());
    let worker = Arc::clone(&core);
    let project_id = request.project_id.clone();
    let campaign = run_core(move || worker.resume_intruder_campaign(&request)).await?;
    emit_core_event(&app, &core, "intruder_resumed", Some(project_id));
    Ok(campaign)
}

#[tauri::command]
async fn list_intruder_campaigns(
    state: State<'_, Arc<CoreService>>,
    request: ListIntruderCampaignsRequest,
) -> Result<IntruderCampaignPage, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.list_intruder_campaigns(&request)).await
}

#[tauri::command]
async fn list_intruder_attempts(
    state: State<'_, Arc<CoreService>>,
    request: IntruderAttemptPageRequest,
) -> Result<IntruderAttemptPage, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.list_intruder_attempts(&request)).await
}

#[tauri::command]
async fn parse_multipart_message(
    state: State<'_, Arc<CoreService>>,
    request: ParseMultipartRequest,
) -> Result<MultipartDocument, CommandError> {
    let core = Arc::clone(state.inner());
    run_core(move || core.parse_multipart_message(&request)).await
}

#[tauri::command]
async fn start_metasploit(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: StartMetasploitRequest,
) -> Result<MetasploitStatus, CommandError> {
    let core = Arc::clone(state.inner());
    let project_id = request.project_id.clone();
    let status = core
        .start_metasploit(&request)
        .await
        .map_err(CommandError::from)?;
    emit_core_event(&app, &core, "metasploit_ready", Some(project_id));
    Ok(status)
}

#[tauri::command]
async fn metasploit_status(
    state: State<'_, Arc<CoreService>>,
    request: ProjectContextRequest,
) -> Result<MetasploitStatus, CommandError> {
    state
        .metasploit_status(&request.project_id)
        .await
        .map_err(Into::into)
}

#[tauri::command]
async fn stop_metasploit(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: StopMetasploitRequest,
) -> Result<MetasploitStatus, CommandError> {
    let core = Arc::clone(state.inner());
    let project_id = request.project_id.clone();
    let status = core
        .stop_metasploit(&request)
        .await
        .map_err(CommandError::from)?;
    emit_core_event(&app, &core, "metasploit_stopped", Some(project_id));
    Ok(status)
}

#[tauri::command]
async fn search_metasploit_modules(
    state: State<'_, Arc<CoreService>>,
    request: SearchMetasploitModulesRequest,
) -> Result<Vec<MetasploitModuleSummary>, CommandError> {
    state
        .search_metasploit_modules(&request)
        .await
        .map_err(Into::into)
}

#[tauri::command]
async fn get_metasploit_options(
    state: State<'_, Arc<CoreService>>,
    request: GetMetasploitOptionsRequest,
) -> Result<Vec<MetasploitModuleOption>, CommandError> {
    state
        .get_metasploit_options(&request)
        .await
        .map_err(Into::into)
}

#[tauri::command]
async fn execute_metasploit_module(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: ExecuteMetasploitModuleRequest,
) -> Result<MetasploitExecutionResult, CommandError> {
    let core = Arc::clone(state.inner());
    let project_id = request.project_id.clone();
    let result = core
        .execute_metasploit_module(&request)
        .await
        .map_err(CommandError::from)?;
    emit_core_event(&app, &core, "metasploit_module_executed", Some(project_id));
    Ok(result)
}

#[tauri::command]
async fn list_metasploit_entities(
    state: State<'_, Arc<CoreService>>,
    request: ProjectContextRequest,
) -> Result<MetasploitEntityPage, CommandError> {
    state
        .list_metasploit_entities(&request.project_id)
        .await
        .map_err(Into::into)
}

#[tauri::command]
async fn create_metasploit_console(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: ProjectContextRequest,
) -> Result<AdapterEntity, CommandError> {
    let core = Arc::clone(state.inner());
    let project_id = request.project_id;
    let entity = core
        .create_metasploit_console(&project_id)
        .await
        .map_err(CommandError::from)?;
    emit_core_event(&app, &core, "metasploit_console_created", Some(project_id));
    Ok(entity)
}

#[tauri::command]
async fn stop_metasploit_entity(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: StopMetasploitEntityRequest,
) -> Result<AdapterEntity, CommandError> {
    let core = Arc::clone(state.inner());
    let project_id = request.project_id.clone();
    let entity = core
        .stop_metasploit_entity(&request)
        .await
        .map_err(CommandError::from)?;
    emit_core_event(&app, &core, "metasploit_entity_stopped", Some(project_id));
    Ok(entity)
}

#[tauri::command]
async fn metasploit_console_command(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: MetasploitConsoleCommandRequest,
) -> Result<MetasploitTranscriptResult, CommandError> {
    let core = Arc::clone(state.inner());
    let project_id = request.project_id.clone();
    let result = core
        .metasploit_console_command(&request)
        .await
        .map_err(CommandError::from)?;
    emit_core_event(&app, &core, "metasploit_console_updated", Some(project_id));
    Ok(result)
}

#[tauri::command]
async fn metasploit_session_command(
    app: AppHandle,
    state: State<'_, Arc<CoreService>>,
    request: MetasploitSessionCommandRequest,
) -> Result<MetasploitTranscriptResult, CommandError> {
    let core = Arc::clone(state.inner());
    let project_id = request.project_id.clone();
    let result = core
        .metasploit_session_command(&request)
        .await
        .map_err(CommandError::from)?;
    emit_core_event(&app, &core, "metasploit_session_updated", Some(project_id));
    Ok(result)
}

fn allow_navigation(url: &Url) -> bool {
    url.scheme() == "tauri"
        || (cfg!(debug_assertions)
            && url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.port() == Some(14_200))
}

#[cfg(target_os = "linux")]
fn configure_linux_webview(window: &WebviewWindow) -> tauri::Result<()> {
    window.with_webview(|webview| {
        use webkit2gtk::{CacheModel, SettingsExt, WebContextExt, WebViewExt};

        let inner = webview.inner();
        if let Some(context) = inner.context() {
            context.set_cache_model(CacheModel::DocumentViewer);
        }
        if let Some(settings) = inner.settings() {
            settings.set_enable_dns_prefetching(false);
            settings.set_enable_encrypted_media(false);
            settings.set_enable_fullscreen(false);
            settings.set_enable_html5_database(false);
            settings.set_enable_html5_local_storage(false);
            settings.set_enable_media(false);
            settings.set_enable_media_capabilities(false);
            settings.set_enable_media_stream(false);
            settings.set_enable_mediasource(false);
            settings.set_enable_offline_web_application_cache(false);
            settings.set_enable_page_cache(false);
            settings.set_enable_webaudio(false);
            settings.set_enable_webgl(false);
        }
    })
}

#[cfg(not(target_os = "linux"))]
fn configure_linux_webview(_window: &WebviewWindow) -> tauri::Result<()> {
    Ok(())
}

fn create_windows(app: &tauri::App) -> tauri::Result<()> {
    let main = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("FlagDeck")
        .inner_size(1280.0, 820.0)
        .min_inner_size(920.0, 640.0)
        .devtools(false)
        .on_navigation(allow_navigation)
        .on_new_window(|_, _| NewWindowResponse::Deny)
        .build()?;
    configure_linux_webview(&main)?;

    if env::var_os(SECURITY_PROBE_ENV).as_deref() == Some("1".as_ref()) {
        let probe =
            WebviewWindowBuilder::new(app, "untrusted-probe", WebviewUrl::App("probe.html".into()))
                .title("FlagDeck Unprivileged Probe")
                .inner_size(560.0, 280.0)
                .focused(false)
                .devtools(false)
                .on_navigation(allow_navigation)
                .on_new_window(|_, _| NewWindowResponse::Deny)
                .build()?;
        configure_linux_webview(&probe)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn configured_workspaces_root() -> Result<PathBuf, &'static str> {
    if let Some(value) = env::var_os(WORKSPACES_ROOT_ENV) {
        let root = PathBuf::from(value);
        return root
            .is_absolute()
            .then_some(root)
            .ok_or("FLAGDECK_WORKSPACES_ROOT must be absolute");
    }
    if let Some(value) = env::var_os("XDG_DATA_HOME") {
        let root = PathBuf::from(value);
        if root.is_absolute() {
            return Ok(root.join("flagdeck/workspaces"));
        }
    }
    let home = env::var_os("HOME").ok_or("HOME is unavailable")?;
    let home = PathBuf::from(home);
    home.is_absolute()
        .then(|| home.join(".local/share/flagdeck/workspaces"))
        .ok_or("HOME must be absolute")
}

#[cfg(target_os = "macos")]
fn configured_workspaces_root() -> Result<PathBuf, &'static str> {
    if let Some(value) = env::var_os(WORKSPACES_ROOT_ENV) {
        let root = PathBuf::from(value);
        return root
            .is_absolute()
            .then_some(root)
            .ok_or("FLAGDECK_WORKSPACES_ROOT must be absolute");
    }
    let home = env::var_os("HOME").ok_or("HOME is unavailable")?;
    let home = PathBuf::from(home);
    home.is_absolute()
        .then(|| home.join("Library/Application Support/FlagDeck/workspaces"))
        .ok_or("HOME must be absolute")
}

fn configure_private_process() -> Result<(), &'static str> {
    umask(Mode::from_bits_truncate(0o077));
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(|_| "failed to disable core dumps")
}

#[cfg(target_os = "linux")]
fn configure_linux_process() -> Result<(), &'static str> {
    for (name, value) in [
        ("WEBKIT_DISABLE_COMPOSITING_MODE", "1"),
        ("MALLOC_ARENA_MAX", "1"),
        ("JSC_useJIT", "false"),
        ("JSC_useDFGJIT", "false"),
        ("JSC_useFTLJIT", "false"),
    ] {
        webkit2gtk::glib::setenv(name, value, false)
            .map_err(|_| "failed to configure the Linux WebKit process")?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn configure_linux_process() -> Result<(), &'static str> {
    Ok(())
}

pub fn run() {
    configure_private_process().expect("FlagDeck process hardening failed");
    configure_linux_process().expect("FlagDeck platform process configuration failed");
    let workspaces_root =
        configured_workspaces_root().expect("FlagDeck workspace root configuration failed");
    let application = tauri::Builder::default()
        .setup(move |app| {
            let bundled_worker = app.path().resource_dir()?.join("workers/mitmproxy");
            let worker_source = bundled_worker
                .join("pyproject.toml")
                .is_file()
                .then_some(bundled_worker);
            let executable_directory = env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(PathBuf::from));
            let metasploit_adapter = env::var_os("FLAGDECK_METASPLOIT_ADAPTER")
                .map(PathBuf::from)
                .or_else(|| {
                    executable_directory
                        .as_ref()
                        .map(|root| root.join("flagdeck-adapter-metasploit"))
                })
                .filter(|path| path.is_file());
            let metasploit_launcher = env::var_os("FLAGDECK_METASPLOIT_LAUNCHER")
                .map(PathBuf::from)
                .or_else(|| {
                    executable_directory
                        .as_ref()
                        .map(|root| root.join("flagdeck-msf-credential-launcher"))
                })
                .filter(|path| path.is_file());
            let uv_program = executable_directory
                .as_ref()
                .map(|root| root.join("uv"))
                .filter(|path| path.is_file());
            app.manage(Arc::new(CoreService::with_bundled_resources(
                workspaces_root,
                worker_source,
                uv_program,
                metasploit_adapter,
                metasploit_launcher,
            )));
            create_windows(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_status,
            create_project,
            list_projects,
            open_project,
            close_project,
            create_note,
            preview_artifact,
            list_artifacts,
            create_scope,
            list_scopes,
            tool_health,
            list_catalog,
            ensure_target,
            run_catalog_tool,
            delete_job,
            clear_jobs,
            tool_pack_health,
            external_launcher_health,
            payload_source_health,
            list_payloads,
            preview_payload,
            launch_external,
            run_tool,
            preview_job_log,
            cancel_job,
            cancel_all_jobs,
            list_jobs,
            list_discoveries,
            create_dictionary,
            list_dictionaries,
            search_dictionary,
            export_project,
            list_import_packages,
            import_project,
            start_http_proxy,
            stop_http_proxy,
            http_proxy_status,
            list_http_history,
            get_http_message,
            repeat_http,
            diff_http,
            create_sqlmap_request,
            send_raw_http1,
            open_http_browser_preview,
            start_metasploit,
            metasploit_status,
            stop_metasploit,
            search_metasploit_modules,
            get_metasploit_options,
            execute_metasploit_module,
            list_metasploit_entities,
            create_metasploit_console,
            stop_metasploit_entity,
            metasploit_console_command,
            metasploit_session_command,
            start_intruder,
            start_upload_campaign,
            cancel_intruder_campaign,
            resume_intruder_campaign,
            list_intruder_campaigns,
            list_intruder_attempts,
            parse_multipart_message
        ])
        .build(tauri::generate_context!())
        .expect("FlagDeck desktop build failed");
    application.run(|app, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            let core = app.state::<Arc<CoreService>>();
            if core.exit_requires_metasploit_shutdown() {
                api.prevent_exit();
                let _ = app.emit("flagdeck://metasploit-exit-blocked", ());
            } else if core.exit_requires_intruder_shutdown() {
                api.prevent_exit();
                let _ = app.emit("flagdeck://intruder-exit-blocked", ());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_policy_rejects_remote_and_file_urls() {
        assert!(allow_navigation(
            &Url::parse("tauri://localhost/index.html").unwrap()
        ));
        assert!(!allow_navigation(
            &Url::parse("https://example.invalid/").unwrap()
        ));
        assert!(!allow_navigation(
            &Url::parse("file:///etc/passwd").unwrap()
        ));
    }

    #[test]
    fn runtime_errors_have_fixed_public_text() {
        assert_eq!(runtime_error().code, "runtime_error");
        assert!(!runtime_error().message.contains('/'));
    }
}
