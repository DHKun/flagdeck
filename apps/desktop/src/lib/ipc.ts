import { invoke } from "@tauri-apps/api/core";

import type {
  Artifact,
  DictionaryIndex,
  HttpMessage,
  ProjectSummary,
  ProxySession,
} from "../generated/contracts";
import type {
  AppStatus,
  ArtifactPage,
  ArtifactPageRequest,
  ArtifactPreview,
  CancelAllJobsResult,
  CancelJobRequest,
  CancelJobResult,
  CommandError,
  CoreEvent,
  CreateDictionaryRequest,
  CreateSqlmapRequestFileRequest,
  CreateNoteRequest,
  CreateProjectRequest,
  CreateScopeRequest,
  DictionaryPage,
  DictionarySearchResult,
  DiffHttpMessagesRequest,
  DiscoveryPage,
  DiscoveryPageRequest,
  ExportProjectRequest,
  ExportProjectResult,
  ExternalLauncherHealthDto,
  ImportPackagePage,
  ImportProjectRequest,
  ImportProjectResult,
  GetHttpMessageRequest,
  HttpHistoryPage,
  HttpHistoryPageRequest,
  HttpMessageDiff,
  JobPage,
  JobPageRequest,
  JobLogPreview,
  JobView,
  LaunchExternalRequest,
  ListPayloadsRequest,
  OpenHttpBrowserPreviewRequest,
  OpenHttpBrowserPreviewResult,
  OpenProjectRequest,
  PayloadPage,
  PayloadPreview,
  PayloadSourceHealthDto,
  PreviewArtifactRequest,
  PreviewJobLogRequest,
  PreviewPayloadRequest,
  ProjectContextRequest,
  ProjectPage,
  ProjectPageRequest,
  RepeatHttpRequest,
  RepeatHttpResult,
  RunToolRequest,
  ScopePage,
  SearchDictionaryRequest,
  SendRawHttp1Request,
  SendRawHttp1Result,
  StartProxyRequest,
  StopProxyRequest,
  ToolHealthDto,
  ToolPackHealthDto,
  ExecuteMetasploitModuleRequest,
  GetMetasploitOptionsRequest,
  MetasploitConsoleCommandRequest,
  MetasploitEntityPage,
  MetasploitExecutionResult,
  MetasploitModuleOption,
  MetasploitModuleSummary,
  MetasploitSessionCommandRequest,
  MetasploitStatus,
  MetasploitTranscriptResult,
  SearchMetasploitModulesRequest,
  StartMetasploitRequest,
  StopMetasploitEntityRequest,
  StopMetasploitRequest,
  StartIntruderRequest,
  StartUploadCampaignRequest,
  CampaignRequest,
  ListIntruderCampaignsRequest,
  IntruderCampaignPage,
  IntruderAttemptPageRequest,
  IntruderAttemptPage,
  ParseMultipartRequest,
} from "../generated/ipc";
import type {
  AdapterEntity,
  IntruderCampaign,
  MultipartDocument,
  TargetScope,
} from "../generated/contracts";

export const ipc = {
  status: (): Promise<AppStatus> => invoke("app_status"),
  createProject: (request: CreateProjectRequest): Promise<ProjectSummary> =>
    invoke("create_project", { request }),
  listProjects: (request: ProjectPageRequest): Promise<ProjectPage> =>
    invoke("list_projects", { request }),
  openProject: (request: OpenProjectRequest): Promise<ProjectSummary> =>
    invoke("open_project", { request }),
  closeProject: (): Promise<CoreEvent> => invoke("close_project"),
  createNote: (request: CreateNoteRequest): Promise<Artifact> =>
    invoke("create_note", { request }),
  previewArtifact: (
    request: PreviewArtifactRequest,
  ): Promise<ArtifactPreview> => invoke("preview_artifact", { request }),
  listArtifacts: (request: ArtifactPageRequest): Promise<ArtifactPage> =>
    invoke("list_artifacts", { request }),
  createScope: (request: CreateScopeRequest): Promise<TargetScope> =>
    invoke("create_scope", { request }),
  listScopes: (request: ProjectContextRequest): Promise<ScopePage> =>
    invoke("list_scopes", { request }),
  toolHealth: (): Promise<ToolHealthDto[]> => invoke("tool_health"),
  toolPackHealth: (): Promise<ToolPackHealthDto[]> =>
    invoke("tool_pack_health"),
  externalLauncherHealth: (
    request: ProjectContextRequest,
  ): Promise<ExternalLauncherHealthDto[]> =>
    invoke("external_launcher_health", { request }),
  payloadSourceHealth: (
    request: ProjectContextRequest,
  ): Promise<PayloadSourceHealthDto[]> =>
    invoke("payload_source_health", { request }),
  listPayloads: (request: ListPayloadsRequest): Promise<PayloadPage> =>
    invoke("list_payloads", { request }),
  previewPayload: (request: PreviewPayloadRequest): Promise<PayloadPreview> =>
    invoke("preview_payload", { request }),
  launchExternal: (request: LaunchExternalRequest): Promise<JobView> =>
    invoke("launch_external", { request }),
  runTool: (request: RunToolRequest): Promise<JobView> =>
    invoke("run_tool", { request }),
  cancelJob: (request: CancelJobRequest): Promise<CancelJobResult> =>
    invoke("cancel_job", { request }),
  cancelAllJobs: (
    request: ProjectContextRequest,
  ): Promise<CancelAllJobsResult> => invoke("cancel_all_jobs", { request }),
  listJobs: (request: JobPageRequest): Promise<JobPage> =>
    invoke("list_jobs", { request }),
  previewJobLog: (request: PreviewJobLogRequest): Promise<JobLogPreview> =>
    invoke("preview_job_log", { request }),
  listDiscoveries: (request: DiscoveryPageRequest): Promise<DiscoveryPage> =>
    invoke("list_discoveries", { request }),
  createDictionary: (
    request: CreateDictionaryRequest,
  ): Promise<DictionaryIndex> => invoke("create_dictionary", { request }),
  listDictionaries: (request: ProjectContextRequest): Promise<DictionaryPage> =>
    invoke("list_dictionaries", { request }),
  searchDictionary: (
    request: SearchDictionaryRequest,
  ): Promise<DictionarySearchResult> =>
    invoke("search_dictionary", { request }),
  exportProject: (
    request: ExportProjectRequest,
  ): Promise<ExportProjectResult> => invoke("export_project", { request }),
  listImportPackages: (): Promise<ImportPackagePage> =>
    invoke("list_import_packages"),
  importProject: (
    request: ImportProjectRequest,
  ): Promise<ImportProjectResult> => invoke("import_project", { request }),
  startHttpProxy: (request: StartProxyRequest): Promise<ProxySession> =>
    invoke("start_http_proxy", { request }),
  stopHttpProxy: (request: StopProxyRequest): Promise<ProxySession> =>
    invoke("stop_http_proxy", { request }),
  httpProxyStatus: (
    request: ProjectContextRequest,
  ): Promise<ProxySession | null> => invoke("http_proxy_status", { request }),
  listHttpHistory: (
    request: HttpHistoryPageRequest,
  ): Promise<HttpHistoryPage> => invoke("list_http_history", { request }),
  getHttpMessage: (request: GetHttpMessageRequest): Promise<HttpMessage> =>
    invoke("get_http_message", { request }),
  repeatHttp: (request: RepeatHttpRequest): Promise<RepeatHttpResult> =>
    invoke("repeat_http", { request }),
  diffHttp: (request: DiffHttpMessagesRequest): Promise<HttpMessageDiff> =>
    invoke("diff_http", { request }),
  createSqlmapRequest: (
    request: CreateSqlmapRequestFileRequest,
  ): Promise<Artifact> => invoke("create_sqlmap_request", { request }),
  sendRawHttp1: (request: SendRawHttp1Request): Promise<SendRawHttp1Result> =>
    invoke("send_raw_http1", { request }),
  openHttpBrowserPreview: (
    request: OpenHttpBrowserPreviewRequest,
  ): Promise<OpenHttpBrowserPreviewResult> =>
    invoke("open_http_browser_preview", { request }),
  startMetasploit: (
    request: StartMetasploitRequest,
  ): Promise<MetasploitStatus> => invoke("start_metasploit", { request }),
  metasploitStatus: (
    request: ProjectContextRequest,
  ): Promise<MetasploitStatus> => invoke("metasploit_status", { request }),
  stopMetasploit: (request: StopMetasploitRequest): Promise<MetasploitStatus> =>
    invoke("stop_metasploit", { request }),
  searchMetasploitModules: (
    request: SearchMetasploitModulesRequest,
  ): Promise<MetasploitModuleSummary[]> =>
    invoke("search_metasploit_modules", { request }),
  getMetasploitOptions: (
    request: GetMetasploitOptionsRequest,
  ): Promise<MetasploitModuleOption[]> =>
    invoke("get_metasploit_options", { request }),
  executeMetasploitModule: (
    request: ExecuteMetasploitModuleRequest,
  ): Promise<MetasploitExecutionResult> =>
    invoke("execute_metasploit_module", { request }),
  listMetasploitEntities: (
    request: ProjectContextRequest,
  ): Promise<MetasploitEntityPage> =>
    invoke("list_metasploit_entities", { request }),
  createMetasploitConsole: (
    request: ProjectContextRequest,
  ): Promise<AdapterEntity> => invoke("create_metasploit_console", { request }),
  stopMetasploitEntity: (
    request: StopMetasploitEntityRequest,
  ): Promise<AdapterEntity> => invoke("stop_metasploit_entity", { request }),
  metasploitConsoleCommand: (
    request: MetasploitConsoleCommandRequest,
  ): Promise<MetasploitTranscriptResult> =>
    invoke("metasploit_console_command", { request }),
  metasploitSessionCommand: (
    request: MetasploitSessionCommandRequest,
  ): Promise<MetasploitTranscriptResult> =>
    invoke("metasploit_session_command", { request }),
  startIntruder: (request: StartIntruderRequest): Promise<IntruderCampaign> =>
    invoke("start_intruder", { request }),
  startUploadCampaign: (
    request: StartUploadCampaignRequest,
  ): Promise<IntruderCampaign> => invoke("start_upload_campaign", { request }),
  cancelIntruderCampaign: (
    request: CampaignRequest,
  ): Promise<IntruderCampaign> =>
    invoke("cancel_intruder_campaign", { request }),
  resumeIntruderCampaign: (
    request: CampaignRequest,
  ): Promise<IntruderCampaign> =>
    invoke("resume_intruder_campaign", { request }),
  listIntruderCampaigns: (
    request: ListIntruderCampaignsRequest,
  ): Promise<IntruderCampaignPage> =>
    invoke("list_intruder_campaigns", { request }),
  listIntruderAttempts: (
    request: IntruderAttemptPageRequest,
  ): Promise<IntruderAttemptPage> =>
    invoke("list_intruder_attempts", { request }),
  parseMultipartMessage: (
    request: ParseMultipartRequest,
  ): Promise<MultipartDocument> =>
    invoke("parse_multipart_message", { request }),
};

export function commandErrorMessage(error: unknown): string {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    "message" in error
  ) {
    const candidate = error as Partial<CommandError>;
    if (
      typeof candidate.code === "string" &&
      typeof candidate.message === "string" &&
      candidate.code.length <= 64 &&
      candidate.message.length <= 256
    ) {
      return `${candidate.message} (${candidate.code})`;
    }
  }
  return "Operation failed (ipc_error)";
}
