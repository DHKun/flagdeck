<script lang="ts">
  import { onMount } from "svelte";

  import type {
    Artifact,
    AdapterEntity,
    DictionaryIndex,
    Discovery,
    HttpMessage,
    IntruderAttackMode,
    IntruderAttempt,
    IntruderCampaign,
    MultipartDocument,
    OrderedValue,
    PayloadLocation,
    PayloadPosition,
    ProxySession,
    Sensitivity,
    TargetScope,
    UploadMutationKind,
  } from "./generated/contracts";
  import type {
    AlphaTool,
    AppStatus,
    ArtifactPreview,
    ExternalLauncherHealthDto,
    ExternalLauncherId,
    HttpMessageDiff,
    JobView,
    JobLogStream,
    MetasploitExecutionKind,
    MetasploitModuleOption,
    MetasploitModuleSummary,
    MetasploitStatus,
    PayloadEntryDto,
    PayloadPreview,
    PayloadSourceHealthDto,
    TokenSource,
    ToolHealthDto,
    ToolPackHealthDto,
    UploadVerificationMode,
  } from "./generated/ipc";
  import { hostileFixture } from "./lib/fixtures";
  import { commandErrorMessage, ipc } from "./lib/ipc";
  import { safeDisplayFilename, toSafeTextPreview } from "./lib/preview";
  import { buildStateMacro, encodeExecutionMarker } from "./lib/stateMacro";

  const navigationGroups = [
    {
      label: "WORKBENCH",
      items: [
        ["recon", "工具箱", "⌁"],
        ["http", "HTTP 工作台", "↗"],
        ["metasploit", "Metasploit", "M"],
        ["intruder", "Intruder", "I"],
      ],
    },
    {
      label: "DATA",
      items: [
        ["discovery", "发现结果", "D"],
        ["payloads", "Payload 库", "P"],
        ["jobs", "运行任务", "J"],
        ["evidence", "记录与笔记", "N"],
      ],
    },
    {
      label: "SYSTEM",
      items: [
        ["adapters", "独立工具", "A"],
        ["health", "环境检查", "H"],
        ["settings", "设置", "S"],
      ],
    },
  ] as const;

  const sectionMeta: Record<
    string,
    { eyebrow: string; title: string; description: string }
  > = {
    recon: {
      eyebrow: "TOOLBOX",
      title: "工具箱",
      description: "选择工具，填写目标，在同一个窗口里运行并查看输出。",
    },
    http: {
      eyebrow: "HTTP",
      title: "HTTP 工作台",
      description: "捕获、检查并重放 HTTP 流量。",
    },
    metasploit: {
      eyebrow: "METASPLOIT",
      title: "Metasploit",
      description: "管理模块、Console、Session 与执行记录。",
    },
    intruder: {
      eyebrow: "INTRUDER",
      title: "Intruder",
      description: "配置字典、请求位置、速率与上传变异。",
    },
    discovery: {
      eyebrow: "RESULTS",
      title: "发现结果",
      description: "集中查看工具解析后的路径、参数、主机和服务。",
    },
    payloads: {
      eyebrow: "PAYLOADS",
      title: "Payload 库",
      description: "检索本地 Payload 源并预览可用内容。",
    },
    jobs: {
      eyebrow: "ACTIVITY",
      title: "运行任务",
      description: "查看进程状态、执行命令和实时日志。",
    },
    evidence: {
      eyebrow: "NOTES",
      title: "记录与笔记",
      description: "保存测试记录、证据文件和操作笔记。",
    },
    adapters: {
      eyebrow: "EXTERNAL TOOLS",
      title: "独立工具",
      description: "启动需要独立窗口或专用运行时的工具。",
    },
    health: {
      eyebrow: "ENVIRONMENT",
      title: "环境检查",
      description: "检查工具包、可执行文件和运行时状态。",
    },
    settings: {
      eyebrow: "SETTINGS",
      title: "设置",
      description: "管理目标范围、字典与本地数据。",
    },
  };

  const attackModes: IntruderAttackMode[] = [
    "sniper",
    "battering_ram",
    "pitchfork",
    "cluster_bomb",
  ];
  const uploadMutationKinds: UploadMutationKind[] = [
    "extension_case",
    "double_extension",
    "trailing_character",
    "content_type",
    "filename_encoding",
    "magic_bytes",
    "image_polyglot",
    "extra_form_field",
  ];
  const payloadLocations: PayloadLocation[] = [
    "byte_range",
    "path",
    "header",
    "query",
    "form",
    "multipart_name",
    "multipart_filename",
    "multipart_body",
    "multipart_content_type",
  ];

  let status: AppStatus | null = null;
  let artifacts: Artifact[] = [];
  let scopes: TargetScope[] = [];
  let jobs: JobView[] = [];
  let selectedLogJobId = "";
  let selectedLogStream: JobLogStream = "stdout";
  let jobLogContent = "";
  let jobLogOffset = 0;
  let jobLogEof = false;
  let discoveries: Discovery[] = [];
  let discoveryNextCursor: string | null = null;
  let discoveryPageNumber = 1;
  let dictionaries: DictionaryIndex[] = [];
  let tools: ToolHealthDto[] = [];
  let toolPacks: ToolPackHealthDto[] = [];
  let externalLaunchers: ExternalLauncherHealthDto[] = [];
  let payloadSources: PayloadSourceHealthDto[] = [];
  let payloadEntries: PayloadEntryDto[] = [];
  let selectedPayload: PayloadEntryDto | null = null;
  let payloadPreview: PayloadPreview | null = null;
  let selectedPayloadSource = "";
  let payloadQuery = "";
  let payloadCursor: string | null = null;
  let proxySession: ProxySession | null = null;
  let httpMessages: HttpMessage[] = [];
  let selectedHttpMessage: HttpMessage | null = null;
  let historyQuery = "";
  let historyDirection: "" | "request" | "response" = "";
  let historySource: "" | "proxy" | "repeater" = "";
  let repeaterMethod = "GET";
  let repeaterPath = "/";
  let repeaterHeaders = "";
  let repeaterBody = "";
  let repeatResponse: HttpMessage | null = null;
  let diffLeftId = "";
  let diffRightId = "";
  let httpDiff: HttpMessageDiff | null = null;
  let strictCapture = false;
  let proxySslInsecure = false;
  let rawHttpText =
    "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
  let rawTls = false;
  let metasploitStatus: MetasploitStatus | null = null;
  let metasploitModules: MetasploitModuleSummary[] = [];
  let metasploitOptions: MetasploitModuleOption[] = [];
  let metasploitEntities: AdapterEntity[] = [];
  let metasploitQuery = "type:auxiliary http";
  let selectedMetasploitModule: MetasploitModuleSummary | null = null;
  let metasploitOptionJson = '{\n  "RHOSTS": "127.0.0.1",\n  "RPORT": 8080\n}';
  let metasploitExecutionKind: MetasploitExecutionKind = "check";
  let metasploitConfirmation = "";
  let metasploitStopConfirmation = "";
  let metasploitConsoleId = "";
  let metasploitConsoleCommand = "help";
  let metasploitSessionId = "";
  let metasploitSessionCommand = "whoami";
  let metasploitTranscript = "";
  let metasploitEntityStopConfirmation = "";
  let selectedArtifact: Artifact | null = null;
  let preview: ArtifactPreview | null = null;
  let intruderCampaigns: IntruderCampaign[] = [];
  let intruderAttempts: IntruderAttempt[] = [];
  let intruderParentMessageId = "";
  let intruderAttackMode: IntruderAttackMode = "sniper";
  let intruderDictionaryIds = "";
  let intruderGlobalRate = 8;
  let intruderTargetRate = 8;
  let intruderPositionLocation: PayloadLocation = "form";
  let intruderPositionName = "q";
  let intruderPositionOccurrence = 0;
  let intruderPositionStart = 0;
  let intruderPositionEnd = 1;
  let uploadParentMessageId = "";
  let uploadPartOrdinal = 0;
  let uploadMutations: UploadMutationKind[] = ["magic_bytes"];
  let uploadVerificationMode: UploadVerificationMode = "safe_retrieval";
  let uploadExpectedExecutionMarker = "";
  let uploadConfirmation = "";
  let stateMacroEnabled = false;
  let stateMacroStepName = "refresh-csrf";
  let stateMacroMessageId = "";
  let stateMacroVariable = "csrf";
  let stateMacroSource: TokenSource = "response_body";
  let stateMacroHeaderName = "";
  let stateMacroPrefix = 'value="';
  let stateMacroSuffix = '"';
  let stateMacroMaximumLength = 64;
  let multipartMessageId = "";
  let multipartDocument: MultipartDocument | null = null;
  let selectedCampaignId = "";
  let activeSection = "recon";
  let scopeUrl = "http://127.0.0.1:8000/";
  let selectedScopeId = "";
  let selectedTool: AlphaTool = "curl";
  let targetUrl = "http://127.0.0.1:8000/";
  let selectedExternalLauncher: ExternalLauncherId = "ant_sword";
  let externalTargetUrl = "http://127.0.0.1:8000/";
  let externalConfirmation = "";
  let wordlistText = "admin\napi\nredirect\nmissing-r3";
  let dictionaryName = "paths";
  let dictionaryContent = "admin\napi\nassets\n";
  let selectedDictionaryId = "";
  let dictionaryPrefix = "a";
  let dictionaryMatches: string[] = [];
  let noteName = "evidence.txt";
  let noteContent = "";
  let noteSensitivity: Sensitivity = "normal";
  let busy = false;
  let notice = "正在连接 Rust Core…";
  let noticeKind: "info" | "success" | "error" = "info";
  let pollTimer: ReturnType<typeof setTimeout> | undefined;

  async function loadArtifacts(): Promise<void> {
    if (!status?.active_project) {
      externalLaunchers = [];
      artifacts = [];
      return;
    }
    const page = await ipc.listArtifacts({
      project_id: status.active_project.project_id,
      cursor: null,
      limit: 100,
    });
    artifacts = page.items;
  }

  async function loadAlphaData(): Promise<void> {
    [tools, toolPacks] = await Promise.all([
      ipc.toolHealth(),
      ipc.toolPackHealth(),
    ]);
    if (!status?.active_project) {
      scopes = [];
      jobs = [];
      discoveries = [];
      discoveryNextCursor = null;
      discoveryPageNumber = 1;
      dictionaries = [];
      payloadSources = [];
      payloadEntries = [];
      selectedPayload = null;
      payloadPreview = null;
      selectedScopeId = "";
      selectedDictionaryId = "";
      return;
    }
    const project_id = status.active_project.project_id;
    const [
      scopePage,
      jobPage,
      discoveryPage,
      dictionaryPage,
      launcherHealth,
      payloadHealth,
    ] = await Promise.all([
      ipc.listScopes({ project_id }),
      ipc.listJobs({ project_id, cursor: null, limit: 100 }),
      ipc.listDiscoveries({ project_id, cursor: null, limit: 100 }),
      ipc.listDictionaries({ project_id }),
      ipc.externalLauncherHealth({ project_id }),
      ipc.payloadSourceHealth({ project_id }),
    ]);
    scopes = scopePage.items;
    jobs = jobPage.items;
    if (
      selectedLogJobId &&
      !jobs.some((item) => item.job.job_id === selectedLogJobId)
    ) {
      selectedLogJobId = "";
      jobLogContent = "";
      jobLogOffset = 0;
      jobLogEof = false;
    }
    discoveries = discoveryPage.items;
    discoveryNextCursor = discoveryPage.next_cursor;
    discoveryPageNumber = 1;
    dictionaries = dictionaryPage.items;
    externalLaunchers = launcherHealth;
    payloadSources = payloadHealth;
    if (
      !payloadSources.some(
        (source) =>
          source.source_id === selectedPayloadSource && source.healthy,
      )
    ) {
      selectedPayloadSource =
        payloadSources.find((source) => source.healthy)?.source_id ?? "";
      payloadEntries = [];
      selectedPayload = null;
      payloadPreview = null;
      payloadCursor = null;
    }
    if (!scopes.some((scope) => scope.scope_id === selectedScopeId)) {
      selectedScopeId = scopes[0]?.scope_id ?? "";
      if (scopes[0]) {
        targetUrl = scopeOrigin(scopes[0]);
        externalTargetUrl = targetUrl;
      }
    }
    if (
      !dictionaries.some(
        (dictionary) => dictionary.dictionary_id === selectedDictionaryId,
      )
    ) {
      selectedDictionaryId = dictionaries[0]?.dictionary_id ?? "";
      dictionaryMatches = [];
    }
  }

  async function loadHttpData(): Promise<void> {
    if (!status?.active_project) {
      proxySession = null;
      httpMessages = [];
      selectedHttpMessage = null;
      return;
    }
    const project_id = status.active_project.project_id;
    const [session, history] = await Promise.all([
      ipc.httpProxyStatus({ project_id }),
      ipc.listHttpHistory({
        project_id,
        cursor: null,
        limit: 100,
        query: historyQuery || null,
        source: historySource || null,
        direction: historyDirection || null,
        host: null,
        status_code: null,
      }),
    ]);
    proxySession = session;
    httpMessages = history.items;
    if (
      selectedHttpMessage &&
      !httpMessages.some(
        (message) => message.message_id === selectedHttpMessage?.message_id,
      )
    ) {
      selectedHttpMessage = null;
    }
  }

  async function initializeLocalData(): Promise<void> {
    await ipc.listImportPackages();
  }

  async function loadMetasploitData(): Promise<void> {
    if (!status?.active_project) {
      metasploitStatus = null;
      metasploitEntities = [];
      return;
    }
    const project_id = status.active_project.project_id;
    metasploitStatus = await ipc.metasploitStatus({ project_id });
    if (metasploitStatus.state === "ready") {
      metasploitEntities = (await ipc.listMetasploitEntities({ project_id }))
        .items;
    } else {
      metasploitEntities = [];
    }
  }

  function scopeOrigin(scope: TargetScope): string {
    const rawHost = scope.exact_hosts[0] ?? "";
    const host = rawHost.includes(":") ? `[${rawHost}]` : rawHost;
    return `${scope.schemes[0]}://${host}:${scope.ports[0]?.start ?? ""}/`;
  }

  function selectScope(scope: TargetScope): void {
    selectedScopeId = scope.scope_id;
    targetUrl = scopeOrigin(scope);
    externalTargetUrl = targetUrl;
    externalConfirmation = "";
  }

  function externalConfirmationPhrase(): string {
    const id =
      selectedExternalLauncher === "ant_sword"
        ? "antsword"
        : selectedExternalLauncher;
    return selectedScopeId ? `LAUNCH EXTERNAL ${id} ${selectedScopeId}` : "";
  }

  async function ensureToolboxWorkspace(): Promise<void> {
    status = await ipc.status();
    if (status.active_project) return;

    const page = await ipc.listProjects({ cursor: null, limit: 100 });
    const latest = [...page.items].sort((left, right) =>
      right.updated_at.localeCompare(left.updated_at),
    )[0];
    if (latest) {
      await ipc.openProject({
        project_id: latest.project_id,
        mode: "read_write",
      });
    } else {
      await ipc.createProject({ name: "FlagDeck Workspace" });
    }
    status = await ipc.status();
  }

  async function refresh(): Promise<void> {
    await ensureToolboxWorkspace();
    await Promise.all([
      loadArtifacts(),
      loadAlphaData(),
      loadHttpData(),
      loadMetasploitData(),
      loadIntruderCampaigns(),
      initializeLocalData(),
    ]);
  }

  function jobIsActive(item: JobView): boolean {
    return ["queued", "starting", "running", "stopping"].includes(
      item.job.execution_status,
    );
  }

  function scheduleJobPoll(): void {
    if (pollTimer || !jobs.some(jobIsActive)) return;
    pollTimer = setTimeout(() => {
      pollTimer = undefined;
      void pollJobs();
    }, 500);
  }

  async function pollJobs(): Promise<void> {
    try {
      await refresh();
      await loadJobLog(false);
    } catch (error) {
      reportError(error);
    }
    scheduleJobPoll();
  }

  async function selectJobLog(item: JobView): Promise<void> {
    if (selectedLogJobId !== item.job.job_id) {
      selectedLogJobId = item.job.job_id;
      selectedLogStream = "stdout";
      jobLogContent = "";
      jobLogOffset = 0;
      jobLogEof = false;
    }
    await loadJobLog(true);
  }

  async function selectJobLogStream(stream: JobLogStream): Promise<void> {
    selectedLogStream = stream;
    jobLogContent = "";
    jobLogOffset = 0;
    jobLogEof = false;
    await loadJobLog(true);
  }

  async function loadJobLog(reset: boolean): Promise<void> {
    if (!status?.active_project || !selectedLogJobId) return;
    const offset = reset ? 0 : jobLogOffset;
    const preview = await ipc.previewJobLog({
      project_id: status.active_project.project_id,
      job_id: selectedLogJobId,
      stream: selectedLogStream,
      offset,
      limit: 65536,
    });
    const combined = reset
      ? preview.content
      : `${jobLogContent}${preview.content}`;
    jobLogContent = combined.slice(-262144);
    jobLogOffset = preview.next_offset;
    jobLogEof = preview.eof;
  }

  function reportError(error: unknown): void {
    notice = commandErrorMessage(error);
    noticeKind = "error";
  }

  async function guarded(
    operation: () => Promise<void>,
    success: string,
  ): Promise<void> {
    busy = true;
    try {
      await operation();
      notice = success;
      noticeKind = "success";
    } catch (error) {
      reportError(error);
    } finally {
      busy = false;
    }
  }

  async function createNote(): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      const artifact = await ipc.createNote({
        project_id: status!.active_project!.project_id,
        logical_name: noteName,
        content: noteContent,
        sensitivity: noteSensitivity,
      });
      noteContent = "";
      await refresh();
      await selectArtifact(artifact);
    }, "笔记已通过原子 Artifact 协议提交");
  }

  async function createScope(): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      const scope = await ipc.createScope({
        project_id: status!.active_project!.project_id,
        base_url: scopeUrl,
      });
      selectedScopeId = scope.scope_id;
      targetUrl = scopeUrl;
      await refresh();
    }, "TargetScope 已保存，DNS 快照已固定");
  }

  function selectTool(tool: AlphaTool): void {
    selectedTool = tool;
    if (tool === "arjun") {
      wordlistText = "debug\nid\nunused";
    } else if (tool === "ffuf" || tool === "gobuster") {
      wordlistText = "admin\napi\nredirect\nmissing-r3";
    }
  }

  function scopeAcceptsTarget(scope: TargetScope, target: string): boolean {
    try {
      return new URL(scopeOrigin(scope)).origin === new URL(target).origin;
    } catch {
      return false;
    }
  }

  async function ensureScopeForTarget(target: string): Promise<string> {
    const existing = scopes.find((scope) => scopeAcceptsTarget(scope, target));
    if (existing) {
      selectedScopeId = existing.scope_id;
      return existing.scope_id;
    }
    const scope = await ipc.createScope({
      project_id: status!.active_project!.project_id,
      base_url: target,
    });
    scopes = [...scopes, scope];
    selectedScopeId = scope.scope_id;
    return scope.scope_id;
  }

  async function runSelectedTool(): Promise<void> {
    if (!status?.active_project || !targetUrl) return;
    const terms = ["ffuf", "arjun", "gobuster"].includes(selectedTool)
      ? wordlistText
          .split("\n")
          .map((value) => value.trim())
          .filter(Boolean)
      : [];
    await guarded(async () => {
      const scopeId = await ensureScopeForTarget(targetUrl);
      const job = await ipc.runTool({
        project_id: status!.active_project!.project_id,
        scope_id: scopeId,
        tool: selectedTool,
        target_url: targetUrl,
        wordlist_terms: terms,
      });
      selectedLogJobId = job.job.job_id;
      selectedLogStream = "stdout";
      jobLogContent = "";
      jobLogOffset = 0;
      jobLogEof = false;
      await refresh();
      scheduleJobPoll();
      notice = `${selectedTool} 已进入 ${job.job.execution_status} · ${job.job.job_id}`;
    }, `${selectedTool} 任务已进入受管队列`);
  }

  async function launchSelectedExternal(): Promise<void> {
    if (!status?.active_project || !selectedScopeId) return;
    await guarded(async () => {
      const job = await ipc.launchExternal({
        project_id: status!.active_project!.project_id,
        scope_id: selectedScopeId,
        launcher: selectedExternalLauncher,
        target_url: externalTargetUrl,
        confirmation: externalConfirmation,
      });
      selectedLogJobId = job.job.job_id;
      selectedLogStream = "stdout";
      jobLogContent = "";
      jobLogOffset = 0;
      jobLogEof = false;
      externalConfirmation = "";
      await refresh();
      scheduleJobPoll();
      notice = `${selectedExternalLauncher} 已进入 ${job.job.execution_status} · ${job.job.job_id}`;
    }, `${selectedExternalLauncher} 已进入受管启动队列`);
  }

  async function loadNextDiscoveries(): Promise<void> {
    if (!status?.active_project || !discoveryNextCursor) return;
    await guarded(async () => {
      const page = await ipc.listDiscoveries({
        project_id: status!.active_project!.project_id,
        cursor: discoveryNextCursor,
        limit: 100,
      });
      discoveries = page.items;
      discoveryNextCursor = page.next_cursor;
      discoveryPageNumber += 1;
    }, "下一页 Discovery 已加载");
  }

  async function loadLatestDiscoveries(): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      const page = await ipc.listDiscoveries({
        project_id: status!.active_project!.project_id,
        cursor: null,
        limit: 100,
      });
      discoveries = page.items;
      discoveryNextCursor = page.next_cursor;
      discoveryPageNumber = 1;
    }, "最新 Discovery 页已加载");
  }

  async function searchPayloads(append = false): Promise<void> {
    if (!status?.active_project || !selectedPayloadSource) return;
    await guarded(
      async () => {
        const page = await ipc.listPayloads({
          project_id: status!.active_project!.project_id,
          source_id: selectedPayloadSource,
          query: payloadQuery,
          cursor: append ? payloadCursor : null,
          limit: 100,
        });
        payloadEntries = append
          ? [...payloadEntries, ...page.items]
          : page.items;
        payloadCursor = page.next_cursor;
        if (
          selectedPayload &&
          !payloadEntries.some(
            (entry) => entry.payload_id === selectedPayload?.payload_id,
          )
        ) {
          selectedPayload = null;
          payloadPreview = null;
        }
      },
      append ? "下一页 Payload 已加载" : "Payload 索引查询完成",
    );
  }

  async function selectPayload(entry: PayloadEntryDto): Promise<void> {
    if (!status?.active_project) return;
    selectedPayload = entry;
    payloadPreview = null;
    await guarded(async () => {
      payloadPreview = await ipc.previewPayload({
        project_id: status!.active_project!.project_id,
        payload_id: entry.payload_id,
        offset: 0,
        limit: 65_536,
      });
    }, "Payload 已通过有界只读预览加载");
  }

  async function cancelJob(item: JobView): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      const result = await ipc.cancelJob({
        project_id: status!.active_project!.project_id,
        job_id: item.job.job_id,
      });
      await refresh();
      scheduleJobPoll();
      notice = `取消已确认 · cleanup=${result.cleanup_verified} · residual=${result.residual_processes}`;
    }, "任务树已停止并完成归属清理");
  }

  async function cancelAllJobs(): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      const result = await ipc.cancelAllJobs({
        project_id: status!.active_project!.project_id,
      });
      await refresh();
      scheduleJobPoll();
      notice = `已处理 ${result.requested} 个活动任务`;
    }, "全部活动任务已完成停止流程");
  }

  async function createDictionary(): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      const dictionary = await ipc.createDictionary({
        project_id: status!.active_project!.project_id,
        name: dictionaryName,
        content: dictionaryContent,
      });
      selectedDictionaryId = dictionary.dictionary_id;
      await refresh();
    }, "字典已规范化、归档并建立索引");
  }

  async function searchDictionary(): Promise<void> {
    if (!status?.active_project || !selectedDictionaryId) return;
    await guarded(async () => {
      const result = await ipc.searchDictionary({
        project_id: status!.active_project!.project_id,
        dictionary_id: selectedDictionaryId,
        prefix: dictionaryPrefix,
        limit: 100,
      });
      dictionaryMatches = result.terms;
    }, "字典索引查询完成");
  }

  async function selectArtifact(artifact: Artifact): Promise<void> {
    if (!status?.active_project) return;
    selectedArtifact = artifact;
    preview = null;
    await guarded(async () => {
      preview = await ipc.previewArtifact({
        project_id: status!.active_project!.project_id,
        artifact_id: artifact.artifact_id,
        offset: 0,
        limit: 65_536,
        mode: "text",
      });
    }, "已加载脱敏预览");
  }

  function headersToText(headers: OrderedValue[]): string {
    return headers
      .map((header) => `${header.name}: ${header.value}`)
      .join("\n");
  }

  function parseHeaderText(value: string): OrderedValue[] {
    return value
      .split("\n")
      .map((line) => line.replace(/\r$/, ""))
      .filter(Boolean)
      .map((line) => {
        const separator = line.indexOf(":");
        if (separator <= 0) throw new Error("Header format is invalid");
        return {
          name: line.slice(0, separator).trim(),
          value: line.slice(separator + 1).trimStart(),
        };
      });
  }

  function selectHttpMessage(message: HttpMessage): void {
    selectedHttpMessage = message;
    if (message.direction === "request") {
      repeaterMethod = message.method ?? "GET";
      repeaterPath = message.path;
      repeaterHeaders = headersToText(message.headers);
      repeaterBody = message.body_inline
        ? new TextDecoder().decode(new Uint8Array(message.body_inline))
        : "";
      diffLeftId = message.message_id;
    } else {
      diffRightId = message.message_id;
    }
  }

  async function startHttpProxy(): Promise<void> {
    if (!status?.active_project || !selectedScopeId) return;
    await guarded(async () => {
      proxySession = await ipc.startHttpProxy({
        project_id: status!.active_project!.project_id,
        scope_id: selectedScopeId,
        capture_mode: strictCapture ? "evidence_strict" : "pass_through",
        ssl_insecure: proxySslInsecure,
        launch_browser: true,
      });
      await loadHttpData();
    }, "代理、独立 CA、NSS DB 与私有 Chrome 已就绪");
  }

  async function stopHttpProxy(): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      await ipc.stopHttpProxy({
        project_id: status!.active_project!.project_id,
      });
      await loadHttpData();
    }, "代理与 Chrome 进程组已停止，捕获消息已提交");
  }

  async function repeatSelectedHttp(): Promise<void> {
    if (
      !status?.active_project ||
      !selectedScopeId ||
      !selectedHttpMessage ||
      selectedHttpMessage.direction !== "request"
    )
      return;
    await guarded(async () => {
      const result = await ipc.repeatHttp({
        project_id: status!.active_project!.project_id,
        scope_id: selectedScopeId,
        parent_message_id: selectedHttpMessage!.message_id,
        method: repeaterMethod,
        path: repeaterPath,
        headers: parseHeaderText(repeaterHeaders),
        body: Array.from(new TextEncoder().encode(repeaterBody)),
        ssl_insecure: proxySslInsecure,
      });
      repeatResponse = result.response;
      diffRightId = result.response.message_id;
      await loadHttpData();
    }, "Repeater 请求与响应已按父子关系归档");
  }

  async function diffHttpMessages(): Promise<void> {
    if (!status?.active_project || !diffLeftId || !diffRightId) return;
    await guarded(async () => {
      httpDiff = await ipc.diffHttp({
        project_id: status!.active_project!.project_id,
        left_message_id: diffLeftId,
        right_message_id: diffRightId,
      });
    }, "Header、参数、Body 与响应时间 Diff 已生成");
  }

  async function createSqlmapRequest(): Promise<void> {
    if (!status?.active_project || !selectedHttpMessage) return;
    await guarded(async () => {
      const artifact = await ipc.createSqlmapRequest({
        project_id: status!.active_project!.project_id,
        message_id: selectedHttpMessage!.message_id,
        confirm_sensitive: selectedHttpMessage!.sensitivity !== "normal",
      });
      await loadArtifacts();
      notice = `SQLMap -r 文件已归档 · ${artifact.artifact_id}`;
    }, "SQLMap 请求文件已按 serializer v1 生成");
  }

  function isHtmlResponse(message: HttpMessage): boolean {
    return (
      message.direction === "response" &&
      message.headers.some(
        (header) =>
          header.name.toLowerCase() === "content-type" &&
          header.value.split(";", 1)[0].trim().toLowerCase() === "text/html",
      )
    );
  }

  async function openBrowserPreview(): Promise<void> {
    if (!status?.active_project || !selectedHttpMessage) return;
    await guarded(async () => {
      const result = await ipc.openHttpBrowserPreview({
        project_id: status!.active_project!.project_id,
        message_id: selectedHttpMessage!.message_id,
      });
      notice = `私有 Chrome 已打开 ${result.url}`;
    }, "HTML 目标已在私有 Chrome 新标签打开");
  }

  async function sendRawHttp(): Promise<void> {
    if (!status?.active_project || !selectedScopeId) return;
    const scope = scopes.find((item) => item.scope_id === selectedScopeId);
    if (!scope) return;
    await guarded(async () => {
      const result = await ipc.sendRawHttp1({
        project_id: status!.active_project!.project_id,
        scope_id: selectedScopeId,
        host: scope.exact_hosts[0],
        port: scope.ports[0].start,
        tls: rawTls,
        ssl_insecure: proxySslInsecure,
        wire_bytes: Array.from(new TextEncoder().encode(rawHttpText)),
      });
      selectedHttpMessage = result.response;
      await loadHttpData();
    }, "Raw HTTP/1 请求与响应线格式 Artifact 已归档");
  }

  async function startMetasploit(): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      metasploitStatus = await ipc.startMetasploit({
        project_id: status!.active_project!.project_id,
      });
      await loadMetasploitData();
    }, "Metasploit 动态 Loopback RPC、TLS pin 与独立 Workspace 已就绪");
  }

  async function loadIntruderCampaigns(): Promise<void> {
    if (!status?.active_project) {
      intruderCampaigns = [];
      return;
    }
    const page = await ipc.listIntruderCampaigns({
      project_id: status.active_project.project_id,
      limit: 50,
    });
    intruderCampaigns = page.items;
  }

  async function refreshIntruderCampaigns(): Promise<void> {
    await guarded(loadIntruderCampaigns, "Campaign 列表已刷新");
  }

  function parsedDictionaryIds(): string[] {
    return intruderDictionaryIds
      .split(",")
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
  }

  function configuredStateMacro() {
    return buildStateMacro({
      enabled: stateMacroEnabled,
      stepName: stateMacroStepName,
      messageId: stateMacroMessageId,
      variable: stateMacroVariable,
      source: stateMacroSource,
      headerName: stateMacroHeaderName,
      prefix: stateMacroPrefix,
      suffix: stateMacroSuffix,
      maximumLength: stateMacroMaximumLength,
    });
  }

  function configuredIntruderPosition(): PayloadPosition {
    if (intruderPositionLocation === "byte_range") {
      return {
        location: intruderPositionLocation,
        name: null,
        occurrence: intruderPositionOccurrence,
        start: intruderPositionStart,
        end: intruderPositionEnd,
      };
    }
    return {
      location: intruderPositionLocation,
      name: intruderPositionName,
      occurrence: intruderPositionOccurrence,
      start: null,
      end: null,
    };
  }

  async function startIntruder(): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      await ipc.startIntruder({
        project_id: status!.active_project!.project_id,
        scope_id: selectedScopeId,
        parent_message_id: intruderParentMessageId,
        attack_mode: intruderAttackMode,
        positions: [configuredIntruderPosition()],
        dictionary_ids: parsedDictionaryIds(),
        global_rate_per_second: intruderGlobalRate,
        target_rate_per_second: intruderTargetRate,
        state_macro: configuredStateMacro(),
      });
      await loadIntruderCampaigns();
    }, "Intruder Campaign 已排队，后台线程受限速运行");
  }

  async function startUpload(): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      await ipc.startUploadCampaign({
        project_id: status!.active_project!.project_id,
        scope_id: selectedScopeId,
        parent_message_id: uploadParentMessageId,
        part_ordinal: uploadPartOrdinal,
        mutations: uploadMutations,
        global_rate_per_second: intruderGlobalRate,
        target_rate_per_second: intruderTargetRate,
        state_macro: configuredStateMacro(),
        verification: {
          mode: uploadVerificationMode,
          path_extractor:
            uploadVerificationMode === "none"
              ? null
              : {
                  variable: "path",
                  source: "response_body",
                  header_name: null,
                  prefix: Array.from('"path":"').map((c) => c.charCodeAt(0)),
                  suffix: [34],
                  maximum_length: 256,
                },
          expected_execution_marker:
            uploadVerificationMode === "execution"
              ? encodeExecutionMarker(uploadExpectedExecutionMarker)
              : null,
        },
        confirmation:
          uploadVerificationMode === "execution"
            ? uploadConfirmation || null
            : null,
      });
      await loadIntruderCampaigns();
    }, "上传变异 Campaign 已排队");
  }

  async function cancelCampaign(id: string): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      await ipc.cancelIntruderCampaign({
        project_id: status!.active_project!.project_id,
        intruder_campaign_id: id,
      });
      await loadIntruderCampaigns();
    }, "Campaign 已请求取消并暂停");
  }

  async function resumeCampaign(id: string): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      await ipc.resumeIntruderCampaign({
        project_id: status!.active_project!.project_id,
        intruder_campaign_id: id,
      });
      await loadIntruderCampaigns();
    }, "Campaign 已从中断点恢复");
  }

  async function loadIntruderAttempts(id: string): Promise<void> {
    if (!status?.active_project) return;
    selectedCampaignId = id;
    await guarded(async () => {
      const page = await ipc.listIntruderAttempts({
        project_id: status!.active_project!.project_id,
        intruder_campaign_id: id,
        cursor: null,
        limit: 100,
      });
      intruderAttempts = page.items;
    }, "Attempt 分页结果已加载");
  }

  async function parseMultipart(): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      multipartDocument = await ipc.parseMultipartMessage({
        project_id: status!.active_project!.project_id,
        message_id: multipartMessageId,
      });
    }, "Multipart 结构已解析");
  }

  function toggleUploadMutation(kind: UploadMutationKind): void {
    uploadMutations = uploadMutations.includes(kind)
      ? uploadMutations.filter((value) => value !== kind)
      : [...uploadMutations, kind];
  }

  function decodeBytes(values: number[] | null): string {
    if (!values) return "—";
    return toSafeTextPreview(
      String.fromCharCode(...values.map((value) => value & 0xff)),
    );
  }

  async function stopMetasploit(): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      metasploitStatus = await ipc.stopMetasploit({
        project_id: status!.active_project!.project_id,
        confirmation: metasploitStopConfirmation || null,
      });
      metasploitModules = [];
      metasploitOptions = [];
      metasploitEntities = [];
    }, "Metasploit 受管对象、RPC Token 与 Supervisor 生命周期已清理");
  }

  async function searchMetasploitModules(): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      metasploitModules = await ipc.searchMetasploitModules({
        project_id: status!.active_project!.project_id,
        query: metasploitQuery,
      });
    }, "模块目录搜索完成并保存脱敏快照");
  }

  async function selectMetasploitModule(
    module: MetasploitModuleSummary,
  ): Promise<void> {
    if (!status?.active_project) return;
    selectedMetasploitModule = module;
    metasploitConfirmation = `EXECUTE ${module.module_type}/${module.fullname}`;
    await guarded(async () => {
      metasploitOptions = await ipc.getMetasploitOptions({
        project_id: status!.active_project!.project_id,
        module_type: module.module_type,
        fullname: module.fullname,
      });
    }, "模块选项、必填项与默认值已加载");
  }

  async function executeMetasploitModule(): Promise<void> {
    if (
      !status?.active_project ||
      !selectedScopeId ||
      !selectedMetasploitModule
    )
      return;
    await guarded(async () => {
      const options = JSON.parse(metasploitOptionJson) as Record<
        string,
        unknown
      >;
      const result = await ipc.executeMetasploitModule({
        project_id: status!.active_project!.project_id,
        scope_id: selectedScopeId,
        module_type: selectedMetasploitModule!.module_type,
        fullname: selectedMetasploitModule!.fullname,
        execution_kind: metasploitExecutionKind,
        options,
        confirmation: metasploitConfirmation,
      });
      await loadMetasploitData();
      notice = `L3 审计已提交 · Job ${result.job_entity?.external_id ?? "同步完成"}`;
    }, "Metasploit 执行请求已完成 Scope 与 L3 门禁");
  }

  async function createMetasploitConsole(): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      const entity = await ipc.createMetasploitConsole({
        project_id: status!.active_project!.project_id,
      });
      metasploitConsoleId = entity.external_id;
      await loadMetasploitData();
    }, "受管 Console 已创建并建立所有权映射");
  }

  async function runMetasploitConsoleCommand(): Promise<void> {
    if (!status?.active_project || !metasploitConsoleId) return;
    await guarded(async () => {
      const result = await ipc.metasploitConsoleCommand({
        project_id: status!.active_project!.project_id,
        console_id: metasploitConsoleId,
        command: metasploitConsoleCommand,
        confirmation: `CONSOLE ${metasploitConsoleId}`,
      });
      metasploitTranscript = result.redacted;
      await loadMetasploitData();
    }, "Console 完整记录已保存为敏感 Artifact");
  }

  async function runMetasploitSessionCommand(): Promise<void> {
    if (!status?.active_project || !metasploitSessionId) return;
    await guarded(async () => {
      const result = await ipc.metasploitSessionCommand({
        project_id: status!.active_project!.project_id,
        session_id: metasploitSessionId,
        command: metasploitSessionCommand,
        confirmation: `SESSION ${metasploitSessionId}`,
      });
      metasploitTranscript = result.redacted;
      await loadMetasploitData();
    }, "Session 命令与敏感证据已完成所有权和 L3 审计");
  }

  async function stopMetasploitEntity(entity: AdapterEntity): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      await ipc.stopMetasploitEntity({
        project_id: status!.active_project!.project_id,
        entity_kind: entity.entity_kind,
        external_id: entity.external_id,
        confirmation: metasploitEntityStopConfirmation,
      });
      metasploitEntityStopConfirmation = "";
      await loadMetasploitData();
    }, "受管 Metasploit 对象已停止并归档终止状态");
  }

  function loadSecurityFixture(): void {
    noteName = `hostile${String.fromCodePoint(0x202e)}exe.html`;
    noteContent = hostileFixture;
    noteSensitivity = "sensitive_evidence";
    notice = "恶意 HTML、SVG、iframe、日志与凭据 fixture 已作为文本载入";
    noticeKind = "info";
  }

  onMount(() => {
    void guarded(async () => {
      await refresh();
      scheduleJobPoll();
    }, "工具箱已就绪");
    return () => {
      if (pollTimer) clearTimeout(pollTimer);
    };
  });
</script>

<svelte:head>
  <title>FlagDeck · Security Toolbox</title>
</svelte:head>

<div class="shell">
  <header class="topbar">
    <div class="brand" aria-label="FlagDeck">
      <span class="brand-mark">FD</span>
      <div>
        <strong>FlagDeck</strong>
        <small>Security Toolbox</small>
      </div>
    </div>
    <div class="project-context" data-testid="active-project">
      <span class="pulse"></span>
      <div>
        <small>当前目标</small>
        <strong
          >{busy
            ? "正在处理…"
            : scopes.find((scope) => scope.scope_id === selectedScopeId)
              ? scopeOrigin(
                  scopes.find((scope) => scope.scope_id === selectedScopeId)!,
                )
              : "尚未设置目标"}</strong
        >
      </div>
    </div>
    <div class="top-status">
      <span>Tools <b>{tools.filter((tool) => tool.healthy).length}</b></span>
      <span>任务 <b>{status?.active_jobs ?? 0}</b></span>
      <button
        class="stop-button"
        data-testid="cancel-all-jobs"
        disabled={busy ||
          !status?.active_project ||
          status.active_project.read_only ||
          (status.active_jobs ?? 0) === 0}
        onclick={() => void cancelAllJobs()}>全部停止</button
      >
    </div>
  </header>

  <aside class="sidebar">
    <nav aria-label="主导航">
      {#each navigationGroups as group}
        <p class="nav-group-label">{group.label}</p>
        {#each group.items as [id, label, icon]}
          <button
            class:active={activeSection === id}
            onclick={() => (activeSection = id)}
          >
            <span class="nav-icon">{icon}</span>{label}
            {#if id === "jobs" && (status?.active_jobs ?? 0) > 0}
              <em>{status?.active_jobs}</em>
            {/if}
          </button>
        {/each}
      {/each}
    </nav>
    <div class="trust-card">
      <span class="trust-icon"></span>
      <div>
        <strong>本地核心已连接</strong>
        <small>{tools.filter((tool) => tool.healthy).length} 个工具可用</small>
      </div>
    </div>
  </aside>

  <main class="workspace">
    <div class="page-heading">
      <div>
        <p class="eyebrow">{sectionMeta[activeSection]?.eyebrow}</p>
        <h1>{sectionMeta[activeSection]?.title ?? "FlagDeck"}</h1>
        <p>{sectionMeta[activeSection]?.description}</p>
      </div>
      <div class="version-chip">
        <span class="status-led"></span>
        <div>
          <strong>Core v{status?.application_version ?? "—"}</strong>
          <small>contract {status?.contract_version ?? "—"}</small>
        </div>
      </div>
    </div>

    <div
      class:success={noticeKind === "success"}
      class:error={noticeKind === "error"}
      class="notice"
      data-testid="notice"
    >
      <span></span>{notice}
    </div>

    {#if !status?.active_project}
      <section class="panel boot-panel">
        <span class="boot-spinner"></span>
        <div>
          <h2>正在准备本地工作区</h2>
          <p>任务、日志和结果会自动保存在应用数据目录。</p>
        </div>
      </section>
    {:else}
      {#if activeSection === "http" || activeSection === "metasploit" || activeSection === "settings"}
        <section
          class="panel alpha-panel target-panel"
          data-testid="scope-panel"
        >
          <div class="section-heading">
            <div>
              <p class="section-label">TARGETS</p>
              <h2>目标范围</h2>
            </div>
            <span class="count">{scopes.length}</span>
          </div>
          <form
            onsubmit={(event) => {
              event.preventDefault();
              void createScope();
            }}
          >
            <label for="scope-url">目标 Base URL</label>
            <div class="inline-form">
              <input
                id="scope-url"
                data-testid="scope-url"
                bind:value={scopeUrl}
                maxlength="4096"
                required
              />
              <button
                class="primary"
                type="submit"
                disabled={busy || status.active_project.read_only}
                >添加目标</button
              >
            </div>
          </form>
          {#if scopes.length > 0}
            <div class="scope-list">
              {#each scopes as scope}
                <label class:selected={scope.scope_id === selectedScopeId}>
                  <input
                    type="radio"
                    bind:group={selectedScopeId}
                    value={scope.scope_id}
                    onchange={() => selectScope(scope)}
                  />
                  <span>
                    <strong
                      >{scope.schemes[0]}://{scope.exact_hosts[0]}:{scope
                        .ports[0]?.start}</strong
                    >
                    <small
                      >{scope.network_class} · DNS {scope.dns_snapshots[0]?.addresses.join(
                        ", ",
                      )}</small
                    >
                  </span>
                </label>
              {/each}
            </div>
          {/if}
        </section>
      {/if}

      {#if activeSection === "http"}
        <section class="panel alpha-panel" data-testid="http-proxy-panel">
          <div class="section-heading">
            <div>
              <p class="section-label">MITMPROXY / LOCAL TRUST</p>
              <h2>单活动代理会话</h2>
            </div>
            <span
              class:active={proxySession?.state === "ready"}
              class="risk-pill"
            >
              {proxySession?.state ?? "stopped"}
            </span>
          </div>
          {#if proxySession}
            <div class="proxy-status-grid">
              <div>
                <span>Listener</span><code
                  >{proxySession.listen_host}:{proxySession.listen_port}</code
                >
              </div>
              <div>
                <span>Capture</span><code>{proxySession.capture_mode}</code>
              </div>
              <div>
                <span>CA SHA-256</span><code
                  >{proxySession.ca_sha256 ?? "pending"}</code
                >
              </div>
              <div>
                <span>Chrome PGID</span><code
                  >{proxySession.chrome_pid ?? "—"}</code
                >
              </div>
            </div>
            <button
              class="row-stop full"
              disabled={busy || status.active_project.read_only}
              onclick={() => void stopHttpProxy()}>停止代理与私有 Chrome</button
            >
          {:else}
            <div class="http-controls">
              <label class="check-row">
                <input type="checkbox" bind:checked={strictCapture} />
                <span>Evidence-strict · 每个 chunk 等待 writer ack</span>
              </label>
              <label class="check-row">
                <input type="checkbox" bind:checked={proxySslInsecure} />
                <span>允许当前目标使用自签名上游 TLS</span>
              </label>
              <button
                class="primary"
                disabled={busy ||
                  status.active_project.read_only ||
                  !selectedScopeId}
                onclick={() => void startHttpProxy()}
                >启动代理并打开私有 Chrome</button
              >
            </div>
          {/if}
          <p class="boundary-note">
            动态 Loopback 端口 · 4 MiB / 256 frames · 默认 TLS 校验 · 无 direct
            fallback · 首次启用约 60 MiB 下载 / 190 MiB 独立运行环境
          </p>
        </section>

        <section class="panel alpha-panel" data-testid="http-history-panel">
          <div class="section-heading">
            <div>
              <p class="section-label">PAGED SQLITE / FTS5</p>
              <h2>HTTP History</h2>
            </div>
            <span class="count">{httpMessages.length}</span>
          </div>
          <div class="history-filters">
            <input
              bind:value={historyQuery}
              placeholder="脱敏全文搜索"
              maxlength="1024"
            />
            <select bind:value={historyDirection}>
              <option value="">全部方向</option>
              <option value="request">Request</option>
              <option value="response">Response</option>
            </select>
            <select bind:value={historySource}>
              <option value="">全部来源</option>
              <option value="proxy">Proxy</option>
              <option value="repeater">Repeater</option>
            </select>
            <button disabled={busy} onclick={() => void loadHttpData()}
              >刷新</button
            >
          </div>
          <div class="http-history-list">
            {#each httpMessages as message}
              <button
                class:selected={selectedHttpMessage?.message_id ===
                  message.message_id}
                onclick={() => selectHttpMessage(message)}
              >
                <span
                  class:response={message.direction === "response"}
                  class="kind-chip"
                >
                  {message.direction === "request"
                    ? (message.method ?? "REQ")
                    : message.status_code}
                </span>
                <strong>{message.host}:{message.port}{message.path}</strong>
                <small
                  >{message.source} · {message.representation_kind} · {message.body_state}
                  · {message.actual_length} B</small
                >
                <em>{message.duration_millis ?? "—"} ms</em>
              </button>
            {/each}
            {#if httpMessages.length === 0}<div class="empty compact">
                代理捕获与 Repeater 消息将在此分页显示。
              </div>{/if}
          </div>
        </section>

        {#if selectedHttpMessage}
          <div class="http-work-grid">
            <section class="panel alpha-panel">
              <p class="section-label">SAFE STRUCTURED VIEW</p>
              <h2>消息详情</h2>
              <pre
                class="http-safe-preview">{selectedHttpMessage.redacted_view}</pre>
              <div class="message-contract">
                <code>{selectedHttpMessage.serializer_version}</code>
                <span
                  >parent {selectedHttpMessage.parent_message_id ?? "—"}</span
                >
                <span
                  >body {selectedHttpMessage.body_artifact_id ??
                    "inline / empty"}</span
                >
                <span
                  >wire {selectedHttpMessage.wire_artifact_id ??
                    "semantic boundary"}</span
                >
              </div>
              {#if selectedHttpMessage.direction === "request" && selectedHttpMessage.representation_kind === "semantic"}
                <button
                  disabled={busy || status.active_project.read_only}
                  onclick={() => void createSqlmapRequest()}
                  >生成 SQLMap -r Artifact</button
                >
              {/if}
              {#if isHtmlResponse(selectedHttpMessage)}
                <button
                  disabled={busy || !proxySession?.chrome_pid}
                  onclick={() => void openBrowserPreview()}
                  >在私有 Chrome 打开 HTML 目标</button
                >
              {/if}
            </section>

            <section class="panel alpha-panel" data-testid="repeater-panel">
              <p class="section-label">SEMANTIC REPEATER</p>
              <h2>安全 HTTP/1 serializer</h2>
              <fieldset
                disabled={selectedHttpMessage.direction !== "request" ||
                  busy ||
                  status.active_project.read_only}
              >
                <div class="method-path-row">
                  <input bind:value={repeaterMethod} maxlength="32" />
                  <input bind:value={repeaterPath} maxlength="65536" />
                </div>
                <label for="repeater-headers">有序 Header</label>
                <textarea
                  id="repeater-headers"
                  bind:value={repeaterHeaders}
                  rows="7"></textarea>
                <label for="repeater-body">Body 文本</label>
                <textarea id="repeater-body" bind:value={repeaterBody} rows="5"
                ></textarea>
                <button
                  class="primary full"
                  onclick={() => void repeatSelectedHttp()}
                  >发送并归档父子消息</button
                >
              </fieldset>
              {#if repeatResponse}
                <pre
                  class="http-safe-preview compact">{repeatResponse.redacted_view}</pre>
              {/if}
            </section>
          </div>
        {:else}
          <section class="panel alpha-panel" data-testid="repeater-panel">
            <p class="section-label">SEMANTIC REPEATER</p>
            <h2>安全 HTTP/1 serializer</h2>
            <div class="empty compact">
              从 HTTP History 选择一条消息后加载 Repeater。
            </div>
          </section>
        {/if}

        <div class="http-work-grid">
          <section class="panel alpha-panel" data-testid="http-diff-panel">
            <p class="section-label">SEMANTIC DIFF</p>
            <h2>Header · 参数 · Body · 时间</h2>
            <div class="diff-selectors">
              <select bind:value={diffLeftId}>
                <option value="">左侧消息</option>
                {#each httpMessages as message}<option
                    value={message.message_id}
                    >{message.direction} · {message.method ??
                      message.status_code} · {message.path}</option
                  >{/each}
              </select>
              <select bind:value={diffRightId}>
                <option value="">右侧消息</option>
                {#each httpMessages as message}<option
                    value={message.message_id}
                    >{message.direction} · {message.method ??
                      message.status_code} · {message.path}</option
                  >{/each}
              </select>
              <button
                disabled={busy || !diffLeftId || !diffRightId}
                onclick={() => void diffHttpMessages()}>比较</button
              >
            </div>
            {#if httpDiff}
              <div class="diff-result">
                <strong
                  >{httpDiff.body.kind} · {httpDiff.body.left_length} → {httpDiff
                    .body.right_length} B</strong
                >
                <small
                  >Δ {httpDiff.duration_delta_millis ?? "—"} ms · Header {httpDiff
                    .headers.length} · Params {httpDiff.parameters
                    .length}</small
                >
                <code>{httpDiff.body.left_sha256}</code>
                <code>{httpDiff.body.right_sha256}</code>
                {#each httpDiff.body.text_changes as change}<pre>{change}</pre>{/each}
              </div>
            {/if}
          </section>

          <section class="panel alpha-panel" data-testid="raw-http-panel">
            <p class="section-label">RAW_HTTP1 / WIRE ARTIFACT</p>
            <h2>畸形请求专用边界</h2>
            <textarea bind:value={rawHttpText} rows="10" maxlength="1048576"
            ></textarea>
            <label class="check-row">
              <input type="checkbox" bind:checked={rawTls} />
              <span>TLS 连接</span>
            </label>
            <button
              class="primary full"
              disabled={busy ||
                status.active_project.read_only ||
                !selectedScopeId}
              onclick={() => void sendRawHttp()}
              >原样发送并保存双向 Wire Artifact</button
            >
          </section>
        </div>
      {/if}

      {#if activeSection === "metasploit"}
        <section class="panel alpha-panel" data-testid="metasploit-lifecycle">
          <div class="section-heading">
            <div>
              <p class="section-label">STANDARD MESSAGEPACK / TLS</p>
              <h2>独立 RPC 生命周期</h2>
            </div>
            <span
              class:active={metasploitStatus?.state === "ready"}
              class="risk-pill">{metasploitStatus?.state ?? "stopped"}</span
            >
          </div>
          {#if metasploitStatus?.state === "ready"}
            <div class="proxy-status-grid">
              <div>
                <span>Listener</span><code
                  >127.0.0.1:{metasploitStatus.listen_port}</code
                >
              </div>
              <div>
                <span>Framework</span><code
                  >{metasploitStatus.framework_version ?? "—"}</code
                >
              </div>
              <div>
                <span>TLS SHA-256</span><code
                  >{metasploitStatus.certificate_sha256}</code
                >
              </div>
              <div>
                <span>Supervisor</span><code>{metasploitStatus.supervisor}</code
                >
              </div>
              <div>
                <span>Workspace</span><code>{metasploitStatus.workspace}</code>
              </div>
              <div>
                <span>Sessions</span><code
                  >{metasploitStatus.active_sessions}</code
                >
              </div>
            </div>
            <label for="msf-stop-confirmation">活动 Session 终止确认</label>
            <input
              id="msf-stop-confirmation"
              bind:value={metasploitStopConfirmation}
              placeholder="TERMINATE ACTIVE SESSIONS"
              maxlength="64"
            />
            <button
              class="row-stop full"
              disabled={busy || status.active_project.read_only}
              onclick={() => void stopMetasploit()}
              >停止受管 RPC 生命周期</button
            >
          {:else}
            <button
              class="primary full"
              disabled={busy || status.active_project.read_only}
              onclick={() => void startMetasploit()}
              >启动动态 Loopback RPC</button
            >
          {/if}
          <p class="boundary-note">
            临时 256-bit+ 凭据 · TLS 生命周期 pin · Token 401 只读单次重放 ·
            执行请求零重放 · 输入 Scope 门禁 + 审计隔离等级
          </p>
        </section>

        {#if metasploitStatus?.state === "ready"}
          <section class="panel alpha-panel" data-testid="metasploit-modules">
            <div class="section-heading">
              <div>
                <p class="section-label">MODULE CATALOG</p>
                <h2>模块搜索与按需选项</h2>
              </div>
              <span class="count">{metasploitModules.length}</span>
            </div>
            <div class="inline-form">
              <input bind:value={metasploitQuery} maxlength="512" />
              <button
                disabled={busy}
                onclick={() => void searchMetasploitModules()}>搜索</button
              >
            </div>
            <div class="http-history-list">
              {#each metasploitModules as module}
                <button
                  class:selected={selectedMetasploitModule?.fullname ===
                    module.fullname}
                  onclick={() => void selectMetasploitModule(module)}
                >
                  <span class="kind-chip">{module.module_type}</span>
                  <strong>{module.fullname}</strong>
                  <small>{module.rank} · {module.name}</small>
                </button>
              {/each}
            </div>
          </section>

          {#if selectedMetasploitModule}
            <div class="http-work-grid">
              <section class="panel alpha-panel">
                <p class="section-label">STRUCTURED OPTIONS</p>
                <h2>{selectedMetasploitModule.fullname}</h2>
                <div class="data-list">
                  {#each metasploitOptions as option}
                    <article>
                      <div>
                        <strong>{option.name}</strong>
                        <small
                          >{option.option_type} · {option.required
                            ? "required"
                            : "optional"} · {option.description}</small
                        >
                      </div>
                      <code>{JSON.stringify(option.default)}</code>
                    </article>
                  {/each}
                </div>
              </section>
              <section
                class="panel alpha-panel"
                data-testid="metasploit-execute"
              >
                <p class="section-label">L3 CONFIRMATION</p>
                <h2>Scope 复核与执行</h2>
                <select bind:value={metasploitExecutionKind}>
                  <option value="check">check</option>
                  <option value="run">run</option>
                  <option value="exploit">exploit</option>
                </select>
                <label for="msf-options">结构化 Options JSON</label>
                <textarea
                  id="msf-options"
                  bind:value={metasploitOptionJson}
                  rows="10"
                  maxlength="1048576"></textarea>
                <label for="msf-confirmation">精确确认短语</label>
                <input
                  id="msf-confirmation"
                  bind:value={metasploitConfirmation}
                  maxlength="600"
                />
                <button
                  class="primary full"
                  disabled={busy ||
                    status.active_project.read_only ||
                    !selectedScopeId}
                  onclick={() => void executeMetasploitModule()}
                  >执行 Scope 与 L3 门禁</button
                >
              </section>
            </div>
          {/if}

          <div class="http-work-grid">
            <section class="panel alpha-panel" data-testid="metasploit-console">
              <p class="section-label">OWNED CONSOLE</p>
              <h2>Console 与敏感 Transcript</h2>
              <div class="inline-form">
                <input
                  bind:value={metasploitConsoleId}
                  placeholder="受管 Console ID"
                  maxlength="128"
                />
                <button
                  disabled={busy}
                  onclick={() => void createMetasploitConsole()}>新建</button
                >
              </div>
              <textarea
                bind:value={metasploitConsoleCommand}
                rows="4"
                maxlength="16384"></textarea>
              <button
                disabled={busy || !metasploitConsoleId}
                onclick={() => void runMetasploitConsoleCommand()}
                >确认并执行 Console 命令</button
              >
            </section>
            <section class="panel alpha-panel" data-testid="metasploit-session">
              <p class="section-label">OWNED SESSION / L3</p>
              <h2>Session 命令与退出固定</h2>
              <input
                bind:value={metasploitSessionId}
                placeholder="受管 Session ID"
                maxlength="128"
              />
              <textarea
                bind:value={metasploitSessionCommand}
                rows="4"
                maxlength="16384"></textarea>
              <button
                disabled={busy || !metasploitSessionId}
                onclick={() => void runMetasploitSessionCommand()}
                >确认并执行 Session 命令</button
              >
            </section>
          </div>

          <section class="panel alpha-panel">
            <div class="section-heading">
              <div>
                <p class="section-label">ADAPTER ENTITIES</p>
                <h2>Job · Console · Session · 证据</h2>
              </div>
              <span class="count">{metasploitEntities.length}</span>
            </div>
            {#if metasploitTranscript}<pre
                class="http-safe-preview">{metasploitTranscript}</pre>{/if}
            <label for="msf-entity-stop"
              >对象停止确认：STOP JOB/CONSOLE/SESSION &lt;id&gt;</label
            >
            <input
              id="msf-entity-stop"
              bind:value={metasploitEntityStopConfirmation}
              maxlength="256"
              placeholder="STOP SESSION 1"
            />
            <div class="data-list">
              {#each metasploitEntities as entity}
                <article>
                  <span class="status-dot" class:active={!entity.terminated_at}
                  ></span>
                  <div>
                    <strong>{entity.entity_kind} · {entity.external_id}</strong>
                    <small>{entity.redacted_view}</small>
                  </div>
                  <code>{entity.ownership}</code>
                  {#if ["job", "console", "session"].includes(entity.entity_kind) && !entity.terminated_at}
                    <button
                      class="row-stop"
                      disabled={busy || !metasploitEntityStopConfirmation}
                      onclick={() => void stopMetasploitEntity(entity)}
                      >停止</button
                    >
                  {/if}
                </article>
              {/each}
            </div>
          </section>
        {/if}
      {/if}

      {#if activeSection === "intruder"}
        <section class="panel alpha-panel" data-testid="intruder-config">
          <div class="section-heading">
            <div>
              <p class="section-label">
                SNIPER / RAM / PITCHFORK / CLUSTER BOMB
              </p>
              <h2>Intruder 攻击配置</h2>
            </div>
            <span class="count">{intruderCampaigns.length}</span>
          </div>
          {#if status?.active_project}
            <label for="intruder-parent">父 HttpMessage ID</label>
            <input
              id="intruder-parent"
              bind:value={intruderParentMessageId}
              maxlength="64"
              placeholder="00000000-0000-0000-0000-000000000000"
            />
            <label for="intruder-mode">攻击模式</label>
            <select id="intruder-mode" bind:value={intruderAttackMode}>
              {#each attackModes as mode}
                <option value={mode}>{mode}</option>
              {/each}
            </select>
            <label for="intruder-scope">TargetScope</label>
            <select id="intruder-scope" bind:value={selectedScopeId}>
              {#each scopes as scope}
                <option value={scope.scope_id}
                  >{scope.exact_hosts.join(",")}</option
                >
              {/each}
            </select>
            <fieldset
              class="state-macro-grid"
              data-testid="payload-position-selector"
            >
              <legend>Payload 位置选择器</legend>
              <label for="intruder-position-location">位置类型</label>
              <select
                id="intruder-position-location"
                bind:value={intruderPositionLocation}
              >
                {#each payloadLocations as location}
                  <option value={location}>{location}</option>
                {/each}
              </select>
              {#if intruderPositionLocation === "byte_range"}
                <div class="inline-form">
                  <label>
                    起始 byte
                    <input
                      type="number"
                      min="0"
                      max="16777215"
                      bind:value={intruderPositionStart}
                    />
                  </label>
                  <label>
                    结束 byte
                    <input
                      type="number"
                      min="1"
                      max="16777216"
                      bind:value={intruderPositionEnd}
                    />
                  </label>
                </div>
              {:else}
                <label for="intruder-position-name">字段或节点名称</label>
                <input
                  id="intruder-position-name"
                  bind:value={intruderPositionName}
                  maxlength="4096"
                  placeholder="q / Authorization / part"
                />
              {/if}
              <label for="intruder-position-occurrence">
                {intruderPositionLocation.startsWith("multipart_")
                  ? "Multipart part ordinal"
                  : "重复项 occurrence"}
              </label>
              <input
                id="intruder-position-occurrence"
                type="number"
                min="0"
                max="65535"
                bind:value={intruderPositionOccurrence}
              />
              <p class="macro-summary">
                Byte range 作用于 Body；Multipart 类型按解析后的 part ordinal
                定位并保留其他节点 bytes。
              </p>
            </fieldset>
            <label for="intruder-dicts">字典 ID（逗号分隔）</label>
            <input
              id="intruder-dicts"
              bind:value={intruderDictionaryIds}
              maxlength="1024"
            />
            <div class="inline-form">
              <input
                type="number"
                min="1"
                max="10000"
                bind:value={intruderGlobalRate}
                aria-label="全局速率"
              />
              <input
                type="number"
                min="1"
                max="10000"
                bind:value={intruderTargetRate}
                aria-label="单目标速率"
              />
            </div>
            <fieldset class="state-macro-grid">
              <legend>状态宏（Intruder 与上传共用）</legend>
              <label class="check-row">
                <input type="checkbox" bind:checked={stateMacroEnabled} />
                每次 Attempt 前刷新 Token
              </label>
              {#if stateMacroEnabled}
                <label for="macro-step">步骤名称</label>
                <input
                  id="macro-step"
                  bind:value={stateMacroStepName}
                  maxlength="256"
                />
                <label for="macro-message">Token 刷新 HttpMessage ID</label>
                <input
                  id="macro-message"
                  bind:value={stateMacroMessageId}
                  maxlength="64"
                />
                <label for="macro-variable">Token 变量名</label>
                <input
                  id="macro-variable"
                  bind:value={stateMacroVariable}
                  maxlength="64"
                />
                <label for="macro-source">来源</label>
                <select id="macro-source" bind:value={stateMacroSource}>
                  <option value="response_body">response_body</option>
                  <option value="response_header">response_header</option>
                </select>
                {#if stateMacroSource === "response_header"}
                  <label for="macro-header">Header 名称</label>
                  <input
                    id="macro-header"
                    bind:value={stateMacroHeaderName}
                    maxlength="256"
                  />
                {/if}
                <label for="macro-prefix">prefix</label>
                <input
                  id="macro-prefix"
                  bind:value={stateMacroPrefix}
                  maxlength="1024"
                />
                <label for="macro-suffix">suffix</label>
                <input
                  id="macro-suffix"
                  bind:value={stateMacroSuffix}
                  maxlength="1024"
                />
                <label for="macro-maximum">maximum_length</label>
                <input
                  id="macro-maximum"
                  type="number"
                  min="1"
                  max="4096"
                  bind:value={stateMacroMaximumLength}
                />
                <p class="macro-summary" data-testid="state-macro-summary">
                  1 步 · 变量 {stateMacroVariable} · {stateMacroSource}
                </p>
              {/if}
            </fieldset>
            <button
              class="primary full"
              disabled={busy ||
                status.active_project.read_only ||
                !selectedScopeId ||
                !intruderParentMessageId ||
                parsedDictionaryIds().length === 0 ||
                (intruderPositionLocation === "byte_range"
                  ? intruderPositionStart >= intruderPositionEnd
                  : intruderPositionName.length === 0)}
              onclick={() => void startIntruder()}
              >启动 Intruder Campaign</button
            >
          {:else}
            <p class="boundary-note">本地工作区正在初始化。</p>
          {/if}
          <p class="boundary-note">
            字典分页流式读取 · 全局/单目标令牌桶限速 · 范围外 parent
            在网络前拒绝
          </p>
        </section>

        <section class="panel alpha-panel" data-testid="upload-config">
          <div class="section-heading">
            <div>
              <p class="section-label">MULTIPART UPLOAD MUTATIONS</p>
              <h2>上传变异与验证</h2>
            </div>
          </div>
          {#if status?.active_project}
            <label for="upload-parent">父上传 HttpMessage ID</label>
            <input
              id="upload-parent"
              bind:value={uploadParentMessageId}
              maxlength="64"
            />
            <label for="upload-part">文件节点 ordinal</label>
            <input
              id="upload-part"
              type="number"
              min="0"
              bind:value={uploadPartOrdinal}
            />
            <fieldset class="mutation-grid">
              <legend>变异类别</legend>
              {#each uploadMutationKinds as kind}
                <label
                  ><input
                    type="checkbox"
                    checked={uploadMutations.includes(kind)}
                    onchange={() => toggleUploadMutation(kind)}
                  />{kind}</label
                >
              {/each}
            </fieldset>
            <label for="upload-verify">验证模式</label>
            <select id="upload-verify" bind:value={uploadVerificationMode}>
              <option value="none">none</option>
              <option value="safe_retrieval">safe_retrieval</option>
              <option value="execution">execution（L3）</option>
            </select>
            {#if uploadVerificationMode === "execution"}
              <label for="upload-execution-marker">期望执行输出 marker</label>
              <input
                id="upload-execution-marker"
                bind:value={uploadExpectedExecutionMarker}
                maxlength="256"
                placeholder="flagdeck-executed-<unique>"
              />
              <label for="upload-confirm">L3 精确确认短语</label>
              <input
                id="upload-confirm"
                bind:value={uploadConfirmation}
                maxlength="512"
                placeholder="VERIFY UPLOAD EXECUTION <message_id>"
              />
            {/if}
            <button
              class="primary full"
              disabled={busy ||
                status.active_project.read_only ||
                uploadMutations.length === 0 ||
                (uploadVerificationMode === "execution" &&
                  uploadExpectedExecutionMarker.length === 0)}
              onclick={() => void startUpload()}>启动上传变异 Campaign</button
            >
          {/if}
          <p class="boundary-note">
            变异保留字段顺序/重复键/原始 bytes · SafeRetrieval 内容哈希验证 ·
            Execution 精确确认 + 审计
          </p>
        </section>

        <section class="panel alpha-panel" data-testid="multipart-view">
          <div class="section-heading">
            <div>
              <p class="section-label">STRUCTURED MULTIPART</p>
              <h2>Multipart 结构化查看</h2>
            </div>
          </div>
          <div class="inline-form">
            <input
              bind:value={multipartMessageId}
              maxlength="64"
              placeholder="消息 ID"
            />
            <button
              class="primary"
              disabled={busy}
              onclick={() => void parseMultipart()}>解析</button
            >
          </div>
          {#if multipartDocument}
            <div class="proxy-status-grid">
              <div>
                <span>Boundary</span><code
                  >{decodeBytes(multipartDocument.boundary)}</code
                >
              </div>
              <div>
                <span>节点数</span><code>{multipartDocument.parts.length}</code>
              </div>
            </div>
            {#each multipartDocument.parts as part}
              <article class="entity-card">
                <div>
                  <span>#{part.ordinal}</span>
                  <code>name={decodeBytes(part.name)}</code>
                </div>
                <div>
                  <code>filename={decodeBytes(part.filename)}</code>
                  <code>content_type={decodeBytes(part.content_type)}</code>
                </div>
                <div><code>body_bytes={part.body.length}</code></div>
              </article>
            {/each}
          {/if}
        </section>

        <section class="panel alpha-panel" data-testid="intruder-campaigns">
          <div class="section-heading">
            <div>
              <p class="section-label">CAMPAIGNS</p>
              <h2>Campaign 状态与恢复</h2>
            </div>
            <button
              class="primary"
              disabled={busy}
              onclick={() => void refreshIntruderCampaigns()}>刷新</button
            >
          </div>
          {#each intruderCampaigns as campaign}
            <article class="entity-card">
              <div>
                <span
                  class="risk-pill"
                  class:active={campaign.state === "running"}
                  >{campaign.state}</span
                >
                <code>{campaign.campaign_kind}/{campaign.attack_mode}</code>
              </div>
              <div>
                <code
                  >ordinal {campaign.next_ordinal}/{campaign.total_attempts}</code
                >
                <code>ok {campaign.completed_attempts}</code>
                <code>fail {campaign.failed_attempts}</code>
              </div>
              <div class="inline-form">
                <button
                  class="row-stop"
                  disabled={busy}
                  onclick={() =>
                    void cancelCampaign(campaign.intruder_campaign_id)}
                  >取消</button
                >
                <button
                  class="primary"
                  disabled={busy}
                  onclick={() =>
                    void resumeCampaign(campaign.intruder_campaign_id)}
                  >恢复</button
                >
                <button
                  class="primary"
                  disabled={busy}
                  onclick={() =>
                    void loadIntruderAttempts(campaign.intruder_campaign_id)}
                  >Attempts</button
                >
              </div>
            </article>
          {/each}
          {#if selectedCampaignId}
            <div class="section-heading">
              <div>
                <p class="section-label">ATTEMPTS</p>
                <h2>Attempt 分页结果</h2>
              </div>
              <span class="count">{intruderAttempts.length}</span>
            </div>
            {#each intruderAttempts as attempt}
              <article class="entity-card">
                <div>
                  <code>#{attempt.ordinal}</code>
                  <span
                    class="risk-pill"
                    class:active={attempt.state === "succeeded"}
                    >{attempt.state}</span
                  >
                  <code>status {attempt.response_status ?? "—"}</code>
                  <code>len {attempt.response_length ?? "—"}</code>
                </div>
                <div>
                  <code
                    >{toSafeTextPreview(
                      attempt.verification_summary ??
                        attempt.error_summary ??
                        "",
                    )}</code
                  >
                </div>
                <div>
                  <code
                    >payload {toSafeTextPreview(
                      attempt.payload_preview.join(" "),
                    )}</code
                  >
                </div>
              </article>
            {/each}
          {/if}
        </section>
      {/if}

      {#if activeSection === "recon"}
        <div class="tool-workbench" data-testid="tool-runner">
          <section class="panel tool-catalog">
            <div class="section-heading">
              <div>
                <p class="section-label">AVAILABLE TOOLS</p>
                <h2>已安装工具</h2>
              </div>
              <span class="count"
                >{tools.filter((tool) => tool.healthy)
                  .length}/{tools.length}</span
              >
            </div>
            <div class="tool-library" aria-label="CLI 工具">
              {#each tools as tool}
                <button
                  class:selected={tool.tool === selectedTool}
                  class:unavailable={!tool.healthy}
                  disabled={!tool.healthy}
                  onclick={() => selectTool(tool.tool)}
                >
                  <span class="tool-avatar"
                    >{tool.name.slice(0, 2).toUpperCase()}</span
                  >
                  <span class="tool-copy">
                    <strong>{tool.name}</strong>
                    <small>{tool.summary}</small>
                  </span>
                  <span class:ready={tool.healthy} class="tool-state"></span>
                </button>
              {/each}
            </div>
            <div class="pack-summary">
              {#each toolPacks as pack}
                <div>
                  <span class:ready={pack.state === "ready"} class="tool-state"
                  ></span>
                  <span>
                    <strong>{pack.name}</strong>
                    <small
                      >{pack.tools_ready}/{pack.tools_total} ready · {pack.version}</small
                    >
                  </span>
                </div>
              {/each}
            </div>
          </section>

          <section class="panel tool-run-config">
            <div class="tool-run-header">
              <div>
                <span class="selected-tool-icon"
                  >{(
                    tools.find((tool) => tool.tool === selectedTool)?.name ??
                    selectedTool
                  )
                    .slice(0, 2)
                    .toUpperCase()}</span
                >
                <div>
                  <p class="section-label">RUN TOOL</p>
                  <h2>
                    {tools.find((tool) => tool.tool === selectedTool)?.name ??
                      selectedTool}
                  </h2>
                  <small
                    >{tools.find((tool) => tool.tool === selectedTool)
                      ?.summary}</small
                  >
                </div>
              </div>
              <span class="risk-pill"
                >{tools.find((tool) => tool.tool === selectedTool)
                  ?.risk_level ?? "—"}</span
              >
            </div>
            <div class="run-form">
              <label for="run-target">目标 URL</label>
              <input
                id="run-target"
                data-testid="run-target"
                bind:value={targetUrl}
                maxlength="4096"
                placeholder="https://target.example/"
              />
              <p class="field-help">首次运行会自动记录目标范围。</p>
              {#if selectedTool === "ffuf" || selectedTool === "arjun" || selectedTool === "gobuster"}
                <label for="wordlist">字典内容</label>
                <textarea
                  id="wordlist"
                  bind:value={wordlistText}
                  rows="7"
                  maxlength="32768"></textarea>
                <p class="field-help">每行一项，内容只保存在本机。</p>
              {/if}
            </div>
            <div class="run-footer">
              <div class="tool-runtime">
                <span class="tool-state ready"></span>
                <span>
                  <strong>运行环境就绪</strong>
                  <small
                    >{tools.find((tool) => tool.tool === selectedTool)
                      ?.resolution_source ?? "missing"}</small
                  >
                </span>
              </div>
              <button
                class="primary run-button"
                data-testid="run-tool"
                disabled={busy ||
                  status.active_project.read_only ||
                  !targetUrl ||
                  !tools.find((tool) => tool.tool === selectedTool)?.healthy}
                onclick={() => void runSelectedTool()}>运行工具</button
              >
            </div>
          </section>
        </div>
      {/if}

      {#if activeSection === "recon" || activeSection === "jobs"}
        <section class="panel alpha-panel" data-testid="job-list">
          <div class="section-heading">
            <div>
              <p class="section-label">RECENT ACTIVITY</p>
              <h2>最近运行</h2>
            </div>
            <span class="count">{jobs.length}</span>
          </div>
          <div class="data-list">
            {#each jobs as item}
              <article>
                <span
                  class:active={jobIsActive(item)}
                  class:failed={!jobIsActive(item) &&
                    item.job.execution_status !== "succeeded"}
                  class="status-dot"
                ></span>
                <div>
                  <strong
                    >{item.tool_id} · {item.job.execution_status} / {item.job
                      .import_status}</strong
                  >
                  <small
                    >{item.job.job_id} · {item.job.supervisor_backend ??
                      "pending"}</small
                  >
                </div>
                <em>{item.discovery_count} discoveries</em>
                <code>{item.parser_version ?? "—"}</code>
                <div class="job-actions">
                  <button
                    class="row-log"
                    onclick={() => void selectJobLog(item)}>日志</button
                  >
                  {#if jobIsActive(item)}
                    <button
                      class="row-stop"
                      disabled={busy || status.active_project.read_only}
                      onclick={() => void cancelJob(item)}>停止</button
                    >
                  {/if}
                </div>
              </article>
              <p class="command-preview">{item.command_preview}</p>
              {#if item.parser_error}<p class="row-error">
                  {item.parser_error}
                </p>{/if}
            {/each}
            {#if jobs.length === 0}<div class="empty compact">
                运行工具后，任务和日志会显示在这里。
              </div>{/if}
          </div>
          {#if selectedLogJobId}
            <div class="live-log" data-testid="job-live-log">
              <div class="live-log-heading">
                <div>
                  <strong>任务日志</strong>
                  <code>{selectedLogJobId}</code>
                </div>
                <div class="live-log-actions">
                  <button
                    class:active={selectedLogStream === "stdout"}
                    onclick={() => void selectJobLogStream("stdout")}
                    >stdout</button
                  >
                  <button
                    class:active={selectedLogStream === "stderr"}
                    onclick={() => void selectJobLogStream("stderr")}
                    >stderr</button
                  >
                  <button onclick={() => void loadJobLog(true)}>刷新</button>
                  <button onclick={() => (selectedLogJobId = "")}>关闭</button>
                </div>
              </div>
              <pre>{toSafeTextPreview(jobLogContent) || "等待日志输出…"}</pre>
              <small>{jobLogOffset} bytes · {jobLogEof ? "EOF" : "LIVE"}</small>
            </div>
          {/if}
        </section>
      {/if}

      {#if activeSection === "adapters"}
        <section class="panel alpha-panel" data-testid="external-launchers">
          <div class="section-heading">
            <div>
              <p class="section-label">GUI / SPECIAL CLIENT COMPATIBILITY</p>
              <h2>独立客户端兼容入口</h2>
            </div>
            <span class="count"
              >{externalLaunchers.filter((item) => item.healthy)
                .length}/{externalLaunchers.length}</span
            >
          </div>
          <div class="tool-grid">
            <div>
              <label for="external-launcher">启动器</label>
              <select
                id="external-launcher"
                bind:value={selectedExternalLauncher}
                onchange={() => (externalConfirmation = "")}
              >
                {#each externalLaunchers as launcher}
                  <option value={launcher.launcher}
                    >{launcher.name} · {launcher.healthy
                      ? "ready"
                      : "blocked"}</option
                  >
                {/each}
              </select>
            </div>
            <div>
              <label for="external-target">TargetScope 内目标 URL</label>
              <input
                id="external-target"
                bind:value={externalTargetUrl}
                maxlength="4096"
              />
            </div>
          </div>
          <label for="external-confirmation">L3 精确确认短语</label>
          <input
            id="external-confirmation"
            bind:value={externalConfirmation}
            maxlength="256"
            placeholder={externalConfirmationPhrase()}
          />
          <div class="command-policy">
            <span>工具包或用户路径 + SHA-256</span>
            <span>TargetScope 输入门禁</span>
            <span>允许/拒绝审计</span>
            <span>独立 HOME / TMPDIR</span>
          </div>
          <button
            class="primary full"
            data-testid="launch-external"
            disabled={busy ||
              status.active_project.read_only ||
              !selectedScopeId ||
              !externalTargetUrl ||
              !externalLaunchers.find(
                (item) => item.launcher === selectedExternalLauncher,
              )?.healthy}
            onclick={() => void launchSelectedExternal()}
            >启动 {selectedExternalLauncher}</button
          >
        </section>
      {/if}

      {#if activeSection === "discovery" || activeSection === "recon"}
        <section class="panel alpha-panel" data-testid="discovery-list">
          <div class="section-heading">
            <div>
              <p class="section-label">DEDUPLICATED RESULTS</p>
              <h2>统一 Discovery</h2>
            </div>
            <span class="count">{discoveries.length}</span>
          </div>
          <div class="data-list discovery-rows">
            {#each discoveries as discovery}
              <article>
                <span class="kind-chip">{discovery.kind}</span>
                <div>
                  <strong>{discovery.canonical_value}</strong>
                  <small>raw: {discovery.raw_value}</small>
                </div>
                <em>{discovery.status}</em>
              </article>
            {/each}
            {#if discoveries.length === 0}<div class="empty compact">
                运行工具后显示统一结果。
              </div>{/if}
          </div>
          <div class="inline-form">
            <button
              class="primary quiet"
              disabled={busy || discoveryPageNumber === 1}
              onclick={() => void loadLatestDiscoveries()}>回到最新</button
            >
            <button
              class="primary quiet"
              disabled={busy || !discoveryNextCursor}
              onclick={() => void loadNextDiscoveries()}>下一页</button
            >
            <code>page {discoveryPageNumber} · 100 rows max</code>
          </div>
        </section>
      {/if}

      {#if activeSection === "discovery" || activeSection === "settings"}
        <section class="panel alpha-panel" data-testid="dictionary-panel">
          <div class="section-heading">
            <div>
              <p class="section-label">INDEXED INPUT</p>
              <h2>本地字典</h2>
            </div>
            <span class="count">{dictionaries.length}</span>
          </div>
          <div class="dictionary-grid">
            <fieldset disabled={busy || status.active_project.read_only}>
              <label for="dictionary-name">字典名称</label>
              <input
                id="dictionary-name"
                bind:value={dictionaryName}
                maxlength="256"
              />
              <label for="dictionary-content">每行一项</label>
              <textarea
                id="dictionary-content"
                bind:value={dictionaryContent}
                maxlength="1048576"
                rows="7"></textarea>
              <button
                class="primary full"
                disabled={!dictionaryName || !dictionaryContent}
                onclick={() => void createDictionary()}>归档并索引</button
              >
            </fieldset>
            <div class="dictionary-browser">
              <label for="dictionary-select">已索引字典</label>
              <select
                id="dictionary-select"
                bind:value={selectedDictionaryId}
                onchange={() => (dictionaryMatches = [])}
              >
                <option value="">选择字典</option>
                {#each dictionaries as dictionary}
                  <option value={dictionary.dictionary_id}
                    >{dictionary.name} · {dictionary.term_count}</option
                  >
                {/each}
              </select>
              <label for="dictionary-prefix">前缀查询</label>
              <div class="inline-form">
                <input
                  id="dictionary-prefix"
                  bind:value={dictionaryPrefix}
                  maxlength="512"
                />
                <button
                  disabled={busy || !selectedDictionaryId}
                  onclick={() => void searchDictionary()}>查询</button
                >
              </div>
              <div class="dictionary-matches">
                {#each dictionaryMatches as term}<code>{term}</code>{/each}
                {#if dictionaryMatches.length === 0}
                  <span>查询结果将在此显示。</span>
                {/if}
              </div>
            </div>
          </div>
        </section>
      {/if}

      {#if activeSection === "payloads" || activeSection === "intruder"}
        <section class="panel alpha-panel" data-testid="payload-browser">
          <div class="section-heading">
            <div>
              <p class="section-label">BOUNDED LOCAL PAYLOAD INDEX</p>
              <h2>Payload TXT / YAML / JSON 浏览器</h2>
            </div>
            <span class="count">{payloadEntries.length}</span>
          </div>
          <div class="tool-grid">
            <div>
              <label for="payload-source">来源</label>
              <select
                id="payload-source"
                bind:value={selectedPayloadSource}
                onchange={() => {
                  payloadEntries = [];
                  payloadCursor = null;
                  selectedPayload = null;
                  payloadPreview = null;
                }}
              >
                {#each payloadSources as source}
                  <option value={source.source_id} disabled={!source.healthy}
                    >{source.name} · {source.healthy
                      ? "ready"
                      : "blocked"}</option
                  >
                {/each}
              </select>
            </div>
            <div>
              <label for="payload-query">路径或标签查询</label>
              <input
                id="payload-query"
                bind:value={payloadQuery}
                maxlength="512"
                placeholder="xss / sql / upload"
              />
            </div>
          </div>
          <button
            class="primary full"
            disabled={busy || !selectedPayloadSource}
            onclick={() => void searchPayloads(false)}>查询 Payload</button
          >
          <div class="data-list">
            {#each payloadEntries as entry}
              <button
                class:selected={selectedPayload?.payload_id ===
                  entry.payload_id}
                onclick={() => void selectPayload(entry)}
              >
                <span class="kind-chip">{entry.format}</span>
                <span>
                  <strong>{safeDisplayFilename(entry.display_path)}</strong>
                  <small>{entry.source_name} · {entry.size} B</small>
                </span>
                <em>{entry.risk_level}</em>
              </button>
            {/each}
            {#if payloadEntries.length === 0}
              <div class="empty compact">选择健康来源并执行查询。</div>
            {/if}
          </div>
          {#if payloadCursor}
            <button
              class="primary quiet"
              disabled={busy}
              onclick={() => void searchPayloads(true)}>加载下一页</button
            >
          {/if}
          {#if payloadPreview && selectedPayload}
            <div class="preview-meta">
              <span>{payloadPreview.format}</span>
              <span>{payloadPreview.total_size} B</span>
              <span>{payloadPreview.truncated ? "PARTIAL" : "EOF"}</span>
            </div>
            <code>{payloadPreview.sha256}</code>
            <pre data-testid="payload-preview">{toSafeTextPreview(
                payloadPreview.content,
              )}</pre>
          {/if}
          <p class="boundary-note">
            来源目录、owner、权限、深度与条目数由 Rust Core 复核；预览上限 64
            KiB，符号链接跳过。
          </p>
        </section>
      {/if}

      {#if activeSection === "health" || activeSection === "adapters"}
        <section class="panel alpha-panel" data-testid="tool-health">
          <div class="section-heading">
            <div>
              <p class="section-label">TOOL PACK STATUS</p>
              <h2>工具包、运行时与解析器</h2>
            </div>
            <span class="count"
              >{tools.filter((tool) => tool.healthy)
                .length}/{tools.length}</span
            >
          </div>
          <div class="health-grid">
            {#each tools as tool}
              <article class:unhealthy={!tool.healthy}>
                <div>
                  <strong>{tool.name}</strong><span>{tool.version}</span>
                </div>
                <small>{tool.path}</small>
                <code>{tool.sha256.slice(0, 20)}…</code>
                <p>
                  {tool.health_strategy} · {tool.parser_id}/{tool.parser_version}
                </p>
                <p>
                  {tool.pack_name}
                  {tool.pack_version} · {tool.resolution_source} ·
                  {tool.adapter_type}
                </p>
                <p>
                  {tool.capabilities.join(", ")} ·
                  {Math.round(tool.memory_max_bytes / 1048576)} MiB / {tool.tasks_max}
                  tasks
                </p>
                <p>{tool.detail}</p>
              </article>
            {/each}
            {#each externalLaunchers as launcher}
              <article class:unhealthy={!launcher.healthy}>
                <div>
                  <strong>{launcher.name}</strong><span>{launcher.version}</span
                  >
                </div>
                <small>{launcher.program}</small>
                <code>{launcher.program_sha256.slice(0, 20)}…</code>
                <p>{launcher.summary}</p>
                <p>
                  {launcher.pack_name}
                  {launcher.pack_version} ·
                  {launcher.integration_mode} · {launcher.resolution_source}
                </p>
                <p>{launcher.capability} · {launcher.risk_level}</p>
                <p>
                  {launcher.adapter_type} · {launcher.network_policy} ·
                  {Math.round(launcher.memory_max_bytes / 1048576)} MiB / {launcher.tasks_max}
                  tasks
                </p>
                <p>{launcher.detail}</p>
              </article>
            {/each}
          </div>
        </section>
      {/if}

      {#if activeSection === "evidence"}
        <div class="content-grid">
          <section class="panel note-panel">
            <div class="section-heading">
              <div>
                <p class="section-label">ATOMIC ARTIFACT</p>
                <h2>新建证据笔记</h2>
              </div>
              <button
                class="fixture-button"
                disabled={busy || status.active_project.read_only}
                onclick={loadSecurityFixture}>载入安全 fixture</button
              >
            </div>
            <fieldset disabled={busy || status.active_project.read_only}>
              <label for="note-name">逻辑名称</label>
              <input
                id="note-name"
                data-testid="note-name"
                bind:value={noteName}
                maxlength="256"
              />
              <label for="note-sensitivity">敏感级别</label>
              <select id="note-sensitivity" bind:value={noteSensitivity}>
                <option value="normal">普通</option>
                <option value="sensitive_evidence">敏感证据</option>
                <option value="credential">凭据（持久化会被 Core 拒绝）</option>
              </select>
              <label for="note-content">内容</label>
              <textarea
                id="note-content"
                data-testid="note-content"
                bind:value={noteContent}
                maxlength="1048576"
                rows="9"></textarea>
              <button
                class="primary full"
                data-testid="create-note"
                onclick={() => void createNote()}
                disabled={!noteContent}>提交 Artifact</button
              >
            </fieldset>
          </section>

          <section class="panel artifact-panel">
            <div class="section-heading">
              <div>
                <p class="section-label">CONTENT ADDRESSED</p>
                <h2>证据与笔记</h2>
              </div>
              <span class="count">{artifacts.length}</span>
            </div>
            <div class="artifact-list" data-testid="artifact-list">
              {#each artifacts as artifact}
                <button
                  class:selected={selectedArtifact?.artifact_id ===
                    artifact.artifact_id}
                  onclick={() => void selectArtifact(artifact)}
                >
                  <span class="file-icon">TXT</span>
                  <span>
                    <strong>{safeDisplayFilename(artifact.logical_name)}</strong
                    >
                    <small
                      >{artifact.sha256?.slice(0, 16) ?? "staging"} · {artifact.size ??
                        0} B</small
                    >
                  </span>
                  <em>{artifact.sensitivity}</em>
                </button>
              {/each}
              {#if artifacts.length === 0}<div class="empty compact">
                  暂无 Artifact。
                </div>{/if}
            </div>
          </section>
        </div>

        {#if preview && selectedArtifact}
          <section class="panel preview-panel" data-testid="preview-panel">
            <div class="section-heading">
              <div>
                <p class="section-label">DATA-ONLY PREVIEW</p>
                <h2>{safeDisplayFilename(selectedArtifact.logical_name)}</h2>
              </div>
              <div class="preview-meta">
                <span>{preview.bytes_returned} B</span>
                <span>{preview.redacted ? "REDACTED" : "RAW"}</span>
                <span>{preview.eof ? "EOF" : "PARTIAL"}</span>
              </div>
            </div>
            <pre data-testid="artifact-preview">{toSafeTextPreview(
                preview.content,
              )}</pre>
          </section>
        {/if}
      {/if}
    {/if}
  </main>
</div>
