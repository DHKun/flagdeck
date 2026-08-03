<script lang="ts">
  import { onMount, tick } from "svelte";
  import {
    ArrowDown,
    ArrowUp,
    CircleHelp,
    Eye,
    EyeOff,
    House,
    LibraryBig,
    ListChecks,
    Pin,
    PinOff,
    Search,
    Settings,
    X,
  } from "@lucide/svelte";

  import type {
    Artifact,
    TargetScope,
    ToolIoKind,
  } from "./generated/contracts";
  import type {
    AppStatus,
    CatalogDiagnosticStatus,
    CatalogFormFieldDto,
    CatalogRunPreview,
    CatalogSnapshot,
    CatalogToolDiagnosticDto,
    CatalogToolDto,
    ExportJobArtifactResult,
    JobLogStream,
    JobView,
    StructuredResultPage,
    WordlistDto,
  } from "./generated/ipc";
  import { commandErrorMessage, ipc } from "./lib/ipc";
  import {
    applyJobLogPage,
    jobLogRangeLabel,
    mergeJobHistoryPage,
    type JobLogWindow,
  } from "./lib/jobHistory";
  import {
    exportStructuredRowsTsv,
    filterStructuredRows,
    sortStructuredRows,
    type ResultSortDir,
  } from "./lib/structuredResults";
  import {
    listCompatibleSendToTargets,
    prefillSendToForm,
    sendToTargetUrl,
    type CompatibleTarget,
    type SendToSource,
  } from "./lib/sendTo";
  import {
    loadWorkbenchPrefs,
    rememberTool,
    saveWorkbenchPrefs,
    type WorkbenchPrefs,
  } from "./lib/workbenchPrefs";
  import {
    executionStatusLabel,
    exportPolicyLabel,
    logStreamLabel,
    riskLevelLabel,
    sensitivityLabel,
    structuredResultKindLabel,
  } from "./lib/uiLabels";
  import {
    capabilityLabel,
    searchTools,
    type InstallationFilter,
  } from "./lib/toolSearch";
  import { buildProgressiveForm } from "./lib/progressiveForm";
  import {
    arrangeToolFields,
    evaluateRelations,
    filterToolFields,
    recommendedOptionValues,
    searchHelpText,
    splitMultiValue,
    toggleMultiValue,
    type FieldLayout,
  } from "./lib/guidedTool";
  import {
    buildRunPlan,
    reconcileTargetUrl,
    resolveRunTarget,
    toolHasHostField,
  } from "./lib/runPlanning";
  import { computeToolDefaults, pickInitialTool } from "./lib/toolSelection";
  import {
    nextLogOffset,
    shouldFallbackToStderr,
    shouldReplaceJobCursor,
  } from "./lib/jobView";
  import {
    createPersonalPreset,
    deletePersonalPreset,
    emptyPersonalPresetStore,
    exportPersonalPresets,
    findPersonalPreset,
    importPersonalPresets,
    personalPresetsForTool,
    resolvePresetBaseId,
    isPresetValidForTool,
    renamePersonalPreset,
    resolveDefaultPresetId,
    setDefaultPersonalPreset,
    updatePersonalPreset,
    type PersonalPresetStore,
  } from "./lib/personalPresets";

  type NavId = "home" | "tools" | "jobs" | "settings";
  type OutputTab = "log" | "result" | "evidence";
  type DiagnosticCacheEntry = {
    diagnostic: CatalogToolDiagnosticDto;
    checkedAt: number;
  };

  const DIAGNOSTIC_TTL_MS = 30_000;
  const JOB_POLL_INTERVAL_MS = 1_000;
  const LOG_APPEND_BYTES = 32_768;
  const LOG_PAGE_BYTES = 65_536;
  const PREFS_PERSIST_DELAY_MS = 300;

  type Scenario = {
    id: string;
    title: string;
    summary: string;
    toolIds: string[];
    category?: string;
  };

  const navItems: Array<{ id: NavId; label: string }> = [
    { id: "home", label: "工作台" },
    { id: "tools", label: "工具库" },
    { id: "jobs", label: "任务" },
    { id: "settings", label: "设置" },
  ];

  const scenarios: Scenario[] = [
    {
      id: "dirscan",
      title: "目录扫描",
      summary: "用字典探测路径与隐藏入口",
      toolIds: ["ffuf", "gobuster"],
      category: "content_discovery",
    },
    {
      id: "fingerprint",
      title: "资产指纹",
      summary: "主机发现与服务识别",
      toolIds: ["dddd", "fscan"],
      category: "fingerprint",
    },
    {
      id: "http",
      title: "HTTP 探活",
      summary: "快速请求与响应检查",
      toolIds: ["curl", "arjun"],
      category: "http",
    },
    {
      id: "gui",
      title: "独立应用",
      summary: "一键启动 GUI 客户端",
      toolIds: ["shiro", "antsword", "behinder", "godzilla", "uploadranger"],
      category: "gui",
    },
  ];

  let prefs: WorkbenchPrefs = loadWorkbenchPrefs();
  let status: AppStatus | null = null;
  let catalog: CatalogSnapshot | null = null;
  let jobs: JobView[] = [];
  let scopes: TargetScope[] = [];
  let activeNav: NavId = "home";
  let targetUrl = prefs.targetUrl;
  let selectedToolId = prefs.selectedToolId;
  let formValues: Record<string, string> = {};
  let busy = false;
  let notice = "";
  let noticeKind: "info" | "success" | "error" = "info";
  let selectedLogJobId = "";
  let selectedLogStream: JobLogStream = "stdout";
  let jobLogWindow: JobLogWindow | null = null;
  let jobLogLoading = false;
  let jobNextCursor: string | null = null;
  let jobHistoryLoading = false;
  let jobArtifacts: Artifact[] = [];
  let jobEvidenceNotice = "";
  let lastJobExport: ExportJobArtifactResult | null = null;
  let evidenceLoadedForJobId = "";
  let resultLoadedForJobId = "";
  let pollTimer: ReturnType<typeof setTimeout> | undefined;
  let prefsPersistTimer: ReturnType<typeof setTimeout> | undefined;
  let toolQuery = "";
  let categoryFilter = "";
  let capabilityFilter = "";
  let tierFilter = "";
  let installationFilter: InstallationFilter = "";
  let selectedPresetId = "";
  let personalPresetStore: PersonalPresetStore = emptyPersonalPresetStore();
  let personalPresetStoreLoaded = false;
  let presetTransferOpen = false;
  let presetTransferText = "";
  let advancedFieldsExpanded = false;
  let parameterQuery = "";
  let helpQuery = "";
  let helpOpen = false;
  let showHiddenFields = false;
  let toolDiagnostic: CatalogToolDiagnosticDto | null = null;
  let diagnosticBusy = false;
  let diagnosticUpdatedAt = "";
  const diagnosticCache = new Map<string, DiagnosticCacheEntry>();
  let runPreview: CatalogRunPreview | null = null;
  let runPreviewError = "";
  let runPreviewTimer: ReturnType<typeof setTimeout> | undefined;
  let jobFilterToolId = prefs.jobFilterToolId;
  let autoScrollLog = prefs.autoScrollLog;
  let outputTab: OutputTab = "log";
  let structuredResult: StructuredResultPage | null = null;
  let resultFilter = "";
  let resultSortKey = "status";
  let resultSortDir: ResultSortDir = "asc";
  let sendToSource: SendToSource | null = null;
  let sendToTargets: CompatibleTarget[] = [];
  let pendingSendTo: {
    sourceJobId: string;
    sourceResultId: string;
    sourceArtifactId: string | null;
  } | null = null;
  let logPaneEl: HTMLPreElement | null = null;

  $: selectedTool =
    catalog?.tools.find((tool) => tool.id === selectedToolId) ?? null;
  $: selectedPersonalPreset = findPersonalPreset(
    personalPresetStore,
    selectedPresetId,
  );
  $: selectedFormPresetId =
    selectedTool && selectedPersonalPreset
      ? selectedTool.presets.some(
          (preset) => preset.id === selectedPersonalPreset?.base_preset_id,
        )
        ? selectedPersonalPreset.base_preset_id
        : (selectedTool.presets[0]?.id ?? "")
      : selectedPresetId;
  $: progressiveForm = selectedTool
    ? buildProgressiveForm(
        selectedTool,
        selectedFormPresetId,
        advancedFieldsExpanded,
      )
    : null;
  $: selectedFieldLayout = selectedTool
    ? prefs.fieldLayoutByTool[selectedTool.id]
    : undefined;
  $: progressiveFields = selectedTool
    ? (progressiveForm?.visibleFields ?? selectedTool.fields)
    : [];
  $: parameterSourceFields = selectedTool
    ? parameterQuery.trim()
      ? selectedTool.fields
      : [
          ...progressiveFields,
          ...selectedTool.fields.filter(
            (field) =>
              selectedFieldLayout?.pinned.includes(field.id) &&
              !progressiveFields.some((visible) => visible.id === field.id),
          ),
        ]
    : [];
  $: visibleToolFields = arrangeToolFields(
    filterToolFields(parameterSourceFields, parameterQuery),
    selectedFieldLayout,
    showHiddenFields || Boolean(parameterQuery.trim()),
  );
  $: relationNotices = evaluateRelations(selectedTool, formValues);
  $: relationErrors = relationNotices.filter(
    (item) => item.severity === "error",
  );
  $: relationWarnings = relationNotices.filter(
    (item) => item.severity === "warning",
  );
  $: helpSearchResult = searchHelpText(
    toolDiagnostic?.help.content ?? "",
    helpQuery,
  );
  $: selectedToolPersonalPresets = selectedTool
    ? personalPresetsForTool(personalPresetStore, selectedTool.id)
    : [];
  $: availableTools = (catalog?.tools ?? []).filter((tool) => tool.available);
  $: featuredTools = availableTools.filter((tool) => tool.featured);
  $: recentTools = prefs.recentToolIds
    .map((id) => catalog?.tools.find((tool) => tool.id === id))
    .filter((tool): tool is CatalogToolDto => Boolean(tool));
  $: catalogTools = catalog?.tools ?? [];
  $: filteredTools = searchTools(catalogTools, {
    query: toolQuery,
    category: categoryFilter,
    capability: capabilityFilter,
    tier: tierFilter,
    installation: installationFilter,
  });
  $: toolsByCategory = filteredTools.reduce((grouped, tool) => {
    const items = grouped.get(tool.category) ?? [];
    items.push(tool);
    grouped.set(tool.category, items);
    return grouped;
  }, new Map<string, CatalogToolDto[]>());
  $: capabilityOptions = [
    ...new Set(catalogTools.flatMap((tool) => tool.capabilities)),
  ].sort();
  $: tierOptions = [...new Set(catalogTools.map((tool) => tool.tier))].sort();
  $: categories = catalog?.categories ?? [];
  $: wordlists = (catalog?.wordlists ?? []).filter((item) => item.available);
  $: activeJobCount = jobs.filter(jobIsActive).length;
  $: filteredJobs = jobFilterToolId
    ? jobs.filter((item) => item.tool_id === jobFilterToolId)
    : jobs;
  $: jobToolOptions = [...new Set(jobs.map((item) => item.tool_id))].sort();
  $: jobLogContent = jobLogWindow?.content ?? "";
  $: jobLogRange = jobLogRangeLabel(jobLogWindow);
  $: resultRows = structuredResult
    ? sortStructuredRows(
        filterStructuredRows(structuredResult.rows, resultFilter),
        resultSortKey,
        resultSortDir,
      )
    : [];
  $: resultColumns = structuredResult?.columns ?? [];

  function updatePrefsContext(): void {
    prefs = {
      ...prefs,
      targetUrl,
      selectedToolId,
      jobFilterToolId,
      autoScrollLog,
    };
  }

  function persistPrefs(): void {
    updatePrefsContext();
    saveWorkbenchPrefs(prefs);
  }

  function schedulePrefsPersist(): void {
    updatePrefsContext();
    if (prefsPersistTimer) clearTimeout(prefsPersistTimer);
    prefsPersistTimer = setTimeout(() => {
      prefsPersistTimer = undefined;
      saveWorkbenchPrefs(prefs);
    }, PREFS_PERSIST_DELAY_MS);
  }

  function jobIsActive(item: JobView): boolean {
    return ["queued", "starting", "running", "stopping"].includes(
      item.job.execution_status,
    );
  }

  function reportError(error: unknown): void {
    notice = commandErrorMessage(error);
    noticeKind = "error";
  }

  function reportLocalError(error: unknown): void {
    const ipcMessage = commandErrorMessage(error);
    notice =
      error instanceof Error && error.message.length <= 256
        ? error.message
        : ipcMessage === "Operation failed (ipc_error)"
          ? "个人预设操作失败"
          : ipcMessage;
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

  function applyToolDefaults(tool: CatalogToolDto): void {
    formValues = computeToolDefaults(
      tool,
      prefs.formByTool[tool.id] ?? {},
      targetUrl,
    );
  }

  function applyToolPreset(tool: CatalogToolDto, presetId: string): void {
    selectedPresetId = presetId;
    advancedFieldsExpanded = false;
    const personal = findPersonalPreset(personalPresetStore, presetId);
    const basePresetId = resolvePresetBaseId(tool, presetId, personal);
    const plan = buildProgressiveForm(tool, basePresetId, false);
    formValues = {
      ...formValues,
      ...plan.presetDefaults,
      ...(personal?.values ?? {}),
    };
    scheduleRunPreview();
  }

  async function persistPersonalPresetStore(
    next: PersonalPresetStore,
  ): Promise<void> {
    personalPresetStore = await ipc.savePersonalPresets({ store: next });
  }

  async function createCurrentPersonalPreset(): Promise<void> {
    if (!selectedTool) return;
    const name = window.prompt("个人预设名称", `${selectedTool.name} 个人预设`);
    if (name === null) return;
    busy = true;
    try {
      const personal = findPersonalPreset(
        personalPresetStore,
        selectedPresetId,
      );
      const basePresetId =
        personal?.base_preset_id ||
        selectedTool.presets.find((preset) => preset.id === selectedPresetId)
          ?.id ||
        selectedTool.presets[0]?.id ||
        "";
      const next = createPersonalPreset(personalPresetStore, selectedTool, {
        name,
        basePresetId,
        values: formValues,
      });
      await persistPersonalPresetStore(next);
      const created = next.presets.at(-1);
      if (created) applyToolPreset(selectedTool, created.id);
      notice = "已保存个人预设";
      noticeKind = "success";
    } catch (error) {
      reportLocalError(error);
    } finally {
      busy = false;
    }
  }

  async function updateCurrentPersonalPreset(): Promise<void> {
    if (!selectedTool || !selectedPersonalPreset) return;
    busy = true;
    try {
      const next = updatePersonalPreset(
        personalPresetStore,
        selectedTool,
        selectedPersonalPreset.id,
        formValues,
      );
      await persistPersonalPresetStore(next);
      notice = "已更新个人预设";
      noticeKind = "success";
    } catch (error) {
      reportLocalError(error);
    } finally {
      busy = false;
    }
  }

  async function renameCurrentPersonalPreset(): Promise<void> {
    if (!selectedPersonalPreset) return;
    const name = window.prompt("新的预设名称", selectedPersonalPreset.name);
    if (name === null) return;
    busy = true;
    try {
      const next = renamePersonalPreset(
        personalPresetStore,
        selectedPersonalPreset.id,
        name,
      );
      await persistPersonalPresetStore(next);
      notice = "已重命名个人预设";
      noticeKind = "success";
    } catch (error) {
      reportLocalError(error);
    } finally {
      busy = false;
    }
  }

  async function deleteCurrentPersonalPreset(): Promise<void> {
    if (!selectedTool || !selectedPersonalPreset) return;
    if (!window.confirm(`删除个人预设“${selectedPersonalPreset.name}”？`))
      return;
    busy = true;
    try {
      const next = deletePersonalPreset(
        personalPresetStore,
        selectedPersonalPreset.id,
      );
      await persistPersonalPresetStore(next);
      applyToolPreset(
        selectedTool,
        resolveDefaultPresetId(personalPresetStore, selectedTool),
      );
      notice = "已删除个人预设";
      noticeKind = "success";
    } catch (error) {
      reportLocalError(error);
    } finally {
      busy = false;
    }
  }

  async function setCurrentPersonalPresetAsDefault(): Promise<void> {
    if (!selectedTool || !selectedPersonalPreset) return;
    busy = true;
    try {
      const next = setDefaultPersonalPreset(
        personalPresetStore,
        selectedTool.id,
        selectedPersonalPreset.id,
      );
      await persistPersonalPresetStore(next);
      notice = "已设为当前工具的默认个人预设";
      noticeKind = "success";
    } catch (error) {
      reportLocalError(error);
    } finally {
      busy = false;
    }
  }

  function openPresetExport(): void {
    if (!catalog) return;
    try {
      presetTransferText = exportPersonalPresets(
        personalPresetStore,
        catalog.tools,
      );
      presetTransferOpen = true;
    } catch (error) {
      reportLocalError(error);
    }
  }

  async function importPresetPackage(): Promise<void> {
    if (!catalog) return;
    busy = true;
    try {
      const next = importPersonalPresets(presetTransferText, catalog.tools);
      await persistPersonalPresetStore(next);
      presetTransferOpen = false;
      if (selectedTool) {
        applyToolPreset(
          selectedTool,
          resolveDefaultPresetId(personalPresetStore, selectedTool),
        );
      }
      notice = "已导入个人预设";
      noticeKind = "success";
    } catch (error) {
      reportLocalError(error);
    } finally {
      busy = false;
    }
  }

  function advancedGroupName(fieldId: string): string {
    const group = progressiveForm?.advancedGroups.find(
      (item) => item.fields[0]?.id === fieldId,
    );
    return group?.name ?? "";
  }

  function fieldUsesFullRow(field: CatalogFormFieldDto): boolean {
    return (
      ["url", "wordlist", "textarea", "multiselect", "args"].includes(
        field.field_type,
      ) || ["headers", "request_file"].includes(field.id)
    );
  }

  function currentFieldLayout(): FieldLayout {
    return selectedTool
      ? (prefs.fieldLayoutByTool[selectedTool.id] ?? {
          pinned: [],
          hidden: [],
          order: selectedTool.fields.map((field) => field.id),
        })
      : { pinned: [], hidden: [], order: [] };
  }

  function saveFieldLayout(layout: FieldLayout): void {
    if (!selectedTool) return;
    prefs = {
      ...prefs,
      fieldLayoutByTool: {
        ...prefs.fieldLayoutByTool,
        [selectedTool.id]: layout,
      },
    };
    persistPrefs();
  }

  function toggleFieldPin(fieldId: string): void {
    const layout = currentFieldLayout();
    const pinned = layout.pinned.includes(fieldId)
      ? layout.pinned.filter((id) => id !== fieldId)
      : [...layout.pinned, fieldId];
    saveFieldLayout({ ...layout, pinned });
  }

  function toggleFieldHidden(fieldId: string): void {
    const layout = currentFieldLayout();
    const hidden = layout.hidden.includes(fieldId)
      ? layout.hidden.filter((id) => id !== fieldId)
      : [...layout.hidden, fieldId];
    saveFieldLayout({ ...layout, hidden });
  }

  function moveField(fieldId: string, direction: -1 | 1): void {
    const layout = currentFieldLayout();
    const order = selectedTool?.fields.map((field) => field.id) ?? [];
    order.sort((left, right) => {
      const leftIndex = layout.order.indexOf(left);
      const rightIndex = layout.order.indexOf(right);
      return (
        (leftIndex < 0 ? Number.MAX_SAFE_INTEGER : leftIndex) -
        (rightIndex < 0 ? Number.MAX_SAFE_INTEGER : rightIndex)
      );
    });
    const index = order.indexOf(fieldId);
    const target = index + direction;
    if (index < 0 || target < 0 || target >= order.length) return;
    [order[index], order[target]] = [order[target], order[index]];
    saveFieldLayout({ ...layout, order });
  }

  function optionLabel(fieldId: string, value: string): string {
    const field = selectedTool?.fields.find((item) => item.id === fieldId);
    const detail = field?.option_details.find((item) => item.value === value);
    return detail?.label || value || "自动";
  }

  function updateMultiValue(
    fieldId: string,
    option: string,
    enabled: boolean,
  ): void {
    formValues[fieldId] = toggleMultiValue(
      formValues[fieldId] ?? "",
      option,
      enabled,
    );
    if (selectedToolId) rememberFormForTool(selectedToolId);
    scheduleRunPreview();
  }

  function rememberFormForTool(toolId: string, deferred = false): void {
    const tool = catalog?.tools.find((item) => item.id === toolId);
    const persistedValues = Object.fromEntries(
      Object.entries(formValues).filter(
        ([fieldId]) =>
          !tool?.fields.find((field) => field.id === fieldId)?.sensitive,
      ),
    );
    prefs = {
      ...prefs,
      formByTool: {
        ...prefs.formByTool,
        [toolId]: persistedValues,
      },
      recentToolIds: rememberTool(prefs, toolId),
    };
    if (deferred) schedulePrefsPersist();
    else persistPrefs();
  }

  function selectTool(tool: CatalogToolDto): void {
    if (selectedToolId && selectedToolId !== tool.id) {
      rememberFormForTool(selectedToolId);
    }
    selectedToolId = tool.id;
    applyToolDefaults(tool);
    applyToolPreset(tool, resolveDefaultPresetId(personalPresetStore, tool));
    prefs = {
      ...prefs,
      selectedToolId: tool.id,
      recentToolIds: rememberTool(prefs, tool.id),
    };
    persistPrefs();
    if (activeNav === "home") activeNav = "tools";
    toolDiagnostic = null;
    diagnosticUpdatedAt = "";
    parameterQuery = "";
    helpQuery = "";
    helpOpen = false;
    showHiddenFields = false;
    void loadToolDiagnostic(tool.id, false);
  }

  async function loadToolDiagnostic(
    toolId: string,
    announce: boolean,
  ): Promise<void> {
    const cached = diagnosticCache.get(toolId);
    if (
      !announce &&
      cached &&
      Date.now() - cached.checkedAt < DIAGNOSTIC_TTL_MS
    ) {
      if (selectedToolId === toolId) {
        toolDiagnostic = cached.diagnostic;
        diagnosticUpdatedAt = new Date(cached.checkedAt).toLocaleTimeString(
          "zh-CN",
          { hour12: false },
        );
      }
      return;
    }
    diagnosticBusy = true;
    try {
      const diagnostic = await ipc.diagnoseCatalogTool({
        tool_id: toolId,
        refresh_help: announce,
      });
      const checkedAt = Date.now();
      diagnosticCache.set(toolId, { diagnostic, checkedAt });
      if (selectedToolId !== toolId) return;
      toolDiagnostic = diagnostic;
      diagnosticUpdatedAt = new Date(checkedAt).toLocaleTimeString("zh-CN", {
        hour12: false,
      });
      if (announce) {
        const nextCatalog = await ipc.listCatalog();
        if (selectedToolId !== toolId) return;
        catalog = nextCatalog;
        notice =
          diagnostic.status === "usable"
            ? "环境诊断已更新，工具可用"
            : "环境诊断已更新，请按检查项修复";
        noticeKind = diagnostic.status === "usable" ? "success" : "info";
      }
    } catch (error) {
      if (selectedToolId === toolId) reportError(error);
    } finally {
      if (selectedToolId === toolId) diagnosticBusy = false;
    }
  }

  function openScenario(scenario: Scenario): void {
    const pick =
      scenario.toolIds
        .map((id) => catalog?.tools.find((tool) => tool.id === id))
        .find((tool) => tool?.available) ??
      scenario.toolIds
        .map((id) => catalog?.tools.find((tool) => tool.id === id))
        .find(Boolean) ??
      (scenario.category
        ? catalog?.tools.find(
            (tool) => tool.category === scenario.category && tool.available,
          )
        : undefined);
    if (pick) {
      selectTool(pick);
      activeNav = "tools";
      if (scenario.category) categoryFilter = scenario.category;
      notice = `已打开场景：${scenario.title} → ${pick.name}`;
      noticeKind = "info";
    } else {
      notice = `场景「${scenario.title}」暂无可用工具`;
      noticeKind = "error";
    }
  }

  async function refresh(): Promise<void> {
    await ensureToolboxWorkspace();
    const projectId = status?.active_project?.project_id;
    const [nextCatalog, nextJobs, nextScopes, nextPersonalPresets] =
      await Promise.all([
        ipc.listCatalog(),
        projectId
          ? ipc.listJobs({ project_id: projectId, cursor: null, limit: 50 })
          : Promise.resolve({ items: [], next_cursor: null }),
        projectId
          ? ipc.listScopes({ project_id: projectId })
          : Promise.resolve({ items: [] }),
        personalPresetStoreLoaded
          ? Promise.resolve(personalPresetStore)
          : ipc.loadPersonalPresets(),
      ]);
    catalog = nextCatalog;
    if (!personalPresetStoreLoaded) {
      personalPresetStore = importPersonalPresets(
        JSON.stringify(nextPersonalPresets),
        catalog.tools,
      );
      personalPresetStoreLoaded = true;
    }
    jobs = nextJobs.items;
    jobNextCursor = nextJobs.next_cursor;
    scopes = nextScopes.items;

    if (!selectedToolId) {
      const preferred = pickInitialTool(catalog.tools, prefs.selectedToolId);
      if (preferred) selectTool(preferred);
    } else if (selectedTool) {
      if (Object.keys(formValues).length === 0) {
        applyToolDefaults(selectedTool);
      } else {
        for (const field of selectedTool.fields) {
          if (!formValues[field.id] && field.default_value) {
            formValues = { ...formValues, [field.id]: field.default_value };
          }
        }
      }
      if (
        !isPresetValidForTool(
          personalPresetStore,
          selectedTool,
          selectedPresetId,
        )
      ) {
        applyToolPreset(
          selectedTool,
          resolveDefaultPresetId(personalPresetStore, selectedTool),
        );
      }
    }
    if (selectedToolId && !diagnosticBusy) {
      await loadToolDiagnostic(selectedToolId, false);
    }
  }

  async function loadJobLog(options: {
    mode: "reset" | "append" | "page";
    offset?: number;
  }): Promise<void> {
    if (!status?.active_project || !selectedLogJobId || jobLogLoading) return;
    jobLogLoading = true;
    try {
      const offset = nextLogOffset(options.mode, options.offset, jobLogWindow);
      const preview = await ipc.previewJobLog({
        project_id: status.active_project.project_id,
        job_id: selectedLogJobId,
        stream: selectedLogStream,
        offset,
        limit: options.mode === "append" ? LOG_APPEND_BYTES : LOG_PAGE_BYTES,
      });

      // Empty stdout on a finished job: surface stderr so failures stay visible.
      if (
        shouldFallbackToStderr(
          options.mode,
          selectedLogStream,
          preview.content,
          preview.eof,
        )
      ) {
        const err = await ipc.previewJobLog({
          project_id: status.active_project.project_id,
          job_id: selectedLogJobId,
          stream: "stderr",
          offset: 0,
          limit: 65536,
        });
        if (err.content.trim().length > 0) {
          selectedLogStream = "stderr";
          jobLogWindow = applyJobLogPage({
            previous: null,
            content: err.content,
            offset: 0,
            nextOffset: err.next_offset,
            eof: err.eof,
          });
          return;
        }
      }

      const nextWindow = applyJobLogPage({
        previous: options.mode === "append" ? jobLogWindow : null,
        content: preview.content,
        offset,
        nextOffset: preview.next_offset,
        eof: preview.eof,
      });
      const logChanged =
        !jobLogWindow ||
        jobLogWindow.content !== nextWindow.content ||
        jobLogWindow.nextOffset !== nextWindow.nextOffset ||
        jobLogWindow.eof !== nextWindow.eof;
      if (!logChanged) return;
      jobLogWindow = nextWindow;
      if (
        autoScrollLog &&
        (options.mode === "append" || options.mode === "reset")
      ) {
        await tick();
        if (logPaneEl) logPaneEl.scrollTop = logPaneEl.scrollHeight;
      }
    } finally {
      jobLogLoading = false;
    }
  }

  async function loadMoreJobs(): Promise<void> {
    if (!status?.active_project || !jobNextCursor || jobHistoryLoading) return;
    jobHistoryLoading = true;
    try {
      const page = await ipc.listJobs({
        project_id: status.active_project.project_id,
        cursor: jobNextCursor,
        limit: 50,
      });
      jobs = mergeJobHistoryPage({
        loaded: jobs,
        page: page.items,
        mode: "append",
      });
      jobNextCursor = page.next_cursor;
    } catch (error) {
      reportError(error);
    } finally {
      jobHistoryLoading = false;
    }
  }

  async function loadJobEvidence(force = false): Promise<void> {
    if (!status?.active_project || !selectedLogJobId) return;
    const jobId = selectedLogJobId;
    if (!force && evidenceLoadedForJobId === jobId) return;
    jobArtifacts = [];
    jobEvidenceNotice = "";
    lastJobExport = null;
    try {
      const page = await ipc.listJobArtifacts({
        project_id: status.active_project.project_id,
        job_id: jobId,
        cursor: null,
        limit: 100,
      });
      if (selectedLogJobId !== jobId) return;
      jobArtifacts = page.items;
      evidenceLoadedForJobId = jobId;
    } catch (error) {
      reportError(error);
    }
  }

  async function exportJobEvidence(artifact: Artifact): Promise<void> {
    if (!status?.active_project || !selectedLogJobId) return;
    const needsConfirm = artifact.export_policy === "confirm_sensitive";
    if (
      needsConfirm &&
      !window.confirm(
        `导出敏感证据「${artifact.logical_name}」？大小 ${artifact.size ?? "?"} 字节，SHA-256 ${artifact.sha256 ?? "?"}。`,
      )
    ) {
      return;
    }
    busy = true;
    try {
      const result = await ipc.exportJobArtifact({
        project_id: status.active_project.project_id,
        job_id: selectedLogJobId,
        artifact_id: artifact.artifact_id,
        confirm_sensitive: needsConfirm,
      });
      lastJobExport = result;
      jobEvidenceNotice = `已导出 ${result.export_name} · ${result.size} 字节 · ${result.sha256.slice(0, 12)}…`;
      notice = jobEvidenceNotice;
      noticeKind = "success";
    } catch (error) {
      reportError(error);
    } finally {
      busy = false;
    }
  }

  async function previewJobEvidence(artifact: Artifact): Promise<void> {
    if (!status?.active_project) return;
    try {
      const preview = await ipc.previewArtifact({
        project_id: status.active_project.project_id,
        artifact_id: artifact.artifact_id,
        offset: 0,
        limit: 4096,
        mode: "text",
      });
      jobEvidenceNotice = `预览 ${artifact.logical_name}（${preview.bytes_returned} 字节${preview.eof ? " · eof" : ""}）\n${preview.content}`;
    } catch (error) {
      reportError(error);
    }
  }

  async function loadJobResult(force = false): Promise<void> {
    if (!status?.active_project || !selectedLogJobId) return;
    const jobId = selectedLogJobId;
    if (!force && resultLoadedForJobId === jobId) return;
    structuredResult = null;
    try {
      const result = await ipc.listStructuredResults({
        project_id: status.active_project.project_id,
        job_id: jobId,
        cursor: null,
        limit: 500,
      });
      if (selectedLogJobId !== jobId) return;
      structuredResult = result;
      resultLoadedForJobId = jobId;
    } catch (error) {
      reportError(error);
    }
  }

  function selectedJob(): JobView | null {
    return jobs.find((item) => item.job.job_id === selectedLogJobId) ?? null;
  }

  async function copyJobLog(): Promise<void> {
    if (!jobLogContent) return;
    try {
      await navigator.clipboard.writeText(jobLogContent);
      notice = "日志已复制";
      noticeKind = "success";
    } catch {
      notice = "复制失败（浏览器/桌面权限限制）";
      noticeKind = "error";
    }
  }

  async function copyResultTsv(): Promise<void> {
    if (!structuredResult || resultRows.length === 0) return;
    try {
      await navigator.clipboard.writeText(
        exportStructuredRowsTsv(resultColumns, resultRows),
      );
      notice = `已复制 ${resultRows.length} 行结果`;
      noticeKind = "success";
    } catch {
      notice = "复制失败";
      noticeKind = "error";
    }
  }

  function jumpToSourceArtifact(artifactId: string | null | undefined): void {
    if (!artifactId) return;
    outputTab = "evidence";
    void loadJobEvidence();
    notice = `已定位原始证据 ${artifactId}`;
    noticeKind = "info";
  }

  function openSendTo(row: {
    result_id: string;
    cells: Record<string, string>;
    source_job_id: string;
    source_artifact_id: string | null;
  }): void {
    if (!catalog) return;
    const source: SendToSource = {
      resultKind: structuredResult?.kind ?? "unknown",
      cells: row.cells,
      sourceJobId: row.source_job_id,
      sourceResultId: row.result_id,
      sourceArtifactId: row.source_artifact_id,
    };
    const targets = listCompatibleSendToTargets(catalog.tools, source);
    if (targets.length === 0) {
      notice = "没有接受 URL 输入的可用兼容工具";
      noticeKind = "error";
      return;
    }
    sendToSource = source;
    sendToTargets = targets;
  }

  function cancelSendTo(): void {
    sendToSource = null;
    sendToTargets = [];
  }

  function applySendTo(target: CompatibleTarget): void {
    if (!sendToSource) return;
    const url = sendToTargetUrl(sendToSource);
    const tool = target.tool;
    selectTool(tool);
    const presetId = resolveDefaultPresetId(personalPresetStore, tool);
    applyToolPreset(tool, presetId);
    formValues = prefillSendToForm({
      tool,
      baseValues: { ...formValues },
      sourceUrl: url,
      urlFieldIds: target.urlFieldIds,
    });
    targetUrl = url;
    pendingSendTo = {
      sourceJobId: sendToSource.sourceJobId,
      sourceResultId: sendToSource.sourceResultId,
      sourceArtifactId: sendToSource.sourceArtifactId,
    };
    sendToSource = null;
    sendToTargets = [];
    activeNav = "tools";
    persistPrefs();
    scheduleRunPreview();
    notice = `已发送到 ${tool.name}，仅填充 URL 字段；请确认 Scope 与风险后运行`;
    noticeKind = "info";
  }

  function jobStatusLabel(item: JobView | null): string {
    if (!item) return "未选择任务";
    const reason = item.job.exit_reason ? ` · ${item.job.exit_reason}` : "";
    return `${item.tool_id} · ${executionStatusLabel(item.job.execution_status)}${reason}`;
  }

  async function selectJobLog(item: JobView): Promise<void> {
    if (selectedLogJobId !== item.job.job_id) {
      selectedLogJobId = item.job.job_id;
      selectedLogStream = "stdout";
      jobLogWindow = null;
      structuredResult = null;
      jobArtifacts = [];
      resultLoadedForJobId = "";
      evidenceLoadedForJobId = "";
      lastJobExport = null;
      jobEvidenceNotice = "";
      outputTab = "log";
    }
    await loadJobLog({ mode: "reset" });
    await Promise.all([loadJobResult(), loadJobEvidence()]);
  }

  function scheduleJobPoll(): void {
    if (pollTimer || !jobs.some(jobIsActive)) return;
    pollTimer = setTimeout(() => {
      pollTimer = undefined;
      void pollJobs();
    }, JOB_POLL_INTERVAL_MS);
  }

  async function pollJobs(): Promise<void> {
    try {
      if (!status?.active_project) return;
      const previous = selectedJob();
      const page = await ipc.listJobs({
        project_id: status.active_project.project_id,
        cursor: null,
        limit: 50,
      });
      jobs = mergeJobHistoryPage({
        loaded: jobs,
        page: page.items,
        mode: "refresh",
      });
      // Keep next_cursor from deeper pages; only replace when history is still the first page.
      if (
        shouldReplaceJobCursor(jobNextCursor, jobs.length, page.items.length)
      ) {
        jobNextCursor = page.next_cursor;
      }
      const current = selectedJob();
      if (current && jobIsActive(current)) {
        await loadJobLog({ mode: "append" });
      } else if (
        previous &&
        current &&
        previous.job.job_id === current.job.job_id &&
        jobIsActive(previous)
      ) {
        await loadJobLog({ mode: "reset" });
        await loadJobResult(true);
        await loadJobEvidence(true);
      }
    } catch (error) {
      reportError(error);
    }
    scheduleJobPoll();
  }

  function contextTargetForRun(): string {
    return resolveRunTarget(selectedTool, formValues, targetUrl);
  }

  function scheduleRunPreview(): void {
    if (runPreviewTimer) clearTimeout(runPreviewTimer);
    runPreview = null;
    runPreviewError = "";
    runPreviewTimer = setTimeout(() => {
      void refreshRunPreview();
    }, 250);
  }

  async function refreshRunPreview(): Promise<void> {
    if (!status?.active_project || !selectedTool) return;
    try {
      runPreview = await ipc.previewCatalogTool({
        project_id: status.active_project.project_id,
        tool_id: selectedTool.id,
        target_url: contextTargetForRun(),
        form: { ...formValues },
      });
    } catch (error) {
      runPreview = null;
      runPreviewError = commandErrorMessage(error);
    }
  }

  async function runSelectedTool(): Promise<void> {
    if (!status?.active_project || !selectedTool) return;
    if (!selectedTool.available) {
      notice = selectedTool.detail
        ? `${selectedTool.name} 当前不可用：${selectedTool.detail}`
        : `${selectedTool.name} 当前不可用，请查看运行环境诊断`;
      noticeKind = "error";
      await loadToolDiagnostic(selectedTool.id, false);
      return;
    }
    if (relationErrors.length > 0) {
      notice = relationErrors.map((item) => item.message).join("；");
      noticeKind = "error";
      return;
    }
    if (
      relationWarnings.length > 0 &&
      !window.confirm(
        `参数提示：\n${relationWarnings.map((item) => `• ${item.message}`).join("\n")}\n\n确认继续？`,
      )
    ) {
      return;
    }
    const contextTarget = contextTargetForRun();
    if (selectedTool.needs_target && !contextTarget) {
      notice = "请先填写目标（URL / 主机）";
      noticeKind = "error";
      return;
    }
    const plan = buildRunPlan(selectedTool, formValues, runPreview?.risk_level);
    let confirmL2 = false;
    let l3Confirmation: string | null = null;
    if (plan.tier === "l2") {
      if (!window.confirm("确认运行此 L2 工具？")) return;
      confirmL2 = true;
    } else if (plan.tier === "l3") {
      l3Confirmation = plan.l3Phrase;
    }
    await guarded(async () => {
      if (contextTarget) {
        const reconciled = reconcileTargetUrl(
          contextTarget,
          targetUrl,
          toolHasHostField(selectedTool!),
        );
        targetUrl = reconciled.targetUrl;
        persistPrefs();
        await ipc.ensureTarget({
          project_id: status!.active_project!.project_id,
          base_url: reconciled.ensureBaseUrl,
        });
      }
      rememberFormForTool(selectedTool!.id);
      const job = await ipc.runCatalogTool({
        project_id: status!.active_project!.project_id,
        tool_id: selectedTool!.id,
        target_url: contextTarget,
        form: { ...formValues },
        confirm_sensitive_argv: plan.hasSensitiveArgv,
        confirm_l2: confirmL2,
        l3_confirmation: l3Confirmation,
        source_job_id: pendingSendTo?.sourceJobId ?? null,
        source_result_id: pendingSendTo?.sourceResultId ?? null,
        source_artifact_id: pendingSendTo?.sourceArtifactId ?? null,
      });
      pendingSendTo = null;
      selectedLogJobId = job.job.job_id;
      selectedLogStream = "stdout";
      jobLogWindow = null;
      structuredResult = null;
      jobArtifacts = [];
      resultLoadedForJobId = "";
      evidenceLoadedForJobId = "";
      lastJobExport = null;
      jobEvidenceNotice = "";
      outputTab = "log";
      await refresh();
      await loadJobLog({ mode: "reset" });
      const current = selectedJob();
      if (current && !jobIsActive(current)) {
        await Promise.all([loadJobResult(true), loadJobEvidence(true)]);
      }
      scheduleJobPoll();
      activeNav = "tools";
    }, `${selectedTool.name} 已开始运行`);
  }

  async function cancelSelectedJob(): Promise<void> {
    if (!status?.active_project || !selectedLogJobId) return;
    await guarded(async () => {
      await ipc.cancelJob({
        project_id: status!.active_project!.project_id,
        job_id: selectedLogJobId,
      });
      await refresh();
      await loadJobLog({ mode: "reset" });
    }, "已请求取消任务");
  }

  async function deleteJobById(jobId: string): Promise<void> {
    if (!status?.active_project) return;
    await guarded(async () => {
      await ipc.deleteJob({
        project_id: status!.active_project!.project_id,
        job_id: jobId,
      });
      if (selectedLogJobId === jobId) {
        selectedLogJobId = "";
        jobLogWindow = null;
        structuredResult = null;
        jobArtifacts = [];
        resultLoadedForJobId = "";
        evidenceLoadedForJobId = "";
        lastJobExport = null;
        jobEvidenceNotice = "";
      }
      await refresh();
      if (!selectedLogJobId && jobs.length > 0) {
        await selectJobLog(jobs[0]);
      }
    }, "任务已删除");
  }

  async function clearAllJobs(): Promise<void> {
    if (!status?.active_project) return;
    if (jobs.some(jobIsActive)) {
      notice = "仍有任务在运行，请先取消或等待结束后再清空";
      noticeKind = "error";
      return;
    }
    await guarded(async () => {
      const result = await ipc.clearJobs({
        project_id: status!.active_project!.project_id,
      });
      selectedLogJobId = "";
      jobLogWindow = null;
      structuredResult = null;
      jobArtifacts = [];
      resultLoadedForJobId = "";
      evidenceLoadedForJobId = "";
      lastJobExport = null;
      jobEvidenceNotice = "";
      await refresh();
      notice = `已清空 ${result.deleted} 个任务`;
    }, "任务列表已清空");
  }

  function toolsInCategory(categoryId: string): CatalogToolDto[] {
    return toolsByCategory.get(categoryId) ?? [];
  }

  function wordlistLabel(item: WordlistDto): string {
    return item.available ? item.name : `${item.name}（不可用）`;
  }

  function jobTabLabel(item: JobView): string {
    return `${item.tool_id} · ${executionStatusLabel(item.job.execution_status)}`;
  }

  function toolUsage(tool: CatalogToolDto | null | undefined): string {
    if (!tool) return "";
    return (tool.usage || tool.summary || "").trim();
  }

  function tierLabel(tier: string): string {
    const match = /^tier_(\d+)$/.exec(tier);
    return match ? `Tier ${match[1]}` : tier;
  }

  function diagnosticStatusLabel(status: CatalogDiagnosticStatus): string {
    return (
      {
        usable: "可用",
        missing: "缺失",
        version_abnormal: "版本异常",
        path_abnormal: "路径异常",
        permission_abnormal: "权限异常",
      } satisfies Record<CatalogDiagnosticStatus, string>
    )[status];
  }

  async function copyDiagnosticValue(value: string): Promise<void> {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      notice = "修复内容已复制";
      noticeKind = "success";
    } catch {
      window.prompt("复制修复内容", value);
    }
  }

  function installationSummary(tool: CatalogToolDto): string {
    return [
      tool.installation.distribution,
      tool.installation.license,
      tool.installation.version,
    ]
      .filter(Boolean)
      .join(" · ");
  }

  const ioKindLabels: Record<ToolIoKind, string> = {
    url: "URL",
    wordlist: "字典",
    http_discovery: "HTTP 发现",
    raw_artifact: "原始文件",
  };

  function ioKindList(items: Array<{ kind: ToolIoKind }>): string {
    return items.map((item) => ioKindLabels[item.kind]).join("、");
  }

  onMount(() => {
    const refreshDiagnosticOnFocus = () => {
      if (selectedToolId && !diagnosticBusy) {
        void loadToolDiagnostic(selectedToolId, false);
      }
    };
    window.addEventListener("focus", refreshDiagnosticOnFocus);
    void guarded(async () => {
      await refresh();
      scheduleJobPoll();
    }, "工作台已就绪");
    return () => {
      if (pollTimer) clearTimeout(pollTimer);
      if (runPreviewTimer) clearTimeout(runPreviewTimer);
      if (prefsPersistTimer) {
        clearTimeout(prefsPersistTimer);
        prefsPersistTimer = undefined;
        persistPrefs();
      }
      window.removeEventListener("focus", refreshDiagnosticOnFocus);
    };
  });
</script>

<svelte:head>
  <title>FlagDeck</title>
</svelte:head>

<div class="shell">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark">F</div>
      <div>
        <strong>FlagDeck</strong>
        <small>本地工具工作台</small>
      </div>
    </div>

    <nav class="nav" aria-label="主导航">
      {#each navItems as item}
        <button
          data-testid={`nav-${item.id}`}
          class:active={activeNav === item.id}
          aria-current={activeNav === item.id ? "page" : undefined}
          type="button"
          onclick={() => (activeNav = item.id)}
        >
          <span class="nav-icon" aria-hidden="true">
            {#if item.id === "home"}
              <House size={18} />
            {:else if item.id === "tools"}
              <LibraryBig size={18} />
            {:else if item.id === "jobs"}
              <ListChecks size={18} />
            {:else}
              <Settings size={18} />
            {/if}
          </span>
          {item.label}
        </button>
      {/each}
    </nav>

    <div class="sidebar-foot">
      {#if catalog}
        工具根目录<br />
        <code
          style="font-size: 11px; word-break: break-all"
          data-testid="catalog-root">{catalog.tools_root}</code
        >
      {:else}
        正在加载工具目录…
      {/if}
    </div>
  </aside>

  <div class="main">
    <header class="topbar">
      {#if !selectedTool || selectedTool.needs_target}
        <div class="target-field">
          <label for="target-url">目标</label>
          <input
            id="target-url"
            bind:value={targetUrl}
            oninput={() => schedulePrefsPersist()}
            placeholder="https://example.com 或 192.168.1.1"
            spellcheck="false"
          />
        </div>
      {:else}
        <div class="target-field">
          <label for="target-url">上下文</label>
          <input
            id="target-url"
            value="当前工具无需目标 URL"
            disabled
            spellcheck="false"
          />
        </div>
      {/if}
      <div class="top-meta">
        <span>{availableTools.length} 可用工具</span>
        <span>{activeJobCount} 运行中</span>
      </div>
    </header>

    <div class="content">
      <div
        data-testid="notice"
        class:show={notice.length > 0}
        class:success={noticeKind === "success"}
        class:error={noticeKind === "error"}
        class="notice"
        role={noticeKind === "error" ? "alert" : "status"}
        aria-live={noticeKind === "error" ? "assertive" : "polite"}
        aria-atomic="true"
      >
        {notice}
      </div>

      {#if !status?.active_project}
        <section class="card">
          <h2>正在准备本地工作区</h2>
          <p class="sub">任务、日志与结果会自动保存在应用数据目录。</p>
        </section>
      {:else if activeNav === "home"}
        <div class="page-header">
          <h1>工作台</h1>
          <p>输入目标，选择工具，点运行。无需手写命令。</p>
        </div>

        <div class="section-label">场景</div>
        <div class="scenario-grid">
          {#each scenarios as scenario}
            <button
              class="scenario-card"
              type="button"
              onclick={() => openScenario(scenario)}
            >
              <strong>{scenario.title}</strong>
              <small>{scenario.summary}</small>
            </button>
          {/each}
        </div>

        <div class="hero">
          <section class="card">
            <div class="card-head">
              <div>
                <h2>快速开始</h2>
                <p class="sub">目标会在工具之间记忆；切换工具时自动回填。</p>
              </div>
              <span class="pill">推荐</span>
            </div>
            <div class="field">
              <label for="home-url">目标 URL</label>
              <input
                id="home-url"
                bind:value={targetUrl}
                oninput={() => schedulePrefsPersist()}
              />
            </div>
            <div class="actions">
              <button
                class="btn btn-primary"
                type="button"
                disabled={busy || !selectedTool?.available}
                onclick={() => void runSelectedTool()}
              >
                运行 {selectedTool?.name ?? "工具"}
              </button>
              <button
                class="btn btn-secondary"
                type="button"
                onclick={() => (activeNav = "tools")}
              >
                浏览全部工具
              </button>
            </div>
          </section>

          <section class="card">
            <div class="card-head">
              <div>
                <h2>最近任务</h2>
                <p class="sub">点击可查看日志输出。</p>
              </div>
            </div>
            {#if jobs.length === 0}
              <div class="empty">还没有任务。运行一个工具即可开始。</div>
            {:else}
              <div class="job-list">
                {#each jobs.slice(0, 5) as item}
                  <button
                    class="job-item"
                    class:selected={selectedLogJobId === item.job.job_id}
                    type="button"
                    onclick={() => {
                      activeNav = "jobs";
                      void selectJobLog(item);
                    }}
                  >
                    <strong>{item.tool_id}</strong>
                    <small
                      >{executionStatusLabel(item.job.execution_status)} · {item.command_preview.slice(
                        0,
                        80,
                      )}</small
                    >
                  </button>
                {/each}
              </div>
            {/if}
          </section>
        </div>

        {#if recentTools.length > 0}
          <div class="section-label">最近使用</div>
          <div class="tool-grid">
            {#each recentTools.slice(0, 6) as tool}
              <div
                class="tool-card"
                class:selected={tool.id === selectedToolId}
                class:disabled={!tool.available}
              >
                <button
                  data-testid={`home-recent-tool-${tool.id}`}
                  class="tool-card-main"
                  type="button"
                  disabled={!tool.available}
                  onclick={() => selectTool(tool)}
                >
                  <div class="tool-card-title">
                    <strong>{tool.name}</strong>
                  </div>
                  <small>{tool.summary}</small>
                </button>
              </div>
            {/each}
          </div>
        {/if}

        <div class="section-label">精选工具</div>
        <div class="tool-grid">
          {#each featuredTools as tool}
            <div
              class="tool-card"
              class:selected={tool.id === selectedToolId}
              class:disabled={!tool.available}
            >
              <button
                data-testid={`home-featured-tool-${tool.id}`}
                class="tool-card-main"
                type="button"
                disabled={!tool.available}
                onclick={() => selectTool(tool)}
              >
                <div class="tool-card-title">
                  <strong>{tool.name}</strong>
                </div>
                <small>{tool.summary}</small>
                <div class="meta">
                  <span class="pill muted">{tool.category_name}</span>
                  <span class={tool.available ? "pill ok" : "pill warn"}>
                    {tool.available ? "可用" : "未找到"}
                  </span>
                </div>
              </button>
            </div>
          {/each}
        </div>
      {:else if activeNav === "tools"}
        <div class="page-header">
          <h1>工具库</h1>
          <p>选择工具，填写参数，查看命令与输出。</p>
        </div>

        <div class="filter-row">
          <div class="filter-primary">
            <div class="field">
              <label for="tool-query">搜索工具</label>
              <input
                id="tool-query"
                bind:value={toolQuery}
                placeholder="名称、用途、参数"
              />
            </div>
          </div>
          <div class="filter-selects">
            <div class="field">
              <label for="tool-capability-filter">能力</label>
              <select id="tool-capability-filter" bind:value={capabilityFilter}>
                <option value="">全部</option>
                {#each capabilityOptions as capability}
                  <option value={capability}
                    >{capabilityLabel(capability)}</option
                  >
                {/each}
              </select>
            </div>
            <div class="field">
              <label for="tool-tier-filter">层级</label>
              <select id="tool-tier-filter" bind:value={tierFilter}>
                <option value="">全部</option>
                {#each tierOptions as tier}
                  <option value={tier}>{tierLabel(tier)}</option>
                {/each}
              </select>
            </div>
            <div class="field">
              <label for="tool-installation-filter">状态</label>
              <select
                id="tool-installation-filter"
                bind:value={installationFilter}
              >
                <option value="">全部</option>
                <option value="available">可用</option>
                <option value="missing">缺失</option>
              </select>
            </div>
          </div>
          <div class="chip-row">
            <button
              data-testid="category-all"
              type="button"
              class="chip"
              class:active={categoryFilter === ""}
              onclick={() => (categoryFilter = "")}>全部</button
            >
            {#each categories as category}
              <button
                data-testid={`category-${category.id}`}
                type="button"
                class="chip"
                class:active={categoryFilter === category.id}
                onclick={() => (categoryFilter = category.id)}
                >{category.name}</button
              >
            {/each}
          </div>
        </div>

        <div class="workspace tools-workspace">
          <section class="stack tool-catalog-panel">
            <div class="catalog-panel-head">
              <div>
                <strong>工具索引</strong>
                <small>{filteredTools.length} / {catalogTools.length}</small>
              </div>
              <span>{availableTools.length} 可用</span>
            </div>
            {#if filteredTools.length === 0}
              <div class="empty">没有匹配工具。</div>
            {/if}
            {#each categories as category}
              {@const items = toolsInCategory(category.id)}
              {#if items.length > 0}
                <div class="tool-category">
                  <div class="section-label">{category.name}</div>
                  <div class="tool-grid">
                    {#each items as tool}
                      <div
                        class="tool-card"
                        class:selected={tool.id === selectedToolId}
                        class:disabled={!tool.available}
                      >
                        <button
                          data-testid={`tool-${tool.id}`}
                          class="tool-card-main"
                          type="button"
                          aria-label={tool.available
                            ? tool.name
                            : `${tool.name}，不可用，查看诊断`}
                          onclick={() => selectTool(tool)}
                        >
                          <div class="tool-card-title">
                            <strong>{tool.name}</strong>
                          </div>
                          <small>{tool.summary}</small>
                          <div class="meta">
                            <span class="pill muted"
                              >{tool.mode === "external_launch"
                                ? "一键启动"
                                : "内嵌运行"}</span
                            >
                            <span
                              class={tool.available ? "pill ok" : "pill warn"}
                            >
                              {tool.available ? "可用" : tool.detail}
                            </span>
                          </div>
                        </button>
                      </div>
                    {/each}
                  </div>
                </div>
              {/if}
            {/each}
          </section>

          <section class="card tool-runner-card" data-testid="tool-runner">
            {#if selectedTool}
              <div class="card-head runner-head">
                <div>
                  <div class="tool-title-row">
                    <h2>{selectedTool.name}</h2>
                    {#if toolUsage(selectedTool) || toolDiagnostic?.help.command}
                      <button
                        type="button"
                        class="help-tip"
                        aria-label={`${selectedTool.name} 用法说明`}
                        aria-expanded={helpOpen}
                        aria-controls="tool-help-drawer"
                        onclick={() => (helpOpen = !helpOpen)}
                      >
                        <CircleHelp class="help-icon" size={17} />
                        <span class="help-panel help-panel-wide"
                          >{toolUsage(selectedTool) || "查看版本帮助"}</span
                        >
                      </button>
                    {/if}
                  </div>
                  <p class="sub">{selectedTool.summary}</p>
                </div>
                <span class={selectedTool.available ? "pill ok" : "pill warn"}>
                  {selectedTool.available ? "就绪" : "不可用"}
                </span>
              </div>

              <div class="runner-facts">
                <div class="meta">
                  <span class="pill muted" data-testid="tool-tier">
                    {tierLabel(selectedTool.tier)}
                  </span>
                  <span class="pill muted" data-testid="tool-risk">
                    {riskLevelLabel(selectedTool.risk_level)}
                  </span>
                  {#if selectedTool.capabilities.length > 0}
                    <span class="pill muted" data-testid="tool-capabilities">
                      {selectedTool.capabilities
                        .map(capabilityLabel)
                        .join(" · ")}
                    </span>
                  {/if}
                </div>
                {#if installationSummary(selectedTool)}
                  <p class="sub" data-testid="tool-installation">
                    安装：{installationSummary(selectedTool)}
                  </p>
                {/if}
                {#if selectedTool.io.schema_version > 0}
                  <p class="sub" data-testid="tool-io-contract">
                    输入：{ioKindList(selectedTool.io.inputs)}<br />
                    输出：{ioKindList(selectedTool.io.outputs)}
                  </p>
                {/if}
              </div>

              <section class="diagnostic-panel" data-testid="tool-diagnostic">
                <div class="diagnostic-head">
                  <div>
                    <div class="section-label">运行环境诊断</div>
                    <p class="sub">
                      检查二进制、路径、权限、版本、运行时与默认字典。
                      {#if diagnosticUpdatedAt}
                        最近检测：{diagnosticUpdatedAt}
                      {/if}
                    </p>
                  </div>
                  <div class="diagnostic-actions">
                    {#if toolDiagnostic}
                      <span
                        class={toolDiagnostic.status === "usable"
                          ? "pill ok"
                          : "pill warn"}
                        data-testid="tool-diagnostic-status"
                      >
                        {diagnosticStatusLabel(toolDiagnostic.status)}
                      </span>
                    {/if}
                    <button
                      class="btn btn-secondary"
                      type="button"
                      data-testid="recheck-tool-diagnostic"
                      disabled={diagnosticBusy}
                      onclick={() =>
                        void loadToolDiagnostic(selectedTool.id, true)}
                    >
                      {diagnosticBusy ? "检测中…" : "重新检测"}
                    </button>
                  </div>
                </div>

                {#if toolDiagnostic}
                  <div class="diagnostic-list">
                    {#each toolDiagnostic.checks as check}
                      <article
                        class="diagnostic-item"
                        data-testid={`diagnostic-${check.id}`}
                      >
                        <div class="diagnostic-item-head">
                          <strong>{check.label}</strong>
                          <span
                            class={check.status === "usable"
                              ? "pill ok"
                              : "pill warn"}
                          >
                            {diagnosticStatusLabel(check.status)}
                          </span>
                        </div>
                        <p class="sub">{check.detail}</p>
                        {#if check.source}
                          <div class="diagnostic-line">
                            <span>来源</span>
                            <code>{check.source}</code>
                          </div>
                        {/if}
                        {#if check.fix}
                          <p class="diagnostic-fix">{check.fix}</p>
                        {/if}
                        {#if check.copy_value}
                          <div class="diagnostic-copy">
                            <code>{check.copy_value}</code>
                            <button
                              class="btn btn-secondary"
                              type="button"
                              onclick={() =>
                                void copyDiagnosticValue(check.copy_value)}
                            >
                              复制
                            </button>
                          </div>
                        {/if}
                      </article>
                    {/each}
                  </div>
                {:else}
                  <p class="sub">正在读取环境状态…</p>
                {/if}
              </section>

              {#if helpOpen}
                <section
                  id="tool-help-drawer"
                  class="help-drawer"
                  data-testid="tool-help-drawer"
                  aria-labelledby="tool-help-heading"
                >
                  <div class="diagnostic-head">
                    <div>
                      <div class="section-label" id="tool-help-heading">
                        版本帮助
                      </div>
                      <p class="sub">
                        {toolDiagnostic?.help.command ||
                          "当前工具未声明帮助命令"}
                        {#if toolDiagnostic?.help.detected_version}
                          · {toolDiagnostic.help.detected_version}
                        {/if}
                      </p>
                    </div>
                    <button
                      class="btn btn-secondary icon-label-button"
                      type="button"
                      disabled={diagnosticBusy}
                      onclick={() =>
                        void loadToolDiagnostic(selectedTool.id, true)}
                    >
                      <CircleHelp size={15} />
                      刷新帮助
                    </button>
                  </div>
                  <label class="search-control" for="tool-help-query">
                    <Search size={16} aria-hidden="true" />
                    <input
                      id="tool-help-query"
                      bind:value={helpQuery}
                      placeholder="搜索参数名、选项或说明"
                      spellcheck="false"
                    />
                  </label>
                  {#if toolDiagnostic?.help.available}
                    <div class="help-meta">
                      {toolDiagnostic.help.cached
                        ? "已读取缓存"
                        : "已刷新本地快照"}
                      {#if helpQuery.trim()}
                        · {helpSearchResult.matchCount} 处匹配
                      {/if}
                    </div>
                    <pre class="help-content">{helpSearchResult.content ||
                        "没有匹配内容"}</pre>
                  {:else}
                    <p class="empty">
                      {toolDiagnostic?.help.detail || "帮助内容暂不可用"}
                    </p>
                  {/if}
                </section>
              {/if}

              {#if selectedTool.fields.length > 0}
                <div class="parameter-toolbar">
                  <label class="search-control" for="parameter-query">
                    <Search size={16} aria-hidden="true" />
                    <input
                      id="parameter-query"
                      bind:value={parameterQuery}
                      placeholder="搜索参数名、flag、含义或示例"
                      spellcheck="false"
                    />
                  </label>
                  <button
                    class="btn btn-secondary icon-label-button"
                    class:active={showHiddenFields}
                    type="button"
                    aria-pressed={showHiddenFields}
                    onclick={() => (showHiddenFields = !showHiddenFields)}
                  >
                    {#if showHiddenFields}
                      <EyeOff size={15} />
                      收起隐藏项
                    {:else}
                      <Eye size={15} />
                      查看隐藏项
                    {/if}
                  </button>
                </div>
              {/if}

              <div
                class="runner-form"
                oninput={scheduleRunPreview}
                onchange={scheduleRunPreview}
              >
                {#if selectedTool.presets.length > 0 || selectedToolPersonalPresets.length > 0}
                  <div class="field">
                    <label for="tool-preset">任务预设</label>
                    <select
                      id="tool-preset"
                      data-testid="tool-preset"
                      value={selectedPresetId}
                      onchange={(event) =>
                        applyToolPreset(
                          selectedTool,
                          event.currentTarget.value,
                        )}
                    >
                      {#if selectedTool.presets.length > 0}
                        <optgroup label="内置预设">
                          {#each selectedTool.presets as preset}
                            <option value={preset.id}>{preset.name}</option>
                          {/each}
                        </optgroup>
                      {/if}
                      {#if selectedToolPersonalPresets.length > 0}
                        <optgroup label="个人预设">
                          {#each selectedToolPersonalPresets as preset}
                            <option value={preset.id}>{preset.name}</option>
                          {/each}
                        </optgroup>
                      {/if}
                    </select>
                  </div>
                  <div class="actions" style="margin: 0 0 12px">
                    <button
                      data-testid="toggle-advanced-fields"
                      class="btn btn-secondary"
                      type="button"
                      aria-expanded={advancedFieldsExpanded}
                      aria-controls="tool-parameter-fields"
                      onclick={() =>
                        (advancedFieldsExpanded = !advancedFieldsExpanded)}
                    >
                      {advancedFieldsExpanded ? "收起高级参数" : "显示高级参数"}
                    </button>
                    <button
                      data-testid="create-personal-preset"
                      class="btn btn-secondary"
                      type="button"
                      onclick={createCurrentPersonalPreset}
                    >
                      保存为个人预设
                    </button>
                    {#if selectedPersonalPreset}
                      <button
                        data-testid="update-personal-preset"
                        class="btn btn-secondary"
                        type="button"
                        onclick={updateCurrentPersonalPreset}
                      >
                        更新
                      </button>
                      <button
                        class="btn btn-secondary"
                        type="button"
                        onclick={renameCurrentPersonalPreset}
                      >
                        重命名
                      </button>
                      <button
                        data-testid="default-personal-preset"
                        class="btn btn-secondary"
                        type="button"
                        disabled={personalPresetStore.default_by_tool[
                          selectedTool.id
                        ] === selectedPersonalPreset.id}
                        onclick={setCurrentPersonalPresetAsDefault}
                      >
                        {personalPresetStore.default_by_tool[
                          selectedTool.id
                        ] === selectedPersonalPreset.id
                          ? "当前默认"
                          : "设为默认"}
                      </button>
                      <button
                        class="btn btn-danger"
                        type="button"
                        onclick={deleteCurrentPersonalPreset}
                      >
                        删除
                      </button>
                    {/if}
                    <button
                      data-testid="export-personal-presets"
                      class="btn btn-secondary"
                      type="button"
                      onclick={openPresetExport}
                    >
                      导入/导出
                    </button>
                  </div>
                  {#if presetTransferOpen}
                    <div class="field" data-testid="personal-preset-transfer">
                      <label for="personal-preset-json">个人预设 JSON</label>
                      <textarea
                        id="personal-preset-json"
                        bind:value={presetTransferText}
                        rows="8"
                        spellcheck="false"></textarea>
                      <small class="field-hint">
                        导出内容已填入。粘贴预设包后点击导入，版本和字段会经过严格校验。
                      </small>
                      <div class="actions" style="margin: 8px 0 0">
                        <button
                          data-testid="import-personal-presets"
                          class="btn btn-primary"
                          type="button"
                          onclick={importPresetPackage}
                        >
                          导入
                        </button>
                        <button
                          class="btn btn-secondary"
                          type="button"
                          onclick={() => (presetTransferOpen = false)}
                        >
                          关闭
                        </button>
                      </div>
                    </div>
                  {/if}
                {/if}

                {#if selectedTool.fields.length === 0}
                  <p class="sub" style="margin-bottom: 14px">
                    此工具无需在 FlagDeck 内填写参数，点击启动即可打开独立窗口。
                  </p>
                {:else}
                  <div class="parameter-fields-grid" id="tool-parameter-fields">
                    {#each visibleToolFields as field}
                      {@const groupName = advancedGroupName(field.id)}
                      {#if groupName}
                        <div class="section-label parameter-group-label">
                          {groupName}
                        </div>
                      {/if}
                      <div
                        class="field parameter-field"
                        class:wide-field={fieldUsesFullRow(field)}
                        class:hidden-field={selectedFieldLayout?.hidden.includes(
                          field.id,
                        )}
                      >
                        <div class="parameter-field-head">
                          <label for={`field-${field.id}`}>{field.label}</label>
                          <div class="parameter-field-actions">
                            <button
                              class="icon-button"
                              class:active={selectedFieldLayout?.pinned.includes(
                                field.id,
                              )}
                              type="button"
                              title={selectedFieldLayout?.pinned.includes(
                                field.id,
                              )
                                ? "取消置顶"
                                : "置顶参数"}
                              aria-label={selectedFieldLayout?.pinned.includes(
                                field.id,
                              )
                                ? `取消置顶 ${field.label}`
                                : `置顶 ${field.label}`}
                              onclick={() => toggleFieldPin(field.id)}
                            >
                              {#if selectedFieldLayout?.pinned.includes(field.id)}
                                <PinOff size={14} />
                              {:else}
                                <Pin size={14} />
                              {/if}
                            </button>
                            <button
                              class="icon-button"
                              type="button"
                              title="上移参数"
                              aria-label={`上移 ${field.label}`}
                              onclick={() => moveField(field.id, -1)}
                            >
                              <ArrowUp size={14} />
                            </button>
                            <button
                              class="icon-button"
                              type="button"
                              title="下移参数"
                              aria-label={`下移 ${field.label}`}
                              onclick={() => moveField(field.id, 1)}
                            >
                              <ArrowDown size={14} />
                            </button>
                            <button
                              class="icon-button"
                              type="button"
                              title={selectedFieldLayout?.hidden.includes(
                                field.id,
                              )
                                ? "恢复参数"
                                : "隐藏参数"}
                              aria-label={selectedFieldLayout?.hidden.includes(
                                field.id,
                              )
                                ? `恢复 ${field.label}`
                                : `隐藏 ${field.label}`}
                              onclick={() => toggleFieldHidden(field.id)}
                            >
                              {#if selectedFieldLayout?.hidden.includes(field.id)}
                                <Eye size={14} />
                              {:else}
                                <EyeOff size={14} />
                              {/if}
                            </button>
                          </div>
                        </div>
                        {#if field.flag || field.examples.length > 0}
                          <div class="field-reference">
                            {#if field.flag}<code>{field.flag}</code>{/if}
                            {#if field.examples.length > 0}
                              <span>例：{field.examples.join(" · ")}</span>
                            {/if}
                          </div>
                        {/if}
                        {#if field.field_type === "wordlist"}
                          <select
                            id={`field-${field.id}`}
                            bind:value={formValues[field.id]}
                            onchange={() =>
                              selectedToolId &&
                              rememberFormForTool(selectedToolId)}
                          >
                            {#if wordlists.length === 0}
                              <option value="">未找到可用字典</option>
                            {:else}
                              {#each wordlists as wl}
                                <option value={wl.id}
                                  >{wordlistLabel(wl)}</option
                                >
                              {/each}
                            {/if}
                          </select>
                        {:else if field.field_type === "select"}
                          <select
                            id={`field-${field.id}`}
                            bind:value={formValues[field.id]}
                            onchange={() =>
                              selectedToolId &&
                              rememberFormForTool(selectedToolId)}
                          >
                            {#each field.options.length > 0 ? field.options : [field.default_value || ""] as opt}
                              <option value={opt}
                                >{optionLabel(field.id, opt)}</option
                              >
                            {/each}
                          </select>
                        {:else if field.field_type === "multiselect"}
                          {@const selectedMulti = splitMultiValue(
                            formValues[field.id] ?? "",
                          )}
                          {@const recommendedValues = recommendedOptionValues(
                            field,
                            formValues,
                          )}
                          <div
                            class="multiselect-grid"
                            data-testid={`multiselect-${field.id}`}
                          >
                            {#each field.options as opt}
                              {@const detail = field.option_details.find(
                                (item) => item.value === opt,
                              )}
                              <label
                                class="multiselect-option"
                                class:selected={selectedMulti.includes(opt)}
                                class:recommended={recommendedValues.includes(
                                  opt,
                                )}
                              >
                                <input
                                  type="checkbox"
                                  checked={selectedMulti.includes(opt)}
                                  onchange={(event) =>
                                    updateMultiValue(
                                      field.id,
                                      opt,
                                      event.currentTarget.checked,
                                    )}
                                />
                                <span>
                                  <strong>{detail?.label || opt}</strong>
                                  {#if recommendedValues.includes(opt)}
                                    <em>推荐</em>
                                  {/if}
                                  {#if detail?.summary}
                                    <small>{detail.summary}</small>
                                  {/if}
                                </span>
                              </label>
                            {/each}
                          </div>
                        {:else if field.field_type === "number"}
                          <input
                            id={`field-${field.id}`}
                            type="number"
                            bind:value={formValues[field.id]}
                            oninput={() =>
                              selectedToolId &&
                              rememberFormForTool(selectedToolId, true)}
                          />
                        {:else if field.field_type === "textarea"}
                          <textarea
                            id={`field-${field.id}`}
                            bind:value={formValues[field.id]}
                            rows="3"
                            oninput={() =>
                              selectedToolId &&
                              rememberFormForTool(selectedToolId, true)}
                          ></textarea>
                        {:else}
                          <input
                            id={`field-${field.id}`}
                            type={field.sensitive ? "password" : "text"}
                            bind:value={formValues[field.id]}
                            oninput={() => {
                              if (
                                field.from === "target_url" ||
                                field.id === "url" ||
                                field.id === "host" ||
                                field.id === "target"
                              ) {
                                const value = formValues[field.id] ?? "";
                                if (value.startsWith("http")) {
                                  targetUrl = value;
                                  schedulePrefsPersist();
                                } else if (value && field.id === "host") {
                                  try {
                                    const base = targetUrl.startsWith("http")
                                      ? targetUrl
                                      : `http://${targetUrl || "127.0.0.1"}/`;
                                    const u = new URL(base);
                                    u.hostname = value;
                                    targetUrl = u.toString();
                                    schedulePrefsPersist();
                                  } catch {
                                    /* ignore */
                                  }
                                }
                              }
                              if (selectedToolId)
                                rememberFormForTool(selectedToolId, true);
                            }}
                          />
                        {/if}
                        {#if field.hint}
                          <small class="field-hint">{field.hint}</small>
                        {/if}
                      </div>
                    {/each}
                    {#if visibleToolFields.length === 0}
                      <p class="empty wide-field">没有匹配参数。</p>
                    {/if}
                  </div>
                {/if}
              </div>

              {#if relationNotices.length > 0}
                <div class="relation-list" data-testid="parameter-relations">
                  {#each relationNotices as item}
                    <p class:error={item.severity === "error"}>
                      {item.severity === "error"
                        ? "需修正"
                        : "请确认"}：{item.message}
                    </p>
                  {/each}
                </div>
              {/if}

              {#if runPreview}
                <div class="card command-ribbon" data-testid="run-preview">
                  <div class="section-label">运行预览</div>
                  <code
                    data-testid="preview-command"
                    style="word-break: break-all"
                    >{runPreview.command_preview}</code
                  >
                  <div class="meta" style="margin-top: 10px">
                    <span class="pill muted" data-testid="preview-scope">
                      范围：{runPreview.scope}
                    </span>
                    <span class="pill muted" data-testid="preview-rate">
                      速率：{runPreview.rate_per_second == null
                        ? "不限"
                        : `${runPreview.rate_per_second} req/s`}
                    </span>
                    <span class="pill muted" data-testid="preview-size">
                      预计请求：{runPreview.estimated_request_count ?? "未知"}
                    </span>
                    <span class="pill muted" data-testid="preview-risk">
                      风险：{riskLevelLabel(runPreview.risk_level)}
                    </span>
                  </div>
                  <p
                    class="sub"
                    data-testid="preview-confirmation"
                    style="margin: 10px 0 0"
                  >
                    {runPreview.risk_level === "l3"
                      ? "点击运行后记录 L3 审计"
                      : "运行前需确认 L2 操作"}
                  </p>
                </div>
              {:else if runPreviewError}
                <div class="relation-list" data-testid="run-preview-error">
                  <p class="error">预览失败：{runPreviewError}</p>
                </div>
              {/if}

              {#if selectedTool.binary_path}
                <p class="sub" style="margin-bottom: 12px; font-size: 12px">
                  入口：<code style="word-break: break-all"
                    >{selectedTool.binary_path}</code
                  >
                </p>
              {/if}

              <div class="actions">
                <button
                  data-testid="run-selected-tool"
                  class="btn btn-primary"
                  type="button"
                  disabled={busy}
                  aria-describedby={!selectedTool.available
                    ? "run-blocked-reason"
                    : undefined}
                  onclick={() => void runSelectedTool()}
                >
                  {selectedTool.mode === "external_launch" ? "启动" : "运行"}
                </button>
                {#if selectedLogJobId && selectedJob() && jobIsActive(selectedJob()!)}
                  <button
                    class="btn btn-danger"
                    type="button"
                    disabled={busy}
                    onclick={() => void cancelSelectedJob()}
                  >
                    {selectedTool?.mode === "external_launch"
                      ? "停止当前任务"
                      : "取消当前任务"}
                  </button>
                {/if}
              </div>
              {#if !selectedTool.available}
                <p
                  class="sub"
                  id="run-blocked-reason"
                  data-testid="run-blocked-reason"
                >
                  当前无法运行：{selectedTool.detail || "请查看运行环境诊断"}
                </p>
              {/if}
            {:else}
              <div class="empty">选择左侧工具以配置参数。</div>
            {/if}

            <section class="runner-output">
              <div class="section-label">输出</div>
              <div class="job-tabs-row">
                <div class="job-tabs" role="list" aria-label="任务输出">
                  {#if filteredJobs.length === 0}
                    <span class="pill muted">暂无任务</span>
                  {:else}
                    {#each filteredJobs.slice(0, 16) as item}
                      <div
                        class="job-tab"
                        class:selected={selectedLogJobId === item.job.job_id}
                        role="listitem"
                      >
                        <button
                          type="button"
                          class="job-tab-main"
                          title={item.command_preview}
                          aria-pressed={selectedLogJobId === item.job.job_id}
                          onclick={() => void selectJobLog(item)}
                        >
                          {jobTabLabel(item)}
                        </button>
                        <button
                          type="button"
                          class="job-tab-close"
                          title={`删除 ${jobTabLabel(item)}`}
                          disabled={busy || jobIsActive(item)}
                          onclick={(event) => {
                            event.stopPropagation();
                            void deleteJobById(item.job.job_id);
                          }}
                          aria-label={`删除 ${jobTabLabel(item)}`}
                        >
                          <X size={13} />
                        </button>
                      </div>
                    {/each}
                  {/if}
                </div>
                <div class="actions" style="margin: 0">
                  {#if jobToolOptions.length > 0}
                    <select
                      class="inline-select"
                      aria-label="按工具筛选任务输出"
                      bind:value={jobFilterToolId}
                      onchange={() => persistPrefs()}
                    >
                      <option value="">全部工具</option>
                      {#each jobToolOptions as toolId}
                        <option value={toolId}>{toolId}</option>
                      {/each}
                    </select>
                  {/if}
                  <button
                    class="btn btn-secondary"
                    type="button"
                    disabled={busy ||
                      jobs.length === 0 ||
                      jobs.some(jobIsActive)}
                    onclick={() => void clearAllJobs()}
                  >
                    清空全部
                  </button>
                </div>
              </div>

              <div class="output-tabs" role="tablist" aria-label="输出视图">
                <button
                  id="output-tab-log"
                  type="button"
                  class="chip"
                  role="tab"
                  aria-selected={outputTab === "log"}
                  aria-controls="output-panel"
                  class:active={outputTab === "log"}
                  onclick={() => (outputTab = "log")}>日志</button
                >
                <button
                  id="output-tab-result"
                  type="button"
                  class="chip"
                  role="tab"
                  aria-selected={outputTab === "result"}
                  aria-controls="output-panel"
                  class:active={outputTab === "result"}
                  onclick={() => {
                    outputTab = "result";
                    void loadJobResult();
                  }}
                >
                  结果{structuredResult
                    ? ` · ${structuredResult.rows.length}`
                    : ""}
                </button>
                <button
                  id="output-tab-evidence"
                  type="button"
                  class="chip"
                  role="tab"
                  aria-selected={outputTab === "evidence"}
                  aria-controls="output-panel"
                  class:active={outputTab === "evidence"}
                  data-testid="output-tab-evidence"
                  onclick={() => {
                    outputTab = "evidence";
                    void loadJobEvidence();
                  }}
                >
                  证据{jobArtifacts.length ? ` · ${jobArtifacts.length}` : ""}
                </button>
              </div>

              <div
                class="output-panel"
                id="output-panel"
                role="tabpanel"
                aria-labelledby={`output-tab-${outputTab}`}
              >
                {#if outputTab === "log"}
                  <div class="actions" style="margin: 10px 0">
                    <span class="pill muted"
                      >{jobStatusLabel(selectedJob())}</span
                    >
                    <span class="pill muted" data-testid="job-log-range"
                      >{jobLogRange}</span
                    >
                    <button
                      class="btn btn-secondary"
                      type="button"
                      disabled={!selectedLogJobId || jobLogLoading}
                      aria-pressed={selectedLogStream === "stdout"}
                      aria-label="查看标准输出 stdout"
                      title="stdout"
                      onclick={() => {
                        selectedLogStream = "stdout";
                        void loadJobLog({ mode: "reset" });
                      }}>标准输出</button
                    >
                    <button
                      class="btn btn-secondary"
                      type="button"
                      disabled={!selectedLogJobId || jobLogLoading}
                      aria-pressed={selectedLogStream === "stderr"}
                      aria-label="查看错误输出 stderr"
                      title="stderr"
                      onclick={() => {
                        selectedLogStream = "stderr";
                        void loadJobLog({ mode: "reset" });
                      }}>错误输出</button
                    >
                    <button
                      class="btn btn-secondary"
                      type="button"
                      data-testid="job-log-head"
                      disabled={!selectedLogJobId || jobLogLoading}
                      onclick={() =>
                        void loadJobLog({ mode: "page", offset: 0 })}
                      >从头</button
                    >
                    <button
                      class="btn btn-secondary"
                      type="button"
                      data-testid="job-log-prev"
                      disabled={!selectedLogJobId ||
                        jobLogLoading ||
                        !jobLogWindow ||
                        jobLogWindow.windowStart <= 0}
                      onclick={() =>
                        void loadJobLog({
                          mode: "page",
                          offset: Math.max(
                            0,
                            (jobLogWindow?.windowStart ?? 0) - 65536,
                          ),
                        })}>上一段</button
                    >
                    <button
                      class="btn btn-secondary"
                      type="button"
                      data-testid="job-log-next"
                      disabled={!selectedLogJobId ||
                        jobLogLoading ||
                        !jobLogWindow ||
                        jobLogWindow.eof}
                      onclick={() =>
                        void loadJobLog({
                          mode: "page",
                          offset: jobLogWindow?.nextOffset ?? 0,
                        })}>下一段</button
                    >
                    <button
                      class="btn btn-secondary"
                      type="button"
                      disabled={!selectedLogJobId || jobLogLoading}
                      onclick={() => void loadJobLog({ mode: "reset" })}
                      >刷新</button
                    >
                    <button
                      class="btn btn-secondary"
                      type="button"
                      disabled={!jobLogContent}
                      onclick={() => void copyJobLog()}>复制窗口</button
                    >
                    <label class="check-inline">
                      <input
                        type="checkbox"
                        bind:checked={autoScrollLog}
                        onchange={() => persistPrefs()}
                      />
                      自动滚底
                    </label>
                    {#if selectedLogJobId && selectedJob() && !jobIsActive(selectedJob()!)}
                      <button
                        class="btn btn-danger"
                        type="button"
                        disabled={busy}
                        onclick={() => void deleteJobById(selectedLogJobId)}
                      >
                        删除此任务
                      </button>
                    {/if}
                  </div>
                  <p class="sub" data-testid="job-log-bound-hint">
                    当前显示{logStreamLabel(
                      selectedLogStream,
                    )}的有界窗口。完整日志与原始输出可在「证据」中导出。
                  </p>
                  <pre
                    class="log-pane"
                    bind:this={logPaneEl}
                    role="log"
                    aria-live="polite"
                    aria-label={logStreamLabel(
                      selectedLogStream,
                    )}>{jobLogContent ||
                      "运行后日志会显示在这里。用上方标签切换不同任务的输出。"}</pre>
                {:else if outputTab === "evidence"}
                  <div class="actions" style="margin: 10px 0">
                    <span class="pill muted">任务证据</span>
                    <button
                      class="btn btn-secondary"
                      type="button"
                      data-testid="refresh-job-evidence"
                      disabled={!selectedLogJobId || busy}
                      onclick={() => void loadJobEvidence(true)}>刷新</button
                    >
                  </div>
                  {#if !selectedLogJobId}
                    <div class="empty">
                      选择任务后查看标准输出、错误输出与原始证据。
                    </div>
                  {:else if jobArtifacts.length === 0}
                    <div class="empty" data-testid="job-evidence-empty">
                      暂无已提交的证据文件。失败或解析错误时仍可分页查看日志。
                    </div>
                  {:else}
                    <div
                      class="job-evidence-list"
                      data-testid="job-evidence-list"
                    >
                      {#each jobArtifacts as artifact}
                        <div
                          class="job-evidence-item"
                          data-testid={`job-evidence-${artifact.logical_name}`}
                        >
                          <div>
                            <strong>{artifact.logical_name}</strong>
                            <small>
                              {artifact.size ?? "?"} 字节 · {sensitivityLabel(
                                artifact.sensitivity,
                              )} · {exportPolicyLabel(artifact.export_policy)}
                            </small>
                            <small class="mono"
                              >{artifact.sha256 ?? "哈希待提交"}</small
                            >
                          </div>
                          <div class="actions" style="margin: 0">
                            <button
                              class="btn btn-secondary"
                              type="button"
                              disabled={busy}
                              onclick={() => void previewJobEvidence(artifact)}
                              >有界预览</button
                            >
                            <button
                              class="btn btn-primary"
                              type="button"
                              data-testid={`export-job-evidence-${artifact.logical_name}`}
                              disabled={busy ||
                                artifact.export_policy ===
                                  "exclude_credential" ||
                                artifact.export_policy === "exclude_runtime"}
                              onclick={() => void exportJobEvidence(artifact)}
                              >导出</button
                            >
                          </div>
                        </div>
                      {/each}
                    </div>
                  {/if}
                  {#if jobEvidenceNotice}
                    <pre
                      class="log-pane"
                      data-testid="job-evidence-notice">{jobEvidenceNotice}</pre>
                  {/if}
                  {#if lastJobExport}
                    <p class="sub" data-testid="job-export-result">
                      导出文件 {lastJobExport.export_name} · {lastJobExport.size}
                      字节 · SHA-256 {lastJobExport.sha256}
                    </p>
                  {/if}
                {:else}
                  <div class="actions" style="margin: 10px 0">
                    <span
                      class="pill muted"
                      data-testid="structured-result-status"
                    >
                      {#if !structuredResult}
                        无结构化结果
                      {:else if structuredResult.status === "parse_failed"}
                        解析失败 · 原始证据仍可访问
                      {:else if structuredResult.status === "pending"}
                        结果导入中
                      {:else if structuredResult.status === "empty"}
                        无结果行
                      {:else}
                        {structuredResultKindLabel(structuredResult.kind)} · 解析器
                        {structuredResult.parser_id ?? "内置"} · {resultRows.length}/{structuredResult
                          .rows.length} 行
                      {/if}
                    </span>
                    <input
                      class="inline-search"
                      data-testid="result-filter"
                      aria-label="过滤结构化结果"
                      placeholder="过滤结果…"
                      bind:value={resultFilter}
                    />
                    <select
                      class="inline-select"
                      data-testid="result-sort-key"
                      aria-label="结果排序字段"
                      bind:value={resultSortKey}
                    >
                      {#each resultColumns as col}
                        <option value={col.key}>{col.label}</option>
                      {/each}
                    </select>
                    <button
                      class="btn btn-secondary"
                      type="button"
                      data-testid="result-sort-dir"
                      onclick={() =>
                        (resultSortDir =
                          resultSortDir === "asc" ? "desc" : "asc")}
                      >{resultSortDir === "asc" ? "升序" : "降序"}</button
                    >
                    <button
                      class="btn btn-secondary"
                      type="button"
                      disabled={!structuredResult}
                      onclick={() => void loadJobResult(true)}>刷新</button
                    >
                    <button
                      class="btn btn-secondary"
                      type="button"
                      data-testid="copy-result-tsv"
                      disabled={resultRows.length === 0}
                      onclick={() => void copyResultTsv()}
                      >复制表格（TSV）</button
                    >
                  </div>
                  {#if structuredResult?.parser_error}
                    <div class="empty" data-testid="structured-parse-error">
                      解析诊断：{structuredResult.parser_error}。请打开「证据」查看原始文件。
                    </div>
                  {/if}
                  {#if !structuredResult || structuredResult.status === "empty"}
                    <div class="empty">
                      当前任务没有可展示的结构化结果。原始日志与证据文件仍可在其它标签访问。
                    </div>
                  {:else if structuredResult.status === "parse_failed"}
                    <div class="empty">
                      解析失败，结构化结果不可用。原始证据保留。
                      <button
                        class="btn btn-secondary"
                        type="button"
                        onclick={() => {
                          outputTab = "evidence";
                          void loadJobEvidence();
                        }}>打开证据</button
                      >
                    </div>
                  {:else if resultRows.length === 0}
                    <div class="empty">没有匹配过滤条件的行。</div>
                  {:else}
                    <div
                      class="result-table-wrap"
                      data-testid="structured-result-table"
                    >
                      <table class="result-table">
                        <caption class="visually-hidden">结构化结果</caption>
                        <thead>
                          <tr>
                            {#each resultColumns as col}
                              <th>{col.label}</th>
                            {/each}
                            <th>定位</th>
                          </tr>
                        </thead>
                        <tbody>
                          {#each resultRows as row}
                            <tr data-testid={`result-row-${row.result_id}`}>
                              {#each resultColumns as col}
                                <td title={row.cells[col.key] ?? ""}
                                  >{row.cells[col.key] ?? ""}</td
                                >
                              {/each}
                              <td>
                                <button
                                  class="btn btn-secondary"
                                  type="button"
                                  data-testid={`result-source-${row.result_id}`}
                                  disabled={!row.source_artifact_id}
                                  onclick={() =>
                                    jumpToSourceArtifact(
                                      row.source_artifact_id,
                                    )}>原始证据</button
                                >
                                {#if row.cells.url}
                                  <button
                                    class="btn btn-primary"
                                    type="button"
                                    data-testid={`send-to-${row.result_id}`}
                                    onclick={() => openSendTo(row)}
                                    >发送到…</button
                                  >
                                {/if}
                              </td>
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                    </div>
                  {/if}
                  {#if sendToSource}
                    <div class="send-to-panel" data-testid="send-to-panel">
                      <h3>发送到兼容工具</h3>
                      <p class="sub">
                        来源 {sendToSource.sourceResultId} · URL
                        {sendToTargetUrl(sendToSource)}
                      </p>
                      <div class="actions">
                        {#each sendToTargets as target}
                          <button
                            class="btn btn-secondary"
                            type="button"
                            data-testid={`send-to-target-${target.tool.id}`}
                            onclick={() => applySendTo(target)}
                            >{target.tool.name}</button
                          >
                        {/each}
                        <button
                          class="btn btn-danger"
                          type="button"
                          data-testid="send-to-cancel"
                          onclick={() => cancelSendTo()}>取消</button
                        >
                      </div>
                    </div>
                  {/if}
                {/if}
              </div>
            </section>
          </section>
        </div>
      {:else if activeNav === "jobs"}
        <div class="page-header">
          <h1>任务</h1>
          <p>受管进程状态、命令预览与实时日志。</p>
        </div>
        <div class="split-2">
          <section class="card">
            <div class="card-head">
              <div>
                <h2>任务列表</h2>
                <p class="sub" data-testid="job-history-count">
                  已加载 {filteredJobs.length}
                  {jobFilterToolId ? ` / ${jobs.length}` : ""} 条
                  {jobNextCursor
                    ? " · 可继续加载"
                    : jobs.length
                      ? " · 已加载全部"
                      : ""}
                </p>
              </div>
              <div class="actions" style="margin: 0">
                {#if jobToolOptions.length > 0}
                  <select
                    class="inline-select"
                    aria-label="按工具筛选任务"
                    bind:value={jobFilterToolId}
                    onchange={() => persistPrefs()}
                  >
                    <option value="">全部工具</option>
                    {#each jobToolOptions as toolId}
                      <option value={toolId}>{toolId}</option>
                    {/each}
                  </select>
                {/if}
                <button
                  class="btn btn-secondary"
                  type="button"
                  data-testid="load-more-jobs"
                  disabled={busy || jobHistoryLoading || !jobNextCursor}
                  onclick={() => void loadMoreJobs()}
                >
                  {jobHistoryLoading
                    ? "加载中…"
                    : jobNextCursor
                      ? "加载更多历史"
                      : "已加载全部"}
                </button>
                <button
                  class="btn btn-secondary"
                  type="button"
                  disabled={busy || jobs.length === 0 || jobs.some(jobIsActive)}
                  onclick={() => void clearAllJobs()}
                >
                  清空全部
                </button>
              </div>
            </div>
            {#if filteredJobs.length === 0}
              <div class="empty">暂无任务。</div>
            {:else}
              <div class="job-list" data-testid="job-history-list">
                {#each filteredJobs as item}
                  <div
                    class="job-item-row"
                    class:selected={selectedLogJobId === item.job.job_id}
                  >
                    <button
                      class="job-item"
                      type="button"
                      aria-pressed={selectedLogJobId === item.job.job_id}
                      onclick={() => void selectJobLog(item)}
                    >
                      <strong
                        >{item.tool_id} · {executionStatusLabel(
                          item.job.execution_status,
                        )}</strong
                      >
                      <small>{item.command_preview}</small>
                      {#if item.io.schema_version > 0}
                        <small data-testid={`job-io-${item.job.job_id}`}>
                          输入：{ioKindList(item.io.inputs)}。输出：{ioKindList(
                            item.io.outputs,
                          )}。
                        </small>
                      {/if}
                    </button>
                    {#if jobIsActive(item)}
                      <button
                        class="btn btn-danger job-delete"
                        type="button"
                        disabled={busy}
                        aria-label={`停止 ${jobTabLabel(item)}`}
                        onclick={() => {
                          selectedLogJobId = item.job.job_id;
                          void cancelSelectedJob();
                        }}>停止</button
                      >
                    {:else}
                      <button
                        class="btn btn-danger job-delete"
                        type="button"
                        disabled={busy}
                        aria-label={`删除 ${jobTabLabel(item)}`}
                        onclick={() => void deleteJobById(item.job.job_id)}
                        >删除</button
                      >
                    {/if}
                  </div>
                {/each}
              </div>
            {/if}
          </section>
          <section class="card">
            <div class="card-head">
              <div>
                <h2>日志 / 证据</h2>
                <p class="sub">{selectedLogJobId || "未选择任务"}</p>
              </div>
            </div>
            <div class="actions" style="margin-bottom: 12px">
              <span class="pill muted" data-testid="job-log-range-jobs"
                >{jobLogRange}</span
              >
              <button
                class="btn btn-secondary"
                type="button"
                disabled={!selectedLogJobId || jobLogLoading}
                aria-pressed={selectedLogStream === "stdout"}
                aria-label="查看标准输出 stdout"
                title="stdout"
                onclick={() => {
                  selectedLogStream = "stdout";
                  void loadJobLog({ mode: "reset" });
                }}>标准输出</button
              >
              <button
                class="btn btn-secondary"
                type="button"
                disabled={!selectedLogJobId || jobLogLoading}
                aria-pressed={selectedLogStream === "stderr"}
                aria-label="查看错误输出 stderr"
                title="stderr"
                onclick={() => {
                  selectedLogStream = "stderr";
                  void loadJobLog({ mode: "reset" });
                }}>错误输出</button
              >
              <button
                class="btn btn-secondary"
                type="button"
                disabled={!selectedLogJobId ||
                  jobLogLoading ||
                  !jobLogWindow ||
                  jobLogWindow.windowStart <= 0}
                onclick={() =>
                  void loadJobLog({
                    mode: "page",
                    offset: Math.max(
                      0,
                      (jobLogWindow?.windowStart ?? 0) - 65536,
                    ),
                  })}>上一段</button
              >
              <button
                class="btn btn-secondary"
                type="button"
                disabled={!selectedLogJobId ||
                  jobLogLoading ||
                  !jobLogWindow ||
                  jobLogWindow.eof}
                onclick={() =>
                  void loadJobLog({
                    mode: "page",
                    offset: jobLogWindow?.nextOffset ?? 0,
                  })}>下一段</button
              >
              <button
                class="btn btn-secondary"
                type="button"
                disabled={!jobLogContent}
                onclick={() => void copyJobLog()}>复制窗口</button
              >
              <button
                class="btn btn-secondary"
                type="button"
                disabled={!selectedLogJobId}
                onclick={() => {
                  outputTab = "evidence";
                  void loadJobEvidence();
                }}>打开证据</button
              >
            </div>
            <p class="sub">界面保留有界日志窗口。完整文件可从证据列表导出。</p>
            <pre
              class="log-pane"
              bind:this={logPaneEl}
              role="log"
              aria-live="polite"
              aria-label={logStreamLabel(selectedLogStream)}>{jobLogContent ||
                "选择任务后显示日志。"}</pre>
            {#if jobArtifacts.length > 0}
              <div class="job-evidence-list" style="margin-top: 12px">
                {#each jobArtifacts as artifact}
                  <div class="job-evidence-item">
                    <div>
                      <strong>{artifact.logical_name}</strong>
                      <small>
                        {artifact.size ?? "?"} 字节 · {exportPolicyLabel(
                          artifact.export_policy,
                        )}
                      </small>
                    </div>
                    <button
                      class="btn btn-primary"
                      type="button"
                      disabled={busy}
                      onclick={() => void exportJobEvidence(artifact)}
                      >导出</button
                    >
                  </div>
                {/each}
              </div>
            {/if}
          </section>
        </div>
      {:else}
        <div class="page-header">
          <h1>设置</h1>
          <p>工具与字典根目录。新增工具只需编辑 catalog TOML。</p>
        </div>
        <div class="split-2">
          <section class="card">
            <h2>路径</h2>
            <p class="sub">可通过环境变量覆盖默认值。</p>
            <div class="section-label">FLAGDECK_TOOLS_ROOT</div>
            <code style="font-size: 13px; word-break: break-all"
              >{catalog?.tools_root ?? "—"}</code
            >
            <div class="section-label">FLAGDECK_WORDLISTS_ROOT</div>
            <code style="font-size: 13px; word-break: break-all"
              >{catalog?.wordlists_root ?? "—"}</code
            >
            <div class="section-label">文档</div>
            <p class="sub">见仓库 docs/TOOL_CATALOG.md（AI 加工具 SOP）。</p>
          </section>
          <section class="card">
            <h2>目标范围</h2>
            <p class="sub">运行工具时会自动创建匹配的范围。</p>
            {#if scopes.length === 0}
              <div class="empty">尚未保存目标。</div>
            {:else}
              <div class="job-list">
                {#each scopes as scope}
                  <div class="job-item">
                    <strong
                      >{scope.schemes[0]}://{scope.exact_hosts[0]}:{scope
                        .ports[0]?.start}</strong
                    >
                    <small>{scope.network_class}</small>
                  </div>
                {/each}
              </div>
            {/if}
            <div class="section-label">字典快捷方式</div>
            {#each wordlists as wl}
              <div class="job-item" style="margin-bottom: 8px">
                <strong>{wl.name}</strong>
                <small>{wl.path}</small>
              </div>
            {/each}
          </section>
        </div>
      {/if}
    </div>
  </div>
</div>
