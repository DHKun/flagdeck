<script lang="ts">
  import { onMount, tick } from "svelte";

  import type { TargetScope } from "./generated/contracts";
  import type {
    AppStatus,
    CatalogSnapshot,
    CatalogToolDto,
    JobLogStream,
    JobView,
    WordlistDto,
  } from "./generated/ipc";
  import { commandErrorMessage, ipc } from "./lib/ipc";
  import {
    parseJobResult,
    resultCandidatesForTool,
    type ParsedJobResult,
  } from "./lib/jobResults";
  import {
    loadWorkbenchPrefs,
    rememberTool,
    saveWorkbenchPrefs,
    type WorkbenchPrefs,
  } from "./lib/workbenchPrefs";

  type NavId = "home" | "tools" | "jobs" | "settings";
  type OutputTab = "log" | "result";

  type Scenario = {
    id: string;
    title: string;
    summary: string;
    toolIds: string[];
    category?: string;
  };

  const navItems: Array<{ id: NavId; label: string; icon: string }> = [
    { id: "home", label: "工作台", icon: "⌂" },
    { id: "tools", label: "工具库", icon: "▦" },
    { id: "jobs", label: "任务", icon: "◉" },
    { id: "settings", label: "设置", icon: "⚙" },
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
  let jobLogContent = "";
  let jobLogOffset = 0;
  let jobLogEof = false;
  let pollTimer: ReturnType<typeof setTimeout> | undefined;
  let toolQuery = "";
  let categoryFilter = "";
  let jobFilterToolId = prefs.jobFilterToolId;
  let autoScrollLog = prefs.autoScrollLog;
  let outputTab: OutputTab = "log";
  let parsedResult: ParsedJobResult | null = null;
  let resultFilter = "";
  let logPaneEl: HTMLPreElement | null = null;

  $: selectedTool =
    catalog?.tools.find((tool) => tool.id === selectedToolId) ?? null;
  $: availableTools = (catalog?.tools ?? []).filter((tool) => tool.available);
  $: featuredTools = availableTools.filter((tool) => tool.featured);
  $: recentTools = prefs.recentToolIds
    .map((id) => catalog?.tools.find((tool) => tool.id === id))
    .filter((tool): tool is CatalogToolDto => Boolean(tool));
  $: filteredTools = (catalog?.tools ?? []).filter((tool) => {
    if (categoryFilter && tool.category !== categoryFilter) return false;
    if (!toolQuery.trim()) return true;
    const q = toolQuery.toLowerCase();
    return (
      tool.id.toLowerCase().includes(q) ||
      tool.name.toLowerCase().includes(q) ||
      tool.summary.toLowerCase().includes(q) ||
      tool.category_name.toLowerCase().includes(q)
    );
  });
  $: categories = catalog?.categories ?? [];
  $: wordlists = (catalog?.wordlists ?? []).filter((item) => item.available);
  $: activeJobCount = jobs.filter(jobIsActive).length;
  $: filteredJobs = jobFilterToolId
    ? jobs.filter((item) => item.tool_id === jobFilterToolId)
    : jobs;
  $: jobToolOptions = [...new Set(jobs.map((item) => item.tool_id))].sort();
  $: resultRows = parsedResult
    ? parsedResult.rows.filter((row) => {
        if (!resultFilter.trim()) return true;
        const q = resultFilter.toLowerCase();
        return Object.values(row).some((value) =>
          String(value).toLowerCase().includes(q),
        );
      })
    : [];

  function persistPrefs(): void {
    prefs = {
      ...prefs,
      targetUrl,
      selectedToolId,
      jobFilterToolId,
      autoScrollLog,
    };
    saveWorkbenchPrefs(prefs);
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
    const remembered = prefs.formByTool[tool.id] ?? {};
    const next: Record<string, string> = {};
    for (const field of tool.fields) {
      const saved = remembered[field.id];
      if (
        (field.from === "target_url" ||
          field.id === "url" ||
          field.id === "host" ||
          field.id === "target") &&
        targetUrl.trim()
      ) {
        // Prefer live top-bar target for host/url fields.
        if (field.id === "host" || field.field_type === "host") {
          next[field.id] = hostFromTarget(targetUrl);
        } else {
          next[field.id] = targetUrl.trim();
        }
      } else if (saved != null && saved !== "") {
        next[field.id] = saved;
      } else if (field.default_value) {
        next[field.id] = field.default_value;
      } else {
        next[field.id] = "";
      }
    }
    formValues = next;
  }

  function hostFromTarget(value: string): string {
    const raw = value.trim();
    if (!raw) return "";
    try {
      if (raw.includes("://")) return new URL(raw).hostname;
    } catch {
      /* ignore */
    }
    return raw.replace(/\/.*$/, "").replace(/:\d+$/, "");
  }

  function rememberFormForTool(toolId: string): void {
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
    persistPrefs();
  }

  function selectTool(tool: CatalogToolDto): void {
    if (selectedToolId && selectedToolId !== tool.id) {
      rememberFormForTool(selectedToolId);
    }
    selectedToolId = tool.id;
    applyToolDefaults(tool);
    prefs = {
      ...prefs,
      selectedToolId: tool.id,
      recentToolIds: rememberTool(prefs, tool.id),
    };
    persistPrefs();
    if (activeNav === "home") activeNav = "tools";
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
    const [nextCatalog, nextJobs, nextScopes] = await Promise.all([
      ipc.listCatalog(),
      projectId
        ? ipc.listJobs({ project_id: projectId, cursor: null, limit: 50 })
        : Promise.resolve({ items: [], next_cursor: null }),
      projectId
        ? ipc.listScopes({ project_id: projectId })
        : Promise.resolve({ items: [] }),
    ]);
    catalog = nextCatalog;
    jobs = nextJobs.items;
    scopes = nextScopes.items;

    if (!selectedToolId) {
      const preferred =
        (prefs.selectedToolId
          ? catalog.tools.find((tool) => tool.id === prefs.selectedToolId)
          : undefined) ??
        featuredTools[0] ??
        availableTools[0] ??
        catalog.tools.find((tool) => tool.id === "dddd") ??
        catalog.tools[0];
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
    }
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
    let combined = reset
      ? preview.content
      : `${jobLogContent}${preview.content}`;

    // If stdout is empty after finish, automatically surface stderr so failures are visible.
    if (
      reset &&
      selectedLogStream === "stdout" &&
      combined.trim().length === 0
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
        combined = err.content;
        jobLogOffset = err.next_offset;
        jobLogEof = err.eof;
        jobLogContent = combined.slice(-262144);
        return;
      }
    }

    jobLogContent = combined.slice(-262144);
    jobLogOffset = preview.next_offset;
    jobLogEof = preview.eof;
    if (autoScrollLog) {
      await tick();
      if (logPaneEl) logPaneEl.scrollTop = logPaneEl.scrollHeight;
    }
  }

  async function loadJobResult(): Promise<void> {
    parsedResult = null;
    if (!status?.active_project || !selectedLogJobId) return;
    const item = selectedJob();
    if (!item) return;
    const candidates = resultCandidatesForTool(item.tool_id);
    for (const filename of candidates) {
      try {
        const file = await ipc.previewJobFile({
          project_id: status.active_project.project_id,
          job_id: selectedLogJobId,
          filename,
          limit: 1024 * 1024,
        });
        if (!file.found || !file.content.trim()) continue;
        const parsed = parseJobResult(item.tool_id, filename, file.content);
        if (parsed && parsed.rows.length > 0) {
          parsedResult = parsed;
          return;
        }
      } catch {
        /* try next candidate */
      }
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
    if (!parsedResult || resultRows.length === 0) return;
    const cols = parsedResult.columns;
    const lines = [
      cols.map((c) => c.label).join("\t"),
      ...resultRows.map((row) => cols.map((c) => row[c.key] ?? "").join("\t")),
    ];
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      notice = `已复制 ${resultRows.length} 行结果`;
      noticeKind = "success";
    } catch {
      notice = "复制失败";
      noticeKind = "error";
    }
  }

  function jobStatusLabel(item: JobView | null): string {
    if (!item) return "未选择任务";
    const reason = item.job.exit_reason ? ` · ${item.job.exit_reason}` : "";
    return `${item.tool_id} · ${item.job.execution_status}${reason}`;
  }

  async function selectJobLog(item: JobView): Promise<void> {
    if (selectedLogJobId !== item.job.job_id) {
      selectedLogJobId = item.job.job_id;
      selectedLogStream = "stdout";
      jobLogContent = "";
      jobLogOffset = 0;
      jobLogEof = false;
      parsedResult = null;
      outputTab = "log";
    }
    await loadJobLog(true);
    await loadJobResult();
  }

  function scheduleJobPoll(): void {
    if (pollTimer || !jobs.some(jobIsActive)) return;
    pollTimer = setTimeout(() => {
      pollTimer = undefined;
      void pollJobs();
    }, 400);
  }

  async function pollJobs(): Promise<void> {
    try {
      if (!status?.active_project) return;
      const page = await ipc.listJobs({
        project_id: status.active_project.project_id,
        cursor: null,
        limit: 50,
      });
      jobs = page.items;
      await loadJobLog(false);
      const current = selectedJob();
      if (current && !jobIsActive(current)) {
        await loadJobResult();
      }
    } catch (error) {
      reportError(error);
    }
    scheduleJobPoll();
  }

  function contextTargetForRun(): string {
    if (!selectedTool) return targetUrl.trim();
    const fromForm =
      formValues.url?.trim() ||
      formValues.target?.trim() ||
      formValues.host?.trim() ||
      "";
    if (fromForm) return fromForm;
    return selectedTool.needs_target ? targetUrl.trim() : "";
  }

  async function runSelectedTool(): Promise<void> {
    if (!status?.active_project || !selectedTool) return;
    const contextTarget = contextTargetForRun();
    if (selectedTool.needs_target && !contextTarget) {
      notice = "请先填写目标（URL / 主机）";
      noticeKind = "error";
      return;
    }
    const hasSensitiveArgv = selectedTool.fields.some(
      (field) => field.sensitive && Boolean(formValues[field.id]),
    );
    if (
      hasSensitiveArgv &&
      !window.confirm(
        "该工具只能通过进程参数接收此敏感值。运行期间，同一用户的进程列表可能看到该值。确认继续？",
      )
    ) {
      return;
    }
    await guarded(async () => {
      if (contextTarget) {
        if (contextTarget.startsWith("http")) {
          targetUrl = contextTarget;
        } else if (
          selectedTool!.fields.some(
            (field) => field.id === "host" || field.field_type === "host",
          )
        ) {
          // keep existing url scheme if only host was edited
          try {
            const u = new URL(
              targetUrl.startsWith("http") ? targetUrl : `http://${targetUrl}/`,
            );
            u.hostname = contextTarget;
            targetUrl = u.toString();
          } catch {
            targetUrl = `http://${contextTarget}/`;
          }
        } else {
          targetUrl = contextTarget.startsWith("http")
            ? contextTarget
            : `http://${contextTarget}/`;
        }
        persistPrefs();
        await ipc.ensureTarget({
          project_id: status!.active_project!.project_id,
          base_url: contextTarget.startsWith("http")
            ? contextTarget
            : `http://${contextTarget}/`,
        });
      }
      rememberFormForTool(selectedTool!.id);
      const job = await ipc.runCatalogTool({
        project_id: status!.active_project!.project_id,
        tool_id: selectedTool!.id,
        target_url: contextTarget,
        form: { ...formValues },
        confirm_sensitive_argv: hasSensitiveArgv,
      });
      selectedLogJobId = job.job.job_id;
      selectedLogStream = "stdout";
      jobLogContent = "";
      jobLogOffset = 0;
      jobLogEof = false;
      parsedResult = null;
      outputTab = "log";
      await refresh();
      await loadJobLog(true);
      await loadJobResult();
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
      await loadJobLog(true);
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
        jobLogContent = "";
        jobLogOffset = 0;
        jobLogEof = false;
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
      jobLogContent = "";
      jobLogOffset = 0;
      jobLogEof = false;
      await refresh();
      notice = `已清空 ${result.deleted} 个任务`;
    }, "任务列表已清空");
  }

  function toolsInCategory(categoryId: string): CatalogToolDto[] {
    return filteredTools.filter((tool) => tool.category === categoryId);
  }

  function wordlistLabel(item: WordlistDto): string {
    return item.available ? item.name : `${item.name}（不可用）`;
  }

  function jobTabLabel(item: JobView): string {
    const status = item.job.execution_status;
    const short =
      status === "succeeded"
        ? "ok"
        : status === "failed"
          ? "fail"
          : status === "running" || status === "starting" || status === "queued"
            ? "run"
            : status.slice(0, 4);
    return `${item.tool_id} · ${short}`;
  }

  function toolUsage(tool: CatalogToolDto | null | undefined): string {
    if (!tool) return "";
    return (tool.usage || tool.summary || "").trim();
  }

  onMount(() => {
    void guarded(async () => {
      await refresh();
      scheduleJobPoll();
    }, "工作台已就绪");
    return () => {
      if (pollTimer) clearTimeout(pollTimer);
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

    <nav class="nav">
      {#each navItems as item}
        <button
          data-testid={`nav-${item.id}`}
          class:active={activeNav === item.id}
          type="button"
          onclick={() => (activeNav = item.id)}
        >
          <span class="nav-icon">{item.icon}</span>
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
            oninput={() => persistPrefs()}
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
                oninput={() => persistPrefs()}
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
                      >{item.job.execution_status} · {item.command_preview.slice(
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
                  data-testid={`tool-${tool.id}`}
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
                data-testid={`tool-${tool.id}`}
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
          <p>选择工具、填写参数并运行。输出在右侧，用标签切换不同任务。</p>
        </div>

        <div class="filter-row">
          <div class="field" style="max-width: 280px; margin-bottom: 0">
            <label for="tool-query">搜索</label>
            <input
              id="tool-query"
              bind:value={toolQuery}
              placeholder="id、名称、分类、说明"
            />
          </div>
          <div class="chip-row">
            <button
              type="button"
              class="chip"
              class:active={categoryFilter === ""}
              onclick={() => (categoryFilter = "")}>全部</button
            >
            {#each categories as category}
              <button
                type="button"
                class="chip"
                class:active={categoryFilter === category.id}
                onclick={() => (categoryFilter = category.id)}
                >{category.name}</button
              >
            {/each}
          </div>
        </div>

        <div class="workspace">
          <section class="stack">
            {#each categories as category}
              {@const items = toolsInCategory(category.id)}
              {#if items.length > 0}
                <div>
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
                          disabled={!tool.available}
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

          <section class="card" data-testid="tool-runner">
            {#if selectedTool}
              <div class="card-head">
                <div>
                  <div class="tool-title-row">
                    <h2>{selectedTool.name}</h2>
                    {#if toolUsage(selectedTool)}
                      <button
                        type="button"
                        class="help-tip"
                        aria-label={`${selectedTool.name} 用法说明`}
                      >
                        <span class="help-icon">?</span>
                        <span class="help-panel help-panel-wide"
                          >{toolUsage(selectedTool)}</span
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

              {#if selectedTool.fields.length === 0}
                <p class="sub" style="margin-bottom: 14px">
                  此工具无需在 FlagDeck 内填写参数，点击启动即可打开独立窗口。
                </p>
              {:else}
                {#each selectedTool.fields as field}
                  <div class="field">
                    <label for={`field-${field.id}`}>{field.label}</label>
                    {#if field.field_type === "wordlist"}
                      <select
                        id={`field-${field.id}`}
                        bind:value={formValues[field.id]}
                        onchange={() =>
                          selectedToolId && rememberFormForTool(selectedToolId)}
                      >
                        {#if wordlists.length === 0}
                          <option value="">未找到可用字典</option>
                        {:else}
                          {#each wordlists as wl}
                            <option value={wl.id}>{wordlistLabel(wl)}</option>
                          {/each}
                        {/if}
                      </select>
                    {:else if field.field_type === "select"}
                      <select
                        id={`field-${field.id}`}
                        bind:value={formValues[field.id]}
                        onchange={() =>
                          selectedToolId && rememberFormForTool(selectedToolId)}
                      >
                        {#each field.options.length > 0 ? field.options : [field.default_value || ""] as opt}
                          <option value={opt}>{opt}</option>
                        {/each}
                      </select>
                    {:else if field.field_type === "number"}
                      <input
                        id={`field-${field.id}`}
                        type="number"
                        bind:value={formValues[field.id]}
                        oninput={() =>
                          selectedToolId && rememberFormForTool(selectedToolId)}
                      />
                    {:else if field.field_type === "textarea"}
                      <textarea
                        id={`field-${field.id}`}
                        bind:value={formValues[field.id]}
                        rows="3"
                        oninput={() =>
                          selectedToolId && rememberFormForTool(selectedToolId)}
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
                              persistPrefs();
                            } else if (value && field.id === "host") {
                              try {
                                const base = targetUrl.startsWith("http")
                                  ? targetUrl
                                  : `http://${targetUrl || "127.0.0.1"}/`;
                                const u = new URL(base);
                                u.hostname = value;
                                targetUrl = u.toString();
                                persistPrefs();
                              } catch {
                                /* ignore */
                              }
                            }
                          }
                          if (selectedToolId)
                            rememberFormForTool(selectedToolId);
                        }}
                      />
                    {/if}
                    {#if field.hint}
                      <small class="field-hint">{field.hint}</small>
                    {/if}
                  </div>
                {/each}
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
                  disabled={busy || !selectedTool.available}
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
            {:else}
              <div class="empty">选择左侧工具以配置参数。</div>
            {/if}

            <div class="section-label">输出</div>
            <div class="job-tabs-row">
              <div class="job-tabs">
                {#if filteredJobs.length === 0}
                  <span class="pill muted">暂无任务</span>
                {:else}
                  {#each filteredJobs.slice(0, 16) as item}
                    <div
                      class="job-tab"
                      class:selected={selectedLogJobId === item.job.job_id}
                    >
                      <button
                        type="button"
                        class="job-tab-main"
                        title={item.command_preview}
                        onclick={() => void selectJobLog(item)}
                      >
                        {jobTabLabel(item)}
                      </button>
                      <button
                        type="button"
                        class="job-tab-close"
                        title="删除此任务"
                        disabled={busy || jobIsActive(item)}
                        onclick={(event) => {
                          event.stopPropagation();
                          void deleteJobById(item.job.job_id);
                        }}>×</button
                      >
                    </div>
                  {/each}
                {/if}
              </div>
              <div class="actions" style="margin: 0">
                {#if jobToolOptions.length > 0}
                  <select
                    class="inline-select"
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
                  disabled={busy || jobs.length === 0 || jobs.some(jobIsActive)}
                  onclick={() => void clearAllJobs()}
                >
                  清空全部
                </button>
              </div>
            </div>

            <div class="output-tabs">
              <button
                type="button"
                class="chip"
                class:active={outputTab === "log"}
                onclick={() => (outputTab = "log")}>日志</button
              >
              <button
                type="button"
                class="chip"
                class:active={outputTab === "result"}
                onclick={() => {
                  outputTab = "result";
                  void loadJobResult();
                }}
              >
                结果{parsedResult ? ` · ${parsedResult.rows.length}` : ""}
              </button>
            </div>

            {#if outputTab === "log"}
              <div class="actions" style="margin: 10px 0">
                <span class="pill muted">{jobStatusLabel(selectedJob())}</span>
                <button
                  class="btn btn-secondary"
                  type="button"
                  disabled={!selectedLogJobId}
                  onclick={() => {
                    selectedLogStream = "stdout";
                    void loadJobLog(true);
                  }}>stdout</button
                >
                <button
                  class="btn btn-secondary"
                  type="button"
                  disabled={!selectedLogJobId}
                  onclick={() => {
                    selectedLogStream = "stderr";
                    void loadJobLog(true);
                  }}>stderr</button
                >
                <button
                  class="btn btn-secondary"
                  type="button"
                  disabled={!selectedLogJobId}
                  onclick={() => void loadJobLog(true)}>刷新</button
                >
                <button
                  class="btn btn-secondary"
                  type="button"
                  disabled={!jobLogContent}
                  onclick={() => void copyJobLog()}>复制</button
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
              <pre class="log-pane" bind:this={logPaneEl}>{jobLogContent ||
                  "运行后日志会显示在这里。用上方标签切换不同任务的输出。"}</pre>
            {:else}
              <div class="actions" style="margin: 10px 0">
                <span class="pill muted"
                  >{parsedResult?.title ?? "无结构化结果"}</span
                >
                <input
                  class="inline-search"
                  placeholder="过滤结果…"
                  bind:value={resultFilter}
                />
                <button
                  class="btn btn-secondary"
                  type="button"
                  disabled={!parsedResult}
                  onclick={() => void loadJobResult()}>刷新</button
                >
                <button
                  class="btn btn-secondary"
                  type="button"
                  disabled={resultRows.length === 0}
                  onclick={() => void copyResultTsv()}>复制 TSV</button
                >
              </div>
              {#if !parsedResult}
                <div class="empty">
                  当前任务没有可解析的结果文件（如 ffuf
                  JSON）。请查看日志，或换用 ffuf / dddd / fscan / gobuster /
                  arjun。
                </div>
              {:else if resultRows.length === 0}
                <div class="empty">没有匹配过滤条件的行。</div>
              {:else}
                <div class="result-table-wrap">
                  <table class="result-table">
                    <thead>
                      <tr>
                        {#each parsedResult.columns as col}
                          <th>{col.label}</th>
                        {/each}
                      </tr>
                    </thead>
                    <tbody>
                      {#each resultRows as row}
                        <tr>
                          {#each parsedResult.columns as col}
                            <td title={row[col.key] ?? ""}
                              >{row[col.key] ?? ""}</td
                            >
                          {/each}
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {/if}
            {/if}
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
                <p class="sub">
                  共 {filteredJobs.length}
                  {jobFilterToolId ? ` / ${jobs.length}` : ""} 条
                </p>
              </div>
              <div class="actions" style="margin: 0">
                {#if jobToolOptions.length > 0}
                  <select
                    class="inline-select"
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
              <div class="job-list">
                {#each filteredJobs as item}
                  <div
                    class="job-item-row"
                    class:selected={selectedLogJobId === item.job.job_id}
                  >
                    <button
                      class="job-item"
                      type="button"
                      onclick={() => void selectJobLog(item)}
                    >
                      <strong
                        >{item.tool_id} · {item.job.execution_status}</strong
                      >
                      <small>{item.command_preview}</small>
                    </button>
                    {#if jobIsActive(item)}
                      <button
                        class="btn btn-danger job-delete"
                        type="button"
                        disabled={busy}
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
                <h2>日志</h2>
                <p class="sub">{selectedLogJobId || "未选择任务"}</p>
              </div>
            </div>
            <div class="actions" style="margin-bottom: 12px">
              <button
                class="btn btn-secondary"
                type="button"
                onclick={() => {
                  selectedLogStream = "stdout";
                  void loadJobLog(true);
                }}>stdout</button
              >
              <button
                class="btn btn-secondary"
                type="button"
                onclick={() => {
                  selectedLogStream = "stderr";
                  void loadJobLog(true);
                }}>stderr</button
              >
              <button
                class="btn btn-secondary"
                type="button"
                disabled={!jobLogContent}
                onclick={() => void copyJobLog()}>复制</button
              >
            </div>
            <pre class="log-pane" bind:this={logPaneEl}>{jobLogContent ||
                "选择任务后显示日志。"}</pre>
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
