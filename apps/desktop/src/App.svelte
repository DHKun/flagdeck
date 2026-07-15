<script lang="ts">
  import { onMount } from "svelte";

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

  type NavId = "home" | "tools" | "jobs" | "settings";

  const navItems: Array<{ id: NavId; label: string; icon: string }> = [
    { id: "home", label: "工作台", icon: "⌂" },
    { id: "tools", label: "工具库", icon: "▦" },
    { id: "jobs", label: "任务", icon: "◉" },
    { id: "settings", label: "设置", icon: "⚙" },
  ];

  let status: AppStatus | null = null;
  let catalog: CatalogSnapshot | null = null;
  let jobs: JobView[] = [];
  let scopes: TargetScope[] = [];
  let activeNav: NavId = "home";
  let targetUrl = "http://127.0.0.1/";
  let selectedToolId = "";
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

  $: selectedTool =
    catalog?.tools.find((tool) => tool.id === selectedToolId) ?? null;
  $: availableTools = (catalog?.tools ?? []).filter((tool) => tool.available);
  $: featuredTools = availableTools.filter((tool) => tool.featured);
  $: filteredTools = (catalog?.tools ?? []).filter((tool) => {
    if (!toolQuery.trim()) return true;
    const q = toolQuery.toLowerCase();
    return (
      tool.name.toLowerCase().includes(q) ||
      tool.summary.toLowerCase().includes(q) ||
      tool.category_name.toLowerCase().includes(q)
    );
  });
  $: categories = catalog?.categories ?? [];
  $: wordlists = (catalog?.wordlists ?? []).filter((item) => item.available);
  $: activeJobCount = jobs.filter(jobIsActive).length;

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
    const next: Record<string, string> = {};
    for (const field of tool.fields) {
      if (field.from === "target_url" && targetUrl.trim()) {
        next[field.id] = targetUrl.trim();
      } else if (field.default_value) {
        next[field.id] = field.default_value;
      } else {
        next[field.id] = formValues[field.id] ?? "";
      }
    }
    formValues = next;
  }

  function selectTool(tool: CatalogToolDto): void {
    selectedToolId = tool.id;
    applyToolDefaults(tool);
    if (activeNav === "home") activeNav = "tools";
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
        featuredTools[0] ??
        availableTools[0] ??
        catalog.tools.find((tool) => tool.id === "dddd") ??
        catalog.tools[0];
      if (preferred) selectTool(preferred);
    } else if (selectedTool) {
      // keep form; only fill missing defaults
      for (const field of selectedTool.fields) {
        if (!formValues[field.id] && field.default_value) {
          formValues = { ...formValues, [field.id]: field.default_value };
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
  }

  function selectedJob(): JobView | null {
    return jobs.find((item) => item.job.job_id === selectedLogJobId) ?? null;
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
    }
    await loadJobLog(true);
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
    await guarded(async () => {
      if (contextTarget) {
        targetUrl = contextTarget.startsWith("http")
          ? contextTarget
          : targetUrl;
        await ipc.ensureTarget({
          project_id: status!.active_project!.project_id,
          base_url: contextTarget.startsWith("http")
            ? contextTarget
            : `http://${contextTarget}/`,
        });
      }
      const job = await ipc.runCatalogTool({
        project_id: status!.active_project!.project_id,
        tool_id: selectedTool!.id,
        target_url: contextTarget,
        form: { ...formValues },
      });
      selectedLogJobId = job.job.job_id;
      selectedLogStream = "stdout";
      jobLogContent = "";
      jobLogOffset = 0;
      jobLogEof = false;
      await refresh();
      await loadJobLog(true);
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
        <code style="font-size: 11px; word-break: break-all"
          >{catalog.tools_root}</code
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

        <div class="hero">
          <section class="card">
            <div class="card-head">
              <div>
                <h2>快速开始</h2>
                <p class="sub">当前目标会自动建立范围，并在工具之间复用。</p>
              </div>
              <span class="pill">推荐</span>
            </div>
            <div class="field">
              <label for="home-url">目标 URL</label>
              <input id="home-url" bind:value={targetUrl} />
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

        <div class="section-label">精选工具</div>
        <div class="tool-grid">
          {#each featuredTools as tool}
            <div
              class="tool-card"
              class:selected={tool.id === selectedToolId}
              class:disabled={!tool.available}
            >
              <button
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

        <div class="field" style="max-width: 360px">
          <label for="tool-query">搜索</label>
          <input
            id="tool-query"
            bind:value={toolQuery}
            placeholder="名称、分类、说明"
          />
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

          <section class="card">
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
                      />
                    {:else if field.field_type === "textarea"}
                      <textarea
                        id={`field-${field.id}`}
                        bind:value={formValues[field.id]}
                        rows="3"></textarea>
                    {:else}
                      <input
                        id={`field-${field.id}`}
                        bind:value={formValues[field.id]}
                        oninput={() => {
                          if (
                            field.from === "target_url" ||
                            field.id === "url" ||
                            field.id === "host" ||
                            field.id === "target"
                          ) {
                            const value = formValues[field.id] ?? "";
                            if (value.startsWith("http")) targetUrl = value;
                          }
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
                    取消当前任务
                  </button>
                {/if}
              </div>
            {:else}
              <div class="empty">选择左侧工具以配置参数。</div>
            {/if}

            <div class="section-label">输出</div>
            <div class="job-tabs-row">
              <div class="job-tabs">
                {#if jobs.length === 0}
                  <span class="pill muted">暂无任务</span>
                {:else}
                  {#each jobs.slice(0, 16) as item}
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
              <button
                class="btn btn-secondary"
                type="button"
                disabled={busy || jobs.length === 0 || jobs.some(jobIsActive)}
                onclick={() => void clearAllJobs()}
              >
                清空全部
              </button>
            </div>

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
            <div class="log-pane">
              {jobLogContent ||
                "运行后日志会显示在这里。用上方标签切换不同任务的输出。"}
            </div>
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
                <p class="sub">共 {jobs.length} 条</p>
              </div>
              <button
                class="btn btn-secondary"
                type="button"
                disabled={busy || jobs.length === 0 || jobs.some(jobIsActive)}
                onclick={() => void clearAllJobs()}
              >
                清空全部
              </button>
            </div>
            {#if jobs.length === 0}
              <div class="empty">暂无任务。</div>
            {:else}
              <div class="job-list">
                {#each jobs as item}
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
                    <button
                      class="btn btn-danger job-delete"
                      type="button"
                      disabled={busy || jobIsActive(item)}
                      onclick={() => void deleteJobById(item.job.job_id)}
                      >删除</button
                    >
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
            </div>
            <div class="log-pane">
              {jobLogContent || "选择任务后显示日志。"}
            </div>
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
