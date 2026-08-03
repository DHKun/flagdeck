// @vitest-environment happy-dom

import { mount, tick, unmount } from "svelte";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "../src/App.svelte";
import type {
  CatalogSnapshot,
  CatalogToolDiagnosticDto,
} from "../src/generated/ipc";

const ipcMocks = vi.hoisted(() => ({
  status: vi.fn(),
  listCatalog: vi.fn(),
  listJobs: vi.fn(),
  listScopes: vi.fn(),
  loadPersonalPresets: vi.fn(),
  diagnoseCatalogTool: vi.fn(),
  previewCatalogTool: vi.fn(),
  ensureTarget: vi.fn(),
  runCatalogTool: vi.fn(),
}));

vi.mock("../src/lib/ipc", () => ({
  commandErrorMessage: () => "操作失败",
  ipc: ipcMocks,
}));

const baseInstallation = {
  distribution: "system",
  license: "MIT",
  homepage: "https://example.test",
  version: "1.0",
  health_strategy: "path",
  runtime: "native",
  version_args: ["--version"],
  install_command: "",
  path_fix: "",
  wordlist_source: "",
  wordlist_install_command: "",
};

const catalog = {
  tools_root: "/tools",
  wordlists_root: "/wordlists",
  user_catalog_root: "/user-tools",
  categories: [{ id: "web", name: "Web", summary: "Web tools", order: 1 }],
  wordlists: [],
  tools: [
    {
      id: "fixture",
      name: "Fixture Tool",
      category: "web",
      category_name: "Web",
      tier: "tier_1",
      capabilities: ["http_request"],
      aliases: [],
      presets: [
        {
          id: "quick",
          name: "快速",
          core_fields: ["url"],
          defaults: { url: "https://example.test" },
        },
      ],
      field_groups: [],
      relations: [],
      risk_level: "l1",
      installation: baseInstallation,
      io: { schema_version: 1, inputs: [], outputs: [] },
      summary: "Fixture summary",
      usage: "Fixture usage",
      mode: "managed_cli",
      featured: true,
      available: true,
      binary_path: "/usr/bin/fixture",
      detail: "",
      icon: "",
      accent: "",
      fields: [
        {
          id: "url",
          field_type: "url",
          label: "目标 URL",
          required: true,
          default_value: "",
          from: "target_url",
          options: [],
          flag: "--url",
          hint: "输入授权目标",
          examples: ["https://example.test"],
          option_details: [],
          recommend_from: [],
          sensitive: false,
        },
      ],
      needs_target: true,
    },
    {
      id: "missing",
      name: "Missing Tool",
      category: "web",
      category_name: "Web",
      tier: "tier_1",
      capabilities: [],
      aliases: [],
      presets: [],
      field_groups: [],
      relations: [],
      risk_level: "l0",
      installation: baseInstallation,
      io: { schema_version: 1, inputs: [], outputs: [] },
      summary: "Unavailable fixture",
      usage: "",
      mode: "managed_cli",
      featured: false,
      available: false,
      binary_path: "",
      detail: "未找到",
      icon: "",
      accent: "",
      fields: [],
      needs_target: false,
    },
  ],
} satisfies CatalogSnapshot;

function diagnostic(toolId: string): CatalogToolDiagnosticDto {
  return {
    tool_id: toolId,
    status: toolId === "fixture" ? "usable" : "missing",
    binary_path: toolId === "fixture" ? "/usr/bin/fixture" : "",
    detected_version: "1.0",
    checks: [],
    help: {
      available: toolId === "fixture",
      cached: false,
      command: toolId === "fixture" ? "/usr/bin/fixture --help" : "",
      detected_version: "1.0",
      binary_sha256: "a".repeat(64),
      captured_at_epoch_secs: null,
      content: "Fixture usage",
      detail: "",
    },
  };
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 0));
  await tick();
}

describe("App accessibility and tool runner contracts", () => {
  let instance: ReturnType<typeof mount> | null = null;

  beforeEach(() => {
    localStorage.clear();
    document.body.innerHTML = '<div id="app"></div>';
    ipcMocks.status.mockResolvedValue({
      application_version: "1.0",
      contract_version: 1,
      active_project: { project_id: "project-1" },
      storage: null,
      recovery: null,
      active_jobs: 0,
      security: {},
    });
    ipcMocks.listCatalog.mockResolvedValue(catalog);
    ipcMocks.listJobs.mockResolvedValue({ items: [], next_cursor: null });
    ipcMocks.listScopes.mockResolvedValue({ items: [] });
    ipcMocks.loadPersonalPresets.mockResolvedValue({
      schema_version: 1,
      presets: [],
      default_by_tool: {},
    });
    ipcMocks.diagnoseCatalogTool.mockImplementation(({ tool_id }) =>
      Promise.resolve(diagnostic(tool_id)),
    );
    ipcMocks.previewCatalogTool.mockResolvedValue({
      command_preview: "/usr/bin/fixture --url https://example.test",
      scope: "https://example.test",
      rate_per_second: null,
      estimated_request_count: null,
      risk_level: "l1",
    });
    ipcMocks.ensureTarget.mockResolvedValue({});
    ipcMocks.runCatalogTool.mockResolvedValue({
      job: { job_id: "job-1", execution_status: "queued" },
      tool_id: "fixture",
      command_preview: "/usr/bin/fixture --url https://example.test",
    });
  });

  afterEach(async () => {
    if (instance) await unmount(instance);
    instance = null;
    vi.clearAllMocks();
  });

  it("announces navigation and notice state", async () => {
    instance = mount(App, { target: document.querySelector("#app")! });
    await settle();

    const nav = document.querySelector("nav[aria-label='主导航']");
    const home = document.querySelector<HTMLButtonElement>(
      "[data-testid='nav-home']",
    );
    const tools = document.querySelector<HTMLButtonElement>(
      "[data-testid='nav-tools']",
    );
    expect(nav).not.toBeNull();
    expect(tools?.getAttribute("aria-current")).toBe("page");
    expect(
      document.querySelector("[data-testid='notice']")?.getAttribute("role"),
    ).toBe("status");

    home?.click();
    await tick();
    expect(home?.getAttribute("aria-current")).toBe("page");
    expect(tools?.hasAttribute("aria-current")).toBe(false);
  });

  it("exposes runner controls and output views with stable semantics", async () => {
    instance = mount(App, { target: document.querySelector("#app")! });
    await settle();
    document
      .querySelector<HTMLButtonElement>("[data-testid='nav-tools']")
      ?.click();
    await settle();

    expect(
      document.querySelector("[data-testid='tool-runner'] h2")?.textContent,
    ).toContain("Fixture Tool");
    expect(
      document.querySelector("[data-testid='tool-risk']")?.textContent,
    ).toContain("L1 · 低风险");
    expect(
      document.querySelector("[role='tablist'][aria-label='输出视图']"),
    ).not.toBeNull();
    for (const tab of document.querySelectorAll<HTMLElement>("[role='tab']")) {
      const controlledId = tab.getAttribute("aria-controls");
      expect(controlledId).toBe("output-panel");
      expect(document.getElementById(controlledId!)).not.toBeNull();
    }
    const advanced = document.querySelector<HTMLButtonElement>(
      "[data-testid='toggle-advanced-fields']",
    );
    expect(advanced?.getAttribute("aria-expanded")).toBe("false");
    expect(advanced?.getAttribute("aria-controls")).toBe(
      "tool-parameter-fields",
    );
    expect(document.querySelector("#tool-parameter-fields")).not.toBeNull();

    const evidence = document.querySelector<HTMLButtonElement>(
      "#output-tab-evidence",
    );
    evidence?.click();
    await tick();
    expect(evidence?.getAttribute("aria-selected")).toBe("true");
    expect(
      document.querySelector("#output-panel[role='tabpanel']"),
    ).not.toBeNull();
    expect(
      document.querySelector("#output-panel")?.getAttribute("aria-labelledby"),
    ).toBe("output-tab-evidence");

    document.querySelector<HTMLButtonElement>("#output-tab-result")?.click();
    await tick();
    expect(
      document.querySelector("input[aria-label='过滤结构化结果']"),
    ).not.toBeNull();
    expect(
      document.querySelector("select[aria-label='结果排序字段']"),
    ).not.toBeNull();

    const help = document.querySelector<HTMLButtonElement>(
      "button[aria-controls='tool-help-drawer']",
    );
    help?.click();
    await tick();
    expect(help?.getAttribute("aria-expanded")).toBe("true");
    expect(
      document.querySelector(
        "#tool-help-drawer[aria-labelledby='tool-help-heading']",
      ),
    ).not.toBeNull();
  });

  it("keeps unavailable tools diagnosable and explains blocked execution", async () => {
    instance = mount(App, { target: document.querySelector("#app")! });
    await settle();
    document
      .querySelector<HTMLButtonElement>("[data-testid='nav-tools']")
      ?.click();
    await settle();

    const missing = document.querySelector<HTMLButtonElement>(
      "[data-testid='tool-missing']",
    );
    expect(missing?.getAttribute("aria-label")).toContain("不可用，查看诊断");
    missing?.click();
    await settle();
    expect(
      document.querySelector("[data-testid='tool-runner'] h2")?.textContent,
    ).toContain("Missing Tool");
    const run = document.querySelector<HTMLButtonElement>(
      "[data-testid='run-selected-tool']",
    );
    expect(run?.disabled).toBe(false);
    expect(
      document.querySelector("[data-testid='run-blocked-reason']")?.textContent,
    ).toContain("未找到");
    run?.click();
    await settle();
    expect(
      document.querySelector("[data-testid='notice']")?.textContent,
    ).toContain("当前不可用");
    expect(ipcMocks.runCatalogTool).not.toHaveBeenCalled();
  });

  it("submits an L3 catalog run and creates a job without a prompt phrase dialog", async () => {
    const l3Catalog = {
      ...catalog,
      tools: catalog.tools.map((tool) =>
        tool.id === "fixture" ? { ...tool, risk_level: "l3" as const } : tool,
      ),
    };
    ipcMocks.listCatalog.mockResolvedValue(l3Catalog);
    instance = mount(App, { target: document.querySelector("#app")! });
    await settle();
    document
      .querySelector<HTMLButtonElement>("[data-testid='nav-tools']")
      ?.click();
    await settle();

    document
      .querySelector<HTMLButtonElement>("[data-testid='run-selected-tool']")
      ?.click();
    await settle();

    expect(ipcMocks.runCatalogTool).toHaveBeenCalledTimes(1);
    expect(ipcMocks.runCatalogTool.mock.calls[0][0]).toMatchObject({
      project_id: "project-1",
      tool_id: "fixture",
      l3_confirmation: "RUN CATALOG fixture",
    });
  });

  it("reruns the live environment diagnostic and refreshes catalog state", async () => {
    instance = mount(App, { target: document.querySelector("#app")! });
    await settle();
    document
      .querySelector<HTMLButtonElement>("[data-testid='nav-tools']")
      ?.click();
    await settle();
    const initialCalls = ipcMocks.diagnoseCatalogTool.mock.calls.length;
    window.dispatchEvent(new Event("focus"));
    await settle();
    expect(ipcMocks.diagnoseCatalogTool).toHaveBeenCalledTimes(initialCalls);

    document
      .querySelector<HTMLButtonElement>(
        "[data-testid='recheck-tool-diagnostic']",
      )
      ?.click();
    await settle();

    expect(ipcMocks.diagnoseCatalogTool.mock.calls.length).toBeGreaterThan(
      initialCalls,
    );
    expect(ipcMocks.diagnoseCatalogTool).toHaveBeenLastCalledWith({
      tool_id: "fixture",
      refresh_help: true,
    });
    expect(
      document.querySelector("[data-testid='tool-diagnostic']")?.textContent,
    ).toContain("最近检测");
  });
});
