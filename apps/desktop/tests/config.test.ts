import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");
const read = (path: string): string =>
  readFileSync(resolve(root, path), "utf8");
const configuration = JSON.parse(read("src-tauri/tauri.conf.json"));
const capability = JSON.parse(
  read("src-tauri/capabilities/main-capability.json"),
);
const backend = read("src-tauri/src/lib.rs");
const manifest = read("src-tauri/build.rs");
const application = read("src/App.svelte");
const isolation = read("dist-isolation/index.js");

const commands = [
  "app_status",
  "create_project",
  "list_projects",
  "open_project",
  "close_project",
  "create_note",
  "preview_artifact",
  "list_artifacts",
  "create_scope",
  "list_scopes",
  "tool_health",
  "list_catalog",
  "ensure_target",
  "run_catalog_tool",
  "delete_job",
  "clear_jobs",
  "tool_pack_health",
  "external_launcher_health",
  "payload_source_health",
  "list_payloads",
  "preview_payload",
  "launch_external",
  "run_tool",
  "cancel_job",
  "cancel_all_jobs",
  "list_jobs",
  "preview_job_log",
  "preview_job_file",
  "list_discoveries",
  "create_dictionary",
  "list_dictionaries",
  "search_dictionary",
  "export_project",
  "list_import_packages",
  "import_project",
  "start_http_proxy",
  "stop_http_proxy",
  "http_proxy_status",
  "list_http_history",
  "get_http_message",
  "repeat_http",
  "diff_http",
  "create_sqlmap_request",
  "send_raw_http1",
  "open_http_browser_preview",
  "start_metasploit",
  "metasploit_status",
  "stop_metasploit",
  "search_metasploit_modules",
  "get_metasploit_options",
  "execute_metasploit_module",
  "list_metasploit_entities",
  "create_metasploit_console",
  "stop_metasploit_entity",
  "metasploit_console_command",
  "metasploit_session_command",
  "start_intruder",
  "start_upload_campaign",
  "cancel_intruder_campaign",
  "resume_intruder_campaign",
  "list_intruder_campaigns",
  "list_intruder_attempts",
  "parse_multipart_message",
];

describe("Tauri Stable security configuration", () => {
  it("uses Isolation and one explicit main-window capability", () => {
    expect(configuration.app.security.pattern.use).toBe("isolation");
    expect(configuration.app.security.capabilities).toEqual([
      "main-capability",
    ]);
    expect(configuration.app.security.freezePrototype).toBe(true);
    expect(configuration.app.windows).toEqual([]);
    expect(capability.windows).toEqual(["main"]);
    expect(capability.webviews).toEqual(["main"]);
    expect(capability.remote).toBeUndefined();
  });

  it("grants every registered custom command and nothing broader", () => {
    expect(capability.permissions).toEqual(
      commands.map((command) => `allow-${command.replaceAll("_", "-")}`),
    );
    for (const command of commands) {
      expect(manifest).toContain(`"${command}"`);
      expect(backend).toContain(`fn ${command}(`);
      expect(isolation).toContain(`"${command}"`);
    }
  });

  it("keeps executable content and navigation local", () => {
    const csp: string = configuration.app.security.csp;
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("https:");
    expect(backend).toContain(".on_navigation(allow_navigation)");
    expect(backend).toContain("NewWindowResponse::Deny");
    expect(backend).toContain(".devtools(false)");
  });

  it("renders target-controlled content through text bindings", () => {
    expect(application).not.toContain("{@html");
    expect(application).not.toContain("innerHTML");
    // Workbench shows tool output as text in the log pane, never as HTML.
    expect(application).toContain("log-pane");
    expect(application).toContain("jobLogContent");
  });

  it("keeps filesystem paths out of command DTOs", () => {
    expect(application).not.toContain("filesystem");
    expect(
      capability.permissions.some((value: string) => value.includes("fs:")),
    ).toBe(false);
    expect(isolation).toContain("1_048_576");
    expect(isolation).toContain("65_536");
  });
});
