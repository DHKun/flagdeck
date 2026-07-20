import { invoke } from "@tauri-apps/api/core";

const attempts = [
  ["app_status", {}],
  ["list_projects", { request: { cursor: null, limit: 20 } }],
  ["create_project", { request: { name: "probe" } }],
  [
    "open_project",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        mode: "read_only",
      },
    },
  ],
  ["close_project", {}],
  [
    "create_note",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        logical_name: "probe.txt",
        content: "probe",
        sensitivity: "normal",
      },
    },
  ],
  [
    "preview_artifact",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        artifact_id: "00000000-0000-0000-0000-000000000000",
        offset: 0,
        limit: 1,
        mode: "text",
      },
    },
  ],
  [
    "list_artifacts",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        cursor: null,
        limit: 20,
      },
    },
  ],
  [
    "create_scope",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        base_url: "http://127.0.0.1:1/",
      },
    },
  ],
  [
    "list_scopes",
    { request: { project_id: "00000000-0000-0000-0000-000000000000" } },
  ],
  ["tool_health", {}],
  ["list_catalog", {}],
  [
    "ensure_target",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        base_url: "http://127.0.0.1:1/",
      },
    },
  ],
  [
    "run_catalog_tool",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        tool_id: "curl",
        target_url: "http://127.0.0.1:1/",
        form: {},
      },
    },
  ],
  ["tool_pack_health", {}],
  [
    "external_launcher_health",
    { request: { project_id: "00000000-0000-0000-0000-000000000000" } },
  ],
  [
    "payload_source_health",
    { request: { project_id: "00000000-0000-0000-0000-000000000000" } },
  ],
  [
    "list_payloads",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        source_id: null,
        query: "",
        cursor: null,
        limit: 20,
      },
    },
  ],
  [
    "preview_payload",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        payload_id: "0".repeat(64),
        offset: 0,
        limit: 1,
      },
    },
  ],
  [
    "launch_external",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        scope_id: "00000000-0000-0000-0000-000000000000",
        launcher: "ant_sword",
        target_url: "http://127.0.0.1:1/",
        confirmation:
          "LAUNCH EXTERNAL antsword 00000000-0000-0000-0000-000000000000",
      },
    },
  ],
  [
    "run_tool",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        scope_id: "00000000-0000-0000-0000-000000000000",
        tool: "curl",
        target_url: "http://127.0.0.1:1/",
        wordlist_terms: [],
      },
    },
  ],
  [
    "cancel_job",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        job_id: "00000000-0000-0000-0000-000000000000",
      },
    },
  ],
  [
    "cancel_all_jobs",
    { request: { project_id: "00000000-0000-0000-0000-000000000000" } },
  ],
  [
    "delete_job",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        job_id: "00000000-0000-0000-0000-000000000000",
      },
    },
  ],
  [
    "clear_jobs",
    { request: { project_id: "00000000-0000-0000-0000-000000000000" } },
  ],
  [
    "list_jobs",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        cursor: null,
        limit: 20,
      },
    },
  ],
  [
    "preview_job_log",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        job_id: "00000000-0000-0000-0000-000000000000",
        stream: "stdout",
        offset: 0,
        limit: 1,
      },
    },
  ],
  [
    "preview_job_file",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        job_id: "00000000-0000-0000-0000-000000000000",
        filename: "ffuf-output.json",
        limit: 1,
      },
    },
  ],
  [
    "list_discoveries",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        cursor: null,
        limit: 20,
      },
    },
  ],
  [
    "create_dictionary",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        name: "probe",
        content: "probe\n",
      },
    },
  ],
  [
    "list_dictionaries",
    { request: { project_id: "00000000-0000-0000-0000-000000000000" } },
  ],
  [
    "search_dictionary",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        dictionary_id: "00000000-0000-0000-0000-000000000000",
        prefix: "p",
        limit: 10,
      },
    },
  ],
  [
    "export_project",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        confirm_sensitive: false,
      },
    },
  ],
  ["list_import_packages", {}],
  ["import_project", { request: { archive_name: "probe.flagdeck.zip" } }],
  [
    "start_http_proxy",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        scope_id: "00000000-0000-0000-0000-000000000000",
        capture_mode: "pass_through",
        ssl_insecure: false,
        launch_browser: false,
      },
    },
  ],
  [
    "stop_http_proxy",
    { request: { project_id: "00000000-0000-0000-0000-000000000000" } },
  ],
  [
    "http_proxy_status",
    { request: { project_id: "00000000-0000-0000-0000-000000000000" } },
  ],
  [
    "list_http_history",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        cursor: null,
        limit: 20,
        query: null,
        source: null,
        direction: null,
        host: null,
        status_code: null,
      },
    },
  ],
  [
    "get_http_message",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        message_id: "00000000-0000-0000-0000-000000000000",
      },
    },
  ],
  [
    "repeat_http",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        scope_id: "00000000-0000-0000-0000-000000000000",
        parent_message_id: "00000000-0000-0000-0000-000000000000",
        method: "GET",
        path: "/",
        headers: [],
        body: [],
        ssl_insecure: false,
      },
    },
  ],
  [
    "diff_http",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        left_message_id: "00000000-0000-0000-0000-000000000000",
        right_message_id: "00000000-0000-0000-0000-000000000000",
      },
    },
  ],
  [
    "create_sqlmap_request",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        message_id: "00000000-0000-0000-0000-000000000000",
        confirm_sensitive: false,
      },
    },
  ],
  [
    "send_raw_http1",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        scope_id: "00000000-0000-0000-0000-000000000000",
        host: "127.0.0.1",
        port: 1,
        tls: false,
        ssl_insecure: false,
        wire_bytes: [71],
      },
    },
  ],
  [
    "open_http_browser_preview",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        message_id: "00000000-0000-0000-0000-000000000000",
      },
    },
  ],
  [
    "start_metasploit",
    { request: { project_id: "00000000-0000-0000-0000-000000000000" } },
  ],
  [
    "metasploit_status",
    { request: { project_id: "00000000-0000-0000-0000-000000000000" } },
  ],
  [
    "stop_metasploit",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        confirmation: null,
      },
    },
  ],
  [
    "search_metasploit_modules",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        query: "http",
      },
    },
  ],
  [
    "get_metasploit_options",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        module_type: "auxiliary",
        fullname: "scanner/http/http_version",
      },
    },
  ],
  [
    "execute_metasploit_module",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        scope_id: "00000000-0000-0000-0000-000000000000",
        module_type: "auxiliary",
        fullname: "scanner/http/http_version",
        execution_kind: "check",
        options: {},
        confirmation: "",
      },
    },
  ],
  [
    "list_metasploit_entities",
    { request: { project_id: "00000000-0000-0000-0000-000000000000" } },
  ],
  [
    "create_metasploit_console",
    { request: { project_id: "00000000-0000-0000-0000-000000000000" } },
  ],
  [
    "stop_metasploit_entity",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        entity_kind: "job",
        external_id: "1",
        confirmation: "STOP JOB 1",
      },
    },
  ],
  [
    "metasploit_console_command",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        console_id: "0",
        command: "help",
        confirmation: "CONSOLE 0",
      },
    },
  ],
  [
    "metasploit_session_command",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        session_id: "1",
        command: "whoami",
        confirmation: "SESSION 1",
      },
    },
  ],
  [
    "start_intruder",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        scope_id: "00000000-0000-0000-0000-000000000000",
        parent_message_id: "00000000-0000-0000-0000-000000000000",
        attack_mode: "sniper",
        positions: [
          {
            location: "form",
            name: "q",
            occurrence: 0,
            start: null,
            end: null,
          },
        ],
        dictionary_ids: ["00000000-0000-0000-0000-000000000000"],
        global_rate_per_second: 8,
        target_rate_per_second: 8,
        state_macro: null,
      },
    },
  ],
  [
    "start_upload_campaign",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        scope_id: "00000000-0000-0000-0000-000000000000",
        parent_message_id: "00000000-0000-0000-0000-000000000000",
        part_ordinal: 0,
        mutations: ["magic_bytes"],
        global_rate_per_second: 8,
        target_rate_per_second: 8,
        state_macro: null,
        verification: {
          mode: "none",
          path_extractor: null,
          expected_execution_marker: null,
        },
        confirmation: null,
      },
    },
  ],
  [
    "cancel_intruder_campaign",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        intruder_campaign_id: "00000000-0000-0000-0000-000000000000",
      },
    },
  ],
  [
    "resume_intruder_campaign",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        intruder_campaign_id: "00000000-0000-0000-0000-000000000000",
      },
    },
  ],
  [
    "list_intruder_campaigns",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        limit: 20,
      },
    },
  ],
  [
    "list_intruder_attempts",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        intruder_campaign_id: "00000000-0000-0000-0000-000000000000",
        cursor: null,
        limit: 20,
      },
    },
  ],
  [
    "parse_multipart_message",
    {
      request: {
        project_id: "00000000-0000-0000-0000-000000000000",
        message_id: "00000000-0000-0000-0000-000000000000",
      },
    },
  ],
] as const;

async function denied(
  command: string,
  payload: Record<string, unknown>,
): Promise<boolean> {
  try {
    await invoke(command, payload);
    return false;
  } catch {
    return true;
  }
}

async function run(): Promise<void> {
  const deniedCommands: string[] = [];
  for (const [command, payload] of attempts) {
    if (await denied(command, payload)) deniedCommands.push(command);
  }

  let localFile: "blocked" | "unexpected-allowed" = "blocked";
  try {
    await fetch("file:///etc/passwd");
    localFile = "unexpected-allowed";
  } catch {
    localFile = "blocked";
  }

  const status = document.getElementById("probe-status");
  if (!status) throw new Error("missing probe status element");
  status.textContent = JSON.stringify({
    deniedCommands,
    allIpcDenied: deniedCommands.length === attempts.length,
    localFile,
  });
  document.documentElement.dataset.ready = "true";
}

void run();
