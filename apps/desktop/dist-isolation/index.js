(() => {
  "use strict";

  const commands = new Set([
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
  ]);
  const uuid =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
  const object = (value) => value !== null && typeof value === "object";
  const boundedString = (value, maximum) =>
    typeof value === "string" && value.length <= maximum;
  const cursor = (value) => value === null || boundedString(value, 256);
  const page = (request) =>
    object(request) &&
    cursor(request.cursor) &&
    Number.isSafeInteger(request.limit) &&
    request.limit >= 1 &&
    request.limit <= 100;
  const projectId = (value) => typeof value === "string" && uuid.test(value);
  const archiveName = (value) =>
    boundedString(value, 255) &&
    value.endsWith(".flagdeck.zip") &&
    /^[A-Za-z0-9._-]+$/u.test(value);
  const bytes = (value) =>
    Array.isArray(value) &&
    value.length <= 1_048_576 &&
    value.every(
      (byte) => Number.isSafeInteger(byte) && byte >= 0 && byte <= 255,
    );
  const orderedValues = (value) =>
    Array.isArray(value) &&
    value.length <= 4096 &&
    value.every(
      (item) =>
        object(item) &&
        boundedString(item.name, 1024) &&
        item.name.length > 0 &&
        boundedString(item.value, 65_536),
    );
  const moduleIdentity = (request) =>
    boundedString(request.module_type, 32) &&
    request.module_type.length > 0 &&
    boundedString(request.fullname, 512) &&
    request.fullname.length > 0;
  const optionMap = (value) =>
    object(value) &&
    !Array.isArray(value) &&
    Object.keys(value).length <= 256 &&
    Object.keys(value).every((key) => /^[A-Za-z0-9_]{1,128}$/u.test(key));
  const rate = (value) =>
    Number.isSafeInteger(value) && value >= 1 && value <= 10_000;
  const uploadMutations = new Set([
    "extension_case",
    "double_extension",
    "trailing_character",
    "content_type",
    "filename_encoding",
    "magic_bytes",
    "image_polyglot",
    "extra_form_field",
  ]);
  const payloadPosition = (value) =>
    object(value) &&
    [
      "byte_range",
      "path",
      "header",
      "query",
      "form",
      "multipart_name",
      "multipart_filename",
      "multipart_body",
      "multipart_content_type",
    ].includes(value.location) &&
    (value.name == null || boundedString(value.name, 4096)) &&
    Number.isSafeInteger(value.occurrence) &&
    value.occurrence >= 0 &&
    (value.start == null || Number.isSafeInteger(value.start)) &&
    (value.end == null || Number.isSafeInteger(value.end));
  const tokenExtractor = (value) =>
    object(value) &&
    boundedString(value.variable, 64) &&
    value.variable.length > 0 &&
    ["response_body", "response_header"].includes(value.source) &&
    (value.header_name == null || boundedString(value.header_name, 256)) &&
    bytes(value.prefix) &&
    bytes(value.suffix) &&
    Number.isSafeInteger(value.maximum_length) &&
    value.maximum_length >= 1 &&
    value.maximum_length <= 4096;
  const stateMacro = (value) =>
    object(value) &&
    Array.isArray(value.steps) &&
    value.steps.length >= 1 &&
    value.steps.length <= 16 &&
    value.steps.every(
      (step) =>
        object(step) &&
        boundedString(step.name, 256) &&
        step.name.length > 0 &&
        projectId(step.message_id) &&
        Array.isArray(step.extractors) &&
        step.extractors.length <= 16 &&
        step.extractors.every(tokenExtractor),
    );

  window.__TAURI_ISOLATION_HOOK__ = (message) => {
    if (!object(message) || !commands.has(message.cmd)) {
      throw new Error("isolation rejected unknown command");
    }
    const payload = message.payload ?? {};
    if (!object(payload) || JSON.stringify(payload).length > 1_100_000) {
      throw new Error("isolation rejected malformed payload");
    }
    const request = payload.request;
    let valid = false;
    switch (message.cmd) {
      case "app_status":
      case "close_project":
      case "tool_health":
      case "tool_pack_health":
      case "list_import_packages":
        valid = Object.keys(payload).length === 0;
        break;
      case "create_project":
        valid =
          object(request) &&
          boundedString(request.name, 256) &&
          request.name.length > 0;
        break;
      case "list_projects":
        valid = page(request);
        break;
      case "open_project":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          ["read_write", "read_only"].includes(request.mode);
        break;
      case "create_note":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          boundedString(request.logical_name, 256) &&
          request.logical_name.length > 0 &&
          boundedString(request.content, 1_048_576) &&
          ["normal", "sensitive_evidence", "credential"].includes(
            request.sensitivity,
          );
        break;
      case "preview_artifact":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.artifact_id) &&
          Number.isSafeInteger(request.offset) &&
          request.offset >= 0 &&
          Number.isSafeInteger(request.limit) &&
          request.limit >= 1 &&
          request.limit <= 65_536 &&
          ["text", "hex"].includes(request.mode);
        break;
      case "list_artifacts":
        valid =
          object(request) && projectId(request.project_id) && page(request);
        break;
      case "create_scope":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          boundedString(request.base_url, 4096) &&
          request.base_url.length > 0;
        break;
      case "list_scopes":
      case "external_launcher_health":
      case "payload_source_health":
        valid = object(request) && projectId(request.project_id);
        break;
      case "list_payloads":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          (request.source_id === null ||
            boundedString(request.source_id, 64)) &&
          boundedString(request.query, 512) &&
          !/[\0\r\n]/u.test(request.query) &&
          cursor(request.cursor) &&
          Number.isSafeInteger(request.limit) &&
          request.limit >= 1 &&
          request.limit <= 500;
        break;
      case "preview_payload":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          typeof request.payload_id === "string" &&
          /^[0-9a-f]{64}$/u.test(request.payload_id) &&
          Number.isSafeInteger(request.offset) &&
          request.offset >= 0 &&
          Number.isSafeInteger(request.limit) &&
          request.limit >= 1 &&
          request.limit <= 65_536;
        break;
      case "launch_external":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.scope_id) &&
          ["shiro", "ysoserial", "ant_sword", "behinder", "godzilla"].includes(
            request.launcher,
          ) &&
          boundedString(request.target_url, 4096) &&
          request.target_url.length > 0 &&
          boundedString(request.confirmation, 256);
        break;
      case "run_tool":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.scope_id) &&
          [
            "curl",
            "dddd",
            "ffuf",
            "arjun",
            "fscan",
            "gobuster",
            "wafw00f",
          ].includes(request.tool) &&
          boundedString(request.target_url, 4096) &&
          request.target_url.length > 0 &&
          Array.isArray(request.wordlist_terms) &&
          request.wordlist_terms.length <= 256 &&
          request.wordlist_terms.every(
            (value) => boundedString(value, 128) && value.length > 0,
          );
        break;
      case "cancel_job":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.job_id);
        break;
      case "cancel_all_jobs":
      case "list_dictionaries":
        valid = object(request) && projectId(request.project_id);
        break;
      case "list_jobs":
      case "list_discoveries":
        valid =
          object(request) && projectId(request.project_id) && page(request);
        break;
      case "preview_job_log":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.job_id) &&
          ["stdout", "stderr"].includes(request.stream) &&
          Number.isSafeInteger(request.offset) &&
          request.offset >= 0 &&
          Number.isSafeInteger(request.limit) &&
          request.limit >= 1 &&
          request.limit <= 65_536;
        break;
      case "create_dictionary":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          boundedString(request.name, 256) &&
          request.name.length > 0 &&
          boundedString(request.content, 1_048_576) &&
          request.content.length > 0;
        break;
      case "search_dictionary":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.dictionary_id) &&
          boundedString(request.prefix, 512) &&
          Number.isSafeInteger(request.limit) &&
          request.limit >= 1 &&
          request.limit <= 100;
        break;
      case "export_project":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          typeof request.confirm_sensitive === "boolean";
        break;
      case "import_project":
        valid = object(request) && archiveName(request.archive_name);
        break;
      case "start_http_proxy":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.scope_id) &&
          ["pass_through", "evidence_strict"].includes(request.capture_mode) &&
          typeof request.ssl_insecure === "boolean" &&
          typeof request.launch_browser === "boolean";
        break;
      case "stop_http_proxy":
      case "http_proxy_status":
        valid = object(request) && projectId(request.project_id);
        break;
      case "list_http_history":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          page(request) &&
          (request.query === null || boundedString(request.query, 1024)) &&
          [null, "proxy", "repeater", "import", "tool"].includes(
            request.source,
          ) &&
          [null, "request", "response"].includes(request.direction) &&
          (request.host === null || boundedString(request.host, 253)) &&
          (request.status_code === null ||
            (Number.isSafeInteger(request.status_code) &&
              request.status_code >= 100 &&
              request.status_code <= 599));
        break;
      case "get_http_message":
      case "open_http_browser_preview":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.message_id);
        break;
      case "repeat_http":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.scope_id) &&
          projectId(request.parent_message_id) &&
          boundedString(request.method, 32) &&
          request.method.length > 0 &&
          boundedString(request.path, 65_536) &&
          request.path.length > 0 &&
          orderedValues(request.headers) &&
          bytes(request.body) &&
          typeof request.ssl_insecure === "boolean";
        break;
      case "diff_http":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.left_message_id) &&
          projectId(request.right_message_id);
        break;
      case "create_sqlmap_request":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.message_id) &&
          typeof request.confirm_sensitive === "boolean";
        break;
      case "send_raw_http1":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.scope_id) &&
          boundedString(request.host, 253) &&
          request.host.length > 0 &&
          Number.isSafeInteger(request.port) &&
          request.port >= 1 &&
          request.port <= 65_535 &&
          typeof request.tls === "boolean" &&
          typeof request.ssl_insecure === "boolean" &&
          bytes(request.wire_bytes) &&
          request.wire_bytes.length > 0;
        break;
      case "start_metasploit":
      case "metasploit_status":
      case "list_metasploit_entities":
      case "create_metasploit_console":
        valid = object(request) && projectId(request.project_id);
        break;
      case "stop_metasploit":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          (request.confirmation === null ||
            boundedString(request.confirmation, 64));
        break;
      case "search_metasploit_modules":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          boundedString(request.query, 512);
        break;
      case "get_metasploit_options":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          moduleIdentity(request);
        break;
      case "execute_metasploit_module":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.scope_id) &&
          moduleIdentity(request) &&
          ["check", "run", "exploit"].includes(request.execution_kind) &&
          optionMap(request.options) &&
          boundedString(request.confirmation, 600);
        break;
      case "metasploit_console_command":
      case "metasploit_session_command": {
        const idKey =
          message.cmd === "metasploit_console_command"
            ? "console_id"
            : "session_id";
        valid =
          object(request) &&
          projectId(request.project_id) &&
          boundedString(request[idKey], 128) &&
          request[idKey].length > 0 &&
          boundedString(request.command, 16_384) &&
          request.command.length > 0 &&
          boundedString(request.confirmation, 256);
        break;
      }
      case "stop_metasploit_entity":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          ["job", "console", "session"].includes(request.entity_kind) &&
          boundedString(request.external_id, 128) &&
          request.external_id.length > 0 &&
          boundedString(request.confirmation, 256);
        break;
      case "start_intruder":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.scope_id) &&
          projectId(request.parent_message_id) &&
          ["sniper", "battering_ram", "pitchfork", "cluster_bomb"].includes(
            request.attack_mode,
          ) &&
          Array.isArray(request.positions) &&
          request.positions.length >= 1 &&
          request.positions.length <= 16 &&
          request.positions.every(payloadPosition) &&
          Array.isArray(request.dictionary_ids) &&
          request.dictionary_ids.length <= 16 &&
          request.dictionary_ids.every(projectId) &&
          rate(request.global_rate_per_second) &&
          rate(request.target_rate_per_second) &&
          (request.state_macro == null || stateMacro(request.state_macro));
        break;
      case "start_upload_campaign":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.scope_id) &&
          projectId(request.parent_message_id) &&
          Number.isSafeInteger(request.part_ordinal) &&
          request.part_ordinal >= 0 &&
          Array.isArray(request.mutations) &&
          request.mutations.length >= 1 &&
          request.mutations.length <= 32 &&
          request.mutations.every((value) => uploadMutations.has(value)) &&
          rate(request.global_rate_per_second) &&
          rate(request.target_rate_per_second) &&
          (request.state_macro == null || stateMacro(request.state_macro)) &&
          object(request.verification) &&
          ["none", "safe_retrieval", "execution"].includes(
            request.verification.mode,
          ) &&
          (request.verification.path_extractor == null ||
            tokenExtractor(request.verification.path_extractor)) &&
          (request.confirmation == null ||
            boundedString(request.confirmation, 512));
        break;
      case "cancel_intruder_campaign":
      case "resume_intruder_campaign":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.intruder_campaign_id);
        break;
      case "list_intruder_campaigns":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          Number.isSafeInteger(request.limit) &&
          request.limit >= 1 &&
          request.limit <= 500;
        break;
      case "list_intruder_attempts":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.intruder_campaign_id) &&
          (request.cursor == null ||
            (Number.isSafeInteger(request.cursor) && request.cursor >= 0)) &&
          Number.isSafeInteger(request.limit) &&
          request.limit >= 1 &&
          request.limit <= 500;
        break;
      case "parse_multipart_message":
        valid =
          object(request) &&
          projectId(request.project_id) &&
          projectId(request.message_id);
        break;
    }
    if (!valid) throw new Error("isolation rejected invalid payload");
    return message;
  };
})();
