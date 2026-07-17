import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  readlink,
  realpath,
  rename,
  rm,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import process from "node:process";

const webdriverUrl = "http://127.0.0.1:4444";
const workspace = resolve(import.meta.dirname, "../..");
const application = process.env.TAURI_BINARY
  ? resolve(process.env.TAURI_BINARY)
  : resolve(workspace, "target/release/flagdeck-desktop");
const driverBinary =
  process.env.TAURI_DRIVER ?? resolve(homedir(), ".cargo/bin/tauri-driver");
const evidencePath = process.env.TAURI_EVIDENCE
  ? resolve(process.env.TAURI_EVIDENCE)
  : resolve(import.meta.dirname, "evidence/webdriver.json");
const temporaryRoot = await mkdtemp(join(tmpdir(), "flagdeck-r7-gui-"));
const workspacesRoot = join(temporaryRoot, "workspaces");
const forbiddenCredential = "should-never-persist-r7";
const hostileFixture = [
  "Authorization: Bearer flagdeck-secret-value",
  "Cookie: session=flagdeck-cookie-value",
  "<script data-fixture>window.__FLAGDECK_PWNED__=true</script>",
  '<img src=x onerror="window.__FLAGDECK_PWNED__=true">',
  '<iframe src="https://example.invalid"></iframe>',
  '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
  "token=flagdeck-token-value",
].join("\n");

let driverProcess;
let sessionId;
let driverLog = "";
let driverExitCode;

async function request(path, method = "GET", body) {
  const response = await fetch(`${webdriverUrl}${path}`, {
    method,
    headers:
      body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = await response.json();
  const protocolError =
    payload.value &&
    typeof payload.value === "object" &&
    typeof payload.value.error === "string" &&
    typeof payload.value.message === "string" &&
    "stacktrace" in payload.value;
  if (!response.ok || protocolError) {
    throw new Error(
      `WebDriver ${method} ${path}: ${JSON.stringify(payload.value)}`,
    );
  }
  return payload.value;
}

async function waitFor(description, predicate, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const value = await predicate();
      if (value) return value;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 80));
  }
  throw new Error(
    `${description} timed out${lastError ? `: ${lastError.message}` : ""}`,
  );
}

async function execute(script, args = []) {
  return request(`/session/${sessionId}/execute/sync`, "POST", {
    script,
    args,
  });
}

async function executeAsync(script, args = []) {
  return request(`/session/${sessionId}/execute/async`, "POST", {
    script,
    args,
  });
}

async function invokeMainResult(command, payload = {}) {
  return executeAsync(
    "const done = arguments[arguments.length - 1]; window.__TAURI_INTERNALS__.invoke(arguments[0], arguments[1]).then((value) => done({ ok: true, value })).catch((error) => done({ ok: false, error: typeof error === 'string' ? error : JSON.stringify(error) }));",
    [command, payload],
  );
}

async function invokeMain(command, payload = {}) {
  const result = await invokeMainResult(command, payload);
  if (!result.ok) {
    throw new Error(`IPC ${command} failed: ${result.error}`);
  }
  return result.value;
}

async function switchTo(handle) {
  await request(`/session/${sessionId}/window`, "POST", { handle });
}

async function text(selector) {
  return execute(
    "const element = document.querySelector(arguments[0]); return element ? element.textContent.trim() : null;",
    [selector],
  );
}

async function click(selector) {
  const clicked = await execute(
    "const element = document.querySelector(arguments[0]); if (!element) return false; element.click(); return true;",
    [selector],
  );
  if (!clicked) throw new Error(`missing clickable element: ${selector}`);
}

async function setValue(selector, value) {
  const changed = await execute(
    "const element = document.querySelector(arguments[0]); if (!element) return false; element.value = arguments[1]; element.dispatchEvent(new Event(element.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true })); return true;",
    [selector, value],
  );
  if (!changed) throw new Error(`missing input element: ${selector}`);
}

async function writePrivateJson(path, value) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp-${process.pid}`;
  const file = await open(temporary, "w", 0o600);
  try {
    await file.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await file.sync();
  } finally {
    await file.close();
  }
  await rename(temporary, path);
  await chmod(path, 0o600);
}

async function applicationProcessEvidence() {
  const expected = await realpath(application);
  const entries = await readdir("/proc");
  for (const entry of entries) {
    if (!/^\d+$/u.test(entry)) continue;
    const base = `/proc/${entry}`;
    try {
      if ((await readlink(`${base}/exe`)) !== expected) continue;
      const environment = await readFile(`${base}/environ`);
      if (!environment.includes(Buffer.from(workspacesRoot))) continue;
      const [limits, commandLine, status] = await Promise.all([
        readFile(`${base}/limits`, "utf8"),
        readFile(`${base}/cmdline`),
        readFile(`${base}/status`, "utf8"),
      ]);
      const rssMatch = status.match(/^VmRSS:\s+(\d+)\s+kB$/mu);
      const coreLimitLine = limits
        .split("\n")
        .find((line) => line.startsWith("Max core file size"));
      const coreLimitFields = coreLimitLine?.trim().split(/\s+/u) ?? [];
      const processTree = await processTreeEvidence(Number(entry));
      return {
        pid: Number(entry),
        coreLimitZero: coreLimitFields.slice(-3).join(" ") === "0 0 bytes",
        coreLimitLine,
        argvContainsFixtureSecret: commandLine.includes(
          Buffer.from("flagdeck-secret-value"),
        ),
        argvContainsRejectedCredential: commandLine.includes(
          Buffer.from(forbiddenCredential),
        ),
        rssKiB: rssMatch ? Number(rssMatch[1]) : null,
        processTree,
      };
    } catch {
      // Processes may exit while /proc is inspected.
    }
  }
  throw new Error("FlagDeck process was not found in /proc");
}

async function processTreeEvidence(rootPid) {
  const entries = (await readdir("/proc")).filter((entry) =>
    /^\d+$/u.test(entry),
  );
  const processes = new Map();
  for (const entry of entries) {
    try {
      const status = await readFile(`/proc/${entry}/status`, "utf8");
      const parent = status.match(/^PPid:\s+(\d+)$/mu);
      const name = status.match(/^Name:\s+(.+)$/mu);
      processes.set(Number(entry), {
        pid: Number(entry),
        parentPid: parent ? Number(parent[1]) : 0,
        name: name?.[1]?.trim() ?? "unknown",
      });
    } catch {
      // Processes may exit while /proc is inspected.
    }
  }
  const selected = new Set([rootPid]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const processRecord of processes.values()) {
      if (
        selected.has(processRecord.parentPid) &&
        !selected.has(processRecord.pid)
      ) {
        selected.add(processRecord.pid);
        changed = true;
      }
    }
  }
  const records = [];
  for (const pid of selected) {
    const processRecord = processes.get(pid);
    if (!processRecord) continue;
    try {
      const [rollup, commandLine] = await Promise.all([
        readFile(`/proc/${pid}/smaps_rollup`, "utf8"),
        readFile(`/proc/${pid}/cmdline`),
      ]);
      const metric = (name) => {
        const match = rollup.match(
          new RegExp(`^${name}:\\s+(\\d+)\\s+kB$`, "mu"),
        );
        return match ? Number(match[1]) : 0;
      };
      records.push({
        ...processRecord,
        command: commandLine
          .toString()
          .replaceAll("\0", " ")
          .trim()
          .slice(0, 512),
        rssKiB: metric("Rss"),
        pssKiB: metric("Pss"),
        privateKiB: metric("Private_Clean") + metric("Private_Dirty"),
        sharedKiB: metric("Shared_Clean") + metric("Shared_Dirty"),
      });
    } catch {
      // A short-lived process can disappear after the tree snapshot.
    }
  }
  return {
    processCount: records.length,
    rssKiB: records.reduce((total, record) => total + record.rssKiB, 0),
    pssKiB: records.reduce((total, record) => total + record.pssKiB, 0),
    privateKiB: records.reduce((total, record) => total + record.privateKiB, 0),
    sharedKiB: records.reduce((total, record) => total + record.sharedKiB, 0),
    processes: records,
  };
}

async function workspaceEvidence() {
  const rootEntries = await readdir(workspacesRoot);
  const projects = rootEntries.filter((entry) =>
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(
      entry,
    ),
  );
  if (projects.length !== 1) {
    throw new Error(
      `expected one project directory, received ${projects.length}`,
    );
  }
  const projectRoot = join(workspacesRoot, projects[0]);
  const importInbox = join(workspacesRoot, ".imports");
  let importInboxExists = true;
  let importInboxPrivate = false;
  try {
    const importInboxMetadata = await lstat(importInbox);
    importInboxPrivate =
      importInboxMetadata.isDirectory() &&
      !importInboxMetadata.isSymbolicLink() &&
      (importInboxMetadata.mode & 0o777) === 0o700;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    importInboxExists = false;
    importInboxPrivate = true;
  }
  const records = [];
  const forbidden = Buffer.from(forbiddenCredential);
  let forbiddenPersisted = false;
  let blobPath;
  let manifestPath;

  async function walk(path) {
    const metadata = await lstat(path);
    if (metadata.isSymbolicLink()) {
      throw new Error(`workspace symlink detected: ${path}`);
    }
    const mode = metadata.mode & 0o777;
    if ((mode & 0o077) !== 0) {
      throw new Error(
        `workspace mode is too broad: ${path} ${mode.toString(8)}`,
      );
    }
    records.push({
      path: relative(workspacesRoot, path),
      mode: mode.toString(8),
    });
    if (metadata.isDirectory()) {
      for (const entry of await readdir(path)) await walk(join(path, entry));
      return;
    }
    const contents = await readFile(path);
    forbiddenPersisted ||= contents.includes(forbidden);
    const relativePath = relative(projectRoot, path);
    if (relativePath.startsWith("blobs/sha256/")) blobPath = path;
    if (relativePath.startsWith("artifacts/")) manifestPath = path;
  }

  await walk(workspacesRoot);
  if (!blobPath || !manifestPath) {
    throw new Error("committed blob or Artifact manifest is missing");
  }
  const blob = await readFile(blobPath);
  const digest = createHash("sha256").update(blob).digest("hex");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const temporaryFiles = await readdir(join(projectRoot, "tmp"));
  return {
    projectId: projects[0],
    importInboxExists,
    importInboxPrivate,
    privateEntryCount: records.length,
    allModesPrivate: true,
    forbiddenCredentialPersisted: forbiddenPersisted,
    blobSha256: digest,
    blobFilenameMatchesSha256: blobPath.endsWith(`/${digest}`),
    manifestMatchesBlob: manifest.sha256 === digest,
    manifestState: manifest.state,
    temporaryFiles,
    representativeModes: Object.fromEntries(
      records
        .filter(({ path }) =>
          [
            "",
            projects[0],
            `${projects[0]}/project.sqlite`,
            `${projects[0]}/.flagdeck.lock`,
          ].includes(path),
        )
        .map(({ path, mode }) => [path || "workspaces", mode]),
    ),
  };
}

async function main() {
  driverProcess = spawn(driverBinary, [], {
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      HOME: process.env.HOME,
      LANG: "C.UTF-8",
      PATH: "/usr/bin:/bin",
      XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR,
      WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY,
      DISPLAY: process.env.DISPLAY,
      DBUS_SESSION_BUS_ADDRESS: process.env.DBUS_SESSION_BUS_ADDRESS,
      FLAGDECK_SECURITY_PROBE: "1",
      FLAGDECK_WORKSPACES_ROOT: workspacesRoot,
      RUST_BACKTRACE: "0",
      __NV_DISABLE_EXPLICIT_SYNC: "1",
    },
  });
  driverProcess.stdout.on("data", (chunk) => {
    driverLog += chunk.toString();
  });
  driverProcess.stderr.on("data", (chunk) => {
    driverLog += chunk.toString();
  });
  driverProcess.on("exit", (code) => {
    driverExitCode = code;
  });

  await waitFor("tauri-driver readiness", async () => {
    const response = await fetch(`${webdriverUrl}/status`).catch(
      () => undefined,
    );
    return response?.ok;
  });

  const sessionStarted = performance.now();
  const session = await request("/session", "POST", {
    capabilities: {
      alwaysMatch: {
        browserName: "wry",
        "tauri:options": { application },
      },
    },
  });
  sessionId = session.sessionId;
  const handles = await waitFor("two Tauri windows", async () => {
    const current = await request(`/session/${sessionId}/window/handles`);
    return current.length === 2 ? current : undefined;
  });
  const byTitle = new Map();
  for (const handle of handles) {
    await switchTo(handle);
    byTitle.set(await request(`/session/${sessionId}/title`), handle);
  }
  const mainHandle =
    byTitle.get("FlagDeck · Security Toolbox") ?? byTitle.get("FlagDeck");
  const probeHandle = byTitle.get("FlagDeck Unprivileged Probe");
  if (!mainHandle || !probeHandle) {
    throw new Error(
      `unexpected windows: ${JSON.stringify([...byTitle.keys()])}`,
    );
  }

  await switchTo(mainHandle);
  await waitFor("Core readiness", async () => {
    const value = await text('[data-testid="notice"]');
    return value?.includes("工作台已就绪") ? value : undefined;
  });
  const interactiveMillis = Math.round(performance.now() - sessionStarted);
  const workspaceUi = await waitFor("toolbox workspace", async () => {
    const value = await execute(
      "return { catalogRoot: document.querySelector('[data-testid=catalog-root]')?.textContent.trim(), target: Boolean(document.querySelector('#target-url')), toolsNavigation: Boolean(document.querySelector('[data-testid=nav-tools]')) };",
    );
    return value.catalogRoot && value.target && value.toolsNavigation
      ? value
      : undefined;
  });
  await click('[data-testid="nav-tools"]');
  await setValue("#target-url", "http://flagdeck-secret-value.invalid/");
  await setValue("#tool-query", "curl");
  await waitFor("curl catalog result", async () =>
    execute(
      "return Boolean(document.querySelector('[data-testid=tool-curl]'));",
    ),
  );
  await click('[data-testid="tool-curl"]');
  const catalogWorkbench = await waitFor("curl workbench", async () => {
    const value = await execute(
      "const cookie = document.querySelector('#field-cookie'); return { catalogLoaded: Boolean(document.querySelector('[data-testid=catalog-root]')), toolCount: document.querySelectorAll('[data-testid^=tool-]').length, curlSelected: document.querySelector('[data-testid=tool-runner] h2')?.textContent.trim() === 'curl', sensitiveInputPassword: cookie?.getAttribute('type') === 'password', runButton: Boolean(document.querySelector('[data-testid=run-selected-tool]')) };",
    );
    return value.catalogLoaded &&
      value.toolCount > 0 &&
      value.curlSelected &&
      value.sensitiveInputPassword &&
      value.runButton
      ? value
      : undefined;
  });
  await setValue("#field-cookie", "session=flagdeck-cookie-value");
  const preferenceEvidence = await execute(
    "const storage = window.localStorage; if (!storage) return { entries: 0, storageUnavailable: true, targetDenied: true, formSecretDenied: true }; const values = Array.from({ length: storage.length }, (_, index) => storage.getItem(storage.key(index))).filter(Boolean); const serialized = values.join('\\n'); return { entries: values.length, storageUnavailable: false, targetDenied: !serialized.includes('flagdeck-secret-value'), formSecretDenied: !serialized.includes('flagdeck-cookie-value') };",
  );
  if (
    !preferenceEvidence.targetDenied ||
    !preferenceEvidence.formSecretDenied
  ) {
    throw new Error(
      `sensitive preferences persisted: ${JSON.stringify(preferenceEvidence)}`,
    );
  }

  const status = await invokeMain("app_status");
  const projectId = status.active_project?.project_id;
  if (!projectId) throw new Error("automatic workspace is unavailable");
  const artifact = await invokeMain("create_note", {
    request: {
      project_id: projectId,
      logical_name: "hostile-fixture.txt",
      content: hostileFixture,
      sensitivity: "sensitive_evidence",
    },
  });
  const preview = await invokeMain("preview_artifact", {
    request: {
      project_id: projectId,
      artifact_id: artifact.artifact_id,
      offset: 0,
      limit: 64 * 1024,
      mode: "text",
    },
  });
  const previewText = preview.content;
  if (
    preview.redacted !== true ||
    previewText.includes("flagdeck-secret-value") ||
    previewText.includes("flagdeck-cookie-value") ||
    previewText.includes("flagdeck-token-value") ||
    !previewText.includes("<redacted>")
  ) {
    throw new Error("preview redaction contract failed");
  }
  await execute(
    "const preview = document.createElement('pre'); preview.dataset.testid = 'artifact-preview'; preview.textContent = arguments[0]; document.body.append(preview); return true;",
    [previewText],
  );
  const hostileDom = await execute(
    "return { marker: Boolean(window.__FLAGDECK_PWNED__), dangerousNodes: document.querySelectorAll('script[data-fixture], img[onerror], svg, iframe:not(#__tauri_isolation__)').length, isolationFrames: document.querySelectorAll('iframe#__tauri_isolation__').length, previewCount: document.querySelectorAll('[data-testid=artifact-preview]').length };",
  );
  if (
    hostileDom.marker ||
    hostileDom.dangerousNodes !== 0 ||
    hostileDom.isolationFrames !== 1 ||
    hostileDom.previewCount !== 1
  ) {
    throw new Error(`unsafe preview DOM: ${JSON.stringify(hostileDom)}`);
  }

  const artifactsBeforeDenial = await invokeMain("list_artifacts", {
    request: { project_id: projectId, cursor: null, limit: 100 },
  });
  const artifactCount = artifactsBeforeDenial.items.length;
  const credentialAttempt = await invokeMainResult("create_note", {
    request: {
      project_id: projectId,
      logical_name: "credential.txt",
      content: `password=${forbiddenCredential}`,
      sensitivity: "credential",
    },
  });
  if (
    credentialAttempt.ok ||
    !String(credentialAttempt.error).includes("credential_persistence_denied")
  ) {
    throw new Error(
      `credential persistence boundary failed: ${JSON.stringify(credentialAttempt)}`,
    );
  }
  const artifactsAfterDenial = await invokeMain("list_artifacts", {
    request: { project_id: projectId, cursor: null, limit: 100 },
  });
  const artifactCountAfterDenial = artifactsAfterDenial.items.length;
  if (artifactCountAfterDenial !== artifactCount) {
    throw new Error("credential denial created an Artifact row");
  }

  await execute(
    "window.__flagdeckFileProbe = 'pending'; fetch('file:///etc/passwd').then(() => { window.__flagdeckFileProbe = 'unexpected-allowed'; }).catch(() => { window.__flagdeckFileProbe = 'blocked'; }); return true;",
  );
  const localFile = await waitFor("local file denial", async () => {
    const value = await execute("return window.__flagdeckFileProbe;");
    return value === "blocked" ? value : undefined;
  });
  const handlesBeforeWindow = await request(
    `/session/${sessionId}/window/handles`,
  );
  await execute(
    "window.open('https://example.invalid/flagdeck-r1', '_blank'); return true;",
  );
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  const handlesAfterWindow = await request(
    `/session/${sessionId}/window/handles`,
  );
  const urlBeforeNavigation = await request(`/session/${sessionId}/url`);
  await execute(
    "window.location.assign('https://example.invalid/flagdeck-r1'); return true;",
  );
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  const urlAfterNavigation = await request(`/session/${sessionId}/url`);
  if (
    handlesAfterWindow.length !== handlesBeforeWindow.length ||
    urlAfterNavigation !== urlBeforeNavigation
  ) {
    throw new Error("remote navigation boundary failed");
  }

  const processEvidence = await applicationProcessEvidence();

  await switchTo(probeHandle);
  const probe = await waitFor("unprivileged IPC denial", async () => {
    const value = await text("#probe-status");
    if (!value) return undefined;
    const parsed = JSON.parse(value);
    return parsed.allIpcDenied && parsed.localFile === "blocked"
      ? parsed
      : undefined;
  });
  const storage = await workspaceEvidence();
  if (
    storage.forbiddenCredentialPersisted ||
    !storage.blobFilenameMatchesSha256 ||
    !storage.manifestMatchesBlob ||
    storage.manifestState !== "committed" ||
    storage.temporaryFiles.length !== 0 ||
    !processEvidence.coreLimitZero ||
    processEvidence.argvContainsFixtureSecret ||
    processEvidence.argvContainsRejectedCredential
  ) {
    throw new Error(
      `process or workspace evidence contract failed: ${JSON.stringify({ processEvidence, storage })}`,
    );
  }

  await writePrivateJson(evidencePath, {
    status: "PASS",
    application,
    driver: driverBinary,
    interactiveMillis,
    windows: [...byTitle.keys()].sort(),
    main: {
      authorizedCoreLifecycle: true,
      hostileDom,
      redactedPreview: true,
      credentialPersistenceDenied: true,
      catalogWorkbench,
      preferenceEvidence,
      workspaceUi,
      artifactCount,
      artifactCountAfterDenial,
      localFile,
      urlBeforeNavigation,
      urlAfterNavigation,
      windowCountBefore: handlesBeforeWindow.length,
      windowCountAfter: handlesAfterWindow.length,
      automaticWorkspace: true,
    },
    unprivilegedProbe: probe,
    process: processEvidence,
    storage,
    environment: {
      displayProtocol: process.env.WAYLAND_DISPLAY ? "wayland" : "x11",
      nvidiaExplicitSyncDisabledForDriver: true,
    },
  });
  console.log("FlagDeck R7 WebDriver security gate: PASS");
}

try {
  await main();
} catch (error) {
  console.error(`tauri-driver exit code: ${String(driverExitCode)}`);
  console.error(driverLog.slice(-8_000));
  throw error;
} finally {
  if (sessionId) {
    await request(`/session/${sessionId}`, "DELETE").catch(() => undefined);
  }
  if (driverProcess && !driverProcess.killed) {
    driverProcess.kill("SIGTERM");
    await Promise.race([
      new Promise((resolveExit) => driverProcess.once("exit", resolveExit)),
      new Promise((resolveDelay) => setTimeout(resolveDelay, 1_000)),
    ]);
  }
  await rm(temporaryRoot, { recursive: true, force: true });
}
