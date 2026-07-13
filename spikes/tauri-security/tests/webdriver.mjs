import { spawn } from "node:child_process";
import { chmod, mkdir, open, rename } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import process from "node:process";

const webdriverUrl = "http://127.0.0.1:4444";
const workspace = resolve(import.meta.dirname, "../../..");
const application =
  process.env.TAURI_BINARY ??
  resolve(workspace, "target/release/tauri-security-spike");
const driverBinary =
  process.env.TAURI_DRIVER ?? resolve(homedir(), ".cargo/bin/tauri-driver");
const evidencePath = process.env.TAURI_EVIDENCE
  ? resolve(process.env.TAURI_EVIDENCE)
  : resolve(import.meta.dirname, "../evidence/webdriver.json");

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
  if (!response.ok || payload.value?.error) {
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
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
  }
  throw new Error(
    `${description} timed out${lastError ? `: ${lastError.message}` : ""}`,
  );
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
  if (!clicked) {
    throw new Error(`missing clickable element: ${selector}`);
  }
}

async function execute(script, args = []) {
  return request(`/session/${sessionId}/execute/sync`, "POST", {
    script,
    args,
  });
}

async function switchTo(handle) {
  await request(`/session/${sessionId}/window`, "POST", { handle });
}

async function currentUrl() {
  return request(`/session/${sessionId}/url`);
}

async function writeEvidence(value) {
  await mkdir(dirname(evidencePath), { recursive: true, mode: 0o700 });
  const temporary = `${evidencePath}.tmp`;
  const file = await open(temporary, "w", 0o600);
  try {
    await file.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await file.sync();
  } finally {
    await file.close();
  }
  await rename(temporary, evidencePath);
  await chmod(evidencePath, 0o600);
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
  const mainHandle = byTitle.get("FlagDeck Tauri Security Spike");
  const probeHandle = byTitle.get("FlagDeck Unprivileged Probe");
  if (!mainHandle || !probeHandle) {
    throw new Error(
      `unexpected window titles: ${JSON.stringify([...byTitle.keys()])}`,
    );
  }

  await switchTo(mainHandle);
  await click('[data-testid="ping-button"]');
  const ping = await waitFor("authorized ping", async () => {
    const value = await text('[data-testid="ping-result"]');
    return value === "pong:flagdeck" ? value : undefined;
  });
  await click('[data-testid="read-button"]');
  const restrictedFile = await waitFor("restricted file command", async () => {
    const value = await text('[data-testid="read-result"]');
    return value === "temporary fixture" ? value : undefined;
  });
  await click('[data-testid="browser-probe-button"]');
  const browserProbe = await waitFor("browser security probes", async () => {
    const value = await text('[data-testid="browser-probe-result"]');
    return value.includes('"localFile":"blocked"') ? value : undefined;
  });
  const hostileDom = await execute(
    "return { marker: Boolean(window.__FLAGDECK_PWNED__), dangerousNodes: document.querySelectorAll('svg, iframe:not(#__tauri_isolation__), img[onerror], script[data-fixture]').length, isolationFrames: document.querySelectorAll('iframe#__tauri_isolation__').length, fixtureCards: document.querySelectorAll('.fixture').length };",
  );
  if (
    hostileDom.marker ||
    hostileDom.dangerousNodes !== 0 ||
    hostileDom.isolationFrames !== 1 ||
    hostileDom.fixtureCards !== 6
  ) {
    throw new Error(
      `hostile fixture rendered unsafely: ${JSON.stringify(hostileDom)}`,
    );
  }

  const handlesBeforeWindowOpen = await request(
    `/session/${sessionId}/window/handles`,
  );
  await execute(
    "window.open('https://example.invalid/flagdeck-r0', '_blank'); return true;",
  );
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 300));
  const handlesAfterWindowOpen = await request(
    `/session/${sessionId}/window/handles`,
  );
  if (handlesAfterWindowOpen.length !== handlesBeforeWindowOpen.length) {
    throw new Error("remote window creation succeeded");
  }

  const urlBeforeNavigation = await currentUrl();
  await execute(
    "window.location.assign('https://example.invalid/flagdeck-r0'); return true;",
  );
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 300));
  const urlAfterNavigation = await currentUrl();
  if (urlAfterNavigation !== urlBeforeNavigation) {
    throw new Error(`remote navigation succeeded: ${urlAfterNavigation}`);
  }

  await switchTo(probeHandle);
  const probeStatusText = await waitFor("unprivileged IPC denial", async () => {
    const value = await text("#probe-status");
    return value.includes('"pingIpc":"denied"') &&
      value.includes('"fileIpc":"denied"')
      ? value
      : undefined;
  });

  await writeEvidence({
    status: "PASS",
    application,
    driver: driverBinary,
    windows: [...byTitle.keys()].sort(),
    main: {
      ping,
      restrictedFile,
      browserProbe: JSON.parse(browserProbe),
      hostileDom,
      urlBeforeNavigation,
      urlAfterNavigation,
      windowCountBefore: handlesBeforeWindowOpen.length,
      windowCountAfter: handlesAfterWindowOpen.length,
    },
    unprivilegedProbe: JSON.parse(probeStatusText),
    testEnvironment: {
      displayProtocol: process.env.WAYLAND_DISPLAY ? "wayland" : "x11",
      nvidiaExplicitSyncDisabledForDriver: true,
    },
  });
  console.log("Tauri WebDriver security gate: PASS");
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
}
