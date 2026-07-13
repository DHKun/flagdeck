import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, open, readFile, rename } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import process from "node:process";

const workspace = resolve(import.meta.dirname, "../../..");
const evidenceRoot = resolve(import.meta.dirname, "../evidence");
const runsRoot = resolve(evidenceRoot, "release-runs");
const webdriverGate = resolve(import.meta.dirname, "webdriver.mjs");
const application = resolve(workspace, "target/release/tauri-security-spike");
const tauriDriver = resolve(homedir(), ".cargo/bin/tauri-driver");
const webkitDriver = "/usr/bin/WebKitWebDriver";
const runCount = 10;

async function sha256(path) {
  const contents = await readFile(path);
  return createHash("sha256").update(contents).digest("hex");
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

function run(program, args, options = {}) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(program, args, {
      cwd: workspace,
      env: options.env ?? process.env,
      stdio: options.stdio ?? ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr?.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolveRun({ stdout, stderr });
        return;
      }
      rejectRun(
        new Error(
          `${program} exited code=${String(code)} signal=${String(signal)}\n${stdout}${stderr}`,
        ),
      );
    });
  });
}

function validate(result) {
  return (
    result.status === "PASS" &&
    result.main?.ping === "pong:flagdeck" &&
    result.main?.restrictedFile === "temporary fixture" &&
    result.main?.browserProbe?.localFile === "blocked" &&
    result.main?.browserProbe?.newWindowCountStable === true &&
    result.main?.browserProbe?.scriptMarker === false &&
    result.main?.hostileDom?.marker === false &&
    result.main?.hostileDom?.dangerousNodes === 0 &&
    result.main?.hostileDom?.isolationFrames === 1 &&
    result.main?.hostileDom?.fixtureCards === 6 &&
    result.main?.urlBeforeNavigation === result.main?.urlAfterNavigation &&
    result.main?.windowCountBefore === result.main?.windowCountAfter &&
    result.unprivilegedProbe?.pingIpc === "denied" &&
    result.unprivilegedProbe?.fileIpc === "denied" &&
    result.unprivilegedProbe?.localFile === "blocked"
  );
}

await mkdir(runsRoot, { recursive: true, mode: 0o700 });
const results = [];
for (let index = 1; index <= runCount; index += 1) {
  const runPath = resolve(
    runsRoot,
    `run-${String(index).padStart(2, "0")}.json`,
  );
  await run(process.execPath, [webdriverGate], {
    env: {
      ...process.env,
      TAURI_BINARY: application,
      TAURI_DRIVER: tauriDriver,
      TAURI_EVIDENCE: runPath,
    },
  });
  const result = JSON.parse(await readFile(runPath, "utf8"));
  if (!validate(result)) {
    throw new Error(`release run ${index} failed its result contract`);
  }
  results.push(result);
  console.log(`Tauri Release WebDriver run ${index}/${runCount}: PASS`);
}

const packageJson = JSON.parse(
  await readFile(resolve(import.meta.dirname, "../package.json"), "utf8"),
);
const cargoInstalls = JSON.parse(
  await readFile(resolve(homedir(), ".cargo/.crates2.json"), "utf8"),
).installs;
const driverInstall = Object.keys(cargoInstalls).find((name) =>
  name.startsWith("tauri-driver "),
);
const driverVersion = driverInstall?.match(/^tauri-driver ([^ ]+)/)?.[1];
if (!driverVersion) {
  throw new Error("tauri-driver version missing from Cargo install metadata");
}
const webkitVersion = (
  await run("/usr/bin/rpm", ["-q", "--qf", "%{VERSION}", "webkitgtk6.0"])
).stdout.trim();
const summary = {
  build_profile: "release",
  runs: runCount,
  passes: results.filter(validate).length,
  failures: results.filter((result) => !validate(result)).length,
  tauri: "2.11.5",
  tauri_build: "2.6.3",
  tauri_api: packageJson.dependencies["@tauri-apps/api"],
  tauri_cli: packageJson.devDependencies["@tauri-apps/cli"],
  tauri_driver: driverVersion,
  webkitgtk: webkitVersion,
  all_authorized_ping_succeeded: results.every(
    (result) => result.main.ping === "pong:flagdeck",
  ),
  all_authorized_restricted_file_reads_succeeded: results.every(
    (result) => result.main.restrictedFile === "temporary fixture",
  ),
  all_unprivileged_ipc_calls_denied: results.every(
    (result) =>
      result.unprivilegedProbe.pingIpc === "denied" &&
      result.unprivilegedProbe.fileIpc === "denied",
  ),
  all_local_file_fetches_blocked: results.every(
    (result) =>
      result.main.browserProbe.localFile === "blocked" &&
      result.unprivilegedProbe.localFile === "blocked",
  ),
  all_hostile_dom_previews_safe: results.every(
    (result) =>
      result.main.hostileDom.marker === false &&
      result.main.hostileDom.dangerousNodes === 0,
  ),
  all_remote_navigations_blocked: results.every(
    (result) =>
      result.main.urlBeforeNavigation === result.main.urlAfterNavigation,
  ),
  all_remote_new_windows_blocked: results.every(
    (result) => result.main.windowCountBefore === result.main.windowCountAfter,
  ),
  isolation_iframe_count_per_main_window: 1,
  test_only_graphics_environment: "__NV_DISABLE_EXPLICIT_SYNC=1",
  application_bytes: (await readFile(application)).byteLength,
  application_sha256: await sha256(application),
  tauri_driver_sha256: await sha256(tauriDriver),
  webkit_webdriver_sha256: await sha256(webkitDriver),
};

if (summary.passes !== runCount || summary.failures !== 0) {
  throw new Error("Tauri Release summary contains a failed run");
}
await writePrivateJson(resolve(evidenceRoot, "webdriver.json"), results.at(-1));
await writePrivateJson(resolve(evidenceRoot, "summary.json"), summary);
console.log(`Tauri Release WebDriver summary: ${runCount}/${runCount} PASS`);
