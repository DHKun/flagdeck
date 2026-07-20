import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import process from "node:process";

const workspace = resolve(import.meta.dirname, "../..");
const evidenceRoot = resolve(import.meta.dirname, "evidence");
const runsRoot = resolve(evidenceRoot, "release-runs");
const webdriverGate = resolve(import.meta.dirname, "webdriver.mjs");
const application = process.env.TAURI_BINARY
  ? resolve(process.env.TAURI_BINARY)
  : resolve(workspace, "target/release/flagdeck-desktop");
const packagePath = process.env.TAURI_PACKAGE
  ? resolve(process.env.TAURI_PACKAGE)
  : undefined;
const tauriDriver = process.env.TAURI_DRIVER
  ? resolve(process.env.TAURI_DRIVER)
  : resolve(homedir(), ".cargo/bin/tauri-driver");
const runCount = Number(process.env.FLAGDECK_R7_GUI_RUNS ?? "10");
const capability = JSON.parse(
  await readFile(
    resolve(
      workspace,
      "apps/desktop/src-tauri/capabilities/main-capability.json",
    ),
    "utf8",
  ),
);
const expectedCommands = capability.permissions
  .filter((permission) => permission.startsWith("allow-"))
  .map((permission) => permission.slice("allow-".length).replaceAll("-", "_"))
  .sort();

function allExpectedCommandsDenied(result) {
  const deniedCommands = result.unprivilegedProbe?.deniedCommands;
  return (
    Array.isArray(deniedCommands) &&
    JSON.stringify([...deniedCommands].sort()) ===
      JSON.stringify(expectedCommands)
  );
}

async function sha256(path) {
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
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

function run(program, args, environment) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(program, args, {
      cwd: workspace,
      env: environment,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (chunk) => {
      output += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      output += chunk.toString();
    });
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (code === 0) resolveRun(output);
      else
        rejectRun(
          new Error(
            `${program} exited code=${String(code)} signal=${String(signal)}\n${output}`,
          ),
        );
    });
  });
}

function percentile(values, quantile) {
  const sorted = [...values].sort((left, right) => left - right);
  const index = Math.ceil(quantile * sorted.length) - 1;
  return sorted[Math.max(0, index)];
}

function validate(result) {
  return (
    result.status === "PASS" &&
    result.main?.authorizedCoreLifecycle === true &&
    result.main?.hostileDom?.marker === false &&
    result.main?.hostileDom?.dangerousNodes === 0 &&
    result.main?.hostileDom?.isolationFrames === 1 &&
    result.main?.redactedPreview === true &&
    result.main?.credentialPersistenceDenied === true &&
    result.main?.artifactCount === result.main?.artifactCountAfterDenial &&
    result.main?.localFile === "blocked" &&
    result.main?.urlBeforeNavigation === result.main?.urlAfterNavigation &&
    result.main?.windowCountBefore === result.main?.windowCountAfter &&
    result.main?.automaticWorkspace === true &&
    result.unprivilegedProbe?.allIpcDenied === true &&
    allExpectedCommandsDenied(result) &&
    result.main?.catalogWorkbench?.catalogLoaded === true &&
    result.main?.catalogWorkbench?.toolCount > 0 &&
    result.main?.catalogWorkbench?.curlSelected === true &&
    result.main?.catalogWorkbench?.sensitiveInputPassword === true &&
    result.main?.preferenceEvidence?.targetDenied === true &&
    result.main?.preferenceEvidence?.formSecretDenied === true &&
    result.unprivilegedProbe?.localFile === "blocked" &&
    result.process?.coreLimitZero === true &&
    result.process?.argvContainsFixtureSecret === false &&
    result.process?.argvContainsRejectedCredential === false &&
    result.storage?.allModesPrivate === true &&
    result.storage?.importInboxPrivate === true &&
    result.storage?.forbiddenCredentialPersisted === false &&
    result.storage?.blobFilenameMatchesSha256 === true &&
    result.storage?.manifestMatchesBlob === true &&
    result.storage?.manifestState === "committed" &&
    result.storage?.temporaryFiles?.length === 0
  );
}

if (!Number.isInteger(runCount) || runCount < 1 || runCount > 50) {
  throw new Error("FLAGDECK_R7_GUI_RUNS must be an integer in 1..=50");
}
await stat(application);
await mkdir(runsRoot, { recursive: true, mode: 0o700 });
const results = [];
for (let index = 1; index <= runCount; index += 1) {
  const runPath = resolve(
    runsRoot,
    `run-${String(index).padStart(2, "0")}.json`,
  );
  const output = await run(process.execPath, [webdriverGate], {
    ...process.env,
    TAURI_BINARY: application,
    TAURI_DRIVER: tauriDriver,
    TAURI_EVIDENCE: runPath,
  });
  const result = JSON.parse(await readFile(runPath, "utf8"));
  if (!validate(result)) {
    throw new Error(`release run ${index} failed its evidence contract`);
  }
  results.push(result);
  process.stdout.write(output);
  console.log(`FlagDeck R7 Release run ${index}/${runCount}: PASS`);
}

const timings = results.map((result) => result.interactiveMillis);
const hotTimings = timings.length > 1 ? timings.slice(1) : timings;
const rssValues = results
  .map((result) => result.process.rssKiB)
  .filter((value) => Number.isFinite(value));
const processTreePssValues = results
  .map((result) => result.process.processTree?.pssKiB)
  .filter((value) => Number.isFinite(value));
const processTreeRssValues = results
  .map((result) => result.process.processTree?.rssKiB)
  .filter((value) => Number.isFinite(value));
const processTreePrivateValues = results
  .map((result) => result.process.processTree?.privateKiB)
  .filter((value) => Number.isFinite(value));
const binary = await stat(application);
const summary = {
  status: "PASS",
  buildProfile: "release",
  runs: runCount,
  passes: results.filter(validate).length,
  failures: results.filter((result) => !validate(result)).length,
  interactiveMillis: {
    minimum: Math.min(...timings),
    p50: percentile(timings, 0.5),
    p95: percentile(timings, 0.95),
    maximum: Math.max(...timings),
    measurement: "WebDriver session request through rendered Core-ready UI",
  },
  coldHotInteractiveMillis: {
    coldCandidate: timings[0],
    hotP50: percentile(hotTimings, 0.5),
    hotP95: percentile(hotTimings, 0.95),
    protocol:
      "first run after release build is the cold candidate; remaining isolated sessions are hot-cache runs",
  },
  securityProbeMainProcessRssKiB: {
    p50: percentile(rssValues, 0.5),
    p95: percentile(rssValues, 0.95),
    maximum: Math.max(...rssValues),
  },
  securityProbeProcessTree: {
    pssKiB: {
      p50: percentile(processTreePssValues, 0.5),
      p95: percentile(processTreePssValues, 0.95),
      maximum: Math.max(...processTreePssValues),
    },
    rssKiB: {
      p50: percentile(processTreeRssValues, 0.5),
      p95: percentile(processTreeRssValues, 0.95),
      maximum: Math.max(...processTreeRssValues),
    },
    privateKiB: {
      p50: percentile(processTreePrivateValues, 0.5),
      p95: percentile(processTreePrivateValues, 0.95),
      maximum: Math.max(...processTreePrivateValues),
    },
    measurement:
      "two-window security-probe process tree; Stable single-window budget is measured separately",
  },
  allCustomCommandsDeniedFromProbe: results.every(allExpectedCommandsDenied),
  allHostilePreviewsDataOnly: results.every(
    (result) => result.main.hostileDom.dangerousNodes === 0,
  ),
  allCatalogWorkbenchesReady: results.every(
    (result) =>
      result.main.catalogWorkbench.catalogLoaded &&
      result.main.catalogWorkbench.curlSelected &&
      result.main.catalogWorkbench.sensitiveInputPassword,
  ),
  allSensitivePreferencesDenied: results.every(
    (result) =>
      result.main.preferenceEvidence.targetDenied &&
      result.main.preferenceEvidence.formSecretDenied,
  ),
  allCredentialsRejectedWithoutPersistence: results.every(
    (result) =>
      result.main.credentialPersistenceDenied &&
      !result.storage.forbiddenCredentialPersisted,
  ),
  allWorkspaceEntriesPrivate: results.every(
    (result) => result.storage.allModesPrivate,
  ),
  allImportInboxesPrivate: results.every(
    (result) => result.storage.importInboxPrivate,
  ),
  allArtifactHashesVerified: results.every(
    (result) =>
      result.storage.blobFilenameMatchesSha256 &&
      result.storage.manifestMatchesBlob,
  ),
  allCoreLimitsZero: results.every((result) => result.process.coreLimitZero),
  applicationBytes: binary.size,
  applicationSha256: await sha256(application),
  packagePath,
  packageBytes: packagePath ? (await stat(packagePath)).size : null,
  packageSha256: packagePath ? await sha256(packagePath) : null,
  tauriDriverSha256: await sha256(tauriDriver),
  generatedAt: new Date().toISOString(),
};
await writePrivateJson(resolve(evidenceRoot, "webdriver.json"), results.at(-1));
await writePrivateJson(resolve(evidenceRoot, "summary.json"), summary);
console.log(
  `FlagDeck R7 Release WebDriver summary: ${runCount}/${runCount} PASS`,
);
