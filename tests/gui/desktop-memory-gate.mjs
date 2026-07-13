import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import process from "node:process";

const workspace = resolve(import.meta.dirname, "../..");
const application = process.env.TAURI_BINARY
  ? resolve(process.env.TAURI_BINARY)
  : resolve(workspace, "target/release/flagdeck-desktop");
const evidencePath = resolve(
  import.meta.dirname,
  "evidence/desktop-memory.json",
);
const runCount = Number(process.env.FLAGDECK_R7_MEMORY_RUNS ?? "10");
const privateBudgetKiB = 150 * 1024;

function percentile(values, quantile) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.max(0, Math.ceil(quantile * sorted.length) - 1)];
}

function distribution(values) {
  return {
    unit: "KiB",
    samples: values,
    minimum: Math.min(...values),
    p50: percentile(values, 0.5),
    p95: percentile(values, 0.95),
    maximum: Math.max(...values),
    mean: values.reduce((total, value) => total + value, 0) / values.length,
  };
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

async function processTable() {
  const table = new Map();
  for (const entry of await readdir("/proc")) {
    if (!/^\d+$/u.test(entry)) continue;
    try {
      const status = await readFile(`/proc/${entry}/status`, "utf8");
      table.set(Number(entry), {
        pid: Number(entry),
        parentPid: Number(status.match(/^PPid:\s+(\d+)$/mu)?.[1] ?? 0),
        name: status.match(/^Name:\s+(.+)$/mu)?.[1]?.trim() ?? "unknown",
      });
    } catch {
      // Processes may exit between directory and status reads.
    }
  }
  return table;
}

async function processTree(rootPid) {
  const table = await processTable();
  const selected = new Set([rootPid]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const record of table.values()) {
      if (selected.has(record.parentPid) && !selected.has(record.pid)) {
        selected.add(record.pid);
        changed = true;
      }
    }
  }
  const records = [];
  for (const pid of selected) {
    try {
      const rollup = await readFile(`/proc/${pid}/smaps_rollup`, "utf8");
      const metric = (name) =>
        Number(
          rollup.match(new RegExp(`^${name}:\\s+(\\d+)\\s+kB$`, "mu"))?.[1] ??
            0,
        );
      records.push({
        ...table.get(pid),
        rssKiB: metric("Rss"),
        pssKiB: metric("Pss"),
        privateKiB: metric("Private_Clean") + metric("Private_Dirty"),
      });
    } catch {
      // Short-lived helpers can exit after the tree snapshot.
    }
  }
  return {
    processCount: records.length,
    webProcessCount: records.filter(({ name }) => name === "WebKitWebProces")
      .length,
    rssKiB: records.reduce((total, record) => total + record.rssKiB, 0),
    pssKiB: records.reduce((total, record) => total + record.pssKiB, 0),
    privateKiB: records.reduce((total, record) => total + record.privateKiB, 0),
    rootPssKiB: records.find(({ pid }) => pid === rootPid)?.pssKiB ?? null,
    processes: records,
  };
}

async function waitForTree(rootPid) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const tree = await processTree(rootPid);
    if (tree.webProcessCount === 1) {
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 1_500));
      return processTree(rootPid);
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 80));
  }
  throw new Error("single-window WebKit process did not become ready");
}

async function stop(child) {
  if (child.exitCode !== null) return true;
  child.kill("SIGTERM");
  const exited = await Promise.race([
    new Promise((resolveExit) => child.once("exit", () => resolveExit(true))),
    new Promise((resolveTimeout) =>
      setTimeout(() => resolveTimeout(false), 5_000),
    ),
  ]);
  if (!exited) child.kill("SIGKILL");
  return exited;
}

if (!Number.isInteger(runCount) || runCount < 1 || runCount > 50) {
  throw new Error("FLAGDECK_R7_MEMORY_RUNS must be an integer in 1..=50");
}
await stat(application);
const runs = [];
for (let index = 1; index <= runCount; index += 1) {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "flagdeck-r7-memory-"));
  const workspacesRoot = join(temporaryRoot, "workspaces");
  const child = spawn(application, [], {
    cwd: workspace,
    env: {
      HOME: homedir(),
      LANG: "C.UTF-8",
      PATH: "/usr/bin:/bin",
      XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR,
      WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY,
      DISPLAY: process.env.DISPLAY,
      DBUS_SESSION_BUS_ADDRESS: process.env.DBUS_SESSION_BUS_ADDRESS,
      XDG_SESSION_TYPE: process.env.XDG_SESSION_TYPE,
      XDG_CURRENT_DESKTOP: process.env.XDG_CURRENT_DESKTOP,
      FLAGDECK_WORKSPACES_ROOT: workspacesRoot,
      RUST_BACKTRACE: "0",
      __NV_DISABLE_EXPLICIT_SYNC: "1",
    },
    stdio: "ignore",
  });
  try {
    const tree = await waitForTree(child.pid);
    const limits = await readFile(`/proc/${child.pid}/limits`, "utf8");
    const coreLimitLine = limits
      .split("\n")
      .find((line) => line.startsWith("Max core file size"));
    runs.push({
      index,
      tree,
      coreLimitZero:
        coreLimitLine?.trim().split(/\s+/u).slice(-3).join(" ") === "0 0 bytes",
    });
  } finally {
    const cleanupPassed = await stop(child);
    runs.at(-1).cleanupPassed = cleanupPassed;
    await rm(temporaryRoot, { recursive: true, force: true });
  }
  console.log(`FlagDeck R7 desktop memory run ${index}/${runCount}: PASS`);
}

const privateValues = runs.map(({ tree }) => tree.privateKiB);
const pssValues = runs.map(({ tree }) => tree.pssKiB);
const rssValues = runs.map(({ tree }) => tree.rssKiB);
const rootPssValues = runs.map(({ tree }) => tree.rootPssKiB);
const assertions = {
  privateResidentP95Le150MiB:
    percentile(privateValues, 0.95) <= privateBudgetKiB,
  oneWebProcessPerRun: runs.every(({ tree }) => tree.webProcessCount === 1),
  coreLimitZero: runs.every(({ coreLimitZero }) => coreLimitZero),
  cleanupPassed: runs.every(({ cleanupPassed }) => cleanupPassed),
};
const binary = await readFile(application);
const result = {
  schema: "flagdeck.desktop-memory.r7.v1",
  status: Object.values(assertions).every(Boolean) ? "PASS" : "FAIL",
  generatedAt: new Date().toISOString(),
  environment: {
    desktop: process.env.XDG_CURRENT_DESKTOP ?? "unknown",
    session: process.env.XDG_SESSION_TYPE ?? "unknown",
  },
  application,
  applicationSha256: createHash("sha256").update(binary).digest("hex"),
  runs: runCount,
  measurement:
    "single-window process-tree private resident memory; PSS and summed RSS are preserved as supporting distributions",
  privateBudgetKiB,
  privateResident: distribution(privateValues),
  proportionalSet: distribution(pssValues),
  summedRss: distribution(rssValues),
  rootProcessPss: distribution(rootPssValues),
  assertions,
  samples: runs,
};
await writePrivateJson(evidencePath, result);
console.log(
  `FlagDeck R7 desktop memory gate ${result.status}: ${evidencePath}`,
);
if (result.status !== "PASS") process.exitCode = 1;
