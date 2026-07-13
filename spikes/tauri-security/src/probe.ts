import { invoke } from "@tauri-apps/api/core";

interface ProbeResult {
  pingIpc: "denied" | "unexpected-allowed";
  fileIpc: "denied" | "unexpected-allowed";
  localFile: "blocked" | "unexpected-allowed";
}

async function denied(
  command: string,
  argumentsValue: Record<string, string>,
): Promise<boolean> {
  try {
    await invoke(command, argumentsValue);
    return false;
  } catch {
    return true;
  }
}

async function run(): Promise<void> {
  const result: ProbeResult = {
    pingIpc: (await denied("ping", { input: "probe" }))
      ? "denied"
      : "unexpected-allowed",
    fileIpc: (await denied("read_fixture", { name: "safe.txt" }))
      ? "denied"
      : "unexpected-allowed",
    localFile: "blocked",
  };
  try {
    await fetch("file:///etc/passwd");
    result.localFile = "unexpected-allowed";
  } catch {
    result.localFile = "blocked";
  }
  const status = document.getElementById("probe-status");
  if (!status) {
    throw new Error("missing probe status element");
  }
  status.textContent = JSON.stringify(result);
  document.documentElement.dataset.ready = "true";
}

void run();
