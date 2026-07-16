const STORAGE_KEY = "flagdeck.workbench.v1";

export type WorkbenchPrefs = {
  targetUrl: string;
  selectedToolId: string;
  /** toolId → fieldId → value */
  formByTool: Record<string, Record<string, string>>;
  recentToolIds: string[];
  jobFilterToolId: string;
  autoScrollLog: boolean;
};

const defaults: WorkbenchPrefs = {
  targetUrl: "http://127.0.0.1/",
  selectedToolId: "",
  formByTool: {},
  recentToolIds: [],
  jobFilterToolId: "",
  autoScrollLog: true,
};

export function loadWorkbenchPrefs(): WorkbenchPrefs {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...defaults, formByTool: {} };
    const parsed = JSON.parse(raw) as Partial<WorkbenchPrefs>;
    return {
      targetUrl:
        typeof parsed.targetUrl === "string" && parsed.targetUrl.trim()
          ? parsed.targetUrl
          : defaults.targetUrl,
      selectedToolId:
        typeof parsed.selectedToolId === "string" ? parsed.selectedToolId : "",
      formByTool:
        parsed.formByTool && typeof parsed.formByTool === "object"
          ? parsed.formByTool
          : {},
      recentToolIds: Array.isArray(parsed.recentToolIds)
        ? parsed.recentToolIds.filter(
            (id): id is string => typeof id === "string",
          )
        : [],
      jobFilterToolId:
        typeof parsed.jobFilterToolId === "string"
          ? parsed.jobFilterToolId
          : "",
      autoScrollLog:
        typeof parsed.autoScrollLog === "boolean" ? parsed.autoScrollLog : true,
    };
  } catch {
    return { ...defaults, formByTool: {} };
  }
}

export function saveWorkbenchPrefs(prefs: WorkbenchPrefs): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    // ignore quota / private mode
  }
}

export function rememberTool(prefs: WorkbenchPrefs, toolId: string): string[] {
  const next = [toolId, ...prefs.recentToolIds.filter((id) => id !== toolId)];
  return next.slice(0, 12);
}
