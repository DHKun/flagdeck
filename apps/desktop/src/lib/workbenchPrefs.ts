import type { FieldLayout } from "./guidedTool";

const STORAGE_KEY = "flagdeck.workbench.v3";
const LEGACY_STORAGE_KEYS = ["flagdeck.workbench.v1", "flagdeck.workbench.v2"];

export type WorkbenchPrefs = {
  targetUrl: string;
  selectedToolId: string;
  /** toolId → fieldId → value */
  formByTool: Record<string, Record<string, string>>;
  fieldLayoutByTool: Record<string, FieldLayout>;
  recentToolIds: string[];
  jobFilterToolId: string;
  autoScrollLog: boolean;
};

const defaults: WorkbenchPrefs = {
  targetUrl: "http://127.0.0.1/",
  selectedToolId: "",
  formByTool: {},
  fieldLayoutByTool: {},
  recentToolIds: [],
  jobFilterToolId: "",
  autoScrollLog: true,
};

export function loadWorkbenchPrefs(): WorkbenchPrefs {
  try {
    const current = localStorage.getItem(STORAGE_KEY);
    const raw = current ?? localStorage.getItem("flagdeck.workbench.v2");
    localStorage.removeItem("flagdeck.workbench.v1");
    if (current) localStorage.removeItem("flagdeck.workbench.v2");
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
      fieldLayoutByTool:
        parsed.fieldLayoutByTool && typeof parsed.fieldLayoutByTool === "object"
          ? parsed.fieldLayoutByTool
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
    return { ...defaults, formByTool: {}, fieldLayoutByTool: {} };
  }
}

export function saveWorkbenchPrefs(prefs: WorkbenchPrefs): void {
  try {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        ...prefs,
        targetUrl: defaults.targetUrl,
      }),
    );
    for (const key of LEGACY_STORAGE_KEYS) localStorage.removeItem(key);
  } catch {
    // ignore quota / private mode
  }
}

export function rememberTool(prefs: WorkbenchPrefs, toolId: string): string[] {
  const next = [toolId, ...prefs.recentToolIds.filter((id) => id !== toolId)];
  return next.slice(0, 12);
}
