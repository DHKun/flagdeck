import type { CatalogToolDto } from "../generated/ipc";

/**
 * 运行目标的优先级：表单里的 url / target / host 优先，其次（且工具需要目标时）用顶栏目标。
 * 从 App.svelte 的 contextTargetForRun 提出，成为可单测的纯函数。
 */
export function resolveRunTarget(
  tool: Pick<CatalogToolDto, "needs_target"> | null,
  formValues: Record<string, string>,
  topbarTarget: string,
): string {
  if (!tool) return topbarTarget.trim();
  const fromForm =
    formValues.url?.trim() ||
    formValues.target?.trim() ||
    formValues.host?.trim() ||
    "";
  if (fromForm) return fromForm;
  return tool.needs_target ? topbarTarget.trim() : "";
}

export interface RunPlan {
  /** 表单里有已填的敏感 argv 字段：强制升到 L3。 */
  hasSensitiveArgv: boolean;
  /** 确认层级：敏感 argv 强制 l3，否则用预览风险或工具声明的层级。 */
  tier: string;
  /** L3 需要用户逐字输入的确认短语。 */
  l3Phrase: string;
}

/** 由工具、当前表单与预览风险，算出运行前的确认计划。 */
export function buildRunPlan(
  tool: CatalogToolDto,
  formValues: Record<string, string>,
  previewRisk: string | undefined,
): RunPlan {
  const hasSensitiveArgv = tool.fields.some(
    (field) => field.sensitive && Boolean(formValues[field.id]),
  );
  const tier = hasSensitiveArgv
    ? "l3"
    : (previewRisk ?? tool.risk_level.toLowerCase());
  return { hasSensitiveArgv, tier, l3Phrase: `RUN CATALOG ${tool.id}` };
}

/** 工具是否声明了 host 字段：决定目标 URL 是整体替换还是只换主机名。 */
export function toolHasHostField(tool: CatalogToolDto): boolean {
  return tool.fields.some(
    (field) => field.id === "host" || field.field_type === "host",
  );
}

/**
 * 由确认后的目标、当前顶栏 URL 与工具是否有 host 字段，算出要写回顶栏的 URL 和
 * ensureTarget 用的 base_url。只换主机名时保留原有 scheme；URL 解析失败时回退到 `http://<target>/`。
 */
export function reconcileTargetUrl(
  contextTarget: string,
  currentUrl: string,
  hasHostField: boolean,
): { targetUrl: string; ensureBaseUrl: string } {
  const ensureBaseUrl = contextTarget.startsWith("http")
    ? contextTarget
    : `http://${contextTarget}/`;
  if (contextTarget.startsWith("http")) {
    return { targetUrl: contextTarget, ensureBaseUrl };
  }
  if (hasHostField) {
    try {
      const url = new URL(
        currentUrl.startsWith("http") ? currentUrl : `http://${currentUrl}/`,
      );
      url.hostname = contextTarget;
      return { targetUrl: url.toString(), ensureBaseUrl };
    } catch {
      return { targetUrl: `http://${contextTarget}/`, ensureBaseUrl };
    }
  }
  return { targetUrl: ensureBaseUrl, ensureBaseUrl };
}
