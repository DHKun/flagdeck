import type { CatalogToolDto } from "../generated/ipc";

/** 从 URL 或裸主机串里取出主机名。有 scheme 时用 URL 解析，否则去掉路径与端口。 */
export function hostFromTarget(value: string): string {
  const raw = value.trim();
  if (!raw) return "";
  try {
    if (raw.includes("://")) return new URL(raw).hostname;
  } catch {
    /* ignore */
  }
  return raw.replace(/\/.*$/, "").replace(/:\d+$/, "");
}

/**
 * 首次进入工具库时的自动选择回退链：偏好设置里的工具 → 首个 featured → 首个 available →
 * `dddd` → 目录里第一个。从 App.svelte 的 refresh 提出，成为可单测的纯函数。
 */
export function pickInitialTool(
  tools: CatalogToolDto[],
  preferredId: string | undefined,
): CatalogToolDto | undefined {
  const available = tools.filter((tool) => tool.available);
  const featured = available.filter((tool) => tool.featured);
  return (
    (preferredId ? tools.find((tool) => tool.id === preferredId) : undefined) ??
    featured[0] ??
    available[0] ??
    tools.find((tool) => tool.id === "dddd") ??
    tools[0]
  );
}

/**
 * 由工具、上次记住的表单值与顶栏目标，算出表单初值。url/host/target 类字段优先用顶栏目标
 * （host 字段取主机名），其次用记住的值，再次用字段默认值。从 App.svelte 的 applyToolDefaults 提出。
 */
export function computeToolDefaults(
  tool: CatalogToolDto,
  remembered: Record<string, string>,
  topbarTarget: string,
): Record<string, string> {
  const trimmed = topbarTarget.trim();
  const next: Record<string, string> = {};
  for (const field of tool.fields) {
    const saved = remembered[field.id];
    if (
      (field.from === "target_url" ||
        field.id === "url" ||
        field.id === "host" ||
        field.id === "target") &&
      trimmed
    ) {
      if (field.id === "host" || field.field_type === "host") {
        next[field.id] = hostFromTarget(topbarTarget);
      } else {
        next[field.id] = trimmed;
      }
    } else if (saved != null && saved !== "") {
      next[field.id] = saved;
    } else if (field.default_value) {
      next[field.id] = field.default_value;
    } else {
      next[field.id] = "";
    }
  }
  return next;
}
