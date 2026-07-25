import type { CatalogToolDto } from "../generated/ipc";
import type { ToolIoKind } from "../generated/contracts";

export type SendToSource = {
  /** Output kind of the source structured result page. */
  resultKind: "http_discovery" | "raw_only" | "unknown" | string;
  /** Cell map from the selected structured result row. */
  cells: Record<string, string>;
  sourceJobId: string;
  sourceResultId: string;
  sourceArtifactId: string | null;
};

export type CompatibleTarget = {
  tool: CatalogToolDto;
  urlFieldIds: string[];
};

/** True when a catalog tool accepts a URL-typed input. */
export function toolAcceptsUrlInput(tool: CatalogToolDto): boolean {
  return tool.io.inputs.some((input) => input.kind === ("url" as ToolIoKind));
}

/**
 * Compatible send-to targets follow typed IO contracts:
 * - source exposes a URL cell (http_discovery rows)
 * - target is available and declares at least one url input
 * Hard-coded ffuf→curl lists are intentionally avoided.
 */
export function listCompatibleSendToTargets(
  tools: CatalogToolDto[],
  source: SendToSource,
): CompatibleTarget[] {
  const url = source.cells.url?.trim() || "";
  // Require a real URL cell so path-only rows are not silently treated as hosts.
  if (!url) return [];
  if (source.resultKind !== "http_discovery") {
    return [];
  }
  return tools
    .filter((tool) => tool.available && toolAcceptsUrlInput(tool))
    .map((tool) => ({
      tool,
      urlFieldIds: tool.io.inputs
        .filter((input) => input.kind === ("url" as ToolIoKind))
        .map((input) => input.field)
        .filter(Boolean),
    }))
    .filter((item) => item.urlFieldIds.length > 0)
    .sort((left, right) => left.tool.name.localeCompare(right.tool.name));
}

/**
 * Prefill only typed URL fields; other values come from the target preset/defaults.
 */
export function prefillSendToForm(options: {
  tool: CatalogToolDto;
  baseValues: Record<string, string>;
  sourceUrl: string;
  urlFieldIds: string[];
}): Record<string, string> {
  const next = { ...options.baseValues };
  const url = options.sourceUrl.trim();
  for (const fieldId of options.urlFieldIds) {
    next[fieldId] = url;
  }
  // Keep target_url bar aligned when the tool uses from=target_url.
  if (options.tool.fields.some((field) => field.from === "target_url")) {
    // form field already covered; caller may also set targetUrl
  }
  return next;
}

export function sendToTargetUrl(source: SendToSource): string {
  return (source.cells.url || "").trim();
}
