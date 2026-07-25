import type { CatalogToolDto } from "../generated/ipc";

export type InstallationFilter = "" | "available" | "missing";

export type ToolSearchFilters = {
  query: string;
  category: string;
  capability: string;
  tier: string;
  installation: InstallationFilter;
};

type CapabilityMetadata = {
  label: string;
  terms: string[];
};

const capabilityMetadata: Record<string, CapabilityMetadata> = {
  path_discovery: {
    label: "路径发现",
    terms: ["路径发现", "目录扫描", "扫目录", "路径扫描"],
  },
};

export function capabilityLabel(capability: string): string {
  return capabilityMetadata[capability]?.label ?? capability;
}

function normalize(value: string): string {
  return value.trim().toLocaleLowerCase();
}

function capabilityTerms(tool: CatalogToolDto): string[] {
  return tool.capabilities.flatMap((capability) => [
    capability,
    capabilityLabel(capability),
    ...(capabilityMetadata[capability]?.terms ?? []),
  ]);
}

function parameterTerms(tool: CatalogToolDto): string[] {
  return tool.fields.flatMap((field) => [
    field.id,
    field.label,
    field.hint,
    field.from,
    ...field.options,
  ]);
}

function tokenScore(tool: CatalogToolDto, token: string): number {
  const primary = [tool.id, tool.name].map(normalize);
  const aliases = tool.aliases.map(normalize);
  const capabilities = capabilityTerms(tool).map(normalize);
  const details = [
    tool.category,
    tool.category_name,
    tool.summary,
    tool.usage,
  ].map(normalize);
  const parameters = parameterTerms(tool).map(normalize);

  if (primary.includes(token)) return 1_000;
  if (aliases.includes(token)) return 900;
  if (capabilities.includes(token)) return 850;
  if (primary.some((value) => value.startsWith(token))) return 750;
  if (aliases.some((value) => value.startsWith(token))) return 700;
  if (capabilities.some((value) => value.startsWith(token))) return 650;
  if (primary.some((value) => value.includes(token))) return 600;
  if (aliases.some((value) => value.includes(token))) return 550;
  if (capabilities.some((value) => value.includes(token))) return 500;
  if (details.some((value) => value.includes(token))) return 300;
  if (parameters.some((value) => value.includes(token))) return 200;
  return 0;
}

function matchesFilters(
  tool: CatalogToolDto,
  filters: ToolSearchFilters,
): boolean {
  if (filters.category && tool.category !== filters.category) return false;
  if (filters.capability && !tool.capabilities.includes(filters.capability)) {
    return false;
  }
  if (filters.tier && tool.tier !== filters.tier) return false;
  if (filters.installation === "available" && !tool.available) return false;
  if (filters.installation === "missing" && tool.available) return false;
  return true;
}

export function searchTools(
  tools: CatalogToolDto[],
  filters: ToolSearchFilters,
): CatalogToolDto[] {
  const tokens = normalize(filters.query).split(/\s+/).filter(Boolean);
  const candidates = tools
    .map((tool, index) => ({ tool, index }))
    .filter(({ tool }) => matchesFilters(tool, filters));
  if (tokens.length === 0) return candidates.map(({ tool }) => tool);

  return candidates
    .map(({ tool, index }) => {
      const scores = tokens.map((token) => tokenScore(tool, token));
      return {
        tool,
        index,
        score: scores.every((score) => score > 0)
          ? scores.reduce((total, score) => total + score, 0)
          : 0,
      };
    })
    .filter(({ score }) => score > 0)
    .sort((left, right) => right.score - left.score || left.index - right.index)
    .map(({ tool }) => tool);
}
