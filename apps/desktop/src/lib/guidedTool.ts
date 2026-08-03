import type {
  CatalogFormFieldDto,
  CatalogFormRelationDto,
  CatalogToolDto,
} from "../generated/ipc";

export type FieldLayout = {
  pinned: string[];
  hidden: string[];
  order: string[];
};

export type RelationNotice = {
  severity: "error" | "warning";
  message: string;
  fields: [string, string];
};

export type HelpSearchResult = {
  content: string;
  matchCount: number;
  truncated: boolean;
};

const inactiveValues = new Set(["", "no", "none", "false", "0", "unknown"]);

function normalize(value: string): string {
  return value.trim().toLocaleLowerCase();
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

export function splitMultiValue(value: string): string[] {
  return unique(value.split(",").map((item) => item.trim()));
}

export function toggleMultiValue(
  value: string,
  option: string,
  enabled: boolean,
): string {
  const current = splitMultiValue(value).filter((item) => item !== option);
  if (enabled) current.push(option);
  return current.join(",");
}

function effectiveValue(
  tool: CatalogToolDto,
  values: Record<string, string>,
  fieldId: string,
): string {
  const provided = values[fieldId];
  if (provided !== undefined) return provided.trim();
  return (
    tool.fields.find((field) => field.id === fieldId)?.default_value.trim() ??
    ""
  );
}

function valueMatches(value: string, expected: string): boolean {
  if (expected) return value === expected;
  return !inactiveValues.has(normalize(value));
}

function relationViolated(
  tool: CatalogToolDto,
  values: Record<string, string>,
  relation: CatalogFormRelationDto,
): boolean {
  const left = valueMatches(
    effectiveValue(tool, values, relation.field),
    relation.equals,
  );
  const right = valueMatches(
    effectiveValue(tool, values, relation.other),
    relation.other_equals,
  );
  if (relation.kind === "conflicts") return left && right;
  if (relation.kind === "requires") return left && !right;
  return false;
}

export function evaluateRelations(
  tool: CatalogToolDto | null,
  values: Record<string, string>,
): RelationNotice[] {
  if (!tool) return [];
  return tool.relations
    .filter((relation) => relationViolated(tool, values, relation))
    .map((relation) => ({
      severity: relation.severity === "warning" ? "warning" : "error",
      message: relation.message,
      fields: [relation.field, relation.other],
    }));
}

export function recommendedOptionValues(
  field: CatalogFormFieldDto,
  values: Record<string, string>,
  limit = 4,
): string[] {
  if (field.recommend_from.length === 0) return [];
  const contextTags = new Set(
    field.recommend_from.flatMap((source) => {
      const value = normalize(values[source] ?? "");
      return value && !inactiveValues.has(value)
        ? [`${normalize(source)}:${value}`]
        : [];
    }),
  );
  const ranked = field.option_details
    .map((option, index) => {
      const tags = option.tags.map(normalize);
      const contextual = tags.filter((tag) => contextTags.has(tag)).length;
      const generic = tags.includes("generic") ? 1 : 0;
      return { value: option.value, score: contextual * 10 + generic, index };
    })
    .filter((item) => item.score > 0)
    .sort(
      (left, right) => right.score - left.score || left.index - right.index,
    );
  return unique(ranked.map((item) => item.value)).slice(0, limit);
}

export function filterToolFields(
  fields: CatalogFormFieldDto[],
  query: string,
): CatalogFormFieldDto[] {
  const tokens = normalize(query).split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return fields;
  return fields.filter((field) => {
    const haystack = normalize(
      [
        field.id,
        field.label,
        field.flag,
        field.hint,
        ...field.examples,
        ...field.options,
        ...field.option_details.flatMap((option) => [
          option.value,
          option.label,
          option.summary,
          ...option.tags,
        ]),
      ].join(" "),
    );
    return tokens.every((token) => haystack.includes(token));
  });
}

export function arrangeToolFields(
  fields: CatalogFormFieldDto[],
  layout: FieldLayout | undefined,
  includeHidden: boolean,
): CatalogFormFieldDto[] {
  if (!layout) return fields;
  const hidden = new Set(layout.hidden);
  const pinned = new Set(layout.pinned);
  const order = new Map(layout.order.map((fieldId, index) => [fieldId, index]));
  return fields
    .filter((field) => includeHidden || !hidden.has(field.id))
    .map((field, index) => ({ field, index }))
    .sort((left, right) => {
      const pinDifference =
        Number(pinned.has(right.field.id)) - Number(pinned.has(left.field.id));
      if (pinDifference !== 0) return pinDifference;
      const leftOrder = order.get(left.field.id) ?? Number.MAX_SAFE_INTEGER;
      const rightOrder = order.get(right.field.id) ?? Number.MAX_SAFE_INTEGER;
      return leftOrder - rightOrder || left.index - right.index;
    })
    .map(({ field }) => field);
}

export function searchHelpText(
  source: string,
  query: string,
  maxLines = 180,
): HelpSearchResult {
  const lines = source.split(/\r?\n/);
  const tokens = normalize(query).split(/\s+/).filter(Boolean);
  if (tokens.length === 0) {
    return {
      content: lines.slice(0, maxLines).join("\n"),
      matchCount: 0,
      truncated: lines.length > maxLines,
    };
  }
  const matching = lines
    .map((line, index) => ({ line: normalize(line), index }))
    .filter(({ line }) => tokens.every((token) => line.includes(token)))
    .map(({ index }) => index);
  const selected = new Set<number>();
  for (const index of matching) {
    for (
      let cursor = Math.max(0, index - 1);
      cursor <= Math.min(lines.length - 1, index + 1);
      cursor += 1
    ) {
      selected.add(cursor);
    }
  }
  const indexes = [...selected].sort((left, right) => left - right);
  return {
    content: indexes
      .slice(0, maxLines)
      .map((index) => lines[index])
      .join("\n"),
    matchCount: matching.length,
    truncated: indexes.length > maxLines,
  };
}
