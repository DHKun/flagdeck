import type {
  CatalogToolDto,
  PersonalPresetDto,
  PersonalPresetStoreDto,
} from "../generated/ipc";

const SCHEMA_VERSION = 1;
const MAX_PRESETS = 200;
const MAX_NAME_LENGTH = 80;
const MAX_VALUE_LENGTH = 16_384;

export type PersonalPreset = PersonalPresetDto;
export type PersonalPresetStore = PersonalPresetStoreDto;

type CreatePersonalPresetInput = {
  id?: string;
  name: string;
  basePresetId: string;
  values: Record<string, unknown>;
  now?: string;
};

export function emptyPersonalPresetStore(): PersonalPresetStore {
  return {
    schema_version: SCHEMA_VERSION,
    presets: [],
    default_by_tool: {},
  };
}

export function personalPresetsForTool(
  store: PersonalPresetStore,
  toolId: string,
): PersonalPreset[] {
  return store.presets.filter((preset) => preset.tool_id === toolId);
}

export function findPersonalPreset(
  store: PersonalPresetStore,
  presetId: string,
): PersonalPreset | undefined {
  return store.presets.find((preset) => preset.id === presetId);
}

export function resolveDefaultPresetId(
  store: PersonalPresetStore,
  tool: CatalogToolDto,
): string {
  const personalId = store.default_by_tool[tool.id];
  if (
    personalId &&
    store.presets.some(
      (preset) => preset.id === personalId && preset.tool_id === tool.id,
    )
  ) {
    return personalId;
  }
  return tool.presets[0]?.id ?? "";
}

/**
 * 应用个人预设时，算出它要基于的内置预设 ID：个人预设声明的 base 若在本工具里存在就用它，
 * 否则退到工具的第一个内置预设；非个人预设（即内置预设本身）直接返回它自己。
 */
export function resolvePresetBaseId(
  tool: CatalogToolDto,
  presetId: string,
  personal: PersonalPreset | undefined,
): string {
  if (!personal) return presetId;
  return tool.presets.some((preset) => preset.id === personal.base_preset_id)
    ? personal.base_preset_id
    : (tool.presets[0]?.id ?? "");
}

/** 当前选中的预设 ID 对该工具是否仍有效（是它的内置预设或个人预设之一）。 */
export function isPresetValidForTool(
  store: PersonalPresetStore,
  tool: CatalogToolDto,
  presetId: string,
): boolean {
  if (!presetId) return false;
  return (
    tool.presets.some((preset) => preset.id === presetId) ||
    personalPresetsForTool(store, tool.id).some(
      (preset) => preset.id === presetId,
    )
  );
}

export function createPersonalPreset(
  store: PersonalPresetStore,
  tool: CatalogToolDto,
  input: CreatePersonalPresetInput,
): PersonalPresetStore {
  if (store.presets.length >= MAX_PRESETS) {
    throw new Error(`个人预设最多保存 ${MAX_PRESETS} 个`);
  }
  const id = input.id ?? newPersonalPresetId(tool.id);
  validatePresetId(id);
  if (store.presets.some((preset) => preset.id === id)) {
    throw new Error("个人预设 ID 已存在");
  }
  validateName(input.name);
  validateBasePreset(tool, input.basePresetId);
  const now = input.now ?? new Date().toISOString();
  const preset: PersonalPreset = {
    id,
    tool_id: tool.id,
    name: input.name.trim(),
    base_preset_id: input.basePresetId,
    values: persistentValues(tool, input.values),
    created_at: now,
    updated_at: now,
  };
  return {
    ...store,
    presets: [...store.presets, preset],
  };
}

export function updatePersonalPreset(
  store: PersonalPresetStore,
  tool: CatalogToolDto,
  presetId: string,
  values: Record<string, unknown>,
  now = new Date().toISOString(),
): PersonalPresetStore {
  const current = requirePreset(store, presetId);
  if (current.tool_id !== tool.id) {
    throw new Error("个人预设与当前工具不匹配");
  }
  return {
    ...store,
    presets: store.presets.map((preset) =>
      preset.id === presetId
        ? {
            ...preset,
            values: persistentValues(tool, values),
            updated_at: now,
          }
        : preset,
    ),
  };
}

export function renamePersonalPreset(
  store: PersonalPresetStore,
  presetId: string,
  name: string,
  now = new Date().toISOString(),
): PersonalPresetStore {
  requirePreset(store, presetId);
  validateName(name);
  return {
    ...store,
    presets: store.presets.map((preset) =>
      preset.id === presetId
        ? { ...preset, name: name.trim(), updated_at: now }
        : preset,
    ),
  };
}

export function deletePersonalPreset(
  store: PersonalPresetStore,
  presetId: string,
): PersonalPresetStore {
  const current = requirePreset(store, presetId);
  const defaultByTool = { ...store.default_by_tool };
  if (defaultByTool[current.tool_id] === presetId) {
    delete defaultByTool[current.tool_id];
  }
  return {
    ...store,
    presets: store.presets.filter((preset) => preset.id !== presetId),
    default_by_tool: defaultByTool,
  };
}

export function setDefaultPersonalPreset(
  store: PersonalPresetStore,
  toolId: string,
  presetId: string | null,
): PersonalPresetStore {
  const defaultByTool = { ...store.default_by_tool };
  if (presetId === null) {
    delete defaultByTool[toolId];
  } else {
    const preset = requirePreset(store, presetId);
    if (preset.tool_id !== toolId) {
      throw new Error("个人预设与当前工具不匹配");
    }
    defaultByTool[toolId] = presetId;
  }
  return { ...store, default_by_tool: defaultByTool };
}

export function exportPersonalPresets(
  store: PersonalPresetStore,
  tools: CatalogToolDto[],
): string {
  const validated = parsePersonalPresetStore(JSON.stringify(store), tools);
  return JSON.stringify(validated, null, 2);
}

export function importPersonalPresets(
  raw: string,
  tools: CatalogToolDto[],
): PersonalPresetStore {
  return parsePersonalPresetStore(raw, tools);
}

function parsePersonalPresetStore(
  raw: string,
  tools: CatalogToolDto[],
): PersonalPresetStore {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("个人预设 JSON 无效");
  }
  const root = requireRecord(parsed, "个人预设包");
  assertExactKeys(
    root,
    ["schema_version", "presets", "default_by_tool"],
    "个人预设包",
  );
  if (root.schema_version !== SCHEMA_VERSION) {
    throw new Error(`不支持的个人预设版本：${String(root.schema_version)}`);
  }
  if (!Array.isArray(root.presets) || root.presets.length > MAX_PRESETS) {
    throw new Error(`个人预设列表无效，最多允许 ${MAX_PRESETS} 个`);
  }
  const toolById = new Map(tools.map((tool) => [tool.id, tool]));
  const seen = new Set<string>();
  const presets = root.presets.map((entry, index) => {
    const value = requireRecord(entry, `个人预设 ${index + 1}`);
    assertExactKeys(
      value,
      [
        "id",
        "tool_id",
        "name",
        "base_preset_id",
        "values",
        "created_at",
        "updated_at",
      ],
      `个人预设 ${index + 1}`,
    );
    const id = requireString(value.id, "个人预设 ID");
    validatePresetId(id);
    if (seen.has(id)) throw new Error(`个人预设 ID 重复：${id}`);
    seen.add(id);
    const toolId = requireString(value.tool_id, "工具 ID");
    const tool = toolById.get(toolId);
    if (!tool) throw new Error(`个人预设引用未知工具：${toolId}`);
    const name = requireString(value.name, "个人预设名称");
    validateName(name);
    const basePresetId = requireString(value.base_preset_id, "内置预设 ID");
    if (!basePresetId) throw new Error("内置预设 ID 不能为空");
    const values = validateImportedValues(tool, value.values);
    return {
      id,
      tool_id: toolId,
      name,
      base_preset_id: basePresetId,
      values,
      created_at: requireString(value.created_at, "创建时间"),
      updated_at: requireString(value.updated_at, "更新时间"),
    } satisfies PersonalPreset;
  });

  const defaultRecord = requireRecord(root.default_by_tool, "默认预设映射");
  const defaultByTool: Record<string, string> = {};
  for (const [toolId, presetIdValue] of Object.entries(defaultRecord)) {
    if (!toolById.has(toolId)) {
      throw new Error(`默认预设引用未知工具：${toolId}`);
    }
    const presetId = requireString(presetIdValue, "默认预设 ID");
    if (
      !presets.some(
        (preset) => preset.id === presetId && preset.tool_id === toolId,
      )
    ) {
      throw new Error(`默认预设引用无效：${toolId}/${presetId}`);
    }
    defaultByTool[toolId] = presetId;
  }

  return {
    schema_version: SCHEMA_VERSION,
    presets,
    default_by_tool: defaultByTool,
  };
}

function persistentValues(
  tool: CatalogToolDto,
  values: Record<string, unknown>,
): Record<string, string> {
  const fields = new Map(tool.fields.map((field) => [field.id, field]));
  const result: Record<string, string> = {};
  for (const [fieldId, raw] of Object.entries(values)) {
    const field = fields.get(fieldId);
    if (!field || field.sensitive || raw === "") continue;
    const text =
      typeof raw === "string"
        ? raw
        : typeof raw === "number" && Number.isFinite(raw)
          ? String(raw)
          : null;
    if (text === null || text.length > MAX_VALUE_LENGTH) {
      throw new Error(`字段值无效：${fieldId}`);
    }
    result[fieldId] = text;
  }
  return result;
}

function validateImportedValues(
  tool: CatalogToolDto,
  raw: unknown,
): Record<string, string> {
  const values = requireRecord(raw, "预设参数");
  const fields = new Map(tool.fields.map((field) => [field.id, field]));
  const result: Record<string, string> = {};
  for (const [fieldId, value] of Object.entries(values)) {
    const field = fields.get(fieldId);
    if (!field) throw new Error(`预设包含未知字段：${fieldId}`);
    if (field.sensitive) throw new Error(`预设包含敏感字段：${fieldId}`);
    const text = requireString(value, `字段 ${fieldId}`);
    if (text.length > MAX_VALUE_LENGTH) {
      throw new Error(`字段值过长：${fieldId}`);
    }
    result[fieldId] = text;
  }
  return result;
}

function validateBasePreset(tool: CatalogToolDto, presetId: string): void {
  if (!tool.presets.some((preset) => preset.id === presetId)) {
    throw new Error(`内置预设不存在：${presetId}`);
  }
}

function validatePresetId(id: string): void {
  if (!/^user:[a-z0-9][a-z0-9_-]{0,63}:[a-z0-9][a-z0-9_-]{0,63}$/.test(id)) {
    throw new Error("个人预设 ID 格式无效");
  }
}

function validateName(name: string): void {
  if (!name.trim() || name.trim().length > MAX_NAME_LENGTH) {
    throw new Error(`个人预设名称长度需为 1–${MAX_NAME_LENGTH} 个字符`);
  }
}

function requirePreset(
  store: PersonalPresetStore,
  presetId: string,
): PersonalPreset {
  const preset = store.presets.find((item) => item.id === presetId);
  if (!preset) throw new Error("个人预设不存在");
  return preset;
}

function newPersonalPresetId(toolId: string): string {
  const token =
    typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID().replaceAll("-", "").slice(0, 16)
      : `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  return `user:${toolId}:${token}`;
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label}必须是对象`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label}必须是字符串`);
  return value;
}

function assertExactKeys(
  value: Record<string, unknown>,
  allowed: string[],
  label: string,
): void {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    throw new Error(`${label}包含未知字段：${unknown.join(", ")}`);
  }
  const missing = allowed.filter((key) => !(key in value));
  if (missing.length > 0) {
    throw new Error(`${label}缺少字段：${missing.join(", ")}`);
  }
}
