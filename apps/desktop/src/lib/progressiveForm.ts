import type { CatalogFormFieldDto, CatalogToolDto } from "../generated/ipc";

export type ProgressiveFormPlan = {
  visibleFields: CatalogFormFieldDto[];
  presetDefaults: Record<string, string>;
  advancedGroups: Array<{
    id: string;
    name: string;
    fields: CatalogFormFieldDto[];
  }>;
};

export function buildProgressiveForm(
  tool: CatalogToolDto,
  presetId: string,
  advancedExpanded: boolean,
): ProgressiveFormPlan {
  const preset = tool.presets.find((item) => item.id === presetId);
  if (!preset) {
    return {
      visibleFields: tool.fields,
      presetDefaults: {},
      advancedGroups: [],
    };
  }
  const coreFields = new Set(preset?.core_fields ?? []);
  const fieldById = new Map(tool.fields.map((field) => [field.id, field]));
  const orderedCoreFields = preset.core_fields
    .map((fieldId) => fieldById.get(fieldId))
    .filter((field): field is CatalogFormFieldDto => Boolean(field));
  const advancedGroups = advancedExpanded
    ? tool.field_groups
        .map((group) => ({
          id: group.id,
          name: group.name,
          fields: group.fields
            .filter((fieldId) => !coreFields.has(fieldId))
            .map((fieldId) => fieldById.get(fieldId))
            .filter((field): field is CatalogFormFieldDto => Boolean(field)),
        }))
        .filter((group) => group.fields.length > 0)
    : [];
  return {
    visibleFields: advancedExpanded
      ? [
          ...orderedCoreFields,
          ...advancedGroups.flatMap((group) => group.fields),
        ]
      : orderedCoreFields,
    presetDefaults: { ...preset?.defaults },
    advancedGroups,
  };
}
