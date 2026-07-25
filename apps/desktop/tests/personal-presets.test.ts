import { describe, expect, it } from "vitest";

import type { CatalogToolDto } from "../src/generated/ipc";
import {
  createPersonalPreset,
  deletePersonalPreset,
  emptyPersonalPresetStore,
  exportPersonalPresets,
  importPersonalPresets,
  renamePersonalPreset,
  resolveDefaultPresetId,
  setDefaultPersonalPreset,
  updatePersonalPreset,
} from "../src/lib/personalPresets";

const ffuf = {
  id: "ffuf",
  presets: [
    {
      id: "quick",
      name: "快速扫描",
      core_fields: ["url", "wordlist"],
      defaults: { threads: "20" },
    },
  ],
  fields: [
    {
      id: "url",
      field_type: "text",
      label: "目标",
      required: true,
      default_value: "",
      from: "target_url",
      options: [],
      hint: "",
      sensitive: false,
    },
    {
      id: "threads",
      field_type: "number",
      label: "并发",
      required: false,
      default_value: "20",
      from: "",
      options: [],
      hint: "",
      sensitive: false,
    },
    {
      id: "authorization",
      field_type: "text",
      label: "Authorization",
      required: false,
      default_value: "",
      from: "",
      options: [],
      hint: "",
      sensitive: true,
    },
  ],
} as unknown as CatalogToolDto;

describe("personal presets", () => {
  it("creates, updates, renames, defaults, exports, imports and deletes a preset", () => {
    const created = createPersonalPreset(emptyPersonalPresetStore(), ffuf, {
      id: "user:ffuf:quick-local",
      name: "本地快速扫描",
      basePresetId: "quick",
      values: {
        url: "https://example.test/FUZZ",
        threads: 40,
        authorization: "Bearer secret",
      },
      now: "2026-07-25T00:00:00.000Z",
    });

    expect(created.presets[0]?.values).toEqual({
      url: "https://example.test/FUZZ",
      threads: "40",
    });

    const updated = updatePersonalPreset(
      created,
      ffuf,
      "user:ffuf:quick-local",
      {
        url: "https://updated.test/FUZZ",
        threads: "80",
        authorization: "Bearer newer-secret",
      },
      "2026-07-25T01:00:00.000Z",
    );
    const renamed = renamePersonalPreset(
      updated,
      "user:ffuf:quick-local",
      "高并发扫描",
      "2026-07-25T02:00:00.000Z",
    );
    const defaulted = setDefaultPersonalPreset(
      renamed,
      "ffuf",
      "user:ffuf:quick-local",
    );

    expect(resolveDefaultPresetId(defaulted, ffuf)).toBe(
      "user:ffuf:quick-local",
    );

    const exported = exportPersonalPresets(defaulted, [ffuf]);
    expect(exported).not.toContain("secret");
    expect(importPersonalPresets(exported, [ffuf])).toEqual(defaulted);

    const deleted = deletePersonalPreset(defaulted, "user:ffuf:quick-local");
    expect(deleted.presets).toEqual([]);
    expect(deleted.default_by_tool).toEqual({});
    expect(resolveDefaultPresetId(deleted, ffuf)).toBe("quick");
  });

  it("rejects unsupported versions, unknown fields and sensitive values on import", () => {
    const validPreset = {
      id: "user:ffuf:imported",
      tool_id: "ffuf",
      name: "导入预设",
      base_preset_id: "quick",
      values: { threads: "30" },
      created_at: "2026-07-25T00:00:00.000Z",
      updated_at: "2026-07-25T00:00:00.000Z",
    };

    expect(() =>
      importPersonalPresets(
        JSON.stringify({
          schema_version: 2,
          presets: [],
          default_by_tool: {},
        }),
        [ffuf],
      ),
    ).toThrow(/版本/);

    expect(() =>
      importPersonalPresets(
        JSON.stringify({
          schema_version: 1,
          presets: [{ ...validPreset, future_field: true }],
          default_by_tool: {},
        }),
        [ffuf],
      ),
    ).toThrow(/未知字段/);

    expect(() =>
      importPersonalPresets(
        JSON.stringify({
          schema_version: 1,
          presets: [
            {
              ...validPreset,
              values: { authorization: "Bearer imported-secret" },
            },
          ],
          default_by_tool: {},
        }),
        [ffuf],
      ),
    ).toThrow(/敏感字段/);
  });

  it("keeps personal presets independent from built-in preset upgrades", () => {
    const stored = createPersonalPreset(emptyPersonalPresetStore(), ffuf, {
      id: "user:ffuf:stable",
      name: "稳定个人预设",
      basePresetId: "quick",
      values: { threads: "60" },
      now: "2026-07-25T00:00:00.000Z",
    });
    const upgradedFfuf = {
      ...ffuf,
      presets: [
        {
          ...ffuf.presets[0],
          id: "quick-v2",
          name: "升级后的内置预设",
          defaults: { threads: "100" },
        },
      ],
    };

    expect(
      importPersonalPresets(exportPersonalPresets(stored, [ffuf]), [
        upgradedFfuf,
      ]),
    ).toEqual(stored);
  });

  it("restores the default personal preset from a persisted store", () => {
    const created = createPersonalPreset(emptyPersonalPresetStore(), ffuf, {
      id: "user:ffuf:restored",
      name: "启动时恢复",
      basePresetId: "quick",
      values: { threads: "70" },
      now: "2026-07-25T00:00:00.000Z",
    });
    const defaulted = setDefaultPersonalPreset(
      created,
      "ffuf",
      "user:ffuf:restored",
    );

    const restored = importPersonalPresets(
      exportPersonalPresets(defaulted, [ffuf]),
      [ffuf],
    );

    expect(resolveDefaultPresetId(restored, ffuf)).toBe("user:ffuf:restored");
    expect(restored).toEqual(defaulted);
  });
});
