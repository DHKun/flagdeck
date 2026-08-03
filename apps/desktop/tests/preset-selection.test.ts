import { describe, expect, it } from "vitest";

import type { CatalogToolDto, PersonalPresetDto } from "../src/generated/ipc";
import {
  emptyPersonalPresetStore,
  isPresetValidForTool,
  resolvePresetBaseId,
} from "../src/lib/personalPresets";

function tool(presetIds: string[]): CatalogToolDto {
  return {
    id: "ffuf",
    name: "ffuf",
    category: "c",
    category_name: "c",
    tier: "tier_1",
    capabilities: [],
    aliases: [],
    presets: presetIds.map((id) => ({
      id,
      name: id,
      core_fields: [],
      defaults: {},
    })),
    field_groups: [],
    relations: [],
    risk_level: "L1",
    installation: {} as CatalogToolDto["installation"],
    io: {} as CatalogToolDto["io"],
    summary: "",
    usage: "",
    mode: "embedded_cli",
    featured: false,
    available: true,
    binary_path: "",
    detail: "",
    icon: "",
    accent: "",
    fields: [],
    needs_target: true,
  };
}

function personal(id: string, basePresetId: string): PersonalPresetDto {
  return {
    id,
    tool_id: "ffuf",
    name: id,
    base_preset_id: basePresetId,
    values: {},
    created_at: "",
    updated_at: "",
  };
}

describe("resolvePresetBaseId", () => {
  it("returns the preset id itself for a built-in preset", () => {
    expect(resolvePresetBaseId(tool(["quick"]), "quick", undefined)).toBe(
      "quick",
    );
  });

  it("uses the personal preset base when it exists on the tool", () => {
    expect(
      resolvePresetBaseId(
        tool(["quick", "deep"]),
        "p1",
        personal("p1", "deep"),
      ),
    ).toBe("deep");
  });

  it("falls back to the first built-in when the personal base is gone", () => {
    expect(
      resolvePresetBaseId(tool(["quick"]), "p1", personal("p1", "removed")),
    ).toBe("quick");
  });
});

describe("isPresetValidForTool", () => {
  it("is false for an empty selection", () => {
    expect(
      isPresetValidForTool(emptyPersonalPresetStore(), tool(["quick"]), ""),
    ).toBe(false);
  });

  it("is true for a built-in preset of the tool", () => {
    expect(
      isPresetValidForTool(
        emptyPersonalPresetStore(),
        tool(["quick"]),
        "quick",
      ),
    ).toBe(true);
  });

  it("is true for a personal preset of the tool", () => {
    const store = emptyPersonalPresetStore();
    store.presets.push(personal("p1", "quick"));
    expect(isPresetValidForTool(store, tool(["quick"]), "p1")).toBe(true);
  });

  it("is false for a preset that belongs to neither", () => {
    expect(
      isPresetValidForTool(emptyPersonalPresetStore(), tool(["quick"]), "gone"),
    ).toBe(false);
  });
});
