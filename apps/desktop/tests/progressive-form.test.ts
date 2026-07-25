import { describe, expect, it } from "vitest";

import type { CatalogFormFieldDto, CatalogToolDto } from "../src/generated/ipc";
import { buildProgressiveForm } from "../src/lib/progressiveForm";

function field(id: string): CatalogFormFieldDto {
  return {
    id,
    field_type: "text",
    label: id,
    required: false,
    default_value: "",
    from: "",
    options: [],
    hint: "",
    sensitive: false,
  };
}

const ffuf: CatalogToolDto = {
  id: "ffuf",
  name: "ffuf",
  category: "content_discovery",
  category_name: "内容发现",
  tier: "tier_1",
  capabilities: ["path_discovery"],
  aliases: ["扫目录"],
  presets: [
    {
      id: "quick_scan",
      name: "快速扫描",
      core_fields: ["url", "wordlist", "threads", "mc"],
      defaults: { recursion: "no" },
    },
  ],
  field_groups: [
    {
      id: "target",
      name: "目标",
      fields: ["url", "wordlist"],
    },
    {
      id: "execution",
      name: "执行",
      fields: ["threads", "rate", "recursion"],
    },
  ],
  risk_level: "l2",
  installation: {
    distribution: "hybrid",
    license: "MIT",
    homepage: "",
    version: "",
    health_strategy: "",
  },
  io: { schema_version: 1, inputs: [], outputs: [] },
  summary: "",
  usage: "",
  mode: "embedded_cli",
  featured: true,
  available: true,
  binary_path: "/usr/bin/ffuf",
  detail: "",
  icon: "",
  accent: "",
  fields: [
    field("url"),
    field("wordlist"),
    field("threads"),
    field("mc"),
    field("rate"),
    field("recursion"),
  ],
  needs_target: true,
};

describe("buildProgressiveForm", () => {
  it("shows only quick scan core fields by default", () => {
    const plan = buildProgressiveForm(ffuf, "quick_scan", false);

    expect(plan.visibleFields.map((item) => item.id)).toEqual([
      "url",
      "wordlist",
      "threads",
      "mc",
    ]);
  });

  it("provides the selected preset defaults", () => {
    const plan = buildProgressiveForm(ffuf, "quick_scan", false);

    expect(plan.presetDefaults).toEqual({ recursion: "no" });
  });

  it("expands advanced fields in Catalog groups", () => {
    const plan = buildProgressiveForm(ffuf, "quick_scan", true);

    expect(
      plan.advancedGroups.map((group) => ({
        id: group.id,
        fields: group.fields.map((item) => item.id),
      })),
    ).toEqual([{ id: "execution", fields: ["rate", "recursion"] }]);
    expect(plan.visibleFields.map((item) => item.id)).toEqual([
      "url",
      "wordlist",
      "threads",
      "mc",
      "rate",
      "recursion",
    ]);
  });

  it("keeps every field visible for tools without presets", () => {
    const plan = buildProgressiveForm({ ...ffuf, presets: [] }, "", false);

    expect(plan.visibleFields.map((item) => item.id)).toEqual([
      "url",
      "wordlist",
      "threads",
      "mc",
      "rate",
      "recursion",
    ]);
  });
});
