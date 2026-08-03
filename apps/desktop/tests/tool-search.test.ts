import { describe, expect, it } from "vitest";

import type { CatalogToolDto } from "../src/generated/ipc";
import {
  capabilityLabel,
  searchTools,
  type ToolSearchFilters,
} from "../src/lib/toolSearch";

function catalogTool(overrides: Partial<CatalogToolDto>): CatalogToolDto {
  return {
    id: "tool",
    name: "tool",
    category: "misc",
    category_name: "其他",
    tier: "tier_2",
    capabilities: [],
    aliases: [],
    presets: [],
    field_groups: [],
    relations: [],
    risk_level: "l1",
    installation: {
      distribution: "",
      license: "",
      homepage: "",
      version: "",
      health_strategy: "",
      runtime: "",
      version_args: [],
      install_command: "",
      path_fix: "",
      wordlist_source: "",
      wordlist_install_command: "",
    },
    io: { schema_version: 0, inputs: [], outputs: [] },
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
    needs_target: false,
    ...overrides,
  };
}

const ffuf = catalogTool({
  id: "ffuf",
  name: "ffuf",
  category: "content_discovery",
  category_name: "内容发现",
  tier: "tier_1",
  capabilities: ["path_discovery"],
  aliases: ["扫目录", "路径发现", "目录扫描"],
  summary: "目录和路径模糊测试",
  usage: "使用字典扫描目标路径",
  fields: [
    {
      id: "threads",
      field_type: "number",
      label: "线程 -t",
      required: true,
      default_value: "40",
      from: "",
      options: [],
      flag: "-t",
      hint: "并发 worker 数",
      examples: ["40"],
      option_details: [],
      recommend_from: [],
      sensitive: false,
    },
  ],
});

const curl = catalogTool({
  id: "curl",
  name: "curl",
  category: "http",
  category_name: "HTTP",
  summary: "发送 HTTP 请求并查看响应",
});

const emptyFilters: ToolSearchFilters = {
  query: "",
  category: "",
  capability: "",
  tier: "",
  installation: "",
};

describe("toolSearch", () => {
  it.each(["扫目录", "路径发现", "ffuf"])(
    "ranks ffuf first for %s",
    (query) => {
      expect(searchTools([curl, ffuf], { ...emptyFilters, query })[0]?.id).toBe(
        "ffuf",
      );
    },
  );

  it("indexes Chinese capability terms, parameter words, and V1 name and summary", () => {
    expect(
      searchTools([curl, ffuf], {
        ...emptyFilters,
        query: capabilityLabel("path_discovery"),
      })[0]?.id,
    ).toBe("ffuf");
    expect(
      searchTools([curl, ffuf], { ...emptyFilters, query: "线程" })[0]?.id,
    ).toBe("ffuf");
    expect(
      searchTools([curl, ffuf], { ...emptyFilters, query: "curl" })[0]?.id,
    ).toBe("curl");
    expect(
      searchTools([curl, ffuf], {
        ...emptyFilters,
        query: "查看响应",
      })[0]?.id,
    ).toBe("curl");
  });

  it("combines category, capability, tier, and installation filters", () => {
    const missingTier2 = catalogTool({
      id: "gobuster",
      name: "gobuster",
      category: "content_discovery",
      category_name: "内容发现",
      tier: "tier_2",
      capabilities: ["path_discovery"],
      available: false,
    });
    const tools = [curl, missingTier2, ffuf];

    expect(
      searchTools(tools, {
        query: "",
        category: "content_discovery",
        capability: "path_discovery",
        tier: "tier_1",
        installation: "available",
      }).map((tool) => tool.id),
    ).toEqual(["ffuf"]);
    expect(
      searchTools(tools, {
        query: "",
        category: "content_discovery",
        capability: "path_discovery",
        tier: "tier_2",
        installation: "missing",
      }).map((tool) => tool.id),
    ).toEqual(["gobuster"]);
  });
});
