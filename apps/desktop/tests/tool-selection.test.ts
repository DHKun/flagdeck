import { describe, expect, it } from "vitest";

import type { CatalogFormFieldDto, CatalogToolDto } from "../src/generated/ipc";
import {
  computeToolDefaults,
  hostFromTarget,
  pickInitialTool,
} from "../src/lib/toolSelection";

function field(
  id: string,
  overrides: Partial<CatalogFormFieldDto> = {},
): CatalogFormFieldDto {
  return {
    id,
    field_type: "text",
    label: id,
    required: false,
    default_value: "",
    from: "",
    options: [],
    flag: "",
    hint: "",
    examples: [],
    option_details: [],
    recommend_from: [],
    sensitive: false,
    ...overrides,
  };
}

function tool(overrides: Partial<CatalogToolDto> = {}): CatalogToolDto {
  return {
    id: "ffuf",
    name: "ffuf",
    category: "c",
    category_name: "c",
    tier: "tier_1",
    capabilities: [],
    aliases: [],
    presets: [],
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
    ...overrides,
  };
}

describe("hostFromTarget", () => {
  it("extracts the hostname from a url with a scheme", () => {
    expect(hostFromTarget("https://example.com:8443/path")).toBe("example.com");
  });

  it("strips path and port from a bare host", () => {
    expect(hostFromTarget("example.com:80/a/b")).toBe("example.com");
  });

  it("returns empty for blank input", () => {
    expect(hostFromTarget("   ")).toBe("");
  });
});

describe("pickInitialTool", () => {
  const dddd = tool({ id: "dddd", available: true });
  const featured = tool({ id: "ffuf", available: true, featured: true });
  const plain = tool({ id: "curl", available: true });
  const unavailable = tool({ id: "x", available: false });

  it("prefers the tool named by the preference when present", () => {
    expect(pickInitialTool([dddd, featured, plain], "curl")?.id).toBe("curl");
  });

  it("falls back to the first featured tool when the preference is missing", () => {
    expect(pickInitialTool([plain, featured, dddd], "gone")?.id).toBe("ffuf");
  });

  it("falls back to the first available tool when nothing is featured", () => {
    expect(pickInitialTool([unavailable, plain], undefined)?.id).toBe("curl");
  });

  it("falls back to dddd, then the first tool", () => {
    expect(pickInitialTool([unavailable, dddd], undefined)?.id).toBe("dddd");
    expect(pickInitialTool([unavailable], undefined)?.id).toBe("x");
  });

  it("returns undefined for an empty catalog", () => {
    expect(pickInitialTool([], "anything")).toBeUndefined();
  });
});

describe("computeToolDefaults", () => {
  it("fills url/target fields from the trimmed topbar target", () => {
    const t = tool({ fields: [field("url", { from: "target_url" })] });
    expect(computeToolDefaults(t, {}, "  http://a/  ")).toEqual({
      url: "http://a/",
    });
  });

  it("fills a host field with only the hostname", () => {
    const t = tool({ fields: [field("host", { field_type: "host" })] });
    expect(computeToolDefaults(t, {}, "https://example.com:8443/x")).toEqual({
      host: "example.com",
    });
  });

  it("uses a remembered value when there is no live target", () => {
    const t = tool({ fields: [field("threads")] });
    expect(computeToolDefaults(t, { threads: "40" }, "")).toEqual({
      threads: "40",
    });
  });

  it("uses the field default when nothing else applies", () => {
    const t = tool({ fields: [field("mc", { default_value: "200" })] });
    expect(computeToolDefaults(t, {}, "")).toEqual({ mc: "200" });
  });
});
