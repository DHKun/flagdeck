import { describe, expect, it } from "vitest";

import type { CatalogFormFieldDto, CatalogToolDto } from "../src/generated/ipc";
import {
  buildRunPlan,
  reconcileTargetUrl,
  resolveRunTarget,
  toolHasHostField,
} from "../src/lib/runPlanning";

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

describe("resolveRunTarget", () => {
  it("prefers form url/target/host over the topbar target", () => {
    expect(resolveRunTarget(tool(), { url: "http://a/" }, "http://b/")).toBe(
      "http://a/",
    );
    expect(resolveRunTarget(tool(), { target: "t" }, "http://b/")).toBe("t");
    expect(resolveRunTarget(tool(), { host: "h" }, "http://b/")).toBe("h");
  });

  it("falls back to the topbar only when the tool needs a target", () => {
    expect(
      resolveRunTarget(tool({ needs_target: true }), {}, " http://b/ "),
    ).toBe("http://b/");
    expect(
      resolveRunTarget(tool({ needs_target: false }), {}, "http://b/"),
    ).toBe("");
  });

  it("uses the trimmed topbar target when no tool is selected", () => {
    expect(resolveRunTarget(null, {}, "  http://b/  ")).toBe("http://b/");
  });
});

describe("buildRunPlan", () => {
  it("escalates to l3 when a filled sensitive field is present", () => {
    const t = tool({
      fields: [field("token", { sensitive: true })],
      risk_level: "L1",
    });
    const plan = buildRunPlan(t, { token: "secret" }, "l1");
    expect(plan.hasSensitiveArgv).toBe(true);
    expect(plan.tier).toBe("l3");
  });

  it("uses preview risk, then the tool risk_level, when no sensitive argv is filled", () => {
    const t = tool({
      risk_level: "L2",
      fields: [field("token", { sensitive: true })],
    });
    expect(buildRunPlan(t, {}, "l1").tier).toBe("l1");
    expect(buildRunPlan(t, {}, undefined).tier).toBe("l2");
  });

  it("builds the exact L3 confirmation phrase", () => {
    expect(buildRunPlan(tool({ id: "sqlmap" }), {}, "l3").l3Phrase).toBe(
      "RUN CATALOG sqlmap",
    );
  });
});

describe("toolHasHostField", () => {
  it("detects a host field by id or field_type", () => {
    expect(toolHasHostField(tool({ fields: [field("host")] }))).toBe(true);
    expect(
      toolHasHostField(tool({ fields: [field("x", { field_type: "host" })] })),
    ).toBe(true);
    expect(toolHasHostField(tool({ fields: [field("url")] }))).toBe(false);
  });
});

describe("reconcileTargetUrl", () => {
  it("passes an http target through unchanged", () => {
    expect(reconcileTargetUrl("http://t/", "http://old/", true)).toEqual({
      targetUrl: "http://t/",
      ensureBaseUrl: "http://t/",
    });
  });

  it("swaps only the hostname (keeping scheme and port) when the tool has a host field", () => {
    const result = reconcileTargetUrl(
      "example.com",
      "https://old:8443/path",
      true,
    );
    expect(result.targetUrl).toBe("https://example.com:8443/path");
    expect(result.ensureBaseUrl).toBe("http://example.com/");
  });

  it("wraps a bare host as http when the tool has no host field", () => {
    expect(reconcileTargetUrl("example.com", "http://old/", false)).toEqual({
      targetUrl: "http://example.com/",
      ensureBaseUrl: "http://example.com/",
    });
  });

  it("falls back to http://<target>/ when the current url cannot be parsed", () => {
    const result = reconcileTargetUrl("example.com", "::not a url::", true);
    expect(result.targetUrl).toBe("http://example.com/");
  });
});
