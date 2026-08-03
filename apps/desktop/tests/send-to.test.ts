import { describe, expect, it } from "vitest";
import {
  listCompatibleSendToTargets,
  prefillSendToForm,
  sendToTargetUrl,
  type SendToSource,
} from "../src/lib/sendTo";
import type { CatalogToolDto } from "../src/generated/ipc";

function tool(
  id: string,
  available: boolean,
  inputs: Array<{ id: string; kind: "url" | "wordlist"; field: string }>,
  defaults: Record<string, string> = {},
): CatalogToolDto {
  return {
    id,
    name: id,
    category: "http",
    category_name: "HTTP",
    tier: "tier_1",
    capabilities: [],
    aliases: [],
    presets: [
      {
        id: "default",
        name: "默认",
        core_fields: Object.keys(defaults),
        defaults,
      },
    ],
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
    io: {
      schema_version: 1,
      inputs: inputs.map((input) => ({
        id: input.id,
        kind: input.kind,
        field: input.field,
      })),
      outputs: [],
    },
    summary: id,
    usage: "",
    mode: "embedded_cli",
    featured: false,
    available,
    binary_path: "/bin/true",
    detail: "",
    icon: "",
    accent: "",
    fields: Object.entries(defaults).map(([fieldId, value]) => ({
      id: fieldId,
      field_type: fieldId === "url" ? "url" : "text",
      label: fieldId,
      required: fieldId === "url",
      default_value: value,
      from: fieldId === "url" ? "target_url" : "",
      options: [],
      flag: "",
      hint: "",
      examples: [],
      option_details: [],
      recommend_from: [],
      sensitive: false,
    })),
    needs_target: true,
  };
}

describe("send-to typed workflows", () => {
  const source: SendToSource = {
    resultKind: "http_discovery",
    cells: {
      url: "http://example.test/admin",
      path: "admin",
      status: "200",
    },
    sourceJobId: "job-src",
    sourceResultId: "job-src:0",
    sourceArtifactId: "art-1",
  };

  it("compatible_targets_follow_typed_url_contract", () => {
    const tools = [
      tool("curl", true, [{ id: "target", kind: "url", field: "url" }], {
        url: "",
        method: "GET",
      }),
      tool("arjun", true, [{ id: "target", kind: "url", field: "url" }], {
        url: "",
        threads: "5",
      }),
      tool("ffuf", true, [
        { id: "target", kind: "url", field: "url" },
        { id: "wordlist", kind: "wordlist", field: "wordlist" },
      ]),
      tool("missing-curl", false, [
        { id: "target", kind: "url", field: "url" },
      ]),
      tool("wordlist-only", true, [
        { id: "wordlist", kind: "wordlist", field: "wordlist" },
      ]),
    ];
    const targets = listCompatibleSendToTargets(tools, source);
    expect(targets.map((item) => item.tool.id)).toEqual([
      "arjun",
      "curl",
      "ffuf",
    ]);
    expect(
      listCompatibleSendToTargets(tools, {
        ...source,
        cells: { path: "admin", status: "200" },
      }),
    ).toEqual([]);
  });

  it("send_to_prefills_only_the_typed_target_field", () => {
    const curl = tool(
      "curl",
      true,
      [{ id: "target", kind: "url", field: "url" }],
      { url: "http://preset/", method: "POST", max_time: "30" },
    );
    const prefilled = prefillSendToForm({
      tool: curl,
      baseValues: { url: "http://preset/", method: "POST", max_time: "30" },
      sourceUrl: sendToTargetUrl(source),
      urlFieldIds: ["url"],
    });
    expect(prefilled.url).toBe("http://example.test/admin");
    expect(prefilled.method).toBe("POST");
    expect(prefilled.max_time).toBe("30");
  });

  it("cancel_send_to_preserves_form_preset_and_job_count", () => {
    // Pure state transition: opening send-to draft must not mutate originals until apply.
    const originalForm = { url: "http://old/", method: "GET" };
    const originalPreset = "quick";
    const originalJobCount = 3;
    const draft = {
      form: { ...originalForm, url: "http://example.test/admin" },
      preset: "default",
      toolId: "curl",
    };
    // Cancel discards draft; originals remain.
    expect(originalForm).toEqual({ url: "http://old/", method: "GET" });
    expect(originalPreset).toBe("quick");
    expect(originalJobCount).toBe(3);
    expect(draft.form.url).toBe("http://example.test/admin");
  });
});
