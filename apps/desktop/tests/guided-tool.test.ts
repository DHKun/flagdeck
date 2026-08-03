import { describe, expect, it } from "vitest";

import type { CatalogFormFieldDto, CatalogToolDto } from "../src/generated/ipc";
import {
  arrangeToolFields,
  evaluateRelations,
  filterToolFields,
  recommendedOptionValues,
  searchHelpText,
  splitMultiValue,
  toggleMultiValue,
} from "../src/lib/guidedTool";

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
    id: "sqlmap",
    name: "sqlmap",
    category: "web_exploit",
    category_name: "Web",
    tier: "tier_1",
    capabilities: ["sqli"],
    aliases: ["SQL 注入"],
    presets: [],
    field_groups: [],
    relations: [],
    risk_level: "l3",
    installation: {} as CatalogToolDto["installation"],
    io: {} as CatalogToolDto["io"],
    summary: "",
    usage: "",
    mode: "embedded_cli",
    featured: true,
    available: true,
    binary_path: "/usr/bin/sqlmap",
    detail: "",
    icon: "",
    accent: "",
    fields: [],
    needs_target: true,
    ...overrides,
  };
}

describe("guided tool fields", () => {
  it("keeps multiselect argv values unique and ordered", () => {
    expect(splitMultiValue("between, space2comment,between")).toEqual([
      "between",
      "space2comment",
    ]);
    const selected = toggleMultiValue("between", "space2comment", true);
    expect(selected).toBe("between,space2comment");
    expect(toggleMultiValue(selected, "between", false)).toBe("space2comment");
  });

  it("ranks recommendations from declared DBMS and WAF tags", () => {
    const tamper = field("tamper", {
      field_type: "multiselect",
      recommend_from: ["dbms", "waf"],
      option_details: [
        {
          value: "between",
          label: "",
          summary: "",
          tags: ["generic", "dbms:mysql"],
        },
        {
          value: "modsecurityversioned",
          label: "",
          summary: "",
          tags: ["dbms:mysql", "waf:modsecurity"],
        },
        {
          value: "xforwardedfor",
          label: "",
          summary: "",
          tags: ["waf:nginx"],
        },
      ],
    });
    expect(
      recommendedOptionValues(tamper, { dbms: "MySQL", waf: "ModSecurity" }),
    ).toEqual(["modsecurityversioned", "between"]);
  });

  it("filters help and field metadata without changing source text", () => {
    const fields = [
      field("threads", { flag: "--threads", hint: "并发请求数" }),
      field("tamper", {
        flag: "--tamper",
        hint: "WAF 绕过脚本",
        examples: ["space2comment"],
      }),
    ];
    expect(
      filterToolFields(fields, "WAF space2comment").map((item) => item.id),
    ).toEqual(["tamper"]);
    const result = searchHelpText("first\n  --tamper=SCRIPT\nlast", "tamper");
    expect(result.matchCount).toBe(1);
    expect(result.content).toContain("--tamper=SCRIPT");
  });

  it("evaluates relation errors and applies personal field layout", () => {
    const fields = [field("url"), field("user_agent"), field("random_agent")];
    const sqlmap = tool({
      fields,
      relations: [
        {
          kind: "conflicts",
          field: "user_agent",
          equals: "",
          other: "random_agent",
          other_equals: "yes",
          severity: "error",
          message: "UA 冲突",
        },
      ],
    });
    expect(
      evaluateRelations(sqlmap, {
        user_agent: "FlagDeck",
        random_agent: "yes",
      }),
    ).toEqual([
      {
        severity: "error",
        message: "UA 冲突",
        fields: ["user_agent", "random_agent"],
      },
    ]);
    expect(
      arrangeToolFields(
        fields,
        {
          pinned: ["random_agent"],
          hidden: ["user_agent"],
          order: ["url", "user_agent", "random_agent"],
        },
        false,
      ).map((item) => item.id),
    ).toEqual(["random_agent", "url"]);
  });
});
