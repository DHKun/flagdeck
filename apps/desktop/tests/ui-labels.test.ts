import { describe, expect, it } from "vitest";

import {
  executionStatusLabel,
  exportPolicyLabel,
  logStreamLabel,
  riskLevelLabel,
  sensitivityLabel,
  structuredResultKindLabel,
} from "../src/lib/uiLabels";

describe("ui labels", () => {
  it("renders execution and risk states in Chinese", () => {
    expect(executionStatusLabel("running")).toBe("运行中");
    expect(executionStatusLabel("timed_out")).toBe("超时");
    expect(riskLevelLabel("l3")).toBe("L3 · 高风险");
  });

  it("explains evidence policies without exposing raw enum values", () => {
    expect(sensitivityLabel("sensitive_evidence")).toBe("敏感证据");
    expect(exportPolicyLabel("confirm_sensitive")).toBe("导出前确认");
    expect(exportPolicyLabel("exclude_credential")).toBe("禁止导出凭据");
  });

  it("labels stdout and stderr by meaning", () => {
    expect(logStreamLabel("stdout")).toBe("标准输出");
    expect(logStreamLabel("stderr")).toBe("错误输出");
  });

  it("labels structured result kinds", () => {
    expect(structuredResultKindLabel("http_discovery")).toBe("HTTP 发现");
    expect(structuredResultKindLabel("raw_only")).toBe("原始结果");
  });

  it("keeps unexpected backend values visible for diagnosis", () => {
    expect(executionStatusLabel("paused")).toBe("未知状态（paused）");
    expect(sensitivityLabel("classified")).toBe("未知敏感度（classified）");
    expect(exportPolicyLabel("review")).toBe("未知导出策略（review）");
    expect(structuredResultKindLabel("custom")).toBe("未知结果（custom）");
  });
});
