import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const css = readFileSync(new URL("../src/styles.css", import.meta.url), "utf8");

function luminance(hex: string): number {
  const channels = [1, 3, 5].map((index) =>
    Number.parseInt(hex.slice(index, index + 2), 16),
  );
  const [red, green, blue] = channels.map((channel) => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
}

function contrast(foreground: string, background: string): number {
  const values = [luminance(foreground), luminance(background)].sort(
    (left, right) => right - left,
  );
  return (values[0] + 0.05) / (values[1] + 0.05);
}

describe("tool workspace layout contract", () => {
  it("keeps tertiary text above the normal-text contrast target", () => {
    const tertiary = /--text-tertiary:\s*(#[0-9a-f]{6})/i.exec(css)?.[1];
    expect(tertiary).toBeDefined();
    for (const background of ["#ffffff", "#f3f6fa", "#f8fafc"]) {
      expect(contrast(tertiary!, background)).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("keeps unavailable tool content fully opaque", () => {
    const disabledRule = /\.tool-card\.disabled\s*\{([^}]*)\}/.exec(css)?.[1];
    expect(disabledRule).toBeDefined();
    expect(disabledRule).not.toMatch(/\bopacity\s*:/);
  });

  it("preserves desktop, compact, and mobile workspace breakpoints", () => {
    expect(css).toContain("@media (max-width: 1180px)");
    expect(css).toContain("@media (max-width: 980px)");
    expect(css).toContain("@media (max-width: 760px)");
    expect(css).toContain(".parameter-fields-grid");
    expect(css).toContain(".tools-workspace");
  });

  it("provides coarse-pointer targets and reduced-motion behavior", () => {
    expect(css).toMatch(/@media \(pointer: coarse\)[\s\S]*min-width: 44px/);
    expect(css).toMatch(/@media \(pointer: coarse\)[\s\S]*min-height: 44px/);
    expect(css).toContain("@media (prefers-reduced-motion: reduce)");
  });
});
