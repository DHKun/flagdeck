import { describe, expect, it } from "vitest";

import { maliciousFixtures } from "../src/fixtures";
import {
  safeDisplayFilename,
  toHexPreview,
  toSafeTextPreview,
} from "../src/preview";

describe("safe previews", () => {
  it("turns control and bidi characters into visible text", () => {
    const preview = toSafeTextPreview("a\u0000b\u202Ec");
    expect(preview).toBe("a\\u{0000}b\\u{202e}c");
  });

  it("enforces text and byte limits", () => {
    expect(toSafeTextPreview("abcdef", 3)).toBe("abc\n…[truncated]");
    expect(toHexPreview("abcdef", 3)).toBe("61 62 63 …");
  });

  it("keeps every hostile fixture as a string", () => {
    for (const fixture of maliciousFixtures) {
      const preview = toSafeTextPreview(fixture.value);
      expect(typeof preview).toBe("string");
      expect(preview.length).toBeGreaterThan(0);
    }
  });

  it("neutralizes path separators and display controls in filenames", () => {
    const display = safeDisplayFilename("../bad\\name\u202Egnp.exe");
    expect(display).toContain("／");
    expect(display).toContain("＼");
    expect(display).not.toContain("/");
    expect(display).not.toContain("bad\\name");
    expect(display).toContain("\\u{202e}");
  });
});
