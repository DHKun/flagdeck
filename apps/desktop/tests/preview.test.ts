import { describe, expect, it } from "vitest";

import { safeDisplayFilename, toSafeTextPreview } from "../src/lib/preview";

describe("data-only preview helpers", () => {
  it("preserves markup as text and exposes control characters", () => {
    const value = "<script>window.__PWNED__=1</script>\u0000\u202eflag";
    const preview = toSafeTextPreview(value);
    expect(preview).toContain("<script>");
    expect(preview).toContain("\\u{0000}");
    expect(preview).toContain("\\u{202e}");
    expect(preview).not.toContain("\u0000");
  });

  it("bounds previews and neutralizes path separators in labels", () => {
    expect(toSafeTextPreview("abcdef", 3)).toBe("abc\n…[truncated]");
    expect(safeDisplayFilename("../../etc\\passwd")).toBe(
      "..／..／etc＼passwd",
    );
    expect(() => toSafeTextPreview("x", -1)).toThrow(RangeError);
  });
});
