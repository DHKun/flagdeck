import { describe, expect, it } from "vitest";

import type { JobLogWindow } from "../src/lib/jobHistory";
import {
  nextLogOffset,
  shouldFallbackToStderr,
  shouldReplaceJobCursor,
} from "../src/lib/jobView";

function window(offset: number, nextOffset: number): JobLogWindow {
  return {
    content: "",
    offset,
    nextOffset,
    eof: false,
    windowStart: offset,
    windowEnd: nextOffset,
  };
}

describe("nextLogOffset", () => {
  it("resets to 0", () => {
    expect(nextLogOffset("reset", 999, window(10, 20))).toBe(0);
  });

  it("uses an explicit offset when given", () => {
    expect(nextLogOffset("append", 42, window(10, 20))).toBe(42);
  });

  it("uses the window nextOffset when appending", () => {
    expect(nextLogOffset("append", undefined, window(10, 20))).toBe(20);
    expect(nextLogOffset("append", undefined, null)).toBe(0);
  });

  it("uses the window offset when paging", () => {
    expect(nextLogOffset("page", undefined, window(10, 20))).toBe(10);
    expect(nextLogOffset("page", undefined, null)).toBe(0);
  });
});

describe("shouldFallbackToStderr", () => {
  it("triggers only for an empty, finished stdout on the first load", () => {
    expect(shouldFallbackToStderr("reset", "stdout", "   ", true)).toBe(true);
  });

  it("does not trigger when stdout has content, is not eof, or is not the first load", () => {
    expect(shouldFallbackToStderr("reset", "stdout", "x", true)).toBe(false);
    expect(shouldFallbackToStderr("reset", "stdout", "", false)).toBe(false);
    expect(shouldFallbackToStderr("append", "stdout", "", true)).toBe(false);
    expect(shouldFallbackToStderr("reset", "stderr", "", true)).toBe(false);
  });
});

describe("shouldReplaceJobCursor", () => {
  it("replaces when there is no cursor yet", () => {
    expect(shouldReplaceJobCursor(null, 200, 50)).toBe(true);
  });

  it("replaces while history is still the first page", () => {
    expect(shouldReplaceJobCursor("c", 40, 50)).toBe(true);
    expect(shouldReplaceJobCursor("c", 50, 50)).toBe(true);
  });

  it("keeps the deeper cursor once history has grown past one page", () => {
    expect(shouldReplaceJobCursor("c", 80, 50)).toBe(false);
  });
});
