import { describe, expect, it } from "vitest";

import {
  loadWorkbenchPrefs,
  rememberTool,
  saveWorkbenchPrefs,
} from "../src/lib/workbenchPrefs";

describe("workbenchPrefs", () => {
  it("keeps targets and form values session-only", () => {
    const store = new Map<string, string>();
    const storage = {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => {
        store.set(key, value);
      },
      removeItem: (key: string) => {
        store.delete(key);
      },
      clear: () => store.clear(),
      key: (index: number) => [...store.keys()][index] ?? null,
      get length() {
        return store.size;
      },
    };
    Object.defineProperty(globalThis, "localStorage", {
      value: storage,
      configurable: true,
    });

    storage.clear();
    const base = loadWorkbenchPrefs();
    base.targetUrl = "http://example.test/";
    base.selectedToolId = "ffuf";
    base.formByTool = { ffuf: { wordlist: "seclists-common" } };
    base.recentToolIds = rememberTool(base, "ffuf");
    base.recentToolIds = rememberTool(
      { ...base, recentToolIds: base.recentToolIds },
      "dddd",
    );
    saveWorkbenchPrefs(base);
    const loaded = loadWorkbenchPrefs();
    expect(loaded.targetUrl).toBe("http://127.0.0.1/");
    expect([...store.values()].join("\n")).not.toContain("example.test");
    expect(loaded.selectedToolId).toBe("ffuf");
    expect(loaded.formByTool).toEqual({});
    expect(loaded.recentToolIds[0]).toBe("dddd");
    expect(loaded.recentToolIds[1]).toBe("ffuf");
  });
});
