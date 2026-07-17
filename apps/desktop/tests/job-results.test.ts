import { describe, expect, it } from "vitest";

import { parseJobResult, resultCandidatesForTool } from "../src/lib/jobResults";
import {
  loadWorkbenchPrefs,
  rememberTool,
  saveWorkbenchPrefs,
} from "../src/lib/workbenchPrefs";

describe("jobResults", () => {
  it("maps tool ids to sidecar filenames", () => {
    expect(resultCandidatesForTool("ffuf")).toEqual(["ffuf-output.json"]);
    expect(resultCandidatesForTool("dddd")[0]).toContain("dddd");
    expect(resultCandidatesForTool("unknown")).toEqual([]);
  });

  it("parses ffuf json results", () => {
    const parsed = parseJobResult(
      "ffuf",
      "ffuf-output.json",
      JSON.stringify({
        results: [
          {
            url: "http://t/admin",
            input: { FUZZ: "admin" },
            status: 200,
            length: 10,
            words: 1,
            lines: 1,
          },
        ],
      }),
    );
    expect(parsed?.rows).toHaveLength(1);
    expect(parsed?.rows[0].path).toBe("admin");
    expect(parsed?.rows[0].status).toBe("200");
  });

  it("parses gobuster text lines", () => {
    const parsed = parseJobResult(
      "gobuster",
      "gobuster-output.txt",
      "/admin                (Status: 200) [Size: 1234]\n/x (Status: 403) [Size: 9]\n",
    );
    expect(parsed?.rows).toHaveLength(2);
    expect(parsed?.rows[0].path).toBe("/admin");
    expect(parsed?.rows[1].status).toBe("403");
  });

  it("returns null for empty or invalid ffuf payload", () => {
    expect(parseJobResult("ffuf", "ffuf-output.json", "")).toBeNull();
    expect(parseJobResult("ffuf", "ffuf-output.json", "not-json")).toBeNull();
  });
});

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
