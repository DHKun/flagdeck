import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");
const configuration = JSON.parse(
  readFileSync(resolve(root, "src-tauri/tauri.conf.json"), "utf8"),
);
const capability = JSON.parse(
  readFileSync(
    resolve(root, "src-tauri/capabilities/main-capability.json"),
    "utf8",
  ),
);
const backend = readFileSync(resolve(root, "src-tauri/src/lib.rs"), "utf8");
const application = readFileSync(resolve(root, "src/App.svelte"), "utf8");

describe("Tauri security configuration", () => {
  it("uses isolation and an explicit capability list", () => {
    expect(configuration.app.security.pattern.use).toBe("isolation");
    expect(configuration.app.security.capabilities).toEqual([
      "main-capability",
    ]);
    expect(configuration.app.windows).toEqual([]);
    expect(configuration.app.security.freezePrototype).toBe(true);
  });

  it("keeps script, frame and object sources local", () => {
    const csp: string = configuration.app.security.csp;
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).not.toContain("unsafe-inline");
    expect(csp).not.toContain("https:");
    expect(csp.replace("http://ipc.localhost", "")).not.toContain("http:");
  });

  it("grants custom commands only to the main label", () => {
    expect(capability.windows).toEqual(["main"]);
    expect(capability.webviews).toEqual(["main"]);
    expect(capability.remote).toBeUndefined();
    expect(capability.permissions).toEqual([
      "allow-ping",
      "allow-read-fixture",
    ]);
  });

  it("blocks remote navigation and new windows in Rust", () => {
    expect(backend).toContain(".on_navigation(allow_navigation)");
    expect(backend).toContain("NewWindowResponse::Deny");
    expect(backend).toContain(".devtools(false)");
  });

  it("contains no raw HTML rendering sink", () => {
    expect(application).not.toContain("{@html");
    expect(application).not.toContain("innerHTML");
  });
});
