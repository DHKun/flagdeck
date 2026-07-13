<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";

  import { maliciousFixtures } from "./fixtures";
  import {
    safeDisplayFilename,
    toHexPreview,
    toSafeTextPreview,
  } from "./preview";

  let pingResult = "idle";
  let fileResult = "idle";
  let probeResult = "idle";

  async function callPing(): Promise<void> {
    try {
      pingResult = await invoke<string>("ping", { input: "flagdeck" });
    } catch {
      pingResult = "error";
    }
  }

  async function readFixture(): Promise<void> {
    try {
      fileResult = await invoke<string>("read_fixture", { name: "safe.txt" });
    } catch {
      fileResult = "error";
    }
  }

  async function runBrowserProbes(): Promise<void> {
    let localFile = "blocked";
    try {
      await fetch("file:///etc/passwd");
      localFile = "unexpected-allowed";
    } catch {
      localFile = "blocked";
    }
    const before = window.length;
    window.open("https://example.invalid/flagdeck-r0", "_blank");
    await new Promise((resolve) => window.setTimeout(resolve, 150));
    probeResult = JSON.stringify({
      localFile,
      newWindowCountStable: window.length === before,
      scriptMarker: Boolean(
        (window as Window & { __FLAGDECK_PWNED__?: boolean })
          .__FLAGDECK_PWNED__,
      ),
    });
  }
</script>

<svelte:head>
  <title>FlagDeck Tauri Security Spike</title>
</svelte:head>

<main>
  <header>
    <p class="eyebrow">R0 · Tauri trust boundary</p>
    <h1>Trusted main window</h1>
    <p>All hostile samples below remain text data.</p>
  </header>

  <section class="commands" aria-label="Authorized commands">
    <button data-testid="ping-button" onclick={callPing}>Invoke ping</button>
    <output data-testid="ping-result">{pingResult}</output>
    <button data-testid="read-button" onclick={readFixture}
      >Read restricted fixture</button
    >
    <output data-testid="read-result">{fileResult}</output>
    <button data-testid="browser-probe-button" onclick={runBrowserProbes}
      >Run browser probes</button
    >
    <output data-testid="browser-probe-result">{probeResult}</output>
  </section>

  <section aria-labelledby="fixtures-title">
    <h2 id="fixtures-title">Hostile fixtures</h2>
    <div class="fixture-grid">
      {#each maliciousFixtures as fixture}
        <article class="fixture" data-kind={fixture.kind}>
          <h3>{safeDisplayFilename(fixture.label)}</h3>
          <pre data-testid={`fixture-${fixture.kind}`}>{toSafeTextPreview(
              fixture.value,
            )}</pre>
          <code>{toHexPreview(fixture.value, 48)}</code>
        </article>
      {/each}
    </div>
  </section>
</main>
