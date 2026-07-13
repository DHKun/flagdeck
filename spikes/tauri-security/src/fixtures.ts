export interface HostileFixture {
  kind: string;
  label: string;
  value: string;
}

export const maliciousFixtures: readonly HostileFixture[] = [
  {
    kind: "html",
    label: "response.html",
    value:
      '<script>window.__FLAGDECK_PWNED__=true</script><img src=x onerror="window.__FLAGDECK_PWNED__=true">',
  },
  {
    kind: "iframe",
    label: "frame.html",
    value:
      '<iframe src="https://example.invalid" onload="window.__FLAGDECK_PWNED__=true"></iframe>',
  },
  {
    kind: "svg",
    label: "payload.svg",
    value:
      '<svg xmlns="http://www.w3.org/2000/svg"><script>window.__FLAGDECK_PWNED__=true</script></svg>',
  },
  {
    kind: "markdown",
    label: "note.md",
    value:
      '# Finding\n\n<img src=x onerror="window.__FLAGDECK_PWNED__=true">\n[remote](javascript:alert(1))',
  },
  {
    kind: "filename",
    label: "../../escape\u202Egnp.exe",
    value: "../../../../etc/passwd\u0000.svg",
  },
  {
    kind: "log",
    label: "worker.log",
    value:
      "\u001b]8;;file:///etc/passwd\u0007open me\u001b]8;;\u0007 <script>alert(1)</script>",
  },
] as const;
