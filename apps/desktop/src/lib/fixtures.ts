export const hostileFixture = [
  "Authorization: Bearer flagdeck-secret-value",
  "Cookie: session=flagdeck-cookie-value",
  "<script data-fixture>window.__FLAGDECK_PWNED__=true</script>",
  '<img src=x onerror="window.__FLAGDECK_PWNED__=true">',
  '<iframe src="https://example.invalid"></iframe>',
  '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
  "token=flagdeck-token-value",
  "Filename: ../../escape\\payload.svg",
  "worker\u0000log\u202eexe.txt",
].join("\n");
