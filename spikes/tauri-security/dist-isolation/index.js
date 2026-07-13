(() => {
  "use strict";

  const allowedCommands = new Set(["ping", "read_fixture"]);
  window.__TAURI_ISOLATION_HOOK__ = (message) => {
    if (
      message === null ||
      typeof message !== "object" ||
      !allowedCommands.has(message.cmd)
    ) {
      throw new Error("isolation rejected unknown command");
    }
    if (message.payload === null || typeof message.payload !== "object") {
      throw new Error("isolation rejected malformed payload");
    }
    if (message.cmd === "ping") {
      if (
        typeof message.payload.input !== "string" ||
        message.payload.input.length > 128
      ) {
        throw new Error("isolation rejected ping payload");
      }
    }
    if (message.cmd === "read_fixture" && message.payload.name !== "safe.txt") {
      throw new Error("isolation rejected file selector");
    }
    return message;
  };
})();
