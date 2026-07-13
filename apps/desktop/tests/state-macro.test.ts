import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));

import { ipc } from "../src/lib/ipc";
import { buildStateMacro, encodeExecutionMarker } from "../src/lib/stateMacro";

const projectId = "00000000-0000-0000-0000-000000000001";
const scopeId = "00000000-0000-0000-0000-000000000002";
const parentMessageId = "00000000-0000-0000-0000-000000000003";
const refreshMessageId = "00000000-0000-0000-0000-000000000004";

describe("state macro IPC requests", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("forwards the enabled bounded macro to Intruder and upload", async () => {
    const stateMacro = buildStateMacro({
      enabled: true,
      stepName: "refresh-csrf",
      messageId: refreshMessageId,
      variable: "csrf",
      source: "response_header",
      headerName: "X-CSRF-Token",
      prefix: "token=",
      suffix: ";",
      maximumLength: 128,
    });

    await ipc.startIntruder({
      project_id: projectId,
      scope_id: scopeId,
      parent_message_id: parentMessageId,
      attack_mode: "sniper",
      positions: [
        {
          location: "form",
          name: "q",
          occurrence: 0,
          start: null,
          end: null,
        },
      ],
      dictionary_ids: ["00000000-0000-0000-0000-000000000005"],
      global_rate_per_second: 8,
      target_rate_per_second: 8,
      state_macro: stateMacro,
    });
    await ipc.startUploadCampaign({
      project_id: projectId,
      scope_id: scopeId,
      parent_message_id: parentMessageId,
      part_ordinal: 1,
      mutations: ["magic_bytes"],
      global_rate_per_second: 8,
      target_rate_per_second: 8,
      state_macro: stateMacro,
      verification: {
        mode: "none",
        path_extractor: null,
        expected_execution_marker: null,
      },
      confirmation: null,
    });

    expect(invoke).toHaveBeenNthCalledWith(1, "start_intruder", {
      request: expect.objectContaining({ state_macro: stateMacro }),
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "start_upload_campaign", {
      request: expect.objectContaining({ state_macro: stateMacro }),
    });
  });

  it("bounds state macro and execution marker inputs", () => {
    expect(
      buildStateMacro({
        enabled: false,
        stepName: "",
        messageId: "",
        variable: "",
        source: "response_body",
        headerName: "",
        prefix: "",
        suffix: "",
        maximumLength: 0,
      }),
    ).toBeNull();
    expect(encodeExecutionMarker("flagdeck-executed-42")).toEqual(
      Array.from(new TextEncoder().encode("flagdeck-executed-42")),
    );
    expect(() => encodeExecutionMarker("x".repeat(257))).toThrow(RangeError);
  });
});
