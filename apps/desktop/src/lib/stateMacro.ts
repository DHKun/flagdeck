import type { StateMacro, TokenSource } from "../generated/ipc";

export interface StateMacroDraft {
  enabled: boolean;
  stepName: string;
  messageId: string;
  variable: string;
  source: TokenSource;
  headerName: string;
  prefix: string;
  suffix: string;
  maximumLength: number;
}

const encoder = new TextEncoder();

export function buildStateMacro(draft: StateMacroDraft): StateMacro | null {
  if (!draft.enabled) return null;

  const stepName = draft.stepName.trim();
  const messageId = draft.messageId.trim();
  const variable = draft.variable.trim();
  const headerName = draft.headerName.trim();
  const prefix = encoder.encode(draft.prefix);
  const suffix = encoder.encode(draft.suffix);
  if (
    stepName.length === 0 ||
    stepName.length > 256 ||
    messageId.length === 0 ||
    messageId.length > 64 ||
    variable.length === 0 ||
    variable.length > 64 ||
    !/^[A-Za-z0-9_]+$/.test(variable) ||
    prefix.length > 4096 ||
    suffix.length > 4096 ||
    !Number.isInteger(draft.maximumLength) ||
    draft.maximumLength < 1 ||
    draft.maximumLength > 4096 ||
    (draft.source === "response_body" && prefix.length === 0) ||
    (draft.source === "response_header" &&
      (headerName.length === 0 || headerName.length > 256))
  ) {
    throw new RangeError("状态宏配置超出安全边界");
  }

  return {
    steps: [
      {
        name: stepName,
        message_id: messageId,
        extractors: [
          {
            variable,
            source: draft.source,
            header_name: draft.source === "response_header" ? headerName : null,
            prefix: Array.from(prefix),
            suffix: Array.from(suffix),
            maximum_length: draft.maximumLength,
          },
        ],
      },
    ],
  };
}

export function encodeExecutionMarker(value: string): number[] {
  const marker = encoder.encode(value);
  if (
    marker.length === 0 ||
    marker.length > 256 ||
    marker.some(
      (byte) =>
        byte <= 8 ||
        byte === 11 ||
        byte === 12 ||
        (byte >= 14 && byte <= 31) ||
        byte === 127,
    )
  ) {
    throw new RangeError("执行输出 marker 超出安全边界");
  }
  return Array.from(marker);
}
