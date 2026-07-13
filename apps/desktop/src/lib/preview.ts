const CONTROL_CHARACTERS =
  /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/gu;

function visibleCodePoint(character: string): string {
  const point = character.codePointAt(0);
  return point === undefined
    ? ""
    : `\\u{${point.toString(16).padStart(4, "0")}}`;
}

export function toSafeTextPreview(
  value: string,
  maximumCodeUnits = 65_536,
): string {
  if (!Number.isSafeInteger(maximumCodeUnits) || maximumCodeUnits < 0) {
    throw new RangeError("invalid preview limit");
  }
  const clipped = value.slice(0, maximumCodeUnits);
  const visible = clipped.replace(CONTROL_CHARACTERS, visibleCodePoint);
  return value.length > maximumCodeUnits ? `${visible}\n…[truncated]` : visible;
}

export function safeDisplayFilename(value: string): string {
  return toSafeTextPreview(
    value.replaceAll("/", "／").replaceAll("\\", "＼"),
    255,
  );
}
