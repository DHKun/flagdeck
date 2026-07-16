export type ResultColumn = { key: string; label: string };
export type ResultRow = Record<string, string>;

export type ParsedJobResult = {
  title: string;
  columns: ResultColumn[];
  rows: ResultRow[];
  note?: string;
};

/** Map tool_id → candidate sidecar filenames in the job scan directory. */
export function resultCandidatesForTool(toolId: string): string[] {
  switch (toolId) {
    case "ffuf":
      return ["ffuf-output.json"];
    case "dddd":
      return ["dddd-output.jsonl", "dddd-output.json"];
    case "fscan":
      return ["fscan-output.json", "fscan-output.txt"];
    case "gobuster":
      return ["gobuster-output.txt"];
    case "arjun":
      return ["arjun-output.json"];
    default:
      return [];
  }
}

export function parseJobResult(
  toolId: string,
  filename: string,
  content: string,
): ParsedJobResult | null {
  const text = content.trim();
  if (!text) return null;

  if (toolId === "ffuf" || filename.endsWith("ffuf-output.json")) {
    return parseFfuf(text);
  }
  if (toolId === "dddd" || filename.includes("dddd-output")) {
    return parseDddd(text);
  }
  if (toolId === "fscan" || filename.includes("fscan-output")) {
    return parseFscan(text);
  }
  if (toolId === "gobuster" || filename.includes("gobuster-output")) {
    return parseGobuster(text);
  }
  if (toolId === "arjun" || filename.includes("arjun-output")) {
    return parseArjun(text);
  }
  return {
    title: filename,
    columns: [{ key: "line", label: "内容" }],
    rows: text
      .split("\n")
      .filter(Boolean)
      .slice(0, 500)
      .map((line) => ({ line })),
  };
}

function parseFfuf(text: string): ParsedJobResult | null {
  try {
    const data = JSON.parse(text) as {
      results?: Array<{
        url?: string;
        input?: { FUZZ?: string };
        status?: number | string;
        length?: number | string;
        words?: number | string;
        lines?: number | string;
      }>;
    };
    const results = data.results ?? [];
    const rows: ResultRow[] = results.map((item) => ({
      path: String(item.input?.FUZZ ?? item.url ?? ""),
      url: String(item.url ?? ""),
      status: String(item.status ?? ""),
      length: String(item.length ?? ""),
      words: String(item.words ?? ""),
      lines: String(item.lines ?? ""),
    }));
    return {
      title: `ffuf · ${rows.length} 条`,
      columns: [
        { key: "status", label: "状态" },
        { key: "path", label: "路径" },
        { key: "length", label: "长度" },
        { key: "words", label: "词" },
        { key: "url", label: "URL" },
      ],
      rows,
    };
  } catch {
    return null;
  }
}

function parseDddd(text: string): ParsedJobResult | null {
  // JSONL preferred
  if (text.startsWith("{") && text.includes("\n")) {
    const rows: ResultRow[] = [];
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const obj = JSON.parse(trimmed) as Record<string, unknown>;
        rows.push(flattenRow(obj));
      } catch {
        rows.push({ raw: trimmed });
      }
      if (rows.length >= 500) break;
    }
    if (rows.length === 0) return null;
    const columns = columnsFromRows(rows);
    return { title: `dddd · ${rows.length} 条`, columns, rows };
  }
  try {
    const data = JSON.parse(text) as unknown;
    if (Array.isArray(data)) {
      const rows = data
        .slice(0, 500)
        .map((item) =>
          typeof item === "object" && item
            ? flattenRow(item as Record<string, unknown>)
            : { value: String(item) },
        );
      return {
        title: `dddd · ${rows.length} 条`,
        columns: columnsFromRows(rows),
        rows,
      };
    }
  } catch {
    /* fallthrough */
  }
  return {
    title: "dddd",
    columns: [{ key: "line", label: "内容" }],
    rows: text
      .split("\n")
      .filter(Boolean)
      .slice(0, 500)
      .map((line) => ({ line })),
  };
}

function parseFscan(text: string): ParsedJobResult | null {
  if (text.startsWith("[") || text.startsWith("{")) {
    try {
      const data = JSON.parse(text) as unknown;
      const list = Array.isArray(data)
        ? data
        : data && typeof data === "object"
          ? [data]
          : [];
      const rows = list
        .slice(0, 500)
        .map((item) =>
          typeof item === "object" && item
            ? flattenRow(item as Record<string, unknown>)
            : { value: String(item) },
        );
      return {
        title: `fscan · ${rows.length} 条`,
        columns: columnsFromRows(rows),
        rows,
      };
    } catch {
      /* fallthrough */
    }
  }
  const rows = text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, 500)
    .map((line) => ({ line }));
  return {
    title: `fscan · ${rows.length} 行`,
    columns: [{ key: "line", label: "输出" }],
    rows,
  };
}

function parseGobuster(text: string): ParsedJobResult | null {
  const rows: ResultRow[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("=") || trimmed.startsWith("Gobuster")) {
      continue;
    }
    // e.g. /admin                (Status: 200) [Size: 1234]
    const match = trimmed.match(
      /^(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?/i,
    );
    if (match) {
      rows.push({
        path: match[1],
        status: match[2],
        size: match[3] ?? "",
      });
    } else {
      rows.push({ path: trimmed, status: "", size: "" });
    }
    if (rows.length >= 500) break;
  }
  if (rows.length === 0) return null;
  return {
    title: `gobuster · ${rows.length} 条`,
    columns: [
      { key: "status", label: "状态" },
      { key: "path", label: "路径" },
      { key: "size", label: "大小" },
    ],
    rows,
  };
}

function parseArjun(text: string): ParsedJobResult | null {
  try {
    const data = JSON.parse(text) as Record<string, unknown>;
    const rows: ResultRow[] = [];
    for (const [url, params] of Object.entries(data)) {
      if (Array.isArray(params)) {
        for (const p of params) {
          rows.push({ url, param: String(p) });
        }
      } else {
        rows.push({ url, param: String(params) });
      }
      if (rows.length >= 500) break;
    }
    return {
      title: `arjun · ${rows.length} 条`,
      columns: [
        { key: "url", label: "URL" },
        { key: "param", label: "参数" },
      ],
      rows,
    };
  } catch {
    return null;
  }
}

function flattenRow(obj: Record<string, unknown>): ResultRow {
  const row: ResultRow = {};
  for (const [key, value] of Object.entries(obj)) {
    if (value == null) {
      row[key] = "";
    } else if (typeof value === "object") {
      row[key] = JSON.stringify(value);
    } else {
      row[key] = String(value);
    }
  }
  return row;
}

function columnsFromRows(rows: ResultRow[]): ResultColumn[] {
  const keys = new Set<string>();
  for (const row of rows.slice(0, 20)) {
    for (const key of Object.keys(row)) keys.add(key);
  }
  const preferred = [
    "ip",
    "host",
    "port",
    "status",
    "url",
    "path",
    "service",
    "title",
    "line",
    "raw",
  ];
  const ordered = [
    ...preferred.filter((k) => keys.has(k)),
    ...[...keys].filter((k) => !preferred.includes(k)),
  ].slice(0, 8);
  return ordered.map((key) => ({ key, label: key }));
}
