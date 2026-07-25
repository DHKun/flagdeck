import type {
  StructuredResultColumnDto,
  StructuredResultRowDto,
} from "../generated/ipc";

export type ResultSortDir = "asc" | "desc";

export function filterStructuredRows(
  rows: StructuredResultRowDto[],
  query: string,
): StructuredResultRowDto[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return rows;
  return rows.filter((row) =>
    Object.values(row.cells).some((value) =>
      String(value).toLowerCase().includes(needle),
    ),
  );
}

export function sortStructuredRows(
  rows: StructuredResultRowDto[],
  sortKey: string,
  dir: ResultSortDir,
): StructuredResultRowDto[] {
  const factor = dir === "asc" ? 1 : -1;
  return [...rows].sort((left, right) => {
    const leftValue = left.cells[sortKey] ?? "";
    const rightValue = right.cells[sortKey] ?? "";
    const primary = leftValue.localeCompare(rightValue, undefined, {
      numeric: true,
      sensitivity: "base",
    });
    if (primary !== 0) return primary * factor;
    return left.result_id.localeCompare(right.result_id);
  });
}

export function exportStructuredRowsTsv(
  columns: StructuredResultColumnDto[],
  rows: StructuredResultRowDto[],
): string {
  const header = columns.map((column) => column.label).join("\t");
  const body = rows.map((row) =>
    columns.map((column) => escapeTsv(row.cells[column.key] ?? "")).join("\t"),
  );
  return [header, ...body].join("\n");
}

export function exportStructuredRowsCsv(
  columns: StructuredResultColumnDto[],
  rows: StructuredResultRowDto[],
): string {
  const header = columns.map((column) => escapeCsv(column.label)).join(",");
  const body = rows.map((row) =>
    columns.map((column) => escapeCsv(row.cells[column.key] ?? "")).join(","),
  );
  return [header, ...body].join("\n");
}

function escapeTsv(value: string): string {
  return value.replaceAll("\t", " ").replaceAll("\n", " ").replaceAll("\r", "");
}

function escapeCsv(value: string): string {
  if (/[",\n\r]/.test(value)) {
    return `"${value.replaceAll('"', '""')}"`;
  }
  return value;
}
