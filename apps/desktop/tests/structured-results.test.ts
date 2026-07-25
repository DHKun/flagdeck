import { describe, expect, it } from "vitest";
import {
  exportStructuredRowsCsv,
  exportStructuredRowsTsv,
  filterStructuredRows,
  sortStructuredRows,
} from "../src/lib/structuredResults";
import type { StructuredResultRowDto } from "../src/generated/ipc";

function row(
  id: string,
  cells: Record<string, string>,
): StructuredResultRowDto {
  return {
    result_id: id,
    cells,
    source_job_id: "job-1",
    source_artifact_id: "art-1",
  };
}

describe("structured result filter/sort/export", () => {
  const rows = [
    row("r-2", { path: "/b", status: "200", url: "http://x/b" }),
    row("r-1", { path: "/a", status: "403", url: "http://x/a" }),
    row("r-3", { path: "/a", status: "200", url: "http://x/a2" }),
  ];

  it("result_filter_and_sort_are_deterministic", () => {
    const filtered = filterStructuredRows(rows, "200");
    expect(filtered.map((item) => item.result_id)).toEqual(["r-2", "r-3"]);
    const sorted = sortStructuredRows(filtered, "path", "asc");
    expect(sorted.map((item) => item.result_id)).toEqual(["r-3", "r-2"]);
    // Same path uses stable result_id tie-break when sorting path desc.
    const byPath = sortStructuredRows(rows, "path", "desc");
    expect(byPath.map((item) => item.result_id)).toEqual(["r-2", "r-1", "r-3"]);
  });

  it("export_current_result_set_matches_visible_rows", () => {
    const columns = [
      { key: "path", label: "路径" },
      { key: "status", label: "状态" },
    ];
    const visible = sortStructuredRows(
      filterStructuredRows(rows, "a"),
      "status",
      "asc",
    );
    const tsv = exportStructuredRowsTsv(columns, visible);
    expect(tsv).toBe("路径\t状态\n/a\t200\n/a\t403");
    const csv = exportStructuredRowsCsv(columns, visible);
    expect(csv).toBe("路径,状态\n/a,200\n/a,403");
  });
});
