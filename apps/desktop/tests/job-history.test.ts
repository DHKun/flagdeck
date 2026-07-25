import { describe, expect, it } from "vitest";
import {
  applyJobLogPage,
  compareJobHistoryOrder,
  jobLogRangeLabel,
  mergeJobHistoryPage,
  type JobLogWindow,
} from "../src/lib/jobHistory";
import type { JobView } from "../src/generated/ipc";

function jobView(
  jobId: string,
  createdAt: string,
  status: JobView["job"]["execution_status"] = "succeeded",
): JobView {
  return {
    job: {
      job_id: jobId,
      parent_job_id: null,
      command_spec_id: "cmd",
      execution_status: status,
      import_status: "imported",
      created_at: createdAt,
      started_at: createdAt,
      stopped_at: createdAt,
      pid: null,
      process_group_id: null,
      process_start_ticks: null,
      exit_code: 0,
      exit_reason: "exit_code:0",
      systemd_unit: null,
      cgroup_path: null,
      invocation_id: null,
      supervisor_backend: null,
      ownership_verified: true,
      cleanup_verified: true,
      residual_processes: 0,
      cancel_duration_millis: null,
      stdout_artifact_id: null,
      stderr_artifact_id: null,
      retry_count: 0,
      source_job_id: null,
    },
    tool_id: "ffuf",
    command_preview: "ffuf -u http://x/FUZZ",
    network_isolation: "loopback",
    io: { schema_version: 1, inputs: [], outputs: [] },
    parser_id: null,
    parser_version: null,
    parser_error: null,
    discovery_count: 0,
    http_message_count: 0,
  };
}

describe("job history page merge", () => {
  it("job_history_page_merge_preserves_loaded_rows_during_poll", () => {
    const page1 = [
      jobView("j-75", "1700000000075"),
      jobView("j-74", "1700000000074"),
      jobView("j-73", "1700000000073"),
    ];
    const page2 = [
      jobView("j-72", "1700000000072"),
      jobView("j-71", "1700000000071"),
    ];
    const afterAppend = mergeJobHistoryPage({
      loaded: page1,
      page: page2,
      mode: "append",
    });
    expect(afterAppend.map((item) => item.job.job_id)).toEqual([
      "j-75",
      "j-74",
      "j-73",
      "j-72",
      "j-71",
    ]);

    const polledFirstPage = [
      jobView("j-76", "1700000000076", "running"),
      jobView("j-75", "1700000000075", "failed"),
      jobView("j-74", "1700000000074"),
    ];
    const afterPoll = mergeJobHistoryPage({
      loaded: afterAppend,
      page: polledFirstPage,
      mode: "refresh",
    });
    expect(afterPoll.map((item) => item.job.job_id)).toEqual([
      "j-76",
      "j-75",
      "j-74",
      "j-73",
      "j-72",
      "j-71",
    ]);
    expect(
      afterPoll.find((item) => item.job.job_id === "j-75")?.job
        .execution_status,
    ).toBe("failed");
    expect(afterPoll.find((item) => item.job.job_id === "j-72")).toBeTruthy();
    expect(
      compareJobHistoryOrder(afterPoll[0], afterPoll[1]),
    ).toBeLessThanOrEqual(0);
  });
});

describe("bounded job log window", () => {
  it("replaces or caps content so UI memory stays bounded", () => {
    const first = applyJobLogPage({
      previous: null,
      content: "a".repeat(1000),
      offset: 0,
      nextOffset: 1000,
      eof: false,
      maxWindowBytes: 1500,
    });
    expect(first.content.length).toBe(1000);
    expect(first.windowStart).toBe(0);
    expect(first.windowEnd).toBe(1000);
    expect(jobLogRangeLabel(first)).toContain("字节 0–1000");

    const second = applyJobLogPage({
      previous: first,
      content: "b".repeat(1000),
      offset: 1000,
      nextOffset: 2000,
      eof: true,
      maxWindowBytes: 1500,
    });
    expect(second.content.length).toBeLessThanOrEqual(1500);
    expect(second.eof).toBe(true);
    expect(second.windowEnd).toBe(2000);
    expect(second.content.endsWith("b".repeat(10))).toBe(true);

    const jump: JobLogWindow = applyJobLogPage({
      previous: second,
      content: "head-page",
      offset: 0,
      nextOffset: 9,
      eof: false,
      maxWindowBytes: 1500,
    });
    expect(jump.content).toBe("head-page");
    expect(jump.windowStart).toBe(0);
    expect(jump.nextOffset).toBe(9);
  });
});
