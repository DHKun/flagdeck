import type { JobView } from "../generated/ipc";

/** Stable job history order: created_at DESC, job_id DESC. */
export function compareJobHistoryOrder(left: JobView, right: JobView): number {
  if (left.job.created_at !== right.job.created_at) {
    return right.job.created_at.localeCompare(left.job.created_at);
  }
  return right.job.job_id.localeCompare(left.job.job_id);
}

/**
 * Merge a freshly polled first page into already-loaded history.
 * - newer/changed rows replace by job_id
 * - previously loaded older pages are retained
 * - order stays stable
 */
export function mergeJobHistoryPage(options: {
  loaded: JobView[];
  page: JobView[];
  mode: "refresh" | "append";
}): JobView[] {
  const byId = new Map<string, JobView>();
  if (options.mode === "append") {
    for (const item of options.loaded) {
      byId.set(item.job.job_id, item);
    }
  }
  for (const item of options.page) {
    byId.set(item.job.job_id, item);
  }
  if (options.mode === "refresh") {
    // Keep older rows that were already loaded beyond the first page.
    for (const item of options.loaded) {
      if (!byId.has(item.job.job_id)) {
        byId.set(item.job.job_id, item);
      }
    }
  }
  return [...byId.values()].sort(compareJobHistoryOrder);
}

export type JobLogWindow = {
  content: string;
  offset: number;
  nextOffset: number;
  eof: boolean;
  /** Inclusive start of the retained window in absolute file bytes. */
  windowStart: number;
  /** Exclusive end of the retained window. */
  windowEnd: number;
};

export const JOB_LOG_PAGE_BYTES = 65_536;
export const JOB_LOG_WINDOW_BYTES = 262_144;

/** Replace the in-memory log window with a single bounded page (no unbounded append). */
export function applyJobLogPage(options: {
  previous: JobLogWindow | null;
  content: string;
  offset: number;
  nextOffset: number;
  eof: boolean;
  maxWindowBytes?: number;
}): JobLogWindow {
  const maxWindow = options.maxWindowBytes ?? JOB_LOG_WINDOW_BYTES;
  const pageBytes = new TextEncoder().encode(options.content).length;
  // Prefer the server-reported nextOffset span; fall back to encoded length.
  const reportedSpan = Math.max(
    0,
    Number(options.nextOffset) - Number(options.offset),
  );
  const span = reportedSpan > 0 ? reportedSpan : pageBytes;
  let content = options.content;
  let windowStart = Number(options.offset);
  let windowEnd = Number(options.offset) + span;

  if (content.length > maxWindow) {
    // Keep a character window as an upper bound for UI memory.
    content = content.slice(-maxWindow);
    windowStart = Math.max(windowStart, windowEnd - maxWindow);
  }

  // When paging forward from a previous window, do not accumulate past maxWindow.
  if (
    options.previous &&
    options.offset === options.previous.nextOffset &&
    options.previous.content
  ) {
    const combined = `${options.previous.content}${options.content}`;
    if (combined.length <= maxWindow) {
      content = combined;
      windowStart = options.previous.windowStart;
      windowEnd = Number(options.nextOffset);
    } else {
      content = combined.slice(-maxWindow);
      windowEnd = Number(options.nextOffset);
      windowStart = Math.max(0, windowEnd - maxWindow);
    }
  }

  return {
    content,
    offset: Number(options.offset),
    nextOffset: Number(options.nextOffset),
    eof: options.eof,
    windowStart,
    windowEnd,
  };
}

export function jobLogRangeLabel(window: JobLogWindow | null): string {
  if (!window) return "未加载";
  const start = window.windowStart;
  const end = window.windowEnd;
  const eof = window.eof ? " · eof" : "";
  return `字节 ${start}–${end}${eof}`;
}
