import type { JobLogWindow } from "./jobHistory";

export type JobLogMode = "reset" | "append" | "page";

/** 由加载模式、显式偏移和当前日志窗口，算出这次 previewJobLog 的 offset。 */
export function nextLogOffset(
  mode: JobLogMode,
  explicitOffset: number | undefined,
  window: JobLogWindow | null,
): number {
  if (mode === "reset") return 0;
  if (explicitOffset != null) return explicitOffset;
  return mode === "append" ? (window?.nextOffset ?? 0) : (window?.offset ?? 0);
}

/**
 * 是否该回退到 stderr：只在首屏（reset）看 stdout、且 stdout 读到结尾仍为空时，
 * 转去显示 stderr，让失败信息不被吞掉。
 */
export function shouldFallbackToStderr(
  mode: JobLogMode,
  stream: string,
  stdoutContent: string,
  stdoutEof: boolean,
): boolean {
  return (
    mode === "reset" &&
    stream === "stdout" &&
    stdoutContent.trim().length === 0 &&
    stdoutEof
  );
}

/**
 * 轮询任务列表时是否用本次分页的 next_cursor 覆盖已存游标：只有当历史还停在第一页
 * （已加载数不超过本页数）或还没有游标时才覆盖，避免抹掉更深分页的游标。
 */
export function shouldReplaceJobCursor(
  currentCursor: string | null,
  loadedCount: number,
  pageCount: number,
): boolean {
  return !currentCursor || loadedCount <= pageCount;
}
