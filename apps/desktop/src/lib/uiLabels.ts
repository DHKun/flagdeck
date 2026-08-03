import type {
  ExecutionStatus,
  ExportPolicy,
  RiskLevel,
  Sensitivity,
} from "../generated/contracts";
import type { StructuredResultKind } from "../generated/ipc";

const executionStatusLabels: Record<ExecutionStatus, string> = {
  queued: "排队中",
  starting: "启动中",
  running: "运行中",
  stopping: "停止中",
  succeeded: "成功",
  failed: "失败",
  timed_out: "超时",
  cancelled: "已取消",
  interrupted: "已中断",
};

const riskLevelLabels: Record<RiskLevel, string> = {
  l0: "L0 · 本地操作",
  l1: "L1 · 低风险",
  l2: "L2 · 需确认",
  l3: "L3 · 高风险",
};

const sensitivityLabels: Record<Sensitivity, string> = {
  normal: "普通",
  sensitive_evidence: "敏感证据",
  credential: "凭据",
};

const exportPolicyLabels: Record<ExportPolicy, string> = {
  include: "可直接导出",
  confirm_sensitive: "导出前确认",
  exclude_credential: "禁止导出凭据",
  exclude_runtime: "禁止导出运行文件",
};

const structuredResultKindLabels: Record<StructuredResultKind, string> = {
  http_discovery: "HTTP 发现",
  raw_only: "原始结果",
  unknown: "未知结果",
};

export function executionStatusLabel(status: ExecutionStatus | string): string {
  return (
    executionStatusLabels[status as ExecutionStatus] ?? `未知状态（${status}）`
  );
}

export function riskLevelLabel(level: RiskLevel | string): string {
  return riskLevelLabels[level as RiskLevel] ?? level.toUpperCase();
}

export function sensitivityLabel(value: Sensitivity | string): string {
  return sensitivityLabels[value as Sensitivity] ?? `未知敏感度（${value}）`;
}

export function exportPolicyLabel(value: ExportPolicy | string): string {
  return (
    exportPolicyLabels[value as ExportPolicy] ?? `未知导出策略（${value}）`
  );
}

export function structuredResultKindLabel(
  value: StructuredResultKind | string,
): string {
  return (
    structuredResultKindLabels[value as StructuredResultKind] ??
    `未知结果（${value}）`
  );
}

export function logStreamLabel(stream: "stdout" | "stderr"): string {
  return stream === "stdout" ? "标准输出" : "错误输出";
}
