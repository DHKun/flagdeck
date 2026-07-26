export function percentile(values, quantile) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.max(0, Math.ceil(quantile * sorted.length) - 1)];
}

// The root process shows a recurring 3-19 MiB allocation spike that
// appears 0.5-3.5 s after readiness and is released within ~1.5 s
// (Stable run 30191686034 and local KDE/Wayland forensics), while the
// baseline and every WebKit process stay flat. The minimum across the
// snapshot window therefore measures the durably retained residency:
// a released transient never survives it, and a genuinely retained
// allocation elevates every snapshot and is reported unchanged.
export function selectSteadyStateSample(snapshots) {
  if (!Array.isArray(snapshots) || snapshots.length === 0) {
    throw new Error("steady-state selection requires at least one snapshot");
  }
  return snapshots.reduce((lowest, snapshot) =>
    snapshot.privateKiB < lowest.privateKiB ? snapshot : lowest,
  );
}
