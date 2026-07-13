# Supervisor/cgroup R0 spike

状态：`PASS`（2026-07-12）

本 spike 用 Release Rust fixture 验证完整任务树取消、崩溃清理、归属保护、有界日志和 coredump 策略。systemd user transient service 为首选后端；强制进入“user manager unavailable”分支后使用独立 Session/PGID 和已拥有后代登记表。

## 冻结合同

- systemd 后端每个任务使用唯一 transient service/cgroup，记录 Unit、Invocation ID、ControlGroup、MainPID、ActiveEnterTimestampMonotonic 和后端类型。
- Unit 属性固定 `KillMode=control-group`、`LimitCORE=0`、`NoNewPrivileges=yes`、`MemoryMax=256MiB`、`TasksMax=64`、`CPUQuota=100%`、`TimeoutStopSec=2s` 与 `UMask=0077`。
- 取消序列固定为 `SIGINT → 2 s → SIGTERM → 2 s → SIGKILL`，从第一信号到任务树清空的门禁为 5 秒。
- PGID 回退通过 `/usr/bin/prlimit --core=0:0 -- /usr/bin/setsid /usr/bin/env -i ...` 建立独立 Session；根进程组与所有已登记逃逸后代在每次信号前复核 PID、`/proc/<pid>/stat` start ticks 和 PGID。
- systemd 恢复/取消要求 Unit prefix、Invocation ID、ExecStart、MainPID 和 cgroup 一致。PID 或 Invocation ID 任一不匹配都会拒绝发送信号。
- 任务程序使用绝对路径与 argv 数组，Shell 保持禁用；最终环境为空，活跃 fixture 每个最多 3 个 FD（stdin/stdout/stderr）。
- stdout/stderr 各自持续读取并进入共享的 64 × 8 KiB `sync_channel`，队列硬上限 512 KiB，预览上限 256 KiB；队列满时记录 dropped chunk，读取线程继续排空 OS pipe。
- gate 与受管进程均设置 `RLIMIT_CORE=0`；systemd 路径再设置 `LimitCORE=0`，PGID 路径由 `prlimit` 在 exec 前设置。

## Fixture

取消树包含普通子进程、孙进程、标准 double-fork daemon、两个 `setsid()` 后代、忽略 SIGINT、忽略 SIGTERM、同时洪泛 stdout/stderr 的进程，以及同时忽略两阶段信号的根进程。独立 crash 场景让主进程执行 `abort()`，并保留普通与 `setsid()` 后代用于自动清理/恢复测试。

门禁另外启动一个独立 Session 的 protected sentinel。错误 start ticks 的 PID 记录和错误 Invocation ID 均被拒绝；四个测试生命周期结束后 sentinel 的 PID、start ticks 与 PGID 保持一致，最后再按其独立所有权记录清理。

## 最近一次正式证据

| 指标 | systemd cgroup | PGID 回退 |
|---|---:|---:|
| 分阶段取消到清空 | 4.072 s | 4.021 s |
| SIGINT 后存活 | 2 | 2 |
| SIGTERM 后存活 | 1 | 1 |
| 逃逸 Session | 2（仍在同一 cgroup） | 2（逐 PID 复核） |
| 主进程崩溃后清理 | 0.101 s | 0.201 s |
| 日志输入 | 614,400 bytes | 2,162,688 bytes |
| dropped chunks | 86 | 464 |
| 最大活跃 FD | 3 | 3 |

Supervisor 本身稳态/峰值 RSS 为 2,624 / 3,680 KiB，增量 1,056 KiB，门禁为 16 MiB。两次 abort 都产生 `COREFILE=none` 等价 metadata，`coredumpctl` 未报告存储文件，runtime 中无 core 文件。两轮正式实机门禁均通过，最近一轮 14 项断言全部为真。

PGID 回退保留四项能力边界：缺少 cgroup CPU/内存/任务数强制上限；所有权快照后新建的未知后代可能逃逸发现；start-time 复核到 signal 之间存在窄竞态；同 UID 恶意进程可以影响可观察的 `/proc` 状态。产品默认选择 systemd 后端，并在 GUI/审计记录实际后端。

## 复现

```bash
MISE_LOCKED=1 mise run r0-supervisor-static
MISE_LOCKED=1 mise run r0-supervisor-evidence
```

结构化证据位于 `evidence/results.json` 与 `evidence/summary.json`，权限均为 `0600`。门禁失败时 emergency cleanup 只匹配唯一 Unit prefix + ExecStart，或逐项复核 marker 中的 PID/start ticks/PGID。
