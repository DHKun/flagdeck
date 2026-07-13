# ADR 0005: Supervisor backend and cancellation boundary

- 状态：Accepted
- 日期：2026-07-12

## Context

FlagDeck 需要取消普通子进程、孙进程、double-fork daemon、独立 Session 和忽略信号的进程，同时保护同 UID 的无关任务。Fedora 44 提供 systemd 259.7 与统一 cgroup v2；user manager 当前状态为 degraded，实际 transient service 能力可用。无 user manager 环境仍需要受限回退路径。

## Decision

- 首选 systemd user transient service，每个任务使用唯一 Unit 与 cgroup；调用方已持有的既有进程才使用 transient scope。
- 恢复与取消要求 Unit name、Invocation ID、ExecStart、MainPID、ControlGroup 和启动时间记录一致。任何不一致直接拒绝控制操作。
- 默认资源/执行属性固定 `KillMode=control-group`、`LimitCORE=0`、`NoNewPrivileges=yes`、`MemoryMax=256MiB`、`TasksMax=64`、`CPUQuota=100%`、`TimeoutStopSec=2s` 与 `UMask=0077`。工具 manifest 可在后续阶段按任务类型收紧数值。
- 取消顺序固定为对整个边界发送 SIGINT、等待 2 秒、发送 SIGTERM、等待 2 秒、向存活对象发送 SIGKILL；5 秒内必须清空边界并收集 Unit。
- user manager 能力不可用时采用独立 Session/PGID。Supervisor 保存 PID、start ticks 和 PGID，并登记已发现后代；离开根 PGID 的已拥有后代逐 PID 复核和发送相同信号序列。
- 启动只使用绝对路径、argv 数组和空环境，Shell 保持禁用。受管程序只保留 stdin/stdout/stderr 三个声明 FD。
- stdout/stderr 进入 64 × 8 KiB 有界 Channel，内存上限 512 KiB；UI 预览上限为 256 KiB。完整原始 Artifact 的写入器在 R3 采用独立有界路径与背压/丢失状态。
- gate、systemd Unit 和 PGID 回退全部设置 core limit 0。`coredumpctl` metadata 可以保留退出诊断，存储 core 文件保持禁止。

## Alternatives assessed

- 仅向 MainPID 发送信号：double-fork 与 `setsid()` 后代会存活，排除。
- 只凭 PID 恢复：PID 复用会扩大误杀风险，排除。
- 仅使用 PGID：独立 Session 后代可以离开根 PGID；保留为带登记表和明确能力提示的回退。
- 无界 stdout/stderr 队列：日志洪泛会推动 Core RSS 持续增长，排除。
- transient scope 作为新任务默认值：service 对主进程状态、资源和清理语义更完整，默认采用 service。

## Evidence

`spikes/supervisor-cgroup/evidence/results.json` 最近一次 14 项断言全部通过。九个活跃 fixture 包含两个逃逸 Session；systemd/PGID 分阶段取消分别在 4.072/4.021 秒完成。SIGINT 后均剩 2 个进程，SIGTERM 后均剩 1 个，SIGKILL 后 cgroup/PGID 与全部登记 PID 清空。

systemd 主进程 crash 后 0.101 秒清空 cgroup并收集 Unit；PGID 恢复路径在 0.201 秒内复核并清理所有登记对象。错误 Invocation ID、错误 start ticks 均被拒绝，protected sentinel 身份保持一致。

日志洪泛向 systemd/PGID 路径分别输入 614,400 / 2,162,688 bytes，固定队列分别丢弃 86 / 464 个 chunk，预览均停在 262,144 bytes。Supervisor RSS 增量为 1,056 KiB。两次 abort 只留下无存储文件的 systemd-coredump metadata，runtime core 文件计数为 0。Release 二进制为 1,235,400 bytes，SHA-256 为 `cd91482994367ecfdb438cfc450aa24bbbc0a6aad6f8671d7cf3989ab89a90ee`。

## Remaining risk

PGID 回退缺少 cgroup 级 CPU、内存和任务数上限。所有权快照之后产生的未知后代可能逃逸发现，PID/start-time/PGID 复核到 signal 之间仍有窄竞态；生产恢复优先使用 systemd Invocation ID/cgroup。R3 需要加入 pidfd、动态后代发现、原始日志 Artifact 写入器、资源 profile 与长时间 soak。

## References checked 2026-07-12

- <https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html>
- <https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html>
- <https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html>
- <https://man7.org/linux/man-pages/man2/setsid.2.html>
- <https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html>
