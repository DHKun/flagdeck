# ADR 0009: R3 reliable orchestration and project package boundary

- 状态：Accepted
- 日期：2026-07-13

## Context

R2 已贯通四个 Alpha CLI、统一 Discovery、Artifact 和重启恢复。R3 需要把任务启动后的所有权、主动取消、Worker 崩溃、短期凭据、字典和项目包纳入可验证合同，并将这些能力接入桌面操作面。

## Decision

- Core contract 升至 v3，SQLite schema 升至 v3。Job 持久化 PID start ticks、所有权验证、清理验证、残留进程数和取消耗时；字典元数据与词项使用独立表和索引。
- Tauri 的 `run_tool` 返回持久化的 queued Job，Core 在后台执行任务。桌面端每 500 ms 对活动任务做有界 resync，支持单任务停止和项目级全部停止。
- systemd user service 使用 Unit、Invocation ID、cgroup、MainPID 和目标程序复核所有权。PGID 回退使用 PID、`/proc/<pid>/stat` start ticks 和 PGID 复核所有权。
- 取消流程固定为 SIGINT、2 秒宽限、systemd stop/SIGTERM、2 秒宽限、SIGKILL。完成条件为 5 秒内 cgroup/进程组为空，并持久化信号、耗时和残留证据。身份变化直接返回所有权错误。
- `flagdeck-adapter-host` 承载 `flagdeck.adapter.v1` stdio Worker。Host 固定 4-byte 大端长度帧、1 MiB 控制帧上限、绝对 deadline、有界 stderr 哈希证据、`RLIMIT_CORE=0` 和崩溃后新 Worker 恢复。
- Rust 与 Python 使用 `tests/fixtures/r3/adapter-protocol/messages.json` 作为共同合同夹具。未知字段、帧长度、元数据和 deadline 在两侧执行一致检查。
- 一次性凭据通道使用项目私有目录中的随机 AF_UNIX Socket。Socket 权限为 `0600`，服务端用 `SO_PEERCRED` 校验同 UID，发送一次后关闭、unlink 并清零内存。systemd Unit 属性只包含 credential ID 与 Socket 路径。
- 通用执行器只直接接受 `none` 和经 L3 确认的 `argv_exception`。environment、stdin、inherited FD 和 protected file 模式需要受审计 launcher，未绑定 launcher 的请求直接失败。
- 字典输入在 Core 中去空白、去重并执行项数/长度限制，规范文本先提交为内容寻址 Artifact，再写入 SQLite 前缀索引。
- 项目导出获取 writer 屏障并通过 SQLite Online Backup API 生成快照。ZIP 内的 `project.toml` 记录相对路径、大小、SHA-256、敏感等级和排除原因；完整包复核后原子改名并设置 `0600`。
- 项目导入只接受 Workspace 根目录固定私有 `.imports` 收件箱中的安全包名。预检覆盖路径归一化、Zip Slip、符号链接、加密项、重复项、文件数、总大小、单文件大小、压缩比、allowlist 和 manifest 哈希。
- Tauri capability 扩展为 22 个显式命令。主 WebView 获得逐命令权限；无权限 probe WebView 的 22 个调用全部需要由 ACL 拒绝。Isolation 层同步验证 UUID、页大小、字典上限和包名格式。
- R3 Release 量化门禁对 systemd 取消、PGID 取消、Worker 崩溃恢复、凭据投递、项目导出和项目导入各运行 10 轮，保存 p50/p95、CPU、RSS、逻辑写入量、环境版本与 fixture 哈希。

## Consequences

- 任务 API 在排队后快速返回，GUI 可以持续操作并观察真实状态。
- 用户取消依赖经过复核的任务树边界，PID 复用和 Invocation ID 变化不会触发误杀。
- Worker 协议故障只终止对应 Worker，Rust Core 和桌面进程保持存活。
- 敏感项目包拥有明确确认、完整性和导入资源预算；前端 IPC 不接受任意文件系统路径。
- schema v3 migration 继续使用 Backup API 保存升级前快照；R2 数据可原位迁移。
- `zip`/`zlib-rs` 用于项目包容器和压缩项预检，`zeroize` 用于凭据内存清理；版本、许可证和用途已进入 `THIRD_PARTY.md`。

## Evidence

- `cargo test --workspace --locked`：R3 Core、storage、exec、Adapter Host、Adapter protocol、桌面和既有 spike 测试全部通过。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`：严格 workspace Clippy 零 warning；Rustfmt 通过。
- `python3 -m unittest tests/contract/test_adapter_protocol.py`：共同 Adapter v1 夹具 3/3 通过。
- `pnpm --dir apps/desktop test:all`：Svelte 0 error/0 warning，Prettier、Vitest 7/7 和 Vite production build 通过。
- `mise run r3-reliability-gate`：六组 Release 门禁各 10/10 通过，结果保存在 `tests/performance/baselines/r3-reliable-orchestration.json`。
- `mise run package` 与 `mise run gui-release-gate`：0.3.0 RPM 和 10 轮内部 Release WebKitGTK 证据保存在 `tests/gui/evidence/`。

## Remaining risk

桌面安全探针场景在 R2 的完整进程 RSS p95 为 218032 KiB，高于 150 MiB Alpha 预算。R7 继续拆分主进程、WebKitNetworkProcess、WebKitWebProcess、共享页和 probe 开销，并执行 100,000 条数据、冷/热启动、SELinux 安装生命周期、签名、SBOM 与许可证门禁。

Metasploit 使用环境凭据的受审计 launcher、RPM 交付哈希和 RPC 生命周期进入 R5。mitmproxy 长生命周期 Worker 的 socketpair、高吞吐背压、心跳和空闲回收进入 R4。
