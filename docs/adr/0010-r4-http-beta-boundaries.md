# ADR 0010: R4 HTTP Beta process, message, browser and wire boundaries

- 状态：Accepted
- 日期：2026-07-13

## Context

R3 已冻结任务所有权、Adapter v1、项目包和桌面权限边界。R4 需要把 R0 的 mitmproxy 分块实验转成正式 Worker，并贯通动态代理、项目私有浏览器、HttpMessage、History、Repeater、Diff、SQLMap 和 Raw HTTP/1。

## Decision

- Core contract 升至 v4，SQLite schema 升至 v4。`http_messages` 新增 exchange、source、representation、method/status、origin、长度、耗时和敏感等级结构化列；`proxy_sessions` 持久化 Starting、Ready、Stopping、Stopped、Failed 与 Interrupted 生命周期。
- 正式 Worker 位于 `workers/mitmproxy`，由独立 `pyproject.toml` 和 `uv.lock` 固定 Python 3.12.13 与 mitmproxy 12.2.3。RPM 携带 Worker 源码和锁文件；首次启用通过 uv 0.11.26 创建项目私有环境并验证版本。
- Adapter Host 为内建高吞吐 Worker 创建继承式 Unix socketpair。控制帧继续使用 4-byte 大端长度和 1 MiB 上限。Core 通过 `snapshot(after_sequence)` 在 socketpair 上同步单调序号 HTTP 元数据；Body 只通过项目私有随机文件传递。
- Addon 在 requestheaders/responseheaders 安装同步 stream transform。每方向队列固定 4 MiB 和 256 frames，全局 writer 上限为 8。pass-through 等待 250 ms，evidence-strict writer ack 上限为 5 秒。
- Body 文件使用随机名称、`O_EXCL`、`0600`、增量 SHA-256 和长度证据。Core 复核路径后按 Artifact 原子协议提交。状态集合固定为 complete、streamed_complete、truncated、missing 与 capture_failed。
- Proxy 消息固定为 semantic。Flow ID 与代理会话 ID 组成 exchange ID，请求和响应独立提交；413 提前响应、分块 Body 和压缩 Body保持关联。完整线格式只由 `raw_http1` Wire Artifact 表达。
- 单活动代理在五次有界尝试内选择动态 `127.0.0.1` 端口。Ready 前复核 `/proc/net/tcp` Socket inode 与 mitmdump PID 所有权。会话关闭时停止 Adapter/mitmdump 进程组、Chrome 进程组并导入尾部事件。
- mitmproxy confdir、CA、Chrome HOME、Profile 和 NSS DB全部属于项目私有目录。Chrome 150 使用 `$HOME/.local/share/pki/nssdb`；certutil 以项目 UUID nickname 导入 CA，Core 复算导出证书 SHA-256。
- Chrome 参数包含唯一代理地址和项目 Profile。TargetScope 显式包含 Loopback 时加入 `<-loopback>`。代理配置仅包含代理路径。HTML 目标由项目私有 Chrome 新标签打开；Tauri 只显示转义文本和结构化字段。
- History 使用结构化过滤、脱敏 FTS5、100 条上限的游标分页和按需 Body Artifact。FTS 内容只来自 `redacted_view`。
- Repeater 使用 `flagdeck.semantic-http1/1`。serializer 保留有序重复 Header，统一生成 Host、Content-Length 和 Connection，拒绝 CR/LF 注入，并保留父消息关系。
- Diff 覆盖 Header、query/form 参数、UTF-8 文本行、二进制 SHA-256/长度和响应耗时。SQLMap `-r` 文件通过同一 serializer 生成并归档为 Artifact。
- Raw HTTP/1 客户端先复核 TargetScope 和 DNS 快照，再原样发送用户 bytes；请求与响应分别保存 Wire Artifact，并标记 `representation_kind=raw_http1`。
- Tauri capability 扩展为 32 个显式命令。Isolation 同步限制 UUID、分页、Header 数量、Body byte 数组、端口、枚举和布尔值；无权限 probe WebView 对 32 个命令逐项验证 ACL 拒绝。

## Consequences

- 大 Body 捕获保持增量内存上界，Worker 无需持有完整 Flow Body。
- socketpair 承载控制和元数据 resync，项目私有文件承载 Body bytes。Worker 崩溃留下的事件日志支持停止与重启恢复。
- semantic Repeater 提供字段与 Body bytes 稳定性。Raw HTTP/1 提供畸形请求与线格式证据。
- 项目 CA 信任限定在项目 Chrome HOME，日常浏览器信任库保持独立。
- schema v4 migration 继续在升级前生成私有 SQLite Backup 快照；活动代理会话在重启时恢复为 Interrupted。
- Worker 可选运行时约占 190 MiB，RPM 核心安装载荷保持 30 MiB 预算内。

## Evidence

- `cargo test --workspace --locked`：72/72 Rust 测试通过，另有 1 项 190 MiB Worker 安装门禁按发布流程单独通过。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`：严格 Clippy 零 warning；Rustfmt 通过。
- 正式 Worker：ruff、mypy 和 pytest 16/16 通过；Rust/Python Adapter v1 共同合同 3/3 通过。
- `tests/performance/r4-mitmproxy/summary.json`：17 个真实代理 case 全部通过；50 MiB 上传/下载、HTTP/HTTPS、413、chunked、gzip、brotli、截断和失败状态完整覆盖。
- pass-through Worker 增量 RSS 为 4364 KiB，evidence-strict 为 948 KiB，均满足 32 MiB 门禁。
- Core 实机测试通过动态端口、监听 PID 所有权、项目 CA、Chrome 150 NSS 路径、私有 Chrome 进程组、socketpair snapshot 和 History Artifact 导入。
- 1000 条 Proxy HttpMessage 完成关闭、重开和游标分页恢复。
- Release WebKitGTK 门禁 10/10 通过；32 个无权限命令、恶意预览、凭据拒绝、私有权限、Artifact 哈希和 `RLIMIT_CORE=0` 全部通过。
- RPM `FlagDeck-0.4.0-1.x86_64.rpm` 携带正式 Worker 源码、uv 锁文件、桌面二进制和图标。

## Remaining risk

桌面安全探针场景的主进程 RSS p95 为 218740 KiB，高于 150 MiB 桌面预算。R7 继续按主进程、WebKitNetworkProcess、WebKitWebProcess、共享页和 probe 开销拆分测量。

RPM 当前签名状态为 `none`。GPG 签名、SBOM、完整许可证归档和 Fedora 安装/升级/卸载生命周期进入 R7。
