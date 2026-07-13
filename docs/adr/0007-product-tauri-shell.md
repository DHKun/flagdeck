# ADR 0007: Product Tauri shell and narrow IPC

- 状态：Accepted
- 日期：2026-07-12

## Context

R0 已验证 Tauri capability 和 Linux iframe 权限边界。R1 需要把相同约束扩展到产品主窗口、Rust Core 和真实项目数据。

## Decision

- 产品使用一个受信 `main` WebView；安全自动化通过进程环境显式启用 `untrusted-probe` 窗口。
- 八个自定义命令同时登记在 `AppManifest::commands`、`invoke_handler`、Isolation allowlist 和 `main-capability`。
- DTO 从 Rust 生成，所有命令绑定项目 ID、枚举和大小上限。文件系统路径不进入前端命令。
- 磁盘操作通过 `spawn_blocking` 离开 GUI 线程。
- CSP 保持本地脚本与样式，导航策略拒绝 remote/file URL，新窗口策略返回 `Deny`，Release 关闭 DevTools。
- 目标 HTML、SVG、iframe、Markdown 和日志使用 Svelte 文本绑定与 `<pre>` 展示。
- IPC 错误使用固定公开消息；Storage 路径和 SQLite 上下文留在 Core 内。
- 主进程启动时设置 umask 077 与 `RLIMIT_CORE=0`。

## Evidence

Svelte 检查 0 error/0 warning，Vitest 7/7，产品 Rust 测试 24/24，严格 Clippy 通过。Fedora Wayland WebKitGTK 的 Release 自动化运行 10 次，8 个命令在无权限窗口全部拒绝；恶意预览保持 0 个危险节点；file URL、远程导航和新窗口全部阻止；凭据请求 10/10 被拒绝且未写入 Workspace。

WebDriver session 到 Core-ready UI 的 p50/p95 为 1269/1300 ms。安全探针场景主进程 RSS p95 为 215652 KiB，超过 Alpha 150 MiB 目标；该数字进入 R7 正式 RSS 基准与优化门禁。

## Remaining risk

WebKitGTK 与同 UID 调试主体保持在威胁模型中。正式 RSS 需要区分主进程、WebKitNetworkProcess、WebKitWebProcess、共享页与测试探针开销，并按照计划保存完整进程树证据。
