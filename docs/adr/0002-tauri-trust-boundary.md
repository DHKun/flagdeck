# ADR 0002: Tauri trust boundary

- 状态：Accepted
- 日期：2026-07-11

## Context

Tauri 2 capability 以 window/webview label 决定权限。官方文档明确说明 Linux 无法区分嵌入 iframe 与宿主窗口发出的 IPC，因此拥有 IPC 的主 WebView 必须只承载受信打包资源，目标 HTML/SVG/Markdown 保持数据形态。

## Decision

- 锁定 Tauri 2.11.5、tauri-build 2.6.3、`@tauri-apps/api` 2.11.1 和 CLI 2.11.4。
- 每个 `invoke_handler` 命令同步进入 `AppManifest::commands` 与显式 capability。
- capability 仅授权 `main` label；无 remote URL、fs plugin、shell、opener或 window 创建权限。
- 启用 Isolation Pattern，hook 校验命令名和参数上限。
- 主 WebView 只加载打包资产；目标内容使用安全文本、Hex 与结构化预览。
- 通过 `on_navigation` 与 `on_new_window` 拒绝远程顶层导航和新窗口。
- Release 关闭 DevTools。

## Alternatives assessed

- 在主 WebView 中 sandbox iframe 展示目标 HTML：Linux capability 无法区分 iframe IPC 来源，放弃。
- 只依赖 CSP：无法覆盖 Rust command 自身校验和 label 授权，放弃单层控制。
- 允许通用文件路径 command：扩大本地文件暴露面，采用固定 selector 与私有临时文件。
- remote capability：R0 无远程 API 场景，保持空集合。

## Evidence

Rust tests 3/3、Vitest 9/9、Svelte 0 error/0 warning、Clippy 和 Release build 全部通过。Fedora `tauri-driver 2.0.6 → WebKitWebDriver 2.52.4` 的 10 次独立运行全部证明：main 两个命令成功；`untrusted-probe` 两个命令被拒绝；恶意 fixture 保持六个文本卡片、0 个危险 DOM 节点；file URL、远程导航和新窗口全部被阻止；Isolation iframe 每轮恰好一个。

最终 R0 Release binary SHA-256 为 `4974925a68bb9aec14c9801e46e9962526520b49564a6fbc3f7e59f9faa07cf8`，同一产物的自动 release gate 为 10/10。Isolation 构建材料参与二进制，门禁摘要因此在构建后重新绑定当前 SHA-256。`pnpm-lock.yaml` 固定 Svelte 5.56.4、Vite 8.1.4、TypeScript 6.0.3 与前端 Tauri 包。TypeScript 7.0.2 与 svelte-check 4.7.2 的初始化兼容失败已通过实测排除。

## Remaining risk

Linux 的 iframe IPC 来源限制固定为架构约束，目标内容永不进入 IPC WebView 执行。Wayland/NVIDIA 自动化需要测试进程设置 `__NV_DISABLE_EXPLICIT_SYNC=1`；正式应用仅在用户实机证据确认图形故障后才考虑该兼容开关。WebKitGTK 0-day 与同 UID 调试主体保持在威胁模型中。

## References checked 2026-07-11

- <https://v2.tauri.app/security/capabilities/>
- <https://v2.tauri.app/concept/inter-process-communication/isolation/>
- <https://v2.tauri.app/develop/tests/webdriver/>
- <https://docs.rs/tauri-build/2.6.3/tauri_build/struct.AppManifest.html>
- <https://docs.rs/tauri/2.11.5/tauri/webview/struct.WebviewWindowBuilder.html>
