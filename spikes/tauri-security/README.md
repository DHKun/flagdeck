# Tauri security spike

## Goal and hypothesis

证明 Fedora WebKitGTK 上只有标签为 `main` 的内建窗口拥有两个测试命令权限；所有目标内容始终以文本、Hex 或结构化数据展示。假设 Tauri 2.11 的 `AppManifest::commands`、显式 capability、Isolation Pattern、CSP 与 WebviewWindow 导航回调可以共同形成可测试边界。

## Risks

- Linux 无法区分窗口自身与嵌入 iframe 发出的 IPC。
- capability 标签过宽会把权限合并给无关窗口或 WebView。
- CSP 或前端 raw HTML sink 会把目标内容转为脚本。
- 顶层导航和 `window.open` 需要原生 WebView 回调限制。

## Controls

- `build.rs` 将 `ping` 与 `read_fixture` 写入 `AppManifest::commands`。
- `main-capability.json` 仅匹配 `main` window/webview，不声明 remote URL。
- Isolation hook 只接受两个命令及窄参数。
- CSP 的默认、script、style、connect、object、base、form 与 frame-ancestor source 均显式收紧；Tauri 在构建期加入随机 Isolation scheme。
- Linux iframe 限制通过架构边界处理：主 WebView 不嵌入目标内容；远程 frame 由 `default-src 'self'` 拒绝；所有恶意 fixture 仅进入 Svelte 文本节点。
- 两个 WebviewWindow 都拒绝远程顶层导航与新窗口。
- Release 与 probe 窗口始终 `.devtools(false)`。

## Reproduction

```bash
MISE_LOCKED=1 mise run r0-tauri-install
MISE_LOCKED=1 mise run r0-tauri-static
MISE_LOCKED=1 mise run r0-tauri-build
MISE_LOCKED=1 mise run r0-tauri-webdriver
MISE_LOCKED=1 mise run r0-tauri-release-gate
```

## Result: PASS

- Svelte check 为 0 error/0 warning；Vitest 9/9；Prettier 和 Vite Release build 通过。
- Rust command/navigation 合同 3/3；Clippy `-D warnings` 通过。
- Tauri 2.11.5 Release 成功编译，二进制 10,415,032 bytes。
- Fedora `tauri-driver 2.0.6 → WebKitWebDriver 2.52.4` 连续 10/10 PASS。
- 最终 R0 二进制 SHA-256 为 `4974925a68bb9aec14c9801e46e9962526520b49564a6fbc3f7e59f9faa07cf8`；release gate 在构建后自动绑定当前产物哈希。
- main 窗口每轮成功执行 `ping` 与固定 selector 临时文件读取。
- `untrusted-probe` 每轮的 `ping` 与 `read_fixture` IPC 均被拒绝。
- file URL、远程顶层导航与远程新窗口每轮均被阻止。
- 六类恶意 fixture 每轮保留六个文本卡片、0 个恶意 DOM 节点、0 脚本 marker；Tauri 随机 scheme Isolation iframe 恰好 1 个。

结构化证据：`evidence/webdriver.json`、`evidence/summary.json` 与 `evidence/release-runs/`，权限均为 `0600`。

实机偏差：Wayland/NVIDIA 驱动在默认环境出现 GDK protocol error；测试子进程采用 Tauri 官方建议顺序中的 `__NV_DISABLE_EXPLICIT_SYNC=1` 后稳定通过。Release 未内置 workaround。GTK 仍输出缺少 `appmenu-gtk-module` 的非致命消息；当前 spike 不启用 tray/menu capability。

剩余风险：Linux 的宿主窗口/iframe IPC 来源不可区分是上游平台限制。FlagDeck 通过“IPC 主 WebView 只加载受信打包资源”保持边界；任何未来目标 HTML iframe 预览方案都需要重新进入安全门禁。WebKitGTK 0-day 与同 UID 调试主体继续属于声明风险。
