# Third-party software

FlagDeck 使用 Cargo、pnpm、uv 与 mise 锁文件固定直接依赖和传递依赖。发布制品应同时提供 CycloneDX SBOM、许可证文本和 SHA-256。

## 核心依赖

| Component                | License                 | Purpose                         |
| ------------------------ | ----------------------- | ------------------------------- |
| Tauri                    | Apache-2.0 OR MIT       | Linux / macOS 桌面壳与 IPC      |
| Svelte / Vite            | MIT                     | 内置界面与前端构建              |
| rusqlite / SQLite        | MIT / Public Domain     | 本地状态、FTS5 与备份           |
| Tokio                    | MIT                     | 进程、IPC 与取消流程            |
| serde / schemars / ts-rs | Apache-2.0 OR MIT / MIT | 合同、Schema 与 TypeScript 类型 |
| nix                      | MIT                     | Unix 权限、资源限制与进程策略   |
| sha2                     | Apache-2.0 OR MIT       | 工具与 Artifact 完整性          |
| zip / zlib-rs            | MIT / Zlib              | 本地数据包导入与校验            |
| zeroize                  | Apache-2.0 OR MIT       | 一次性凭据内存清理              |
| mitmproxy                | MIT                     | HTTP Worker                     |
| uv                       | Apache-2.0 OR MIT       | Linux/macOS HTTP Runtime 引导   |
| Metasploit Framework     | BSD-3-Clause            | 本地 RPC、模块与 Session        |
| WebKitGTK                | LGPL-2.1-or-later 等    | Linux 系统 WebView              |

完整版本和来源以 `Cargo.lock`、`pnpm-lock.yaml`、`workers/mitmproxy/uv.lock` 和 `mise.lock` 为准。

## 外部工具

以下工具通过 Tool Pack、系统路径或用户配置接入。源码仓库不包含这些工具的二进制。

| Tool                            | Declared license           | Integration |
| ------------------------------- | -------------------------- | ----------- |
| curl                            | curl license               | 受管 CLI    |
| dddd                            | MIT                        | 受管 CLI    |
| ffuf                            | MIT                        | 受管 CLI    |
| Arjun                           | GPL-3.0                    | 受管 CLI    |
| fscan / fscan-web               | 发布前核对具体上游与许可证 | 受管 CLI    |
| gobuster                        | Apache-2.0                 | 受管 CLI    |
| wafw00f                         | BSD-3-Clause               | 受管 CLI    |
| ShiroExploit / ysoserial bundle | 发布前核对上游分发条款     | 独立客户端  |
| AntSword                        | MIT                        | 独立客户端  |
| Behinder                        | 发布前核对上游分发条款     | 独立客户端  |
| Godzilla                        | BSD-3-Clause               | 独立客户端  |
| PayloadsAllTheThings            | 上游许可证                 | 用户数据源  |

Tool Pack 只有在满足固定上游版本、来源可复现、许可证允许再分发、许可证正文随包安装、SHA-256 与 SBOM 完整的条件后才可以公开发布。

## 参考实现

FlagDeck 的上传变异与验证流程参考 UploadRanger v1.1.1 的公开行为和测试思路。FlagDeck 使用独立实现，仓库和发布包均不包含 UploadRanger 代码。
