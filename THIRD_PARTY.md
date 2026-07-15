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

以下工具通过 **Tool Catalog**、Tool Pack、系统 PATH 或用户配置接入。  
**本源码仓库与默认 GitHub Release 均不包含这些工具的二进制、JDK/JavaFX 运行时或字典数据包。**

| Tool | Declared license (upstream) | Integration | Notes |
| --- | --- | --- | --- |
| curl | curl license | Catalog / 系统 | 通常由操作系统提供 |
| dddd | MIT | Catalog / 本机 Active | 用户自备二进制 |
| ffuf | MIT | Catalog / PATH | 用户自备 |
| gobuster | Apache-2.0 | Catalog / PATH | 用户自备 |
| fscan / fscan-web | 以上游发布为准 | Catalog / 本机 Active | 用户自备 |
| Arjun | GPL-3.0 | 旧 Alpha 注册表 | 可选 |
| wafw00f | BSD-3-Clause | 旧 Alpha 注册表 | 可选 |
| ShiroExploit | 上游分发条款 | Catalog GUI | 需本机 Java 8+JavaFX 等运行时 |
| ysoserial | 上游条款 | 外部 launcher | 用户自备 |
| AntSword | MIT | Catalog GUI | 用户自备 Loader |
| Behinder | 上游分发条款 | Catalog GUI | 用户自备 |
| Godzilla | BSD-3-Clause | Catalog GUI | 用户自备 |
| SecLists / 其他字典 | 各上游许可证 | Wordlists 根目录 | 用户自备 |

清单仅描述**如何调用**（路径解析、表单、argv），不构成对上游代码的再分发。  
Tool Pack 只有在满足：固定上游版本、来源可复现、**许可证允许再分发**、许可证正文随包、SHA-256 与 SBOM 完整时，才可单独公开发布。

若你在本机 `/data/CTF/Tools` 下放置了 Liberica JDK、OpenJFX、各类客户端等，请保留在工具库目录，**不要**提交进 FlagDeck git 仓库。

## 参考实现

FlagDeck 的上传变异与验证流程参考 UploadRanger v1.1.1 的公开行为和测试思路。FlagDeck 使用独立实现，仓库和发布包均不包含 UploadRanger 代码。
