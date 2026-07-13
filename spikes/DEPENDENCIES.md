# R0 dependency decisions

锁文件决定精确版本；本表记录 R0 主动引入的直接依赖。体积以当前 Fedora x86-64 Release spike 实测，运行成本描述热路径。

## SQLite spike

| 依赖 | 锁定版本 / 许可证 | 用途与运行成本 | 替代方案与决定 |
|---|---|---|---|
| rusqlite | 0.40.1 / MIT | SQLite API；数据库操作主热路径 | 原始 C FFI 增加 unsafe 面；采用 rusqlite |
| libsqlite3-sys bundled | 0.38.1，SQLite 3.53.2 / MIT + SQLite public domain | 将已修复 WAL-reset 的引擎编入进程 | 系统 3.51.2 存在已公布缺陷；采用 bundled |
| anyhow | 1.0.103 / MIT OR Apache-2.0 | spike 错误上下文；仅错误路径 | 自定义错误枚举适合产品阶段；R0 采用 anyhow |
| fs2 | 0.4.3 / MIT OR Apache-2.0 | 跨进程 `flock` 包装；每项目打开一次 | 直接 libc 增加 unsafe；采用 fs2 |
| nix | 0.30.1 / MIT | umask、Signal 和 PID 类型；启动/故障注入路径 | 外部 `kill` 命令增加进程依赖；采用 nix |
| serde / serde_json | 1.0.228 / 1.0.150，MIT OR Apache-2.0 | 写结构化证据；门禁结束时使用 | 手写 JSON 容易产生转义错误；采用 serde |
| sha2 | 0.10.9 / MIT OR Apache-2.0 | 流式内容哈希；逐 Artifact 热路径 | OpenSSL 引入系统 ABI；采用纯 Rust sha2 |
| tempfile | 3.27.0 / MIT OR Apache-2.0 | 自动清理测试 Workspace；仅测试/证据运行 | 手工临时目录增加残留风险；采用 tempfile |

SQLite spike 最终 R0 Release 二进制为 3,254,208 bytes，其中 text+data+bss 为 2,884,850 bytes。该数字包含 bundled SQLite 与证据自哈希，仅用于 R0 相对成本记录。

## Tauri security spike

| 依赖 | 锁定版本 / 许可证 | 用途与运行成本 | 替代方案与决定 |
|---|---|---|---|
| tauri / tauri-build | 2.11.5 / 2.6.3，MIT OR Apache-2.0 | 系统 WebView、ACL、Isolation 和资源嵌入；桌面壳主运行时 | Electron 自带 Chromium 增加发布体积；采用 Tauri |
| @tauri-apps/api / CLI | 2.11.1 / 2.11.4，MIT OR Apache-2.0 | 类型化前端 invoke / 构建工具；CLI 仅开发时 | 手写 IPC 与构建脚本扩大协议面；采用官方包 |
| Svelte | 5.56.4 / MIT | 可信内建 UI 与默认文本转义；渲染热路径 | 原生 DOM 可进一步缩小 spike，产品计划固定 Svelte |
| Vite | 8.1.4 / MIT | 两个静态入口构建；仅开发/构建 | 手写 bundle 缺少模块和哈希管理；采用 Vite |
| Vitest | 4.1.10 / MIT | 配置和预览合同；仅测试 | Node test runner 可替代；与 Vite 转换保持一致 |
| TypeScript | 6.0.3 / Apache-2.0 | 前端类型检查；仅构建 | 7.0.2 与 svelte-check 4.7.2 实测初始化崩溃；锁定 6.0.3 |
| svelte-check | 4.7.2 / MIT | Svelte/TS 诊断；仅构建 | 单独 `tsc` 无法完整检查 `.svelte`；采用官方检查器 |
| Prettier / Svelte plugin | 3.9.5 / 4.1.1，MIT | 确定性格式；仅开发 | 手工格式审查不稳定；采用锁定 formatter |
| tempfile | 3.27.0 / MIT OR Apache-2.0 | Rust 私有 fixture 生命周期；启动时创建一个小目录 | 固定 `/tmp` 路径存在竞态；采用 tempfile |
| tauri-driver | 2.0.6 / MIT OR Apache-2.0 | WebDriver 中间层；仅测试运行 | 嵌入 WDIO plugin 会进入应用依赖；R0 使用外部 driver |

Tauri Release spike 为 10,415,032 bytes；前端 `dist/` 合计 39,835 bytes；完整前端开发 `node_modules` 为 135 MiB且不进入发行产物。用户级 `tauri-driver` 为 2,274,800 bytes。

## mitmproxy streaming spike

| 依赖 | 锁定版本 / 许可证 | 用途与运行成本 | 替代方案与决定 |
|---|---|---|---|
| mitmproxy | 12.2.3 / MIT | 语义 HTTP/TLS 代理与同步 Body stream API；独立 Worker 主运行时 | 自建 HTTP/1/2/3 代理协议面过大；采用官方 mitmproxy |
| Brotli | 1.2.0 / MIT | R0 生成与校验 br 原始编码 fixture；仅门禁 | 预生成二进制 fixture 增加仓库存量；采用锁定库动态生成 |
| cryptography | 48.0.1 / Apache-2.0 OR BSD-3-Clause | R0 生成私有 CA 和 HTTPS server 证书；仅门禁 | 外部 openssl 子进程增加 argv/文件生命周期；采用 Python API |
| mypy | 1.19.1 / MIT | Worker strict 类型门禁；仅开发 | 仅运行时测试无法覆盖 hook/状态字段漂移；采用 mypy |
| pytest | 9.0.2 / MIT | 队列、故障和 hook 合同测试；仅开发 | 手写测试入口缺少隔离 fixture；采用 pytest |
| Ruff | 0.14.13 / MIT | Python 格式与 lint；仅开发 | 多个 formatter/linter 增加锁定面；采用单一 Rust 工具 |
| hatchling | 1.28.0 / MIT | editable wheel build backend；仅同步依赖时 | setuptools 引入额外配置面；采用最小 hatchling backend |

独立 `.venv` 当前占用 183,701,238 bytes（`du -sb`，文件系统显示 187 MiB）。该体积包含 mitmproxy 及 TLS/HTTP 协议依赖，发布阶段在用户首次启用代理时按计划展示下载量与安装占用。`uv.lock` SHA-256 为 `cc8704c7…f06cf`。

## Metasploit RPC spike

| 依赖 | 锁定版本 / 许可证 | 用途与运行成本 | 替代方案与决定 |
|---|---|---|---|
| Metasploit Framework RPM | 6.4.135~20260522060012 / BSD-3-Clause（上游） | 本机标准 MessagePack/TLS RPC server；只在用户进入 Metasploit 能力时懒加载 | 自建模块执行引擎超出范围；引用本机受管 Framework |
| systemd user manager | 259.7 / LGPL-2.1-or-later | transient service、cgroup 与 `LoadCredential` 生命周期；每个 RPC 生命周期一个 Unit | 一次性 Socket + PGID 可降级；首选 systemd |
| anyhow | 1.0.103 / MIT OR Apache-2.0 | launcher 错误上下文；只在 exec 前路径 | 自定义错误码进入产品化；R0 采用 anyhow |
| nix | 0.30.1 / MIT | launcher `execve` 与 Unix 进程接口；启动路径 | libc FFI 增加 unsafe；采用 nix |
| zeroize | 1.9.0 / Apache-2.0 OR MIT | launcher 凭据中间 buffer 清零；启动路径 | 手写 volatile 清零容易被优化；采用 zeroize |
| msgpack | 1.1.2 / Apache-2.0 | Python 门禁客户端编码标准 RPC；只在 spike 门禁运行 | JSON-RPC `-j` 超出首版协议；采用 MessagePack |
| mypy / pytest / Ruff | 1.19.1 / 9.0.2 / 0.14.13 | 类型、合同和格式门禁；仅开发 | 与 mitm Worker 共享版本策略 |
| hatchling | 1.28.0 / MIT | spike editable wheel backend；仅依赖同步 | 与 mitm Worker 共享最小 backend |

凭据 launcher Release 二进制为 623,648 bytes，SHA-256 为 `66c66641…b3ceb43`。Metasploit spike 的 `uv.lock` SHA-256 为 `8250e564…f042bc`。

## Supervisor/cgroup spike

| 依赖 | 锁定版本 / 许可证 | 用途与运行成本 | 替代方案与决定 |
|---|---|---|---|
| systemd user manager | 259.7 / LGPL-2.1-or-later | transient service、cgroup v2、资源上限与整树信号；任务主路径 | 独立 Session/PGID 保留为降级后端 |
| anyhow | 1.0.103 / MIT OR Apache-2.0 | gate/fixture 错误上下文；控制路径 | 产品阶段可转换为稳定错误码；R0 采用 anyhow |
| nix | 0.30.1 / MIT | signal、setsid、rlimit、umask 和 FD 操作；启动/取消路径 | 直接 libc FFI 增加 unsafe；采用 nix |
| signal-hook | 0.3.18 / Apache-2.0 OR MIT | 安全构造忽略 SIGINT/SIGTERM fixture；仅 spike 测试 | C helper 会增加额外构建产物；采用纯 Rust fixture |
| serde / serde_json | 1.0.228 / 1.0.150 | 进程身份 marker 与证据；R0 gate | 与现有 Rust spike 共享版本 |
| sha2 | 0.10.9 / MIT OR Apache-2.0 | Release 可执行文件流式哈希；门禁结束时使用 | 外部 `sha256sum` 增加子进程合同；采用现有纯 Rust 依赖 |

Supervisor Release spike 为 1,235,400 bytes，SHA-256 为 `cd914829…a90ee`。新增生产依赖只有 `signal-hook`/`signal-hook-registry`；其用途限定于 R0 fixture，R1 的 Supervisor 运行时代码可直接使用 Tokio signal API。
