# 0013 — R7 Stable 1.0 发布边界

- 状态：Accepted
- 日期：2026-07-13
- 版本：1.0.0；Domain `CONTRACT_VERSION=6`；Storage `SCHEMA_VERSION=6`
- 相关：[[0009-r3-reliable-orchestration]]、[[0011-r5-metasploit-product-boundaries]]、[[0012-r6-intruder-upload-boundaries]]

## 背景

R7 将 R0–R6 的功能收束为 Fedora 44 x86-64 Stable 1.0，补齐高数据量性能、桌面内存、安全 GUI、外部工具、Payload 来源、供应链审计、SBOM、RPM 签名和安装生命周期证据。发布门禁绑定最终二进制、RPM、锁文件和证据文件的 SHA-256。

## 决策

### 性能与桌面内存

- Core 使用 Release profile 跑 10 轮项目启动、Headless 空闲 RSS、100,000 条 Discovery 插入与游标分页，以及 80 个并发任务完成和清理。
- 桌面预算采用单窗口完整进程树私有驻留：逐进程读取 `/proc/<pid>/smaps_rollup`，求和 `Private_Clean + Private_Dirty`，10 轮 p95 上限为 150 MiB。
- PSS 与汇总 RSS作为辅助分布完整保留。PSS按共享页比例计费；汇总 RSS 会在多个 WebKit 进程中重复计入共享映射。
- WebKitGTK 每轮要求一个 WebProcess、core dump 限额为 0、退出后进程完成回收。主 WebView 使用 DocumentViewer 缓存模型，并关闭产品未使用的媒体、WebGL、WebAudio、离线缓存与本地存储能力。

### 供应链与 Python 覆盖

- `cargo audit`、`cargo deny`、`pnpm audit --prod` 与基于 `uv.lock` 哈希的 `pip-audit` 组成发布审计。许可证、来源、yanked crate 与重复依赖分别记录。
- mitmproxy 12.2.3 的兼容范围内固定 `msgpack 1.2.1` 与 `tornado 6.5.7`，覆盖已修复的 Python 安全版本；Worker 的 pytest、ruff 与 mypy 门禁持续执行。
- 15 条 Cargo 公告作为上游维护公告单列接受，范围集中于 Tauri Linux GTK3/WebKitGTK、urlpattern 与 glib 传递依赖。审计产物记录公告 ID、接受原因和零已知漏洞结果。
- CycloneDX 1.6 SBOM 汇总 Cargo、pnpm、uv 和受管外部工具/launcher，并写入四份锁文件的 SHA-256。

### RPM 签名与密钥

- Stable 1.0 正式制品为 Fedora 44 x86-64 RPM。隔离 GnuPG Home 中的 Ed25519 发布私钥执行 Header 签名，私钥目录由版本控制和发布包排除。
- 公钥 `release/FlagDeck-1.0.0-signing-key.asc` 作为交付物发布；独立 RPM 密钥库导入公钥并验证 OpenPGP、Header SHA-256 与 Payload SHA-256。
- RPM 携带 LICENSE、THIRD_PARTY、CycloneDX SBOM、五份配置模板、mitmproxy Worker 与 Metasploit Adapter Schema。卸载脚本清理 RPM 创建的空目录，用户 Workspace 与项目证据保持独立生命周期。

### Fedora 生命周期矩阵

- 宿主证据记录 Fedora 44、KDE、Wayland 与 SELinux Enforcing。
- 干净 `registry.fedoraproject.org/fedora:44` 容器安装 0.6.0，导入 1.0 公钥，以 `localpkg_gpgcheck=True` 升级到 1.0，验证 desktop entry、资源和动态链接。
- 同一容器继续执行 1.0→0.6 降级、0.6→1.0 再升级和卸载，最终检查 RPM 数据库、可执行文件、desktop entry 与 `/usr/lib/flagdeck` 零残留。
- GUI 门禁在宿主 KDE/Wayland 会话运行，覆盖 55 个显式 Tauri 命令的非授权 WebView 拒绝、恶意内容数据化展示、私有目录、Artifact 哈希与 core dump 限额。

### 外部能力边界

- fscan、gobuster 与 wafw00f 使用锁定路径、版本、二进制 SHA-256、类型化 argv 和真实 fixture。
- ShiroExploit、ysoserial、AntSword、Behinder 与 Godzilla 保持外部安装，通过 `external-launchers.toml` 固定程序、运行时、能力与风险等级。
- Payload 来源只读取配置允许的 TXT、YAML 和 JSON 文件；列表分页、预览大小与输入路径均有界。目标内容继续采用安全文本、结构化数据或 Hex 展示。

## 结果

Stable 1.0 的性能、GUI、供应链、签名与 Fedora 生命周期证据集中在 `tests/performance`、`tests/gui/evidence` 和 `release/evidence`。`release/evidence/release-manifest.json` 对最终 RPM、公钥、SBOM、锁文件、验收报告和关键证据统一哈希，作为发布交接入口。
