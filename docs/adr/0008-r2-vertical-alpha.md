# ADR 0008: R2 vertical Alpha execution and import boundary

- 状态：Accepted
- 日期：2026-07-12

## Context

R2 需要贯通项目创建、精确 Scope、四个本机 CLI、受管执行、原始证据、统一 Discovery 和重启恢复。工具行为、网络边界、进程状态与解析状态需要形成可审计的持久合同。

## Decision

- `config/tools.toml` 固定 curl、dddd、ffuf、Arjun 的绝对路径、版本、SHA-256、健康策略、解析器版本和真实输出 fixture manifest。
- 每次任务启动前统一复核可执行文件类型、owner、写权限和 SHA-256；curl/ffuf 同时复核无副作用版本标记，Arjun 同时复核 Python 解释器哈希。dddd 使用静态 Go build metadata 与二进制哈希，避免执行会初始化 XDG 配置的帮助命令。
- `TargetScope` 保存精确 scheme、host、port、解析地址快照和 `deny` DNS 变化策略。Core 在每次运行前重新解析目标并执行精确 origin 检查。
- 四个工具使用独立 argv builder。执行链直接传递 argv，从空环境构造最小 allowlist，并为 ffuf/Arjun 创建 `0600` 私有字典。重定向、外部代理、被动来源、PoC、爆破与 dddd 内置代理测试均按 Alpha 预设关闭。
- systemd user service 是主执行后端，应用 `KillMode=control-group`、`LimitCORE=0`、`NoNewPrivileges=yes`、`MemoryMax=256MiB`、`TasksMax=64`、`CPUQuota=100%`、`UMask=0077`。Loopback Scope 增加 `IPAddressDeny=any` 与 `IPAddressAllow=localhost`。PGID 后端使用 `prlimit --core=0:0`、`setsid` 和空环境作为显式回退。
- stdout、stderr、结构化输出和私有输入先提交为内容寻址 Artifact，随后由版本化解析器导入。进程终态与导入终态独立持久化；`exit=0` 加损坏输出形成 `succeeded/parser_failed`。
- SQLite schema v2 增加 `job_imports`、任务/发现查询索引和 Observation 去重约束。migration 前执行 SQLite Backup，Discovery upsert、来源 Observation、Job import 与 HttpMessage 在单一事务中提交。
- 启动恢复将活动执行状态转为 `interrupted`，将中断的导入状态转为 `parser_failed`。游标分页负责 Job、Discovery 和 Scope 的重启后 resync。
- Tauri capability 扩展为 14 个显式命令。Svelte 页面展示 Scope、工具健康、任务执行/导入状态、脱敏命令预览、Discovery 和证据。

## Evidence

- `mise run r2-fixtures`：6/6 适配器、命令构造、真实 fixture 与哈希合同测试通过。
- `mise run r2-alpha-gate`：四个真实工具均通过 systemd 主后端访问动态 Loopback fixture；重启后恢复 4 个 `succeeded/imported` Job、1 个 curl HttpMessage 和至少 7 个 Discovery。
- `mise run test`：workspace 48 项 Rust 测试通过，产品 Rust 38 项通过，严格 Clippy 零 warning；Svelte 0 error/0 warning，Vitest 7/7，Release 前端 bundle 通过。
- RPM 内部 Release 二进制完成 10/10 WebKitGTK 门禁；14 个无权限 IPC 命令全部拒绝，恶意预览保持数据模式，Workspace 权限、Artifact 哈希与 core limit 全部通过。

## Plan adjustments

- Arjun 2.2.7 的 `--stable` 在本机引入 3–9 秒随机请求延迟。R2 使用固定 `-d 0.1`、`-t 5`、`--rate-limit 20`，获得有界且可重复的 Loopback 运行时间。
- dddd 2.0.2 的帮助路径会创建 XDG 配置。健康检查使用固定 Go module revision、路径属性和 SHA-256，任务环境使用项目私有 `XDG_CONFIG_HOME`。
- Loopback systemd 任务增加 cgroup IP 白名单。Internet/Private Scope 继续显示 `input-gate-and-audit` 隔离等级。

## Remaining risk

R3 负责用户取消、全局停止、cgroup/PGID 五秒清理证明、Worker 崩溃隔离、一致导出和跨语言 Adapter fixture。R7 负责 100,000 条 Discovery、完整进程树 RSS、冷/热启动、SELinux 安装生命周期、SBOM、许可证和签名 RPM。

当前安全探针场景的桌面主进程 RSS p95 为 218032 KiB，高于 150 MiB Alpha 预算。该指标保持为 R7 性能阻断门禁。
