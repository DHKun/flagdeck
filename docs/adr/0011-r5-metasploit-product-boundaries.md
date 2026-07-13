# ADR 0011: R5 Metasploit product boundaries

- 状态：Accepted
- 日期：2026-07-13

## Context

R5 需要把 R0 的只读 RPC spike 转为项目独占产品能力，并覆盖模块、选项、Job、Console、Session、敏感证据、L3 与 TargetScope。Metasploit Framework 6.4.135 的标准 RPC 使用 TLS 上的 MessagePack；Ruby `ASCII-8BIT` 值会编码为 MessagePack binary。Metasploit 数据库是机器级共享状态，RPC 进程仍需项目私有 HOME。

## Decision

- 发布两个 Rust sidecar：`flagdeck-adapter-metasploit` 与 `flagdeck-msf-credential-launcher`。Core 只使用有界 JSON-RPC 控制面；MessagePack、TLS、Token 与 Metasploit 对象留在 Adapter 进程。
- RPC 监听固定为动态 `127.0.0.1`。Ready 前复核 listener inode 与 Unit MainPID，读取证书 DER SHA-256 并在生命周期内固定。
- systemd user service 的 `LoadCredential=flagdeck.msf-rpc:<one-shot AF_UNIX socket>` 为首选凭据通道；PGID 路径使用同一短生命周期 Socket。Socket 位于私有 `/run/user/<uid>/fd-msf-*`，规避 Linux `sockaddr_un` 108-byte 路径上限，消费后删除。
- launcher 只执行固定 `/opt/metasploit-framework/embedded/framework/msfrpcd`，参数使用 `-f -a 127.0.0.1 -p <dynamic> -t 300`。产品路径启用数据库，以满足 `flagdeck_<project UUID>` Workspace 映射。
- RPC 进程使用项目私有 HOME；`MSF_CFGROOT_CONFIG` 原位引用当前用户的 `~/.msf4`，用于机器级共享数据库配置。数据库未运行时产品健康门禁失败；R5 实机门禁只执行安全的 `msfdb start` 启动现有已初始化数据库。
- MessagePack binary 字符串按 UTF-8 规范化；非 UTF-8 Transcript 使用有损文本视图并保存敏感 Artifact。控制帧上限 1 MiB，单次 Transcript 上限 256 KiB。
- 401 只允许 `core.version`、模块目录/选项和对象列表等 allowlist 只读方法重新认证一次并重放一次。`module.execute`、Job/Console/Session、Workspace 与停止操作保持零自动重放。
- Core 在 RPC 前验证模块标识、`RHOST/RHOSTS`、`RPORT`、`TARGETURI`、`LHOST/LPORT` 和代理选项。范围、端口与监听策略失败直接拒绝。
- 执行类操作使用精确确认短语。Core 保存 L3 审计；Options 中密码、Token、Cookie、Authorization、Secret 和 Key 类字段只保存 `[REDACTED]`。
- Job、Console 与 Session 只允许操作当前 Adapter 生命周期返回并映射为 managed ownership 的对象。外部对象可以查看摘要，停止和命令操作会被拒绝。
- Console/Session 完整记录进入 `Sensitivity::SensitiveEvidence` Artifact，普通导出需要确认。审计只记录命令 SHA-256、对象 ID 与 Artifact ID。
- 活动 Metasploit 生命周期阻止项目关闭和桌面退出。活动 Session 的 RPC 停止要求 `TERMINATE ACTIVE SESSIONS`。
- 首版显示 `input_scope_gate_and_audit` 隔离等级。模块内部二次连接缺少内核级网络强制；该边界在 UI 和审计中保持可见。

## R0 deviation

R0 launcher 使用 `-n` 关闭数据库，适合只读生命周期验证。R5 移除 `-n` 并原位引用机器级 `.msf4` 配置，满足计划要求的 Metasploit Workspace 映射。RPC 凭据通道、TLS pin、Loopback、标准 MessagePack、Token 策略和 Unit 清理继续沿用 R0 冻结结果。

## Evidence

- 10 轮真实生命周期：p50 2940 ms、p95 3031 ms，`msfrpcd` RSS p95 258808 KiB，10/10 PASS。
- Rust Adapter 单元门禁覆盖 TLS HTTP 边界、Ruby binary 值、Token 失效单次重认证、执行零重放、凭据熵、输入上限和所有权。
- 产品真实门禁覆盖动态 Loopback、TLS pin、认证、`core.version`、项目 Workspace、只读模块搜索、logout、listener/Unit/Socket 清理和 SQLite 凭据键扫描。
- Release GUI 门禁 10/10 PASS；非授权 WebView 的 43 个命令每轮全部拒绝。

## Remaining risk

- 同 UID 主体可在 RPC 生命周期内读取 `/proc/<msfrpcd-pid>/environ`；systemd credential copy 在 Unit 生命周期内也对同 UID 可见。停止后两处均消失。
- Metasploit 数据库与 Workspace 属于机器级共享状态，项目删除不会自动删除对应 Metasploit Workspace。
- `msfrpcd` 实测 RSS p95 为 258808 KiB，低于 1 GiB Unit 上限；完整桌面主进程 RSS 仍超过 150 MiB 目标，归入 R7。
- 内核网络 namespace/bubblewrap/Podman 强制策略归入 R7。R5 使用输入 Scope 门禁、所有权、显式 L3 和审计。
