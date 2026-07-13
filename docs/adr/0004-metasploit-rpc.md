# ADR 0004: Metasploit RPC credential lifecycle

- 状态：Accepted
- 日期：2026-07-12

## Context

本机 Metasploit Framework 6.4.135 的 `msfrpcd` 支持从 `MSF_RPC_USER`/`MSF_RPC_PASS` 读取凭据，最终目标进程因此需要短期环境变量。FlagDeck 需要把凭据字面量排除在 argv、systemd Unit 属性、D-Bus、journal 和普通文件之外，同时保留标准 MessagePack、默认 TLS、动态 Loopback 与完整 Unit 清理。`msgrpc` 本机源码会向 Console 输出用户名和密码，托管启动路径保持禁用。

## Decision

- 采用 systemd user service 的 `LoadCredential=ID:<AF_UNIX socket>` 作为首选凭据通道；一次性私有 AF_UNIX Socket 直读作为 user manager 能力不足时的回退。
- 使用项目内建 Rust launcher 读取长度前缀二进制 payload，校验 Socket peer、字段边界和最小密码长度，清零中间 buffer，并直接 `execve` 固定绝对路径的 `msfrpcd`。
- launcher 最终环境采用白名单，只在 `execve` 前加入 `MSF_RPC_USER`/`MSF_RPC_PASS`。Shell、systemd `Environment=`/`SetEnvironment=`/`--setenv` 和凭据 argv 保持禁用。
- `msfrpcd` 参数固定为 `-f -a 127.0.0.1 -p <dynamic> -t 2 -n`；省略 `-j`、`-S`、`-U`、`-P`，使用 TLS 上的标准 MessagePack `/api/`。
- 每次生命周期读取服务端证书 SHA-256 并固定；Ready 前用 socket inode、PID、Unit、Invocation ID 与 cgroup 验证 listener 归属。
- 401 只触发一次重新认证，并且只允许重放幂等只读方法。执行类请求的自动重放保持禁用。
- systemd Unit 固定 `KillMode=control-group`、`LimitCORE=0`、`NoNewPrivileges=yes`、`MemoryMax=1GiB`、`TasksMax=256`、`CPUQuota=200%` 和受限地址族。

## Alternatives assessed

- 一次性 AF_UNIX Socket 直读：完整门禁通过，凭据副本更少，保留为 PGID/user-manager 降级路径。
- systemd `LoadCredential` 从普通文件读取：增加持久化文件生命周期，排除。
- systemd 环境属性或凭据 argv：会扩大 Unit/D-Bus/进程元数据暴露面，排除。
- `msgrpc` plugin：本机源码第 49–50 行输出凭据，托管路径禁用。
- JSON-RPC `-j`：首版协议固定标准 MessagePack，排除。

## Evidence

`spikes/metasploit-rpc/evidence/results.json` 中两个候选分别在 1.940 s 与 1.947 s Ready，完整门禁耗时 12.506 s。两条通道均完成 TLS pin、`auth.login`、`core.version`、只读模块元数据、Token 闲置过期、单次重认证/只读重放、`auth.logout` 和 6/6 清理断言。静态与单元门禁包含 Rust 3/3、Python 6/6、Clippy、Ruff 和 mypy strict。

launcher Release 二进制为 623,648 bytes，SHA-256 为 `66c666414768eda2364ca900db1a9a677ff4e14b2458063a4515d8c7db3ceb43`。受管 `msfrpcd` SHA-256 为 `160b94ae5529f483235b72c6055c9ac776a007eee4c5c1bdcc420c83ed49d6e8`；`msgrpc.rb` SHA-256 为 `5ab79e7eb57d7c21df1797ba86906a78e338ec5c33b6747313fb0bf37755624d`。

## Remaining risk

同 UID 主体在服务运行期间可以读取 `/proc/<msfrpcd-pid>/environ`。`LoadCredential` 路径在 Unit 运行期间还存在 systemd 管理的只读 credential copy，本机同 UID 实测可读；Unit 停止后凭据 copy、Socket 和环境所在进程全部消失。R5 需要继续以本机同 UID 恶意进程作为威胁模型，并验证签名 RPM 对 launcher 的交付完整性。

## References checked 2026-07-12

- <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Credentials>
- <https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html>
- 本机锁定 RPM 中的 `msfrpcd`、`lib/msf/core/rpc/v10` 与 `plugins/msgrpc.rb` 源码
