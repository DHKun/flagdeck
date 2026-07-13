# R0 environment evidence

- 采集时间：2026-07-11T20:31:08+08:00
- 主机：Fedora Linux 44 KDE Plasma Desktop Edition，kernel `7.1.3-200.fc44.x86_64`，x86-64
- 会话：KDE Wayland，本地 user session
- SELinux：enabled、targeted、Enforcing
- cgroup：unified cgroup v2；controllers 为 `cpuset cpu io memory hugetlb pids rdma misc dmem`
- systemd：`259.7-1.fc44`；user manager 可访问，状态 `degraded`，已知失败项为无关的 `nvidia-settings` autostart unit
- core dump：交互 Shell 为 `unlimited`；`kernel.core_pattern` 指向 `systemd-coredump`

## Toolchains

| 工具 | 实测版本 | 备注 |
|---|---|---|
| rustc / cargo | 1.96.0 | `x86_64-unknown-linux-gnu`，LLVM 22.1.2 |
| Node | 22.22.2 | 项目将由 mise 精确锁定 |
| pnpm | 11.7.0 | 项目将由 mise 精确锁定 |
| mise | 2026.7.0 | 本机提示 2026.7.5 可用；R0 不自行升级全局工具 |
| mise Python | 3.12.13 | Worker 固定使用此版本 |
| system Python | 3.14.6 | 不进入 Worker 依赖图 |
| uv | 0.11.26 | x86_64 musl build |
| SQLite CLI | 3.51.2 | `ENABLE_FTS5`、`THREADSAFE=1`；受 WAL-reset 缺陷影响 |

`mise current` 的全局 Node/pnpm 选择分别为 24.18.0/11.9.0，与 R0 基线不同。项目级 `mise.toml` 固定 22.22.2/11.7.0，严格测试使用 `MISE_LOCKED=1`。
项目级 `.miserc.toml` 忽略用户级 `~/.config/mise/config.toml`，防止无关的全局 Go、Gradle、Maven 和 npm 工具进入 R0 严格锁定解析。该隔离方式依据 mise 2026 Config Environments 官方文档。

## Tauri system dependencies

已安装：

- `webkit2gtk4.1-devel-2.52.4-1.fc44.x86_64`
- `openssl-devel-3.5.7-1.fc44.x86_64`
- `curl-8.18.0-6.fc44.x86_64`
- `file-5.46-10.fc44.x86_64`
- `gcc/gcc-c++ 16.1.1`、`make 4.4.1`
- `/usr/bin/WebKitWebDriver`，来源 `webkitgtk6.0-2.52.4-1.fc44.x86_64`

DNF transaction 71（用户 UID 1000，状态 `Ok`）在 2026-07-11 安装：

- `libappindicator-gtk3-devel-12.10.1-10.fc44`
- `librsvg2-devel-2.62.3-1.fc44`
- `libxdo-devel-3.20211022.1-10.fc44`
- 依赖 `libxdo`、`libdav1d-devel`、`dbus-glib-devel`、`dbus-glib`

`/usr/bin/wget` 已由 `wget2-wget-2.2.1-2.fc44` 提供。官方 Tauri Fedora prerequisite 命令的能力集合完整。R0 安装了用户级 `tauri-driver 2.0.6`；其 SHA-256 为 `abe3332…201`。`WebKitWebDriver` 版本随 `webkitgtk6.0-2.52.4`，SHA-256 为 `2be35aa4…45ee`。

Wayland/NVIDIA 原生桌面测试首次出现 `Gdk Error flushing display: Protocol error`。依据 Tauri 官方 Linux Graphics Issues 顺序，仅对 WebDriver 子进程设置 `__NV_DISABLE_EXPLICIT_SYNC=1` 后，10/10 Release 桌面测试通过。Release 应用本身未固化图形 workaround。

## mitmproxy Worker baseline

- Python 3.12.13、uv 0.11.26、mitmproxy 12.2.3；独立 `.venv` 为 183,701,238 bytes。
- `mitmdump` 与所有 fixture listener 只绑定动态 `127.0.0.1` 端口；正式证据通过 socket inode 与 Worker PID 校验归属。
- 私有 confdir、CA、staging 和事件目录均位于模式 `0700` 的临时根目录，证据及 Body 文件为 `0600`。
- HTTPS fixture 使用临时 CA 签发 `127.0.0.1` 证书；mitmproxy 上游验证通过 `ssl_verify_upstream_trusted_ca` 保持开启，客户端只信任该次 Worker confdir 的 CA。
- pass-through Worker 稳态 RSS 75,152 KiB、峰值 81,020 KiB、增量 5,868 KiB；evidence-strict 对应 75,012 / 75,744 / 732 KiB。
- 50 MiB HTTP/HTTPS、chunked、无长度、gzip/br、413、截断和三类证据故障共 17 个真实代理场景通过。

## Metasploit read-only baseline

- RPM：`metasploit-framework-6.4.135~20260522060012~1rapid7-1.fedora30.x86_64`
- `/opt/metasploit-framework/embedded/framework/msfrpcd` SHA-256：`160b94ae5529f483235b72c6055c9ac776a007eee4c5c1bdcc420c83ed49d6e8`
- `plugins/msgrpc.rb` SHA-256：`5ab79e7eb57d7c21df1797ba86906a78e338ec5c33b6747313fb0bf37755624d`
- 本机源码第 208–209 行读取 `MSF_RPC_USER`/`MSF_RPC_PASS`。
- `plugins/msgrpc.rb` 第 49–50 行会输出用户名和密码，托管路径保持禁用。
- `rpm -V` 报告一个嵌入式 sqlite3 gem 缓存归档的元数据差异；R0 将固定实际启动脚本和关键源码哈希。
- 早期预检曾记录 `$HOME/.msf4/db` PostgreSQL 主进程 PID 18131；该外部生命周期在正式门禁前结束，spike 未向其发送信号。最近一次正式门禁的启动前/退出后 protected-process 快照均为空。
- 两条凭据通道均由 systemd user transient service 承载。一次性 Socket 直读 / `LoadCredential` 启动到 Ready 为 1.940 / 1.947 s，完整门禁耗时 12.506 s。
- listener 只绑定动态 `127.0.0.1`，标准 MessagePack 通过默认 TLS `/api/` 传输；每个生命周期固定服务端证书 SHA-256。
- 同 UID 主体在生命周期内可读取最终进程 `/proc/<pid>/environ`；`LoadCredential` 的只读 credential copy 在 Unit 存活期间同样可读。退出后的 listener、进程、cgroup、Socket、credential copy 和 Unit 全部清理。

## Supervisor/cgroup baseline

- systemd user manager 为 259.7，整体状态 `degraded`；无关的 `nvidia-settings` 失败项未影响 transient service、cgroup、resource control、signal 或 collection。
- systemd backend 实测属性：`KillMode=control-group`、`LimitCORE=0`、`NoNewPrivileges=yes`、`MemoryMax=268435456`、`TasksMax=64`、`CPUQuotaPerSecUSec=1s`、`TimeoutStopUSec=2s`、`UMask=0077`。
- 两轮 Release 正式门禁通过。最近一次 systemd/PGID 分阶段取消为 4.072 / 4.021 s，主进程 crash 清理为 0.101 / 0.201 s。
- 64 × 8 KiB 日志 Channel 的队列上限为 512 KiB，预览上限为 256 KiB；最近一次 supervisor RSS 为 2,624 / 3,680 KiB，增量 1,056 KiB。
- abort 产生的 systemd-coredump 条目均为无存储文件状态，fixture runtime 中无 core 文件。所有 transient Unit、cgroup、PGID、进程和 `/run/user/1000/fd-sup-r0-*` 根目录已清理。

## Official references checked on 2026-07-11

- Tauri Fedora prerequisites: <https://v2.tauri.app/start/prerequisites/>
- Tauri capabilities and `AppManifest::commands`: <https://v2.tauri.app/security/capabilities/>
- Tauri Isolation Pattern: <https://v2.tauri.app/concept/inter-process-communication/isolation/>
- SQLite WAL-reset bug: <https://sqlite.org/wal.html#the_wal_reset_bug>
- SQLite current release: <https://www.sqlite.org/releaselog/current.html>
- mise config environments: <https://mise.jdx.dev/configuration/environments.html>
- mitmproxy streaming: <https://docs.mitmproxy.org/stable/overview/features/#streaming>
- mitmproxy `Message.stream`: <https://docs.mitmproxy.org/stable/api/mitmproxy/http.html#Message.stream>
- mitmproxy certificates: <https://docs.mitmproxy.org/stable/concepts/certificates/>
- systemd credentials: <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Credentials>
- systemd transient units: <https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html>
- systemd kill semantics: <https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html>
- systemd resource control: <https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html>
