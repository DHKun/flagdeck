# FlagDeck R0 gate report

状态：`COMPLETE / PASS`

建议进入 R1：`YES`，生效条件为用户接受本报告中的五项门禁、冻结参数和剩余风险。R0 已按实施提示停止产品功能开发。

## 五项门禁

| 门禁 | 结果 | 证据 | 剩余风险 | ADR |
|---|---|---|---|---|
| SQLite | PASS | Release 10/10；SQLite 3.53.2；FTS5、WAL、SIGKILL/abort、Online Backup、flock、migration；`summary.json` SHA-256 `1965347b…fba96` | 断电、存储故障和定向 WAL-reset 注入进入 R3 | 0001 |
| Tauri | PASS | 当前 Release 10/10 WebKitWebDriver；main allow / probe deny；恶意 DOM、file、navigation、window 全阻止；SHA-256 `4974925a…07cf8` | Linux iframe IPC 来源限制；Wayland/NVIDIA 测试开关；clean-build 可复现性进入 R7 | 0002 |
| mitmproxy | PASS | 17 场景；HTTP/HTTPS 50 MiB 三端 SHA-256 一致；增量 RSS 5,868/732 KiB；`results.json` SHA-256 `d43191bd…0f6f` | 真实磁盘故障、HTTP/2 多路并发和长连接 soak 进入 R4/Beta 门禁 | 0003 |
| Metasploit | PASS | 两条凭据通道；TLS pin；只读 RPC + Token 过期/单次重认证；泄漏扫描；6/6 清理；`results.json` SHA-256 `09c34616…08b0` | 同 UID 可读取最终环境；`LoadCredential` unit-lifetime copy 同 UID 可读 | 0004 |
| Supervisor | PASS | 九进程树；systemd/PGID 取消 4.072/4.021 s；crash 0.101/0.201 s；日志增量 RSS 1,056 KiB；`results.json` SHA-256 `88da65a8…e264` | PGID 无资源强制上限，动态未知后代与 check-to-signal 竞态进入 R3 | 0005 |

全部门禁为 PASS，无 FAIL 或 BLOCKED。

## 可审计工时

- R0 首个实现文件：2026-07-11 20:39:52 +08:00。
- 最终门禁与报告收口：2026-07-12 10:25 +08:00。
- 可审计 wall-clock：13 小时 45 分，折合 1.72 个 8 小时工作日，包含构建、依赖同步、实机等待、失败候选校准、两轮正式门禁和文档。
- 自动化代理没有单独的纯活跃工时遥测，因此总工时采用文件时间、证据时间与命令结果可复核的 wall-clock 窗口。后续估算继续采用计划定义的单人完整实现工作日口径。

## 最终锁定

| 层 | R0 决定 |
|---|---|
| Rust / 工具链 | rustc/cargo 1.96.0；mise 2026.7.0；项目锁定 Node 22.22.2、pnpm 11.7.0、Python 3.12.13、uv 0.11.26 |
| SQLite | `rusqlite 0.40.1` + `libsqlite3-sys 0.38.1` bundled SQLite 3.53.2；运行时最低 3.51.3；features `bundled,backup`；FTS5 启动门禁 |
| SQLite 写入/导出 | 容量 32 的单写入线程；短 read-only connection；writer-owned checkpoint；项目 `flock`；导出只走 Online Backup API |
| Tauri | Tauri 2.11.5、tauri-build 2.6.3、API 2.11.1、CLI 2.11.4、Svelte 5.56.4、Vite 8.1.4、TypeScript 6.0.3 |
| Tauri 边界 | `main` label 显式 capability；Isolation hook；可信打包资源；目标数据只进入文本/Hex/结构化预览；远程 navigation/new-window 拒绝；Release DevTools 关闭 |
| mitmproxy | mitmproxy 12.2.3；Python 3.12.13；独立 uv 环境；`store_streamed_bodies=false`；semantic representation 与原始编码 Body bytes |
| systemd Supervisor | `/usr/bin/systemd-run` user transient service；唯一 Unit/cgroup；Unit + Invocation ID + MainPID + cgroup + start time 归属；PGID 为受限回退 |
| systemd Unit 属性 | `KillMode=control-group`、`LimitCORE=0`、`NoNewPrivileges=yes`、`MemoryMax=256MiB`、`TasksMax=64`、`CPUQuota=100%`、`TimeoutStopSec=2s`、`UMask=0077` |
| Metasploit | Framework RPM 6.4.135；`msfrpcd` 前台动态 `127.0.0.1`；默认 TLS；标准 MessagePack `/api/`；省略 `-j/-S/-U/-P`；托管 `msgrpc` 禁用 |
| Metasploit认证 | 每生命周期随机用户名与 384-bit 输入熵密码；TLS 证书生命周期 pin；401 后最多一次重认证和一次幂等只读重放；执行类自动重放禁用 |

计划中的 TargetScope、HttpMessage、CommandSpec、Job、Discovery、Artifact、AdapterEntity 与 Adapter v1 定义继续作为 v3.1 架构基线。类型化代码、migration 和跨对象合同测试属于 R1 交付。

## mitmproxy 冻结参数

| 参数 | pass-through | evidence-strict |
|---|---:|---:|
| 每方向队列 | 4 MiB / 256 frames | 4 MiB / 256 frames |
| 同时活动 writer | 8 | 8 |
| 入队等待 | 最长 250 ms | 最长 250 ms |
| writer ack | 异步有序提交 | 每 chunk 最长 5 s |
| 捕获故障 | 转发继续，状态 `capture_failed` | 停止失败 chunk 与后续转发，保存已确认前缀 |
| 默认模式 | 是 | 显式证据操作 |
| Worker 增量 RSS 门禁 | ≤32 MiB | ≤32 MiB |
| 实测增量 RSS | 5,868 KiB | 732 KiB |

50 MiB HTTP pass-through 上传/下载为 649.6/641.0 MiB/s，strict 为 315.4/360.3 MiB/s。pass-through 峰值队列为 4 MiB/81 frames，最长单次入队等待 0.72 ms。strict writer crash 的目标端实收与已确认 Capture 前缀均为 262,144 bytes。

## Supervisor 与秘密通道冻结

systemd `LoadCredential=ID:<one-shot AF_UNIX socket>` 为 Metasploit 首选通道；同一 Rust launcher 直接读取一次性私有 Socket 为回退。launcher SHA-256 为 `66c666414768eda2364ca900db1a9a677ff4e14b2458063a4515d8c7db3ceb43`。两条通道的 Ready 时间为 1.940/1.947 秒，清理断言均为 6/6。

`LoadCredential` 在 Unit 生命周期内增加一个 systemd 管理的只读 credential copy，本机同 UID 实测可读。最终 `msfrpcd` 环境的 `MSF_RPC_USER/MSF_RPC_PASS` 同样可由同 UID 主体通过 `/proc/<pid>/environ` 读取。Unit 停止后 credential copy、Socket、目标进程与环境全部消失。Unit、D-Bus 属性、journal、argv、普通日志、SQLite、源文件和 coredump metadata 均未发现凭据字面量。

Supervisor 取消序列冻结为 `SIGINT → 2 s → SIGTERM → 2 s → SIGKILL`，5 秒内必须清空边界。stdout/stderr Channel 固定 64 × 8 KiB，队列上限 512 KiB，预览上限 256 KiB。PGID 回退通过 PID + start ticks + PGID 复核根进程组，逃逸 Session 后代逐 PID 复核。

## 测试、性能与失败数

| 命令/门禁 | 最终结果 |
|---|---|
| `MISE_LOCKED=1 mise run r0-sqlite` | 1/1 集成门禁；0 failures |
| `MISE_LOCKED=1 mise run r0-sqlite-evidence` | 当前 Release 代表性门禁 PASS；二进制自哈希 `5dc6a5e2…b2d89` |
| `MISE_LOCKED=1 mise run r0-tauri-static` | Vitest 9/9、Rust 3/3、Svelte 0 error/0 warning；0 failures |
| `MISE_LOCKED=1 mise run r0-tauri-release-gate` | 当前 Release WebDriver 10/10；0 failures |
| `MISE_LOCKED=1 mise run r0-mitm-static` | pytest 13/13、Ruff、mypy strict；0 failures |
| `MISE_LOCKED=1 mise run r0-mitm-evidence` | 17/17 真实 HTTP/HTTPS/fault 场景；0 failures |
| `MISE_LOCKED=1 mise run r0-msf-static` | Rust 3/3、Python 6/6、Clippy/Ruff/mypy；0 failures |
| `MISE_LOCKED=1 mise run r0-msf-evidence` | 两通道、10 项顶层断言；连续两轮 PASS |
| `MISE_LOCKED=1 mise run r0-supervisor-static` | Rust 3/3、Clippy；0 failures |
| `MISE_LOCKED=1 mise run r0-supervisor-evidence` | systemd/PGID、14 项顶层断言；连续两轮 PASS |

最终静态回归共 38 个测试，失败数为 0。SQLite Release 10-run 压力 p50/p95 为 311.5/391 ms，Online Backup 为 2,598/2,610 ms。Metasploit 完整两通道门禁为 12.506 秒。Supervisor 完整门禁为 10.132 秒，systemd/PGID 取消为 4.072/4.021 秒，日志采集 RSS 增量为 1,056 KiB。

当前 R0 Release 产物体积：SQLite 3,254,208 bytes；Tauri 10,415,032 bytes；Metasploit credential launcher 623,648 bytes；Supervisor 1,235,400 bytes。mitmproxy 独立 `.venv` 为 183,701,238 bytes。

## 安全扫描与清理

- SELinux 在全部正式门禁期间保持 Enforcing，cgroup v2 与 systemd 259.7 user manager 可用。
- Tauri 主窗口授权与 probe 拒绝、Isolation iframe、恶意 DOM、file URL、远程 navigation/new-window 均在真实 WebKitWebDriver 中验证。
- mitmproxy listener/fixture 只绑定动态 Loopback；CA、staging、失败前缀和 evidence 权限为 `0700/0600`。
- Metasploit listener 通过 inode、PID、Unit 和 cgroup 证明归属；正式门禁前后 protected process 快照一致。
- Supervisor 的错误 Invocation ID、错误 start ticks 均被拒绝；独立 protected sentinel 在四个生命周期之后身份保持一致。
- 两个 abort 场景产生无存储文件的 systemd-coredump metadata，runtime core 文件数为 0。
- 最终审计未发现 `flagdeck-*r0*` Unit、受管进程、listener、临时 Socket、credential copy 或 `/run/user/1000/fd-*-r0-*` 目录残留。

## 路线图处置

| 处置 | 项目 |
|---|---|
| 继续 | Rust Core + Tauri/Svelte、bundled SQLite 单写入器、Artifact 原子提交、Adapter v1、systemd Supervisor、mitmproxy 进程 Worker、Metasploit Loopback RPC |
| 收缩 | PGID 只作为显式降级后端；目标 HTML 保持数据预览且不进入 IPC WebView；evidence-strict 只用于用户明确选择的证据操作；R5 首批 RPC 继续只读后再开放 L3 执行 |
| 替换 | 系统 SQLite 3.51.2 由 bundled 3.53.2 替换；托管 `msgrpc` 由受管 `msfrpcd` 替换；PID-only 恢复由 Invocation ID/cgroup 或 PID+start-time+PGID 复核替换 |

## 与 PROJECT_PLAN.md 的偏差及 ADR

- ADR 0001 将系统 SQLite 候选收敛为 bundled 3.53.2，原因是本机 3.51.2 落入官方 WAL-reset 缺陷范围。
- ADR 0002 保持目标内容的数据化预览；Wayland/NVIDIA workaround 只存在于 WebDriver 子进程。Tauri Isolation 构建材料参与二进制，release gate 现在执行“构建一次、绑定哈希、同产物测试十次”。
- ADR 0003 将早期 4 MiB/64-frame 无等待候选调整为 4 MiB/256-frame + 250 ms 有界等待，原因是高速 Loopback 50 MiB 上传准确触发 queue full。
- ADR 0004 在两个通过候选中冻结 `LoadCredential`，并保留直接 Socket 回退；同 UID 暴露进入正式威胁模型。
- ADR 0005 为 systemd/PGID 冻结具体资源值、日志 Channel 和归属算法；PGID 通过已登记逃逸后代补足固定 fixture 的完整清理。
- `IMPLEMENTATION_PROMPT.md` 将七个数据契约的代码实现列入 R1；R0 只保留 v3.1 计划定义并完成五个最小 spike。
- 提示中提到的 `锐评byclaude.md` 与 `锐评bychatgpt.md` 在 `/data/CTF` 文件名搜索中缺失；`PROJECT_PLAN.md` v3.1 第 20 节作为吸收决策基线。

## R1–R7 重新估算

| 阶段 | 原估算 | R0 后估算 | 调整依据 |
|---|---:|---:|---|
| R1 Rust/Tauri 安全平台壳 | 5–8 | 5–7 | SQLite/Tauri/Supervisor 合同已实证；七对象、IPC、Artifact 和 migration 仍需产品化 |
| R2 纵向 Alpha | 8–12 | 8–12 | dddd/ffuf/Arjun/curl 的真实输出、解析和恢复尚未进入 R0 |
| R3 可靠编排 | 5–8 | 4–7 | cgroup、PGID、秘密通道与日志上限已冻结；pidfd、动态发现、导出和 soak 仍需完成 |
| R4 HTTP Beta | 15–25 | 13–21 | 50 MiB 双模式流式捕获已通过；History/Repeater/Diff/Chrome/SQLMap/Raw HTTP 仍是主体工作 |
| R5 Metasploit | 8–15 | 7–12 | 安全生命周期与协议已通过；模块选项、Job/Console/Session、Workspace 和 L3 门禁仍需实现 |
| R6 Intruder/上传 | 15–25 | 15–25 | Multipart、宏、状态链和 UploadRanger 合同尚未实证 |
| R7 稳定发布 | 7–12 | 7–11 | Fedora/Wayland/SELinux 基线已覆盖；RPM、SBOM、签名、clean-build、升级卸载仍需完整门禁 |

R1–R7 剩余总量从 63–105 调整为 59–95 个工作日，减少 4–10 个工作日。累计项目量采用已完成 R0 的 1.72 可审计工作日加剩余 59–95 个单人工作日；后续阶段按验收门禁推进。

## 未解决问题与下一步证据

| 问题 | 复现/观测 | 下一步证据 |
|---|---|---|
| SQLite 真实断电、设备 I/O error、WAL-reset 定向触发 | 当前只覆盖 SIGKILL/abort 与 Online Backup | R3 使用 disposable filesystem/VM fault injection，重复完整 DB 合同 |
| Tauri clean-build 哈希与 Isolation 构建材料 | 连续 rebuild 会产生新的受测二进制哈希 | R7 在隔离 build root 比较两次 clean build，签名对象在构建后执行同产物 10-run gate |
| Linux iframe IPC 来源限制与 WebKitGTK 风险 | 目标内容当前只进入文本节点 | R1 对所有 preview sink 做静态+桌面回归；任何 iframe 提案重新进入安全门禁 |
| mitmproxy HTTP/2 多路并发、长连接与真实磁盘错误 | R0 为 HTTP/1 Loopback 与进程内 fault injection | R4/Beta 执行并发多 Flow、磁盘配额/设备错误、12h soak 与 RSS 曲线 |
| Metasploit 同 UID 凭据读取 | `/proc/<pid>/environ` 与 unit-lifetime credential copy 已实测 | R5 评估 user namespace/独立 UID；GUI 明示当前隔离等级并继续最短生命周期 |
| PGID 未知新后代与 check-to-signal 竞态 | 固定 fixture 的已登记逃逸后代已清理 | R3 引入 pidfd、动态 `/proc` 后代发现与 race stress；systemd 保持默认后端 |
| systemd-coredump metadata 保留 | `COREFILE=none`，无存储文件 | R7 核对 RPM 默认策略、journal 脱敏和 crash export 排除规则 |
| 两份锐评原文缺失 | `find /data/CTF` 文件名搜索无结果 | 用户提供原文件后做一次 v3.1 差异审计；当前不阻塞 R1 |

## 锁文件

| 锁文件 | SHA-256 |
|---|---|
| `Cargo.lock` | `2f17545ca8ccb032101084b91cd960e7690d47060b6bcf966d83943fe199f91d` |
| `mise.lock` | `1478f8b6b1da3b02082b50ab61d67405257ab948442006151300caa5e69108ed` |
| `spikes/tauri-security/pnpm-lock.yaml` | `df5612d099179a06c495b47fd4c375ff1bea78ee2fce95600b2fcc6ff5eb1d01` |
| `spikes/mitm-streaming/uv.lock` | `cc8704c74a594fe863f7d44115b07bcbff30005b2cfecbd2a6d521d8785f06cf` |
| `spikes/metasploit-rpc/uv.lock` | `8250e564c35a4fb7ad070ddedeccabd26e730221951e8d5163ed380c82f042bc` |

## 复现入口

```bash
MISE_LOCKED=1 mise run r0-sqlite
MISE_LOCKED=1 mise run r0-sqlite-evidence

MISE_LOCKED=1 mise run r0-tauri-install
MISE_LOCKED=1 mise run r0-tauri-static
MISE_LOCKED=1 mise run r0-tauri-release-gate

MISE_LOCKED=1 mise run r0-mitm-sync
MISE_LOCKED=1 mise run r0-mitm-static
MISE_LOCKED=1 mise run r0-mitm-evidence

MISE_LOCKED=1 mise run r0-msf-sync
MISE_LOCKED=1 mise run r0-msf-static
MISE_LOCKED=1 mise run r0-msf-evidence

MISE_LOCKED=1 mise run r0-supervisor-static
MISE_LOCKED=1 mise run r0-supervisor-evidence
```

## 官方资料核对

| 范围 | 版本/日期 | 官方资料 |
|---|---|---|
| SQLite WAL/Backup | SQLite 3.53.2；2026-07-11 | <https://sqlite.org/wal.html#the_wal_reset_bug>、<https://sqlite.org/backup.html>、<https://www.sqlite.org/releaselog/current.html> |
| Tauri capability/Isolation/WebDriver | Tauri 2.11.5；2026-07-11 | <https://v2.tauri.app/security/capabilities/>、<https://v2.tauri.app/concept/inter-process-communication/isolation/>、<https://v2.tauri.app/develop/tests/webdriver/> |
| Tauri Fedora prerequisites | WebKitGTK 2.52.4；2026-07-11 | <https://v2.tauri.app/start/prerequisites/> |
| mise config isolation | mise 2026.7.0；2026-07-11 | <https://mise.jdx.dev/configuration/environments.html> |
| mitmproxy streaming/events/certificates | mitmproxy 12.2.3；2026-07-12 | <https://docs.mitmproxy.org/stable/overview/features/#streaming>、<https://docs.mitmproxy.org/stable/api/mitmproxy/http.html#Message.stream>、<https://docs.mitmproxy.org/stable/api/events.html>、<https://docs.mitmproxy.org/stable/concepts/certificates/> |
| systemd credentials/transient Unit/kill/resources | systemd 259.7；2026-07-12 | <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Credentials>、<https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html>、<https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html>、<https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html> |
| Metasploit RPC | Framework 6.4.135；2026-07-12 | <https://docs.rapid7.com/metasploit/rpc-api/>、<https://docs.rapid7.com/metasploit/standard-api-methods-reference>，以及锁定 RPM 内 `msfrpcd`/RPC v10/`msgrpc.rb` 源码 |
| Linux Session 与进程身份 | kernel 7.1.3；2026-07-12 | <https://man7.org/linux/man-pages/man2/setsid.2.html>、<https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html> |

进入 R1 前的精确决策门禁：接受 ADR 0001–0005、mitmproxy 4 MiB/256-frame + pass-through 默认、Metasploit `LoadCredential` + 同 UID 暴露、systemd 主后端 + 受限 PGID 回退，以及 R1–R7 的 59–95 工作日重估。
