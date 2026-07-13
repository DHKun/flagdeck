# Metasploit RPC R0 spike

状态：`PASS`（2026-07-12）

本 spike 验证本机 Metasploit Framework 6.4.135 的受管只读 RPC 生命周期，并比较两条一次性凭据通道。正式门禁连续两次通过；最近一次结果保存在 `evidence/results.json`。

## 冻结合同

- 受管目标固定为 `/opt/metasploit-framework/embedded/framework/msfrpcd`，只允许绝对路径和 argv 数组，直接 `execve`，Shell 保持禁用。
- 参数固定为 `-f -a 127.0.0.1 -p <dynamic> -t 2 -n`。`-j`、`-S`、`-U`、`-P` 保持省略，对应默认 TLS、标准 MessagePack 和环境凭据。
- 凭据通道采用 systemd user service 的 `LoadCredential=ID:<AF_UNIX socket>`；一次性私有 AF_UNIX Socket 直读作为回退。
- launcher 固定 SHA-256 `66c666414768eda2364ca900db1a9a677ff4e14b2458063a4515d8c7db3ceb43`，从通道读取二进制长度前缀 payload，校验 peer/长度，清零中间 buffer，只向最终进程注入 `MSF_RPC_USER`/`MSF_RPC_PASS`。
- 每次生命周期生成随机用户名和 `secrets.token_urlsafe(48)` 密码，输入熵为 384 bit，当前 ASCII 密码长度为 64 bytes。
- Ready 条件包含动态 Loopback listener 的 socket inode、PID、Unit、Invocation ID 和 cgroup 归属，以及本次 TLS 证书 SHA-256 固定。
- 只读调用覆盖 `auth.login`、`core.version` 与 `auxiliary/scanner/http/http_version` 元数据。Token 闲置 2 秒后产生 401；客户端最多重新认证一次并重放一次幂等只读请求。执行类调用自动重放保持禁用。
- 退出顺序为 `auth.logout`、停止唯一 Unit、验证 listener/process/cgroup/socket/credential copy/Unit 全部消失。

## 通道比较

| 候选 | 启动时间 | 生命周期内凭据副本 | 退出清理 | 决定 |
|---|---:|---|---|---|
| 一次性 AF_UNIX Socket 直读 | 1.940 s | launcher 内存与最终进程环境 | 6/6 | 回退 |
| systemd `LoadCredential` 从 AF_UNIX Socket 读取 | 1.947 s | systemd 只读 unit-lifetime credential、launcher 内存与最终进程环境 | 6/6 | 采用 |

选择 `LoadCredential` 后，user manager 负责一次读取和 Unit 生命周期清理，Unit 元数据只保存 credential ID/Socket 路径。两条路径的启动时间差为 6.7 ms，未形成性能门槛。

## 正式证据

- 最近一次门禁耗时 12.506 s，两条通道全部通过。
- TLS pin、Loopback listener 归属、只读 RPC、Token 过期、单次重认证/重放和 logout 全部通过。
- `systemctl show`、D-Bus 属性、journal、argv、普通日志、runtime/source 文件与 coredump metadata 未发现凭据字面量。
- 运行期间 `/proc/<pid>/environ` 对同 UID 主体暴露 `MSF_RPC_USER`/`MSF_RPC_PASS`；`LoadCredential` 路径还存在同 UID 可读的 unit-lifetime credential copy。Unit 停止后两处均消失。
- 两次门禁的 protected-process 快照保持一致；最近一次启动前后均为空。
- launcher Release 二进制为 623,648 bytes。Rust 测试 3/3、Python 测试 6/6，Clippy、Ruff 和 mypy strict 全部通过。

## 复现

```bash
MISE_LOCKED=1 mise run r0-msf-sync
MISE_LOCKED=1 mise run r0-msf-static
MISE_LOCKED=1 mise run r0-msf-evidence
```

门禁只访问动态 `127.0.0.1` Endpoint，只调用只读 RPC。健康检查使用 RPM 元数据、静态源码、文件哈希和受管 `core.version`；`msfconsole --version`、`msfrpcd -h`、`msfdb init`、`msfdb reinit` 保持禁用。托管 `msgrpc` 路径保持禁用，其本机源码会输出用户名和密码。
