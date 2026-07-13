# mitmproxy streaming capture spike

状态：`PASS`（2026-07-12，Fedora 44 x86-64）

## 结论

mitmproxy 12.2.3 的同步 `Message.stream` callback 可以在固定容量队列内完成 50 MiB 请求与响应捕获。正式门禁覆盖 HTTP/HTTPS、Content-Length、chunked、无长度、gzip/br 原始编码 Body、提前 413、连接截断、队列满、writer 崩溃与 ENOSPC，共 17 个场景；源、目标端与完整 Artifact 的字节数及 SHA-256 均一致。

Worker 稳态基线、峰值和增量 RSS 如下：

| 模式 | 稳态基线 | 峰值 | 增量 | 50 MiB HTTP 上传/下载吞吐 |
|---|---:|---:|---:|---:|
| pass-through | 75,152 KiB | 81,020 KiB | 5,868 KiB | 649.6 / 641.0 MiB/s |
| evidence-strict | 75,012 KiB | 75,744 KiB | 732 KiB | 315.4 / 360.3 MiB/s |

两种模式均满足 32 MiB 增量 RSS 门禁。数字来自本机 Loopback fixture，用于容量与回归基线。

## 冻结合同

- Python 3.12.13、uv 0.11.26、mitmproxy 12.2.3；精确解析位于独立 `uv.lock`。
- 每个 Body 方向使用 4 MiB / 256-frame 双上限队列和一个有序 writer；同时活动 writer 上限为 8。
- pass-through 的队列入队背压最长 250 ms；超时、writer 或哈希失败后继续原样转发，并提交 `capture_failed`。
- evidence-strict 每个 chunk 等待 writer ack，最长 5 s；失败 chunk 与后续 chunk 返回空字节，目标端只收到已确认前缀，结束阶段显式失败连接。
- staging/Artifact/failed 目录为 `0700`，文件为 `0600`；随机 staging 名通过 `O_EXCL` 创建，完成路径执行 file `fsync`、SHA-256 命名原子 rename 和目录 `fsync`。
- `store_streamed_bodies=false`，请求与响应分别终结并由 flow ID 关联。客户端在提前响应后断开时，`client_disconnected` hook 负责提交未完成请求前缀。
- 上游 TLS 校验保持开启；HTTPS fixture 使用项目私有 CA 显式建立信任。
- `representation_kind=semantic`。保存内容包含语义 HTTP 元数据和原始编码 Body bytes；HTTP/1 chunk 边界、Header 原始空白、HTTP/2/3 frame、HPACK/QPACK 和 packet 边界均不进入合同。

正式 50 MiB 测试中，pass-through 队列峰值为 4 MiB / 81 frames，最长单次入队等待 0.72 ms。64-frame 的早期候选在高速 Loopback 上传中准确触发 `queue_full`，因此正式上限冻结为 256 frames。

## 故障语义证据

- queue full、writer crash 和 ENOSPC 的 pass-through 请求均让目标端收到完整 2 MiB，Capture 状态为 `capture_failed`，完整 Artifact 路径保持空值，失败前缀位于私有 `failed/` 隔离区。
- evidence-strict writer crash 时，Capture 的 `captured_bytes`、`forwarded_bytes` 和目标端实收均为 262,144 bytes；客户端发送的其余 bytes 未进入目标端请求 Body。
- 提前 413 的响应先以 `streamed_complete` 提交，请求随后由 `client_disconnected` 以 `truncated` 提交；两个方向共享同一 flow ID。
- 截断响应声明 2 MiB、实收/捕获 524,288 bytes，客户端长度检查与 Capture `truncated` 状态一致。

## 复现

```bash
MISE_LOCKED=1 mise run r0-mitm-sync
MISE_LOCKED=1 mise run r0-mitm-static
MISE_LOCKED=1 mise run r0-mitm-evidence
```

静态门禁当前为 Ruff、mypy strict 和 pytest 13/13。真实代理结果位于 `evidence/results.json`，摘要位于 `evidence/summary.json`，两者权限均为 `0600`。完整临时 Body Artifact 在校验后自动清理，仓库仅保留结构化测量证据。

## 剩余风险

- R0 使用进程内 ENOSPC/writer fault 注入；真实文件系统配额、设备 I/O error 和断电进入 R3。
- strict 失败在同步 callback 内停止 Body 转发，mitmproxy 12.2.3 会在客户端结束上传后终结该 Flow；当前最坏客户端等待由 5 s 超时限制。
- 32 MiB 门禁覆盖单个 50 MiB 方向。多 Flow 并发、HTTP/2 多路复用和长连接 soak 进入 Beta 前专项基准，活动 writer 上限持续提供硬边界。
- 解压预览未进入本 spike；产品合同继续要求解压后大小和压缩比上限。

## 官方资料（2026-07-12 核对）

- <https://docs.mitmproxy.org/stable/overview/features/#streaming>
- <https://docs.mitmproxy.org/stable/api/mitmproxy/http.html#Message.stream>
- <https://docs.mitmproxy.org/stable/api/events.html>
- <https://docs.mitmproxy.org/stable/concepts/certificates/>
