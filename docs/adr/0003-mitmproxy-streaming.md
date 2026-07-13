# ADR 0003: mitmproxy streaming capture

- 状态：Accepted
- 日期：2026-07-12

## Context

mitmproxy 默认缓冲完整 Body。官方 API 允许在 `requestheaders`/`responseheaders` 设置同步 `Message.stream` transform；callback chunk 边界没有 packet、HTTP/1 chunk 或 HTTP/2/3 frame 语义。FlagDeck 需要在大 Body、提前响应和证据故障下同时保持业务转发状态与证据完整性状态准确。

## Decision

- 锁定 Python 3.12.13、uv 0.11.26 和 mitmproxy 12.2.3，运行参数固定 `store_streamed_bodies=false`。
- 每个请求/响应方向使用 4 MiB / 256-frame 双上限队列、独立有序 writer 和增量 SHA-256；同时活动 writer 上限为 8。
- pass-through 作为默认模式，提供最长 250 ms 的有界入队背压；捕获失败后继续原样转发并提交 `capture_failed`。
- evidence-strict 在返回 chunk 前等待 writer ack，超时为 5 s；失败 chunk 及后续 chunk停止传给目标端，状态保存 writer 已确认的真实前缀。
- Body staging 使用随机名、`O_EXCL`、`0600`、file fsync、SHA-256 命名原子 rename 和目录 fsync；失败前缀只进入私有隔离目录。
- 请求和响应独立终结并通过 flow ID 关联；`client_disconnected` 覆盖提前响应后遗留的未完成请求。
- Proxy 来源固定 `representation_kind=semantic`，保存原始编码 Body。线格式与传输 frame 边界保持在合同外。

## Alternatives assessed

- mitmproxy 完整 Body 缓冲：50 MiB Body 直接扩大 Worker RSS，放弃。
- 无界 asyncio task 或无界队列：缺少确定内存上限与顺序确认，放弃。
- 立即失败的 4 MiB / 64-frame 非阻塞队列：高速 Loopback 的 50 MiB 上传实测触发 `queue_full`；采用 250 ms 有界背压和 256-frame 上限。
- evidence-strict 继续转发失败 chunk：目标端前缀会超过可证明前缀，放弃。
- 依赖 `request` 先于 `response` 完成：提前 413 实测打破该顺序，采用双方向状态。

## Evidence

`spikes/mitm-streaming/evidence/results.json` 的 17 个真实代理场景全部通过。HTTP/HTTPS 的 50 MiB 上传与下载在源、目标和 Artifact 三端字节数及 SHA-256 一致；pass-through / evidence-strict 增量 RSS 分别为 5,868 / 732 KiB，门禁上限为 32 MiB。

pass-through 的 50 MiB HTTP 上传/下载吞吐为 649.6 / 641.0 MiB/s，strict 为 315.4 / 360.3 MiB/s。正式 pass-through 最大队列为 4 MiB / 81 frames，最大单次入队等待 0.72 ms。严格 writer crash 的 Capture 确认前缀与目标端实收均为 262,144 bytes。Ruff、mypy strict 与 pytest 13/13 通过。

## Remaining risk

真实磁盘配额、设备 I/O error、断电、HTTP/2 多路并发和长连接 soak 进入 R3/Beta 前专项门禁。strict 故障后的客户端终结由 5 s 超时限定。解压预览继续执行解压后大小和压缩比上限。

## References checked 2026-07-12

- <https://docs.mitmproxy.org/stable/overview/features/#streaming>
- <https://docs.mitmproxy.org/stable/api/mitmproxy/http.html#Message.stream>
- <https://docs.mitmproxy.org/stable/api/events.html>
- <https://docs.mitmproxy.org/stable/concepts/certificates/>
