# ADR 0006: Core contracts and project storage

- 状态：Accepted
- 日期：2026-07-12

## Context

R1 需要把项目、HTTP、命令、任务、发现、证据和 Adapter 状态固定为可迁移、可生成 Schema、可跨语言验证的合同。SQLite 保存状态与索引，大正文和二进制进入内容寻址 Blob。

## Decision

- 合同版本固定为 `1`，Adapter 协议固定为 `flagdeck.adapter.v1`。
- 七个核心对象由 `flagdeck-domain` 定义，并生成 JSON Schema Draft 2020-12 与 TypeScript 类型。
- SQLite 使用单写线程和容量 32 的同步队列；读取连接使用 `query_only=ON`。
- 项目使用 UUID 目录和非阻塞独占 `flock`；显式只读打开不启动 writer、migration 或 checkpoint。
- Artifact 依次执行私有 staging、流式 SHA-256、文件 fsync、大小/哈希验证、内容寻址 rename、父目录 fsync、人类清单原子写入和 SQLite 最终事务。
- 启动恢复将活动任务标记为 `interrupted`，并将 staging Artifact 晋升为 committed 或降为 orphaned。
- migration 前与显式快照使用 SQLite Online Backup API。

## Evidence

`flagdeck-domain` 4 项合同测试、`flagdeck-storage` 7 项权限/锁/Artifact/恢复/migration 测试、`flagdeck-core` 6 项授权/预览/分页/错误脱敏测试全部通过。WebDriver 的 10 次独立项目生命周期验证均得到 0700 目录、0600 文件、空 tmp、Blob 文件名哈希一致和清单哈希一致。

## Remaining risk

R3 将为 Adapter Host 增加 deadline、幂等、事件缺口、resync 和崩溃恢复。R5/R7 将覆盖 100,000 条 Discovery、50 MiB Body、导出原子包和断电级故障注入。
