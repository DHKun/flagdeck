# ADR 0001: SQLite engine and project writer protocol

- 状态：Accepted
- 日期：2026-07-11

## Context

FlagDeck 同时需要 WAL 并发读取、单写入器、在线一致备份、崩溃恢复、FTS5 和 migration 回滚。SQLite 3.7.0–3.51.2 存在官方公布的 WAL-reset 竞态；最低安全版本固定为 3.51.3。

## Decision

- 使用 `rusqlite 0.40.1`，features 为 `bundled` 与 `backup`。
- 运行时断言 `sqlite3_libversion_number >= 3051003` 并执行 FTS5 查询门禁。
- 使用容量 32 的同步队列和一个专用写线程；checkpoint 也只经该线程执行。
- 每个读线程使用 read-only connection、短查询、`query_only=ON`。
- 项目写权限由 `.flagdeck.lock` 的非阻塞独占 `flock` 决定；锁内容仅用于诊断。
- 导出与 migration 前快照只使用 SQLite Online Backup API。

## Alternatives assessed

- 系统 SQLite 3.51.2：存在 WAL-reset 缺陷，R0 拒绝。
- 直接复制活动 `project.sqlite`：无法包含一致 WAL 状态，合同拒绝。
- 多写连接：扩大 checkpoint/commit 竞态与状态机复杂度，R0 放弃。
- PID 文件单实例：无法安全处理 PID 复用，放弃作为所有权依据。

## Evidence

`spikes/sqlite-safety/evidence/results.json` 和 10 份 Release 原始结果显示：SQLite 3.53.2；PRAGMA/FTS5 全部回读正确；10/10 并发压力、活动 Backup、SIGKILL/abort 恢复、双进程锁和 migration 均通过。Release 压力段 p50/p95 为 311.5/391 ms，Backup 为 2,598/2,610 ms。第二写入者每轮退出 73，显式只读每轮退出 0。

`Cargo.lock` 固定 `rusqlite 0.40.1`、`libsqlite3-sys 0.38.1` 和 bundled SQLite 3.53.2。正式合同采用最小版本断言 3.51.3，当前 R0 source ID 固定为 3.53.2 的 `d6e03d8c…df1a24`。

## Remaining risk

进程级故障注入覆盖 SIGKILL 与 abort。断电、存储写缓存失效、内核崩溃和 SQLite test-control 定向 WAL-reset 触发器进入 R3；项目导出继续强制 Online Backup 与内容 manifest。

## References checked 2026-07-11

- <https://sqlite.org/wal.html#the_wal_reset_bug>
- <https://sqlite.org/backup.html>
- <https://www.sqlite.org/pragma.html>
- <https://docs.rs/crate/rusqlite/0.40.1>
