# SQLite safety spike

## Goal and hypothesis

冻结无 WAL-reset 缺陷的 bundled SQLite、单写入线程、短读事务、Online Backup API 和非阻塞项目 `flock`。假设 `rusqlite 0.40.1` 的 `bundled` + `backup` 组合能够在 Fedora 44 上满足全部合同。

## Risks

- WAL checkpoint 与并发 commit 的竞态可能损坏数据库。
- 直接复制活动数据库可能得到不一致快照。
- PID 判断或锁文件内容无法替代内核持有的 `flock`。
- migration 半途失败可能留下部分 schema。

## Pass conditions

- 运行时 SQLite ≥3.51.3 且 FTS5 门禁通过。
- 安全 PRAGMA 设置与回读完全一致。
- 有界单写入队列、并发短读和 writer-owned checkpoint 稳定完成。
- SIGKILL/abort 后 `integrity_check` 通过，所有已确认 commit 均存在。
- 活动写入期间 Online Backup 快照内部一致，可恢复且哈希有效。
- 第二写入进程被 `flock` 拒绝，显式只读进程可读取。
- 失败 migration 全量回滚，备份可恢复；活动数据库 raw copy 路径被合同拒绝。

## Reproduction

```bash
MISE_LOCKED=1 mise run r0-sqlite
MISE_LOCKED=1 mise run r0-sqlite-evidence
```

## Result: PASS

- `rusqlite 0.40.1` 锁定 `libsqlite3-sys 0.38.1` 与 bundled SQLite 3.53.2，运行时 source ID 为 `d6e03d8c…df1a24`。
- 安全 PRAGMA、FTS5、2,000 行单写入队列压力、四读线程和 21 次 checkpoint 全部通过。
- 活动写入期间 Online Backup 产生 2,400 行一致快照；完整性、外键与逐行 SHA-256 全部通过。
- 10 次 Release 复跑全部 PASS。压力段 p50 311.5 ms、p95 391 ms；Backup 段 p50 2,598 ms、p95 2,610 ms。
- 每轮 SIGKILL 前确认 26–28 个事务，全部恢复；abort 前确认事务同样恢复。
- 第二写入进程固定退出 73；显式只读进程全部成功。
- migration 失败事务完整回滚，v1 Backup 可恢复；raw filesystem copy 合同全部拒绝。

结构化证据：`evidence/results.json`、`evidence/summary.json` 和 `evidence/release-runs/`。Release 代表性结果与汇总文件权限均为 `0600`。

剩余风险：R0 使用进程级 SIGKILL/abort，未模拟断电、存储设备写缓存失效或内核崩溃；这些情形进入 R3 故障注入矩阵。SQLite 官方 WAL-reset 定向 test-control harness 未暴露给 bundled release API，本门禁依赖已修复的 3.53.2 source ID 与高层并发回归。
