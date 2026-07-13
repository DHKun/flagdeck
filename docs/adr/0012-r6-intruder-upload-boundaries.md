# 0012 — R6 Intruder 与上传边界

- 状态：Accepted
- 日期：2026-07-13
- 版本：0.6.0；Domain `CONTRACT_VERSION=6`；Storage `SCHEMA_VERSION=6`
- 相关：[[0006-core-contracts-and-storage]]、[[0010-r4-http-beta-boundaries]]、[[0011-r5-metasploit-product-boundaries]]

## 背景

R6 交付 Stable 的 Intruder、Multipart 结构化编辑、文件上传变异、CSRF/状态链和上传结果验证。目标返回的 Multipart bytes、Header、文件名、响应和日志一律视为不可信输入，所有请求在发出前必须通过 TargetScope 校验，L3 上传执行验证要求精确确认短语并写入审计。

## 决策

### 数据契约（Domain, CONTRACT_VERSION=6）

- 新增标识：`IntruderCampaignId`、`IntruderAttemptId`、`StateChainRunId`。
- 新增枚举：`IntruderAttackMode`（Sniper/BatteringRam/Pitchfork/ClusterBomb）、`IntruderCampaignKind`、`IntruderCampaignState`、`IntruderAttemptState`、`PayloadLocation`、`UploadMutationKind`（八类）。
- 新增对象：`IntruderCampaign`、`IntruderAttempt`、`StateChainRun`/`StateChainStepEvidence`、`PayloadPosition`、`MultipartDocument`/`MultipartPart`。
- 冻结 JSON Schema 由 7 个增至 10 个（新增 `intruder-campaign`、`intruder-attempt`、`state-chain-run`），TypeScript 声明覆盖全部新类型。

### Multipart 精确往返

`MultipartPart` 显式保存 `opening_line_ending`、`raw_headers`、`header_body_separator`、`body`、`boundary_prefix`，文档保存 `preamble`、`boundary`、`closing_suffix`。解析器只按 `--boundary` 定界，序列化按字段顺序重放，实现 CRLF/LF、preamble、epilogue、重复字段名、字段顺序、重复 Header 和任意二进制 Body 的逐字节往返。`name`/`filename`/`content_type` 为展示用途，序列化以 `raw_headers` 为权威。

### 八类上传变异

`ExtensionCase`（大小写切换）、`DoubleExtension`（插入 `.jpg.` 段）、`TrailingCharacter`（尾随空格）、`ContentType`（改为 `image/jpeg`）、`FilenameEncoding`（`.`→`%2e`）、`MagicBytes`（前置 `GIF89a`）、`ImagePolyglot`（前置最小 GIF89a 头并置 `image/gif`）、`ExtraFormField`（追加无害表单节点）。变异只改写目标节点的 `raw_headers`/`body`，其余节点 bytes 保持不变。变异内容为无害标记，不含真实 WebShell。

### 状态化请求与验证

- CSRF/Nonce 状态宏按步执行 GET/POST，用前缀/后缀从响应 Body 或 Header 提取 Token，模板 `{{var}}` 注入 Path/Header/Body。每步记录请求/响应 `HttpMessage` 证据，汇入 `StateChainRun` 并与 `IntruderAttempt` 关联。
- 上传验证区分成功/失败/伪成功：`SafeRetrieval` 提取上传路径并 GET，内容 SHA-256 与预期节点 body 一致判 `Succeeded`；内容不符判 `content_replaced_pseudo_success`；不可取判 `artifact_not_retrievable`。`Execution`（L3）要求取回响应 body 与用户明确提供的 `expected_execution_marker` 逐字节相等。

### 安全边界

- 速率限制：全局与单目标令牌桶，实测吞吐 ≤ 目标速率（8/s 目标实测 8.041/s）。
- Campaign 后台线程可取消/暂停；重启恢复把 `queued/running` 标记为 `interrupted`；恢复后从 `next_ordinal` 继续且 ordinal 不重复。
- `IntruderAttempt` 使用原位 UPSERT 更新，保持其 `StateChainRun` 外键关系；`UNIQUE(intruder_campaign_id, ordinal)` 拒绝以新 Attempt ID 重用已提交 ordinal。
- 每个请求在 socket 写入前经 `connect_scoped` 复核 scheme/host/port 与 DNS pin，范围外 parent 在网络调用前被 `validate_parent_scope` 拒绝。
- `start_upload` 只接受含 `filename` 的 Multipart 文件节点。`None`/`SafeRetrieval` 在应用任何变异前将该节点 Body 替换为 `FLAGDECK_SAFE_UPLOAD`、Campaign ID 和 Attempt ordinal 组成的纯文本 marker；MagicBytes/ImagePolyglot 只与该 marker 组合。`Execution` 保留用户提供的原始文件 Body。
- `expected_execution_marker` 在 `None`/`SafeRetrieval` 中为空；`Execution` 要求 1..=256 bytes 并拒绝 NUL 与危险控制字符。普通页面出现通用 `FLAGDECK-EXEC` 字符串无法通过验证。
- L3 上传执行验证要求精确短语 `VERIFY UPLOAD EXECUTION <message_id>`，denied/allowed 均写入 `AuditEvent`（risk_level L3），`details_json` 只记录期望 marker 的 SHA-256。
- 输入有界：Intruder 尝试上限 100000，速率上限 10000/s，Multipart 上限 64 MiB，字典按 256 条分页流式读取，Attempt 证据进入 SensitiveEvidence Artifact。
- 进程参数使用类型化 argv，无 Shell 拼接；UI 只展示安全文本/Hex/摘要，禁止 `{@html}` 与 `innerHTML`。

### Tauri 表面

新增 7 个显式命令：`start_intruder`、`start_upload_campaign`、`cancel_intruder_campaign`、`resume_intruder_campaign`、`list_intruder_campaigns`、`list_intruder_attempts`、`parse_multipart_message`。每个命令进入 `AppManifest::commands`、`main-capability.json` 显式 permission、隔离层白名单与类型校验、非授权 WebView 探针。总自定义命令 50 个。活动 Campaign 阻止项目关闭与应用退出。桌面页提供单步状态宏配置，Intruder 与上传 IPC 共用有界的步骤、刷新消息、变量、来源、Header、prefix、suffix 与 `maximum_length`。

## UploadRanger 来源

固定参考提交 `686acdc26f94970005f228f8c12789e203effdef`（v1.1.1，MIT）。R6 只提取经审计行为与交互参考；本机未检出该源码树，故上传变异与验证均为 FlagDeck 独立实现，通过独立合同测试与 Loopback fixture 验证，主程序依赖图保持独立。局限：未做与 UploadRanger 原始 fixture 的逐字节比对回归，留待获得源码后补充。

## 放弃方案

- 不引入通用 Multipart 库：需要逐字节往返和重复键/顺序保留，自研 AST 更可控。
- 不在主 WebView 渲染目标响应或执行 payload：只做结构化/文本/Hex 预览。
- 不自动重放 L3 执行验证：每次执行需精确确认与审计。

## 结果

Rust 全工作区 fmt/clippy(`-D warnings`)/test 通过（108 passed，6 ignored）；R6 Loopback 纵向门禁、速率/停止恢复/内存证据门禁通过；前端 `pnpm test:all` 通过（Vitest 9/9）；Python Worker 与 Adapter 合同门禁通过；FlagDeck 0.6.0 RPM 构建并核验。
