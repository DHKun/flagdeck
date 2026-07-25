# Stable 发布操作

Stable 1.0 使用 `.github/workflows/stable-release.yml`。工作流按“无密钥构建 → 隔离签名 → 无密钥验收与发布”三个 Job 运行，发布私钥只进入受保护的签名 Job。

## GitHub 环境

创建名为 `stable-release` 的 Environment，并配置：

- 禁用管理员绕过。
- Deployment branches and tags，仅允许当前 Stable 标签 `v1.0.0`。
- 仓库加入第二名维护者后配置 Required reviewers，并开启禁止发起人自行批准。
- Environment secret `FLAGDECK_RPM_SIGNING_KEY`，内容为 ASCII-armored OpenPGP 私钥。

私钥必须匹配仓库中的 `release/FlagDeck-1.0.0-signing-key.asc`，批准的主密钥指纹为：

```text
18AD547A9ABCBC8B633031213FB7C61845873DE6
```

CI 使用非交互式 `rpmsign`。Environment secret 应提供专用于自动发布、无需交互式口令的最小签名私钥，并依靠 Environment 审批、标签保护和 GitHub Secret 加密控制访问。

## 发布前提

- Stable 标签采用 `vMAJOR.MINOR.PATCH`，版本与 `tauri.conf.json` 一致。
- 标签是 annotated tag，标签提交位于 `main` 历史中。
- `v1.0.0` 是首个 Stable RPM，Fedora 门禁记录明确的 `first-release` 模式以及固定的 `not_applicable` 升级状态。
- 后续 Stable 发布需先扩展工作流，输入上一版 Stable RPM，并恢复升级、回退、再升级门禁。
- 目标 Stable Release 尚未创建。

## 执行

在 GitHub Actions 中运行 `Stable Release`，输入已有 Stable 标签，例如 `v1.0.0`。Environment 审批通过后，工作流会：

1. 从锁文件同步依赖，运行完整测试、供应链审计和 R7 性能门禁。
2. 构建 AppImage、DEB、未签名 RPM 和 CycloneDX SBOM。
3. 在隔离 Job 中导入私钥，验证批准指纹，签名 RPM，删除私钥目录。
4. 在新 Job 中对签名 RPM 运行 10 次 GUI 门禁、10 次桌面内存门禁和 Fedora 44 生命周期门禁。
5. 独立导入公钥验证 RPM 本体，生成哈希绑定的 `release-manifest.json`。
6. 上传完整证据并创建 Stable GitHub Release。

任何证据哈希、签名指纹、运行次数、GUI 安全断言、生命周期结果或锁定输入发生偏差，发布都会在创建 GitHub Release 前终止。
