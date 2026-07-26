# Stable 发布操作

Stable 1.0 使用 `.github/workflows/stable-release.yml`。工作流按“无密钥构建 → 隔离签名 → Fedora 目标机取证 → GitHub-hosted 发布”四个 Job 运行。发布私钥只进入受保护的签名 Job。

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

## Fedora 目标机 runner

`target-evidence` Job 使用带有 `flagdeck-fedora44-kde-wayland` 标签的 repository-level self-hosted runner。runner 必须满足：

- Fedora 44 x86_64。
- 当前图形会话为 KDE on Wayland。
- SELinux 状态为 Enforcing。
- 当前用户可访问 Wayland socket 和 D-Bus session。
- 已安装 `WebKitWebDriver`、`jq`、`podman` 和 `python3`，rootless Podman 可用。

runner 从当前 KDE 会话以前台进程启动，并采用 GitHub Actions 的 ephemeral 注册模式。推荐在 `target-evidence` 进入 queued 后注册和启动 runner，使它只接收该发布 Job。Job 完成后确认 repository runner 列表为空。

目标机 Job 继承 `contents: read` 权限，只下载无密钥构建制品和已签名 RPM。签名私钥保留在 GitHub-hosted `sign` Job 的 Environment secret 中。

## 发布前提

- Stable 标签采用 `vMAJOR.MINOR.PATCH`，版本与 `tauri.conf.json` 一致。
- 标签是 annotated tag，标签提交位于 `main` 历史中。
- `v1.0.0` 是首个 Stable RPM，Fedora 门禁记录明确的 `first-release` 模式以及固定的 `not_applicable` 升级状态。
- 后续 Stable 发布需先扩展工作流，输入上一版 Stable RPM，并恢复升级、回退、再升级门禁。
- 目标 Stable Release 尚未创建。

## 执行

在 GitHub Actions 中以 Stable 标签 ref 运行 `Stable Release`，输入同一标签，例如 `v1.0.0`。Environment 审批通过后，工作流会：

1. 从锁文件同步依赖，运行完整测试、供应链审计和 R7 性能门禁。
2. 构建 AppImage、DEB、未签名 RPM 和 CycloneDX SBOM。
3. 在隔离 Job 中导入私钥，验证批准指纹，签名 RPM，删除私钥目录。
4. 在 Fedora 44 KDE/Wayland 目标机运行 10 次 GUI 门禁、10 次桌面内存门禁和 first-release 生命周期门禁。
5. 将目标机证据上传为 `stable-target-evidence`，证据记录 Fedora、KDE、Wayland、SELinux 状态以及候选制品 SHA-256。
6. 在 GitHub-hosted Job 独立导入公钥验证 RPM 本体，校验目标机环境和证据哈希，生成 `release-manifest.json`。
7. 上传完整证据并创建 Stable GitHub Release。

任何证据哈希、签名指纹、运行次数、GUI 安全断言、生命周期结果或锁定输入发生偏差，发布都会在创建 GitHub Release 前终止。
