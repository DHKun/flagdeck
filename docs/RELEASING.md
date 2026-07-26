# 发布

本文档说明预览版发布。FlagDeck 的安装包由 GitHub Actions 在固定系统环境中构建，手动运行会生成可下载的 Actions Artifact，推送带 SemVer 后缀的预览标签会在两个平台构建都通过后创建 GitHub Prerelease。正式版走 [stable-release.md](stable-release.md) 描述的独立工作流。

## 发布内容

| 平台  | 架构                | 文件                        |
| ----- | ------------------- | --------------------------- |
| Linux | x86-64              | AppImage、DEB、RPM、SHA-256 |
| macOS | Apple Silicon arm64 | DMG、SHA-256                |

Linux 使用 Ubuntu 22.04 作为 AppImage 构建基线。RPM 和 DEB 由同一次源码检出与同一组锁文件生成。macOS 使用 `macos-26` arm64 Runner，并执行 ad-hoc 签名、DMG 挂载、架构和签名校验。

## 创建发布

预览标签在 `vMAJOR.MINOR.PATCH` 基础上带 SemVer 后缀，例如 `v1.0.0-preview.2`。`Packages` 工作流只接受这类带后缀的标签。标签中的基础版本必须与 `apps/desktop/src-tauri/tauri.conf.json` 一致，标签提交必须位于 `main` 历史中。

```bash
git switch main
git pull --ff-only
git tag -a v1.0.0-preview.2 -m "FlagDeck 1.0.0 preview 2"
git push origin v1.0.0-preview.2
```

`Packages` 工作流随后执行 Linux workspace 检查、三种 Linux 打包、macOS DMG 打包、安装内容核验和 SHA-256 复核。完整测试由主 `CI` 工作流执行。构建产物发布为 GitHub Prerelease。

Developer ID 签名与 Apple 公证需要在仓库中配置 Apple Developer 凭据。当前 macOS 预览包使用 ad-hoc 签名，首次启动步骤记录在 [MACOS_PREVIEW.md](MACOS_PREVIEW.md)。
