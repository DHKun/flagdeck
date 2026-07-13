# macOS Apple Silicon 预览版

当前 DMG 面向 M1、M2、M3、M4 系列 Mac，最低系统版本为 macOS 13。macOS 26 与 MacBook Air M4 属于直接支持范围。

## 安装

1. 打开 `FlagDeck_1.0.0_aarch64.dmg`。
2. 将 FlagDeck 拖入 `Applications`。
3. 在“应用程序”中打开 FlagDeck。
4. 首次启动出现开发者提示时，进入“系统设置 → 隐私与安全性”，在 FlagDeck 提示区域选择“仍要打开”，完成一次身份验证。

预览版使用 Apple ad-hoc 签名。Developer ID 签名与 Apple 公证将在正式 macOS 发布链中接入。

## 当前体验范围

- 项目工作区、TargetScope、笔记、Artifact、Payload、Intruder 与上传测试可直接使用。
- 系统自带 curl 会自动进入工具箱；Homebrew 的 `/opt/homebrew/bin` 和 `/usr/local/bin` 会参与工具发现。
- HTTP 工作区内置固定版本的 `uv`。第一次启动代理时，FlagDeck 会在私有工作区下载 Python 3.12.13 和锁定的 mitmproxy 依赖，后续直接复用。
- Google Chrome 安装在标准 `/Applications` 路径时，代理可以启动独立浏览器配置。缺少 Chrome 时，代理仍可启动并显示监听地址。
- Metasploit 和 GUI Compatibility Pack 需要对应的 macOS Tool Pack，缺少组件时工具健康页会显示状态。

项目数据保存在：

```text
~/Library/Application Support/FlagDeck/workspaces
```

用户工具覆盖文件保存在：

```text
~/Library/Application Support/FlagDeck/tool-paths.toml
~/Library/Application Support/FlagDeck/external-launchers.toml
```

工具覆盖继续要求绝对路径与 SHA-256，运行前会复核文件所有权和写权限。
