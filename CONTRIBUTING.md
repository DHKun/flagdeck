# Contributing

FlagDeck 接受 Bug 修复、Linux 兼容性改进、新工具 Adapter 和文档改进。

## 开发流程

1. 从 `main` 创建功能分支。
2. 保持改动范围清晰，并为行为变化补充测试。
3. 运行 `mise run test`。
4. 提交 Pull Request，说明改动目的、用户影响和验证方式。

## 新工具要求

新增工具接入需要包含：

- 上游主页、版本、分发方式与许可证；
- 固定入口和 SHA-256 策略；
- 明确的参数 allowlist 与风险级别；
- 资源限制、停止流程和网络范围策略；
- 输出解析器、真实 fixture 与合同测试。

FlagDeck 源码仓库不接收来源不明的二进制、Payload 数据集或第三方工具副本。

## 提交信息

使用简短的动词短语描述完整改动，例如：

```text
add nuclei tool adapter
fix incremental stderr preview
document Arch Linux prerequisites
```

日志、fixture 和截图需要清除凭据、Cookie、Token、私有目标与本机路径。
