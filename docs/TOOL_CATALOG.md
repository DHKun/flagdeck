# Tool Catalog（声明式工具目录）

FlagDeck 个人工作台通过 **TOML 清单**接入工具。新增工具时优先只改 catalog，不必改 Rust 枚举或 Svelte 专用表单。

## 目录布局

```text
config/tool-catalog/
  categories.toml
  wordlists.toml
  tools/
    <tool-id>.toml
```

环境变量（可选）：

| 变量 | 默认 |
|---|---|
| `FLAGDECK_TOOLS_ROOT` | `/data/CTF/Tools` |
| `FLAGDECK_WORDLISTS_ROOT` | `$FLAGDECK_TOOLS_ROOT/Wordlists` |
| `FLAGDECK_CATALOG_ROOT` | 仓库内 `config/tool-catalog` |

## 最小工具清单

见 `tools/*.toml`。字段含义：

- `mode`：`embedded_cli`（应用内运行）或 `external_launch`（一键启动 GUI）
- `cwd`：工作目录（GUI 很重要）；相对路径基于工具根
- `binary.path` / `binary.command` / `binary.resolve`
- `form.fields`：动态表单。**没有字段 = 无需目标 URL**
- `argv.template`：**只写参数，不要把程序路径写在第一项**（运行时会 `program + argv`）
- `parser.kind`：目前 `none`（看日志）

### 字段类型

| type | 用途 |
|---|---|
| `url` | HTTP URL；也可填主机，会自动补 `http://` |
| `host` | IP/域名/网段（fscan/dddd） |
| `wordlist` | 字典快捷 id 或绝对路径 |
| `text` / `number` | 普通参数 |

### 可用占位符

| 占位符 | 含义 |
|---|---|
| `{url}` / `{url_base}` | URL 与去掉尾 `/` 的 base（ffuf 用 `{url_base}/FUZZ`） |
| `{host}` | 主机名（从 URL 解析或表单） |
| `{target}` | 原始目标字段 |
| `{wordlist}` | 字典绝对路径 |
| `{job_dir}` | 任务私有目录 |
| `{tools_root}` | `/data/CTF/Tools` |

### 二进制解析

按 `resolve` 顺序查找，并额外搜索：

- `$HOME/.local/share/mise/installs/go/*/bin`（ffuf/gobuster）
- `$HOME/.local/share/mise/installs/java/*/bin`
- PATH（优先非 mise shim，避免沙箱 HOME 下 shim 失效）

## AI 添加新工具 SOP

1. 在 `config/tool-catalog/tools/` 新建 `<id>.toml`
2. 填 `id` / `name` / `category` / `mode`
3. 指向 `/data/CTF/Tools` 下二进制，或系统 `command`
4. 写 `form.fields` 与 `argv.template`
5. `parser.kind = "none"` 即可先上线
6. 重启应用或刷新工具库，确认卡片出现且可运行

**无需**修改 `AlphaTool`、无需改前端表单代码（动态渲染）。

## 首批工具

| ID | 模式 | 说明 |
|---|---|---|
| curl | embedded | 系统 curl |
| dddd | embedded | Active/dddd |
| fscan | embedded | Active/fscan |
| ffuf | embedded | PATH 或自行配置 path |
| gobuster | embedded | PATH 或自行配置 path |
| shiro / godzilla / antsword | external | GUI 一键启动 |
