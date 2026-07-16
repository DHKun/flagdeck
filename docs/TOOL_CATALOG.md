# Tool Catalog（声明式工具目录）

FlagDeck 个人工作台通过 **TOML 清单**接入工具。新增工具时优先只改 catalog，不必改 Rust 枚举或 Svelte 专用表单。

工具布局与本机 `/data/CTF/Tools/00-目录说明.md` 对齐：Active 优先、Scripts/Crypto/Binary/Defensive 补齐 CTF 常用 CLI，字典见 Wordlists。

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

- `mode`：`embedded_cli`（应用内运行）或 `external_launch`（一键启动 GUI / 本机服务）
- `detach`：仅 `external_launch`。默认 `true`（短探测后分离）。长驻服务设 `detach = false` 以支持停止。
- `cwd`：工作目录；相对路径基于工具根
- `binary.path` / `binary.command` / `binary.resolve`
- `form.fields`：动态表单。**没有字段 = 无需目标 URL**
- `argv.template`：**只写参数，不要把程序路径写在第一项**（运行时会 `program + argv`）；Python 脚本应 `command=python3`，脚本路径放在 template 首项
- `argv.optional`：字段非空（或 `equals` 匹配）时追加；**可选项必须与真实 CLI 开关一致**
- `argv.suffix`：始终追加在末尾（适合 URL / 查询对象）
- `parser.kind`：目前 `none`（看日志）为主；部分工具支持结果表

### 字段类型

| type | 用途 |
|---|---|
| `url` | HTTP URL；也可填主机，会自动补 `http://` |
| `host` | IP/域名/网段（fscan/dddd） |
| `wordlist` | 字典快捷 id 或绝对路径 |
| `text` / `number` / `select` | 普通参数 |

### 可用占位符

| 占位符 | 含义 |
|---|---|
| `{url}` / `{url_base}` | URL 与去掉尾 `/` 的 base（ffuf 用 `{url_base}/FUZZ`） |
| `{host}` | 主机名（从 URL 解析或表单） |
| `{target}` | 原始目标字段 |
| `{wordlist}` | 字典绝对路径 |
| `{job_dir}` | 任务私有目录 |
| `{tools_root}` | `/data/CTF/Tools` |

## AI 添加新工具 SOP

1. 在 `config/tool-catalog/tools/` 新建 `<id>.toml`
2. 填 `id` / `name` / `category` / `mode`（category 须在 `categories.toml` 中存在）
3. 指向 `/data/CTF/Tools` 下二进制，或系统 `command`
4. **对照真实 `--help` / 本机试跑** 写 `form.fields` 与 `argv`（可选项宁缺毋错）
5. Python 工具：`resolve = ["system"]` + `python3`，脚本路径放 argv，不要把无 +x 的 `.py` 当 program
6. `parser.kind = "none"` 即可先上线
7. 重启应用或刷新工具库

## 工具列表（catalog）

### Active / 扫描

| ID | 模式 | 说明 |
|---|---|---|
| dddd | embedded | Active/dddd 资产发现 |
| fscan | embedded | Active/fscan CLI |
| fscan-web | external | fscan Web UI 二进制 |
| curl | embedded | 系统 curl |
| arjun | embedded | HTTP 参数发现（PATH） |
| ffuf / gobuster | embedded | 目录 fuzz（PATH 或 mise go） |
| sqlmap | embedded | SQL 注入（PATH） |
| wafw00f | embedded | WAF 识别（PATH） |

### DNS / 信息

| ID | 模式 | 说明 |
|---|---|---|
| dig | embedded | DNS 查询 |
| whois | embedded | 注册信息查询 |

### Crypto / 编码

| ID | 模式 | 说明 |
|---|---|---|
| rsa-ctf-tool | embedded | Scripts RsaCtfTool |
| yafu | embedded | Crypto Toolkit 整数分解 |
| hashcat | embedded | 哈希爆破（PATH） |
| openssl-dgst | embedded | 文件摘要 |
| cyberchef | external | 离线 HTML 编解码 |

### Binary / 逆向

| ID | 模式 | 说明 |
|---|---|---|
| strings | embedded | 可打印字符串 |
| pyinstxtractor | embedded | PyInstaller 解包 |

### Web 利用 / 载荷

| ID | 模式 | 说明 |
|---|---|---|
| php-filter-chain | embedded | LFI filter 链生成 |
| githacker | embedded | `.git` 泄露综合还原（GitHacker，Active/git-leak） |
| revshell-gen | external managed | 反弹 shell 生成器本地 HTTP |
| payloader | external managed | Payload 参考站 `npm run dev` |
| uploadranger | external | 上传漏洞 GUI |
| shiro / antsword / behinder / godzilla | external | GUI 客户端 |

### 防守 / 分析

| ID | 模式 | 说明 |
|---|---|---|
| whoamifuck | embedded | Linux 主机排查（需 root） |
| behinder-decryptor | embedded | 冰蝎 pcap 解密 |

### 结构化结果

任务旁路文件（如 `ffuf-output.json`）可通过 `preview_job_file` 读取；工作台「结果」页对 ffuf / dddd / fscan / gobuster / arjun 做表格解析。其它工具默认看日志。

## 未纳入说明

- **Windows 专用 PE**（DIE、D盾、河马、ToolsFx 等）：Linux 工作台不强制接入，建议虚拟机。
- **依赖损坏/过旧**：GScan（`imp` 已移除）、FileMonitor（缺 watchdog）、ROPgadget（缺 capstone）、evilPatcher venv 损坏 — 修好依赖后再加。
- **高敏感 C2/ShellcodeLoader**：仅文档索引，默认不进日常 catalog。
