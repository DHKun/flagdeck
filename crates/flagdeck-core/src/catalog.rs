//! Catalog 工作台：加载声明式工具目录，提供只读的目录快照与逐工具诊断。
//!
//! 与 `HttpWorkbench`、`IntruderWorkbench`、`MetasploitWorkbench` 并列，是 catalog 子系统的
//! 有状态模块，持有 `CatalogPaths`。对外接口只有三样：`load`（launch 路径也经此加载目录）、
//! `snapshot`（目录列表）、`diagnose`（单个工具的二进制/路径/权限/版本/运行时/字典六项检查）。
//! 诊断用到的构造与排序留在模块内部。

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use flagdeck_cli_adapters::catalog::file_sha256;
use flagdeck_cli_adapters::{CatalogPaths, CatalogToolManifest, ToolCatalog};
use sha2::{Digest, Sha256};

use crate::{
    CatalogCategoryDto, CatalogDiagnosticCheckDto, CatalogDiagnosticStatus, CatalogFieldGroupDto,
    CatalogFormFieldDto, CatalogFormOptionDto, CatalogFormRelationDto, CatalogHelpSnapshotDto,
    CatalogInstallationDto, CatalogPresetDto, CatalogSnapshot, CatalogToolDiagnosticDto,
    CatalogToolDto, CoreError, DiagnoseCatalogToolRequest, WordlistDto, map_catalog_error,
};

pub(crate) struct CatalogWorkbench {
    paths: CatalogPaths,
    cache: Mutex<Option<CachedCatalog>>,
}

struct CachedCatalog {
    loaded_at: Instant,
    catalog: ToolCatalog,
}

const CATALOG_CACHE_TTL: Duration = Duration::from_secs(5);

impl CatalogWorkbench {
    pub(crate) fn new(paths: CatalogPaths) -> Self {
        Self {
            paths,
            cache: Mutex::new(None),
        }
    }

    /// 加载当前 `CatalogPaths` 下的工具目录。这是目录唯一的加载点，launch 路径也经此加载。
    pub(crate) fn load(&self) -> Result<ToolCatalog, CoreError> {
        if let Ok(cache) = self.cache.lock()
            && let Some(cached) = cache.as_ref()
            && cached.loaded_at.elapsed() < CATALOG_CACHE_TTL
        {
            return Ok(cached.catalog.clone());
        }
        self.load_fresh()
    }

    fn load_fresh(&self) -> Result<ToolCatalog, CoreError> {
        let catalog =
            ToolCatalog::load(self.paths.clone()).map_err(|error| map_catalog_error(&error))?;
        if let Ok(mut cache) = self.cache.lock() {
            *cache = Some(CachedCatalog {
                loaded_at: Instant::now(),
                catalog: catalog.clone(),
            });
        }
        Ok(catalog)
    }

    pub(crate) fn snapshot(&self) -> Result<CatalogSnapshot, CoreError> {
        let catalog = self.load()?;
        Ok(CatalogSnapshot {
            tools_root: catalog.paths.tools_root.display().to_string(),
            wordlists_root: catalog.paths.wordlists_root.display().to_string(),
            user_catalog_root: catalog.paths.user_catalog_root.display().to_string(),
            categories: catalog
                .categories
                .iter()
                .map(|category| CatalogCategoryDto {
                    id: category.id.clone(),
                    name: category.name.clone(),
                    summary: category.summary.clone(),
                    order: category.order,
                })
                .collect(),
            tools: catalog
                .tool_views()
                .into_iter()
                .map(|view| CatalogToolDto {
                    id: view.id,
                    name: view.name,
                    category: view.category,
                    category_name: view.category_name,
                    tier: view.tier,
                    capabilities: view.capabilities,
                    aliases: view.aliases,
                    presets: view
                        .presets
                        .into_iter()
                        .map(|preset| CatalogPresetDto {
                            id: preset.id,
                            name: preset.name,
                            core_fields: preset.core_fields,
                            defaults: preset.defaults,
                        })
                        .collect(),
                    field_groups: view
                        .field_groups
                        .into_iter()
                        .map(|group| CatalogFieldGroupDto {
                            id: group.id,
                            name: group.name,
                            fields: group.fields,
                        })
                        .collect(),
                    relations: view
                        .relations
                        .into_iter()
                        .map(|relation| CatalogFormRelationDto {
                            kind: relation.kind,
                            field: relation.field,
                            equals: relation.equals,
                            other: relation.other,
                            other_equals: relation.other_equals,
                            severity: relation.severity,
                            message: relation.message,
                        })
                        .collect(),
                    risk_level: view.risk_level,
                    installation: CatalogInstallationDto {
                        distribution: view.installation.distribution,
                        license: view.installation.license,
                        homepage: view.installation.homepage,
                        version: view.installation.version,
                        health_strategy: view.installation.health_strategy,
                        runtime: view.installation.runtime,
                        version_args: view.installation.version_args,
                        install_command: view.installation.install_command,
                        path_fix: view.installation.path_fix,
                        wordlist_source: view.installation.wordlist_source,
                        wordlist_install_command: view.installation.wordlist_install_command,
                    },
                    io: view.io,
                    summary: view.summary,
                    usage: view.usage,
                    mode: view.mode,
                    featured: view.featured,
                    available: view.available,
                    binary_path: view.binary_path,
                    detail: view.detail,
                    icon: view.icon,
                    accent: view.accent,
                    needs_target: view.needs_target,
                    fields: view
                        .fields
                        .into_iter()
                        .map(|field| CatalogFormFieldDto {
                            id: field.id,
                            field_type: field.field_type,
                            label: field.label,
                            required: field.required,
                            default_value: field.default,
                            from: field.from,
                            options: field.options,
                            flag: field.flag,
                            hint: field.hint,
                            examples: field.examples,
                            option_details: field
                                .option_details
                                .into_iter()
                                .map(|option| CatalogFormOptionDto {
                                    value: option.value,
                                    label: option.label,
                                    summary: option.summary,
                                    tags: option.tags,
                                })
                                .collect(),
                            recommend_from: field.recommend_from,
                            sensitive: field.sensitive,
                        })
                        .collect(),
                })
                .collect(),
            wordlists: catalog
                .wordlist_views()
                .into_iter()
                .map(|view| WordlistDto {
                    id: view.id,
                    name: view.name,
                    path: view.path,
                    available: view.available,
                    tags: view.tags,
                })
                .collect(),
        })
    }

    pub(crate) fn diagnose(
        &self,
        request: &DiagnoseCatalogToolRequest,
    ) -> Result<CatalogToolDiagnosticDto, CoreError> {
        if request.tool_id.is_empty() || request.tool_id.len() > 64 {
            return Err(CoreError::InvalidRequest);
        }
        let catalog = if request.refresh_help {
            self.load_fresh()?
        } else {
            self.load()?
        };
        let tool = catalog
            .tool(&request.tool_id)
            .ok_or(CoreError::InvalidRequest)?;
        let source = if tool.installation.homepage.trim().is_empty() {
            format!("Catalog 清单 tools/{}.toml", tool.id)
        } else {
            tool.installation.homepage.clone()
        };
        let install_fix = if tool.installation.install_command.trim().is_empty() {
            format!("安装 {} 并确认其二进制可由 PATH 解析", tool.id)
        } else {
            tool.installation.install_command.clone()
        };
        let path_repair_copy = if tool.installation.path_fix.trim().is_empty() {
            install_fix.clone()
        } else {
            tool.installation.path_fix.clone()
        };
        let mut checks = Vec::with_capacity(6);
        let mut binary_path = String::new();
        let mut detected_version = String::new();

        let resolved = catalog.resolve_tool_binary(&request.tool_id);
        let missing_status = if tool.binary.path.is_empty() {
            CatalogDiagnosticStatus::Missing
        } else {
            CatalogDiagnosticStatus::PathAbnormal
        };
        match &resolved {
            Ok(path) => {
                binary_path = path.display().to_string();
                checks.push(catalog_diagnostic_check(
                    "binary",
                    "二进制解析",
                    CatalogDiagnosticStatus::Usable,
                    format!("已解析 {}", path.display()),
                    &source,
                    "",
                    "",
                ));
            }
            Err(_) => checks.push(catalog_diagnostic_check(
                "binary",
                "二进制解析",
                missing_status,
                "未解析到工具二进制",
                &source,
                "从官方来源安装工具后重新检测",
                &install_fix,
            )),
        }

        let path_status = match &resolved {
            Ok(path) => {
                if path.is_absolute() && path.is_file() {
                    CatalogDiagnosticStatus::Usable
                } else {
                    CatalogDiagnosticStatus::PathAbnormal
                }
            }
            Err(_) if !tool.binary.path.is_empty() => CatalogDiagnosticStatus::PathAbnormal,
            Err(_) => CatalogDiagnosticStatus::Missing,
        };
        checks.push(catalog_diagnostic_check(
            "path",
            "路径",
            path_status,
            if path_status == CatalogDiagnosticStatus::Usable {
                "路径存在且为普通文件"
            } else {
                "配置路径无效或工具目录未进入 PATH"
            },
            &source,
            if path_status == CatalogDiagnosticStatus::Usable {
                ""
            } else {
                "修复工具路径后重新检测"
            },
            &path_repair_copy,
        ));

        let permission_status = resolved.as_ref().map_or(missing_status, |path| {
            fs::metadata(path).map_or(CatalogDiagnosticStatus::PathAbnormal, |metadata| {
                if metadata.permissions().mode() & 0o111 == 0 {
                    CatalogDiagnosticStatus::PermissionAbnormal
                } else {
                    CatalogDiagnosticStatus::Usable
                }
            })
        });
        let permission_copy = match permission_status {
            CatalogDiagnosticStatus::Usable => String::new(),
            CatalogDiagnosticStatus::PermissionAbnormal => {
                format!("chmod u+x -- {binary_path}")
            }
            _ => path_repair_copy.clone(),
        };
        checks.push(catalog_diagnostic_check(
            "permission",
            "执行权限",
            permission_status,
            if permission_status == CatalogDiagnosticStatus::Usable {
                "当前用户可执行该文件"
            } else if permission_status == CatalogDiagnosticStatus::PermissionAbnormal {
                "文件缺少执行权限"
            } else {
                "等待有效二进制路径"
            },
            &source,
            match permission_status {
                CatalogDiagnosticStatus::Usable => "",
                CatalogDiagnosticStatus::PermissionAbnormal => "为当前用户添加执行权限",
                _ => "先修复工具二进制路径",
            },
            &permission_copy,
        ));

        let version_status = if permission_status == CatalogDiagnosticStatus::Usable {
            if tool.installation.version_args.is_empty() {
                CatalogDiagnosticStatus::VersionAbnormal
            } else if let Ok(path) = &resolved {
                let runtime_home = catalog.paths.cache_root.join("diagnostics").join(&tool.id);
                let output = ensure_private_directory(&runtime_home).ok().and_then(|()| {
                    capture_bounded_command(
                        path,
                        &tool.installation.version_args,
                        &runtime_home,
                        5_000,
                        4 * 1024,
                    )
                    .ok()
                });
                match output {
                    Some((true, evidence)) => {
                        detected_version = bounded_diagnostic_text(evidence.as_bytes());
                        if tool.installation.version.is_empty()
                            || detected_version.contains(&tool.installation.version)
                        {
                            CatalogDiagnosticStatus::Usable
                        } else {
                            CatalogDiagnosticStatus::VersionAbnormal
                        }
                    }
                    _ => CatalogDiagnosticStatus::VersionAbnormal,
                }
            } else {
                CatalogDiagnosticStatus::PathAbnormal
            }
        } else {
            permission_status
        };
        checks.push(catalog_diagnostic_check(
            "version",
            "版本",
            version_status,
            if version_status == CatalogDiagnosticStatus::Usable {
                format!("检测到 {detected_version}")
            } else {
                format!("期望版本 {}", tool.installation.version)
            },
            &source,
            match version_status {
                CatalogDiagnosticStatus::Usable => "",
                CatalogDiagnosticStatus::VersionAbnormal => "从官方来源安装清单声明的版本",
                CatalogDiagnosticStatus::PermissionAbnormal => "先修复二进制执行权限",
                _ => "先修复工具二进制路径",
            },
            match version_status {
                CatalogDiagnosticStatus::Usable => "",
                CatalogDiagnosticStatus::VersionAbnormal => &install_fix,
                CatalogDiagnosticStatus::PermissionAbnormal => &permission_copy,
                _ => &path_repair_copy,
            },
        ));

        let runtime_status = if tool.installation.runtime.trim().is_empty() {
            CatalogDiagnosticStatus::VersionAbnormal
        } else if resolved.is_ok() {
            CatalogDiagnosticStatus::Usable
        } else {
            missing_status
        };
        checks.push(catalog_diagnostic_check(
            "runtime",
            "运行时",
            runtime_status,
            if tool.installation.runtime.is_empty() {
                "清单未声明运行时".to_owned()
            } else {
                tool.installation.runtime.clone()
            },
            &source,
            match runtime_status {
                CatalogDiagnosticStatus::Usable => "",
                CatalogDiagnosticStatus::VersionAbnormal => "更新 Catalog 的运行时声明",
                _ => "先修复工具二进制路径",
            },
            match runtime_status {
                CatalogDiagnosticStatus::Usable => "",
                CatalogDiagnosticStatus::VersionAbnormal => &install_fix,
                _ => &path_repair_copy,
            },
        ));

        let wordlist_field = tool
            .form
            .fields
            .iter()
            .find(|field| field.field_type == "wordlist");
        let default_wordlist = wordlist_field.map_or("", |field| field.default.as_str());
        let wordlist_source = if tool.installation.wordlist_source.trim().is_empty() {
            format!("Catalog 清单 tools/{}.toml#默认字典", tool.id)
        } else {
            tool.installation.wordlist_source.clone()
        };
        let wordlist_repair_copy = if tool.installation.wordlist_install_command.trim().is_empty() {
            format!("安装工具 {} 声明的默认字典 {}", tool.id, default_wordlist)
        } else {
            tool.installation.wordlist_install_command.clone()
        };
        let wordlist = catalog
            .wordlist_views()
            .into_iter()
            .find(|entry| entry.id == default_wordlist);
        let wordlist_status = if wordlist_field.is_none() {
            CatalogDiagnosticStatus::Usable
        } else if default_wordlist.is_empty() {
            CatalogDiagnosticStatus::VersionAbnormal
        } else if wordlist.as_ref().is_some_and(|entry| entry.available) {
            CatalogDiagnosticStatus::Usable
        } else {
            CatalogDiagnosticStatus::Missing
        };
        checks.push(catalog_diagnostic_check(
            "wordlist",
            "默认字典",
            wordlist_status,
            wordlist.as_ref().map_or_else(
                || {
                    if wordlist_field.is_none() {
                        "该工具无需默认字典".to_owned()
                    } else {
                        format!("未找到默认字典 {default_wordlist}")
                    }
                },
                |entry| {
                    if entry.available {
                        format!("已找到 {}", entry.name)
                    } else {
                        format!("缺少 {}", entry.path)
                    }
                },
            ),
            &wordlist_source,
            match wordlist_status {
                CatalogDiagnosticStatus::Usable => "",
                CatalogDiagnosticStatus::VersionAbnormal => "补全默认字典清单声明",
                _ => "从声明来源安装默认字典",
            },
            match wordlist_status {
                CatalogDiagnosticStatus::Usable => "",
                _ => &wordlist_repair_copy,
            },
        ));

        let status = checks
            .iter()
            .map(|check| check.status)
            .max_by_key(|status| catalog_diagnostic_priority(*status))
            .unwrap_or(CatalogDiagnosticStatus::Missing);
        let help = resolved.as_ref().map_or_else(
            |_| CatalogHelpSnapshotDto {
                available: false,
                cached: false,
                command: String::new(),
                detected_version: detected_version.clone(),
                binary_sha256: String::new(),
                captured_at_epoch_secs: None,
                content: String::new(),
                detail: "修复工具路径后读取完整帮助".to_owned(),
            },
            |binary| {
                capture_help_snapshot(
                    &catalog,
                    tool,
                    binary,
                    &detected_version,
                    request.refresh_help,
                )
            },
        );
        Ok(CatalogToolDiagnosticDto {
            tool_id: request.tool_id.clone(),
            status,
            binary_path,
            detected_version,
            checks,
            help,
        })
    }
}

fn capture_help_snapshot(
    catalog: &ToolCatalog,
    tool: &CatalogToolManifest,
    binary: &Path,
    detected_version: &str,
    refresh: bool,
) -> CatalogHelpSnapshotDto {
    if tool.help.args.is_empty() {
        return CatalogHelpSnapshotDto {
            available: false,
            cached: false,
            command: String::new(),
            detected_version: detected_version.to_owned(),
            binary_sha256: String::new(),
            captured_at_epoch_secs: None,
            content: String::new(),
            detail: "Catalog 未声明安全帮助命令".to_owned(),
        };
    }
    let command = std::iter::once(binary.display().to_string())
        .chain(tool.help.args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    let Ok(binary_sha256) = file_sha256(binary) else {
        return unavailable_help_snapshot(
            command,
            detected_version,
            String::new(),
            "无法计算工具哈希",
        );
    };
    let mut hasher = Sha256::new();
    hasher.update(tool.id.as_bytes());
    hasher.update([0]);
    hasher.update(binary_sha256.as_bytes());
    hasher.update([0]);
    hasher.update(detected_version.as_bytes());
    for arg in &tool.help.args {
        hasher.update([0]);
        hasher.update(arg.as_bytes());
    }
    let cache_key = format!("{:x}", hasher.finalize());
    let cache_dir = catalog.paths.cache_root.join("tool-help");
    let cache_path = cache_dir.join(format!("{}-{cache_key}.txt", tool.id));
    if !refresh
        && let Some((content, captured_at)) = read_help_cache(&cache_path, tool.help.max_bytes)
    {
        return CatalogHelpSnapshotDto {
            available: true,
            cached: true,
            command,
            detected_version: detected_version.to_owned(),
            binary_sha256,
            captured_at_epoch_secs: captured_at,
            content,
            detail: "已读取版本匹配的帮助缓存".to_owned(),
        };
    }

    if let Err(error) = ensure_private_directory(&cache_dir) {
        return unavailable_help_snapshot(
            command,
            detected_version,
            binary_sha256,
            &format!("无法创建帮助缓存：{error}"),
        );
    }
    let runtime_home = cache_dir.join(format!("runtime-{}", tool.id));
    if let Err(error) = ensure_private_directory(&runtime_home) {
        return unavailable_help_snapshot(
            command,
            detected_version,
            binary_sha256,
            &format!("无法创建帮助运行目录：{error}"),
        );
    }
    match capture_bounded_command(
        binary,
        &tool.help.args,
        &runtime_home,
        tool.help.timeout_millis,
        tool.help.max_bytes,
    )
    .and_then(require_successful_help_capture)
    {
        Ok(content) => {
            let captured_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_secs());
            let detail = if write_help_cache(&cache_path, content.as_bytes()).is_ok() {
                "已刷新版本匹配的帮助缓存"
            } else {
                "已读取帮助，缓存写入失败"
            };
            CatalogHelpSnapshotDto {
                available: true,
                cached: false,
                command,
                detected_version: detected_version.to_owned(),
                binary_sha256,
                captured_at_epoch_secs: captured_at,
                content,
                detail: detail.to_owned(),
            }
        }
        Err(detail) => unavailable_help_snapshot(command, detected_version, binary_sha256, &detail),
    }
}

fn require_successful_help_capture(capture: (bool, String)) -> Result<String, String> {
    let (success, content) = capture;
    if success {
        Ok(content)
    } else {
        Err(format!(
            "帮助命令执行失败：{}",
            bounded_diagnostic_text(content.as_bytes())
        ))
    }
}

fn unavailable_help_snapshot(
    command: String,
    detected_version: &str,
    binary_sha256: String,
    detail: &str,
) -> CatalogHelpSnapshotDto {
    CatalogHelpSnapshotDto {
        available: false,
        cached: false,
        command,
        detected_version: detected_version.to_owned(),
        binary_sha256,
        captured_at_epoch_secs: None,
        content: String::new(),
        detail: detail.chars().take(512).collect(),
    }
}

fn ensure_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn read_help_cache(path: &Path, maximum: usize) -> Option<(String, Option<u64>)> {
    let mut file = File::options()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return None;
    }
    let length = usize::try_from(metadata.len()).ok()?;
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes).ok()?;
    let content = String::from_utf8(bytes).ok()?;
    let captured_at = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs());
    Some((content, captured_at))
}

fn write_help_cache(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "cache path has no parent")
    })?;
    ensure_private_directory(parent)?;
    let temporary = parent.join(format!(
        ".help-cache-{}-{}.tmp",
        std::process::id(),
        path.file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("entry")
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn capture_bounded_command(
    binary: &Path,
    args: &[String],
    runtime_home: &Path,
    timeout_millis: u64,
    maximum: usize,
) -> Result<(bool, String), String> {
    let mut command = Command::new(binary);
    command
        .args(args)
        .env_clear()
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("HOME", runtime_home)
        .env("XDG_CONFIG_HOME", runtime_home.join("config"))
        .current_dir(runtime_home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path) = env::var_os("PATH") {
        command.env("PATH", path);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("命令启动失败：{error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "命令缺少 stdout".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "命令缺少 stderr".to_owned())?;
    let stdout_reader = thread::spawn(move || read_stream_bounded(stdout, maximum));
    let stderr_reader = thread::spawn(move || read_stream_bounded(stderr, maximum));
    let deadline = Instant::now() + Duration::from_millis(timeout_millis);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("命令超时".to_owned());
            }
            Err(error) => return Err(format!("命令等待失败：{error}")),
        }
    };
    let mut bytes = stdout_reader
        .join()
        .map_err(|_| "读取 stdout 失败".to_owned())?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "读取 stderr 失败".to_owned())?;
    if !bytes.is_empty() && !stderr.is_empty() && bytes.len() < maximum {
        bytes.push(b'\n');
    }
    let remaining = maximum.saturating_sub(bytes.len());
    bytes.extend_from_slice(&stderr[..stderr.len().min(remaining)]);
    if bytes.is_empty() {
        return Err(format!("命令未返回内容，退出状态 {status}"));
    }
    Ok((
        status.success(),
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
}

fn read_stream_bounded(mut stream: impl Read, maximum: usize) -> Vec<u8> {
    let mut retained = Vec::with_capacity(maximum.min(64 * 1024));
    let mut buffer = [0_u8; 8192];
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
        let remaining = maximum.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..read.min(remaining)]);
    }
    retained
}

fn catalog_diagnostic_check(
    id: &str,
    label: &str,
    status: CatalogDiagnosticStatus,
    detail: impl Into<String>,
    source: &str,
    fix: &str,
    copy_value: &str,
) -> CatalogDiagnosticCheckDto {
    CatalogDiagnosticCheckDto {
        id: id.to_owned(),
        label: label.to_owned(),
        status,
        detail: detail.into(),
        source: source.chars().take(512).collect(),
        fix: fix.chars().take(512).collect(),
        copy_value: copy_value.chars().take(1024).collect(),
    }
}

fn catalog_diagnostic_priority(status: CatalogDiagnosticStatus) -> u8 {
    match status {
        CatalogDiagnosticStatus::Usable => 0,
        CatalogDiagnosticStatus::VersionAbnormal => 1,
        CatalogDiagnosticStatus::Missing => 2,
        CatalogDiagnosticStatus::PathAbnormal => 3,
        CatalogDiagnosticStatus::PermissionAbnormal => 4,
    }
}

fn bounded_diagnostic_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(512)])
        .split_whitespace()
        .take(32)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_load_reuses_short_lived_cache_and_supports_explicit_refresh() {
        let temporary = tempfile::tempdir().unwrap();
        let catalog_root = temporary.path().join("catalog");
        let tools = catalog_root.join("tools");
        fs::create_dir_all(&tools).unwrap();
        let manifest = tools.join("fixture.toml");
        let write_manifest = |name: &str| {
            fs::write(
                &manifest,
                format!(
                    r#"
id = "fixture"
name = "{name}"
category = "test"
mode = "embedded_cli"

[binary]
path = "/usr/bin/true"
resolve = ["path"]

[argv]
template = ["--help"]
"#
                ),
            )
            .unwrap();
        };
        write_manifest("first");
        let workbench = CatalogWorkbench::new(CatalogPaths {
            tools_root: temporary.path().join("tool-root"),
            wordlists_root: temporary.path().join("wordlists"),
            catalog_root,
            user_catalog_root: temporary.path().join("user-catalog"),
            cache_root: temporary.path().join("cache"),
        });

        assert_eq!(
            workbench.load().unwrap().tool("fixture").unwrap().name,
            "first"
        );
        write_manifest("second");
        assert_eq!(
            workbench.load().unwrap().tool("fixture").unwrap().name,
            "first"
        );
        assert_eq!(
            workbench
                .load_fresh()
                .unwrap()
                .tool("fixture")
                .unwrap()
                .name,
            "second"
        );
    }

    #[test]
    fn help_capture_uses_private_runtime_and_bounded_cache() {
        let temporary = tempfile::tempdir().unwrap();
        let runtime_home = temporary.path().join("runtime");
        ensure_private_directory(&runtime_home).unwrap();
        let script = temporary.path().join("help-fixture");
        fs::write(
            &script,
            "#!/bin/sh\nprintf '%s\\n' \"$PWD\" \"$HOME\" \"$1\"\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();

        let (success, output) =
            capture_bounded_command(&script, &["--help".to_owned()], &runtime_home, 1_000, 1_024)
                .unwrap();
        assert!(success);
        let runtime = runtime_home.display().to_string();
        assert_eq!(
            output.lines().collect::<Vec<_>>(),
            [runtime.as_str(), runtime.as_str(), "--help"]
        );

        let cache_path = temporary.path().join("cache").join("fixture.txt");
        write_help_cache(&cache_path, output.as_bytes()).unwrap();
        let (cached, captured_at) = read_help_cache(&cache_path, 1_024).unwrap();
        assert_eq!(cached, output);
        assert!(captured_at.is_some());
        assert!(read_help_cache(&cache_path, 4).is_none());

        let cache_link = temporary.path().join("cache-link.txt");
        std::os::unix::fs::symlink(&cache_path, &cache_link).unwrap();
        assert!(read_help_cache(&cache_link, 1_024).is_none());
    }

    #[test]
    fn failed_help_command_is_detected_and_keeps_bounded_diagnostics() {
        let temporary = tempfile::tempdir().unwrap();
        let runtime_home = temporary.path().join("runtime");
        ensure_private_directory(&runtime_home).unwrap();
        let script = temporary.path().join("failed-help-fixture");
        fs::write(
            &script,
            "#!/bin/sh\nprintf 'missing dependency\\n' >&2\nexit 2\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();

        let (success, output) =
            capture_bounded_command(&script, &["--help".to_owned()], &runtime_home, 1_000, 1_024)
                .unwrap();
        assert!(!success);
        assert_eq!(
            bounded_diagnostic_text(output.as_bytes()),
            "missing dependency"
        );
        assert_eq!(
            require_successful_help_capture((success, output)).unwrap_err(),
            "帮助命令执行失败：missing dependency"
        );
    }
}
