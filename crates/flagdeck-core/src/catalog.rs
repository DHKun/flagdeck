//! Catalog 工作台：加载声明式工具目录，提供只读的目录快照与逐工具诊断。
//!
//! 与 `HttpWorkbench`、`IntruderWorkbench`、`MetasploitWorkbench` 并列，是 catalog 子系统的
//! 有状态模块，持有 `CatalogPaths`。对外接口只有三样：`load`（launch 路径也经此加载目录）、
//! `snapshot`（目录列表）、`diagnose`（单个工具的二进制/路径/权限/版本/运行时/字典六项检查）。
//! 诊断用到的构造与排序留在模块内部。

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use flagdeck_cli_adapters::{CatalogPaths, ToolCatalog};

use crate::{
    CatalogCategoryDto, CatalogDiagnosticCheckDto, CatalogDiagnosticStatus, CatalogFieldGroupDto,
    CatalogFormFieldDto, CatalogInstallationDto, CatalogPresetDto, CatalogSnapshot,
    CatalogToolDiagnosticDto, CatalogToolDto, CoreError, DiagnoseCatalogToolRequest, WordlistDto,
    map_catalog_error,
};

pub(crate) struct CatalogWorkbench {
    paths: CatalogPaths,
}

impl CatalogWorkbench {
    pub(crate) fn new(paths: CatalogPaths) -> Self {
        Self { paths }
    }

    /// 加载当前 `CatalogPaths` 下的工具目录。这是目录唯一的加载点，launch 路径也经此加载。
    pub(crate) fn load(&self) -> Result<ToolCatalog, CoreError> {
        ToolCatalog::load(self.paths.clone()).map_err(|error| map_catalog_error(&error))
    }

    pub(crate) fn snapshot(&self) -> Result<CatalogSnapshot, CoreError> {
        let catalog = self.load()?;
        Ok(CatalogSnapshot {
            tools_root: catalog.paths.tools_root.display().to_string(),
            wordlists_root: catalog.paths.wordlists_root.display().to_string(),
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
                            hint: field.hint,
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
        let catalog = self.load()?;
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
                let mut command = Command::new(path);
                command
                    .args(&tool.installation.version_args)
                    .env_clear()
                    .env("LANG", "C.UTF-8")
                    .env("LC_ALL", "C.UTF-8")
                    .stdin(Stdio::null());
                if let Some(path) = env::var_os("PATH") {
                    command.env("PATH", path);
                }
                let output = command.output();
                match output {
                    Ok(output) if output.status.success() => {
                        let mut evidence = output.stdout;
                        evidence.extend_from_slice(&output.stderr);
                        detected_version = bounded_diagnostic_text(&evidence);
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
        Ok(CatalogToolDiagnosticDto {
            tool_id: request.tool_id.clone(),
            status,
            binary_path,
            detected_version,
            checks,
        })
    }
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
