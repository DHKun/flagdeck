use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use flagdeck_domain::{
    CommandSpec, CommandSpecId, ProjectId, ResourceLimits, RiskLevel, ScopeId, SecretTransport,
};
use flagdeck_exec::validate_program;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ts_rs::TS;

pub const EXTERNAL_LAUNCHERS_SOURCE: &str = include_str!("../../../config/external-launchers.toml");
#[cfg(target_os = "linux")]
const EXPECTED_PLATFORM: &str = "linux-x86_64";
#[cfg(target_os = "macos")]
const EXPECTED_PLATFORM: &str = "macos-aarch64";

#[derive(Debug, Error)]
pub enum ExternalLauncherError {
    #[error("external launcher registry is invalid")]
    Registry,
    #[error("external launcher integrity policy failed")]
    Integrity,
    #[error("external launcher request is invalid")]
    InvalidRequest,
    #[error("the exact external launcher L3 confirmation phrase is required")]
    ConfirmationRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ExternalLauncherId {
    Shiro,
    Ysoserial,
    AntSword,
    Behinder,
    Godzilla,
}

impl ExternalLauncherId {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shiro => "shiro",
            Self::Ysoserial => "ysoserial",
            Self::AntSword => "antsword",
            Self::Behinder => "behinder",
            Self::Godzilla => "godzilla",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RequiredFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExternalToolPackManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub platform: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExternalLauncherManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub pack_id: String,
    pub category: String,
    pub summary: String,
    pub integration_mode: String,
    pub distribution: String,
    pub license: String,
    pub homepage: String,
    #[serde(default)]
    pub resolution_source: String,
    pub program: String,
    pub program_sha256: String,
    pub cwd: String,
    pub argv: Vec<String>,
    pub adapter_type: String,
    pub capability: String,
    pub permissions: Vec<String>,
    pub risk_level: String,
    pub network_policy: String,
    pub memory_max_bytes: u64,
    pub tasks_max: u32,
    pub cpu_quota_percent: u16,
    pub timeout_millis: u64,
    pub known_state_scope: String,
    #[serde(default)]
    pub required_file: Vec<RequiredFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ExternalLauncherRegistry {
    pub schema_version: u32,
    pub pack: ExternalToolPackManifest,
    #[serde(rename = "launcher")]
    pub launchers: Vec<ExternalLauncherManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ExternalLauncherHealthDto {
    pub launcher: ExternalLauncherId,
    pub name: String,
    pub version: String,
    pub pack_id: String,
    pub pack_name: String,
    pub pack_version: String,
    pub category: String,
    pub summary: String,
    pub integration_mode: String,
    pub distribution: String,
    pub license: String,
    pub homepage: String,
    pub resolution_source: String,
    pub program: String,
    pub program_sha256: String,
    pub adapter_type: String,
    pub capability: String,
    pub permissions: Vec<String>,
    pub risk_level: String,
    pub network_policy: String,
    #[ts(type = "number")]
    pub memory_max_bytes: u64,
    pub tasks_max: u32,
    pub cpu_quota_percent: u16,
    pub known_state_scope: String,
    pub healthy: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct LaunchExternalRequest {
    pub project_id: ProjectId,
    pub scope_id: ScopeId,
    pub launcher: ExternalLauncherId,
    pub target_url: String,
    pub confirmation: String,
}

pub fn registry() -> Result<ExternalLauncherRegistry, ExternalLauncherError> {
    let mut registry: ExternalLauncherRegistry =
        toml::from_str(EXTERNAL_LAUNCHERS_SOURCE).map_err(|_| ExternalLauncherError::Registry)?;
    apply_platform_defaults(&mut registry);
    apply_user_overrides(&mut registry);
    let expected = BTreeSet::from(["antsword", "behinder", "godzilla", "shiro", "ysoserial"]);
    let actual = registry
        .launchers
        .iter()
        .map(|launcher| launcher.id.as_str())
        .collect::<BTreeSet<_>>();
    if registry.schema_version != 2
        || registry.pack.id.is_empty()
        || registry.pack.name.is_empty()
        || registry.pack.version.is_empty()
        || registry.pack.platform != EXPECTED_PLATFORM
        || registry.launchers.len() != 5
        || actual != expected
        || registry.launchers.iter().any(|launcher| {
            !launcher.program.starts_with('/')
                || !launcher.cwd.starts_with('/')
                || launcher.pack_id != registry.pack.id
                || launcher.category.is_empty()
                || launcher.summary.is_empty()
                || !matches!(
                    launcher.integration_mode.as_str(),
                    "gui_compat" | "special_client"
                )
                || launcher.distribution != "bundled_or_override"
                || launcher.license.is_empty()
                || !launcher.homepage.starts_with("https://")
                || launcher.program_sha256.len() != 64
                || launcher.adapter_type != "external-launcher"
                || launcher.capability.is_empty()
                || launcher.permissions.is_empty()
                || launcher.risk_level != "l3"
                || launcher.network_policy != "target-scope-input-gate-and-audit"
                || launcher.memory_max_bytes == 0
                || launcher.tasks_max == 0
                || launcher.cpu_quota_percent == 0
                || launcher.timeout_millis == 0
                || launcher.required_file.is_empty()
        })
    {
        return Err(ExternalLauncherError::Registry);
    }
    Ok(registry)
}

#[cfg(target_os = "linux")]
fn apply_platform_defaults(_registry: &mut ExternalLauncherRegistry) {}

#[cfg(target_os = "macos")]
fn apply_platform_defaults(registry: &mut ExternalLauncherRegistry) {
    EXPECTED_PLATFORM.clone_into(&mut registry.pack.platform);
    let Some(home) = env::var_os("HOME") else {
        return;
    };
    let root = PathBuf::from(home)
        .join("Library/Application Support/FlagDeck/tool-packs")
        .display()
        .to_string();
    const LINUX_ROOT: &str = "/usr/lib/FlagDeck/tool-packs";
    for launcher in &mut registry.launchers {
        launcher.program = launcher.program.replace(LINUX_ROOT, &root);
        launcher.cwd = launcher.cwd.replace(LINUX_ROOT, &root);
        launcher.argv = launcher
            .argv
            .iter()
            .map(|value| value.replace(LINUX_ROOT, &root))
            .collect();
        for required in &mut launcher.required_file {
            required.path = required.path.replace(LINUX_ROOT, &root);
        }
    }
}

#[derive(Debug, Deserialize)]
struct ExternalOverrideRegistry {
    schema_version: u32,
    #[serde(default)]
    launcher: BTreeMap<String, ExternalLauncherOverride>,
}

#[derive(Debug, Deserialize)]
struct ExternalLauncherOverride {
    program: String,
    program_sha256: String,
    cwd: String,
    argv: Vec<String>,
    required_file: Vec<RequiredFile>,
}

fn apply_user_overrides(registry: &mut ExternalLauncherRegistry) {
    let path = env::var_os("FLAGDECK_EXTERNAL_LAUNCHERS_FILE")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .map(|root| root.join("flagdeck/external-launchers.toml"))
        })
        .or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .map(|root| default_user_config(&root, "external-launchers.toml"))
        });
    let Some(path) = path else {
        return;
    };
    let Ok(source) = fs::read_to_string(path) else {
        return;
    };
    let Ok(overrides) = toml::from_str::<ExternalOverrideRegistry>(&source) else {
        return;
    };
    if overrides.schema_version != 1 {
        return;
    }
    for launcher in &mut registry.launchers {
        if let Some(value) = overrides.launcher.get(&launcher.id) {
            launcher.program.clone_from(&value.program);
            launcher.program_sha256.clone_from(&value.program_sha256);
            launcher.cwd.clone_from(&value.cwd);
            launcher.argv.clone_from(&value.argv);
            launcher.required_file.clone_from(&value.required_file);
            "user_override".clone_into(&mut launcher.resolution_source);
        } else {
            "tool_pack".clone_into(&mut launcher.resolution_source);
        }
    }
}

#[cfg(target_os = "linux")]
fn default_user_config(home: &Path, name: &str) -> PathBuf {
    home.join(".config/flagdeck").join(name)
}

#[cfg(target_os = "macos")]
fn default_user_config(home: &Path, name: &str) -> PathBuf {
    home.join("Library/Application Support/FlagDeck").join(name)
}

pub fn manifest(
    launcher: ExternalLauncherId,
) -> Result<ExternalLauncherManifest, ExternalLauncherError> {
    registry()?
        .launchers
        .into_iter()
        .find(|item| item.id == launcher.as_str())
        .ok_or(ExternalLauncherError::InvalidRequest)
}

pub fn health() -> Result<Vec<ExternalLauncherHealthDto>, ExternalLauncherError> {
    let registry = registry()?;
    let pack_name = registry.pack.name;
    let pack_version = registry.pack.version;
    registry
        .launchers
        .into_iter()
        .map(|manifest| {
            let launcher = launcher_id(&manifest.id)?;
            let result = validate_manifest_integrity(&manifest);
            Ok(ExternalLauncherHealthDto {
                launcher,
                name: manifest.name,
                version: manifest.version,
                pack_id: manifest.pack_id,
                pack_name: pack_name.clone(),
                pack_version: pack_version.clone(),
                category: manifest.category,
                summary: manifest.summary,
                integration_mode: manifest.integration_mode,
                distribution: manifest.distribution,
                license: manifest.license,
                homepage: manifest.homepage,
                resolution_source: manifest.resolution_source,
                program: manifest.program,
                program_sha256: manifest.program_sha256,
                adapter_type: manifest.adapter_type,
                capability: manifest.capability,
                permissions: manifest.permissions,
                risk_level: manifest.risk_level,
                network_policy: manifest.network_policy,
                memory_max_bytes: manifest.memory_max_bytes,
                tasks_max: manifest.tasks_max,
                cpu_quota_percent: manifest.cpu_quota_percent,
                known_state_scope: manifest.known_state_scope,
                healthy: result.is_ok(),
                detail: result.map_or_else(|error| error.to_string(), |()| "ready".to_owned()),
            })
        })
        .collect()
}

pub fn prepare_command(
    manifest: &ExternalLauncherManifest,
    scope_id: &ScopeId,
    job_directory: &Path,
) -> Result<CommandSpec, ExternalLauncherError> {
    validate_manifest_integrity(manifest)?;
    let cwd = PathBuf::from(&manifest.cwd);
    if !job_directory.is_absolute() || !cwd.is_dir() {
        return Err(ExternalLauncherError::InvalidRequest);
    }
    let environment = launcher_environment(job_directory);
    Ok(CommandSpec {
        command_spec_id: CommandSpecId::new(),
        tool_id: format!("external.{}", manifest.id),
        tool_version: manifest.version.clone(),
        tool_sha256: manifest.program_sha256.clone(),
        program: manifest.program.clone(),
        argv_exec: manifest.argv.clone(),
        argv_redacted: manifest.argv.clone(),
        env_exec: environment.clone(),
        env_redacted: environment.clone(),
        secret_transport: SecretTransport::None,
        secret_inputs: Vec::new(),
        cwd: manifest.cwd.clone(),
        environment_allowlist: environment.keys().cloned().collect(),
        timeout_millis: manifest.timeout_millis,
        stop_grace_millis: 2_000,
        expected_outputs: Vec::new(),
        risk_level: RiskLevel::L3,
        scope_id: Some(scope_id.clone()),
        sandbox_profile: "stable-external-launcher-systemd-or-pgid".to_owned(),
        resource_limits: ResourceLimits {
            memory_max_bytes: manifest.memory_max_bytes,
            tasks_max: manifest.tasks_max,
            cpu_quota_percent: manifest.cpu_quota_percent,
            core_dump_bytes: 0,
        },
        network_isolation: manifest.network_policy.clone(),
    })
}

fn validate_manifest_integrity(
    manifest: &ExternalLauncherManifest,
) -> Result<(), ExternalLauncherError> {
    validate_program(Path::new(&manifest.program), &manifest.program_sha256)
        .map_err(|_| ExternalLauncherError::Integrity)?;
    for required in &manifest.required_file {
        validate_program(Path::new(&required.path), &required.sha256)
            .map_err(|_| ExternalLauncherError::Integrity)?;
    }
    Ok(())
}

fn launcher_id(value: &str) -> Result<ExternalLauncherId, ExternalLauncherError> {
    match value {
        "shiro" => Ok(ExternalLauncherId::Shiro),
        "ysoserial" => Ok(ExternalLauncherId::Ysoserial),
        "antsword" => Ok(ExternalLauncherId::AntSword),
        "behinder" => Ok(ExternalLauncherId::Behinder),
        "godzilla" => Ok(ExternalLauncherId::Godzilla),
        _ => Err(ExternalLauncherError::Registry),
    }
}

fn launcher_environment(job_directory: &Path) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::from([
        (
            "HOME".to_owned(),
            job_directory.join("home").display().to_string(),
        ),
        (
            "TMPDIR".to_owned(),
            job_directory.join("tmp").display().to_string(),
        ),
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ("LC_ALL".to_owned(), "C.UTF-8".to_owned()),
    ]);
    for name in [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_SESSION_TYPE",
    ] {
        if let Ok(value) = std::env::var(name)
            && !value.contains(['\0', '\n', '\r'])
            && value.len() <= 4096
        {
            environment.insert(name.to_owned(), value);
        }
    }
    environment
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use sha2::{Digest, Sha256};

    use super::*;

    fn fixture_manifest(
        launcher: ExternalLauncherId,
    ) -> (tempfile::TempDir, ExternalLauncherManifest) {
        let temporary = tempfile::tempdir().unwrap();
        let cwd = temporary.path().join("launcher");
        fs::create_dir(&cwd).unwrap();
        let program = cwd.join("start.sh");
        let program_bytes = b"#!/bin/sh\nexit 0\n";
        fs::write(&program, program_bytes).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let required = cwd.join("payload.bin");
        let required_bytes = b"flagdeck external launcher fixture";
        fs::write(&required, required_bytes).unwrap();
        fs::set_permissions(&required, fs::Permissions::from_mode(0o600)).unwrap();
        let mut manifest = manifest(launcher).unwrap();
        manifest.program = program.display().to_string();
        manifest.program_sha256 = format!("{:x}", Sha256::digest(program_bytes));
        manifest.cwd = cwd.display().to_string();
        manifest.required_file = vec![RequiredFile {
            path: required.display().to_string(),
            sha256: format!("{:x}", Sha256::digest(required_bytes)),
        }];
        (temporary, manifest)
    }

    #[test]
    fn registry_declares_l3_capabilities_and_reports_unsafe_files() {
        let registry = registry().unwrap();
        assert_eq!(registry.launchers.len(), 5);
        assert!(registry.launchers.iter().all(|launcher| {
            launcher.risk_level == "l3"
                && launcher.adapter_type == "external-launcher"
                && !launcher.permissions.is_empty()
        }));
        let health = health().unwrap();
        assert_eq!(health.len(), 5);
        assert!(
            health
                .iter()
                .all(|item| item.healthy == (item.detail == "ready"))
        );

        let (_temporary, manifest) = fixture_manifest(ExternalLauncherId::AntSword);
        fs::set_permissions(&manifest.program, fs::Permissions::from_mode(0o722)).unwrap();
        assert!(matches!(
            validate_manifest_integrity(&manifest),
            Err(ExternalLauncherError::Integrity)
        ));
    }

    #[test]
    fn managed_command_uses_fixed_program_argv_scope_and_resource_budget() {
        let (temporary, manifest) = fixture_manifest(ExternalLauncherId::Behinder);
        let command = prepare_command(&manifest, &ScopeId::new(), temporary.path()).unwrap();
        assert_eq!(command.program, manifest.program);
        assert_eq!(command.argv_exec, manifest.argv);
        assert_eq!(command.risk_level, RiskLevel::L3);
        assert!(command.scope_id.is_some());
        assert_eq!(command.resource_limits.core_dump_bytes, 0);
    }
}
