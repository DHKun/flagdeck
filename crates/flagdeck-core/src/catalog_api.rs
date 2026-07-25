//! Declarative catalog DTOs for the personal workbench UI.

use std::collections::BTreeMap;

use flagdeck_domain::{ProjectId, RiskLevel, ToolIoContract};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CatalogCategoryDto {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub order: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CatalogFormFieldDto {
    pub id: String,
    pub field_type: String,
    pub label: String,
    pub required: bool,
    pub default_value: String,
    pub from: String,
    pub options: Vec<String>,
    pub hint: String,
    pub sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CatalogPresetDto {
    pub id: String,
    pub name: String,
    pub core_fields: Vec<String>,
    pub defaults: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CatalogFieldGroupDto {
    pub id: String,
    pub name: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CatalogInstallationDto {
    pub distribution: String,
    pub license: String,
    pub homepage: String,
    pub version: String,
    pub health_strategy: String,
    pub runtime: String,
    pub version_args: Vec<String>,
    pub install_command: String,
    pub path_fix: String,
    pub wordlist_source: String,
    pub wordlist_install_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum CatalogDiagnosticStatus {
    Usable,
    Missing,
    VersionAbnormal,
    PathAbnormal,
    PermissionAbnormal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CatalogDiagnosticCheckDto {
    pub id: String,
    pub label: String,
    pub status: CatalogDiagnosticStatus,
    pub detail: String,
    pub source: String,
    pub fix: String,
    pub copy_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CatalogToolDiagnosticDto {
    pub tool_id: String,
    pub status: CatalogDiagnosticStatus,
    pub binary_path: String,
    pub detected_version: String,
    pub checks: Vec<CatalogDiagnosticCheckDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct DiagnoseCatalogToolRequest {
    pub tool_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CatalogToolDto {
    pub id: String,
    pub name: String,
    pub category: String,
    pub category_name: String,
    pub tier: String,
    pub capabilities: Vec<String>,
    pub aliases: Vec<String>,
    pub presets: Vec<CatalogPresetDto>,
    pub field_groups: Vec<CatalogFieldGroupDto>,
    pub risk_level: String,
    pub installation: CatalogInstallationDto,
    pub io: ToolIoContract,
    pub summary: String,
    pub usage: String,
    pub mode: String,
    pub featured: bool,
    pub available: bool,
    pub binary_path: String,
    pub detail: String,
    pub icon: String,
    pub accent: String,
    pub fields: Vec<CatalogFormFieldDto>,
    pub needs_target: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct WordlistDto {
    pub id: String,
    pub name: String,
    pub path: String,
    pub available: bool,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CatalogSnapshot {
    pub tools_root: String,
    pub wordlists_root: String,
    pub categories: Vec<CatalogCategoryDto>,
    pub tools: Vec<CatalogToolDto>,
    pub wordlists: Vec<WordlistDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct RunCatalogToolRequest {
    pub project_id: ProjectId,
    pub tool_id: String,
    pub target_url: String,
    pub form: BTreeMap<String, String>,
    #[serde(default)]
    pub confirm_sensitive_argv: bool,
    #[serde(default)]
    pub confirm_l2: bool,
    #[serde(default)]
    pub l3_confirmation: Option<String>,
    /// Optional provenance when launched via typed "send to" from another job result.
    #[serde(default)]
    pub source_job_id: Option<flagdeck_domain::JobId>,
    #[serde(default)]
    pub source_result_id: Option<String>,
    #[serde(default)]
    pub source_artifact_id: Option<flagdeck_domain::ArtifactId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PreviewCatalogToolRequest {
    pub project_id: ProjectId,
    pub tool_id: String,
    pub target_url: String,
    pub form: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CatalogRunPreview {
    pub command_preview: String,
    pub scope: String,
    pub rate_per_second: Option<u32>,
    pub estimated_request_count: Option<u32>,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EnsureTargetRequest {
    pub project_id: ProjectId,
    pub base_url: String,
}
