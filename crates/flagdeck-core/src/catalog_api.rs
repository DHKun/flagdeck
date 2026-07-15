//! Declarative catalog DTOs for the personal workbench UI.

use std::collections::BTreeMap;

use flagdeck_domain::ProjectId;
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CatalogToolDto {
    pub id: String,
    pub name: String,
    pub category: String,
    pub category_name: String,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EnsureTargetRequest {
    pub project_id: ProjectId,
    pub base_url: String,
}
