//! Declarative tool catalog: load TOML manifests and prepare managed commands.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use flagdeck_domain::{
    CommandSpec, CommandSpecId, ResourceLimits, RiskLevel, ScopeId, SecretInputLifecycle,
    SecretTransport, ToolInputRecord, ToolInputSource, ToolIoContract, ToolRunIo,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

const DEFAULT_TOOLS_ROOT: &str = "/data/CTF/Tools";

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("tool catalog is invalid: {0}")]
    Invalid(String),
    #[error("tool not found in catalog")]
    NotFound,
    #[error("tool binary could not be resolved")]
    BinaryMissing,
    #[error("tool form input is invalid")]
    InvalidInput,
    #[error("catalog I/O failed")]
    Io(#[from] std::io::Error),
    #[error("catalog TOML failed")]
    Toml(#[from] toml::de::Error),
    #[error("URL is invalid")]
    Url(#[from] url::ParseError),
}

#[derive(Debug, Clone, Deserialize)]
struct CategoriesFile {
    #[serde(default)]
    category: Vec<CatalogCategory>,
}

#[derive(Debug, Clone, Deserialize)]
struct WordlistsFile {
    #[serde(default)]
    wordlist: Vec<WordlistShortcut>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogCategory {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub order: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WordlistShortcut {
    pub id: String,
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ToolMode {
    #[default]
    EmbeddedCli,
    ExternalLaunch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinarySpec {
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub path: String,
    #[serde(default = "default_resolve")]
    pub resolve: Vec<String>,
}

impl Default for BinarySpec {
    fn default() -> Self {
        Self {
            command: String::new(),
            path: String::new(),
            resolve: default_resolve(),
        }
    }
}

fn default_resolve() -> Vec<String> {
    vec![
        "tools_root".to_owned(),
        "path".to_owned(),
        "system".to_owned(),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormField {
    pub id: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub label: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: String,
    #[serde(default)]
    pub from: String,
    /// For type=select: dropdown choices.
    #[serde(default)]
    pub options: Vec<String>,
    /// CLI flag shown beside the field label, for example `--tamper`.
    #[serde(default)]
    pub flag: String,
    /// Short helper under the field.
    #[serde(default)]
    pub hint: String,
    /// Concrete values that help the user fill the field without opening external docs.
    #[serde(default)]
    pub examples: Vec<String>,
    /// Rich metadata for select and multiselect values.
    #[serde(default)]
    pub option_details: Vec<FormOptionDetail>,
    /// Field ids whose values are matched against option tags for local recommendations.
    #[serde(default)]
    pub recommend_from: Vec<String>,
    /// Values that must stay out of preferences, logs, and persisted command previews.
    #[serde(default)]
    pub sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FormOptionDetail {
    pub value: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FormSpec {
    #[serde(default)]
    pub fields: Vec<FormField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogPreset {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub core_fields: Vec<String>,
    #[serde(default)]
    pub defaults: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogFieldGroup {
    pub id: String,
    pub name: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CatalogFormRelation {
    /// `requires` or `conflicts`.
    pub kind: String,
    pub field: String,
    #[serde(default)]
    pub equals: String,
    pub other: String,
    #[serde(default)]
    pub other_equals: String,
    /// `error` blocks execution; `warning` requires a UI acknowledgement.
    #[serde(default = "default_relation_severity")]
    pub severity: String,
    pub message: String,
}

fn default_relation_severity() -> String {
    "error".to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CatalogHelpSpec {
    /// Explicit side-effect-reviewed argv used to obtain version-matched help.
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_help_timeout")]
    pub timeout_millis: u64,
    #[serde(default = "default_help_max_bytes")]
    pub max_bytes: usize,
}

fn default_help_timeout() -> u64 {
    5_000
}

fn default_help_max_bytes() -> usize {
    256 * 1024
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CatalogInstallation {
    #[serde(default)]
    pub distribution: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub homepage: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub health_strategy: String,
    #[serde(default)]
    pub runtime: String,
    #[serde(default)]
    pub version_args: Vec<String>,
    #[serde(default)]
    pub install_command: String,
    #[serde(default)]
    pub path_fix: String,
    #[serde(default)]
    pub wordlist_source: String,
    #[serde(default)]
    pub wordlist_install_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OptionalArgGroup {
    /// Include these args when `field` is non-empty (or equals `equals` if set).
    pub field: String,
    #[serde(default)]
    pub equals: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ArgvSpec {
    #[serde(default)]
    pub template: Vec<String>,
    /// Appended after optional groups (e.g. URL must be last for curl).
    #[serde(default)]
    pub suffix: Vec<String>,
    #[serde(default)]
    pub optional: Vec<OptionalArgGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ParserSpec {
    #[serde(default = "default_parser_kind")]
    pub kind: String,
    /// Optional stable parser identity used by structured-result adapters.
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub version: String,
}

fn default_parser_kind() -> String {
    "none".to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UiSpec {
    #[serde(default)]
    pub icon: String,
    #[serde(default)]
    pub accent: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitsSpec {
    #[serde(default = "default_timeout")]
    pub timeout_millis: u64,
    #[serde(default = "default_memory")]
    pub memory_max_bytes: u64,
    #[serde(default = "default_tasks")]
    pub tasks_max: u32,
    #[serde(default = "default_cpu")]
    pub cpu_quota_percent: u16,
}

impl Default for LimitsSpec {
    fn default() -> Self {
        Self {
            timeout_millis: default_timeout(),
            memory_max_bytes: default_memory(),
            tasks_max: default_tasks(),
            cpu_quota_percent: default_cpu(),
        }
    }
}

fn default_timeout() -> u64 {
    120_000
}
fn default_memory() -> u64 {
    256 * 1024 * 1024
}
fn default_tasks() -> u32 {
    64
}
fn default_cpu() -> u16 {
    100
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogToolManifest {
    pub id: String,
    pub name: String,
    pub category: String,
    #[serde(default = "default_tier")]
    pub tier: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub presets: Vec<CatalogPreset>,
    #[serde(default)]
    pub field_groups: Vec<CatalogFieldGroup>,
    #[serde(default)]
    pub relations: Vec<CatalogFormRelation>,
    #[serde(default = "default_catalog_risk_level")]
    pub risk_level: String,
    #[serde(default)]
    pub installation: CatalogInstallation,
    #[serde(default)]
    pub io: ToolIoContract,
    #[serde(default)]
    pub summary: String,
    /// Hover help: practical usage for this tool (CLI flags / GUI notes).
    #[serde(default)]
    pub usage: String,
    #[serde(default)]
    pub mode: ToolMode,
    #[serde(default)]
    pub featured: bool,
    /// Empty means all supported desktop platforms.
    #[serde(default)]
    pub platforms: Vec<String>,
    /// Working directory (absolute, or relative to tools root). Empty = job dir (CLI) or binary parent (GUI).
    #[serde(default)]
    pub cwd: String,
    /// Process lifecycle for `external_launch` tools.
    ///
    /// - `true` (default): spawn, brief probe, mark succeeded and detach (classic GUI windows).
    /// - `false`: keep waiting so cancel/stop works (long-running servers like `npm run dev`).
    ///
    /// Ignored for `embedded_cli` (always managed).
    #[serde(default)]
    pub detach: Option<bool>,
    #[serde(default)]
    pub binary: BinarySpec,
    #[serde(default)]
    pub form: FormSpec,
    #[serde(default)]
    pub argv: ArgvSpec,
    #[serde(default)]
    pub parser: ParserSpec,
    #[serde(default)]
    pub help: CatalogHelpSpec,
    #[serde(default)]
    pub ui: UiSpec,
    #[serde(default)]
    pub limits: LimitsSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogToolView {
    pub id: String,
    pub name: String,
    pub category: String,
    pub category_name: String,
    pub tier: String,
    pub capabilities: Vec<String>,
    pub aliases: Vec<String>,
    pub presets: Vec<CatalogPreset>,
    pub field_groups: Vec<CatalogFieldGroup>,
    pub relations: Vec<CatalogFormRelation>,
    pub risk_level: String,
    pub installation: CatalogInstallation,
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
    pub fields: Vec<FormField>,
    pub help: CatalogHelpSpec,
    pub needs_target: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WordlistView {
    pub id: String,
    pub name: String,
    pub path: String,
    pub available: bool,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CatalogPaths {
    pub tools_root: PathBuf,
    pub wordlists_root: PathBuf,
    pub catalog_root: PathBuf,
    pub user_catalog_root: PathBuf,
    pub cache_root: PathBuf,
}

impl CatalogPaths {
    #[must_use]
    pub fn from_env() -> Self {
        let tools_root = env::var_os("FLAGDECK_TOOLS_ROOT")
            .map_or_else(|| PathBuf::from(DEFAULT_TOOLS_ROOT), PathBuf::from);
        let wordlists_root = env::var_os("FLAGDECK_WORDLISTS_ROOT")
            .map_or_else(|| tools_root.join("Wordlists"), PathBuf::from);
        let catalog_root =
            env::var_os("FLAGDECK_CATALOG_ROOT").map_or_else(default_catalog_root, PathBuf::from);
        let user_catalog_root = env::var_os("FLAGDECK_USER_CATALOG_ROOT")
            .map_or_else(default_user_catalog_root, PathBuf::from);
        let cache_root =
            env::var_os("FLAGDECK_CACHE_ROOT").map_or_else(default_cache_root, PathBuf::from);
        Self {
            tools_root,
            wordlists_root,
            catalog_root,
            user_catalog_root,
            cache_root,
        }
    }
}

fn default_user_catalog_root() -> PathBuf {
    env::var_os("XDG_CONFIG_HOME").map_or_else(
        || {
            env::var_os("HOME").map_or_else(
                || PathBuf::from("config/flagdeck/catalog"),
                |home| PathBuf::from(home).join(".config/flagdeck/catalog"),
            )
        },
        |root| PathBuf::from(root).join("flagdeck/catalog"),
    )
}

fn default_cache_root() -> PathBuf {
    env::var_os("XDG_CACHE_HOME").map_or_else(
        || {
            env::var_os("HOME").map_or_else(
                || PathBuf::from(".cache/flagdeck"),
                |home| PathBuf::from(home).join(".cache/flagdeck"),
            )
        },
        |root| PathBuf::from(root).join("flagdeck"),
    )
}

fn default_catalog_root() -> PathBuf {
    let mut candidates = Vec::new();
    if let Ok(current) = env::current_dir() {
        candidates.extend(
            current
                .ancestors()
                .take(8)
                .map(|ancestor| ancestor.join("config/tool-catalog")),
        );
    }
    if let Ok(executable) = env::current_exe() {
        candidates.extend(
            executable
                .ancestors()
                .take(8)
                .map(|ancestor| ancestor.join("config/tool-catalog")),
        );
    }
    candidates.push(PathBuf::from("/usr/lib/FlagDeck/config/tool-catalog"));
    candidates
        .into_iter()
        .find(|path| path.join("tools").is_dir())
        .unwrap_or_else(|| PathBuf::from("config/tool-catalog"))
}

#[derive(Debug, Clone)]
pub struct ToolCatalog {
    pub paths: CatalogPaths,
    pub categories: Vec<CatalogCategory>,
    pub tools: Vec<CatalogToolManifest>,
    pub wordlists: Vec<WordlistShortcut>,
}

impl ToolCatalog {
    pub fn load(paths: CatalogPaths) -> Result<Self, CatalogError> {
        let categories = load_categories(&paths.catalog_root)?;
        let wordlists = load_wordlists(&paths.catalog_root)?;
        let tools = load_tools(&paths.catalog_root, &paths.user_catalog_root)?;
        Ok(Self {
            paths,
            categories,
            tools,
            wordlists,
        })
    }

    pub fn load_default() -> Result<Self, CatalogError> {
        Self::load(CatalogPaths::from_env())
    }

    #[must_use]
    pub fn tool(&self, id: &str) -> Option<&CatalogToolManifest> {
        self.tools.iter().find(|tool| tool.id == id)
    }

    pub fn resolve_tool_binary(&self, id: &str) -> Result<PathBuf, CatalogError> {
        let tool = self.tool(id).ok_or(CatalogError::NotFound)?;
        if !tool_supports_current_platform(tool) {
            return Err(CatalogError::BinaryMissing);
        }
        resolve_binary(tool, &self.paths)
    }

    #[must_use]
    pub fn tool_views(&self) -> Vec<CatalogToolView> {
        let mut views = self
            .tools
            .iter()
            .map(|tool| {
                let category_name = self
                    .categories
                    .iter()
                    .find(|category| category.id == tool.category)
                    .map_or_else(|| tool.category.clone(), |category| category.name.clone());
                let resolved =
                    tool_supports_current_platform(tool).then(|| resolve_binary(tool, &self.paths));
                let (available, binary_path, detail) = match resolved {
                    None => (
                        false,
                        String::new(),
                        format!("unsupported platform: {}", env::consts::OS),
                    ),
                    Some(Ok(path)) if tool.cwd.is_empty() => {
                        (true, path.display().to_string(), "ready".to_owned())
                    }
                    Some(Ok(path)) => {
                        let cwd = if Path::new(&tool.cwd).is_absolute() {
                            PathBuf::from(&tool.cwd)
                        } else {
                            self.paths.tools_root.join(&tool.cwd)
                        };
                        if cwd.is_dir() {
                            (true, path.display().to_string(), "ready".to_owned())
                        } else {
                            (
                                false,
                                path.display().to_string(),
                                format!("working directory not found: {}", cwd.display()),
                            )
                        }
                    }
                    Some(Err(error)) => (false, String::new(), error.to_string()),
                };
                CatalogToolView {
                    id: tool.id.clone(),
                    name: tool.name.clone(),
                    category: tool.category.clone(),
                    category_name,
                    tier: tool.tier.clone(),
                    capabilities: tool.capabilities.clone(),
                    aliases: tool.aliases.clone(),
                    presets: tool.presets.clone(),
                    field_groups: tool.field_groups.clone(),
                    relations: tool.relations.clone(),
                    risk_level: catalog_risk_level_name(effective_catalog_risk_level(tool))
                        .to_owned(),
                    installation: tool.installation.clone(),
                    io: tool.io.clone(),
                    summary: tool.summary.clone(),
                    usage: tool.usage.clone(),
                    mode: match tool.mode {
                        ToolMode::EmbeddedCli => "embedded_cli".to_owned(),
                        ToolMode::ExternalLaunch => "external_launch".to_owned(),
                    },
                    featured: tool.featured,
                    available,
                    binary_path,
                    detail,
                    icon: tool.ui.icon.clone(),
                    accent: tool.ui.accent.clone(),
                    fields: tool.form.fields.clone(),
                    help: tool.help.clone(),
                    needs_target: tool_needs_target(tool),
                }
            })
            .collect::<Vec<_>>();
        views.sort_by(|left, right| left.name.cmp(&right.name));
        views
    }

    #[must_use]
    pub fn wordlist_views(&self) -> Vec<WordlistView> {
        self.wordlists
            .iter()
            .map(|entry| {
                let absolute = self.paths.wordlists_root.join(&entry.path);
                WordlistView {
                    id: entry.id.clone(),
                    name: entry.name.clone(),
                    path: absolute.display().to_string(),
                    available: absolute.is_file(),
                    tags: entry.tags.clone(),
                }
            })
            .collect()
    }

    pub fn resolve_wordlist_path(&self, value: &str) -> Result<PathBuf, CatalogError> {
        if value.is_empty() {
            return Err(CatalogError::InvalidInput);
        }
        if let Some(shortcut) = self.wordlists.iter().find(|entry| entry.id == value) {
            let path = self.paths.wordlists_root.join(&shortcut.path);
            if path.is_file() {
                return Ok(path);
            }
            return Err(CatalogError::InvalidInput);
        }
        let path = PathBuf::from(value);
        if path.is_absolute() && path.is_file() {
            return Ok(path);
        }
        let relative = self.paths.wordlists_root.join(value);
        if relative.is_file() {
            return Ok(relative);
        }
        Err(CatalogError::InvalidInput)
    }

    fn preview_wordlist_path(&self, value: &str) -> Result<PathBuf, CatalogError> {
        if value.is_empty() {
            return Err(CatalogError::InvalidInput);
        }
        if let Some(shortcut) = self.wordlists.iter().find(|entry| entry.id == value) {
            return Ok(self.paths.wordlists_root.join(&shortcut.path));
        }
        let path = PathBuf::from(value);
        if path.is_absolute() {
            return Ok(path);
        }
        Ok(self.paths.wordlists_root.join(path))
    }
}

fn default_tier() -> String {
    "tier_2".to_owned()
}

fn default_catalog_risk_level() -> String {
    String::new()
}

fn effective_catalog_risk_level(tool: &CatalogToolManifest) -> RiskLevel {
    match tool.risk_level.to_ascii_lowercase().as_str() {
        "l0" => RiskLevel::L0,
        "l1" => RiskLevel::L1,
        "l2" => RiskLevel::L2,
        "l3" => RiskLevel::L3,
        _ => match tool.mode {
            ToolMode::ExternalLaunch => RiskLevel::L3,
            ToolMode::EmbeddedCli => RiskLevel::L2,
        },
    }
}

fn catalog_risk_level_name(risk_level: RiskLevel) -> &'static str {
    match risk_level {
        RiskLevel::L0 => "l0",
        RiskLevel::L1 => "l1",
        RiskLevel::L2 => "l2",
        RiskLevel::L3 => "l3",
    }
}

fn tool_needs_target(tool: &CatalogToolManifest) -> bool {
    tool.form.fields.iter().any(|field| {
        field.required
            && (field.field_type == "url"
                || field.field_type == "host"
                || field.from == "target_url"
                || field.id == "url"
                || field.id == "host"
                || field.id == "target")
    })
}

fn load_categories(root: &Path) -> Result<Vec<CatalogCategory>, CatalogError> {
    let path = root.join("categories.toml");
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path)?;
    let file: CategoriesFile = toml::from_str(&text)?;
    let mut categories = file.category;
    categories.sort_by_key(|category| category.order);
    Ok(categories)
}

fn load_wordlists(root: &Path) -> Result<Vec<WordlistShortcut>, CatalogError> {
    let path = root.join("wordlists.toml");
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path)?;
    let file: WordlistsFile = toml::from_str(&text)?;
    Ok(file.wordlist)
}

fn load_tools(root: &Path, user_root: &Path) -> Result<Vec<CatalogToolManifest>, CatalogError> {
    let mut definitions = BTreeMap::<String, (PathBuf, toml::Value)>::new();
    for (path, value) in load_tool_values(&root.join("tools"), true)? {
        let id = tool_value_id(&path, &value)?;
        if definitions
            .insert(id.clone(), (path.clone(), value))
            .is_some()
        {
            return Err(CatalogError::Invalid(format!(
                "{} duplicates tool id {id}",
                path.display()
            )));
        }
    }
    for (path, overlay) in load_tool_values(&user_root.join("tools"), false)? {
        let id = tool_value_id(&path, &overlay)?;
        if let Some((source, base)) = definitions.get_mut(&id) {
            merge_toml_value(base, overlay);
            *source = path;
        } else {
            definitions.insert(id, (path, overlay));
        }
    }

    let mut tools = Vec::with_capacity(definitions.len());
    for (_, (path, value)) in definitions {
        let tool: CatalogToolManifest = value
            .try_into()
            .map_err(|error| CatalogError::Invalid(format!("{}: {error}", path.display())))?;
        validate_tool_manifest(&path, &tool)?;
        tools.push(tool);
    }
    tools.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(tools)
}

fn load_tool_values(
    tools_dir: &Path,
    required: bool,
) -> Result<Vec<(PathBuf, toml::Value)>, CatalogError> {
    if !tools_dir.is_dir() {
        if required {
            return Err(CatalogError::Invalid(format!(
                "missing tools directory at {}",
                tools_dir.display()
            )));
        }
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    for entry in fs::read_dir(tools_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }
        let text = fs::read_to_string(&path)?;
        let value = toml::from_str(&text)
            .map_err(|error| CatalogError::Invalid(format!("{}: {error}", path.display())))?;
        values.push((path, value));
    }
    values.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(values)
}

fn tool_value_id(path: &Path, value: &toml::Value) -> Result<String, CatalogError> {
    value
        .get("id")
        .and_then(toml::Value::as_str)
        .filter(|id| is_safe_identifier(id))
        .map(str::to_owned)
        .ok_or_else(|| {
            CatalogError::Invalid(format!(
                "{} has an invalid or missing tool id",
                path.display()
            ))
        })
}

fn is_safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn merge_toml_value(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base), toml::Value::Table(overlay)) => {
            for (key, value) in overlay {
                if let Some(existing) = base.get_mut(&key) {
                    merge_toml_value(existing, value);
                } else {
                    base.insert(key, value);
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn validate_tool_manifest(path: &Path, tool: &CatalogToolManifest) -> Result<(), CatalogError> {
    if tool.id.is_empty() || tool.name.is_empty() {
        return Err(CatalogError::Invalid(format!(
            "{} missing required fields",
            path.display()
        )));
    }
    let field_ids = tool
        .form
        .fields
        .iter()
        .map(|field| field.id.as_str())
        .collect::<BTreeSet<_>>();
    if field_ids.len() != tool.form.fields.len()
        || field_ids.iter().any(|field| !is_safe_identifier(field))
    {
        return Err(CatalogError::Invalid(format!(
            "{} has duplicate or invalid form field ids",
            path.display()
        )));
    }
    for field in &tool.form.fields {
        if !matches!(
            field.field_type.as_str(),
            "url"
                | "host"
                | "wordlist"
                | "text"
                | "textarea"
                | "number"
                | "select"
                | "multiselect"
                | "args"
        ) {
            return Err(CatalogError::Invalid(format!(
                "{} field {} uses unsupported type {}",
                path.display(),
                field.id,
                field.field_type
            )));
        }
        if matches!(field.field_type.as_str(), "select" | "multiselect") && field.options.is_empty()
        {
            return Err(CatalogError::Invalid(format!(
                "{} field {} requires options",
                path.display(),
                field.id
            )));
        }
        if field
            .option_details
            .iter()
            .any(|option| !field.options.contains(&option.value))
            || field
                .recommend_from
                .iter()
                .any(|source| !field_ids.contains(source.as_str()))
        {
            return Err(CatalogError::Invalid(format!(
                "{} field {} has invalid option metadata",
                path.display(),
                field.id
            )));
        }
    }
    for relation in &tool.relations {
        if !matches!(relation.kind.as_str(), "requires" | "conflicts")
            || !matches!(relation.severity.as_str(), "error" | "warning")
            || !field_ids.contains(relation.field.as_str())
            || !field_ids.contains(relation.other.as_str())
            || relation.message.trim().is_empty()
            || relation.message.len() > 512
        {
            return Err(CatalogError::Invalid(format!(
                "{} has an invalid form relation",
                path.display()
            )));
        }
    }
    if tool.help.timeout_millis > 15_000
        || tool.help.max_bytes > 1024 * 1024
        || (!tool.help.args.is_empty()
            && (tool.help.timeout_millis == 0
                || tool.help.max_bytes == 0
                || tool.help.args.len() > 64))
        || tool
            .help
            .args
            .iter()
            .any(|arg| arg.contains('\0') || arg.len() > 1024)
    {
        return Err(CatalogError::Invalid(format!(
            "{} has an unsafe help command",
            path.display()
        )));
    }
    validate_existing_tool_contract(path, tool)
}

fn validate_existing_tool_contract(
    path: &Path,
    tool: &CatalogToolManifest,
) -> Result<(), CatalogError> {
    if !matches!(tool.io.schema_version, 0 | 1) {
        return Err(CatalogError::Invalid(format!(
            "{} unsupported I/O schema version {}",
            path.display(),
            tool.io.schema_version
        )));
    }
    if tool.io.schema_version == 0 && (!tool.io.inputs.is_empty() || !tool.io.outputs.is_empty()) {
        return Err(CatalogError::Invalid(format!(
            "{} typed I/O requires schema version 1",
            path.display()
        )));
    }
    if tool.io.schema_version == 1
        && tool.io.inputs.iter().any(|input| {
            input.id.is_empty()
                || input.field.is_empty()
                || !tool.form.fields.iter().any(|field| field.id == input.field)
        })
    {
        return Err(CatalogError::Invalid(format!(
            "{} typed I/O input references an unknown field",
            path.display()
        )));
    }
    // external_launch may have empty argv (binary is the full entrypoint).
    // embedded_cli needs at least one of template / optional / suffix so prepare can build argv.
    if tool.mode == ToolMode::EmbeddedCli
        && tool.argv.template.is_empty()
        && tool.argv.optional.is_empty()
        && tool.argv.suffix.is_empty()
    {
        return Err(CatalogError::Invalid(format!(
            "{} embedded_cli requires argv.template, optional, or suffix",
            path.display()
        )));
    }
    Ok(())
}

pub fn resolve_binary(
    tool: &CatalogToolManifest,
    paths: &CatalogPaths,
) -> Result<PathBuf, CatalogError> {
    for strategy in &tool.binary.resolve {
        match strategy.as_str() {
            "path" | "tools_root" if !tool.binary.path.is_empty() => {
                let candidate = resolve_path_candidate(&tool.binary.path, paths);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
            "system" if !tool.binary.command.is_empty() => {
                if let Some(found) = find_on_path(&tool.binary.command) {
                    return Ok(found);
                }
            }
            _ => {}
        }
    }
    if !tool.binary.path.is_empty() {
        let candidate = resolve_path_candidate(&tool.binary.path, paths);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    if !tool.binary.command.is_empty()
        && let Some(found) = find_on_path(&tool.binary.command)
    {
        return Ok(found);
    }
    Err(CatalogError::BinaryMissing)
}

fn resolve_path_candidate(path: &str, paths: &CatalogPaths) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        candidate
    } else {
        paths.tools_root.join(path)
    }
}

fn find_on_path(command: &str) -> Option<PathBuf> {
    if command.contains('/') {
        let path = PathBuf::from(command);
        return path.is_file().then_some(path);
    }

    let mut preferred: Vec<PathBuf> = Vec::new();
    let mut fallback: Vec<PathBuf> = Vec::new();

    if let Ok(home) = env::var("HOME") {
        let home = PathBuf::from(home);
        // Prefer real mise install bins over shims — shims need a full user HOME/mise context.
        let go_installs = home.join(".local/share/mise/installs/go");
        if go_installs.is_dir()
            && let Ok(entries) = fs::read_dir(&go_installs)
        {
            for entry in entries.flatten() {
                let bin = entry.path().join("bin");
                if bin.is_dir() {
                    preferred.push(bin);
                }
            }
        }
        let java_installs = home.join(".local/share/mise/installs/java");
        if java_installs.is_dir()
            && let Ok(entries) = fs::read_dir(&java_installs)
        {
            for entry in entries.flatten() {
                let bin = entry.path().join("bin");
                if bin.is_dir() {
                    preferred.push(bin);
                }
            }
        }
        preferred.push(home.join(".local/bin"));
        fallback.push(home.join(".local/share/mise/shims"));
    }

    if let Some(path_var) = env::var_os("PATH") {
        for directory in env::split_paths(&path_var) {
            let text = directory.to_string_lossy();
            if text.contains("mise/shims") {
                fallback.push(directory);
            } else {
                preferred.push(directory);
            }
        }
    }

    for directory in ["/usr/local/bin", "/usr/bin", "/bin", "/opt/homebrew/bin"] {
        preferred.push(PathBuf::from(directory));
    }

    for directory in preferred.into_iter().chain(fallback) {
        let candidate = directory.join(command);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub fn file_sha256(path: &Path) -> Result<String, CatalogError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[derive(Debug, Clone)]
pub struct PreparedCatalogCommand {
    pub tool_id: String,
    pub tool_name: String,
    pub mode: ToolMode,
    pub parser_id: String,
    pub parser_version: String,
    /// See [`CatalogToolManifest::detach`].
    pub detach: bool,
    pub spec: CommandSpec,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub target_url: Option<String>,
}

pub fn prepare_catalog_command(
    catalog: &ToolCatalog,
    tool_id: &str,
    scope_id: &ScopeId,
    form_values: &BTreeMap<String, String>,
    job_directory: &Path,
) -> Result<PreparedCatalogCommand, CatalogError> {
    let input_sources = form_values
        .keys()
        .map(|field| (field.clone(), ToolInputSource::Form))
        .collect();
    prepare_catalog_command_with_sources(
        catalog,
        tool_id,
        scope_id,
        form_values,
        &input_sources,
        job_directory,
    )
}

pub fn prepare_catalog_command_with_sources(
    catalog: &ToolCatalog,
    tool_id: &str,
    scope_id: &ScopeId,
    form_values: &BTreeMap<String, String>,
    input_sources: &BTreeMap<String, ToolInputSource>,
    job_directory: &Path,
) -> Result<PreparedCatalogCommand, CatalogError> {
    prepare_catalog_command_with_sources_impl(
        catalog,
        tool_id,
        scope_id,
        form_values,
        input_sources,
        job_directory,
        true,
    )
}

pub fn prepare_catalog_preview_with_sources(
    catalog: &ToolCatalog,
    tool_id: &str,
    scope_id: &ScopeId,
    form_values: &BTreeMap<String, String>,
    input_sources: &BTreeMap<String, ToolInputSource>,
    job_directory: &Path,
) -> Result<PreparedCatalogCommand, CatalogError> {
    prepare_catalog_command_with_sources_impl(
        catalog,
        tool_id,
        scope_id,
        form_values,
        input_sources,
        job_directory,
        false,
    )
}

fn prepare_catalog_command_with_sources_impl(
    catalog: &ToolCatalog,
    tool_id: &str,
    scope_id: &ScopeId,
    form_values: &BTreeMap<String, String>,
    input_sources: &BTreeMap<String, ToolInputSource>,
    job_directory: &Path,
    require_available_binary: bool,
) -> Result<PreparedCatalogCommand, CatalogError> {
    let tool = catalog.tool(tool_id).ok_or(CatalogError::NotFound)?;
    if !tool_supports_current_platform(tool) {
        return Err(CatalogError::BinaryMissing);
    }
    if !job_directory.is_absolute() {
        return Err(CatalogError::InvalidInput);
    }
    fs::create_dir_all(job_directory)?;
    fs::create_dir_all(job_directory.join("tmp"))?;
    fs::create_dir_all(job_directory.join("home"))?;

    validate_form_values(tool, form_values)?;

    let (binary, sha256) = if require_available_binary {
        let binary = resolve_binary(tool, &catalog.paths)?;
        let sha256 = file_sha256(&binary)?;
        (binary, sha256)
    } else {
        let binary = {
            if tool.binary.command.is_empty() {
                resolve_path_candidate(&tool.binary.path, &catalog.paths)
            } else {
                PathBuf::from(&tool.binary.command)
            }
        };
        (binary, String::new())
    };
    let binary_str = binary.display().to_string();

    let mut values = form_values.clone();
    values.insert("binary".to_owned(), binary_str.clone());
    values.insert("job_dir".to_owned(), job_directory.display().to_string());
    values.insert(
        "tools_root".to_owned(),
        catalog.paths.tools_root.display().to_string(),
    );
    values.insert(
        "wordlists_root".to_owned(),
        catalog.paths.wordlists_root.display().to_string(),
    );

    // Apply defaults first
    for field in &tool.form.fields {
        if !field.default.is_empty() {
            values
                .entry(field.id.clone())
                .or_insert_with(|| field.default.clone());
        }
    }

    // Resolve wordlist fields to absolute paths
    for field in &tool.form.fields {
        if field.field_type != "wordlist" {
            continue;
        }
        let raw = values
            .get(&field.id)
            .cloned()
            .filter(|value| !value.is_empty())
            .or_else(|| {
                if field.default.is_empty() {
                    None
                } else {
                    Some(field.default.clone())
                }
            })
            .ok_or(CatalogError::InvalidInput)?;
        let path = if require_available_binary {
            catalog.resolve_wordlist_path(&raw)?
        } else {
            catalog.preview_wordlist_path(&raw)?
        };
        values.insert(field.id.clone(), path.display().to_string());
        values.insert("wordlist".to_owned(), path.display().to_string());
    }

    // Normalize URL / host / target fields for tools that need them.
    if let Some(url_text) = values.get("url").cloned().filter(|v| !v.is_empty()) {
        if looks_like_url(&url_text) {
            let parsed = Url::parse(&url_text).map_err(|_| CatalogError::InvalidInput)?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(CatalogError::InvalidInput);
            }
            if let Some(host) = parsed.host_str() {
                values
                    .entry("host".to_owned())
                    .or_insert_with(|| host.to_owned());
            }
            values.insert(
                "url_base".to_owned(),
                url_text.trim_end_matches('/').to_owned(),
            );
        } else {
            // User typed host into a url field — treat as host and synthesize http URL.
            values
                .entry("host".to_owned())
                .or_insert_with(|| url_text.clone());
            let synthesized = format!("http://{url_text}");
            values.insert("url".to_owned(), synthesized.clone());
            values.insert(
                "url_base".to_owned(),
                synthesized.trim_end_matches('/').to_owned(),
            );
        }
    }

    // host field may still contain a full URL from the global target bar
    if let Some(host_raw) = values.get("host").cloned().filter(|v| !v.is_empty())
        && looks_like_url(&host_raw)
        && let Ok(parsed) = Url::parse(&host_raw)
        && let Some(host) = parsed.host_str()
    {
        values.insert("host".to_owned(), host.to_owned());
    }

    if let Some(target) = values.get("target").cloned().filter(|v| !v.is_empty()) {
        if looks_like_url(&target) {
            if let Ok(parsed) = Url::parse(&target) {
                if let Some(host) = parsed.host_str() {
                    values
                        .entry("host".to_owned())
                        .or_insert_with(|| host.to_owned());
                }
                values
                    .entry("url".to_owned())
                    .or_insert_with(|| target.clone());
                values
                    .entry("url_base".to_owned())
                    .or_insert_with(|| target.trim_end_matches('/').to_owned());
            }
        } else {
            values.entry("host".to_owned()).or_insert(target);
        }
    }

    // Ensure url_base / ffuf_url exist when url is present
    if let Some(url) = values.get("url").cloned() {
        let base = url.trim_end_matches('/').to_owned();
        values.entry("url_base".to_owned()).or_insert(base.clone());
        let ffuf_url = if url.contains("FUZZ") {
            url
        } else {
            format!("{base}/FUZZ")
        };
        values.insert("ffuf_url".to_owned(), ffuf_url);
    }

    // rate=0 means unlimited for ffuf: treat as unset so optional group skips.
    if values.get("rate").is_some_and(|value| value == "0") {
        values.insert("rate".to_owned(), String::new());
    }

    let target_url = values
        .get("url")
        .cloned()
        .filter(|value| !value.is_empty())
        .or_else(|| values.get("target").cloned().filter(|v| !v.is_empty()));

    // Expand argv template. Templates must list ARGS ONLY (not the program).
    // We still strip a leading {binary} for backward compatibility.
    let mut argv = Vec::new();
    for part in &tool.argv.template {
        argv.extend(expand_argv_part(tool, part, &values)?);
    }
    for group in &tool.argv.optional {
        let raw = values.get(&group.field).map_or("", String::as_str);
        let include = if group.equals.is_empty() {
            !raw.is_empty()
        } else {
            raw == group.equals
        };
        if !include {
            continue;
        }
        for part in &group.args {
            argv.extend(expand_argv_part(tool, part, &values)?);
        }
    }
    for part in &tool.argv.suffix {
        argv.extend(expand_argv_part(tool, part, &values)?);
    }
    if argv
        .first()
        .is_some_and(|first| first == &binary_str || first == &tool.binary.command)
    {
        argv.remove(0);
    }
    // Drop empty tokens (should be rare; optional groups already gated).
    argv.retain(|part| !part.is_empty());
    if tool.mode == ToolMode::EmbeddedCli && argv.is_empty() {
        return Err(CatalogError::InvalidInput);
    }

    let cwd = resolve_cwd(
        tool,
        &catalog.paths,
        &binary,
        job_directory,
        require_available_binary,
    )?;
    let environment = build_environment(tool, job_directory, &cwd);

    let risk_level = effective_catalog_risk_level(tool);

    let mut sensitive_values = tool
        .form
        .fields
        .iter()
        .filter(|field| field.sensitive)
        .filter_map(|field| {
            values
                .get(&field.id)
                .filter(|value| !value.is_empty())
                .map(|value| (field.id.clone(), value.clone()))
        })
        .collect::<Vec<_>>();
    sensitive_values.sort_by_key(|(_, value)| std::cmp::Reverse(value.len()));
    let argv_redacted = argv
        .iter()
        .map(|argument| redact_argument(argument, &sensitive_values))
        .collect();
    let has_sensitive_argv = !sensitive_values.is_empty();
    let io = ToolRunIo {
        schema_version: tool.io.schema_version,
        inputs: tool
            .io
            .inputs
            .iter()
            .filter(|input| {
                values
                    .get(&input.field)
                    .is_some_and(|value| !value.is_empty())
            })
            .map(|input| ToolInputRecord {
                id: input.id.clone(),
                kind: input.kind,
                source: input_sources.get(&input.field).copied().unwrap_or_else(|| {
                    let uses_default = tool
                        .form
                        .fields
                        .iter()
                        .find(|field| field.id == input.field)
                        .is_some_and(|field| !field.default.is_empty());
                    if uses_default {
                        ToolInputSource::CatalogDefault
                    } else {
                        ToolInputSource::Form
                    }
                }),
                source_id: input.field.clone(),
            })
            .collect(),
        outputs: tool.io.outputs.clone(),
    };

    let spec = CommandSpec {
        command_spec_id: CommandSpecId::new(),
        tool_id: tool.id.clone(),
        tool_version: "catalog".to_owned(),
        tool_sha256: sha256,
        program: binary_str,
        argv_exec: argv.clone(),
        argv_redacted,
        env_exec: environment.clone(),
        env_redacted: environment.clone(),
        secret_transport: if has_sensitive_argv {
            SecretTransport::ArgvException
        } else {
            SecretTransport::None
        },
        secret_inputs: sensitive_values
            .iter()
            .map(|(identifier, _)| SecretInputLifecycle {
                identifier: identifier.clone(),
                transport: SecretTransport::ArgvException,
                destroy_after_open: false,
                lifetime_millis: None,
            })
            .collect(),
        cwd: cwd.display().to_string(),
        environment_allowlist: environment.keys().cloned().collect(),
        timeout_millis: tool.limits.timeout_millis,
        stop_grace_millis: 2_000,
        expected_outputs: vec!["stdout.log".to_owned(), "stderr.log".to_owned()],
        io,
        risk_level: if has_sensitive_argv {
            RiskLevel::L3
        } else {
            risk_level
        },
        scope_id: Some(scope_id.clone()),
        sandbox_profile: "catalog-systemd-or-pgid".to_owned(),
        resource_limits: ResourceLimits {
            memory_max_bytes: tool.limits.memory_max_bytes,
            tasks_max: tool.limits.tasks_max,
            cpu_quota_percent: tool.limits.cpu_quota_percent,
            core_dump_bytes: 0,
        },
        network_isolation: "input-gate-and-audit".to_owned(),
    };

    let detach = tool
        .detach
        .unwrap_or(matches!(tool.mode, ToolMode::ExternalLaunch));

    Ok(PreparedCatalogCommand {
        tool_id: tool.id.clone(),
        tool_name: tool.name.clone(),
        mode: tool.mode.clone(),
        parser_id: tool.parser.id.clone(),
        parser_version: tool.parser.version.clone(),
        detach,
        spec,
        stdout_path: job_directory.join("stdout.log"),
        stderr_path: job_directory.join("stderr.log"),
        target_url,
    })
}

fn validate_form_values(
    tool: &CatalogToolManifest,
    form_values: &BTreeMap<String, String>,
) -> Result<(), CatalogError> {
    if form_values
        .keys()
        .any(|key| !tool.form.fields.iter().any(|field| field.id == *key))
    {
        return Err(CatalogError::InvalidInput);
    }
    for field in &tool.form.fields {
        let value = form_values.get(&field.id).map_or("", String::as_str);
        if value.contains('\0') || value.len() > 16 * 1024 {
            return Err(CatalogError::InvalidInput);
        }
        if field.required
            && value.trim().is_empty()
            && (form_values.contains_key(&field.id) || field.default.is_empty())
        {
            return Err(CatalogError::InvalidInput);
        }
        if value.is_empty() {
            continue;
        }
        match field.field_type.as_str() {
            "select" if !field.options.iter().any(|option| option == value) => {
                return Err(CatalogError::InvalidInput);
            }
            "multiselect" => {
                let selected = parse_multiselect(value)?;
                if selected.is_empty()
                    || selected
                        .iter()
                        .any(|item| !field.options.iter().any(|option| option == item))
                {
                    return Err(CatalogError::InvalidInput);
                }
            }
            "number" => {
                let number = value
                    .parse::<f64>()
                    .map_err(|_| CatalogError::InvalidInput)?;
                if !number.is_finite() || !(0.0..=1_000_000_000.0).contains(&number) {
                    return Err(CatalogError::InvalidInput);
                }
            }
            "url" => {
                let parsed = Url::parse(value).map_err(|_| CatalogError::InvalidInput)?;
                if !valid_http_target(&parsed) {
                    return Err(CatalogError::InvalidInput);
                }
            }
            "host" => validate_single_target(value)?,
            "args" => {
                parse_argv_fragment(value)?;
            }
            "select" | "text" | "textarea" | "wordlist" => {}
            _ => return Err(CatalogError::InvalidInput),
        }
    }
    for relation in &tool.relations {
        if relation.severity == "error" && relation_is_violated(tool, relation, form_values) {
            return Err(CatalogError::InvalidInput);
        }
    }
    Ok(())
}

fn relation_is_violated(
    tool: &CatalogToolManifest,
    relation: &CatalogFormRelation,
    form_values: &BTreeMap<String, String>,
) -> bool {
    let left = effective_form_value(tool, form_values, &relation.field);
    let right = effective_form_value(tool, form_values, &relation.other);
    let left_active = value_matches_relation(left, &relation.equals);
    let right_active = value_matches_relation(right, &relation.other_equals);
    match relation.kind.as_str() {
        "requires" => left_active && !right_active,
        "conflicts" => left_active && right_active,
        _ => false,
    }
}

fn effective_form_value<'a>(
    tool: &'a CatalogToolManifest,
    form_values: &'a BTreeMap<String, String>,
    field_id: &str,
) -> &'a str {
    form_values.get(field_id).map_or_else(
        || {
            tool.form
                .fields
                .iter()
                .find(|field| field.id == field_id)
                .map_or("", |field| field.default.as_str())
        },
        String::as_str,
    )
}

fn value_matches_relation(value: &str, expected: &str) -> bool {
    if !expected.is_empty() {
        return value == expected || value.split(',').map(str::trim).any(|part| part == expected);
    }
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "no" | "none" | "false" | "0" | "unknown"
    )
}

fn parse_multiselect(value: &str) -> Result<Vec<&str>, CatalogError> {
    let mut seen = BTreeSet::new();
    let mut selected = Vec::new();
    for item in value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if item.len() > 256 || !seen.insert(item) {
            return Err(CatalogError::InvalidInput);
        }
        selected.push(item);
    }
    if selected.len() > 64 {
        return Err(CatalogError::InvalidInput);
    }
    Ok(selected)
}

fn validate_single_target(value: &str) -> Result<(), CatalogError> {
    if looks_like_url(value) {
        let parsed = Url::parse(value).map_err(|_| CatalogError::InvalidInput)?;
        if valid_http_target(&parsed) {
            return Ok(());
        }
    }
    if value.starts_with('-')
        || value.contains('/')
        || value.contains('\\')
        || value.chars().any(char::is_whitespace)
    {
        return Err(CatalogError::InvalidInput);
    }
    Ok(())
}

fn valid_http_target(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

fn redact_argument(argument: &str, sensitive_values: &[(String, String)]) -> String {
    sensitive_values
        .iter()
        .fold(argument.to_owned(), |redacted, (_, value)| {
            redacted.replace(value, "[REDACTED]")
        })
}

fn looks_like_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

fn tool_supports_current_platform(tool: &CatalogToolManifest) -> bool {
    tool.platforms.is_empty() || tool.platforms.iter().any(|value| value == env::consts::OS)
}

fn resolve_cwd(
    tool: &CatalogToolManifest,
    paths: &CatalogPaths,
    binary: &Path,
    job_directory: &Path,
    require_existing: bool,
) -> Result<PathBuf, CatalogError> {
    if !tool.cwd.is_empty() {
        let cwd = if Path::new(&tool.cwd).is_absolute() {
            PathBuf::from(&tool.cwd)
        } else {
            paths.tools_root.join(&tool.cwd)
        };
        if cwd.is_dir() || !require_existing {
            return Ok(cwd);
        }
        return Err(CatalogError::InvalidInput);
    }
    match tool.mode {
        ToolMode::ExternalLaunch => {
            if let Some(parent) = binary.parent()
                && parent.is_dir()
            {
                return Ok(parent.to_path_buf());
            }
            Ok(job_directory.to_path_buf())
        }
        ToolMode::EmbeddedCli => Ok(job_directory.to_path_buf()),
    }
}

fn build_environment(
    tool: &CatalogToolManifest,
    job_directory: &Path,
    cwd: &Path,
) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::new();
    let path = enriched_path();
    environment.insert(
        "TMPDIR".to_owned(),
        job_directory.join("tmp").display().to_string(),
    );

    match tool.mode {
        ToolMode::ExternalLaunch => {
            // Forward only the desktop-session values required by GUI applications.
            for key in [
                "DISPLAY",
                "WAYLAND_DISPLAY",
                "XAUTHORITY",
                "XDG_RUNTIME_DIR",
                "XDG_CURRENT_DESKTOP",
                "XDG_SESSION_TYPE",
                "DBUS_SESSION_BUS_ADDRESS",
                "LANG",
                "LC_ALL",
                "LC_CTYPE",
                "GDK_BACKEND",
                "QT_QPA_PLATFORM",
            ] {
                if let Ok(value) = env::var(key)
                    && !value.contains('\0')
                    && value.len() <= 4096
                {
                    environment.insert(key.to_owned(), value);
                }
            }
            environment.insert("PATH".to_owned(), path);
            environment.insert("PWD".to_owned(), cwd.display().to_string());
            if !environment.contains_key("XAUTHORITY")
                && let Some(xauth) = resolve_xauthority()
            {
                environment.insert("XAUTHORITY".to_owned(), xauth);
            }
            if !environment.contains_key("DISPLAY") && Path::new("/tmp/.X11-unix/X0").exists() {
                environment.insert("DISPLAY".to_owned(), ":0".to_owned());
            }
            environment
                .entry("GDK_BACKEND".to_owned())
                .or_insert_with(|| "x11".to_owned());
            environment
                .entry("LANG".to_owned())
                .or_insert_with(|| "zh_CN.UTF-8".to_owned());
        }
        ToolMode::EmbeddedCli => {
            environment.insert("PATH".to_owned(), path);
            environment.insert("LANG".to_owned(), "C.UTF-8".to_owned());
            environment.insert("LC_ALL".to_owned(), "C.UTF-8".to_owned());
            environment.insert(
                "HOME".to_owned(),
                job_directory.join("home").display().to_string(),
            );
            if tool.id == "dddd" {
                environment.insert(
                    "XDG_CONFIG_HOME".to_owned(),
                    job_directory.join("xdg-config").display().to_string(),
                );
            }
        }
    }
    environment
}

fn resolve_xauthority() -> Option<String> {
    if let Ok(value) = env::var("XAUTHORITY")
        && Path::new(&value).is_file()
    {
        return Some(value);
    }
    if let Ok(home) = env::var("HOME") {
        let candidate = PathBuf::from(home).join(".Xauthority");
        if candidate.is_file() {
            return Some(candidate.display().to_string());
        }
    }
    if let Ok(runtime) = env::var("XDG_RUNTIME_DIR") {
        let runtime = PathBuf::from(runtime);
        if let Ok(entries) = fs::read_dir(&runtime) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let text = name.to_string_lossy();
                if text.starts_with("xauth") && entry.path().is_file() {
                    return Some(entry.path().display().to_string());
                }
            }
        }
    }
    None
}

fn enriched_path() -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Ok(path) = env::var("PATH") {
        parts.extend(path.split(':').filter(|p| !p.is_empty()).map(str::to_owned));
    }
    if let Ok(home) = env::var("HOME") {
        parts.push(format!("{home}/.local/bin"));
        parts.push(format!("{home}/.local/share/mise/shims"));
        let go_installs = PathBuf::from(&home).join(".local/share/mise/installs/go");
        if go_installs.is_dir()
            && let Ok(entries) = fs::read_dir(go_installs)
        {
            for entry in entries.flatten() {
                let bin = entry.path().join("bin");
                if bin.is_dir() {
                    parts.push(bin.display().to_string());
                }
            }
        }
        let java_installs = PathBuf::from(&home).join(".local/share/mise/installs/java");
        if java_installs.is_dir()
            && let Ok(entries) = fs::read_dir(java_installs)
        {
            for entry in entries.flatten() {
                let bin = entry.path().join("bin");
                if bin.is_dir() {
                    parts.push(bin.display().to_string());
                }
            }
        }
    }
    for fixed in ["/usr/local/bin", "/usr/bin", "/bin"] {
        parts.push(fixed.to_owned());
    }
    let mut seen = std::collections::BTreeSet::new();
    parts
        .into_iter()
        .filter(|part| seen.insert(part.clone()))
        .collect::<Vec<_>>()
        .join(":")
}

fn expand_argv_part(
    tool: &CatalogToolManifest,
    template: &str,
    values: &BTreeMap<String, String>,
) -> Result<Vec<String>, CatalogError> {
    if let Some(field_id) = template
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        && tool
            .form
            .fields
            .iter()
            .any(|field| field.id == field_id && field.field_type == "args")
    {
        let value = values.get(field_id).ok_or(CatalogError::InvalidInput)?;
        return parse_argv_fragment(value);
    }
    Ok(vec![expand_template(template, values)?])
}

fn parse_argv_fragment(value: &str) -> Result<Vec<String>, CatalogError> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = value.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(character) = chars.next() {
        match (quote, character) {
            (Some(active), value) if value == active => quote = None,
            (_, '\\') => {
                let escaped = chars.next().ok_or(CatalogError::InvalidInput)?;
                current.push(escaped);
            }
            (None, '\'' | '"') => quote = Some(character),
            (None, value) if value.is_whitespace() => {
                if !current.is_empty() {
                    if current.len() > 4096 {
                        return Err(CatalogError::InvalidInput);
                    }
                    args.push(std::mem::take(&mut current));
                }
            }
            (_, value) => current.push(value),
        }
    }
    if quote.is_some() {
        return Err(CatalogError::InvalidInput);
    }
    if !current.is_empty() {
        if current.len() > 4096 {
            return Err(CatalogError::InvalidInput);
        }
        args.push(current);
    }
    if args.len() > 128 || args.iter().any(|arg| arg.contains('\0')) {
        return Err(CatalogError::InvalidInput);
    }
    Ok(args)
}

fn expand_template(
    template: &str,
    values: &BTreeMap<String, String>,
) -> Result<String, CatalogError> {
    let mut result = String::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let (head, tail) = rest.split_at(start);
        result.push_str(head);
        let Some(end) = tail.find('}') else {
            return Err(CatalogError::InvalidInput);
        };
        let key = &tail[1..end];
        let value = values.get(key).ok_or(CatalogError::InvalidInput)?;
        result.push_str(value);
        rest = &tail[end + 1..];
    }
    result.push_str(rest);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn loads_workspace_catalog() {
        let catalog = ToolCatalog::load_default().expect("catalog loads");
        assert!(catalog.tools.iter().any(|tool| tool.id == "curl"));
        assert!(catalog.tools.iter().any(|tool| tool.id == "dddd"));
        assert!(catalog.tools.iter().any(|tool| tool.id == "behinder"));
        assert!(!catalog.wordlists.is_empty());
        let curl = catalog.tool("curl").expect("curl manifest");
        assert_eq!(curl.io.schema_version, 1);
        assert!(curl.io.inputs.iter().any(|input| {
            input.kind == flagdeck_domain::ToolIoKind::Url && input.field == "url"
        }));
        assert!(!curl.io.outputs.is_empty());
        assert_eq!(curl.tier, "tier_1");
        assert!(curl.presets.len() >= 3);
        let payloader = catalog.tool("payloader").expect("payloader manifest");
        assert_eq!(
            payloader.argv.template,
            [
                "--ozone-platform=x11",
                "--disable-gpu",
                "--disable-gpu-compositing",
            ]
        );
    }

    #[test]
    fn legacy_catalog_risk_defaults_follow_execution_mode() {
        let embedded: CatalogToolManifest = toml::from_str(
            r#"
id = "embedded"
name = "embedded"
category = "test"
mode = "embedded_cli"
"#,
        )
        .unwrap();
        let external: CatalogToolManifest = toml::from_str(
            r#"
id = "external"
name = "external"
category = "test"
mode = "external_launch"
"#,
        )
        .unwrap();

        assert_eq!(effective_catalog_risk_level(&embedded), RiskLevel::L2);
        assert_eq!(effective_catalog_risk_level(&external), RiskLevel::L3);
    }

    #[test]
    fn rejects_unknown_tool_io_schema_version() {
        let temporary = tempdir().unwrap();
        let tools_dir = temporary.path().join("tools");
        fs::create_dir_all(&tools_dir).unwrap();
        fs::write(
            tools_dir.join("typed.toml"),
            r#"
id = "typed"
name = "typed"
category = "test"
mode = "embedded_cli"

[io]
schema_version = 2

[binary]
path = "/usr/bin/true"
resolve = ["path"]

[argv]
template = ["--version"]
"#,
        )
        .unwrap();
        let paths = CatalogPaths {
            tools_root: temporary.path().join("tools-root"),
            wordlists_root: temporary.path().join("wordlists"),
            catalog_root: temporary.path().to_path_buf(),
            user_catalog_root: temporary.path().join("user-catalog"),
            cache_root: temporary.path().join("cache"),
        };

        assert!(matches!(
            ToolCatalog::load(paths),
            Err(CatalogError::Invalid(message)) if message.contains("unsupported I/O schema version")
        ));
    }

    #[test]
    fn expands_argv_template() {
        let mut values = BTreeMap::new();
        values.insert("url".to_owned(), "http://127.0.0.1/".to_owned());
        let expanded = expand_template("-u {url}", &values).unwrap();
        assert_eq!(expanded, "-u http://127.0.0.1/");
    }

    #[test]
    fn argv_does_not_duplicate_program() {
        if !Path::new("/usr/bin/curl").is_file() {
            return;
        }
        let catalog = ToolCatalog::load_default().unwrap();
        let job = tempdir().unwrap();
        let scope = ScopeId::new();
        let mut form = BTreeMap::new();
        form.insert("url".to_owned(), "http://127.0.0.1:9/".to_owned());
        form.insert("method".to_owned(), "GET".to_owned());
        let prepared =
            prepare_catalog_command(&catalog, "curl", &scope, &form, job.path()).unwrap();
        assert_eq!(prepared.spec.program, "/usr/bin/curl");
        assert_ne!(
            prepared.spec.argv_exec.first().map(String::as_str),
            Some("/usr/bin/curl")
        );
        assert!(prepared.spec.argv_exec.iter().any(|part| part == "-X"));
    }

    #[test]
    fn sensitive_catalog_values_are_redacted_and_declared() {
        if !Path::new("/usr/bin/curl").is_file() {
            return;
        }
        let catalog = ToolCatalog::load_default().unwrap();
        let job = tempdir().unwrap();
        let mut form = BTreeMap::new();
        form.insert("url".to_owned(), "http://127.0.0.1:9/".to_owned());
        form.insert("method".to_owned(), "GET".to_owned());
        form.insert("cookie".to_owned(), "session=top-secret".to_owned());
        let prepared =
            prepare_catalog_command(&catalog, "curl", &ScopeId::new(), &form, job.path()).unwrap();
        assert!(
            prepared
                .spec
                .argv_exec
                .iter()
                .any(|value| value == "session=top-secret")
        );
        assert!(
            prepared
                .spec
                .argv_redacted
                .iter()
                .all(|value| !value.contains("top-secret"))
        );
        assert_eq!(
            prepared.spec.secret_transport,
            SecretTransport::ArgvException
        );
        assert_eq!(prepared.spec.risk_level, RiskLevel::L3);
    }

    #[test]
    fn form_validation_rejects_unknown_enum_and_multi_target_values() {
        let catalog = ToolCatalog::load_default().unwrap();
        let curl = catalog.tool("curl").unwrap();
        let mut form = BTreeMap::new();
        form.insert("url".to_owned(), "http://127.0.0.1/".to_owned());
        form.insert("method".to_owned(), "TRACE".to_owned());
        assert!(matches!(
            validate_form_values(curl, &form),
            Err(CatalogError::InvalidInput)
        ));
        form.insert("method".to_owned(), "GET".to_owned());
        form.insert("unknown".to_owned(), "value".to_owned());
        assert!(matches!(
            validate_form_values(curl, &form),
            Err(CatalogError::InvalidInput)
        ));
        form.remove("unknown");
        form.insert("method".to_owned(), String::new());
        assert!(matches!(
            validate_form_values(curl, &form),
            Err(CatalogError::InvalidInput)
        ));
        assert!(matches!(
            validate_single_target("192.0.2.0/24"),
            Err(CatalogError::InvalidInput)
        ));
        assert!(matches!(
            validate_single_target("/tmp/targets.txt"),
            Err(CatalogError::InvalidInput)
        ));
    }

    #[test]
    fn external_environment_uses_a_fixed_desktop_allowlist() {
        let catalog = ToolCatalog::load_default().unwrap();
        let tool = catalog.tool("behinder").unwrap();
        let job = tempdir().unwrap();
        let environment = build_environment(tool, job.path(), job.path());
        assert!(!environment.contains_key("HOME"));
        assert!(!environment.contains_key("SSH_AUTH_SOCK"));
        assert!(!environment.contains_key("GITHUB_TOKEN"));
        assert!(environment.contains_key("PATH"));
    }

    #[test]
    fn resolves_ffuf_from_mise_when_present() {
        let catalog = ToolCatalog::load_default().unwrap();
        let tool = catalog.tool("ffuf").expect("ffuf manifest");
        let resolved = resolve_binary(tool, &catalog.paths);
        if find_on_path("ffuf").is_some() {
            assert!(resolved.is_ok(), "{resolved:?}");
        }
    }

    #[test]
    fn gui_tools_have_no_required_url() {
        let catalog = ToolCatalog::load_default().unwrap();
        for id in [
            "antsword",
            "behinder",
            "cyberchef",
            "godzilla",
            "godzilla-super",
            "godzilla-super-mcp",
            "payloader",
            "shiro",
            "uploadranger",
        ] {
            let tool = catalog.tool(id).unwrap_or_else(|| panic!("missing {id}"));
            assert!(!tool_needs_target(tool), "{id} should not require target");
        }
    }

    #[test]
    fn resolve_wordlist_shortcut() {
        let root = tempdir().unwrap();
        let catalog_root = root.path().join("catalog");
        let tools_dir = catalog_root.join("tools");
        fs::create_dir_all(&tools_dir).unwrap();
        let wordlists = root.path().join("wordlists");
        fs::create_dir_all(&wordlists).unwrap();
        let list = wordlists.join("demo.txt");
        File::create(&list).unwrap().write_all(b"admin\n").unwrap();
        fs::write(
            catalog_root.join("wordlists.toml"),
            r#"
schema_version = 1
[[wordlist]]
id = "demo"
name = "Demo"
path = "demo.txt"
"#,
        )
        .unwrap();
        fs::write(
            tools_dir.join("echo.toml"),
            r#"
id = "echo"
name = "echo"
category = "http"
summary = "demo"
mode = "embedded_cli"
[binary]
command = "echo"
path = "/usr/bin/echo"
resolve = ["path", "system"]
[[form.fields]]
id = "url"
type = "url"
label = "URL"
required = true
[argv]
template = ["{url}"]
"#,
        )
        .unwrap();
        let catalog = ToolCatalog::load(CatalogPaths {
            tools_root: root.path().to_path_buf(),
            wordlists_root: wordlists,
            catalog_root,
            user_catalog_root: root.path().join("user-catalog"),
            cache_root: root.path().join("cache"),
        })
        .unwrap();
        let path = catalog.resolve_wordlist_path("demo").unwrap();
        assert!(path.ends_with("demo.txt"));
    }

    #[test]
    fn user_catalog_overlay_replaces_only_declared_values() {
        let root = tempdir().unwrap();
        let base = root.path().join("base");
        let user = root.path().join("user");
        fs::create_dir_all(base.join("tools")).unwrap();
        fs::create_dir_all(user.join("tools")).unwrap();
        fs::write(
            base.join("tools/demo.toml"),
            r#"
id = "demo"
name = "Demo"
category = "test"
summary = "base"
[binary]
path = "/usr/bin/echo"
resolve = ["path"]
[argv]
template = ["ok"]
"#,
        )
        .unwrap();
        fs::write(
            user.join("tools/demo.toml"),
            r#"
id = "demo"
summary = "personal"
aliases = ["我的演示"]
"#,
        )
        .unwrap();
        let catalog = ToolCatalog::load(CatalogPaths {
            tools_root: root.path().join("tools"),
            wordlists_root: root.path().join("wordlists"),
            catalog_root: base,
            user_catalog_root: user,
            cache_root: root.path().join("cache"),
        })
        .unwrap();
        let tool = catalog.tool("demo").unwrap();
        assert_eq!(tool.name, "Demo");
        assert_eq!(tool.summary, "personal");
        assert_eq!(tool.aliases, ["我的演示"]);
        assert_eq!(tool.binary.path, "/usr/bin/echo");
    }

    #[test]
    fn validates_multiselect_relations_and_additional_args() {
        let tool: CatalogToolManifest = toml::from_str(
            r#"
id = "guided"
name = "Guided"
category = "test"

[[form.fields]]
id = "mode"
type = "select"
label = "Mode"
default = "safe"
options = ["safe", "random"]

[[form.fields]]
id = "agent"
type = "text"
label = "Agent"

[[form.fields]]
id = "tamper"
type = "multiselect"
label = "Tamper"
options = ["between", "space2comment"]

[[form.fields]]
id = "extra"
type = "args"
label = "Extra"

[[relations]]
kind = "conflicts"
field = "mode"
equals = "random"
other = "agent"
severity = "error"
message = "Choose one agent source"

[binary]
path = "/usr/bin/echo"
resolve = ["path"]

[argv]
template = ["{tamper}", "{extra}"]
"#,
        )
        .unwrap();
        let mut values = BTreeMap::from([
            ("mode".to_owned(), "safe".to_owned()),
            ("tamper".to_owned(), "between,space2comment".to_owned()),
            (
                "extra".to_owned(),
                "--answer 'two words' --batch".to_owned(),
            ),
        ]);
        validate_form_values(&tool, &values).unwrap();
        assert_eq!(
            parse_argv_fragment(values.get("extra").unwrap()).unwrap(),
            ["--answer", "two words", "--batch"]
        );
        values.insert("mode".to_owned(), "random".to_owned());
        values.insert("agent".to_owned(), "FlagDeck".to_owned());
        assert!(matches!(
            validate_form_values(&tool, &values),
            Err(CatalogError::InvalidInput)
        ));
        values.insert("tamper".to_owned(), "unknown".to_owned());
        assert!(matches!(
            validate_form_values(&tool, &values),
            Err(CatalogError::InvalidInput)
        ));

        let mut invalid_help = tool.clone();
        invalid_help.help.args = vec!["--help".to_owned()];
        assert!(matches!(
            validate_tool_manifest(Path::new("guided.toml"), &invalid_help),
            Err(CatalogError::Invalid(_))
        ));
    }
}

#[cfg(test)]
mod prepare_all_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn prepares_all_catalog_tools_when_binaries_exist() {
        let catalog = ToolCatalog::load_default().unwrap();
        let job = tempdir().unwrap();
        let scope = ScopeId::new();
        for tool in &catalog.tools {
            if resolve_binary(tool, &catalog.paths).is_err() {
                println!("skip missing binary {}", tool.id);
                continue;
            }
            let mut form = BTreeMap::new();
            for field in &tool.form.fields {
                if !field.default.is_empty() {
                    form.insert(field.id.clone(), field.default.clone());
                }
                match field.field_type.as_str() {
                    "url" => {
                        form.insert(field.id.clone(), "http://127.0.0.1:9/".to_owned());
                    }
                    "host" => {
                        form.insert(field.id.clone(), "127.0.0.1".to_owned());
                    }
                    "wordlist" => {
                        form.insert(field.id.clone(), "seclists-common".to_owned());
                    }
                    "number" => {
                        form.entry(field.id.clone())
                            .or_insert_with(|| "1".to_owned());
                    }
                    "text" | "textarea" | "select" if field.required => {
                        form.entry(field.id.clone()).or_insert_with(|| {
                            if field.id.contains("key") {
                                "deadbeef".to_owned()
                            } else if field.id.contains("pcap") || field.id.contains("file") {
                                "/tmp/flagdeck-test.pcap".to_owned()
                            } else if field.id.contains("path") || field.id.contains("url") {
                                "/shell.php".to_owned()
                            } else {
                                "test".to_owned()
                            }
                        });
                    }
                    _ => {}
                }
                if field.from == "target_url" && !form.contains_key(&field.id) {
                    form.insert(field.id.clone(), "http://127.0.0.1:9/".to_owned());
                }
            }
            match prepare_catalog_command(&catalog, &tool.id, &scope, &form, job.path()) {
                Ok(prepared) => {
                    assert!(
                        prepared.spec.argv_exec.first() != Some(&prepared.spec.program),
                        "{} argv duplicates program",
                        tool.id
                    );
                    println!(
                        "prepared {} -> {} + {:?}",
                        tool.id, prepared.spec.program, prepared.spec.argv_exec
                    );
                }
                Err(error) => {
                    // Missing wordlists, cwd, or optional local layout should not fail CI.
                    println!("skip prepare {} due to {error}", tool.id);
                }
            }
        }
    }
}
