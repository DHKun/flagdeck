//! Declarative tool catalog: load TOML manifests and prepare managed commands.

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use flagdeck_domain::{
    CommandSpec, CommandSpecId, ResourceLimits, RiskLevel, ScopeId, SecretTransport,
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
    /// Short helper under the field.
    #[serde(default)]
    pub hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FormSpec {
    #[serde(default)]
    pub fields: Vec<FormField>,
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
    #[serde(default)]
    pub summary: String,
    /// Hover help: practical usage for this tool (CLI flags / GUI notes).
    #[serde(default)]
    pub usage: String,
    #[serde(default)]
    pub mode: ToolMode,
    #[serde(default)]
    pub featured: bool,
    /// Working directory (absolute, or relative to tools root). Empty = job dir (CLI) or binary parent (GUI).
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub binary: BinarySpec,
    #[serde(default)]
    pub form: FormSpec,
    #[serde(default)]
    pub argv: ArgvSpec,
    #[serde(default)]
    pub parser: ParserSpec,
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
        Self {
            tools_root,
            wordlists_root,
            catalog_root,
        }
    }
}

fn default_catalog_root() -> PathBuf {
    let candidates = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/tool-catalog"),
        PathBuf::from("config/tool-catalog"),
        PathBuf::from("/usr/lib/flagdeck/config/tool-catalog"),
    ];
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
        let tools = load_tools(&paths.catalog_root)?;
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
                let resolved = resolve_binary(tool, &self.paths);
                let (available, binary_path, detail) = match resolved {
                    Ok(path) if tool.cwd.is_empty() => {
                        (true, path.display().to_string(), "ready".to_owned())
                    }
                    Ok(path) => {
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
                    Err(error) => (false, String::new(), error.to_string()),
                };
                CatalogToolView {
                    id: tool.id.clone(),
                    name: tool.name.clone(),
                    category: tool.category.clone(),
                    category_name,
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

fn load_tools(root: &Path) -> Result<Vec<CatalogToolManifest>, CatalogError> {
    let tools_dir = root.join("tools");
    if !tools_dir.is_dir() {
        return Err(CatalogError::Invalid(format!(
            "missing tools directory at {}",
            tools_dir.display()
        )));
    }
    let mut tools = Vec::new();
    for entry in fs::read_dir(tools_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }
        let text = fs::read_to_string(&path)?;
        let tool: CatalogToolManifest = toml::from_str(&text)
            .map_err(|error| CatalogError::Invalid(format!("{}: {error}", path.display())))?;
        if tool.id.is_empty() || tool.name.is_empty() {
            return Err(CatalogError::Invalid(format!(
                "{} missing required fields",
                path.display()
            )));
        }
        // external_launch may have empty argv (binary is the full entrypoint)
        if tool.mode == ToolMode::EmbeddedCli && tool.argv.template.is_empty() {
            return Err(CatalogError::Invalid(format!(
                "{} embedded_cli requires argv.template",
                path.display()
            )));
        }
        tools.push(tool);
    }
    tools.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(tools)
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
    let tool = catalog.tool(tool_id).ok_or(CatalogError::NotFound)?;
    if !job_directory.is_absolute() {
        return Err(CatalogError::InvalidInput);
    }
    fs::create_dir_all(job_directory)?;
    fs::create_dir_all(job_directory.join("tmp"))?;
    fs::create_dir_all(job_directory.join("home"))?;

    let binary = resolve_binary(tool, &catalog.paths)?;
    let sha256 = file_sha256(&binary)?;
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
        let path = catalog.resolve_wordlist_path(&raw)?;
        values.insert(field.id.clone(), path.display().to_string());
        values.insert("wordlist".to_owned(), path.display().to_string());
    }

    // Validate required fields
    for field in &tool.form.fields {
        if !field.required {
            continue;
        }
        let value = values.get(&field.id).map_or("", String::as_str);
        if value.is_empty() {
            return Err(CatalogError::InvalidInput);
        }
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
    let mut argv = tool
        .argv
        .template
        .iter()
        .map(|part| expand_template(part, &values))
        .collect::<Result<Vec<_>, _>>()?;
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
            argv.push(expand_template(part, &values)?);
        }
    }
    for part in &tool.argv.suffix {
        argv.push(expand_template(part, &values)?);
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

    let cwd = resolve_cwd(tool, &catalog.paths, &binary, job_directory)?;
    let environment = build_environment(tool, job_directory, &cwd);

    let risk_level = match tool.mode {
        ToolMode::ExternalLaunch => RiskLevel::L3,
        ToolMode::EmbeddedCli => RiskLevel::L2,
    };

    let spec = CommandSpec {
        command_spec_id: CommandSpecId::new(),
        tool_id: tool.id.clone(),
        tool_version: "catalog".to_owned(),
        tool_sha256: sha256,
        program: binary_str,
        argv_exec: argv.clone(),
        argv_redacted: argv,
        env_exec: environment.clone(),
        env_redacted: environment.clone(),
        secret_transport: SecretTransport::None,
        secret_inputs: Vec::new(),
        cwd: cwd.display().to_string(),
        environment_allowlist: environment.keys().cloned().collect(),
        timeout_millis: tool.limits.timeout_millis,
        stop_grace_millis: 2_000,
        expected_outputs: vec!["stdout.log".to_owned(), "stderr.log".to_owned()],
        risk_level,
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

    Ok(PreparedCatalogCommand {
        tool_id: tool.id.clone(),
        tool_name: tool.name.clone(),
        mode: tool.mode.clone(),
        spec,
        stdout_path: job_directory.join("stdout.log"),
        stderr_path: job_directory.join("stderr.log"),
        target_url,
    })
}

fn looks_like_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

fn resolve_cwd(
    tool: &CatalogToolManifest,
    paths: &CatalogPaths,
    binary: &Path,
    job_directory: &Path,
) -> Result<PathBuf, CatalogError> {
    if !tool.cwd.is_empty() {
        let cwd = if Path::new(&tool.cwd).is_absolute() {
            PathBuf::from(&tool.cwd)
        } else {
            paths.tools_root.join(&tool.cwd)
        };
        if cwd.is_dir() {
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
            // Desktop GUIs need the real session environment (GTK, X11, dbus, locale…).
            // Start from the parent process env, then ensure critical display vars exist.
            for (key, value) in env::vars() {
                // Skip oversized / noisy vars that can break argv/env validation.
                if key.starts_with("BASH_FUNC_") || value.contains('\0') {
                    continue;
                }
                environment.insert(key, value);
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
        for id in ["antsword", "behinder", "godzilla", "shiro"] {
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
        })
        .unwrap();
        let path = catalog.resolve_wordlist_path("demo").unwrap();
        assert!(path.ends_with("demo.txt"));
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
                    "text" | "textarea" | "select" => {}
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
