#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::{self, Display};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use flagdeck_domain::{
    CommandSpec, CommandSpecId, Discovery, DiscoveryId, DiscoveryKind, OrderedValue, ProjectId,
    ResourceLimits, RiskLevel, ScopeId, SecretTransport, Sensitivity, Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

pub const REGISTRY_SOURCE: &str = include_str!("../../../config/tools.toml");
pub const MAX_WORDLIST_TERMS: usize = 256;
pub const MAX_WORDLIST_TERM_BYTES: usize = 128;
pub const MAX_STRUCTURED_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_HEADER_OUTPUT_BYTES: u64 = 256 * 1024;
pub const MAX_INLINE_RESPONSE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("tool registry is invalid")]
    Registry(#[from] toml::de::Error),
    #[error("unknown Alpha tool")]
    UnknownTool,
    #[error("tool input is outside the Alpha allowlist")]
    InvalidInput,
    #[error("tool output is missing")]
    MissingOutput,
    #[error("tool output exceeds the parser limit")]
    OutputTooLarge,
    #[error("tool output does not match parser schema")]
    ParserSchema,
    #[error("tool output I/O failed")]
    Io(#[from] std::io::Error),
    #[error("tool output JSON failed")]
    Json(#[from] serde_json::Error),
    #[error("tool output URL is invalid")]
    Url(#[from] url::ParseError),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ToolRegistry {
    pub schema_version: u32,
    pub pack: ToolPackManifest,
    pub policy: RegistryPolicy,
    #[serde(rename = "tool")]
    pub tools: Vec<ToolManifest>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ToolPackManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub platform: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RegistryPolicy {
    pub absolute_paths: bool,
    pub verify_owner: bool,
    pub reject_group_or_world_writable: bool,
    pub verify_sha256_before_each_run: bool,
    pub inherit_environment: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ToolManifest {
    pub id: String,
    pub name: String,
    pub pack_id: String,
    pub category: String,
    pub summary: String,
    pub integration_mode: String,
    pub distribution: String,
    pub license: String,
    pub homepage: String,
    pub command: String,
    pub bundled_path: String,
    pub system_paths: Vec<String>,
    pub pinned_sha256: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub resolution_source: String,
    pub risk_level: String,
    pub health_strategy: String,
    pub health_argv: Vec<String>,
    pub health_version_marker: String,
    pub parser_id: String,
    pub parser_version: String,
    pub fixture_manifest: String,
    pub side_effect_free_help: bool,
    pub adapter_type: String,
    pub capabilities: Vec<String>,
    pub permissions: Vec<String>,
    pub network_policy: String,
    pub memory_max_bytes: u64,
    pub tasks_max: u32,
    pub cpu_quota_percent: u16,
    pub timeout_millis: u64,
    pub runtime_fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolId {
    Curl,
    Dddd,
    Ffuf,
    Arjun,
    Fscan,
    Gobuster,
    Wafw00f,
}

impl ToolId {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Curl => "curl",
            Self::Dddd => "dddd",
            Self::Ffuf => "ffuf",
            Self::Arjun => "arjun",
            Self::Fscan => "fscan",
            Self::Gobuster => "gobuster",
            Self::Wafw00f => "wafw00f",
        }
    }
}

impl Display for ToolId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ToolId {
    type Err = AdapterError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "curl" => Ok(Self::Curl),
            "dddd" => Ok(Self::Dddd),
            "ffuf" => Ok(Self::Ffuf),
            "arjun" => Ok(Self::Arjun),
            "fscan" => Ok(Self::Fscan),
            "gobuster" => Ok(Self::Gobuster),
            "wafw00f" => Ok(Self::Wafw00f),
            _ => Err(AdapterError::UnknownTool),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputRole {
    CurlHeaders,
    CurlBody,
    DdddJsonLines,
    FfufJson,
    ArjunJson,
    FscanJson,
    GobusterText,
    Wafw00fJson,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedOutput {
    pub role: OutputRole,
    pub path: PathBuf,
    pub logical_name: String,
    pub mime: String,
    pub sensitivity: Sensitivity,
}

#[derive(Debug, Clone)]
pub struct PreparedToolCommand {
    pub manifest: ToolManifest,
    pub spec: CommandSpec,
    pub outputs: Vec<ExpectedOutput>,
    pub input_wordlist: Option<PathBuf>,
    pub target: Url,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDiscovery {
    pub kind: DiscoveryKind,
    pub target: String,
    pub raw_value: String,
    pub canonical_value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedHttpResponse {
    pub url: Url,
    pub status_code: u16,
    pub http_version: String,
    pub headers: Vec<OrderedValue>,
    pub inline_body: Option<Vec<u8>>,
    pub actual_length: u64,
    pub declared_length: Option<u64>,
    pub remote_ip: Option<String>,
    pub remote_port: u16,
    pub duration_millis: Option<u64>,
    pub content_encoding: Option<String>,
    pub body_role: OutputRole,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedToolOutput {
    pub discoveries: Vec<ParsedDiscovery>,
    pub http_response: Option<ParsedHttpResponse>,
}

pub fn registry() -> Result<ToolRegistry, AdapterError> {
    let mut registry: ToolRegistry = toml::from_str(REGISTRY_SOURCE)?;
    if registry.schema_version != 2
        || registry.pack.id.is_empty()
        || registry.pack.name.is_empty()
        || registry.pack.version.is_empty()
        || registry.pack.platform != "linux-x86_64"
        || !registry.policy.absolute_paths
        || !registry.policy.verify_owner
        || !registry.policy.reject_group_or_world_writable
        || !registry.policy.verify_sha256_before_each_run
        || registry.policy.inherit_environment
        || registry.tools.len() != 7
    {
        return Err(AdapterError::InvalidInput);
    }
    let ids = registry
        .tools
        .iter()
        .map(|tool| tool.id.as_str())
        .collect::<BTreeSet<_>>();
    if ids
        != BTreeSet::from([
            "arjun", "curl", "dddd", "ffuf", "fscan", "gobuster", "wafw00f",
        ])
        || registry.tools.iter().any(|tool| {
            tool.pack_id != registry.pack.id
                || tool.category.is_empty()
                || tool.summary.is_empty()
                || tool.integration_mode != "project_cli"
                || !matches!(tool.distribution.as_str(), "bundled" | "hybrid" | "system")
                || tool.license.is_empty()
                || !tool.homepage.starts_with("https://")
                || tool.command.is_empty()
                || tool.command.contains('/')
                || Path::new(&tool.bundled_path).is_absolute()
                || tool.bundled_path.contains("..")
                || tool.system_paths.iter().any(|path| !path.starts_with('/'))
                || tool.pinned_sha256.len() != 64
                || !tool
                    .pinned_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || tool.parser_id.is_empty()
                || tool.parser_version.is_empty()
                || tool.adapter_type != "declarative-cli"
                || tool.capabilities.is_empty()
                || tool.permissions.is_empty()
                || tool.network_policy != "input-gate-and-audit"
                || tool.memory_max_bytes == 0
                || tool.tasks_max == 0
                || tool.cpu_quota_percent == 0
                || tool.timeout_millis == 0
                || tool.runtime_fingerprint.is_empty()
        })
    {
        return Err(AdapterError::InvalidInput);
    }
    for tool in &mut registry.tools {
        if let Some(resolved) = resolve_tool(tool) {
            tool.path = resolved.path.display().to_string();
            tool.sha256 = resolved.sha256;
            tool.resolution_source = resolved.source;
        } else {
            tool.sha256.clone_from(&tool.pinned_sha256);
            "missing".clone_into(&mut tool.resolution_source);
        }
    }
    Ok(registry)
}

#[derive(Debug)]
struct ResolvedTool {
    path: PathBuf,
    sha256: String,
    source: String,
}

#[derive(Debug, Deserialize)]
struct ToolOverrideRegistry {
    schema_version: u32,
    #[serde(default)]
    tool: BTreeMap<String, ToolOverride>,
}

#[derive(Debug, Deserialize)]
struct ToolOverride {
    path: String,
    sha256: String,
}

fn resolve_tool(tool: &ToolManifest) -> Option<ResolvedTool> {
    if let Some(tool_override) = tool_overrides().get(&tool.id)
        && let Some(resolved) = resolve_candidate(
            Path::new(&tool_override.path),
            Some(&tool_override.sha256),
            "user_override",
        )
    {
        return Some(resolved);
    }
    for root in tool_pack_roots() {
        let candidate = root.join(&tool.bundled_path);
        if let Some(resolved) =
            resolve_candidate(&candidate, Some(&tool.pinned_sha256), "tool_pack")
        {
            return Some(resolved);
        }
    }
    let expected_system_hash = tool
        .health_argv
        .is_empty()
        .then_some(tool.pinned_sha256.as_str());
    for path in &tool.system_paths {
        if let Some(resolved) = resolve_candidate(Path::new(path), expected_system_hash, "system") {
            return Some(resolved);
        }
    }
    for directory in env::var_os("PATH")
        .map(|value| env::split_paths(&value).collect::<Vec<_>>())
        .unwrap_or_default()
    {
        if !directory.is_absolute() {
            continue;
        }
        if let Some(resolved) = resolve_candidate(
            &directory.join(&tool.command),
            expected_system_hash,
            "path_discovery",
        ) {
            return Some(resolved);
        }
    }
    None
}

fn resolve_candidate(path: &Path, expected: Option<&str>, source: &str) -> Option<ResolvedTool> {
    if !path.is_absolute() {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    let metadata = fs::metadata(&canonical).ok()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o022 != 0 {
        return None;
    }
    let sha256 = sha256_path(&canonical).ok()?;
    if expected.is_some_and(|value| value != sha256) {
        return None;
    }
    Some(ResolvedTool {
        path: canonical,
        sha256,
        source: source.to_owned(),
    })
}

fn tool_overrides() -> BTreeMap<String, ToolOverride> {
    let path = env::var_os("FLAGDECK_TOOL_PATHS_FILE")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .map(|root| root.join("flagdeck/tool-paths.toml"))
        })
        .or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .map(|root| root.join(".config/flagdeck/tool-paths.toml"))
        });
    let Some(path) = path else {
        return BTreeMap::new();
    };
    let Ok(source) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    toml::from_str::<ToolOverrideRegistry>(&source)
        .ok()
        .filter(|registry| registry.schema_version == 1)
        .map(|registry| registry.tool)
        .unwrap_or_default()
}

fn tool_pack_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(root) = env::var_os("FLAGDECK_TOOL_PACK_ROOT") {
        roots.push(PathBuf::from(root));
    }
    if let Some(root) = env::var_os("XDG_DATA_HOME") {
        roots.push(PathBuf::from(root).join("flagdeck/tool-packs"));
    } else if let Some(home) = env::var_os("HOME") {
        roots.push(PathBuf::from(home).join(".local/share/flagdeck/tool-packs"));
    }
    roots.extend([
        PathBuf::from("/usr/lib/flagdeck/tool-packs"),
        PathBuf::from("/usr/lib/FlagDeck/tool-packs"),
    ]);
    roots
}

fn sha256_path(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn manifest(tool_id: ToolId) -> Result<ToolManifest, AdapterError> {
    registry()?
        .tools
        .into_iter()
        .find(|item| item.id == tool_id.as_str())
        .ok_or(AdapterError::UnknownTool)
}

pub fn write_wordlist(tool_id: ToolId, terms: &[String], path: &Path) -> Result<(), AdapterError> {
    if !matches!(tool_id, ToolId::Ffuf | ToolId::Arjun | ToolId::Gobuster)
        || terms.is_empty()
        || terms.len() > MAX_WORDLIST_TERMS
        || terms.iter().any(|term| !valid_term(tool_id, term))
    {
        return Err(AdapterError::InvalidInput);
    }
    let mut options = fs::OpenOptions::new();
    let mut file = options
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    for term in terms {
        file.write_all(term.as_bytes())?;
        file.write_all(b"\n")?;
    }
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn valid_term(tool_id: ToolId, term: &str) -> bool {
    if term.is_empty() || term.len() > MAX_WORDLIST_TERM_BYTES || term.contains(['\0', '\n', '\r'])
    {
        return false;
    }
    match tool_id {
        ToolId::Ffuf | ToolId::Gobuster => {
            !term.starts_with('/')
                && !term.contains("..")
                && !term.contains("FUZZ")
                && term.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/')
                })
        }
        ToolId::Arjun => {
            term.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && term.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'[' | b']')
                })
        }
        ToolId::Curl | ToolId::Dddd | ToolId::Fscan | ToolId::Wafw00f => false,
    }
}

pub fn prepare_command(
    tool_id: ToolId,
    scope_id: &ScopeId,
    target: &Url,
    job_directory: &Path,
    wordlist: Option<&Path>,
) -> Result<PreparedToolCommand, AdapterError> {
    validate_target_url(target)?;
    if !job_directory.is_absolute() {
        return Err(AdapterError::InvalidInput);
    }
    let manifest = manifest(tool_id)?;
    let outputs = output_contract(tool_id, job_directory);
    let argv = match tool_id {
        ToolId::Curl => curl_argv(target, &outputs),
        ToolId::Dddd => dddd_argv(target, &outputs)?,
        ToolId::Ffuf => ffuf_argv(target, &outputs, required_wordlist(wordlist)?),
        ToolId::Arjun => arjun_argv(target, &outputs, required_wordlist(wordlist)?),
        ToolId::Fscan => fscan_argv(target, &outputs)?,
        ToolId::Gobuster => gobuster_argv(target, &outputs, required_wordlist(wordlist)?),
        ToolId::Wafw00f => wafw00f_argv(target, &outputs),
    };
    if matches!(
        tool_id,
        ToolId::Curl | ToolId::Dddd | ToolId::Fscan | ToolId::Wafw00f
    ) && wordlist.is_some()
    {
        return Err(AdapterError::InvalidInput);
    }
    let mut environment = BTreeMap::from([
        (
            "HOME".to_owned(),
            job_directory.join("home").display().to_string(),
        ),
        ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ("LC_ALL".to_owned(), "C.UTF-8".to_owned()),
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        (
            "TMPDIR".to_owned(),
            job_directory.join("tmp").display().to_string(),
        ),
    ]);
    if tool_id == ToolId::Dddd {
        environment.insert(
            "XDG_CONFIG_HOME".to_owned(),
            job_directory.join("xdg-config").display().to_string(),
        );
    }
    let risk_level = match manifest.risk_level.as_str() {
        "l1" => RiskLevel::L1,
        "l2" => RiskLevel::L2,
        _ => return Err(AdapterError::InvalidInput),
    };
    let timeout_millis = manifest.timeout_millis;
    let spec = CommandSpec {
        command_spec_id: CommandSpecId::new(),
        tool_id: manifest.id.clone(),
        tool_version: manifest.version.clone(),
        tool_sha256: manifest.sha256.clone(),
        program: manifest.path.clone(),
        argv_exec: argv.clone(),
        argv_redacted: argv,
        env_exec: environment.clone(),
        env_redacted: environment.clone(),
        secret_transport: SecretTransport::None,
        secret_inputs: Vec::new(),
        cwd: job_directory.display().to_string(),
        environment_allowlist: environment.keys().cloned().collect(),
        timeout_millis,
        stop_grace_millis: 2_000,
        expected_outputs: outputs
            .iter()
            .map(|output| output.logical_name.clone())
            .collect(),
        risk_level,
        scope_id: Some(scope_id.clone()),
        sandbox_profile: "stable-systemd-or-pgid".to_owned(),
        resource_limits: ResourceLimits {
            memory_max_bytes: manifest.memory_max_bytes,
            tasks_max: manifest.tasks_max,
            cpu_quota_percent: manifest.cpu_quota_percent,
            core_dump_bytes: 0,
        },
        network_isolation: manifest.network_policy.clone(),
    };
    Ok(PreparedToolCommand {
        manifest,
        spec,
        outputs,
        input_wordlist: wordlist.map(Path::to_path_buf),
        target: target.clone(),
        stdout_path: job_directory.join("stdout.log"),
        stderr_path: job_directory.join("stderr.log"),
    })
}

fn required_wordlist(wordlist: Option<&Path>) -> Result<&Path, AdapterError> {
    let path = wordlist.ok_or(AdapterError::InvalidInput)?;
    if !path.is_absolute() || !path.is_file() {
        return Err(AdapterError::InvalidInput);
    }
    Ok(path)
}

fn validate_target_url(target: &Url) -> Result<(), AdapterError> {
    if !matches!(target.scheme(), "http" | "https")
        || target.host_str().is_none()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.fragment().is_some()
    {
        return Err(AdapterError::InvalidInput);
    }
    Ok(())
}

fn output_contract(tool_id: ToolId, directory: &Path) -> Vec<ExpectedOutput> {
    let output = |role, name: &str, mime: &str, sensitivity| ExpectedOutput {
        role,
        path: directory.join(name),
        logical_name: name.to_owned(),
        mime: mime.to_owned(),
        sensitivity,
    };
    match tool_id {
        ToolId::Curl => vec![
            output(
                OutputRole::CurlHeaders,
                "curl-headers.txt",
                "application/http; msgtype=response",
                Sensitivity::SensitiveEvidence,
            ),
            output(
                OutputRole::CurlBody,
                "curl-body.bin",
                "application/octet-stream",
                Sensitivity::SensitiveEvidence,
            ),
        ],
        ToolId::Dddd => vec![output(
            OutputRole::DdddJsonLines,
            "dddd-output.jsonl",
            "application/x-ndjson",
            Sensitivity::SensitiveEvidence,
        )],
        ToolId::Ffuf => vec![output(
            OutputRole::FfufJson,
            "ffuf-output.json",
            "application/json",
            Sensitivity::Normal,
        )],
        ToolId::Arjun => vec![output(
            OutputRole::ArjunJson,
            "arjun-output.json",
            "application/json",
            Sensitivity::SensitiveEvidence,
        )],
        ToolId::Fscan => vec![output(
            OutputRole::FscanJson,
            "fscan-output.json",
            "application/json",
            Sensitivity::SensitiveEvidence,
        )],
        ToolId::Gobuster => vec![output(
            OutputRole::GobusterText,
            "gobuster-output.txt",
            "text/plain",
            Sensitivity::Normal,
        )],
        ToolId::Wafw00f => vec![output(
            OutputRole::Wafw00fJson,
            "wafw00f-output.json",
            "application/json",
            Sensitivity::Normal,
        )],
    }
}

fn curl_argv(target: &Url, outputs: &[ExpectedOutput]) -> Vec<String> {
    let headers = output_path(outputs, OutputRole::CurlHeaders);
    let body = output_path(outputs, OutputRole::CurlBody);
    string_arguments(&[
        "-q",
        "--silent",
        "--show-error",
        "--fail-early",
        "--connect-timeout",
        "5",
        "--max-time",
        "30",
        "--max-filesize",
        "8388608",
        "--proto",
        "=http,https",
        "--proto-redir",
        "=http,https",
        "--max-redirs",
        "0",
        "--noproxy",
        "*",
        "--dump-header",
        headers,
        "--output",
        body,
        "--write-out",
        "%{json}\n",
        target.as_str(),
    ])
}

fn dddd_argv(target: &Url, outputs: &[ExpectedOutput]) -> Result<Vec<String>, AdapterError> {
    let port = target
        .port_or_known_default()
        .ok_or(AdapterError::InvalidInput)?
        .to_string();
    Ok(string_arguments(&[
        "-t",
        target.as_str(),
        "-p",
        &port,
        "-Pn",
        "-npoc",
        "-ngp",
        "-dgp",
        "-nb",
        "-ni",
        "-pt=false",
        "-nd",
        "-tst",
        "100",
        "-tc",
        "50",
        "-wt",
        "20",
        "-pst",
        "6",
        "-nto",
        "5",
        "-wto",
        "10",
        "-o",
        output_path(outputs, OutputRole::DdddJsonLines),
        "-ot",
        "json",
    ]))
}

fn ffuf_argv(target: &Url, outputs: &[ExpectedOutput], wordlist: &Path) -> Vec<String> {
    let endpoint = format!("{}/FUZZ", target.as_str().trim_end_matches('/'));
    string_arguments(&[
        "-w",
        &wordlist.display().to_string(),
        "-u",
        &endpoint,
        "-o",
        output_path(outputs, OutputRole::FfufJson),
        "-of",
        "json",
        "-noninteractive",
        "-s",
        "-t",
        "20",
        "-rate",
        "50",
        "-timeout",
        "10",
        "-maxtime",
        "60",
        "-ac",
        "-fc",
        "404",
    ])
}

fn arjun_argv(target: &Url, outputs: &[ExpectedOutput], wordlist: &Path) -> Vec<String> {
    string_arguments(&[
        "-u",
        target.as_str(),
        "-o",
        output_path(outputs, OutputRole::ArjunJson),
        "-w",
        &wordlist.display().to_string(),
        "-t",
        "5",
        "-d",
        "0.1",
        "-T",
        "10",
        "--rate-limit",
        "20",
        "--disable-redirects",
        "-q",
    ])
}

fn fscan_argv(target: &Url, outputs: &[ExpectedOutput]) -> Result<Vec<String>, AdapterError> {
    let host = target.host_str().ok_or(AdapterError::InvalidInput)?;
    let port = target
        .port_or_known_default()
        .ok_or(AdapterError::InvalidInput)?
        .to_string();
    Ok(string_arguments(&[
        "-h",
        host,
        "-p",
        &port,
        "-np",
        "-nopoc",
        "-nobr",
        "-noredis",
        "-nocolor",
        "-nopg",
        "-t",
        "100",
        "-mt",
        "10",
        "-rate",
        "300",
        "-f",
        "json",
        "-o",
        output_path(outputs, OutputRole::FscanJson),
    ]))
}

fn gobuster_argv(target: &Url, outputs: &[ExpectedOutput], wordlist: &Path) -> Vec<String> {
    string_arguments(&[
        "dir",
        "--url",
        target.as_str(),
        "--wordlist",
        &wordlist.display().to_string(),
        "--threads",
        "20",
        "--timeout",
        "10s",
        "--no-error",
        "--no-color",
        "--status-codes-blacklist",
        "404",
        "--output",
        output_path(outputs, OutputRole::GobusterText),
    ])
}

fn wafw00f_argv(target: &Url, outputs: &[ExpectedOutput]) -> Vec<String> {
    string_arguments(&[
        target.as_str(),
        "--noredirect",
        "--no-colors",
        "--format",
        "json",
        "--output",
        output_path(outputs, OutputRole::Wafw00fJson),
    ])
}

fn string_arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn output_path(outputs: &[ExpectedOutput], role: OutputRole) -> &str {
    outputs
        .iter()
        .find(|output| output.role == role)
        .and_then(|output| output.path.to_str())
        .expect("internal output contract uses UTF-8 paths")
}

pub fn parse_output(prepared: &PreparedToolCommand) -> Result<ParsedToolOutput, AdapterError> {
    let mut output = match ToolId::from_str(&prepared.manifest.id)? {
        ToolId::Curl => parse_curl(prepared)?,
        ToolId::Dddd => parse_dddd(prepared)?,
        ToolId::Ffuf => parse_ffuf(prepared)?,
        ToolId::Arjun => parse_arjun(prepared)?,
        ToolId::Fscan => parse_fscan(prepared)?,
        ToolId::Gobuster => parse_gobuster(prepared)?,
        ToolId::Wafw00f => parse_wafw00f(prepared)?,
    };
    deduplicate(&mut output.discoveries);
    Ok(output)
}

fn parse_curl(prepared: &PreparedToolCommand) -> Result<ParsedToolOutput, AdapterError> {
    let metadata_bytes = read_bounded(&prepared.stdout_path, 1024 * 1024)?;
    let metadata: Value = serde_json::from_slice(&metadata_bytes)?;
    let status = metadata
        .get("response_code")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| (100..=599).contains(value))
        .ok_or(AdapterError::ParserSchema)?;
    let effective_url = metadata
        .get("url_effective")
        .and_then(Value::as_str)
        .ok_or(AdapterError::ParserSchema)?;
    let url = Url::parse(effective_url)?;
    validate_target_url(&url)?;
    let remote_port = metadata
        .get("remote_port")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(AdapterError::ParserSchema)?;
    let actual_length = metadata
        .get("size_download")
        .and_then(Value::as_u64)
        .ok_or(AdapterError::ParserSchema)?;
    let headers_path = role_path(prepared, OutputRole::CurlHeaders)?;
    let body_path = role_path(prepared, OutputRole::CurlBody)?;
    if fs::metadata(body_path)?.len() != actual_length {
        return Err(AdapterError::ParserSchema);
    }
    let header_bytes = read_bounded(headers_path, MAX_HEADER_OUTPUT_BYTES)?;
    let (http_version, parsed_status, headers) = parse_response_headers(&header_bytes)?;
    if parsed_status != status {
        return Err(AdapterError::ParserSchema);
    }
    let inline_body = (actual_length <= MAX_INLINE_RESPONSE_BYTES)
        .then(|| read_bounded(body_path, MAX_INLINE_RESPONSE_BYTES))
        .transpose()?;
    let declared_length =
        header_value(&headers, "content-length").and_then(|value| value.parse::<u64>().ok());
    let content_encoding = header_value(&headers, "content-encoding").map(str::to_owned);
    let duration_millis = metadata
        .get("time_total")
        .and_then(Value::as_f64)
        .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
        .and_then(|seconds| {
            u64::try_from(std::time::Duration::from_secs_f64(seconds).as_millis()).ok()
        });
    let discovery = url_discovery(&url);
    Ok(ParsedToolOutput {
        discoveries: vec![discovery],
        http_response: Some(ParsedHttpResponse {
            url,
            status_code: status,
            http_version,
            headers,
            inline_body,
            actual_length,
            declared_length,
            remote_ip: metadata
                .get("remote_ip")
                .and_then(Value::as_str)
                .map(str::to_owned),
            remote_port,
            duration_millis,
            content_encoding,
            body_role: OutputRole::CurlBody,
        }),
    })
}

fn parse_response_headers(bytes: &[u8]) -> Result<(String, u16, Vec<OrderedValue>), AdapterError> {
    let text = String::from_utf8_lossy(bytes).replace("\r\n", "\n");
    let mut version = None;
    let mut status = None;
    let mut headers = Vec::new();
    for line in text.lines() {
        if let Some(status_line) = line.strip_prefix("HTTP/") {
            let mut parts = status_line.split_whitespace();
            version = parts.next().map(str::to_owned);
            status = parts.next().and_then(|value| value.parse::<u16>().ok());
            headers.clear();
        } else if !line.is_empty() {
            let (name, value) = line.split_once(':').ok_or(AdapterError::ParserSchema)?;
            if name.trim().is_empty() || name.len() > 1024 || value.len() > 64 * 1024 {
                return Err(AdapterError::ParserSchema);
            }
            headers.push(OrderedValue {
                name: name.trim().to_owned(),
                value: value.trim().to_owned(),
            });
        }
    }
    let version = version.ok_or(AdapterError::ParserSchema)?;
    let status = status
        .filter(|value| (100..=599).contains(value))
        .ok_or(AdapterError::ParserSchema)?;
    Ok((version, status, headers))
}

fn parse_dddd(prepared: &PreparedToolCommand) -> Result<ParsedToolOutput, AdapterError> {
    let bytes = read_bounded(
        role_path(prepared, OutputRole::DdddJsonLines)?,
        MAX_STRUCTURED_OUTPUT_BYTES,
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| AdapterError::ParserSchema)?;
    let mut discoveries = Vec::new();
    let mut records = 0_usize;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        records += 1;
        let record: Value = serde_json::from_str(line)?;
        let record_type = record
            .get("type")
            .and_then(Value::as_str)
            .ok_or(AdapterError::ParserSchema)?;
        if let Some(uri) = record.get("uri").and_then(Value::as_str) {
            let url = Url::parse(uri)?;
            discoveries.push(url_discovery(&url));
            let target = canonical_url(&url)?;
            if let Some(title) = record
                .get("web")
                .and_then(|web| web.get("title"))
                .and_then(Value::as_str)
                .filter(|title| !title.trim().is_empty())
            {
                discoveries.push(ParsedDiscovery {
                    kind: DiscoveryKind::Fingerprint,
                    target,
                    raw_value: title.to_owned(),
                    canonical_value: format!("title:{}", title.trim().to_ascii_lowercase()),
                });
            }
        }
        if let Some(host) = record.get("domain").and_then(Value::as_str) {
            discoveries.push(ParsedDiscovery {
                kind: DiscoveryKind::Host,
                target: prepared.target.origin().ascii_serialization(),
                raw_value: host.to_owned(),
                canonical_value: host.trim().to_ascii_lowercase(),
            });
        }
        if let Some(fingers) = record.get("finger").and_then(Value::as_array) {
            for finger in fingers.iter().filter_map(Value::as_str) {
                discoveries.push(ParsedDiscovery {
                    kind: DiscoveryKind::Fingerprint,
                    target: prepared.target.origin().ascii_serialization(),
                    raw_value: finger.to_owned(),
                    canonical_value: finger.trim().to_ascii_lowercase(),
                });
            }
        }
        if record_type == "Port" || record_type == "Service" {
            let port = record
                .get("port")
                .and_then(Value::as_u64)
                .ok_or(AdapterError::ParserSchema)?;
            let protocol = record
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("tcp");
            discoveries.push(ParsedDiscovery {
                kind: DiscoveryKind::Service,
                target: prepared.target.origin().ascii_serialization(),
                raw_value: format!("{protocol}/{port}"),
                canonical_value: format!("{}/{port}", protocol.to_ascii_lowercase()),
            });
        }
    }
    if records == 0 {
        return Err(AdapterError::ParserSchema);
    }
    Ok(ParsedToolOutput {
        discoveries,
        http_response: None,
    })
}

fn parse_ffuf(prepared: &PreparedToolCommand) -> Result<ParsedToolOutput, AdapterError> {
    let bytes = read_bounded(
        role_path(prepared, OutputRole::FfufJson)?,
        MAX_STRUCTURED_OUTPUT_BYTES,
    )?;
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return parse_ffuf_json_lines(&bytes);
    };
    let records = if let Some(results) = value.get("results").and_then(Value::as_array) {
        results.clone()
    } else if let Some(results) = value.as_array() {
        results.clone()
    } else if value.get("url").is_some() {
        vec![value]
    } else {
        return parse_ffuf_json_lines(&bytes);
    };
    parse_ffuf_records(records)
}

fn parse_ffuf_json_lines(bytes: &[u8]) -> Result<ParsedToolOutput, AdapterError> {
    let text = std::str::from_utf8(bytes).map_err(|_| AdapterError::ParserSchema)?;
    let records = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?;
    parse_ffuf_records(records)
}

fn parse_ffuf_records(records: Vec<Value>) -> Result<ParsedToolOutput, AdapterError> {
    let mut discoveries = Vec::new();
    for record in records {
        let status = record
            .get("status")
            .and_then(Value::as_u64)
            .filter(|value| (100..=599).contains(value))
            .ok_or(AdapterError::ParserSchema)?;
        let raw_url = record
            .get("url")
            .and_then(Value::as_str)
            .ok_or(AdapterError::ParserSchema)?;
        let url = Url::parse(raw_url)?;
        validate_target_url(&url)?;
        discoveries.push(url_discovery(&url));
        discoveries.push(ParsedDiscovery {
            kind: DiscoveryKind::Path,
            target: url.origin().ascii_serialization(),
            raw_value: url.path().to_owned(),
            canonical_value: canonical_path(&url),
        });
        let _ = status;
    }
    Ok(ParsedToolOutput {
        discoveries,
        http_response: None,
    })
}

fn parse_arjun(prepared: &PreparedToolCommand) -> Result<ParsedToolOutput, AdapterError> {
    let bytes = read_bounded(
        role_path(prepared, OutputRole::ArjunJson)?,
        MAX_STRUCTURED_OUTPUT_BYTES,
    )?;
    let targets: BTreeMap<String, Value> = serde_json::from_slice(&bytes)?;
    let mut discoveries = Vec::new();
    for (raw_url, result) in targets {
        let url = Url::parse(&raw_url)?;
        validate_target_url(&url)?;
        let method = result
            .get("method")
            .and_then(Value::as_str)
            .ok_or(AdapterError::ParserSchema)?;
        if !matches!(method, "GET" | "POST" | "JSON" | "XML") {
            return Err(AdapterError::ParserSchema);
        }
        let params = result
            .get("params")
            .and_then(Value::as_array)
            .ok_or(AdapterError::ParserSchema)?;
        let target = canonical_url(&url)?;
        for parameter in params {
            let parameter = parameter
                .as_str()
                .filter(|value| !value.is_empty() && value.len() <= MAX_WORDLIST_TERM_BYTES)
                .ok_or(AdapterError::ParserSchema)?;
            discoveries.push(ParsedDiscovery {
                kind: DiscoveryKind::Parameter,
                target: target.clone(),
                raw_value: parameter.to_owned(),
                canonical_value: format!("{}:{}", method.to_ascii_lowercase(), parameter),
            });
        }
    }
    Ok(ParsedToolOutput {
        discoveries,
        http_response: None,
    })
}

fn parse_fscan(prepared: &PreparedToolCommand) -> Result<ParsedToolOutput, AdapterError> {
    let bytes = read_bounded(
        role_path(prepared, OutputRole::FscanJson)?,
        MAX_STRUCTURED_OUTPUT_BYTES,
    )?;
    let records = parse_json_records(&bytes)?;
    let expected_host = prepared
        .target
        .host_str()
        .ok_or(AdapterError::ParserSchema)?;
    let expected_port = prepared
        .target
        .port_or_known_default()
        .ok_or(AdapterError::ParserSchema)?;
    let mut discoveries = Vec::new();
    for record in records {
        if let Some(raw_url) = record.get("url").and_then(Value::as_str) {
            let url = Url::parse(raw_url)?;
            ensure_same_origin(&prepared.target, &url)?;
            discoveries.push(url_discovery(&url));
        }
        let host = record
            .get("host")
            .or_else(|| record.get("ip"))
            .and_then(Value::as_str)
            .unwrap_or(expected_host);
        let port = record
            .get("port")
            .and_then(|value| {
                value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|item| item.parse().ok()))
            })
            .and_then(|value| u16::try_from(value).ok())
            .unwrap_or(expected_port);
        if !host.eq_ignore_ascii_case(expected_host) || port != expected_port {
            return Err(AdapterError::ParserSchema);
        }
        let protocol = record
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or("tcp")
            .to_ascii_lowercase();
        let service = record
            .get("service")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        discoveries.push(ParsedDiscovery {
            kind: DiscoveryKind::Service,
            target: prepared.target.origin().ascii_serialization(),
            raw_value: format!("{protocol}/{port} {service}"),
            canonical_value: format!("{protocol}/{port}:{}", service.to_ascii_lowercase()),
        });
        if let Some(info) = record
            .get("info")
            .or_else(|| record.get("title"))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty() && value.len() <= 4096)
        {
            discoveries.push(ParsedDiscovery {
                kind: DiscoveryKind::Fingerprint,
                target: prepared.target.origin().ascii_serialization(),
                raw_value: info.to_owned(),
                canonical_value: info.trim().to_ascii_lowercase(),
            });
        }
    }
    Ok(ParsedToolOutput {
        discoveries,
        http_response: None,
    })
}

fn parse_gobuster(prepared: &PreparedToolCommand) -> Result<ParsedToolOutput, AdapterError> {
    let bytes = read_bounded(
        role_path(prepared, OutputRole::GobusterText)?,
        MAX_STRUCTURED_OUTPUT_BYTES,
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| AdapterError::ParserSchema)?;
    let mut discoveries = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let path = line
            .split_whitespace()
            .next()
            .filter(|value| {
                value.starts_with('/')
                    && value.len() <= 4096
                    && !value.contains(['\0', '\r', '\n'])
                    && !value.split('/').any(|segment| segment == "..")
            })
            .ok_or(AdapterError::ParserSchema)?;
        let url = prepared.target.join(path)?;
        ensure_same_origin(&prepared.target, &url)?;
        discoveries.push(url_discovery(&url));
        discoveries.push(ParsedDiscovery {
            kind: DiscoveryKind::Path,
            target: url.origin().ascii_serialization(),
            raw_value: path.to_owned(),
            canonical_value: canonical_path(&url),
        });
    }
    Ok(ParsedToolOutput {
        discoveries,
        http_response: None,
    })
}

fn parse_wafw00f(prepared: &PreparedToolCommand) -> Result<ParsedToolOutput, AdapterError> {
    let bytes = read_bounded(
        role_path(prepared, OutputRole::Wafw00fJson)?,
        MAX_STRUCTURED_OUTPUT_BYTES,
    )?;
    let records = parse_json_records(&bytes)?;
    let mut discoveries = Vec::new();
    for record in records {
        let raw_url = record
            .get("url")
            .and_then(Value::as_str)
            .ok_or(AdapterError::ParserSchema)?;
        let url = Url::parse(raw_url)?;
        ensure_same_origin(&prepared.target, &url)?;
        discoveries.push(url_discovery(&url));
        let detected = record
            .get("detected")
            .and_then(Value::as_bool)
            .ok_or(AdapterError::ParserSchema)?;
        let firewall = record
            .get("firewall")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .ok_or(AdapterError::ParserSchema)?;
        let manufacturer = record
            .get("manufacturer")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .ok_or(AdapterError::ParserSchema)?;
        let raw_value = if detected {
            format!("WAF: {firewall} ({manufacturer})")
        } else {
            "WAF: none detected".to_owned()
        };
        discoveries.push(ParsedDiscovery {
            kind: DiscoveryKind::Fingerprint,
            target: url.origin().ascii_serialization(),
            raw_value,
            canonical_value: format!(
                "waf:{}:{}",
                firewall.to_ascii_lowercase(),
                manufacturer.to_ascii_lowercase()
            ),
        });
    }
    Ok(ParsedToolOutput {
        discoveries,
        http_response: None,
    })
}

fn parse_json_records(bytes: &[u8]) -> Result<Vec<Value>, AdapterError> {
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        return match value {
            Value::Array(records) => Ok(records),
            Value::Object(mut object) => object
                .remove("results")
                .and_then(|value| value.as_array().cloned())
                .map_or_else(|| Ok(vec![Value::Object(object)]), Ok),
            _ => Err(AdapterError::ParserSchema),
        };
    }
    std::str::from_utf8(bytes)
        .map_err(|_| AdapterError::ParserSchema)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

fn ensure_same_origin(expected: &Url, actual: &Url) -> Result<(), AdapterError> {
    validate_target_url(actual)?;
    if expected.scheme() != actual.scheme()
        || expected.host_str() != actual.host_str()
        || expected.port_or_known_default() != actual.port_or_known_default()
    {
        return Err(AdapterError::ParserSchema);
    }
    Ok(())
}

fn role_path(prepared: &PreparedToolCommand, role: OutputRole) -> Result<&Path, AdapterError> {
    prepared
        .outputs
        .iter()
        .find(|output| output.role == role)
        .map(|output| output.path.as_path())
        .ok_or(AdapterError::MissingOutput)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, AdapterError> {
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AdapterError::MissingOutput
        } else {
            AdapterError::Io(error)
        }
    })?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(AdapterError::OutputTooLarge);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| AdapterError::OutputTooLarge)?;
    let mut output = Vec::with_capacity(capacity);
    File::open(path)?.read_to_end(&mut output)?;
    Ok(output)
}

fn header_value<'a>(headers: &'a [OrderedValue], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .rev()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn url_discovery(url: &Url) -> ParsedDiscovery {
    ParsedDiscovery {
        kind: DiscoveryKind::Url,
        target: url.origin().ascii_serialization(),
        raw_value: url.as_str().to_owned(),
        canonical_value: canonical_url(url).unwrap_or_else(|_| url.as_str().to_owned()),
    }
}

fn canonical_url(url: &Url) -> Result<String, AdapterError> {
    validate_target_url(url)?;
    let mut value = url.clone();
    value.set_fragment(None);
    if value.path().is_empty() {
        value.set_path("/");
    }
    Ok(value.to_string())
}

fn canonical_path(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    }
}

fn deduplicate(discoveries: &mut Vec<ParsedDiscovery>) {
    let mut seen = BTreeSet::new();
    discoveries.retain(|item| {
        seen.insert(format!(
            "{}\u{0}{}\u{0}{}",
            discovery_kind_name(item.kind),
            item.target,
            item.canonical_value
        ))
    });
}

#[must_use]
pub fn materialize_discoveries(
    project_id: &ProjectId,
    parsed: Vec<ParsedDiscovery>,
    observed_at: &Timestamp,
) -> Vec<Discovery> {
    parsed
        .into_iter()
        .map(|item| {
            let canonical_key = discovery_key(&item);
            Discovery {
                discovery_id: DiscoveryId::new(),
                project_id: project_id.clone(),
                kind: item.kind,
                raw_value: item.raw_value,
                canonical_value: item.canonical_value,
                canonical_key,
                first_seen_at: observed_at.clone(),
                last_seen_at: observed_at.clone(),
                status: "active".to_owned(),
                manual_labels: Vec::new(),
            }
        })
        .collect()
}

fn discovery_key(item: &ParsedDiscovery) -> String {
    let mut hasher = Sha256::new();
    hasher.update(item.target.as_bytes());
    hasher.update([0]);
    hasher.update(discovery_kind_name(item.kind).as_bytes());
    hasher.update([0]);
    hasher.update(item.canonical_value.as_bytes());
    format!("{:x}", hasher.finalize())
}

const fn discovery_kind_name(kind: DiscoveryKind) -> &'static str {
    match kind {
        DiscoveryKind::Url => "url",
        DiscoveryKind::Path => "path",
        DiscoveryKind::Parameter => "parameter",
        DiscoveryKind::Service => "service",
        DiscoveryKind::Fingerprint => "fingerprint",
        DiscoveryKind::Host => "host",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_directory(tool: &str) -> PathBuf {
        let release = if matches!(tool, "fscan" | "gobuster" | "wafw00f") {
            "r7"
        } else {
            "r2"
        };
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../tests/fixtures/{release}/real"))
            .join(tool)
    }

    fn prepared_for_fixture(tool_id: ToolId) -> PreparedToolCommand {
        let temporary = tempfile::tempdir().unwrap();
        let scope = ScopeId::new();
        let target = Url::parse("http://127.0.0.1:38001/").unwrap();
        let wordlist =
            matches!(tool_id, ToolId::Ffuf | ToolId::Arjun | ToolId::Gobuster).then(|| {
                let path = temporary.path().join("words.txt");
                write_wordlist(tool_id, &["admin".to_owned()], &path).unwrap();
                path
            });
        let mut prepared = prepare_command(
            tool_id,
            &scope,
            &target,
            temporary.path(),
            wordlist.as_deref(),
        )
        .unwrap();
        let fixture = fixture_directory(tool_id.as_str());
        match tool_id {
            ToolId::Curl => {
                prepared.spec.cwd = fixture.display().to_string();
                prepared.stdout_path = fixture.join("meta.json");
                prepared.outputs = vec![
                    ExpectedOutput {
                        role: OutputRole::CurlHeaders,
                        path: fixture.join("headers.txt"),
                        logical_name: "headers.txt".to_owned(),
                        mime: "application/http".to_owned(),
                        sensitivity: Sensitivity::SensitiveEvidence,
                    },
                    ExpectedOutput {
                        role: OutputRole::CurlBody,
                        path: fixture.join("body.html"),
                        logical_name: "body.html".to_owned(),
                        mime: "text/html".to_owned(),
                        sensitivity: Sensitivity::SensitiveEvidence,
                    },
                ];
            }
            ToolId::Dddd => prepared.outputs[0].path = fixture.join("output.jsonl"),
            ToolId::Ffuf | ToolId::Arjun | ToolId::Fscan | ToolId::Wafw00f => {
                prepared.outputs[0].path = fixture.join("output.json");
            }
            ToolId::Gobuster => prepared.outputs[0].path = fixture.join("output.txt"),
        }
        prepared
    }

    #[test]
    fn registry_freezes_all_tools_and_health_strategies() {
        let registry = registry().unwrap();
        assert_eq!(registry.tools.len(), 7);
        let dddd = registry
            .tools
            .iter()
            .find(|tool| tool.id == "dddd")
            .unwrap();
        assert!(dddd.health_argv.is_empty());
        assert!(!dddd.side_effect_free_help);
        assert_eq!(dddd.sha256.len(), 64);
    }

    #[test]
    fn command_builders_are_shell_free_bounded_and_scope_bound() {
        let temporary = tempfile::tempdir().unwrap();
        for tool_id in [
            ToolId::Curl,
            ToolId::Dddd,
            ToolId::Ffuf,
            ToolId::Arjun,
            ToolId::Fscan,
            ToolId::Gobuster,
            ToolId::Wafw00f,
        ] {
            let directory = temporary.path().join(tool_id.as_str());
            fs::create_dir(&directory).unwrap();
            let wordlist =
                matches!(tool_id, ToolId::Ffuf | ToolId::Arjun | ToolId::Gobuster).then(|| {
                    let path = directory.join("wordlist.txt");
                    write_wordlist(tool_id, &["admin".to_owned()], &path).unwrap();
                    path
                });
            let prepared = prepare_command(
                tool_id,
                &ScopeId::new(),
                &Url::parse("http://127.0.0.1:38001/search").unwrap(),
                &directory,
                wordlist.as_deref(),
            )
            .unwrap();
            assert!(prepared.spec.program.starts_with('/'));
            assert!(prepared.spec.scope_id.is_some());
            assert_eq!(prepared.spec.argv_exec, prepared.spec.argv_redacted);
            assert!(!matches!(
                Path::new(&prepared.spec.program)
                    .file_name()
                    .and_then(|name| name.to_str()),
                Some("sh" | "bash" | "zsh")
            ));
            if tool_id == ToolId::Dddd {
                assert!(
                    prepared
                        .spec
                        .argv_exec
                        .iter()
                        .any(|item| item == "-pt=false")
                );
                assert!(prepared.spec.argv_exec.iter().any(|item| item == "-npoc"));
                assert!(
                    !prepared
                        .spec
                        .argv_exec
                        .iter()
                        .any(|item| item.contains("baidu.com") || item == "-ptu")
                );
            }
            if tool_id == ToolId::Arjun {
                assert!(
                    prepared
                        .spec
                        .argv_exec
                        .windows(2)
                        .any(|items| items[0] == "-d" && items[1] == "0.1")
                );
                assert!(
                    !prepared
                        .spec
                        .argv_exec
                        .iter()
                        .any(|item| item == "--passive")
                );
            }
            if tool_id == ToolId::Fscan {
                for flag in ["-np", "-nopoc", "-nobr", "-noredis"] {
                    assert!(prepared.spec.argv_exec.iter().any(|item| item == flag));
                }
            }
            if tool_id == ToolId::Wafw00f {
                assert!(
                    prepared
                        .spec
                        .argv_exec
                        .iter()
                        .any(|item| item == "--noredirect")
                );
            }
        }
    }

    #[test]
    fn real_version_bound_fixtures_parse() {
        let curl = parse_output(&prepared_for_fixture(ToolId::Curl)).unwrap();
        assert_eq!(curl.http_response.unwrap().status_code, 200);
        assert_eq!(curl.discoveries.len(), 1);

        let dddd = parse_output(&prepared_for_fixture(ToolId::Dddd)).unwrap();
        assert!(dddd.discoveries.iter().any(|item| {
            item.kind == DiscoveryKind::Fingerprint && item.raw_value == "FlagDeck R2 Fixture"
        }));

        let ffuf = parse_output(&prepared_for_fixture(ToolId::Ffuf)).unwrap();
        assert_eq!(
            ffuf.discoveries
                .iter()
                .filter(|item| item.kind == DiscoveryKind::Path)
                .count(),
            3
        );

        let arjun = parse_output(&prepared_for_fixture(ToolId::Arjun)).unwrap();
        let parameters = arjun
            .discoveries
            .iter()
            .map(|item| item.raw_value.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(parameters, BTreeSet::from(["debug", "id"]));

        let fscan = parse_output(&prepared_for_fixture(ToolId::Fscan)).unwrap();
        assert!(
            fscan
                .discoveries
                .iter()
                .any(|item| item.kind == DiscoveryKind::Service)
        );

        let gobuster = parse_output(&prepared_for_fixture(ToolId::Gobuster)).unwrap();
        assert_eq!(
            gobuster
                .discoveries
                .iter()
                .filter(|item| item.kind == DiscoveryKind::Path)
                .count(),
            3
        );

        let wafw00f = parse_output(&prepared_for_fixture(ToolId::Wafw00f)).unwrap();
        assert!(wafw00f.discoveries.iter().any(|item| {
            item.kind == DiscoveryKind::Fingerprint && item.canonical_value == "waf:none:none"
        }));
    }

    #[test]
    fn fixture_manifests_bind_tool_and_output_hashes() {
        for tool_id in [
            ToolId::Curl,
            ToolId::Dddd,
            ToolId::Ffuf,
            ToolId::Arjun,
            ToolId::Fscan,
            ToolId::Gobuster,
            ToolId::Wafw00f,
        ] {
            let directory = fixture_directory(tool_id.as_str());
            let fixture_manifest: Value =
                serde_json::from_slice(&fs::read(directory.join("manifest.json")).unwrap())
                    .unwrap();
            let configured = manifest(tool_id).unwrap();
            assert_eq!(fixture_manifest["tool"]["sha256"], configured.pinned_sha256);
            let outputs = fixture_manifest
                .get("outputs")
                .or_else(|| fixture_manifest.get("output"))
                .and_then(Value::as_object)
                .unwrap();
            for (name, expected) in outputs {
                let bytes = fs::read(directory.join(name)).unwrap();
                let actual = format!("{:x}", Sha256::digest(bytes));
                assert_eq!(expected.as_str(), Some(actual.as_str()));
            }
        }
    }

    #[test]
    fn corrupted_success_output_is_a_parser_error() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("ffuf-output.json");
        fs::write(&path, b"{broken").unwrap();
        let mut prepared = prepared_for_fixture(ToolId::Ffuf);
        prepared.outputs[0].path = path;
        assert!(parse_output(&prepared).is_err());
    }

    #[test]
    fn wordlists_reject_command_and_url_injection() {
        let temporary = tempfile::tempdir().unwrap();
        for value in ["../etc/passwd", "admin\n-o evil", "https://example.invalid"] {
            assert!(
                write_wordlist(
                    ToolId::Ffuf,
                    &[value.to_owned()],
                    &temporary.path().join(value.len().to_string()),
                )
                .is_err()
            );
        }
    }
}
