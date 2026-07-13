use std::env;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::unistd::Uid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use ts_rs::TS;

pub const PAYLOAD_SOURCES_SOURCE: &str = include_str!("../../../config/payload-sources.toml");
const MAX_PAGE: usize = 500;
const MAX_QUERY_BYTES: usize = 512;

#[derive(Debug, Error)]
pub enum PayloadBrowserError {
    #[error("payload source registry is invalid")]
    Registry,
    #[error("payload source is unavailable")]
    SourceUnavailable,
    #[error("payload browser request is invalid")]
    InvalidRequest,
    #[error("payload entry was not found")]
    NotFound,
    #[error("payload browser I/O failed")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PayloadSourceManifest {
    pub id: String,
    pub name: String,
    pub root: String,
    pub labels: Vec<String>,
    pub variables: Vec<String>,
    pub contexts: Vec<String>,
    pub risk_level: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PayloadSourceRegistry {
    pub schema_version: u32,
    pub maximum_depth: usize,
    pub maximum_entries: usize,
    pub maximum_preview_bytes: usize,
    #[serde(rename = "source")]
    pub sources: Vec<PayloadSourceManifest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PayloadFormat {
    Txt,
    Yaml,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PayloadSourceHealthDto {
    pub source_id: String,
    pub name: String,
    pub labels: Vec<String>,
    pub variables: Vec<String>,
    pub contexts: Vec<String>,
    pub risk_level: String,
    pub healthy: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PayloadEntryDto {
    pub payload_id: String,
    pub source_id: String,
    pub source_name: String,
    pub display_path: String,
    pub format: PayloadFormat,
    #[ts(type = "number")]
    pub size: u64,
    pub labels: Vec<String>,
    pub variables: Vec<String>,
    pub contexts: Vec<String>,
    pub risk_level: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ListPayloadsRequest {
    pub project_id: flagdeck_domain::ProjectId,
    pub source_id: Option<String>,
    pub query: String,
    pub cursor: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PayloadPage {
    pub items: Vec<PayloadEntryDto>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PreviewPayloadRequest {
    pub project_id: flagdeck_domain::ProjectId,
    pub payload_id: String,
    #[ts(type = "number")]
    pub offset: u64,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PayloadPreview {
    pub payload_id: String,
    pub source_id: String,
    pub display_path: String,
    pub format: PayloadFormat,
    #[ts(type = "number")]
    pub offset: u64,
    #[ts(type = "number")]
    pub total_size: u64,
    pub content: String,
    pub sha256: String,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
struct PayloadEntryRef {
    dto: PayloadEntryDto,
    path: PathBuf,
}

pub fn registry() -> Result<PayloadSourceRegistry, PayloadBrowserError> {
    let source = payload_source_override()
        .and_then(|path| fs::read_to_string(path).ok())
        .unwrap_or_else(|| PAYLOAD_SOURCES_SOURCE.to_owned());
    let registry: PayloadSourceRegistry =
        toml::from_str(&source).map_err(|_| PayloadBrowserError::Registry)?;
    if registry.schema_version != 1
        || registry.sources.is_empty()
        || registry.maximum_depth == 0
        || registry.maximum_depth > 32
        || registry.maximum_entries == 0
        || registry.maximum_entries > 100_000
        || registry.maximum_preview_bytes == 0
        || registry.maximum_preview_bytes > 65_536
        || registry.sources.iter().any(|source| {
            source.id.is_empty()
                || source.id.len() > 64
                || !source
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || source.name.is_empty()
                || source.name.len() > 128
                || !source.root.starts_with('/')
                || source.labels.is_empty()
                || source.contexts.is_empty()
                || !matches!(source.risk_level.as_str(), "l0" | "l1" | "l2" | "l3")
        })
    {
        return Err(PayloadBrowserError::Registry);
    }
    let mut ids = registry
        .sources
        .iter()
        .map(|source| source.id.as_str())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != registry.sources.len() {
        return Err(PayloadBrowserError::Registry);
    }
    Ok(registry)
}

fn payload_source_override() -> Option<PathBuf> {
    env::var_os("FLAGDECK_PAYLOAD_SOURCES_FILE")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .map(|root| root.join("flagdeck/payload-sources.toml"))
        })
        .or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .map(|root| root.join(".config/flagdeck/payload-sources.toml"))
        })
}

pub fn source_health() -> Result<Vec<PayloadSourceHealthDto>, PayloadBrowserError> {
    Ok(registry()?
        .sources
        .into_iter()
        .map(|source| {
            let result = validated_root(&source);
            PayloadSourceHealthDto {
                source_id: source.id,
                name: source.name,
                labels: source.labels,
                variables: source.variables,
                contexts: source.contexts,
                risk_level: source.risk_level,
                healthy: result.is_ok(),
                detail: result.map_or_else(|error| error.to_string(), |_| "ready".to_owned()),
            }
        })
        .collect())
}

pub fn list(request: &ListPayloadsRequest) -> Result<PayloadPage, PayloadBrowserError> {
    if request.limit == 0
        || request.limit > MAX_PAGE
        || request.query.len() > MAX_QUERY_BYTES
        || request.query.contains(['\0', '\n', '\r'])
    {
        return Err(PayloadBrowserError::InvalidRequest);
    }
    let start = request
        .cursor
        .as_deref()
        .unwrap_or("0")
        .parse::<usize>()
        .map_err(|_| PayloadBrowserError::InvalidRequest)?;
    let registry = registry()?;
    let mut entries = collect_registry(&registry, request.source_id.as_deref())?;
    let query = request.query.to_lowercase();
    if !query.is_empty() {
        entries.retain(|entry| {
            entry.dto.display_path.to_lowercase().contains(&query)
                || entry
                    .dto
                    .labels
                    .iter()
                    .any(|label| label.to_lowercase().contains(&query))
        });
    }
    entries.sort_by(|left, right| {
        (&left.dto.source_id, &left.dto.display_path)
            .cmp(&(&right.dto.source_id, &right.dto.display_path))
    });
    if start > entries.len() {
        return Err(PayloadBrowserError::InvalidRequest);
    }
    let end = start.saturating_add(request.limit).min(entries.len());
    let items = entries[start..end]
        .iter()
        .map(|entry| entry.dto.clone())
        .collect();
    Ok(PayloadPage {
        items,
        next_cursor: (end < entries.len()).then(|| end.to_string()),
    })
}

pub fn preview(request: &PreviewPayloadRequest) -> Result<PayloadPreview, PayloadBrowserError> {
    if request.payload_id.len() != 64
        || !request
            .payload_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(PayloadBrowserError::InvalidRequest);
    }
    let registry = registry()?;
    if request.limit == 0 || request.limit > registry.maximum_preview_bytes {
        return Err(PayloadBrowserError::InvalidRequest);
    }
    let entry = collect_registry(&registry, None)?
        .into_iter()
        .find(|entry| entry.dto.payload_id == request.payload_id)
        .ok_or(PayloadBrowserError::NotFound)?;
    let total_size = entry.dto.size;
    if request.offset > total_size {
        return Err(PayloadBrowserError::InvalidRequest);
    }
    let canonical = entry.path.canonicalize()?;
    let mut file = File::open(&canonical)?;
    let sha256 = sha256_reader(&mut file)?;
    file.seek(SeekFrom::Start(request.offset))?;
    let remaining = total_size.saturating_sub(request.offset);
    let read_length = usize::try_from(remaining.min(request.limit as u64))
        .map_err(|_| PayloadBrowserError::InvalidRequest)?;
    let mut bytes = vec![0_u8; read_length];
    file.read_exact(&mut bytes)?;
    let content = String::from_utf8_lossy(&bytes).into_owned();
    Ok(PayloadPreview {
        payload_id: entry.dto.payload_id,
        source_id: entry.dto.source_id,
        display_path: entry.dto.display_path,
        format: entry.dto.format,
        offset: request.offset,
        total_size,
        content,
        sha256,
        truncated: request.offset.saturating_add(read_length as u64) < total_size,
    })
}

fn collect_registry(
    registry: &PayloadSourceRegistry,
    source_filter: Option<&str>,
) -> Result<Vec<PayloadEntryRef>, PayloadBrowserError> {
    if source_filter.is_some_and(|filter| !registry.sources.iter().any(|item| item.id == filter)) {
        return Err(PayloadBrowserError::InvalidRequest);
    }
    let mut entries = Vec::new();
    for source in registry
        .sources
        .iter()
        .filter(|source| source_filter.is_none_or(|filter| source.id == filter))
    {
        let root = validated_root(source)?;
        collect_directory(
            source,
            &root,
            &root,
            0,
            registry.maximum_depth,
            registry.maximum_entries,
            &mut entries,
        )?;
    }
    Ok(entries)
}

fn collect_directory(
    source: &PayloadSourceManifest,
    root: &Path,
    directory: &Path,
    depth: usize,
    maximum_depth: usize,
    maximum_entries: usize,
    entries: &mut Vec<PayloadEntryRef>,
) -> Result<(), PayloadBrowserError> {
    if depth > maximum_depth || entries.len() >= maximum_entries {
        return Ok(());
    }
    let directory_metadata = fs::symlink_metadata(directory)?;
    if !trusted_metadata(&directory_metadata, true) {
        return Ok(());
    }
    let mut children = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        if entries.len() >= maximum_entries {
            break;
        }
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !trusted_metadata(&metadata, metadata.is_dir()) {
            continue;
        }
        if metadata.is_dir() {
            collect_directory(
                source,
                root,
                &path,
                depth + 1,
                maximum_depth,
                maximum_entries,
                entries,
            )?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let Some(format) = payload_format(&path) else {
            continue;
        };
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(root) {
            continue;
        }
        let relative = canonical
            .strip_prefix(root)
            .map_err(|_| PayloadBrowserError::SourceUnavailable)?;
        let display_path = relative.to_string_lossy().replace('\\', "/");
        if display_path.is_empty() || display_path.contains('\0') {
            continue;
        }
        let mut labels = source.labels.clone();
        labels.extend(
            relative
                .parent()
                .into_iter()
                .flat_map(Path::components)
                .take(3)
                .map(|component| component.as_os_str().to_string_lossy().into_owned()),
        );
        labels.sort();
        labels.dedup();
        let payload_id = opaque_id(&source.id, &display_path);
        entries.push(PayloadEntryRef {
            dto: PayloadEntryDto {
                payload_id,
                source_id: source.id.clone(),
                source_name: source.name.clone(),
                display_path,
                format,
                size: metadata.len(),
                labels,
                variables: source.variables.clone(),
                contexts: source.contexts.clone(),
                risk_level: source.risk_level.clone(),
            },
            path: canonical,
        });
    }
    Ok(())
}

fn validated_root(source: &PayloadSourceManifest) -> Result<PathBuf, PayloadBrowserError> {
    let path = Path::new(&source.root);
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PayloadBrowserError::SourceUnavailable)?;
    if metadata.file_type().is_symlink() || !trusted_metadata(&metadata, true) {
        return Err(PayloadBrowserError::SourceUnavailable);
    }
    path.canonicalize()
        .map_err(|_| PayloadBrowserError::SourceUnavailable)
}

fn trusted_metadata(metadata: &fs::Metadata, directory: bool) -> bool {
    metadata.uid() == Uid::effective().as_raw()
        && metadata.permissions().mode() & 0o022 == 0
        && if directory {
            metadata.is_dir()
        } else {
            metadata.is_file()
        }
}

fn payload_format(path: &Path) -> Option<PayloadFormat> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "txt" => Some(PayloadFormat::Txt),
        "yaml" | "yml" => Some(PayloadFormat::Yaml),
        "json" => Some(PayloadFormat::Json),
        _ => None,
    }
}

fn opaque_id(source_id: &str, display_path: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(source_id.as_bytes());
    digest.update([0]);
    digest.update(display_path.as_bytes());
    format!("{:x}", digest.finalize())
}

fn sha256_reader(file: &mut File) -> Result<String, std::io::Error> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn registry_is_bounded_and_sources_report_health() {
        let registry = registry().unwrap();
        assert_eq!(registry.schema_version, 1);
        assert_eq!(registry.maximum_preview_bytes, 65_536);
        let health = source_health().unwrap();
        assert_eq!(health.len(), 2);
        assert!(health.iter().all(|source| !source.name.is_empty()));
    }

    #[test]
    fn collection_accepts_declared_formats_and_skips_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        fs::write(root.join("one.txt"), b"one").unwrap();
        fs::write(root.join("two.yaml"), b"value: two\n").unwrap();
        fs::write(root.join("three.json"), b"{\"value\":3}\n").unwrap();
        fs::write(root.join("skip.md"), b"skip").unwrap();
        symlink(root.join("one.txt"), root.join("linked.txt")).unwrap();
        let source = PayloadSourceManifest {
            id: "fixture".to_owned(),
            name: "Fixture".to_owned(),
            root: root.display().to_string(),
            labels: vec!["test".to_owned()],
            variables: vec!["TARGET".to_owned()],
            contexts: vec!["unit".to_owned()],
            risk_level: "l1".to_owned(),
        };
        let canonical = validated_root(&source).unwrap();
        let mut entries = Vec::new();
        collect_directory(&source, &canonical, &canonical, 0, 4, 10, &mut entries).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|entry| entry.dto.payload_id.len() == 64));
        assert!(
            entries
                .iter()
                .all(|entry| entry.dto.labels.contains(&"test".to_owned()))
        );
    }
}
