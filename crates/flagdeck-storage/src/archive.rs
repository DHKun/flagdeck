//! 项目归档：export/import 的打包、解包与 zip-slip / symlink / 大小 / 压缩比 / 哈希校验。
//! 从单文件的 storage crate 里析出，把「归档」这一关注点集中到一处。逐字搬迁，逻辑不变。
//! `project_summary_from_database` 被 store 方法与 import 共用，留在 crate 根，这里经 `crate::` 引用。

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use flagdeck_domain::{Artifact, ArtifactId, Sensitivity, Validate};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::{
    ArchiveLimits, MAX_ARCHIVE_MANIFEST_BYTES, ProjectArchiveEntry, ProjectArchiveManifest,
    SCHEMA_VERSION, StorageError, WorkspaceLayout, create_private_dir, ensure_descendant,
    open_reader_connection, project_summary_from_database, sha256_file, sync_directory,
    write_private_bytes,
};

#[derive(Debug, Clone)]
pub(crate) struct ArchiveSource {
    pub(crate) entry: ProjectArchiveEntry,
    pub(crate) source: PathBuf,
}

pub(crate) struct ValidatedArchive {
    pub(crate) manifest: ProjectArchiveManifest,
    pub(crate) manifest_bytes: Vec<u8>,
    pub(crate) archive_sha256: String,
    pub(crate) file_count: usize,
    pub(crate) total_bytes: u64,
}

pub(crate) fn insert_archive_source(
    sources: &mut BTreeMap<String, ArchiveSource>,
    entry: ProjectArchiveEntry,
    source: PathBuf,
) -> Result<(), StorageError> {
    if let Some(existing) = sources.get_mut(&entry.path) {
        if existing.entry.sha256 != entry.sha256 || existing.entry.size != entry.size {
            return Err(StorageError::HashMismatch);
        }
        existing.entry.sensitivity = most_sensitive(existing.entry.sensitivity, entry.sensitivity);
        return Ok(());
    }
    validate_archive_payload_path(&entry.path)?;
    sources.insert(entry.path.clone(), ArchiveSource { entry, source });
    Ok(())
}

const fn most_sensitive(left: Sensitivity, right: Sensitivity) -> Sensitivity {
    match (left, right) {
        (Sensitivity::Credential, _) | (_, Sensitivity::Credential) => Sensitivity::Credential,
        (Sensitivity::SensitiveEvidence, _) | (_, Sensitivity::SensitiveEvidence) => {
            Sensitivity::SensitiveEvidence
        }
        (Sensitivity::Normal, Sensitivity::Normal) => Sensitivity::Normal,
    }
}

pub(crate) fn all_committed_artifacts(database: &Path) -> Result<Vec<Artifact>, StorageError> {
    let connection = open_reader_connection(database)?;
    let mut statement = connection.prepare(
        "SELECT payload_json FROM artifacts WHERE state='committed' ORDER BY artifact_id",
    )?;
    statement
        .query_map([], |row| row.get::<_, String>(0))?
        .map(|value| {
            value
                .map_err(StorageError::from)
                .and_then(|payload| serde_json::from_str(&payload).map_err(Into::into))
        })
        .collect()
}

pub(crate) fn write_project_archive(
    path: &Path,
    manifest: &ProjectArchiveManifest,
    sources: &BTreeMap<String, ArchiveSource>,
) -> Result<(), StorageError> {
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o600);
    for (name, source) in sources {
        writer.start_file(name, options)?;
        let mut input = File::open(&source.source)?;
        let copied = std::io::copy(&mut input, &mut writer)?;
        if copied != source.entry.size {
            return Err(StorageError::SizeMismatch);
        }
    }
    let manifest_bytes = toml::to_string_pretty(manifest)?.into_bytes();
    if u64::try_from(manifest_bytes.len()).map_err(|_| StorageError::ArchiveLimit)?
        > MAX_ARCHIVE_MANIFEST_BYTES
    {
        return Err(StorageError::ArchiveLimit);
    }
    writer.start_file("project.toml", options)?;
    writer.write_all(&manifest_bytes)?;
    let output = writer.finish()?;
    output.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub(crate) fn validate_project_archive(
    path: &Path,
    limits: ArchiveLimits,
) -> Result<ValidatedArchive, StorageError> {
    if limits.maximum_files == 0
        || limits.maximum_total_bytes == 0
        || limits.maximum_file_bytes == 0
        || limits.maximum_compression_ratio == 0
        || limits.maximum_manifest_bytes == 0
    {
        return Err(StorageError::ArchiveLimit);
    }
    let archive_sha256 = sha256_file(path)?;
    let mut archive = ZipArchive::new(File::open(path)?)?;
    if archive.is_empty() || archive.len() > limits.maximum_files {
        return Err(StorageError::ArchiveLimit);
    }
    let mut metadata = BTreeMap::<String, (u64, u64)>::new();
    let mut manifest_bytes = None;
    let mut total_bytes = 0_u64;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let name = validate_zip_entry(&file)?;
        if metadata.contains_key(&name) {
            return Err(StorageError::InvalidArchive(
                "duplicate archive entry".to_owned(),
            ));
        }
        if file.size() > limits.maximum_file_bytes {
            return Err(StorageError::ArchiveLimit);
        }
        total_bytes = total_bytes
            .checked_add(file.size())
            .ok_or(StorageError::ArchiveLimit)?;
        if total_bytes > limits.maximum_total_bytes {
            return Err(StorageError::ArchiveLimit);
        }
        let compressed = file.compressed_size();
        if (compressed == 0 && file.size() > 0)
            || (compressed > 0
                && file.size() > compressed.saturating_mul(limits.maximum_compression_ratio))
        {
            return Err(StorageError::ArchiveLimit);
        }
        if name == "project.toml" {
            if file.size() > limits.maximum_manifest_bytes {
                return Err(StorageError::ArchiveLimit);
            }
            let capacity = usize::try_from(file.size()).map_err(|_| StorageError::ArchiveLimit)?;
            let mut bytes = Vec::with_capacity(capacity);
            file.read_to_end(&mut bytes)?;
            manifest_bytes = Some(bytes);
        }
        metadata.insert(name, (file.size(), compressed));
    }
    let manifest_bytes = manifest_bytes
        .ok_or_else(|| StorageError::InvalidArchive("project.toml is missing".to_owned()))?;
    let manifest: ProjectArchiveManifest = toml::from_slice(&manifest_bytes)?;
    validate_archive_manifest(&manifest, &metadata)?;
    for entry in &manifest.entries {
        let mut file = archive.by_name(&entry.path)?;
        let mut hasher = Sha256::new();
        let copied = copy_with_hash(&mut file, std::io::sink(), &mut hasher)?;
        if copied != entry.size || format!("{:x}", hasher.finalize()) != entry.sha256 {
            return Err(StorageError::HashMismatch);
        }
    }
    Ok(ValidatedArchive {
        manifest,
        manifest_bytes,
        archive_sha256,
        file_count: archive.len(),
        total_bytes,
    })
}

fn validate_zip_entry(file: &zip::read::ZipFile<'_, File>) -> Result<String, StorageError> {
    if file.is_dir() || file.is_symlink() || file.encrypted() {
        return Err(StorageError::InvalidArchive(
            "directories, symlinks, and encrypted entries are rejected".to_owned(),
        ));
    }
    let name = file.name().to_owned();
    let enclosed = file
        .enclosed_name()
        .ok_or_else(|| StorageError::InvalidArchive("archive path escapes its root".to_owned()))?;
    if name.is_empty()
        || name.contains(['\\', '\0'])
        || enclosed.as_os_str().to_string_lossy() != name
        || enclosed
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(StorageError::InvalidArchive(
            "archive path is not canonical".to_owned(),
        ));
    }
    Ok(name)
}

fn validate_archive_manifest(
    manifest: &ProjectArchiveManifest,
    metadata: &BTreeMap<String, (u64, u64)>,
) -> Result<(), StorageError> {
    manifest
        .project_id
        .validate()
        .map_err(|error| StorageError::InvalidArchive(error.to_string()))?;
    if manifest.format != "flagdeck.project-export"
        || manifest.format_version != 1
        || manifest.contract_version != flagdeck_domain::CONTRACT_VERSION
        || manifest.schema_version != SCHEMA_VERSION
        || manifest.project_name.trim().is_empty()
        || manifest.project_name.len() > 256
        || manifest.entries.is_empty()
        || manifest.entries.len() + 1 != metadata.len()
    {
        return Err(StorageError::InvalidArchive(
            "manifest header contract failed".to_owned(),
        ));
    }
    let mut names = BTreeSet::new();
    let mut database_entries = 0_usize;
    for entry in &manifest.entries {
        validate_archive_payload_path(&entry.path)?;
        let expected_kind = archive_entry_kind(&entry.path)?;
        let Some((size, _)) = metadata.get(&entry.path) else {
            return Err(StorageError::InvalidArchive(
                "manifest entry is missing from ZIP".to_owned(),
            ));
        };
        if !names.insert(entry.path.clone())
            || *size != entry.size
            || entry.kind != expected_kind
            || entry.sha256.len() != 64
            || !entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(StorageError::InvalidArchive(
                "manifest entry contract failed".to_owned(),
            ));
        }
        if entry.path == "project.sqlite" {
            database_entries += 1;
        }
    }
    if database_entries != 1
        || metadata
            .keys()
            .any(|name| name != "project.toml" && !names.contains(name))
    {
        return Err(StorageError::InvalidArchive(
            "archive contains an unmanifested entry".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_archive_payload_path(path: &str) -> Result<(), StorageError> {
    archive_entry_kind(path).map(|_| ())
}

fn archive_entry_kind(path: &str) -> Result<String, StorageError> {
    if path == "project.sqlite" {
        return Ok("database".to_owned());
    }
    if let Some(value) = path.strip_prefix("blobs/sha256/") {
        let mut parts = value.split('/');
        let prefix = parts.next().unwrap_or_default();
        let digest = parts.next().unwrap_or_default();
        if parts.next().is_none()
            && prefix.len() == 2
            && digest.len() == 64
            && digest.starts_with(prefix)
            && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Ok("blob".to_owned());
        }
    }
    if let Some(value) = path.strip_prefix("artifacts/")
        && let Some(identifier) = value.strip_suffix(".json")
        && ArtifactId::parse(identifier).is_ok()
    {
        return Ok("artifact_manifest".to_owned());
    }
    Err(StorageError::InvalidArchive(
        "manifest path is outside the export allowlist".to_owned(),
    ))
}

pub(crate) fn extract_project_archive(
    archive_path: &Path,
    validated: &ValidatedArchive,
    layout: &WorkspaceLayout,
) -> Result<(), StorageError> {
    write_private_bytes(&layout.root.join("project.toml"), &validated.manifest_bytes)?;
    let mut archive = ZipArchive::new(File::open(archive_path)?)?;
    for entry in &validated.manifest.entries {
        validate_archive_payload_path(&entry.path)?;
        let destination = layout.root.join(&entry.path);
        ensure_descendant(&layout.root, &destination)?;
        let parent = destination.parent().ok_or_else(|| {
            StorageError::InvalidLayout("archive destination lacks parent".to_owned())
        })?;
        create_private_dir(parent)?;
        let mut source = archive.by_name(&entry.path)?;
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&destination)?;
        let mut hasher = Sha256::new();
        let copied = copy_with_hash(&mut source, &mut output, &mut hasher)?;
        output.sync_all()?;
        drop(output);
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
        if copied != entry.size || format!("{:x}", hasher.finalize()) != entry.sha256 {
            return Err(StorageError::HashMismatch);
        }
        sync_directory(parent)?;
    }
    Ok(())
}

pub(crate) fn validate_imported_database(
    database: &Path,
    manifest: &ProjectArchiveManifest,
) -> Result<(), StorageError> {
    let connection = open_reader_connection(database)?;
    let quick_check: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    let version: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if quick_check != "ok" || version != manifest.schema_version {
        return Err(StorageError::InvalidArchive(
            "database integrity or schema check failed".to_owned(),
        ));
    }
    drop(connection);
    let project = project_summary_from_database(database, false)?;
    if project.project_id != manifest.project_id || project.name != manifest.project_name {
        return Err(StorageError::InvalidArchive(
            "database project identity differs from manifest".to_owned(),
        ));
    }
    Ok(())
}

fn copy_with_hash<R: Read, W: Write>(
    reader: &mut R,
    mut writer: W,
    hasher: &mut Sha256,
) -> Result<u64, StorageError> {
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let length = reader.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        writer.write_all(&buffer[..length])?;
        hasher.update(&buffer[..length]);
        copied = copied
            .checked_add(u64::try_from(length).map_err(|_| StorageError::ArchiveLimit)?)
            .ok_or(StorageError::ArchiveLimit)?;
    }
    Ok(copied)
}
