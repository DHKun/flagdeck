//! 项目工作区：目录布局（`WorkspaceLayout`）、独占 flock（`WorkspaceLock`）与锁元数据。
//! 从单文件的 storage crate 里析出。文件系统权限与锁的底层辅助（`create_private_dir`、
//! `sync_directory`、`current_process_start_ticks`）仍在 crate 根，这里经 `crate::` 引用。

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use flagdeck_domain::{ProjectId, Timestamp};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{StorageError, create_private_dir, current_process_start_ticks, sync_directory};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockMetadata {
    pub instance_id: String,
    pub pid: u32,
    pub process_start_ticks: u64,
    pub hostname: String,
    pub acquired_at: Timestamp,
}

#[derive(Debug, Clone)]
pub struct WorkspaceLayout {
    pub root: PathBuf,
    pub database: PathBuf,
    pub lock: PathBuf,
    pub blobs: PathBuf,
    pub artifacts: PathBuf,
    pub scans: PathBuf,
    pub notes: PathBuf,
    pub exports: PathBuf,
    pub backups: PathBuf,
    pub runtime: PathBuf,
    pub tmp: PathBuf,
    pub browser_home: PathBuf,
    pub browser_profile: PathBuf,
    pub mitm_confdir: PathBuf,
    pub metasploit: PathBuf,
}

impl WorkspaceLayout {
    #[must_use]
    pub fn for_project(workspaces_root: &Path, project_id: &ProjectId) -> Self {
        Self::for_root(workspaces_root.join(&project_id.0))
    }

    #[must_use]
    pub(crate) fn for_root(root: PathBuf) -> Self {
        Self {
            database: root.join("project.sqlite"),
            lock: root.join(".flagdeck.lock"),
            blobs: root.join("blobs/sha256"),
            artifacts: root.join("artifacts"),
            scans: root.join("scans"),
            notes: root.join("notes"),
            exports: root.join("exports"),
            backups: root.join("backups"),
            runtime: root.join("runtime"),
            tmp: root.join("tmp"),
            browser_home: root.join("browser-home"),
            browser_profile: root.join("browser-profile"),
            mitm_confdir: root.join("mitm-confdir"),
            metasploit: root.join("metasploit"),
            root,
        }
    }

    pub(crate) fn create(&self) -> Result<(), StorageError> {
        create_private_dir(&self.root)?;
        for directory in [
            &self.blobs,
            &self.artifacts,
            &self.scans,
            &self.notes,
            &self.exports,
            &self.backups,
            &self.runtime,
            &self.tmp,
            &self.browser_home,
            &self.browser_profile,
            &self.mitm_confdir,
            &self.metasploit,
        ] {
            create_private_dir(directory)?;
        }
        sync_directory(&self.root)?;
        Ok(())
    }

    pub fn verify(&self) -> Result<(), StorageError> {
        for directory in [
            &self.root,
            &self.blobs,
            &self.artifacts,
            &self.scans,
            &self.notes,
            &self.exports,
            &self.backups,
            &self.runtime,
            &self.tmp,
            &self.browser_home,
            &self.browser_profile,
            &self.mitm_confdir,
            &self.metasploit,
        ] {
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(StorageError::InvalidLayout(directory.display().to_string()));
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(StorageError::InvalidLayout(format!(
                    "{} mode {:o}",
                    directory.display(),
                    metadata.permissions().mode() & 0o777
                )));
            }
        }
        if self.database.exists() && fs::metadata(&self.database)?.permissions().mode() & 0o077 != 0
        {
            return Err(StorageError::InvalidLayout(
                self.database.display().to_string(),
            ));
        }
        Ok(())
    }
}

pub(crate) struct WorkspaceLock {
    file: File,
}

impl WorkspaceLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self, StorageError> {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                StorageError::WriterLocked
            } else {
                StorageError::Io(error)
            }
        })?;
        let metadata = LockMetadata {
            instance_id: Uuid::new_v4().to_string(),
            pid: std::process::id(),
            process_start_ticks: current_process_start_ticks().unwrap_or(0),
            hostname: fs::read_to_string("/etc/hostname")
                .unwrap_or_else(|_| "unknown".to_owned())
                .trim()
                .to_owned(),
            acquired_at: Timestamp::now(),
        };
        file.set_len(0)?;
        file.write_all(&serde_json::to_vec_pretty(&metadata)?)?;
        file.sync_all()?;
        Ok(Self { file })
    }
}

impl Drop for WorkspaceLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}
