#![allow(clippy::missing_errors_doc)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use fs2::FileExt;
use nix::sys::signal::{Signal, kill};
use nix::sys::stat::{Mode, umask};
use nix::unistd::Pid;
use rusqlite::backup::Backup;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MIN_SAFE_SQLITE_VERSION: i32 = 3_051_003;
const BUSY_TIMEOUT_MS: u64 = 5_000;
const WRITE_QUEUE_CAPACITY: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PragmaEvidence {
    pub sqlite_version: String,
    pub sqlite_version_number: i32,
    pub sqlite_source_id: String,
    pub journal_mode: String,
    pub synchronous: i64,
    pub foreign_keys: i64,
    pub busy_timeout_ms: i64,
    pub trusted_schema: i64,
    pub fts5_match_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressEvidence {
    pub inserted_rows: u64,
    pub reader_threads: usize,
    pub reader_iterations: u64,
    pub writer_queue_capacity: usize,
    pub checkpoints: u64,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEvidence {
    pub snapshot_rows: u64,
    pub final_rows: u64,
    pub active_writes_observed: bool,
    pub foreign_key_violations: u64,
    pub integrity_check: String,
    pub content_hash: String,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashEvidence {
    pub sigkill_acknowledged_rows: u64,
    pub sigkill_rows_recovered: u64,
    pub abort_commit_recovered: bool,
    pub integrity_check: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockEvidence {
    pub second_writer_exit_code: i32,
    pub readonly_exit_code: i32,
    pub writer_rejected: bool,
    pub readonly_succeeded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationEvidence {
    pub failed_migration_rolled_back: bool,
    pub successful_version: i64,
    pub restored_backup_version: i64,
    pub restored_integrity_check: String,
    pub raw_copy_rejected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateEvidence {
    pub status: String,
    pub build_profile: String,
    pub binary_bytes: u64,
    pub binary_sha256: String,
    pub pragma: PragmaEvidence,
    pub stress: StressEvidence,
    pub backup: BackupEvidence,
    pub crash: CrashEvidence,
    pub lock: LockEvidence,
    pub migration: MigrationEvidence,
}

#[derive(Clone)]
pub struct WriterHandle {
    tx: SyncSender<WriteCommand>,
}

pub struct WriterRuntime {
    handle: WriterHandle,
    join: Option<thread::JoinHandle<Result<()>>>,
}

enum WriteCommand {
    Insert {
        id: i64,
        payload: Vec<u8>,
        reply: SyncSender<Result<()>>,
    },
    Checkpoint {
        reply: SyncSender<Result<()>>,
    },
    Shutdown,
}

#[derive(Debug, Clone, Copy)]
pub enum ExportStrategy {
    OnlineBackup,
    RawFilesystemCopy,
}

pub fn set_private_umask() {
    umask(Mode::from_bits_truncate(0o077));
}

pub fn open_configured(path: &Path) -> Result<(Connection, PragmaEvidence)> {
    let connection = Connection::open(path)
        .with_context(|| format!("open SQLite database {}", path.display()))?;
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    let evidence = configure_connection(&connection)?;
    Ok((connection, evidence))
}

pub fn configure_connection(connection: &Connection) -> Result<PragmaEvidence> {
    let version_number = rusqlite::version_number();
    ensure!(
        version_number >= MIN_SAFE_SQLITE_VERSION,
        "SQLite runtime {version_number} is below WAL-safe minimum {MIN_SAFE_SQLITE_VERSION}"
    );

    connection.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    let journal_mode: String =
        connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    connection.execute_batch(
        "PRAGMA synchronous=FULL;
         PRAGMA foreign_keys=ON;
         PRAGMA trusted_schema=OFF;
         PRAGMA wal_autocheckpoint=0;",
    )?;

    let synchronous = pragma_i64(connection, "synchronous")?;
    let foreign_keys = pragma_i64(connection, "foreign_keys")?;
    let busy_timeout_ms = pragma_i64(connection, "busy_timeout")?;
    let trusted_schema = pragma_i64(connection, "trusted_schema")?;
    ensure!(journal_mode.eq_ignore_ascii_case("wal"));
    ensure!(synchronous == 2, "synchronous must read back as FULL (2)");
    ensure!(foreign_keys == 1, "foreign_keys must read back as ON");
    ensure!(
        busy_timeout_ms == i64::try_from(BUSY_TIMEOUT_MS)?,
        "busy_timeout mismatch"
    );
    ensure!(trusted_schema == 0, "trusted_schema must read back as OFF");

    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS parents(
             id INTEGER PRIMARY KEY,
             name TEXT NOT NULL UNIQUE
         );
         CREATE TABLE IF NOT EXISTS events(
             id INTEGER PRIMARY KEY,
             parent_id INTEGER NOT NULL REFERENCES parents(id),
             payload BLOB NOT NULL,
             payload_sha256 TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS schema_migrations(
             version INTEGER PRIMARY KEY,
             applied_at TEXT NOT NULL
         );
         CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(content);
         INSERT OR IGNORE INTO parents(id, name) VALUES(1, 'fixture');",
    )?;
    let existing_fts: i64 =
        connection.query_row("SELECT count(*) FROM notes_fts", [], |row| row.get(0))?;
    if existing_fts == 0 {
        connection.execute(
            "INSERT INTO notes_fts(content) VALUES(?1)",
            ["flagdeck runtime fts gate"],
        )?;
    }
    let fts5_match_count: i64 = connection.query_row(
        "SELECT count(*) FROM notes_fts WHERE notes_fts MATCH 'flagdeck'",
        [],
        |row| row.get(0),
    )?;
    ensure!(fts5_match_count > 0, "FTS5 runtime gate failed");

    let sqlite_source_id: String =
        connection.query_row("SELECT sqlite_source_id()", [], |row| row.get(0))?;
    Ok(PragmaEvidence {
        sqlite_version: rusqlite::version().to_owned(),
        sqlite_version_number: version_number,
        sqlite_source_id,
        journal_mode,
        synchronous,
        foreign_keys,
        busy_timeout_ms,
        trusted_schema,
        fts5_match_count,
    })
}

fn pragma_i64(connection: &Connection, name: &str) -> Result<i64> {
    let allowed = [
        "synchronous",
        "foreign_keys",
        "busy_timeout",
        "trusted_schema",
    ];
    ensure!(allowed.contains(&name), "unsupported PRAGMA name");
    connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .map_err(Into::into)
}

fn open_reader(path: &Path) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    connection.execute_batch(
        "PRAGMA query_only=ON;
         PRAGMA foreign_keys=ON;
         PRAGMA trusted_schema=OFF;",
    )?;
    Ok(connection)
}

impl WriterRuntime {
    #[must_use]
    pub fn start(path: PathBuf) -> Self {
        let (tx, rx) = mpsc::sync_channel(WRITE_QUEUE_CAPACITY);
        let join = thread::spawn(move || writer_loop(&path, &rx));
        Self {
            handle: WriterHandle { tx },
            join: Some(join),
        }
    }

    #[must_use]
    pub fn handle(&self) -> WriterHandle {
        self.handle.clone()
    }

    pub fn shutdown(mut self) -> Result<()> {
        self.handle.tx.send(WriteCommand::Shutdown)?;
        self.join
            .take()
            .ok_or_else(|| anyhow!("writer join handle missing"))?
            .join()
            .map_err(|_| anyhow!("writer thread panicked"))??;
        Ok(())
    }
}

impl WriterHandle {
    pub fn enqueue_insert(&self, id: i64, payload: Vec<u8>) -> Result<Receiver<Result<()>>> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.tx.send(WriteCommand::Insert { id, payload, reply })?;
        Ok(receiver)
    }

    pub fn checkpoint(&self) -> Result<()> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.tx.send(WriteCommand::Checkpoint { reply })?;
        receiver.recv()??;
        Ok(())
    }
}

fn writer_loop(path: &Path, receiver: &Receiver<WriteCommand>) -> Result<()> {
    let (mut connection, _) = open_configured(path)?;
    while let Ok(command) = receiver.recv() {
        match command {
            WriteCommand::Insert { id, payload, reply } => {
                let result = insert_event(&mut connection, id, &payload);
                let _ = reply.send(result);
            }
            WriteCommand::Checkpoint { reply } => {
                let result = checkpoint(&connection);
                let _ = reply.send(result);
            }
            WriteCommand::Shutdown => break,
        }
    }
    Ok(())
}

fn insert_event(connection: &mut Connection, id: i64, payload: &[u8]) -> Result<()> {
    let digest = sha256_hex(payload);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO events(id, parent_id, payload, payload_sha256) VALUES(?1, 1, ?2, ?3)",
        params![id, payload, digest],
    )?;
    transaction.commit()?;
    Ok(())
}

fn checkpoint(connection: &Connection) -> Result<()> {
    let (_busy, _log_frames, _checkpointed): (i64, i64, i64) =
        connection.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    Ok(())
}

pub fn run_stress(path: &Path) -> Result<StressEvidence> {
    let started = Instant::now();
    let runtime = WriterRuntime::start(path.to_path_buf());
    let handle = runtime.handle();
    let done = Arc::new(AtomicBool::new(false));
    let reader_iterations = Arc::new(AtomicU64::new(0));
    let mut readers = Vec::new();

    for _ in 0..4 {
        let reader_path = path.to_path_buf();
        let reader_done = Arc::clone(&done);
        let iterations = Arc::clone(&reader_iterations);
        readers.push(thread::spawn(move || -> Result<()> {
            let connection = open_reader(&reader_path)?;
            while !reader_done.load(Ordering::Acquire) {
                let _: i64 = connection.query_row(
                    "SELECT count(*) FROM events WHERE id >= 0",
                    [],
                    |row| row.get(0),
                )?;
                iterations.fetch_add(1, Ordering::Relaxed);
                thread::yield_now();
            }
            Ok(())
        }));
    }

    let mut replies = Vec::with_capacity(2_000);
    let mut checkpoints = 0_u64;
    for id in 1_i64..=2_000_i64 {
        let payload = deterministic_payload(id, 4 * 1_024);
        replies.push(handle.enqueue_insert(id, payload)?);
        if id % 100 == 0 {
            handle.checkpoint()?;
            checkpoints += 1;
        }
    }
    for reply in replies {
        reply.recv()??;
    }
    handle.checkpoint()?;
    checkpoints += 1;
    done.store(true, Ordering::Release);
    for reader in readers {
        reader
            .join()
            .map_err(|_| anyhow!("reader thread panicked"))??;
    }
    runtime.shutdown()?;

    let reader = open_reader(path)?;
    let count = u64::try_from(reader.query_row("SELECT count(*) FROM events", [], |row| {
        row.get::<_, i64>(0)
    })?)?;
    ensure!(count == 2_000, "stress row count mismatch");
    Ok(StressEvidence {
        inserted_rows: count,
        reader_threads: 4,
        reader_iterations: reader_iterations.load(Ordering::Relaxed),
        writer_queue_capacity: WRITE_QUEUE_CAPACITY,
        checkpoints,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

pub fn run_online_backup(path: &Path, snapshot_path: &Path) -> Result<BackupEvidence> {
    let started = Instant::now();
    let runtime = WriterRuntime::start(path.to_path_buf());
    let writer = runtime.handle();
    let completed = Arc::new(AtomicU64::new(0));
    let completed_by_writer = Arc::clone(&completed);
    let producer = thread::spawn(move || -> Result<()> {
        for id in 10_000_i64..10_400_i64 {
            let reply = writer.enqueue_insert(id, deterministic_payload(id, 64 * 1_024))?;
            reply.recv()??;
            completed_by_writer.fetch_add(1, Ordering::Release);
            thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    });

    wait_until(Duration::from_secs(10), || {
        completed.load(Ordering::Acquire) >= 5
    })?;
    let writes_before = completed.load(Ordering::Acquire);
    online_backup(path, snapshot_path, 5, Duration::from_millis(1))?;
    let writes_after = completed.load(Ordering::Acquire);
    producer
        .join()
        .map_err(|_| anyhow!("backup producer panicked"))??;
    runtime.shutdown()?;

    let snapshot = verify_database(snapshot_path)?;
    let final_db = verify_database(path)?;
    ensure!(
        writes_after > writes_before,
        "backup did not overlap active writes"
    );
    ensure!(snapshot.rows <= final_db.rows);
    Ok(BackupEvidence {
        snapshot_rows: snapshot.rows,
        final_rows: final_db.rows,
        active_writes_observed: writes_after > writes_before,
        foreign_key_violations: snapshot.foreign_key_violations,
        integrity_check: snapshot.integrity_check,
        content_hash: snapshot.content_hash,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

fn online_backup(
    source_path: &Path,
    destination_path: &Path,
    pages_per_step: i32,
    pause: Duration,
) -> Result<()> {
    if destination_path.exists() {
        fs::remove_file(destination_path)?;
    }
    let source = open_reader(source_path)?;
    let mut destination = Connection::open(destination_path)?;
    if destination_path.exists() {
        fs::set_permissions(destination_path, fs::Permissions::from_mode(0o600))?;
    }
    let backup = Backup::new(&source, &mut destination)?;
    backup.run_to_completion(pages_per_step, pause, None)?;
    drop(backup);
    destination.execute_batch("PRAGMA journal_mode=DELETE;")?;
    Ok(())
}

struct DatabaseVerification {
    rows: u64,
    foreign_key_violations: u64,
    integrity_check: String,
    content_hash: String,
}

fn verify_database(path: &Path) -> Result<DatabaseVerification> {
    let connection = open_reader(path)?;
    let integrity_check: String =
        connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    ensure!(integrity_check == "ok");
    let foreign_key_violations = u64::try_from(connection.query_row(
        "SELECT count(*) FROM pragma_foreign_key_check",
        [],
        |row| row.get::<_, i64>(0),
    )?)?;
    ensure!(foreign_key_violations == 0);
    let schema_count: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name IN ('events', 'notes_fts')",
        [],
        |row| row.get(0),
    )?;
    ensure!(schema_count == 2, "snapshot schema is incomplete");

    let mut statement =
        connection.prepare("SELECT id, payload, payload_sha256 FROM events ORDER BY id")?;
    let mut rows = statement.query([])?;
    let mut count = 0_u64;
    let mut aggregate = Sha256::new();
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let payload: Vec<u8> = row.get(1)?;
        let stored_hash: String = row.get(2)?;
        ensure!(sha256_hex(&payload) == stored_hash, "row hash mismatch");
        aggregate.update(id.to_le_bytes());
        aggregate.update(u64::try_from(payload.len())?.to_le_bytes());
        aggregate.update(&payload);
        count += 1;
    }
    Ok(DatabaseVerification {
        rows: count,
        foreign_key_violations,
        integrity_check,
        content_hash: bytes_to_hex(&aggregate.finalize()),
    })
}

pub fn crash_writer(path: &Path, ack_path: &Path, abort_after_first: bool) -> Result<()> {
    set_private_umask();
    let (mut connection, _) = open_configured(path)?;
    let mut ack = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(ack_path)?;
    let start = if abort_after_first {
        900_000_i64
    } else {
        500_000_i64
    };
    for offset in 0_i64.. {
        let id = start + offset;
        insert_event(&mut connection, id, &deterministic_payload(id, 1_024))?;
        writeln!(ack, "{id}")?;
        ack.sync_data()?;
        if abort_after_first {
            std::process::abort();
        }
        thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}

pub fn run_crash_recovery(
    path: &Path,
    executable: &Path,
    directory: &Path,
) -> Result<CrashEvidence> {
    let ack_path = directory.join("sigkill-acks.txt");
    let mut sigkill_child = spawn_child(
        executable,
        &["crash-writer", path_arg(path)?, path_arg(&ack_path)?],
    )?;
    wait_until(Duration::from_secs(10), || {
        acknowledged_ids(&ack_path).is_ok_and(|ids| ids.len() >= 25)
    })?;
    kill_child(&mut sigkill_child, Signal::SIGKILL)?;
    let acknowledged = acknowledged_ids(&ack_path)?;
    ensure!(!acknowledged.is_empty());
    let reader = open_reader(path)?;
    for id in &acknowledged {
        let exists: i64 = reader.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE id=?1)",
            [id],
            |row| row.get(0),
        )?;
        ensure!(exists == 1, "acknowledged commit {id} was lost");
    }
    let sigkill_rows_recovered = u64::try_from(reader.query_row(
        "SELECT count(*) FROM events WHERE id >= 500000 AND id < 900000",
        [],
        |row| row.get::<_, i64>(0),
    )?)?;
    drop(reader);

    let abort_ack = directory.join("abort-acks.txt");
    let mut abort_child = spawn_child(
        executable,
        &["abort-writer", path_arg(path)?, path_arg(&abort_ack)?],
    )?;
    let abort_status = abort_child.wait()?;
    ensure!(
        !abort_status.success(),
        "abort child unexpectedly succeeded"
    );
    let reader = open_reader(path)?;
    let abort_commit_recovered: bool = reader.query_row(
        "SELECT EXISTS(SELECT 1 FROM events WHERE id=900000)",
        [],
        |row| row.get(0),
    )?;
    ensure!(abort_commit_recovered, "commit before abort was lost");
    let integrity_check: String =
        reader.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    ensure!(integrity_check == "ok");
    Ok(CrashEvidence {
        sigkill_acknowledged_rows: u64::try_from(acknowledged.len())?,
        sigkill_rows_recovered,
        abort_commit_recovered,
        integrity_check,
    })
}

fn spawn_child(executable: &Path, arguments: &[&str]) -> Result<Child> {
    Command::new(executable)
        .args(arguments)
        .env_clear()
        .env("LANG", "C.UTF-8")
        .spawn()
        .with_context(|| format!("spawn {}", executable.display()))
}

fn kill_child(child: &mut Child, signal: Signal) -> Result<ExitStatus> {
    kill(Pid::from_raw(i32::try_from(child.id())?), signal)?;
    Ok(child.wait()?)
}

fn acknowledged_ids(path: &Path) -> Result<Vec<i64>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut input = String::new();
    File::open(path)?.read_to_string(&mut input)?;
    input
        .lines()
        .map(|line| line.parse::<i64>().map_err(Into::into))
        .collect()
}

pub fn lock_holder(lock_path: &Path, ready_path: &Path, hold_ms: u64) -> Result<()> {
    set_private_umask();
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(lock_path)?;
    file.try_lock_exclusive()?;
    atomic_write(ready_path, b"ready\n")?;
    thread::sleep(Duration::from_millis(hold_ms));
    FileExt::unlock(&file)?;
    Ok(())
}

pub fn lock_probe(mode: &str, lock_path: &Path, database_path: &Path) -> Result<i32> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(lock_path)?;
    match file.try_lock_exclusive() {
        Ok(()) => {
            FileExt::unlock(&file)?;
            Ok(0)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            if mode == "readonly" {
                let connection = open_reader(database_path)?;
                let _: i64 =
                    connection.query_row("SELECT count(*) FROM events", [], |row| row.get(0))?;
                Ok(0)
            } else {
                Ok(73)
            }
        }
        Err(error) => Err(error.into()),
    }
}

pub fn run_lock_test(
    database_path: &Path,
    executable: &Path,
    directory: &Path,
) -> Result<LockEvidence> {
    let lock_path = directory.join(".flagdeck.lock");
    let ready_path = directory.join("lock-ready");
    let mut holder = spawn_child(
        executable,
        &[
            "lock-holder",
            path_arg(&lock_path)?,
            path_arg(&ready_path)?,
            "10000",
        ],
    )?;
    wait_until(Duration::from_secs(5), || ready_path.exists())?;

    let writer = Command::new(executable)
        .args([
            "lock-probe",
            "writer",
            path_arg(&lock_path)?,
            path_arg(database_path)?,
        ])
        .env_clear()
        .env("LANG", "C.UTF-8")
        .status()?;
    let readonly = Command::new(executable)
        .args([
            "lock-probe",
            "readonly",
            path_arg(&lock_path)?,
            path_arg(database_path)?,
        ])
        .env_clear()
        .env("LANG", "C.UTF-8")
        .status()?;
    let _ = kill_child(&mut holder, Signal::SIGTERM);
    let writer_code = writer.code().unwrap_or(-1);
    let readonly_code = readonly.code().unwrap_or(-1);
    ensure!(writer_code == 73, "second writer was not rejected");
    ensure!(readonly_code == 0, "explicit readonly mode failed");
    Ok(LockEvidence {
        second_writer_exit_code: writer_code,
        readonly_exit_code: readonly_code,
        writer_rejected: writer_code == 73,
        readonly_succeeded: readonly_code == 0,
    })
}

pub fn run_migration_test(directory: &Path) -> Result<MigrationEvidence> {
    let database_path = directory.join("migration.sqlite");
    let backup_path = directory.join("migration-v1.backup.sqlite");
    let restored_path = directory.join("migration-restored.sqlite");
    let (mut connection, _) = open_configured(&database_path)?;
    connection.execute_batch(
        "PRAGMA user_version=1;
         INSERT OR IGNORE INTO schema_migrations(version, applied_at)
         VALUES(1, 'fixture-v1');",
    )?;
    insert_event(&mut connection, 42, b"migration-fixture")?;
    drop(connection);
    create_export_snapshot(&database_path, &backup_path, ExportStrategy::OnlineBackup)?;

    let mut connection = Connection::open(&database_path)?;
    configure_connection(&connection)?;
    let failed = {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = transaction.execute_batch(
            "CREATE TABLE migration_partial(id INTEGER PRIMARY KEY);
             INSERT INTO table_that_does_not_exist(id) VALUES(1);
             PRAGMA user_version=2;",
        );
        if let Ok(()) = result {
            transaction.commit()?;
            false
        } else {
            transaction.rollback()?;
            true
        }
    };
    ensure!(failed, "failure injection did not fail");
    let partial_table: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name='migration_partial'",
        [],
        |row| row.get(0),
    )?;
    let version_after_failure: i64 =
        connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let failed_migration_rolled_back = partial_table == 0 && version_after_failure == 1;
    ensure!(failed_migration_rolled_back);

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TABLE migration_v2(id INTEGER PRIMARY KEY, note TEXT NOT NULL);
         INSERT INTO schema_migrations(version, applied_at) VALUES(2, 'fixture-v2');
         PRAGMA user_version=2;",
    )?;
    transaction.commit()?;
    let successful_version: i64 =
        connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    drop(connection);

    let mut restored = Connection::open(&restored_path)?;
    restored.restore(rusqlite::MAIN_DB, &backup_path, None::<fn(_)>)?;
    let restored_backup_version: i64 =
        restored.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let restored_integrity_check: String =
        restored.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let restored_row: i64 =
        restored.query_row("SELECT count(*) FROM events WHERE id=42", [], |row| {
            row.get(0)
        })?;
    ensure!(restored_backup_version == 1);
    ensure!(restored_integrity_check == "ok");
    ensure!(restored_row == 1);

    let raw_copy_rejected = create_export_snapshot(
        &database_path,
        &directory.join("forbidden-copy.sqlite"),
        ExportStrategy::RawFilesystemCopy,
    )
    .is_err();
    ensure!(raw_copy_rejected);
    Ok(MigrationEvidence {
        failed_migration_rolled_back,
        successful_version,
        restored_backup_version,
        restored_integrity_check,
        raw_copy_rejected,
    })
}

pub fn create_export_snapshot(
    source: &Path,
    destination: &Path,
    strategy: ExportStrategy,
) -> Result<()> {
    match strategy {
        ExportStrategy::OnlineBackup => {
            online_backup(source, destination, 16, Duration::from_millis(1))
        }
        ExportStrategy::RawFilesystemCopy => {
            bail!("active project.sqlite export requires SQLite Online Backup API")
        }
    }
}

pub fn run_full_gate(directory: &Path, executable: &Path) -> Result<GateEvidence> {
    set_private_umask();
    fs::create_dir_all(directory)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    let database_path = directory.join("project.sqlite");
    let snapshot_path = directory.join("project.snapshot.sqlite");
    let (connection, pragma) = open_configured(&database_path)?;
    drop(connection);
    let stress = run_stress(&database_path)?;
    let backup = run_online_backup(&database_path, &snapshot_path)?;
    let crash = run_crash_recovery(&database_path, executable, directory)?;
    let lock = run_lock_test(&database_path, executable, directory)?;
    let migration = run_migration_test(directory)?;
    Ok(GateEvidence {
        status: "PASS".to_owned(),
        build_profile: if cfg!(debug_assertions) {
            "debug".to_owned()
        } else {
            "release".to_owned()
        },
        binary_bytes: fs::metadata(executable)?.len(),
        binary_sha256: sha256_file(executable)?,
        pragma,
        stress,
        backup,
        crash,
        lock,
        migration,
    })
}

pub fn write_evidence(path: &Path, evidence: &GateEvidence) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("evidence path has no parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .ok_or_else(|| anyhow!("evidence path has no filename"))?
            .to_string_lossy()
    ));
    let bytes = serde_json::to_vec_pretty(evidence)?;
    atomic_write(&temporary, &bytes)?;
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn wait_until<F>(timeout: Duration, mut predicate: F) -> Result<()>
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    bail!("condition timed out after {} ms", timeout.as_millis())
}

fn deterministic_payload(id: i64, length: usize) -> Vec<u8> {
    let seed = id.to_le_bytes();
    (0..length)
        .map(|index| seed[index % seed.len()] ^ u8::try_from(index % 251).unwrap_or(0))
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    bytes_to_hex(&Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        hasher.update(&buffer[..length]);
    }
    Ok(bytes_to_hex(&hasher.finalize()))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn path_arg(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("path is not valid UTF-8: {}", path.display()))
}
