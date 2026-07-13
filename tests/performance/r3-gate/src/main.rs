#![allow(
    clippy::cast_precision_loss,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use flagdeck_adapter_host::{AdapterHost, AdapterHostConfig, HostError};
use flagdeck_adapter_protocol::{JSON_RPC_VERSION, JsonRpcRequest, RequestMetadata};
use flagdeck_domain::{
    CommandSpec, CommandSpecId, ExportPolicy, ResourceLimits, RiskLevel, SecretTransport,
    Sensitivity, SupervisorBackend,
};
use flagdeck_exec::{
    cancel_managed, start_managed_with_backend, start_one_shot_credential, systemd_user_available,
};
use flagdeck_storage::{ArtifactWriteRequest, ProjectStore, SCHEMA_VERSION};
use nix::sys::resource::{UsageWho, getrusage};
use nix::sys::time::TimeValLike;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

const ITERATIONS: usize = 10;
const ARTIFACT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Distribution {
    runs: usize,
    passed: usize,
    samples_millis: Vec<f64>,
    min_millis: f64,
    p50_millis: f64,
    p95_millis: f64,
    max_millis: f64,
    mean_millis: f64,
}

impl Distribution {
    fn from_samples(samples: Vec<f64>) -> Result<Self> {
        ensure!(
            samples.len() == ITERATIONS,
            "suite produced an incomplete sample set"
        );
        let mut sorted = samples.clone();
        sorted.sort_by(f64::total_cmp);
        let sum = sorted.iter().sum::<f64>();
        Ok(Self {
            runs: sorted.len(),
            passed: sorted.len(),
            samples_millis: samples,
            min_millis: sorted[0],
            p50_millis: sorted[4],
            p95_millis: sorted[9],
            max_millis: sorted[9],
            mean_millis: sum / sorted.len() as f64,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct ResourceSnapshot {
    user_micros: i64,
    system_micros: i64,
    child_user_micros: i64,
    child_system_micros: i64,
    block_writes: i64,
    child_block_writes: i64,
    process_write_bytes: u64,
    self_peak_rss_kib: i64,
    child_peak_rss_kib: i64,
}

impl ResourceSnapshot {
    fn capture() -> Result<Self> {
        let own = getrusage(UsageWho::RUSAGE_SELF)?;
        let children = getrusage(UsageWho::RUSAGE_CHILDREN)?;
        Ok(Self {
            user_micros: own.user_time().num_microseconds(),
            system_micros: own.system_time().num_microseconds(),
            child_user_micros: children.user_time().num_microseconds(),
            child_system_micros: children.system_time().num_microseconds(),
            block_writes: own.block_writes(),
            child_block_writes: children.block_writes(),
            process_write_bytes: proc_write_bytes()?,
            self_peak_rss_kib: own.max_rss(),
            child_peak_rss_kib: children.max_rss(),
        })
    }

    fn delta(self, after: Self) -> ResourceDelta {
        ResourceDelta {
            cpu_user_millis: (after.user_micros - self.user_micros) as f64 / 1000.0,
            cpu_system_millis: (after.system_micros - self.system_micros) as f64 / 1000.0,
            child_cpu_user_millis: (after.child_user_micros - self.child_user_micros) as f64
                / 1000.0,
            child_cpu_system_millis: (after.child_system_micros - self.child_system_micros) as f64
                / 1000.0,
            block_writes: after.block_writes - self.block_writes,
            child_block_writes: after.child_block_writes - self.child_block_writes,
            process_write_bytes: after
                .process_write_bytes
                .saturating_sub(self.process_write_bytes),
            self_peak_rss_kib: after.self_peak_rss_kib,
            child_peak_rss_kib: after.child_peak_rss_kib,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceDelta {
    cpu_user_millis: f64,
    cpu_system_millis: f64,
    child_cpu_user_millis: f64,
    child_cpu_system_millis: f64,
    block_writes: i64,
    child_block_writes: i64,
    process_write_bytes: u64,
    self_peak_rss_kib: i64,
    child_peak_rss_kib: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SuiteReport {
    available: bool,
    distribution: Option<Distribution>,
    logical_output_bytes: u64,
    resources: ResourceDelta,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GateReport {
    schema: String,
    generated_at: String,
    profile: String,
    iterations: usize,
    environment: BTreeMap<String, String>,
    fixtures: BTreeMap<String, Value>,
    suites: BTreeMap<String, SuiteReport>,
    assertions: BTreeMap<String, bool>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let root = workspace_root()?;
    let mut suites = BTreeMap::new();
    let pgid = cancellation_suite(SupervisorBackend::PgidFallback).await?;
    let systemd = if systemd_user_available().await {
        cancellation_suite(SupervisorBackend::SystemdUserService).await?
    } else {
        unavailable_suite()?
    };
    let adapter = adapter_suite(&root).await?;
    let credential = credential_suite().await?;
    let (export, import, artifact_sha256) = archive_suite()?;
    suites.insert("adapterCrashRecovery".to_owned(), adapter);
    suites.insert("credentialDelivery".to_owned(), credential);
    suites.insert("pgidCancellation".to_owned(), pgid.clone());
    suites.insert("projectExport".to_owned(), export);
    suites.insert("projectImport".to_owned(), import);
    suites.insert("systemdCancellation".to_owned(), systemd.clone());

    let fixture_paths = [
        (
            "adapterMessages",
            "tests/fixtures/r3/adapter-protocol/messages.json",
        ),
        ("adapterWorker", "tests/fixtures/r3/adapter_worker.py"),
        ("slowTarget", "tests/fixtures/r2/target_server.py"),
    ];
    let mut fixtures = BTreeMap::from([
        ("artifactBytes".to_owned(), json!(ARTIFACT_BYTES)),
        ("artifactSha256".to_owned(), json!(artifact_sha256)),
    ]);
    for (name, relative) in fixture_paths {
        let path = root.join(relative);
        fixtures.insert(
            name.to_owned(),
            json!({"path": relative, "sha256": digest_file(&path)?}),
        );
    }

    let systemd_available = systemd.available;
    let pgid_under_deadline = pgid
        .distribution
        .as_ref()
        .is_some_and(|value| value.max_millis <= 5_000.0);
    let systemd_under_deadline = systemd
        .distribution
        .as_ref()
        .is_some_and(|value| value.max_millis <= 5_000.0);
    let assertions = BTreeMap::from([
        (
            "allSuitesHaveTenPassingRuns".to_owned(),
            suites.values().all(|suite| {
                !suite.available
                    || suite
                        .distribution
                        .as_ref()
                        .is_some_and(|value| value.runs == ITERATIONS && value.passed == ITERATIONS)
            }),
        ),
        (
            "pgidCleanupWithinFiveSeconds".to_owned(),
            pgid_under_deadline,
        ),
        ("systemdBackendAvailable".to_owned(), systemd_available),
        (
            "systemdCleanupWithinFiveSeconds".to_owned(),
            systemd_under_deadline,
        ),
    ]);
    ensure!(
        assertions.values().all(|value| *value),
        "R3 reliability assertion failed"
    );

    let report = GateReport {
        schema: "flagdeck.performance.r3.v1".to_owned(),
        generated_at: flagdeck_domain::Timestamp::now().0,
        profile: if cfg!(debug_assertions) {
            "debug".to_owned()
        } else {
            "release".to_owned()
        },
        iterations: ITERATIONS,
        environment: environment(&root)?,
        fixtures,
        suites,
        assertions,
    };
    let bytes = serde_json::to_vec_pretty(&report)?;
    if let Some(output) = output_path()? {
        write_atomic(&output, &bytes)?;
        println!("{}", output.display());
    } else {
        println!("{}", String::from_utf8(bytes)?);
    }
    Ok(())
}

async fn cancellation_suite(backend: SupervisorBackend) -> Result<SuiteReport> {
    let before = ResourceSnapshot::capture()?;
    let mut samples = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let temporary = tempfile::tempdir()?;
        let spec = fixture_spec(temporary.path())?;
        let execution = start_managed_with_backend(
            &spec,
            &temporary.path().join("stdout.log"),
            &temporary.path().join("stderr.log"),
            backend,
        )
        .await?;
        let identity = execution.identity().clone();
        let started = Instant::now();
        let cancellation = cancel_managed(&identity, Duration::from_millis(50)).await?;
        samples.push(started.elapsed().as_secs_f64() * 1000.0);
        ensure!(
            cancellation.cleanup_verified,
            "cancellation cleanup was unverified"
        );
        ensure!(
            cancellation.residual_processes == 0,
            "cancellation left a process"
        );
        ensure!(
            cancellation.duration_millis <= 5_000,
            "cancellation exceeded deadline"
        );
        let _ = execution.wait().await?;
    }
    let after = ResourceSnapshot::capture()?;
    Ok(SuiteReport {
        available: true,
        distribution: Some(Distribution::from_samples(samples)?),
        logical_output_bytes: 0,
        resources: before.delta(after),
    })
}

async fn adapter_suite(root: &Path) -> Result<SuiteReport> {
    let before = ResourceSnapshot::capture()?;
    let script = root.join("tests/fixtures/r3/adapter_worker.py");
    let mut config = AdapterHostConfig::new(PathBuf::from("/usr/bin/python3"), root);
    config.arguments = vec![script.to_string_lossy().into_owned()];
    config.stderr_limit_bytes = 1024;
    let host = AdapterHost::new(config)?;
    let mut samples = Vec::with_capacity(ITERATIONS);
    for index in 0..ITERATIONS {
        let started = Instant::now();
        let mut crashed = host.spawn()?;
        let error = crashed.request(&adapter_request("crash", index)).await;
        ensure!(
            matches!(error, Err(HostError::WorkerCrashed { code: Some(23) })),
            "fixture worker did not report its crash"
        );
        let _ = crashed.shutdown().await?;
        let mut healthy = host.spawn()?;
        let response = healthy
            .request(&adapter_request("health", index + ITERATIONS))
            .await?;
        ensure!(
            response.result == Some(json!({"healthy": true})),
            "worker failed recovery"
        );
        let _ = healthy.shutdown().await?;
        samples.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    let after = ResourceSnapshot::capture()?;
    Ok(SuiteReport {
        available: true,
        distribution: Some(Distribution::from_samples(samples)?),
        logical_output_bytes: 0,
        resources: before.delta(after),
    })
}

async fn credential_suite() -> Result<SuiteReport> {
    let before = ResourceSnapshot::capture()?;
    let mut samples = Vec::with_capacity(ITERATIONS);
    for index in 0..ITERATIONS {
        let temporary = tempfile::tempdir()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
        let payload = format!("r3-credential-{index:02}-{}", std::process::id()).into_bytes();
        let started = Instant::now();
        let server = start_one_shot_credential(
            temporary.path(),
            "flagdeck.r3-gate",
            payload.clone(),
            Duration::from_secs(1),
        )?;
        let source = server.socket_path().to_path_buf();
        let mut stream = tokio::net::UnixStream::connect(&source).await?;
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await?;
        let evidence = server.wait().await?;
        samples.push(started.elapsed().as_secs_f64() * 1000.0);
        ensure!(received == payload, "credential payload changed");
        ensure!(
            evidence.source_removed && !source.exists(),
            "credential source remained"
        );
    }
    let after = ResourceSnapshot::capture()?;
    Ok(SuiteReport {
        available: true,
        distribution: Some(Distribution::from_samples(samples)?),
        logical_output_bytes: 0,
        resources: before.delta(after),
    })
}

fn archive_suite() -> Result<(SuiteReport, SuiteReport, String)> {
    let payload = (0..ARTIFACT_BYTES)
        .map(|index| u8::try_from(index % 251).unwrap_or_default())
        .collect::<Vec<_>>();
    let payload_sha256 = digest_bytes(&payload);
    let before_export = ResourceSnapshot::capture()?;
    let mut export_samples = Vec::with_capacity(ITERATIONS);
    let mut import_samples = Vec::with_capacity(ITERATIONS);
    let mut export_bytes = 0_u64;
    let mut import_bytes = 0_u64;
    let mut prepared = Vec::with_capacity(ITERATIONS);
    for index in 0..ITERATIONS {
        let temporary = tempfile::tempdir()?;
        let source_root = temporary.path().join("source");
        let (store, _) = ProjectStore::create(&source_root, &format!("R3 archive {index}"))?;
        store.commit_artifact(
            &ArtifactWriteRequest {
                logical_name: "fixture.bin".to_owned(),
                mime: "application/octet-stream".to_owned(),
                sensitivity: Sensitivity::Normal,
                export_policy: ExportPolicy::Include,
                source_job_id: None,
                source_message_id: None,
                expected_size: Some(u64::try_from(payload.len())?),
                expected_sha256: Some(payload_sha256.clone()),
            },
            payload.as_slice(),
        )?;
        let started = Instant::now();
        let exported = store.export_project(false)?;
        export_bytes = export_bytes.saturating_add(exported.size);
        export_samples.push(started.elapsed().as_secs_f64() * 1000.0);
        let archive = store.layout().exports.join(&exported.archive_name);
        drop(store);
        prepared.push((temporary, archive));
    }
    let after_export = ResourceSnapshot::capture()?;
    let before_import = after_export;
    for (temporary, archive) in &prepared {
        let destination = temporary.path().join("destination");
        let started = Instant::now();
        let imported = ProjectStore::import_project_archive(&destination, archive)?;
        import_bytes = import_bytes.saturating_add(imported.extracted_bytes);
        import_samples.push(started.elapsed().as_secs_f64() * 1000.0);
        ensure!(imported.file_count >= 4, "archive omitted required entries");
        ensure!(
            imported.extracted_bytes >= u64::try_from(ARTIFACT_BYTES)?,
            "archive was truncated"
        );
    }
    let after_import = ResourceSnapshot::capture()?;
    Ok((
        SuiteReport {
            available: true,
            distribution: Some(Distribution::from_samples(export_samples)?),
            logical_output_bytes: export_bytes,
            resources: before_export.delta(after_export),
        },
        SuiteReport {
            available: true,
            distribution: Some(Distribution::from_samples(import_samples)?),
            logical_output_bytes: import_bytes,
            resources: before_import.delta(after_import),
        },
        payload_sha256,
    ))
}

fn unavailable_suite() -> Result<SuiteReport> {
    let snapshot = ResourceSnapshot::capture()?;
    Ok(SuiteReport {
        available: false,
        distribution: None,
        logical_output_bytes: 0,
        resources: snapshot.delta(snapshot),
    })
}

fn fixture_spec(cwd: &Path) -> Result<CommandSpec> {
    Ok(CommandSpec {
        command_spec_id: CommandSpecId::new(),
        tool_id: "r3-cancellation-fixture".to_owned(),
        tool_version: "system".to_owned(),
        tool_sha256: digest_file(Path::new("/usr/bin/sleep"))?,
        program: "/usr/bin/sleep".to_owned(),
        argv_exec: vec!["30".to_owned()],
        argv_redacted: vec!["30".to_owned()],
        env_exec: BTreeMap::from([("LANG".to_owned(), "C.UTF-8".to_owned())]),
        env_redacted: BTreeMap::from([("LANG".to_owned(), "C.UTF-8".to_owned())]),
        secret_transport: SecretTransport::None,
        secret_inputs: Vec::new(),
        cwd: cwd.display().to_string(),
        environment_allowlist: vec!["LANG".to_owned()],
        timeout_millis: 60_000,
        stop_grace_millis: 50,
        expected_outputs: Vec::new(),
        risk_level: RiskLevel::L0,
        scope_id: None,
        sandbox_profile: "r3-gate".to_owned(),
        resource_limits: ResourceLimits::default(),
        network_isolation: "none".to_owned(),
    })
}

fn adapter_request(method: &str, index: usize) -> JsonRpcRequest {
    let deadline = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .saturating_add(5_000)
        .to_string();
    JsonRpcRequest {
        jsonrpc: JSON_RPC_VERSION.to_owned(),
        id: format!("r3-{method}-{index}"),
        method: method.to_owned(),
        metadata: RequestMetadata {
            core_job_id: format!("core-r3-{index}"),
            adapter_job_id: None,
            idempotency_key: format!("idem-r3-{method}-{index}"),
            deadline_unix_millis: deadline,
        },
        params: Value::Null,
    }
}

fn environment(root: &Path) -> Result<BTreeMap<String, String>> {
    Ok(BTreeMap::from([
        ("architecture".to_owned(), std::env::consts::ARCH.to_owned()),
        ("cargo".to_owned(), command_version("cargo", &["--version"])),
        (
            "cargoLockSha256".to_owned(),
            digest_file(&root.join("Cargo.lock"))?,
        ),
        ("kernel".to_owned(), command_version("uname", &["-r"])),
        ("rustc".to_owned(), command_version("rustc", &["--version"])),
        ("selinux".to_owned(), command_version("getenforce", &[])),
        ("sqlite".to_owned(), rusqlite::version().to_owned()),
        ("storageSchema".to_owned(), SCHEMA_VERSION.to_string()),
        (
            "systemd".to_owned(),
            command_version("systemctl", &["--version"])
                .lines()
                .next()
                .unwrap_or("unavailable")
                .to_owned(),
        ),
    ]))
}

fn command_version(program: &str, arguments: &[&str]) -> String {
    Command::new(program)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn proc_write_bytes() -> Result<u64> {
    let value = fs::read_to_string("/proc/self/io")?;
    value
        .lines()
        .find_map(|line| line.strip_prefix("write_bytes:")?.trim().parse().ok())
        .context("/proc/self/io omitted write_bytes")
}

fn digest_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
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

fn digest_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .context("workspace root unavailable")
}

fn output_path() -> Result<Option<PathBuf>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [] => Ok(None),
        [flag, path] if flag == "--output" => Ok(Some(PathBuf::from(path))),
        _ => bail!("usage: flagdeck-r3-gate [--output PATH]"),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("partial");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
