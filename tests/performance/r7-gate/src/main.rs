#![allow(
    clippy::cast_precision_loss,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use flagdeck_domain::{
    CommandSpec, CommandSpecId, Discovery, DiscoveryId, DiscoveryKind, ResourceLimits, RiskLevel,
    SecretTransport, SupervisorBackend, Timestamp,
};
use flagdeck_exec::start_managed_with_backend;
use flagdeck_storage::{OpenMode, ProjectStore, SCHEMA_VERSION};
use serde::Serialize;
use sha2::{Digest, Sha256};

const ITERATIONS: usize = 10;
const DISCOVERY_ROWS: usize = 100_000;
const CONCURRENT_TASKS: usize = 8;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Distribution {
    unit: &'static str,
    samples: Vec<f64>,
    minimum: f64,
    p50: f64,
    p95: f64,
    maximum: f64,
    mean: f64,
}

impl Distribution {
    fn new(samples_millis: Vec<f64>) -> Result<Self> {
        ensure!(!samples_millis.is_empty(), "distribution needs samples");
        let mut sorted = samples_millis.clone();
        sorted.sort_by(f64::total_cmp);
        let p50 = percentile(&sorted, 50, 100);
        let p95 = percentile(&sorted, 95, 100);
        let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
        Ok(Self {
            unit: "milliseconds",
            samples: samples_millis,
            minimum: sorted[0],
            p50,
            p95,
            maximum: *sorted.last().context("distribution is empty")?,
            mean,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DatasetReport {
    rows: usize,
    fixture_sha256: String,
    insert_millis: f64,
    full_pagination_millis: f64,
    page_latency: Distribution,
    pages: usize,
    unique_ids: usize,
    restart_open_millis: f64,
    database_bytes: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConcurrencyReport {
    tasks_per_run: usize,
    runs: usize,
    completed_tasks: usize,
    cleanup_verified_tasks: usize,
    latency: Distribution,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GateReport {
    schema: String,
    generated_at_unix_millis: u128,
    profile: String,
    environment: BTreeMap<String, String>,
    project_startup: Distribution,
    headless_idle_rss_kib: u64,
    dataset: DatasetReport,
    concurrency: ConcurrencyReport,
    assertions: BTreeMap<String, bool>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let output = output_path()?;
    let temporary = tempfile::tempdir()?;
    let startup_root = temporary.path().join("startup");
    let mut startup_samples = Vec::with_capacity(ITERATIONS);
    for index in 0..ITERATIONS {
        let root = startup_root.join(format!("run-{index:02}"));
        let started = Instant::now();
        let (store, _) = ProjectStore::create(&root, "R7 startup gate")?;
        startup_samples.push(started.elapsed().as_secs_f64() * 1000.0);
        drop(store);
    }
    let startup = Distribution::new(startup_samples)?;
    let headless_idle_rss_kib = current_rss_kib()?;

    let dataset_root = temporary.path().join("dataset");
    let (store, summary) = ProjectStore::create(&dataset_root, "R7 100k gate")?;
    let now = Timestamp::now();
    let mut fixture_digest = Sha256::new();
    let rows = (0..DISCOVERY_ROWS)
        .map(|index| {
            let canonical_value = format!("/r7/path/{index:06}");
            fixture_digest.update(canonical_value.as_bytes());
            fixture_digest.update([b'\n']);
            Discovery {
                discovery_id: DiscoveryId::new(),
                project_id: summary.project_id.clone(),
                kind: DiscoveryKind::Path,
                raw_value: canonical_value.clone(),
                canonical_value,
                canonical_key: format!("{index:064x}"),
                first_seen_at: now.clone(),
                last_seen_at: now.clone(),
                status: "active".to_owned(),
                manual_labels: vec!["r7-performance".to_owned()],
            }
        })
        .collect::<Vec<_>>();
    let fixture_sha256 = format!("{:x}", fixture_digest.finalize());
    let insert_started = Instant::now();
    store.save_discoveries(rows)?;
    let insert_millis = insert_started.elapsed().as_secs_f64() * 1000.0;

    let pagination_started = Instant::now();
    let mut cursor = None;
    let mut unique_ids = HashSet::with_capacity(DISCOVERY_ROWS);
    let mut page_samples = Vec::new();
    loop {
        let page_started = Instant::now();
        let (items, next) = store.list_discoveries(100, cursor.as_deref())?;
        page_samples.push(page_started.elapsed().as_secs_f64() * 1000.0);
        for item in items {
            unique_ids.insert(item.discovery_id.0);
        }
        cursor = next;
        if cursor.is_none() {
            break;
        }
    }
    let full_pagination_millis = pagination_started.elapsed().as_secs_f64() * 1000.0;
    let pages = page_samples.len();
    let page_latency = Distribution::new(page_samples)?;
    let database_path = store.layout().database.clone();
    drop(store);
    let restart_started = Instant::now();
    let reopened = ProjectStore::open(&dataset_root, &summary.project_id, OpenMode::ReadOnly)?;
    let restart_open_millis = restart_started.elapsed().as_secs_f64() * 1000.0;
    ensure!(reopened.list_discoveries(100, None)?.0.len() == 100);
    drop(reopened);
    let database_bytes = fs::metadata(database_path)?.len();
    let dataset = DatasetReport {
        rows: DISCOVERY_ROWS,
        fixture_sha256,
        insert_millis,
        full_pagination_millis,
        page_latency,
        pages,
        unique_ids: unique_ids.len(),
        restart_open_millis,
        database_bytes,
    };

    let concurrency = concurrency_gate(temporary.path()).await?;
    let mut assertions = BTreeMap::new();
    assertions.insert(
        "project_startup_p95_le_2000ms".to_owned(),
        startup.p95 <= 2_000.0,
    );
    assertions.insert(
        "headless_idle_rss_le_40mib".to_owned(),
        headless_idle_rss_kib <= 40 * 1024,
    );
    assertions.insert(
        "discovery_rows_100000".to_owned(),
        dataset.rows == DISCOVERY_ROWS,
    );
    assertions.insert(
        "discovery_ids_unique".to_owned(),
        dataset.unique_ids == DISCOVERY_ROWS,
    );
    assertions.insert(
        "discovery_insert_le_30s".to_owned(),
        dataset.insert_millis <= 30_000.0,
    );
    assertions.insert(
        "discovery_page_p95_le_100ms".to_owned(),
        dataset.page_latency.p95 <= 100.0,
    );
    assertions.insert(
        "discovery_full_pagination_le_60s".to_owned(),
        dataset.full_pagination_millis <= 60_000.0,
    );
    assertions.insert(
        "concurrent_tasks_complete".to_owned(),
        concurrency.completed_tasks == ITERATIONS * CONCURRENT_TASKS,
    );
    assertions.insert(
        "concurrent_tasks_cleanup_verified".to_owned(),
        concurrency.cleanup_verified_tasks == ITERATIONS * CONCURRENT_TASKS,
    );
    assertions.insert(
        "concurrent_task_p95_le_2s".to_owned(),
        concurrency.latency.p95 <= 2_000.0,
    );

    let report = GateReport {
        schema: "flagdeck.performance.r7.v1".to_owned(),
        generated_at_unix_millis: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
        .to_owned(),
        environment: environment()?,
        project_startup: startup,
        headless_idle_rss_kib,
        dataset,
        concurrency,
        assertions,
    };
    write_private_json(&output, &report)?;
    ensure!(
        report.assertions.values().all(|passed| *passed),
        "R7 performance assertion failed; inspect {}",
        output.display()
    );
    println!("R7 performance gate PASS: {}", output.display());
    Ok(())
}

async fn concurrency_gate(root: &Path) -> Result<ConcurrencyReport> {
    let cwd = root.join("concurrency");
    fs::create_dir_all(&cwd)?;
    fs::set_permissions(&cwd, fs::Permissions::from_mode(0o700))?;
    let sleep_sha256 = digest_file(Path::new("/usr/bin/sleep"))?;
    let mut samples = Vec::with_capacity(ITERATIONS);
    let mut completed_tasks = 0;
    let mut cleanup_verified_tasks = 0;
    for run in 0..ITERATIONS {
        let started = Instant::now();
        let mut executions = Vec::with_capacity(CONCURRENT_TASKS);
        for task in 0..CONCURRENT_TASKS {
            let spec = sleep_spec(&cwd, &sleep_sha256);
            let stdout = cwd.join(format!("run-{run:02}-task-{task:02}.out"));
            let stderr = cwd.join(format!("run-{run:02}-task-{task:02}.err"));
            executions.push(
                start_managed_with_backend(
                    &spec,
                    &stdout,
                    &stderr,
                    SupervisorBackend::PgidFallback,
                )
                .await?,
            );
        }
        for execution in executions {
            let result = execution.wait().await?;
            if result.exit_code == Some(0) {
                completed_tasks += 1;
            }
            if result.cleanup_verified && result.residual_processes == 0 {
                cleanup_verified_tasks += 1;
            }
        }
        samples.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    Ok(ConcurrencyReport {
        tasks_per_run: CONCURRENT_TASKS,
        runs: ITERATIONS,
        completed_tasks,
        cleanup_verified_tasks,
        latency: Distribution::new(samples)?,
    })
}

fn sleep_spec(cwd: &Path, sha256: &str) -> CommandSpec {
    CommandSpec {
        command_spec_id: CommandSpecId::new(),
        tool_id: "r7-concurrency-fixture".to_owned(),
        tool_version: "system".to_owned(),
        tool_sha256: sha256.to_owned(),
        program: "/usr/bin/sleep".to_owned(),
        argv_exec: vec!["0.02".to_owned()],
        argv_redacted: vec!["0.02".to_owned()],
        env_exec: BTreeMap::from([("LANG".to_owned(), "C.UTF-8".to_owned())]),
        env_redacted: BTreeMap::from([("LANG".to_owned(), "C.UTF-8".to_owned())]),
        secret_transport: SecretTransport::None,
        secret_inputs: Vec::new(),
        cwd: cwd.display().to_string(),
        environment_allowlist: vec!["LANG".to_owned()],
        timeout_millis: 5_000,
        stop_grace_millis: 100,
        expected_outputs: Vec::new(),
        risk_level: RiskLevel::L0,
        scope_id: None,
        sandbox_profile: "r7-concurrency-gate".to_owned(),
        resource_limits: ResourceLimits::default(),
        network_isolation: "none".to_owned(),
    }
}

fn percentile(sorted: &[f64], numerator: usize, denominator: usize) -> f64 {
    let index = sorted
        .len()
        .saturating_mul(numerator)
        .div_ceil(denominator)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[index]
}

fn output_path() -> Result<PathBuf> {
    let mut arguments = std::env::args().skip(1);
    ensure!(
        arguments.next().as_deref() == Some("--output"),
        "expected --output PATH"
    );
    let output = PathBuf::from(arguments.next().context("missing output path")?);
    ensure!(arguments.next().is_none(), "unexpected arguments");
    Ok(output)
}

fn current_rss_kib() -> Result<u64> {
    let status = fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .context("VmRSS is unavailable")?;
    line.split_whitespace()
        .nth(1)
        .context("VmRSS value is unavailable")?
        .parse()
        .context("VmRSS is invalid")
}

fn environment() -> Result<BTreeMap<String, String>> {
    Ok(BTreeMap::from([
        ("architecture".to_owned(), std::env::consts::ARCH.to_owned()),
        ("kernel".to_owned(), command_output("uname", &["-r"])?),
        (
            "fedora".to_owned(),
            fs::read_to_string("/etc/fedora-release")?.trim().to_owned(),
        ),
        ("rustc".to_owned(), command_output("rustc", &["--version"])?),
        ("cargo".to_owned(), command_output("cargo", &["--version"])?),
        ("sqlite".to_owned(), rusqlite::version().to_owned()),
        ("storageSchema".to_owned(), SCHEMA_VERSION.to_string()),
        (
            "selinux".to_owned(),
            command_output("getenforce", &[]).unwrap_or_else(|_| "unknown".to_owned()),
        ),
        (
            "session".to_owned(),
            std::env::var("XDG_SESSION_TYPE").unwrap_or_else(|_| "unknown".to_owned()),
        ),
        (
            "desktop".to_owned(),
            std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_else(|_| "unknown".to_owned()),
        ),
    ]))
}

fn command_output(program: &str, arguments: &[&str]) -> Result<String> {
    let output = Command::new(program).args(arguments).output()?;
    ensure!(output.status.success(), "{program} failed");
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
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

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("output path has no parent")?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
