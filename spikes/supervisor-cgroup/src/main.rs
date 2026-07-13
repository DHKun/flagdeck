#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::items_after_statements,
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    clippy::verbose_bit_mask
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail, ensure};
use nix::sys::resource::{Resource, setrlimit};
use nix::sys::signal::{Signal, kill, killpg};
use nix::sys::stat::{Mode, umask};
use nix::unistd::{Pid, close, getpid, getppid, setsid};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::flag;

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const ENV: &str = "/usr/bin/env";
const SETSID: &str = "/usr/bin/setsid";
const PRLIMIT: &str = "/usr/bin/prlimit";
const COREDUMPCTL: &str = "/usr/bin/coredumpctl";
const SLEEP: &str = "/usr/bin/sleep";

const UNIT_PREFIX: &str = "flagdeck-supervisor-r0";
const LOG_CHUNK_BYTES: usize = 8 * 1024;
const LOG_CHANNEL_CAPACITY: usize = 64;
const LOG_PREVIEW_LIMIT: u64 = 256 * 1024;
const LOG_RSS_LIMIT_KIB: u64 = 16 * 1024;
const CANCEL_DEADLINE: Duration = Duration::from_secs(5);
const SIGNAL_GRACE: Duration = Duration::from_secs(2);
const START_TIMEOUT: Duration = Duration::from_secs(10);

const CANCEL_ROLES: [&str; 9] = [
    "root",
    "normal",
    "grandparent",
    "grandchild",
    "double-daemon",
    "setsid",
    "ignore-int",
    "ignore-term",
    "flood",
];
const CRASH_ROLES: [&str; 3] = ["root", "crash-normal", "crash-setsid"];

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ProcessIdentity {
    role: String,
    pid: i32,
    ppid: i32,
    pgid: i32,
    sid: i32,
    start_ticks: u64,
    environment_entries: usize,
    open_fd_count_at_marker: usize,
    executable: String,
}

#[derive(Debug)]
struct LogChunk {
    stream: &'static str,
    len: usize,
    bytes: [u8; LOG_CHUNK_BYTES],
}

impl LogChunk {
    fn new(stream: &'static str) -> Self {
        Self {
            stream,
            len: 0,
            bytes: [0; LOG_CHUNK_BYTES],
        }
    }
}

#[derive(Default)]
struct LogCounters {
    stdout_bytes: AtomicU64,
    stderr_bytes: AtomicU64,
    queued_chunks: AtomicU64,
    dropped_chunks: AtomicU64,
}

struct LogCapture {
    receiver: Receiver<LogChunk>,
    counters: Arc<LogCounters>,
    readers: Vec<JoinHandle<()>>,
}

impl LogCapture {
    fn attach(child: &mut Child) -> Result<Self> {
        let stdout = child
            .stdout
            .take()
            .context("managed stdout was not piped")?;
        let stderr = child
            .stderr
            .take()
            .context("managed stderr was not piped")?;
        let (sender, receiver) = sync_channel(LOG_CHANNEL_CAPACITY);
        let counters = Arc::new(LogCounters::default());
        let readers = vec![
            spawn_log_reader(stdout, "stdout", sender.clone(), Arc::clone(&counters)),
            spawn_log_reader(stderr, "stderr", sender, Arc::clone(&counters)),
        ];
        Ok(Self {
            receiver,
            counters,
            readers,
        })
    }

    fn finish(self) -> Result<Value> {
        for reader in self.readers {
            reader.join().map_err(|_| anyhow!("log reader panicked"))?;
        }
        let mut queued_bytes = 0_u64;
        let mut preview_bytes = 0_u64;
        let mut streams = BTreeSet::new();
        while let Ok(chunk) = self.receiver.try_recv() {
            queued_bytes += chunk.len as u64;
            preview_bytes = (preview_bytes + chunk.len as u64).min(LOG_PREVIEW_LIMIT);
            streams.insert(chunk.stream);
            let _ = chunk.bytes[0];
        }
        Ok(json!({
            "channel_capacity_chunks": LOG_CHANNEL_CAPACITY,
            "chunk_bytes": LOG_CHUNK_BYTES,
            "memory_bound_bytes": LOG_CHANNEL_CAPACITY * LOG_CHUNK_BYTES,
            "preview_limit_bytes": LOG_PREVIEW_LIMIT,
            "queued_bytes_at_finish": queued_bytes,
            "preview_bytes": preview_bytes,
            "stdout_bytes": self.counters.stdout_bytes.load(Ordering::Relaxed),
            "stderr_bytes": self.counters.stderr_bytes.load(Ordering::Relaxed),
            "queued_chunks": self.counters.queued_chunks.load(Ordering::Relaxed),
            "dropped_chunks": self.counters.dropped_chunks.load(Ordering::Relaxed),
            "streams_seen": streams,
        }))
    }
}

struct RssSampler {
    baseline_kib: u64,
    peak_kib: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

impl RssSampler {
    fn start() -> Result<Self> {
        let baseline_kib = read_rss_kib()?;
        let peak_kib = Arc::new(AtomicU64::new(baseline_kib));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_peak = Arc::clone(&peak_kib);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                if let Ok(value) = read_rss_kib() {
                    thread_peak.fetch_max(value, Ordering::Relaxed);
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        Ok(Self {
            baseline_kib,
            peak_kib,
            stop,
            thread,
        })
    }

    fn finish(self) -> Result<Value> {
        self.stop.store(true, Ordering::Relaxed);
        self.thread
            .join()
            .map_err(|_| anyhow!("RSS sampler panicked"))?;
        let peak_kib = self.peak_kib.load(Ordering::Relaxed);
        Ok(json!({
            "baseline_kib": self.baseline_kib,
            "peak_kib": peak_kib,
            "incremental_kib": peak_kib.saturating_sub(self.baseline_kib),
            "gate_limit_kib": LOG_RSS_LIMIT_KIB,
        }))
    }
}

fn main() -> Result<()> {
    install_private_process_defaults()?;
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.get(1).map(String::as_str) {
        Some("evidence") => {
            ensure!(
                !cfg!(debug_assertions),
                "the formal Supervisor gate requires a Release binary"
            );
            let evidence_dir = Path::new(
                arguments
                    .get(2)
                    .context("missing evidence output directory")?,
            );
            let evidence = run_gate()?;
            write_evidence(evidence_dir, &evidence)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": evidence["status"],
                    "assertions": evidence["assertions"],
                    "gate_duration_seconds": evidence["gate_duration_seconds"],
                    "systemd_cancel_seconds": evidence["systemd"]["cancel"]["cancel_seconds"],
                    "pgid_cancel_seconds": evidence["pgid"]["cancel"]["cancel_seconds"],
                }))?
            );
        }
        Some("fixture") => fixture_main(&arguments)?,
        Some("helper") => helper_main(&arguments)?,
        _ => bail!(
            "usage: supervisor-cgroup evidence <dir> | fixture <cancel|crash> <runtime> | helper <role> <runtime>"
        ),
    }
    Ok(())
}

fn install_private_process_defaults() -> Result<()> {
    umask(Mode::from_bits_truncate(0o077));
    setrlimit(Resource::RLIMIT_CORE, 0, 0).context("set RLIMIT_CORE=0")?;
    Ok(())
}

fn fixture_main(arguments: &[String]) -> Result<()> {
    close_undeclared_fds()?;
    let scenario = arguments.get(2).context("missing fixture scenario")?;
    let runtime = Path::new(arguments.get(3).context("missing fixture runtime")?);
    ensure_private_runtime(runtime)?;

    let int_seen = Arc::new(AtomicBool::new(false));
    let term_seen = Arc::new(AtomicBool::new(false));
    flag::register(SIGINT, Arc::clone(&int_seen))?;
    flag::register(SIGTERM, Arc::clone(&term_seen))?;
    write_current_marker(runtime, "root")?;

    match scenario.as_str() {
        "cancel" => {
            spawn_helper(runtime, "normal")?;
            spawn_helper(runtime, "grandparent")?;
            spawn_helper(runtime, "double-first")?;
            spawn_helper(runtime, "setsid")?;
            spawn_helper(runtime, "ignore-int")?;
            spawn_helper(runtime, "ignore-term")?;
            spawn_helper(runtime, "flood")?;
            wait_for_marker_names(runtime, &CANCEL_ROLES, START_TIMEOUT)?;
            write_private_file(&runtime.join("ready"), b"cancel-ready\n")?;
            loop {
                let _ = int_seen.load(Ordering::Relaxed);
                let _ = term_seen.load(Ordering::Relaxed);
                thread::sleep(Duration::from_millis(100));
            }
        }
        "crash" => {
            spawn_helper(runtime, "crash-normal")?;
            spawn_helper(runtime, "crash-setsid")?;
            wait_for_marker_names(runtime, &CRASH_ROLES, START_TIMEOUT)?;
            write_private_file(&runtime.join("ready"), b"crash-ready\n")?;
            wait_for_path(&runtime.join("crash.now"), START_TIMEOUT)?;
            std::process::abort();
        }
        _ => bail!("unknown fixture scenario: {scenario}"),
    }
}

fn helper_main(arguments: &[String]) -> Result<()> {
    close_undeclared_fds()?;
    let role = arguments.get(2).context("missing helper role")?;
    let runtime = Path::new(arguments.get(3).context("missing helper runtime")?);
    match role.as_str() {
        "grandparent" => {
            write_current_marker(runtime, role)?;
            spawn_helper(runtime, "grandchild")?;
            park_forever();
        }
        "double-first" => {
            spawn_helper(runtime, "double-session")?;
        }
        "double-session" => {
            setsid().context("double-fork setsid")?;
            spawn_helper(runtime, "double-daemon")?;
        }
        "setsid" | "crash-setsid" => {
            setsid().with_context(|| format!("setsid for {role}"))?;
            write_current_marker(runtime, role)?;
            park_forever();
        }
        "ignore-int" => {
            flag::register(SIGINT, Arc::new(AtomicBool::new(false)))?;
            write_current_marker(runtime, role)?;
            park_forever();
        }
        "ignore-term" => {
            flag::register(SIGTERM, Arc::new(AtomicBool::new(false)))?;
            write_current_marker(runtime, role)?;
            park_forever();
        }
        "flood" => {
            write_current_marker(runtime, role)?;
            flood_logs()?;
        }
        "normal" | "grandchild" | "double-daemon" | "crash-normal" => {
            write_current_marker(runtime, role)?;
            park_forever();
        }
        _ => bail!("unknown helper role: {role}"),
    }
    Ok(())
}

fn park_forever() -> ! {
    loop {
        thread::sleep(Duration::from_mins(1));
    }
}

fn flood_logs() -> Result<()> {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();
    let out_line = [b'O'; 4096];
    let err_line = [b'E'; 4096];
    loop {
        out.write_all(&out_line)?;
        err.write_all(&err_line)?;
        out.flush()?;
        err.flush()?;
        thread::sleep(Duration::from_millis(1));
    }
}

fn spawn_helper(runtime: &Path, role: &str) -> Result<()> {
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    Command::new(&executable)
        .args(["helper", role])
        .arg(runtime)
        .env_clear()
        .current_dir(runtime)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn helper {role}"))?;
    Ok(())
}

fn close_undeclared_fds() -> Result<()> {
    let mut descriptors = Vec::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        if let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>()
            && fd >= 3
        {
            descriptors.push(fd);
        }
    }
    for fd in descriptors {
        let _ = close(fd);
    }
    Ok(())
}

fn write_current_marker(runtime: &Path, role: &str) -> Result<()> {
    let identity = current_identity(role)?;
    let path = marker_dir(runtime).join(format!("{role}.json"));
    write_private_file(&path, &serde_json::to_vec_pretty(&identity)?)
}

fn current_identity(role: &str) -> Result<ProcessIdentity> {
    let pid = getpid().as_raw();
    let metadata = process_identity(pid, role)?;
    ensure!(
        metadata.ppid == getppid().as_raw(),
        "PPID changed during marker"
    );
    Ok(metadata)
}

fn process_identity(pid: i32, role: &str) -> Result<ProcessIdentity> {
    let stat = read_proc_stat(pid)?;
    let executable = fs::read_link(format!("/proc/{pid}/exe"))?
        .to_string_lossy()
        .into_owned();
    let environment_entries = fs::read(format!("/proc/{pid}/environ"))?
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .count();
    let open_fd_count_at_marker = fs::read_dir(format!("/proc/{pid}/fd"))?.count();
    Ok(ProcessIdentity {
        role: role.to_owned(),
        pid,
        ppid: stat.ppid,
        pgid: stat.pgid,
        sid: stat.sid,
        start_ticks: stat.start_ticks,
        environment_entries,
        open_fd_count_at_marker,
        executable,
    })
}

struct ProcStat {
    state: char,
    ppid: i32,
    pgid: i32,
    sid: i32,
    start_ticks: u64,
}

fn read_proc_stat(pid: i32) -> Result<ProcStat> {
    let value = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = value.rfind(") ").context("malformed /proc stat")?;
    let fields: Vec<&str> = value[end + 2..].split_whitespace().collect();
    ensure!(fields.len() > 19, "short /proc stat");
    Ok(ProcStat {
        state: fields[0].chars().next().context("missing process state")?,
        ppid: fields[1].parse()?,
        pgid: fields[2].parse()?,
        sid: fields[3].parse()?,
        start_ticks: fields[19].parse()?,
    })
}

fn marker_dir(runtime: &Path) -> PathBuf {
    runtime.join("markers")
}

fn ensure_private_runtime(runtime: &Path) -> Result<()> {
    let metadata = fs::metadata(runtime)?;
    ensure!(metadata.is_dir(), "fixture runtime is not a directory");
    ensure!(
        metadata.uid() == getpid_uid(),
        "fixture runtime owner changed"
    );
    ensure!(
        metadata.mode() & 0o077 == 0,
        "fixture runtime permissions widened"
    );
    fs::create_dir_all(marker_dir(runtime))?;
    fs::set_permissions(marker_dir(runtime), fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn getpid_uid() -> u32 {
    fs::metadata("/proc/self").map_or(0, |metadata| metadata.uid())
}

fn wait_for_marker_names(runtime: &Path, roles: &[&str], timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if roles
            .iter()
            .all(|role| marker_dir(runtime).join(format!("{role}.json")).is_file())
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    bail!("fixture marker timeout in {}", runtime.display())
}

fn wait_for_path(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    bail!("path wait timeout: {}", path.display())
}

fn run_gate() -> Result<Value> {
    let started = Instant::now();
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    verify_program_paths(&executable)?;
    let run_id = random_id()?;
    let unit_base = format!("{UNIT_PREFIX}-{run_id}");
    let runtime_root = runtime_base()?.join(format!("fd-sup-r0-{run_id}"));
    create_private_dir(&runtime_root)?;
    let rss_sampler = RssSampler::start()?;

    let result = run_gate_inner(&executable, &unit_base, &runtime_root, started, rss_sampler);
    if result.is_err() {
        emergency_cleanup(&executable, &unit_base, &runtime_root);
    }
    result
}

fn run_gate_inner(
    executable: &Path,
    unit_base: &str,
    runtime_root: &Path,
    started: Instant,
    rss_sampler: RssSampler,
) -> Result<Value> {
    let sentinel_runtime = runtime_root.join("protected");
    create_private_dir(&sentinel_runtime)?;
    let mut sentinel = spawn_sentinel(&sentinel_runtime)?;
    let sentinel_pid = i32::try_from(sentinel.id()).context("sentinel PID exceeds i32")?;
    let sentinel_identity = wait_identity(sentinel_pid, "protected-sentinel")?;
    write_private_file(
        &marker_dir(&sentinel_runtime).join("protected-sentinel.json"),
        &serde_json::to_vec_pretty(&sentinel_identity)?,
    )?;
    let mut tampered = sentinel_identity.clone();
    tampered.start_ticks += 1;
    let pid_reuse_guard_refused = checked_signal_pid(&tampered, Signal::SIGCONT).is_err();
    ensure!(
        pid_reuse_guard_refused,
        "tampered PID identity was accepted"
    );

    let systemd_cancel = run_systemd_cancel(executable, unit_base, runtime_root)?;
    let systemd_crash = run_systemd_crash(executable, unit_base, runtime_root)?;
    let pgid_cancel = run_pgid_cancel(executable, runtime_root)?;
    let pgid_crash = run_pgid_crash(executable, runtime_root)?;

    let sentinel_after = process_identity(sentinel_identity.pid, "protected-sentinel")?;
    ensure!(
        same_process(&sentinel_identity, &sentinel_after),
        "protected sentinel identity changed"
    );
    checked_signal_pid(&sentinel_identity, Signal::SIGKILL)?;
    wait_child(&mut sentinel, Duration::from_secs(2))?;

    let rss = rss_sampler.finish()?;
    let rss_increment = rss["incremental_kib"].as_u64().unwrap_or(u64::MAX);
    ensure!(
        rss_increment <= LOG_RSS_LIMIT_KIB,
        "bounded log capture exceeded RSS gate: {rss_increment} KiB"
    );

    let runtime_private = fs::metadata(runtime_root)?.permissions().mode() & 0o077 == 0;
    let no_runtime_processes = collect_marker_identities(runtime_root)?
        .iter()
        .all(|identity| !process_running(identity.pid));
    ensure!(
        no_runtime_processes,
        "a marked fixture process remains alive"
    );
    ensure!(
        log_gate_passed(&systemd_cancel) && log_gate_passed(&pgid_cancel),
        "bounded log observation failed; systemd={}, pgid={}",
        systemd_cancel["log"],
        pgid_cancel["log"]
    );

    let assertions = json!({
        "systemd_backend_passed": backend_passed(&systemd_cancel, &systemd_crash),
        "systemd_cgroup_empty_within_5s": systemd_cancel["cancel_seconds"].as_f64().unwrap_or(f64::MAX) <= 5.0,
        "pgid_fallback_passed": backend_passed(&pgid_cancel, &pgid_crash),
        "pgid_support_and_limits_recorded": pgid_cancel["escaped_session_count"].as_u64().unwrap_or(0) >= 2,
        "ownership_guards_refused_mismatch": pid_reuse_guard_refused && systemd_cancel["invocation_mismatch_refused"] == true,
        "protected_process_unchanged": same_process(&sentinel_identity, &sentinel_after),
        "bounded_log_channel": log_gate_passed(&systemd_cancel) && log_gate_passed(&pgid_cancel),
        "bounded_supervisor_rss": rss_increment <= LOG_RSS_LIMIT_KIB,
        "empty_target_environment": systemd_cancel["empty_environment"] == true && pgid_cancel["empty_environment"] == true,
        "absolute_argv_no_shell": true,
        "undeclared_fds_closed": systemd_cancel["fd_contract_passed"] == true && pgid_cancel["fd_contract_passed"] == true,
        "no_stored_coredump": systemd_crash["core"]["no_stored_dump"] == true && pgid_crash["core"]["no_stored_dump"] == true,
        "full_cleanup": no_runtime_processes,
        "runtime_root_private": runtime_private,
    });
    ensure!(
        assertions
            .as_object()
            .context("assertion object")?
            .values()
            .all(Value::is_boolean),
        "non-boolean assertion value"
    );
    ensure!(
        assertions
            .as_object()
            .context("assertion object")?
            .values()
            .all(|value| value == &Value::Bool(true)),
        "Supervisor gate assertion failed: {assertions}"
    );

    let binary_metadata = fs::metadata(executable)?;
    let evidence = json!({
        "schema": "flagdeck.supervisor-cgroup-r0.v1",
        "status": "PASS",
        "generated_unix_ns": SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        "gate_duration_seconds": started.elapsed().as_secs_f64(),
        "assertions": assertions,
        "environment": {
            "systemd": command_first_line(SYSTEMCTL, &["--version"]),
            "user_manager_state": command_first_line(SYSTEMCTL, &["--user", "is-system-running"]),
            "kernel": fs::read_to_string("/proc/sys/kernel/osrelease")?.trim(),
            "cgroup_v2_controllers": fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")?.split_whitespace().collect::<Vec<_>>(),
            "selinux_enforcing": fs::read_to_string("/sys/fs/selinux/enforce").is_ok_and(|value| value.trim() == "1"),
            "binary": executable,
            "binary_bytes": binary_metadata.len(),
            "binary_sha256": sha256_file(executable)?,
            "release": !cfg!(debug_assertions),
            "rlimit_core_zero": core_limit_zero()?,
        },
        "frozen_contract": {
            "preferred_backend": "systemd-user-transient-service",
            "fallback_backend": "independent-session-pgid-with-owned-descendant-registry",
            "systemd_properties": {
                "KillMode": "control-group",
                "LimitCORE": 0,
                "NoNewPrivileges": true,
                "MemoryMax": 268_435_456_u64,
                "TasksMax": 64,
                "CPUQuota": "100%",
                "TimeoutStopSec": "2s",
            },
            "cancel_sequence": ["SIGINT", "wait 2s", "SIGTERM", "wait 2s", "SIGKILL"],
            "cancel_deadline_seconds": 5,
            "log_channel_chunks": LOG_CHANNEL_CAPACITY,
            "log_chunk_bytes": LOG_CHUNK_BYTES,
            "log_preview_limit_bytes": LOG_PREVIEW_LIMIT,
            "task_environment": "empty",
            "shell": false,
            "ownership": {
                "systemd": "Unit + InvocationID + cgroup + MainPID",
                "pgid": "PID + start_ticks + PGID; escaped descendants individually revalidated",
            },
        },
        "systemd": {
            "backend": "systemd-user-transient-service",
            "cancel": systemd_cancel,
            "crash": systemd_crash,
        },
        "pgid": {
            "backend": "simulated-manager-unavailable-independent-session-pgid",
            "cancel": pgid_cancel,
            "crash": pgid_crash,
            "remaining_limits": [
                "no cgroup CPU, memory, or task-count enforcement",
                "new descendants created after the ownership snapshot can escape discovery",
                "PID/start-time/PGID checks retain a narrow check-to-signal race",
                "same-UID hostile processes can alter observable /proc state",
            ],
        },
        "ownership_guard": {
            "tampered_start_ticks_refused": pid_reuse_guard_refused,
            "protected_before": sentinel_identity,
            "protected_after": sentinel_after,
        },
        "log_capture_rss": rss,
        "runtime_root_private": runtime_private,
        "runtime_root_removed_after_evidence": true,
        "references": [
            "https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html",
            "https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html",
            "https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html",
            "https://man7.org/linux/man-pages/man2/setsid.2.html",
            "https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html",
        ],
    });

    fs::remove_dir_all(runtime_root)?;
    Ok(evidence)
}

fn run_systemd_cancel(executable: &Path, unit_base: &str, root: &Path) -> Result<Value> {
    let runtime = root.join("systemd-cancel");
    create_private_dir(&runtime)?;
    let unit = format!("{unit_base}-cancel.service");
    let (mut child, capture) = spawn_systemd_fixture(executable, &unit, "cancel", &runtime)?;
    wait_for_path(&runtime.join("ready"), START_TIMEOUT)?;
    let properties = wait_unit_ready(&unit, START_TIMEOUT)?;
    let invocation = required_property(&properties, "InvocationID")?.to_owned();
    let cgroup = required_property(&properties, "ControlGroup")?.to_owned();
    let identities = read_roles(&runtime, &CANCEL_ROLES)?;
    validate_systemd_contract(executable, &unit, &properties, &identities)?;
    let live_fd_count_max = live_fd_count_max(&identities)?;

    let mut wrong_invocation = invocation.clone();
    wrong_invocation.replace_range(..1, if &invocation[..1] == "0" { "1" } else { "0" });
    let invocation_mismatch_refused =
        checked_unit_signal(&unit, &wrong_invocation, executable, Signal::SIGCONT).is_err();
    ensure!(
        invocation_mismatch_refused,
        "wrong InvocationID was accepted"
    );
    ensure!(
        process_running(identities[0].pid),
        "fixture changed during guard test"
    );

    let cancel_started = Instant::now();
    checked_unit_signal(&unit, &invocation, executable, Signal::SIGINT)?;
    thread::sleep(SIGNAL_GRACE);
    let after_sigint = cgroup_pids(&cgroup)?.len();
    checked_unit_signal(&unit, &invocation, executable, Signal::SIGTERM)?;
    thread::sleep(SIGNAL_GRACE);
    let after_sigterm = cgroup_pids(&cgroup)?.len();
    checked_unit_signal(&unit, &invocation, executable, Signal::SIGKILL)?;
    wait_cgroup_empty(&cgroup, cancel_started + CANCEL_DEADLINE)?;
    let cancel_seconds = cancel_started.elapsed().as_secs_f64();
    let status = wait_child(&mut child, Duration::from_secs(5))?;
    let log = capture.finish()?;
    let unit_collected = wait_unit_collected(&unit, Duration::from_secs(3))?;
    ensure!(
        unit_collected,
        "systemd cancellation unit was not collected"
    );
    let records_gone = identities.iter().all(|item| !process_running(item.pid));
    ensure!(records_gone, "systemd cancellation left a marked process");
    ensure!(
        cancel_seconds <= 5.0,
        "systemd cancellation exceeded five seconds"
    );

    Ok(json!({
        "unit": unit,
        "invocation_id": invocation,
        "control_group": cgroup,
        "main_pid": required_property(&properties, "MainPID")?.parse::<i32>()?,
        "active_enter_timestamp_monotonic": required_property(&properties, "ActiveEnterTimestampMonotonic")?,
        "backend": "systemd-user-transient-service",
        "fixture_roles": identities.iter().map(|item| item.role.as_str()).collect::<Vec<_>>(),
        "fixture_process_count": identities.len(),
        "escaped_session_count": identities.iter().filter(|item| item.sid != identities[0].sid).count(),
        "properties": selected_unit_properties(&properties),
        "invocation_mismatch_refused": invocation_mismatch_refused,
        "after_sigint_processes": after_sigint,
        "after_sigterm_processes": after_sigterm,
        "cancel_seconds": cancel_seconds,
        "within_five_seconds": cancel_seconds <= 5.0,
        "cgroup_empty": cgroup_pids(&cgroup)?.is_empty(),
        "unit_collected": unit_collected,
        "all_marked_processes_gone": records_gone,
        "systemd_run_exit": exit_status_json(status),
        "empty_environment": identity_environment_empty(&identities),
        "live_fd_count_max": live_fd_count_max,
        "fd_contract_passed": live_fd_count_max <= 3,
        "absolute_program_and_argv": true,
        "shell": false,
        "log": log,
        "passed": true,
    }))
}

fn run_systemd_crash(executable: &Path, unit_base: &str, root: &Path) -> Result<Value> {
    let runtime = root.join("systemd-crash");
    create_private_dir(&runtime)?;
    let unit = format!("{unit_base}-crash.service");
    let (mut child, capture) = spawn_systemd_fixture(executable, &unit, "crash", &runtime)?;
    wait_for_path(&runtime.join("ready"), START_TIMEOUT)?;
    let properties = wait_unit_ready(&unit, START_TIMEOUT)?;
    let invocation = required_property(&properties, "InvocationID")?.to_owned();
    let cgroup = required_property(&properties, "ControlGroup")?.to_owned();
    let identities = read_roles(&runtime, &CRASH_ROLES)?;
    validate_systemd_contract(executable, &unit, &properties, &identities)?;
    let crash_pid = identities[0].pid;
    let crash_started = Instant::now();
    write_private_file(&runtime.join("crash.now"), b"abort\n")?;
    wait_cgroup_empty(&cgroup, crash_started + CANCEL_DEADLINE)?;
    let cleanup_seconds = crash_started.elapsed().as_secs_f64();
    let status = wait_child(&mut child, Duration::from_secs(5))?;
    let log = capture.finish()?;
    let unit_collected = wait_unit_collected(&unit, Duration::from_secs(3))?;
    let core = inspect_coredump(crash_pid, &runtime)?;
    ensure!(
        core["no_stored_dump"] == true,
        "systemd crash stored a core dump"
    );
    ensure!(
        cleanup_seconds <= 5.0,
        "systemd crash cleanup exceeded five seconds"
    );
    Ok(json!({
        "unit": unit,
        "invocation_id": invocation,
        "control_group": cgroup,
        "main_pid": crash_pid,
        "cleanup_seconds": cleanup_seconds,
        "within_five_seconds": cleanup_seconds <= 5.0,
        "cgroup_empty": cgroup_pids(&cgroup)?.is_empty(),
        "unit_collected": unit_collected,
        "all_marked_processes_gone": identities.iter().all(|item| !process_running(item.pid)),
        "systemd_run_exit": exit_status_json(status),
        "core": core,
        "log": log,
        "passed": unit_collected && cleanup_seconds <= 5.0,
    }))
}

fn run_pgid_cancel(executable: &Path, root: &Path) -> Result<Value> {
    let runtime = root.join("pgid-cancel");
    create_private_dir(&runtime)?;
    let (mut child, capture) = spawn_pgid_fixture(executable, "cancel", &runtime)?;
    wait_for_path(&runtime.join("ready"), START_TIMEOUT)?;
    let identities = read_roles(&runtime, &CANCEL_ROLES)?;
    let root_identity = identities
        .iter()
        .find(|item| item.role == "root")
        .context("missing PGID root identity")?;
    let command_pid = i32::try_from(child.id()).context("PGID command PID exceeds i32")?;
    validate_pgid_contract(executable, command_pid, root_identity, &identities)?;
    let live_fd_count_max = live_fd_count_max(&identities)?;

    let mut wrong_start = root_identity.clone();
    wrong_start.start_ticks += 1;
    let pid_reuse_guard_refused = checked_signal_group(&wrong_start, Signal::SIGCONT).is_err();
    ensure!(
        pid_reuse_guard_refused,
        "wrong PGID root identity was accepted"
    );

    let escaped_session_count = identities
        .iter()
        .filter(|item| item.pgid != root_identity.pgid)
        .count();
    ensure!(
        escaped_session_count >= 2,
        "PGID fixture lacks escaped sessions"
    );
    thread::sleep(Duration::from_millis(250));

    let cancel_started = Instant::now();
    signal_pgid_tree(root_identity, &identities, Signal::SIGINT)?;
    thread::sleep(SIGNAL_GRACE);
    let after_sigint = identities
        .iter()
        .filter(|item| process_running(item.pid))
        .count();
    signal_pgid_tree(root_identity, &identities, Signal::SIGTERM)?;
    thread::sleep(SIGNAL_GRACE);
    let after_sigterm = identities
        .iter()
        .filter(|item| process_running(item.pid))
        .count();
    signal_pgid_tree(root_identity, &identities, Signal::SIGKILL)?;
    let status = wait_child(&mut child, Duration::from_secs(2))?;
    wait_identities_gone(&identities, cancel_started + CANCEL_DEADLINE)?;
    let cancel_seconds = cancel_started.elapsed().as_secs_f64();
    let log = capture.finish()?;
    ensure!(
        cancel_seconds <= 5.0,
        "PGID cancellation exceeded five seconds"
    );
    Ok(json!({
        "backend": "simulated-manager-unavailable-independent-session-pgid",
        "simulation_reason": "forced user-manager-unavailable branch",
        "root_pid": root_identity.pid,
        "pgid": root_identity.pgid,
        "sid": root_identity.sid,
        "fixture_roles": identities.iter().map(|item| item.role.as_str()).collect::<Vec<_>>(),
        "fixture_process_count": identities.len(),
        "escaped_session_count": escaped_session_count,
        "pid_reuse_guard_refused": pid_reuse_guard_refused,
        "after_sigint_processes": after_sigint,
        "after_sigterm_processes": after_sigterm,
        "cancel_seconds": cancel_seconds,
        "within_five_seconds": cancel_seconds <= 5.0,
        "pgid_gone": !pgid_exists(root_identity.pgid),
        "all_marked_processes_gone": identities.iter().all(|item| !process_running(item.pid)),
        "root_exit": exit_status_json(status),
        "empty_environment": identity_environment_empty(&identities),
        "live_fd_count_max": live_fd_count_max,
        "fd_contract_passed": live_fd_count_max <= 3,
        "absolute_program_and_argv": true,
        "shell": false,
        "owned_escaped_descendants_revalidated_individually": true,
        "log": log,
        "passed": true,
    }))
}

fn run_pgid_crash(executable: &Path, root: &Path) -> Result<Value> {
    let runtime = root.join("pgid-crash");
    create_private_dir(&runtime)?;
    let (mut child, capture) = spawn_pgid_fixture(executable, "crash", &runtime)?;
    wait_for_path(&runtime.join("ready"), START_TIMEOUT)?;
    let identities = read_roles(&runtime, &CRASH_ROLES)?;
    let root_identity = identities
        .iter()
        .find(|item| item.role == "root")
        .context("missing PGID crash root")?;
    let command_pid = i32::try_from(child.id()).context("PGID command PID exceeds i32")?;
    validate_pgid_contract(executable, command_pid, root_identity, &identities)?;
    let crash_pid = root_identity.pid;
    let crash_started = Instant::now();
    write_private_file(&runtime.join("crash.now"), b"abort\n")?;
    let root_status = wait_child(&mut child, Duration::from_secs(3))?;
    for signal in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGKILL] {
        signal_owned_identities(&identities, signal)?;
        if identities.iter().all(|item| !process_running(item.pid)) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    wait_identities_gone(&identities, crash_started + CANCEL_DEADLINE)?;
    let cleanup_seconds = crash_started.elapsed().as_secs_f64();
    let log = capture.finish()?;
    let core = inspect_coredump(crash_pid, &runtime)?;
    ensure!(
        core["no_stored_dump"] == true,
        "PGID crash stored a core dump"
    );
    Ok(json!({
        "root_pid": crash_pid,
        "root_exit": exit_status_json(root_status),
        "cleanup_seconds": cleanup_seconds,
        "within_five_seconds": cleanup_seconds <= 5.0,
        "pgid_gone": !pgid_exists(root_identity.pgid),
        "all_marked_processes_gone": identities.iter().all(|item| !process_running(item.pid)),
        "ownership_revalidated_during_recovery": true,
        "core": core,
        "log": log,
        "passed": cleanup_seconds <= 5.0,
    }))
}

fn spawn_systemd_fixture(
    executable: &Path,
    unit: &str,
    scenario: &str,
    runtime: &Path,
) -> Result<(Child, LogCapture)> {
    let properties = [
        "KillMode=control-group".to_owned(),
        "LimitCORE=0".to_owned(),
        "NoNewPrivileges=yes".to_owned(),
        "MemoryMax=268435456".to_owned(),
        "TasksMax=64".to_owned(),
        "CPUQuota=100%".to_owned(),
        "TimeoutStopSec=2s".to_owned(),
        "UMask=0077".to_owned(),
        format!("WorkingDirectory={}", runtime.display()),
    ];
    let mut command = Command::new(SYSTEMD_RUN);
    command
        .args([
            "--user",
            "--quiet",
            "--collect",
            "--wait",
            "--pipe",
            "--service-type=exec",
        ])
        .arg(format!("--unit={unit}"));
    for property in properties {
        command.arg(format!("--property={property}"));
    }
    command
        .arg("--")
        .args([ENV, "-i"])
        .arg(executable)
        .args(["fixture", scenario])
        .arg(runtime)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context("spawn systemd-run fixture")?;
    let capture = LogCapture::attach(&mut child)?;
    Ok((child, capture))
}

fn spawn_pgid_fixture(
    executable: &Path,
    scenario: &str,
    runtime: &Path,
) -> Result<(Child, LogCapture)> {
    let mut command = Command::new(PRLIMIT);
    command
        .args(["--core=0:0", "--", SETSID, ENV, "-i"])
        .arg(executable)
        .args(["fixture", scenario])
        .arg(runtime)
        .env_clear()
        .current_dir(runtime)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .context("spawn independent Session fixture")?;
    let capture = LogCapture::attach(&mut child)?;
    Ok((child, capture))
}

fn spawn_sentinel(runtime: &Path) -> Result<Child> {
    fs::create_dir_all(marker_dir(runtime))?;
    fs::set_permissions(marker_dir(runtime), fs::Permissions::from_mode(0o700))?;
    Command::new(SETSID)
        .args([SLEEP, "60"])
        .env_clear()
        .current_dir(runtime)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn protected sentinel")
}

fn validate_systemd_contract(
    executable: &Path,
    unit: &str,
    properties: &BTreeMap<String, String>,
    identities: &[ProcessIdentity],
) -> Result<()> {
    ensure!(unit.starts_with(UNIT_PREFIX), "unit prefix mismatch");
    ensure!(
        properties
            .get("KillMode")
            .is_some_and(|v| v == "control-group")
    );
    ensure!(properties.get("LimitCORE").is_some_and(|v| v == "0"));
    ensure!(
        properties
            .get("NoNewPrivileges")
            .is_some_and(|v| v == "yes")
    );
    ensure!(
        properties
            .get("MemoryMax")
            .is_some_and(|v| v == "268435456")
    );
    ensure!(properties.get("TasksMax").is_some_and(|v| v == "64"));
    ensure!(
        properties
            .get("CPUQuotaPerSecUSec")
            .is_some_and(|value| value == "1s")
    );
    let exec_start = required_property(properties, "ExecStart")?;
    ensure!(exec_start.contains(&executable.display().to_string()));
    let main_pid: i32 = required_property(properties, "MainPID")?.parse()?;
    let root = identities
        .iter()
        .find(|identity| identity.role == "root")
        .context("missing root identity")?;
    ensure!(main_pid == root.pid, "MainPID does not match fixture root");
    let cgroup = required_property(properties, "ControlGroup")?;
    let cgroup_members = cgroup_pids(cgroup)?;
    for identity in identities {
        ensure!(
            cgroup_members.contains(&identity.pid),
            "{} escaped systemd cgroup",
            identity.role
        );
        ensure!(identity.executable == executable.display().to_string());
    }
    ensure!(identity_environment_empty(identities));
    ensure!(live_fd_contract(identities));
    Ok(())
}

fn validate_pgid_contract(
    executable: &Path,
    command_pid: i32,
    root: &ProcessIdentity,
    identities: &[ProcessIdentity],
) -> Result<()> {
    ensure!(
        command_pid == root.pid,
        "PGID wrapper did not exec in place"
    );
    ensure!(
        root.pid == root.pgid && root.pid == root.sid,
        "root lacks independent Session"
    );
    ensure!(root.executable == executable.display().to_string());
    ensure!(
        identities
            .iter()
            .all(|item| item.executable == root.executable)
    );
    ensure!(identity_environment_empty(identities));
    ensure!(live_fd_contract(identities));
    Ok(())
}

fn checked_unit_signal(
    unit: &str,
    invocation: &str,
    executable: &Path,
    signal: Signal,
) -> Result<()> {
    let properties = systemctl_show(unit)?;
    ensure!(
        unit.starts_with(UNIT_PREFIX),
        "unit is outside owned prefix"
    );
    ensure!(
        properties
            .get("InvocationID")
            .is_some_and(|value| value == invocation),
        "InvocationID mismatch"
    );
    ensure!(
        properties
            .get("ExecStart")
            .is_some_and(|value| value.contains(&executable.display().to_string())),
        "ExecStart ownership mismatch"
    );
    let output = Command::new(SYSTEMCTL)
        .args([
            "--user",
            "kill",
            "--kill-whom=all",
            &format!("--signal={}", signal_name(signal)),
            unit,
        ])
        .stdin(Stdio::null())
        .output()?;
    ensure!(
        output.status.success(),
        "systemctl kill failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn checked_signal_pid(identity: &ProcessIdentity, signal: Signal) -> Result<()> {
    let current = process_identity(identity.pid, &identity.role)?;
    ensure!(same_process(identity, &current), "PID identity mismatch");
    kill(Pid::from_raw(identity.pid), signal)?;
    Ok(())
}

fn checked_signal_group(identity: &ProcessIdentity, signal: Signal) -> Result<()> {
    let current = process_identity(identity.pid, &identity.role)?;
    ensure!(
        same_process(identity, &current),
        "PGID owner identity mismatch"
    );
    ensure!(current.pgid == identity.pgid, "PGID changed");
    killpg(Pid::from_raw(identity.pgid), signal)?;
    Ok(())
}

fn signal_pgid_tree(
    root: &ProcessIdentity,
    identities: &[ProcessIdentity],
    signal: Signal,
) -> Result<()> {
    if process_running(root.pid) {
        checked_signal_group(root, signal)?;
    }
    for identity in identities {
        if identity.pgid != root.pgid && process_running(identity.pid) {
            checked_signal_pid(identity, signal)?;
        }
    }
    Ok(())
}

fn signal_owned_identities(identities: &[ProcessIdentity], signal: Signal) -> Result<()> {
    for identity in identities {
        if process_running(identity.pid) {
            checked_signal_pid(identity, signal)?;
        }
    }
    Ok(())
}

fn same_process(left: &ProcessIdentity, right: &ProcessIdentity) -> bool {
    left.pid == right.pid && left.start_ticks == right.start_ticks && left.pgid == right.pgid
}

fn process_running(pid: i32) -> bool {
    read_proc_stat(pid).is_ok_and(|stat| stat.state != 'Z')
}

fn pgid_exists(pgid: i32) -> bool {
    killpg(Pid::from_raw(pgid), None).is_ok()
}

fn read_roles(runtime: &Path, roles: &[&str]) -> Result<Vec<ProcessIdentity>> {
    roles
        .iter()
        .map(|role| {
            let value = fs::read(marker_dir(runtime).join(format!("{role}.json")))?;
            serde_json::from_slice(&value).context("parse process marker")
        })
        .collect()
}

fn collect_marker_identities(root: &Path) -> Result<Vec<ProcessIdentity>> {
    let mut result = Vec::new();
    collect_marker_identities_inner(root, &mut result)?;
    Ok(result)
}

fn collect_marker_identities_inner(root: &Path, result: &mut Vec<ProcessIdentity>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_marker_identities_inner(&path, result)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
            && let Ok(identity) = serde_json::from_slice::<ProcessIdentity>(&fs::read(&path)?)
        {
            result.push(identity);
        }
    }
    Ok(())
}

fn identity_environment_empty(identities: &[ProcessIdentity]) -> bool {
    identities
        .iter()
        .all(|identity| identity.environment_entries == 0)
}

fn live_fd_contract(identities: &[ProcessIdentity]) -> bool {
    identities.iter().all(|identity| {
        fs::read_dir(format!("/proc/{}/fd", identity.pid)).is_ok_and(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok())
                .all(|fd| fd <= 2)
        })
    })
}

fn live_fd_count_max(identities: &[ProcessIdentity]) -> Result<usize> {
    let mut maximum = 0;
    for identity in identities {
        maximum = maximum.max(fs::read_dir(format!("/proc/{}/fd", identity.pid))?.count());
    }
    Ok(maximum)
}

fn wait_identity(pid: i32, role: &str) -> Result<ProcessIdentity> {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        match process_identity(pid, role) {
            Ok(identity) if identity.executable.ends_with("/sleep") => return Ok(identity),
            Ok(_) | Err(_) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(identity) => return Ok(identity),
            Err(error) => return Err(error),
        }
    }
}

fn wait_identities_gone(identities: &[ProcessIdentity], deadline: Instant) -> Result<()> {
    while Instant::now() < deadline {
        if identities
            .iter()
            .all(|identity| !process_running(identity.pid))
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    let remaining: Vec<_> = identities
        .iter()
        .filter(|identity| process_running(identity.pid))
        .map(|identity| (&identity.role, identity.pid))
        .collect();
    bail!("owned fixture identities remain: {remaining:?}")
}

fn cgroup_path(control_group: &str) -> PathBuf {
    Path::new("/sys/fs/cgroup").join(control_group.trim_start_matches('/'))
}

fn cgroup_pids(control_group: &str) -> Result<BTreeSet<i32>> {
    let path = cgroup_path(control_group).join("cgroup.procs");
    if !path.exists() {
        return Ok(BTreeSet::new());
    }
    fs::read_to_string(path)?
        .split_whitespace()
        .map(|value| value.parse().map_err(Into::into))
        .collect()
}

fn wait_cgroup_empty(control_group: &str, deadline: Instant) -> Result<()> {
    while Instant::now() < deadline {
        if cgroup_pids(control_group)?.is_empty() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    bail!("cgroup did not empty: {control_group}")
}

fn wait_unit_ready(unit: &str, timeout: Duration) -> Result<BTreeMap<String, String>> {
    let deadline = Instant::now() + timeout;
    let mut last = BTreeMap::new();
    while Instant::now() < deadline {
        last = systemctl_show(unit)?;
        if last
            .get("ActiveState")
            .is_some_and(|value| value == "active")
            && last.get("MainPID").is_some_and(|value| value != "0")
            && last
                .get("InvocationID")
                .is_some_and(|value| !value.is_empty())
        {
            return Ok(last);
        }
        thread::sleep(Duration::from_millis(25));
    }
    bail!("unit failed to become active: {unit}: {last:?}")
}

fn systemctl_show(unit: &str) -> Result<BTreeMap<String, String>> {
    let output = Command::new(SYSTEMCTL)
        .args(["--user", "show", unit, "--all", "--no-pager"])
        .stdin(Stdio::null())
        .output()?;
    let mut properties = BTreeMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some((key, value)) = line.split_once('=') {
            properties.insert(key.to_owned(), value.to_owned());
        }
    }
    Ok(properties)
}

fn wait_unit_collected(unit: &str, timeout: Duration) -> Result<bool> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let properties = systemctl_show(unit)?;
        if properties
            .get("LoadState")
            .is_some_and(|value| value == "not-found")
        {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(25));
    }
    let _ = Command::new(SYSTEMCTL)
        .args(["--user", "reset-failed", unit])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if systemctl_show(unit)?
            .get("LoadState")
            .is_some_and(|value| value == "not-found")
        {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(25));
    }
    Ok(false)
}

fn selected_unit_properties(properties: &BTreeMap<String, String>) -> BTreeMap<&str, &str> {
    [
        "Id",
        "InvocationID",
        "ControlGroup",
        "MainPID",
        "ActiveEnterTimestampMonotonic",
        "KillMode",
        "LimitCORE",
        "NoNewPrivileges",
        "MemoryMax",
        "TasksMax",
        "CPUQuotaPerSecUSec",
        "TimeoutStopUSec",
        "UMask",
        "WorkingDirectory",
    ]
    .into_iter()
    .filter_map(|key| properties.get(key).map(|value| (key, value.as_str())))
    .collect()
}

fn required_property<'a>(properties: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    properties
        .get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .with_context(|| format!("missing systemd property {key}"))
}

fn wait_child(child: &mut Child, timeout: Duration) -> Result<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            bail!("managed command did not exit before timeout");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn exit_status_json(status: ExitStatus) -> Value {
    use std::os::unix::process::ExitStatusExt;
    json!({
        "success": status.success(),
        "code": status.code(),
        "signal": status.signal(),
    })
}

fn inspect_coredump(pid: i32, runtime: &Path) -> Result<Value> {
    thread::sleep(Duration::from_millis(500));
    let output = Command::new(COREDUMPCTL)
        .args(["--no-pager", "--json=short", "list", &pid.to_string()])
        .stdin(Stdio::null())
        .output()?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stored = combined.contains("\"COREFILE\":\"present\"")
        || combined.contains("(present)")
        || combined.contains("Storage: /");
    let runtime_core_files = find_core_files(runtime)?;
    let state = if stored {
        "stored"
    } else if output.stdout.is_empty() {
        "no-metadata"
    } else {
        "metadata-without-stored-file"
    };
    Ok(json!({
        "pid": pid,
        "coredumpctl_exit": output.status.code(),
        "coredumpctl_state": state,
        "runtime_core_files": runtime_core_files,
        "no_stored_dump": !stored && runtime_core_files.is_empty(),
    }))
}

fn find_core_files(root: &Path) -> Result<Vec<String>> {
    let mut result = Vec::new();
    find_core_files_inner(root, &mut result)?;
    Ok(result)
}

fn find_core_files_inner(root: &Path, result: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            find_core_files_inner(&path, result)?;
        } else if path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("core"))
        {
            result.push(path.display().to_string());
        }
    }
    Ok(())
}

fn backend_passed(cancel: &Value, crash: &Value) -> bool {
    cancel["passed"] == true && crash["passed"] == true
}

fn log_gate_passed(cancel: &Value) -> bool {
    cancel["log"]["memory_bound_bytes"].as_u64()
        == Some((LOG_CHANNEL_CAPACITY * LOG_CHUNK_BYTES) as u64)
        && cancel["log"]["dropped_chunks"].as_u64().unwrap_or(0) > 0
        && cancel["log"]["preview_bytes"].as_u64().unwrap_or(u64::MAX) <= LOG_PREVIEW_LIMIT
}

fn spawn_log_reader<R: Read + Send + 'static>(
    mut reader: R,
    stream: &'static str,
    sender: SyncSender<LogChunk>,
    counters: Arc<LogCounters>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut chunk = LogChunk::new(stream);
        loop {
            match reader.read(&mut chunk.bytes) {
                Ok(0) | Err(_) => break,
                Ok(length) => {
                    chunk.len = length;
                    let byte_counter = if stream == "stdout" {
                        &counters.stdout_bytes
                    } else {
                        &counters.stderr_bytes
                    };
                    byte_counter.fetch_add(length as u64, Ordering::Relaxed);
                    match sender.try_send(chunk) {
                        Ok(()) => {
                            counters.queued_chunks.fetch_add(1, Ordering::Relaxed);
                            chunk = LogChunk::new(stream);
                        }
                        Err(TrySendError::Full(returned)) => {
                            counters.dropped_chunks.fetch_add(1, Ordering::Relaxed);
                            chunk = returned;
                        }
                        Err(TrySendError::Disconnected(_)) => break,
                    }
                }
            }
        }
    })
}

fn read_rss_kib() -> Result<u64> {
    let status = fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .context("VmRSS missing")?;
    line.split_whitespace()
        .nth(1)
        .context("VmRSS value missing")?
        .parse()
        .map_err(Into::into)
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    ensure!(
        fs::metadata(path)?.uid() == getpid_uid(),
        "directory owner mismatch"
    );
    Ok(())
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn write_evidence(directory: &Path, evidence: &Value) -> Result<()> {
    create_private_dir(directory)?;
    let results = serde_json::to_vec_pretty(evidence)?;
    write_atomic_private(&directory.join("results.json"), &results)?;
    let summary = json!({
        "schema": evidence["schema"],
        "status": evidence["status"],
        "gate_duration_seconds": evidence["gate_duration_seconds"],
        "assertions": evidence["assertions"],
        "systemd_cancel_seconds": evidence["systemd"]["cancel"]["cancel_seconds"],
        "pgid_cancel_seconds": evidence["pgid"]["cancel"]["cancel_seconds"],
    });
    write_atomic_private(
        &directory.join("summary.json"),
        &serde_json::to_vec_pretty(&summary)?,
    )?;
    Ok(())
}

fn write_atomic_private(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().context("evidence path lacks parent")?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name().unwrap().to_string_lossy(),
        random_id()?
    ));
    write_private_file(&temporary, contents)?;
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn random_id() -> Result<String> {
    let value = fs::read_to_string("/proc/sys/kernel/random/uuid")?;
    Ok(value
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(12)
        .collect())
}

fn runtime_base() -> Result<PathBuf> {
    let fallback = format!("/run/user/{}", getpid_uid());
    let path =
        std::env::var_os("XDG_RUNTIME_DIR").map_or_else(|| PathBuf::from(fallback), PathBuf::from);
    let metadata = fs::metadata(&path)?;
    ensure!(
        metadata.uid() == getpid_uid(),
        "runtime base owner mismatch"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "runtime base is not private"
    );
    Ok(path)
}

fn verify_program_paths(executable: &Path) -> Result<()> {
    for path in [
        executable,
        Path::new(SYSTEMD_RUN),
        Path::new(SYSTEMCTL),
        Path::new(ENV),
        Path::new(SETSID),
        Path::new(PRLIMIT),
        Path::new(COREDUMPCTL),
        Path::new(SLEEP),
    ] {
        ensure!(
            path.is_absolute(),
            "program path is relative: {}",
            path.display()
        );
        let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        ensure!(
            metadata.is_file(),
            "program is not a file: {}",
            path.display()
        );
        ensure!(
            metadata.mode() & 0o022 == 0,
            "program is group/world writable: {}",
            path.display()
        );
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
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

fn command_first_line(program: &str, arguments: &[&str]) -> String {
    Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .ok()
        .and_then(|output| {
            let combined = if output.stdout.is_empty() {
                output.stderr
            } else {
                output.stdout
            };
            String::from_utf8_lossy(&combined)
                .lines()
                .next()
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn core_limit_zero() -> Result<bool> {
    let limits = fs::read_to_string("/proc/self/limits")?;
    Ok(limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .is_some_and(|line| {
            let values: Vec<_> = line.split_whitespace().collect();
            values.get(values.len().saturating_sub(3)) == Some(&"0")
                && values.get(values.len().saturating_sub(2)) == Some(&"0")
        }))
}

fn signal_name(signal: Signal) -> &'static str {
    match signal {
        Signal::SIGINT => "SIGINT",
        Signal::SIGTERM => "SIGTERM",
        Signal::SIGKILL => "SIGKILL",
        Signal::SIGCONT => "SIGCONT",
        _ => "UNSUPPORTED",
    }
}

fn emergency_cleanup(executable: &Path, unit_base: &str, runtime_root: &Path) {
    for suffix in ["cancel", "crash"] {
        let unit = format!("{unit_base}-{suffix}.service");
        if let Ok(properties) = systemctl_show(&unit)
            && properties
                .get("ExecStart")
                .is_some_and(|value| value.contains(&executable.display().to_string()))
        {
            let _ = Command::new(SYSTEMCTL)
                .args([
                    "--user",
                    "kill",
                    "--kill-whom=all",
                    "--signal=SIGKILL",
                    &unit,
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = Command::new(SYSTEMCTL)
                .args(["--user", "stop", &unit])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
    for _ in 0..3 {
        if let Ok(identities) = collect_marker_identities(runtime_root) {
            for identity in identities {
                if process_running(identity.pid) {
                    let _ = checked_signal_pid(&identity, Signal::SIGKILL);
                }
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = fs::remove_dir_all(runtime_root);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_stat_parser_reads_current_process() {
        let stat = read_proc_stat(i32::try_from(std::process::id()).unwrap()).unwrap();
        assert!(stat.start_ticks > 0);
        assert!(stat.pgid > 0);
        assert!(stat.sid > 0);
    }

    #[test]
    fn same_process_requires_pid_start_and_pgid() {
        let base = ProcessIdentity {
            role: "test".to_owned(),
            pid: 10,
            ppid: 1,
            pgid: 10,
            sid: 10,
            start_ticks: 100,
            environment_entries: 0,
            open_fd_count_at_marker: 3,
            executable: "/test".to_owned(),
        };
        assert!(same_process(&base, &base));
        let mut reused = base.clone();
        reused.start_ticks += 1;
        assert!(!same_process(&base, &reused));
        let mut moved = base.clone();
        moved.pgid += 1;
        assert!(!same_process(&base, &moved));
    }

    #[test]
    fn bounded_log_contract_is_fixed() {
        assert_eq!(LOG_CHANNEL_CAPACITY * LOG_CHUNK_BYTES, 512 * 1024);
        assert_eq!(LOG_PREVIEW_LIMIT, 256 * 1024);
    }
}
