use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use flagdeck_core::{
    CoreError, CoreService, CreateProjectRequest, JobLogStream, JobPageRequest,
    PreviewCatalogToolRequest, PreviewJobLogRequest, RunCatalogToolRequest,
};
use flagdeck_domain::{ExecutionStatus, RiskLevel, ToolInputSource, ToolIoKind};
use tempfile::tempdir;

fn tools_root_available() -> bool {
    Path::new("/data/CTF/Tools").is_dir() || Path::new("/usr/bin/curl").is_file()
}

fn write_typed_ffuf_catalog(catalog_root: &Path) {
    let tools_dir = catalog_root.join("tools");
    fs::create_dir_all(&tools_dir).unwrap();
    fs::write(
        tools_dir.join("ffuf.toml"),
        r#"
id = "ffuf"
name = "ffuf"
category = "content_discovery"
mode = "embedded_cli"

[io]
schema_version = 1

[[io.inputs]]
id = "target"
kind = "url"
field = "url"

[[io.inputs]]
id = "wordlist"
kind = "wordlist"
field = "wordlist"

[[io.outputs]]
id = "discoveries"
kind = "http_discovery"

[[io.outputs]]
id = "raw_output"
kind = "raw_artifact"

[binary]
path = "/usr/bin/true"
resolve = ["path"]

[[form.fields]]
id = "url"
type = "url"
label = "目标"
required = true
from = "target_url"

[[form.fields]]
id = "wordlist"
type = "text"
label = "字典"
required = true

[[form.fields]]
id = "rate"
type = "number"
label = "速率"
default = "0"

[[form.fields]]
id = "secret"
type = "text"
label = "令牌"
sensitive = true

[argv]
template = ["--", "{url}", "{wordlist}", "{secret}"]
"#,
    )
    .unwrap();
}

#[test]
fn catalog_snapshot_exposes_ffuf_tier() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    let tools_dir = catalog_root.join("tools");
    fs::create_dir_all(&tools_dir).unwrap();
    fs::write(
        tools_dir.join("ffuf.toml"),
        r#"
id = "ffuf"
name = "ffuf"
category = "content_discovery"
tier = "tier_1"
mode = "embedded_cli"

[binary]
command = "ffuf"
resolve = ["system"]

[argv]
template = ["-V"]
"#,
    )
    .unwrap();

    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let snapshot = core.list_catalog().expect("catalog should load");
    let ffuf = snapshot
        .tools
        .iter()
        .find(|tool| tool.id == "ffuf")
        .expect("ffuf should be listed");

    assert_eq!(ffuf.tier, "tier_1");
}

#[test]
fn catalog_snapshot_exposes_ffuf_path_discovery_capability() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    let tools_dir = catalog_root.join("tools");
    fs::create_dir_all(&tools_dir).unwrap();
    fs::write(
        tools_dir.join("ffuf.toml"),
        r#"
id = "ffuf"
name = "ffuf"
category = "content_discovery"
capabilities = ["path_discovery"]
mode = "embedded_cli"

[binary]
command = "ffuf"
resolve = ["system"]

[argv]
template = ["-V"]
"#,
    )
    .unwrap();

    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let snapshot = core.list_catalog().expect("catalog should load");
    let ffuf = snapshot
        .tools
        .iter()
        .find(|tool| tool.id == "ffuf")
        .expect("ffuf should be listed");

    assert_eq!(ffuf.capabilities, ["path_discovery"]);
}

#[test]
fn catalog_snapshot_exposes_ffuf_chinese_aliases() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    let tools_dir = catalog_root.join("tools");
    fs::create_dir_all(&tools_dir).unwrap();
    fs::write(
        tools_dir.join("ffuf.toml"),
        r#"
id = "ffuf"
name = "ffuf"
category = "content_discovery"
aliases = ["扫目录", "路径发现", "目录扫描"]
mode = "embedded_cli"

[binary]
command = "ffuf"
resolve = ["system"]

[argv]
template = ["-V"]
"#,
    )
    .unwrap();

    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let snapshot = core.list_catalog().expect("catalog should load");
    let ffuf = snapshot
        .tools
        .iter()
        .find(|tool| tool.id == "ffuf")
        .expect("ffuf should be listed");

    assert_eq!(ffuf.aliases, ["扫目录", "路径发现", "目录扫描"]);
}

#[test]
fn catalog_snapshot_exposes_ffuf_presets() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    let tools_dir = catalog_root.join("tools");
    fs::create_dir_all(&tools_dir).unwrap();
    fs::write(
        tools_dir.join("ffuf.toml"),
        r#"
id = "ffuf"
name = "ffuf"
category = "content_discovery"
mode = "embedded_cli"

[[presets]]
id = "quick_scan"
name = "快速扫描"

[[presets]]
id = "recursive_scan"
name = "递归扫描"

[[presets]]
id = "virtual_host_discovery"
name = "虚拟主机发现"

[binary]
command = "ffuf"
resolve = ["system"]

[argv]
template = ["-V"]
"#,
    )
    .unwrap();

    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let snapshot = core.list_catalog().expect("catalog should load");
    let ffuf = snapshot
        .tools
        .iter()
        .find(|tool| tool.id == "ffuf")
        .expect("ffuf should be listed");
    let preset_ids = ffuf
        .presets
        .iter()
        .map(|preset| preset.id.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        preset_ids,
        ["quick_scan", "recursive_scan", "virtual_host_discovery"]
    );
}

#[test]
fn catalog_snapshot_exposes_ffuf_quick_scan_behavior() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    let tools_dir = catalog_root.join("tools");
    fs::create_dir_all(&tools_dir).unwrap();
    fs::write(
        tools_dir.join("ffuf.toml"),
        r#"
id = "ffuf"
name = "ffuf"
category = "content_discovery"
mode = "embedded_cli"

[[presets]]
id = "quick_scan"
name = "快速扫描"
core_fields = ["url", "wordlist", "threads", "mc"]

[presets.defaults]
recursion = "no"

[binary]
command = "ffuf"
resolve = ["system"]

[argv]
template = ["-V"]
"#,
    )
    .unwrap();

    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let snapshot = core.list_catalog().expect("catalog should load");
    let ffuf = snapshot
        .tools
        .iter()
        .find(|tool| tool.id == "ffuf")
        .expect("ffuf should be listed");
    let quick_scan = ffuf
        .presets
        .iter()
        .find(|preset| preset.id == "quick_scan")
        .expect("quick scan should be listed");

    assert_eq!(quick_scan.core_fields, ["url", "wordlist", "threads", "mc"]);
    assert_eq!(
        quick_scan.defaults.get("recursion").map(String::as_str),
        Some("no")
    );
}

#[test]
fn catalog_snapshot_exposes_ffuf_recursive_scan_behavior() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    let tools_dir = catalog_root.join("tools");
    fs::create_dir_all(&tools_dir).unwrap();
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/tool-catalog/tools/ffuf.toml"),
        tools_dir.join("ffuf.toml"),
    )
    .unwrap();

    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let snapshot = core.list_catalog().expect("catalog should load");
    let ffuf = snapshot
        .tools
        .iter()
        .find(|tool| tool.id == "ffuf")
        .expect("ffuf should be listed");
    let recursive_scan = ffuf
        .presets
        .iter()
        .find(|preset| preset.id == "recursive_scan")
        .expect("recursive scan should be listed");

    assert_eq!(
        recursive_scan.core_fields,
        ["url", "wordlist", "threads", "mc", "recursion_depth"]
    );
    assert_eq!(
        recursive_scan.defaults.get("recursion").map(String::as_str),
        Some("yes")
    );
}

#[test]
fn catalog_snapshot_exposes_ffuf_virtual_host_discovery_behavior() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    let tools_dir = catalog_root.join("tools");
    fs::create_dir_all(&tools_dir).unwrap();
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/tool-catalog/tools/ffuf.toml"),
        tools_dir.join("ffuf.toml"),
    )
    .unwrap();

    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let snapshot = core.list_catalog().expect("catalog should load");
    let ffuf = snapshot
        .tools
        .iter()
        .find(|tool| tool.id == "ffuf")
        .expect("ffuf should be listed");
    let virtual_host_discovery = ffuf
        .presets
        .iter()
        .find(|preset| preset.id == "virtual_host_discovery")
        .expect("virtual host discovery should be listed");

    assert_eq!(
        virtual_host_discovery.core_fields,
        ["url", "wordlist", "threads", "mc", "vhost"]
    );
    assert_eq!(
        virtual_host_discovery
            .defaults
            .get("recursion")
            .map(String::as_str),
        Some("no")
    );
}

#[test]
fn catalog_snapshot_exposes_ffuf_field_groups() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    let tools_dir = catalog_root.join("tools");
    fs::create_dir_all(&tools_dir).unwrap();
    fs::write(
        tools_dir.join("ffuf.toml"),
        r#"
id = "ffuf"
name = "ffuf"
category = "content_discovery"
mode = "embedded_cli"

[[field_groups]]
id = "target"
name = "目标"
fields = ["url", "wordlist"]

[[field_groups]]
id = "matching"
name = "匹配与过滤"
fields = ["mc", "fc"]

[[field_groups]]
id = "request"
name = "请求"
fields = ["method", "headers"]

[[field_groups]]
id = "execution"
name = "执行"
fields = ["threads", "rate"]

[binary]
command = "ffuf"
resolve = ["system"]

[argv]
template = ["-V"]
"#,
    )
    .unwrap();

    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let snapshot = core.list_catalog().expect("catalog should load");
    let ffuf = snapshot
        .tools
        .iter()
        .find(|tool| tool.id == "ffuf")
        .expect("ffuf should be listed");
    let group_ids = ffuf
        .field_groups
        .iter()
        .map(|group| group.id.as_str())
        .collect::<Vec<_>>();

    assert_eq!(group_ids, ["target", "matching", "request", "execution"]);
}

#[test]
fn catalog_snapshot_exposes_ffuf_risk_level() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    let tools_dir = catalog_root.join("tools");
    fs::create_dir_all(&tools_dir).unwrap();
    fs::write(
        tools_dir.join("ffuf.toml"),
        r#"
id = "ffuf"
name = "ffuf"
category = "content_discovery"
risk_level = "l2"
mode = "embedded_cli"

[binary]
command = "ffuf"
resolve = ["system"]

[argv]
template = ["-V"]
"#,
    )
    .unwrap();

    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let snapshot = core.list_catalog().expect("catalog should load");
    let ffuf = snapshot
        .tools
        .iter()
        .find(|tool| tool.id == "ffuf")
        .expect("ffuf should be listed");

    assert_eq!(ffuf.risk_level, "l2");
}

#[test]
fn catalog_snapshot_exposes_ffuf_installation_summary() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    let tools_dir = catalog_root.join("tools");
    fs::create_dir_all(&tools_dir).unwrap();
    fs::write(
        tools_dir.join("ffuf.toml"),
        r#"
id = "ffuf"
name = "ffuf"
category = "content_discovery"
mode = "embedded_cli"

[installation]
distribution = "hybrid"
license = "MIT"
homepage = "https://github.com/ffuf/ffuf"
version = "2.1.0-dev"
health_strategy = "safe-version-command"

[binary]
command = "ffuf"
resolve = ["system"]

[argv]
template = ["-V"]
"#,
    )
    .unwrap();

    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let snapshot = core.list_catalog().expect("catalog should load");
    let ffuf = snapshot
        .tools
        .iter()
        .find(|tool| tool.id == "ffuf")
        .expect("ffuf should be listed");

    assert_eq!(
        (
            ffuf.installation.distribution.as_str(),
            ffuf.installation.license.as_str(),
            ffuf.installation.homepage.as_str(),
            ffuf.installation.version.as_str(),
            ffuf.installation.health_strategy.as_str(),
        ),
        (
            "hybrid",
            "MIT",
            "https://github.com/ffuf/ffuf",
            "2.1.0-dev",
            "safe-version-command",
        )
    );
}

#[test]
fn catalog_snapshot_exposes_ffuf_typed_io_contract() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    write_typed_ffuf_catalog(&catalog_root);

    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let snapshot = core.list_catalog().expect("catalog should load");
    let ffuf = snapshot
        .tools
        .iter()
        .find(|tool| tool.id == "ffuf")
        .expect("ffuf should be listed");

    assert_eq!(ffuf.io.schema_version, 1);
    assert_eq!(
        ffuf.io
            .inputs
            .iter()
            .map(|input| (input.id.as_str(), input.kind, input.field.as_str()))
            .collect::<Vec<_>>(),
        [
            ("target", ToolIoKind::Url, "url"),
            ("wordlist", ToolIoKind::Wordlist, "wordlist"),
        ]
    );
    assert_eq!(
        ffuf.io
            .outputs
            .iter()
            .map(|output| (output.id.as_str(), output.kind))
            .collect::<Vec<_>>(),
        [
            ("discoveries", ToolIoKind::HttpDiscovery),
            ("raw_output", ToolIoKind::RawArtifact),
        ]
    );
}

async fn wait_terminal(
    core: &CoreService,
    project_id: &flagdeck_domain::ProjectId,
    job_id: &flagdeck_domain::JobId,
) {
    for _ in 0..80 {
        tokio::time::sleep(Duration::from_millis(150)).await;
        let page = core
            .list_jobs(&JobPageRequest {
                project_id: project_id.clone(),
                cursor: None,
                limit: 20,
            })
            .unwrap();
        let current = page
            .items
            .iter()
            .find(|item| item.job.job_id == *job_id)
            .unwrap();
        if !matches!(
            current.job.execution_status,
            ExecutionStatus::Queued
                | ExecutionStatus::Starting
                | ExecutionStatus::Running
                | ExecutionStatus::Stopping
        ) {
            println!(
                "terminal status={:?} reason={:?}",
                current.job.execution_status, current.job.exit_reason
            );
            return;
        }
    }
    panic!("job did not finish in time");
}

#[tokio::test]
async fn catalog_job_records_typed_io_sources_without_sensitive_values() {
    if !Path::new("/usr/bin/true").is_file() {
        eprintln!("skip typed catalog run: /usr/bin/true missing");
        return;
    }

    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    write_typed_ffuf_catalog(&catalog_root);

    let core = Arc::new(CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    ));
    let project = core
        .create_project(&CreateProjectRequest {
            name: "typed-io".to_owned(),
        })
        .unwrap();
    let view = core
        .start_catalog_tool(RunCatalogToolRequest {
            project_id: project.project_id.clone(),
            tool_id: "ffuf".to_owned(),
            target_url: "http://127.0.0.1:9/".to_owned(),
            form: BTreeMap::from([
                ("url".to_owned(), "http://127.0.0.1:9/".to_owned()),
                ("wordlist".to_owned(), "common.txt".to_owned()),
                ("secret".to_owned(), "top-secret-token".to_owned()),
            ]),
            confirm_sensitive_argv: true,
            confirm_l2: true,
            l3_confirmation: Some("RUN CATALOG ffuf".to_owned()),
        })
        .unwrap();

    assert_eq!(view.io.schema_version, 1);
    assert_eq!(
        view.io
            .inputs
            .iter()
            .map(|input| (
                input.id.as_str(),
                input.kind,
                input.source,
                input.source_id.as_str(),
            ))
            .collect::<Vec<_>>(),
        [
            (
                "target",
                ToolIoKind::Url,
                ToolInputSource::TargetContext,
                "url",
            ),
            (
                "wordlist",
                ToolIoKind::Wordlist,
                ToolInputSource::Form,
                "wordlist",
            ),
        ]
    );
    assert_eq!(
        view.io
            .outputs
            .iter()
            .map(|output| (output.id.as_str(), output.kind))
            .collect::<Vec<_>>(),
        [
            ("discoveries", ToolIoKind::HttpDiscovery),
            ("raw_output", ToolIoKind::RawArtifact),
        ]
    );
    assert!(
        !serde_json::to_string(&view)
            .unwrap()
            .contains("top-secret-token")
    );

    wait_terminal(&core, &project.project_id, &view.job.job_id).await;
}

#[tokio::test]
async fn catalog_curl_writes_visible_logs() {
    if !Path::new("/usr/bin/curl").is_file() {
        eprintln!("skip catalog_curl: /usr/bin/curl missing");
        return;
    }

    let temporary = tempdir().unwrap();
    let core = Arc::new(CoreService::new(temporary.path().join("workspaces")));
    let project = core
        .create_project(&CreateProjectRequest {
            name: "catalog-log".to_owned(),
        })
        .unwrap();

    let mut form = BTreeMap::new();
    form.insert("url".to_owned(), "http://127.0.0.1:9/".to_owned());
    form.insert("method".to_owned(), "GET".to_owned());
    form.insert("max_time".to_owned(), "2".to_owned());

    let job = core
        .start_catalog_tool(RunCatalogToolRequest {
            project_id: project.project_id.clone(),
            tool_id: "curl".to_owned(),
            target_url: "http://127.0.0.1:9/".to_owned(),
            form,
            confirm_sensitive_argv: false,
            confirm_l2: true,
            l3_confirmation: None,
        })
        .unwrap();

    wait_terminal(&core, &project.project_id, &job.job.job_id).await;

    let stdout = core
        .preview_job_log(&PreviewJobLogRequest {
            project_id: project.project_id.clone(),
            job_id: job.job.job_id.clone(),
            stream: JobLogStream::Stdout,
            offset: 0,
            limit: 64 * 1024,
        })
        .unwrap();
    let stderr = core
        .preview_job_log(&PreviewJobLogRequest {
            project_id: project.project_id.clone(),
            job_id: job.job.job_id.clone(),
            stream: JobLogStream::Stderr,
            offset: 0,
            limit: 64 * 1024,
        })
        .unwrap();

    let combined = format!("{}\n{}", stdout.content, stderr.content);
    assert!(
        combined.contains("FlagDeck launch"),
        "missing launch banner: {combined}"
    );
    assert!(
        combined.contains("process started")
            || combined.contains("finished")
            || combined.contains("curl:"),
        "expected process output: {combined}"
    );
}

#[tokio::test]
async fn catalog_gui_godzilla_detaches_or_logs_error() {
    let launcher = Path::new("/data/CTF/Tools/Active/webshell-tools/Godzilla/start-godzilla.sh");
    if !launcher.is_file() {
        eprintln!("skip godzilla launch: local tools root unavailable");
        return;
    }
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        eprintln!("skip godzilla launch: no display session");
        return;
    }

    let temporary = tempdir().unwrap();
    let core = Arc::new(CoreService::new(temporary.path().join("workspaces")));
    let project = core
        .create_project(&CreateProjectRequest {
            name: "catalog-gui".to_owned(),
        })
        .unwrap();

    let job = core
        .start_catalog_tool(RunCatalogToolRequest {
            project_id: project.project_id.clone(),
            tool_id: "godzilla".to_owned(),
            target_url: String::new(),
            form: BTreeMap::new(),
            confirm_sensitive_argv: false,
            confirm_l2: false,
            l3_confirmation: Some("RUN CATALOG godzilla".to_owned()),
        })
        .unwrap();

    wait_terminal(&core, &project.project_id, &job.job.job_id).await;

    let stdout = core
        .preview_job_log(&PreviewJobLogRequest {
            project_id: project.project_id.clone(),
            job_id: job.job.job_id.clone(),
            stream: JobLogStream::Stdout,
            offset: 0,
            limit: 64 * 1024,
        })
        .unwrap();
    assert!(
        stdout.content.contains("FlagDeck launch"),
        "missing banner: {}",
        stdout.content
    );
    assert!(
        stdout.content.contains("gui")
            || stdout.content.contains("detached")
            || stdout.content.contains("spawned")
            || stdout.content.contains("failed"),
        "unexpected gui log: {}",
        stdout.content
    );

    let _ = std::process::Command::new("pkill")
        .args(["-f", "godzilla.jar"])
        .status();
}

#[tokio::test]
async fn catalog_lists_without_local_tools_root() {
    // Catalog metadata must load from the repo config even when /data/CTF/Tools is absent.
    let temporary = tempdir().unwrap();
    let core = Arc::new(CoreService::new(temporary.path().join("workspaces")));
    let snapshot = core
        .list_catalog()
        .expect("catalog should load from repo config");
    assert!(
        snapshot.tools.iter().any(|tool| tool.id == "curl"),
        "expected curl in catalog"
    );
    let _ = tools_root_available();
}

#[test]
fn catalog_sensitive_argv_requires_explicit_confirmation() {
    if !Path::new("/usr/bin/curl").is_file() {
        return;
    }
    let temporary = tempdir().unwrap();
    let core = Arc::new(CoreService::new(temporary.path().join("workspaces")));
    let project = core
        .create_project(&CreateProjectRequest {
            name: "catalog-sensitive-confirmation".to_owned(),
        })
        .unwrap();
    let form = BTreeMap::from([
        ("url".to_owned(), "http://127.0.0.1:9/".to_owned()),
        ("method".to_owned(), "GET".to_owned()),
        ("cookie".to_owned(), "session=secret".to_owned()),
    ]);
    assert!(
        core.start_catalog_tool(RunCatalogToolRequest {
            project_id: project.project_id,
            tool_id: "curl".to_owned(),
            target_url: "http://127.0.0.1:9/".to_owned(),
            form,
            confirm_sensitive_argv: false,
            confirm_l2: true,
            l3_confirmation: None,
        })
        .is_err()
    );
}

#[test]
fn catalog_preview_redacts_sensitive_command_without_creating_job() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    write_typed_ffuf_catalog(&catalog_root);
    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let project = core
        .create_project(&CreateProjectRequest {
            name: "catalog-preview".to_owned(),
        })
        .unwrap();

    let preview = core
        .preview_catalog_tool(PreviewCatalogToolRequest {
            project_id: project.project_id.clone(),
            tool_id: "ffuf".to_owned(),
            target_url: "http://127.0.0.1:9/".to_owned(),
            form: BTreeMap::from([
                ("url".to_owned(), "http://127.0.0.1:9/".to_owned()),
                ("wordlist".to_owned(), "common.txt".to_owned()),
                ("secret".to_owned(), "top-secret-token".to_owned()),
            ]),
        })
        .unwrap();
    let jobs = core
        .list_jobs(&JobPageRequest {
            project_id: project.project_id,
            cursor: None,
            limit: 20,
        })
        .unwrap();

    assert!(preview.command_preview.contains("[REDACTED]"));
    assert!(!preview.command_preview.contains("top-secret-token"));
    assert!(jobs.items.is_empty());
}

#[test]
fn catalog_preview_summarizes_scope_rate_size_and_risk() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    write_typed_ffuf_catalog(&catalog_root);
    let wordlist = temporary.path().join("preview-wordlist.txt");
    fs::write(&wordlist, "admin\nlogin\napi\n").unwrap();
    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let project = core
        .create_project(&CreateProjectRequest {
            name: "catalog-preview-summary".to_owned(),
        })
        .unwrap();

    let preview = core
        .preview_catalog_tool(PreviewCatalogToolRequest {
            project_id: project.project_id,
            tool_id: "ffuf".to_owned(),
            target_url: "http://127.0.0.1:9/".to_owned(),
            form: BTreeMap::from([
                ("url".to_owned(), "http://127.0.0.1:9/".to_owned()),
                ("wordlist".to_owned(), wordlist.display().to_string()),
                ("rate".to_owned(), "25".to_owned()),
                ("secret".to_owned(), String::new()),
            ]),
        })
        .unwrap();

    assert_eq!(
        (
            preview.scope.as_str(),
            preview.rate_per_second,
            preview.estimated_request_count,
            preview.risk_level,
        ),
        (
            "http://127.0.0.1:9/",
            Some(25),
            Some(3),
            flagdeck_domain::RiskLevel::L2,
        )
    );
}

#[test]
fn catalog_preview_remains_available_when_binary_is_missing() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    let tools_dir = catalog_root.join("tools");
    fs::create_dir_all(&tools_dir).unwrap();
    fs::write(
        tools_dir.join("ffuf.toml"),
        r#"
id = "ffuf"
name = "ffuf"
category = "content_discovery"
mode = "embedded_cli"

[binary]
command = "flagdeck-test-missing-ffuf"
resolve = ["system"]

[[form.fields]]
id = "url"
type = "url"
label = "目标"
required = true
from = "target_url"

[[form.fields]]
id = "wordlist"
type = "text"
label = "字典"
required = true

[argv]
template = ["-u", "{url}", "-w", "{wordlist}"]
"#,
    )
    .unwrap();
    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let project = core
        .create_project(&CreateProjectRequest {
            name: "catalog-preview-missing-binary".to_owned(),
        })
        .unwrap();

    let preview = core
        .preview_catalog_tool(PreviewCatalogToolRequest {
            project_id: project.project_id,
            tool_id: "ffuf".to_owned(),
            target_url: "http://127.0.0.1:9/".to_owned(),
            form: BTreeMap::from([("wordlist".to_owned(), "common.txt".to_owned())]),
        })
        .expect("preview should describe the command before ffuf is installed");

    assert!(
        preview
            .command_preview
            .contains("flagdeck-test-missing-ffuf")
    );
}

#[tokio::test]
async fn catalog_l2_run_requires_explicit_confirmation() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    write_typed_ffuf_catalog(&catalog_root);
    let core = Arc::new(CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    ));
    let project = core
        .create_project(&CreateProjectRequest {
            name: "catalog-l2-confirmation".to_owned(),
        })
        .unwrap();

    let result = core.start_catalog_tool(RunCatalogToolRequest {
        project_id: project.project_id,
        tool_id: "ffuf".to_owned(),
        target_url: "http://127.0.0.1:9/".to_owned(),
        form: BTreeMap::from([
            ("url".to_owned(), "http://127.0.0.1:9/".to_owned()),
            ("wordlist".to_owned(), "common.txt".to_owned()),
            ("secret".to_owned(), String::new()),
        ]),
        confirm_sensitive_argv: false,
        confirm_l2: false,
        l3_confirmation: None,
    });

    assert!(
        matches!(
            result,
            Err(CoreError::CatalogConfirmationRequired(RiskLevel::L2))
        ),
        "unexpected catalog run result: {result:?}"
    );
}

#[test]
fn real_ffuf_catalog_preview_returns_for_desktop_form_values() {
    let temporary = tempdir().unwrap();
    let core = CoreService::new(temporary.path().join("workspaces"));
    let project = core
        .create_project(&CreateProjectRequest {
            name: "real-ffuf-preview".to_owned(),
        })
        .unwrap();
    let form = BTreeMap::from([
        (
            "url".to_owned(),
            "http://flagdeck-preview.invalid/".to_owned(),
        ),
        ("wordlist".to_owned(), "seclists-common".to_owned()),
        ("threads".to_owned(), "40".to_owned()),
        ("mc".to_owned(), "200,204,301,302,307,401,403".to_owned()),
    ]);

    let preview = core
        .preview_catalog_tool(PreviewCatalogToolRequest {
            project_id: project.project_id,
            tool_id: "ffuf".to_owned(),
            target_url: "http://flagdeck-preview.invalid/".to_owned(),
            form,
        })
        .expect("the real ffuf preview should return for the desktop form");

    assert!(preview.command_preview.contains("ffuf"));
}

#[test]
fn catalog_preview_does_not_persist_target_scope() {
    let temporary = tempdir().unwrap();
    let catalog_root = temporary.path().join("catalog");
    write_typed_ffuf_catalog(&catalog_root);
    let core = CoreService::with_bundled_resources(
        temporary.path().join("workspaces"),
        None,
        None,
        None,
        None,
        Some(catalog_root),
    );
    let project = core
        .create_project(&CreateProjectRequest {
            name: "catalog-preview-scope".to_owned(),
        })
        .unwrap();
    let project_id = project.project_id;

    core.preview_catalog_tool(PreviewCatalogToolRequest {
        project_id: project_id.clone(),
        tool_id: "ffuf".to_owned(),
        target_url: "http://127.0.0.1:9/".to_owned(),
        form: BTreeMap::from([
            ("url".to_owned(), "http://127.0.0.1:9/".to_owned()),
            ("wordlist".to_owned(), "common.txt".to_owned()),
            ("secret".to_owned(), String::new()),
        ]),
    })
    .unwrap();

    assert!(core.list_scopes(&project_id).unwrap().items.is_empty());
}
