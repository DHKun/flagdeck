use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use flagdeck_core::{
    CoreService, CreateProjectRequest, JobLogStream, JobPageRequest, PreviewJobLogRequest,
    RunCatalogToolRequest,
};
use flagdeck_domain::ExecutionStatus;
use tempfile::tempdir;

fn tools_root_available() -> bool {
    Path::new("/data/CTF/Tools").is_dir() || Path::new("/usr/bin/curl").is_file()
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
    let core = CoreService::new(temporary.path().join("workspaces"));
    let snapshot = core
        .list_catalog()
        .expect("catalog should load from repo config");
    assert!(
        snapshot.tools.iter().any(|tool| tool.id == "curl"),
        "expected curl in catalog"
    );
    let _ = tools_root_available();
}
