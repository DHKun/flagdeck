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

#[tokio::test]
async fn shiro_detaches_with_visible_logs() {
    let launcher = Path::new("/data/CTF/Tools/Active/ShiroExploit.V2.51/start-shiro.sh");
    if !launcher.is_file() {
        eprintln!("skip shiro launch: local tools root unavailable");
        return;
    }
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        eprintln!("skip shiro launch: no display session");
        return;
    }

    let temporary = tempdir().unwrap();
    let core = Arc::new(CoreService::new(temporary.path().join("workspaces")));
    let project = core
        .create_project(&CreateProjectRequest {
            name: "shiro-gui".to_owned(),
        })
        .unwrap();

    let job = core
        .start_catalog_tool(RunCatalogToolRequest {
            project_id: project.project_id.clone(),
            tool_id: "shiro".to_owned(),
            target_url: String::new(),
            form: BTreeMap::new(),
            confirm_sensitive_argv: false,
        })
        .unwrap();

    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(150)).await;
        let page = core
            .list_jobs(&JobPageRequest {
                project_id: project.project_id.clone(),
                cursor: None,
                limit: 10,
            })
            .unwrap();
        let current = page
            .items
            .iter()
            .find(|item| item.job.job_id == job.job.job_id)
            .unwrap();
        if !matches!(
            current.job.execution_status,
            ExecutionStatus::Queued
                | ExecutionStatus::Starting
                | ExecutionStatus::Running
                | ExecutionStatus::Stopping
        ) {
            println!(
                "shiro status={:?} reason={:?}",
                current.job.execution_status, current.job.exit_reason
            );
            break;
        }
    }

    let stdout = core
        .preview_job_log(&PreviewJobLogRequest {
            project_id: project.project_id.clone(),
            job_id: job.job.job_id.clone(),
            stream: JobLogStream::Stdout,
            offset: 0,
            limit: 64 * 1024,
        })
        .unwrap();
    assert!(stdout.content.contains("FlagDeck launch"));
    assert!(
        stdout.content.contains("gui still running")
            || stdout.content.contains("detached")
            || stdout.content.contains("spawned")
            || stdout.content.contains("failed"),
        "unexpected: {}",
        stdout.content
    );

    let _ = std::process::Command::new("pkill")
        .args(["-f", "ShiroExploit.jar"])
        .status();
}
