//! JobRunner：工具运行的执行引擎。把 `CommandSpec` 作为 `Job` 跑起来，登记可取消句柄，
//! 执行结束后注销，并驱动取消。持有 `active_executions` 注册表；服务级的 `active_runs`
//! 忙碌计数留在 `CoreService`（被状态查询、建项目、清任务、导入、导出等读取）。
//!
//! 这一步先落地一个共享的 `Job` 构造器，消掉三处启动路径里重复的 23 字段字面量。

use flagdeck_domain::{CommandSpecId, ExecutionStatus, ImportStatus, Job, JobId, Timestamp};

/// 构造一个刚入队的工具 `Job`。只暴露三条启动路径真正不同的字段，其余固定为初始值。
pub(crate) fn queued_tool_job(
    job_id: JobId,
    command_spec_id: CommandSpecId,
    import_status: ImportStatus,
    created_at: Timestamp,
    source_job_id: Option<JobId>,
) -> Job {
    Job {
        job_id,
        parent_job_id: None,
        command_spec_id,
        execution_status: ExecutionStatus::Queued,
        import_status,
        created_at,
        started_at: None,
        stopped_at: None,
        pid: None,
        process_group_id: None,
        process_start_ticks: None,
        exit_code: None,
        exit_reason: None,
        systemd_unit: None,
        cgroup_path: None,
        invocation_id: None,
        supervisor_backend: None,
        ownership_verified: false,
        cleanup_verified: false,
        residual_processes: 0,
        cancel_duration_millis: None,
        stdout_artifact_id: None,
        stderr_artifact_id: None,
        retry_count: 0,
        source_job_id,
    }
}
