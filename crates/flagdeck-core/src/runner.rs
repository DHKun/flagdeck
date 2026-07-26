//! JobRunner：工具运行的执行引擎。把 `CommandSpec` 作为 `Job` 跑起来，登记可取消句柄，
//! 执行结束后注销，并驱动取消。持有 `active_executions` 注册表；服务级的 `active_runs`
//! 忙碌计数留在 `CoreService`（被状态查询、建项目、清任务、导入、导出等读取）。
//!
//! 这一步先落地一个共享的 `Job` 构造器，消掉三处启动路径里重复的 23 字段字面量。

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use flagdeck_domain::{
    CommandSpecId, ExecutionStatus, ImportStatus, Job, JobId, ProjectId, Timestamp, Validate,
};
use flagdeck_storage::ProjectStore;

use crate::{
    ActiveExecution, CancelAllJobsResult, CancelJobRequest, CancelJobResult, CoreError,
    cancel_job_result, drive_cancellation,
};

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

/// 运行中工具作业的取消注册表加取消驱动。`active_executions` 把 `JobId` 映射到可取消句柄。
/// 三条启动路径经 [`JobRunner::register`] 登记作业，执行器完成后 [`JobRunner::unregister`]，
/// `cancel_job`/`cancel_all_jobs` 从这里查句柄并驱动取消。服务级的 `active_runs` 忙碌计数
/// 不在这里，仍由 `CoreService` 持有。
#[derive(Default)]
pub(crate) struct JobRunner {
    active_executions: Mutex<HashMap<JobId, Arc<ActiveExecution>>>,
}

impl JobRunner {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 登记一个刚启动、可被取消的作业。
    pub(crate) fn register(
        &self,
        job_id: JobId,
        control: Arc<ActiveExecution>,
    ) -> Result<(), CoreError> {
        self.active_executions
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .insert(job_id, control);
        Ok(())
    }

    /// 作业结束后注销。
    pub(crate) fn unregister(&self, job_id: &JobId) -> Result<(), CoreError> {
        self.active_executions
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .remove(job_id);
        Ok(())
    }

    /// 是否有该作业仍在活动集合中（供 `delete_job` 守卫）。
    pub(crate) fn is_job_active(&self, job_id: &JobId) -> Result<bool, CoreError> {
        Ok(self
            .active_executions
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .contains_key(job_id))
    }

    /// 是否还有活动作业（供 `clear_jobs` 守卫）。
    pub(crate) fn has_active_jobs(&self) -> Result<bool, CoreError> {
        Ok(!self
            .active_executions
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .is_empty())
    }

    fn control(&self, job_id: &JobId) -> Result<Option<Arc<ActiveExecution>>, CoreError> {
        Ok(self
            .active_executions
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .get(job_id)
            .cloned())
    }

    fn active_job_ids(&self) -> Result<Vec<JobId>, CoreError> {
        Ok(self
            .active_executions
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .keys()
            .cloned()
            .collect())
    }

    pub(crate) async fn cancel_job(
        &self,
        store: &ProjectStore,
        request: &CancelJobRequest,
    ) -> Result<CancelJobResult, CoreError> {
        request
            .job_id
            .validate()
            .map_err(|_| CoreError::InvalidRequest)?;
        let control = self
            .control(&request.job_id)?
            .ok_or(CoreError::JobNotActive)?;
        control.cancel_requested.store(true, Ordering::SeqCst);
        let has_identity = control
            .identity
            .lock()
            .map_err(|_| CoreError::StateLock)?
            .is_some();
        if has_identity {
            let mut job = store.job(&request.job_id)?.job;
            if matches!(
                job.execution_status,
                ExecutionStatus::Queued | ExecutionStatus::Starting | ExecutionStatus::Running
            ) {
                job.transition(ExecutionStatus::Stopping)
                    .map_err(|_| CoreError::InvalidRequest)?;
                store.save_job(&job)?;
            }
        }
        let cancellation = drive_cancellation(&control).await?;
        Ok(cancel_job_result(request.job_id.clone(), cancellation))
    }

    pub(crate) async fn cancel_all_jobs(
        &self,
        store: &ProjectStore,
        project_id: &ProjectId,
    ) -> Result<CancelAllJobsResult, CoreError> {
        let job_ids = self.active_job_ids()?;
        let mut results = Vec::with_capacity(job_ids.len());
        for job_id in &job_ids {
            results.push(
                self.cancel_job(
                    store,
                    &CancelJobRequest {
                        project_id: project_id.clone(),
                        job_id: job_id.clone(),
                    },
                )
                .await?,
            );
        }
        Ok(CancelAllJobsResult {
            requested: job_ids.len(),
            results,
        })
    }
}
