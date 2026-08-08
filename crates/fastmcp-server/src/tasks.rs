//! Background task manager (Docket/SEP-1686).
//!
//! Provides support for long-running background tasks that outlive individual
//! request lifecycles. Tasks are managed in a dedicated region that survives
//! until server shutdown.
//!
//! # Architecture
//!
//! ```text
//! Server Region (root)
//! ├── Session Region (per connection)
//! │   └── Request Regions (tools/call, etc.)
//! └── Background Task Region (managed by TaskManager)
//!     ├── Task 1
//!     ├── Task 2
//!     └── ...
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let task_manager = TaskManager::new();
//!
//! // Submit a background task
//! let task_id = task_manager.submit(&cx, "long_analysis", Some(json!({"data": ...})))?;
//!
//! // Check status
//! let info = task_manager.get_info(&task_id);
//!
//! // Cancel if needed
//! task_manager.cancel(&task_id, Some("User requested"))?;
//! ```

#[cfg(test)]
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::num::{NonZeroU64, NonZeroUsize};
#[cfg(test)]
use std::sync::RwLock;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

#[cfg(test)]
use asupersync::Budget;
#[cfg(test)]
use asupersync::runtime::{RuntimeBuilder, RuntimeHandle};
#[cfg(test)]
use asupersync::{CancelKind, Cx};
use base64::Engine as _;
#[cfg(test)]
use fastmcp_core::logging::{debug, info, targets, warn};
use fastmcp_core::{McpError, McpResult, draw_security_identifier};
use fastmcp_protocol::tasks_extension::TaskStatusNotificationParams as FinalTaskStatusNotificationParams;
use fastmcp_protocol::{
    CreateTaskResult, FinalCancelTaskResult, FinalGetTaskResult, FinalTaskCallToolResult,
    FinalTaskError, FinalTaskId, FinalTaskStatus, GetTaskParams, Task as FinalTask,
    TaskBase as FinalTaskBase, TaskDuration as FinalTaskDuration,
    TaskInputLedger as FinalTaskInputLedger, TaskInputRequests as FinalTaskInputRequests,
    TaskInputResponses as FinalTaskInputResponses,
    TaskStatusNotification as FinalTaskStatusNotification, TaskTimestamp as FinalTaskTimestamp,
    UpdateTaskParams, UpdateTaskResult,
};
#[cfg(test)]
use fastmcp_protocol::{
    JsonRpcRequest, TaskId, TaskInfo, TaskResult, TaskStatus, TaskStatusNotificationParams,
};

/// Notification sender used for task status updates.
#[cfg(test)]
pub type TaskNotificationSender = Arc<dyn Fn(JsonRpcRequest) + Send + Sync>;

/// Callback type for task execution.
///
/// Task handlers receive the context and parameters, and return a result.
#[cfg(test)]
pub type TaskHandler = Box<dyn Fn(&Cx, serde_json::Value) -> TaskFuture + Send + Sync + 'static>;

/// Future type for task execution.
#[cfg(test)]
pub type TaskFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = McpResult<serde_json::Value>> + Send + 'static>,
>;

/// Internal state for a running task.
#[cfg(test)]
struct TaskState {
    /// Task information.
    info: TaskInfo,
    /// Whether cancellation has been requested.
    cancel_requested: bool,
    /// Task result once completed.
    result: Option<TaskResult>,
    /// Task-scoped cancellation context.
    cx: Cx,
}

#[cfg(test)]
fn can_transition(from: TaskStatus, to: TaskStatus) -> bool {
    matches!(
        (from, to),
        (
            TaskStatus::Pending,
            TaskStatus::Running | TaskStatus::Failed | TaskStatus::Cancelled
        ) | (
            TaskStatus::Running,
            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
        )
    )
}

#[cfg(test)]
fn transition_state(state: &mut TaskState, to: TaskStatus) -> bool {
    let from = state.info.status;
    if from == to {
        return true;
    }
    if !can_transition(from, to) {
        warn!(
            target: targets::SERVER,
            "task {} invalid transition {:?} -> {:?}",
            state.info.id,
            from,
            to
        );
        return false;
    }

    state.info.status = to;
    let now = chrono::Utc::now().to_rfc3339();
    match to {
        TaskStatus::Running => {
            state.info.started_at = Some(now.clone());
        }
        TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled => {
            state.info.completed_at = Some(now.clone());
        }
        TaskStatus::Pending => {}
    }

    info!(
        target: targets::SERVER,
        "task {} status {:?} -> {:?} at {}",
        state.info.id,
        from,
        to,
        now
    );
    true
}

#[cfg(test)]
fn mark_task_failed_snapshot(
    tasks: &Arc<RwLock<HashMap<TaskId, TaskState>>>,
    task_id: &TaskId,
    error_msg: String,
    lock_context: &'static str,
) -> Option<TaskStatusSnapshot> {
    let mut tasks_guard = tasks.write().unwrap_or_else(|poisoned| {
        warn!(
            target: targets::SERVER,
            "tasks lock poisoned in {}, recovering",
            lock_context
        );
        poisoned.into_inner()
    });

    let state = tasks_guard.get_mut(task_id)?;
    if state.cancel_requested || !transition_state(state, TaskStatus::Failed) {
        return None;
    }

    state.info.error = Some(error_msg.clone());
    state.result = Some(TaskResult {
        id: task_id.clone(),
        success: false,
        data: None,
        error: Some(error_msg),
    });
    Some(TaskStatusSnapshot::from(state))
}

#[cfg(test)]
fn build_runtime_handle() -> Option<RuntimeHandle> {
    match RuntimeBuilder::multi_thread().build() {
        Ok(runtime) => Some(runtime.handle()),
        Err(multi_err) => {
            warn!(
                target: targets::SERVER,
                "failed to initialize multi-thread runtime for tasks: {}; attempting current-thread fallback",
                multi_err
            );
            match RuntimeBuilder::current_thread().build() {
                Ok(runtime) => Some(runtime.handle()),
                Err(single_err) => {
                    warn!(
                        target: targets::SERVER,
                        "failed to initialize current-thread runtime fallback for tasks: {}",
                        single_err
                    );
                    None
                }
            }
        }
    }
}

/// Background task manager.
///
/// Manages the lifecycle of background tasks including submission, status
/// tracking, and cancellation.
#[cfg(test)]
pub struct TaskManager {
    /// Active and completed tasks by ID.
    tasks: Arc<RwLock<HashMap<TaskId, TaskState>>>,
    /// Registered task handlers by type.
    handlers: Arc<RwLock<HashMap<String, TaskHandler>>>,
    /// Counter for generating unique task IDs.
    task_counter: AtomicU64,
    /// Whether task list changes should trigger notifications.
    list_changed_notifications: bool,
    /// Background runtime handle for executing tasks.
    runtime: Option<RuntimeHandle>,
    /// Whether submitted tasks should execute immediately.
    auto_execute: bool,
    /// Optional notification sender for task status updates.
    notification_sender: Arc<RwLock<Option<TaskNotificationSender>>>,
}

#[cfg(test)]
impl TaskManager {
    /// Creates a new task manager.
    #[must_use]
    pub fn new() -> Self {
        let runtime = build_runtime_handle();
        if runtime.is_none() {
            warn!(
                target: targets::SERVER,
                "TaskManager runtime unavailable; auto-executed tasks will fail until runtime becomes available"
            );
        }
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
            handlers: Arc::new(RwLock::new(HashMap::new())),
            task_counter: AtomicU64::new(0),
            list_changed_notifications: false,
            runtime,
            auto_execute: true,
            notification_sender: Arc::new(RwLock::new(None)),
        }
    }

    /// Creates a new task manager with list change notifications enabled.
    #[must_use]
    pub fn with_list_changed_notifications() -> Self {
        Self {
            list_changed_notifications: true,
            ..Self::new()
        }
    }

    /// Creates a task manager configured for deterministic tests.
    ///
    /// Tasks are not executed automatically; tests can drive state manually.
    #[must_use]
    pub fn new_for_testing() -> Self {
        let mut manager = Self::new();
        manager.auto_execute = false;
        manager
    }

    /// Converts this manager into a shared handle.
    #[must_use]
    pub fn into_shared(self) -> SharedTaskManager {
        Arc::new(self)
    }

    /// Returns whether list change notifications are enabled.
    #[must_use]
    pub fn has_list_changed_notifications(&self) -> bool {
        self.list_changed_notifications
    }

    /// Sets the notification sender for task status updates.
    pub fn set_notification_sender(&self, sender: TaskNotificationSender) {
        let mut guard = self.notification_sender.write().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "notification sender lock poisoned, recovering");
            poisoned.into_inner()
        });
        *guard = Some(sender);
    }

    /// Registers a task handler for a specific task type.
    ///
    /// The handler will be invoked when a task of this type is submitted.
    pub fn register_handler<F, Fut>(&self, task_type: impl Into<String>, handler: F)
    where
        F: Fn(&Cx, serde_json::Value) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = McpResult<serde_json::Value>> + Send + 'static,
    {
        let task_type = task_type.into();
        let boxed_handler: TaskHandler = Box::new(move |cx, params| Box::pin(handler(cx, params)));

        let mut handlers = self.handlers.write().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "handlers lock poisoned, recovering");
            poisoned.into_inner()
        });
        handlers.insert(task_type, boxed_handler);
    }

    /// Submits a new background task.
    ///
    /// Returns the task ID for tracking. The task runs asynchronously in the
    /// background region.
    pub fn submit(
        &self,
        cx: &Cx,
        task_type: impl Into<String>,
        params: Option<serde_json::Value>,
    ) -> McpResult<TaskId> {
        let task_type = task_type.into();

        // Check if handler exists
        {
            let handlers = self.handlers.read().unwrap_or_else(|poisoned| {
                warn!(target: targets::SERVER, "handlers lock poisoned, recovering");
                poisoned.into_inner()
            });
            if !handlers.contains_key(&task_type) {
                return Err(McpError::invalid_params(format!(
                    "Unknown task type: {task_type}"
                )));
            }
        }

        // Generate unique task ID
        let counter = self.task_counter.fetch_add(1, Ordering::SeqCst);
        let task_id = TaskId::from_string(format!("task-{counter:08x}"));

        // Create task info
        let now = chrono::Utc::now().to_rfc3339();
        let task_cx = cx.clone();
        let info = TaskInfo {
            id: task_id.clone(),
            task_type: task_type.clone(),
            status: TaskStatus::Pending,
            progress: None,
            message: None,
            created_at: now,
            started_at: None,
            completed_at: None,
            error: None,
        };

        let info_snapshot = info.clone();

        // Store task state
        let state = TaskState {
            info,
            cancel_requested: false,
            result: None,
            cx: task_cx.clone(),
        };

        {
            let mut tasks = self.tasks.write().unwrap_or_else(|poisoned| {
                warn!(target: targets::SERVER, "tasks lock poisoned, recovering");
                poisoned.into_inner()
            });
            tasks.insert(task_id.clone(), state);
        }

        self.notify_status(info_snapshot, None);

        if self.auto_execute {
            let params = params.unwrap_or_else(|| serde_json::json!({}));
            self.spawn_task(task_id.clone(), task_type, task_cx, params);
        }

        Ok(task_id)
    }

    #[allow(clippy::too_many_lines)]
    fn spawn_task(
        &self,
        task_id: TaskId,
        task_type: String,
        task_cx: Cx,
        params: serde_json::Value,
    ) {
        let Some(runtime) = self.runtime.clone() else {
            let failure_snapshot = mark_task_failed_snapshot(
                &self.tasks,
                &task_id,
                "Task runtime unavailable".to_string(),
                "spawn_task runtime unavailable",
            );
            self.notify_snapshot(failure_snapshot);
            return;
        };

        let tasks = Arc::clone(&self.tasks);
        let handlers = Arc::clone(&self.handlers);
        let notification_sender = Arc::clone(&self.notification_sender);
        let scheduled_task_id = task_id.clone();
        let scheduling = runtime.try_spawn(async move {
            let running_snapshot = {
                let mut tasks_guard = tasks.write().unwrap_or_else(|poisoned| {
                    warn!(target: targets::SERVER, "tasks lock poisoned in spawn_task, recovering");
                    poisoned.into_inner()
                });
                match tasks_guard.get_mut(&task_id) {
                    Some(state) => {
                        if state.cancel_requested || !transition_state(state, TaskStatus::Running) {
                            None
                        } else {
                            Some(TaskStatusSnapshot::from(state))
                        }
                    }
                    None => None,
                }
            };

            let should_start = running_snapshot.is_some();
            notify_snapshot(&notification_sender, running_snapshot);

            if !should_start {
                return;
            }

            let task_future = {
                let handlers_guard = handlers.read().unwrap_or_else(|poisoned| {
                    warn!(target: targets::SERVER, "handlers lock poisoned in spawn_task, recovering");
                    poisoned.into_inner()
                });
                let Some(handler) = handlers_guard.get(&task_type) else {
                    let failure_snapshot = mark_task_failed_snapshot(
                        &tasks,
                        &task_id,
                        format!("Unknown task type: {task_type}"),
                        "spawn_task failure",
                    );
                    notify_snapshot(&notification_sender, failure_snapshot);
                    return;
                };
                (handler)(&task_cx, params)
            };

            let result = task_future.await;

            let completion_snapshot = {
                let mut tasks_guard = tasks.write().unwrap_or_else(|poisoned| {
                    warn!(target: targets::SERVER, "tasks lock poisoned in spawn_task completion, recovering");
                    poisoned.into_inner()
                });
                match tasks_guard.get_mut(&task_id) {
                    Some(state) => {
                        if state.cancel_requested {
                            None
                        } else {
                            let mut snapshot = None;
                            match result {
                                Ok(data) => {
                                    if transition_state(state, TaskStatus::Completed) {
                                        state.info.progress = Some(1.0);
                                        state.result = Some(TaskResult {
                                            id: task_id.clone(),
                                            success: true,
                                            data: Some(data),
                                            error: None,
                                        });
                                        snapshot = Some(TaskStatusSnapshot::from(state));
                                    }
                                }
                                Err(err) => {
                                    let error_msg = err.message;
                                    if transition_state(state, TaskStatus::Failed) {
                                        state.info.error = Some(error_msg.clone());
                                        state.result = Some(TaskResult {
                                            id: task_id.clone(),
                                            success: false,
                                            data: None,
                                            error: Some(error_msg),
                                        });
                                        snapshot = Some(TaskStatusSnapshot::from(state));
                                    }
                                }
                            }
                            snapshot
                        }
                    }
                    None => None,
                }
            };

            notify_snapshot(&notification_sender, completion_snapshot);
        });

        if let Err(err) = scheduling {
            warn!(
                target: targets::SERVER,
                "failed to schedule task {}: {}",
                scheduled_task_id,
                err
            );
            let failure_snapshot = mark_task_failed_snapshot(
                &self.tasks,
                &scheduled_task_id,
                format!("Failed to schedule task: {err}"),
                "spawn_task scheduling",
            );
            self.notify_snapshot(failure_snapshot);
        }
    }

    /// Starts execution of a pending task.
    ///
    /// This is called internally to transition a task from Pending to Running.
    pub fn start_task(&self, task_id: &TaskId) -> McpResult<()> {
        let snapshot = {
            let mut tasks = self.tasks.write().unwrap_or_else(|poisoned| {
                warn!(target: targets::SERVER, "tasks lock poisoned in start_task, recovering");
                poisoned.into_inner()
            });
            let state = tasks
                .get_mut(task_id)
                .ok_or_else(|| McpError::invalid_params(format!("Task not found: {task_id}")))?;

            if state.info.status != TaskStatus::Pending {
                return Err(McpError::invalid_params(format!(
                    "Task {task_id} is not pending"
                )));
            }

            if !transition_state(state, TaskStatus::Running) {
                return Err(McpError::invalid_params(format!(
                    "Task {task_id} cannot transition to running"
                )));
            }
            Some(TaskStatusSnapshot::from(state))
        };

        self.notify_snapshot(snapshot);
        Ok(())
    }

    /// Updates progress for a running task.
    pub fn update_progress(&self, task_id: &TaskId, progress: f64, message: Option<String>) {
        let snapshot = {
            let mut tasks = self.tasks.write().unwrap_or_else(|poisoned| {
                warn!(target: targets::SERVER, "tasks lock poisoned in update_progress, recovering");
                poisoned.into_inner()
            });
            if let Some(state) = tasks.get_mut(task_id) {
                if state.info.status != TaskStatus::Running {
                    debug!(
                        target: targets::SERVER,
                        "task {} progress update ignored in state {:?}",
                        task_id,
                        state.info.status
                    );
                    return;
                }
                state.info.progress = Some(progress.clamp(0.0, 1.0));
                state.info.message = message;
                Some(TaskStatusSnapshot::from(state))
            } else {
                None
            }
        };

        self.notify_snapshot(snapshot);
    }

    /// Completes a task with a successful result.
    pub fn complete_task(&self, task_id: &TaskId, data: serde_json::Value) {
        let snapshot = {
            let mut tasks = self.tasks.write().unwrap_or_else(|poisoned| {
                warn!(target: targets::SERVER, "tasks lock poisoned in complete_task, recovering");
                poisoned.into_inner()
            });
            if let Some(state) = tasks.get_mut(task_id) {
                if !transition_state(state, TaskStatus::Completed) {
                    return;
                }
                state.info.progress = Some(1.0);
                state.result = Some(TaskResult {
                    id: task_id.clone(),
                    success: true,
                    data: Some(data),
                    error: None,
                });
                Some(TaskStatusSnapshot::from(state))
            } else {
                None
            }
        };

        self.notify_snapshot(snapshot);
    }

    /// Fails a task with an error.
    pub fn fail_task(&self, task_id: &TaskId, error: impl Into<String>) {
        let error = error.into();
        let snapshot = {
            let mut tasks = self.tasks.write().unwrap_or_else(|poisoned| {
                warn!(target: targets::SERVER, "tasks lock poisoned in fail_task, recovering");
                poisoned.into_inner()
            });
            if let Some(state) = tasks.get_mut(task_id) {
                if !transition_state(state, TaskStatus::Failed) {
                    return;
                }
                state.info.error = Some(error.clone());
                state.result = Some(TaskResult {
                    id: task_id.clone(),
                    success: false,
                    data: None,
                    error: Some(error),
                });
                Some(TaskStatusSnapshot::from(state))
            } else {
                None
            }
        };

        self.notify_snapshot(snapshot);
    }

    /// Gets information about a task.
    #[must_use]
    pub fn get_info(&self, task_id: &TaskId) -> Option<TaskInfo> {
        let tasks = self.tasks.read().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "tasks lock poisoned in get_info, recovering");
            poisoned.into_inner()
        });
        tasks.get(task_id).map(|s| s.info.clone())
    }

    /// Gets the result of a completed task.
    #[must_use]
    pub fn get_result(&self, task_id: &TaskId) -> Option<TaskResult> {
        let tasks = self.tasks.read().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "tasks lock poisoned in get_result, recovering");
            poisoned.into_inner()
        });
        tasks.get(task_id).and_then(|s| s.result.clone())
    }

    /// Lists all tasks, optionally filtered by status.
    #[must_use]
    pub fn list_tasks(&self, status_filter: Option<TaskStatus>) -> Vec<TaskInfo> {
        let tasks = self.tasks.read().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "tasks lock poisoned in list_tasks, recovering");
            poisoned.into_inner()
        });
        tasks
            .values()
            .filter(|s| status_filter.is_none_or(|f| s.info.status == f))
            .map(|s| s.info.clone())
            .collect()
    }

    /// Requests cancellation of a task.
    ///
    /// Returns true if the task exists and cancellation was requested.
    /// The task may still be running until it checks for cancellation.
    pub fn cancel(&self, task_id: &TaskId, reason: Option<String>) -> McpResult<TaskInfo> {
        let snapshot = {
            let mut tasks = self.tasks.write().unwrap_or_else(|poisoned| {
                warn!(target: targets::SERVER, "tasks lock poisoned in cancel, recovering");
                poisoned.into_inner()
            });
            let state = tasks
                .get_mut(task_id)
                .ok_or_else(|| McpError::invalid_params(format!("Task not found: {task_id}")))?;

            // Can only cancel pending or running tasks
            if state.info.status.is_terminal() {
                return Err(McpError::invalid_params(format!(
                    "Task {task_id} is already in terminal state: {:?}",
                    state.info.status
                )));
            }

            if !transition_state(state, TaskStatus::Cancelled) {
                return Err(McpError::invalid_params(format!(
                    "Task {task_id} cannot be cancelled from {:?}",
                    state.info.status
                )));
            }

            state.cancel_requested = true;

            state.cx.cancel_with(CancelKind::User, None);
            if !state.cx.is_cancel_requested() {
                warn!(
                    target: targets::SERVER,
                    "task {} cancel signal not observed on context",
                    task_id
                );
            }

            let error_msg = reason.unwrap_or_else(|| "Cancelled by request".to_string());
            state.info.error = Some(error_msg.clone());
            state.result = Some(TaskResult {
                id: task_id.clone(),
                success: false,
                data: None,
                error: Some(error_msg),
            });

            let snapshot = TaskStatusSnapshot::from(state);
            (snapshot, state.info.clone())
        };

        let (snapshot, info) = snapshot;
        self.notify_snapshot(Some(snapshot));
        Ok(info)
    }

    /// Checks if cancellation has been requested for a task.
    #[must_use]
    pub fn is_cancel_requested(&self, task_id: &TaskId) -> bool {
        let tasks = self.tasks.read().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "tasks lock poisoned in is_cancel_requested, recovering");
            poisoned.into_inner()
        });
        tasks.get(task_id).is_some_and(|s| s.cancel_requested)
    }

    /// Returns the number of active (non-terminal) tasks.
    #[must_use]
    pub fn active_count(&self) -> usize {
        let tasks = self.tasks.read().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "tasks lock poisoned in active_count, recovering");
            poisoned.into_inner()
        });
        tasks.values().filter(|s| s.info.status.is_active()).count()
    }

    /// Returns the total number of tasks.
    #[must_use]
    pub fn total_count(&self) -> usize {
        let tasks = self.tasks.read().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "tasks lock poisoned in total_count, recovering");
            poisoned.into_inner()
        });
        tasks.len()
    }

    /// Removes completed tasks older than the specified duration.
    ///
    /// This is useful for preventing unbounded memory growth from completed tasks.
    pub fn cleanup_completed(&self, max_age: std::time::Duration) {
        let cutoff = chrono::Utc::now() - chrono::Duration::from_std(max_age).unwrap_or_default();

        let mut tasks = self.tasks.write().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "tasks lock poisoned in cleanup_completed, recovering");
            poisoned.into_inner()
        });
        tasks.retain(|_, state| {
            // Keep active tasks
            if state.info.status.is_active() {
                return true;
            }

            // Keep recent completed tasks
            if let Some(ref completed) = state.info.completed_at {
                if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(completed) {
                    return parsed.with_timezone(&chrono::Utc) > cutoff;
                }
                return true;
            }

            true
        });
    }

    fn notify_snapshot(&self, snapshot: Option<TaskStatusSnapshot>) {
        if let Some(snapshot) = snapshot {
            self.notify_status(snapshot.info, snapshot.result);
        }
    }

    fn notify_status(&self, info: TaskInfo, result: Option<TaskResult>) {
        let sender = {
            let guard = self.notification_sender.read().unwrap_or_else(|poisoned| {
                warn!(target: targets::SERVER, "notification sender lock poisoned in notify_status, recovering");
                poisoned.into_inner()
            });
            guard.clone()
        };
        let Some(sender) = sender else {
            return;
        };

        let params = TaskStatusNotificationParams {
            id: info.id.clone(),
            status: info.status,
            progress: info.progress,
            message: info.message.clone(),
            error: info.error.clone(),
            result,
        };
        let payload = match serde_json::to_value(params) {
            Ok(value) => value,
            Err(err) => {
                warn!(
                    target: targets::SERVER,
                    "failed to serialize task status notification: {}",
                    err
                );
                return;
            }
        };
        sender(JsonRpcRequest::notification(
            "notifications/tasks/status",
            Some(payload),
        ));
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct TaskStatusSnapshot {
    info: TaskInfo,
    result: Option<TaskResult>,
}

#[cfg(test)]
impl TaskStatusSnapshot {
    fn from(state: &TaskState) -> Self {
        Self {
            info: state.info.clone(),
            result: state.result.clone(),
        }
    }
}

#[cfg(test)]
fn notify_snapshot(
    sender: &Arc<RwLock<Option<TaskNotificationSender>>>,
    snapshot: Option<TaskStatusSnapshot>,
) {
    let Some(snapshot) = snapshot else {
        return;
    };
    let sender = {
        let guard = sender.read().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "notification sender lock poisoned in notify_snapshot, recovering");
            poisoned.into_inner()
        });
        guard.clone()
    };
    let Some(sender) = sender else {
        return;
    };
    let params = TaskStatusNotificationParams {
        id: snapshot.info.id.clone(),
        status: snapshot.info.status,
        progress: snapshot.info.progress,
        message: snapshot.info.message.clone(),
        error: snapshot.info.error.clone(),
        result: snapshot.result,
    };
    let payload = match serde_json::to_value(params) {
        Ok(value) => value,
        Err(err) => {
            warn!(
                target: targets::SERVER,
                "failed to serialize task status notification: {}",
                err
            );
            return;
        }
    };
    sender(JsonRpcRequest::notification(
        "notifications/tasks/status",
        Some(payload),
    ));
}

// ============================================================================
// MCP Tasks extension lifecycle (2026-07-28)
// ============================================================================

/// The only storage boundary implemented by [`OfficialTaskLifecycle`].
///
/// This is deliberately process-local. It makes no persistence, recovery,
/// multi-instance, tenant-isolation, or server-capability claim. The modern
/// router must keep the extension unadvertised until the Task wire model,
/// authenticated durable backend, and application-owned supervisor have been
/// installed together.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskStorageKind {
    /// Bounded process memory, lost when the process exits.
    ProcessLocal,
}

/// Public task status for the official `io.modelcontextprotocol/tasks`
/// extension.
///
/// Private execution phases such as `queued`, `claimed`, or `leased` are not
/// represented here and therefore cannot leak into a wire task snapshot.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum OfficialTaskStatus {
    /// Work has been accepted and may be executing.
    #[serde(rename = "working")]
    Working,
    /// The task cannot proceed until all exposed input requests are answered.
    #[serde(rename = "input_required")]
    InputRequired,
    /// The underlying operation produced its final result.
    #[serde(rename = "completed")]
    Completed,
    /// The underlying operation ended in a JSON-RPC execution error.
    #[serde(rename = "failed")]
    Failed,
    /// The task worker honored a cooperative cancellation request.
    #[serde(rename = "cancelled")]
    Cancelled,
}

#[cfg(test)]
impl OfficialTaskStatus {
    #[must_use]
    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// A task-owned embedded request that needs a response from the client.
///
/// The final protocol types for these descriptors are owned by TASK-01 and
/// MRTR. Keeping the method separate from its parameters prevents an old
/// JSON-RPC envelope from becoming execution or correlation authority here.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub(crate) struct OfficialTaskInputRequest {
    /// The supported server-to-client request method.
    pub method: OfficialTaskInputMethod,
    /// Method parameters, to be validated by the TASK-01/MRTR integration.
    pub params: serde_json::Value,
}

/// The only embedded request kinds admitted by the process-local lifecycle.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub(crate) enum OfficialTaskInputMethod {
    /// An elicitation input request.
    #[serde(rename = "elicitation/create")]
    ElicitationCreate,
    /// A sampling input request.
    #[serde(rename = "sampling/createMessage")]
    SamplingCreateMessage,
}

/// Process-local lifecycle configuration.
///
/// A finite positive TTL is required because this implementation has no
/// durable, authorized reclamation path for retained/null-TTL records.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OfficialTaskLifecycleConfig {
    ttl_ms: NonZeroU64,
    poll_interval_ms: Option<NonZeroU64>,
    max_tasks: NonZeroUsize,
}

#[cfg(test)]
impl OfficialTaskLifecycleConfig {
    /// Creates a bounded process-local lifecycle configuration.
    pub(crate) fn new(
        ttl_ms: u64,
        poll_interval_ms: Option<u64>,
        max_tasks: usize,
    ) -> McpResult<Self> {
        let ttl_ms = NonZeroU64::new(ttl_ms)
            .ok_or_else(|| McpError::invalid_params("Task TTL must be a positive integer"))?;
        let poll_interval_ms = match poll_interval_ms {
            Some(poll_interval_ms) => Some(NonZeroU64::new(poll_interval_ms).ok_or_else(|| {
                McpError::invalid_params("Task poll interval must be a positive integer")
            })?),
            None => None,
        };
        let max_tasks = NonZeroUsize::new(max_tasks)
            .ok_or_else(|| McpError::invalid_params("Task capacity must be positive"))?;

        Ok(Self {
            ttl_ms,
            poll_interval_ms,
            max_tasks,
        })
    }
}

/// The status-discriminated task shape returned to an eventual Tasks router.
///
/// It intentionally has no storage or owner fields. Authorization, durable
/// retention, and wire validation are integration responsibilities; callers
/// must not serialize this private primitive directly as a protocol response.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub(crate) struct OfficialTaskSnapshot {
    /// Server-generated opaque task identifier.
    #[serde(rename = "taskId")]
    pub task_id: TaskId,
    /// Official extension task status.
    pub status: OfficialTaskStatus,
    /// Bounded human-readable status text supplied by the application layer.
    #[serde(rename = "statusMessage", skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    /// Creation timestamp in canonical UTC millisecond form.
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// Timestamp of the latest visible state change.
    #[serde(rename = "lastUpdatedAt")]
    pub last_updated_at: String,
    /// Finite local retention period; an eventual wire layer renders this as
    /// the extension's required `ttlMs` field.
    #[serde(rename = "ttlMs")]
    pub ttl_ms: u64,
    /// Suggested polling interval when configured.
    #[serde(rename = "pollIntervalMs", skip_serializing_if = "Option::is_none")]
    pub poll_interval_ms: Option<u64>,
    /// Requests still awaiting client input, present only while input is
    /// required.
    #[serde(rename = "inputRequests", skip_serializing_if = "Option::is_none")]
    pub input_requests: Option<BTreeMap<String, OfficialTaskInputRequest>>,
    /// The final underlying result, present only on successful completion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// The final JSON-RPC error, present only on execution failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
}

/// Outcome of accepting input responses for a known task.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OfficialTaskInputUpdate {
    /// At least one outstanding request was satisfied.
    Applied,
    /// Every supplied key was unknown or had already been satisfied.
    Ignored,
}

#[cfg(test)]
struct OfficialTaskRecord {
    snapshot: OfficialTaskSnapshot,
    /// Process-local retention backstop. A durable backend owns the
    /// authoritative time source in the eventual persistent implementation.
    expires_at: Instant,
    /// Monotonic local ordering when the rendered wall-clock timestamps are
    /// equal. It is private and never a wire field.
    update_revision: u64,
    /// Lifetime ledger that prevents input-key reuse after satisfaction.
    issued_input_keys: BTreeSet<String>,
    /// Cooperative cancellation intent. A worker may complete first.
    cancellation_requested: bool,
}

/// Bounded, process-local official Tasks lifecycle state.
///
/// This is a real status machine, but it deliberately does not execute
/// handlers, create a runtime, own a task region, or persist records. Those
/// actions require the application-owned supervisor and qualified backend
/// defined by TASK-02. It is not a server capability and must remain
/// unadvertised until that integration exists.
#[cfg(test)]
pub(crate) struct OfficialTaskLifecycle {
    config: OfficialTaskLifecycleConfig,
    records: RwLock<HashMap<TaskId, OfficialTaskRecord>>,
}

#[cfg(test)]
impl OfficialTaskLifecycle {
    /// Creates an empty process-local lifecycle.
    #[must_use]
    pub(crate) fn new(config: OfficialTaskLifecycleConfig) -> Self {
        Self {
            config,
            records: RwLock::new(HashMap::new()),
        }
    }

    /// Identifies the deliberately non-durable storage boundary.
    #[must_use]
    pub(crate) const fn storage_kind(&self) -> TaskStorageKind {
        TaskStorageKind::ProcessLocal
    }

    /// Creates a task in its immediately readable `working` state.
    ///
    /// The ID is a fresh 256-bit OS-CSPRNG draw encoded as 43 unpadded
    /// base64url bytes. It is retried on the astronomically unlikely local
    /// collision, and no record is overwritten.
    pub(crate) fn create(&self, status_message: Option<String>) -> McpResult<OfficialTaskSnapshot> {
        let expires_at = Instant::now()
            .checked_add(StdDuration::from_millis(self.config.ttl_ms.get()))
            .ok_or_else(|| {
                McpError::internal_error("Task TTL exceeds process-local clock range")
            })?;
        let mut records = self.records.write().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "official task lifecycle lock poisoned in create, recovering");
            poisoned.into_inner()
        });
        let now = Instant::now();
        records.retain(|_, record| record.expires_at > now);
        if records.len() >= self.config.max_tasks.get() {
            return Err(McpError::internal_error(
                "Process-local task lifecycle capacity is exhausted",
            ));
        }

        for _ in 0..4 {
            let task_id = generate_official_task_id()?;
            if records.contains_key(&task_id) {
                continue;
            }

            let now = official_task_timestamp();
            let snapshot = OfficialTaskSnapshot {
                task_id: task_id.clone(),
                status: OfficialTaskStatus::Working,
                status_message,
                created_at: now.clone(),
                last_updated_at: now,
                ttl_ms: self.config.ttl_ms.get(),
                poll_interval_ms: self.config.poll_interval_ms.map(NonZeroU64::get),
                input_requests: None,
                result: None,
                error: None,
            };
            records.insert(
                task_id,
                OfficialTaskRecord {
                    snapshot: snapshot.clone(),
                    expires_at,
                    update_revision: 0,
                    issued_input_keys: BTreeSet::new(),
                    cancellation_requested: false,
                },
            );
            return Ok(snapshot);
        }

        Err(McpError::internal_error(
            "Unable to allocate a unique task identifier after four secure draws",
        ))
    }

    /// Returns the current snapshot for an immediately readable task.
    pub(crate) fn get(&self, task_id: &TaskId) -> McpResult<OfficialTaskSnapshot> {
        let mut records = self.records.write().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "official task lifecycle lock poisoned in get, recovering");
            poisoned.into_inner()
        });
        Ok(official_task_record_mut(&mut records, task_id)?
            .snapshot
            .clone())
    }

    /// Places a working task into `input_required` with a complete outstanding
    /// input map. Keys are unique over the task lifetime.
    pub(crate) fn require_input(
        &self,
        task_id: &TaskId,
        requests: BTreeMap<String, OfficialTaskInputRequest>,
        status_message: Option<String>,
    ) -> McpResult<OfficialTaskSnapshot> {
        if requests.is_empty() {
            return Err(McpError::invalid_params(
                "input_required tasks need at least one outstanding input request",
            ));
        }
        for (key, request) in &requests {
            validate_official_task_input_request(key, request)?;
        }

        let mut records = self.records.write().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "official task lifecycle lock poisoned in require_input, recovering");
            poisoned.into_inner()
        });
        let record = official_task_record_mut(&mut records, task_id)?;
        if record.snapshot.status != OfficialTaskStatus::Working {
            return Err(invalid_official_task_transition(
                record.snapshot.status,
                OfficialTaskStatus::InputRequired,
            ));
        }
        if requests
            .keys()
            .any(|key| record.issued_input_keys.contains(key))
        {
            return Err(McpError::invalid_params(
                "Task input request keys cannot be reused",
            ));
        }

        advance_official_task(record, OfficialTaskStatus::InputRequired)?;
        record.issued_input_keys.extend(requests.keys().cloned());
        record.snapshot.status_message = status_message;
        record.snapshot.input_requests = Some(requests);
        record.snapshot.result = None;
        record.snapshot.error = None;
        Ok(record.snapshot.clone())
    }

    /// Accepts a strict subset of outstanding input responses.
    ///
    /// Unknown and already-satisfied keys are ignored. The task returns to
    /// `working` only after its final outstanding input is satisfied.
    pub(crate) fn update_input(
        &self,
        task_id: &TaskId,
        responses: BTreeMap<String, serde_json::Value>,
    ) -> McpResult<OfficialTaskInputUpdate> {
        let mut records = self.records.write().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "official task lifecycle lock poisoned in update_input, recovering");
            poisoned.into_inner()
        });
        let record = official_task_record_mut(&mut records, task_id)?;
        let all_inputs_satisfied = {
            let Some(outstanding) = record.snapshot.input_requests.as_mut() else {
                return Ok(OfficialTaskInputUpdate::Ignored);
            };

            let matched_keys: Vec<String> = responses
                .keys()
                .filter(|key| outstanding.contains_key(*key))
                .cloned()
                .collect();
            if matched_keys.is_empty() {
                return Ok(OfficialTaskInputUpdate::Ignored);
            }

            for key in matched_keys {
                outstanding.remove(&key);
            }
            outstanding.is_empty()
        };
        if all_inputs_satisfied {
            advance_official_task(record, OfficialTaskStatus::Working)?;
            record.snapshot.input_requests = None;
            record.snapshot.status_message = None;
        } else {
            touch_official_task(record)?;
        }
        Ok(OfficialTaskInputUpdate::Applied)
    }

    /// Records cooperative cancellation intent without making a premature
    /// terminal-state claim. The worker may still commit completion first.
    pub(crate) fn request_cancellation(&self, task_id: &TaskId) -> McpResult<()> {
        let mut records = self.records.write().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "official task lifecycle lock poisoned in request_cancellation, recovering");
            poisoned.into_inner()
        });
        let record = official_task_record_mut(&mut records, task_id)?;
        record.cancellation_requested = true;
        Ok(())
    }

    /// Returns whether cancellation intent is still pending for a nonterminal
    /// task. This is private execution state, not a wire task field.
    #[must_use]
    pub(crate) fn is_cancellation_requested(&self, task_id: &TaskId) -> bool {
        let mut records = self.records.write().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "official task lifecycle lock poisoned in is_cancellation_requested, recovering");
            poisoned.into_inner()
        });
        official_task_record_mut(&mut records, task_id).is_ok_and(|record| {
            record.cancellation_requested && !record.snapshot.status.is_terminal()
        })
    }

    /// Lets the supervised worker honor a cancellation request.
    pub(crate) fn honor_cancellation(
        &self,
        task_id: &TaskId,
        status_message: Option<String>,
    ) -> McpResult<OfficialTaskSnapshot> {
        let mut records = self.records.write().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "official task lifecycle lock poisoned in honour_cancellation, recovering");
            poisoned.into_inner()
        });
        let record = official_task_record_mut(&mut records, task_id)?;
        if !record.cancellation_requested {
            return Err(McpError::invalid_params(
                "Task cancellation has not been requested",
            ));
        }
        transition_to_terminal(
            record,
            OfficialTaskStatus::Cancelled,
            status_message,
            None,
            None,
        )
    }

    /// Commits a validated final tool result to a working task.
    pub(crate) fn complete(
        &self,
        task_id: &TaskId,
        result: serde_json::Value,
        status_message: Option<String>,
    ) -> McpResult<OfficialTaskSnapshot> {
        validate_final_tool_result(&result)?;
        let mut records = self.records.write().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "official task lifecycle lock poisoned in complete, recovering");
            poisoned.into_inner()
        });
        let record = official_task_record_mut(&mut records, task_id)?;
        transition_to_terminal(
            record,
            OfficialTaskStatus::Completed,
            status_message,
            Some(result),
            None,
        )
    }

    /// Commits a JSON-RPC execution error to an active task.
    pub(crate) fn fail(
        &self,
        task_id: &TaskId,
        error: serde_json::Value,
        status_message: Option<String>,
    ) -> McpResult<OfficialTaskSnapshot> {
        validate_json_rpc_error(&error)?;
        let mut records = self.records.write().unwrap_or_else(|poisoned| {
            warn!(target: targets::SERVER, "official task lifecycle lock poisoned in fail, recovering");
            poisoned.into_inner()
        });
        let record = official_task_record_mut(&mut records, task_id)?;
        let status_message = status_message.or_else(|| Some("Task execution failed".to_string()));
        transition_to_terminal(
            record,
            OfficialTaskStatus::Failed,
            status_message,
            None,
            Some(error),
        )
    }
}

#[cfg(test)]
fn generate_official_task_id() -> McpResult<TaskId> {
    let identifier = draw_security_identifier().map_err(|error| {
        McpError::internal_error(format!("Task identifier generation failed: {error}"))
    })?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(identifier.as_bytes());
    debug_assert_eq!(
        encoded.len(),
        43,
        "a 256-bit task ID must be 43 base64url bytes"
    );
    Ok(TaskId::from_string(encoded))
}

#[cfg(test)]
fn official_task_timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
fn official_task_record_mut<'a>(
    records: &'a mut HashMap<TaskId, OfficialTaskRecord>,
    task_id: &TaskId,
) -> McpResult<&'a mut OfficialTaskRecord> {
    let expired = records
        .get(task_id)
        .is_some_and(|record| record.expires_at <= Instant::now());
    if expired {
        records.remove(task_id);
    }
    records
        .get_mut(task_id)
        .ok_or_else(|| McpError::invalid_params("Task not found"))
}

#[cfg(test)]
fn can_transition_official_task(from: OfficialTaskStatus, to: OfficialTaskStatus) -> bool {
    matches!(
        (from, to),
        (
            OfficialTaskStatus::Working,
            OfficialTaskStatus::InputRequired
        ) | (OfficialTaskStatus::Working, OfficialTaskStatus::Completed)
            | (OfficialTaskStatus::Working, OfficialTaskStatus::Failed)
            | (OfficialTaskStatus::Working, OfficialTaskStatus::Cancelled)
            | (
                OfficialTaskStatus::InputRequired,
                OfficialTaskStatus::Working
            )
            | (
                OfficialTaskStatus::InputRequired,
                OfficialTaskStatus::Failed
            )
            | (
                OfficialTaskStatus::InputRequired,
                OfficialTaskStatus::Cancelled
            )
    )
}

#[cfg(test)]
fn invalid_official_task_transition(from: OfficialTaskStatus, to: OfficialTaskStatus) -> McpError {
    McpError::invalid_params(format!(
        "Invalid official task transition from {from:?} to {to:?}"
    ))
}

#[cfg(test)]
fn touch_official_task(record: &mut OfficialTaskRecord) -> McpResult<()> {
    record.update_revision = record
        .update_revision
        .checked_add(1)
        .ok_or_else(|| McpError::internal_error("Task update revision exhausted"))?;
    record.snapshot.last_updated_at = official_task_timestamp();
    Ok(())
}

#[cfg(test)]
fn advance_official_task(
    record: &mut OfficialTaskRecord,
    status: OfficialTaskStatus,
) -> McpResult<()> {
    if !can_transition_official_task(record.snapshot.status, status) {
        return Err(invalid_official_task_transition(
            record.snapshot.status,
            status,
        ));
    }
    touch_official_task(record)?;
    record.snapshot.status = status;
    Ok(())
}

#[cfg(test)]
fn transition_to_terminal(
    record: &mut OfficialTaskRecord,
    status: OfficialTaskStatus,
    status_message: Option<String>,
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
) -> McpResult<OfficialTaskSnapshot> {
    debug_assert!(status.is_terminal());
    advance_official_task(record, status)?;
    record.snapshot.status_message = status_message;
    record.snapshot.input_requests = None;
    record.snapshot.result = result;
    record.snapshot.error = error;
    Ok(record.snapshot.clone())
}

#[cfg(test)]
fn validate_official_task_input_request(
    key: &str,
    request: &OfficialTaskInputRequest,
) -> McpResult<()> {
    if key.is_empty() || key.len() > 256 {
        return Err(McpError::invalid_params(
            "Task input request keys must be non-empty and at most 256 bytes",
        ));
    }
    if !request.params.is_object() {
        return Err(McpError::invalid_params(
            "Task input request parameters must be an object",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_final_tool_result(result: &serde_json::Value) -> McpResult<()> {
    let result = result
        .as_object()
        .ok_or_else(|| McpError::invalid_params("Completed task result must be an object"))?;
    if result.get("resultType") != Some(&serde_json::Value::String("complete".to_string())) {
        return Err(McpError::invalid_params(
            "Completed task result must be a final complete result",
        ));
    }
    if !result
        .get("content")
        .is_some_and(serde_json::Value::is_array)
    {
        return Err(McpError::invalid_params(
            "Completed task result must contain tool content",
        ));
    }
    if result
        .get("isError")
        .is_some_and(|is_error| !is_error.is_boolean())
    {
        return Err(McpError::invalid_params(
            "Completed task isError must be a boolean when present",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_json_rpc_error(error: &serde_json::Value) -> McpResult<()> {
    let error = error
        .as_object()
        .ok_or_else(|| McpError::invalid_params("Failed task error must be an object"))?;
    let Some(code) = error.get("code") else {
        return Err(McpError::invalid_params(
            "Failed task error must include a JSON-RPC code",
        ));
    };
    if !code.is_i64() {
        return Err(McpError::invalid_params(
            "Failed task error code must be an integer",
        ));
    }
    if !error
        .get("message")
        .is_some_and(serde_json::Value::is_string)
    {
        return Err(McpError::invalid_params(
            "Failed task error must include a message",
        ));
    }
    Ok(())
}

// ============================================================================
// Final MCP Tasks durable state machine (2026-07-28)
// ============================================================================

/// Application-owned durable storage for final Tasks.
///
/// `create_task` and `replace_task` must atomically retain the task and its
/// typed notification before returning success. That is the create-before-reply
/// boundary: a caller may return the `CreateTaskResult` only after this method
/// has succeeded. Delivery is deliberately separate from persistence so a
/// transport reconnect cannot erase an accepted task transition.
pub trait FinalTaskStore: Send + Sync {
    /// Durably records a newly created task and its status notification.
    fn create_task(
        &self,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> McpResult<()>;

    /// Loads one task by its opaque final identifier.
    fn get_task(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTask>>;

    /// Loads one task together with its store-issued monotonic generation.
    fn get_task_snapshot(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTaskSnapshot>>;

    /// Durably replaces a task and records its status notification atomically.
    fn replace_task(
        &self,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> McpResult<()>;

    /// Atomically compares a store-issued generation, replaces, and records
    /// the replacement notification.
    ///
    /// The comparison against `expected.generation`, replacement task write, and
    /// replacement notification write form one atomic operation. Returns
    /// `false` without changing either retained value when another transition
    /// won first.
    fn replace_task_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> McpResult<bool>;

    /// Durably records cooperative cancellation intent for a known task.
    fn request_cancellation(&self, task_id: &FinalTaskId) -> McpResult<()>;

    /// Atomically records cancellation intent only when the task retains
    /// `expected`'s store-issued generation.
    ///
    /// Returns `false` without mutation when another transition won first.
    fn request_cancellation_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<bool>;

    /// Returns the durable cooperative-cancellation intent for a known task.
    fn is_cancellation_requested(&self, task_id: &FinalTaskId) -> McpResult<bool>;
}

/// One final task plus the opaque monotonic generation assigned by its store.
///
/// A generation changes on every accepted task-state or cancellation-intent
/// mutation, even when the wire task value itself is unchanged. It therefore
/// prevents ABA transitions that task-value equality cannot detect.
#[derive(Clone, Debug)]
pub struct FinalTaskSnapshot {
    task: FinalTask,
    generation: u64,
}

impl FinalTaskSnapshot {
    /// Creates a snapshot returned by a [`FinalTaskStore`].
    ///
    /// `generation` is an opaque, store-owned version token: an external
    /// durable store must allocate a new strictly monotonic value for every
    /// accepted task-state or cancellation-intent mutation of this task. It
    /// must compare that value atomically with the corresponding replacement
    /// or cancellation write. Callers must treat it solely as a CAS token.
    #[must_use]
    pub fn new(task: FinalTask, generation: u64) -> Self {
        Self { task, generation }
    }

    /// Returns the retained final task.
    #[must_use]
    pub const fn task(&self) -> &FinalTask {
        &self.task
    }

    /// Returns the store-issued generation for compare-and-swap operations.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Consumes this snapshot and returns its task.
    #[must_use]
    pub fn into_task(self) -> FinalTask {
        self.task
    }
}

/// Default maximum number of retained tasks in [`InMemoryFinalTaskStore`].
///
/// Each retained task has at most one retained status notification, so this
/// bound also caps the store's notification memory.
pub const DEFAULT_IN_MEMORY_FINAL_TASKS: usize = 1_024;

/// Bounded process-local [`FinalTaskStore`] for embeddings and development.
///
/// This store retains the current task, its latest typed status notification,
/// cancellation intent, and monotonic expiry together under one mutex. Expired
/// tasks are reclaimed before every operation. It deliberately provides no
/// restart recovery or multi-process durability; production deployments that
/// need either property must supply their own [`FinalTaskStore`].
pub struct InMemoryFinalTaskStore {
    max_tasks: usize,
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    state: Mutex<InMemoryFinalTaskState>,
}

#[derive(Default)]
struct InMemoryFinalTaskState {
    tasks: BTreeMap<FinalTaskId, FinalTask>,
    generations: BTreeMap<FinalTaskId, u64>,
    next_generation: u64,
    cancellation_requests: BTreeSet<FinalTaskId>,
    latest_notifications: BTreeMap<FinalTaskId, FinalTaskStatusNotification>,
    expires_at: BTreeMap<FinalTaskId, Instant>,
}

impl InMemoryFinalTaskStore {
    /// Creates a store with the system monotonic clock and bounded retention.
    pub fn new(max_tasks: usize) -> McpResult<Self> {
        Self::with_clock(max_tasks, Arc::new(Instant::now))
    }

    /// Creates a store with an application-supplied monotonic retention clock.
    pub fn with_clock(
        max_tasks: usize,
        clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> McpResult<Self> {
        if max_tasks == 0 {
            return Err(McpError::invalid_params(
                "In-memory final task store capacity must be positive",
            ));
        }
        Ok(Self {
            max_tasks,
            clock,
            state: Mutex::new(InMemoryFinalTaskState::default()),
        })
    }

    /// Returns the configured maximum number of retained tasks.
    #[must_use]
    pub const fn max_tasks(&self) -> usize {
        self.max_tasks
    }

    /// Returns the current number of retained tasks.
    #[must_use]
    pub fn task_count(&self) -> usize {
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reclaim_expired_in_memory_final_tasks(&mut state, now);
        state.tasks.len()
    }

    /// Returns the latest durably recorded notification for one retained task.
    #[must_use]
    pub fn latest_notification(
        &self,
        task_id: &FinalTaskId,
    ) -> Option<FinalTaskStatusNotification> {
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reclaim_expired_in_memory_final_tasks(&mut state, now);
        state.latest_notifications.get(task_id).cloned()
    }
}

impl Default for InMemoryFinalTaskStore {
    fn default() -> Self {
        Self::new(DEFAULT_IN_MEMORY_FINAL_TASKS)
            .expect("the fixed default in-memory final task capacity is positive")
    }
}

impl FinalTaskStore for InMemoryFinalTaskStore {
    fn create_task(
        &self,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> McpResult<()> {
        let task_id = task.base().task_id.clone();
        ensure_final_task_notification_matches_task(&task, &notification)?;
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reclaim_expired_in_memory_final_tasks(&mut state, now);
        if state.tasks.contains_key(&task_id) {
            return Err(McpError::invalid_params("Task already exists"));
        }
        if state.tasks.len() == self.max_tasks {
            return Err(McpError::invalid_params(
                "In-memory final task store capacity reached",
            ));
        }
        let expires_at = in_memory_final_task_expiry(&task, now)?;
        let generation = next_in_memory_final_task_generation(&mut state)?;
        state
            .latest_notifications
            .insert(task_id.clone(), notification);
        state.tasks.insert(task_id.clone(), task);
        state.generations.insert(task_id.clone(), generation);
        if let Some(expires_at) = expires_at {
            state.expires_at.insert(task_id, expires_at);
        }
        Ok(())
    }

    fn get_task(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTask>> {
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reclaim_expired_in_memory_final_tasks(&mut state, now);
        Ok(state.tasks.get(task_id).cloned())
    }

    fn get_task_snapshot(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTaskSnapshot>> {
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reclaim_expired_in_memory_final_tasks(&mut state, now);
        let Some(task) = state.tasks.get(task_id).cloned() else {
            return Ok(None);
        };
        let generation = state.generations.get(task_id).copied().ok_or_else(|| {
            McpError::internal_error("In-memory final task store is missing a task generation")
        })?;
        Ok(Some(FinalTaskSnapshot::new(task, generation)))
    }

    fn replace_task(
        &self,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> McpResult<()> {
        let task_id = task.base().task_id.clone();
        ensure_final_task_notification_matches_task(&task, &notification)?;
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reclaim_expired_in_memory_final_tasks(&mut state, now);
        if !state.tasks.contains_key(&task_id) {
            return Err(McpError::invalid_params("Task not found"));
        }
        replace_in_memory_final_task(&mut state, task, notification, now)?;
        Ok(())
    }

    fn replace_task_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> McpResult<bool> {
        let task_id = task.base().task_id.clone();
        if expected.task().base().task_id != task_id {
            return Err(McpError::invalid_params(
                "Expected and replacement final task IDs must match",
            ));
        }
        ensure_final_task_notification_matches_task(&task, &notification)?;
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reclaim_expired_in_memory_final_tasks(&mut state, now);
        if state.generations.get(&task_id) != Some(&expected.generation()) {
            return Ok(false);
        }
        replace_in_memory_final_task(&mut state, task, notification, now)?;
        Ok(true)
    }

    fn request_cancellation(&self, task_id: &FinalTaskId) -> McpResult<()> {
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reclaim_expired_in_memory_final_tasks(&mut state, now);
        if !state.tasks.contains_key(task_id) {
            return Err(McpError::invalid_params("Task not found"));
        }
        if !state.cancellation_requests.contains(task_id) {
            let generation = next_in_memory_final_task_generation(&mut state)?;
            state.cancellation_requests.insert(task_id.clone());
            state.generations.insert(task_id.clone(), generation);
        }
        Ok(())
    }

    fn request_cancellation_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<bool> {
        let task_id = &expected.task().base().task_id;
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reclaim_expired_in_memory_final_tasks(&mut state, now);
        if state.generations.get(task_id) != Some(&expected.generation()) {
            return Ok(false);
        }
        if state.cancellation_requests.contains(task_id) {
            return Ok(true);
        }
        let generation = next_in_memory_final_task_generation(&mut state)?;
        state.cancellation_requests.insert(task_id.clone());
        state.generations.insert(task_id.clone(), generation);
        Ok(true)
    }

    fn is_cancellation_requested(&self, task_id: &FinalTaskId) -> McpResult<bool> {
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reclaim_expired_in_memory_final_tasks(&mut state, now);
        if !state.tasks.contains_key(task_id) {
            return Err(McpError::invalid_params("Task not found"));
        }
        Ok(state.cancellation_requests.contains(task_id))
    }
}

fn ensure_final_task_notification_matches_task(
    task: &FinalTask,
    notification: &FinalTaskStatusNotification,
) -> McpResult<()> {
    let retained_task = serde_json::to_value(task).map_err(|error| {
        McpError::internal_error(format!(
            "Could not encode retained final task for validation: {error}"
        ))
    })?;
    let notified_task = serde_json::to_value(&notification.params.task).map_err(|error| {
        McpError::internal_error(format!(
            "Could not encode final task notification for validation: {error}"
        ))
    })?;
    if notified_task != retained_task {
        return Err(McpError::invalid_params(
            "Final task notification must contain exactly the retained task",
        ));
    }
    Ok(())
}

fn in_memory_final_task_expiry(task: &FinalTask, now: Instant) -> McpResult<Option<Instant>> {
    let Some(ttl_ms) = task
        .base()
        .ttl_ms
        .as_ref()
        .map(FinalTaskDuration::as_millis)
    else {
        return Ok(None);
    };
    now.checked_add(StdDuration::from_millis(ttl_ms))
        .map(Some)
        .ok_or_else(|| McpError::internal_error("Task TTL exceeds process-local clock range"))
}

fn next_in_memory_final_task_generation(state: &mut InMemoryFinalTaskState) -> McpResult<u64> {
    let generation = state.next_generation.checked_add(1).ok_or_else(|| {
        McpError::internal_error("In-memory final task generation space is exhausted")
    })?;
    state.next_generation = generation;
    Ok(generation)
}

fn replace_in_memory_final_task(
    state: &mut InMemoryFinalTaskState,
    task: FinalTask,
    notification: FinalTaskStatusNotification,
    now: Instant,
) -> McpResult<()> {
    let task_id = task.base().task_id.clone();
    let expires_at = in_memory_final_task_expiry(&task, now)?;
    let generation = next_in_memory_final_task_generation(state)?;
    let terminal = matches!(
        &task,
        FinalTask::Completed { .. } | FinalTask::Failed { .. } | FinalTask::Cancelled(_)
    );
    state
        .latest_notifications
        .insert(task_id.clone(), notification);
    state.tasks.insert(task_id.clone(), task);
    state.generations.insert(task_id.clone(), generation);
    match expires_at {
        Some(expires_at) => {
            state.expires_at.insert(task_id.clone(), expires_at);
        }
        None => {
            state.expires_at.remove(&task_id);
        }
    }
    if terminal {
        state.cancellation_requests.remove(&task_id);
    }
    Ok(())
}

fn reclaim_expired_in_memory_final_tasks(state: &mut InMemoryFinalTaskState, now: Instant) {
    let expired_task_ids = state
        .expires_at
        .iter()
        .filter_map(|(task_id, expires_at)| (*expires_at <= now).then(|| task_id.clone()))
        .collect::<Vec<_>>();
    for task_id in expired_task_ids {
        state.expires_at.remove(&task_id);
        state.tasks.remove(&task_id);
        state.generations.remove(&task_id);
        state.cancellation_requests.remove(&task_id);
        state.latest_notifications.remove(&task_id);
    }
}

/// Typed notification delivery hook installed by the application transport.
///
/// The store receives the same notification first, so a failed or disconnected
/// delivery path never changes whether the task transition was durable.
pub type FinalTaskNotificationEmitter = Arc<dyn Fn(FinalTaskStatusNotification) + Send + Sync>;

/// Accepted task input made available exactly once to the task supervisor.
///
/// This is deliberately not part of the public task snapshot or notification:
/// task input belongs to the task's private execution state. The caller-owned
/// supervisor takes this value after a task returns to `working` and uses it to
/// resume the associated operation.
#[derive(Clone, Debug, PartialEq)]
pub struct FinalTaskAcceptedInput {
    task_id: FinalTaskId,
    input_responses: FinalTaskInputResponses,
}

impl FinalTaskAcceptedInput {
    /// Returns the task whose worker may now resume.
    #[must_use]
    pub const fn task_id(&self) -> &FinalTaskId {
        &self.task_id
    }

    /// Returns every validated input response accumulated for this resumption.
    #[must_use]
    pub const fn input_responses(&self) -> &FinalTaskInputResponses {
        &self.input_responses
    }

    /// Splits this one-shot supervisor handoff into its task ID and input map.
    #[must_use]
    pub fn into_parts(self) -> (FinalTaskId, FinalTaskInputResponses) {
        (self.task_id, self.input_responses)
    }
}

/// Immutable final Tasks timing policy supplied with the durable store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalTaskRuntimeConfig {
    ttl_ms: u64,
    poll_interval_ms: Option<u64>,
}

impl FinalTaskRuntimeConfig {
    /// Creates a final Tasks policy with a required finite retention duration.
    pub fn new(ttl_ms: u64, poll_interval_ms: Option<u64>) -> McpResult<Self> {
        final_task_duration(ttl_ms)?;
        if let Some(interval) = poll_interval_ms {
            final_task_duration(interval)?;
        }
        Ok(Self {
            ttl_ms,
            poll_interval_ms,
        })
    }
}

/// Final Tasks state machine backed by an application-supplied durable store.
///
/// This type owns neither a runtime nor a task region. A caller-owned
/// asupersync supervisor may invoke these synchronous durable transitions from
/// its own children; the legacy `TaskManager` remains entirely separate.
#[derive(Clone)]
pub struct FinalTaskRuntime {
    store: Arc<dyn FinalTaskStore>,
    config: FinalTaskRuntimeConfig,
    notification_emitters: Arc<Mutex<Vec<FinalTaskNotificationEmitter>>>,
    /// Validated task inputs retained until the caller-owned supervisor takes
    /// one complete resumption handoff. Partial updates accumulate here but
    /// cannot be observed until every outstanding input request is satisfied.
    accepted_inputs: Arc<Mutex<BTreeMap<FinalTaskId, FinalTaskInputResponses>>>,
}

impl FinalTaskRuntime {
    /// Binds final Tasks to one application-owned durable store.
    #[must_use]
    pub fn new(
        store: Arc<dyn FinalTaskStore>,
        config: FinalTaskRuntimeConfig,
        notification_emitter: FinalTaskNotificationEmitter,
    ) -> Self {
        Self {
            store,
            config,
            notification_emitters: Arc::new(Mutex::new(vec![notification_emitter])),
            accepted_inputs: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Creates a usable bounded process-local final Tasks runtime.
    ///
    /// This is appropriate for embeddings that accept process-local task
    /// retention. For restart recovery or multi-process operation, construct
    /// the runtime with an application-owned durable [`FinalTaskStore`].
    #[must_use]
    pub fn in_memory(
        config: FinalTaskRuntimeConfig,
        notification_emitter: FinalTaskNotificationEmitter,
    ) -> Self {
        Self::new(
            Arc::new(InMemoryFinalTaskStore::default()),
            config,
            notification_emitter,
        )
    }

    /// Creates a bounded process-local final Tasks runtime with an explicit capacity.
    pub fn in_memory_with_capacity(
        max_tasks: usize,
        config: FinalTaskRuntimeConfig,
        notification_emitter: FinalTaskNotificationEmitter,
    ) -> McpResult<Self> {
        Ok(Self::new(
            Arc::new(InMemoryFinalTaskStore::new(max_tasks)?),
            config,
            notification_emitter,
        ))
    }

    /// Adds one framework-owned observer to the shared notification fanout.
    ///
    /// Runtime clones share this registry, so a server builder can attach its
    /// subscription publisher after extension handlers have retained their
    /// runtime clone. Application-owned delivery remains installed alongside
    /// the framework observer.
    pub(crate) fn add_notification_emitter(&self, emitter: FinalTaskNotificationEmitter) {
        self.notification_emitters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(emitter);
    }

    /// Takes the validated inputs for a task that has returned to `working`.
    ///
    /// A task supervisor calls this after observing the task's resumed state.
    /// Input values remain private runtime state rather than leaking through a
    /// task snapshot or `notifications/tasks`; the returned value is removed
    /// atomically so one worker cannot replay another worker's inputs. While a
    /// task remains `input_required`, or if it has no accepted inputs, this
    /// returns `None` without changing runtime state.
    pub fn take_accepted_input(
        &self,
        task_id: &FinalTaskId,
    ) -> McpResult<Option<FinalTaskAcceptedInput>> {
        let current = self.load_task_snapshot(task_id)?;
        if !matches!(current.task(), FinalTask::Working(_)) {
            return Ok(None);
        }
        let input_responses = self
            .accepted_inputs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(task_id);
        Ok(input_responses.map(|input_responses| FinalTaskAcceptedInput {
            task_id: task_id.clone(),
            input_responses,
        }))
    }

    /// Durably creates the initial working task before returning its wire result.
    pub fn create_task(&self, status_message: Option<String>) -> McpResult<CreateTaskResult> {
        let task_id = generate_final_task_id()?;
        let now = final_task_timestamp()?;
        let task = FinalTask::Working(FinalTaskBase {
            task_id,
            status: FinalTaskStatus::Working,
            status_message,
            created_at: now.clone(),
            last_updated_at: now,
            ttl_ms: Some(final_task_duration(self.config.ttl_ms)?),
            poll_interval_ms: self
                .config
                .poll_interval_ms
                .map(final_task_duration)
                .transpose()?,
        });
        self.persist_new(task.clone())?;
        Ok(CreateTaskResult {
            task,
            meta: None,
            additional: BTreeMap::new(),
        })
    }

    /// Returns the exact final `tasks/get` complete result.
    pub fn get_task(&self, task_id: &FinalTaskId) -> McpResult<FinalGetTaskResult> {
        Ok(fastmcp_protocol::CompleteTaskResult {
            task: self.load_task_snapshot(task_id)?.into_task(),
            meta: None,
            additional: BTreeMap::new(),
        })
    }

    /// Enters `input_required` with typed final embedded requests.
    pub fn require_input(
        &self,
        task_id: &FinalTaskId,
        input_requests: FinalTaskInputRequests,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        if input_requests.is_empty() {
            return Err(McpError::invalid_params(
                "input_required tasks require at least one input request",
            ));
        }
        FinalTaskInputLedger::from_requests(&input_requests)
            .map_err(|error| McpError::invalid_params(error.to_string()))?;
        let current = self.load_task_snapshot(task_id)?;
        let FinalTask::Working(base) = current.task() else {
            return Err(McpError::invalid_params(
                "only a working task can require client input",
            ));
        };
        let task = FinalTask::InputRequired {
            base: transition_final_task_base(
                base.clone(),
                FinalTaskStatus::InputRequired,
                status_message,
            )?,
            input_requests,
        };
        self.persist_transition(&current, task.clone())?;
        Ok(task)
    }

    /// Applies matching typed input responses and returns the empty final acknowledgement.
    pub fn update_task(
        &self,
        task_id: &FinalTaskId,
        input_responses: &FinalTaskInputResponses,
    ) -> McpResult<UpdateTaskResult> {
        let current = self.load_task_snapshot(task_id)?;
        let FinalTask::InputRequired {
            base,
            input_requests,
        } = current.task()
        else {
            return Ok(UpdateTaskResult::default());
        };
        let mut input_requests = input_requests.clone();
        let ledger = FinalTaskInputLedger::from_requests(&input_requests)
            .map_err(|error| McpError::invalid_params(error.to_string()))?;
        ledger
            .validate_responses(input_responses)
            .map_err(|error| McpError::invalid_params(error.to_string()))?;
        for key in input_responses.keys() {
            input_requests.remove(key);
        }
        let task = if input_requests.is_empty() {
            FinalTask::Working(transition_final_task_base(
                base.clone(),
                FinalTaskStatus::Working,
                None,
            )?)
        } else {
            FinalTask::InputRequired {
                base: transition_final_task_base(
                    base.clone(),
                    FinalTaskStatus::InputRequired,
                    None,
                )?,
                input_requests,
            }
        };
        // Hold the handoff lock across the durable transition. A polling
        // supervisor can therefore never observe `working` and consume an
        // empty handoff in the interval before this accepted input is stored.
        let mut accepted_inputs = self
            .accepted_inputs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let notification = self.persist_transition_without_emit(&current, task)?;
        if !input_responses.is_empty() {
            let accumulated = accepted_inputs.entry(task_id.clone()).or_default();
            accumulated.extend(input_responses.clone());
        }
        drop(accepted_inputs);
        self.emit(notification);
        Ok(UpdateTaskResult::default())
    }

    /// Durably acknowledges cooperative `tasks/cancel` intent.
    pub fn cancel_task(&self, task_id: &FinalTaskId) -> McpResult<FinalCancelTaskResult> {
        let current = self.load_task_snapshot(task_id)?;
        if matches!(
            current.task(),
            FinalTask::Completed { .. } | FinalTask::Failed { .. } | FinalTask::Cancelled(_)
        ) {
            return Err(McpError::invalid_params(
                "terminal tasks cannot be cancelled",
            ));
        }
        if !self.store.request_cancellation_if_current(&current)? {
            return Err(McpError::invalid_params(
                "Task state changed before cancellation could be recorded",
            ));
        }
        Ok(FinalCancelTaskResult::default())
    }

    /// Returns durable cancellation intent for a caller-owned task worker.
    pub fn is_cancellation_requested(&self, task_id: &FinalTaskId) -> McpResult<bool> {
        self.store.is_cancellation_requested(task_id)
    }

    /// Lets a caller-owned worker record the cooperative cancellation outcome.
    pub fn honor_cancellation(
        &self,
        task_id: &FinalTaskId,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        if !self.store.is_cancellation_requested(task_id)? {
            return Err(McpError::invalid_params(
                "task cancellation has not been requested",
            ));
        }
        let current = self.load_task_snapshot(task_id)?;
        if matches!(
            current.task(),
            FinalTask::Completed { .. } | FinalTask::Failed { .. } | FinalTask::Cancelled(_)
        ) {
            return Err(McpError::invalid_params(
                "terminal tasks cannot be cancelled",
            ));
        }
        let task = FinalTask::Cancelled(transition_terminal_final_task_base(
            current.task().base().clone(),
            FinalTaskStatus::Cancelled,
            status_message,
        )?);
        self.persist_transition(&current, task.clone())?;
        self.discard_accepted_input(task_id);
        Ok(task)
    }

    /// Records a typed final tools/call result for a working task.
    pub fn complete_task(
        &self,
        task_id: &FinalTaskId,
        result: FinalTaskCallToolResult,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        let current = self.load_task_snapshot(task_id)?;
        let FinalTask::Working(base) = current.task() else {
            return Err(McpError::invalid_params("only a working task can complete"));
        };
        let task = FinalTask::Completed {
            base: transition_terminal_final_task_base(
                base.clone(),
                FinalTaskStatus::Completed,
                status_message,
            )?,
            result,
        };
        self.persist_transition(&current, task.clone())?;
        self.discard_accepted_input(task_id);
        Ok(task)
    }

    /// Records a typed final task failure for an active task.
    pub fn fail_task(
        &self,
        task_id: &FinalTaskId,
        error: FinalTaskError,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        let current = self.load_task_snapshot(task_id)?;
        if matches!(
            current.task(),
            FinalTask::Completed { .. } | FinalTask::Failed { .. } | FinalTask::Cancelled(_)
        ) {
            return Err(McpError::invalid_params("terminal tasks cannot fail"));
        }
        let task = FinalTask::Failed {
            base: transition_terminal_final_task_base(
                current.task().base().clone(),
                FinalTaskStatus::Failed,
                status_message,
            )?,
            error,
        };
        self.persist_transition(&current, task.clone())?;
        self.discard_accepted_input(task_id);
        Ok(task)
    }

    fn load_task_snapshot(&self, task_id: &FinalTaskId) -> McpResult<FinalTaskSnapshot> {
        let snapshot = self
            .store
            .get_task_snapshot(task_id)?
            .ok_or_else(|| McpError::invalid_params("Task not found"))?;
        if &snapshot.task().base().task_id != task_id {
            return Err(McpError::internal_error(
                "Final task store returned a task under the wrong identifier",
            ));
        }
        Ok(snapshot)
    }

    fn persist_new(&self, task: FinalTask) -> McpResult<()> {
        let notification = final_task_notification(&task);
        self.store.create_task(task, notification.clone())?;
        self.emit(notification);
        Ok(())
    }

    fn persist_transition(&self, expected: &FinalTaskSnapshot, task: FinalTask) -> McpResult<()> {
        let notification = self.persist_transition_without_emit(expected, task)?;
        self.emit(notification);
        Ok(())
    }

    fn persist_transition_without_emit(
        &self,
        expected: &FinalTaskSnapshot,
        task: FinalTask,
    ) -> McpResult<FinalTaskStatusNotification> {
        let notification = final_task_notification(&task);
        if !self
            .store
            .replace_task_if_current(expected, task, notification.clone())?
        {
            return Err(McpError::invalid_params(
                "Task state changed before the transition could be recorded",
            ));
        }
        Ok(notification)
    }

    fn discard_accepted_input(&self, task_id: &FinalTaskId) {
        self.accepted_inputs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(task_id);
    }

    fn emit(&self, notification: FinalTaskStatusNotification) {
        let emitters = self
            .notification_emitters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for emitter in emitters {
            emitter(notification.clone());
        }
    }
}

/// Decodes and serves a negotiated `tasks/get` request through the final runtime.
pub(crate) fn dispatch_final_tasks_get(
    runtime: &FinalTaskRuntime,
    parameters: serde_json::Value,
) -> McpResult<serde_json::Value> {
    let parameters = serde_json::from_value::<GetTaskParams>(parameters)
        .map_err(|_| McpError::invalid_params("Invalid final tasks/get parameters"))?;
    let task_id = FinalTaskId::parse(parameters.id.as_str())
        .map_err(|_| McpError::invalid_params("Invalid final tasks/get parameters"))?;
    serde_json::to_value(runtime.get_task(&task_id)?)
        .map_err(|_| McpError::internal_error("final tasks/get response serialization failed"))
}

/// Decodes and serves a negotiated `tasks/update` request through the final runtime.
pub(crate) fn dispatch_final_tasks_update(
    runtime: &FinalTaskRuntime,
    parameters: serde_json::Value,
) -> McpResult<serde_json::Value> {
    let parameters = serde_json::from_value::<UpdateTaskParams>(parameters)
        .map_err(|_| McpError::invalid_params("Invalid final tasks/update parameters"))?;
    serde_json::to_value(runtime.update_task(&parameters.task_id, &parameters.input_responses)?)
        .map_err(|_| McpError::internal_error("final tasks/update response serialization failed"))
}

/// Decodes and serves a negotiated `tasks/cancel` request through the final runtime.
pub(crate) fn dispatch_final_tasks_cancel(
    runtime: &FinalTaskRuntime,
    parameters: serde_json::Value,
) -> McpResult<serde_json::Value> {
    let parameters = serde_json::from_value::<GetTaskParams>(parameters)
        .map_err(|_| McpError::invalid_params("Invalid final tasks/cancel parameters"))?;
    let task_id = FinalTaskId::parse(parameters.id.as_str())
        .map_err(|_| McpError::invalid_params("Invalid final tasks/cancel parameters"))?;
    serde_json::to_value(runtime.cancel_task(&task_id)?)
        .map_err(|_| McpError::internal_error("final tasks/cancel response serialization failed"))
}

fn generate_final_task_id() -> McpResult<FinalTaskId> {
    let identifier = draw_security_identifier().map_err(|error| {
        McpError::internal_error(format!("Task identifier generation failed: {error}"))
    })?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(identifier.as_bytes());
    FinalTaskId::parse(encoded).map_err(|error| McpError::internal_error(error.to_string()))
}

fn final_task_timestamp() -> McpResult<FinalTaskTimestamp> {
    FinalTaskTimestamp::parse(
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    )
    .map_err(|error| McpError::internal_error(error.to_string()))
}

fn final_task_duration(milliseconds: u64) -> McpResult<FinalTaskDuration> {
    serde_json::from_value(serde_json::json!(milliseconds))
        .map_err(|error| McpError::invalid_params(format!("invalid task duration: {error}")))
}

fn transition_final_task_base(
    mut base: FinalTaskBase,
    status: FinalTaskStatus,
    status_message: Option<String>,
) -> McpResult<FinalTaskBase> {
    base.status = status;
    base.status_message = status_message;
    base.last_updated_at = final_task_timestamp()?;
    Ok(base)
}

fn transition_terminal_final_task_base(
    base: FinalTaskBase,
    status: FinalTaskStatus,
    status_message: Option<String>,
) -> McpResult<FinalTaskBase> {
    if !matches!(
        status,
        FinalTaskStatus::Completed | FinalTaskStatus::Failed | FinalTaskStatus::Cancelled
    ) {
        return Err(McpError::internal_error(
            "terminal task transition requires a terminal status",
        ));
    }
    transition_final_task_base(base, status, status_message)
}

fn final_task_notification(task: &FinalTask) -> FinalTaskStatusNotification {
    FinalTaskStatusNotification::new(FinalTaskStatusNotificationParams {
        task: task.clone(),
        meta: None,
        additional: BTreeMap::new(),
    })
}

#[cfg(test)]
impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl std::fmt::Debug for TaskManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Use poison recovery to avoid panic during Debug formatting
        let task_count = self
            .tasks
            .read()
            .map(|g| g.len())
            .unwrap_or_else(|poisoned| poisoned.into_inner().len());
        let handler_count = self
            .handlers
            .read()
            .map(|g| g.len())
            .unwrap_or_else(|poisoned| poisoned.into_inner().len());
        f.debug_struct("TaskManager")
            .field("task_count", &task_count)
            .field("handler_count", &handler_count)
            .field("task_counter", &self.task_counter.load(Ordering::SeqCst))
            .field(
                "list_changed_notifications",
                &self.list_changed_notifications,
            )
            .field("auto_execute", &self.auto_execute)
            .finish_non_exhaustive()
    }
}

/// Thread-safe handle to a TaskManager.
#[cfg(test)]
pub type SharedTaskManager = Arc<TaskManager>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    use std::thread;
    use std::time::Duration;

    fn final_task_runtime(
        store: Arc<InMemoryFinalTaskStore>,
        delivery_after_durable_commit: Arc<AtomicBool>,
    ) -> FinalTaskRuntime {
        let store_for_emitter = Arc::clone(&store);
        FinalTaskRuntime::new(
            store,
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(move |notification| {
                if store_for_emitter
                    .get_task(&notification.params.task.base().task_id)
                    .expect("in-memory final task store read")
                    .is_some()
                {
                    delivery_after_durable_commit.store(true, AtomicOrdering::SeqCst);
                }
            }),
        )
    }

    fn final_roots_request() -> FinalTaskInputRequests {
        let mut requests = FinalTaskInputRequests::new();
        requests.insert(
            "roots".to_owned(),
            serde_json::from_value(serde_json::json!({"method": "roots/list"}))
                .expect("typed roots input request"),
        );
        requests
    }

    fn final_working_task_without_ttl(task_id: &str) -> FinalTask {
        let timestamp = FinalTaskTimestamp::parse("2026-07-28T12:00:00.000Z")
            .expect("fixed test timestamp is valid");
        FinalTask::Working(FinalTaskBase {
            task_id: FinalTaskId::parse(task_id).expect("fixed test task ID is valid"),
            status: FinalTaskStatus::Working,
            status_message: None,
            created_at: timestamp.clone(),
            last_updated_at: timestamp,
            ttl_ms: None,
            poll_interval_ms: None,
        })
    }

    fn final_working_task_with_ttl(task_id: &str, ttl_ms: u64) -> FinalTask {
        let FinalTask::Working(mut base) = final_working_task_without_ttl(task_id) else {
            unreachable!("the helper always constructs a working task");
        };
        base.ttl_ms = Some(final_task_duration(ttl_ms).expect("fixed test task TTL is valid"));
        FinalTask::Working(base)
    }

    fn in_memory_store_with_test_clock(
        max_tasks: usize,
    ) -> (Arc<InMemoryFinalTaskStore>, Arc<Mutex<Instant>>) {
        let now = Arc::new(Mutex::new(Instant::now()));
        let clock_now = Arc::clone(&now);
        let clock: Arc<dyn Fn() -> Instant + Send + Sync> = Arc::new(move || {
            *clock_now
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        });
        (
            Arc::new(
                InMemoryFinalTaskStore::with_clock(max_tasks, clock)
                    .expect("positive bounded store capacity is valid"),
            ),
            now,
        )
    }

    #[test]
    fn task_03_in_memory_runtime_constructor_lifecycle_positive() {
        let runtime = FinalTaskRuntime::in_memory(
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid in-memory task policy"),
            Arc::new(|_| {}),
        );

        let task_id = runtime
            .create_task(Some("accepted".to_owned()))
            .expect("the shipped in-memory runtime creates a task")
            .task
            .base()
            .task_id
            .clone();
        assert!(matches!(
            runtime
                .get_task(&task_id)
                .expect("created task remains readable")
                .task,
            FinalTask::Working(_)
        ));
        runtime
            .cancel_task(&task_id)
            .expect("created task accepts cancellation intent");
        assert!(
            runtime
                .is_cancellation_requested(&task_id)
                .expect("cancellation intent remains readable")
        );
    }

    #[test]
    fn task_03_in_memory_runtime_capacity_one_variable_rejection() {
        let runtime = FinalTaskRuntime::in_memory_with_capacity(
            1,
            FinalTaskRuntimeConfig::new(60_000, None).expect("valid in-memory task policy"),
            Arc::new(|_| {}),
        )
        .expect("positive capacity constructs the in-memory runtime");
        let first = runtime
            .create_task(None)
            .expect("first task fits the one-task capacity");
        let first_id = first.task.base().task_id.clone();

        assert!(
            runtime.create_task(None).is_err(),
            "only the second create changes from the admitted one-task baseline"
        );
        assert!(matches!(
            runtime
                .get_task(&first_id)
                .expect("rejected second create preserves the first task")
                .task,
            FinalTask::Working(_)
        ));
    }

    #[test]
    fn task_03_in_memory_store_positive_ttl_reclaims_capacity_at_deterministic_deadline() {
        const TTL_MS: u64 = 60_000;
        let (store, now) = in_memory_store_with_test_clock(1);
        let first = final_working_task_with_ttl("task-positive-ttl-first", TTL_MS);
        let first_id = first.base().task_id.clone();
        store
            .create_task(first.clone(), final_task_notification(&first))
            .expect("first task fits the bounded store");
        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(StdDuration::from_millis(TTL_MS))
            .expect("positive task TTL fits the monotonic test clock");
        drop(clock);

        let second = final_working_task_without_ttl("task-positive-ttl-second");
        let second_id = second.base().task_id.clone();
        store
            .create_task(second.clone(), final_task_notification(&second))
            .expect("the expired first task releases bounded capacity");

        assert!(
            store
                .get_task(&first_id)
                .expect("expired task lookup is readable")
                .is_none()
        );
        assert!(store.latest_notification(&first_id).is_none());
        assert_eq!(store.task_count(), 1);
        assert!(
            store
                .get_task(&second_id)
                .expect("replacement task lookup is readable")
                .is_some()
        );
    }

    #[test]
    fn task_03_in_memory_store_positive_ttl_one_millisecond_before_deadline_preserves_state() {
        const TTL_MS: u64 = 60_000;
        let (store, now) = in_memory_store_with_test_clock(1);
        let first = final_working_task_with_ttl("task-positive-ttl-first", TTL_MS);
        let first_id = first.base().task_id.clone();
        store
            .create_task(first.clone(), final_task_notification(&first))
            .expect("first task fits the bounded store");
        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(StdDuration::from_millis(TTL_MS - 1))
            .expect("pre-deadline duration fits the monotonic test clock");
        drop(clock);

        let second = final_working_task_without_ttl("task-positive-ttl-second");
        assert!(
            store
                .create_task(second.clone(), final_task_notification(&second))
                .is_err(),
            "only advancing the clock by one fewer millisecond preserves the first task"
        );
        assert_eq!(store.task_count(), 1);
        assert!(
            store
                .get_task(&first_id)
                .expect("pre-deadline task lookup is readable")
                .is_some()
        );
    }

    #[test]
    fn task_03_in_memory_store_absent_ttl_has_no_automatic_expiry() {
        const ELAPSED_MS: u64 = 60_000;
        let (store, now) = in_memory_store_with_test_clock(1);
        let first = final_working_task_without_ttl("task-absent-ttl-first");
        let first_id = first.base().task_id.clone();
        store
            .create_task(first.clone(), final_task_notification(&first))
            .expect("first task without a TTL fits the bounded store");
        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(StdDuration::from_millis(ELAPSED_MS))
            .expect("test clock can advance without an automatic task expiry");
        drop(clock);

        let second = final_working_task_without_ttl("task-absent-ttl-second");
        assert!(
            store
                .create_task(second.clone(), final_task_notification(&second))
                .is_err(),
            "an omitted TTL leaves the first task retained and capacity unavailable"
        );
        assert_eq!(store.task_count(), 1);
        assert!(
            store
                .get_task(&first_id)
                .expect("task without a TTL remains readable")
                .is_some()
        );
    }

    #[test]
    fn task_03_in_memory_store_rejects_stale_transition_after_terminal_commit() {
        let store = InMemoryFinalTaskStore::default();
        let working = final_working_task_without_ttl("task-atomic-transition");
        let task_id = working.base().task_id.clone();
        store
            .create_task(working.clone(), final_task_notification(&working))
            .expect("working task creates");
        let working_snapshot = store
            .get_task_snapshot(&task_id)
            .expect("working task snapshot is readable")
            .expect("working task snapshot is retained");

        let mut cancelled_base = working.base().clone();
        cancelled_base.status = FinalTaskStatus::Cancelled;
        let cancelled = FinalTask::Cancelled(cancelled_base);
        assert!(
            store
                .replace_task_if_current(
                    &working_snapshot,
                    cancelled.clone(),
                    final_task_notification(&cancelled),
                )
                .expect("terminal compare-and-replace is readable")
        );

        let mut input_required_base = working.base().clone();
        input_required_base.status = FinalTaskStatus::InputRequired;
        let stale_input_required = FinalTask::InputRequired {
            base: input_required_base,
            input_requests: final_roots_request(),
        };
        assert!(
            !store
                .replace_task_if_current(
                    &working_snapshot,
                    stale_input_required.clone(),
                    final_task_notification(&stale_input_required),
                )
                .expect("stale compare-and-replace is readable"),
            "the stale working snapshot cannot overwrite a terminal transition"
        );
        assert!(matches!(
            store
                .get_task(&task_id)
                .expect("terminal task lookup is readable"),
            Some(FinalTask::Cancelled(_))
        ));
    }

    #[test]
    fn task_03_final_task_snapshot_public_constructor_retains_opaque_generation() {
        let task = final_working_task_without_ttl("task-public-snapshot");
        let task_id = task.base().task_id.clone();
        let snapshot = FinalTaskSnapshot::new(task, 41);

        assert_eq!(snapshot.task().base().task_id, task_id);
        assert_eq!(snapshot.generation(), 41);
    }

    #[test]
    fn task_03_in_memory_store_generation_rejects_aba_replacement() {
        let store = InMemoryFinalTaskStore::default();
        let working = final_working_task_without_ttl("task-generation-aba");
        let task_id = working.base().task_id.clone();
        store
            .create_task(working.clone(), final_task_notification(&working))
            .expect("working task creates");
        let initial_snapshot = store
            .get_task_snapshot(&task_id)
            .expect("initial snapshot is readable")
            .expect("working task is retained");

        assert!(
            store
                .replace_task_if_current(
                    &initial_snapshot,
                    working.clone(),
                    final_task_notification(&working),
                )
                .expect("same-value replacement is accepted for the current generation")
        );
        assert!(
            !store
                .replace_task_if_current(
                    &initial_snapshot,
                    working.clone(),
                    final_task_notification(&working),
                )
                .expect("stale same-value replacement is readable"),
            "only the store generation changes, so a reused wire value cannot pass CAS"
        );
    }

    #[test]
    fn task_03_in_memory_store_replacement_recomputes_expiry_atomically() {
        const TTL_MS: u64 = 60_000;
        let (store, now) = in_memory_store_with_test_clock(1);
        let expiring = final_working_task_with_ttl("task-replacement-expiry", TTL_MS);
        let task_id = expiring.base().task_id.clone();
        store
            .create_task(expiring.clone(), final_task_notification(&expiring))
            .expect("expiring task creates");

        let non_expiring = final_working_task_without_ttl("task-replacement-expiry");
        store
            .replace_task(non_expiring.clone(), final_task_notification(&non_expiring))
            .expect("finite-to-absent replacement updates retained expiry atomically");
        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(StdDuration::from_millis(TTL_MS))
            .expect("test clock reaches the original expiry");
        drop(clock);
        assert!(
            store
                .get_task(&task_id)
                .expect("replacement task lookup is readable")
                .is_some(),
            "removing the TTL removes the original expiry at the same replacement boundary"
        );

        let expiring_again = final_working_task_with_ttl("task-replacement-expiry", TTL_MS);
        store
            .replace_task(
                expiring_again.clone(),
                final_task_notification(&expiring_again),
            )
            .expect("absent-to-finite replacement installs a new expiry atomically");
        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(StdDuration::from_millis(TTL_MS))
            .expect("test clock reaches the replacement expiry");
        drop(clock);
        assert!(
            store
                .get_task(&task_id)
                .expect("expired replacement task lookup is readable")
                .is_none(),
            "only the replacement TTL changes from the retained non-expiring baseline"
        );
    }

    #[test]
    fn task_03_in_memory_runtime_reclaims_expired_task_before_capacity_check_positive() {
        let store = Arc::new(
            InMemoryFinalTaskStore::new(1).expect("one retained task is a valid bounded store"),
        );
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let first = runtime
            .create_task(None)
            .expect("first task fits the one-task capacity");
        let first_id = first.task.base().task_id.clone();
        {
            let mut state = store
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.expires_at.insert(
                first_id.clone(),
                std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_millis(1))
                    .expect("a just-created monotonic instant can be moved back one millisecond"),
            );
        }

        let second = runtime
            .create_task(None)
            .expect("expired retention is reclaimed before admitting the next task");
        let second_id = second.task.base().task_id.clone();

        assert_eq!(store.task_count(), 1);
        assert!(
            store
                .get_task(&first_id)
                .expect("expired task lookup is readable")
                .is_none(),
            "reclamation removes the expired task"
        );
        assert!(store.latest_notification(&first_id).is_none());
        assert!(
            store
                .get_task(&second_id)
                .expect("replacement task lookup is readable")
                .is_some()
        );
    }

    #[test]
    fn task_03_in_memory_store_rejects_one_field_notification_task_id_mismatch() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let first_id = runtime
            .create_task(None)
            .expect("first task creates")
            .task
            .base()
            .task_id
            .clone();
        let second_id = runtime
            .create_task(None)
            .expect("second task creates")
            .task
            .base()
            .task_id
            .clone();
        let first_task = store
            .get_task(&first_id)
            .expect("first task reads")
            .expect("first task remains retained");
        let first_notification = store
            .latest_notification(&first_id)
            .expect("first notification remains retained");
        let mut mismatched_notification = first_notification.clone();
        let FinalTask::Working(base) = &mut mismatched_notification.params.task else {
            panic!("created task notification must begin in the working state");
        };
        base.task_id = second_id;
        let first_task_before = serde_json::to_value(&first_task).expect("serialize first task");
        let first_notification_before =
            serde_json::to_value(&first_notification).expect("serialize first notification");

        let error = store
            .replace_task(first_task, mismatched_notification)
            .expect_err("only the notification task ID differs from the accepted replacement");

        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
        assert_eq!(
            store.task_count(),
            2,
            "rejection preserves both retained tasks"
        );
        let first_task_after = store
            .get_task(&first_id)
            .expect("first task remains readable after rejection")
            .expect("rejection cannot remove the retained task");
        assert_eq!(
            serde_json::to_value(first_task_after).expect("serialize post-rejection task"),
            first_task_before,
            "mismatched notification cannot replace the retained task"
        );
        let first_notification_after = store
            .latest_notification(&first_id)
            .expect("rejection cannot remove the retained notification");
        assert_eq!(
            serde_json::to_value(first_notification_after)
                .expect("serialize post-rejection notification"),
            first_notification_before,
            "mismatched notification cannot replace the retained notification"
        );
    }

    #[test]
    fn task_03_in_memory_store_rejects_same_id_notification_base_drift_without_mutation() {
        let store = InMemoryFinalTaskStore::default();
        let task = final_working_task_without_ttl("task-notification-base-drift");
        let task_id = task.base().task_id.clone();
        let notification = final_task_notification(&task);
        store
            .create_task(task.clone(), notification.clone())
            .expect("matching task and notification create");
        let snapshot_before = store
            .get_task_snapshot(&task_id)
            .expect("stored task snapshot is readable")
            .expect("created task is retained");
        let task_before = serde_json::to_value(snapshot_before.task())
            .expect("serialize retained task before rejection");
        let notification_before = serde_json::to_value(&notification)
            .expect("serialize retained notification before rejection");

        let mut drifted_notification = notification.clone();
        let FinalTask::Working(base) = &mut drifted_notification.params.task else {
            panic!("baseline notification contains the working task");
        };
        base.status_message = Some("only the notification task base drifted".to_owned());

        let error = store
            .replace_task_if_current(&snapshot_before, task, drifted_notification)
            .expect_err("same-ID notification base drift must be rejected");

        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
        let snapshot_after = store
            .get_task_snapshot(&task_id)
            .expect("stored task snapshot remains readable")
            .expect("rejection preserves the retained task");
        assert_eq!(
            serde_json::to_value(snapshot_after.task())
                .expect("serialize retained task after rejection"),
            task_before,
            "rejection preserves the retained task"
        );
        assert_eq!(
            snapshot_after.generation(),
            snapshot_before.generation(),
            "rejection preserves the compare-and-swap generation"
        );
        assert_eq!(
            serde_json::to_value(
                store
                    .latest_notification(&task_id)
                    .expect("rejection preserves the retained notification"),
            )
            .expect("serialize retained notification after rejection"),
            notification_before,
            "rejection preserves the retained notification"
        );
    }

    #[test]
    fn task_03_final_durable_runtime_positive() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let delivered_after_durable_commit = Arc::new(AtomicBool::new(false));
        let runtime = final_task_runtime(
            Arc::clone(&store),
            Arc::clone(&delivered_after_durable_commit),
        );

        let created = runtime
            .create_task(Some("accepted".to_owned()))
            .expect("durable create before wire reply");
        let task_id = created.task.base().task_id.clone();
        assert!(matches!(created.task, FinalTask::Working(_)));
        assert_eq!(store.task_count(), 1, "create result retains one task");
        assert!(
            delivered_after_durable_commit.load(AtomicOrdering::SeqCst),
            "typed notification delivery runs only after the store has accepted the task"
        );
        let created_notification = store
            .latest_notification(&task_id)
            .expect("durable create records its typed notification");
        let notification_wire =
            serde_json::to_value(created_notification).expect("encode task notification");
        assert_eq!(notification_wire["method"], "notifications/tasks");
        assert_eq!(notification_wire["params"]["taskId"], task_id.as_str());
        assert_eq!(
            runtime
                .get_task(&task_id)
                .expect("get newly created task")
                .task
                .base()
                .task_id,
            task_id
        );

        runtime
            .require_input(
                &task_id,
                final_roots_request(),
                Some("awaiting roots".to_owned()),
            )
            .expect("working task accepts typed roots request");
        let input_responses: FinalTaskInputResponses = serde_json::from_value(serde_json::json!({
            "roots": {"roots": []}
        }))
        .expect("typed roots response");
        let update = runtime
            .update_task(&task_id, &input_responses)
            .expect("matching typed input response updates task");
        assert_eq!(
            serde_json::to_value(update).expect("encode empty update acknowledgement")["resultType"],
            "complete"
        );
        assert!(matches!(
            runtime
                .get_task(&task_id)
                .expect("get task after update")
                .task,
            FinalTask::Working(_)
        ));

        let cancel = runtime
            .cancel_task(&task_id)
            .expect("durably record cancellation intent");
        assert_eq!(
            serde_json::to_value(cancel).expect("encode empty cancel acknowledgement")["resultType"],
            "complete"
        );
        assert!(
            runtime
                .is_cancellation_requested(&task_id)
                .expect("read durable cancellation intent")
        );
        assert!(matches!(
            runtime
                .honor_cancellation(&task_id, Some("cancelled".to_owned()))
                .expect("caller-owned worker honors cancellation"),
            FinalTask::Cancelled(_)
        ));
        assert!(
            store.latest_notification(&task_id).is_some(),
            "the bounded store retains the terminal typed notification"
        );
    }

    #[test]
    fn task_03_final_accepted_input_reaches_resumed_supervisor() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = runtime
            .create_task(None)
            .expect("create task before requesting input")
            .task
            .base()
            .task_id
            .clone();

        let mut requests = final_roots_request();
        requests.insert(
            "workspace-roots".to_owned(),
            serde_json::from_value(serde_json::json!({"method": "roots/list"}))
                .expect("typed second roots input request"),
        );
        runtime
            .require_input(&task_id, requests, Some("awaiting both roots responses".to_owned()))
            .expect("working task requests two typed inputs");

        let first: FinalTaskInputResponses = serde_json::from_value(serde_json::json!({
            "roots": {"roots": [{"uri": "file:///first"}]}
        }))
        .expect("typed first roots response");
        runtime
            .update_task(&task_id, &first)
            .expect("accept first matching input response");
        assert!(
            runtime
                .take_accepted_input(&task_id)
                .expect("read input handoff while task remains input_required")
                .is_none(),
            "a supervisor cannot resume until every outstanding input is satisfied"
        );

        let second: FinalTaskInputResponses = serde_json::from_value(serde_json::json!({
            "workspace-roots": {"roots": [{"uri": "file:///second"}]}
        }))
        .expect("typed second roots response");
        runtime
            .update_task(&task_id, &second)
            .expect("accept final matching input response");

        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("resumed task exposes one supervisor handoff")
            .expect("all accepted input values are retained for the resumed worker");
        assert_eq!(accepted.task_id(), &task_id);
        assert_eq!(accepted.input_responses().get("roots"), first.get("roots"));
        assert_eq!(
            accepted.input_responses().get("workspace-roots"),
            second.get("workspace-roots")
        );
        assert!(matches!(
            runtime
                .get_task(&task_id)
                .expect("resumed task remains readable")
                .task,
            FinalTask::Working(_)
        ));
        assert!(
            runtime
                .take_accepted_input(&task_id)
                .expect("second handoff read is valid")
                .is_none(),
            "the supervisor handoff is one-shot and cannot replay accepted input"
        );
    }

    #[test]
    fn task_03_final_rejected_input_preserves_supervisor_handoff_state() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = runtime
            .create_task(None)
            .expect("create task before requesting input")
            .task
            .base()
            .task_id
            .clone();
        runtime
            .require_input(&task_id, final_roots_request(), None)
            .expect("task awaits one roots response");
        let before = serde_json::to_vec(
            &runtime
                .get_task(&task_id)
                .expect("read input-required task before planted response")
                .task,
        )
        .expect("serialize input-required task before planted response");
        let notification_before = store
            .latest_notification(&task_id)
            .expect("input-required task retains its notification before planted response");

        // This differs from the accepted roots response only in the embedded
        // response kind: sampling is well-formed but cannot satisfy roots/list.
        let wrong_kind: FinalTaskInputResponses = serde_json::from_value(serde_json::json!({
            "roots": {
                "role": "assistant",
                "model": "final-model",
                "content": {"type": "text", "text": "wrong response kind"}
            }
        }))
        .expect("well-formed mismatched typed response");
        assert!(
            runtime.update_task(&task_id, &wrong_kind).is_err(),
            "a mismatched response kind fails before it can reach the supervisor"
        );

        let after = serde_json::to_vec(
            &runtime
                .get_task(&task_id)
                .expect("read task after rejected response")
                .task,
        )
        .expect("serialize task after rejected response");
        assert_eq!(after, before, "rejected input leaves durable task state unchanged");
        assert_eq!(
            serde_json::to_vec(&store.latest_notification(&task_id))
                .expect("serialize retained notification after rejection"),
            serde_json::to_vec(&Some(notification_before))
                .expect("serialize baseline notification"),
            "rejected input cannot replace the retained notification"
        );
        assert!(
            runtime
                .take_accepted_input(&task_id)
                .expect("read unchanged supervisor handoff state")
                .is_none(),
            "rejected input cannot create a supervisor handoff"
        );
    }

    #[test]
    fn task_03_final_durable_runtime_wrong_response_kind_preserves_state() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = runtime
            .create_task(None)
            .expect("create durable task")
            .task
            .base()
            .task_id
            .clone();
        runtime
            .require_input(&task_id, final_roots_request(), None)
            .expect("task awaits a roots response");
        let before = serde_json::to_vec(
            &runtime
                .get_task(&task_id)
                .expect("snapshot task before planted response")
                .task,
        )
        .expect("serialize task snapshot");
        let notification_before = store
            .latest_notification(&task_id)
            .expect("input-required task retains a typed notification");

        // The response key is unchanged from the accepted case; only its
        // discriminating payload changes from a roots result to sampling.
        let wrong_kind: FinalTaskInputResponses = serde_json::from_value(serde_json::json!({
            "roots": {
                "role": "assistant",
                "model": "final-model",
                "content": {"type": "text", "text": "wrong response kind"}
            }
        }))
        .expect("well-formed but mismatched typed response");
        assert!(
            runtime.update_task(&task_id, &wrong_kind).is_err(),
            "a response whose type does not match the issued request fails closed"
        );

        let after = serde_json::to_vec(
            &runtime
                .get_task(&task_id)
                .expect("snapshot task after rejected response")
                .task,
        )
        .expect("serialize task snapshot");
        assert_eq!(
            after, before,
            "rejected input cannot mutate durable task state"
        );
        assert_eq!(
            serde_json::to_vec(&store.latest_notification(&task_id))
                .expect("serialize retained notification"),
            serde_json::to_vec(&Some(notification_before))
                .expect("serialize baseline notification"),
            "rejected input cannot replace the retained typed notification"
        );
    }

    #[test]
    fn test_task_manager_creation() {
        let manager = TaskManager::new();
        assert_eq!(manager.total_count(), 0);
        assert_eq!(manager.active_count(), 0);
        assert!(!manager.has_list_changed_notifications());
    }

    #[test]
    fn test_task_manager_with_notifications() {
        let manager = TaskManager::with_list_changed_notifications();
        assert!(manager.has_list_changed_notifications());
    }

    #[test]
    fn test_register_handler() {
        let manager = TaskManager::new();

        manager.register_handler("test_task", |_cx, _params| async {
            Ok(serde_json::json!({}))
        });

        // Submit should succeed now
        let cx = Cx::for_testing();
        let result = manager.submit(&cx, "test_task", None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_submit_auto_execute_fails_when_runtime_unavailable() {
        let mut manager = TaskManager::new_for_testing();
        manager.auto_execute = true;
        manager.runtime = None;

        manager.register_handler("test_task", |_cx, _params| async {
            Ok(serde_json::json!({}))
        });

        let cx = Cx::for_testing();
        let task_id = manager.submit(&cx, "test_task", None).unwrap();

        let info = manager.get_info(&task_id).unwrap();
        assert_eq!(info.status, TaskStatus::Failed);
        assert_eq!(info.error.as_deref(), Some("Task runtime unavailable"));

        let result = manager.get_result(&task_id).unwrap();
        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("Task runtime unavailable"));
    }

    #[test]
    fn test_submit_unknown_task_type() {
        let manager = TaskManager::new();
        let cx = Cx::for_testing();

        let result = manager.submit(&cx, "unknown_task", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_task_lifecycle() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();

        manager.register_handler("test", |_cx, _params| async {
            Ok(serde_json::json!({"done": true}))
        });

        // Submit
        let task_id = manager.submit(&cx, "test", None).unwrap();

        // Check initial state
        let info = manager.get_info(&task_id).unwrap();
        assert_eq!(info.status, TaskStatus::Pending);
        assert!(info.started_at.is_none());

        // Start
        manager.start_task(&task_id).unwrap();
        let info = manager.get_info(&task_id).unwrap();
        assert_eq!(info.status, TaskStatus::Running);
        assert!(info.started_at.is_some());

        // Update progress
        manager.update_progress(&task_id, 0.5, Some("Halfway done".into()));
        let info = manager.get_info(&task_id).unwrap();
        assert_eq!(info.progress, Some(0.5));
        assert_eq!(info.message, Some("Halfway done".into()));

        // Complete
        manager.complete_task(&task_id, serde_json::json!({"result": 42}));
        let info = manager.get_info(&task_id).unwrap();
        assert_eq!(info.status, TaskStatus::Completed);
        assert!(info.completed_at.is_some());

        // Check result
        let result = manager.get_result(&task_id).unwrap();
        assert!(result.success);
        assert_eq!(result.data, Some(serde_json::json!({"result": 42})));
    }

    #[test]
    fn test_task_failure() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();

        manager.register_handler("fail_test", |_cx, _params| async {
            Ok(serde_json::json!({}))
        });

        let task_id = manager.submit(&cx, "fail_test", None).unwrap();
        manager.start_task(&task_id).unwrap();
        manager.fail_task(&task_id, "Something went wrong");

        let info = manager.get_info(&task_id).unwrap();
        assert_eq!(info.status, TaskStatus::Failed);
        assert_eq!(info.error, Some("Something went wrong".into()));

        let result = manager.get_result(&task_id).unwrap();
        assert!(!result.success);
        assert_eq!(result.error, Some("Something went wrong".into()));
    }

    #[test]
    fn test_task_cancellation() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();

        manager.register_handler("cancel_test", |_cx, _params| async {
            Ok(serde_json::json!({}))
        });

        let task_id = manager.submit(&cx, "cancel_test", None).unwrap();
        manager.start_task(&task_id).unwrap();

        // Cancel
        let info = manager
            .cancel(&task_id, Some("User cancelled".into()))
            .unwrap();
        assert_eq!(info.status, TaskStatus::Cancelled);

        // Check cancel flag
        assert!(manager.is_cancel_requested(&task_id));

        // Cannot cancel again
        let result = manager.cancel(&task_id, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_tasks() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();

        manager.register_handler("list_test", |_cx, _params| async {
            Ok(serde_json::json!({}))
        });

        let task1 = manager.submit(&cx, "list_test", None).unwrap();
        let task2 = manager.submit(&cx, "list_test", None).unwrap();
        let _task3 = manager.submit(&cx, "list_test", None).unwrap();

        // All pending initially
        assert_eq!(manager.list_tasks(Some(TaskStatus::Pending)).len(), 3);
        assert_eq!(manager.list_tasks(Some(TaskStatus::Running)).len(), 0);

        // Start one
        manager.start_task(&task1).unwrap();
        assert_eq!(manager.list_tasks(Some(TaskStatus::Pending)).len(), 2);
        assert_eq!(manager.list_tasks(Some(TaskStatus::Running)).len(), 1);

        // Complete one
        manager.start_task(&task2).unwrap();
        manager.complete_task(&task2, serde_json::json!({}));
        assert_eq!(manager.list_tasks(Some(TaskStatus::Completed)).len(), 1);

        // All tasks
        assert_eq!(manager.list_tasks(None).len(), 3);
    }

    #[test]
    fn test_active_count() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();

        manager.register_handler("count_test", |_cx, _params| async {
            Ok(serde_json::json!({}))
        });

        let task1 = manager.submit(&cx, "count_test", None).unwrap();
        let task2 = manager.submit(&cx, "count_test", None).unwrap();

        assert_eq!(manager.active_count(), 2);
        assert_eq!(manager.total_count(), 2);

        manager.start_task(&task1).unwrap();
        assert_eq!(manager.active_count(), 2);

        manager.complete_task(&task1, serde_json::json!({}));
        assert_eq!(manager.active_count(), 1);

        manager.cancel(&task2, None).unwrap();
        assert_eq!(manager.active_count(), 0);
        assert_eq!(manager.total_count(), 2);
    }

    #[test]
    fn test_progress_clamping() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();

        manager.register_handler("clamp_test", |_cx, _params| async {
            Ok(serde_json::json!({}))
        });

        let task_id = manager.submit(&cx, "clamp_test", None).unwrap();
        manager.start_task(&task_id).unwrap();

        // Progress should be clamped to [0.0, 1.0]
        manager.update_progress(&task_id, -0.5, None);
        assert_eq!(manager.get_info(&task_id).unwrap().progress, Some(0.0));

        manager.update_progress(&task_id, 1.5, None);
        assert_eq!(manager.get_info(&task_id).unwrap().progress, Some(1.0));

        manager.update_progress(&task_id, 0.75, None);
        assert_eq!(manager.get_info(&task_id).unwrap().progress, Some(0.75));
    }

    #[test]
    fn test_invalid_transition_rejected() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();

        manager.register_handler("transition_test", |_cx, _params| async {
            Ok(serde_json::json!({}))
        });

        let task_id = manager.submit(&cx, "transition_test", None).unwrap();

        // Completing before running should be ignored.
        manager.complete_task(&task_id, serde_json::json!({"result": "noop"}));
        let info = manager.get_info(&task_id).unwrap();
        assert_eq!(info.status, TaskStatus::Pending);

        manager.start_task(&task_id).unwrap();
        manager.complete_task(&task_id, serde_json::json!({"result": "ok"}));
        let info = manager.get_info(&task_id).unwrap();
        assert_eq!(info.status, TaskStatus::Completed);

        // Starting after completion should fail.
        let result = manager.start_task(&task_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_concurrent_submissions() {
        let manager = Arc::new(TaskManager::new_for_testing());
        manager.register_handler("concurrent_test", |_cx, _params| async {
            Ok(serde_json::json!({}))
        });

        let mut handles = Vec::new();
        for _ in 0..4 {
            let manager = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                let cx = Cx::for_testing();
                for _ in 0..10 {
                    let _ = manager.submit(&cx, "concurrent_test", None).unwrap();
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread join failed");
        }

        assert_eq!(manager.total_count(), 40);
        assert_eq!(manager.list_tasks(Some(TaskStatus::Pending)).len(), 40);
    }

    #[test]
    fn test_task_status_notifications() {
        let manager = TaskManager::new_for_testing();
        manager.register_handler("notify_test", |_cx, _params| async {
            Ok(serde_json::json!({"ok": true}))
        });

        let events: Arc<std::sync::Mutex<Vec<TaskStatusNotificationParams>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender_events = Arc::clone(&events);
        let sender: TaskNotificationSender = Arc::new(move |request| {
            if request.method != "notifications/tasks/status" {
                return;
            }
            let params = request
                .params
                .as_ref()
                .and_then(|value| serde_json::from_value(value.clone()).ok())
                .expect("task status params");
            sender_events
                .lock()
                .expect("events lock poisoned")
                .push(params);
        });
        manager.set_notification_sender(sender);

        let cx = Cx::for_testing();
        let task_id = manager.submit(&cx, "notify_test", None).unwrap();
        manager.start_task(&task_id).unwrap();
        manager.update_progress(&task_id, 0.5, Some("half".to_string()));
        manager.complete_task(&task_id, serde_json::json!({"result": 1}));

        let recorded = events.lock().expect("events lock poisoned").clone();
        assert!(!recorded.is_empty(), "expected task status notifications");
        assert_eq!(recorded[0].id, task_id);
        assert_eq!(recorded[0].status, TaskStatus::Pending);
        assert_eq!(recorded[1].status, TaskStatus::Running);
        assert_eq!(recorded[2].progress, Some(0.5));
        assert_eq!(recorded.last().expect("last").status, TaskStatus::Completed);
    }

    // ── can_transition ─────────────────────────────────────────────────

    #[test]
    fn can_transition_valid_pairs() {
        assert!(can_transition(TaskStatus::Pending, TaskStatus::Running));
        assert!(can_transition(TaskStatus::Pending, TaskStatus::Failed));
        assert!(can_transition(TaskStatus::Pending, TaskStatus::Cancelled));
        assert!(can_transition(TaskStatus::Running, TaskStatus::Completed));
        assert!(can_transition(TaskStatus::Running, TaskStatus::Failed));
        assert!(can_transition(TaskStatus::Running, TaskStatus::Cancelled));
    }

    #[test]
    fn can_transition_invalid_pairs() {
        assert!(!can_transition(TaskStatus::Pending, TaskStatus::Completed));
        assert!(!can_transition(TaskStatus::Completed, TaskStatus::Running));
        assert!(!can_transition(TaskStatus::Completed, TaskStatus::Pending));
        assert!(!can_transition(
            TaskStatus::Completed,
            TaskStatus::Cancelled
        ));
        assert!(!can_transition(TaskStatus::Failed, TaskStatus::Running));
        assert!(!can_transition(TaskStatus::Cancelled, TaskStatus::Running));
    }

    // ── Default / Debug / into_shared ──────────────────────────────────

    #[test]
    fn default_creates_empty_manager() {
        let manager = TaskManager::default();
        assert_eq!(manager.total_count(), 0);
        assert!(!manager.has_list_changed_notifications());
    }

    #[test]
    fn new_for_testing_disables_auto_execute() {
        let manager = TaskManager::new_for_testing();
        assert!(!manager.auto_execute);
    }

    #[test]
    fn into_shared_returns_arc() {
        let manager = TaskManager::new_for_testing();
        let shared: SharedTaskManager = manager.into_shared();
        assert_eq!(shared.total_count(), 0);
    }

    #[test]
    fn debug_output_contains_fields() {
        let manager = TaskManager::new_for_testing();
        let debug = format!("{:?}", manager);
        assert!(debug.contains("TaskManager"));
        assert!(debug.contains("task_count"));
        assert!(debug.contains("handler_count"));
        assert!(debug.contains("task_counter"));
        assert!(debug.contains("list_changed_notifications"));
        assert!(debug.contains("auto_execute"));
    }

    // ── get_info / get_result for nonexistent tasks ────────────────────

    #[test]
    fn get_info_nonexistent_returns_none() {
        let manager = TaskManager::new_for_testing();
        let fake_id = TaskId::from_string("nonexistent".to_string());
        assert!(manager.get_info(&fake_id).is_none());
    }

    #[test]
    fn get_result_nonexistent_returns_none() {
        let manager = TaskManager::new_for_testing();
        let fake_id = TaskId::from_string("nonexistent".to_string());
        assert!(manager.get_result(&fake_id).is_none());
    }

    #[test]
    fn get_result_pending_task_returns_none() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        assert!(manager.get_result(&id).is_none());
    }

    // ── is_cancel_requested edge cases ─────────────────────────────────

    #[test]
    fn is_cancel_requested_nonexistent_returns_false() {
        let manager = TaskManager::new_for_testing();
        let fake_id = TaskId::from_string("nonexistent".to_string());
        assert!(!manager.is_cancel_requested(&fake_id));
    }

    #[test]
    fn is_cancel_requested_before_cancel_returns_false() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        assert!(!manager.is_cancel_requested(&id));
    }

    // ── update_progress edge cases ─────────────────────────────────────

    #[test]
    fn update_progress_on_pending_task_is_ignored() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        // Task is pending, progress update should be ignored
        manager.update_progress(&id, 0.5, Some("test".to_string()));
        let info = manager.get_info(&id).unwrap();
        assert!(info.progress.is_none());
    }

    #[test]
    fn update_progress_on_completed_task_is_ignored() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.complete_task(&id, serde_json::json!({}));
        // Task is completed, progress update should be ignored
        manager.update_progress(&id, 0.1, None);
        let info = manager.get_info(&id).unwrap();
        assert_eq!(info.progress, Some(1.0)); // unchanged from completion
    }

    // ── complete_task / fail_task on nonexistent ────────────────────────

    #[test]
    fn complete_task_nonexistent_does_not_panic() {
        let manager = TaskManager::new_for_testing();
        let fake_id = TaskId::from_string("nonexistent".to_string());
        manager.complete_task(&fake_id, serde_json::json!({})); // should not panic
    }

    #[test]
    fn fail_task_nonexistent_does_not_panic() {
        let manager = TaskManager::new_for_testing();
        let fake_id = TaskId::from_string("nonexistent".to_string());
        manager.fail_task(&fake_id, "error"); // should not panic
    }

    // ── cancel edge cases ──────────────────────────────────────────────

    #[test]
    fn cancel_nonexistent_task_returns_error() {
        let manager = TaskManager::new_for_testing();
        let fake_id = TaskId::from_string("nonexistent".to_string());
        let err = manager.cancel(&fake_id, None).unwrap_err();
        assert!(err.message.contains("not found"));
    }

    #[test]
    fn cancel_pending_task_directly() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        // Cancel from Pending (valid: Pending -> Cancelled)
        let info = manager.cancel(&id, None).unwrap();
        assert_eq!(info.status, TaskStatus::Cancelled);
        assert!(manager.is_cancel_requested(&id));
    }

    #[test]
    fn cancel_with_default_reason() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        let info = manager.cancel(&id, None).unwrap();
        assert_eq!(info.error, Some("Cancelled by request".to_string()));
    }

    // ── task ID sequencing ─────────────────────────────────────────────

    #[test]
    fn task_ids_are_sequential() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id1 = manager.submit(&cx, "t", None).unwrap();
        let id2 = manager.submit(&cx, "t", None).unwrap();
        assert_ne!(id1, id2);
        assert!(id1.0.starts_with("task-"));
        assert!(id2.0.starts_with("task-"));
    }

    // ── start_task edge cases ──────────────────────────────────────────

    #[test]
    fn start_task_nonexistent_returns_error() {
        let manager = TaskManager::new_for_testing();
        let fake_id = TaskId::from_string("nonexistent".to_string());
        let err = manager.start_task(&fake_id).unwrap_err();
        assert!(err.message.contains("not found"));
    }

    #[test]
    fn start_task_already_running_returns_error() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        let err = manager.start_task(&id).unwrap_err();
        assert!(err.message.contains("not pending"));
    }

    // ── cleanup_completed ──────────────────────────────────────────────

    #[test]
    fn cleanup_completed_removes_old_terminal_tasks() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });

        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.complete_task(&id, serde_json::json!({}));
        assert_eq!(manager.total_count(), 1);

        // Cleanup with 0 duration removes all completed tasks
        manager.cleanup_completed(std::time::Duration::from_secs(0));
        assert_eq!(manager.total_count(), 0);
    }

    #[test]
    fn cleanup_completed_keeps_active_tasks() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });

        let id1 = manager.submit(&cx, "t", None).unwrap();
        let id2 = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id1).unwrap();
        manager.complete_task(&id1, serde_json::json!({}));
        // id2 is still pending (active)

        manager.cleanup_completed(std::time::Duration::from_secs(0));
        assert_eq!(manager.total_count(), 1); // only id2 remains
        assert!(manager.get_info(&id2).is_some());
    }

    #[test]
    fn cleanup_completed_keeps_recent_tasks() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });

        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.complete_task(&id, serde_json::json!({}));

        // Cleanup with large duration keeps recently completed
        manager.cleanup_completed(std::time::Duration::from_secs(3600));
        assert_eq!(manager.total_count(), 1);
    }

    // ── identity transition ────────────────────────────────────────────

    #[test]
    fn transition_same_state_returns_true() {
        // Create a minimal TaskState to test transition_state
        let task_id = TaskId::from_string("test".to_string());
        let mut state = TaskState {
            info: TaskInfo {
                id: task_id,
                task_type: "t".to_string(),
                status: TaskStatus::Running,
                progress: None,
                message: None,
                created_at: String::new(),
                started_at: None,
                completed_at: None,
                error: None,
            },
            cancel_requested: false,
            result: None,
            cx: Cx::for_testing(),
        };
        // Same state transition returns true
        assert!(transition_state(&mut state, TaskStatus::Running));
    }

    // ── submit with params ─────────────────────────────────────────────

    #[test]
    fn submit_with_none_params_creates_task() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        let info = manager.get_info(&id).unwrap();
        assert_eq!(info.task_type, "t");
        assert_eq!(info.status, TaskStatus::Pending);
        assert!(info.started_at.is_none());
        assert!(info.completed_at.is_none());
        assert!(info.error.is_none());
    }

    #[test]
    fn submit_with_some_params_creates_task() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager
            .submit(&cx, "t", Some(serde_json::json!({"key": "value"})))
            .unwrap();
        assert!(manager.get_info(&id).is_some());
    }

    // ── fail_task sets result ──────────────────────────────────────────

    #[test]
    fn fail_task_sets_error_result() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.fail_task(&id, "boom");
        let result = manager.get_result(&id).unwrap();
        assert!(!result.success);
        assert_eq!(result.error, Some("boom".to_string()));
        assert!(result.data.is_none());
    }

    // ── update_progress on nonexistent task ──────────────────────────────

    #[test]
    fn update_progress_nonexistent_does_not_panic() {
        let manager = TaskManager::new_for_testing();
        let fake_id = TaskId::from_string("nonexistent".to_string());
        manager.update_progress(&fake_id, 0.5, None); // should not panic
    }

    // ── fail_task on already-terminal task ───────────────────────────────

    #[test]
    fn fail_task_on_completed_is_ignored() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.complete_task(&id, serde_json::json!({"done": true}));
        // Attempt to fail a completed task - should be ignored
        manager.fail_task(&id, "too late");
        let info = manager.get_info(&id).unwrap();
        assert_eq!(info.status, TaskStatus::Completed);
        let result = manager.get_result(&id).unwrap();
        assert!(result.success);
    }

    // ── complete_task on already-terminal task ───────────────────────────

    #[test]
    fn complete_task_on_failed_is_ignored() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.fail_task(&id, "something broke");
        // Attempt to complete a failed task - should be ignored
        manager.complete_task(&id, serde_json::json!({"late": true}));
        let info = manager.get_info(&id).unwrap();
        assert_eq!(info.status, TaskStatus::Failed);
        let result = manager.get_result(&id).unwrap();
        assert!(!result.success);
    }

    // ── register_handler replaces existing handler ──────────────────────

    #[test]
    fn register_handler_replaces_existing() {
        let manager = TaskManager::new_for_testing();
        manager.register_handler("t", |_cx, _params| async {
            Ok(serde_json::json!({"v": 1}))
        });
        manager.register_handler("t", |_cx, _params| async {
            Ok(serde_json::json!({"v": 2}))
        });
        // Should succeed with the new handler
        let cx = Cx::for_testing();
        let id = manager.submit(&cx, "t", None).unwrap();
        assert!(manager.get_info(&id).is_some());
    }

    // ── transition_state timestamps ─────────────────────────────────────

    #[test]
    fn transition_to_running_sets_started_at() {
        let task_id = TaskId::from_string("ts-test".to_string());
        let mut state = TaskState {
            info: TaskInfo {
                id: task_id,
                task_type: "t".to_string(),
                status: TaskStatus::Pending,
                progress: None,
                message: None,
                created_at: String::new(),
                started_at: None,
                completed_at: None,
                error: None,
            },
            cancel_requested: false,
            result: None,
            cx: Cx::for_testing(),
        };
        assert!(state.info.started_at.is_none());
        assert!(transition_state(&mut state, TaskStatus::Running));
        assert!(state.info.started_at.is_some());
    }

    #[test]
    fn transition_to_completed_sets_completed_at() {
        let task_id = TaskId::from_string("ts-test".to_string());
        let mut state = TaskState {
            info: TaskInfo {
                id: task_id,
                task_type: "t".to_string(),
                status: TaskStatus::Running,
                progress: None,
                message: None,
                created_at: String::new(),
                started_at: Some("earlier".to_string()),
                completed_at: None,
                error: None,
            },
            cancel_requested: false,
            result: None,
            cx: Cx::for_testing(),
        };
        assert!(state.info.completed_at.is_none());
        assert!(transition_state(&mut state, TaskStatus::Completed));
        assert!(state.info.completed_at.is_some());
    }

    #[test]
    fn transition_to_failed_sets_completed_at() {
        let task_id = TaskId::from_string("ts-test".to_string());
        let mut state = TaskState {
            info: TaskInfo {
                id: task_id,
                task_type: "t".to_string(),
                status: TaskStatus::Running,
                progress: None,
                message: None,
                created_at: String::new(),
                started_at: Some("earlier".to_string()),
                completed_at: None,
                error: None,
            },
            cancel_requested: false,
            result: None,
            cx: Cx::for_testing(),
        };
        assert!(transition_state(&mut state, TaskStatus::Failed));
        assert!(state.info.completed_at.is_some());
    }

    #[test]
    fn transition_to_cancelled_sets_completed_at() {
        let task_id = TaskId::from_string("ts-test".to_string());
        let mut state = TaskState {
            info: TaskInfo {
                id: task_id,
                task_type: "t".to_string(),
                status: TaskStatus::Running,
                progress: None,
                message: None,
                created_at: String::new(),
                started_at: Some("earlier".to_string()),
                completed_at: None,
                error: None,
            },
            cancel_requested: false,
            result: None,
            cx: Cx::for_testing(),
        };
        assert!(transition_state(&mut state, TaskStatus::Cancelled));
        assert!(state.info.completed_at.is_some());
    }

    #[test]
    fn transition_invalid_returns_false() {
        let task_id = TaskId::from_string("ts-test".to_string());
        let mut state = TaskState {
            info: TaskInfo {
                id: task_id,
                task_type: "t".to_string(),
                status: TaskStatus::Pending,
                progress: None,
                message: None,
                created_at: String::new(),
                started_at: None,
                completed_at: None,
                error: None,
            },
            cancel_requested: false,
            result: None,
            cx: Cx::for_testing(),
        };
        // Pending -> Completed is invalid
        assert!(!transition_state(&mut state, TaskStatus::Completed));
        // State should remain Pending
        assert_eq!(state.info.status, TaskStatus::Pending);
    }

    // ── TaskStatusSnapshot ──────────────────────────────────────────────

    #[test]
    fn task_status_snapshot_debug_and_clone() {
        let task_id = TaskId::from_string("snap-test".to_string());
        let state = TaskState {
            info: TaskInfo {
                id: task_id,
                task_type: "t".to_string(),
                status: TaskStatus::Running,
                progress: Some(0.5),
                message: Some("testing".to_string()),
                created_at: "now".to_string(),
                started_at: Some("now".to_string()),
                completed_at: None,
                error: None,
            },
            cancel_requested: false,
            result: None,
            cx: Cx::for_testing(),
        };
        let snapshot = TaskStatusSnapshot::from(&state);
        let debug = format!("{:?}", snapshot);
        assert!(debug.contains("TaskStatusSnapshot"));
        let cloned = snapshot.clone();
        assert_eq!(cloned.info.status, TaskStatus::Running);
        assert!(cloned.result.is_none());
    }

    // ── cleanup with failed/cancelled tasks ─────────────────────────────

    #[test]
    fn cleanup_completed_removes_failed_and_cancelled() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });

        let id1 = manager.submit(&cx, "t", None).unwrap();
        let id2 = manager.submit(&cx, "t", None).unwrap();
        let id3 = manager.submit(&cx, "t", None).unwrap();

        // Complete one
        manager.start_task(&id1).unwrap();
        manager.complete_task(&id1, serde_json::json!({}));

        // Fail one
        manager.start_task(&id2).unwrap();
        manager.fail_task(&id2, "error");

        // Cancel one
        manager.cancel(&id3, None).unwrap();

        assert_eq!(manager.total_count(), 3);

        // Cleanup with 0 duration should remove all terminal tasks
        manager.cleanup_completed(std::time::Duration::from_secs(0));
        assert_eq!(manager.total_count(), 0);
    }

    // ── set_notification_sender replaces sender ─────────────────────────

    #[test]
    fn set_notification_sender_replaces_existing() {
        let manager = TaskManager::new_for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });

        let count1 = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count2 = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let c1 = Arc::clone(&count1);
        let sender1: TaskNotificationSender = Arc::new(move |_| {
            c1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        manager.set_notification_sender(sender1);

        let cx = Cx::for_testing();
        let _id1 = manager.submit(&cx, "t", None).unwrap();
        assert!(count1.load(std::sync::atomic::Ordering::SeqCst) > 0);

        // Replace sender
        let c2 = Arc::clone(&count2);
        let sender2: TaskNotificationSender = Arc::new(move |_| {
            c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        manager.set_notification_sender(sender2);

        let _id2 = manager.submit(&cx, "t", None).unwrap();
        assert!(count2.load(std::sync::atomic::Ordering::SeqCst) > 0);
    }

    // ── cancel with custom reason ───────────────────────────────────────

    #[test]
    fn cancel_with_custom_reason() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        let info = manager.cancel(&id, Some("Timeout".to_string())).unwrap();
        assert_eq!(info.error, Some("Timeout".to_string()));
        let result = manager.get_result(&id).unwrap();
        assert_eq!(result.error, Some("Timeout".to_string()));
    }

    // ── can_transition self-transitions ──────────────────────────────────

    #[test]
    fn can_transition_self_is_false() {
        // Self-transitions are not in the match arms, so can_transition returns false,
        // but transition_state handles identity specially (returns true without changing state).
        assert!(!can_transition(TaskStatus::Pending, TaskStatus::Pending));
        assert!(!can_transition(TaskStatus::Running, TaskStatus::Running));
        assert!(!can_transition(
            TaskStatus::Completed,
            TaskStatus::Completed
        ));
        assert!(!can_transition(TaskStatus::Failed, TaskStatus::Failed));
        assert!(!can_transition(
            TaskStatus::Cancelled,
            TaskStatus::Cancelled
        ));
    }

    // ── transition_state with Pending -> Pending (identity) ─────────────

    #[test]
    fn transition_state_identity_pending_returns_true() {
        let task_id = TaskId::from_string("identity-test".to_string());
        let mut state = TaskState {
            info: TaskInfo {
                id: task_id,
                task_type: "t".to_string(),
                status: TaskStatus::Pending,
                progress: None,
                message: None,
                created_at: String::new(),
                started_at: None,
                completed_at: None,
                error: None,
            },
            cancel_requested: false,
            result: None,
            cx: Cx::for_testing(),
        };
        assert!(transition_state(&mut state, TaskStatus::Pending));
        assert_eq!(state.info.status, TaskStatus::Pending);
    }

    // ── list_tasks with no filter ───────────────────────────────────────

    #[test]
    fn list_tasks_no_filter_returns_all() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id1 = manager.submit(&cx, "t", None).unwrap();
        let _id2 = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id1).unwrap();
        manager.complete_task(&id1, serde_json::json!({}));
        // id1 is Completed, id2 is Pending
        let all = manager.list_tasks(None);
        assert_eq!(all.len(), 2);
    }

    // ── notification sender status content ──────────────────────────────

    #[test]
    fn cancel_notification_includes_error_and_result() {
        let manager = TaskManager::new_for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });

        let events: Arc<std::sync::Mutex<Vec<TaskStatusNotificationParams>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender_events = Arc::clone(&events);
        let sender: TaskNotificationSender = Arc::new(move |request| {
            if request.method == "notifications/tasks/status" {
                let params: TaskStatusNotificationParams = request
                    .params
                    .as_ref()
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap();
                sender_events.lock().unwrap().push(params);
            }
        });
        manager.set_notification_sender(sender);

        let cx = Cx::for_testing();
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.cancel(&id, Some("user abort".to_string())).unwrap();

        let recorded = events.lock().unwrap().clone();
        // Last notification should be the cancellation
        let last = recorded.last().unwrap();
        assert_eq!(last.status, TaskStatus::Cancelled);
        assert_eq!(last.error, Some("user abort".to_string()));
        assert!(last.result.is_some());
        let result = last.result.as_ref().unwrap();
        assert!(!result.success);
    }

    // ── complete sets progress to 1.0 ───────────────────────────────────

    #[test]
    fn complete_task_sets_progress_to_one() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.update_progress(&id, 0.5, None);
        manager.complete_task(&id, serde_json::json!({}));
        let info = manager.get_info(&id).unwrap();
        assert_eq!(info.progress, Some(1.0));
    }

    // ── cleanup_completed — edge cases ─────────────────────────────────

    #[test]
    fn cleanup_completed_keeps_terminal_without_completed_at() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.complete_task(&id, serde_json::json!({}));

        // Manually remove completed_at to simulate edge case
        {
            let mut tasks = manager.tasks.write().unwrap();
            tasks.get_mut(&id).unwrap().info.completed_at = None;
        }

        // Cleanup should keep the task (no completed_at → can't determine age)
        manager.cleanup_completed(std::time::Duration::from_secs(0));
        assert_eq!(manager.total_count(), 1);
    }

    #[test]
    fn cleanup_completed_keeps_terminal_with_unparseable_timestamp() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.complete_task(&id, serde_json::json!({}));

        // Set completed_at to unparseable value
        {
            let mut tasks = manager.tasks.write().unwrap();
            tasks.get_mut(&id).unwrap().info.completed_at = Some("not-a-date".to_string());
        }

        manager.cleanup_completed(std::time::Duration::from_secs(0));
        assert_eq!(manager.total_count(), 1);
    }

    // ── Debug with populated state ──────────────────────────────────────

    #[test]
    fn debug_output_with_tasks_and_handlers() {
        let manager = TaskManager::new_for_testing();
        manager.register_handler("type_a", |_cx, _params| async { Ok(serde_json::json!({})) });
        manager.register_handler("type_b", |_cx, _params| async { Ok(serde_json::json!({})) });
        let cx = Cx::for_testing();
        let _ = manager.submit(&cx, "type_a", None).unwrap();
        let _ = manager.submit(&cx, "type_b", None).unwrap();

        let debug = format!("{:?}", manager);
        assert!(debug.contains("task_count: 2"));
        assert!(debug.contains("handler_count: 2"));
    }

    // ── Multiple handler types ──────────────────────────────────────────

    #[test]
    fn multiple_handler_types_independent() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("analyze", |_cx, _params| async {
            Ok(serde_json::json!({"type": "analyze"}))
        });
        manager.register_handler("summarize", |_cx, _params| async {
            Ok(serde_json::json!({"type": "summarize"}))
        });

        let id_a = manager.submit(&cx, "analyze", None).unwrap();
        let id_s = manager.submit(&cx, "summarize", None).unwrap();

        let info_a = manager.get_info(&id_a).unwrap();
        let info_s = manager.get_info(&id_s).unwrap();
        assert_eq!(info_a.task_type, "analyze");
        assert_eq!(info_s.task_type, "summarize");
    }

    // ── list_tasks filters for all terminal statuses ────────────────────

    #[test]
    fn list_tasks_filter_failed() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });

        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.fail_task(&id, "err");

        assert_eq!(manager.list_tasks(Some(TaskStatus::Failed)).len(), 1);
        assert_eq!(manager.list_tasks(Some(TaskStatus::Completed)).len(), 0);
    }

    #[test]
    fn list_tasks_filter_cancelled() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });

        let id = manager.submit(&cx, "t", None).unwrap();
        manager.cancel(&id, None).unwrap();

        assert_eq!(manager.list_tasks(Some(TaskStatus::Cancelled)).len(), 1);
        assert_eq!(manager.list_tasks(Some(TaskStatus::Pending)).len(), 0);
    }

    // ── notification content for progress ────────────────────────────────

    #[test]
    fn progress_notification_includes_message() {
        let manager = TaskManager::new_for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });

        let events: Arc<std::sync::Mutex<Vec<TaskStatusNotificationParams>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender_events = Arc::clone(&events);
        let sender: TaskNotificationSender = Arc::new(move |request| {
            if request.method == "notifications/tasks/status" {
                let params: TaskStatusNotificationParams = request
                    .params
                    .as_ref()
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap();
                sender_events.lock().unwrap().push(params);
            }
        });
        manager.set_notification_sender(sender);

        let cx = Cx::for_testing();
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.update_progress(&id, 0.75, Some("three quarters".to_string()));

        let recorded = events.lock().unwrap().clone();
        let progress_event = recorded
            .iter()
            .find(|e| e.progress == Some(0.75))
            .expect("progress notification");
        assert_eq!(progress_event.message, Some("three quarters".to_string()));
        assert_eq!(progress_event.status, TaskStatus::Running);
    }

    // ── TaskStatusSnapshot with result ────────────────────────────────────

    #[test]
    fn task_status_snapshot_includes_result() {
        let task_id = TaskId::from_string("snap-result");
        let state = TaskState {
            info: TaskInfo {
                id: task_id.clone(),
                task_type: "t".to_string(),
                status: TaskStatus::Completed,
                progress: Some(1.0),
                message: None,
                created_at: "now".to_string(),
                started_at: Some("now".to_string()),
                completed_at: Some("now".to_string()),
                error: None,
            },
            cancel_requested: false,
            result: Some(TaskResult {
                id: task_id,
                success: true,
                data: Some(serde_json::json!({"done": true})),
                error: None,
            }),
            cx: Cx::for_testing(),
        };
        let snapshot = TaskStatusSnapshot::from(&state);
        assert!(snapshot.result.is_some());
        let result = snapshot.result.unwrap();
        assert!(result.success);
        assert_eq!(result.data, Some(serde_json::json!({"done": true})));
    }

    // ── submit error message ──────────────────────────────────────────────

    #[test]
    fn submit_unknown_task_type_error_message() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        let err = manager.submit(&cx, "nonexistent_type", None).unwrap_err();
        assert!(err.message.contains("Unknown task type"));
        assert!(err.message.contains("nonexistent_type"));
    }

    // ── cancel result data ───────────────────────────────────────────────

    #[test]
    fn cancel_result_has_no_data() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.cancel(&id, Some("abort".to_string())).unwrap();
        let result = manager.get_result(&id).unwrap();
        assert!(!result.success);
        assert!(result.data.is_none());
        assert_eq!(result.error, Some("abort".to_string()));
    }

    // ── Additional coverage — uncovered terminal-state cancel paths ──

    #[test]
    fn cancel_completed_task_returns_error() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.complete_task(&id, serde_json::json!({}));
        let err = manager.cancel(&id, None).unwrap_err();
        assert!(err.message.contains("terminal"));
    }

    #[test]
    fn cancel_failed_task_returns_error() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.fail_task(&id, "broke");
        let err = manager.cancel(&id, None).unwrap_err();
        assert!(err.message.contains("terminal"));
    }

    #[test]
    fn fail_task_on_pending_records_failure() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.fail_task(&id, "too early");
        let info = manager.get_info(&id).unwrap();
        assert_eq!(info.status, TaskStatus::Failed);
        assert_eq!(info.error.as_deref(), Some("too early"));
        assert!(info.completed_at.is_some());

        let result = manager
            .get_result(&id)
            .expect("failed task should record a result");
        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("too early"));
    }

    #[test]
    fn spawn_task_skips_handler_for_pre_failed_pending_task() {
        let manager = TaskManager::new();
        let task_runs = Arc::new(AtomicU64::new(0));
        let task_type = "never-run".to_string();
        let task_id = TaskId::from_string("task-prefailed");
        let task_cx = Cx::for_request_with_budget(Budget::INFINITE);
        let now = chrono::Utc::now().to_rfc3339();

        manager.register_handler(task_type.clone(), {
            let task_runs = Arc::clone(&task_runs);
            move |_cx, _params| {
                let task_runs = Arc::clone(&task_runs);
                async move {
                    task_runs.fetch_add(1, Ordering::SeqCst);
                    Ok(serde_json::json!({"unexpected": true}))
                }
            }
        });

        {
            let mut tasks = manager.tasks.write().unwrap_or_else(|poisoned| {
                warn!(target: targets::SERVER, "tasks lock poisoned in test, recovering");
                poisoned.into_inner()
            });
            tasks.insert(
                task_id.clone(),
                TaskState {
                    info: TaskInfo {
                        id: task_id.clone(),
                        task_type: task_type.clone(),
                        status: TaskStatus::Failed,
                        progress: None,
                        message: None,
                        created_at: now,
                        started_at: None,
                        completed_at: Some(chrono::Utc::now().to_rfc3339()),
                        error: Some("prefailed".to_string()),
                    },
                    cancel_requested: false,
                    result: Some(TaskResult {
                        id: task_id.clone(),
                        success: false,
                        data: None,
                        error: Some("prefailed".to_string()),
                    }),
                    cx: task_cx.clone(),
                },
            );
        }

        manager.spawn_task(task_id.clone(), task_type, task_cx, serde_json::json!({}));

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while std::time::Instant::now() < deadline {
            if task_runs.load(Ordering::SeqCst) > 0 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(
            task_runs.load(Ordering::SeqCst),
            0,
            "pre-failed pending task must not execute its handler"
        );

        let info = manager
            .get_info(&task_id)
            .expect("prefailed task should remain present");
        assert_eq!(info.status, TaskStatus::Failed);
        assert_eq!(info.error.as_deref(), Some("prefailed"));
    }

    #[test]
    fn complete_task_on_cancelled_is_ignored() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.cancel(&id, Some("aborted".to_string())).unwrap();
        // Cancelled -> Completed is not valid
        manager.complete_task(&id, serde_json::json!({"late": true}));
        let info = manager.get_info(&id).unwrap();
        assert_eq!(info.status, TaskStatus::Cancelled);
    }

    #[test]
    fn update_progress_none_message_clears_previous() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.update_progress(&id, 0.3, Some("step 1".to_string()));
        assert_eq!(
            manager.get_info(&id).unwrap().message,
            Some("step 1".to_string())
        );
        manager.update_progress(&id, 0.6, None);
        assert!(manager.get_info(&id).unwrap().message.is_none());
    }

    #[test]
    fn no_notification_sender_does_not_panic() {
        let manager = TaskManager::new_for_testing();
        let cx = Cx::for_testing();
        manager.register_handler("t", |_cx, _params| async { Ok(serde_json::json!({})) });
        // No notification sender set — all operations should still work
        let id = manager.submit(&cx, "t", None).unwrap();
        manager.start_task(&id).unwrap();
        manager.update_progress(&id, 0.5, None);
        manager.complete_task(&id, serde_json::json!({}));
        assert_eq!(manager.get_info(&id).unwrap().status, TaskStatus::Completed);
    }

    fn official_task_lifecycle() -> OfficialTaskLifecycle {
        OfficialTaskLifecycle::new(
            OfficialTaskLifecycleConfig::new(60_000, Some(5_000), 8)
                .expect("valid bounded lifecycle configuration"),
        )
    }

    fn task_input_request() -> OfficialTaskInputRequest {
        OfficialTaskInputRequest {
            method: OfficialTaskInputMethod::ElicitationCreate,
            params: serde_json::json!({"message": "Approve the operation?"}),
        }
    }

    fn final_tool_result() -> serde_json::Value {
        serde_json::json!({
            "resultType": "complete",
            "content": [{"type": "text", "text": "done"}],
        })
    }

    #[test]
    fn task_02_a_positive() {
        let lifecycle = official_task_lifecycle();
        assert_eq!(lifecycle.storage_kind(), TaskStorageKind::ProcessLocal);

        let created = lifecycle
            .create(None)
            .expect("create immediately readable task");
        assert_eq!(created.status, OfficialTaskStatus::Working);
        assert_eq!(created.ttl_ms, 60_000);
        assert_eq!(created.poll_interval_ms, Some(5_000));
        assert_eq!(created.task_id.as_str().len(), 43);
        assert!(
            created
                .task_id
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "local task IDs must use canonical unpadded base64url"
        );
        assert_eq!(
            lifecycle
                .get(&created.task_id)
                .expect("created task lookup"),
            created
        );

        let mut requests = BTreeMap::new();
        requests.insert("approval".to_string(), task_input_request());
        requests.insert("details".to_string(), task_input_request());
        let waiting = lifecycle
            .require_input(&created.task_id, requests, None)
            .expect("working task enters input_required");
        assert_eq!(waiting.status, OfficialTaskStatus::InputRequired);
        assert_eq!(waiting.input_requests.as_ref().map(BTreeMap::len), Some(2));

        let mut first_response = BTreeMap::new();
        first_response.insert(
            "approval".to_string(),
            serde_json::json!({"approved": true}),
        );
        assert_eq!(
            lifecycle
                .update_input(&created.task_id, first_response)
                .expect("partial update"),
            OfficialTaskInputUpdate::Applied
        );
        let partially_satisfied = lifecycle.get(&created.task_id).expect("task lookup");
        assert_eq!(
            partially_satisfied.status,
            OfficialTaskStatus::InputRequired
        );
        assert_eq!(
            partially_satisfied
                .input_requests
                .as_ref()
                .map(BTreeMap::len),
            Some(1)
        );

        let mut final_response = BTreeMap::new();
        final_response.insert("details".to_string(), serde_json::json!({"accepted": true}));
        assert_eq!(
            lifecycle
                .update_input(&created.task_id, final_response)
                .expect("final input update"),
            OfficialTaskInputUpdate::Applied
        );
        assert_eq!(
            lifecycle
                .get(&created.task_id)
                .expect("resumed task")
                .status,
            OfficialTaskStatus::Working
        );

        let completed = lifecycle
            .complete(
                &created.task_id,
                final_tool_result(),
                Some("Completed".to_string()),
            )
            .expect("complete after all input is satisfied");
        assert_eq!(completed.status, OfficialTaskStatus::Completed);
        assert_eq!(completed.result, Some(final_tool_result()));
        assert!(completed.input_requests.is_none());
        assert!(completed.error.is_none());

        let failed = lifecycle.create(None).expect("create task to fail");
        let failed = lifecycle
            .fail(
                &failed.task_id,
                serde_json::json!({"code": -32603, "message": "Execution failed"}),
                None,
            )
            .expect("working task records a JSON-RPC failure");
        assert_eq!(failed.status, OfficialTaskStatus::Failed);
        assert_eq!(
            failed.status_message.as_deref(),
            Some("Task execution failed"),
            "the safe failure message is not copied from raw error data"
        );
        assert!(failed.result.is_none());
        assert!(failed.error.is_some());

        let cancelled = lifecycle.create(None).expect("create task to cancel");
        lifecycle
            .request_cancellation(&cancelled.task_id)
            .expect("cooperative cancellation acknowledgement");
        assert!(lifecycle.is_cancellation_requested(&cancelled.task_id));
        let cancelled = lifecycle
            .honor_cancellation(&cancelled.task_id, Some("Cancelled".to_string()))
            .expect("supervised worker honors cancellation");
        assert_eq!(cancelled.status, OfficialTaskStatus::Cancelled);
        assert!(
            lifecycle
                .complete(&cancelled.task_id, final_tool_result(), None)
                .is_err(),
            "terminal task states are immutable"
        );
        assert_eq!(
            lifecycle
                .get(&cancelled.task_id)
                .expect("cancelled task lookup")
                .status,
            OfficialTaskStatus::Cancelled
        );
    }

    #[test]
    fn task_02_a_planted_negative() {
        let lifecycle = official_task_lifecycle();
        let created = lifecycle.create(None).expect("create task");
        let mut requests = BTreeMap::new();
        requests.insert("approval".to_string(), task_input_request());
        requests.insert("details".to_string(), task_input_request());
        lifecycle
            .require_input(&created.task_id, requests, None)
            .expect("task awaits the same inputs as the positive case");
        let before = serde_json::to_vec(
            &lifecycle
                .get(&created.task_id)
                .expect("task snapshot before planted input"),
        )
        .expect("serialize stable snapshot");

        // The only changed dimension from the accepted update is the request
        // key: this key was never issued and must be a no-op.
        let mut planted_unknown_response = BTreeMap::new();
        planted_unknown_response.insert(
            "not-approval".to_string(),
            serde_json::json!({"approved": true}),
        );
        assert_eq!(
            lifecycle
                .update_input(&created.task_id, planted_unknown_response)
                .expect("known task ignores an unknown input key"),
            OfficialTaskInputUpdate::Ignored
        );
        let after = serde_json::to_vec(
            &lifecycle
                .get(&created.task_id)
                .expect("task snapshot after planted input"),
        )
        .expect("serialize stable snapshot");

        assert_eq!(after, before, "unknown input must not mutate task state");
        assert_eq!(
            lifecycle
                .get(&created.task_id)
                .expect("task remains readable")
                .status,
            OfficialTaskStatus::InputRequired
        );
    }
}
