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
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicU64, Ordering as TaskServiceOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;

#[cfg(test)]
use asupersync::Budget;
#[cfg(test)]
use asupersync::CancelKind;
use asupersync::Cx;
use asupersync::channel::mpsc::{self, Receiver, Sender};
#[cfg(test)]
use asupersync::runtime::{RuntimeBuilder, RuntimeHandle};
use base64::Engine as _;
#[cfg(test)]
use fastmcp_core::logging::{debug, info, targets, warn};
use fastmcp_core::{McpError, McpResult, draw_security_identifier};
use fastmcp_protocol::tasks_extension::TaskStatusNotificationParams as FinalTaskStatusNotificationParams;
use fastmcp_protocol::{
    CreateTaskResult, FINAL_PROTOCOL_VERSION, FinalCancelTaskParams, FinalCancelTaskResult,
    FinalGetTaskParams, FinalGetTaskResult, FinalTaskCallToolResult, FinalTaskError, FinalTaskId,
    FinalTaskStatus, Task as FinalTask, TaskBase as FinalTaskBase,
    TaskDuration as FinalTaskDuration, TaskInputLedger as FinalTaskInputLedger,
    TaskInputRequests as FinalTaskInputRequests, TaskInputResponses as FinalTaskInputResponses,
    TaskRequestMeta as FinalTaskRequestMeta, TaskStatusNotification as FinalTaskStatusNotification,
    TaskTimestamp as FinalTaskTimestamp, UpdateTaskParams, UpdateTaskResult,
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
/// transport reconnect cannot erase an accepted task transition. Every write
/// must retain a status-shaped task, a notification containing that exact task,
/// and the immutable task identity and retention fields from its prior
/// generation. Atomic operations returning `false` must leave all of those
/// retained values unchanged.
pub trait FinalTaskStore: Send + Sync {
    /// Durably records a newly created task and its status notification.
    fn create_task(
        &self,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> McpResult<()>;

    /// Durably creates a task, its status notification, and the opaque
    /// application work that must begin from its initial `working` state.
    ///
    /// The task must not be advertised until all three values are durable.
    /// Older stores fail closed rather than creating unexecutable work.
    fn create_task_with_work(
        &self,
        _task: FinalTask,
        _notification: FinalTaskStatusNotification,
        _work_descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<()> {
        Err(McpError::internal_error(
            "Final task store does not implement atomic task-work creation",
        ))
    }

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

    /// Atomically compares the current generation, replaces the task and its
    /// notification, and appends validated input to the private worker
    /// handoff. No task, notification, generation, or handoff state may change
    /// when the comparison fails.
    ///
    /// Stores written before this operation was added fail closed by default;
    /// accepting an update while discarding its input is never a valid
    /// compatibility fallback.
    fn replace_task_and_append_input_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
        _task: FinalTask,
        _notification: FinalTaskStatusNotification,
        _input_responses: FinalTaskInputResponses,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Final task store does not implement atomic task-input append",
        ))
    }

    /// Atomically compares the current generation, replaces the task and its
    /// notification, and clears every unconsumed input from an earlier input
    /// cycle. This operation is required when entering `input_required` and
    /// when committing a terminal state.
    fn replace_task_and_clear_input_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
        _task: FinalTask,
        _notification: FinalTaskStatusNotification,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Final task store does not implement atomic task-input clearing",
        ))
    }

    /// Atomically commits one application-owned handoff transition only when
    /// the exact elected owner, generation, and dispatch fence remain live.
    ///
    /// `cancellation_required` selects the only two valid cancellation
    /// dispositions. Normal completion, failure, and input-required
    /// transitions require that cancellation has not won. A cancellation
    /// terminal transition requires that cancellation intent has won. The
    /// check and replacement share one durable linearization point, so a
    /// former worker cannot mutate a task after its lease is reclaimed.
    fn replace_task_and_clear_input_for_handoff_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
        _owner_id: &str,
        _dispatch_fence: u64,
        _cancellation_required: bool,
        _task: FinalTask,
        _notification: FinalTaskStatusNotification,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Final task store does not implement fenced handoff transitions",
        ))
    }

    /// Legacy raw accepted-input claim.
    ///
    /// New task-service code must use
    /// [`Self::take_input_handoff_for_owner_if_current`], which binds the
    /// claim to a service owner before it can reach application code.
    fn take_input_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskInputResponses>> {
        Err(McpError::internal_error(
            "Final task store does not implement atomic task-input consumption",
        ))
    }

    /// Atomically leases the private accepted-input handoff to one service
    /// owner only when the store still contains the exact supplied generation
    /// in `working` state.
    ///
    /// The payload must remain durably recoverable until the matching dispatch
    /// finishes, a newer transition wins, cancellation wins, or the finite
    /// pre-dispatch recovery claim expires. Dispatch election upgrades that
    /// claim to exclusive owned fencing until finish or restoration. A stale
    /// generation, a non-working state, or an already-leased handoff returns
    /// `None` without delivering application work.
    fn take_input_for_owner_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
        _owner_id: &str,
    ) -> McpResult<Option<FinalTaskInputResponses>> {
        Err(McpError::internal_error(
            "Final task store does not implement atomic task-input consumption",
        ))
    }

    /// Reads the immutable operation descriptor only if `expected` still
    /// names the exact live task generation.
    fn work_descriptor_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskWorkDescriptor>> {
        Err(McpError::internal_error(
            "Final task store does not implement task-work lookup",
        ))
    }

    /// Atomically claims the complete accepted-input handoff and attests its
    /// task, generation, and owner binding. Existing stores may derive this
    /// from the established claim methods, but durable stores must preserve
    /// the same association atomically.
    fn take_input_handoff_for_owner_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
    ) -> McpResult<Option<FinalTaskAcceptedInputClaim>> {
        let Some(work_descriptor) = self.work_descriptor_if_current(expected)? else {
            return Ok(None);
        };
        let Some(input_responses) = self.take_input_for_owner_if_current(expected, owner_id)?
        else {
            return Ok(None);
        };
        Ok(Some(FinalTaskAcceptedInputClaim::new(
            expected.task().base().task_id.clone(),
            expected.generation(),
            owner_id,
            work_descriptor,
            input_responses,
        )))
    }

    /// Returns one `working` task whose initial application work has not yet
    /// been claimed by a supervisor, continuing after `after_task_id` and
    /// wrapping to the beginning when necessary.
    ///
    /// The cursor is part of the durable recovery contract: it prevents a
    /// permanently retryable low-sort-key task from starving later work.
    fn next_initial_work_snapshot(&self) -> McpResult<Option<FinalTaskSnapshot>> {
        Err(McpError::internal_error(
            "Final task store does not implement initial-work recovery",
        ))
    }

    /// Cursor-based initial-work recovery. Implementations must continue
    /// after `after_task_id` and wrap to the beginning when necessary.
    fn next_initial_work_snapshot_after(
        &self,
        _after_task_id: Option<&FinalTaskId>,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        Err(McpError::internal_error(
            "Final task store does not implement initial-work recovery",
        ))
    }

    /// Atomically leases the initial operation descriptor to one service
    /// owner for `expected`.
    ///
    /// The descriptor must remain durably recoverable until the matching
    /// dispatch finishes, a newer transition wins, cancellation wins, or the
    /// finite pre-dispatch recovery claim expires. Dispatch election upgrades
    /// that claim to exclusive owned fencing until finish or restoration.
    /// Cancellation, terminal, stale, or previously leased tasks return
    /// `None` without delivering application work.
    fn take_initial_work_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskWorkDescriptor>> {
        Err(McpError::internal_error(
            "Final task store does not implement initial-work claiming",
        ))
    }

    /// Owner-bound initial-work claim used exclusively by the authorized
    /// runner.
    fn take_initial_work_for_owner_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
        _owner_id: &str,
    ) -> McpResult<Option<FinalTaskWorkDescriptor>> {
        Err(McpError::internal_error(
            "Final task store does not implement initial-work claiming",
        ))
    }

    /// Atomically claims initial work and attests its task, generation, and
    /// owner binding before the runtime can pass it to application code.
    fn take_initial_work_handoff_for_owner_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
    ) -> McpResult<Option<FinalTaskInitialWorkClaim>> {
        Ok(self
            .take_initial_work_for_owner_if_current(expected, owner_id)?
            .map(|work_descriptor| {
                FinalTaskInitialWorkClaim::new(
                    expected.task().base().task_id.clone(),
                    expected.generation(),
                    owner_id,
                    work_descriptor,
                )
            }))
    }

    /// Releases an initial-work recovery lease after a supervisor did not
    /// successfully accept it. Only the exact original uncancelled `working`
    /// generation may become recoverable again.
    ///
    /// If cancellation has won an elected handoff, implementations must
    /// either atomically record the terminal cancellation or retain the exact
    /// elected fence for the runner to do so. They must never release the last
    /// owner fence while leaving a `working` task with cancellation intent.
    fn restore_initial_work_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
        _work_descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Final task store does not implement initial-work restoration",
        ))
    }

    /// Owner- and fence-bound initial-work restoration used by the execution
    /// guard. See [`Self::restore_initial_work_if_current`] for the required
    /// cancellation-retirement invariant.
    fn restore_initial_work_for_owner_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
        _owner_id: &str,
        _dispatch_fence: Option<u64>,
        _work_descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Final task store does not implement initial-work restoration",
        ))
    }

    /// Returns one current `working` task with an unconsumed accepted-input
    /// handoff without consuming that handoff, continuing after
    /// `after_task_id` and wrapping to the beginning when necessary.
    ///
    /// The returned snapshot is only a compare-and-swap candidate. A service
    /// must still call [`Self::take_input_for_owner_if_current`] before
    /// delivering any input to application code, so a concurrent terminal
    /// transition or another service generation wins without replaying the
    /// handoff.
    ///
    /// Stores that cannot enumerate their durable accepted-input handoffs fail
    /// closed. A service runner must never claim restart recovery merely
    /// because ordinary `get_task` is available.
    fn next_accepted_input_snapshot(&self) -> McpResult<Option<FinalTaskSnapshot>> {
        Err(McpError::internal_error(
            "Final task store does not implement accepted-input recovery",
        ))
    }

    /// Cursor-based accepted-input recovery. Implementations must continue
    /// after `after_task_id` and wrap to the beginning when necessary.
    fn next_accepted_input_snapshot_after(
        &self,
        _after_task_id: Option<&FinalTaskId>,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        Err(McpError::internal_error(
            "Final task store does not implement accepted-input recovery",
        ))
    }

    /// Releases an accepted-input recovery lease after a supervisor returns
    /// an error. Only the exact uncancelled working generation may become
    /// recoverable again.
    ///
    /// This preserves at-least-once recovery semantics for the handoff rather
    /// than silently dropping it when a caller-owned service generation exits.
    /// A `false` result means cancellation or a newer durable transition won
    /// and the input must not be made available in that state. If cancellation
    /// won an elected handoff, implementations must atomically terminalize it
    /// or retain the elected fence for the runner's terminal cancellation.
    fn restore_input_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
        _input_responses: FinalTaskInputResponses,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Final task store does not implement accepted-input restoration",
        ))
    }

    /// Owner- and fence-bound accepted-input restoration used by the
    /// execution guard. See [`Self::restore_input_if_current`] for the
    /// required cancellation-retirement invariant.
    fn restore_input_for_owner_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
        _owner_id: &str,
        _dispatch_fence: Option<u64>,
        _input_responses: FinalTaskInputResponses,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Final task store does not implement accepted-input restoration",
        ))
    }

    /// Atomically elects a claimed handoff to begin application execution.
    ///
    /// The election is the linearization point between cancellation and
    /// invocation: a cancellation that commits first makes this return
    /// `false`; an elected handoff is logically running before this method
    /// returns, so a later cancellation cannot interpose between a separate
    /// preflight check and the application call. The matching
    /// [`Self::finish_handoff_dispatch_for_owner_if_current`] or restoration
    /// operation releases the owner-held dispatch fence. The returned
    /// monotonically increasing fence identifies this exact election. Before
    /// and after election the durable lease must expire unless renewed; expiry
    /// fences the former owner before a restarted service can take over. If
    /// cancellation intent exists at expiry, a store must atomically terminalize
    /// that task or retain its exact retirement fence; it must never release
    /// the final owner and leave `working` plus cancellation intent.
    fn begin_handoff_dispatch_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Final task store does not implement atomic handoff dispatch election",
        ))
    }

    /// Owner-bound dispatch election returning the store-issued fencing token.
    fn begin_handoff_dispatch_for_owner_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
        _owner_id: &str,
    ) -> McpResult<Option<u64>> {
        Err(McpError::internal_error(
            "Final task store does not implement atomic handoff dispatch election",
        ))
    }

    /// Extends the exact elected dispatch lease. A false result means expiry,
    /// cancellation, a newer task generation, or a newer owner won first;
    /// callers must stop using the handoff immediately.
    fn renew_handoff_dispatch_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
        _owner_id: &str,
        _dispatch_fence: u64,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Final task store does not implement durable handoff lease renewal",
        ))
    }

    /// Returns a positive interval strictly shorter than the store's elected
    /// dispatch lease. The runner renews at this cadence while application
    /// work is pending, so a durable store can safely reclaim only a crashed
    /// or partitioned owner after its own lease expires.
    fn handoff_dispatch_lease_heartbeat_interval(&self) -> McpResult<StdDuration> {
        Err(McpError::internal_error(
            "Final task store does not disclose a durable handoff lease heartbeat interval",
        ))
    }

    /// Releases a successfully completed durable dispatch lease. A `false`
    /// result means a newer state transition has already released it.
    fn finish_handoff_dispatch_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Final task store does not implement atomic handoff dispatch completion",
        ))
    }

    /// Owner- and fence-bound dispatch completion. If cancellation intent won
    /// this elected handoff, implementations must atomically terminalize the
    /// task or retain the fence so the runner can do so.
    fn finish_handoff_dispatch_for_owner_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
        _owner_id: &str,
        _dispatch_fence: u64,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Final task store does not implement atomic handoff dispatch completion",
        ))
    }

    /// Atomically cancels an unelected task or records cancellation intent for
    /// an already elected handoff when `expected` is still current.
    ///
    /// A cancellation and input-handoff clearing must share one durable
    /// linearization point. Otherwise a recovery worker can observe an input
    /// accepted before cancellation and deliver cancelled work to application
    /// code. If no atomic dispatch election has won, this must durably replace
    /// the task with `cancelled_task` and retain `cancelled_notification` in
    /// the same transaction. If an election already won, it instead records
    /// cooperative intent for that logically running invocation.
    ///
    /// `Ok(None)` means another transition won before cancellation. A returned
    /// `Cancelled` snapshot is the committed terminal cancellation; a returned
    /// active snapshot is the elected handoff that must cooperatively observe
    /// the cancellation request. Stores that do not provide this boundary fail
    /// closed.
    fn request_cancellation_and_clear_input_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
        _cancelled_task: FinalTask,
        _cancelled_notification: FinalTaskStatusNotification,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        Err(McpError::internal_error(
            "Final task store does not implement atomic task cancellation",
        ))
    }

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
/// mutation and whenever an expired handoff lease is reclaimed, even when the
/// wire task value itself is unchanged. It therefore prevents ABA transitions
/// that task-value equality cannot detect.
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
    /// accepted task-state or cancellation-intent mutation, and when it
    /// reclaims an expired handoff lease. It must compare that value atomically
    /// with the corresponding replacement or cancellation write. Callers must
    /// treat it solely as a CAS token.
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

    /// Returns the retained task's identifier.
    #[cfg(test)]
    fn task_id(&self) -> &FinalTaskId {
        &self.task.base().task_id
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
    next_dispatch_fence: u64,
    work_descriptors: BTreeMap<FinalTaskId, FinalTaskWorkDescriptor>,
    initial_work: BTreeMap<FinalTaskId, FinalTaskWorkDescriptor>,
    accepted_inputs: BTreeMap<FinalTaskId, FinalTaskInputResponses>,
    handoff_leases: BTreeMap<FinalTaskId, InMemoryFinalTaskHandoffLease>,
    cancellation_requests: BTreeSet<FinalTaskId>,
    latest_notifications: BTreeMap<FinalTaskId, FinalTaskStatusNotification>,
    expires_at: BTreeMap<FinalTaskId, Instant>,
}

/// A durable handoff claim in the process-local store.
///
/// The payload stays in its original durable map while this lease is live, so
/// a service crash between claim and dispatch cannot erase recoverable work.
/// Both the claim and an elected dispatch have a renewable deadline. Expiry
/// advances the task generation before another runner can recover the payload,
/// fencing every late finish or restoration from the former owner.
struct InMemoryFinalTaskHandoffLease {
    generation: u64,
    kind: InMemoryFinalTaskHandoffKind,
    dispatch_elected: bool,
    owner_id: String,
    dispatch_fence: Option<u64>,
    recovery_expires_at: Option<Instant>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InMemoryFinalTaskHandoffKind {
    Initial,
    Resumed,
}

const IN_MEMORY_FINAL_TASK_HANDOFF_LEASE: StdDuration = StdDuration::from_secs(30);
const IN_MEMORY_FINAL_TASK_HANDOFF_HEARTBEAT: StdDuration = StdDuration::from_secs(10);

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
        validate_final_task_storage_shape(&task)?;
        ensure_final_task_notification_matches_task(&task, &notification)?;
        let now = (self.clock)();
        validate_final_task_runtime_durations(&task)?;
        let expires_at = in_memory_final_task_expiry(&task, now)?;
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

    fn create_task_with_work(
        &self,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
        work_descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<()> {
        let task_id = task.base().task_id.clone();
        validate_final_task_storage_shape(&task)?;
        ensure_final_task_notification_matches_task(&task, &notification)?;
        if !matches!(task, FinalTask::Working(_)) {
            return Err(McpError::invalid_params(
                "Initial application work requires a working final task",
            ));
        }
        let now = (self.clock)();
        validate_final_task_runtime_durations(&task)?;
        let expires_at = in_memory_final_task_expiry(&task, now)?;
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
        let generation = next_in_memory_final_task_generation(&mut state)?;
        state
            .latest_notifications
            .insert(task_id.clone(), notification);
        state.tasks.insert(task_id.clone(), task);
        state.generations.insert(task_id.clone(), generation);
        state
            .work_descriptors
            .insert(task_id.clone(), work_descriptor.clone());
        state.initial_work.insert(task_id.clone(), work_descriptor);
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
        validate_final_task_runtime_durations(&task)?;
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reclaim_expired_in_memory_final_tasks(&mut state, now);
        if !state.tasks.contains_key(&task_id) {
            return Err(McpError::invalid_params("Task not found"));
        }
        replace_in_memory_final_task(
            &mut state,
            task,
            notification,
            now,
            InMemoryFinalTaskInputMutation::Clear,
        )?;
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
        validate_final_task_runtime_durations(&task)?;
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generations.get(&task_id) != Some(&expected.generation()) {
            return Ok(false);
        }
        replace_in_memory_final_task(
            &mut state,
            task,
            notification,
            now,
            InMemoryFinalTaskInputMutation::Clear,
        )?;
        Ok(true)
    }

    fn replace_task_and_append_input_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
        input_responses: FinalTaskInputResponses,
    ) -> McpResult<bool> {
        let task_id = task.base().task_id.clone();
        if expected.task().base().task_id != task_id {
            return Err(McpError::invalid_params(
                "Expected and replacement final task IDs must match",
            ));
        }
        ensure_final_task_notification_matches_task(&task, &notification)?;
        validate_final_task_runtime_durations(&task)?;
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generations.get(&task_id) != Some(&expected.generation()) {
            return Ok(false);
        }
        replace_in_memory_final_task(
            &mut state,
            task,
            notification,
            now,
            InMemoryFinalTaskInputMutation::Append(input_responses),
        )?;
        Ok(true)
    }

    fn replace_task_and_clear_input_if_current(
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
        validate_final_task_runtime_durations(&task)?;
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generations.get(&task_id) != Some(&expected.generation()) {
            return Ok(false);
        }
        replace_in_memory_final_task(
            &mut state,
            task,
            notification,
            now,
            InMemoryFinalTaskInputMutation::Clear,
        )?;
        Ok(true)
    }

    fn replace_task_and_clear_input_for_handoff_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
        dispatch_fence: u64,
        cancellation_required: bool,
        task: FinalTask,
        notification: FinalTaskStatusNotification,
    ) -> McpResult<bool> {
        if owner_id.is_empty() {
            return Err(McpError::invalid_params(
                "Final task handoff owner must be non-empty",
            ));
        }
        let task_id = task.base().task_id.clone();
        if expected.task().base().task_id != task_id {
            return Err(McpError::invalid_params(
                "Expected and replacement final task IDs must match",
            ));
        }
        if matches!(&task, FinalTask::Cancelled(_)) != cancellation_required {
            return Err(McpError::invalid_params(
                "Fenced final task cancellation disposition does not match the replacement task",
            ));
        }
        ensure_final_task_notification_matches_task(&task, &notification)?;
        validate_final_task_runtime_durations(&task)?;
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let owns_exact_dispatch = state.handoff_leases.get(&task_id).is_some_and(|lease| {
            lease.generation == expected.generation()
                && lease.dispatch_elected
                && lease.owner_id == owner_id
                && lease.dispatch_fence == Some(dispatch_fence)
        });
        if state.generations.get(&task_id) != Some(&expected.generation())
            || !owns_exact_dispatch
            || state.cancellation_requests.contains(&task_id) != cancellation_required
        {
            return Ok(false);
        }
        replace_in_memory_final_task(
            &mut state,
            task,
            notification,
            now,
            InMemoryFinalTaskInputMutation::Clear,
        )?;
        Ok(true)
    }

    fn take_input_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskInputResponses>> {
        Err(McpError::internal_error(
            "Raw final task input claims require an authorized service owner",
        ))
    }

    fn take_input_for_owner_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
    ) -> McpResult<Option<FinalTaskInputResponses>> {
        Ok(self
            .take_input_handoff_for_owner_if_current(expected, owner_id)?
            .map(|claim| claim.input_responses))
    }

    fn take_input_handoff_for_owner_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
    ) -> McpResult<Option<FinalTaskAcceptedInputClaim>> {
        if owner_id.is_empty() {
            return Err(McpError::invalid_params(
                "Final task handoff owner must be non-empty",
            ));
        }
        let task_id = &expected.task().base().task_id;
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generations.get(task_id) != Some(&expected.generation())
            || !state
                .tasks
                .get(task_id)
                .is_some_and(|task| matches!(task, FinalTask::Working(_)))
            || state.cancellation_requests.contains(task_id)
            || state.handoff_leases.contains_key(task_id)
        {
            return Ok(None);
        }
        let Some(input_responses) = state.accepted_inputs.get(task_id).cloned() else {
            return Ok(None);
        };
        let work_descriptor = state
            .work_descriptors
            .get(task_id)
            .cloned()
            .ok_or_else(|| {
                McpError::internal_error(
                    "In-memory final task store is missing a working task descriptor",
                )
            })?;
        insert_in_memory_final_task_handoff_lease(
            &mut state,
            task_id.clone(),
            expected.generation(),
            InMemoryFinalTaskHandoffKind::Resumed,
            owner_id,
            now,
        )?;
        Ok(Some(FinalTaskAcceptedInputClaim::new(
            task_id.clone(),
            expected.generation(),
            owner_id,
            work_descriptor,
            input_responses,
        )))
    }

    fn work_descriptor_if_current(
        &self,
        expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskWorkDescriptor>> {
        let task_id = &expected.task().base().task_id;
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reclaim_expired_in_memory_final_tasks(&mut state, now);
        if state.generations.get(task_id) != Some(&expected.generation())
            || !state
                .tasks
                .get(task_id)
                .is_some_and(|task| matches!(task, FinalTask::Working(_)))
            || state.cancellation_requests.contains(task_id)
        {
            return Ok(None);
        }
        state
            .work_descriptors
            .get(task_id)
            .cloned()
            .map(Some)
            .ok_or_else(|| {
                McpError::internal_error(
                    "In-memory final task store is missing a working task descriptor",
                )
            })
    }

    fn next_initial_work_snapshot_after(
        &self,
        after_task_id: Option<&FinalTaskId>,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reclaim_expired_in_memory_final_tasks(&mut state, now);
        let Some(task_id) = next_in_memory_final_task_recovery_id(
            state.initial_work.keys(),
            after_task_id,
            |task_id| {
                matches!(state.tasks.get(task_id), Some(FinalTask::Working(_)))
                    && !state.cancellation_requests.contains(task_id)
                    && !state.handoff_leases.contains_key(task_id)
            },
        ) else {
            return Ok(None);
        };
        let task = state.tasks.get(&task_id).cloned().ok_or_else(|| {
            McpError::internal_error(
                "In-memory final task store retained initial work for a missing task",
            )
        })?;
        let generation = state.generations.get(&task_id).copied().ok_or_else(|| {
            McpError::internal_error(
                "In-memory final task store retained initial work without a task generation",
            )
        })?;
        Ok(Some(FinalTaskSnapshot::new(task, generation)))
    }

    fn next_initial_work_snapshot(&self) -> McpResult<Option<FinalTaskSnapshot>> {
        self.next_initial_work_snapshot_after(None)
    }

    fn take_initial_work_if_current(
        &self,
        _expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskWorkDescriptor>> {
        Err(McpError::internal_error(
            "Raw final task initial-work claims require an authorized service owner",
        ))
    }

    fn take_initial_work_for_owner_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
    ) -> McpResult<Option<FinalTaskWorkDescriptor>> {
        Ok(self
            .take_initial_work_handoff_for_owner_if_current(expected, owner_id)?
            .map(|claim| claim.work_descriptor))
    }

    fn take_initial_work_handoff_for_owner_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
    ) -> McpResult<Option<FinalTaskInitialWorkClaim>> {
        if owner_id.is_empty() {
            return Err(McpError::invalid_params(
                "Final task handoff owner must be non-empty",
            ));
        }
        let task_id = &expected.task().base().task_id;
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generations.get(task_id) != Some(&expected.generation())
            || !state
                .tasks
                .get(task_id)
                .is_some_and(|task| matches!(task, FinalTask::Working(_)))
            || state.cancellation_requests.contains(task_id)
            || state.handoff_leases.contains_key(task_id)
        {
            return Ok(None);
        }
        let Some(work_descriptor) = state.initial_work.get(task_id).cloned() else {
            return Ok(None);
        };
        insert_in_memory_final_task_handoff_lease(
            &mut state,
            task_id.clone(),
            expected.generation(),
            InMemoryFinalTaskHandoffKind::Initial,
            owner_id,
            now,
        )?;
        Ok(Some(FinalTaskInitialWorkClaim::new(
            task_id.clone(),
            expected.generation(),
            owner_id,
            work_descriptor,
        )))
    }

    fn restore_initial_work_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
        _work_descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Raw final task initial-work restoration requires an authorized service owner",
        ))
    }

    fn restore_initial_work_for_owner_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: Option<u64>,
        work_descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<bool> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let owns_matching_lease = state.handoff_leases.get(task_id).is_some_and(|lease| {
            lease.generation == generation
                && lease.kind == InMemoryFinalTaskHandoffKind::Initial
                && lease.owner_id == owner_id
                && lease.dispatch_fence == dispatch_fence
        });
        if !owns_matching_lease {
            return Ok(false);
        }
        // Preserve the elected fence for the runner's automatic cancellation
        // retirement. Releasing it here would strand a `working` task with
        // cancellation intent after a supervisor error/drop race.
        if state.cancellation_requests.contains(task_id) {
            return Ok(false);
        }
        state.handoff_leases.remove(task_id);
        Ok(state.generations.get(task_id) == Some(&generation)
            && state
                .tasks
                .get(task_id)
                .is_some_and(|task| matches!(task, FinalTask::Working(_)))
            && !state.cancellation_requests.contains(task_id)
            && state.initial_work.get(task_id) == Some(&work_descriptor))
    }

    fn next_accepted_input_snapshot_after(
        &self,
        after_task_id: Option<&FinalTaskId>,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reclaim_expired_in_memory_final_tasks(&mut state, now);

        let Some(task_id) = next_in_memory_final_task_recovery_id(
            state.accepted_inputs.keys(),
            after_task_id,
            |task_id| {
                matches!(state.tasks.get(task_id), Some(FinalTask::Working(_)))
                    && !state.cancellation_requests.contains(task_id)
                    && !state.handoff_leases.contains_key(task_id)
            },
        ) else {
            return Ok(None);
        };
        let task = state.tasks.get(&task_id).cloned().ok_or_else(|| {
            McpError::internal_error("In-memory final task store retained input for a missing task")
        })?;
        let generation = state.generations.get(&task_id).copied().ok_or_else(|| {
            McpError::internal_error(
                "In-memory final task store retained input without a task generation",
            )
        })?;
        Ok(Some(FinalTaskSnapshot::new(task, generation)))
    }

    fn next_accepted_input_snapshot(&self) -> McpResult<Option<FinalTaskSnapshot>> {
        self.next_accepted_input_snapshot_after(None)
    }

    fn restore_input_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
        _input_responses: FinalTaskInputResponses,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Raw final task input restoration requires an authorized service owner",
        ))
    }

    fn restore_input_for_owner_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: Option<u64>,
        input_responses: FinalTaskInputResponses,
    ) -> McpResult<bool> {
        if input_responses.is_empty() {
            return Err(McpError::internal_error(
                "Cannot restore an empty accepted-input handoff",
            ));
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let owns_matching_lease = state.handoff_leases.get(task_id).is_some_and(|lease| {
            lease.generation == generation
                && lease.kind == InMemoryFinalTaskHandoffKind::Resumed
                && lease.owner_id == owner_id
                && lease.dispatch_fence == dispatch_fence
        });
        if !owns_matching_lease {
            return Ok(false);
        }
        // See the initial-work restoration path above. A cancellation winner
        // must retain this exact fence until the runner records the terminal
        // cancellation outcome.
        if state.cancellation_requests.contains(task_id) {
            return Ok(false);
        }
        state.handoff_leases.remove(task_id);
        Ok(state.generations.get(task_id) == Some(&generation)
            && state
                .tasks
                .get(task_id)
                .is_some_and(|task| matches!(task, FinalTask::Working(_)))
            && !state.cancellation_requests.contains(task_id)
            && state.accepted_inputs.get(task_id) == Some(&input_responses))
    }

    fn begin_handoff_dispatch_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Raw final task dispatch election requires an authorized service owner",
        ))
    }

    fn begin_handoff_dispatch_for_owner_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
    ) -> McpResult<Option<u64>> {
        if owner_id.is_empty() {
            return Err(McpError::invalid_params(
                "Final task handoff owner must be non-empty",
            ));
        }
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generations.get(task_id) != Some(&generation)
            || !state
                .tasks
                .get(task_id)
                .is_some_and(|task| matches!(task, FinalTask::Working(_)))
            || state.cancellation_requests.contains(task_id)
            || !state.handoff_leases.get(task_id).is_some_and(|lease| {
                lease.generation == generation
                    && !lease.dispatch_elected
                    && lease.owner_id == owner_id
                    && lease
                        .recovery_expires_at
                        .is_some_and(|expires_at| expires_at > now)
            })
        {
            return Ok(None);
        }
        let dispatch_fence = next_in_memory_final_task_dispatch_fence(&mut state)?;
        let dispatch_expires_at = in_memory_final_task_handoff_lease_expiry(now)?;
        let lease = state.handoff_leases.get_mut(task_id).ok_or_else(|| {
            McpError::internal_error("In-memory final task store lost a handoff lease")
        })?;
        lease.dispatch_elected = true;
        lease.dispatch_fence = Some(dispatch_fence);
        // The elected owner renews this durable lease while application work
        // is pending. If its process dies, expiry advances the generation
        // before a later service may take the retained payload.
        lease.recovery_expires_at = Some(dispatch_expires_at);
        Ok(Some(dispatch_fence))
    }

    fn renew_handoff_dispatch_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: u64,
    ) -> McpResult<bool> {
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let renewed_expires_at = in_memory_final_task_handoff_lease_expiry(now)?;
        let Some(lease) = state.handoff_leases.get(task_id) else {
            return Ok(false);
        };
        if lease.generation != generation
            || !lease.dispatch_elected
            || lease.owner_id != owner_id
            || lease.dispatch_fence != Some(dispatch_fence)
            || state.generations.get(task_id) != Some(&generation)
            || !state
                .tasks
                .get(task_id)
                .is_some_and(|task| matches!(task, FinalTask::Working(_)))
        {
            return Ok(false);
        }
        let Some(lease) = state.handoff_leases.get_mut(task_id) else {
            return Ok(false);
        };
        lease.recovery_expires_at = Some(renewed_expires_at);
        Ok(true)
    }

    fn handoff_dispatch_lease_heartbeat_interval(&self) -> McpResult<StdDuration> {
        Ok(IN_MEMORY_FINAL_TASK_HANDOFF_HEARTBEAT)
    }

    fn finish_handoff_dispatch_if_current(
        &self,
        _task_id: &FinalTaskId,
        _generation: u64,
    ) -> McpResult<bool> {
        Err(McpError::internal_error(
            "Raw final task dispatch completion requires an authorized service owner",
        ))
    }

    fn finish_handoff_dispatch_for_owner_if_current(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: u64,
    ) -> McpResult<bool> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(lease) = state.handoff_leases.get(task_id) else {
            return Ok(false);
        };
        if lease.generation != generation
            || !lease.dispatch_elected
            || lease.owner_id != owner_id
            || lease.dispatch_fence != Some(dispatch_fence)
        {
            return Ok(false);
        }
        // Keep the elected fence live for the caller to convert durable
        // cancellation intent into a terminal cancellation. Otherwise a
        // cancellation that races a successful supervisor return could remove
        // the last authority capable of retiring its `working` task.
        if state.cancellation_requests.contains(task_id) {
            return Ok(false);
        }
        let still_dispatchable = state.generations.get(task_id) == Some(&generation)
            && state
                .tasks
                .get(task_id)
                .is_some_and(|task| matches!(task, FinalTask::Working(_)))
            && !state.cancellation_requests.contains(task_id);
        let kind = lease.kind;
        state.handoff_leases.remove(task_id);
        if still_dispatchable {
            match kind {
                InMemoryFinalTaskHandoffKind::Initial => {
                    state.initial_work.remove(task_id);
                }
                InMemoryFinalTaskHandoffKind::Resumed => {
                    state.accepted_inputs.remove(task_id);
                }
            }
        }
        Ok(still_dispatchable)
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
        record_in_memory_final_task_cancellation(&mut state, task_id)?;
        Ok(())
    }

    fn request_cancellation_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<bool> {
        let task_id = &expected.task().base().task_id;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generations.get(task_id) != Some(&expected.generation()) {
            return Ok(false);
        }
        record_in_memory_final_task_cancellation(&mut state, task_id)?;
        Ok(true)
    }

    fn request_cancellation_and_clear_input_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        cancelled_task: FinalTask,
        cancelled_notification: FinalTaskStatusNotification,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        let task_id = &expected.task().base().task_id;
        if &cancelled_task.base().task_id != task_id {
            return Err(McpError::invalid_params(
                "Expected and cancelled final task IDs must match",
            ));
        }
        if !matches!(&cancelled_task, FinalTask::Cancelled(_)) {
            return Err(McpError::invalid_params(
                "Atomic task cancellation requires a cancelled final task",
            ));
        }
        ensure_final_task_notification_matches_task(&cancelled_task, &cancelled_notification)?;
        validate_final_task_transition(expected.task(), &cancelled_task)?;
        validate_final_task_runtime_durations(&cancelled_task)?;
        let now = (self.clock)();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generations.get(task_id) != Some(&expected.generation()) {
            return Ok(None);
        }
        let dispatch_elected = state.handoff_leases.get(task_id).is_some_and(|lease| {
            lease.generation == expected.generation() && lease.dispatch_elected
        });
        if dispatch_elected {
            record_in_memory_final_task_cancellation(&mut state, task_id)?;
            let task = state.tasks.get(task_id).cloned().ok_or_else(|| {
                McpError::internal_error(
                    "In-memory final task store lost an elected task during cancellation",
                )
            })?;
            let generation = state.generations.get(task_id).copied().ok_or_else(|| {
                McpError::internal_error(
                    "In-memory final task store lost an elected task generation during cancellation",
                )
            })?;
            return Ok(Some(FinalTaskSnapshot::new(task, generation)));
        }
        replace_in_memory_final_task(
            &mut state,
            cancelled_task.clone(),
            cancelled_notification,
            now,
            InMemoryFinalTaskInputMutation::Clear,
        )?;
        let generation = state.generations.get(task_id).copied().ok_or_else(|| {
            McpError::internal_error("In-memory final task store lost a cancelled task generation")
        })?;
        Ok(Some(FinalTaskSnapshot::new(cancelled_task, generation)))
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

/// Compares complete durable task values without relying on handwritten
/// equality across the protocol's open-preserving task result fields.
fn final_tasks_match_exactly(left: &FinalTask, right: &FinalTask) -> McpResult<bool> {
    let left = serde_json::to_value(left).map_err(|error| {
        McpError::internal_error(format!(
            "Could not encode retained final task for exact comparison: {error}"
        ))
    })?;
    let right = serde_json::to_value(right).map_err(|error| {
        McpError::internal_error(format!(
            "Could not encode retained final task for exact comparison: {error}"
        ))
    })?;
    Ok(left == right)
}

fn validate_final_task_runtime_durations(task: &FinalTask) -> McpResult<()> {
    for (field, duration) in [
        ("ttlMs", task.base().ttl_ms.as_ref()),
        ("pollIntervalMs", task.base().poll_interval_ms.as_ref()),
    ] {
        if let Some(duration) = duration {
            duration.try_as_millis().map_err(|error| {
                McpError::invalid_params(format!(
                    "Task {field} cannot be represented by the local millisecond runtime: {error}"
                ))
            })?;
        }
    }
    Ok(())
}

/// Validates the final Task shape before it crosses a durable-store boundary.
///
/// `FinalTask` is intentionally constructible as Rust data, so the store must
/// not rely on wire deserialization to keep the discriminating status aligned
/// with its variant. In particular, an empty `input_required` task would have
/// no valid MRTR handoff to recover or deliver to a supervisor.
fn validate_final_task_storage_shape(task: &FinalTask) -> McpResult<()> {
    let expected_status = match task {
        FinalTask::Working(_) => FinalTaskStatus::Working,
        FinalTask::InputRequired { input_requests, .. } => {
            if input_requests.is_empty() {
                return Err(McpError::invalid_params(
                    "input_required tasks require at least one input request",
                ));
            }
            FinalTaskInputLedger::from_requests(input_requests)
                .map_err(|error| McpError::invalid_params(error.to_string()))?;
            FinalTaskStatus::InputRequired
        }
        FinalTask::Completed { .. } => FinalTaskStatus::Completed,
        FinalTask::Failed { .. } => FinalTaskStatus::Failed,
        FinalTask::Cancelled(_) => FinalTaskStatus::Cancelled,
    };
    if task.base().status != expected_status {
        return Err(McpError::invalid_params(
            "Final task status must match its status-specific payload",
        ));
    }
    Ok(())
}

/// Validates a final Task transition before mutating any retained state.
///
/// A task's identity and retention contract are fixed at creation. Letting a
/// later state transition change `ttlMs`, `pollIntervalMs`, or `createdAt`
/// would make the wire-visible task disagree with the durable expiry and can
/// turn a recovered supervisor handoff into an unbounded retention leak.
fn validate_final_task_transition(current: &FinalTask, replacement: &FinalTask) -> McpResult<()> {
    validate_final_task_storage_shape(replacement)?;

    let current_base = current.base();
    let replacement_base = replacement.base();
    if current_base.task_id != replacement_base.task_id {
        return Err(McpError::invalid_params(
            "Final task replacement must preserve taskId",
        ));
    }
    if current_base.created_at != replacement_base.created_at {
        return Err(McpError::invalid_params(
            "Final task replacement must preserve createdAt",
        ));
    }
    if current_base.ttl_ms != replacement_base.ttl_ms {
        return Err(McpError::invalid_params(
            "Final task replacement must preserve ttlMs",
        ));
    }
    if current_base.poll_interval_ms != replacement_base.poll_interval_ms {
        return Err(McpError::invalid_params(
            "Final task replacement must preserve pollIntervalMs",
        ));
    }

    let transition_is_valid = match current_base.status {
        FinalTaskStatus::Working => matches!(
            replacement_base.status,
            FinalTaskStatus::Working
                | FinalTaskStatus::InputRequired
                | FinalTaskStatus::Completed
                | FinalTaskStatus::Failed
                | FinalTaskStatus::Cancelled
        ),
        FinalTaskStatus::InputRequired => matches!(
            replacement_base.status,
            FinalTaskStatus::Working
                | FinalTaskStatus::InputRequired
                | FinalTaskStatus::Completed
                | FinalTaskStatus::Failed
                | FinalTaskStatus::Cancelled
        ),
        FinalTaskStatus::Completed | FinalTaskStatus::Failed | FinalTaskStatus::Cancelled => false,
    };
    if !transition_is_valid {
        return Err(McpError::invalid_params(
            "Final task replacement is not a valid lifecycle transition",
        ));
    }
    Ok(())
}

/// Re-validates the store attestation that binds a private handoff payload to
/// the exact candidate and service owner that claimed it.
fn validate_final_task_handoff_binding(
    expected: &FinalTaskSnapshot,
    expected_owner_id: &str,
    task_id: &FinalTaskId,
    generation: u64,
    owner_id: &str,
    handoff_kind: &'static str,
) -> McpResult<()> {
    if !matches!(expected.task(), FinalTask::Working(_))
        || task_id != &expected.task().base().task_id
        || generation != expected.generation()
        || owner_id != expected_owner_id
        || owner_id.is_empty()
    {
        return Err(McpError::internal_error(format!(
            "Final task store returned a {handoff_kind} handoff for the wrong task, generation, or owner"
        )));
    }
    Ok(())
}

/// Ensures an opaque descriptor still satisfies its one required structural
/// invariant at the durable handoff boundary.
fn validate_final_task_work_descriptor(work_descriptor: &FinalTaskWorkDescriptor) -> McpResult<()> {
    if work_descriptor.as_value().is_null() {
        return Err(McpError::internal_error(
            "Final task store returned a null application work descriptor",
        ));
    }
    Ok(())
}

fn stale_final_task_handoff_error() -> McpError {
    McpError::invalid_params(
        "Final task handoff is no longer the elected generation and dispatch fence",
    )
}

fn in_memory_final_task_expiry(task: &FinalTask, now: Instant) -> McpResult<Option<Instant>> {
    let Some(ttl_ms) = task.base().ttl_ms.as_ref() else {
        return Ok(None);
    };
    let ttl_ms = ttl_ms.try_as_millis().map_err(|error| {
        McpError::invalid_params(format!(
            "Task ttlMs cannot be represented by the local millisecond runtime: {error}"
        ))
    })?;
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

fn next_in_memory_final_task_dispatch_fence(state: &mut InMemoryFinalTaskState) -> McpResult<u64> {
    let fence = state.next_dispatch_fence.checked_add(1).ok_or_else(|| {
        McpError::internal_error("In-memory final task dispatch fence space is exhausted")
    })?;
    state.next_dispatch_fence = fence;
    Ok(fence)
}

fn next_in_memory_final_task_recovery_id<'a>(
    task_ids: impl Iterator<Item = &'a FinalTaskId>,
    after_task_id: Option<&FinalTaskId>,
    mut eligible: impl FnMut(&FinalTaskId) -> bool,
) -> Option<FinalTaskId> {
    let task_ids = task_ids.collect::<Vec<_>>();
    after_task_id
        .and_then(|after_task_id| {
            task_ids
                .iter()
                .copied()
                .find(|task_id| *task_id > after_task_id && eligible(*task_id))
        })
        .or_else(|| task_ids.into_iter().find(|task_id| eligible(*task_id)))
        .cloned()
}

/// Records cancellation at the same durable linearization point as handoff
/// clearing. An already elected dispatch lease wins the start-vs-cancel race,
/// so cancellation is retained without changing its generation; otherwise the
/// generation moves and any stale handoff is fenced before application code.
/// The fallible generation allocation happens before every payload, lease, or
/// cancellation mutation so exhaustion leaves the durable state unchanged.
fn record_in_memory_final_task_cancellation(
    state: &mut InMemoryFinalTaskState,
    task_id: &FinalTaskId,
) -> McpResult<()> {
    let generation = state.generations.get(task_id).copied().ok_or_else(|| {
        McpError::internal_error("In-memory final task store is missing a task generation")
    })?;
    let dispatch_elected = state
        .handoff_leases
        .get(task_id)
        .is_some_and(|lease| lease.generation == generation && lease.dispatch_elected);
    let needs_generation_fence =
        !dispatch_elected && !state.cancellation_requests.contains(task_id);
    let next_generation = needs_generation_fence
        .then(|| next_in_memory_final_task_generation(state))
        .transpose()?;

    state.accepted_inputs.remove(task_id);
    state.initial_work.remove(task_id);
    if !dispatch_elected {
        state.handoff_leases.remove(task_id);
    }
    state.cancellation_requests.insert(task_id.clone());
    if let Some(next_generation) = next_generation {
        state.generations.insert(task_id.clone(), next_generation);
    }
    Ok(())
}

enum InMemoryFinalTaskInputMutation {
    Clear,
    Append(FinalTaskInputResponses),
}

fn replace_in_memory_final_task(
    state: &mut InMemoryFinalTaskState,
    task: FinalTask,
    notification: FinalTaskStatusNotification,
    _now: Instant,
    input_mutation: InMemoryFinalTaskInputMutation,
) -> McpResult<()> {
    let task_id = task.base().task_id.clone();
    let current = state
        .tasks
        .get(&task_id)
        .ok_or_else(|| McpError::invalid_params("Task not found"))?;
    validate_final_task_transition(current, &task)?;
    let generation = next_in_memory_final_task_generation(state)?;
    let working = matches!(&task, FinalTask::Working(_));
    let terminal = matches!(
        &task,
        FinalTask::Completed { .. } | FinalTask::Failed { .. } | FinalTask::Cancelled(_)
    );
    state
        .latest_notifications
        .insert(task_id.clone(), notification);
    state.tasks.insert(task_id.clone(), task);
    state.generations.insert(task_id.clone(), generation);
    state.handoff_leases.remove(&task_id);
    if !working {
        state.initial_work.remove(&task_id);
    }
    match input_mutation {
        InMemoryFinalTaskInputMutation::Clear => {
            state.accepted_inputs.remove(&task_id);
        }
        InMemoryFinalTaskInputMutation::Append(input_responses) => {
            if !input_responses.is_empty() {
                state
                    .accepted_inputs
                    .entry(task_id.clone())
                    .or_default()
                    .extend(input_responses);
            }
        }
    }
    if terminal {
        // Keep the originating descriptor beside the terminal outcome until
        // the task's creation-time retention record expires or is reclaimed.
        // It is private store state, not a wire-visible task field.
        state.initial_work.remove(&task_id);
        state.cancellation_requests.remove(&task_id);
    }
    Ok(())
}

fn reclaim_expired_in_memory_final_tasks(state: &mut InMemoryFinalTaskState, now: Instant) {
    let expired_handoff_task_ids = state
        .handoff_leases
        .iter()
        .filter_map(|(task_id, lease)| {
            lease
                .recovery_expires_at
                .is_some_and(|expires_at| expires_at <= now)
                .then(|| task_id.clone())
        })
        .collect::<Vec<_>>();
    for task_id in expired_handoff_task_ids {
        let Some(lease_generation) = state
            .handoff_leases
            .get(&task_id)
            .map(|lease| lease.generation)
        else {
            continue;
        };
        let cancellation_requires_retirement = state.cancellation_requests.contains(&task_id)
            && state
                .tasks
                .get(&task_id)
                .is_some_and(|task| matches!(task, FinalTask::Working(_)));
        if cancellation_requires_retirement {
            // The elected runner may have crashed after `tasks/cancel` won.
            // Turn intent into a terminal state while this expired lease still
            // identifies the retiring owner. If a checked transition fails,
            // retaining the fence is safer than exposing working+cancellation.
            let _ = terminalize_expired_in_memory_final_task_cancellation(state, &task_id, now);
            continue;
        }
        let still_recoverable = state.generations.get(&task_id) == Some(&lease_generation)
            && state
                .tasks
                .get(&task_id)
                .is_some_and(|task| matches!(task, FinalTask::Working(_)))
            && !state.cancellation_requests.contains(&task_id);
        if still_recoverable {
            // Fence the abandoned claimant before a new worker can recover
            // the retained payload. Without this generation advance, a late
            // drop from the old worker could release a newer worker's lease.
            match next_in_memory_final_task_generation(state) {
                Ok(generation) => {
                    state.handoff_leases.remove(&task_id);
                    state.generations.insert(task_id, generation);
                }
                // Generation exhaustion cannot safely release an abandoned
                // claim: doing so would let an old claimant and a new
                // claimant share the same CAS fence. Leave it retained.
                Err(_) => {}
            }
        } else {
            state.handoff_leases.remove(&task_id);
        }
    }
    let expired_task_ids = state
        .expires_at
        .iter()
        .filter_map(|(task_id, expires_at)| (*expires_at <= now).then(|| task_id.clone()))
        .collect::<Vec<_>>();
    for task_id in expired_task_ids {
        state.expires_at.remove(&task_id);
        state.tasks.remove(&task_id);
        state.generations.remove(&task_id);
        state.work_descriptors.remove(&task_id);
        state.initial_work.remove(&task_id);
        state.accepted_inputs.remove(&task_id);
        state.handoff_leases.remove(&task_id);
        state.cancellation_requests.remove(&task_id);
        state.latest_notifications.remove(&task_id);
    }
}

/// Converts an expired elected cancellation lease into a terminal task.
///
/// A transition failure leaves the lease in place, preserving the exact
/// retirement fence instead of stranding a working task with cancellation
/// intent and no authorized owner.
fn terminalize_expired_in_memory_final_task_cancellation(
    state: &mut InMemoryFinalTaskState,
    task_id: &FinalTaskId,
    now: Instant,
) -> McpResult<()> {
    let Some(FinalTask::Working(base)) = state.tasks.get(task_id).cloned() else {
        return Err(McpError::internal_error(
            "Expired cancellation lease no longer owns a working final task",
        ));
    };
    let task = FinalTask::Cancelled(transition_terminal_final_task_base(
        base,
        FinalTaskStatus::Cancelled,
        None,
    )?);
    replace_in_memory_final_task(
        state,
        task.clone(),
        final_task_notification(&task),
        now,
        InMemoryFinalTaskInputMutation::Clear,
    )
}

fn insert_in_memory_final_task_handoff_lease(
    state: &mut InMemoryFinalTaskState,
    task_id: FinalTaskId,
    generation: u64,
    kind: InMemoryFinalTaskHandoffKind,
    owner_id: &str,
    now: Instant,
) -> McpResult<()> {
    let expires_at = in_memory_final_task_handoff_lease_expiry(now)?;
    if state
        .handoff_leases
        .insert(
            task_id,
            InMemoryFinalTaskHandoffLease {
                generation,
                kind,
                dispatch_elected: false,
                owner_id: owner_id.to_owned(),
                dispatch_fence: None,
                recovery_expires_at: Some(expires_at),
            },
        )
        .is_some()
    {
        return Err(McpError::internal_error(
            "In-memory final task store overwrote a live handoff lease",
        ));
    }
    Ok(())
}

fn in_memory_final_task_handoff_lease_expiry(now: Instant) -> McpResult<Instant> {
    now.checked_add(IN_MEMORY_FINAL_TASK_HANDOFF_LEASE)
        .ok_or_else(|| {
            McpError::internal_error("Task handoff lease exceeds process-local clock range")
        })
}

/// Typed notification delivery hook installed by the application transport.
///
/// The store receives the same notification first, so a failed or disconnected
/// delivery path never changes whether the task transition was durable.
pub type FinalTaskNotificationEmitter = Arc<dyn Fn(FinalTaskStatusNotification) + Send + Sync>;

/// Opaque application work bound durably to a final Task at creation.
///
/// The descriptor is intentionally private to the caller-owned Task service:
/// it never appears in task snapshots, status notifications, or MCP wire
/// results. Applications commonly encode a handler identity plus operation
/// payload, but the framework treats the value as opaque.
#[derive(Clone, Debug, PartialEq)]
pub struct FinalTaskWorkDescriptor(serde_json::Value);

impl FinalTaskWorkDescriptor {
    /// Creates a non-null opaque work descriptor for one Task operation.
    pub fn new(descriptor: serde_json::Value) -> McpResult<Self> {
        if descriptor.is_null() {
            return Err(McpError::invalid_params(
                "Final task work descriptor must identify an application operation",
            ));
        }
        Ok(Self(descriptor))
    }

    /// Returns the opaque descriptor supplied by the creating application.
    #[must_use]
    pub const fn as_value(&self) -> &serde_json::Value {
        &self.0
    }
}

/// Store-attested initial-work payload for one exact owner-bound handoff.
///
/// A durable store returns this only from its atomic initial-work claim. The
/// runtime checks every binding again before the opaque descriptor can reach
/// application code, so a permissive store cannot substitute another task's
/// operation into a valid recovery candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct FinalTaskInitialWorkClaim {
    task_id: FinalTaskId,
    generation: u64,
    owner_id: String,
    work_descriptor: FinalTaskWorkDescriptor,
}

impl FinalTaskInitialWorkClaim {
    /// Creates one store-returned initial-work claim.
    #[must_use]
    pub fn new(
        task_id: FinalTaskId,
        generation: u64,
        owner_id: impl Into<String>,
        work_descriptor: FinalTaskWorkDescriptor,
    ) -> Self {
        Self {
            task_id,
            generation,
            owner_id: owner_id.into(),
            work_descriptor,
        }
    }
}

/// Store-attested accepted-input payload for one exact owner-bound handoff.
///
/// The descriptor and accepted inputs are returned together so no recovery
/// path can combine a descriptor from one durable task with input retained for
/// another task or generation.
#[derive(Clone, Debug, PartialEq)]
pub struct FinalTaskAcceptedInputClaim {
    task_id: FinalTaskId,
    generation: u64,
    owner_id: String,
    work_descriptor: FinalTaskWorkDescriptor,
    input_responses: FinalTaskInputResponses,
}

impl FinalTaskAcceptedInputClaim {
    /// Creates one store-returned accepted-input claim.
    #[must_use]
    pub fn new(
        task_id: FinalTaskId,
        generation: u64,
        owner_id: impl Into<String>,
        work_descriptor: FinalTaskWorkDescriptor,
        input_responses: FinalTaskInputResponses,
    ) -> Self {
        Self {
            task_id,
            generation,
            owner_id: owner_id.into(),
            work_descriptor,
            input_responses,
        }
    }
}

/// Exact authority for one elected application handoff.
///
/// This is deliberately retained inside the non-cloneable handoff values
/// below. Application code can observe it only while the task service is
/// invoking the supervisor, and every mutation carries the store-issued
/// generation, owner, and dispatch fence that elected that invocation.
struct FinalTaskHandoffAuthority {
    runtime: FinalTaskRuntime,
    task_id: FinalTaskId,
    generation: u64,
    owner_id: String,
    dispatch_fence: u64,
}

impl std::fmt::Debug for FinalTaskHandoffAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The runtime holds trait-object store/emitter handles and is omitted.
        formatter
            .debug_struct("FinalTaskHandoffAuthority")
            .field("task_id", &self.task_id)
            .field("generation", &self.generation)
            .field("owner_id", &self.owner_id)
            .field("dispatch_fence", &self.dispatch_fence)
            .finish_non_exhaustive()
    }
}

impl FinalTaskHandoffAuthority {
    fn require_input(
        &self,
        input_requests: FinalTaskInputRequests,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        self.runtime.fenced_require_input(
            &self.task_id,
            self.generation,
            &self.owner_id,
            self.dispatch_fence,
            input_requests,
            status_message,
        )
    }

    fn complete_task(
        &self,
        result: FinalTaskCallToolResult,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        self.runtime.fenced_complete_task(
            &self.task_id,
            self.generation,
            &self.owner_id,
            self.dispatch_fence,
            result,
            status_message,
        )
    }

    fn fail_task(
        &self,
        error: FinalTaskError,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        self.runtime.fenced_fail_task(
            &self.task_id,
            self.generation,
            &self.owner_id,
            self.dispatch_fence,
            error,
            status_message,
        )
    }

    fn honor_cancellation(&self, status_message: Option<String>) -> McpResult<FinalTask> {
        self.runtime.fenced_honor_cancellation(
            &self.task_id,
            self.generation,
            &self.owner_id,
            self.dispatch_fence,
            status_message,
        )
    }

    fn is_cancellation_requested(&self) -> McpResult<bool> {
        self.runtime
            .fenced_cancellation_requested(&self.task_id, self.generation)
    }
}

/// Initial caller-owned work recovered from a newly created final Task.
#[derive(Debug)]
#[must_use = "initial task work must be handed to the application supervisor"]
pub struct FinalTaskInitialWork {
    task_id: FinalTaskId,
    generation: u64,
    work_descriptor: FinalTaskWorkDescriptor,
    authority: Option<FinalTaskHandoffAuthority>,
}

impl PartialEq for FinalTaskInitialWork {
    fn eq(&self, other: &Self) -> bool {
        self.task_id == other.task_id
            && self.generation == other.generation
            && self.work_descriptor == other.work_descriptor
    }
}

impl FinalTaskInitialWork {
    /// Returns the task whose originating work may now begin.
    #[must_use]
    pub const fn task_id(&self) -> &FinalTaskId {
        &self.task_id
    }

    /// Returns the exact `working` generation that authorized this handoff.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the opaque descriptor durably bound when the task was created.
    #[must_use]
    pub const fn work_descriptor(&self) -> &FinalTaskWorkDescriptor {
        &self.work_descriptor
    }

    /// Enters `input_required` under this handoff's exact elected fence.
    pub fn require_input(
        &self,
        input_requests: FinalTaskInputRequests,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        self.authority()?
            .require_input(input_requests, status_message)
    }

    /// Completes this task under this handoff's exact elected fence.
    pub fn complete_task(
        &self,
        result: FinalTaskCallToolResult,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        self.authority()?.complete_task(result, status_message)
    }

    /// Fails this task under this handoff's exact elected fence.
    pub fn fail_task(
        &self,
        error: FinalTaskError,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        self.authority()?.fail_task(error, status_message)
    }

    /// Returns whether cancellation has been requested for this exact handoff.
    pub fn is_cancellation_requested(&self) -> McpResult<bool> {
        self.authority()?.is_cancellation_requested()
    }

    /// Records the cooperative cancellation outcome under the elected fence.
    pub fn honor_cancellation(&self, status_message: Option<String>) -> McpResult<FinalTask> {
        self.authority()?.honor_cancellation(status_message)
    }

    fn authority(&self) -> McpResult<&FinalTaskHandoffAuthority> {
        self.authority.as_ref().ok_or_else(|| {
            McpError::internal_error(
                "Final task application mutations require an elected service handoff",
            )
        })
    }

    fn attach_authority(&mut self, authority: FinalTaskHandoffAuthority) {
        self.authority = Some(authority);
    }

    fn restore_copy(&self) -> FinalTaskWorkDescriptor {
        self.work_descriptor.clone()
    }
}

/// Accepted task input made available exactly once to the task supervisor.
///
/// This is deliberately not part of the public task snapshot or notification:
/// task input belongs to the task's private execution state. The caller-owned
/// supervisor takes this value after a task returns to `working` and uses it to
/// resume the associated operation.
#[derive(Debug)]
#[must_use = "accepted task input must be handed to the resumed worker"]
pub struct FinalTaskAcceptedInput {
    task_id: FinalTaskId,
    generation: u64,
    work_descriptor: FinalTaskWorkDescriptor,
    input_responses: FinalTaskInputResponses,
    authority: Option<FinalTaskHandoffAuthority>,
}

impl PartialEq for FinalTaskAcceptedInput {
    fn eq(&self, other: &Self) -> bool {
        self.task_id == other.task_id
            && self.generation == other.generation
            && self.work_descriptor == other.work_descriptor
            && self.input_responses == other.input_responses
    }
}

impl FinalTaskAcceptedInput {
    /// Returns the task whose worker may now resume.
    #[must_use]
    pub const fn task_id(&self) -> &FinalTaskId {
        &self.task_id
    }

    /// Returns the exact store generation whose `working` state authorized
    /// this one-shot handoff.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the opaque descriptor durably bound when the task was created.
    #[must_use]
    pub const fn work_descriptor(&self) -> &FinalTaskWorkDescriptor {
        &self.work_descriptor
    }

    /// Returns every validated input response accumulated for this resumption.
    #[must_use]
    pub const fn input_responses(&self) -> &FinalTaskInputResponses {
        &self.input_responses
    }

    /// Splits this one-shot supervisor handoff into its task ID and input map.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        FinalTaskId,
        u64,
        FinalTaskWorkDescriptor,
        FinalTaskInputResponses,
    ) {
        (
            self.task_id,
            self.generation,
            self.work_descriptor,
            self.input_responses,
        )
    }

    /// Enters `input_required` under this handoff's exact elected fence.
    pub fn require_input(
        &self,
        input_requests: FinalTaskInputRequests,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        self.authority()?
            .require_input(input_requests, status_message)
    }

    /// Completes this task under this handoff's exact elected fence.
    pub fn complete_task(
        &self,
        result: FinalTaskCallToolResult,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        self.authority()?.complete_task(result, status_message)
    }

    /// Fails this task under this handoff's exact elected fence.
    pub fn fail_task(
        &self,
        error: FinalTaskError,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        self.authority()?.fail_task(error, status_message)
    }

    /// Returns whether cancellation has been requested for this exact handoff.
    pub fn is_cancellation_requested(&self) -> McpResult<bool> {
        self.authority()?.is_cancellation_requested()
    }

    /// Records the cooperative cancellation outcome under the elected fence.
    pub fn honor_cancellation(&self, status_message: Option<String>) -> McpResult<FinalTask> {
        self.authority()?.honor_cancellation(status_message)
    }

    fn authority(&self) -> McpResult<&FinalTaskHandoffAuthority> {
        self.authority.as_ref().ok_or_else(|| {
            McpError::internal_error(
                "Final task application mutations require an elected service handoff",
            )
        })
    }

    fn attach_authority(&mut self, authority: FinalTaskHandoffAuthority) {
        self.authority = Some(authority);
    }

    fn restore_copy(&self) -> FinalTaskInputResponses {
        self.input_responses.clone()
    }
}

/// One caller-owned application Task invocation recovered from durable state.
#[must_use = "task supervisor handoffs must be consumed by the application"]
pub enum FinalTaskSupervisorHandoff {
    /// The task's original operation has not yet been delivered to the app.
    Initial(FinalTaskInitialWork),
    /// The task's original operation resumes with accepted client input.
    Resumed(FinalTaskAcceptedInput),
}

impl FinalTaskSupervisorHandoff {
    fn attach_authority(&mut self, authority: FinalTaskHandoffAuthority) {
        match self {
            Self::Initial(initial) => initial.attach_authority(authority),
            Self::Resumed(accepted) => accepted.attach_authority(authority),
        }
    }
}

/// Application-owned admission authority for Tasks with unlimited retention.
///
/// Supplying this authority is an explicit declaration that the embedding owns
/// the task-retention policy for `ttlMs: null`. It is deliberately distinct
/// from the process-local store: accepting unlimited retention without an
/// application decision would make unbounded task retention an accidental
/// default.
pub trait FinalTaskRetentionAuthority: Send + Sync {
    /// Confirms that this application accepts responsibility for retaining one
    /// unlimited final Task according to its own retention policy.
    fn authorize_unlimited_retention(&self) -> McpResult<()>;
}

/// Immutable final Tasks timing policy supplied with the durable store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalTaskRuntimeConfig {
    ttl_ms: Option<u64>,
    poll_interval_ms: Option<u64>,
}

impl FinalTaskRuntimeConfig {
    /// Creates a final Tasks policy with a required finite retention duration.
    pub fn new(ttl_ms: u64, poll_interval_ms: Option<u64>) -> McpResult<Self> {
        Self::with_ttl(Some(ttl_ms), poll_interval_ms)
    }

    /// Creates a final Tasks policy whose required wire `ttlMs` field is
    /// a positive duration.
    ///
    /// Passing `None` fails closed. Call [`Self::with_unlimited_ttl`] with an
    /// explicit [`FinalTaskRetentionAuthority`] instead.
    pub fn with_ttl(ttl_ms: Option<u64>, poll_interval_ms: Option<u64>) -> McpResult<Self> {
        let ttl_ms = ttl_ms.ok_or_else(|| {
            McpError::invalid_params("Tasks ttlMs null requires an explicit retention authority")
        })?;
        final_task_duration(ttl_ms)?;
        if let Some(interval) = poll_interval_ms {
            final_task_duration(interval)?;
        }
        Ok(Self {
            ttl_ms: Some(ttl_ms),
            poll_interval_ms,
        })
    }

    /// Creates a `ttlMs: null` policy after the application authorizes its
    /// own durable retention and reclamation path.
    pub fn with_unlimited_ttl(
        retention_authority: &dyn FinalTaskRetentionAuthority,
        poll_interval_ms: Option<u64>,
    ) -> McpResult<Self> {
        retention_authority.authorize_unlimited_retention()?;
        if let Some(interval) = poll_interval_ms {
            final_task_duration(interval)?;
        }
        Ok(Self {
            ttl_ms: None,
            poll_interval_ms,
        })
    }

    /// Returns the configured presence-aware TTL for locally created Tasks.
    #[must_use]
    pub const fn ttl_ms(&self) -> Option<u64> {
        self.ttl_ms
    }
}

/// Application callback invoked for one durable Task handoff.
///
/// The callback receives an initial opaque work descriptor or that descriptor
/// plus validated input responses, together with the task identity and store
/// generation. Its handoff is the only application mutation authority: its
/// `require_input`, `complete_task`, `fail_task`, and
/// `honor_cancellation` methods carry the elected dispatch fence. It never
/// receives a store record, queue handle, or task-service control surface. The enclosing
/// [`AuthorizedTaskServiceRunner`] must be run by the embedding application in
/// its own structured `Cx` region; FastMCP never creates a runtime or detaches
/// a worker for it.
pub type FinalTaskSupervisorFuture<'a> = Pin<Box<dyn Future<Output = McpResult<()>> + Send + 'a>>;

/// Caller-owned execution hook for initial and resumed final-Tasks work.
///
/// Implementations run under the `Cx` supplied to
/// [`AuthorizedTaskServiceRunner::run`]. They should treat a repeated call
/// after a service restart as at-least-once recovery and make external effects
/// idempotent. They cannot construct or clone the runner, inspect its queue,
/// or bypass the durable handoff. Once `tasks/cancel` wins for an elected
/// handoff, the runner wakes it and records terminal cancellation under the
/// same fence. A supervisor can record a custom cancellation status only if
/// it observes and honours that winner before the runner's next poll boundary.
pub trait ApplicationTaskSupervisor: Send + Sync {
    /// Begins or resumes one operation after its durable handoff is claimed.
    fn resume<'a>(
        &'a self,
        cx: &'a Cx,
        handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a>;
}

const MAX_FINAL_TASK_RECOVERY_HANDOFFS_PER_SCAN: usize = 64;
const MAX_FINAL_TASK_RECOVERY_CAS_RETRIES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FinalTaskRecoveryKind {
    Initial,
    Resumed,
}

impl FinalTaskRecoveryKind {
    const fn other(self) -> Self {
        match self {
            Self::Initial => Self::Resumed,
            Self::Resumed => Self::Initial,
        }
    }
}

#[cfg(test)]
const FINAL_TASK_TEST_DIRECT_OWNER: &str = "final-task-test-direct-owner";

struct FinalTaskServiceSignal {
    /// Monotonically unique ownership generation for the sole installed
    /// runner. It fences both readiness publication and revocation.
    service_id: u64,
    sender: Sender<FinalTaskId>,
    /// The runner generation that has passed its entry checkpoint and still
    /// owns the live readiness lease. `None` means installation has not yet
    /// entered a runnable service, or that service has exited.
    ready_generation: Option<u64>,
    /// A direct wake path for the one supervisor handoff currently running in
    /// this service generation. The durable store remains the cancellation
    /// authority; this merely makes a newly-recorded cancellation observable
    /// without waiting for the dispatch-lease heartbeat.
    cancellation_wake: Arc<FinalTaskCancellationWake>,
}

/// Per-runner wake registration for an elected application handoff.
///
/// There is only one non-cloneable runner per service generation, so it can
/// execute only one supervisor handoff at once. Keeping the task ID and last
/// task waker together prevents a cancellation for another durable task from
/// spuriously polling the active supervisor. The durable cancellation record
/// remains the source of truth and closes the registration-vs-cancel race.
#[derive(Default)]
struct FinalTaskCancellationWake {
    state: Mutex<FinalTaskCancellationWakeState>,
}

#[derive(Default)]
struct FinalTaskCancellationWakeState {
    active_task_id: Option<FinalTaskId>,
    waker: Option<std::task::Waker>,
}

/// RAII registration that makes an elected handoff immediately wakeable by
/// `tasks/cancel`. Dropping it clears only its matching task ID, so a stale
/// future cannot unregister a later handoff.
struct FinalTaskCancellationWakeRegistration {
    wake: Arc<FinalTaskCancellationWake>,
    task_id: FinalTaskId,
}

impl FinalTaskCancellationWake {
    fn activate(
        self: &Arc<Self>,
        task_id: &FinalTaskId,
    ) -> McpResult<FinalTaskCancellationWakeRegistration> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active_task_id.is_some() {
            return Err(McpError::internal_error(
                "Task service attempted to execute concurrent supervisor handoffs",
            ));
        }
        state.active_task_id = Some(task_id.clone());
        state.waker = None;
        Ok(FinalTaskCancellationWakeRegistration {
            wake: Arc::clone(self),
            task_id: task_id.clone(),
        })
    }

    fn register_waker(&self, task_id: &FinalTaskId, waker: &std::task::Waker) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active_task_id.as_ref() == Some(task_id) {
            state.waker = Some(waker.clone());
        }
    }

    fn wake_if_active(&self, task_id: &FinalTaskId) {
        let waker = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (state.active_task_id.as_ref() == Some(task_id))
                .then(|| state.waker.clone())
                .flatten()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl FinalTaskCancellationWakeRegistration {
    fn register_waker(&self, waker: &std::task::Waker) {
        self.wake.register_waker(&self.task_id, waker);
    }
}

impl Drop for FinalTaskCancellationWakeRegistration {
    fn drop(&mut self) {
        let mut state = self
            .wake
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active_task_id.as_ref() == Some(&self.task_id) {
            state.active_task_id = None;
            state.waker = None;
        }
    }
}

/// RAII proof that one entered task-service runner still owns readiness.
///
/// The proof is intentionally local to [`AuthorizedTaskServiceRunner::run`]:
/// dropping or cancelling that future revokes readiness under the same mutex
/// that creation uses for its read-only readiness probe.
struct FinalTaskServiceReadinessLease {
    runtime: FinalTaskRuntime,
    service_id: u64,
    ready_generation: u64,
}

/// Non-cloneable framework handle for a caller-owned application Task service.
///
/// Only [`FinalTaskRuntime::install_task_service`] can construct this type.
/// It is intentionally not cloneable: one runner owns one bounded wakeup
/// receiver, while the durable store remains the recovery authority when a
/// wakeup is missed, coalesced, or its service generation exits. Its
/// [`run_service`](Self::run_service) method borrows the handle so an
/// application supervisor can retain it across a failed or cancelled service
/// invocation and explicitly re-enter durable recovery.
pub struct AuthorizedTaskServiceRunner {
    runtime: FinalTaskRuntime,
    service_id: u64,
    dispatch_owner: String,
    receiver: Receiver<FinalTaskId>,
    supervisor: Arc<dyn ApplicationTaskSupervisor>,
    next_recovery_kind: FinalTaskRecoveryKind,
    initial_recovery_cursor: Option<FinalTaskId>,
    accepted_recovery_cursor: Option<FinalTaskId>,
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
    service_signal: Arc<Mutex<Option<FinalTaskServiceSignal>>>,
    next_task_service_id: Arc<AtomicU64>,
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
            service_signal: Arc::new(Mutex::new(None)),
            next_task_service_id: Arc::new(AtomicU64::new(0)),
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

    /// Reserves one bounded wakeup channel for a caller-owned structured Task
    /// service and returns its non-cloneable runner.
    ///
    /// The caller must run the returned runner in an application-lifetime
    /// asupersync region with [`AuthorizedTaskServiceRunner::run_service`]. A
    /// full wakeup queue deliberately does not reject a durable transition:
    /// the runner rescans the store's accepted-input handoffs after every
    /// wakeup and when it starts, so the store rather than this process-local
    /// signal remains authoritative for recovery. Installation alone is not a
    /// ready creation authority; readiness begins only when
    /// `runner.run_service` is polled.
    pub fn install_task_service(
        &self,
        queue_capacity: usize,
        supervisor: Arc<dyn ApplicationTaskSupervisor>,
    ) -> McpResult<AuthorizedTaskServiceRunner> {
        if queue_capacity == 0 {
            return Err(McpError::invalid_params(
                "Task service queue capacity must be positive",
            ));
        }
        let service_id = self
            .next_task_service_id
            .try_update(
                TaskServiceOrdering::Relaxed,
                TaskServiceOrdering::Relaxed,
                |current| current.checked_add(1),
            )
            .map_err(|_| McpError::internal_error("Task service generation space is exhausted"))?
            .checked_add(1)
            .ok_or_else(|| {
                McpError::internal_error("Task service generation space is exhausted")
            })?;
        let (sender, receiver) = mpsc::channel(queue_capacity);
        #[cfg(test)]
        let dispatch_owner = FINAL_TASK_TEST_DIRECT_OWNER.to_owned();
        #[cfg(not(test))]
        let dispatch_owner = generate_final_task_dispatch_owner()?;
        let mut signal = self
            .service_signal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if signal.is_some() {
            return Err(McpError::invalid_params(
                "A task service is already installed for this runtime",
            ));
        }
        *signal = Some(FinalTaskServiceSignal {
            service_id,
            sender,
            // Installation reserves the one non-cloneable receiver, but only
            // an entered `runner.run_service` that holds its readiness lease
            // establishes the ready creation authority.
            ready_generation: None,
            cancellation_wake: Arc::new(FinalTaskCancellationWake::default()),
        });
        Ok(AuthorizedTaskServiceRunner {
            runtime: self.clone(),
            service_id,
            dispatch_owner,
            receiver,
            supervisor,
            next_recovery_kind: FinalTaskRecoveryKind::Initial,
            initial_recovery_cursor: None,
            accepted_recovery_cursor: None,
        })
    }

    /// Takes the validated inputs for a task that has returned to `working`.
    ///
    /// A task supervisor calls this after observing the task's resumed state.
    /// Input values remain private durable-store state rather than leaking
    /// through a task snapshot or `notifications/tasks`. The store atomically
    /// verifies the exact current `working` generation and removes the handoff,
    /// so a stale or second worker cannot replay another worker's inputs.
    #[cfg(test)]
    fn take_accepted_input(
        &self,
        task_id: &FinalTaskId,
    ) -> McpResult<Option<FinalTaskAcceptedInput>> {
        let current = self.load_task_snapshot(task_id)?;
        let claim = self
            .store
            .take_input_handoff_for_owner_if_current(&current, FINAL_TASK_TEST_DIRECT_OWNER)?;
        claim
            .map(|claim| {
                self.validate_accepted_input_claim(&current, FINAL_TASK_TEST_DIRECT_OWNER, claim)
            })
            .transpose()
    }

    /// Atomically recovers one durably accepted input handoff for a newly
    /// installed service generation.
    ///
    /// This intentionally does not infer recoverability from ordinary task
    /// reads. The store returns a compare-and-swap candidate and the runtime
    /// consumes it only if that exact `working` generation is still current.
    /// A stale candidate therefore has no side effect and can never replay a
    /// terminal transition.
    #[cfg(test)]
    fn recover_accepted_input(&self) -> McpResult<Option<FinalTaskAcceptedInput>> {
        for _ in 0..MAX_FINAL_TASK_RECOVERY_CAS_RETRIES {
            let Some(candidate) = self.store.next_accepted_input_snapshot_after(None)? else {
                return Ok(None);
            };
            let candidate = self.validate_loaded_task_snapshot(candidate, None)?;
            let task_id = candidate.task().base().task_id.clone();
            if !matches!(candidate.task(), FinalTask::Working(_)) {
                return Err(McpError::internal_error(
                    "Final task store returned a non-working accepted-input recovery candidate",
                ));
            }
            let Some(claim) = self.store.take_input_handoff_for_owner_if_current(
                &candidate,
                FINAL_TASK_TEST_DIRECT_OWNER,
            )?
            else {
                continue;
            };
            let handoff = self.validate_accepted_input_claim(
                &candidate,
                FINAL_TASK_TEST_DIRECT_OWNER,
                claim,
            )?;
            debug_assert_eq!(handoff.task_id(), &task_id);
            return Ok(Some(handoff));
        }
        Err(McpError::internal_error(
            "Accepted-input recovery exceeded bounded lost-CAS retries",
        ))
    }

    /// Service-only accepted-input recovery with a cancellation checkpoint
    /// directly before every durable handoff claim.
    fn recover_accepted_input_with_checkpoints(
        &self,
        cx: &Cx,
        owner_id: &str,
        after_task_id: Option<&FinalTaskId>,
    ) -> McpResult<Option<FinalTaskAcceptedInput>> {
        for _ in 0..MAX_FINAL_TASK_RECOVERY_CAS_RETRIES {
            cx.checkpoint()
                .map_err(|error| McpError::internal_error(error.to_string()))?;
            let Some(candidate) = self
                .store
                .next_accepted_input_snapshot_after(after_task_id)?
            else {
                return Ok(None);
            };
            let candidate = self.validate_loaded_task_snapshot(candidate, None)?;
            if !matches!(candidate.task(), FinalTask::Working(_)) {
                return Err(McpError::internal_error(
                    "Final task store returned a non-working accepted-input recovery candidate",
                ));
            }
            cx.checkpoint()
                .map_err(|error| McpError::internal_error(error.to_string()))?;
            let Some(claim) = self
                .store
                .take_input_handoff_for_owner_if_current(&candidate, owner_id)?
            else {
                continue;
            };
            return self
                .validate_accepted_input_claim(&candidate, owner_id, claim)
                .map(Some);
        }
        Err(McpError::internal_error(
            "Accepted-input recovery exceeded bounded lost-CAS retries",
        ))
    }

    /// Atomically recovers one initial task operation that has never reached
    /// the application supervisor.
    #[cfg(test)]
    fn recover_initial_work(&self) -> McpResult<Option<FinalTaskInitialWork>> {
        for _ in 0..MAX_FINAL_TASK_RECOVERY_CAS_RETRIES {
            let Some(candidate) = self.store.next_initial_work_snapshot_after(None)? else {
                return Ok(None);
            };
            let candidate = self.validate_loaded_task_snapshot(candidate, None)?;
            if !matches!(candidate.task(), FinalTask::Working(_)) {
                return Err(McpError::internal_error(
                    "Final task store returned a non-working initial-work recovery candidate",
                ));
            }
            let task_id = candidate.task().base().task_id.clone();
            let Some(claim) = self.store.take_initial_work_handoff_for_owner_if_current(
                &candidate,
                FINAL_TASK_TEST_DIRECT_OWNER,
            )?
            else {
                continue;
            };
            let handoff =
                self.validate_initial_work_claim(&candidate, FINAL_TASK_TEST_DIRECT_OWNER, claim)?;
            debug_assert_eq!(handoff.task_id(), &task_id);
            return Ok(Some(handoff));
        }
        Err(McpError::internal_error(
            "Initial-work recovery exceeded bounded lost-CAS retries",
        ))
    }

    /// Service-only initial-work recovery with a cancellation checkpoint
    /// directly before every durable work claim.
    fn recover_initial_work_with_checkpoints(
        &self,
        cx: &Cx,
        owner_id: &str,
        after_task_id: Option<&FinalTaskId>,
    ) -> McpResult<Option<FinalTaskInitialWork>> {
        for _ in 0..MAX_FINAL_TASK_RECOVERY_CAS_RETRIES {
            cx.checkpoint()
                .map_err(|error| McpError::internal_error(error.to_string()))?;
            let Some(candidate) = self.store.next_initial_work_snapshot_after(after_task_id)?
            else {
                return Ok(None);
            };
            let candidate = self.validate_loaded_task_snapshot(candidate, None)?;
            if !matches!(candidate.task(), FinalTask::Working(_)) {
                return Err(McpError::internal_error(
                    "Final task store returned a non-working initial-work recovery candidate",
                ));
            }
            cx.checkpoint()
                .map_err(|error| McpError::internal_error(error.to_string()))?;
            let Some(claim) = self
                .store
                .take_initial_work_handoff_for_owner_if_current(&candidate, owner_id)?
            else {
                continue;
            };
            return self
                .validate_initial_work_claim(&candidate, owner_id, claim)
                .map(Some);
        }
        Err(McpError::internal_error(
            "Initial-work recovery exceeded bounded lost-CAS retries",
        ))
    }

    fn take_initial_work_with_checkpoint(
        &self,
        cx: &Cx,
        task_id: &FinalTaskId,
        owner_id: &str,
    ) -> McpResult<Option<FinalTaskInitialWork>> {
        let current = self.load_task_snapshot(task_id)?;
        cx.checkpoint()
            .map_err(|error| McpError::internal_error(error.to_string()))?;
        let claim = self
            .store
            .take_initial_work_handoff_for_owner_if_current(&current, owner_id)?;
        claim
            .map(|claim| self.validate_initial_work_claim(&current, owner_id, claim))
            .transpose()
    }

    fn take_accepted_input_with_checkpoint(
        &self,
        cx: &Cx,
        task_id: &FinalTaskId,
        owner_id: &str,
    ) -> McpResult<Option<FinalTaskAcceptedInput>> {
        let current = self.load_task_snapshot(task_id)?;
        cx.checkpoint()
            .map_err(|error| McpError::internal_error(error.to_string()))?;
        let claim = self
            .store
            .take_input_handoff_for_owner_if_current(&current, owner_id)?;
        claim
            .map(|claim| self.validate_accepted_input_claim(&current, owner_id, claim))
            .transpose()
    }

    /// Refuses bare Tasks because no originating application work can be
    /// recovered or executed from them.
    pub fn create_task(&self, _status_message: Option<String>) -> McpResult<CreateTaskResult> {
        Err(McpError::invalid_params(
            "Final task creation requires an opaque application work descriptor",
        ))
    }

    /// Durably binds an initial `working` task to caller-owned application
    /// work before advertising it to an MCP client.
    pub fn create_task_with_work(
        &self,
        work_descriptor: FinalTaskWorkDescriptor,
        status_message: Option<String>,
    ) -> McpResult<CreateTaskResult> {
        let task_id = generate_final_task_id()?;
        let now = final_task_timestamp()?;
        let task = FinalTask::Working(FinalTaskBase {
            task_id,
            status: FinalTaskStatus::Working,
            status_message,
            created_at: now.clone(),
            last_updated_at: now,
            ttl_ms: self.config.ttl_ms.map(final_task_duration).transpose()?,
            poll_interval_ms: self
                .config
                .poll_interval_ms
                .map(final_task_duration)
                .transpose()?,
        });
        self.persist_new_with_work_while_service_ready(task.clone(), work_descriptor)?;
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

    fn fenced_require_input(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: u64,
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
        if current.generation() != generation {
            return Err(stale_final_task_handoff_error());
        }
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
        self.persist_fenced_handoff_transition_clearing_input(
            &current,
            owner_id,
            dispatch_fence,
            false,
            task.clone(),
        )?;
        Ok(task)
    }

    fn fenced_complete_task(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: u64,
        result: FinalTaskCallToolResult,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        let current = self.load_task_snapshot(task_id)?;
        if current.generation() != generation {
            return Err(stale_final_task_handoff_error());
        }
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
        self.persist_fenced_handoff_transition_clearing_input(
            &current,
            owner_id,
            dispatch_fence,
            false,
            task.clone(),
        )?;
        Ok(task)
    }

    fn fenced_fail_task(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: u64,
        error: FinalTaskError,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        let current = self.load_task_snapshot(task_id)?;
        if current.generation() != generation {
            return Err(stale_final_task_handoff_error());
        }
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
        self.persist_fenced_handoff_transition_clearing_input(
            &current,
            owner_id,
            dispatch_fence,
            false,
            task.clone(),
        )?;
        Ok(task)
    }

    fn fenced_honor_cancellation(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: u64,
        status_message: Option<String>,
    ) -> McpResult<FinalTask> {
        let current = self.load_task_snapshot(task_id)?;
        if current.generation() != generation {
            return Err(stale_final_task_handoff_error());
        }
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
        self.persist_fenced_handoff_transition_clearing_input(
            &current,
            owner_id,
            dispatch_fence,
            true,
            task.clone(),
        )?;
        Ok(task)
    }

    fn fenced_cancellation_requested(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
    ) -> McpResult<bool> {
        let current = self.load_task_snapshot(task_id)?;
        if current.generation() != generation {
            return Err(stale_final_task_handoff_error());
        }
        self.store.is_cancellation_requested(task_id)
    }

    /// Enters `input_required` with typed final embedded requests.
    #[cfg(test)]
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
        self.persist_transition_clearing_input(&current, task.clone())?;
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
        // The protocol permits replayed/already-satisfied and unknown keys.
        // Retain only the keys still outstanding before type validation so an
        // ignored key can neither fail a valid update nor create a durable
        // notification, generation, or worker handoff mutation.
        let outstanding_responses = input_responses
            .iter()
            .filter(|(key, _)| input_requests.contains_key(*key))
            .map(|(key, response)| (key.clone(), response.clone()))
            .collect::<FinalTaskInputResponses>();
        if outstanding_responses.is_empty() {
            return Ok(UpdateTaskResult::default());
        }
        ledger
            .validate_responses(&outstanding_responses)
            .map_err(|error| McpError::invalid_params(error.to_string()))?;
        for key in outstanding_responses.keys() {
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
        self.persist_transition_appending_input(&current, task, outstanding_responses)?;
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
        let cancelled_task = FinalTask::Cancelled(transition_terminal_final_task_base(
            current.task().base().clone(),
            FinalTaskStatus::Cancelled,
            None,
        )?);
        let cancelled_notification = final_task_notification(&cancelled_task);
        self.validate_task_transition_write(&current, &cancelled_task, &cancelled_notification)?;
        let cancellation = self.store.request_cancellation_and_clear_input_if_current(
            &current,
            cancelled_task.clone(),
            cancelled_notification.clone(),
        )?;
        let Some(cancellation) = cancellation else {
            return Err(McpError::invalid_params(
                "Task state changed before cancellation could be recorded",
            ));
        };
        let cancellation = self.validate_loaded_task_snapshot(cancellation, Some(task_id))?;
        let terminal_cancellation =
            self.validate_cancellation_store_result(&current, &cancelled_task, cancellation)?;
        if terminal_cancellation {
            self.emit(cancelled_notification);
        }
        self.signal_task_service_cancellation(task_id.clone());
        Ok(FinalCancelTaskResult::default())
    }

    /// Ensures cancellation's store result is either the unchanged exact
    /// elected snapshot or the exact terminal cancellation proposed by this
    /// runtime. A permissive backend must not substitute another active or
    /// terminal task after winning the cancellation compare-and-swap.
    fn validate_cancellation_store_result(
        &self,
        expected: &FinalTaskSnapshot,
        cancelled_task: &FinalTask,
        returned: FinalTaskSnapshot,
    ) -> McpResult<bool> {
        let terminal = match returned.task() {
            FinalTask::Cancelled(_) => {
                validate_final_task_transition(expected.task(), returned.task()).map_err(|_| {
                    McpError::internal_error(
                        "Final task store returned an invalid terminal cancellation transition",
                    )
                })?;
                if returned.generation() == expected.generation()
                    || !final_tasks_match_exactly(returned.task(), cancelled_task)?
                {
                    return Err(McpError::internal_error(
                        "Final task store substituted the intended terminal cancellation",
                    ));
                }
                true
            }
            FinalTask::Working(_) => {
                if returned.generation() != expected.generation()
                    || !final_tasks_match_exactly(returned.task(), expected.task())?
                    || !self
                        .store
                        .is_cancellation_requested(&expected.task().base().task_id)?
                {
                    return Err(McpError::internal_error(
                        "Final task store returned a substituted active cancellation snapshot",
                    ));
                }
                false
            }
            _ => {
                return Err(McpError::internal_error(
                    "Final task store returned a non-working active cancellation snapshot",
                ));
            }
        };
        let committed = self.load_task_snapshot(&expected.task().base().task_id)?;
        if committed.generation() != returned.generation()
            || !final_tasks_match_exactly(committed.task(), returned.task())?
        {
            return Err(McpError::internal_error(
                "Final task store returned cancellation data that is not durably retained",
            ));
        }
        Ok(terminal)
    }

    /// Returns durable cancellation intent for a caller-owned task worker.
    pub fn is_cancellation_requested(&self, task_id: &FinalTaskId) -> McpResult<bool> {
        self.store.is_cancellation_requested(task_id)
    }

    /// Lets a caller-owned worker record the cooperative cancellation outcome.
    #[cfg(test)]
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
        self.persist_transition_clearing_input(&current, task.clone())?;
        Ok(task)
    }

    /// Records a typed final tools/call result for a working task.
    #[cfg(test)]
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
        self.persist_transition_clearing_input(&current, task.clone())?;
        Ok(task)
    }

    /// Records a typed final task failure for an active task.
    #[cfg(test)]
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
        self.persist_transition_clearing_input(&current, task.clone())?;
        Ok(task)
    }

    fn load_task_snapshot(&self, task_id: &FinalTaskId) -> McpResult<FinalTaskSnapshot> {
        let snapshot = self
            .store
            .get_task_snapshot(task_id)?
            .ok_or_else(|| McpError::invalid_params("Task not found"))?;
        self.validate_loaded_task_snapshot(snapshot, Some(task_id))
    }

    /// Admits task data returned by any durable-store implementation before
    /// runtime code can branch on its status or hand it to a worker.
    fn validate_loaded_task_snapshot(
        &self,
        snapshot: FinalTaskSnapshot,
        expected_task_id: Option<&FinalTaskId>,
    ) -> McpResult<FinalTaskSnapshot> {
        validate_final_task_storage_shape(snapshot.task()).map_err(|error| {
            McpError::internal_error(format!(
                "Final task store returned an invalid durable task shape: {}",
                error.message
            ))
        })?;
        validate_final_task_runtime_durations(snapshot.task()).map_err(|error| {
            McpError::internal_error(format!(
                "Final task store returned a task with an invalid runtime duration: {}",
                error.message
            ))
        })?;
        if let Some(expected_task_id) = expected_task_id
            && &snapshot.task().base().task_id != expected_task_id
        {
            return Err(McpError::internal_error(
                "Final task store returned a task under the wrong identifier",
            ));
        }
        Ok(snapshot)
    }

    /// Validates a store-returned initial-work claim before application code
    /// can observe its descriptor.
    fn validate_initial_work_claim(
        &self,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
        claim: FinalTaskInitialWorkClaim,
    ) -> McpResult<FinalTaskInitialWork> {
        validate_final_task_handoff_binding(
            expected,
            owner_id,
            &claim.task_id,
            claim.generation,
            &claim.owner_id,
            "initial-work",
        )?;
        validate_final_task_work_descriptor(&claim.work_descriptor)?;
        self.validate_claim_snapshot_still_current(expected)?;
        Ok(FinalTaskInitialWork {
            task_id: claim.task_id,
            generation: claim.generation,
            work_descriptor: claim.work_descriptor,
            authority: None,
        })
    }

    /// Validates a store-returned accepted-input claim before application code
    /// can observe either the originating descriptor or private input map.
    fn validate_accepted_input_claim(
        &self,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
        claim: FinalTaskAcceptedInputClaim,
    ) -> McpResult<FinalTaskAcceptedInput> {
        validate_final_task_handoff_binding(
            expected,
            owner_id,
            &claim.task_id,
            claim.generation,
            &claim.owner_id,
            "accepted-input",
        )?;
        validate_final_task_work_descriptor(&claim.work_descriptor)?;
        if claim.input_responses.is_empty() {
            return Err(McpError::internal_error(
                "Final task store returned an empty accepted-input handoff",
            ));
        }
        self.validate_claim_snapshot_still_current(expected)?;
        Ok(FinalTaskAcceptedInput {
            task_id: claim.task_id,
            generation: claim.generation,
            work_descriptor: claim.work_descriptor,
            input_responses: claim.input_responses,
            authority: None,
        })
    }

    /// Re-reads the durable record after a handoff claim so even a legacy
    /// claim implementation cannot pass work to the application after its
    /// expected active generation has changed.
    fn validate_claim_snapshot_still_current(&self, expected: &FinalTaskSnapshot) -> McpResult<()> {
        let current = self.load_task_snapshot(&expected.task().base().task_id)?;
        if current.generation() != expected.generation()
            || !final_tasks_match_exactly(current.task(), expected.task())?
        {
            return Err(McpError::internal_error(
                "Final task store changed the claimed task before application handoff",
            ));
        }
        Ok(())
    }

    /// Checks the store's post-commit value before observers can treat a
    /// successful compare-and-swap as an application-visible transition.
    fn validate_committed_transition(
        &self,
        expected: &FinalTaskSnapshot,
        intended: &FinalTask,
    ) -> McpResult<()> {
        let committed = self.load_task_snapshot(&intended.base().task_id)?;
        validate_final_task_transition(expected.task(), committed.task()).map_err(|_| {
            McpError::internal_error(
                "Final task store committed an invalid durable task transition",
            )
        })?;
        if committed.generation() == expected.generation()
            || !final_tasks_match_exactly(committed.task(), intended)?
        {
            return Err(McpError::internal_error(
                "Final task store substituted a durable task transition",
            ));
        }
        Ok(())
    }

    /// Checks the store's create-before-reply value before publishing a task
    /// handle or observer notification.
    fn validate_committed_new_task(&self, intended: &FinalTask) -> McpResult<()> {
        let committed = self.load_task_snapshot(&intended.base().task_id)?;
        if !final_tasks_match_exactly(committed.task(), intended)? {
            return Err(McpError::internal_error(
                "Final task store substituted a newly created durable task",
            ));
        }
        Ok(())
    }

    /// Validates a new task immediately before its durable create boundary.
    fn validate_new_task_write(
        &self,
        task: &FinalTask,
        notification: &FinalTaskStatusNotification,
    ) -> McpResult<()> {
        validate_final_task_storage_shape(task)?;
        ensure_final_task_notification_matches_task(task, notification)?;
        validate_final_task_runtime_durations(task)
    }

    /// Validates a replacement immediately before an atomic durable write.
    fn validate_task_transition_write(
        &self,
        expected: &FinalTaskSnapshot,
        task: &FinalTask,
        notification: &FinalTaskStatusNotification,
    ) -> McpResult<()> {
        self.validate_new_task_write(task, notification)?;
        validate_final_task_transition(expected.task(), task)
    }

    fn persist_new_with_work(
        &self,
        task: FinalTask,
        work_descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<()> {
        let task_id = task.base().task_id.clone();
        let notification = final_task_notification(&task);
        self.validate_new_task_write(&task, &notification)?;
        validate_final_task_work_descriptor(&work_descriptor)?;
        self.store
            .create_task_with_work(task.clone(), notification.clone(), work_descriptor)?;
        self.validate_committed_new_task(&task)?;
        // Creation has crossed the durable create-before-reply boundary. A
        // post-commit observer failure must never erase the client handle by
        // turning this accepted operation into an RPC error.
        self.emit(notification);
        self.signal_task_service(task_id);
        Ok(())
    }

    /// Persists a publicly created task while its exact ready service
    /// generation is still live.
    ///
    /// A readiness probe followed by an independent durable write would be a
    /// TOCTOU boundary: a runner could exit after the probe but before a
    /// caller receives an accepted task handle. Holding the signal lock only
    /// through the synchronous store commit makes runner teardown wait until
    /// the task is recoverable by the generation that authorized it. Delivery
    /// and best-effort wakeup remain outside that lock.
    fn persist_new_with_work_while_service_ready(
        &self,
        task: FinalTask,
        work_descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<()> {
        let task_id = task.base().task_id.clone();
        let notification = final_task_notification(&task);
        self.validate_new_task_write(&task, &notification)?;
        validate_final_task_work_descriptor(&work_descriptor)?;
        {
            let signal = self
                .service_signal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !Self::task_service_is_ready(signal.as_ref()) {
                return Err(McpError::invalid_params(
                    "Final task creation requires an installed ready task service",
                ));
            }
            self.store.create_task_with_work(
                task.clone(),
                notification.clone(),
                work_descriptor,
            )?;
        }
        self.validate_committed_new_task(&task)?;
        // The durable commit above is the acceptance point. Observer failures
        // cannot revoke the returned task handle.
        self.emit(notification);
        self.signal_task_service(task_id);
        Ok(())
    }

    fn persist_transition_appending_input(
        &self,
        expected: &FinalTaskSnapshot,
        task: FinalTask,
        input_responses: FinalTaskInputResponses,
    ) -> McpResult<()> {
        let wakeup_task_id = match &task {
            FinalTask::Working(base) => Some(base.task_id.clone()),
            _ => None,
        };
        let notification = final_task_notification(&task);
        self.validate_task_transition_write(expected, &task, &notification)?;
        if !self.store.replace_task_and_append_input_if_current(
            expected,
            task.clone(),
            notification.clone(),
            input_responses,
        )? {
            return Err(McpError::invalid_params(
                "Task state changed before the transition could be recorded",
            ));
        }
        self.validate_committed_transition(expected, &task)?;
        self.emit(notification);
        if let Some(task_id) = wakeup_task_id {
            self.signal_task_service(task_id);
        }
        Ok(())
    }

    fn persist_transition_clearing_input(
        &self,
        expected: &FinalTaskSnapshot,
        task: FinalTask,
    ) -> McpResult<()> {
        let notification = final_task_notification(&task);
        self.validate_task_transition_write(expected, &task, &notification)?;
        if !self.store.replace_task_and_clear_input_if_current(
            expected,
            task.clone(),
            notification.clone(),
        )? {
            return Err(McpError::invalid_params(
                "Task state changed before the transition could be recorded",
            ));
        }
        self.validate_committed_transition(expected, &task)?;
        self.emit(notification);
        Ok(())
    }

    fn persist_fenced_handoff_transition_clearing_input(
        &self,
        expected: &FinalTaskSnapshot,
        owner_id: &str,
        dispatch_fence: u64,
        cancellation_required: bool,
        task: FinalTask,
    ) -> McpResult<()> {
        let notification = final_task_notification(&task);
        self.validate_task_transition_write(expected, &task, &notification)?;
        if !self
            .store
            .replace_task_and_clear_input_for_handoff_if_current(
                expected,
                owner_id,
                dispatch_fence,
                cancellation_required,
                task.clone(),
                notification.clone(),
            )?
        {
            return Err(stale_final_task_handoff_error());
        }
        self.validate_committed_transition(expected, &task)?;
        self.emit(notification);
        Ok(())
    }

    /// Delivers a durable notification to every observer after the store
    /// mutation. A panic from one observer is contained and recorded as
    /// delivery degradation; it cannot revoke the already-committed state or
    /// turn the accepted transition into an RPC error.
    fn emit(&self, notification: FinalTaskStatusNotification) {
        let emitters = self
            .notification_emitters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut panicked_emitter_count = 0usize;
        for emitter in emitters {
            if catch_unwind(AssertUnwindSafe(|| emitter(notification.clone()))).is_err() {
                panicked_emitter_count += 1;
            }
        }
        if panicked_emitter_count != 0 {
            log::error!(
                target: "fastmcp_rust::server",
                "Final Task notification delivery degraded after durable mutation; panicked_emitter_count={}",
                panicked_emitter_count
            );
        }
    }

    fn restore_accepted_input(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: Option<u64>,
        input_responses: FinalTaskInputResponses,
    ) -> McpResult<bool> {
        self.store.restore_input_for_owner_if_current(
            task_id,
            generation,
            owner_id,
            dispatch_fence,
            input_responses,
        )
    }

    fn restore_initial_work(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: Option<u64>,
        work_descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<bool> {
        self.store.restore_initial_work_for_owner_if_current(
            task_id,
            generation,
            owner_id,
            dispatch_fence,
            work_descriptor,
        )
    }

    fn begin_handoff_dispatch(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
    ) -> McpResult<Option<u64>> {
        self.store
            .begin_handoff_dispatch_for_owner_if_current(task_id, generation, owner_id)
    }

    fn renew_handoff_dispatch(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: u64,
    ) -> McpResult<bool> {
        self.store
            .renew_handoff_dispatch_if_current(task_id, generation, owner_id, dispatch_fence)
    }

    fn handoff_dispatch_lease_heartbeat_interval(&self) -> McpResult<StdDuration> {
        let interval = self.store.handoff_dispatch_lease_heartbeat_interval()?;
        if interval.is_zero() {
            return Err(McpError::internal_error(
                "Final task store returned a zero dispatch lease heartbeat interval",
            ));
        }
        Ok(interval)
    }

    fn finish_handoff_dispatch(
        &self,
        task_id: &FinalTaskId,
        generation: u64,
        owner_id: &str,
        dispatch_fence: u64,
    ) -> McpResult<bool> {
        self.store.finish_handoff_dispatch_for_owner_if_current(
            task_id,
            generation,
            owner_id,
            dispatch_fence,
        )
    }

    /// Verifies, without mutation, that a live entered task-service runner
    /// currently owns this runtime's readiness generation.
    ///
    /// This is the public readiness observation for an application-owned
    /// task-service region. It becomes true only after a runner has passed its
    /// entry checkpoint and keeps its exact readiness lease alive. Merely
    /// installing a runner, retaining a runtime clone, or retaining durable
    /// work is not readiness.
    ///
    /// The result is observational only: it cannot install, start, stop, or
    /// wake a runner. Creation still takes the same lock through the durable
    /// create boundary, so callers must not use this observation as a
    /// substitute for the framework's fail-closed creation check.
    #[must_use]
    pub fn is_task_service_ready(&self) -> bool {
        let signal = self
            .service_signal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::task_service_is_ready(signal.as_ref())
    }

    /// Verifies, without mutation, that a live entered task-service runner
    /// currently owns this runtime's readiness generation.
    ///
    /// Router integration uses this before accepting a Task-creating request.
    /// It preserves the public observation's semantics while returning the
    /// protocol-facing fail-closed error.
    pub(crate) fn ensure_task_service_ready(&self) -> McpResult<()> {
        if !self.is_task_service_ready() {
            return Err(McpError::invalid_params(
                "Final task creation requires an installed ready task service",
            ));
        }
        Ok(())
    }

    fn task_service_is_ready(service: Option<&FinalTaskServiceSignal>) -> bool {
        service.is_some_and(|service| {
            service.ready_generation == Some(service.service_id) && !service.sender.is_closed()
        })
    }

    /// Elects readiness only for a runner that has already passed its entry
    /// checkpoint, returning the live lease that keeps the exact generation
    /// eligible for task creation.
    fn mark_task_service_ready(
        &self,
        service_id: u64,
    ) -> McpResult<FinalTaskServiceReadinessLease> {
        let mut signal = self
            .service_signal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(service) = signal.as_mut() else {
            return Err(McpError::internal_error(
                "Task service runner has no installed wakeup authority",
            ));
        };
        if service.service_id != service_id {
            return Err(McpError::internal_error(
                "A stale task service runner cannot establish readiness",
            ));
        }
        if service.sender.is_closed() {
            *signal = None;
            return Err(McpError::internal_error(
                "Task service wakeup authority closed before runner start",
            ));
        }
        if service.ready_generation.is_some() {
            return Err(McpError::internal_error(
                "Task service readiness is already owned by a live runner",
            ));
        }
        // `service_id` is allocated monotonically at installation. Recording
        // it while returning the RAII lease makes the creation probe and the
        // live runner's ownership one mutex-protected generation election.
        service.ready_generation = Some(service_id);
        Ok(FinalTaskServiceReadinessLease {
            runtime: self.clone(),
            service_id,
            ready_generation: service_id,
        })
    }

    fn signal_task_service(&self, task_id: FinalTaskId) {
        let mut signal = self
            .service_signal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(service) = signal.as_ref() else {
            return;
        };
        if service.sender.try_send(task_id).is_err() && service.sender.is_closed() {
            // A completed or cancelled runner releases this process-local
            // signal. The durable accepted-input record stays untouched for a
            // later service generation to recover.
            *signal = None;
        }
    }

    /// Wakes a live elected handoff after cancellation has committed, while
    /// retaining the ordinary durable-store wakeup for unelected work and
    /// restart recovery. The registration is advisory only: the subsequent
    /// fenced store read decides whether cancellation actually won.
    fn signal_task_service_cancellation(&self, task_id: FinalTaskId) {
        let cancellation_wake = self
            .service_signal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|service| Arc::clone(&service.cancellation_wake));
        self.signal_task_service(task_id.clone());
        if let Some(cancellation_wake) = cancellation_wake {
            cancellation_wake.wake_if_active(&task_id);
        }
    }

    fn register_task_cancellation_wake(
        &self,
        service_id: u64,
        task_id: &FinalTaskId,
    ) -> McpResult<FinalTaskCancellationWakeRegistration> {
        let cancellation_wake = {
            let signal = self
                .service_signal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let service = signal.as_ref().ok_or_else(|| {
                McpError::internal_error("Task service runner lost its cancellation wake authority")
            })?;
            if service.service_id != service_id {
                return Err(McpError::internal_error(
                    "A stale task service runner cannot register cancellation wakeups",
                ));
            }
            Arc::clone(&service.cancellation_wake)
        };
        cancellation_wake.activate(task_id)
    }
}

impl AuthorizedTaskServiceRunner {
    /// Runs the service once, consuming this one-shot runner.
    ///
    /// New embeddings that supervise stdio or HTTP alongside Tasks should use
    /// [`Self::run_service`] instead. That retained-runner surface can be
    /// re-entered by the caller after its prior service future exits, allowing
    /// recovery to remain inside one caller-owned structured region.
    pub async fn run(mut self, cx: &Cx) -> McpResult<()> {
        self.run_service(cx).await
    }

    /// Runs recovery and bounded wakeup handling while retaining this
    /// caller-owned service runner.
    ///
    /// The durable store is scanned before the first wait and after every
    /// wakeup. A queue-full or missed synchronous signal therefore delays
    /// recovery but cannot erase a committed handoff. If the application
    /// supervisor returns an error, the exact current handoff is restored
    /// before that error leaves the region; a subsequent invocation on this
    /// runner or a newly installed service may recover it. This is at-least-once
    /// handoff semantics, not an exactly-once side-effect claim.
    ///
    /// This future borrows the runner, so an application cannot start two
    /// service loops from one runner concurrently. When it exits because of a
    /// supervisor error, caller-context cancellation, or a dropped future,
    /// its readiness lease is revoked immediately and any unconsumed durable
    /// handoff remains recoverable. The embedding may then call this method
    /// again on the same runner to restart recovery, or drop it and install a
    /// new runner generation. The latter is the process-restart path and
    /// requires an application-provided durable [`FinalTaskStore`];
    /// [`InMemoryFinalTaskStore`] intentionally cannot survive a process
    /// restart.
    ///
    /// FastMCP neither creates a runtime nor spawns this future. Start it as a
    /// child of the embedding's application region alongside `run_stdio` or
    /// HTTP serving, and let that region own its cancellation and join.
    ///
    /// The mutable borrow is the API's non-concurrency boundary: one runner
    /// cannot have two live service futures. Use separate runtimes and
    /// separately installed runners only when the durable store supplies the
    /// necessary cross-owner fencing.
    ///
    /// ```compile_fail
    /// # use fastmcp_server::AuthorizedTaskServiceRunner;
    /// # async fn cannot_start_two_service_loops(
    /// #     runner: &mut AuthorizedTaskServiceRunner,
    /// #     cx: &asupersync::Cx,
    /// # ) {
    /// let first = runner.run_service(cx);
    /// let second = runner.run_service(cx);
    /// let _ = (first, second);
    /// # }
    /// ```
    pub async fn run_service(&mut self, cx: &Cx) -> McpResult<()> {
        cx.checkpoint()
            .map_err(|error| McpError::internal_error(error.to_string()))?;
        // A pre-cancelled runner must never publish readiness, even briefly.
        // The returned lease remains alive across every await in this run and
        // revokes its exact generation on normal exit, cancellation, or drop.
        let _readiness_lease = self.runtime.mark_task_service_ready(self.service_id)?;
        if let Err(error) = self.recover_pending(cx).await {
            if cx.checkpoint().is_err() {
                return Ok(());
            }
            return Err(error);
        }
        loop {
            let task_id = match self.receiver.recv(cx).await {
                Ok(task_id) => task_id,
                Err(_) if cx.checkpoint().is_err() => return Ok(()),
                Err(error) => {
                    return Err(McpError::internal_error(format!(
                        "Task service wakeup receive failed: {error}"
                    )));
                }
            };
            if let Err(error) = self.resume_task(cx, &task_id).await {
                if cx.checkpoint().is_err() {
                    return Ok(());
                }
                return Err(error);
            }
            if let Err(error) = self.recover_pending(cx).await {
                if cx.checkpoint().is_err() {
                    return Ok(());
                }
                return Err(error);
            }
        }
    }

    async fn recover_pending(&mut self, cx: &Cx) -> McpResult<()> {
        let mut last_recovered_task_id = None;
        let mut first_retryable_error = None;
        let mut retried_handoffs = BTreeSet::new();
        for _ in 0..MAX_FINAL_TASK_RECOVERY_HANDOFFS_PER_SCAN {
            let recovered = match self.next_recovery_kind {
                FinalTaskRecoveryKind::Initial => {
                    if let Some(handoff) = self.runtime.recover_initial_work_with_checkpoints(
                        cx,
                        &self.dispatch_owner,
                        self.initial_recovery_cursor.as_ref(),
                    )? {
                        Some((
                            FinalTaskRecoveryKind::Initial,
                            FinalTaskSupervisorHandoff::Initial(handoff),
                        ))
                    } else {
                        self.runtime
                            .recover_accepted_input_with_checkpoints(
                                cx,
                                &self.dispatch_owner,
                                self.accepted_recovery_cursor.as_ref(),
                            )?
                            .map(|handoff| {
                                (
                                    FinalTaskRecoveryKind::Resumed,
                                    FinalTaskSupervisorHandoff::Resumed(handoff),
                                )
                            })
                    }
                }
                FinalTaskRecoveryKind::Resumed => {
                    if let Some(handoff) = self.runtime.recover_accepted_input_with_checkpoints(
                        cx,
                        &self.dispatch_owner,
                        self.accepted_recovery_cursor.as_ref(),
                    )? {
                        Some((
                            FinalTaskRecoveryKind::Resumed,
                            FinalTaskSupervisorHandoff::Resumed(handoff),
                        ))
                    } else {
                        self.runtime
                            .recover_initial_work_with_checkpoints(
                                cx,
                                &self.dispatch_owner,
                                self.initial_recovery_cursor.as_ref(),
                            )?
                            .map(|handoff| {
                                (
                                    FinalTaskRecoveryKind::Initial,
                                    FinalTaskSupervisorHandoff::Initial(handoff),
                                )
                            })
                    }
                }
            };
            let Some((kind, handoff)) = recovered else {
                break;
            };
            let task_id = final_task_handoff_task_id(&handoff).clone();
            match kind {
                FinalTaskRecoveryKind::Initial => {
                    self.initial_recovery_cursor = Some(task_id.clone());
                }
                FinalTaskRecoveryKind::Resumed => {
                    self.accepted_recovery_cursor = Some(task_id.clone());
                }
            }
            self.next_recovery_kind = kind.other();
            let retry_key = (kind, task_id.clone());
            last_recovered_task_id = Some(task_id);
            if let Err(error) = self.resume_handoff(cx, handoff).await {
                // A supervisor error restores this exact durable handoff.
                // Advance the scan first so a low-ID retry cannot starve
                // later work whenever the caller restarts its runner.
                if !retried_handoffs.insert(retry_key) {
                    if first_retryable_error.is_none() {
                        first_retryable_error = Some(error);
                    }
                    break;
                }
                if first_retryable_error.is_none() {
                    first_retryable_error = Some(error);
                }
            }
        }
        if let Some(task_id) = last_recovered_task_id {
            // Recovery is deliberately bounded. A self-wakeup continues the
            // durable scan without allowing a single service turn to starve
            // cancellation, shutdown, or other application work.
            self.runtime.signal_task_service(task_id);
        }
        if let Some(error) = first_retryable_error {
            Err(error)
        } else {
            Ok(())
        }
    }

    async fn resume_task(&self, cx: &Cx, task_id: &FinalTaskId) -> McpResult<()> {
        cx.checkpoint()
            .map_err(|error| McpError::internal_error(error.to_string()))?;
        if let Some(initial) =
            self.runtime
                .take_initial_work_with_checkpoint(cx, task_id, &self.dispatch_owner)?
        {
            self.resume_handoff(cx, FinalTaskSupervisorHandoff::Initial(initial))
                .await?;
            return Ok(());
        }
        cx.checkpoint()
            .map_err(|error| McpError::internal_error(error.to_string()))?;
        if let Some(accepted) =
            self.runtime
                .take_accepted_input_with_checkpoint(cx, task_id, &self.dispatch_owner)?
        {
            self.resume_handoff(cx, FinalTaskSupervisorHandoff::Resumed(accepted))
                .await?;
        }
        Ok(())
    }

    async fn resume_handoff(
        &self,
        cx: &Cx,
        mut handoff: FinalTaskSupervisorHandoff,
    ) -> McpResult<()> {
        let mut guard = FinalTaskExecutionGuard::new(&self.runtime, &self.dispatch_owner, &handoff);
        cx.checkpoint()
            .map_err(|error| McpError::internal_error(error.to_string()))?;
        if !guard.elect()? {
            // Cancellation or another service won the atomic election before
            // this handoff could begin. That winner owns the handoff outcome;
            // do not let this losing caller restore over its durable state.
            guard.disarm();
            return Ok(());
        }
        let cancellation_wake = self
            .runtime
            .register_task_cancellation_wake(self.service_id, guard.task_id())?;
        if guard.retire_if_cancellation_requested()? {
            return Ok(());
        }
        handoff.attach_authority(guard.authority()?);
        match self
            .run_supervisor_with_lease_heartbeat(cx, handoff, &mut guard, &cancellation_wake)
            .await
        {
            Ok(()) => {
                if guard.retire_if_cancellation_requested()? {
                    return Ok(());
                }
                if guard.is_recoverable_without_transition()? {
                    let restored = guard.restore()?;
                    if !restored {
                        if guard.retire_if_cancellation_requested()? {
                            return Ok(());
                        }
                        return Err(McpError::internal_error(
                            "Final task supervisor returned success without a fenced transition and its handoff could not be restored",
                        ));
                    }
                    return Err(McpError::internal_error(
                        "Final task supervisor returned success without a fenced task transition",
                    ));
                }
                let finished = guard.finish()?;
                if !finished && guard.retire_if_cancellation_requested()? {
                    return Ok(());
                }
                guard.disarm();
                Ok(())
            }
            Err(error) => {
                // Returned errors restore synchronously so a recovery runner
                // sees the exact pre-await payload. Cancellation, dropped
                // futures, and unwinding use the same lease in `Drop`.
                if guard.retire_if_cancellation_requested()? {
                    return Ok(());
                }
                let restored = guard.restore()?;
                if !restored && guard.retire_if_cancellation_requested()? {
                    return Ok(());
                }
                Err(error)
            }
        }
    }

    async fn run_supervisor_with_lease_heartbeat(
        &self,
        cx: &Cx,
        handoff: FinalTaskSupervisorHandoff,
        guard: &mut FinalTaskExecutionGuard,
        cancellation_wake: &FinalTaskCancellationWakeRegistration,
    ) -> McpResult<()> {
        let mut supervisor = self.supervisor.resume(cx, handoff);
        let heartbeat_interval = guard.heartbeat_interval()?;
        loop {
            // The application callback is allowed to be pending for longer
            // than one lease interval. The service context is nevertheless
            // authoritative: observe its cancellation before polling more
            // application work and before renewing durable ownership.
            cx.checkpoint()
                .map_err(|error| McpError::internal_error(error.to_string()))?;
            if guard.retire_if_cancellation_requested()? {
                return Ok(());
            }
            let mut heartbeat = Box::pin(asupersync::time::sleep(cx.now(), heartbeat_interval));
            let completed = std::future::poll_fn(|task_context| {
                if let Err(error) = cx.checkpoint() {
                    return std::task::Poll::Ready(Some(Err(McpError::internal_error(
                        error.to_string(),
                    ))));
                }
                cancellation_wake.register_waker(task_context.waker());
                match guard.is_cancellation_requested() {
                    Ok(true) => return std::task::Poll::Ready(Some(Ok(()))),
                    Ok(false) => {}
                    Err(error) => return std::task::Poll::Ready(Some(Err(error))),
                }
                if let std::task::Poll::Ready(result) = supervisor.as_mut().poll(task_context) {
                    // A completed application result is authoritative. The
                    // sanctioned wind-down idiom cancels the service region
                    // and then returns success; observing that cancellation
                    // here would overwrite the success and restore a durable
                    // handoff the application already consumed.
                    return std::task::Poll::Ready(Some(result));
                }
                if heartbeat.as_mut().poll(task_context).is_ready() {
                    return std::task::Poll::Ready(None);
                }
                std::task::Poll::Pending
            })
            .await;
            let Some(result) = completed else {
                cx.checkpoint()
                    .map_err(|error| McpError::internal_error(error.to_string()))?;
                if guard.retire_if_cancellation_requested()? {
                    return Ok(());
                }
                if !guard.renew()? {
                    return Err(McpError::internal_error(
                        "Final task dispatch lease was lost while application work was running",
                    ));
                }
                continue;
            };
            if guard.retire_if_cancellation_requested()? {
                return Ok(());
            }
            return result;
        }
    }
}

fn final_task_handoff_task_id(handoff: &FinalTaskSupervisorHandoff) -> &FinalTaskId {
    match handoff {
        FinalTaskSupervisorHandoff::Initial(initial) => initial.task_id(),
        FinalTaskSupervisorHandoff::Resumed(accepted) => accepted.task_id(),
    }
}

enum FinalTaskHandoffRestoration {
    Initial(FinalTaskWorkDescriptor),
    Resumed(FinalTaskInputResponses),
}

/// Private guard that is the only path from a claimed durable handoff to an
/// application invocation. It owns the service identity, exact dispatch
/// fence, completion, renewal, and restoration rights for one handoff.
struct FinalTaskExecutionGuard {
    runtime: FinalTaskRuntime,
    task_id: FinalTaskId,
    generation: u64,
    owner_id: String,
    dispatch_fence: Option<u64>,
    restoration: Option<FinalTaskHandoffRestoration>,
}

impl FinalTaskExecutionGuard {
    fn new(
        runtime: &FinalTaskRuntime,
        owner_id: &str,
        handoff: &FinalTaskSupervisorHandoff,
    ) -> Self {
        let (task_id, generation, restoration) = match handoff {
            FinalTaskSupervisorHandoff::Initial(initial) => (
                initial.task_id().clone(),
                initial.generation(),
                FinalTaskHandoffRestoration::Initial(initial.restore_copy()),
            ),
            FinalTaskSupervisorHandoff::Resumed(accepted) => (
                accepted.task_id().clone(),
                accepted.generation(),
                FinalTaskHandoffRestoration::Resumed(accepted.restore_copy()),
            ),
        };
        Self {
            runtime: runtime.clone(),
            task_id,
            generation,
            owner_id: owner_id.to_owned(),
            dispatch_fence: None,
            restoration: Some(restoration),
        }
    }

    fn elect(&mut self) -> McpResult<bool> {
        let Some(dispatch_fence) =
            self.runtime
                .begin_handoff_dispatch(&self.task_id, self.generation, &self.owner_id)?
        else {
            return Ok(false);
        };
        self.dispatch_fence = Some(dispatch_fence);
        Ok(true)
    }

    fn task_id(&self) -> &FinalTaskId {
        &self.task_id
    }

    fn is_cancellation_requested(&self) -> McpResult<bool> {
        let current = self.runtime.load_task_snapshot(&self.task_id)?;
        if current.generation() != self.generation {
            // A terminal or newer fenced transition already consumed this
            // handoff. It is not this guard's cancellation to retire.
            return Ok(false);
        }
        self.runtime.store.is_cancellation_requested(&self.task_id)
    }

    /// Converts durable cancellation intent into the terminal task outcome
    /// while this guard still owns its exact elected fence. This is called
    /// around every supervisor poll and by `Drop`, so cancellation cannot
    /// strand a `working` task merely because application work returns, errors,
    /// or is dropped at the same time.
    fn retire_if_cancellation_requested(&mut self) -> McpResult<bool> {
        if !self.is_cancellation_requested()? {
            return Ok(false);
        }
        self.runtime.fenced_honor_cancellation(
            &self.task_id,
            self.generation,
            &self.owner_id,
            self.dispatch_fence.ok_or_else(|| {
                McpError::internal_error(
                    "Final task cancellation retirement requires an elected dispatch fence",
                )
            })?,
            None,
        )?;
        self.disarm();
        Ok(true)
    }

    fn renew(&self) -> McpResult<bool> {
        let Some(dispatch_fence) = self.dispatch_fence else {
            return Ok(false);
        };
        self.runtime.renew_handoff_dispatch(
            &self.task_id,
            self.generation,
            &self.owner_id,
            dispatch_fence,
        )
    }

    fn heartbeat_interval(&self) -> McpResult<StdDuration> {
        self.runtime.handoff_dispatch_lease_heartbeat_interval()
    }

    /// Returns whether the elected handoff remains the exact live `working`
    /// state without a cancellation winner. A successful supervisor return in
    /// that state has not consumed its mutation authority and must be restored
    /// for a later service generation rather than silently dropping work.
    fn is_recoverable_without_transition(&self) -> McpResult<bool> {
        let current = self.runtime.load_task_snapshot(&self.task_id)?;
        Ok(current.generation() == self.generation
            && matches!(current.task(), FinalTask::Working(_))
            && !self
                .runtime
                .store
                .is_cancellation_requested(&self.task_id)?)
    }

    fn authority(&self) -> McpResult<FinalTaskHandoffAuthority> {
        let dispatch_fence = self.dispatch_fence.ok_or_else(|| {
            McpError::internal_error(
                "Final task handoff authority was requested before dispatch election",
            )
        })?;
        Ok(FinalTaskHandoffAuthority {
            runtime: self.runtime.clone(),
            task_id: self.task_id.clone(),
            generation: self.generation,
            owner_id: self.owner_id.clone(),
            dispatch_fence,
        })
    }

    fn finish(&self) -> McpResult<bool> {
        let Some(dispatch_fence) = self.dispatch_fence else {
            return Ok(false);
        };
        self.runtime.finish_handoff_dispatch(
            &self.task_id,
            self.generation,
            &self.owner_id,
            dispatch_fence,
        )
    }

    fn disarm(&mut self) {
        self.restoration = None;
    }

    fn restore(&mut self) -> McpResult<bool> {
        let Some(restoration) = self.restoration.as_ref() else {
            return Ok(false);
        };
        let restored = match restoration {
            FinalTaskHandoffRestoration::Initial(work_descriptor) => {
                self.runtime.restore_initial_work(
                    &self.task_id,
                    self.generation,
                    &self.owner_id,
                    self.dispatch_fence,
                    work_descriptor.clone(),
                )
            }
            FinalTaskHandoffRestoration::Resumed(input_responses) => {
                self.runtime.restore_accepted_input(
                    &self.task_id,
                    self.generation,
                    &self.owner_id,
                    self.dispatch_fence,
                    input_responses.clone(),
                )
            }
        };
        if matches!(&restored, Ok(true)) {
            self.restoration = None;
        }
        restored
    }
}

impl Drop for FinalTaskExecutionGuard {
    fn drop(&mut self) {
        // A Rust future can be dropped during cancellation or unwinding, when
        // there is no result channel for a restoration failure. The durable
        // store operation is still attempted synchronously and is generation
        // fenced, so a concurrent terminal or cancellation winner is never
        // resurrected. A cancellation winner is retired before restoration;
        // if it races the first probe, in-memory restoration retains the
        // elected fence and the second probe records the terminal outcome.
        if self.retire_if_cancellation_requested().unwrap_or(false) {
            return;
        }
        let _ = self.restore();
        let _ = self.retire_if_cancellation_requested();
    }
}

impl Drop for FinalTaskServiceReadinessLease {
    fn drop(&mut self) {
        let mut signal = self
            .runtime
            .service_signal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A stale future must never revoke a replacement runner's readiness.
        // The matching lease is the sole proof that this exact entered runner
        // still owns the generation observed by `ensure_task_service_ready`.
        let Some(service) = signal.as_mut() else {
            return;
        };
        if service.service_id == self.service_id
            && service.ready_generation == Some(self.ready_generation)
        {
            service.ready_generation = None;
        }
    }
}

impl Drop for AuthorizedTaskServiceRunner {
    fn drop(&mut self) {
        self.receiver.close();
        let mut signal = self
            .runtime
            .service_signal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A runner is the sole owner of its generation. Its exit or future
        // drop revokes readiness immediately, but a stale generation must not
        // clear a newly installed service that won a close/install interleave.
        if signal
            .as_ref()
            .is_some_and(|service| service.service_id == self.service_id)
        {
            *signal = None;
        }
    }
}

/// Decodes and serves a negotiated `tasks/get` request through the final runtime.
pub(crate) fn dispatch_final_tasks_get(
    runtime: &FinalTaskRuntime,
    parameters: serde_json::Value,
) -> McpResult<serde_json::Value> {
    let parameters = serde_json::from_value::<FinalGetTaskParams>(parameters)
        .map_err(|_| McpError::invalid_params("Invalid final tasks/get parameters"))?;
    validate_final_task_request_meta(&parameters.request, "tasks/get")?;
    serde_json::to_value(runtime.get_task(&parameters.task_id)?)
        .map_err(|_| McpError::internal_error("final tasks/get response serialization failed"))
}

/// Decodes and serves a negotiated `tasks/update` request through the final runtime.
pub(crate) fn dispatch_final_tasks_update(
    runtime: &FinalTaskRuntime,
    parameters: serde_json::Value,
) -> McpResult<serde_json::Value> {
    let parameters = serde_json::from_value::<UpdateTaskParams>(parameters)
        .map_err(|_| McpError::invalid_params("Invalid final tasks/update parameters"))?;
    validate_final_task_request_meta(&parameters.request, "tasks/update")?;
    serde_json::to_value(runtime.update_task(&parameters.task_id, &parameters.input_responses)?)
        .map_err(|_| McpError::internal_error("final tasks/update response serialization failed"))
}

/// Decodes and serves a negotiated `tasks/cancel` request through the final runtime.
pub(crate) fn dispatch_final_tasks_cancel(
    runtime: &FinalTaskRuntime,
    parameters: serde_json::Value,
) -> McpResult<serde_json::Value> {
    let parameters = serde_json::from_value::<FinalCancelTaskParams>(parameters)
        .map_err(|_| McpError::invalid_params("Invalid final tasks/cancel parameters"))?;
    validate_final_task_request_meta(&parameters.request, "tasks/cancel")?;
    serde_json::to_value(runtime.cancel_task(&parameters.task_id)?)
        .map_err(|_| McpError::internal_error("final tasks/cancel response serialization failed"))
}

fn validate_final_task_request_meta(
    request: &FinalTaskRequestMeta,
    method: &'static str,
) -> McpResult<()> {
    // Typed modern admission consumes the protocol-version marker upstream
    // and deliberately strips it before handler parameter decoding, so its
    // absence here is the normal dispatched shape; when a direct caller does
    // supply it, it must still be the exact final version. Client
    // capabilities survive stripping and remain required.
    let Ok(protocol_version) = request.meta.protocol_version() else {
        return Err(McpError::invalid_params(format!(
            "Invalid final {method} parameters"
        )));
    };
    let client_capabilities = request.meta.client_capabilities().ok().flatten();
    if protocol_version.is_some_and(|version| version != FINAL_PROTOCOL_VERSION)
        || client_capabilities.is_none()
    {
        return Err(McpError::invalid_params(format!(
            "Invalid final {method} parameters"
        )));
    }
    Ok(())
}

fn generate_final_task_id() -> McpResult<FinalTaskId> {
    let identifier = draw_security_identifier().map_err(|error| {
        McpError::internal_error(format!("Task identifier generation failed: {error}"))
    })?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(identifier.as_bytes());
    FinalTaskId::parse(encoded).map_err(|error| McpError::internal_error(error.to_string()))
}

#[cfg(not(test))]
fn generate_final_task_dispatch_owner() -> McpResult<String> {
    generate_final_task_id().map(|task_id| task_id.as_str().to_owned())
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

pub(crate) fn transition_terminal_final_task_base(
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

pub(crate) fn final_task_notification(task: &FinalTask) -> FinalTaskStatusNotification {
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
    use std::thread;
    use std::time::Duration;

    fn test_take_input(
        store: &InMemoryFinalTaskStore,
        expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskInputResponses>> {
        FinalTaskStore::take_input_for_owner_if_current(
            store,
            expected,
            FINAL_TASK_TEST_DIRECT_OWNER,
        )
    }

    fn test_take_initial_work(
        store: &InMemoryFinalTaskStore,
        expected: &FinalTaskSnapshot,
    ) -> McpResult<Option<FinalTaskWorkDescriptor>> {
        FinalTaskStore::take_initial_work_for_owner_if_current(
            store,
            expected,
            FINAL_TASK_TEST_DIRECT_OWNER,
        )
    }

    fn test_next_initial_work(
        store: &InMemoryFinalTaskStore,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        FinalTaskStore::next_initial_work_snapshot_after(store, None)
    }

    fn test_next_accepted_input(
        store: &InMemoryFinalTaskStore,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        FinalTaskStore::next_accepted_input_snapshot_after(store, None)
    }

    fn test_restore_initial_work(
        store: &InMemoryFinalTaskStore,
        task_id: &FinalTaskId,
        generation: u64,
        work_descriptor: FinalTaskWorkDescriptor,
    ) -> McpResult<bool> {
        FinalTaskStore::restore_initial_work_for_owner_if_current(
            store,
            task_id,
            generation,
            FINAL_TASK_TEST_DIRECT_OWNER,
            None,
            work_descriptor,
        )
    }

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

    struct RecordingFinalTaskSupervisor {
        accepted: Arc<Mutex<Vec<(FinalTaskId, FinalTaskInputResponses)>>>,
    }

    impl ApplicationTaskSupervisor for RecordingFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            let recorded = Arc::clone(&self.accepted);
            Box::pin(async move {
                let FinalTaskSupervisorHandoff::Resumed(accepted) = handoff else {
                    return Err(McpError::internal_error(
                        "recording supervisor expected a resumed task handoff",
                    ));
                };
                recorded
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((
                        accepted.task_id().clone(),
                        accepted.input_responses().clone(),
                    ));
                let result: FinalTaskCallToolResult =
                    serde_json::from_value(serde_json::json!({"content": []}))
                        .expect("typed terminal task result");
                accepted.complete_task(result, None)?;
                // The caller controls the structured service region. Ending it
                // after one observed recovery makes this test prove that the
                // runner neither creates a runtime nor detaches a worker.
                cx.cancel_with(CancelKind::User, None);
                Ok(())
            })
        }
    }

    struct RecordingInitialFinalTaskSupervisor {
        started: Arc<Mutex<Vec<(FinalTaskId, FinalTaskWorkDescriptor)>>>,
    }

    impl ApplicationTaskSupervisor for RecordingInitialFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            let started = Arc::clone(&self.started);
            Box::pin(async move {
                let FinalTaskSupervisorHandoff::Initial(initial) = handoff else {
                    return Err(McpError::internal_error(
                        "initial supervisor received a resumed task handoff",
                    ));
                };
                started
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((initial.task_id().clone(), initial.work_descriptor().clone()));
                let result: FinalTaskCallToolResult =
                    serde_json::from_value(serde_json::json!({"content": []}))
                        .expect("typed terminal task result");
                initial.complete_task(result, None)?;
                cx.cancel_with(CancelKind::User, None);
                Ok(())
            })
        }
    }

    struct CancellingAfterInitialHandoffsFinalTaskSupervisor {
        started: Arc<AtomicUsize>,
        cancel_after: usize,
    }

    struct RecordingRecoveryOrderFinalTaskSupervisor {
        order: Arc<Mutex<Vec<&'static str>>>,
        cancel_after: usize,
    }

    impl ApplicationTaskSupervisor for RecordingRecoveryOrderFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            let order = Arc::clone(&self.order);
            let cancel_after = self.cancel_after;
            Box::pin(async move {
                let kind = match &handoff {
                    FinalTaskSupervisorHandoff::Initial(_) => "initial",
                    FinalTaskSupervisorHandoff::Resumed(_) => "resumed",
                };
                let observed = {
                    let mut order = order
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    order.push(kind);
                    order.len()
                };
                complete_final_task_handoff(handoff)?;
                if observed == cancel_after {
                    cx.cancel_with(CancelKind::User, None);
                }
                Ok(())
            })
        }
    }

    impl ApplicationTaskSupervisor for CancellingAfterInitialHandoffsFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            let started = Arc::clone(&self.started);
            let cancel_after = self.cancel_after;
            Box::pin(async move {
                let FinalTaskSupervisorHandoff::Initial(initial) = handoff else {
                    return Err(McpError::internal_error(
                        "bounded recovery supervisor expected an initial task handoff",
                    ));
                };
                let result: FinalTaskCallToolResult =
                    serde_json::from_value(serde_json::json!({"content": []}))
                        .expect("typed terminal task result");
                initial.complete_task(result, None)?;
                if started.fetch_add(1, AtomicOrdering::SeqCst) + 1 == cancel_after {
                    cx.cancel_with(CancelKind::User, None);
                }
                Ok(())
            })
        }
    }

    struct FailingFinalTaskSupervisor;

    impl ApplicationTaskSupervisor for FailingFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            _cx: &'a Cx,
            _handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            Box::pin(async {
                Err(McpError::internal_error(
                    "planted caller-owned supervisor failure",
                ))
            })
        }
    }

    const RUN_SERVICE_SUPERVISOR_FAIL: usize = 0;
    const RUN_SERVICE_SUPERVISOR_PENDING: usize = 1;
    const RUN_SERVICE_SUPERVISOR_COMPLETE: usize = 2;

    /// Test-only supervisor whose next handoff outcome is selected by the
    /// caller. It makes the retained-runner tests distinguish a supervisor
    /// error, a dropped/cancelled pending service future, and a successful
    /// retry without replacing the runner or the durable store.
    struct SwitchableRunServiceSupervisor {
        action: Arc<AtomicUsize>,
    }

    impl ApplicationTaskSupervisor for SwitchableRunServiceSupervisor {
        fn resume<'a>(
            &'a self,
            cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            let action = Arc::clone(&self.action);
            Box::pin(async move {
                match action.load(AtomicOrdering::SeqCst) {
                    RUN_SERVICE_SUPERVISOR_FAIL => {
                        let _handoff = handoff;
                        Err(McpError::internal_error(
                            "planted retained-run-service supervisor failure",
                        ))
                    }
                    RUN_SERVICE_SUPERVISOR_PENDING => {
                        let _handoff = handoff;
                        std::future::pending::<McpResult<()>>().await
                    }
                    RUN_SERVICE_SUPERVISOR_COMPLETE => {
                        complete_final_task_handoff(handoff)?;
                        // A caller-owned service region decides when this
                        // long-lived loop exits after a successful retry.
                        cx.cancel_with(CancelKind::User, None);
                        Ok(())
                    }
                    _ => Err(McpError::internal_error(
                        "invalid retained-run-service test supervisor action",
                    )),
                }
            })
        }
    }

    /// Fails one stable low-ID recovery candidate while completing every later
    /// initial handoff. The bounded recovery test uses this to prove that an
    /// at-least-once retry does not starve the rest of the durable scan.
    struct FailLowIdCompleteLaterInitialSupervisor {
        low_task_id: FinalTaskId,
        attempted: Arc<Mutex<Vec<FinalTaskId>>>,
    }

    impl ApplicationTaskSupervisor for FailLowIdCompleteLaterInitialSupervisor {
        fn resume<'a>(
            &'a self,
            _cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            let low_task_id = self.low_task_id.clone();
            let attempted = Arc::clone(&self.attempted);
            Box::pin(async move {
                let FinalTaskSupervisorHandoff::Initial(initial) = handoff else {
                    return Err(McpError::internal_error(
                        "low-ID recovery fixture expected initial work",
                    ));
                };
                let task_id = initial.task_id().clone();
                attempted
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(task_id.clone());
                if task_id == low_task_id {
                    return Err(McpError::internal_error(
                        "planted retryable low-ID recovery failure",
                    ));
                }
                let result: FinalTaskCallToolResult =
                    serde_json::from_value(serde_json::json!({"content": []}))
                        .expect("typed terminal task result");
                initial.complete_task(result, None)?;
                Ok(())
            })
        }
    }

    struct CancelThenFailingFinalTaskSupervisor {
        runtime: FinalTaskRuntime,
    }

    impl ApplicationTaskSupervisor for CancelThenFailingFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            _cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            let runtime = self.runtime.clone();
            Box::pin(async move {
                runtime
                    .cancel_task(final_task_handoff_task_id(&handoff))
                    .expect("the elected task remains cancellable before the planted error");
                Err(McpError::internal_error(
                    "planted supervisor error after cancellation election",
                ))
            })
        }
    }

    struct CancelThenHonoringCancellationFinalTaskSupervisor {
        runtime: FinalTaskRuntime,
        observed_cancellation: Arc<AtomicBool>,
    }

    impl ApplicationTaskSupervisor for CancelThenHonoringCancellationFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            _cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            let runtime = self.runtime.clone();
            let observed_cancellation = Arc::clone(&self.observed_cancellation);
            Box::pin(async move {
                runtime
                    .cancel_task(final_task_handoff_task_id(&handoff))
                    .expect("the elected task remains cancellable before honouring cancellation");
                let cancellation_requested = match &handoff {
                    FinalTaskSupervisorHandoff::Initial(initial) => {
                        initial.is_cancellation_requested()
                    }
                    FinalTaskSupervisorHandoff::Resumed(accepted) => {
                        accepted.is_cancellation_requested()
                    }
                }?;
                observed_cancellation.store(cancellation_requested, AtomicOrdering::SeqCst);
                if !cancellation_requested {
                    return Err(McpError::internal_error(
                        "the elected handoff did not observe its cancellation winner",
                    ));
                }
                match handoff {
                    FinalTaskSupervisorHandoff::Initial(initial) => initial.honor_cancellation(
                        Some("cancellation won the elected handoff".to_owned()),
                    ),
                    FinalTaskSupervisorHandoff::Resumed(accepted) => accepted.honor_cancellation(
                        Some("cancellation won the elected handoff".to_owned()),
                    ),
                }?;
                Ok(())
            })
        }
    }

    struct PendingFinalTaskSupervisor;

    impl ApplicationTaskSupervisor for PendingFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            _cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            Box::pin(async move {
                let _handoff = handoff;
                std::future::pending::<McpResult<()>>().await
            })
        }
    }

    /// A pending supervisor which reports its first live poll. This makes the
    /// cancellation-wake tests wait for the application future, rather than
    /// merely for task admission.
    struct SignallingPendingFinalTaskSupervisor {
        started: Sender<()>,
    }

    impl ApplicationTaskSupervisor for SignallingPendingFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            _cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            let started = self.started.clone();
            Box::pin(async move {
                started.try_send(()).map_err(|_| {
                    McpError::internal_error(
                        "live pending-supervisor test lost its start notification",
                    )
                })?;
                let _handoff = handoff;
                std::future::pending::<McpResult<()>>().await
            })
        }
    }

    struct PanickingFinalTaskSupervisor;

    impl ApplicationTaskSupervisor for PanickingFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            _cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            Box::pin(async move {
                let _handoff = handoff;
                panic!("planted task supervisor panic");
            })
        }
    }

    /// Test store that observes whether public task creation retains its
    /// durable record while the service-readiness generation is still held.
    struct ReadinessLeaseProbeFinalTaskStore {
        inner: Arc<InMemoryFinalTaskStore>,
        service_signal: Mutex<Option<Arc<Mutex<Option<FinalTaskServiceSignal>>>>>,
        observed_ready_lease: AtomicBool,
    }

    impl ReadinessLeaseProbeFinalTaskStore {
        fn new(inner: Arc<InMemoryFinalTaskStore>) -> Self {
            Self {
                inner,
                service_signal: Mutex::new(None),
                observed_ready_lease: AtomicBool::new(false),
            }
        }

        fn observe_service_signal(
            &self,
            service_signal: Arc<Mutex<Option<FinalTaskServiceSignal>>>,
        ) {
            *self
                .service_signal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(service_signal);
        }
    }

    impl FinalTaskStore for ReadinessLeaseProbeFinalTaskStore {
        fn create_task(
            &self,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<()> {
            self.inner.create_task(task, notification)
        }

        fn create_task_with_work(
            &self,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
            work_descriptor: FinalTaskWorkDescriptor,
        ) -> McpResult<()> {
            let service_signal = self
                .service_signal
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .expect("test store receives the runtime service signal before public creation");
            self.observed_ready_lease.store(
                matches!(
                    service_signal.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ),
                AtomicOrdering::SeqCst,
            );
            self.inner
                .create_task_with_work(task, notification, work_descriptor)
        }

        fn get_task(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTask>> {
            self.inner.get_task(task_id)
        }

        fn get_task_snapshot(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTaskSnapshot>> {
            self.inner.get_task_snapshot(task_id)
        }

        fn replace_task(
            &self,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<()> {
            self.inner.replace_task(task, notification)
        }

        fn replace_task_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<bool> {
            self.inner
                .replace_task_if_current(expected, task, notification)
        }

        fn request_cancellation(&self, task_id: &FinalTaskId) -> McpResult<()> {
            self.inner.request_cancellation(task_id)
        }

        fn request_cancellation_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<bool> {
            self.inner.request_cancellation_if_current(expected)
        }

        fn is_cancellation_requested(&self, task_id: &FinalTaskId) -> McpResult<bool> {
            self.inner.is_cancellation_requested(task_id)
        }

        // The probe wrapper must stay transparent for the initial-work
        // recovery family; the trait defaults reject at the runner's entry
        // checkpoint, which would fail readiness before the lease probe runs.
        fn next_initial_work_snapshot(&self) -> McpResult<Option<FinalTaskSnapshot>> {
            self.inner.next_initial_work_snapshot()
        }

        fn next_initial_work_snapshot_after(
            &self,
            after_task_id: Option<&FinalTaskId>,
        ) -> McpResult<Option<FinalTaskSnapshot>> {
            self.inner.next_initial_work_snapshot_after(after_task_id)
        }

        fn take_initial_work_if_current(
            &self,
            expected: &FinalTaskSnapshot,
        ) -> McpResult<Option<FinalTaskWorkDescriptor>> {
            self.inner.take_initial_work_if_current(expected)
        }

        fn take_initial_work_for_owner_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            owner_id: &str,
        ) -> McpResult<Option<FinalTaskWorkDescriptor>> {
            self.inner
                .take_initial_work_for_owner_if_current(expected, owner_id)
        }

        fn take_initial_work_handoff_for_owner_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            owner_id: &str,
        ) -> McpResult<Option<FinalTaskInitialWorkClaim>> {
            self.inner
                .take_initial_work_handoff_for_owner_if_current(expected, owner_id)
        }

        fn restore_initial_work_if_current(
            &self,
            task_id: &FinalTaskId,
            generation: u64,
            work_descriptor: FinalTaskWorkDescriptor,
        ) -> McpResult<bool> {
            self.inner
                .restore_initial_work_if_current(task_id, generation, work_descriptor)
        }

        fn restore_initial_work_for_owner_if_current(
            &self,
            task_id: &FinalTaskId,
            generation: u64,
            owner_id: &str,
            dispatch_fence: Option<u64>,
            work_descriptor: FinalTaskWorkDescriptor,
        ) -> McpResult<bool> {
            self.inner.restore_initial_work_for_owner_if_current(
                task_id,
                generation,
                owner_id,
                dispatch_fence,
                work_descriptor,
            )
        }

        fn replace_task_and_append_input_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
            input_responses: FinalTaskInputResponses,
        ) -> McpResult<bool> {
            self.inner.replace_task_and_append_input_if_current(
                expected,
                task,
                notification,
                input_responses,
            )
        }

        fn replace_task_and_clear_input_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<bool> {
            self.inner
                .replace_task_and_clear_input_if_current(expected, task, notification)
        }

        fn take_input_if_current(
            &self,
            expected: &FinalTaskSnapshot,
        ) -> McpResult<Option<FinalTaskInputResponses>> {
            self.inner.take_input_if_current(expected)
        }

        fn take_input_for_owner_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            owner_id: &str,
        ) -> McpResult<Option<FinalTaskInputResponses>> {
            self.inner
                .take_input_for_owner_if_current(expected, owner_id)
        }

        fn take_input_handoff_for_owner_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            owner_id: &str,
        ) -> McpResult<Option<FinalTaskAcceptedInputClaim>> {
            self.inner
                .take_input_handoff_for_owner_if_current(expected, owner_id)
        }

        fn next_accepted_input_snapshot(&self) -> McpResult<Option<FinalTaskSnapshot>> {
            self.inner.next_accepted_input_snapshot()
        }

        fn next_accepted_input_snapshot_after(
            &self,
            after_task_id: Option<&FinalTaskId>,
        ) -> McpResult<Option<FinalTaskSnapshot>> {
            self.inner.next_accepted_input_snapshot_after(after_task_id)
        }

        fn restore_input_if_current(
            &self,
            task_id: &FinalTaskId,
            generation: u64,
            input_responses: FinalTaskInputResponses,
        ) -> McpResult<bool> {
            self.inner
                .restore_input_if_current(task_id, generation, input_responses)
        }

        fn restore_input_for_owner_if_current(
            &self,
            task_id: &FinalTaskId,
            generation: u64,
            owner_id: &str,
            dispatch_fence: Option<u64>,
            input_responses: FinalTaskInputResponses,
        ) -> McpResult<bool> {
            self.inner.restore_input_for_owner_if_current(
                task_id,
                generation,
                owner_id,
                dispatch_fence,
                input_responses,
            )
        }

        fn begin_handoff_dispatch_if_current(
            &self,
            task_id: &FinalTaskId,
            generation: u64,
        ) -> McpResult<bool> {
            self.inner
                .begin_handoff_dispatch_if_current(task_id, generation)
        }

        fn begin_handoff_dispatch_for_owner_if_current(
            &self,
            task_id: &FinalTaskId,
            generation: u64,
            owner_id: &str,
        ) -> McpResult<Option<u64>> {
            self.inner
                .begin_handoff_dispatch_for_owner_if_current(task_id, generation, owner_id)
        }

        fn renew_handoff_dispatch_if_current(
            &self,
            task_id: &FinalTaskId,
            generation: u64,
            owner_id: &str,
            dispatch_fence: u64,
        ) -> McpResult<bool> {
            self.inner.renew_handoff_dispatch_if_current(
                task_id,
                generation,
                owner_id,
                dispatch_fence,
            )
        }

        fn handoff_dispatch_lease_heartbeat_interval(&self) -> McpResult<StdDuration> {
            self.inner.handoff_dispatch_lease_heartbeat_interval()
        }

        fn finish_handoff_dispatch_if_current(
            &self,
            task_id: &FinalTaskId,
            generation: u64,
        ) -> McpResult<bool> {
            self.inner
                .finish_handoff_dispatch_if_current(task_id, generation)
        }

        fn finish_handoff_dispatch_for_owner_if_current(
            &self,
            task_id: &FinalTaskId,
            generation: u64,
            owner_id: &str,
            dispatch_fence: u64,
        ) -> McpResult<bool> {
            self.inner.finish_handoff_dispatch_for_owner_if_current(
                task_id,
                generation,
                owner_id,
                dispatch_fence,
            )
        }

        fn request_cancellation_and_clear_input_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            cancelled_task: FinalTask,
            cancelled_notification: FinalTaskStatusNotification,
        ) -> McpResult<Option<FinalTaskSnapshot>> {
            self.inner.request_cancellation_and_clear_input_if_current(
                expected,
                cancelled_task,
                cancelled_notification,
            )
        }
    }

    struct LoseFirstAcceptedRecoveryCandidateStore {
        inner: Arc<InMemoryFinalTaskStore>,
        lose_first_take: Mutex<bool>,
    }

    impl LoseFirstAcceptedRecoveryCandidateStore {
        fn new(inner: Arc<InMemoryFinalTaskStore>) -> Self {
            Self {
                inner,
                lose_first_take: Mutex::new(true),
            }
        }
    }

    impl FinalTaskStore for LoseFirstAcceptedRecoveryCandidateStore {
        fn create_task(
            &self,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<()> {
            self.inner.create_task(task, notification)
        }

        fn get_task(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTask>> {
            self.inner.get_task(task_id)
        }

        fn get_task_snapshot(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTaskSnapshot>> {
            self.inner.get_task_snapshot(task_id)
        }

        fn replace_task(
            &self,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<()> {
            self.inner.replace_task(task, notification)
        }

        fn replace_task_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<bool> {
            self.inner
                .replace_task_if_current(expected, task, notification)
        }

        fn take_input_for_owner_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            owner_id: &str,
        ) -> McpResult<Option<FinalTaskInputResponses>> {
            let mut lose_first_take = self
                .lose_first_take
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *lose_first_take {
                *lose_first_take = false;
                if self
                    .inner
                    .take_input_for_owner_if_current(expected, owner_id)?
                    .is_some()
                    && let Some(dispatch_fence) =
                        self.inner.begin_handoff_dispatch_for_owner_if_current(
                            &expected.task().base().task_id,
                            expected.generation(),
                            owner_id,
                        )?
                {
                    let _ = self.inner.finish_handoff_dispatch_for_owner_if_current(
                        &expected.task().base().task_id,
                        expected.generation(),
                        owner_id,
                        dispatch_fence,
                    )?;
                }
                return Ok(None);
            }
            self.inner
                .take_input_for_owner_if_current(expected, owner_id)
        }

        fn take_input_handoff_for_owner_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            owner_id: &str,
        ) -> McpResult<Option<FinalTaskAcceptedInputClaim>> {
            let mut lose_first_take = self
                .lose_first_take
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *lose_first_take {
                *lose_first_take = false;
                if self
                    .inner
                    .take_input_handoff_for_owner_if_current(expected, owner_id)?
                    .is_some()
                    && let Some(dispatch_fence) =
                        self.inner.begin_handoff_dispatch_for_owner_if_current(
                            &expected.task().base().task_id,
                            expected.generation(),
                            owner_id,
                        )?
                {
                    let _ = self.inner.finish_handoff_dispatch_for_owner_if_current(
                        &expected.task().base().task_id,
                        expected.generation(),
                        owner_id,
                        dispatch_fence,
                    )?;
                }
                return Ok(None);
            }
            self.inner
                .take_input_handoff_for_owner_if_current(expected, owner_id)
        }

        fn next_accepted_input_snapshot_after(
            &self,
            after_task_id: Option<&FinalTaskId>,
        ) -> McpResult<Option<FinalTaskSnapshot>> {
            self.inner.next_accepted_input_snapshot_after(after_task_id)
        }

        fn handoff_dispatch_lease_heartbeat_interval(&self) -> McpResult<StdDuration> {
            self.inner.handoff_dispatch_lease_heartbeat_interval()
        }

        fn request_cancellation(&self, task_id: &FinalTaskId) -> McpResult<()> {
            self.inner.request_cancellation(task_id)
        }

        fn request_cancellation_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<bool> {
            self.inner.request_cancellation_if_current(expected)
        }

        fn is_cancellation_requested(&self, task_id: &FinalTaskId) -> McpResult<bool> {
            self.inner.is_cancellation_requested(task_id)
        }
    }

    /// Test store that injects cancellation at the dispatch-election boundary.
    /// It models a cancellation that races with a supervisor after the
    /// handoff has been claimed but before application code can begin.
    struct CancelBeforeFinalTaskDispatchStore {
        inner: Arc<InMemoryFinalTaskStore>,
    }

    impl FinalTaskStore for CancelBeforeFinalTaskDispatchStore {
        fn create_task(
            &self,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<()> {
            self.inner.create_task(task, notification)
        }

        fn get_task(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTask>> {
            self.inner.get_task(task_id)
        }

        fn get_task_snapshot(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTaskSnapshot>> {
            self.inner.get_task_snapshot(task_id)
        }

        fn replace_task(
            &self,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<()> {
            self.inner.replace_task(task, notification)
        }

        fn replace_task_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<bool> {
            self.inner
                .replace_task_if_current(expected, task, notification)
        }

        fn restore_input_for_owner_if_current(
            &self,
            task_id: &FinalTaskId,
            generation: u64,
            owner_id: &str,
            dispatch_fence: Option<u64>,
            input_responses: FinalTaskInputResponses,
        ) -> McpResult<bool> {
            self.inner.restore_input_for_owner_if_current(
                task_id,
                generation,
                owner_id,
                dispatch_fence,
                input_responses,
            )
        }

        fn take_input_handoff_for_owner_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            owner_id: &str,
        ) -> McpResult<Option<FinalTaskAcceptedInputClaim>> {
            self.inner
                .take_input_handoff_for_owner_if_current(expected, owner_id)
        }

        fn begin_handoff_dispatch_for_owner_if_current(
            &self,
            task_id: &FinalTaskId,
            generation: u64,
            owner_id: &str,
        ) -> McpResult<Option<u64>> {
            let Some(current) = self.inner.get_task_snapshot(task_id)? else {
                return Ok(None);
            };
            let cancelled_task = FinalTask::Cancelled(transition_terminal_final_task_base(
                current.task().base().clone(),
                FinalTaskStatus::Cancelled,
                None,
            )?);
            if current.generation() != generation
                || !self
                    .inner
                    .request_cancellation_and_clear_input_if_current(
                        &current,
                        cancelled_task.clone(),
                        final_task_notification(&cancelled_task),
                    )?
                    .is_some()
            {
                return Ok(None);
            }
            self.inner
                .begin_handoff_dispatch_for_owner_if_current(task_id, generation, owner_id)
        }

        fn renew_handoff_dispatch_if_current(
            &self,
            task_id: &FinalTaskId,
            generation: u64,
            owner_id: &str,
            dispatch_fence: u64,
        ) -> McpResult<bool> {
            self.inner.renew_handoff_dispatch_if_current(
                task_id,
                generation,
                owner_id,
                dispatch_fence,
            )
        }

        fn handoff_dispatch_lease_heartbeat_interval(&self) -> McpResult<StdDuration> {
            self.inner.handoff_dispatch_lease_heartbeat_interval()
        }

        fn finish_handoff_dispatch_for_owner_if_current(
            &self,
            task_id: &FinalTaskId,
            generation: u64,
            owner_id: &str,
            dispatch_fence: u64,
        ) -> McpResult<bool> {
            self.inner.finish_handoff_dispatch_for_owner_if_current(
                task_id,
                generation,
                owner_id,
                dispatch_fence,
            )
        }

        fn request_cancellation(&self, task_id: &FinalTaskId) -> McpResult<()> {
            self.inner.request_cancellation(task_id)
        }

        fn request_cancellation_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<bool> {
            self.inner.request_cancellation_if_current(expected)
        }

        fn is_cancellation_requested(&self, task_id: &FinalTaskId) -> McpResult<bool> {
            self.inner.is_cancellation_requested(task_id)
        }
    }

    struct AllowUnlimitedFinalTaskRetention;

    impl FinalTaskRetentionAuthority for AllowUnlimitedFinalTaskRetention {
        fn authorize_unlimited_retention(&self) -> McpResult<()> {
            Ok(())
        }
    }

    struct TerminalTransitionThenFailingFinalTaskSupervisor {}

    impl ApplicationTaskSupervisor for TerminalTransitionThenFailingFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            _cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            Box::pin(async move {
                let result: FinalTaskCallToolResult =
                    serde_json::from_value(serde_json::json!({"content": []}))
                        .expect("typed terminal task result");
                match handoff {
                    FinalTaskSupervisorHandoff::Initial(initial) => initial
                        .complete_task(result, None)
                        .expect("the elected initial handoff commits the terminal task"),
                    FinalTaskSupervisorHandoff::Resumed(accepted) => accepted
                        .complete_task(result, None)
                        .expect("the elected resumed handoff commits the terminal task"),
                };
                Err(McpError::internal_error(
                    "planted supervisor failure after a newer transition",
                ))
            })
        }
    }

    struct FencedCompletingFinalTaskSupervisor;

    impl ApplicationTaskSupervisor for FencedCompletingFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            _cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            Box::pin(async move {
                let result: FinalTaskCallToolResult =
                    serde_json::from_value(serde_json::json!({"content": []}))
                        .expect("typed terminal task result");
                match handoff {
                    FinalTaskSupervisorHandoff::Initial(initial) => initial
                        .complete_task(result, Some("completed by elected handoff".to_owned())),
                    FinalTaskSupervisorHandoff::Resumed(accepted) => accepted
                        .complete_task(result, Some("completed by elected handoff".to_owned())),
                }?;
                Ok(())
            })
        }
    }

    /// Deliberately returns success without exercising the handoff's fenced
    /// transition authority. The runner must reject this outcome and retain
    /// the durable work for a later service generation.
    struct NoTransitionFinalTaskSupervisor;

    impl ApplicationTaskSupervisor for NoTransitionFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            _cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            Box::pin(async move {
                let _handoff = handoff;
                Ok(())
            })
        }
    }

    struct StaleFenceCompletingFinalTaskSupervisor {
        store: Arc<InMemoryFinalTaskStore>,
        observed_error: Arc<Mutex<Option<McpError>>>,
    }

    impl ApplicationTaskSupervisor for StaleFenceCompletingFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            _cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            let store = Arc::clone(&self.store);
            let observed_error = Arc::clone(&self.observed_error);
            Box::pin(async move {
                let task_id = final_task_handoff_task_id(&handoff).clone();
                {
                    let mut state = store
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let lease = state
                        .handoff_leases
                        .get_mut(&task_id)
                        .expect("the elected handoff retains its exact in-memory dispatch lease");
                    let replacement_fence = lease
                        .dispatch_fence
                        .expect("the supervisor is invoked only after dispatch election")
                        .checked_add(1)
                        .expect("test dispatch fence remains representable");
                    lease.dispatch_fence = Some(replacement_fence);
                    state.next_dispatch_fence = replacement_fence;
                }

                let result: FinalTaskCallToolResult =
                    serde_json::from_value(serde_json::json!({"content": []}))
                        .expect("typed terminal task result");
                let error = match handoff {
                    FinalTaskSupervisorHandoff::Initial(initial) => {
                        initial.complete_task(result, Some("stale fence must fail".to_owned()))
                    }
                    FinalTaskSupervisorHandoff::Resumed(accepted) => {
                        accepted.complete_task(result, Some("stale fence must fail".to_owned()))
                    }
                }
                .expect_err("changing only the elected fence rejects the terminal transition");
                *observed_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
                Ok(())
            })
        }
    }

    struct StaleGenerationCompletingFinalTaskSupervisor {
        runtime: FinalTaskRuntime,
        observed_error: Arc<Mutex<Option<McpError>>>,
    }

    impl ApplicationTaskSupervisor for StaleGenerationCompletingFinalTaskSupervisor {
        fn resume<'a>(
            &'a self,
            _cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            let runtime = self.runtime.clone();
            let observed_error = Arc::clone(&self.observed_error);
            Box::pin(async move {
                let task_id = final_task_handoff_task_id(&handoff).clone();
                runtime
                    .require_input(
                        &task_id,
                        final_roots_request(),
                        Some("newer generation won before completion".to_owned()),
                    )
                    .expect("the competing transition advances the durable generation");

                let result: FinalTaskCallToolResult =
                    serde_json::from_value(serde_json::json!({"content": []}))
                        .expect("typed terminal task result");
                let error = match handoff {
                    FinalTaskSupervisorHandoff::Initial(initial) => {
                        initial.complete_task(result, Some("stale generation must fail".to_owned()))
                    }
                    FinalTaskSupervisorHandoff::Resumed(accepted) => accepted
                        .complete_task(result, Some("stale generation must fail".to_owned())),
                }
                .expect_err("a stale generation cannot commit a terminal handoff");
                *observed_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
                Ok(())
            })
        }
    }

    struct RepeatedTerminalHandoffSupervisor {
        observed_error: Arc<Mutex<Option<McpError>>>,
    }

    impl ApplicationTaskSupervisor for RepeatedTerminalHandoffSupervisor {
        fn resume<'a>(
            &'a self,
            _cx: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            let observed_error = Arc::clone(&self.observed_error);
            Box::pin(async move {
                let first_result: FinalTaskCallToolResult =
                    serde_json::from_value(serde_json::json!({"content": []}))
                        .expect("typed first terminal task result");
                match &handoff {
                    FinalTaskSupervisorHandoff::Initial(initial) => initial
                        .complete_task(first_result, Some("first terminal handoff".to_owned())),
                    FinalTaskSupervisorHandoff::Resumed(accepted) => accepted
                        .complete_task(first_result, Some("first terminal handoff".to_owned())),
                }
                .expect("the elected handoff commits its first terminal result");

                let repeated_result: FinalTaskCallToolResult =
                    serde_json::from_value(serde_json::json!({"content": []}))
                        .expect("typed repeated terminal task result");
                let error =
                    match &handoff {
                        FinalTaskSupervisorHandoff::Initial(initial) => initial
                            .complete_task(repeated_result, Some("repeat must fail".to_owned())),
                        FinalTaskSupervisorHandoff::Resumed(accepted) => accepted
                            .complete_task(repeated_result, Some("repeat must fail".to_owned())),
                    }
                    .expect_err("a terminal handoff cannot commit twice");
                *observed_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
                Ok(())
            })
        }
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

    fn final_test_work_descriptor() -> FinalTaskWorkDescriptor {
        FinalTaskWorkDescriptor::new(serde_json::json!({
            "handler": "tasks-test",
            "payload": {"fixture": "final-task"}
        }))
        .expect("non-null test work descriptor is valid")
    }

    fn complete_final_task_handoff(handoff: FinalTaskSupervisorHandoff) -> McpResult<()> {
        let result: FinalTaskCallToolResult =
            serde_json::from_value(serde_json::json!({"content": []}))
                .expect("typed terminal task result");
        match handoff {
            FinalTaskSupervisorHandoff::Initial(initial) => {
                let _ = initial.complete_task(result, None)?;
            }
            FinalTaskSupervisorHandoff::Resumed(accepted) => {
                let _ = accepted.complete_task(result, None)?;
            }
        }
        Ok(())
    }

    fn final_task_method_parameters(task_id: &FinalTaskId) -> serde_json::Value {
        serde_json::json!({
            "taskId": task_id,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        })
    }

    fn enter_task_service_runner<'a>(
        runner: AuthorizedTaskServiceRunner,
        cx: &'a Cx,
    ) -> Pin<Box<dyn Future<Output = McpResult<()>> + 'a>> {
        let mut running = Box::pin(runner.run(cx));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Future::poll(running.as_mut(), &mut context),
            std::task::Poll::Pending
        ));
        running
    }

    fn poll_retained_task_service(
        runner: &mut AuthorizedTaskServiceRunner,
        cx: &Cx,
    ) -> std::task::Poll<McpResult<()>> {
        let mut running = Box::pin(runner.run_service(cx));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        Future::poll(running.as_mut(), &mut context)
    }

    fn assert_exact_initial_work_is_recoverable(
        store: &InMemoryFinalTaskStore,
        task_id: &FinalTaskId,
        work_descriptor: &FinalTaskWorkDescriptor,
    ) {
        let state = store
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.initial_work.get(task_id), Some(work_descriptor));
        assert_eq!(state.work_descriptors.get(task_id), Some(work_descriptor));
        assert!(
            !state.handoff_leases.contains_key(task_id),
            "a stopped retained service must not retain an initial-work lease"
        );
        assert!(
            matches!(state.tasks.get(task_id), Some(FinalTask::Working(_))),
            "a stopped retained service must leave the initial task working for retry"
        );
    }

    fn assert_exact_accepted_input_is_recoverable(
        store: &InMemoryFinalTaskStore,
        task_id: &FinalTaskId,
        input_responses: &FinalTaskInputResponses,
    ) {
        let state = store
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.accepted_inputs.get(task_id), Some(input_responses));
        assert!(
            !state.handoff_leases.contains_key(task_id),
            "a stopped retained service must not retain an accepted-input lease"
        );
        assert!(
            matches!(state.tasks.get(task_id), Some(FinalTask::Working(_))),
            "a stopped retained service must leave the accepted input working for retry"
        );
    }

    fn create_final_task_state_fixture(
        runtime: &FinalTaskRuntime,
        status_message: Option<String>,
    ) -> CreateTaskResult {
        let task_id = generate_final_task_id().expect("generate final task ID for state fixture");
        let now = final_task_timestamp().expect("generate final task timestamp for state fixture");
        let task = FinalTask::Working(FinalTaskBase {
            task_id,
            status: FinalTaskStatus::Working,
            status_message,
            created_at: now.clone(),
            last_updated_at: now,
            ttl_ms: runtime
                .config
                .ttl_ms
                .map(final_task_duration)
                .transpose()
                .expect("configured fixture TTL is a valid final task duration"),
            poll_interval_ms: runtime
                .config
                .poll_interval_ms
                .map(final_task_duration)
                .transpose()
                .expect("configured fixture poll interval is a valid final task duration"),
        });
        runtime
            .persist_new_with_work(task.clone(), final_test_work_descriptor())
            .expect("persist final task state fixture with durable work descriptor");
        CreateTaskResult {
            task,
            meta: None,
            additional: BTreeMap::new(),
        }
    }

    fn create_accepted_final_input(
        runtime: &FinalTaskRuntime,
        input_responses: FinalTaskInputResponses,
    ) -> FinalTaskId {
        let task_id = create_final_task_state_fixture(runtime, None)
            .task
            .base()
            .task_id
            .clone();
        runtime
            .require_input(&task_id, final_roots_request(), None)
            .expect("task requests roots before accepted input");
        runtime
            .update_task(&task_id, &input_responses)
            .expect("roots response returns the task to working");
        task_id
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

    fn final_working_task_with_wire_durations(
        task_id: &str,
        ttl_ms: Option<&str>,
        poll_interval_ms: Option<&str>,
    ) -> FinalTask {
        let FinalTask::Working(mut base) = final_working_task_without_ttl(task_id) else {
            unreachable!("the helper always constructs a working task");
        };
        base.ttl_ms = ttl_ms.map(|duration| {
            serde_json::from_str(duration).expect("fixed test task TTL wire value is valid")
        });
        base.poll_interval_ms = poll_interval_ms.map(|duration| {
            serde_json::from_str(duration)
                .expect("fixed test task poll interval wire value is valid")
        });
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

    /// Deliberately permissive custom store used to prove that the runtime,
    /// rather than one built-in store implementation, guards task data at its
    /// durable read and write boundaries.
    struct RuntimeBoundaryProbeFinalTaskStore {
        snapshot: Mutex<FinalTaskSnapshot>,
        transition_write_calls: AtomicUsize,
        transition_result_override: Mutex<Option<FinalTask>>,
        work_descriptor: Mutex<Option<FinalTaskWorkDescriptor>>,
        accepted_inputs: Mutex<Option<FinalTaskInputResponses>>,
        initial_claim_override: Mutex<Option<FinalTaskInitialWorkClaim>>,
        accepted_claim_override: Mutex<Option<FinalTaskAcceptedInputClaim>>,
        cancellation_result_override: Mutex<Option<FinalTaskSnapshot>>,
        force_false_cas: AtomicBool,
    }

    impl RuntimeBoundaryProbeFinalTaskStore {
        fn new(task: FinalTask) -> Self {
            Self {
                snapshot: Mutex::new(FinalTaskSnapshot::new(task, 1)),
                transition_write_calls: AtomicUsize::new(0),
                transition_result_override: Mutex::new(None),
                work_descriptor: Mutex::new(Some(final_test_work_descriptor())),
                accepted_inputs: Mutex::new(None),
                initial_claim_override: Mutex::new(None),
                accepted_claim_override: Mutex::new(None),
                cancellation_result_override: Mutex::new(None),
                force_false_cas: AtomicBool::new(false),
            }
        }

        fn snapshot(&self) -> FinalTaskSnapshot {
            self.snapshot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn replace_snapshot_for_read(&self, task: FinalTask) {
            let mut snapshot = self
                .snapshot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *snapshot = FinalTaskSnapshot::new(task, snapshot.generation());
        }

        fn set_accepted_inputs(&self, input_responses: FinalTaskInputResponses) {
            *self
                .accepted_inputs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(input_responses);
        }
    }

    impl FinalTaskStore for RuntimeBoundaryProbeFinalTaskStore {
        fn create_task(
            &self,
            task: FinalTask,
            _notification: FinalTaskStatusNotification,
        ) -> McpResult<()> {
            self.replace_snapshot_for_read(task);
            Ok(())
        }

        fn create_task_with_work(
            &self,
            task: FinalTask,
            _notification: FinalTaskStatusNotification,
            work_descriptor: FinalTaskWorkDescriptor,
        ) -> McpResult<()> {
            self.replace_snapshot_for_read(task);
            *self
                .work_descriptor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(work_descriptor);
            Ok(())
        }

        fn get_task(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTask>> {
            let snapshot = self.snapshot();
            if &snapshot.task().base().task_id != task_id {
                return Ok(None);
            }
            Ok(Some(snapshot.into_task()))
        }

        fn get_task_snapshot(&self, task_id: &FinalTaskId) -> McpResult<Option<FinalTaskSnapshot>> {
            let snapshot = self.snapshot();
            if &snapshot.task().base().task_id != task_id {
                return Ok(None);
            }
            Ok(Some(snapshot))
        }

        fn replace_task(
            &self,
            task: FinalTask,
            _notification: FinalTaskStatusNotification,
        ) -> McpResult<()> {
            self.replace_snapshot_for_read(task);
            Ok(())
        }

        fn replace_task_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            task: FinalTask,
            _notification: FinalTaskStatusNotification,
        ) -> McpResult<bool> {
            if self.force_false_cas.load(AtomicOrdering::SeqCst) {
                return Ok(false);
            }
            let mut snapshot = self
                .snapshot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if snapshot.generation() != expected.generation() {
                return Ok(false);
            }
            let next_generation = snapshot
                .generation()
                .checked_add(1)
                .ok_or_else(|| McpError::internal_error("probe generation exhausted"))?;
            let committed_task = self
                .transition_result_override
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .unwrap_or(task);
            *snapshot = FinalTaskSnapshot::new(committed_task, next_generation);
            Ok(true)
        }

        fn replace_task_and_clear_input_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<bool> {
            self.transition_write_calls
                .fetch_add(1, AtomicOrdering::SeqCst);
            self.replace_task_if_current(expected, task, notification)
        }

        fn next_initial_work_snapshot_after(
            &self,
            _after_task_id: Option<&FinalTaskId>,
        ) -> McpResult<Option<FinalTaskSnapshot>> {
            Ok(Some(self.snapshot()))
        }

        fn take_initial_work_handoff_for_owner_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            owner_id: &str,
        ) -> McpResult<Option<FinalTaskInitialWorkClaim>> {
            if let Some(claim) = self
                .initial_claim_override
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            {
                return Ok(Some(claim));
            }
            Ok(self
                .work_descriptor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .map(|work_descriptor| {
                    FinalTaskInitialWorkClaim::new(
                        expected.task().base().task_id.clone(),
                        expected.generation(),
                        owner_id,
                        work_descriptor,
                    )
                }))
        }

        fn next_accepted_input_snapshot_after(
            &self,
            _after_task_id: Option<&FinalTaskId>,
        ) -> McpResult<Option<FinalTaskSnapshot>> {
            Ok(self
                .accepted_inputs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some()
                .then(|| self.snapshot()))
        }

        fn take_input_handoff_for_owner_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            owner_id: &str,
        ) -> McpResult<Option<FinalTaskAcceptedInputClaim>> {
            if let Some(claim) = self
                .accepted_claim_override
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            {
                return Ok(Some(claim));
            }
            let Some(input_responses) = self
                .accepted_inputs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            else {
                return Ok(None);
            };
            let work_descriptor = self
                .work_descriptor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .ok_or_else(|| McpError::internal_error("probe descriptor missing"))?;
            Ok(Some(FinalTaskAcceptedInputClaim::new(
                expected.task().base().task_id.clone(),
                expected.generation(),
                owner_id,
                work_descriptor,
                input_responses,
            )))
        }

        fn request_cancellation_and_clear_input_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            cancelled_task: FinalTask,
            _cancelled_notification: FinalTaskStatusNotification,
        ) -> McpResult<Option<FinalTaskSnapshot>> {
            if let Some(snapshot) = self
                .cancellation_result_override
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            {
                return Ok(Some(snapshot));
            }
            let mut snapshot = self
                .snapshot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.force_false_cas.load(AtomicOrdering::SeqCst)
                || snapshot.generation() != expected.generation()
            {
                return Ok(None);
            }
            let generation = snapshot
                .generation()
                .checked_add(1)
                .ok_or_else(|| McpError::internal_error("probe generation exhausted"))?;
            *snapshot = FinalTaskSnapshot::new(cancelled_task, generation);
            Ok(Some(snapshot.clone()))
        }

        fn request_cancellation(&self, _task_id: &FinalTaskId) -> McpResult<()> {
            Ok(())
        }

        fn request_cancellation_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<bool> {
            Ok(!self.force_false_cas.load(AtomicOrdering::SeqCst)
                && self.snapshot().generation() == expected.generation())
        }

        fn is_cancellation_requested(&self, _task_id: &FinalTaskId) -> McpResult<bool> {
            Ok(true)
        }
    }

    #[test]
    fn task_03_in_memory_runtime_constructor_lifecycle_positive() {
        let runtime = FinalTaskRuntime::in_memory(
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid in-memory task policy"),
            Arc::new(|_| {}),
        );
        let service_runner = runtime
            .install_task_service(1, Arc::new(FailingFinalTaskSupervisor))
            .expect("installing a caller-owned service reserves the runner");
        let service_cx = Cx::for_testing();
        let _running_service = enter_task_service_runner(service_runner, &service_cx);

        let task_id = runtime
            .create_task_with_work(final_test_work_descriptor(), Some("accepted".to_owned()))
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
    fn task_03_runtime_accepts_bound_custom_store_handoffs() {
        let initial = final_working_task_without_ttl("task-runtime-custom-handoff-positive");
        let task_id = initial.base().task_id.clone();
        let store = Arc::new(RuntimeBoundaryProbeFinalTaskStore::new(initial));
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(|_| {}),
        );

        let initial_work = runtime
            .recover_initial_work()
            .expect("a bound initial-work claim is accepted")
            .expect("the valid custom store provides initial work");
        assert_eq!(initial_work.task_id(), &task_id);
        assert_eq!(initial_work.generation(), store.snapshot().generation());
        assert_eq!(
            initial_work.work_descriptor(),
            &final_test_work_descriptor()
        );

        let responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed accepted-input fixture");
        store.set_accepted_inputs(responses.clone());
        let accepted_input = runtime
            .recover_accepted_input()
            .expect("a bound accepted-input claim is accepted")
            .expect("the valid custom store provides accepted input");
        assert_eq!(accepted_input.task_id(), &task_id);
        assert_eq!(accepted_input.generation(), store.snapshot().generation());
        assert_eq!(accepted_input.input_responses(), &responses);
    }

    #[test]
    fn task_03_runtime_accepts_valid_custom_store_create_with_work() {
        let initial = final_working_task_without_ttl("task-runtime-custom-create-positive-old");
        let store = Arc::new(RuntimeBoundaryProbeFinalTaskStore::new(initial));
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(|_| {}),
        );
        let created = final_working_task_without_ttl("task-runtime-custom-create-positive-new");

        runtime
            .persist_new_with_work(created.clone(), final_test_work_descriptor())
            .expect("a valid custom-store create-with-work remains accepted");

        let committed = store.snapshot();
        assert!(
            final_tasks_match_exactly(committed.task(), &created).expect("compare created task"),
            "the valid custom store retains exactly the create-with-work task"
        );
    }

    #[test]
    fn task_03_runtime_rejects_malformed_custom_store_read_without_mutating_the_snapshot() {
        let valid = final_working_task_without_ttl("task-runtime-custom-read");
        let task_id = valid.base().task_id.clone();
        let store = Arc::new(RuntimeBoundaryProbeFinalTaskStore::new(valid.clone()));
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(|_| {}),
        );

        assert!(matches!(
            runtime
                .get_task(&task_id)
                .expect("the otherwise identical valid custom-store task is admitted")
                .task,
            FinalTask::Working(_)
        ));

        let FinalTask::Working(mut malformed_base) = valid else {
            unreachable!("the fixture is a working task");
        };
        malformed_base.status = FinalTaskStatus::Cancelled;
        store.replace_snapshot_for_read(FinalTask::Working(malformed_base));
        let before = store.snapshot();
        let before_wire = serde_json::to_value(before.task())
            .expect("serialize malformed custom-store snapshot before rejection");

        let error = runtime
            .get_task(&task_id)
            .expect_err("changing only the retained status must reject the custom-store read");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);

        let after = store.snapshot();
        assert_eq!(
            serde_json::to_value(after.task())
                .expect("serialize malformed custom-store snapshot after rejection"),
            before_wire,
            "the runtime must not rewrite a malformed custom-store read"
        );
        assert_eq!(
            after.generation(),
            before.generation(),
            "a rejected custom-store read cannot advance its generation"
        );
    }

    #[test]
    fn task_03_runtime_write_boundary_rejects_malformed_custom_store_transition_unchanged() {
        let initial = final_working_task_without_ttl("task-runtime-custom-write");
        let task_id = initial.base().task_id.clone();
        let store = Arc::new(RuntimeBoundaryProbeFinalTaskStore::new(initial));
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(|_| {}),
        );
        let initial_snapshot = runtime
            .load_task_snapshot(&task_id)
            .expect("the valid custom-store snapshot is admitted at the runtime boundary");

        let FinalTask::Working(mut updated_base) = initial_snapshot.task().clone() else {
            unreachable!("the fixture begins in the working state");
        };
        updated_base.status_message = Some("accepted update".to_owned());
        let accepted = FinalTask::Working(updated_base);
        runtime
            .persist_transition_clearing_input(&initial_snapshot, accepted.clone())
            .expect("the custom store receives an otherwise valid transition");
        assert_eq!(
            store.transition_write_calls.load(AtomicOrdering::SeqCst),
            1,
            "the accepted transition reaches the arbitrary store exactly once"
        );

        let before_rejection = store.snapshot();
        let before_wire = serde_json::to_value(before_rejection.task())
            .expect("serialize custom-store snapshot before malformed write");
        let FinalTask::Working(mut malformed_base) = accepted else {
            unreachable!("the accepted transition remains working");
        };
        malformed_base.status = FinalTaskStatus::Cancelled;
        let malformed = FinalTask::Working(malformed_base);

        let error = runtime
            .persist_transition_clearing_input(&before_rejection, malformed)
            .expect_err(
                "changing only the status/variant alignment rejects before the store write",
            );
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
        assert_eq!(
            store.transition_write_calls.load(AtomicOrdering::SeqCst),
            1,
            "the malformed transition cannot reach an arbitrary store implementation"
        );
        let after_rejection = store.snapshot();
        assert_eq!(
            serde_json::to_value(after_rejection.task())
                .expect("serialize custom-store snapshot after malformed write rejection"),
            before_wire,
            "the near-identical rejected write leaves the durable task unchanged"
        );
        assert_eq!(
            after_rejection.generation(),
            before_rejection.generation(),
            "the rejected write cannot advance the arbitrary store generation"
        );
    }

    #[test]
    fn task_03_runtime_rejects_custom_store_create_descriptor_and_retention_drift_unchanged() {
        let initial = final_working_task_without_ttl("task-runtime-custom-create");
        let task_id = initial.base().task_id.clone();
        let store = Arc::new(RuntimeBoundaryProbeFinalTaskStore::new(initial));
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(|_| {}),
        );
        let before = store.snapshot();

        let invalid_descriptor = FinalTaskWorkDescriptor(serde_json::Value::Null);
        let error = runtime
            .persist_new_with_work(
                final_working_task_without_ttl("task-runtime-custom-new"),
                invalid_descriptor,
            )
            .expect_err("a null work descriptor rejects before a permissive create");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);

        let FinalTask::Working(mut identity_drifted_base) = before.task().clone() else {
            unreachable!("the probe begins working");
        };
        identity_drifted_base.task_id = FinalTaskId::parse("task-runtime-custom-create-other")
            .expect("fixed replacement task ID is valid");
        let error = runtime
            .persist_transition_clearing_input(&before, FinalTask::Working(identity_drifted_base))
            .expect_err("changing only task identity rejects before the store write");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);

        let FinalTask::Working(mut drifted_base) = before.task().clone() else {
            unreachable!("the probe begins working");
        };
        drifted_base.ttl_ms = Some(serde_json::from_str("1").expect("valid ttl fixture"));
        let error = runtime
            .persist_transition_clearing_input(&before, FinalTask::Working(drifted_base))
            .expect_err("changing only retained ttl rejects before the store write");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);

        let after = store.snapshot();
        assert!(
            final_tasks_match_exactly(before.task(), after.task()).expect("compare probe task"),
            "create and retention rejections leave the permissive store unchanged"
        );
        assert_eq!(after.generation(), before.generation());
        assert_eq!(after.task().base().task_id, task_id);
    }

    #[test]
    fn task_03_runtime_rejects_custom_store_recovery_claim_binding_substitution_unchanged() {
        let initial = final_working_task_without_ttl("task-runtime-custom-recovery");
        let task_id = initial.base().task_id.clone();
        let store = Arc::new(RuntimeBoundaryProbeFinalTaskStore::new(initial));
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(|_| {}),
        );
        let baseline = store.snapshot();
        *store
            .initial_claim_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(FinalTaskInitialWorkClaim::new(
                task_id.clone(),
                baseline.generation(),
                "different-owner",
                final_test_work_descriptor(),
            ));
        let error = runtime
            .recover_initial_work()
            .expect_err("changing only the owner rejects an initial recovery handoff");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);

        *store
            .initial_claim_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(FinalTaskInitialWorkClaim::new(
                FinalTaskId::parse("task-runtime-custom-recovery-other")
                    .expect("fixed substituted task ID is valid"),
                baseline.generation(),
                FINAL_TASK_TEST_DIRECT_OWNER,
                final_test_work_descriptor(),
            ));
        let error = runtime
            .recover_initial_work()
            .expect_err("changing only task identity rejects an initial recovery handoff");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);

        *store
            .initial_claim_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(FinalTaskInitialWorkClaim::new(
                task_id.clone(),
                baseline.generation(),
                FINAL_TASK_TEST_DIRECT_OWNER,
                FinalTaskWorkDescriptor(serde_json::Value::Null),
            ));
        let error = runtime
            .recover_initial_work()
            .expect_err("changing only the work descriptor rejects before application handoff");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);

        let responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed accepted-input fixture");
        store.set_accepted_inputs(responses.clone());
        *store
            .accepted_claim_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(FinalTaskAcceptedInputClaim::new(
                task_id.clone(),
                baseline.generation().saturating_add(1),
                FINAL_TASK_TEST_DIRECT_OWNER,
                final_test_work_descriptor(),
                responses,
            ));
        let error = runtime
            .recover_accepted_input()
            .expect_err("changing only the generation rejects an accepted-input handoff");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);

        *store
            .accepted_claim_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(FinalTaskAcceptedInputClaim::new(
                task_id,
                baseline.generation(),
                FINAL_TASK_TEST_DIRECT_OWNER,
                final_test_work_descriptor(),
                FinalTaskInputResponses::new(),
            ));
        let error = runtime
            .recover_accepted_input()
            .expect_err("changing only accepted-input payload emptiness rejects before handoff");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);
        let after = store.snapshot();
        assert!(
            final_tasks_match_exactly(baseline.task(), after.task()).expect("compare probe task"),
            "rejected recovery claims never rewrite the retained task"
        );
        assert_eq!(after.generation(), baseline.generation());
    }

    #[test]
    fn task_03_runtime_rejects_custom_store_cancellation_substitution_and_false_cas_unchanged() {
        let initial = final_working_task_without_ttl("task-runtime-custom-cancel");
        let task_id = initial.base().task_id.clone();
        let store = Arc::new(RuntimeBoundaryProbeFinalTaskStore::new(initial));
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(|_| {}),
        );
        let before = store.snapshot();
        let FinalTask::Working(base) = before.task().clone() else {
            unreachable!("the probe begins working");
        };
        let substituted = FinalTask::Cancelled(
            transition_terminal_final_task_base(
                base,
                FinalTaskStatus::Cancelled,
                Some("substituted cancellation".to_owned()),
            )
            .expect("fixed cancellation transition"),
        );
        *store
            .cancellation_result_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(FinalTaskSnapshot::new(
            substituted,
            before.generation().saturating_add(1),
        ));
        let error = runtime
            .cancel_task(&task_id)
            .expect_err("a near-identical cancelled task cannot substitute the runtime intent");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);

        let FinalTask::Working(mut substituted_active_base) = before.task().clone() else {
            unreachable!("the probe remains working after rejected terminal substitution");
        };
        substituted_active_base.status_message = Some("substituted active cancellation".to_owned());
        *store
            .cancellation_result_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(FinalTaskSnapshot::new(
            FinalTask::Working(substituted_active_base),
            before.generation(),
        ));
        let error = runtime
            .cancel_task(&task_id)
            .expect_err("an active cancellation result must retain the exact expected snapshot");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);

        *store
            .cancellation_result_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        store.force_false_cas.store(true, AtomicOrdering::SeqCst);
        let FinalTask::Working(mut terminal_base) = before.task().clone() else {
            unreachable!("the probe remains working after rejected substitution");
        };
        terminal_base.status_message = Some("terminal candidate".to_owned());
        let error = runtime
            .persist_transition_clearing_input(&before, FinalTask::Working(terminal_base))
            .expect_err("a false compare-and-swap is not an accepted terminal transition");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
        let after = store.snapshot();
        assert!(
            final_tasks_match_exactly(before.task(), after.task()).expect("compare probe task"),
            "substitution and false-CAS rejection leave the durable task unchanged"
        );
        assert_eq!(after.generation(), before.generation());
    }

    #[test]
    fn task_03_runtime_rejects_custom_store_terminal_transition_substitution() {
        let initial = final_working_task_without_ttl("task-runtime-custom-terminal");
        let task_id = initial.base().task_id.clone();
        let store = Arc::new(RuntimeBoundaryProbeFinalTaskStore::new(initial));
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(|_| {}),
        );
        let before = store.snapshot();
        let FinalTask::Working(base) = before.task().clone() else {
            unreachable!("the probe begins working");
        };
        let intended = FinalTask::Cancelled(
            transition_terminal_final_task_base(
                base.clone(),
                FinalTaskStatus::Cancelled,
                Some("intended terminal transition".to_owned()),
            )
            .expect("fixed terminal transition is valid"),
        );
        let substituted = FinalTask::Cancelled(
            transition_terminal_final_task_base(
                base,
                FinalTaskStatus::Cancelled,
                Some("substituted terminal transition".to_owned()),
            )
            .expect("fixed substituted terminal transition is valid"),
        );
        *store
            .transition_result_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(substituted);

        let error = runtime
            .persist_transition_clearing_input(&before, intended)
            .expect_err("a store may not substitute a near-identical terminal transition");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);
        let after = store.snapshot();
        assert!(
            !final_tasks_match_exactly(before.task(), after.task()).expect("compare probe task"),
            "the deliberately permissive store records its substituted write for boundary detection"
        );
        assert_eq!(after.generation(), before.generation().saturating_add(1));
        assert_eq!(after.task().base().task_id, task_id);
    }

    #[test]
    fn task_03_in_memory_false_cas_does_not_reclaim_expired_retained_task() {
        let (store, now) = in_memory_store_with_test_clock(4);
        let task =
            final_working_task_with_wire_durations("task-false-cas-retention", Some("1"), None);
        let task_id = task.base().task_id.clone();
        let notification = final_task_notification(&task);
        store
            .create_task_with_work(task.clone(), notification, final_test_work_descriptor())
            .expect("bounded retained task is created");
        let current = store
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generations
            .get(&task_id)
            .copied()
            .expect("created task retains a generation");
        *now.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) += StdDuration::from_millis(2);
        let stale = FinalTaskSnapshot::new(task.clone(), current.saturating_add(1));
        assert!(
            !store
                .replace_task_if_current(&stale, task.clone(), final_task_notification(&task))
                .expect("stale compare-and-swap returns false"),
            "changing only the expected generation loses the CAS"
        );
        let state = store
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            state.tasks.contains_key(&task_id) && state.expires_at.contains_key(&task_id),
            "a false CAS must not use expiry cleanup to delete retained task state"
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
        let service_runner = runtime
            .install_task_service(1, Arc::new(FailingFinalTaskSupervisor))
            .expect("installing a caller-owned service reserves the runner");
        let service_cx = Cx::for_testing();
        let _running_service = enter_task_service_runner(service_runner, &service_cx);
        let first = runtime
            .create_task_with_work(final_test_work_descriptor(), None)
            .expect("first task fits the one-task capacity");
        let first_id = first.task.base().task_id.clone();

        assert!(
            runtime
                .create_task_with_work(final_test_work_descriptor(), None)
                .is_err(),
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
    fn task_03_in_memory_store_rejects_unrepresentable_durations_before_state_mutation() {
        const ONE_OVER_U64: &str = "18446744073709551616";
        let (store, _) = in_memory_store_with_test_clock(2);

        for (task_id, ttl_ms, poll_interval_ms, field) in [
            (
                "task-unrepresentable-ttl",
                Some(ONE_OVER_U64),
                None,
                "ttlMs",
            ),
            (
                "task-unrepresentable-poll",
                None,
                Some(ONE_OVER_U64),
                "pollIntervalMs",
            ),
        ] {
            let task = final_working_task_with_wire_durations(task_id, ttl_ms, poll_interval_ms);
            let task_id = task.base().task_id.clone();
            let error = store
                .create_task(task.clone(), final_task_notification(&task))
                .expect_err("unbounded wire duration cannot enter the bounded in-memory runtime");

            assert!(error.message.contains(field));
            assert!(
                store
                    .get_task(&task_id)
                    .expect("rejected task lookup remains readable")
                    .is_none(),
                "the rejected {field} duration leaves no retained task"
            );
            assert!(store.latest_notification(&task_id).is_none());
            assert_eq!(store.task_count(), 0);
        }
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
    fn task_03_final_runtime_emits_null_ttl_and_retains_without_automatic_expiry() {
        const ELAPSED_MS: u64 = 60_000;
        let (store, now) = in_memory_store_with_test_clock(1);
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::with_unlimited_ttl(&AllowUnlimitedFinalTaskRetention, None)
                .expect("explicit authority admits null TTL retention"),
            Arc::new(|_| {}),
        );
        let service_runner = runtime
            .install_task_service(1, Arc::new(FailingFinalTaskSupervisor))
            .expect("install caller-owned service runner for task creation");
        let service_cx = Cx::for_testing();
        let _running_service = enter_task_service_runner(service_runner, &service_cx);

        let created = runtime
            .create_task_with_work(final_test_work_descriptor(), None)
            .expect("authorized null-TTL task is durably created");
        let task_id = created.task.base().task_id.clone();
        assert!(created.task.base().ttl_ms.is_none());
        assert_eq!(runtime.config.ttl_ms(), None);

        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(StdDuration::from_millis(ELAPSED_MS))
            .expect("test clock can advance past an unlimited task lifetime");
        drop(clock);

        assert!(
            runtime.get_task(&task_id).is_ok(),
            "only null TTL differs from the finite deadline case, so it remains retained"
        );
        assert_eq!(store.task_count(), 1);
    }

    #[test]
    fn task_03_final_runtime_rejects_null_ttl_without_retention_authority() {
        assert!(
            FinalTaskRuntimeConfig::with_ttl(None, None).is_err(),
            "only omitting the explicit retention authority rejects unlimited task retention"
        );
    }

    #[test]
    fn task_03_final_runtime_finite_ttl_reclaims_at_the_same_deadline() {
        const TTL_MS: u64 = 60_000;
        let (store, now) = in_memory_store_with_test_clock(1);
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::with_ttl(Some(TTL_MS), None)
                .expect("positive TTL is a valid Task retention value"),
            Arc::new(|_| {}),
        );
        let service_runner = runtime
            .install_task_service(1, Arc::new(FailingFinalTaskSupervisor))
            .expect("install caller-owned service runner for task creation");
        let service_cx = Cx::for_testing();
        let _running_service = enter_task_service_runner(service_runner, &service_cx);

        let created = runtime
            .create_task_with_work(final_test_work_descriptor(), None)
            .expect("finite-TTL task is durably created");
        let task_id = created.task.base().task_id.clone();
        assert!(created.task.base().ttl_ms.is_some());

        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(StdDuration::from_millis(TTL_MS))
            .expect("test clock reaches the finite task deadline");
        drop(clock);

        assert!(
            runtime.get_task(&task_id).is_err(),
            "changing only null TTL to a positive TTL permits reclamation at its deadline"
        );
        assert_eq!(store.task_count(), 0);
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
    fn task_03_in_memory_store_allows_status_update_but_rejects_ttl_drift_without_losing_recovery()
    {
        const TTL_MS: u64 = 60_000;
        let (store, now) = in_memory_store_with_test_clock(1);
        let expiring = final_working_task_with_ttl("task-replacement-expiry", TTL_MS);
        let task_id = expiring.base().task_id.clone();
        store
            .create_task_with_work(
                expiring.clone(),
                final_task_notification(&expiring),
                final_test_work_descriptor(),
            )
            .expect("expiring task and its initial supervisor handoff create atomically");
        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(StdDuration::from_millis(TTL_MS - 1))
            .expect("test clock reaches one millisecond before creation expiry");
        drop(clock);

        let snapshot_before_update = store
            .get_task_snapshot(&task_id)
            .expect("pre-deadline task snapshot is readable")
            .expect("pre-deadline task remains retained");
        let FinalTask::Working(mut updated_base) = expiring.clone() else {
            unreachable!("the fixture is a working task");
        };
        updated_base.status_message = Some("still working".to_owned());
        let updated = FinalTask::Working(updated_base);
        assert!(
            store
                .replace_task_if_current(
                    &snapshot_before_update,
                    updated.clone(),
                    final_task_notification(&updated),
                )
                .expect("an otherwise identical working update is accepted"),
            "changing only the mutable status message preserves the creation retention contract"
        );

        let snapshot_before_rejection = store
            .get_task_snapshot(&task_id)
            .expect("post-update task snapshot is readable")
            .expect("post-update task remains retained");
        let task_before_rejection = serde_json::to_value(snapshot_before_rejection.task())
            .expect("serialize retained task before TTL rejection");
        let notification_before_rejection = serde_json::to_value(
            store
                .latest_notification(&task_id)
                .expect("post-update notification remains retained"),
        )
        .expect("serialize retained notification before TTL rejection");
        let FinalTask::Working(mut ttl_drift_base) = updated else {
            unreachable!("the accepted update remains a working task");
        };
        ttl_drift_base.ttl_ms = None;
        let ttl_drift = FinalTask::Working(ttl_drift_base);
        let error = store
            .replace_task_if_current(
                &snapshot_before_rejection,
                ttl_drift.clone(),
                final_task_notification(&ttl_drift),
            )
            .expect_err("changing only ttlMs must not rewrite durable retention");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
        assert!(error.message.contains("ttlMs"));

        let snapshot_after_rejection = store
            .get_task_snapshot(&task_id)
            .expect("task snapshot remains readable after TTL rejection")
            .expect("TTL rejection cannot remove the retained task");
        assert_eq!(
            serde_json::to_value(snapshot_after_rejection.task())
                .expect("serialize retained task after TTL rejection"),
            task_before_rejection,
            "the near-identical rejected transition preserves the durable task"
        );
        assert_eq!(
            snapshot_after_rejection.generation(),
            snapshot_before_rejection.generation(),
            "the rejected TTL drift cannot advance the durable generation"
        );
        assert_eq!(
            serde_json::to_value(
                store
                    .latest_notification(&task_id)
                    .expect("notification remains retained after TTL rejection"),
            )
            .expect("serialize retained notification after TTL rejection"),
            notification_before_rejection,
            "the rejected TTL drift cannot replace the durable notification"
        );
        let recovered = test_next_initial_work(&store)
            .expect("initial supervisor handoff remains recoverable")
            .expect("retention rejection cannot erase initial task work");
        assert_eq!(recovered.task_id(), &task_id);
        assert_eq!(
            store
                .work_descriptor_if_current(&recovered)
                .expect("recovered snapshot exposes its durable work descriptor")
                .expect("initial work retains its descriptor"),
            final_test_work_descriptor()
        );

        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(StdDuration::from_millis(1))
            .expect("test clock reaches the original creation deadline");
        drop(clock);
        assert!(
            store
                .get_task(&task_id)
                .expect("expired task lookup is readable")
                .is_none(),
            "the accepted status update and rejected TTL drift retain the original creation deadline"
        );
    }

    #[test]
    fn task_03_in_memory_runtime_reclaims_expired_task_before_capacity_check_positive() {
        let store = Arc::new(
            InMemoryFinalTaskStore::new(1).expect("one retained task is a valid bounded store"),
        );
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let first = create_final_task_state_fixture(&runtime, None);
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

        let second = create_final_task_state_fixture(&runtime, None);
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
        let first_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();
        let second_id = create_final_task_state_fixture(&runtime, None)
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
        let service_runner = runtime
            .install_task_service(1, Arc::new(FailingFinalTaskSupervisor))
            .expect("install caller-owned service runner before task advertisement");
        let service_cx = Cx::for_testing();
        let _running_service = enter_task_service_runner(service_runner, &service_cx);

        let created = runtime
            .create_task_with_work(final_test_work_descriptor(), Some("accepted".to_owned()))
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
    fn task_03_final_notification_emitters_deliver_after_durable_mutation() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let delivered = Arc::new(AtomicBool::new(false));
        let delivered_by_emitter = Arc::clone(&delivered);
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(move |_| {
                delivered_by_emitter.store(true, AtomicOrdering::SeqCst);
            }),
        );
        let task = final_working_task_without_ttl("task-emitter-positive");
        let task_id = task.base().task_id.clone();

        runtime
            .persist_new_with_work(task, final_test_work_descriptor())
            .expect("a non-panicking emitter preserves successful durable mutation");
        assert!(
            delivered.load(AtomicOrdering::SeqCst),
            "the installed emitter receives the post-commit notification"
        );
        assert!(
            store
                .get_task(&task_id)
                .expect("read task after notification delivery")
                .is_some(),
            "the notification observes a task that was already durable"
        );
    }

    #[test]
    fn task_03_final_panicking_emitter_preserves_accepted_create_and_continues() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let continued = Arc::new(AtomicBool::new(false));
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(|_| panic!("planted final task notification emitter panic")),
        );
        let continued_by_second_emitter = Arc::clone(&continued);
        runtime.add_notification_emitter(Arc::new(move |_| {
            continued_by_second_emitter.store(true, AtomicOrdering::SeqCst);
        }));
        let runner = runtime
            .install_task_service(1, Arc::new(FailingFinalTaskSupervisor))
            .expect("install a ready service before public task creation");
        let service_cx = Cx::for_testing();
        let _running_service = enter_task_service_runner(runner, &service_cx);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.create_task_with_work(final_test_work_descriptor(), None)
        }));
        let created = result
            .expect("an emitter panic is contained after the durable write")
            .expect("a post-commit emitter panic cannot turn accepted creation into an error");
        let task_id = created.task.base().task_id.clone();
        assert!(
            continued.load(AtomicOrdering::SeqCst),
            "a later emitter still receives the same durable notification after one panic"
        );
        assert!(
            store
                .get_task(&task_id)
                .expect("read task after contained emitter panic")
                .is_some(),
            "the durable task mutation survives the contained emitter panic"
        );
    }

    #[test]
    fn task_03_final_update_non_panicking_emitter_preserves_committed_state() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let primary_delivered = Arc::new(AtomicBool::new(false));
        let primary_delivered_by_emitter = Arc::clone(&primary_delivered);
        let runtime = FinalTaskRuntime::new(
            store.clone() as Arc<dyn FinalTaskStore>,
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(move |_| {
                primary_delivered_by_emitter.store(true, AtomicOrdering::SeqCst);
            }),
        );
        let continued = Arc::new(AtomicBool::new(false));
        let continued_by_second_emitter = Arc::clone(&continued);
        runtime.add_notification_emitter(Arc::new(move |_| {
            continued_by_second_emitter.store(true, AtomicOrdering::SeqCst);
        }));
        let task_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();
        runtime
            .require_input(&task_id, final_roots_request(), None)
            .expect("task enters input_required before the update RPC");
        primary_delivered.store(false, AtomicOrdering::SeqCst);
        continued.store(false, AtomicOrdering::SeqCst);

        let mut parameters = final_task_method_parameters(&task_id);
        parameters["inputResponses"] = serde_json::json!({"roots": {"roots": []}});
        let response = dispatch_final_tasks_update(&runtime, parameters)
            .expect("a delivered post-commit notification preserves the update RPC success");

        assert_eq!(response["resultType"], "complete");
        assert!(
            primary_delivered.load(AtomicOrdering::SeqCst),
            "the first emitter receives the committed update notification"
        );
        assert!(
            continued.load(AtomicOrdering::SeqCst),
            "the later emitter receives the same committed update notification"
        );
        assert!(matches!(
            runtime
                .get_task(&task_id)
                .expect("read task after successful update RPC")
                .task,
            FinalTask::Working(_)
        ));
        assert!(matches!(
            store
                .latest_notification(&task_id)
                .expect("read retained update notification")
                .params
                .task,
            FinalTask::Working(_)
        ));
    }

    #[test]
    fn task_03_final_update_panicking_emitter_preserves_committed_state_and_replay_safety() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = FinalTaskRuntime::new(
            store.clone() as Arc<dyn FinalTaskStore>,
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(|_| panic!("planted final task notification emitter panic")),
        );
        let continued = Arc::new(AtomicBool::new(false));
        let continued_by_second_emitter = Arc::clone(&continued);
        runtime.add_notification_emitter(Arc::new(move |_| {
            continued_by_second_emitter.store(true, AtomicOrdering::SeqCst);
        }));
        let task_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();
        runtime
            .require_input(&task_id, final_roots_request(), None)
            .expect("task enters input_required despite prior delivery degradation");
        continued.store(false, AtomicOrdering::SeqCst);

        let mut parameters = final_task_method_parameters(&task_id);
        parameters["inputResponses"] = serde_json::json!({"roots": {"roots": []}});
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dispatch_final_tasks_update(&runtime, parameters.clone())
        }));
        let response = result
            .expect("a panicking emitter is contained after the durable update")
            .expect("delivery degradation cannot turn the committed update RPC into an error");

        assert_eq!(response["resultType"], "complete");
        assert!(
            continued.load(AtomicOrdering::SeqCst),
            "a later emitter still receives the committed update notification"
        );
        assert!(matches!(
            runtime
                .get_task(&task_id)
                .expect("read task after contained emitter panic")
                .task,
            FinalTask::Working(_)
        ));
        assert!(matches!(
            store
                .latest_notification(&task_id)
                .expect("read retained notification after contained emitter panic")
                .params
                .task,
            FinalTask::Working(_)
        ));

        let generation_after_commit = store
            .get_task_snapshot(&task_id)
            .expect("read durable generation after committed update")
            .expect("committed update retains its task")
            .generation();
        let replay = dispatch_final_tasks_update(&runtime, parameters)
            .expect("the retry after delivery degradation is acknowledged as a replay");
        assert_eq!(replay["resultType"], "complete");
        assert_eq!(
            store
                .get_task_snapshot(&task_id)
                .expect("read durable generation after replay")
                .expect("replay retains its task")
                .generation(),
            generation_after_commit,
            "replaying the accepted update cannot create a second durable transition"
        );
    }

    #[test]
    fn task_03_final_get_dispatch_requires_official_task_id_and_metadata() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();

        let response = dispatch_final_tasks_get(&runtime, final_task_method_parameters(&task_id))
            .expect("official final tasks/get parameters are admitted");
        // The frozen final wire is the FLAT complete envelope (resultType +
        // task fields as top-level members), not a nested `task` object —
        // see the protocol GetTaskResult round-trip fixtures.
        assert_eq!(response["resultType"], serde_json::json!("complete"));
        assert_eq!(response["taskId"], serde_json::json!(task_id));
        assert!(
            dispatch_final_tasks_get(
                &runtime,
                serde_json::json!({
                    "id": task_id.clone(),
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                }),
            )
            .is_err(),
            "changing only taskId to the legacy id field fails final strict decoding"
        );
    }

    #[test]
    fn task_03_final_cancel_dispatch_requires_official_task_id_and_metadata() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();
        let missing_capabilities = serde_json::json!({
            "taskId": task_id.clone(),
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION
            }
        });
        assert!(
            dispatch_final_tasks_cancel(&runtime, missing_capabilities).is_err(),
            "changing only the required modern metadata fails final tasks/cancel admission"
        );

        let response =
            dispatch_final_tasks_cancel(&runtime, final_task_method_parameters(&task_id))
                .expect("official final tasks/cancel parameters are admitted");
        assert_eq!(response["resultType"], "complete");
        assert!(
            runtime
                .is_cancellation_requested(&task_id)
                .expect("official final cancellation persists cooperative intent")
        );
    }

    #[test]
    fn task_03_final_update_dispatch_requires_exact_metadata() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();
        runtime
            .require_input(&task_id, final_roots_request(), None)
            .expect("task awaits one typed final input response");
        let input_responses = serde_json::json!({"roots": {"roots": []}});
        let missing_metadata = serde_json::json!({
            "taskId": task_id.clone(),
            "inputResponses": input_responses.clone(),
        });

        assert!(
            dispatch_final_tasks_update(&runtime, missing_metadata).is_err(),
            "changing only the final request metadata rejects tasks/update before mutation"
        );
        assert!(matches!(
            runtime
                .get_task(&task_id)
                .expect("read task after rejected update metadata")
                .task,
            FinalTask::InputRequired { .. }
        ));

        let mut admitted = final_task_method_parameters(&task_id);
        admitted["inputResponses"] = input_responses;
        let response = dispatch_final_tasks_update(&runtime, admitted)
            .expect("exact final metadata admits tasks/update");
        assert_eq!(response["resultType"], "complete");
        assert!(matches!(
            runtime
                .get_task(&task_id)
                .expect("read task after admitted final update")
                .task,
            FinalTask::Working(_)
        ));
    }

    #[test]
    fn task_03_final_accepted_input_reaches_resumed_supervisor() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
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
            .require_input(
                &task_id,
                requests,
                Some("awaiting both roots responses".to_owned()),
            )
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
        let resumed_generation = store
            .get_task_snapshot(&task_id)
            .expect("read resumed task generation")
            .expect("resumed task remains retained")
            .generation();

        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("resumed task exposes one supervisor handoff")
            .expect("all accepted input values are retained for the resumed worker");
        assert_eq!(accepted.task_id(), &task_id);
        assert_eq!(accepted.generation(), resumed_generation);
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
    fn task_03_final_new_input_cycle_clears_unconsumed_prior_handoff() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();

        let mut first_requests = FinalTaskInputRequests::new();
        first_requests.insert(
            "first-roots".to_owned(),
            serde_json::from_value(serde_json::json!({"method": "roots/list"}))
                .expect("typed first-cycle roots request"),
        );
        runtime
            .require_input(&task_id, first_requests, None)
            .expect("enter first input cycle");
        let first_responses: FinalTaskInputResponses = serde_json::from_value(serde_json::json!({
            "first-roots": {"roots": [{"uri": "file:///first-cycle"}]}
        }))
        .expect("typed first-cycle response");
        runtime
            .update_task(&task_id, &first_responses)
            .expect("complete first input cycle without consuming its handoff");

        let mut second_requests = FinalTaskInputRequests::new();
        second_requests.insert(
            "second-roots".to_owned(),
            serde_json::from_value(serde_json::json!({"method": "roots/list"}))
                .expect("typed second-cycle roots request"),
        );
        runtime
            .require_input(&task_id, second_requests, None)
            .expect("enter second input cycle and clear the first handoff");
        let second_responses: FinalTaskInputResponses = serde_json::from_value(serde_json::json!({
            "second-roots": {"roots": [{"uri": "file:///second-cycle"}]}
        }))
        .expect("typed second-cycle response");
        runtime
            .update_task(&task_id, &second_responses)
            .expect("complete second input cycle");

        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("read second-cycle supervisor handoff")
            .expect("second cycle retains its accepted response");
        assert_eq!(accepted.input_responses(), &second_responses);
        assert!(
            !accepted.input_responses().contains_key("first-roots"),
            "starting a new cycle atomically removes unconsumed prior-cycle input"
        );
    }

    #[test]
    fn task_03_final_terminal_transition_fences_stale_input_take() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();
        runtime
            .require_input(&task_id, final_roots_request(), None)
            .expect("task requests roots before terminal race");
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed roots response");
        runtime
            .update_task(&task_id, &input_responses)
            .expect("accepted input returns task to working");
        let stale_working = store
            .get_task_snapshot(&task_id)
            .expect("read pre-terminal generation")
            .expect("working task remains retained");
        let result: FinalTaskCallToolResult =
            serde_json::from_value(serde_json::json!({"content": []}))
                .expect("typed terminal tool result");
        runtime
            .complete_task(&task_id, result, None)
            .expect("terminal transition wins before stale supervisor take");
        let terminal = store
            .get_task_snapshot(&task_id)
            .expect("read terminal generation")
            .expect("terminal task remains retained");

        assert_ne!(terminal.generation(), stale_working.generation());
        assert!(matches!(terminal.task(), FinalTask::Completed { .. }));
        assert!(
            test_take_input(&store, &stale_working)
                .expect("stale generation take fails closed")
                .is_none(),
            "a stale working generation cannot consume after a terminal winner"
        );
        assert!(
            runtime
                .take_accepted_input(&task_id)
                .expect("terminal task has no supervisor handoff")
                .is_none(),
            "the terminal transition atomically clears previously accepted input"
        );
    }

    #[test]
    fn task_03_final_new_runtime_recovers_unconsumed_input_handoff() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let first_runtime =
            final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&first_runtime, None)
            .task
            .base()
            .task_id
            .clone();
        first_runtime
            .require_input(&task_id, final_roots_request(), None)
            .expect("task requests input before runtime replacement");
        let input_responses: FinalTaskInputResponses = serde_json::from_value(
            serde_json::json!({"roots": {"roots": [{"uri": "file:///recovered"}]}}),
        )
        .expect("typed retained roots response");
        first_runtime
            .update_task(&task_id, &input_responses)
            .expect("store commits task state and input together");
        drop(first_runtime);

        let recovered_runtime =
            final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let accepted = recovered_runtime
            .take_accepted_input(&task_id)
            .expect("new runtime reads the store-owned handoff")
            .expect("unconsumed accepted input survives runtime replacement");
        assert_eq!(accepted.input_responses(), &input_responses);
        assert!(
            recovered_runtime
                .take_accepted_input(&task_id)
                .expect("second recovered take is valid")
                .is_none(),
            "the recovered handoff remains one-shot"
        );
    }

    #[test]
    fn task_03_final_recovery_continues_after_lost_candidate_cas() {
        let inner = Arc::new(InMemoryFinalTaskStore::default());
        let setup_runtime =
            final_task_runtime(Arc::clone(&inner), Arc::new(AtomicBool::new(false)));
        for (task_id, uri) in [
            ("task-lost-cas-first", "file:///lost-candidate"),
            ("task-lost-cas-second", "file:///surviving-candidate"),
        ] {
            let task = final_working_task_without_ttl(task_id);
            let task_id = task.base().task_id.clone();
            inner
                .create_task_with_work(
                    task.clone(),
                    final_task_notification(&task),
                    final_test_work_descriptor(),
                )
                .expect("durably create recoverable task work");
            setup_runtime
                .require_input(&task_id, final_roots_request(), None)
                .expect("task requests roots before recovery race");
            let input_responses: FinalTaskInputResponses =
                serde_json::from_value(serde_json::json!({"roots": {"roots": [{"uri": uri}]}}))
                    .expect("typed retained roots response");
            setup_runtime
                .update_task(&task_id, &input_responses)
                .expect("task retains accepted input for recovery");
        }

        let recovery_store = Arc::new(LoseFirstAcceptedRecoveryCandidateStore::new(Arc::clone(
            &inner,
        )));
        let recovery_runtime = FinalTaskRuntime::new(
            recovery_store,
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(|_| {}),
        );
        let recovered = recovery_runtime
            .recover_accepted_input()
            .expect("recovery retries after a lost candidate compare-and-take")
            .expect("a second accepted handoff remains recoverable after the first CAS loss");

        let recovered_wire = serde_json::to_value(recovered.input_responses())
            .expect("serialize recovered accepted input");
        assert_eq!(
            recovered_wire["roots"]["roots"][0]["uri"],
            serde_json::json!("file:///surviving-candidate"),
            "only the first candidate loses its CAS; recovery continues to the next durable handoff"
        );
    }

    #[test]
    fn task_03_final_creation_requires_ready_service_and_recovers_initial_work() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let work_descriptor = FinalTaskWorkDescriptor::new(serde_json::json!({
            "handler": "initial-work",
            "payload": {"request": 7}
        }))
        .expect("non-null application work descriptor is valid");

        assert!(
            runtime.ensure_task_service_ready().is_err(),
            "the read-only readiness probe fails closed before installation"
        );
        assert!(
            runtime
                .create_task_with_work(work_descriptor.clone(), None)
                .is_err(),
            "changing only the absent service authority fails task creation before advertisement"
        );
        assert!(
            runtime.create_task(None).is_err(),
            "bare task creation cannot omit the durable application work descriptor"
        );

        let started = Arc::new(Mutex::new(Vec::new()));
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(RecordingInitialFinalTaskSupervisor {
                    started: Arc::clone(&started),
                }),
            )
            .expect("install caller-owned task service runner");
        assert!(
            runtime
                .create_task_with_work(work_descriptor.clone(), None)
                .is_err(),
            "installing a runner without entering run does not authorize task advertisement"
        );
        assert!(
            runtime.ensure_task_service_ready().is_err(),
            "the probe remains false until the runner has entered"
        );
        let readiness_cx = Cx::for_testing();
        let running_service = enter_task_service_runner(runner, &readiness_cx);
        runtime
            .ensure_task_service_ready()
            .expect("an entered live runner owns the probe generation");
        let created = runtime
            .create_task_with_work(work_descriptor.clone(), Some("accepted".to_owned()))
            .expect("entered service permits durable task creation and advertisement");
        let task_id = created.task.base().task_id.clone();
        drop(running_service);
        assert!(
            runtime.ensure_task_service_ready().is_err(),
            "dropping the entered runner revokes its readiness generation"
        );
        assert!(
            runtime
                .create_task_with_work(final_test_work_descriptor(), None)
                .is_err(),
            "dropping the entered runner revokes creation readiness immediately"
        );
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(RecordingInitialFinalTaskSupervisor {
                    started: Arc::clone(&started),
                }),
            )
            .expect("a dropped runner releases service readiness for recovery");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");
        let cx = Cx::for_testing();

        application_runtime
            .block_on(runner.run(&cx))
            .expect("initial durable work is recovered by the caller-owned supervisor");

        assert!(
            runtime.ensure_task_service_ready().is_err(),
            "a runner that exits from run revokes the readiness probe"
        );
        assert!(
            runtime
                .create_task_with_work(final_test_work_descriptor(), None)
                .is_err(),
            "a runner that exits from run revokes creation readiness"
        );

        assert_eq!(
            started
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            &[(task_id, work_descriptor)],
            "the supervisor receives the exact descriptor bound before task advertisement"
        );
    }

    #[test]
    fn task_03_final_public_creation_holds_readiness_through_durable_commit() {
        let inner = Arc::new(InMemoryFinalTaskStore::default());
        let store = Arc::new(ReadinessLeaseProbeFinalTaskStore::new(inner));
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, None).expect("valid final task policy"),
            Arc::new(|_| {}),
        );
        store.observe_service_signal(Arc::clone(&runtime.service_signal));
        let runner = runtime
            .install_task_service(1, Arc::new(FailingFinalTaskSupervisor))
            .expect("install caller-owned task service runner");
        let service_cx = Cx::for_testing();
        let running_service = enter_task_service_runner(runner, &service_cx);

        runtime
            .create_task_with_work(final_test_work_descriptor(), None)
            .expect("an entered runner accepts a durably recoverable task");

        assert!(
            store.observed_ready_lease.load(AtomicOrdering::SeqCst),
            "the durable create commit holds the exact ready service generation"
        );
        drop(running_service);
    }

    #[test]
    fn task_03_final_public_creation_without_entered_runner_never_reaches_durable_commit() {
        let inner = Arc::new(InMemoryFinalTaskStore::default());
        let store = Arc::new(ReadinessLeaseProbeFinalTaskStore::new(inner));
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, None).expect("valid final task policy"),
            Arc::new(|_| {}),
        );
        store.observe_service_signal(Arc::clone(&runtime.service_signal));
        let _runner = runtime
            .install_task_service(1, Arc::new(FailingFinalTaskSupervisor))
            .expect("installing alone does not enter a task service runner");

        assert!(
            runtime
                .create_task_with_work(final_test_work_descriptor(), None)
                .is_err(),
            "changing only entered runner state rejects public task creation"
        );
        assert!(
            !store.observed_ready_lease.load(AtomicOrdering::SeqCst),
            "a rejected creation cannot call the durable store"
        );
    }

    #[test]
    fn task_03_final_cancelled_before_entry_never_publishes_readiness_or_creates() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let advertised = Arc::new(AtomicBool::new(false));
        let runtime = final_task_runtime(Arc::clone(&store), Arc::clone(&advertised));
        let runner = runtime
            .install_task_service(1, Arc::new(FailingFinalTaskSupervisor))
            .expect("installing a runner reserves, but does not establish, readiness");
        let cx = Cx::for_testing();
        cx.cancel_with(CancelKind::User, None);
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        assert!(
            application_runtime.block_on(runner.run(&cx)).is_err(),
            "an already-cancelled runner stops at its entry checkpoint"
        );
        assert!(
            runtime.ensure_task_service_ready().is_err(),
            "a cancelled-before-entry runner has zero readiness authority"
        );
        assert!(
            runtime
                .create_task_with_work(final_test_work_descriptor(), None)
                .is_err(),
            "zero readiness prevents task creation before durable mutation"
        );
        assert!(
            !advertised.load(AtomicOrdering::SeqCst),
            "the failed creation attempt emits no durable task advertisement"
        );
    }

    #[test]
    fn task_03_final_run_service_error_revokes_readiness_and_retries_exact_initial_work() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task = final_working_task_without_ttl("task-run-service-error-initial");
        let task_id = task.base().task_id.clone();
        let work_descriptor = FinalTaskWorkDescriptor::new(serde_json::json!({
            "handler": "run-service-error",
            "payload": {"initial": true}
        }))
        .expect("non-null initial work descriptor is valid");
        store
            .create_task_with_work(
                task.clone(),
                final_task_notification(&task),
                work_descriptor.clone(),
            )
            .expect("initial work is durable before the service starts");

        let action = Arc::new(AtomicUsize::new(RUN_SERVICE_SUPERVISOR_FAIL));
        let mut runner = runtime
            .install_task_service(
                1,
                Arc::new(SwitchableRunServiceSupervisor {
                    action: Arc::clone(&action),
                }),
            )
            .expect("install retained task service runner");
        let failed_cx = Cx::for_testing();

        assert!(matches!(
            poll_retained_task_service(&mut runner, &failed_cx),
            std::task::Poll::Ready(Err(_))
        ));
        assert!(
            !runtime.is_task_service_ready(),
            "a supervisor error must revoke the entered retained service readiness"
        );
        assert_exact_initial_work_is_recoverable(&store, &task_id, &work_descriptor);

        action.store(RUN_SERVICE_SUPERVISOR_COMPLETE, AtomicOrdering::SeqCst);
        let retry_cx = Cx::for_testing();
        assert!(matches!(
            poll_retained_task_service(&mut runner, &retry_cx),
            std::task::Poll::Ready(Ok(()))
        ));
        assert!(
            !runtime.is_task_service_ready(),
            "the caller-owned retry exit must revoke readiness again"
        );
        assert!(matches!(
            store
                .get_task(&task_id)
                .expect("retried initial task is readable"),
            Some(FinalTask::Completed { .. })
        ));
        assert!(
            test_next_initial_work(&store)
                .expect("completed initial recovery scan is valid")
                .is_none(),
            "the successful retry consumes the exact recovered initial handoff"
        );
    }

    #[test]
    fn task_03_final_run_service_cancellation_revokes_readiness_and_retries_exact_input() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses = serde_json::from_value(
            serde_json::json!({"roots": {"roots": [{"uri": "file:///run-service-cancel"}]}}),
        )
        .expect("typed accepted input is valid");
        let task_id = create_accepted_final_input(&runtime, input_responses.clone());
        let action = Arc::new(AtomicUsize::new(RUN_SERVICE_SUPERVISOR_PENDING));
        let mut runner = runtime
            .install_task_service(
                1,
                Arc::new(SwitchableRunServiceSupervisor {
                    action: Arc::clone(&action),
                }),
            )
            .expect("install retained task service runner");
        let cancelled_cx = Cx::for_testing();
        let mut service = Box::pin(runner.run_service(&cancelled_cx));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());

        assert!(matches!(
            Future::poll(service.as_mut(), &mut context),
            std::task::Poll::Pending
        ));
        assert!(
            runtime.is_task_service_ready(),
            "an entered retained service is the only live readiness authority"
        );
        cancelled_cx.cancel_with(CancelKind::User, None);
        assert!(matches!(
            Future::poll(service.as_mut(), &mut context),
            std::task::Poll::Ready(Ok(()))
        ));
        drop(service);

        assert!(
            !runtime.is_task_service_ready(),
            "caller-context cancellation must revoke retained service readiness"
        );
        assert_exact_accepted_input_is_recoverable(&store, &task_id, &input_responses);

        action.store(RUN_SERVICE_SUPERVISOR_COMPLETE, AtomicOrdering::SeqCst);
        let retry_cx = Cx::for_testing();
        assert!(matches!(
            poll_retained_task_service(&mut runner, &retry_cx),
            std::task::Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            store
                .get_task(&task_id)
                .expect("retried accepted-input task is readable"),
            Some(FinalTask::Completed { .. })
        ));
        assert!(
            test_next_accepted_input(&store)
                .expect("completed accepted-input recovery scan is valid")
                .is_none(),
            "the successful retry consumes the exact recovered accepted-input handoff"
        );
    }

    #[test]
    fn task_03_final_run_service_drop_revokes_readiness_and_retries_exact_initial_work() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task = final_working_task_without_ttl("task-run-service-drop-initial");
        let task_id = task.base().task_id.clone();
        let work_descriptor = FinalTaskWorkDescriptor::new(serde_json::json!({
            "handler": "run-service-drop",
            "payload": {"initial": true}
        }))
        .expect("non-null initial work descriptor is valid");
        store
            .create_task_with_work(
                task.clone(),
                final_task_notification(&task),
                work_descriptor.clone(),
            )
            .expect("initial work is durable before the service starts");

        let action = Arc::new(AtomicUsize::new(RUN_SERVICE_SUPERVISOR_PENDING));
        let mut runner = runtime
            .install_task_service(
                1,
                Arc::new(SwitchableRunServiceSupervisor {
                    action: Arc::clone(&action),
                }),
            )
            .expect("install retained task service runner");
        let service_cx = Cx::for_testing();
        let mut service = Box::pin(runner.run_service(&service_cx));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());

        assert!(matches!(
            Future::poll(service.as_mut(), &mut context),
            std::task::Poll::Pending
        ));
        assert!(runtime.is_task_service_ready());
        drop(service);

        assert!(
            !runtime.is_task_service_ready(),
            "dropping a retained service future must revoke readiness"
        );
        assert_exact_initial_work_is_recoverable(&store, &task_id, &work_descriptor);

        action.store(RUN_SERVICE_SUPERVISOR_COMPLETE, AtomicOrdering::SeqCst);
        let retry_cx = Cx::for_testing();
        assert!(matches!(
            poll_retained_task_service(&mut runner, &retry_cx),
            std::task::Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            store
                .get_task(&task_id)
                .expect("retried dropped-service task is readable"),
            Some(FinalTask::Completed { .. })
        ));
    }

    #[test]
    fn task_03_final_run_service_non_concurrent_runner_boundary_is_live() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let action = Arc::new(AtomicUsize::new(RUN_SERVICE_SUPERVISOR_PENDING));
        let mut runner = runtime
            .install_task_service(
                1,
                Arc::new(SwitchableRunServiceSupervisor {
                    action: Arc::clone(&action),
                }),
            )
            .expect("install the only retained service runner");
        let service_cx = Cx::for_testing();
        let mut service = Box::pin(runner.run_service(&service_cx));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());

        assert!(matches!(
            Future::poll(service.as_mut(), &mut context),
            std::task::Poll::Pending
        ));
        assert!(runtime.is_task_service_ready());
        assert!(
            runtime
                .install_task_service(1, Arc::new(FailingFinalTaskSupervisor))
                .is_err(),
            "a live retained service generation rejects a second service owner"
        );
        // The compile-fail example on `run_service` proves that this same
        // runner cannot be borrowed for a second live service future either.
        drop(service);
        assert!(!runtime.is_task_service_ready());
    }

    #[test]
    fn task_03_final_run_service_reentry_republishes_readiness_on_the_same_runner() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let mut runner = runtime
            .install_task_service(1, Arc::new(PendingFinalTaskSupervisor))
            .expect("install retained task service runner");
        let first_cx = Cx::for_testing();
        let mut first_service = Box::pin(runner.run_service(&first_cx));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());

        assert!(matches!(
            Future::poll(first_service.as_mut(), &mut context),
            std::task::Poll::Pending
        ));
        assert!(
            runtime.is_task_service_ready(),
            "the first retained service entry publishes readiness"
        );
        drop(first_service);
        assert!(
            !runtime.is_task_service_ready(),
            "dropping the first service future revokes its readiness lease"
        );

        let second_cx = Cx::for_testing();
        let mut second_service = Box::pin(runner.run_service(&second_cx));
        assert!(matches!(
            Future::poll(second_service.as_mut(), &mut context),
            std::task::Poll::Pending
        ));
        assert!(
            runtime.is_task_service_ready(),
            "the same retained runner can re-enter and publish a new readiness lease"
        );
        drop(second_service);
        assert!(
            !runtime.is_task_service_ready(),
            "the re-entered service future also revokes readiness on drop"
        );
    }

    #[test]
    fn task_03_final_initial_handoff_error_restores_exact_work_descriptor() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let work_descriptor = FinalTaskWorkDescriptor::new(serde_json::json!({
            "handler": "initial-error-recovery",
            "payload": {"request": 8}
        }))
        .expect("non-null application work descriptor is valid");
        let runner = runtime
            .install_task_service(1, Arc::new(FailingFinalTaskSupervisor))
            .expect("install caller-owned service runner before task advertisement");
        let readiness_cx = Cx::for_testing();
        let running_service = enter_task_service_runner(runner, &readiness_cx);
        let task_id = runtime
            .create_task_with_work(work_descriptor.clone(), None)
            .expect("entered service permits initial durable work")
            .task
            .base()
            .task_id
            .clone();
        drop(running_service);
        let runner = runtime
            .install_task_service(1, Arc::new(FailingFinalTaskSupervisor))
            .expect("a dropped runner releases readiness for initial-work recovery");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        assert!(
            application_runtime
                .block_on(runner.run(&Cx::for_testing()))
                .is_err(),
            "the application supervisor error remains visible after restoring initial work"
        );
        let restored = runtime
            .recover_initial_work()
            .expect("initial recovery scan reads the restored descriptor")
            .expect("a failed initial supervisor handoff is restored");
        assert_eq!(restored.task_id(), &task_id);
        assert_eq!(restored.work_descriptor(), &work_descriptor);
    }

    #[test]
    fn task_03_in_memory_initial_work_lease_expires_and_recovers_exact_descriptor() {
        let (store, now) = in_memory_store_with_test_clock(1);
        let task = final_working_task_without_ttl("task-initial-lease-expiry");
        let task_id = task.base().task_id.clone();
        let work_descriptor = final_test_work_descriptor();
        store
            .create_task_with_work(
                task.clone(),
                final_task_notification(&task),
                work_descriptor.clone(),
            )
            .expect("initial work is durably retained with its task");
        let snapshot = store
            .get_task_snapshot(&task_id)
            .expect("initial task snapshot is readable")
            .expect("initial task snapshot is retained");
        assert_eq!(
            test_take_initial_work(&store, &snapshot).expect("initial handoff lease is claimable"),
            Some(work_descriptor.clone())
        );
        assert!(
            test_next_initial_work(&store)
                .expect("leased initial work scan is readable")
                .is_none(),
            "a live recovery lease prevents concurrent delivery"
        );

        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(IN_MEMORY_FINAL_TASK_HANDOFF_LEASE)
            .expect("fixed handoff lease fits the monotonic test clock");
        drop(clock);

        let recovered = test_next_initial_work(&store)
            .expect("expired initial-work lease scan is readable")
            .expect("an expired claim makes the durable initial work recoverable");
        assert_eq!(recovered.task().base().task_id, task_id);
        assert_eq!(
            test_take_initial_work(&store, &recovered)
                .expect("expired lease permits a new initial claim"),
            Some(work_descriptor),
            "lease expiry changes only recovery eligibility, not the durable descriptor"
        );
    }

    #[test]
    fn task_03_in_memory_initial_work_lease_one_millisecond_before_expiry_blocks_recovery() {
        let (store, now) = in_memory_store_with_test_clock(1);
        let task = final_working_task_without_ttl("task-initial-lease-pre-expiry");
        let task_id = task.base().task_id.clone();
        store
            .create_task_with_work(
                task.clone(),
                final_task_notification(&task),
                final_test_work_descriptor(),
            )
            .expect("initial work is durably retained with its task");
        let snapshot = store
            .get_task_snapshot(&task_id)
            .expect("initial task snapshot is readable")
            .expect("initial task snapshot is retained");
        assert!(
            test_take_initial_work(&store, &snapshot)
                .expect("initial handoff lease is claimable")
                .is_some()
        );

        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(
                IN_MEMORY_FINAL_TASK_HANDOFF_LEASE
                    .checked_sub(StdDuration::from_millis(1))
                    .expect("fixed handoff lease exceeds one millisecond"),
            )
            .expect("pre-expiry handoff lease fits the monotonic test clock");
        drop(clock);

        assert!(
            test_next_initial_work(&store)
                .expect("pre-expiry initial-work scan is readable")
                .is_none(),
            "changing only the final millisecond keeps the live recovery lease exclusive"
        );
    }

    #[test]
    fn task_03_in_memory_resumed_input_lease_expires_and_recovers_exact_payload() {
        let (store, now) = in_memory_store_with_test_clock(1);
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses = serde_json::from_value(
            serde_json::json!({"roots": {"roots": [{"uri": "file:///lease-expiry"}]}}),
        )
        .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses.clone());
        let claimed = store
            .get_task_snapshot(&task_id)
            .expect("accepted-input task snapshot is readable")
            .expect("accepted-input task snapshot is retained");
        assert_eq!(
            test_take_input(&store, &claimed).expect("accepted input claim is valid"),
            Some(input_responses.clone())
        );

        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(IN_MEMORY_FINAL_TASK_HANDOFF_LEASE)
            .expect("fixed handoff lease fits the monotonic test clock");
        drop(clock);

        let recovered = test_next_accepted_input(&store)
            .expect("expired accepted-input lease scan is readable")
            .expect("an expired accepted-input claim becomes recoverable");
        assert_ne!(recovered.generation(), claimed.generation());
        assert_eq!(
            test_take_input(&store, &recovered).expect("expired input lease permits a new claim"),
            Some(input_responses),
            "lease expiry changes only recovery eligibility, not the retained input"
        );
    }

    #[test]
    fn task_03_in_memory_resumed_input_lease_one_millisecond_before_expiry_blocks_recovery() {
        let (store, now) = in_memory_store_with_test_clock(1);
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses);
        let claimed = store
            .get_task_snapshot(&task_id)
            .expect("accepted-input task snapshot is readable")
            .expect("accepted-input task snapshot is retained");
        assert!(
            test_take_input(&store, &claimed)
                .expect("accepted input claim is valid")
                .is_some()
        );

        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(
                IN_MEMORY_FINAL_TASK_HANDOFF_LEASE
                    .checked_sub(StdDuration::from_millis(1))
                    .expect("fixed handoff lease exceeds one millisecond"),
            )
            .expect("pre-expiry handoff lease fits the monotonic test clock");
        drop(clock);

        assert!(
            test_next_accepted_input(&store)
                .expect("pre-expiry accepted-input scan is readable")
                .is_none(),
            "changing only the final millisecond keeps the accepted-input claim exclusive"
        );
    }

    #[test]
    fn task_03_final_raw_input_claim_is_guarded_while_owned_claim_delivers_once() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses.clone());
        let snapshot = store
            .get_task_snapshot(&task_id)
            .expect("accepted-input snapshot is readable")
            .expect("accepted-input task remains retained");

        assert!(
            FinalTaskStore::take_input_if_current(&*store, &snapshot).is_err(),
            "the legacy raw store claim is fail-closed without an execution owner"
        );
        assert_eq!(
            FinalTaskStore::take_input_for_owner_if_current(&*store, &snapshot, "guarded-owner",)
                .expect("owned handoff claim is valid"),
            Some(input_responses),
            "changing only the owner guard makes the durable input available exactly once"
        );
    }

    #[test]
    fn task_03_final_elected_dispatch_renewal_preserves_exclusive_ownership() {
        let (store, now) = in_memory_store_with_test_clock(1);
        let task = final_working_task_without_ttl("task-elected-dispatch-renewal");
        let task_id = task.base().task_id.clone();
        let work_descriptor = final_test_work_descriptor();
        let owner_id = "renewing-owner";
        store
            .create_task_with_work(
                task.clone(),
                final_task_notification(&task),
                work_descriptor.clone(),
            )
            .expect("initial work is durably retained with its task");
        let snapshot = store
            .get_task_snapshot(&task_id)
            .expect("initial task snapshot is readable")
            .expect("initial task snapshot is retained");
        assert_eq!(
            FinalTaskStore::take_initial_work_for_owner_if_current(&*store, &snapshot, owner_id)
                .expect("initial handoff claim is valid"),
            Some(work_descriptor)
        );
        let dispatch_fence = FinalTaskStore::begin_handoff_dispatch_for_owner_if_current(
            &*store,
            &task_id,
            snapshot.generation(),
            owner_id,
        )
        .expect("elected dispatch is valid")
        .expect("claimed owner wins dispatch election");

        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(
                IN_MEMORY_FINAL_TASK_HANDOFF_LEASE
                    .checked_sub(StdDuration::from_millis(1))
                    .expect("fixed handoff lease exceeds one millisecond"),
            )
            .expect("pre-renewal handoff lease fits the monotonic test clock");
        drop(clock);
        assert!(
            FinalTaskStore::renew_handoff_dispatch_if_current(
                &*store,
                &task_id,
                snapshot.generation(),
                owner_id,
                dispatch_fence,
            )
            .expect("matching owner renews the durable dispatch lease"),
            "renewing only the live owner keeps its fence current"
        );

        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(StdDuration::from_millis(1))
            .expect("renewed handoff lease fits the monotonic test clock");
        drop(clock);
        assert!(
            FinalTaskStore::next_initial_work_snapshot_after(&*store, None)
                .expect("renewed dispatch recovery scan is readable")
                .is_none(),
            "the matching renewal keeps an elected live supervisor exclusively fenced"
        );
    }

    #[test]
    fn task_03_in_memory_expired_dispatch_lease_fences_crashed_owner_completion() {
        let (store, now) = in_memory_store_with_test_clock(1);
        let task = final_working_task_without_ttl("task-initial-lease-fence");
        let task_id = task.base().task_id.clone();
        let work_descriptor = final_test_work_descriptor();
        let crashed_owner = "crashed-owner";
        let recovery_owner = "recovery-owner";
        store
            .create_task_with_work(
                task.clone(),
                final_task_notification(&task),
                work_descriptor.clone(),
            )
            .expect("initial work is durably retained with its task");
        let abandoned = store
            .get_task_snapshot(&task_id)
            .expect("initial task snapshot is readable")
            .expect("initial task snapshot is retained");
        assert!(
            FinalTaskStore::take_initial_work_for_owner_if_current(
                &*store,
                &abandoned,
                crashed_owner,
            )
            .expect("initial handoff lease is claimable")
            .is_some()
        );
        let crashed_fence = FinalTaskStore::begin_handoff_dispatch_for_owner_if_current(
            &*store,
            &task_id,
            abandoned.generation(),
            crashed_owner,
        )
        .expect("crashed owner dispatch election is valid")
        .expect("claimed owner is elected before the simulated crash");

        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(IN_MEMORY_FINAL_TASK_HANDOFF_LEASE)
            .expect("fixed handoff lease fits the monotonic test clock");
        drop(clock);

        let replacement = test_next_initial_work(&store)
            .expect("expired lease recovery scan is readable")
            .expect("expired lease yields a newly fenced recovery candidate");
        assert_ne!(replacement.generation(), abandoned.generation());
        assert!(
            FinalTaskStore::take_initial_work_for_owner_if_current(
                &*store,
                &replacement,
                recovery_owner,
            )
            .expect("replacement recovery lease is claimable")
            .is_some()
        );
        assert!(
            !FinalTaskStore::finish_handoff_dispatch_for_owner_if_current(
                &*store,
                &task_id,
                abandoned.generation(),
                crashed_owner,
                crashed_fence,
            )
            .expect("late completion observes its stale fenced owner"),
            "an expired elected owner cannot complete or release a replacement recovery lease"
        );
        assert!(
            test_next_initial_work(&store)
                .expect("newer lease scan is readable")
                .is_none(),
            "the late stale restoration leaves the replacement lease exclusive"
        );
    }

    #[test]
    fn task_03_in_memory_expired_elected_cancellation_lease_retires_task() {
        let (store, now) = in_memory_store_with_test_clock(1);
        let task = final_working_task_without_ttl("task-expired-elected-cancellation");
        let task_id = task.base().task_id.clone();
        let owner_id = "cancelled-crashed-owner";
        store
            .create_task_with_work(
                task.clone(),
                final_task_notification(&task),
                final_test_work_descriptor(),
            )
            .expect("initial work is durably retained with its task");
        let snapshot = store
            .get_task_snapshot(&task_id)
            .expect("initial task snapshot is readable")
            .expect("initial task snapshot is retained");
        assert!(
            FinalTaskStore::take_initial_work_for_owner_if_current(&*store, &snapshot, owner_id)
                .expect("initial handoff lease is claimable")
                .is_some()
        );
        FinalTaskStore::begin_handoff_dispatch_for_owner_if_current(
            &*store,
            &task_id,
            snapshot.generation(),
            owner_id,
        )
        .expect("dispatch election is valid")
        .expect("claimed owner wins dispatch election");
        FinalTaskStore::request_cancellation(&*store, &task_id)
            .expect("elected task records cooperative cancellation intent");

        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(IN_MEMORY_FINAL_TASK_HANDOFF_LEASE)
            .expect("fixed handoff lease fits the monotonic test clock");
        drop(clock);

        let retired = store
            .get_task_snapshot(&task_id)
            .expect("expiry reclamation leaves a readable terminal task")
            .expect("unlimited-retention task remains stored after lease expiry");
        assert!(matches!(retired.task(), FinalTask::Cancelled(_)));
        assert!(
            !store
                .is_cancellation_requested(&task_id)
                .expect("terminal retirement consumes cancellation intent")
        );
        let state = store
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !state.handoff_leases.contains_key(&task_id)
                && !state.initial_work.contains_key(&task_id)
                && !state.accepted_inputs.contains_key(&task_id),
            "changing only cancellation from normal lease expiry retires rather than strands work"
        );
    }

    #[test]
    fn task_03_in_memory_cancellation_fences_claimed_initial_work() {
        let store = InMemoryFinalTaskStore::default();
        let task = final_working_task_without_ttl("task-initial-lease-cancel");
        let task_id = task.base().task_id.clone();
        let work_descriptor = final_test_work_descriptor();
        store
            .create_task_with_work(
                task.clone(),
                final_task_notification(&task),
                work_descriptor.clone(),
            )
            .expect("initial work is durably retained with its task");
        let snapshot = store
            .get_task_snapshot(&task_id)
            .expect("initial task snapshot is readable")
            .expect("initial task snapshot is retained");
        assert!(
            test_take_initial_work(&store, &snapshot)
                .expect("initial handoff lease is claimable")
                .is_some()
        );

        let cancelled = FinalTask::Cancelled(
            transition_terminal_final_task_base(
                snapshot.task().base().clone(),
                FinalTaskStatus::Cancelled,
                None,
            )
            .expect("cancellation transition is valid"),
        );
        let after = store
            .request_cancellation_and_clear_input_if_current(
                &snapshot,
                cancelled.clone(),
                final_task_notification(&cancelled),
            )
            .expect("cancellation is atomically recorded against the claimed generation")
            .expect("the claimed-but-unelected handoff is terminally cancelled");
        assert!(matches!(after.task(), FinalTask::Cancelled(_)));
        assert!(
            !store
                .is_cancellation_requested(&task_id)
                .expect("terminal cancellation consumes cooperative intent")
        );
        assert!(
            test_next_initial_work(&store)
                .expect("cancelled initial-work scan is readable")
                .is_none(),
            "cancellation clears a claimed-but-not-dispatched initial handoff"
        );
        assert!(
            !test_restore_initial_work(&store, &task_id, snapshot.generation(), work_descriptor)
                .expect("stale claimed-work restoration is fenced by cancellation"),
            "only cancellation differs from the retryable supervisor-error path"
        );
    }

    #[test]
    fn task_03_in_memory_cancellation_generation_exhaustion_preserves_claimed_work() {
        let store = InMemoryFinalTaskStore::default();
        let task = final_working_task_without_ttl("task-cancel-generation-exhaustion");
        let task_id = task.base().task_id.clone();
        let work_descriptor = final_test_work_descriptor();
        store
            .create_task_with_work(
                task.clone(),
                final_task_notification(&task),
                work_descriptor.clone(),
            )
            .expect("initial work is durably retained with its task");
        let snapshot = store
            .get_task_snapshot(&task_id)
            .expect("initial task snapshot is readable")
            .expect("initial task snapshot is retained");
        assert_eq!(
            test_take_initial_work(&store, &snapshot).expect("initial handoff claim is valid"),
            Some(work_descriptor.clone())
        );
        {
            let mut state = store
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.next_generation = u64::MAX;
        }

        let cancelled = FinalTask::Cancelled(
            transition_terminal_final_task_base(
                snapshot.task().base().clone(),
                FinalTaskStatus::Cancelled,
                None,
            )
            .expect("cancellation transition is valid"),
        );
        assert!(
            store
                .request_cancellation_and_clear_input_if_current(
                    &snapshot,
                    cancelled.clone(),
                    final_task_notification(&cancelled),
                )
                .is_err(),
            "generation exhaustion rejects cancellation before durable mutation"
        );

        let state = store
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            state.generations.get(&task_id),
            Some(&snapshot.generation())
        );
        assert_eq!(state.initial_work.get(&task_id), Some(&work_descriptor));
        assert!(
            state.handoff_leases.get(&task_id).is_some_and(|lease| {
                lease.generation == snapshot.generation()
                    && lease.kind == InMemoryFinalTaskHandoffKind::Initial
                    && !lease.dispatch_elected
            }),
            "the rejected cancellation leaves the original claim fence intact"
        );
        assert!(
            !state.cancellation_requests.contains(&task_id),
            "the rejected cancellation records no cooperative intent"
        );
    }

    #[test]
    fn task_03_final_public_predispatch_cancellation_commits_cancelled_task_and_notification() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let delivered_for_emitter = Arc::clone(&delivered);
        let runtime_store: Arc<dyn FinalTaskStore> = store.clone();
        let runtime = FinalTaskRuntime::new(
            runtime_store,
            FinalTaskRuntimeConfig::new(60_000, Some(5_000))
                .expect("a finite final task policy is valid"),
            Arc::new(move |notification| {
                delivered_for_emitter
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(notification);
            }),
        );
        let runner = runtime
            .install_task_service(1, Arc::new(PendingFinalTaskSupervisor))
            .expect("a task service is installed before public task creation");
        let service_cx = Cx::for_testing();
        let mut service = Box::pin(runner.run(&service_cx));
        let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Future::poll(service.as_mut(), &mut task_cx),
            std::task::Poll::Pending
        ));

        let created = runtime
            .create_task_with_work(final_test_work_descriptor(), Some("queued".to_owned()))
            .expect("the entered service admits public initial work");
        let task_id = created.task.base().task_id.clone();
        let before = store
            .get_task_snapshot(&task_id)
            .expect("the created task snapshot is readable")
            .expect("the created task is retained");

        runtime
            .cancel_task(&task_id)
            .expect("pre-dispatch cancellation is acknowledged");

        let after = store
            .get_task_snapshot(&task_id)
            .expect("the cancelled task snapshot is readable")
            .expect("the cancelled task is retained");
        assert!(matches!(after.task(), FinalTask::Cancelled(_)));
        assert_eq!(
            after.generation(),
            before
                .generation()
                .checked_add(1)
                .expect("the fixture generation remains representable"),
            "the terminal cancellation is the task's sole post-create durable transition"
        );
        assert!(
            !runtime
                .is_cancellation_requested(&task_id)
                .expect("terminal cancellation consumes cooperative intent")
        );
        assert!(
            test_next_initial_work(&store)
                .expect("cancelled initial-work recovery scan is valid")
                .is_none(),
            "terminal cancellation leaves no initial work for a supervisor"
        );
        let delivered = delivered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(delivered.len(), 2, "creation and cancellation both notify");
        assert!(delivered.last().is_some_and(|notification| {
            matches!(&notification.params.task, FinalTask::Cancelled(_))
        }));
        assert_eq!(
            serde_json::to_value(
                store
                    .latest_notification(&task_id)
                    .expect("the terminal cancellation notification is retained")
                    .params
                    .task,
            )
            .expect("encode retained cancellation notification"),
            serde_json::to_value(after.task()).expect("encode retained cancelled task"),
            "the durable terminal snapshot and emitted notification agree exactly"
        );
    }

    #[test]
    fn task_03_final_cancellation_clears_pending_handoff_before_supervisor_invocation() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses);
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let mut runner = runtime
            .install_task_service(
                1,
                Arc::new(RecordingFinalTaskSupervisor {
                    accepted: Arc::clone(&delivered),
                }),
            )
            .expect("install caller-owned service for cancellation wakeup");

        runtime
            .cancel_task(&task_id)
            .expect("cancellation atomically claims the pending handoff");
        assert_eq!(
            runner
                .receiver
                .try_recv()
                .expect("cancellation wakes the installed task service"),
            task_id
        );
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");
        application_runtime
            .block_on(runner.resume_task(&Cx::for_testing(), &task_id))
            .expect("cancelled task wakeup does not invoke the supervisor");

        assert!(
            delivered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty(),
            "a cancellation that wins before the take cannot reach application code"
        );
        assert!(
            runtime
                .recover_accepted_input()
                .expect("cancelled recovery scan is valid")
                .is_none(),
            "the cancellation transaction clears the durable accepted-input handoff"
        );
    }

    #[test]
    fn task_03_final_cancellation_fences_handoff_claimed_before_invocation() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses);
        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("claim accepted handoff before cancellation")
            .expect("accepted handoff is present before cancellation");
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(RecordingFinalTaskSupervisor {
                    accepted: Arc::clone(&delivered),
                }),
            )
            .expect("install caller-owned service for dispatch fence");

        runtime
            .cancel_task(&task_id)
            .expect("cancellation wins after handoff claim but before invocation");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");
        let cx = Cx::for_testing();
        application_runtime
            .block_on(runner.resume_handoff(&cx, FinalTaskSupervisorHandoff::Resumed(accepted)))
            .expect("stale claimed handoff is fenced without invoking application work");

        assert!(
            delivered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty(),
            "the post-claim cancellation generation fence prevents cancelled work reaching the app"
        );
    }

    #[test]
    fn task_03_final_dispatch_election_delivers_uncancelled_handoff() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses.clone());
        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("claim uncancelled accepted handoff")
            .expect("accepted handoff is present");
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(RecordingFinalTaskSupervisor {
                    accepted: Arc::clone(&delivered),
                }),
            )
            .expect("install caller-owned service for dispatch election");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        application_runtime
            .block_on(runner.resume_handoff(
                &Cx::for_testing(),
                FinalTaskSupervisorHandoff::Resumed(accepted),
            ))
            .expect("the uncancelled dispatch election reaches application work");
        assert_eq!(
            delivered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            &[(task_id, input_responses)],
            "the elected handoff is delivered exactly once"
        );
    }

    #[test]
    fn task_03_final_cancellation_wins_atomic_dispatch_election() {
        let inner = Arc::new(InMemoryFinalTaskStore::default());
        let setup_runtime =
            final_task_runtime(Arc::clone(&inner), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&setup_runtime, input_responses);
        let accepted = setup_runtime
            .take_accepted_input(&task_id)
            .expect("claim handoff before the dispatch race")
            .expect("accepted handoff is present before the dispatch race");
        let runtime = FinalTaskRuntime::new(
            Arc::new(CancelBeforeFinalTaskDispatchStore {
                inner: Arc::clone(&inner),
            }),
            FinalTaskRuntimeConfig::new(60_000, Some(5_000)).expect("valid final task policy"),
            Arc::new(|_| {}),
        );
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(RecordingFinalTaskSupervisor {
                    accepted: Arc::clone(&delivered),
                }),
            )
            .expect("install caller-owned service for atomic dispatch race");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        application_runtime
            .block_on(runner.resume_handoff(
                &Cx::for_testing(),
                FinalTaskSupervisorHandoff::Resumed(accepted),
            ))
            .expect("a cancellation election loser returns without invoking application work");
        assert!(
            delivered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty(),
            "the cancellation that linearizes before dispatch cannot reach the supervisor"
        );
        assert!(
            !runtime
                .is_cancellation_requested(&task_id)
                .expect("read terminal cancellation state"),
            "the pre-dispatch terminal cancellation consumes cooperative intent"
        );
    }

    #[test]
    fn task_03_final_handoff_drop_restores_exact_resumed_input() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses = serde_json::from_value(
            serde_json::json!({"roots": {"roots": [{"uri": "file:///drop-restore"}]}}),
        )
        .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses.clone());
        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("claim accepted input before cancellation-style future drop")
            .expect("accepted input is present before the dropped supervisor future");
        let runner = runtime
            .install_task_service(1, Arc::new(PendingFinalTaskSupervisor))
            .expect("install caller-owned pending service runner");
        let cx = Cx::for_testing();

        {
            let pending = runner.resume_handoff(&cx, FinalTaskSupervisorHandoff::Resumed(accepted));
            let mut pending = std::pin::pin!(pending);
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(matches!(
                std::future::Future::poll(pending.as_mut(), &mut context),
                std::task::Poll::Pending
            ));
        }

        let restored = runtime
            .recover_accepted_input()
            .expect("dropped supervisor handoff recovery scan is valid")
            .expect("drop lease restores the accepted input");
        assert_eq!(restored.input_responses(), &input_responses);
    }

    #[test]
    fn task_03_final_uncancelled_elected_handoff_error_requeues_under_unlimited_retention() {
        const ELAPSED_MS: u64 = 86_400_000;
        let (store, now) = in_memory_store_with_test_clock(1);
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::with_unlimited_ttl(&AllowUnlimitedFinalTaskRetention, None)
                .expect("explicit authority admits unlimited retained handoffs"),
            Arc::new(|_| {}),
        );
        let input_responses: FinalTaskInputResponses = serde_json::from_value(
            serde_json::json!({"roots": {"roots": [{"uri": "file:///uncancelled-error"}]}}),
        )
        .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses.clone());
        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("claim accepted input before the planted supervisor error")
            .expect("accepted input is present before the planted supervisor error");
        let runner = runtime
            .install_task_service(1, Arc::new(FailingFinalTaskSupervisor))
            .expect("install caller-owned failing service runner");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        assert!(
            application_runtime
                .block_on(runner.resume_handoff(
                    &Cx::for_testing(),
                    FinalTaskSupervisorHandoff::Resumed(accepted),
                ))
                .is_err(),
            "the planted supervisor error remains visible after durable restoration"
        );
        assert!(
            !runtime
                .is_cancellation_requested(&task_id)
                .expect("read uncancelled task state"),
            "only cancellation differs from the paired fenced error path"
        );
        assert!(
            !store
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .handoff_leases
                .contains_key(&task_id),
            "an error restoration releases its elected owner fence before requeueing"
        );

        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(StdDuration::from_millis(ELAPSED_MS))
            .expect("test clock can advance through an unlimited retention interval");
        drop(clock);

        assert!(
            runtime.get_task(&task_id).is_ok(),
            "null-TTL retention keeps the task available after error recovery"
        );
        let restored = runtime
            .recover_accepted_input()
            .expect("recovery scan reads the uncancelled restored handoff")
            .expect("uncancelled error requeues the exact accepted handoff");
        assert_eq!(restored.input_responses(), &input_responses);
    }

    #[test]
    fn task_03_final_cancelled_elected_handoff_error_retires_task_under_unlimited_retention() {
        const ELAPSED_MS: u64 = 86_400_000;
        let (store, now) = in_memory_store_with_test_clock(1);
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::with_unlimited_ttl(&AllowUnlimitedFinalTaskRetention, None)
                .expect("explicit authority admits unlimited retained handoffs"),
            Arc::new(|_| {}),
        );
        let input_responses: FinalTaskInputResponses = serde_json::from_value(
            serde_json::json!({"roots": {"roots": [{"uri": "file:///cancelled-error"}]}}),
        )
        .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses);
        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("claim accepted input before cancellation after dispatch election")
            .expect("accepted input is present before cancellation after dispatch election");
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(CancelThenFailingFinalTaskSupervisor {
                    runtime: runtime.clone(),
                }),
            )
            .expect("install caller-owned cancelling failing service runner");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        application_runtime
            .block_on(runner.resume_handoff(
                &Cx::for_testing(),
                FinalTaskSupervisorHandoff::Resumed(accepted),
            ))
            .expect(
                "the cancellation winner retires an elected task even when application work fails",
            );
        assert!(
            !runtime
                .is_cancellation_requested(&task_id)
                .expect("read terminal cancellation state"),
            "automatic retirement consumes the elected cancellation intent"
        );
        assert!(matches!(
            runtime
                .get_task(&task_id)
                .expect("read automatically retired task")
                .task,
            FinalTask::Cancelled(_)
        ));
        {
            let state = store
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                !state.handoff_leases.contains_key(&task_id),
                "automatic cancellation retirement releases the exact elected owner fence"
            );
            assert!(
                !state.accepted_inputs.contains_key(&task_id),
                "cancellation, unlike the paired error path, must not requeue input"
            );
        }

        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(StdDuration::from_millis(ELAPSED_MS))
            .expect("test clock can advance through an unlimited retention interval");
        drop(clock);

        assert!(
            runtime.get_task(&task_id).is_ok(),
            "unbounded task retention preserves the automatically retired terminal task"
        );
        assert!(
            runtime
                .recover_accepted_input()
                .expect("cancelled recovery scan is readable")
                .is_none(),
            "cancelled input is never replayed after its elected owner releases the fence"
        );
    }

    #[test]
    fn task_03_final_cancelled_elected_handoff_drop_retires_task_under_unlimited_retention() {
        const ELAPSED_MS: u64 = 86_400_000;
        let (store, now) = in_memory_store_with_test_clock(1);
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::with_unlimited_ttl(&AllowUnlimitedFinalTaskRetention, None)
                .expect("explicit authority admits unlimited retained handoffs"),
            Arc::new(|_| {}),
        );
        let input_responses: FinalTaskInputResponses = serde_json::from_value(
            serde_json::json!({"roots": {"roots": [{"uri": "file:///cancelled-drop"}]}}),
        )
        .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses);
        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("claim accepted input before dropped elected supervisor")
            .expect("accepted input is present before dropped elected supervisor");
        let runner = runtime
            .install_task_service(1, Arc::new(PendingFinalTaskSupervisor))
            .expect("install caller-owned pending service runner");
        let cx = Cx::for_testing();

        {
            let pending = runner.resume_handoff(&cx, FinalTaskSupervisorHandoff::Resumed(accepted));
            let mut pending = std::pin::pin!(pending);
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(matches!(
                std::future::Future::poll(pending.as_mut(), &mut context),
                std::task::Poll::Pending
            ));
            runtime
                .cancel_task(&task_id)
                .expect("an elected working task accepts cooperative cancellation");
        }

        assert!(
            !runtime
                .is_cancellation_requested(&task_id)
                .expect("read terminal cancellation state after dropping the elected future"),
            "the dropped elected handoff retires an already-recorded cancellation"
        );
        assert!(matches!(
            runtime
                .get_task(&task_id)
                .expect("read automatically retired dropped task")
                .task,
            FinalTask::Cancelled(_)
        ));
        {
            let state = store
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                !state.handoff_leases.contains_key(&task_id),
                "dropping a cancelled elected future retires and releases its exact owner fence"
            );
            assert!(
                !state.accepted_inputs.contains_key(&task_id),
                "cancellation prevents the dropped future from requeueing its input"
            );
        }

        let mut clock = now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *clock = clock
            .checked_add(StdDuration::from_millis(ELAPSED_MS))
            .expect("test clock can advance through an unlimited retention interval");
        drop(clock);

        assert!(
            runtime.get_task(&task_id).is_ok(),
            "unbounded retention keeps the retired cancelled task inspectable without its fence"
        );
        assert!(
            runtime
                .recover_accepted_input()
                .expect("cancelled dropped-future recovery scan is readable")
                .is_none(),
            "a cancelled dropped future cannot replay retained application input"
        );
    }

    #[test]
    fn task_03_final_handoff_cancellation_checkpoint_restores_input_before_invocation() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses.clone());
        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("claim accepted input before cancellation checkpoint")
            .expect("accepted input is present before cancellation");
        let runner = runtime
            .install_task_service(1, Arc::new(PendingFinalTaskSupervisor))
            .expect("install caller-owned pending service runner");
        let cx = Cx::for_testing();
        cx.cancel_with(CancelKind::User, None);
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        assert!(
            application_runtime
                .block_on(runner.resume_handoff(&cx, FinalTaskSupervisorHandoff::Resumed(accepted)))
                .is_err(),
            "the pre-invocation cancellation checkpoint stops application work"
        );
        let restored = runtime
            .recover_accepted_input()
            .expect("cancelled handoff recovery scan is valid")
            .expect("cancellation drops the lease and restores the accepted input");
        assert_eq!(restored.input_responses(), &input_responses);
    }

    #[test]
    fn task_03_final_pending_supervisor_remains_owned_without_context_cancellation() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses);
        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("claim accepted input before pending supervisor start")
            .expect("accepted input is present before the pending supervisor starts");
        let runner = runtime
            .install_task_service(1, Arc::new(PendingFinalTaskSupervisor))
            .expect("install caller-owned pending service runner");
        let cx = Cx::for_testing();
        let pending = runner.resume_handoff(&cx, FinalTaskSupervisorHandoff::Resumed(accepted));
        let mut pending = std::pin::pin!(pending);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());

        assert!(matches!(
            std::future::Future::poll(pending.as_mut(), &mut context),
            std::task::Poll::Pending
        ));
        assert!(
            runtime
                .recover_accepted_input()
                .expect("read pending supervisor recovery state")
                .is_none(),
            "without context cancellation the elected pending supervisor retains its durable lease"
        );
    }

    #[test]
    fn task_03_final_context_cancellation_after_pending_supervisor_start_restores_input() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses.clone());
        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("claim accepted input before pending supervisor start")
            .expect("accepted input is present before the pending supervisor starts");
        let runner = runtime
            .install_task_service(1, Arc::new(PendingFinalTaskSupervisor))
            .expect("install caller-owned pending service runner");
        let cx = Cx::for_testing();
        let pending = runner.resume_handoff(&cx, FinalTaskSupervisorHandoff::Resumed(accepted));
        let mut pending = std::pin::pin!(pending);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());

        assert!(matches!(
            std::future::Future::poll(pending.as_mut(), &mut context),
            std::task::Poll::Pending
        ));
        cx.cancel_with(CancelKind::User, None);
        assert!(matches!(
            std::future::Future::poll(pending.as_mut(), &mut context),
            std::task::Poll::Ready(Err(_))
        ));
        let restored = runtime
            .recover_accepted_input()
            .expect("cancelled pending supervisor recovery scan is valid")
            .expect("context cancellation restores the exact pending input handoff");
        assert_eq!(restored.input_responses(), &input_responses);
    }

    #[test]
    fn task_03_final_live_pending_supervisor_without_cancellation_retains_handoff() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses.clone());
        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("claim accepted input before pending supervisor start")
            .expect("accepted input is present before the pending supervisor starts");
        let (started, mut started_receiver) = mpsc::channel(1);
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(SignallingPendingFinalTaskSupervisor { started }),
            )
            .expect("install caller-owned pending service runner");
        let runtime_for_task = runtime.clone();
        let child_context = Arc::new(Mutex::new(None));
        let child_context_for_task = Arc::clone(&child_context);

        let ((), report) = asupersync::lab::run_async_under_lab(0x71_03, move |cx| async move {
            let runner_context = Arc::clone(&child_context_for_task);
            let mut supervisor = cx
                .spawn(move |supervisor_cx| async move {
                    *runner_context
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(supervisor_cx.clone());
                    runner
                        .resume_handoff(
                            &supervisor_cx,
                            FinalTaskSupervisorHandoff::Resumed(accepted),
                        )
                        .await
                })
                .expect("live runtime admits the pending supervisor");

            started_receiver
                .recv(&cx)
                .await
                .expect("pending supervisor reports its first live poll");
            let supervisor_cx = child_context_for_task
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .expect("the live supervisor publishes its context before polling")
                .clone();
            assert!(
                !supervisor_cx.is_cancel_requested(),
                "only the absence of Cx cancellation differs from the paired wake path"
            );
            assert!(
                runtime_for_task
                    .recover_accepted_input()
                    .expect("read live pending-supervisor recovery state")
                    .is_none(),
                "without Cx cancellation the pending supervisor retains its durable lease"
            );

            // Clean up the deliberately pending supervisor after recording
            // the unchanged state. The paired test performs this cancellation
            // immediately instead.
            supervisor_cx.cancel_with(CancelKind::User, None);
            // A parked supervisor may report cancellation cooperatively (its
            // own error return) or as the runtime's cancellation completion.
            assert!(matches!(
                supervisor.join(&cx).await,
                Ok(Err(_)) | Err(asupersync::runtime::JoinError::Cancelled(_))
            ));
        });

        assert_eq!(
            report.now_nanos, 0,
            "the cleanup cancellation wakes the live task before its heartbeat timer"
        );
        let restored = runtime
            .recover_accepted_input()
            .expect("cancelled pending supervisor recovery scan is valid")
            .expect("cleanup cancellation restores the exact pending input handoff");
        assert_eq!(restored.input_responses(), &input_responses);
    }

    #[test]
    fn task_03_final_task_cancellation_wakes_and_retires_pending_supervisor() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses);
        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("claim accepted input before task-cancellation wakeup")
            .expect("accepted input is present before the pending supervisor starts");
        let (started, mut started_receiver) = mpsc::channel(1);
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(SignallingPendingFinalTaskSupervisor { started }),
            )
            .expect("install caller-owned pending service runner");
        let runtime_for_task = runtime.clone();
        let task_id_for_task = task_id.clone();

        let ((), report) = asupersync::lab::run_async_under_lab(0x71_05, move |cx| async move {
            let mut supervisor = cx
                .spawn(move |supervisor_cx| async move {
                    runner
                        .resume_handoff(
                            &supervisor_cx,
                            FinalTaskSupervisorHandoff::Resumed(accepted),
                        )
                        .await
                })
                .expect("live runtime admits the pending supervisor");

            started_receiver
                .recv(&cx)
                .await
                .expect("pending supervisor reports its first live poll");
            runtime_for_task
                .cancel_task(&task_id_for_task)
                .expect("tasks/cancel commits cancellation and wakes the elected handoff");
            assert!(matches!(supervisor.join(&cx).await, Ok(Ok(()))));
        });

        assert_eq!(
            report.now_nanos, 0,
            "the durable task cancellation wakes the parked supervisor without waiting for a heartbeat"
        );
        assert!(matches!(
            runtime
                .get_task(&task_id)
                .expect("read task after cancellation wakeup")
                .task,
            FinalTask::Cancelled(_)
        ));
        assert!(
            !runtime
                .is_cancellation_requested(&task_id)
                .expect("read terminal cancellation state"),
            "automatic retirement consumes cancellation intent"
        );
        assert!(
            runtime
                .recover_accepted_input()
                .expect("cancelled recovery scan is readable")
                .is_none(),
            "changing only the cancellation winner prevents the paired retained input from replaying"
        );
    }

    #[test]
    fn task_03_final_live_context_cancellation_wakes_pending_supervisor() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses.clone());
        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("claim accepted input before pending supervisor start")
            .expect("accepted input is present before the pending supervisor starts");
        let (started, mut started_receiver) = mpsc::channel(1);
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(SignallingPendingFinalTaskSupervisor { started }),
            )
            .expect("install caller-owned pending service runner");
        let child_context = Arc::new(Mutex::new(None));
        let child_context_for_task = Arc::clone(&child_context);

        let ((), report) = asupersync::lab::run_async_under_lab(0x71_04, move |cx| async move {
            let runner_context = Arc::clone(&child_context_for_task);
            let mut supervisor = cx
                .spawn(move |supervisor_cx| async move {
                    *runner_context
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(supervisor_cx.clone());
                    runner
                        .resume_handoff(
                            &supervisor_cx,
                            FinalTaskSupervisorHandoff::Resumed(accepted),
                        )
                        .await
                })
                .expect("live runtime admits the pending supervisor");

            started_receiver
                .recv(&cx)
                .await
                .expect("pending supervisor reports its first live poll");
            child_context_for_task
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .expect("the live supervisor publishes its context before polling")
                .cancel_with(CancelKind::User, None);
            // A parked supervisor may report cancellation cooperatively (its
            // own error return) or as the runtime's cancellation completion.
            assert!(matches!(
                supervisor.join(&cx).await,
                Ok(Err(_)) | Err(asupersync::runtime::JoinError::Cancelled(_))
            ));
        });

        assert_eq!(
            report.now_nanos, 0,
            "Cx cancellation wakes the live pending supervisor without waiting for a heartbeat"
        );
        let restored = runtime
            .recover_accepted_input()
            .expect("cancelled pending supervisor recovery scan is valid")
            .expect("context cancellation restores the exact pending input handoff");
        assert_eq!(restored.input_responses(), &input_responses);
    }

    #[test]
    fn task_03_final_handoff_panic_restores_exact_resumed_input() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&runtime, input_responses.clone());
        let accepted = runtime
            .take_accepted_input(&task_id)
            .expect("claim accepted input before planted panic")
            .expect("accepted input is present before the panicking supervisor future");
        let runner = runtime
            .install_task_service(1, Arc::new(PanickingFinalTaskSupervisor))
            .expect("install caller-owned panicking service runner");
        let cx = Cx::for_testing();

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let panicking =
                runner.resume_handoff(&cx, FinalTaskSupervisorHandoff::Resumed(accepted));
            let mut panicking = std::pin::pin!(panicking);
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            let _ = std::future::Future::poll(panicking.as_mut(), &mut context);
        }));
        assert!(
            panic.is_err(),
            "the planted supervisor panic reaches the caller"
        );

        let restored = runtime
            .recover_accepted_input()
            .expect("panicking supervisor recovery scan is valid")
            .expect("unwinding drops the lease and restores the accepted input");
        assert_eq!(restored.input_responses(), &input_responses);
    }

    #[test]
    fn task_03_final_service_runner_recovers_and_delivers_accepted_input() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let first_runtime =
            final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses = serde_json::from_value(
            serde_json::json!({"roots": {"roots": [{"uri": "file:///recovery-success"}]}}),
        )
        .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&first_runtime, input_responses.clone());
        drop(first_runtime);

        let recovered_runtime =
            final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let runner = recovered_runtime
            .install_task_service(
                1,
                Arc::new(RecordingFinalTaskSupervisor {
                    accepted: Arc::clone(&delivered),
                }),
            )
            .expect("install caller-owned service runner");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");
        let cx = Cx::for_testing();

        application_runtime
            .block_on(runner.run(&cx))
            .expect("recovered accepted input reaches the supervisor");

        let delivered = delivered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            delivered.as_slice(),
            &[(task_id.clone(), input_responses)],
            "the recovery scan delivers the exact durable handoff once"
        );
        drop(delivered);
        assert!(
            recovered_runtime
                .recover_accepted_input()
                .expect("empty recovery scan is valid")
                .is_none(),
            "a successful supervisor call consumes the durable handoff"
        );
    }

    #[test]
    fn task_03_final_service_runner_continues_after_sixty_four_recoveries() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        for index in 0..=MAX_FINAL_TASK_RECOVERY_HANDOFFS_PER_SCAN {
            let task = final_working_task_without_ttl(&format!("task-bounded-recovery-{index:03}"));
            store
                .create_task_with_work(
                    task.clone(),
                    final_task_notification(&task),
                    final_test_work_descriptor(),
                )
                .expect("every bounded-recovery fixture retains its initial work");
        }
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let started = Arc::new(AtomicUsize::new(0));
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(CancellingAfterInitialHandoffsFinalTaskSupervisor {
                    started: Arc::clone(&started),
                    cancel_after: MAX_FINAL_TASK_RECOVERY_HANDOFFS_PER_SCAN + 1,
                }),
            )
            .expect("install caller-owned bounded recovery service runner");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");
        let cx = Cx::for_testing();

        application_runtime
            .block_on(runner.run(&cx))
            .expect("a self-wakeup continues the bounded recovery scan");

        assert_eq!(
            started.load(AtomicOrdering::SeqCst),
            MAX_FINAL_TASK_RECOVERY_HANDOFFS_PER_SCAN + 1,
            "the sixty-fifth retained initial handoff runs in the continuation turn"
        );
    }

    #[test]
    fn task_03_final_recovery_interleaves_resumed_input_with_initial_backlog() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        for index in 0..=MAX_FINAL_TASK_RECOVERY_HANDOFFS_PER_SCAN {
            let task = final_working_task_without_ttl(&format!("task-fair-initial-{index:03}"));
            store
                .create_task_with_work(
                    task.clone(),
                    final_task_notification(&task),
                    final_test_work_descriptor(),
                )
                .expect("every initial-backlog fixture retains durable work");
        }
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        create_accepted_final_input(&runtime, input_responses);
        let order = Arc::new(Mutex::new(Vec::new()));
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(RecordingRecoveryOrderFinalTaskSupervisor {
                    order: Arc::clone(&order),
                    cancel_after: 2,
                }),
            )
            .expect("install caller-owned fair recovery service runner");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        application_runtime
            .block_on(runner.run(&Cx::for_testing()))
            .expect("cancellation after the paired handoffs exits cleanly");

        assert_eq!(
            order
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            ["initial", "resumed"],
            "a resumed input is delivered on the second bounded recovery claim despite the initial backlog"
        );
    }

    #[test]
    fn task_03_final_recovery_initial_only_backlog_never_fabricates_resumption() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        for index in 0..=MAX_FINAL_TASK_RECOVERY_HANDOFFS_PER_SCAN {
            let task =
                final_working_task_without_ttl(&format!("task-fair-initial-only-{index:03}"));
            store
                .create_task_with_work(
                    task.clone(),
                    final_task_notification(&task),
                    final_test_work_descriptor(),
                )
                .expect("every initial-only fixture retains durable work");
        }
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let order = Arc::new(Mutex::new(Vec::new()));
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(RecordingRecoveryOrderFinalTaskSupervisor {
                    order: Arc::clone(&order),
                    cancel_after: 2,
                }),
            )
            .expect("install caller-owned initial-only recovery service runner");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        application_runtime
            .block_on(runner.run(&Cx::for_testing()))
            .expect("cancellation after two initial handoffs exits cleanly");

        assert_eq!(
            order
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            ["initial", "initial"],
            "changing only the absence of accepted input preserves initial recovery without inventing a resumed handoff"
        );
    }

    #[test]
    fn task_03_final_service_runner_error_restores_exact_accepted_input() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let first_runtime =
            final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses = serde_json::from_value(
            serde_json::json!({"roots": {"roots": [{"uri": "file:///recovery-error"}]}}),
        )
        .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&first_runtime, input_responses.clone());
        drop(first_runtime);

        let recovered_runtime =
            final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let runner = recovered_runtime
            .install_task_service(1, Arc::new(FailingFinalTaskSupervisor))
            .expect("install caller-owned failing service runner");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        assert!(
            application_runtime
                .block_on(runner.run(&Cx::for_testing()))
                .is_err(),
            "the supervisor error remains visible after durable restoration"
        );
        let restored = recovered_runtime
            .recover_accepted_input()
            .expect("recovery scan reads restored handoff")
            .expect("supervisor failure restores the accepted handoff");
        assert_eq!(restored.task_id(), &task_id);
        assert_eq!(
            restored.input_responses(),
            &input_responses,
            "error recovery restores the exact input payload cloned before await"
        );
    }

    #[test]
    fn task_03_final_retryable_low_id_recovery_does_not_starve_later_work_across_runner_restart() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let low = final_working_task_without_ttl("task-recovery-a-retryable-low");
        let high = final_working_task_without_ttl("task-recovery-b-later-work");
        let low_id = low.base().task_id.clone();
        let high_id = high.base().task_id.clone();
        store
            .create_task_with_work(
                low.clone(),
                final_task_notification(&low),
                final_test_work_descriptor(),
            )
            .expect("the low-ID retry fixture is retained before the first runner starts");
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let first_attempted = Arc::new(Mutex::new(Vec::new()));
        let first_runner = runtime
            .install_task_service(
                1,
                Arc::new(FailLowIdCompleteLaterInitialSupervisor {
                    low_task_id: low_id.clone(),
                    attempted: Arc::clone(&first_attempted),
                }),
            )
            .expect("first service runner installs");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        assert!(
            application_runtime
                .block_on(first_runner.run(&Cx::for_testing()))
                .is_err(),
            "the first low-ID-only runner exposes its retryable supervisor error"
        );
        assert_eq!(
            first_attempted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            &[low_id.clone(), low_id.clone()],
            "the one-task baseline retries only the restored low-ID handoff"
        );
        store
            .create_task_with_work(
                high.clone(),
                final_task_notification(&high),
                final_test_work_descriptor(),
            )
            .expect("later durable work is retained before the replacement runner starts");
        let second_attempted = Arc::new(Mutex::new(Vec::new()));
        let second_runner = runtime
            .install_task_service(
                1,
                Arc::new(FailLowIdCompleteLaterInitialSupervisor {
                    low_task_id: low_id.clone(),
                    attempted: Arc::clone(&second_attempted),
                }),
            )
            .expect("replacement service runner installs after the retryable exit");
        assert!(
            application_runtime
                .block_on(second_runner.run(&Cx::for_testing()))
                .is_err(),
            "the replacement runner preserves the original retryable error after advancing past it"
        );
        assert_eq!(
            second_attempted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            &[low_id.clone(), high_id.clone(), low_id.clone()],
            "changing only the later task and restarting the runner reaches it before the low-ID retry repeats"
        );
        assert!(matches!(
            runtime
                .get_task(&high_id)
                .expect("later task remains readable after the retryable failure")
                .task,
            FinalTask::Completed { .. }
        ));
        assert!(matches!(
            runtime
                .get_task(&low_id)
                .expect("retryable low-ID task remains readable")
                .task,
            FinalTask::Working(_)
        ));
    }

    #[test]
    fn task_03_final_service_runner_newer_transition_wins_over_error_restore() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let first_runtime =
            final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let input_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed retained roots response");
        let task_id = create_accepted_final_input(&first_runtime, input_responses);
        drop(first_runtime);

        let recovered_runtime =
            final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let runner = recovered_runtime
            .install_task_service(
                1,
                Arc::new(TerminalTransitionThenFailingFinalTaskSupervisor {}),
            )
            .expect("install caller-owned transitioning failing service runner");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        assert!(
            application_runtime
                .block_on(runner.run(&Cx::for_testing()))
                .is_err(),
            "the supervisor error remains visible when a newer transition wins"
        );
        assert!(matches!(
            recovered_runtime
                .get_task(&task_id)
                .expect("read terminal winner after failed supervisor")
                .task,
            FinalTask::Completed { .. }
        ));
        assert!(
            recovered_runtime
                .recover_accepted_input()
                .expect("recovery scan after terminal transition is valid")
                .is_none(),
            "the generation-fenced restore cannot resurrect input into the newer terminal state"
        );
    }

    #[test]
    fn task_03_final_public_service_rejects_success_without_transition_and_restores_work() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let work_descriptor = FinalTaskWorkDescriptor::new(serde_json::json!({
            "operation": "must-remain-recoverable-after-noop-supervisor",
        }))
        .expect("a non-null task descriptor is valid");
        let runner = runtime
            .install_task_service(1, Arc::new(NoTransitionFinalTaskSupervisor))
            .expect("the caller-owned service installs");
        let service_cx = Cx::for_testing();
        let mut service = Box::pin(runner.run(&service_cx));
        let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Future::poll(service.as_mut(), &mut task_cx),
            std::task::Poll::Pending
        ));
        let task_id = runtime
            .create_task_with_work(work_descriptor.clone(), None)
            .expect("the entered service admits public initial work")
            .task
            .base()
            .task_id
            .clone();

        let error = match Future::poll(service.as_mut(), &mut task_cx) {
            std::task::Poll::Ready(Err(error)) => error,
            std::task::Poll::Ready(Ok(())) => {
                panic!("a no-transition supervisor must not be accepted as successful")
            }
            std::task::Poll::Pending => {
                panic!("the queued no-transition supervisor must resolve to a recovery error")
            }
        };
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);
        assert_eq!(
            error.message,
            "Final task supervisor returned success without a fenced task transition"
        );
        assert!(matches!(
            store
                .get_task(&task_id)
                .expect("the unresolved task remains readable"),
            Some(FinalTask::Working(_))
        ));
        let recovered = runtime
            .recover_initial_work()
            .expect("the rejected handoff remains recoverable")
            .expect("the exact initial work is restored for another service generation");
        assert_eq!(recovered.task_id(), &task_id);
        assert_eq!(recovered.work_descriptor(), &work_descriptor);
    }

    #[test]
    fn task_03_final_elected_handoff_completion_commits_atomically() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();
        let before = store
            .get_task_snapshot(&task_id)
            .expect("read task before elected completion")
            .expect("fixture task is retained");
        let initial = runtime
            .recover_initial_work()
            .expect("recover initial handoff")
            .expect("fixture task retains initial work");
        let runner = runtime
            .install_task_service(1, Arc::new(FencedCompletingFinalTaskSupervisor))
            .expect("install the elected handoff runner");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        application_runtime
            .block_on(runner.resume_handoff(
                &Cx::for_testing(),
                FinalTaskSupervisorHandoff::Initial(initial),
            ))
            .expect("the elected handoff completes the task");

        let after = store
            .get_task_snapshot(&task_id)
            .expect("read task after elected completion")
            .expect("completed task is retained");
        assert!(matches!(after.task(), FinalTask::Completed { .. }));
        assert!(
            after.generation() > before.generation(),
            "the fenced terminal transition advances the durable generation"
        );
        assert!(matches!(
            store
                .latest_notification(&task_id)
                .expect("terminal notification is retained")
                .params
                .task,
            FinalTask::Completed { .. }
        ));
    }

    #[test]
    fn task_03_final_stale_handoff_fence_rejects_identical_completion_without_mutation() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();
        let before = store
            .get_task_snapshot(&task_id)
            .expect("read task before stale-fence completion")
            .expect("fixture task is retained");
        let notification_before = serde_json::to_value(
            store
                .latest_notification(&task_id)
                .expect("fixture task retains its working notification"),
        )
        .expect("encode notification before stale-fence completion");
        let initial = runtime
            .recover_initial_work()
            .expect("recover initial handoff")
            .expect("fixture task retains initial work");
        let observed_error = Arc::new(Mutex::new(None));
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(StaleFenceCompletingFinalTaskSupervisor {
                    store: Arc::clone(&store),
                    observed_error: Arc::clone(&observed_error),
                }),
            )
            .expect("install the stale-fence handoff runner");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        let runner_error = application_runtime
            .block_on(runner.resume_handoff(
                &Cx::for_testing(),
                FinalTaskSupervisorHandoff::Initial(initial),
            ))
            .expect_err("an unfenced successful return must leave recovery visibly failed");
        assert_eq!(
            runner_error.code,
            fastmcp_core::McpErrorCode::InternalError,
            "the runner reports that the supervisor returned success without a valid transition"
        );

        let error = observed_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("the only changed dimension, dispatch fence, rejects completion");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
        let after = store
            .get_task_snapshot(&task_id)
            .expect("read task after stale-fence completion")
            .expect("fixture task remains retained");
        assert_eq!(
            after.generation(),
            before.generation(),
            "a stale fence cannot advance the durable task generation"
        );
        assert!(matches!(after.task(), FinalTask::Working(_)));
        assert_eq!(
            serde_json::to_value(
                store
                    .latest_notification(&task_id)
                    .expect("stale completion preserves the notification"),
            )
            .expect("encode notification after stale-fence completion"),
            notification_before,
            "a stale fence cannot replace the durable task notification"
        );
    }

    #[test]
    fn task_03_final_stale_handoff_generation_rejects_completion_without_second_mutation() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();
        let before = store
            .get_task_snapshot(&task_id)
            .expect("read task before the competing generation transition")
            .expect("fixture task is retained");
        let initial = runtime
            .recover_initial_work()
            .expect("recover initial handoff")
            .expect("fixture task retains initial work");
        let observed_error = Arc::new(Mutex::new(None));
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(StaleGenerationCompletingFinalTaskSupervisor {
                    runtime: runtime.clone(),
                    observed_error: Arc::clone(&observed_error),
                }),
            )
            .expect("install the stale-generation handoff runner");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        application_runtime
            .block_on(runner.resume_handoff(
                &Cx::for_testing(),
                FinalTaskSupervisorHandoff::Initial(initial),
            ))
            .expect("the supervisor records its stale-generation rejection");

        let error = observed_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("the stale generation rejects the terminal handoff");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
        let after = store
            .get_task_snapshot(&task_id)
            .expect("read task after stale-generation completion")
            .expect("the competing task state remains retained");
        assert_eq!(
            after.generation(),
            before
                .generation()
                .checked_add(1)
                .expect("fixture generation remains representable"),
            "the rejected stale handoff cannot add a second durable transition"
        );
        assert!(matches!(
            after.task(),
            FinalTask::InputRequired { base, input_requests }
                if base.status_message.as_deref()
                    == Some("newer generation won before completion")
                    && input_requests.contains_key("roots")
        ));
        assert_eq!(
            serde_json::to_value(
                store
                    .latest_notification(&task_id)
                    .expect("the competing notification remains retained")
                    .params
                    .task,
            )
            .expect("encode notification after stale-generation rejection"),
            serde_json::to_value(after.task())
                .expect("encode competing task after stale-generation rejection"),
            "the stale handoff cannot replace the newer task notification"
        );
    }

    #[test]
    fn task_03_final_repeated_terminal_handoff_is_rejected_without_second_mutation() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();
        let before = store
            .get_task_snapshot(&task_id)
            .expect("read task before repeated terminal handoff")
            .expect("fixture task is retained");
        let initial = runtime
            .recover_initial_work()
            .expect("recover initial handoff")
            .expect("fixture task retains initial work");
        let observed_error = Arc::new(Mutex::new(None));
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(RepeatedTerminalHandoffSupervisor {
                    observed_error: Arc::clone(&observed_error),
                }),
            )
            .expect("install repeated-terminal handoff runner");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        application_runtime
            .block_on(runner.resume_handoff(
                &Cx::for_testing(),
                FinalTaskSupervisorHandoff::Initial(initial),
            ))
            .expect("the repeated terminal attempt is contained by the supervisor");

        let error = observed_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("the second terminal handoff is rejected");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
        let after = store
            .get_task_snapshot(&task_id)
            .expect("read task after repeated terminal handoff")
            .expect("the first terminal result remains retained");
        assert_eq!(
            after.generation(),
            before
                .generation()
                .checked_add(1)
                .expect("fixture generation remains representable"),
            "the repeated terminal handoff cannot add a second durable transition"
        );
        assert!(matches!(
            after.task(),
            FinalTask::Completed { base, .. }
                if base.status_message.as_deref() == Some("first terminal handoff")
        ));
        assert_eq!(
            serde_json::to_value(
                store
                    .latest_notification(&task_id)
                    .expect("the first terminal notification remains retained")
                    .params
                    .task,
            )
            .expect("encode notification after repeated terminal rejection"),
            serde_json::to_value(after.task())
                .expect("encode first terminal task after repeated rejection"),
            "the repeated handoff cannot replace the first terminal notification"
        );
    }

    #[test]
    fn task_03_final_cancellation_winner_can_be_honored_by_the_elected_handoff() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();
        let initial = runtime
            .recover_initial_work()
            .expect("recover initial handoff")
            .expect("fixture task retains initial work");
        let observed_cancellation = Arc::new(AtomicBool::new(false));
        let runner = runtime
            .install_task_service(
                1,
                Arc::new(CancelThenHonoringCancellationFinalTaskSupervisor {
                    runtime: runtime.clone(),
                    observed_cancellation: Arc::clone(&observed_cancellation),
                }),
            )
            .expect("install cancellation-honouring handoff runner");
        let application_runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build application-owned structured runtime");

        application_runtime
            .block_on(runner.resume_handoff(
                &Cx::for_testing(),
                FinalTaskSupervisorHandoff::Initial(initial),
            ))
            .expect("the elected handoff records the cancellation outcome");

        assert!(
            observed_cancellation.load(AtomicOrdering::SeqCst),
            "the elected handoff observes the cancellation winner before its terminal transition"
        );
        let after = store
            .get_task_snapshot(&task_id)
            .expect("read task after honoured cancellation")
            .expect("cancelled task remains retained");
        assert!(matches!(
            after.task(),
            FinalTask::Cancelled(base)
                if base.status_message.as_deref()
                    == Some("cancellation won the elected handoff")
        ));
        assert!(
            !runtime
                .is_cancellation_requested(&task_id)
                .expect("terminal cancellation outcome clears the pending intent"),
            "the final cancellation result consumes the cooperative intent"
        );
    }

    #[test]
    fn task_03_final_external_store_default_fenced_transition_fails_unchanged() {
        let inner = Arc::new(InMemoryFinalTaskStore::default());
        let external_store = ReadinessLeaseProbeFinalTaskStore::new(Arc::clone(&inner));
        let task = final_working_task_without_ttl("task-external-default-fence");
        let task_id = task.base().task_id.clone();
        inner
            .create_task_with_work(
                task.clone(),
                final_task_notification(&task),
                final_test_work_descriptor(),
            )
            .expect("external-store fixture retains the initial task and work");
        let expected = inner
            .get_task_snapshot(&task_id)
            .expect("read external-store fixture snapshot")
            .expect("external-store fixture task is retained");
        test_take_initial_work(&inner, &expected)
            .expect("claim external-store fixture initial handoff")
            .expect("external-store fixture retains initial work");
        let dispatch_fence = FinalTaskStore::begin_handoff_dispatch_for_owner_if_current(
            &*inner,
            &task_id,
            expected.generation(),
            FINAL_TASK_TEST_DIRECT_OWNER,
        )
        .expect("elect external-store fixture handoff")
        .expect("external-store fixture handoff election succeeds");
        let task_before = serde_json::to_value(expected.task())
            .expect("encode external-store task before default rejection");
        let notification_before = serde_json::to_value(
            inner
                .latest_notification(&task_id)
                .expect("external-store fixture notification is retained"),
        )
        .expect("encode external-store notification before default rejection");
        let result: FinalTaskCallToolResult =
            serde_json::from_value(serde_json::json!({"content": []}))
                .expect("typed terminal task result");
        let replacement = FinalTask::Completed {
            base: transition_terminal_final_task_base(
                expected.task().base().clone(),
                FinalTaskStatus::Completed,
                Some("default fenced transition must fail".to_owned()),
            )
            .expect("construct terminal replacement for the external-store probe"),
            result,
        };
        let error = FinalTaskStore::replace_task_and_clear_input_for_handoff_if_current(
            &external_store,
            &expected,
            FINAL_TASK_TEST_DIRECT_OWNER,
            dispatch_fence,
            false,
            replacement.clone(),
            final_task_notification(&replacement),
        )
        .expect_err("an external store must opt into fenced handoff transitions");

        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);
        let after = inner
            .get_task_snapshot(&task_id)
            .expect("read external-store fixture after default rejection")
            .expect("default rejection leaves the task retained");
        assert_eq!(after.generation(), expected.generation());
        assert_eq!(
            serde_json::to_value(after.task())
                .expect("encode external-store task after default rejection"),
            task_before,
            "the default fenced-transition rejection leaves the task unchanged"
        );
        assert_eq!(
            serde_json::to_value(
                inner
                    .latest_notification(&task_id)
                    .expect("default rejection leaves the notification retained"),
            )
            .expect("encode external-store notification after default rejection"),
            notification_before,
            "the default fenced-transition rejection leaves the notification unchanged"
        );
        let state = inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            state.handoff_leases.get(&task_id).is_some_and(|lease| {
                lease.generation == expected.generation()
                    && lease.owner_id == FINAL_TASK_TEST_DIRECT_OWNER
                    && lease.dispatch_elected
                    && lease.dispatch_fence == Some(dispatch_fence)
            }),
            "the default fenced-transition rejection leaves the elected handoff lease unchanged"
        );
    }

    #[test]
    fn task_03_final_rejected_input_preserves_supervisor_handoff_state() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
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
        assert_eq!(
            after, before,
            "rejected input leaves durable task state unchanged"
        );
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
    fn task_03_final_update_ignores_unknown_and_already_satisfied_keys_without_mutation() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();
        let mut requests = final_roots_request();
        requests.insert(
            "other-roots".to_owned(),
            serde_json::from_value(serde_json::json!({"method": "roots/list"}))
                .expect("typed second roots request"),
        );
        runtime
            .require_input(&task_id, requests, None)
            .expect("task awaits two typed roots responses");
        let first_response: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed first roots response");
        runtime
            .update_task(&task_id, &first_response)
            .expect("first outstanding input response is accepted");
        let before = serde_json::to_value(
            &runtime
                .get_task(&task_id)
                .expect("read task before ignored replay")
                .task,
        )
        .expect("encode task before ignored replay");
        let generation_before = store
            .get_task_snapshot(&task_id)
            .expect("read task generation before ignored replay")
            .expect("task is retained before ignored replay")
            .generation();
        let notification_before = serde_json::to_value(store.latest_notification(&task_id))
            .expect("encode notification before ignored replay");
        let ignored_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({
                "roots": {
                    "role": "assistant",
                    "model": "final-model",
                    "content": {"type": "text", "text": "already satisfied"}
                },
                "stale-key": {
                    "role": "assistant",
                    "model": "final-model",
                    "content": {"type": "text", "text": "unknown"}
                }
            }))
            .expect("well-formed ignored response map");

        runtime
            .update_task(&task_id, &ignored_responses)
            .expect("unknown and already-satisfied input keys are acknowledged as a no-op");

        // Task carries no PartialEq; wire-value equality is the semantic
        // identity for these serialized snapshots.
        assert_eq!(
            serde_json::to_value(
                &runtime
                    .get_task(&task_id)
                    .expect("read task after ignored replay")
                    .task,
            )
            .expect("encode task after ignored replay"),
            before,
            "ignored keys cannot change outstanding input state"
        );
        assert_eq!(
            store
                .get_task_snapshot(&task_id)
                .expect("read generation after ignored replay")
                .expect("task remains retained after ignored replay")
                .generation(),
            generation_before,
            "ignored keys cannot advance the durable task generation"
        );
        assert_eq!(
            serde_json::to_value(store.latest_notification(&task_id))
                .expect("encode notification after ignored replay"),
            notification_before,
            "ignored keys cannot emit a replacement task notification"
        );
    }

    #[test]
    fn task_03_final_update_rejects_wrong_kind_for_outstanding_key_with_ignored_keys_present() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
            .task
            .base()
            .task_id
            .clone();
        let mut requests = final_roots_request();
        requests.insert(
            "other-roots".to_owned(),
            serde_json::from_value(serde_json::json!({"method": "roots/list"}))
                .expect("typed second roots request"),
        );
        runtime
            .require_input(&task_id, requests, None)
            .expect("task awaits two typed roots responses");
        let first_response: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({"roots": {"roots": []}}))
                .expect("typed first roots response");
        runtime
            .update_task(&task_id, &first_response)
            .expect("first outstanding input response is accepted");
        let before = serde_json::to_value(
            &runtime
                .get_task(&task_id)
                .expect("read task before planted wrong-kind response")
                .task,
        )
        .expect("encode task before planted wrong-kind response");
        let generation_before = store
            .get_task_snapshot(&task_id)
            .expect("read generation before planted wrong-kind response")
            .expect("task is retained before planted wrong-kind response")
            .generation();
        let rejected_responses: FinalTaskInputResponses =
            serde_json::from_value(serde_json::json!({
                "roots": {
                    "role": "assistant",
                    "model": "final-model",
                    "content": {"type": "text", "text": "already satisfied"}
                },
                "other-roots": {
                    "role": "assistant",
                    "model": "final-model",
                    "content": {"type": "text", "text": "wrong outstanding kind"}
                }
            }))
            .expect("well-formed mixed response map");

        assert!(
            runtime.update_task(&task_id, &rejected_responses).is_err(),
            "changing only the stale key to an outstanding roots key preserves wrong-kind rejection"
        );
        assert_eq!(
            serde_json::to_value(
                &runtime
                    .get_task(&task_id)
                    .expect("read task after rejected response")
                    .task,
            )
            .expect("encode task after rejected response"),
            before,
            "wrong-kind outstanding input cannot mutate task state"
        );
        assert_eq!(
            store
                .get_task_snapshot(&task_id)
                .expect("read generation after rejected response")
                .expect("task remains retained after rejected response")
                .generation(),
            generation_before,
            "wrong-kind outstanding input cannot advance the task generation"
        );
    }

    #[test]
    fn task_03_final_durable_runtime_wrong_response_kind_preserves_state() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = final_task_runtime(Arc::clone(&store), Arc::new(AtomicBool::new(false)));
        let task_id = create_final_task_state_fixture(&runtime, None)
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
