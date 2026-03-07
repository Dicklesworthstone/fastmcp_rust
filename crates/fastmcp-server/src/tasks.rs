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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use asupersync::runtime::{RuntimeBuilder, RuntimeHandle};
use asupersync::{Budget, CancelKind, Cx};
use fastmcp_core::logging::{debug, info, targets, warn};
use fastmcp_core::{McpError, McpResult};
use fastmcp_protocol::{
    JsonRpcRequest, TaskId, TaskInfo, TaskResult, TaskStatus, TaskStatusNotificationParams,
};

/// Notification sender used for task status updates.
pub type TaskNotificationSender = Arc<dyn Fn(JsonRpcRequest) + Send + Sync>;

/// Callback type for task execution.
///
/// Task handlers receive the context and parameters, and return a result.
pub type TaskHandler = Box<dyn Fn(&Cx, serde_json::Value) -> TaskFuture + Send + Sync + 'static>;

/// Future type for task execution.
pub type TaskFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = McpResult<serde_json::Value>> + Send + 'static>,
>;

/// Internal state for a running task.
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
        _cx: &Cx,
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
        let task_cx = Cx::for_request_with_budget(Budget::INFINITE);
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

#[derive(Debug, Clone)]
struct TaskStatusSnapshot {
    info: TaskInfo,
    result: Option<TaskResult>,
}

impl TaskStatusSnapshot {
    fn from(state: &TaskState) -> Self {
        Self {
            info: state.info.clone(),
            result: state.result.clone(),
        }
    }
}

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

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

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
pub type SharedTaskManager = Arc<TaskManager>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

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
}
