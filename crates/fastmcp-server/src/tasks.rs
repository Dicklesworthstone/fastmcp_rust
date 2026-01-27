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
            TaskStatus::Running | TaskStatus::Cancelled
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
    runtime: RuntimeHandle,
    /// Whether submitted tasks should execute immediately.
    auto_execute: bool,
    /// Optional notification sender for task status updates.
    notification_sender: Arc<RwLock<Option<TaskNotificationSender>>>,
}

impl TaskManager {
    /// Creates a new task manager.
    #[must_use]
    pub fn new() -> Self {
        let runtime = RuntimeBuilder::multi_thread()
            .build()
            .expect("failed to build background task runtime")
            .handle();
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
        let tasks = Arc::clone(&self.tasks);
        let handlers = Arc::clone(&self.handlers);
        let notification_sender = Arc::clone(&self.notification_sender);

        self.runtime.spawn(async move {
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

            notify_snapshot(&notification_sender, running_snapshot);

            let task_future = {
                let handlers_guard = handlers.read().unwrap_or_else(|poisoned| {
                    warn!(target: targets::SERVER, "handlers lock poisoned in spawn_task, recovering");
                    poisoned.into_inner()
                });
                let Some(handler) = handlers_guard.get(&task_type) else {
                    let failure_snapshot = {
                        let mut tasks_guard = tasks.write().unwrap_or_else(|poisoned| {
                            warn!(target: targets::SERVER, "tasks lock poisoned in spawn_task failure, recovering");
                            poisoned.into_inner()
                        });
                        match tasks_guard.get_mut(&task_id) {
                            Some(state) => {
                                if !state.cancel_requested {
                                    let error_msg = format!("Unknown task type: {task_type}");
                                    state.info.status = TaskStatus::Failed;
                                    state.info.completed_at = Some(chrono::Utc::now().to_rfc3339());
                                    state.info.error = Some(error_msg.clone());
                                    state.result = Some(TaskResult {
                                        id: task_id.clone(),
                                        success: false,
                                        data: None,
                                        error: Some(error_msg),
                                    });
                                    Some(TaskStatusSnapshot::from(state))
                                } else {
                                    None
                                }
                            }
                            None => None,
                        }
                    };
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
}
