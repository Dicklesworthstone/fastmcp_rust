//! Docket: Distributed task queue for FastMCP.
//!
//! Provides distributed task queue capabilities with support for multiple backends:
//! - **Memory**: In-process queue for testing and development
//! - **Redis**: Distributed queue for production deployments
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │                        Docket                              │
//! │  ┌─────────────────┐  ┌─────────────────┐                  │
//! │  │   DocketClient  │  │   Worker Pool   │                  │
//! │  │   (task submit) │  │   (processing)  │                  │
//! │  └────────┬────────┘  └────────┬────────┘                  │
//! │           │                    │                           │
//! │           └──────────┬─────────┘                           │
//! │                      ▼                                     │
//! │           ┌────────────────────┐                           │
//! │           │   DocketBackend    │                           │
//! │           └─────────┬──────────┘                           │
//! │                     │                                      │
//! │       ┌─────────────┼─────────────┐                        │
//! │       ▼             ▼             ▼                        │
//! │  ┌─────────┐  ┌─────────┐  ┌─────────────┐                 │
//! │  │ Memory  │  │  Redis  │  │   Future    │                 │
//! │  │ Backend │  │ Backend │  │  Backends   │                 │
//! │  └─────────┘  └─────────┘  └─────────────┘                 │
//! └────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use fastmcp_server::docket::{Docket, DocketSettings, Worker};
//!
//! // Create with memory backend (testing/development)
//! let docket = Docket::memory();
//!
//! // Create with Redis backend (production)
//! let settings = DocketSettings::redis("redis://localhost:6379");
//! let docket = Docket::new(settings)?;
//!
//! // Submit a task
//! let task_id = docket.submit("process_data", json!({"input": "data"})).await?;
//!
//! // Create a worker
//! let worker = docket.worker()
//!     .subscribe("process_data", |task| async move {
//!         // Process the task
//!         Ok(json!({"result": "processed"}))
//!     })
//!     .build();
//!
//! // Start processing
//! worker.run().await?;
//! ```

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::McpError;
use fastmcp_core::logging::{debug, info, targets, warn};
use fastmcp_protocol::{TaskId, TaskInfo, TaskResult, TaskStatus};
use serde::{Deserialize, Serialize};

// ============================================================================
// Configuration
// ============================================================================

/// Settings for configuring a Docket instance.
#[derive(Debug, Clone)]
pub struct DocketSettings {
    /// Backend type (memory or redis).
    pub backend: DocketBackendType,
    /// Queue name prefix for namespacing.
    pub queue_prefix: String,
    /// Task visibility timeout (how long before unacked task is requeued).
    pub visibility_timeout: Duration,
    /// Default task timeout.
    pub default_task_timeout: Duration,
    /// Maximum retry count for failed tasks.
    pub max_retries: u32,
    /// Delay between retries (with exponential backoff).
    pub retry_delay: Duration,
    /// Worker poll interval when queue is empty.
    pub poll_interval: Duration,
}

impl Default for DocketSettings {
    fn default() -> Self {
        Self {
            backend: DocketBackendType::Memory,
            queue_prefix: "fastmcp:docket".to_string(),
            visibility_timeout: Duration::from_secs(30),
            default_task_timeout: Duration::from_secs(300),
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
            poll_interval: Duration::from_millis(100),
        }
    }
}

impl DocketSettings {
    /// Creates settings for memory backend (testing/development).
    #[must_use]
    pub fn memory() -> Self {
        Self::default()
    }

    /// Creates settings for Redis backend.
    #[must_use]
    pub fn redis(url: impl Into<String>) -> Self {
        Self {
            backend: DocketBackendType::Redis(RedisSettings {
                url: url.into(),
                pool_size: 10,
                connect_timeout: Duration::from_secs(5),
            }),
            ..Self::default()
        }
    }

    /// Sets the queue prefix.
    #[must_use]
    pub fn with_queue_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.queue_prefix = prefix.into();
        self
    }

    /// Sets the visibility timeout.
    #[must_use]
    pub fn with_visibility_timeout(mut self, timeout: Duration) -> Self {
        self.visibility_timeout = timeout;
        self
    }

    /// Sets the maximum retry count.
    #[must_use]
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Sets the poll interval.
    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }
}

/// Backend type configuration.
#[derive(Debug, Clone)]
pub enum DocketBackendType {
    /// In-memory backend for testing/development.
    Memory,
    /// Redis backend for production.
    Redis(RedisSettings),
}

/// Redis connection settings.
#[derive(Debug, Clone)]
pub struct RedisSettings {
    /// Redis connection URL.
    pub url: String,
    /// Connection pool size.
    pub pool_size: usize,
    /// Connection timeout.
    pub connect_timeout: Duration,
}

// ============================================================================
// Task Types
// ============================================================================

/// A queued task in the Docket system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocketTask {
    /// Unique task identifier.
    pub id: TaskId,
    /// Task type (determines which handler processes it).
    pub task_type: String,
    /// Task parameters.
    pub params: serde_json::Value,
    /// Task priority (higher = processed first).
    pub priority: i32,
    /// Number of retry attempts so far.
    pub retry_count: u32,
    /// Maximum retries allowed.
    pub max_retries: u32,
    /// When the task was created.
    pub created_at: String,
    /// When the task was claimed by a worker.
    pub claimed_at: Option<String>,
    /// Current task status.
    pub status: TaskStatus,
    /// Error message if failed.
    pub error: Option<String>,
    /// Task result if completed.
    pub result: Option<serde_json::Value>,
}

impl DocketTask {
    /// Creates a new task.
    fn new(
        id: TaskId,
        task_type: String,
        params: serde_json::Value,
        priority: i32,
        max_retries: u32,
    ) -> Self {
        Self {
            id,
            task_type,
            params,
            priority,
            retry_count: 0,
            max_retries,
            created_at: chrono::Utc::now().to_rfc3339(),
            claimed_at: None,
            status: TaskStatus::Pending,
            error: None,
            result: None,
        }
    }

    /// Converts to TaskInfo for protocol responses.
    #[must_use]
    pub fn to_task_info(&self) -> TaskInfo {
        TaskInfo {
            id: self.id.clone(),
            task_type: self.task_type.clone(),
            status: self.status,
            progress: None,
            message: None,
            created_at: self.created_at.clone(),
            started_at: self.claimed_at.clone(),
            completed_at: if self.status.is_terminal() {
                Some(chrono::Utc::now().to_rfc3339())
            } else {
                None
            },
            error: self.error.clone(),
        }
    }

    /// Converts to TaskResult for protocol responses.
    #[must_use]
    pub fn to_task_result(&self) -> Option<TaskResult> {
        if !self.status.is_terminal() {
            return None;
        }
        Some(TaskResult {
            id: self.id.clone(),
            success: self.status == TaskStatus::Completed,
            data: self.result.clone(),
            error: self.error.clone(),
        })
    }
}

/// Options for submitting a task.
#[derive(Debug, Clone, Default)]
pub struct SubmitOptions {
    /// Task priority (higher = processed first).
    pub priority: i32,
    /// Maximum retries (overrides default).
    pub max_retries: Option<u32>,
    /// Delay before task becomes visible.
    pub delay: Option<Duration>,
}

impl SubmitOptions {
    /// Creates default options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets task priority.
    #[must_use]
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Sets max retries.
    #[must_use]
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = Some(retries);
        self
    }

    /// Sets initial delay.
    #[must_use]
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}

// ============================================================================
// Backend Trait
// ============================================================================

/// Result type for Docket operations.
pub type DocketResult<T> = Result<T, DocketError>;

/// Errors that can occur in Docket operations.
#[derive(Debug)]
pub enum DocketError {
    /// Task not found.
    NotFound(String),
    /// Backend connection error.
    Connection(String),
    /// Serialization error.
    Serialization(String),
    /// Task handler error.
    Handler(String),
    /// Backend-specific error.
    Backend(String),
    /// Cancelled.
    Cancelled,
}

impl std::fmt::Display for DocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DocketError::NotFound(msg) => write!(f, "Task not found: {msg}"),
            DocketError::Connection(msg) => write!(f, "Connection error: {msg}"),
            DocketError::Serialization(msg) => write!(f, "Serialization error: {msg}"),
            DocketError::Handler(msg) => write!(f, "Handler error: {msg}"),
            DocketError::Backend(msg) => write!(f, "Backend error: {msg}"),
            DocketError::Cancelled => write!(f, "Operation cancelled"),
        }
    }
}

impl std::error::Error for DocketError {}

impl From<DocketError> for McpError {
    fn from(err: DocketError) -> Self {
        McpError::internal_error(err.to_string())
    }
}

/// Backend trait for Docket storage.
///
/// Implementations provide the actual storage and retrieval of tasks.
/// The trait uses synchronous methods but backends can internally use
/// async operations wrapped in blocking.
pub trait DocketBackend: Send + Sync {
    /// Enqueues a task for processing.
    fn enqueue(&self, task: DocketTask) -> DocketResult<()>;

    /// Dequeues a task for the given task types.
    ///
    /// Returns the highest priority task that matches one of the subscribed types.
    /// The task is marked as claimed but not removed from the queue until acknowledged.
    fn dequeue(&self, task_types: &[String]) -> DocketResult<Option<DocketTask>>;

    /// Acknowledges successful task completion.
    fn ack(&self, task_id: &TaskId, result: serde_json::Value) -> DocketResult<()>;

    /// Negative acknowledgement - task failed, may be retried.
    fn nack(&self, task_id: &TaskId, error: &str) -> DocketResult<()>;

    /// Gets task by ID.
    fn get_task(&self, task_id: &TaskId) -> DocketResult<Option<DocketTask>>;

    /// Lists tasks, optionally filtered by status.
    fn list_tasks(&self, status: Option<TaskStatus>, limit: usize)
    -> DocketResult<Vec<DocketTask>>;

    /// Cancels a task.
    fn cancel(&self, task_id: &TaskId, reason: Option<&str>) -> DocketResult<()>;

    /// Returns queue statistics.
    fn stats(&self) -> DocketResult<QueueStats>;

    /// Requeues tasks that have exceeded visibility timeout.
    fn requeue_stale(&self) -> DocketResult<usize>;
}

/// Queue statistics.
#[derive(Debug, Clone, Default)]
pub struct QueueStats {
    /// Number of pending tasks.
    pub pending: usize,
    /// Number of in-progress tasks.
    pub in_progress: usize,
    /// Number of completed tasks.
    pub completed: usize,
    /// Number of failed tasks.
    pub failed: usize,
    /// Number of cancelled tasks.
    pub cancelled: usize,
}

// ============================================================================
// Memory Backend
// ============================================================================

/// In-memory Docket backend for testing and development.
///
/// Tasks are stored in memory and not persisted across restarts.
/// This backend is thread-safe and suitable for single-process deployments.
pub struct MemoryDocketBackend {
    /// All tasks indexed by ID.
    tasks: RwLock<HashMap<TaskId, DocketTask>>,
    /// Pending tasks queue (sorted by priority, then creation time).
    pending: RwLock<VecDeque<TaskId>>,
    /// Settings for visibility timeout, retries, etc.
    settings: DocketSettings,
}

impl MemoryDocketBackend {
    /// Creates a new memory backend.
    #[must_use]
    pub fn new(settings: DocketSettings) -> Self {
        Self {
            tasks: RwLock::new(HashMap::new()),
            pending: RwLock::new(VecDeque::new()),
            settings,
        }
    }
}

impl DocketBackend for MemoryDocketBackend {
    fn enqueue(&self, task: DocketTask) -> DocketResult<()> {
        let task_id = task.id.clone();
        let priority = task.priority;

        {
            let mut tasks = self
                .tasks
                .write()
                .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;
            tasks.insert(task_id.clone(), task);
        }

        {
            let mut pending = self
                .pending
                .write()
                .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;

            // Insert maintaining priority order (higher priority first)
            let tasks = self
                .tasks
                .read()
                .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;

            let pos = pending
                .iter()
                .position(|id| tasks.get(id).is_none_or(|t| t.priority < priority))
                .unwrap_or(pending.len());

            pending.insert(pos, task_id);
        }

        Ok(())
    }

    fn dequeue(&self, task_types: &[String]) -> DocketResult<Option<DocketTask>> {
        let mut pending = self
            .pending
            .write()
            .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;
        let mut tasks = self
            .tasks
            .write()
            .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;

        // Find first pending task matching subscribed types
        let pos = pending.iter().position(|id| {
            tasks.get(id).is_some_and(|t| {
                t.status == TaskStatus::Pending && task_types.contains(&t.task_type)
            })
        });

        if let Some(pos) = pos {
            let task_id = pending.remove(pos).expect("position valid");
            if let Some(task) = tasks.get_mut(&task_id) {
                task.status = TaskStatus::Running;
                task.claimed_at = Some(chrono::Utc::now().to_rfc3339());
                return Ok(Some(task.clone()));
            }
        }

        Ok(None)
    }

    fn ack(&self, task_id: &TaskId, result: serde_json::Value) -> DocketResult<()> {
        let mut tasks = self
            .tasks
            .write()
            .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;

        let task = tasks
            .get_mut(task_id)
            .ok_or_else(|| DocketError::NotFound(task_id.to_string()))?;

        task.status = TaskStatus::Completed;
        task.result = Some(result);

        Ok(())
    }

    fn nack(&self, task_id: &TaskId, error: &str) -> DocketResult<()> {
        let mut tasks = self
            .tasks
            .write()
            .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;
        let mut pending = self
            .pending
            .write()
            .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;

        let task = tasks
            .get_mut(task_id)
            .ok_or_else(|| DocketError::NotFound(task_id.to_string()))?;

        task.retry_count += 1;
        task.error = Some(error.to_string());

        if task.retry_count >= task.max_retries {
            // Max retries exceeded - mark as failed
            task.status = TaskStatus::Failed;
        } else {
            // Requeue for retry
            task.status = TaskStatus::Pending;
            task.claimed_at = None;
            pending.push_back(task_id.clone());
        }

        Ok(())
    }

    fn get_task(&self, task_id: &TaskId) -> DocketResult<Option<DocketTask>> {
        let tasks = self
            .tasks
            .read()
            .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;
        Ok(tasks.get(task_id).cloned())
    }

    fn list_tasks(
        &self,
        status: Option<TaskStatus>,
        limit: usize,
    ) -> DocketResult<Vec<DocketTask>> {
        let tasks = self
            .tasks
            .read()
            .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;

        let iter = tasks
            .values()
            .filter(|t| status.is_none_or(|s| t.status == s));

        Ok(iter.take(limit).cloned().collect())
    }

    fn cancel(&self, task_id: &TaskId, reason: Option<&str>) -> DocketResult<()> {
        let mut tasks = self
            .tasks
            .write()
            .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;
        let mut pending = self
            .pending
            .write()
            .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;

        let task = tasks
            .get_mut(task_id)
            .ok_or_else(|| DocketError::NotFound(task_id.to_string()))?;

        if task.status.is_terminal() {
            return Err(DocketError::Backend(format!(
                "Cannot cancel task in terminal state: {:?}",
                task.status
            )));
        }

        task.status = TaskStatus::Cancelled;
        task.error = reason.map(String::from);

        // Remove from pending queue
        pending.retain(|id| id != task_id);

        Ok(())
    }

    fn stats(&self) -> DocketResult<QueueStats> {
        let tasks = self
            .tasks
            .read()
            .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;

        let mut stats = QueueStats::default();
        for task in tasks.values() {
            match task.status {
                TaskStatus::Pending => stats.pending += 1,
                TaskStatus::Running => stats.in_progress += 1,
                TaskStatus::Completed => stats.completed += 1,
                TaskStatus::Failed => stats.failed += 1,
                TaskStatus::Cancelled => stats.cancelled += 1,
            }
        }

        Ok(stats)
    }

    fn requeue_stale(&self) -> DocketResult<usize> {
        let mut tasks = self
            .tasks
            .write()
            .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;
        let mut pending = self
            .pending
            .write()
            .map_err(|e| DocketError::Backend(format!("Lock poisoned: {e}")))?;

        let now = chrono::Utc::now();
        let timeout = chrono::Duration::from_std(self.settings.visibility_timeout)
            .unwrap_or_else(|_| chrono::Duration::seconds(30));

        let mut requeued = 0;

        for task in tasks.values_mut() {
            if task.status != TaskStatus::Running {
                continue;
            }

            if let Some(ref claimed_at) = task.claimed_at {
                if let Ok(claimed) = chrono::DateTime::parse_from_rfc3339(claimed_at) {
                    if now - claimed.with_timezone(&chrono::Utc) > timeout {
                        // Task has exceeded visibility timeout - requeue
                        task.status = TaskStatus::Pending;
                        task.claimed_at = None;
                        task.retry_count += 1;

                        if task.retry_count >= task.max_retries {
                            task.status = TaskStatus::Failed;
                            task.error = Some("Exceeded visibility timeout".to_string());
                        } else {
                            pending.push_back(task.id.clone());
                            requeued += 1;
                        }
                    }
                }
            }
        }

        Ok(requeued)
    }
}

// ============================================================================
// Redis Backend
// ============================================================================

/// Redis Docket backend for production distributed deployments.
///
/// Uses Redis lists and sorted sets for reliable task queuing with
/// visibility timeout and atomic operations.
#[cfg(feature = "redis")]
pub struct RedisDocketBackend {
    client: redis::Client,
    pool: Vec<std::sync::Mutex<redis::Connection>>,
    next_conn: std::sync::atomic::AtomicUsize,
    settings: RedisSettings,
    docket_settings: DocketSettings,
}

#[cfg(feature = "redis")]
impl RedisDocketBackend {
    /// Creates a new Redis backend.
    pub fn new(
        redis_settings: RedisSettings,
        docket_settings: DocketSettings,
    ) -> DocketResult<Self> {
        let client = redis::Client::open(redis_settings.url.as_str())
            .map_err(|e| DocketError::Backend(format!("Redis client init failed: {e}")))?;

        let mut pool = Vec::new();
        let pool_size = redis_settings.pool_size.max(1);
        for _ in 0..pool_size {
            let conn = client
                .get_connection()
                .map_err(|e| DocketError::Backend(format!("Redis connect failed: {e}")))?;
            pool.push(std::sync::Mutex::new(conn));
        }

        Ok(Self {
            client,
            pool,
            next_conn: std::sync::atomic::AtomicUsize::new(0),
            settings: redis_settings,
            docket_settings,
        })
    }

    fn key_tasks(&self) -> String {
        format!("{}:tasks", self.docket_settings.queue_prefix)
    }

    fn key_running(&self) -> String {
        format!("{}:running", self.docket_settings.queue_prefix)
    }

    fn key_types(&self) -> String {
        format!("{}:types", self.docket_settings.queue_prefix)
    }

    fn key_queue_member(&self) -> String {
        // task_id -> queue member encoding (used for pending/delayed removal)
        format!("{}:queue_member", self.docket_settings.queue_prefix)
    }

    fn key_queue_type(&self) -> String {
        // task_id -> task_type (used for pending/delayed key selection)
        format!("{}:queue_type", self.docket_settings.queue_prefix)
    }

    fn key_pending(&self, task_type: &str) -> String {
        format!("{}:pending:{task_type}", self.docket_settings.queue_prefix)
    }

    fn key_delayed(&self, task_type: &str) -> String {
        format!("{}:delayed:{task_type}", self.docket_settings.queue_prefix)
    }

    fn now_ms() -> i64 {
        chrono::Utc::now().timestamp_millis()
    }

    fn now_rfc3339() -> String {
        chrono::Utc::now().to_rfc3339()
    }

    fn encode_member(task: &DocketTask) -> String {
        let created_ms = chrono::DateTime::parse_from_rfc3339(&task.created_at)
            .map(|dt| dt.timestamp_millis())
            .unwrap_or_else(|_| chrono::Utc::now().timestamp_millis());
        let prio_key: i64 = (i32::MAX as i64) - (task.priority as i64);
        format!("{prio_key:010}:{created_ms:013}:{}", task.id.0)
    }

    fn retry_delay_ms(&self, retry_count: u32) -> i64 {
        let base = self
            .docket_settings
            .retry_delay
            .as_millis()
            .min(i64::MAX as u128) as i64;
        if base <= 0 {
            return 0;
        }
        let exp = retry_count.saturating_sub(1).min(30);
        let factor: i64 = 1i64.checked_shl(exp).unwrap_or(i64::MAX);
        base.saturating_mul(factor)
    }

    fn with_conn<T>(
        &self,
        f: impl FnOnce(&mut redis::Connection) -> redis::RedisResult<T>,
    ) -> DocketResult<T> {
        let idx = self
            .next_conn
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.pool.len();
        let mut guard = self.pool[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard).map_err(|e| DocketError::Backend(format!("Redis error: {e}")))
    }
}

#[cfg(feature = "redis")]
impl DocketBackend for RedisDocketBackend {
    fn enqueue(&self, _task: DocketTask) -> DocketResult<()> {
        let task = _task;
        let task_id = task.id.0.clone();
        let task_type = task.task_type.clone();
        let member = Self::encode_member(&task);
        let json = serde_json::to_string(&task)
            .map_err(|e| DocketError::Backend(format!("Task serialize failed: {e}")))?;

        let tasks_key = self.key_tasks();
        let types_key = self.key_types();
        let member_key = self.key_queue_member();
        let type_key = self.key_queue_type();
        let pending_key = self.key_pending(&task_type);

        self.with_conn(|conn| {
            redis::pipe()
                .atomic()
                .cmd("HSET")
                .arg(&tasks_key)
                .arg(&task_id)
                .arg(&json)
                .ignore()
                .cmd("SADD")
                .arg(&types_key)
                .arg(&task_type)
                .ignore()
                .cmd("HSET")
                .arg(&member_key)
                .arg(&task_id)
                .arg(&member)
                .ignore()
                .cmd("HSET")
                .arg(&type_key)
                .arg(&task_id)
                .arg(&task_type)
                .ignore()
                .cmd("ZADD")
                .arg(&pending_key)
                .arg(0)
                .arg(&member)
                .ignore()
                .query::<()>(conn)
        })?;

        Ok(())
    }

    fn dequeue(&self, _task_types: &[String]) -> DocketResult<Option<DocketTask>> {
        if _task_types.is_empty() {
            return Ok(None);
        }

        // Move any delayed tasks that are now due into the pending queues.
        let _ = self.requeue_stale();

        let mut pending_keys: Vec<String> =
            _task_types.iter().map(|t| self.key_pending(t)).collect();
        let tasks_key = self.key_tasks();
        let running_key = self.key_running();
        let member_key = self.key_queue_member();

        // KEYS: pending..., tasks_key, running_key, member_key
        pending_keys.push(tasks_key.clone());
        pending_keys.push(running_key.clone());
        pending_keys.push(member_key.clone());

        let now_rfc = Self::now_rfc3339();
        let now_ms = Self::now_ms();

        // Atomically pick the best pending task across the subscribed queues.
        const LUA: &str = r#"
local tasks_key = KEYS[#KEYS-2]
local running_key = KEYS[#KEYS-1]
local member_key = KEYS[#KEYS]

local now_rfc = ARGV[1]
local now_ms = tonumber(ARGV[2])

local best = nil
local best_key = nil
for i=1,(#KEYS-3) do
  local k = KEYS[i]
  local r = redis.call('ZRANGE', k, 0, 0)
  if r and r[1] then
    local m = r[1]
    if (not best) or (m < best) then
      best = m
      best_key = k
    end
  end
end

if not best then
  return nil
end

redis.call('ZREM', best_key, best)

-- Extract task_id from member "{prio}:{created}:{task_id}"
local _, _, task_id = string.find(best, "^[^:]+:[^:]+:(.+)$")
if not task_id then
  return nil
end

redis.call('HDEL', member_key, task_id)
redis.call('ZADD', running_key, now_ms, task_id)

local tjson = redis.call('HGET', tasks_key, task_id)
if not tjson then
  return nil
end

local t = cjson.decode(tjson)
t["status"] = "running"
t["claimed_at"] = now_rfc
local out = cjson.encode(t)
redis.call('HSET', tasks_key, task_id, out)
return out
"#;

        let task_json: Option<String> = self.with_conn(|conn| {
            let script = redis::Script::new(LUA);
            let mut inv = script.prepare_invoke();
            for k in &pending_keys {
                inv.key(k);
            }
            inv.arg(now_rfc).arg(now_ms).invoke(conn)
        })?;

        let Some(task_json) = task_json else {
            return Ok(None);
        };

        let task: DocketTask = serde_json::from_str(&task_json)
            .map_err(|e| DocketError::Backend(format!("Task deserialize failed: {e}")))?;
        Ok(Some(task))
    }

    fn ack(&self, _task_id: &TaskId, _result: serde_json::Value) -> DocketResult<()> {
        let task_id = _task_id.0.clone();
        let tasks_key = self.key_tasks();
        let running_key = self.key_running();
        let member_key = self.key_queue_member();
        let type_key = self.key_queue_type();

        let mut task = self
            .get_task(_task_id)?
            .ok_or_else(|| DocketError::NotFound(task_id.clone()))?;
        task.status = TaskStatus::Completed;
        task.result = Some(_result);

        let json = serde_json::to_string(&task)
            .map_err(|e| DocketError::Backend(format!("Task serialize failed: {e}")))?;

        self.with_conn(|conn| {
            redis::pipe()
                .atomic()
                .cmd("HSET")
                .arg(&tasks_key)
                .arg(&task_id)
                .arg(&json)
                .ignore()
                .cmd("ZREM")
                .arg(&running_key)
                .arg(&task_id)
                .ignore()
                .cmd("HDEL")
                .arg(&member_key)
                .arg(&task_id)
                .ignore()
                .cmd("HDEL")
                .arg(&type_key)
                .arg(&task_id)
                .ignore()
                .query::<()>(conn)
        })?;

        Ok(())
    }

    fn nack(&self, _task_id: &TaskId, _error: &str) -> DocketResult<()> {
        let task_id = _task_id.0.clone();
        let tasks_key = self.key_tasks();
        let running_key = self.key_running();
        let member_key = self.key_queue_member();
        let type_key = self.key_queue_type();

        let mut task = self
            .get_task(_task_id)?
            .ok_or_else(|| DocketError::NotFound(task_id.clone()))?;

        task.retry_count += 1;
        task.error = Some(_error.to_string());

        // Remove from running
        self.with_conn(|conn| {
            redis::cmd("ZREM")
                .arg(&running_key)
                .arg(&task_id)
                .query::<()>(conn)
        })?;

        if task.retry_count >= task.max_retries {
            task.status = TaskStatus::Failed;
            let json = serde_json::to_string(&task)
                .map_err(|e| DocketError::Backend(format!("Task serialize failed: {e}")))?;
            self.with_conn(|conn| {
                redis::pipe()
                    .atomic()
                    .cmd("HSET")
                    .arg(&tasks_key)
                    .arg(&task_id)
                    .arg(&json)
                    .ignore()
                    .cmd("HDEL")
                    .arg(&member_key)
                    .arg(&task_id)
                    .ignore()
                    .cmd("HDEL")
                    .arg(&type_key)
                    .arg(&task_id)
                    .ignore()
                    .query::<()>(conn)
            })?;
            return Ok(());
        }

        // Schedule retry with exponential backoff.
        task.status = TaskStatus::Pending;
        task.claimed_at = None;

        let member = Self::encode_member(&task);
        let task_type = task.task_type.clone();
        let delayed_key = self.key_delayed(&task_type);
        let available_ms = Self::now_ms().saturating_add(self.retry_delay_ms(task.retry_count));

        let json = serde_json::to_string(&task)
            .map_err(|e| DocketError::Backend(format!("Task serialize failed: {e}")))?;

        self.with_conn(|conn| {
            redis::pipe()
                .atomic()
                .cmd("HSET")
                .arg(&tasks_key)
                .arg(&task_id)
                .arg(&json)
                .ignore()
                .cmd("HSET")
                .arg(&member_key)
                .arg(&task_id)
                .arg(&member)
                .ignore()
                .cmd("HSET")
                .arg(&type_key)
                .arg(&task_id)
                .arg(&task_type)
                .ignore()
                .cmd("ZADD")
                .arg(&delayed_key)
                .arg(available_ms)
                .arg(&member)
                .ignore()
                .query::<()>(conn)
        })?;

        Ok(())
    }

    fn get_task(&self, _task_id: &TaskId) -> DocketResult<Option<DocketTask>> {
        let tasks_key = self.key_tasks();
        let task_id = _task_id.0.clone();
        let json: Option<String> =
            self.with_conn(|conn| redis::cmd("HGET").arg(&tasks_key).arg(&task_id).query(conn))?;
        let Some(json) = json else {
            return Ok(None);
        };
        let task: DocketTask = serde_json::from_str(&json)
            .map_err(|e| DocketError::Backend(format!("Task deserialize failed: {e}")))?;
        Ok(Some(task))
    }

    fn list_tasks(
        &self,
        _status: Option<TaskStatus>,
        _limit: usize,
    ) -> DocketResult<Vec<DocketTask>> {
        let tasks_key = self.key_tasks();
        let values: Vec<String> =
            self.with_conn(|conn| redis::cmd("HVALS").arg(&tasks_key).query(conn))?;

        let mut tasks = Vec::new();
        for json in values {
            if let Ok(task) = serde_json::from_str::<DocketTask>(&json) {
                if _status.is_none_or(|s| task.status == s) {
                    tasks.push(task);
                }
            }
        }

        tasks.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.0.cmp(&b.id.0))
        });
        tasks.truncate(_limit);
        Ok(tasks)
    }

    fn cancel(&self, _task_id: &TaskId, _reason: Option<&str>) -> DocketResult<()> {
        let task_id = _task_id.0.clone();
        let tasks_key = self.key_tasks();
        let running_key = self.key_running();
        let member_key = self.key_queue_member();
        let type_key = self.key_queue_type();

        let Some(mut task) = self.get_task(_task_id)? else {
            return Err(DocketError::NotFound(task_id));
        };

        task.status = TaskStatus::Cancelled;
        task.error = Some(_reason.unwrap_or("Cancelled").to_string());
        task.result = Some(serde_json::json!({"cancelled": true}));

        let json = serde_json::to_string(&task)
            .map_err(|e| DocketError::Backend(format!("Task serialize failed: {e}")))?;

        let member: Option<String> = self.with_conn(|conn| {
            redis::cmd("HGET")
                .arg(&member_key)
                .arg(&task_id)
                .query(conn)
        })?;
        let task_type: Option<String> =
            self.with_conn(|conn| redis::cmd("HGET").arg(&type_key).arg(&task_id).query(conn))?;

        self.with_conn(|conn| {
            redis::pipe()
                .atomic()
                .cmd("HSET")
                .arg(&tasks_key)
                .arg(&task_id)
                .arg(&json)
                .ignore()
                .cmd("ZREM")
                .arg(&running_key)
                .arg(&task_id)
                .ignore()
                .cmd("HDEL")
                .arg(&member_key)
                .arg(&task_id)
                .ignore()
                .cmd("HDEL")
                .arg(&type_key)
                .arg(&task_id)
                .ignore()
                .query::<()>(conn)
        })?;

        if let (Some(member), Some(task_type)) = (member, task_type) {
            let pending_key = self.key_pending(&task_type);
            let delayed_key = self.key_delayed(&task_type);
            let _ = self.with_conn(|conn| {
                redis::pipe()
                    .atomic()
                    .cmd("ZREM")
                    .arg(&pending_key)
                    .arg(&member)
                    .ignore()
                    .cmd("ZREM")
                    .arg(&delayed_key)
                    .arg(&member)
                    .ignore()
                    .query::<()>(conn)
            });
        }

        Ok(())
    }

    fn stats(&self) -> DocketResult<QueueStats> {
        let tasks = self.list_tasks(None, usize::MAX)?;
        let mut stats = QueueStats::default();
        for t in tasks {
            match t.status {
                TaskStatus::Pending => stats.pending += 1,
                TaskStatus::Running => stats.in_progress += 1,
                TaskStatus::Completed => stats.completed += 1,
                TaskStatus::Failed => stats.failed += 1,
                TaskStatus::Cancelled => stats.cancelled += 1,
            }
        }
        Ok(stats)
    }

    fn requeue_stale(&self) -> DocketResult<usize> {
        let now_ms = Self::now_ms();
        let visibility_ms: i64 = self
            .docket_settings
            .visibility_timeout
            .as_millis()
            .min(i64::MAX as u128) as i64;
        let cutoff = now_ms.saturating_sub(visibility_ms);

        let tasks_key = self.key_tasks();
        let running_key = self.key_running();
        let types_key = self.key_types();
        let member_key = self.key_queue_member();
        let type_key = self.key_queue_type();

        // 1) Promote due delayed tasks into pending queues.
        let types: Vec<String> =
            self.with_conn(|conn| redis::cmd("SMEMBERS").arg(&types_key).query(conn))?;
        for t in &types {
            let delayed_key = self.key_delayed(t);
            let pending_key = self.key_pending(t);
            let due_members: Vec<String> = self.with_conn(|conn| {
                redis::cmd("ZRANGEBYSCORE")
                    .arg(&delayed_key)
                    .arg("-inf")
                    .arg(now_ms)
                    .query(conn)
            })?;
            if due_members.is_empty() {
                continue;
            }
            self.with_conn(|conn| {
                let mut pipe = redis::pipe();
                pipe.atomic();
                for m in &due_members {
                    pipe.cmd("ZREM").arg(&delayed_key).arg(m).ignore();
                    pipe.cmd("ZADD").arg(&pending_key).arg(0).arg(m).ignore();
                }
                pipe.query::<()>(conn)
            })?;
        }

        // 2) Requeue running tasks past visibility timeout.
        let stale: Vec<String> = self.with_conn(|conn| {
            redis::cmd("ZRANGEBYSCORE")
                .arg(&running_key)
                .arg("-inf")
                .arg(cutoff)
                .query(conn)
        })?;

        let mut requeued = 0usize;
        for task_id in stale {
            // Claim the stale record: if another worker already handled it, skip.
            let removed: i64 = self.with_conn(|conn| {
                redis::cmd("ZREM")
                    .arg(&running_key)
                    .arg(&task_id)
                    .query(conn)
            })?;
            if removed == 0 {
                continue;
            }

            let id = TaskId::from_string(task_id.clone());
            let Some(mut task) = self.get_task(&id)? else {
                continue;
            };

            task.retry_count += 1;
            task.claimed_at = None;
            task.error = Some("Exceeded visibility timeout".to_string());

            if task.retry_count >= task.max_retries {
                task.status = TaskStatus::Failed;
                let json = serde_json::to_string(&task)
                    .map_err(|e| DocketError::Backend(format!("Task serialize failed: {e}")))?;
                self.with_conn(|conn| {
                    redis::pipe()
                        .atomic()
                        .cmd("HSET")
                        .arg(&tasks_key)
                        .arg(&task_id)
                        .arg(&json)
                        .ignore()
                        .cmd("HDEL")
                        .arg(&member_key)
                        .arg(&task_id)
                        .ignore()
                        .cmd("HDEL")
                        .arg(&type_key)
                        .arg(&task_id)
                        .ignore()
                        .query::<()>(conn)
                })?;
                continue;
            }

            task.status = TaskStatus::Pending;
            let member = Self::encode_member(&task);
            let task_type = task.task_type.clone();
            let delayed_key = self.key_delayed(&task_type);
            let available_ms = now_ms.saturating_add(self.retry_delay_ms(task.retry_count));

            let json = serde_json::to_string(&task)
                .map_err(|e| DocketError::Backend(format!("Task serialize failed: {e}")))?;
            self.with_conn(|conn| {
                redis::pipe()
                    .atomic()
                    .cmd("HSET")
                    .arg(&tasks_key)
                    .arg(&task_id)
                    .arg(&json)
                    .ignore()
                    .cmd("HSET")
                    .arg(&member_key)
                    .arg(&task_id)
                    .arg(&member)
                    .ignore()
                    .cmd("HSET")
                    .arg(&type_key)
                    .arg(&task_id)
                    .arg(&task_type)
                    .ignore()
                    .cmd("ZADD")
                    .arg(&delayed_key)
                    .arg(available_ms)
                    .arg(&member)
                    .ignore()
                    .query::<()>(conn)
            })?;
            requeued += 1;
        }

        Ok(requeued)
    }
}

// ============================================================================
// Docket Client
// ============================================================================

/// Docket distributed task queue.
///
/// The main entry point for submitting and managing distributed tasks.
pub struct Docket {
    backend: Arc<dyn DocketBackend>,
    settings: DocketSettings,
    task_counter: AtomicU64,
}

impl Docket {
    /// Creates a new Docket with the given settings.
    pub fn new(settings: DocketSettings) -> DocketResult<Self> {
        let backend: Arc<dyn DocketBackend> = match &settings.backend {
            DocketBackendType::Memory => Arc::new(MemoryDocketBackend::new(settings.clone())),
            #[cfg(feature = "redis")]
            DocketBackendType::Redis(redis_settings) => Arc::new(RedisDocketBackend::new(
                redis_settings.clone(),
                settings.clone(),
            )?),
            #[cfg(not(feature = "redis"))]
            DocketBackendType::Redis(_) => {
                return Err(DocketError::Backend(
                    "Redis backend requires 'redis' feature".to_string(),
                ));
            }
        };

        Ok(Self {
            backend,
            settings,
            task_counter: AtomicU64::new(0),
        })
    }

    /// Creates a Docket with memory backend (for testing).
    #[must_use]
    pub fn memory() -> Self {
        Self::new(DocketSettings::memory()).expect("memory backend always succeeds")
    }

    /// Submits a task to the queue.
    pub fn submit(
        &self,
        task_type: impl Into<String>,
        params: serde_json::Value,
    ) -> DocketResult<TaskId> {
        self.submit_with_options(task_type, params, SubmitOptions::default())
    }

    /// Submits a task with custom options.
    pub fn submit_with_options(
        &self,
        task_type: impl Into<String>,
        params: serde_json::Value,
        options: SubmitOptions,
    ) -> DocketResult<TaskId> {
        let counter = self.task_counter.fetch_add(1, Ordering::SeqCst);
        let task_id = TaskId::from_string(format!("docket-{counter:08x}"));

        let max_retries = options.max_retries.unwrap_or(self.settings.max_retries);
        let task = DocketTask::new(
            task_id.clone(),
            task_type.into(),
            params,
            options.priority,
            max_retries,
        );

        self.backend.enqueue(task)?;

        info!(
            target: targets::SERVER,
            "Docket: submitted task {} (type: {})",
            task_id,
            task_id
        );

        Ok(task_id)
    }

    /// Gets a task by ID.
    pub fn get_task(&self, task_id: &TaskId) -> DocketResult<Option<DocketTask>> {
        self.backend.get_task(task_id)
    }

    /// Lists tasks with optional status filter.
    pub fn list_tasks(
        &self,
        status: Option<TaskStatus>,
        limit: usize,
    ) -> DocketResult<Vec<DocketTask>> {
        self.backend.list_tasks(status, limit)
    }

    /// Cancels a task.
    pub fn cancel(&self, task_id: &TaskId, reason: Option<&str>) -> DocketResult<()> {
        self.backend.cancel(task_id, reason)
    }

    /// Returns queue statistics.
    pub fn stats(&self) -> DocketResult<QueueStats> {
        self.backend.stats()
    }

    /// Creates a worker builder.
    #[must_use]
    pub fn worker(&self) -> WorkerBuilder {
        WorkerBuilder::new(Arc::clone(&self.backend), self.settings.clone())
    }

    /// Returns the settings.
    #[must_use]
    pub fn settings(&self) -> &DocketSettings {
        &self.settings
    }

    /// Converts to a shared handle.
    #[must_use]
    pub fn into_shared(self) -> SharedDocket {
        Arc::new(self)
    }
}

impl std::fmt::Debug for Docket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Docket")
            .field("settings", &self.settings)
            .field("task_counter", &self.task_counter.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

/// Thread-safe handle to a Docket.
pub type SharedDocket = Arc<Docket>;

// ============================================================================
// Worker
// ============================================================================

/// Task handler function type.
pub type TaskHandlerFn = Box<
    dyn Fn(DocketTask) -> Pin<Box<dyn Future<Output = DocketResult<serde_json::Value>> + Send>>
        + Send
        + Sync,
>;

/// Builder for creating workers.
pub struct WorkerBuilder {
    backend: Arc<dyn DocketBackend>,
    settings: DocketSettings,
    handlers: HashMap<String, TaskHandlerFn>,
}

impl WorkerBuilder {
    fn new(backend: Arc<dyn DocketBackend>, settings: DocketSettings) -> Self {
        Self {
            backend,
            settings,
            handlers: HashMap::new(),
        }
    }

    /// Subscribes to a task type with a handler.
    pub fn subscribe<F, Fut>(mut self, task_type: impl Into<String>, handler: F) -> Self
    where
        F: Fn(DocketTask) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = DocketResult<serde_json::Value>> + Send + 'static,
    {
        let task_type = task_type.into();
        let boxed: TaskHandlerFn = Box::new(move |task| Box::pin(handler(task)));
        self.handlers.insert(task_type, boxed);
        self
    }

    /// Builds the worker.
    #[must_use]
    pub fn build(self) -> Worker {
        Worker {
            backend: self.backend,
            settings: self.settings,
            handlers: Arc::new(self.handlers),
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// A worker that processes tasks from the queue.
pub struct Worker {
    backend: Arc<dyn DocketBackend>,
    settings: DocketSettings,
    handlers: Arc<HashMap<String, TaskHandlerFn>>,
    running: Arc<AtomicBool>,
}

impl Worker {
    /// Returns the task types this worker is subscribed to.
    #[must_use]
    pub fn subscribed_types(&self) -> Vec<String> {
        self.handlers.keys().cloned().collect()
    }

    /// Returns whether the worker is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stops the worker.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Processes a single task if available.
    ///
    /// Returns true if a task was processed, false if no task was available.
    pub async fn process_one(&self, cx: &Cx) -> DocketResult<bool> {
        let task_types = self.subscribed_types();

        // Check for cancellation
        if cx.is_cancel_requested() {
            return Err(DocketError::Cancelled);
        }

        // Try to dequeue a task
        let Some(task) = self.backend.dequeue(&task_types)? else {
            return Ok(false);
        };

        let task_id = task.id.clone();
        let task_type = task.task_type.clone();

        debug!(
            target: targets::SERVER,
            "Docket worker: processing task {} (type: {})",
            task_id,
            task_type
        );

        // Get handler
        let Some(handler) = self.handlers.get(&task_type) else {
            // This shouldn't happen since we only dequeue subscribed types
            self.backend.nack(&task_id, "No handler for task type")?;
            return Ok(true);
        };

        // Execute handler
        let result = handler(task).await;

        match result {
            Ok(data) => {
                self.backend.ack(&task_id, data)?;
                info!(
                    target: targets::SERVER,
                    "Docket worker: completed task {}",
                    task_id
                );
            }
            Err(e) => {
                let error_msg = e.to_string();
                self.backend.nack(&task_id, &error_msg)?;
                warn!(
                    target: targets::SERVER,
                    "Docket worker: task {} failed: {}",
                    task_id,
                    error_msg
                );
            }
        }

        Ok(true)
    }

    /// Runs the worker loop until stopped.
    pub async fn run(&self, cx: &Cx) -> DocketResult<()> {
        self.running.store(true, Ordering::SeqCst);

        info!(
            target: targets::SERVER,
            "Docket worker starting with subscriptions: {:?}",
            self.subscribed_types()
        );

        while self.running.load(Ordering::SeqCst) {
            // Check for cancellation
            if cx.is_cancel_requested() {
                break;
            }

            // Requeue stale tasks periodically
            let _ = self.backend.requeue_stale();

            // Process tasks
            match self.process_one(cx).await {
                Ok(true) => {
                    // Processed a task, immediately try for another
                    continue;
                }
                Ok(false) => {
                    // No task available, wait before polling again
                    std::thread::sleep(self.settings.poll_interval);
                }
                Err(DocketError::Cancelled) => {
                    break;
                }
                Err(e) => {
                    warn!(
                        target: targets::SERVER,
                        "Docket worker error: {}",
                        e
                    );
                    // Brief pause on error before retrying
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
        info!(target: targets::SERVER, "Docket worker stopped");

        Ok(())
    }
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker")
            .field("subscribed_types", &self.subscribed_types())
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docket_settings_default() {
        let settings = DocketSettings::default();
        assert!(matches!(settings.backend, DocketBackendType::Memory));
        assert_eq!(settings.max_retries, 3);
    }

    #[test]
    fn test_docket_settings_redis() {
        let settings = DocketSettings::redis("redis://localhost:6379");
        assert!(matches!(settings.backend, DocketBackendType::Redis(_)));
    }

    #[test]
    fn test_docket_settings_builder() {
        let settings = DocketSettings::memory()
            .with_queue_prefix("test:queue")
            .with_max_retries(5)
            .with_poll_interval(Duration::from_millis(50));

        assert_eq!(settings.queue_prefix, "test:queue");
        assert_eq!(settings.max_retries, 5);
        assert_eq!(settings.poll_interval, Duration::from_millis(50));
    }

    #[test]
    fn test_docket_memory_creation() {
        let docket = Docket::memory();
        assert!(matches!(docket.settings.backend, DocketBackendType::Memory));
    }

    #[test]
    fn test_docket_submit_task() {
        let docket = Docket::memory();

        let task_id = docket
            .submit("test_task", serde_json::json!({"key": "value"}))
            .unwrap();

        assert!(task_id.to_string().starts_with("docket-"));

        // Verify task exists
        let task = docket.get_task(&task_id).unwrap().unwrap();
        assert_eq!(task.task_type, "test_task");
        assert_eq!(task.status, TaskStatus::Pending);
    }

    #[test]
    fn test_docket_submit_with_priority() {
        let docket = Docket::memory();

        let low_id = docket
            .submit_with_options(
                "task",
                serde_json::json!({"priority": "low"}),
                SubmitOptions::new().with_priority(1),
            )
            .unwrap();

        let high_id = docket
            .submit_with_options(
                "task",
                serde_json::json!({"priority": "high"}),
                SubmitOptions::new().with_priority(10),
            )
            .unwrap();

        // High priority should be dequeued first
        let worker = docket
            .worker()
            .subscribe("task", |t| async move { Ok(t.params) })
            .build();

        let types = worker.subscribed_types();
        let dequeued = docket.backend.dequeue(&types).unwrap().unwrap();
        assert_eq!(dequeued.id, high_id);

        // Ack it
        docket.backend.ack(&high_id, serde_json::json!({})).unwrap();

        // Now low priority should be available
        let dequeued = docket.backend.dequeue(&types).unwrap().unwrap();
        assert_eq!(dequeued.id, low_id);
    }

    #[test]
    fn test_docket_cancel_task() {
        let docket = Docket::memory();

        let task_id = docket.submit("task", serde_json::json!({})).unwrap();

        docket.cancel(&task_id, Some("User cancelled")).unwrap();

        let task = docket.get_task(&task_id).unwrap().unwrap();
        assert_eq!(task.status, TaskStatus::Cancelled);
        assert_eq!(task.error, Some("User cancelled".to_string()));
    }

    #[test]
    fn test_docket_stats() {
        let docket = Docket::memory();

        docket.submit("task1", serde_json::json!({})).unwrap();
        docket.submit("task2", serde_json::json!({})).unwrap();
        let task3 = docket.submit("task3", serde_json::json!({})).unwrap();
        docket.cancel(&task3, None).unwrap();

        let stats = docket.stats().unwrap();
        assert_eq!(stats.pending, 2);
        assert_eq!(stats.cancelled, 1);
    }

    #[test]
    fn test_docket_list_tasks() {
        let docket = Docket::memory();

        docket.submit("type_a", serde_json::json!({})).unwrap();
        docket.submit("type_b", serde_json::json!({})).unwrap();
        let cancelled_id = docket.submit("type_a", serde_json::json!({})).unwrap();
        docket.cancel(&cancelled_id, None).unwrap();

        // All tasks
        let all = docket.list_tasks(None, 100).unwrap();
        assert_eq!(all.len(), 3);

        // Pending only
        let pending = docket.list_tasks(Some(TaskStatus::Pending), 100).unwrap();
        assert_eq!(pending.len(), 2);

        // Cancelled only
        let cancelled = docket.list_tasks(Some(TaskStatus::Cancelled), 100).unwrap();
        assert_eq!(cancelled.len(), 1);
    }

    #[test]
    fn test_worker_builder() {
        let docket = Docket::memory();

        let worker = docket
            .worker()
            .subscribe("type_a", |_| async { Ok(serde_json::json!({})) })
            .subscribe("type_b", |_| async { Ok(serde_json::json!({})) })
            .build();

        let types = worker.subscribed_types();
        assert!(types.contains(&"type_a".to_string()));
        assert!(types.contains(&"type_b".to_string()));
    }

    #[test]
    fn test_memory_backend_retry() {
        let settings = DocketSettings::memory().with_max_retries(2);
        let backend = MemoryDocketBackend::new(settings);

        let task = DocketTask::new(
            TaskId::from_string("test-1"),
            "retry_test".to_string(),
            serde_json::json!({}),
            0,
            2,
        );

        backend.enqueue(task).unwrap();

        // Dequeue and nack (first failure)
        let task = backend
            .dequeue(&["retry_test".to_string()])
            .unwrap()
            .unwrap();
        backend.nack(&task.id, "error 1").unwrap();

        // Should be requeued
        let task = backend
            .dequeue(&["retry_test".to_string()])
            .unwrap()
            .unwrap();
        assert_eq!(task.retry_count, 1);
        backend.nack(&task.id, "error 2").unwrap();

        // Max retries exceeded - should be failed, not requeued
        let task = backend.dequeue(&["retry_test".to_string()]).unwrap();
        assert!(task.is_none());

        // Verify it's marked as failed
        let task = backend
            .get_task(&TaskId::from_string("test-1"))
            .unwrap()
            .unwrap();
        assert_eq!(task.status, TaskStatus::Failed);
    }

    #[test]
    fn test_docket_task_to_info() {
        let task = DocketTask::new(
            TaskId::from_string("test-info"),
            "test_type".to_string(),
            serde_json::json!({"data": 42}),
            5,
            3,
        );

        let info = task.to_task_info();
        assert_eq!(info.id.to_string(), "test-info");
        assert_eq!(info.task_type, "test_type");
        assert_eq!(info.status, TaskStatus::Pending);
        assert!(info.started_at.is_none());
    }

    #[test]
    fn test_worker_process_one() {
        use fastmcp_core::block_on;

        let docket = Docket::memory();

        // Submit a task
        let task_id = docket
            .submit("process_test", serde_json::json!({"x": 1}))
            .unwrap();

        // Create worker
        let worker = docket
            .worker()
            .subscribe("process_test", |task| async move {
                let x = task.params.get("x").and_then(|v| v.as_i64()).unwrap_or(0);
                Ok(serde_json::json!({"result": x * 2}))
            })
            .build();

        // Process
        let cx = Cx::for_testing();
        let processed = block_on(worker.process_one(&cx)).unwrap();
        assert!(processed);

        // Verify completion
        let task = docket.get_task(&task_id).unwrap().unwrap();
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.result, Some(serde_json::json!({"result": 2})));
    }

    #[test]
    fn test_worker_no_task_available() {
        use fastmcp_core::block_on;

        let docket = Docket::memory();

        let worker = docket
            .worker()
            .subscribe("empty_test", |_| async { Ok(serde_json::json!({})) })
            .build();

        let cx = Cx::for_testing();
        let processed = block_on(worker.process_one(&cx)).unwrap();
        assert!(!processed);
    }

    #[test]
    fn test_submit_options() {
        let opts = SubmitOptions::new()
            .with_priority(10)
            .with_max_retries(5)
            .with_delay(Duration::from_secs(60));

        assert_eq!(opts.priority, 10);
        assert_eq!(opts.max_retries, Some(5));
        assert_eq!(opts.delay, Some(Duration::from_secs(60)));
    }

    #[test]
    fn test_docket_error_display() {
        let errors = vec![
            (
                DocketError::NotFound("task-1".into()),
                "Task not found: task-1",
            ),
            (
                DocketError::Connection("refused".into()),
                "Connection error: refused",
            ),
            (DocketError::Handler("panic".into()), "Handler error: panic"),
            (DocketError::Cancelled, "Operation cancelled"),
        ];

        for (error, expected) in errors {
            assert_eq!(error.to_string(), expected);
        }
    }
}
