//! MCP client implementation for FastMCP.
//!
//! This crate provides the client-side implementation:
//! - Client builder pattern
//! - Tool invocation
//! - Resource reading
//! - Prompt fetching
//!
//! MCP 2026-07-28 support is under implementation and remains unverified. The
//! client still initializes with public protocol version `2024-11-05`; this
//! source inventory is not aggregate conformance or release evidence.
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_rust::Client;
//!
//! let mut client = Client::stdio("uvx", &["my-mcp-server"])?;
//!
//! // List tools
//! let tools = client.list_tools()?;
//!
//! // Call a no-argument tool
//! let result = client.call_tool("status", Default::default())?;
//! ```
//!
//! # Role in the System
//!
//! `fastmcp-client` is the **companion client** to `fastmcp-server`. It uses
//! the same protocol models and transport layer to:
//! - Spawn MCP servers as subprocesses (stdio)
//! - Initialize sessions and negotiate capabilities
//! - Call tools, read resources, and fetch prompts
//!
//! If you are embedding FastMCP into a larger application (e.g. testing,
//! orchestration, or local agent tooling), this is the crate that drives the
//! client side of the protocol.

#![forbid(unsafe_code)]
#![allow(dead_code)]

mod builder;
mod execution;
pub mod mcp_config;
mod negotiation;
mod session;

pub use builder::ClientBuilder;
pub use execution::{
    CancellationRequested, ExecutionTerminalReason, ExecutionTerminalRecord,
    ExecutionTerminalState, OpaquePagination, PaginationBounds, PendingRequestRecord, Request,
    RequestExecution, RequestExecutor, clt_01_a_manifest_digest, clt_01_b_manifest_digest,
};
pub use fastmcp_core::CanonicalHttpUrl;
pub use fastmcp_protocol::protocol_policy::{
    HttpEndpointBundle, HttpEndpointBundleError, HttpModernProbe, HttpProbeBody, ProtocolEra,
    ProtocolPolicy, ProtocolVersion,
};
pub use mcp_config::claude_desktop_config_path;
pub use negotiation::{
    ClientHttpNegotiation, ClientHttpNegotiationDecision, ClientHttpNegotiationError,
    ClientHttpNegotiationState,
};
pub use session::{ClientProtocolPlan, ClientProtocolPlanError, ClientSession};

use std::any::Any;
use std::cell::Cell;
#[cfg(target_os = "linux")]
use std::io::Read as _;
use std::io::Write as _;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::Once;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use asupersync::{Cx, channel::oneshot};
use fastmcp_core::{McpError, McpErrorCode, McpResult, Sha256Digest, block_on, sha256_bounded};
use fastmcp_protocol::protocol_policy::MODERN_PROTOCOL_VERSION;
use fastmcp_protocol::{
    CallToolParams, CallToolResult, CancelTaskParams, CancelTaskResult, CancelledParams,
    ClientCapabilities, ClientInfo, Content, CorrelationKey, FinalRequestMeta, GetPromptParams,
    GetPromptResult, GetTaskParams, GetTaskResult, InitializeParams, InitializeResult,
    JSONRPC_VERSION, JsonRpcError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse,
    ListPromptsParams, ListPromptsResult, ListResourceTemplatesParams, ListResourceTemplatesResult,
    ListResourcesParams, ListResourcesResult, ListTasksParams, ListTasksResult, ListToolsParams,
    ListToolsResult, LogLevel, LogMessageParams, PROTOCOL_VERSION, ProgressMarker, Prompt,
    PromptMessage, ReadResourceParams, ReadResourceResult, RequestId, RequestMeta, Resource,
    ResourceContent, ResourceTemplate, ServerCapabilities, ServerInfo, SetLogLevelParams,
    SubmitTaskParams, SubmitTaskResult, TaskId, TaskInfo, TaskResult, TaskStatus, Tool,
};
use fastmcp_protocol::{SERVER_DISCOVER_METHOD, ServerDiscoverRequest, ServerDiscoverResult};

/// Callback for receiving progress notifications during tool execution.
///
/// The callback receives the progress value, optional total, and optional message.
pub type ProgressCallback<'a> = &'a mut dyn FnMut(f64, Option<f64>, Option<&str>);
use fastmcp_transport::{StdioTransport, Transport, TransportError};

const MIN_TASK_POLL_INTERVAL: Duration = Duration::from_millis(1);
const MAX_LOCAL_TASK_POLL_INTERVAL: Duration = Duration::from_mins(5);
const DEFAULT_CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CLIENT_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CLIENT_IDLE_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_CLIENT_ABSOLUTE_TIMEOUT: Duration = Duration::from_mins(15);
const MAX_TASK_POLL_CANCEL_SLICE: Duration = Duration::from_millis(10);
const DIRECT_CHILD_REAP_TIMEOUT: Duration = Duration::from_secs(2);
const DIRECT_CHILD_REAP_POLL_INTERVAL: Duration = Duration::from_millis(10);
const OWNED_PROCESS_GROUP_QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const OWNED_PROCESS_GROUP_INSPECTION_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(target_os = "linux")]
const LINUX_PROC_MOUNTS_MAX_BYTES: u64 = 256 * 1024;
#[cfg(target_os = "linux")]
const LINUX_PROC_STAT_MAX_BYTES: u64 = 64 * 1024;
#[cfg(target_os = "linux")]
const LINUX_PROC_STATUS_MAX_BYTES: u64 = 256 * 1024;
const PROCESS_GROUP_ANCHOR_READY_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_UNVERIFIED_DATA_KEY: &str = "fastmcpCleanupUnverified";
const CLEANUP_DURATION_MS_DATA_KEY: &str = "cleanupDurationMs";

/// Idle and absolute limits for the response-wait phase of one ordinary client
/// request.
///
/// Both timers start after the request send commits; they do not bound a
/// blocking send or later connection teardown. Both limits are nonzero and
/// bounded. The idle timer may be restarted by a valid, strictly increasing
/// progress notification carrying the request's exact progress token when
/// [`Self::reset_idle_on_matching_progress`] is enabled. The absolute timer
/// never moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestTimeoutPolicy {
    idle_timeout: Duration,
    absolute_timeout: Duration,
    reset_idle_on_matching_progress: bool,
}

impl RequestTimeoutPolicy {
    /// Creates and validates an ordinary-request timeout policy.
    ///
    /// # Errors
    ///
    /// Returns an invalid-parameters error when idle is below 1 millisecond or
    /// exceeds 5 minutes, or absolute is below 1 millisecond or exceeds
    /// 15 minutes.
    pub fn new(idle_timeout: Duration, absolute_timeout: Duration) -> McpResult<Self> {
        let policy = Self {
            idle_timeout,
            absolute_timeout,
            reset_idle_on_matching_progress: true,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Selects whether exact, valid, strictly increasing matching progress
    /// restarts the idle timer. This never changes the absolute timer.
    #[must_use]
    pub const fn reset_idle_on_matching_progress(mut self, enabled: bool) -> Self {
        self.reset_idle_on_matching_progress = enabled;
        self
    }

    /// Returns the idle timeout.
    #[must_use]
    pub const fn idle_timeout(self) -> Duration {
        self.idle_timeout
    }

    /// Returns the non-resettable absolute timeout.
    #[must_use]
    pub const fn absolute_timeout(self) -> Duration {
        self.absolute_timeout
    }

    /// Returns whether valid matching progress restarts the idle timer.
    #[must_use]
    pub const fn resets_idle_on_matching_progress(self) -> bool {
        self.reset_idle_on_matching_progress
    }

    fn validate(self) -> McpResult<()> {
        validate_timeout_duration(
            self.idle_timeout,
            MAX_CLIENT_IDLE_TIMEOUT,
            "Client request idle timeout must be between 1 millisecond and 5 minutes",
        )?;
        validate_timeout_duration(
            self.absolute_timeout,
            MAX_CLIENT_ABSOLUTE_TIMEOUT,
            "Client request absolute timeout must be between 1 millisecond and 15 minutes",
        )
    }
}

impl Default for RequestTimeoutPolicy {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_CLIENT_IDLE_TIMEOUT,
            absolute_timeout: DEFAULT_CLIENT_ABSOLUTE_TIMEOUT,
            reset_idle_on_matching_progress: true,
        }
    }
}

/// The request-local timer that selected a timeout outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestTimeoutSource {
    /// No valid request-owned activity arrived before the idle bound.
    Idle,
    /// The non-resettable post-commit response-wait lifetime elapsed.
    Absolute,
}

fn request_timeout_error(source: RequestTimeoutSource) -> McpError {
    let (message, source_name) = match source {
        RequestTimeoutSource::Idle => ("Request timed out at the idle deadline", "idle"),
        RequestTimeoutSource::Absolute => {
            ("Request timed out at the absolute deadline", "absolute")
        }
    };
    McpError::with_data(
        McpErrorCode::InternalError,
        message,
        serde_json::json!({"timeoutSource": source_name}),
    )
}

#[derive(Clone, Copy, Debug)]
struct RequestDeadlines {
    idle: Instant,
    absolute: Instant,
    idle_timeout: Duration,
}

impl RequestDeadlines {
    fn start_at(policy: RequestTimeoutPolicy, committed_at: Instant) -> McpResult<Self> {
        policy.validate()?;
        let idle_timeout = policy.idle_timeout;
        let idle = committed_at.checked_add(idle_timeout).ok_or_else(|| {
            McpError::internal_error("Request idle timeout exceeds the clock range")
        })?;
        let absolute = committed_at
            .checked_add(policy.absolute_timeout)
            .ok_or_else(|| {
                McpError::internal_error("Request absolute timeout exceeds the clock range")
            })?;
        Ok(Self {
            idle,
            absolute,
            idle_timeout,
        })
    }

    fn next(self) -> Instant {
        self.idle.min(self.absolute)
    }

    fn next_kind(self) -> RequestTimeoutSource {
        if self.absolute <= self.idle {
            RequestTimeoutSource::Absolute
        } else {
            RequestTimeoutSource::Idle
        }
    }

    fn expired_at(self, observed_at: Instant) -> Option<RequestTimeoutSource> {
        if observed_at >= self.absolute && self.absolute <= self.idle {
            Some(RequestTimeoutSource::Absolute)
        } else if observed_at >= self.idle {
            Some(RequestTimeoutSource::Idle)
        } else if observed_at >= self.absolute {
            Some(RequestTimeoutSource::Absolute)
        } else {
            None
        }
    }

    fn reset_idle_at(&mut self, observed_at: Instant) -> McpResult<()> {
        self.idle = observed_at.checked_add(self.idle_timeout).ok_or_else(|| {
            McpError::internal_error("Request idle timeout exceeds the clock range")
        })?;
        Ok(())
    }
}

/// Validates the caller-configured local fallback interval.
///
/// This ceiling must not be applied to a future valid server-provided
/// `pollIntervalMs`: the MCP 2026-07-28 plan requires that value to remain a
/// minimum delay. The current public task model does not yet carry that field.
fn validate_task_poll_interval(interval: Duration) -> McpResult<Duration> {
    if !(MIN_TASK_POLL_INTERVAL..=MAX_LOCAL_TASK_POLL_INTERVAL).contains(&interval) {
        return Err(McpError::invalid_params(
            "Local task poll interval must be between 1 millisecond and 5 minutes",
        ));
    }
    Ok(interval)
}

fn validate_task_info(task: &TaskInfo) -> McpResult<()> {
    if let Some(progress) = task.progress
        && (!progress.is_finite() || !(0.0..=1.0).contains(&progress))
    {
        return Err(McpError::invalid_request(
            "Task progress must be finite and between 0.0 and 1.0",
        ));
    }
    if task.status == TaskStatus::Pending && task.started_at.is_some() {
        return Err(McpError::invalid_request(
            "A pending task cannot have a start timestamp",
        ));
    }
    if task.status.is_active() && task.completed_at.is_some() {
        return Err(McpError::invalid_request(
            "A non-terminal task cannot have a completion timestamp",
        ));
    }
    // The current task implementation stores a cancellation reason in
    // `error`, so Cancelled joins Failed as an admitted error-bearing state.
    if matches!(
        task.status,
        TaskStatus::Pending | TaskStatus::Running | TaskStatus::Completed
    ) && task.error.is_some()
    {
        return Err(McpError::invalid_request(
            "Task error details contradict the task status",
        ));
    }
    Ok(())
}

fn validate_task_result(task: &TaskInfo, result: &TaskResult) -> McpResult<()> {
    if result.id != task.id {
        return Err(McpError::invalid_request(
            "Task result ID does not match its task",
        ));
    }
    if !task.status.is_terminal() {
        return Err(McpError::invalid_request(
            "A task result was returned for a non-terminal task",
        ));
    }
    let expected_success = task.status == TaskStatus::Completed;
    if result.success != expected_success {
        return Err(McpError::invalid_request(
            "Task result success contradicts the task status",
        ));
    }
    if result.success && result.error.is_some() {
        return Err(McpError::invalid_request(
            "A successful task result cannot contain an error",
        ));
    }
    if !result.success && result.data.is_some() {
        return Err(McpError::invalid_request(
            "An unsuccessful task result cannot contain success data",
        ));
    }
    Ok(())
}

fn validate_get_task_result(requested_id: &TaskId, result: &GetTaskResult) -> McpResult<()> {
    if &result.task.id != requested_id {
        return Err(McpError::invalid_request(
            "tasks/get response task ID does not match the requested task",
        ));
    }
    validate_task_info(&result.task)?;

    let Some(task_result) = result.result.as_ref() else {
        if result.task.status == TaskStatus::Completed {
            return Err(McpError::invalid_request(
                "tasks/get omitted the result of a completed task",
            ));
        }
        return Ok(());
    };
    validate_task_result(&result.task, task_result)
}

fn validate_cancel_task_result(requested_id: &TaskId, result: &CancelTaskResult) -> McpResult<()> {
    if &result.task.id != requested_id {
        return Err(McpError::invalid_request(
            "tasks/cancel response task ID does not match the requested task",
        ));
    }
    validate_task_info(&result.task)?;
    // Cancellation acknowledgement is eventual, not proof of terminal state.
    // Work may remain active or race to another terminal outcome after the
    // peer accepts the cancellation request.
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectChildStopDecision {
    /// The direct child is still known to be live and may be terminated safely.
    TerminateAndReap,
    /// The child is already reaped, or its identity can no longer be proven.
    DoNotSignal,
}

/// Defines the subprocess resource that a client is responsible for stopping.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ChildOwnership {
    /// Only the exact child handle is owned.
    #[default]
    DirectChild,
    /// The peer is a member of a dedicated Unix process group whose separate
    /// live anchor pins the PGID and owns an owner-death control pipe.
    OwnedProcessGroup,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ClientChildCleanupPhase {
    #[default]
    Active,
    #[cfg(unix)]
    GroupKillAccepted(rustix::process::Pid),
    #[cfg(unix)]
    GroupChildrenReaped(rustix::process::Pid),
    #[cfg(unix)]
    GroupIdentityLost(rustix::process::Pid),
    Complete,
}

#[cfg(unix)]
const PROCESS_GROUP_ANCHOR_SCRIPT: &str = r"
trap '' HUP INT TERM
printf R
exec 1>&-
while IFS= read -r _; do :; done
kill -s KILL 0
exit 127
";

/// A live process-group leader controlled by a close-on-exec pipe.
///
/// The requested MCP peer is spawned directly as this anchor's sibling, so
/// the peer retains the exact executable, argv, environment, working
/// directory, and stdio behavior requested by the caller. Only this owner
/// process retains `control`; EOF therefore tells the anchor that the owner
/// closed normally or died, at which point the anchor kills its own group.
pub(crate) struct ProcessGroupAnchor {
    #[cfg(unix)]
    child: Option<Child>,
    #[cfg(unix)]
    control: Option<OwnedFd>,
    #[cfg(unix)]
    process_group: rustix::process::Pid,
}

impl ProcessGroupAnchor {
    #[cfg(unix)]
    pub(crate) fn spawn() -> McpResult<Self> {
        if !Path::new("/bin/sh").is_file() {
            return Err(McpError::internal_error(
                "Owned subprocess groups require /bin/sh on this Unix platform",
            ));
        }

        // Standard-library Unix sockets are marked close-on-exec and remain
        // available on Apple targets, where rustix intentionally omits its
        // atomic `pipe_with` API. Apple applies CLOEXEC after `socketpair`, so
        // a concurrent host-side raw fork during this short setup window can
        // retain a copy; the public ownership contract documents that limit.
        // Each pair is used only as a one-way channel.
        let (control_reader, control_writer) = UnixStream::pair().map_err(|error| {
            McpError::internal_error(format!(
                "Failed to create the process-group anchor control channel: {error}"
            ))
        })?;
        let (ready_reader, ready_writer) = UnixStream::pair().map_err(|error| {
            McpError::internal_error(format!(
                "Failed to create the process-group anchor readiness channel: {error}"
            ))
        })?;
        let control_reader = OwnedFd::from(control_reader);
        let control_writer = OwnedFd::from(control_writer);
        let ready_reader = OwnedFd::from(ready_reader);
        let ready_writer = OwnedFd::from(ready_writer);
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(PROCESS_GROUP_ANCHOR_SCRIPT)
            .arg("fastmcp-process-group-anchor")
            .stdin(Stdio::from(control_reader))
            .stdout(Stdio::from(ready_writer))
            .stderr(Stdio::null())
            .env_clear()
            .process_group(0);
        let child = command.spawn().map_err(|error| {
            McpError::internal_error(format!("Failed to spawn the process-group anchor: {error}"))
        })?;
        let raw_group_id = i32::try_from(child.id()).map_err(|_| {
            McpError::internal_error("Owned process-group identifier exceeds the platform range")
        })?;
        let process_group = rustix::process::Pid::from_raw(raw_group_id)
            .ok_or_else(|| McpError::internal_error("Owned process-group identifier is invalid"))?;

        let mut anchor = Self {
            child: Some(child),
            control: Some(control_writer),
            process_group,
        };
        match Self::wait_until_ready(&ready_reader) {
            Ok(()) => Ok(anchor),
            Err(error) => combine_operation_with_cleanup(Err(error), || anchor.cleanup()),
        }
    }

    #[cfg(unix)]
    fn wait_until_ready(ready_reader: &OwnedFd) -> McpResult<()> {
        let deadline = Instant::now() + PROCESS_GROUP_ANCHOR_READY_TIMEOUT;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(McpError::internal_error(
                    "Process-group anchor did not become ready within the startup deadline",
                ));
            }
            let timeout =
                rustix::event::Timespec::try_from(deadline.saturating_duration_since(now))
                    .map_err(|_| {
                        McpError::internal_error("Anchor readiness deadline is out of range")
                    })?;
            let mut poll_fds = [rustix::event::PollFd::new(
                ready_reader,
                rustix::event::PollFlags::IN,
            )];
            match rustix::event::poll(&mut poll_fds, Some(&timeout)) {
                Ok(0) => {
                    return Err(McpError::internal_error(
                        "Process-group anchor did not become ready within the startup deadline",
                    ));
                }
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => {
                    return Err(McpError::internal_error(format!(
                        "Failed while waiting for process-group anchor readiness: {error}"
                    )));
                }
            }

            let mut marker = [0_u8; 1];
            match rustix::io::read(ready_reader, &mut marker) {
                Ok(1) if marker[0] == b'R' => return Ok(()),
                Ok(0) => {
                    return Err(McpError::internal_error(
                        "Process-group anchor exited before reporting readiness",
                    ));
                }
                Ok(_) => {
                    return Err(McpError::internal_error(
                        "Process-group anchor emitted an invalid readiness marker",
                    ));
                }
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => {
                    return Err(McpError::internal_error(format!(
                        "Failed to read process-group anchor readiness: {error}"
                    )));
                }
            }
        }
    }

    #[cfg(unix)]
    pub(crate) fn raw_process_group(&self) -> i32 {
        self.process_group.as_raw_nonzero().get()
    }

    #[cfg(unix)]
    fn verify_live(&mut self) -> McpResult<()> {
        let Some(child) = self.child.as_mut() else {
            return Err(McpError::internal_error(
                "Process-group anchor handle is missing",
            ));
        };
        match child.try_wait() {
            Ok(None) => Ok(()),
            Ok(Some(status)) => {
                self.child = None;
                Err(McpError::internal_error(format!(
                    "Process-group anchor exited unexpectedly with {status}"
                )))
            }
            Err(error) => Err(McpError::internal_error(format!(
                "Failed to verify process-group anchor liveness: {error}"
            ))),
        }
    }

    #[cfg(not(unix))]
    fn verify_live(&mut self) -> McpResult<()> {
        Err(McpError::internal_error(
            "Owned subprocess groups are unavailable on this platform",
        ))
    }

    #[cfg(unix)]
    fn request_shutdown(&mut self) {
        // Closing the only post-exec writer produces EOF in the anchor and
        // arms the owner-death fallback. Explicit cleanup first signals while
        // the live anchor pins the PGID, so a stopped peer cannot also stop
        // the only process capable of observing this EOF.
        self.control.take();
    }

    #[cfg(unix)]
    fn reap(&mut self) -> McpResult<()> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        reap_signalled_child(child)?;
        self.child = None;
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn cleanup(&mut self) -> McpResult<()> {
        match request_anchored_group_shutdown(self)? {
            AnchoredGroupShutdown::KillAccepted(process_group) => {
                let reap_result = self.reap();
                let group_result = wait_for_owned_process_group_quiescence(process_group);
                combine_cleanup_results(reap_result, group_result)
            }
            AnchoredGroupShutdown::IdentityLost(process_group) => {
                require_owned_process_group_absent(process_group)
            }
        }
    }

    #[cfg(not(unix))]
    pub(crate) fn cleanup(&mut self) -> McpResult<()> {
        Err(McpError::internal_error(
            "Owned subprocess groups are unavailable on this platform",
        ))
    }
}

impl Drop for ProcessGroupAnchor {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            if let Err(error) = self.cleanup() {
                // Dropping the control writer below still arms the anchor's
                // owner-death kill fallback. Verification failures remain
                // observable only through explicit `Client::close`; Drop
                // cannot return an error or create an orphan cleanup task.
                log::error!("Process-group anchor cleanup was not verified: {error}");
            }
        }
    }
}

fn direct_child_stop_decision(
    probe: &std::io::Result<Option<ExitStatus>>,
) -> DirectChildStopDecision {
    match probe {
        Ok(None) => DirectChildStopDecision::TerminateAndReap,
        Ok(Some(_)) | Err(_) => DirectChildStopDecision::DoNotSignal,
    }
}

fn reap_signalled_child(child: &mut Child) -> McpResult<()> {
    let reap_deadline = Instant::now() + DIRECT_CHILD_REAP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            #[cfg(unix)]
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::CHILD.raw_os_error()) => {
                // Once group shutdown has been requested, a process-wide
                // reaper consuming this exact child is equivalent to a
                // successful reap. This helper is never used to establish
                // pre-signal identity.
                return Ok(());
            }
            Err(error) => {
                return Err(McpError::internal_error(format!(
                    "Failed to reap the owned subprocess: {error}"
                )));
            }
        }

        let now = Instant::now();
        if now >= reap_deadline {
            return Err(McpError::internal_error(
                "Owned subprocess did not exit within the cleanup deadline",
            ));
        }
        std::thread::park_timeout(
            reap_deadline
                .saturating_duration_since(now)
                .min(DIRECT_CHILD_REAP_POLL_INTERVAL),
        );
    }
}

/// Terminates and boundedly reaps the retained direct child process when its
/// identity is still proven by a successful live-status probe.
///
/// Descendant-tree ownership is deliberately not claimed here. Implementing
/// that safely and portably requires runtime support (including Windows Job
/// Objects), not a PATH-resolved helper and a reusable PID.
fn stop_direct_child(child: &mut Child) -> McpResult<()> {
    let probe = child.try_wait();
    match (&probe, direct_child_stop_decision(&probe)) {
        (Ok(Some(_)), DirectChildStopDecision::DoNotSignal) => return Ok(()),
        (Err(error), DirectChildStopDecision::DoNotSignal) => {
            return Err(McpError::internal_error(format!(
                "Failed to establish owned subprocess state: {error}"
            )));
        }
        (_, DirectChildStopDecision::TerminateAndReap) => {}
        (Ok(None), DirectChildStopDecision::DoNotSignal) => unreachable!(),
    }

    // Signal exactly once while the unreaped child handle still pins the
    // process identity. Whether signalling succeeds or fails, only observe
    // afterwards: a failed signal is not authority to target a potentially
    // recycled PID, and a blocking `wait` would defeat request deadlines.
    if let Err(signal_error) = child.kill() {
        return match child.try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(McpError::internal_error(format!(
                "Failed to terminate the owned subprocess: {signal_error}"
            ))),
            Err(probe_error) => Err(McpError::internal_error(format!(
                "Failed to terminate the owned subprocess ({signal_error}) and could not re-check its state ({probe_error})"
            ))),
        };
    }
    reap_signalled_child(child)
}

#[cfg(unix)]
fn owned_process_group_is_absent(process_group: rustix::process::Pid) -> McpResult<bool> {
    match rustix::process::test_kill_process_group(process_group) {
        Err(rustix::io::Errno::SRCH) => Ok(true),
        Ok(()) => Ok(false),
        Err(error) => Err(McpError::internal_error(format!(
            "Failed to verify owned subprocess-group cleanup: {error}"
        ))),
    }
}

#[cfg(target_os = "linux")]
fn linux_ascii_fields(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
}

#[cfg(target_os = "linux")]
fn linux_process_state_group_and_thread_count(stat: &[u8]) -> Option<(char, i32, u64)> {
    let command_end = stat.iter().rposition(|byte| *byte == b')')?;
    let mut fields = linux_ascii_fields(stat.get(command_end + 1..)?);
    let state = fields.next()?;
    if state.len() != 1 {
        return None;
    }
    let state = char::from(state[0]);
    let _parent_process_id = fields.next()?;
    let process_group_id = std::str::from_utf8(fields.next()?).ok()?.parse().ok()?;
    let thread_count = std::str::from_utf8(fields.nth(14)?).ok()?.parse().ok()?;
    Some((state, process_group_id, thread_count))
}

#[cfg(target_os = "linux")]
fn linux_proc_stat_process_id(stat: &[u8]) -> Option<u32> {
    let command_start = stat.iter().position(|byte| *byte == b'(')?;
    let mut fields = linux_ascii_fields(stat.get(..command_start)?);
    let process_id = std::str::from_utf8(fields.next()?).ok()?.parse().ok()?;
    fields.next().is_none().then_some(process_id)
}

#[cfg(target_os = "linux")]
fn linux_status_has_single_current_namespace_pid(status: &[u8], process_id: u32) -> bool {
    let mut observed = None;
    for line in status.split(|byte| *byte == b'\n') {
        let Some(values) = line.strip_prefix(b"NSpid:") else {
            continue;
        };
        if observed.is_some() {
            return false;
        }
        let mut fields = linux_ascii_fields(values);
        let Some(field) = fields.next() else {
            return false;
        };
        if fields.next().is_some() {
            return false;
        }
        observed = std::str::from_utf8(field)
            .ok()
            .and_then(|field| field.parse::<u32>().ok());
        if observed.is_none() {
            return false;
        }
    }
    observed == Some(process_id)
}

#[cfg(target_os = "linux")]
fn linux_process_state_is_live(state: char) -> bool {
    !matches!(state, 'Z' | 'X' | 'x')
}

#[cfg(target_os = "linux")]
fn linux_process_stat_proves_single_terminal_task(state: char, thread_count: u64) -> bool {
    !linux_process_state_is_live(state) && thread_count == 1
}

#[cfg(target_os = "linux")]
fn linux_proc_process_disappeared(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
        || error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error())
}

#[cfg(target_os = "linux")]
fn linux_proc_mounts_allow_complete_process_view(mounts: &str) -> bool {
    let mut proc_mount_options = None;
    for line in mounts.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(_source) = fields.next() else {
            continue;
        };
        let Some(mount_point) = fields.next() else {
            continue;
        };
        let Some(file_system) = fields.next() else {
            continue;
        };
        let Some(options) = fields.next() else {
            continue;
        };
        if mount_point != "/proc" {
            continue;
        }
        if file_system != "proc" || proc_mount_options.is_some() {
            return false;
        }
        proc_mount_options = Some(options);
    }

    proc_mount_options.is_some_and(|options| {
        !options
            .split(',')
            .any(|option| option.starts_with("hidepid=") && option != "hidepid=0")
    })
}

#[cfg(target_os = "linux")]
fn linux_proc_file_mount_id(file: &std::fs::File) -> McpResult<u64> {
    let metadata = rustix::fs::statx(
        file,
        "",
        rustix::fs::AtFlags::EMPTY_PATH,
        rustix::fs::StatxFlags::MNT_ID,
    )
    .map_err(|_| McpError::internal_error("Process-group live-member inspection failed"))?;
    if metadata.stx_mask & rustix::fs::StatxFlags::MNT_ID.bits() == 0 || metadata.stx_mnt_id == 0 {
        return Err(McpError::internal_error(
            "Process-group live-member inspection requires procfs mount identity support",
        ));
    }
    Ok(metadata.stx_mnt_id)
}

#[cfg(target_os = "linux")]
fn linux_verify_proc_file_mount(file: &std::fs::File, proc_mount_id: u64) -> McpResult<()> {
    if linux_proc_file_mount_id(file)? == proc_mount_id {
        Ok(())
    } else {
        Err(McpError::internal_error(
            "Process-group live-member inspection found an inconsistent procfs mount",
        ))
    }
}

#[cfg(target_os = "linux")]
fn linux_read_bounded_proc_file(file: &std::fs::File, max_bytes: u64) -> McpResult<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| McpError::internal_error("Process-group live-member inspection failed"))?;
    let length = u64::try_from(bytes.len())
        .map_err(|_| McpError::internal_error("Process-group live-member inspection failed"))?;
    if length > max_bytes {
        return Err(McpError::internal_error(
            "Process-group live-member inspection exceeded a procfs record bound",
        ));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn linux_open_verified_proc_file(path: &str, proc_mount_id: u64) -> McpResult<std::fs::File> {
    let file = std::fs::File::open(path)
        .map_err(|_| McpError::internal_error("Process-group live-member inspection failed"))?;
    linux_verify_proc_file_mount(&file, proc_mount_id)?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn verify_linux_procfs_process_view(deadline: Instant) -> McpResult<u64> {
    if Instant::now() >= deadline {
        return Err(McpError::internal_error(
            "Process-group live-member inspection exceeded its deadline",
        ));
    }

    let proc_root = std::fs::File::open("/proc")
        .map_err(|_| McpError::internal_error("Process-group live-member inspection failed"))?;
    let proc_mount_id = linux_proc_file_mount_id(&proc_root)?;

    let mounts_file = linux_open_verified_proc_file("/proc/self/mounts", proc_mount_id)?;
    let mounts = linux_read_bounded_proc_file(&mounts_file, LINUX_PROC_MOUNTS_MAX_BYTES)?;
    let mounts = std::str::from_utf8(&mounts)
        .map_err(|_| McpError::internal_error("Process-group live-member inspection failed"))?;
    if !linux_proc_mounts_allow_complete_process_view(mounts) {
        return Err(McpError::internal_error(
            "Process-group live-member inspection requires an unrestricted procfs view",
        ));
    }

    let self_stat_file = linux_open_verified_proc_file("/proc/self/stat", proc_mount_id)?;
    let self_stat = linux_read_bounded_proc_file(&self_stat_file, LINUX_PROC_STAT_MAX_BYTES)?;
    let process_id = std::process::id();
    if linux_proc_stat_process_id(&self_stat) != Some(process_id) {
        return Err(McpError::internal_error(
            "Process-group live-member inspection found a mismatched procfs namespace",
        ));
    }

    let self_status_file = linux_open_verified_proc_file("/proc/self/status", proc_mount_id)?;
    let self_status = linux_read_bounded_proc_file(&self_status_file, LINUX_PROC_STATUS_MAX_BYTES)?;
    if !linux_status_has_single_current_namespace_pid(&self_status, process_id) {
        return Err(McpError::internal_error(
            "Process-group live-member inspection requires procfs mounted in the current PID namespace",
        ));
    }
    if Instant::now() >= deadline {
        return Err(McpError::internal_error(
            "Process-group live-member inspection exceeded its deadline",
        ));
    }
    Ok(proc_mount_id)
}

/// Observes whether a Linux process group currently has a live member.
///
/// This is a read-only workspace utility for process owners that already hold
/// separate authority over the group. `false` means the group was absent or
/// every observed member was a single-threaded terminal zombie for this
/// snapshot; it does not establish ownership and never sends a signal. The
/// scan fails closed for invalid identifiers, restricted or inconsistent
/// procfs views, namespace mismatch, ambiguous dead thread-group leaders,
/// observation races, and deadline expiry.
///
/// # Errors
///
/// Returns an error when a complete, unambiguous procfs snapshot cannot be
/// established before `deadline`.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn linux_process_group_has_live_member(
    process_group_id: i32,
    deadline: Instant,
) -> McpResult<bool> {
    if process_group_id <= 0 {
        return Err(McpError::internal_error(
            "Process-group live-member inspection received an invalid identifier",
        ));
    }
    let process_group = rustix::process::Pid::from_raw(process_group_id).ok_or_else(|| {
        McpError::internal_error(
            "Process-group live-member inspection received an invalid identifier",
        )
    })?;
    let proc_mount_id = verify_linux_procfs_process_view(deadline)?;
    let processes = std::fs::read_dir("/proc")
        .map_err(|_| McpError::internal_error("Process-group live-member inspection failed"))?;
    let mut observed_matching_member = false;
    for entry in processes {
        if Instant::now() >= deadline {
            return Err(McpError::internal_error(
                "Process-group live-member inspection exceeded its deadline",
            ));
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(McpError::internal_error(
                    "Process-group live-member inspection failed",
                ));
            }
        };
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let stat_file = match std::fs::File::open(entry.path().join("stat")) {
            Ok(file) => file,
            Err(error) if linux_proc_process_disappeared(&error) => continue,
            Err(_) => {
                return Err(McpError::internal_error(
                    "Process-group live-member inspection failed",
                ));
            }
        };
        linux_verify_proc_file_mount(&stat_file, proc_mount_id)?;
        let stat = linux_read_bounded_proc_file(&stat_file, LINUX_PROC_STAT_MAX_BYTES)?;
        let (state, observed_group_id, thread_count) =
            linux_process_state_group_and_thread_count(&stat).ok_or_else(|| {
                McpError::internal_error("Process-group live-member inspection failed")
            })?;
        if observed_group_id != process_group_id {
            continue;
        }
        observed_matching_member = true;
        if linux_process_state_is_live(state) {
            return Ok(true);
        }
        if linux_process_stat_proves_single_terminal_task(state, thread_count) {
            continue;
        }
        // `/proc` root enumeration exposes only thread-group leaders. A dead
        // leader with any thread count other than exactly one is ambiguous:
        // live siblings may exist even when `/proc/<tgid>/task` is unavailable.
        return Err(McpError::internal_error(
            "Process-group live-member inspection found an ambiguous terminal member",
        ));
    }
    if Instant::now() >= deadline {
        return Err(McpError::internal_error(
            "Process-group live-member inspection exceeded its deadline",
        ));
    }
    if observed_matching_member || owned_process_group_is_absent(process_group)? {
        Ok(false)
    } else {
        Err(McpError::internal_error(
            "Process-group live-member inspection could not reconcile procfs with the kernel group probe",
        ))
    }
}

#[cfg(unix)]
fn require_owned_process_group_absent(process_group: rustix::process::Pid) -> McpResult<()> {
    if owned_process_group_is_absent(process_group)? {
        Ok(())
    } else {
        Err(McpError::internal_error(
            "Owned process-group identity was lost while the group remained present; refusing to signal an unpinned PGID",
        ))
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnchoredGroupShutdown {
    KillAccepted(rustix::process::Pid),
    IdentityLost(rustix::process::Pid),
}

#[cfg(unix)]
fn request_anchored_group_shutdown(
    anchor: &mut ProcessGroupAnchor,
) -> McpResult<AnchoredGroupShutdown> {
    let process_group = anchor.process_group;
    let Some(child) = anchor.child.as_mut() else {
        anchor.request_shutdown();
        return Ok(AnchoredGroupShutdown::IdentityLost(process_group));
    };

    match child.try_wait() {
        Ok(None) => {
            // The live anchor pins this PGID. Signal while that proof is held;
            // closing the control pipe afterwards also arms owner-death
            // fallback if the shell had not yet observed the signal.
            rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL)
                .map_err(|error| {
                    McpError::internal_error(format!(
                        "Failed to terminate the anchored subprocess group: {error}"
                    ))
                })?;
            anchor.request_shutdown();
            Ok(AnchoredGroupShutdown::KillAccepted(process_group))
        }
        Ok(Some(_)) => {
            anchor.child = None;
            anchor.request_shutdown();
            Ok(AnchoredGroupShutdown::IdentityLost(process_group))
        }
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::CHILD.raw_os_error()) => {
            anchor.child = None;
            anchor.request_shutdown();
            Ok(AnchoredGroupShutdown::IdentityLost(process_group))
        }
        Err(error) => Err(McpError::internal_error(format!(
            "Failed to establish process-group anchor state: {error}"
        ))),
    }
}

#[cfg(unix)]
fn wait_for_owned_process_group_quiescence(process_group: rustix::process::Pid) -> McpResult<()> {
    let deadline = Instant::now() + OWNED_PROCESS_GROUP_QUIESCENCE_TIMEOUT;
    loop {
        if owned_process_group_is_absent(process_group)? {
            return Ok(());
        }

        let now = Instant::now();
        if now >= deadline {
            #[cfg(target_os = "linux")]
            {
                // Linux keeps zombie-only groups observable through
                // `kill(-pgid, 0)`. After the anchored kill was accepted and
                // both direct children were reaped, accept delayed orphan
                // reaping only after two independent complete snapshots prove
                // that no live member remains.
                let process_group_id = process_group.as_raw_nonzero().get();
                let first_deadline = Instant::now()
                    .checked_add(OWNED_PROCESS_GROUP_INSPECTION_TIMEOUT)
                    .unwrap_or_else(Instant::now);
                if !linux_process_group_has_live_member(process_group_id, first_deadline)? {
                    std::thread::park_timeout(DIRECT_CHILD_REAP_POLL_INTERVAL);
                    let second_deadline = Instant::now()
                        .checked_add(OWNED_PROCESS_GROUP_INSPECTION_TIMEOUT)
                        .unwrap_or_else(Instant::now);
                    if !linux_process_group_has_live_member(process_group_id, second_deadline)? {
                        return Ok(());
                    }
                }
            }
            return Err(McpError::internal_error(
                "Owned subprocess group remained present after the cleanup deadline",
            ));
        }
        std::thread::park_timeout(
            deadline
                .saturating_duration_since(now)
                .min(DIRECT_CHILD_REAP_POLL_INTERVAL),
        );
    }
}

#[cfg(unix)]
fn stop_owned_process_group(child: &mut Child, anchor: &mut ProcessGroupAnchor) -> McpResult<()> {
    match request_anchored_group_shutdown(anchor)? {
        AnchoredGroupShutdown::KillAccepted(process_group) => {
            // Reap both direct children before the final non-signalling probe
            // so their zombies cannot keep the group observable.
            let peer_result = reap_signalled_child(child);
            let anchor_result = anchor.reap();
            let group_result = wait_for_owned_process_group_quiescence(process_group);
            combine_cleanup_results(
                combine_cleanup_results(peer_result, anchor_result),
                group_result,
            )
        }
        AnchoredGroupShutdown::IdentityLost(process_group) => {
            // Without a live anchor, signal only the exact retained peer. The
            // old numeric PGID is now observation-only because it may be
            // recycled for an unrelated group.
            let peer_result = stop_direct_child(child);
            let group_result = require_owned_process_group_absent(process_group);
            combine_cleanup_results(peer_result, group_result)
        }
    }
}

#[cfg(not(unix))]
fn stop_owned_process_group(_child: &mut Child, _anchor: &mut ProcessGroupAnchor) -> McpResult<()> {
    Err(McpError::internal_error(
        "Owned subprocess groups are unavailable on this platform",
    ))
}

fn stop_child(
    child: &mut Child,
    ownership: ChildOwnership,
    group_anchor: &mut Option<ProcessGroupAnchor>,
) -> McpResult<()> {
    match ownership {
        ChildOwnership::DirectChild => stop_direct_child(child),
        ChildOwnership::OwnedProcessGroup => group_anchor.as_mut().map_or_else(
            || {
                Err(McpError::internal_error(
                    "Owned process-group anchor is missing",
                ))
            },
            |anchor| stop_owned_process_group(child, anchor),
        ),
    }
}

fn combine_cleanup_errors(first: McpError, second: McpError) -> McpError {
    McpError::internal_error(format!(
        "Multiple client cleanup steps failed ({first}); ({second})"
    ))
}

pub(crate) fn combine_cleanup_results(
    first: McpResult<()>,
    second: McpResult<()>,
) -> McpResult<()> {
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(first), Err(second)) => Err(combine_cleanup_errors(first, second)),
    }
}

pub(crate) fn combine_operation_and_cleanup<T>(
    operation: McpResult<T>,
    cleanup: McpResult<()>,
) -> McpResult<T> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(mark_cleanup_unverified(cleanup_error)),
        (Err(operation_error), Err(cleanup_error)) => Err(McpError::with_data(
            McpErrorCode::InternalError,
            format!("Client cleanup failed after an operation failure: {cleanup_error}"),
            serde_json::json!({
                CLEANUP_UNVERIFIED_DATA_KEY: true,
                "operation": operation_error,
                "cleanup": cleanup_error,
            }),
        )),
    }
}

pub(crate) fn combine_operation_with_cleanup<T, F>(
    operation: McpResult<T>,
    cleanup: F,
) -> McpResult<T>
where
    F: FnOnce() -> McpResult<()>,
{
    let started = Instant::now();
    let mut result = combine_operation_and_cleanup(operation, cleanup());
    if let Err(error) = &mut result
        && is_cleanup_unverified(error)
        && let Some(data) = error
            .data
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
    {
        data.insert(
            CLEANUP_DURATION_MS_DATA_KEY.to_owned(),
            serde_json::json!(started.elapsed().as_secs_f64() * 1000.0),
        );
    }
    result
}

fn mark_cleanup_unverified(mut error: McpError) -> McpError {
    let prior_data = error.data.take();
    error.data = Some(serde_json::json!({
        CLEANUP_UNVERIFIED_DATA_KEY: true,
        "causeData": prior_data,
    }));
    error
}

/// Returns whether a connection error includes an unverified subprocess
/// cleanup outcome.
///
/// Callers that report lifecycle phases separately can use this marker to
/// avoid presenting an initialization failure as though process cleanup was
/// known to have succeeded.
#[must_use]
pub fn is_cleanup_unverified(error: &McpError) -> bool {
    error
        .data
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|data| data.get(CLEANUP_UNVERIFIED_DATA_KEY))
        .and_then(serde_json::Value::as_bool)
        == Some(true)
}

pub(crate) fn resolve_stdio_command(
    command: &str,
    working_dir: Option<&Path>,
) -> McpResult<PathBuf> {
    let command_path = Path::new(command);
    if command_path.is_absolute() || command_path.components().count() <= 1 {
        return Ok(command_path.to_path_buf());
    }

    let process_dir = std::env::current_dir().map_err(|error| {
        McpError::internal_error(format!("Failed to resolve current directory: {error}"))
    })?;
    let base = match working_dir {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => process_dir.join(path),
        None => process_dir,
    };
    Ok(base.join(command_path))
}

/// Owns a subprocess until it is transferred into a [`Client`].
///
/// `std::process::Child` does not terminate or reap a still-running process on
/// drop. Keeping this guard armed across pipe extraction and the initialize
/// handshake prevents failed connection attempts from leaking child processes.
/// Explicit cleanup reports failures; Drop makes one final best-effort attempt
/// but cannot return an error or detach an unstructured cleanup worker.
pub(crate) struct ChildGuard {
    child: Option<Child>,
    ownership: ChildOwnership,
    group_anchor: Option<ProcessGroupAnchor>,
}

impl ChildGuard {
    pub(crate) fn new(child: Child) -> Self {
        Self::with_ownership(child, ChildOwnership::DirectChild)
    }

    pub(crate) fn with_ownership(child: Child, ownership: ChildOwnership) -> Self {
        Self {
            child: Some(child),
            ownership,
            group_anchor: None,
        }
    }

    pub(crate) fn with_process_group(child: Child, anchor: ProcessGroupAnchor) -> Self {
        Self {
            child: Some(child),
            ownership: ChildOwnership::OwnedProcessGroup,
            group_anchor: Some(anchor),
        }
    }

    pub(crate) fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("ChildGuard already disarmed")
    }

    pub(crate) fn verify_group_anchor(&mut self) -> McpResult<()> {
        self.group_anchor
            .as_mut()
            .map_or(Ok(()), ProcessGroupAnchor::verify_live)
    }

    pub(crate) fn disarm(mut self) -> Child {
        debug_assert!(self.group_anchor.is_none());
        self.child.take().expect("ChildGuard already disarmed")
    }

    pub(crate) fn disarm_all(mut self) -> (Child, Option<ProcessGroupAnchor>) {
        (
            self.child.take().expect("ChildGuard already disarmed"),
            self.group_anchor.take(),
        )
    }

    fn try_cleanup(&mut self) -> McpResult<()> {
        let result = match self.child.as_mut() {
            Some(child) => stop_child(child, self.ownership, &mut self.group_anchor),
            None => self
                .group_anchor
                .as_mut()
                .map_or(Ok(()), ProcessGroupAnchor::cleanup),
        };
        if result.is_ok() {
            self.child = None;
            self.group_anchor = None;
        }
        result
    }

    pub(crate) fn cleanup(mut self) -> McpResult<()> {
        self.try_cleanup()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Err(error) = self.try_cleanup() {
            log::error!("Subprocess cleanup was not verified during guard drop: {error}");
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientProgressParams {
    #[serde(rename = "progressTo\x6ben")]
    marker: ProgressMarker,
    progress: f64,
    total: Option<f64>,
    message: Option<String>,
    #[serde(rename = "_meta")]
    meta: Option<serde_json::Map<String, serde_json::Value>>,
}

impl ClientProgressParams {
    fn is_semantically_valid_after(&self, previous: Option<f64>) -> bool {
        self.progress.is_finite()
            && self.total.is_none_or(f64::is_finite)
            && previous.is_none_or(|previous| self.progress > previous)
    }
}

fn parse_valid_client_progress(
    params: &serde_json::Value,
    previous: Option<f64>,
) -> Option<ClientProgressParams> {
    let object = params.as_object()?;
    // Optional protocol members are absent or typed; explicit null is not an
    // alternate spelling for omission and must not acquire timer authority.
    if object.get("total").is_some_and(serde_json::Value::is_null)
        || object
            .get("message")
            .is_some_and(serde_json::Value::is_null)
        || object.get("_meta").is_some_and(serde_json::Value::is_null)
    {
        return None;
    }
    let progress = serde_json::from_value::<ClientProgressParams>(params.clone()).ok()?;
    progress
        .is_semantically_valid_after(previous)
        .then_some(progress)
}

fn method_not_found_response(request: &JsonRpcRequest) -> Option<JsonRpcMessage> {
    let id = request.id.clone()?;
    let error = McpError::method_not_found(&request.method);
    let response = JsonRpcResponse::error(Some(id), error.into());
    Some(JsonRpcMessage::Response(response))
}

fn invalid_notification_request_response(request: &JsonRpcRequest) -> Option<JsonRpcMessage> {
    let id = request.id.clone()?;
    let error = McpError::invalid_request(format!(
        "Notification-only method {:?} must not include an ID",
        request.method
    ));
    let response = JsonRpcResponse::error(Some(id), error.into());
    Some(JsonRpcMessage::Response(response))
}

fn server_request_response(request: &JsonRpcRequest) -> Option<JsonRpcMessage> {
    let id = request.id.clone()?;
    if request.method.starts_with("notifications/") {
        return invalid_notification_request_response(request);
    }
    if request.method == "ping" {
        return Some(JsonRpcMessage::Response(JsonRpcResponse::success(
            id,
            serde_json::json!({}),
        )));
    }
    method_not_found_response(request)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServerNotificationKind {
    Progress,
    LogMessage,
}

fn server_notification_kind(request: &JsonRpcRequest) -> Option<ServerNotificationKind> {
    if request.id.is_some() {
        return None;
    }

    match request.method.as_str() {
        "notifications/progress" => Some(ServerNotificationKind::Progress),
        "notifications/message" => Some(ServerNotificationKind::LogMessage),
        _ => None,
    }
}

const INITIALIZE_REQUEST_ID: i64 = 1;

fn validate_initialize_response_id(response: &JsonRpcResponse) -> McpResult<()> {
    validate_response_envelope(response)?;

    let expected = RequestId::Number(INITIALIZE_REQUEST_ID);
    if response.id.as_ref() == Some(&expected) {
        return Ok(());
    }

    Err(McpError::internal_error(INITIALIZE_RESPONSE_ID_ERROR))
}

fn validate_response_envelope(response: &JsonRpcResponse) -> McpResult<()> {
    if response.jsonrpc.as_ref() != JSONRPC_VERSION {
        return Err(McpError::invalid_request(INVALID_RESPONSE_ENVELOPE_ERROR));
    }

    match (response.result.is_some(), response.error.is_some()) {
        (true, false) | (false, true) => Ok(()),
        (true, true) | (false, false) => {
            Err(McpError::invalid_request(INVALID_RESPONSE_ENVELOPE_ERROR))
        }
    }
}

fn validate_inbound_typed_message(message: &JsonRpcMessage) -> McpResult<()> {
    message
        .validate()
        .map_err(|_| McpError::invalid_request("Server sent an invalid JSON-RPC message"))
}

fn json_rpc_error_to_mcp(error: JsonRpcError) -> McpError {
    let code = McpErrorCode::from(error.code);
    match error.data {
        Some(data) => McpError::with_data(code, error.message, data),
        None => McpError::new(code, error.message),
    }
}

fn cancellation_control_message(
    request_id: RequestId,
    reason: Option<String>,
    await_cleanup: Option<bool>,
) -> McpResult<JsonRpcMessage> {
    let params = serde_json::to_value(CancelledParams {
        request_id,
        reason,
        await_cleanup,
    })
    .map_err(|_| McpError::invalid_params("Invalid cancellation control parameters"))?;
    Ok(JsonRpcMessage::Request(JsonRpcRequest::notification(
        "notifications/cancelled",
        Some(params),
    )))
}

fn decode_response_payload<R: serde::de::DeserializeOwned>(
    value: serde_json::Value,
) -> McpResult<R> {
    serde_json::from_value(value)
        .map_err(|_| McpError::internal_error(INVALID_RESPONSE_PAYLOAD_ERROR))
}

fn validate_initialize_result(result: &InitializeResult) -> McpResult<()> {
    if result.protocol_version == PROTOCOL_VERSION {
        return Ok(());
    }

    Err(McpError::internal_error(UNSUPPORTED_PROTOCOL_VERSION_ERROR))
}

fn auto_legacy_fallback_is_authorized(error: &McpError) -> bool {
    // A completed JSON-RPC discovery refusal is distinguishable from malformed
    // discovery or transport failure because the latter paths surface as
    // InternalError. -32022 is final's recognized unsupported-version error,
    // so it remains modern and cannot authorize a legacy attempt.
    matches!(
        error.code,
        McpErrorCode::ParseError
            | McpErrorCode::InvalidRequest
            | McpErrorCode::MethodNotFound
            | McpErrorCode::InvalidParams
    )
}

fn validate_timeout_duration(
    timeout: Duration,
    maximum: Duration,
    error: &'static str,
) -> McpResult<()> {
    if timeout < Duration::from_millis(1) || timeout > maximum {
        return Err(McpError::invalid_params(error));
    }
    Ok(())
}

#[cfg(unix)]
fn recv_child_transport(
    transport: &mut StdioTransport<ChildStdout, ChildStdin>,
    cx: &Cx,
    deadline: Option<Instant>,
) -> Result<(JsonRpcMessage, Instant), TransportError> {
    transport.recv_until_with_completion(cx, deadline)
}

#[cfg(not(unix))]
fn recv_child_transport(
    transport: &mut StdioTransport<ChildStdout, ChildStdin>,
    cx: &Cx,
    deadline: Option<Instant>,
) -> Result<(JsonRpcMessage, Instant), TransportError> {
    // std::process::ChildStdout exposes no portable safe readiness primitive.
    // Keep the limitation explicit: non-Unix cancellation/deadlines are
    // observed at frame boundaries, but cannot interrupt a blocking pipe read.
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(TransportError::ReceiveDeadlineExceeded);
    }
    transport.recv_with_completion(cx)
}

#[cfg(unix)]
fn send_child_server_response_during_receive(
    transport: &mut StdioTransport<ChildStdout, ChildStdin>,
    _cx: &Cx,
    message: &JsonRpcMessage,
) -> McpResult<()> {
    transport
        .try_send_control_message(message)
        .map_err(transport_error_to_mcp)
}

#[cfg(not(unix))]
fn send_child_server_response_during_receive(
    transport: &mut StdioTransport<ChildStdout, ChildStdin>,
    cx: &Cx,
    message: &JsonRpcMessage,
) -> McpResult<()> {
    // Standard child pipes expose no portable nonblocking write on this path.
    // Preserve frame-boundary behavior explicitly; the caller abandons the
    // connection if this send itself fails.
    transport.send(cx, message).map_err(transport_error_to_mcp)
}

fn initialize_child_transport(
    transport: &mut StdioTransport<ChildStdout, ChildStdin>,
    cx: &Cx,
    client_info: &ClientInfo,
    capabilities: &ClientCapabilities,
    timeout_policy: RequestTimeoutPolicy,
) -> McpResult<InitializeResult> {
    timeout_policy.validate()?;
    let params = InitializeParams {
        protocol_version: PROTOCOL_VERSION.to_string(),
        capabilities: capabilities.clone(),
        client_info: client_info.clone(),
    };
    let params = serde_json::to_value(params).map_err(|error| {
        McpError::internal_error(format!("Failed to serialize params: {error}"))
    })?;
    let request = JsonRpcRequest::new("initialize", Some(params), INITIALIZE_REQUEST_ID);
    transport
        .send(cx, &JsonRpcMessage::Request(request))
        .map_err(transport_error_to_mcp)?;
    // Both timers start at the observed successful commit boundary. The
    // initialization exchange has no request-owned progress token, so its idle
    // timer is never reset. Synchronous writes remain governed by the caller's
    // `Cx` checkpoints before this commit.
    let committed_at = Instant::now();
    let deadlines = RequestDeadlines::start_at(timeout_policy, committed_at)?;

    let response = loop {
        let (message, received_at) = recv_child_transport(transport, cx, Some(deadlines.next()))
            .map_err(|error| match error {
                TransportError::ReceiveDeadlineExceeded => {
                    request_timeout_error(deadlines.next_kind())
                }
                other => transport_error_to_mcp(other),
            })?;
        if let Some(source) = deadlines.expired_at(received_at) {
            return Err(request_timeout_error(source));
        }
        validate_inbound_typed_message(&message)?;
        match message {
            JsonRpcMessage::Response(response) => {
                validate_initialize_response_id(&response)?;
                break response;
            }
            JsonRpcMessage::Request(request) => {
                if let Some(response) = server_request_response(&request) {
                    send_child_server_response_during_receive(transport, cx, &response)?;
                }
            }
        }
    };

    if let Some(error) = response.error {
        return Err(json_rpc_error_to_mcp(error));
    }
    let result = response
        .result
        .ok_or_else(|| McpError::invalid_request("Initialize response has no result"))?;
    let result: InitializeResult = serde_json::from_value(result)
        .map_err(|_| McpError::invalid_request(INVALID_INITIALIZE_PAYLOAD_ERROR))?;
    validate_initialize_result(&result)?;

    transport
        .send(
            cx,
            &JsonRpcMessage::Request(JsonRpcRequest::initialized_notification()),
        )
        .map_err(transport_error_to_mcp)?;
    Ok(result)
}

/// Maximum number of uncorrelated-response warnings emitted per connection.
///
/// Unknown and late IDs are peer activity, not authority to mutate a live
/// waiter. Bounding their diagnostics prevents a noisy peer from turning that
/// discard rule into an unbounded logging side effect.
const MAX_UNCORRELATED_RESPONSE_DIAGNOSTICS: u8 = 8;
/// Default per-connection in-flight waiter bound from LIMIT-01.
const MAX_IN_FLIGHT_RESPONSES: usize = 1_024;
/// Default combined waiter and late-response tombstone bound from LIMIT-01.
const MAX_RESPONSE_CORRELATIONS: usize = 4_096;
/// Default late-response tombstone retention from LIMIT-01.
const RESPONSE_TOMBSTONE_RETENTION: Duration = Duration::from_mins(10);
/// Maximum retained at-most-once cancellation-control markers per connection.
const MAX_CANCELLATION_CONTROL_IDS: usize = 4_096;
/// Retention for an emitted or attempted ordinary-request cancellation ID.
///
/// This is at least the maximum ordinary request lifetime, so a still-live
/// request generation cannot acquire a second control attempt after expiry.
/// A successfully admitted new waiter generation clears its ID explicitly.
const CANCELLATION_CONTROL_RETENTION: Duration = MAX_CLIENT_ABSOLUTE_TIMEOUT;
/// Maximum pages followed by one automatic pagination operation.
const MAX_AUTO_PAGINATION_PAGES: usize = 1_024;
/// Maximum aggregate items retained by one automatic pagination operation.
const MAX_AUTO_PAGINATION_ITEMS: usize = 100_000;
/// Maximum aggregate compact-JSON bytes retained by automatic pagination.
const MAX_AUTO_PAGINATION_SERIALIZED_BYTES: usize = 64 * 1_024 * 1_024;
/// Maximum UTF-8 bytes admitted in a peer-provided pagination cursor.
const MAX_PAGINATION_CURSOR_BYTES: usize = 4 * 1_024;
/// Compact JSON for an empty retained list is exactly `[]`.
const MIN_LIST_PAGE_SERIALIZED_BYTES: usize = 2;
/// Reserved counter value that permanently marks request-ID exhaustion.
///
/// The largest signed 64-bit value is not issued. Reserving it as a sentinel
/// lets the allocator fail closed without ever wrapping or reusing an ID.
const REQUEST_ID_EXHAUSTION_SENTINEL: u64 = 9_223_372_036_854_775_807;

const PAGINATION_PAGE_LIMIT_ERROR: &str = "Automatic pagination page limit exceeded";
const PAGINATION_ITEM_LIMIT_ERROR: &str = "Automatic pagination item limit exceeded";
const PAGINATION_BYTE_LIMIT_ERROR: &str = "Automatic pagination serialized-byte limit exceeded";
const PAGINATION_CURSOR_LIMIT_ERROR: &str = "Automatic pagination cursor byte limit exceeded";
const PAGINATION_CURSOR_CYCLE_ERROR: &str = "Automatic pagination cursor repeated";
const PAGINATION_CURSOR_NO_PROGRESS_ERROR: &str = "Pagination response cursor did not advance";
const PAGINATION_MEASUREMENT_ERROR: &str =
    "Automatic pagination response could not be measured safely";
const LIST_PAGE_BYTE_LIMIT_ERROR: &str = "List page serialized-byte limit must be at least 2 bytes";
const PROGRESS_CALLBACK_PANIC_ERROR: &str = "Client progress callback failed";
const CONTROL_FRAME_CAPACITY_ERROR: &str = "MCP stdio control frame exceeds atomic capacity";
const INVALID_RESPONSE_ENVELOPE_ERROR: &str = "Invalid JSON-RPC response";
const INVALID_RESPONSE_PAYLOAD_ERROR: &str = "Invalid MCP response payload";
const TRANSPORT_CODEC_ERROR: &str = "Invalid MCP transport frame";
const INVALID_INITIALIZE_PAYLOAD_ERROR: &str = "Invalid MCP initialize response payload";
const INITIALIZE_RESPONSE_ID_ERROR: &str = "Initialize response ID mismatch";
const UNSUPPORTED_PROTOCOL_VERSION_ERROR: &str =
    "Server selected an unsupported MCP protocol version";
const REDACTED_CLIENT_CALLBACK_PANIC: &[u8] =
    b"fastmcp client callback panicked; panic payload redacted\n";
static INSTALL_CLIENT_CALLBACK_PANIC_HOOK: Once = Once::new();

thread_local! {
    static REDACT_CLIENT_CALLBACK_PANIC: Cell<bool> = const { Cell::new(false) };
}

struct ClientCallbackPanicRedactionGuard {
    previous: bool,
}

impl ClientCallbackPanicRedactionGuard {
    fn enter() -> Self {
        let previous = REDACT_CLIENT_CALLBACK_PANIC.with(|redact| redact.replace(true));
        Self { previous }
    }
}

impl Drop for ClientCallbackPanicRedactionGuard {
    fn drop(&mut self) {
        REDACT_CLIENT_CALLBACK_PANIC.with(|redact| redact.set(self.previous));
    }
}

fn install_client_callback_panic_hook() {
    INSTALL_CLIENT_CALLBACK_PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            if REDACT_CLIENT_CALLBACK_PANIC
                .try_with(Cell::get)
                .unwrap_or(false)
            {
                let _ = std::io::stderr().write_all(REDACTED_CLIENT_CALLBACK_PANIC);
            } else {
                previous(panic_info);
            }
        }));
    });
}

fn catch_client_callback_unwind<R>(callback: impl FnOnce() -> R) -> Result<R, Box<dyn Any + Send>> {
    install_client_callback_panic_hook();
    let _redaction = ClientCallbackPanicRedactionGuard::enter();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(callback))
}

#[derive(Debug, Clone, Copy)]
struct PaginationLimits {
    pages: usize,
    items: usize,
    serialized_bytes: usize,
    cursor_bytes: usize,
}

impl PaginationLimits {
    const DEFAULT: Self = Self {
        pages: MAX_AUTO_PAGINATION_PAGES,
        items: MAX_AUTO_PAGINATION_ITEMS,
        serialized_bytes: MAX_AUTO_PAGINATION_SERIALIZED_BYTES,
        cursor_bytes: MAX_PAGINATION_CURSOR_BYTES,
    };
}

/// Bounded state for one automatic pagination operation.
///
/// Only fixed-width cursor digests are retained. The peer's opaque cursor is
/// never copied into diagnostics or the cycle-detection set.
struct PaginationBudget {
    limits: PaginationLimits,
    pages: usize,
    items: usize,
    serialized_bytes: usize,
    seen_cursors: std::collections::HashSet<Sha256Digest>,
}

/// Caller-selected bounds for acquiring one page of a list operation.
///
/// MCP's tool, resource, template, and prompt list requests do not carry a
/// client-side item limit. A peer can therefore return more data in one page
/// than a caller intends to retain. These limits bound the retained page and
/// make that loss visible through [`BoundedListPage::local_truncated`]. The
/// normal transport message-size limit remains the first line of defense while
/// the response is being received and decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListPageLimits {
    /// Maximum number of list entries to retain.
    pub max_items: usize,
    /// Maximum compact-JSON bytes for the complete retained `Vec`, including
    /// its brackets and commas. Values below two are invalid because even an
    /// empty vector serializes as `[]`.
    pub max_serialized_bytes: usize,
}

impl ListPageLimits {
    /// Creates limits for a single list page.
    #[must_use]
    pub const fn new(max_items: usize, max_serialized_bytes: usize) -> Self {
        Self {
            max_items,
            max_serialized_bytes,
        }
    }

    fn validate(self) -> McpResult<()> {
        if self.max_serialized_bytes < MIN_LIST_PAGE_SERIALIZED_BYTES {
            return Err(McpError::invalid_params(LIST_PAGE_BYTE_LIMIT_ERROR));
        }
        Ok(())
    }
}

/// A bounded, single-page list acquisition.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundedListPage<T> {
    /// Entries retained within the caller's item and byte budgets.
    pub items: Vec<T>,
    /// Opaque cursor supplied by the peer for the following page. This is
    /// suppressed when [`Self::local_truncated`] is true because following the
    /// peer cursor would skip entries omitted from the current peer page.
    pub next_cursor: Option<String>,
    /// Whether entries from the current peer page were omitted locally.
    pub local_truncated: bool,
    /// Whether the peer supplied a cursor indicating another peer page.
    pub peer_has_more: bool,
}

impl PaginationBudget {
    fn new() -> Self {
        Self::with_limits(PaginationLimits::DEFAULT)
    }

    fn with_limits(limits: PaginationLimits) -> Self {
        Self {
            limits,
            pages: 0,
            items: 0,
            serialized_bytes: 0,
            seen_cursors: std::collections::HashSet::new(),
        }
    }

    fn begin_page(&mut self) -> McpResult<()> {
        let pages = self
            .pages
            .checked_add(1)
            .ok_or_else(|| McpError::internal_error(PAGINATION_PAGE_LIMIT_ERROR))?;
        if pages > self.limits.pages {
            return Err(McpError::internal_error(PAGINATION_PAGE_LIMIT_ERROR));
        }
        self.pages = pages;
        Ok(())
    }

    fn admit_next_cursor(&mut self, cursor: Option<String>) -> McpResult<Option<String>> {
        let Some(cursor) = cursor else {
            return Ok(None);
        };
        let digest = sha256_bounded(cursor.as_bytes(), self.limits.cursor_bytes)
            .map_err(|_| McpError::internal_error(PAGINATION_CURSOR_LIMIT_ERROR))?;
        if !self.seen_cursors.insert(digest) {
            return Err(McpError::internal_error(PAGINATION_CURSOR_CYCLE_ERROR));
        }
        Ok(Some(cursor))
    }

    fn account_page<T: serde::Serialize>(&mut self, items: &[T]) -> McpResult<()> {
        let item_count = self
            .items
            .checked_add(items.len())
            .ok_or_else(|| McpError::internal_error(PAGINATION_ITEM_LIMIT_ERROR))?;
        if item_count > self.limits.items {
            return Err(McpError::internal_error(PAGINATION_ITEM_LIMIT_ERROR));
        }

        let remaining_bytes = self
            .limits
            .serialized_bytes
            .checked_sub(self.serialized_bytes)
            .ok_or_else(|| McpError::internal_error(PAGINATION_BYTE_LIMIT_ERROR))?;
        let page_bytes = measure_serialized_bytes(items, remaining_bytes)?;
        let serialized_bytes = self
            .serialized_bytes
            .checked_add(page_bytes)
            .ok_or_else(|| McpError::internal_error(PAGINATION_BYTE_LIMIT_ERROR))?;
        if serialized_bytes > self.limits.serialized_bytes {
            return Err(McpError::internal_error(PAGINATION_BYTE_LIMIT_ERROR));
        }

        self.items = item_count;
        self.serialized_bytes = serialized_bytes;
        Ok(())
    }
}

struct SerializedByteCounter {
    bytes: usize,
    limit: usize,
    exceeded: bool,
}

impl std::io::Write for SerializedByteCounter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let Some(bytes) = self.bytes.checked_add(buffer.len()) else {
            self.exceeded = true;
            return Err(std::io::Error::other(PAGINATION_BYTE_LIMIT_ERROR));
        };
        if bytes > self.limit {
            self.exceeded = true;
            return Err(std::io::Error::other(PAGINATION_BYTE_LIMIT_ERROR));
        }
        self.bytes = bytes;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn measure_serialized_bytes<T: serde::Serialize + ?Sized>(
    value: &T,
    limit: usize,
) -> McpResult<usize> {
    let mut counter = SerializedByteCounter {
        bytes: 0,
        limit,
        exceeded: false,
    };
    match serde_json::to_writer(&mut counter, value) {
        Ok(()) => Ok(counter.bytes),
        Err(_error) if counter.exceeded => {
            Err(McpError::internal_error(PAGINATION_BYTE_LIMIT_ERROR))
        }
        Err(_error) => Err(McpError::internal_error(PAGINATION_MEASUREMENT_ERROR)),
    }
}

fn bounded_list_page<T: serde::Serialize>(
    items: Vec<T>,
    request_cursor: Option<&str>,
    next_cursor: Option<String>,
    limits: ListPageLimits,
) -> McpResult<BoundedListPage<T>> {
    limits.validate()?;
    let original_items = items.len();
    let mut retained = Vec::with_capacity(original_items.min(limits.max_items));
    let mut local_truncated = original_items > limits.max_items;
    let mut serialized_bytes = MIN_LIST_PAGE_SERIALIZED_BYTES;

    for item in items.into_iter().take(limits.max_items) {
        let separator_bytes = usize::from(!retained.is_empty());
        let Some(remaining) = limits
            .max_serialized_bytes
            .checked_sub(serialized_bytes.saturating_add(separator_bytes))
        else {
            local_truncated = true;
            break;
        };
        let item_bytes = match measure_serialized_bytes(&item, remaining) {
            Ok(item_bytes) => item_bytes,
            Err(error) if error.message == PAGINATION_BYTE_LIMIT_ERROR => {
                local_truncated = true;
                break;
            }
            Err(error) => return Err(error),
        };
        let Some(next_serialized_bytes) = serialized_bytes
            .checked_add(separator_bytes)
            .and_then(|bytes| bytes.checked_add(item_bytes))
        else {
            local_truncated = true;
            break;
        };
        if next_serialized_bytes > limits.max_serialized_bytes {
            local_truncated = true;
            break;
        }
        serialized_bytes = next_serialized_bytes;
        retained.push(item);
    }

    let mut cursor_budget = PaginationBudget::with_limits(PaginationLimits {
        pages: 1,
        items: limits.max_items,
        serialized_bytes: limits.max_serialized_bytes,
        cursor_bytes: MAX_PAGINATION_CURSOR_BYTES,
    });
    let validated_next_cursor = cursor_budget.admit_next_cursor(next_cursor)?;
    if request_cursor.is_some() && request_cursor == validated_next_cursor.as_deref() {
        return Err(McpError::internal_error(
            PAGINATION_CURSOR_NO_PROGRESS_ERROR,
        ));
    }
    let peer_has_more = validated_next_cursor.is_some();
    let next_cursor = if local_truncated {
        None
    } else {
        validated_next_cursor
    };

    Ok(BoundedListPage {
        items: retained,
        next_cursor,
        local_truncated,
        peer_has_more,
    })
}

fn bounded_cursor_parameter(cursor: Option<&str>) -> McpResult<Option<String>> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    if cursor.len() > MAX_PAGINATION_CURSOR_BYTES {
        return Err(McpError::invalid_params(PAGINATION_CURSOR_LIMIT_ERROR));
    }
    Ok(Some(cursor.to_owned()))
}

fn validate_list_page_request(
    cursor: Option<&str>,
    limits: ListPageLimits,
) -> McpResult<Option<String>> {
    limits.validate()?;
    bounded_cursor_parameter(cursor)
}

const REMOTE_LOG_TARGET: &str = "fastmcp_rust::remote";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataSizeBucket {
    Empty,
    Small,
    Medium,
    Large,
    Oversized,
}

impl MetadataSizeBucket {
    const fn for_extent(extent: usize) -> Self {
        match extent {
            0 => Self::Empty,
            1..=64 => Self::Small,
            65..=1_024 => Self::Medium,
            1_025..=65_536 => Self::Large,
            _ => Self::Oversized,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::Oversized => "oversized",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RemoteLogMetadata {
    level: &'static str,
    logger_present: bool,
    logger_bytes: MetadataSizeBucket,
    data_kind: &'static str,
    data_extent: MetadataSizeBucket,
}

impl std::fmt::Display for RemoteLogMetadata {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "remote_log level={} logger_present={} logger_bytes={} data_kind={} data_extent={}",
            self.level,
            self.logger_present,
            self.logger_bytes.as_str(),
            self.data_kind,
            self.data_extent.as_str()
        )
    }
}

fn remote_log_metadata(message: &LogMessageParams) -> RemoteLogMetadata {
    let level = match message.level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warning => "warning",
        LogLevel::Error => "error",
    };
    let (data_kind, data_extent) = match &message.data {
        serde_json::Value::Null => ("null", 0),
        serde_json::Value::Bool(_) => ("boolean", 1),
        serde_json::Value::Number(_) => ("number", 1),
        serde_json::Value::String(value) => ("string", value.len()),
        serde_json::Value::Array(values) => ("array", values.len()),
        serde_json::Value::Object(values) => ("object", values.len()),
    };
    RemoteLogMetadata {
        level,
        logger_present: message.logger.is_some(),
        logger_bytes: MetadataSizeBucket::for_extent(
            message.logger.as_ref().map_or(0, String::len),
        ),
        data_kind,
        data_extent: MetadataSizeBucket::for_extent(data_extent),
    }
}

type CorrelatedResponse = McpResult<JsonRpcResponse>;

/// The receive half owned by exactly one registered request.
///
/// The client's single transport receive loop is the only sender. An
/// asupersync oneshot retains a reordered response until this waiter is polled
/// and wakes an already-polled waiter when the response or a connection-wide
/// error arrives.
#[derive(Debug)]
struct ResponseWaiter {
    id: RequestId,
    receiver: oneshot::Receiver<CorrelatedResponse>,
}

impl ResponseWaiter {
    fn try_response(&mut self) -> McpResult<Option<JsonRpcResponse>> {
        match self.receiver.try_recv() {
            Ok(Ok(response)) => Ok(Some(response)),
            Ok(Err(error)) => Err(error),
            Err(oneshot::TryRecvError::Empty) => Ok(None),
            Err(oneshot::TryRecvError::Closed) => Err(McpError::internal_error(
                "Response waiter closed without a terminal outcome",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseRoute {
    Delivered,
    TombstoneRetired,
    InvalidEnvelope,
    UnknownId,
    MissingId,
    WaiterDropped,
    ConnectionClosed,
}

/// Correlation state owned by the single-reader stdio client.
///
/// Only registered IDs can receive a response. A committed request timeout
/// replaces its waiter with a bounded tombstone, so the exact late response is
/// consumed without being misclassified or waking another owner. Duplicate
/// and unknown-ID responses cannot replace a terminal outcome. This does not
/// make the current `&mut Client` API concurrent; it makes correlation lossless
/// for every ID registered with the one receive loop and provides bounded
/// state for a future multiplexed adapter.
struct ResponseRegistry {
    pending: std::collections::HashMap<CorrelationKey, oneshot::Sender<CorrelatedResponse>>,
    tombstones: std::collections::HashMap<CorrelationKey, Instant>,
    /// IDs whose one permitted cancellation control has been claimed.
    ///
    /// This state is intentionally separate from response tombstones: callers
    /// may cancel an arbitrary peer-known ID, including one the local allocator
    /// has not reached, without preventing a later local waiter registration.
    cancellation_controls: std::collections::HashMap<CorrelationKey, Instant>,
    terminal_error: Option<McpError>,
    uncorrelated_diagnostics: u8,
}

impl ResponseRegistry {
    fn new() -> Self {
        Self {
            pending: std::collections::HashMap::new(),
            tombstones: std::collections::HashMap::new(),
            cancellation_controls: std::collections::HashMap::new(),
            terminal_error: None,
            uncorrelated_diagnostics: 0,
        }
    }

    fn register(&mut self, id: RequestId) -> McpResult<ResponseWaiter> {
        self.prune_expired_retained_state(Instant::now());
        if let Some(error) = &self.terminal_error {
            return Err(error.clone());
        }
        let key = id
            .correlation_key()
            .map_err(|_| McpError::internal_error("Invalid JSON-RPC request ID"))?;
        if self.pending.contains_key(&key) {
            return Err(McpError::internal_error("Duplicate in-flight request ID"));
        }
        if self.tombstones.contains_key(&key) {
            return Err(McpError::internal_error(
                "Retired request ID cannot be reused",
            ));
        }
        if self.pending.len() >= MAX_IN_FLIGHT_RESPONSES {
            return Err(McpError::internal_error(
                "Client in-flight response limit reached",
            ));
        }
        if self.pending.len().saturating_add(self.tombstones.len()) >= MAX_RESPONSE_CORRELATIONS {
            return Err(McpError::internal_error(
                "Client response correlation limit reached",
            ));
        }

        let (sender, receiver) = oneshot::channel();
        // A public caller may have cancelled a peer-known ID before the local
        // monotonic allocator reached it. Admission of a genuinely new waiter
        // starts a new request generation with its own one-control allowance;
        // unlike a response tombstone, the old control marker never blocks it.
        self.cancellation_controls.remove(&key);
        self.pending.insert(key, sender);
        Ok(ResponseWaiter { id, receiver })
    }

    fn route(&mut self, response: JsonRpcResponse) -> ResponseRoute {
        self.prune_expired_retained_state(Instant::now());
        if self.terminal_error.is_some() {
            self.note_uncorrelated_response("response received after connection failure");
            return ResponseRoute::ConnectionClosed;
        }

        if let Err(error) = validate_response_envelope(&response) {
            self.fail_all(error);
            return ResponseRoute::InvalidEnvelope;
        }

        let Some(id) = response.id.clone() else {
            let error = McpError::internal_error("Server response is missing a request ID");
            self.fail_all(error);
            return ResponseRoute::MissingId;
        };
        let Ok(key) = id.correlation_key() else {
            self.fail_all(McpError::internal_error(INVALID_RESPONSE_ENVELOPE_ERROR));
            return ResponseRoute::InvalidEnvelope;
        };
        if self.tombstones.remove(&key).is_some() {
            return ResponseRoute::TombstoneRetired;
        }
        let Some(sender) = self.pending.remove(&key) else {
            self.note_uncorrelated_response("response received for unknown or completed request");
            return ResponseRoute::UnknownId;
        };

        match sender.send_blocking(Ok(response)) {
            Ok(()) => ResponseRoute::Delivered,
            Err(_) => {
                self.note_uncorrelated_response("response owner was already dropped");
                ResponseRoute::WaiterDropped
            }
        }
    }

    fn fail(&mut self, id: &RequestId, error: McpError) -> bool {
        let Ok(key) = id.correlation_key() else {
            return false;
        };
        let Some(sender) = self.pending.remove(&key) else {
            return false;
        };
        let _ = sender.send_blocking(Err(error));
        true
    }

    fn tombstone(&mut self, id: &RequestId, error: McpError) -> McpResult<bool> {
        let now = Instant::now();
        self.prune_expired_retained_state(now);
        if let Some(terminal_error) = &self.terminal_error {
            return Err(terminal_error.clone());
        }
        let key = id
            .correlation_key()
            .map_err(|_| McpError::internal_error("Invalid JSON-RPC request ID"))?;
        if self.tombstones.contains_key(&key) || !self.pending.contains_key(&key) {
            return Ok(false);
        }
        if self.tombstones.len() >= MAX_RESPONSE_CORRELATIONS {
            return Err(McpError::internal_error(
                "Client response tombstone limit reached",
            ));
        }

        let expires_at = now
            .checked_add(RESPONSE_TOMBSTONE_RETENTION)
            .ok_or_else(|| McpError::internal_error("Tombstone retention exceeds clock range"))?;
        let Some(sender) = self.pending.remove(&key) else {
            return Ok(false);
        };
        self.tombstones.insert(key, expires_at);
        let _ = sender.send_blocking(Err(error));
        Ok(true)
    }

    /// Claims the sole cancellation-control attempt for `id`.
    ///
    /// The claim occurs before transport delivery. While the connection stays
    /// live, retrying the public API or racing a later local timeout is therefore
    /// an at-most-once no-op. Delivery failure terminates the connection, whose
    /// terminal cleanup may then release all retained markers.
    fn claim_cancellation_control(&mut self, id: &RequestId) -> McpResult<bool> {
        let now = Instant::now();
        self.prune_expired_retained_state(now);
        if let Some(terminal_error) = &self.terminal_error {
            return Err(terminal_error.clone());
        }
        let key = id
            .correlation_key()
            .map_err(|_| McpError::internal_error("Invalid JSON-RPC request ID"))?;
        if self.cancellation_controls.contains_key(&key) {
            return Ok(false);
        }
        if self.cancellation_controls.len() >= MAX_CANCELLATION_CONTROL_IDS {
            return Err(McpError::internal_error(
                "Client cancellation-control retention limit reached",
            ));
        }

        let expires_at = now
            .checked_add(CANCELLATION_CONTROL_RETENTION)
            .ok_or_else(|| {
                McpError::internal_error("Cancellation-control retention exceeds clock range")
            })?;
        self.cancellation_controls.insert(key, expires_at);
        Ok(true)
    }

    fn prune_expired_retained_state(&mut self, now: Instant) {
        self.tombstones.retain(|_, expires_at| *expires_at > now);
        self.cancellation_controls
            .retain(|_, expires_at| *expires_at > now);
    }

    fn fail_all(&mut self, error: McpError) -> usize {
        self.tombstones.clear();
        self.cancellation_controls.clear();
        if self.terminal_error.is_some() {
            return 0;
        }
        self.terminal_error = Some(error.clone());

        let mut failed = 0;
        for (_, sender) in self.pending.drain() {
            let _ = sender.send_blocking(Err(error.clone()));
            failed += 1;
        }
        failed
    }

    fn note_uncorrelated_response(&mut self, reason: &'static str) {
        if self.uncorrelated_diagnostics < MAX_UNCORRELATED_RESPONSE_DIAGNOSTICS {
            self.uncorrelated_diagnostics += 1;
            log::warn!("Discarding uncorrelated MCP response: {reason}");
        }
    }

    fn terminal_error(&self) -> Option<McpError> {
        self.terminal_error.clone()
    }

    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.pending.len()
    }

    #[cfg(test)]
    fn tombstone_len(&self) -> usize {
        self.tombstones.len()
    }

    #[cfg(test)]
    fn cancellation_control_len(&self) -> usize {
        self.cancellation_controls.len()
    }
}

impl Default for ResponseRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn invoke_tool_progress_callback(
    callback: ProgressCallback<'_>,
    progress: f64,
    total: Option<f64>,
    message: Option<&str>,
) -> McpResult<()> {
    catch_client_callback_unwind(|| {
        callback(progress, total, message);
    })
    .map_err(|_| McpError::internal_error(PROGRESS_CALLBACK_PANIC_ERROR))
}

fn invoke_task_progress_callback<F>(
    callback: &mut F,
    progress: f64,
    message: Option<&str>,
) -> McpResult<()>
where
    F: FnMut(f64, Option<&str>),
{
    catch_client_callback_unwind(|| {
        callback(progress, message);
    })
    .map_err(|_| McpError::internal_error(PROGRESS_CALLBACK_PANIC_ERROR))
}

/// An MCP client instance.
///
/// Clients are built using [`ClientBuilder`] and currently own a stdio
/// subprocess transport. SSE and WebSocket codecs remain lower-level
/// integration surfaces rather than connection modes of this type.
pub struct Client {
    /// The subprocess running the MCP server.
    child: Option<Child>,
    /// Live Unix group anchor and owner-death control descriptor.
    group_anchor: Option<ProcessGroupAnchor>,
    /// Scope that explicit shutdown must terminate and reap.
    child_ownership: ChildOwnership,
    /// Retry-safe cleanup phase for the retained subprocess identity.
    child_cleanup_phase: ClientChildCleanupPhase,
    /// Cleanup failure retained after a terminal connection error has already
    /// consumed the child handle. Explicit `close` must still surface it.
    cleanup_error: Option<McpError>,
    /// Latest retryable process-cleanup failure. This is cleared when a later
    /// close proves that the retained ownership scope is quiescent.
    pending_process_cleanup_error: Option<McpError>,
    /// Transport for communication.
    transport: StdioTransport<ChildStdout, ChildStdin>,
    /// Capability context for cancellation.
    cx: Cx,
    /// Session state after initialization.
    session: ClientSession,
    /// Request ID counter.
    next_id: AtomicU64,
    /// Strict response correlation for every in-flight request.
    responses: ResponseRegistry,
    /// Idle/absolute policy for ordinary stdio responses.
    ///
    /// Unix child pipes use bounded readiness polling, including while a peer
    /// is silent or holds a partial frame. On non-Unix targets, the standard
    /// child pipe has no portable safe readiness primitive, so the deadline is
    /// still observed only at complete-frame boundaries; synchronous response
    /// writes to child stdin are likewise not preemptible there. Bounded atomic
    /// cancellation controls are also unavailable there, so a required cancel
    /// or timeout control fails the connection explicitly.
    timeout_policy: RequestTimeoutPolicy,
    /// Whether auto-initialization is enabled (for documentation/debugging).
    #[allow(dead_code)]
    auto_initialize: bool,
    /// Whether the client has been initialized.
    initialized: AtomicBool,
    /// Terminal auto-initialization failure, preventing lifecycle retries on
    /// the same subprocess connection.
    initialization_error: Option<McpError>,
}

impl Client {
    fn retain_cleanup_error(&mut self, error: McpError) {
        self.cleanup_error = Some(match self.cleanup_error.take() {
            Some(previous) => combine_cleanup_errors(previous, error),
            None => error,
        });
    }

    fn stop_direct_peer(&mut self) -> McpResult<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        let result = stop_direct_child(&mut child);
        match result {
            Ok(()) => Ok(()),
            Err(error) => match child.try_wait() {
                Ok(Some(_)) => Ok(()),
                Ok(None) | Err(_) => {
                    self.child = Some(child);
                    Err(error)
                }
            },
        }
    }

    fn stop_direct_owned_child(&mut self) -> McpResult<()> {
        let result = self.stop_direct_peer();
        if result.is_ok() {
            self.child_cleanup_phase = ClientChildCleanupPhase::Complete;
        }
        result
    }

    #[cfg(unix)]
    fn stop_owned_child_group(&mut self) -> McpResult<()> {
        loop {
            match self.child_cleanup_phase {
                ClientChildCleanupPhase::Active => {
                    let Some(anchor) = self.group_anchor.as_mut() else {
                        let missing_anchor =
                            McpError::internal_error("Owned process-group cleanup lost its anchor");
                        let peer_result = self.stop_direct_peer();
                        if peer_result.is_ok() {
                            self.child_cleanup_phase = ClientChildCleanupPhase::Complete;
                        }
                        return combine_cleanup_results(Err(missing_anchor), peer_result);
                    };
                    match request_anchored_group_shutdown(anchor)? {
                        AnchoredGroupShutdown::KillAccepted(process_group) => {
                            self.child_cleanup_phase =
                                ClientChildCleanupPhase::GroupKillAccepted(process_group);
                        }
                        AnchoredGroupShutdown::IdentityLost(process_group) => {
                            self.child_cleanup_phase =
                                ClientChildCleanupPhase::GroupIdentityLost(process_group);
                        }
                    }
                }
                ClientChildCleanupPhase::GroupKillAccepted(process_group) => {
                    let peer_result = self.child.as_mut().map_or(Ok(()), reap_signalled_child);
                    if peer_result.is_ok() {
                        self.child = None;
                    }
                    let anchor_result = self.group_anchor.as_mut().map_or_else(
                        || {
                            Err(McpError::internal_error(
                                "Owned process-group cleanup lost its anchor",
                            ))
                        },
                        ProcessGroupAnchor::reap,
                    );
                    combine_cleanup_results(peer_result, anchor_result)?;
                    self.child_cleanup_phase =
                        ClientChildCleanupPhase::GroupChildrenReaped(process_group);
                }
                ClientChildCleanupPhase::GroupChildrenReaped(process_group) => {
                    wait_for_owned_process_group_quiescence(process_group)?;
                    self.child_cleanup_phase = ClientChildCleanupPhase::Complete;
                    return Ok(());
                }
                ClientChildCleanupPhase::GroupIdentityLost(process_group) => {
                    let peer_result = self.stop_direct_peer();
                    let group_result = require_owned_process_group_absent(process_group);
                    let result = combine_cleanup_results(peer_result, group_result);
                    if result.is_ok() {
                        self.child_cleanup_phase = ClientChildCleanupPhase::Complete;
                    }
                    return result;
                }
                ClientChildCleanupPhase::Complete => return Ok(()),
            }
        }
    }

    #[cfg(not(unix))]
    fn stop_owned_child_group(&mut self) -> McpResult<()> {
        Err(McpError::internal_error(
            "Owned subprocess groups are unavailable on this platform",
        ))
    }

    fn stop_retained_child(&mut self) -> McpResult<()> {
        if self.child_cleanup_phase == ClientChildCleanupPhase::Complete {
            if self.child.is_none() {
                return Ok(());
            }
            log::error!(
                "Repairing an invalid completed-cleanup state that retained a direct child handle"
            );
            return self.stop_direct_peer();
        }
        match self.child_ownership {
            ChildOwnership::DirectChild => self.stop_direct_owned_child(),
            ChildOwnership::OwnedProcessGroup => self.stop_owned_child_group(),
        }
    }

    /// Creates a client connecting to a subprocess via stdio.
    ///
    /// # Arguments
    ///
    /// * `command` - The command to run (e.g., "uvx", "npx")
    /// * `args` - Arguments to pass to the command
    ///
    /// # Errors
    ///
    /// Returns an error if the subprocess fails to start or initialization fails.
    pub fn stdio(command: &str, args: &[&str]) -> McpResult<Self> {
        block_on(async {
            let cx = Cx::current().expect("fastmcp runtime should install a current Cx");
            Self::stdio_with_cx(command, args, cx)
        })
    }

    /// Creates a client with a provided Cx for cancellation support.
    pub fn stdio_with_cx(command: &str, args: &[&str], cx: Cx) -> McpResult<Self> {
        // Preserve the long-standing direct convenience constructor as an
        // explicit exact-2024 connection. Callers that need an immutable
        // modern-only or auto-selection policy use the plan-aware entry point
        // below, which performs policy selection before exposing a client.
        Self::stdio_with_protocol_plan_with_cx(
            command,
            args,
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            cx,
        )
    }

    /// Creates a stdio client from an immutable protocol plan.
    ///
    /// `ModernOnly` performs a modern `server/discover` exchange, while
    /// `LegacyOnly` performs the exact 2024-11-05 initialization lifecycle.
    /// `Auto` first probes a disposable modern process and starts a fresh
    /// exact-2024 process only for a recognized discovery refusal. Transport
    /// failures and malformed modern discovery never authorize a downgrade.
    pub fn stdio_with_protocol_plan(
        command: &str,
        args: &[&str],
        protocol_plan: ClientProtocolPlan,
    ) -> McpResult<Self> {
        block_on(async {
            let cx = Cx::current().expect("fastmcp runtime should install a current Cx");
            Self::stdio_with_protocol_plan_with_cx(command, args, protocol_plan, cx)
        })
    }

    /// Creates a plan-aware stdio client with a caller-provided cancellation
    /// context.
    pub fn stdio_with_protocol_plan_with_cx(
        command: &str,
        args: &[&str],
        protocol_plan: ClientProtocolPlan,
        cx: Cx,
    ) -> McpResult<Self> {
        match protocol_plan.policy() {
            ProtocolPolicy::ModernOnly | ProtocolPolicy::LegacyOnly => {
                Self::connect_stdio_with_protocol_plan_once(command, args, protocol_plan, cx)
            }
            ProtocolPolicy::Auto => {
                let modern_plan = ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly);
                match Self::connect_stdio_with_protocol_plan_once(
                    command,
                    args,
                    modern_plan,
                    cx.clone(),
                ) {
                    Ok(mut client) => {
                        client.set_protocol_plan_after_selection(protocol_plan);
                        Ok(client)
                    }
                    Err(error) if auto_legacy_fallback_is_authorized(&error) => {
                        let legacy_plan = ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly);
                        let mut client = Self::connect_stdio_with_protocol_plan_once(
                            command,
                            args,
                            legacy_plan,
                            cx,
                        )?;
                        client.set_protocol_plan_after_selection(protocol_plan);
                        Ok(client)
                    }
                    Err(error) => Err(error),
                }
            }
        }
    }

    fn connect_stdio_with_protocol_plan_once(
        command: &str,
        args: &[&str],
        protocol_plan: ClientProtocolPlan,
        cx: Cx,
    ) -> McpResult<Self> {
        if cx.checkpoint().is_err() {
            return Err(McpError::request_cancelled());
        }

        // Spawn the subprocess
        let executable = resolve_stdio_command(command, None)?;
        let mut command = Command::new(executable);
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let child = command
            .spawn()
            .map_err(|e| McpError::internal_error(format!("Failed to spawn subprocess: {e}")))?;
        let mut child_guard = ChildGuard::new(child);

        // Get stdin/stdout handles
        let stdin = match child_guard.child_mut().stdin.take() {
            Some(stdin) => stdin,
            None => {
                return combine_operation_and_cleanup(
                    Err(McpError::internal_error("Failed to get subprocess stdin")),
                    child_guard.cleanup(),
                );
            }
        };
        let stdout = match child_guard.child_mut().stdout.take() {
            Some(stdout) => stdout,
            None => {
                return combine_operation_and_cleanup(
                    Err(McpError::internal_error("Failed to get subprocess stdout")),
                    child_guard.cleanup(),
                );
            }
        };

        // Create transport
        let transport = StdioTransport::new(stdout, stdin);

        // Create client info
        let client_info = ClientInfo {
            name: "fastmcp-client".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        let client_capabilities = ClientCapabilities::default();

        // Create a temporary client for initialization
        let mut client = Self {
            child: Some(child_guard.disarm()),
            group_anchor: None,
            child_ownership: ChildOwnership::DirectChild,
            child_cleanup_phase: ClientChildCleanupPhase::Active,
            cleanup_error: None,
            pending_process_cleanup_error: None,
            transport,
            cx,
            session: ClientSession::new(
                client_info.clone(),
                client_capabilities.clone(),
                ServerInfo {
                    name: String::new(),
                    version: String::new(),
                },
                ServerCapabilities::default(),
                String::new(),
            )
            .with_protocol_plan(protocol_plan.clone()),
            // `initialize()` consumes ID 1 through the same monotonic
            // allocator, leaving ID 2 as the first ordinary request ID.
            next_id: AtomicU64::new(1),
            responses: ResponseRegistry::new(),
            timeout_policy: RequestTimeoutPolicy::default(),
            auto_initialize: false,
            initialized: AtomicBool::new(false),
            initialization_error: None,
        };

        // Perform initialization handshake
        let init_result = match client.initialize(client_info, client_capabilities) {
            Ok(result) => result,
            Err(error) => {
                let cleanup = client.close();
                return combine_operation_and_cleanup(Err(error), cleanup);
            }
        };

        // Update session with server response
        let init_protocol_version = init_result.protocol_version.clone();
        let protocol_plan = client.session.protocol_plan().clone();
        client.session = ClientSession::new(
            client.session.client_info().clone(),
            client.session.client_capabilities().clone(),
            init_result.server_info,
            init_result.capabilities,
            init_result.protocol_version,
        )
        .with_protocol_plan(protocol_plan);

        // Send the spec-correct `notifications/initialized` lifecycle notification.
        if init_protocol_version == PROTOCOL_VERSION
            && let Err(error) = client.send_initialized_notification()
        {
            let cleanup = client.close();
            return combine_operation_and_cleanup(Err(error), cleanup);
        }

        // Mark as initialized
        client.initialized.store(true, Ordering::SeqCst);

        Ok(client)
    }

    fn set_protocol_plan_after_selection(&mut self, protocol_plan: ClientProtocolPlan) {
        let selected_era = self.session.selected_era();
        self.session = ClientSession::new(
            self.session.client_info().clone(),
            self.session.client_capabilities().clone(),
            self.session.server_info().clone(),
            self.session.server_capabilities().clone(),
            self.session.protocol_version().to_owned(),
        )
        .with_protocol_plan(protocol_plan);
        debug_assert!(self.session.selected_era() == selected_era);
    }

    /// Creates a new client builder.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Creates a client from its component parts.
    ///
    /// This is an internal constructor used by the builder.
    pub(crate) fn from_parts(
        child: Child,
        transport: StdioTransport<ChildStdout, ChildStdin>,
        cx: Cx,
        session: ClientSession,
        timeout_policy: RequestTimeoutPolicy,
    ) -> Self {
        Self::from_parts_with_ownership(
            child,
            ChildOwnership::DirectChild,
            None,
            transport,
            cx,
            session,
            timeout_policy,
        )
    }

    pub(crate) fn from_parts_with_ownership(
        child: Child,
        child_ownership: ChildOwnership,
        group_anchor: Option<ProcessGroupAnchor>,
        transport: StdioTransport<ChildStdout, ChildStdin>,
        cx: Cx,
        session: ClientSession,
        timeout_policy: RequestTimeoutPolicy,
    ) -> Self {
        Self {
            child: Some(child),
            group_anchor,
            child_ownership,
            child_cleanup_phase: ClientChildCleanupPhase::Active,
            cleanup_error: None,
            pending_process_cleanup_error: None,
            transport,
            cx,
            session,
            next_id: AtomicU64::new(2), // Start at 2 since initialize used 1
            responses: ResponseRegistry::new(),
            timeout_policy,
            auto_initialize: false,
            initialized: AtomicBool::new(true), // Already initialized by builder
            initialization_error: None,
        }
    }

    /// Creates an uninitialized client for auto-initialize mode.
    ///
    /// This is an internal constructor used by the builder when auto_initialize is enabled.
    pub(crate) fn from_parts_uninitialized(
        child: Child,
        transport: StdioTransport<ChildStdout, ChildStdin>,
        cx: Cx,
        session: ClientSession,
        timeout_policy: RequestTimeoutPolicy,
    ) -> Self {
        Self::from_parts_uninitialized_with_ownership(
            child,
            ChildOwnership::DirectChild,
            None,
            transport,
            cx,
            session,
            timeout_policy,
        )
    }

    pub(crate) fn from_parts_uninitialized_with_ownership(
        child: Child,
        child_ownership: ChildOwnership,
        group_anchor: Option<ProcessGroupAnchor>,
        transport: StdioTransport<ChildStdout, ChildStdin>,
        cx: Cx,
        session: ClientSession,
        timeout_policy: RequestTimeoutPolicy,
    ) -> Self {
        Self {
            child: Some(child),
            group_anchor,
            child_ownership,
            child_cleanup_phase: ClientChildCleanupPhase::Active,
            cleanup_error: None,
            pending_process_cleanup_error: None,
            transport,
            cx,
            session,
            next_id: AtomicU64::new(1), // Start at 1 since initialize hasn't happened
            responses: ResponseRegistry::new(),
            timeout_policy,
            auto_initialize: true,
            initialized: AtomicBool::new(false),
            initialization_error: None,
        }
    }

    /// Ensures the client is initialized.
    ///
    /// In auto-initialize mode, this performs the initialization handshake on first call.
    /// In normal mode, this is a no-op since the client is already initialized.
    ///
    /// Since this method takes `&mut self`, Rust's borrowing rules guarantee exclusive
    /// access, so no additional synchronization is needed.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub fn ensure_initialized(&mut self) -> McpResult<()> {
        if let Some(error) = self.responses.terminal_error() {
            return Err(error);
        }
        // Already initialized - nothing to do
        if self.initialized.load(Ordering::SeqCst) {
            return Ok(());
        }
        if let Some(error) = &self.initialization_error {
            return Err(error.clone());
        }

        // Perform initialization
        let client_info = self.session.client_info().clone();
        let capabilities = self.session.client_capabilities().clone();
        let init_result = match self.initialize(client_info, capabilities) {
            Ok(result) => result,
            Err(error) => return Err(self.record_initialization_failure(error)),
        };

        // Update session with server response
        let init_protocol_version = init_result.protocol_version.clone();
        let protocol_plan = self.session.protocol_plan().clone();
        self.session = ClientSession::new(
            self.session.client_info().clone(),
            self.session.client_capabilities().clone(),
            init_result.server_info,
            init_result.capabilities,
            init_result.protocol_version,
        )
        .with_protocol_plan(protocol_plan);

        // Exact 2024-11-05 transitions require the lifecycle acknowledgement.
        // Modern discovery has no corresponding initialized notification.
        if init_protocol_version == PROTOCOL_VERSION
            && let Err(error) = self.send_initialized_notification()
        {
            return Err(self.record_initialization_failure(error));
        }

        // Mark as initialized
        self.initialized.store(true, Ordering::SeqCst);

        Ok(())
    }

    fn record_initialization_failure(&mut self, error: McpError) -> McpError {
        self.initialization_error = Some(error.clone());
        self.terminate_connection(error)
    }

    /// Permanently closes a subprocess connection after a connection-wide
    /// protocol or I/O failure.
    ///
    /// A partial write can corrupt NDJSON framing, and a malformed inbound
    /// envelope makes peer state untrustworthy. Publish one terminal error to
    /// every waiter before dropping stdin and reaping the owned child so later
    /// public calls cannot retry on that connection.
    fn terminate_connection(&mut self, error: McpError) -> McpError {
        self.initialized.store(false, Ordering::SeqCst);
        self.responses.fail_all(error.clone());
        if let Err(cleanup_error) = self.transport.close().map_err(transport_error_to_mcp) {
            self.retain_cleanup_error(cleanup_error);
        }
        if let Err(cleanup_error) = self.stop_retained_child() {
            log::error!("Subprocess cleanup failed after terminal client error: {cleanup_error}");
            if self.child_cleanup_phase == ClientChildCleanupPhase::Complete {
                self.pending_process_cleanup_error = None;
                self.retain_cleanup_error(cleanup_error);
            } else {
                self.pending_process_cleanup_error = Some(cleanup_error);
            }
        } else {
            self.pending_process_cleanup_error = None;
        }
        error
    }

    /// Returns whether the client has been initialized.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    fn checkpoint_task_poll(&mut self) -> McpResult<()> {
        if self.cx.checkpoint().is_err() {
            return Err(self.terminate_connection(McpError::request_cancelled()));
        }
        Ok(())
    }

    /// Performs a bounded blocking wait at this client's synchronous stdio
    /// host boundary.
    ///
    /// The short slices are intentional: the pinned runtime does not expose a
    /// public cancellation-waker bridge for an arbitrary stored `Cx`. Each
    /// slice therefore re-enters the authoritative client context checkpoint
    /// instead of consulting an unrelated ambient runtime.
    fn wait_for_next_task_poll(&mut self, interval: Duration) -> McpResult<()> {
        self.checkpoint_task_poll()?;
        let interval = validate_task_poll_interval(interval)?;
        let deadline = Instant::now().checked_add(interval).ok_or_else(|| {
            McpError::invalid_params("Task poll interval exceeds the monotonic clock range")
        })?;

        loop {
            self.checkpoint_task_poll()?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return self.checkpoint_task_poll();
            }

            let mut slice = remaining.min(MAX_TASK_POLL_CANCEL_SLICE);
            if let Some(until_budget_deadline) = self.cx.budget().remaining_time(self.cx.now()) {
                slice = slice.min(until_budget_deadline);
            }
            std::thread::park_timeout(slice);
        }
    }

    /// Returns the server info after initialization.
    #[must_use]
    pub fn server_info(&self) -> &ServerInfo {
        self.session.server_info()
    }

    /// Returns the server capabilities after initialization.
    #[must_use]
    pub fn server_capabilities(&self) -> &ServerCapabilities {
        self.session.server_capabilities()
    }

    /// Returns the protocol version negotiated during initialization.
    #[must_use]
    pub fn protocol_version(&self) -> &str {
        self.session.protocol_version()
    }

    /// Returns the immutable policy selected before this client connected.
    #[must_use]
    pub const fn protocol_policy(&self) -> ProtocolPolicy {
        self.session.protocol_plan().policy()
    }

    /// Returns the era selected by the successful public initialization path.
    ///
    /// `None` means that initialization has not completed or a connection
    /// failed before a supported era was selected.
    #[must_use]
    pub const fn selected_protocol_era(&self) -> Option<ProtocolEra> {
        self.session.selected_era()
    }

    /// Returns the immutable transport policy and endpoint configuration.
    #[must_use]
    pub const fn protocol_plan(&self) -> &ClientProtocolPlan {
        self.session.protocol_plan()
    }

    /// Returns the timeout policy applied to subsequent ordinary requests.
    #[must_use]
    pub const fn request_timeout_policy(&self) -> RequestTimeoutPolicy {
        self.timeout_policy
    }

    /// Replaces the timeout policy applied to subsequent ordinary requests.
    ///
    /// # Errors
    ///
    /// Returns an invalid-parameters error without changing the current policy
    /// when either duration is below 1 millisecond or exceeds its hard ceiling.
    pub fn set_request_timeout_policy(&mut self, policy: RequestTimeoutPolicy) -> McpResult<()> {
        policy.validate()?;
        self.timeout_policy = policy;
        Ok(())
    }

    /// Verifies that the initialized server can answer an MCP ping request.
    ///
    /// # Errors
    ///
    /// Returns an error when initialization, transport, envelope validation,
    /// or the server's ping response fails.
    pub fn ping(&mut self) -> McpResult<()> {
        self.ensure_initialized()?;
        let _: serde_json::Value = self.send_request("ping", serde_json::json!({}))?;
        Ok(())
    }

    /// Generates the next request ID.
    fn next_request_id(&self) -> McpResult<u64> {
        self.next_id
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current
                    .checked_add(1)
                    .filter(|next| *next <= REQUEST_ID_EXHAUSTION_SENTINEL)
            })
            .map_err(|_| McpError::internal_error("Client request ID space exhausted"))
    }

    fn with_modern_request_metadata(
        &self,
        mut params: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        let parameters = params.as_object_mut().ok_or_else(|| {
            McpError::invalid_params("Modern MCP requests require object parameters")
        })?;
        let metadata = parameters
            .entry("_meta")
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        let metadata = metadata.as_object_mut().ok_or_else(|| {
            McpError::invalid_params("Modern MCP request metadata must be an object")
        })?;
        let final_metadata = FinalRequestMeta {
            protocol_version: MODERN_PROTOCOL_VERSION.to_owned(),
            client_capabilities: self.session.client_capabilities().clone(),
            client_info: Some(self.session.client_info().clone()),
            additional_metadata: Default::default(),
        };
        let final_metadata = serde_json::to_value(final_metadata).map_err(|error| {
            McpError::internal_error(format!(
                "Failed to serialize modern request metadata: {error}"
            ))
        })?;
        let final_metadata = final_metadata.as_object().ok_or_else(|| {
            McpError::internal_error("Modern request metadata did not serialize as an object")
        })?;
        metadata.extend(final_metadata.clone());
        Ok(params)
    }

    fn prepare_request_parameters(
        &self,
        params: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        if self.session.selected_era() == Some(ProtocolEra::Modern2026) {
            self.with_modern_request_metadata(params)
        } else {
            Ok(params)
        }
    }

    /// Sends a request and waits for response.
    fn send_request<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        method: &str,
        params: P,
    ) -> McpResult<R> {
        // Validate configuration before consuming an ID, registering a waiter,
        // or committing any bytes to the peer.
        let timeout_policy = self.timeout_policy;
        timeout_policy.validate()?;
        let params_value = serde_json::to_value(params)
            .map_err(|e| McpError::internal_error(format!("Failed to serialize params: {e}")))?;
        let params_value = self.prepare_request_parameters(params_value)?;
        let id = self.next_request_id()?;

        let (request_id, request) = {
            let id_i64 = i64::try_from(id).expect("request ID allocator enforces the i64 bound");
            (
                RequestId::Number(id_i64),
                JsonRpcRequest::new(method, Some(params_value), id_i64),
            )
        };

        // Register before the committed send so even an immediate response has
        // an exact owner in the shared-channel correlation registry.
        let waiter = self.responses.register(request_id.clone())?;

        if let Err(error) = self
            .transport
            .send(&self.cx, &JsonRpcMessage::Request(request))
        {
            let error = self.record_send_failure(Some(&request_id), error);
            return Err(error);
        }
        let committed_at = Instant::now();
        let deadlines = match RequestDeadlines::start_at(timeout_policy, committed_at) {
            Ok(deadlines) => deadlines,
            Err(error) => {
                return Err(self.finish_committed_request_locally(&request_id, error));
            }
        };

        // Receive response with ID validation
        let response = self.recv_response(waiter, deadlines)?;

        // Check for error response
        if let Some(error) = response.error {
            return Err(json_rpc_error_to_mcp(error));
        }

        // Parse result
        let result = response
            .result
            .ok_or_else(|| McpError::internal_error("No result in response"))?;

        decode_response_payload(result)
    }

    /// Sends a notification (no response expected).
    fn send_notification<P: serde::Serialize>(&mut self, method: &str, params: P) -> McpResult<()> {
        let params_value = serde_json::to_value(params)
            .map_err(|e| McpError::internal_error(format!("Failed to serialize params: {e}")))?;
        let params_value = self.prepare_request_parameters(params_value)?;

        // Create a notification (request without id)
        let request = JsonRpcRequest {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            method: method.to_string(),
            params: Some(params_value),
            id: None,
        };

        if let Err(error) = self
            .transport
            .send(&self.cx, &JsonRpcMessage::Request(request))
        {
            return Err(self.record_send_failure(None, error));
        }

        Ok(())
    }

    fn send_initialized_notification(&mut self) -> McpResult<()> {
        let notification = JsonRpcRequest::initialized_notification();
        if let Err(error) = self
            .transport
            .send(&self.cx, &JsonRpcMessage::Request(notification))
        {
            return Err(self.record_send_failure(None, error));
        }
        Ok(())
    }

    /// Sends a cancellation notification for a request ID known to the peer.
    ///
    /// Set `await_cleanup` to emit the provisional `awaitCleanup: true` wire
    /// field. This call does not wait for, correlate, or validate a peer cleanup
    /// acknowledgement; peer handling of the field remains server-dependent
    /// and unverified.
    /// The first call for an arbitrary request ID emits at most one bounded
    /// control frame; repeated calls for that ID are retained no-ops through the
    /// maximum ordinary-request lifetime. A successfully admitted later local
    /// request with the same ID begins a new generation. If the ID currently
    /// owns a local waiter, that waiter first receives local cancellation and
    /// its late response is discarded through a tombstone.
    ///
    /// On Unix child pipes the control write is one bounded, nonblocking atomic
    /// write. The standard library exposes no equivalent safe primitive for
    /// child stdin on non-Unix targets, so cancellation there fails the
    /// connection explicitly instead of risking an unbounded write.
    ///
    /// # Errors
    ///
    /// Returns an error if the notification cannot be sent.
    pub fn cancel_request(
        &mut self,
        request_id: impl Into<RequestId>,
        reason: Option<String>,
        await_cleanup: bool,
    ) -> McpResult<()> {
        let request_id = request_id.into();
        let control = cancellation_control_message(
            request_id.clone(),
            reason,
            await_cleanup.then_some(true),
        )?;
        self.ensure_initialized()?;

        let claimed = match self.responses.claim_cancellation_control(&request_id) {
            Ok(claimed) => claimed,
            Err(error) => return Err(self.terminate_connection(error)),
        };
        if !claimed {
            return Ok(());
        }

        if let Err(error) = self
            .responses
            .tombstone(&request_id, McpError::request_cancelled())
        {
            return Err(self.terminate_connection(error));
        }
        // Arbitrary peer-known, already-completed, and not-locally-owned IDs
        // still receive their one public cancellation control. The independent
        // marker does not poison future waiter registration for a locally
        // not-yet-issued ID.
        if let Err(control_error) = self.send_bounded_control_message(control) {
            let terminal = self.terminate_connection(control_error);
            return Err(terminal);
        }
        Ok(())
    }

    /// Records a transport send failure at the narrowest valid scope.
    ///
    /// Codec failures happen before a complete frame is committed and affect
    /// only the request being encoded. Every other send failure makes this
    /// shared stdio connection unusable (or observes its shared `Cx` as
    /// cancelled), so all registered waiters receive the same terminal error.
    fn record_send_failure(
        &mut self,
        request_id: Option<&RequestId>,
        error: TransportError,
    ) -> McpError {
        let is_connection_terminal = !matches!(&error, TransportError::Codec(_));
        let error = transport_error_to_mcp(error);

        if is_connection_terminal {
            return self.terminate_connection(error);
        } else if let Some(request_id) = request_id {
            self.responses.fail(request_id, error.clone());
        }

        error
    }

    fn send_bounded_control_message(&mut self, message: JsonRpcMessage) -> McpResult<()> {
        #[cfg(unix)]
        {
            self.transport
                .try_send_control_message(&message)
                .map_err(transport_error_to_mcp)
        }
        #[cfg(not(unix))]
        {
            let _ = message;
            Err(McpError::internal_error(
                "Nonblocking stdio control is unavailable on this platform",
            ))
        }
    }

    fn send_server_response_during_receive(&mut self, message: JsonRpcMessage) -> McpResult<()> {
        // A peer-controlled server request must not turn the surrounding
        // response deadline into an unbounded child-stdin write on platforms
        // where child pipes expose the required nonblocking primitive.
        send_child_server_response_during_receive(&mut self.transport, &self.cx, &message)
    }

    fn send_timeout_cancellation_control(&mut self, request_id: &RequestId) -> McpResult<()> {
        let control = cancellation_control_message(request_id.clone(), None, None)?;
        self.send_bounded_control_message(control)
    }

    fn finish_committed_request_locally(
        &mut self,
        request_id: &RequestId,
        outcome: McpError,
    ) -> McpError {
        let cancellation_claim = self.responses.claim_cancellation_control(request_id);
        match self.responses.tombstone(request_id, outcome.clone()) {
            Ok(true) => match cancellation_claim {
                Ok(true) => {
                    if let Err(control_error) = self.send_timeout_cancellation_control(request_id)
                        && self.responses.terminal_error().is_none()
                    {
                        let _ = self.terminate_connection(control_error);
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    let _ = self.terminate_connection(error);
                }
            },
            Ok(false) => {}
            Err(capacity_or_terminal_error) => {
                let _ = self.terminate_connection(capacity_or_terminal_error);
            }
        }
        outcome
    }

    fn timeout_committed_request(
        &mut self,
        request_id: &RequestId,
        source: RequestTimeoutSource,
    ) -> McpError {
        self.finish_committed_request_locally(request_id, request_timeout_error(source))
    }

    fn finish_partial_frame_timeout(
        &mut self,
        request_id: &RequestId,
        source: RequestTimeoutSource,
    ) -> McpError {
        let timeout = request_timeout_error(source);
        // The explicit deadline still consumes this ID's sole cancellation
        // marker. The transport has already failed closed on the partial frame,
        // so no control write can be attempted without replacing the selected
        // request-local timeout or violating frame alignment.
        let cancellation_claim = self.responses.claim_cancellation_control(request_id);
        // The peer supplied an incomplete NDJSON frame, so no aligned late
        // response can retire a tombstone. Preserve the request-local timeout
        // as first outcome, then fail the now-unusable connection with that
        // same typed source.
        let _ = self.responses.fail(request_id, timeout.clone());
        match cancellation_claim {
            Ok(_) => {
                let _ = self.terminate_connection(timeout.clone());
            }
            Err(error) => {
                let _ = self.terminate_connection(error);
            }
        }
        timeout
    }

    fn finish_open_context_interruption(
        &mut self,
        request_id: &RequestId,
        context_error: McpError,
    ) -> McpError {
        let outcome = self.finish_committed_request_locally(request_id, context_error);
        // The stored context belongs to this direct connection and remains
        // exhausted after the current request. Send the cancellation control
        // first, then make that connection-wide terminal state explicit.
        if self.responses.terminal_error().is_none() {
            let _ = self.terminate_connection(outcome.clone());
        }
        outcome
    }

    fn finish_timeout_after_complete_message(
        &mut self,
        request_id: &RequestId,
        message: JsonRpcMessage,
        source: RequestTimeoutSource,
    ) -> McpError {
        let timeout = request_timeout_error(source);
        if let Err(protocol_error) = validate_inbound_typed_message(&message) {
            let _ = self.responses.fail(request_id, timeout.clone());
            let _ = self.terminate_connection(protocol_error);
            return timeout;
        }

        let timeout = self.timeout_committed_request(request_id, source);
        if self.responses.terminal_error().is_some() {
            return timeout;
        }

        match message {
            JsonRpcMessage::Response(response) => {
                let route = self.responses.route(response);
                if matches!(
                    route,
                    ResponseRoute::InvalidEnvelope
                        | ResponseRoute::MissingId
                        | ResponseRoute::ConnectionClosed
                ) {
                    let terminal_error = self.responses.terminal_error().unwrap_or_else(|| {
                        McpError::internal_error("Client response correlation failed")
                    });
                    let _ = self.terminate_connection(terminal_error);
                }
            }
            JsonRpcMessage::Request(request) => {
                if let Some(response) = server_request_response(&request) {
                    if let Err(error) = self.send_bounded_control_message(response) {
                        let _ = self.terminate_connection(error);
                    }
                } else if server_notification_kind(&request)
                    == Some(ServerNotificationKind::LogMessage)
                    && let Some(params) = request.params.as_ref()
                    && let Ok(message) = serde_json::from_value::<LogMessageParams>(params.clone())
                {
                    self.emit_log_message(message);
                }
            }
        }
        timeout
    }

    /// Receives a response from the transport, validating the response ID.
    fn recv_response(
        &mut self,
        mut waiter: ResponseWaiter,
        deadlines: RequestDeadlines,
    ) -> McpResult<fastmcp_protocol::JsonRpcResponse> {
        let expected_id = waiter.id.clone();

        loop {
            if let Some(response) = waiter.try_response()? {
                debug_assert_eq!(response.id.as_ref(), Some(&expected_id));
                return Ok(response);
            }

            if let Some(kind) = deadlines.expired_at(Instant::now()) {
                return Err(self.timeout_committed_request(&expected_id, kind));
            }

            let (message, received_at) =
                match recv_child_transport(&mut self.transport, &self.cx, Some(deadlines.next())) {
                    Ok(received) => received,
                    Err(TransportError::ReceiveDeadlineExceeded) => {
                        let kind = deadlines
                            .expired_at(Instant::now())
                            .unwrap_or_else(|| deadlines.next_kind());
                        if self.transport.is_closed() {
                            return Err(self.finish_partial_frame_timeout(&expected_id, kind));
                        }
                        return Err(self.timeout_committed_request(&expected_id, kind));
                    }
                    Err(TransportError::Timeout) if !self.transport.is_closed() => {
                        return Err(self.finish_open_context_interruption(
                            &expected_id,
                            McpError::internal_error("Request timed out"),
                        ));
                    }
                    Err(TransportError::Cancelled) if !self.transport.is_closed() => {
                        return Err(self.finish_open_context_interruption(
                            &expected_id,
                            McpError::request_cancelled(),
                        ));
                    }
                    Err(error) => {
                        let error = transport_error_to_mcp(error);
                        return Err(self.terminate_connection(error));
                    }
                };
            if let Some(kind) = deadlines.expired_at(received_at) {
                return Err(self.finish_timeout_after_complete_message(
                    &expected_id,
                    message,
                    kind,
                ));
            }
            if let Err(error) = validate_inbound_typed_message(&message) {
                return Err(self.terminate_connection(error));
            }

            match message {
                JsonRpcMessage::Response(response) => {
                    // The registry preserves responses for other registered
                    // waiters and never lets an unknown/missing ID consume this
                    // request's response slot.
                    let route = self.responses.route(response);
                    if matches!(
                        route,
                        ResponseRoute::InvalidEnvelope
                            | ResponseRoute::MissingId
                            | ResponseRoute::ConnectionClosed
                    ) {
                        let error = self.responses.terminal_error().unwrap_or_else(|| {
                            McpError::internal_error("Client response correlation failed")
                        });
                        return Err(self.terminate_connection(error));
                    }
                }
                JsonRpcMessage::Request(request) => {
                    if let Some(response) = server_request_response(&request) {
                        if let Err(error) = self.send_server_response_during_receive(response) {
                            return Err(self.terminate_connection(error));
                        }
                        continue;
                    }

                    if server_notification_kind(&request)
                        == Some(ServerNotificationKind::LogMessage)
                    {
                        if let Some(params) = request.params.as_ref() {
                            if let Ok(message) =
                                serde_json::from_value::<LogMessageParams>(params.clone())
                            {
                                self.emit_log_message(message);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Performs the initialization handshake.
    fn initialize(
        &mut self,
        client_info: ClientInfo,
        capabilities: ClientCapabilities,
    ) -> McpResult<InitializeResult> {
        match self.session.protocol_plan().policy() {
            ProtocolPolicy::ModernOnly => self.initialize_modern(client_info, capabilities),
            // The public Auto entry point performs its isolated modern probe
            // before constructing this legacy client. Retaining this exact
            // path here keeps deferred initialization from converting a
            // configured legacy process into a second selection attempt.
            ProtocolPolicy::Auto | ProtocolPolicy::LegacyOnly => {
                self.initialize_legacy(client_info, capabilities)
            }
        }
    }

    fn initialize_legacy(
        &mut self,
        client_info: ClientInfo,
        capabilities: ClientCapabilities,
    ) -> McpResult<InitializeResult> {
        let params = InitializeParams {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities,
            client_info,
        };

        let result = self.send_request("initialize", params)?;
        validate_initialize_result(&result)?;
        Ok(result)
    }

    fn initialize_modern(
        &mut self,
        _client_info: ClientInfo,
        _capabilities: ClientCapabilities,
    ) -> McpResult<InitializeResult> {
        let params = serde_json::to_value(ServerDiscoverRequest::default())
            .map_err(|error| {
                McpError::internal_error(format!(
                    "Failed to serialize modern server/discover parameters: {error}"
                ))
            })
            .and_then(|params| self.with_modern_request_metadata(params))?;
        let result: serde_json::Value = self.send_request(SERVER_DISCOVER_METHOD, params)?;
        serde_json::from_value::<ServerDiscoverResult>(result.clone()).map_err(|_| {
            McpError::internal_error("Invalid modern server/discover response payload")
        })?;
        let server_info = result
            .get("serverInfo")
            .cloned()
            .ok_or_else(|| {
                McpError::internal_error("Modern server/discover response has no serverInfo")
            })
            .and_then(|value| {
                serde_json::from_value(value).map_err(|_| {
                    McpError::internal_error(
                        "Modern server/discover response has invalid serverInfo",
                    )
                })
            })?;
        Ok(InitializeResult {
            protocol_version: MODERN_PROTOCOL_VERSION.to_owned(),
            capabilities: ServerCapabilities::default(),
            server_info,
            instructions: None,
        })
    }

    /// Lists available tools.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
        self.ensure_initialized()?;
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut budget = PaginationBudget::new();

        loop {
            budget.begin_page()?;
            let mut params = ListToolsParams::default();
            params.cursor = cursor.clone();
            let result: ListToolsResult = self.send_request("tools/list", params)?;
            budget.account_page(&result.tools)?;
            all.extend(result.tools);
            cursor = budget.admit_next_cursor(result.next_cursor)?;
            if cursor.is_none() {
                break;
            }
        }

        Ok(all)
    }

    /// Acquires at most one bounded page of tools.
    ///
    /// Unlike [`Self::list_tools`], this method never follows the peer's next
    /// cursor. [`BoundedListPage::local_truncated`] reports entries omitted from
    /// the current peer page, while [`BoundedListPage::peer_has_more`] reports a
    /// peer-provided following page.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller's limits or cursor are invalid, the
    /// request fails, or the peer returns an oversized or non-advancing cursor.
    pub fn list_tools_page(
        &mut self,
        cursor: Option<&str>,
        limits: ListPageLimits,
    ) -> McpResult<BoundedListPage<Tool>> {
        let cursor_parameter = validate_list_page_request(cursor, limits)?;
        self.ensure_initialized()?;
        let params = ListToolsParams {
            cursor: cursor_parameter,
            ..ListToolsParams::default()
        };
        let result: ListToolsResult = self.send_request("tools/list", params)?;
        bounded_list_page(result.tools, cursor, result.next_cursor, limits)
    }

    /// Calls a tool with the given arguments.
    ///
    /// # Errors
    ///
    /// Returns an error if the tool call fails.
    pub fn call_tool(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<Vec<Content>> {
        self.ensure_initialized()?;
        let params = CallToolParams {
            name: name.to_string(),
            arguments: Some(arguments),
            meta: None,
        };
        let result: CallToolResult = self.send_request("tools/call", params)?;

        if result.is_error {
            // Extract error message from content if available
            let error_msg = result
                .content
                .first()
                .and_then(|c| match c {
                    Content::Text { text } => Some(text.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| "Tool execution failed".to_string());
            return Err(McpError::tool_error(error_msg));
        }

        Ok(result.content)
    }

    /// Calls a tool with progress callback support.
    ///
    /// This method allows you to receive progress notifications during tool execution.
    /// The callback is invoked for each progress notification received from the server.
    ///
    /// # Arguments
    ///
    /// * `name` - The tool name to call
    /// * `arguments` - The tool arguments as JSON
    /// * `on_progress` - Callback invoked for each progress notification
    ///
    /// # Errors
    ///
    /// Returns an error if the tool call fails.
    pub fn call_tool_with_progress(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
        on_progress: ProgressCallback<'_>,
    ) -> McpResult<Vec<Content>> {
        self.ensure_initialized()?;
        // Validate before allocating the ID that is also exposed as the
        // progress token. The inner request path validates again immediately
        // before registration so it remains safe when called directly.
        let timeout_policy = self.timeout_policy;
        timeout_policy.validate()?;
        // Generate a unique request ID and reuse it as the progress token.
        let request_id = self.next_request_id()?;
        let progress_marker = ProgressMarker::Number(
            i64::try_from(request_id).expect("request ID allocator enforces the i64 bound"),
        );

        let params = CallToolParams {
            name: name.to_string(),
            arguments: Some(arguments),
            meta: Some(RequestMeta {
                progress_marker: Some(progress_marker.clone()),
            }),
        };

        let result: CallToolResult = self.send_request_with_progress(
            "tools/call",
            params,
            request_id,
            &progress_marker,
            on_progress,
        )?;

        if result.is_error {
            // Extract error message from content if available
            let error_msg = result
                .content
                .first()
                .and_then(|c| match c {
                    Content::Text { text } => Some(text.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| "Tool execution failed".to_string());
            return Err(McpError::tool_error(error_msg));
        }

        Ok(result.content)
    }

    /// Sends a request and waits for response, handling progress notifications.
    fn send_request_with_progress<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        method: &str,
        params: P,
        request_id: u64,
        expected_marker: &ProgressMarker,
        on_progress: ProgressCallback<'_>,
    ) -> McpResult<R> {
        // Validate configuration before serialization, waiter registration, or
        // protocol commitment. The caller already owns `request_id`, so this
        // specifically prevents an invalid duration from creating live state.
        let timeout_policy = self.timeout_policy;
        timeout_policy.validate()?;
        let params_value = serde_json::to_value(params)
            .map_err(|e| McpError::internal_error(format!("Failed to serialize params: {e}")))?;
        let params_value = self.prepare_request_parameters(params_value)?;

        let request_id = RequestId::Number(
            i64::try_from(request_id).expect("request ID allocator enforces the i64 bound"),
        );
        let request = JsonRpcRequest::new(method, Some(params_value), request_id.clone());

        let waiter = self.responses.register(request_id.clone())?;

        if let Err(error) = self
            .transport
            .send(&self.cx, &JsonRpcMessage::Request(request))
        {
            let error = self.record_send_failure(Some(&request_id), error);
            return Err(error);
        }
        let committed_at = Instant::now();
        let deadlines = match RequestDeadlines::start_at(timeout_policy, committed_at) {
            Ok(deadlines) => deadlines,
            Err(error) => {
                return Err(self.finish_committed_request_locally(&request_id, error));
            }
        };

        // Receive response, handling progress notifications
        let response = self.recv_response_with_progress(
            waiter,
            expected_marker,
            on_progress,
            timeout_policy,
            deadlines,
        )?;

        // Check for error response
        if let Some(error) = response.error {
            return Err(json_rpc_error_to_mcp(error));
        }

        // Parse result
        let result = response
            .result
            .ok_or_else(|| McpError::internal_error("No result in response"))?;

        decode_response_payload(result)
    }

    /// Receives a response from the transport, handling progress notifications.
    fn recv_response_with_progress(
        &mut self,
        mut waiter: ResponseWaiter,
        expected_marker: &ProgressMarker,
        on_progress: ProgressCallback<'_>,
        timeout_policy: RequestTimeoutPolicy,
        mut deadlines: RequestDeadlines,
    ) -> McpResult<fastmcp_protocol::JsonRpcResponse> {
        let expected_id = waiter.id.clone();
        let mut last_progress = None;

        loop {
            if let Some(response) = waiter.try_response()? {
                debug_assert_eq!(response.id.as_ref(), Some(&expected_id));
                return Ok(response);
            }

            if let Some(kind) = deadlines.expired_at(Instant::now()) {
                return Err(self.timeout_committed_request(&expected_id, kind));
            }

            let (message, received_at) =
                match recv_child_transport(&mut self.transport, &self.cx, Some(deadlines.next())) {
                    Ok(received) => received,
                    Err(TransportError::ReceiveDeadlineExceeded) => {
                        let kind = deadlines
                            .expired_at(Instant::now())
                            .unwrap_or_else(|| deadlines.next_kind());
                        if self.transport.is_closed() {
                            return Err(self.finish_partial_frame_timeout(&expected_id, kind));
                        }
                        return Err(self.timeout_committed_request(&expected_id, kind));
                    }
                    Err(TransportError::Timeout) if !self.transport.is_closed() => {
                        return Err(self.finish_open_context_interruption(
                            &expected_id,
                            McpError::internal_error("Request timed out"),
                        ));
                    }
                    Err(TransportError::Cancelled) if !self.transport.is_closed() => {
                        return Err(self.finish_open_context_interruption(
                            &expected_id,
                            McpError::request_cancelled(),
                        ));
                    }
                    Err(error) => {
                        let error = transport_error_to_mcp(error);
                        return Err(self.terminate_connection(error));
                    }
                };
            if let Some(kind) = deadlines.expired_at(received_at) {
                return Err(self.finish_timeout_after_complete_message(
                    &expected_id,
                    message,
                    kind,
                ));
            }
            if let Err(error) = validate_inbound_typed_message(&message) {
                return Err(self.terminate_connection(error));
            }

            match message {
                JsonRpcMessage::Response(response) => {
                    let route = self.responses.route(response);
                    if matches!(
                        route,
                        ResponseRoute::InvalidEnvelope
                            | ResponseRoute::MissingId
                            | ResponseRoute::ConnectionClosed
                    ) {
                        let error = self.responses.terminal_error().unwrap_or_else(|| {
                            McpError::internal_error("Client response correlation failed")
                        });
                        return Err(self.terminate_connection(error));
                    }
                }
                JsonRpcMessage::Request(request) => {
                    if let Some(response) = server_request_response(&request) {
                        if let Err(error) = self.send_server_response_during_receive(response) {
                            return Err(self.terminate_connection(error));
                        }
                        continue;
                    }

                    if server_notification_kind(&request) == Some(ServerNotificationKind::Progress)
                    {
                        if let Some(params) = request.params.as_ref()
                            && let Some(progress) =
                                parse_valid_client_progress(params, last_progress)
                            && progress.marker == *expected_marker
                        {
                            if invoke_tool_progress_callback(
                                &mut *on_progress,
                                progress.progress,
                                progress.total,
                                progress.message.as_deref(),
                            )
                            .is_err()
                            {
                                let error = McpError::internal_error(PROGRESS_CALLBACK_PANIC_ERROR);
                                return Err(
                                    self.finish_committed_request_locally(&expected_id, error)
                                );
                            }
                            last_progress = Some(progress.progress);
                            if timeout_policy.reset_idle_on_matching_progress
                                && let Err(error) = deadlines.reset_idle_at(received_at)
                            {
                                return Err(
                                    self.finish_committed_request_locally(&expected_id, error)
                                );
                            }
                        }
                    } else if server_notification_kind(&request)
                        == Some(ServerNotificationKind::LogMessage)
                    {
                        if let Some(params) = request.params.as_ref() {
                            if let Ok(message) =
                                serde_json::from_value::<LogMessageParams>(params.clone())
                            {
                                self.emit_log_message(message);
                            }
                        }
                    }
                    // Continue waiting for actual response
                }
            }
        }
    }

    fn emit_log_message(&self, message: LogMessageParams) {
        let level = match message.level {
            LogLevel::Debug => log::Level::Debug,
            LogLevel::Info => log::Level::Info,
            LogLevel::Warning => log::Level::Warn,
            LogLevel::Error => log::Level::Error,
        };
        let metadata = remote_log_metadata(&message);
        log::log!(target: REMOTE_LOG_TARGET, level, "{metadata}");
    }

    /// Lists available resources.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
        self.ensure_initialized()?;
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut budget = PaginationBudget::new();

        loop {
            budget.begin_page()?;
            let mut params = ListResourcesParams::default();
            params.cursor = cursor.clone();
            let result: ListResourcesResult = self.send_request("resources/list", params)?;
            budget.account_page(&result.resources)?;
            all.extend(result.resources);
            cursor = budget.admit_next_cursor(result.next_cursor)?;
            if cursor.is_none() {
                break;
            }
        }

        Ok(all)
    }

    /// Acquires at most one bounded page of resources.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller's limits or cursor are invalid, the
    /// request fails, or the peer returns an oversized or non-advancing cursor.
    pub fn list_resources_page(
        &mut self,
        cursor: Option<&str>,
        limits: ListPageLimits,
    ) -> McpResult<BoundedListPage<Resource>> {
        let cursor_parameter = validate_list_page_request(cursor, limits)?;
        self.ensure_initialized()?;
        let params = ListResourcesParams {
            cursor: cursor_parameter,
            ..ListResourcesParams::default()
        };
        let result: ListResourcesResult = self.send_request("resources/list", params)?;
        bounded_list_page(result.resources, cursor, result.next_cursor, limits)
    }

    /// Lists available resource templates.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
        self.ensure_initialized()?;
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut budget = PaginationBudget::new();

        loop {
            budget.begin_page()?;
            let mut params = ListResourceTemplatesParams::default();
            params.cursor = cursor.clone();
            let result: ListResourceTemplatesResult =
                self.send_request("resources/templates/list", params)?;
            budget.account_page(&result.resource_templates)?;
            all.extend(result.resource_templates);
            cursor = budget.admit_next_cursor(result.next_cursor)?;
            if cursor.is_none() {
                break;
            }
        }

        Ok(all)
    }

    /// Acquires at most one bounded page of resource templates.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller's limits or cursor are invalid, the
    /// request fails, or the peer returns an oversized or non-advancing cursor.
    pub fn list_resource_templates_page(
        &mut self,
        cursor: Option<&str>,
        limits: ListPageLimits,
    ) -> McpResult<BoundedListPage<ResourceTemplate>> {
        let cursor_parameter = validate_list_page_request(cursor, limits)?;
        self.ensure_initialized()?;
        let params = ListResourceTemplatesParams {
            cursor: cursor_parameter,
            ..ListResourceTemplatesParams::default()
        };
        let result: ListResourceTemplatesResult =
            self.send_request("resources/templates/list", params)?;
        bounded_list_page(
            result.resource_templates,
            cursor,
            result.next_cursor,
            limits,
        )
    }

    /// Sets the server log level (if supported).
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn set_log_level(&mut self, level: LogLevel) -> McpResult<()> {
        self.ensure_initialized()?;
        let params = SetLogLevelParams { level };
        let _: serde_json::Value = self.send_request("logging/setLevel", params)?;
        Ok(())
    }

    /// Reads a resource by URI.
    ///
    /// # Errors
    ///
    /// Returns an error if the resource cannot be read.
    pub fn read_resource(&mut self, uri: &str) -> McpResult<Vec<ResourceContent>> {
        self.ensure_initialized()?;
        let params = ReadResourceParams {
            uri: uri.to_string(),
            meta: None,
        };
        let result: ReadResourceResult = self.send_request("resources/read", params)?;
        Ok(result.contents)
    }

    /// Lists available prompts.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
        self.ensure_initialized()?;
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut budget = PaginationBudget::new();

        loop {
            budget.begin_page()?;
            let mut params = ListPromptsParams::default();
            params.cursor = cursor.clone();
            let result: ListPromptsResult = self.send_request("prompts/list", params)?;
            budget.account_page(&result.prompts)?;
            all.extend(result.prompts);
            cursor = budget.admit_next_cursor(result.next_cursor)?;
            if cursor.is_none() {
                break;
            }
        }

        Ok(all)
    }

    /// Acquires at most one bounded page of prompts.
    ///
    /// # Errors
    ///
    /// Returns an error if the caller's limits or cursor are invalid, the
    /// request fails, or the peer returns an oversized or non-advancing cursor.
    pub fn list_prompts_page(
        &mut self,
        cursor: Option<&str>,
        limits: ListPageLimits,
    ) -> McpResult<BoundedListPage<Prompt>> {
        let cursor_parameter = validate_list_page_request(cursor, limits)?;
        self.ensure_initialized()?;
        let params = ListPromptsParams {
            cursor: cursor_parameter,
            ..ListPromptsParams::default()
        };
        let result: ListPromptsResult = self.send_request("prompts/list", params)?;
        bounded_list_page(result.prompts, cursor, result.next_cursor, limits)
    }

    /// Gets a prompt with the given arguments.
    ///
    /// # Errors
    ///
    /// Returns an error if the prompt cannot be retrieved.
    pub fn get_prompt(
        &mut self,
        name: &str,
        arguments: std::collections::HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        self.ensure_initialized()?;
        let params = GetPromptParams {
            name: name.to_string(),
            arguments: if arguments.is_empty() {
                None
            } else {
                Some(arguments)
            },
            meta: None,
        };
        let result: GetPromptResult = self.send_request("prompts/get", params)?;
        Ok(result.messages)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Task Management (Docket/SEP-1686)
    // ═══════════════════════════════════════════════════════════════════════

    /// Submits a background task for execution.
    ///
    /// # Arguments
    ///
    /// * `task_type` - The type of task to execute (e.g., "data_export", "batch_process")
    /// * `input` - Task parameters as JSON
    ///
    /// # Errors
    ///
    /// Returns an error if the server doesn't support tasks, the request fails,
    /// or the server returns a contradictory task snapshot. A contradictory
    /// peer snapshot terminates the connection.
    pub fn submit_task(
        &mut self,
        task_type: &str,
        input: serde_json::Value,
    ) -> McpResult<TaskInfo> {
        self.ensure_initialized()?;
        let params = SubmitTaskParams {
            task_type: task_type.to_string(),
            params: Some(input),
        };
        let result: SubmitTaskResult = self.send_request("tasks/submit", params)?;
        if let Err(error) = validate_task_info(&result.task) {
            return Err(self.terminate_connection(error));
        }
        Ok(result.task)
    }

    /// Lists tasks with optional status filter.
    ///
    /// # Arguments
    ///
    /// * `status` - Optional filter by task status
    /// * `cursor` - Optional pagination cursor from previous response
    ///
    /// # Errors
    ///
    /// Returns an error if the server doesn't support tasks, the request fails,
    /// or any returned task snapshot is contradictory. A contradictory peer
    /// snapshot terminates the connection.
    pub fn list_tasks(
        &mut self,
        status: Option<TaskStatus>,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> McpResult<ListTasksResult> {
        self.ensure_initialized()?;
        let params = ListTasksParams {
            cursor: cursor.map(ToString::to_string),
            limit,
            status,
        };
        let result: ListTasksResult = self.send_request("tasks/list", params)?;
        if let Some(error) = result
            .tasks
            .iter()
            .find_map(|task| validate_task_info(task).err())
        {
            return Err(self.terminate_connection(error));
        }
        Ok(result)
    }

    /// Lists all tasks by following pagination cursors until exhaustion.
    ///
    /// # Errors
    ///
    /// Returns an error if any request fails.
    pub fn list_tasks_all(&mut self, status: Option<TaskStatus>) -> McpResult<Vec<TaskInfo>> {
        self.ensure_initialized()?;
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut budget = PaginationBudget::new();

        loop {
            budget.begin_page()?;
            let result = self.list_tasks(status, cursor.as_deref(), Some(200))?;
            budget.account_page(&result.tasks)?;
            all.extend(result.tasks);
            cursor = budget.admit_next_cursor(result.next_cursor)?;
            if cursor.is_none() {
                break;
            }
        }

        Ok(all)
    }

    /// Gets detailed information about a specific task.
    ///
    /// # Arguments
    ///
    /// * `task_id` - The task ID to retrieve
    ///
    /// # Errors
    ///
    /// Returns an error if the task is not found, the request fails, or the
    /// response contradicts the requested task or its terminal result. A
    /// contradictory peer response terminates the connection.
    pub fn get_task(&mut self, task_id: &str) -> McpResult<GetTaskResult> {
        self.ensure_initialized()?;
        let requested_id = TaskId::from_string(task_id);
        let params = GetTaskParams {
            id: requested_id.clone(),
        };
        let result = self.send_request("tasks/get", params)?;
        if let Err(error) = validate_get_task_result(&requested_id, &result) {
            return Err(self.terminate_connection(error));
        }
        Ok(result)
    }

    /// Cancels a running or pending task.
    ///
    /// # Arguments
    ///
    /// * `task_id` - The task ID to cancel
    ///
    /// # Errors
    ///
    /// Returns an error if the task cannot be cancelled, is already complete,
    /// or the acknowledgement is contradictory. An accepted acknowledgement
    /// is eventual and does not prove that the returned snapshot is terminal.
    /// A contradictory peer acknowledgement terminates the connection.
    pub fn cancel_task(&mut self, task_id: &str) -> McpResult<TaskInfo> {
        self.cancel_task_with_reason(task_id, None)
    }

    /// Cancels a running or pending task with an optional reason.
    ///
    /// # Arguments
    ///
    /// * `task_id` - The task ID to cancel
    /// * `reason` - Optional reason for the cancellation
    ///
    /// # Errors
    ///
    /// Returns an error if the task cannot be cancelled, is already complete,
    /// or the acknowledgement is contradictory. An accepted acknowledgement
    /// is eventual and does not prove that the returned snapshot is terminal.
    /// A contradictory peer acknowledgement terminates the connection.
    pub fn cancel_task_with_reason(
        &mut self,
        task_id: &str,
        reason: Option<&str>,
    ) -> McpResult<TaskInfo> {
        self.ensure_initialized()?;
        let requested_id = TaskId::from_string(task_id);
        let params = CancelTaskParams {
            id: requested_id.clone(),
            reason: reason.map(ToString::to_string),
        };
        let result: CancelTaskResult = self.send_request("tasks/cancel", params)?;
        if let Err(error) = validate_cancel_task_result(&requested_id, &result) {
            return Err(self.terminate_connection(error));
        }
        if !result.cancelled {
            return Err(McpError::invalid_request(
                "Server did not accept the task cancellation request",
            ));
        }
        Ok(result.task)
    }

    /// Waits for a task to complete by polling.
    ///
    /// This method polls the server at the specified interval until the task
    /// reaches a terminal state (completed, failed, or cancelled).
    ///
    /// # Arguments
    ///
    /// * `task_id` - The task ID to wait for
    /// * `poll_interval` - Local fallback between polls, from 1 ms through 5 minutes
    ///
    /// # Errors
    ///
    /// Returns an error if the local interval is outside the documented range
    /// or polling or response validation fails. Failed and cancelled tasks are
    /// returned as successful method outcomes with [`TaskResult::success`] set
    /// to `false`.
    pub fn wait_for_task(
        &mut self,
        task_id: &str,
        poll_interval: Duration,
    ) -> McpResult<TaskResult> {
        let poll_interval = validate_task_poll_interval(poll_interval)?;
        loop {
            let result = self.get_task(task_id)?;

            // Check if task is complete
            if result.task.status.is_terminal() {
                // If task has a result, return it
                if let Some(task_result) = result.result {
                    return Ok(task_result);
                }

                // Failed and cancelled tasks may carry only TaskInfo error details.
                return Ok(TaskResult {
                    id: result.task.id,
                    success: false,
                    data: None,
                    error: result.task.error,
                });
            }

            self.wait_for_next_task_poll(poll_interval)?;
        }
    }

    /// Waits for a task with progress callback.
    ///
    /// Similar to `wait_for_task` but also provides progress information via callback.
    ///
    /// # Arguments
    ///
    /// * `task_id` - The task ID to wait for
    /// * `poll_interval` - Local fallback between polls, from 1 ms through 5 minutes
    /// * `on_progress` - Callback invoked with progress updates
    ///
    /// # Errors
    ///
    /// Returns an error if the local interval is outside the documented range
    /// or polling, callback execution, or response validation fails. Failed
    /// and cancelled tasks are returned as successful method outcomes with
    /// [`TaskResult::success`] set to `false`.
    pub fn wait_for_task_with_progress<F>(
        &mut self,
        task_id: &str,
        poll_interval: Duration,
        mut on_progress: F,
    ) -> McpResult<TaskResult>
    where
        F: FnMut(f64, Option<&str>),
    {
        let poll_interval = validate_task_poll_interval(poll_interval)?;
        loop {
            let result = self.get_task(task_id)?;

            // Report progress if available
            if let Some(progress) = result.task.progress {
                invoke_task_progress_callback(
                    &mut on_progress,
                    progress,
                    result.task.message.as_deref(),
                )?;
            }

            // Check if task is complete
            if result.task.status.is_terminal() {
                // If task has a result, return it
                if let Some(task_result) = result.result {
                    return Ok(task_result);
                }

                // Failed and cancelled tasks may carry only TaskInfo error details.
                return Ok(TaskResult {
                    id: result.task.id,
                    success: false,
                    data: None,
                    error: result.task.error,
                });
            }

            self.wait_for_next_task_poll(poll_interval)?;
        }
    }

    /// Closes the client connection and verifies bounded subprocess cleanup.
    ///
    /// Drop remains a best-effort safety net. Callers that need to prove that
    /// an owned subprocess (or configured Unix process group) was stopped must
    /// use this explicit method and handle its result. A successful close is
    /// idempotent. Retryable process cleanup failures retain the child handle
    /// and phase so callers may invoke `close` again without re-signalling a
    /// process group after its leader has been reaped.
    ///
    /// Subprocess verification assumes this client exclusively reaps the
    /// retained direct children. Process-wide `waitpid(-1)` consumers,
    /// `SIGCHLD=SIG_IGN`, and `SA_NOCLDWAIT` can consume that evidence before
    /// FastMCP observes it; in that case cleanup fails closed instead of
    /// signalling an identity that is no longer proven. Unix process-group
    /// ownership also cannot contain descendants that deliberately change
    /// process group/session, or guarantee owner-death cleanup while a
    /// host-side `fork` retains a copy of the private control descriptor
    /// (including a concurrent setup-time fork on Unix targets without atomic
    /// close-on-exec socket-pair creation).
    ///
    /// # Errors
    ///
    /// Returns an error when the transport cannot be closed, process state
    /// cannot be established, signalling fails, or the subprocess cannot be
    /// reaped within the cleanup deadline.
    pub fn close(&mut self) -> McpResult<()> {
        self.initialized.store(false, Ordering::SeqCst);
        self.responses
            .fail_all(McpError::internal_error("Client connection closed"));

        // Transport teardown is one-shot. Preserve any failure because a
        // consumed writer cannot make a later close prove that the earlier
        // flush/close succeeded.
        let transport_result = self.transport.close().map_err(transport_error_to_mcp);
        if let Err(error) = transport_result {
            self.retain_cleanup_error(error);
        }

        // Process teardown is phaseful and retryable. Only an error from a
        // terminal phase becomes sticky; a later successful quiescence proof
        // clears the prior attempt's transient failure.
        let process_result = self.stop_retained_child();
        let retryable_process_result = match process_result {
            Ok(()) => {
                self.pending_process_cleanup_error = None;
                Ok(())
            }
            Err(error) if self.child_cleanup_phase == ClientChildCleanupPhase::Complete => {
                self.pending_process_cleanup_error = None;
                self.retain_cleanup_error(error);
                Ok(())
            }
            Err(error) => {
                self.pending_process_cleanup_error = Some(error.clone());
                Err(error)
            }
        };
        let sticky_result = self.cleanup_error.clone().map_or(Ok(()), Err);
        let result = combine_cleanup_results(sticky_result, retryable_process_result);
        if result.is_ok() {
            self.pending_process_cleanup_error = None;
        }
        result
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // Drop cannot report cleanup failure or create an orphan cleanup task;
        // callers requiring proof must call close() and handle its result.
        self.responses
            .fail_all(McpError::internal_error("Client connection closed"));
        let _ = self.transport.close();
        if let Err(error) = self.stop_retained_child() {
            log::error!("Client drop could not verify subprocess cleanup: {error}");
        }
    }
}

/// Converts a TransportError to McpError.
pub(crate) fn transport_error_to_mcp(e: TransportError) -> McpError {
    match e {
        TransportError::Cancelled => McpError::request_cancelled(),
        TransportError::Closed => McpError::internal_error("Transport closed"),
        TransportError::Timeout | TransportError::ReceiveDeadlineExceeded => {
            McpError::internal_error("Request timed out")
        }
        TransportError::ControlFrameTooLarge { .. } => {
            McpError::internal_error(CONTROL_FRAME_CAPACITY_ERROR)
        }
        TransportError::Io(io_err) => McpError::internal_error(format!("I/O error: {io_err}")),
        // Typed codec failures can contain serde diagnostics that echo an
        // attacker-controlled enum value or control characters. The peer's
        // frame is never safe diagnostic text, so expose a fixed error here.
        TransportError::Codec(_) => McpError::internal_error(TRANSPORT_CODEC_ERROR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::process::{Command, Stdio};

    fn task_info(id: &str, status: TaskStatus) -> TaskInfo {
        TaskInfo {
            id: TaskId::from_string(id),
            task_type: "test".to_string(),
            status,
            progress: None,
            message: None,
            created_at: "2026-08-01T00:00:00Z".to_string(),
            started_at: None,
            completed_at: status
                .is_terminal()
                .then(|| "2026-08-01T00:00:01Z".to_string()),
            error: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn spawn_long_running_child() -> (Child, ChildStdout, ChildStdin, u32) {
        let mut command = Command::new("sleep");
        command
            .arg("60")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().expect("spawn long-running child");
        let pid = child.id();
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        (child, stdout, stdin, pid)
    }

    #[cfg(target_os = "linux")]
    fn wait_for_process_exit(pid: u32) {
        let process = std::path::PathBuf::from(format!("/proc/{pid}"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while process.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            !process.exists(),
            "direct child process {pid} survived client cleanup"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reality_check_regression_linux_proc_stat_parser_uses_final_command_delimiter() {
        assert_eq!(
            linux_process_state_group_and_thread_count(
                b"123 (worker) with ) delimiters) S 45 678 6 7 8 9 10 11 12 13 14 15 16 17 18 19 4"
            ),
            Some(('S', 678, 4))
        );
        assert_eq!(
            linux_process_state_group_and_thread_count(b"malformed"),
            None
        );
        let mut non_utf8_name = b"123 (worker-".to_vec();
        non_utf8_name.push(0xff);
        non_utf8_name.extend_from_slice(b") S 45 678 6 7 8 9 10 11 12 13 14 15 16 17 18 19 4");
        assert_eq!(
            linux_process_state_group_and_thread_count(&non_utf8_name),
            Some(('S', 678, 4))
        );
        assert_eq!(linux_proc_stat_process_id(&non_utf8_name), Some(123));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reality_check_regression_linux_status_requires_one_pid_namespace() {
        assert!(linux_status_has_single_current_namespace_pid(
            b"Name:\tworker\nNSpid:\t123\n",
            123
        ));
        assert!(!linux_status_has_single_current_namespace_pid(
            b"Name:\tworker\nNSpid:\t1\t123\n",
            123
        ));
        assert!(!linux_status_has_single_current_namespace_pid(
            b"Name:\tworker\nNSpid:\t123\t123\n",
            123
        ));
        assert!(!linux_status_has_single_current_namespace_pid(
            b"NSpid:\t123\nNSpid:\t123\n",
            123
        ));
        assert!(!linux_status_has_single_current_namespace_pid(
            b"Name:\tworker\n",
            123
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reality_check_regression_linux_process_liveness_excludes_only_terminal_states() {
        for state in ['R', 'S', 'D', 'T', 't', 'I'] {
            assert!(linux_process_state_is_live(state), "state {state}");
            assert!(!linux_process_stat_proves_single_terminal_task(state, 1));
        }
        for state in ['Z', 'X', 'x'] {
            assert!(!linux_process_state_is_live(state), "state {state}");
            assert!(linux_process_stat_proves_single_terminal_task(state, 1));
            assert!(!linux_process_stat_proves_single_terminal_task(state, 0));
            assert!(!linux_process_stat_proves_single_terminal_task(state, 2));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reality_check_regression_linux_proc_scan_accepts_only_disappearance_errors() {
        assert!(linux_proc_process_disappeared(&std::io::Error::from(
            std::io::ErrorKind::NotFound
        )));
        assert!(linux_proc_process_disappeared(
            &std::io::Error::from_raw_os_error(rustix::io::Errno::SRCH.raw_os_error())
        ));
        assert!(!linux_proc_process_disappeared(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reality_check_regression_linux_proc_mount_policy_requires_unrestricted_view() {
        assert!(linux_proc_mounts_allow_complete_process_view(
            "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
        ));
        assert!(linux_proc_mounts_allow_complete_process_view(
            "proc /proc proc rw,hidepid=0 0 0\n"
        ));
        assert!(linux_proc_mounts_allow_complete_process_view(
            "proc /proc proc rw,hidepid=0,subset=pid 0 0\n"
        ));
        assert!(!linux_proc_mounts_allow_complete_process_view(
            "proc /proc proc rw,hidepid=2 0 0\n"
        ));
        assert!(!linux_proc_mounts_allow_complete_process_view(
            "proc /proc proc rw 0 0\nproc /proc proc rw 0 0\n"
        ));
        assert!(!linux_proc_mounts_allow_complete_process_view(
            "tmpfs /proc tmpfs rw 0 0\n"
        ));
        assert!(!linux_proc_mounts_allow_complete_process_view(""));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reality_check_regression_linux_group_scanner_rejects_invalid_id_and_deadline() {
        assert!(
            linux_process_group_has_live_member(0, Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        assert!(
            linux_process_group_has_live_member(-1, Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        assert!(linux_process_group_has_live_member(1, Instant::now()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reality_check_regression_linux_group_scanner_observes_live_member() {
        let child = Command::new("/bin/sh")
            .args(["-c", "exec /bin/sleep 60"])
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn live process-group member");
        let mut guard = ChildGuard::new(child);
        let process_group_id =
            i32::try_from(guard.child_mut().id()).expect("PID fits process-group range");

        let observed = linux_process_group_has_live_member(
            process_group_id,
            Instant::now() + Duration::from_secs(2),
        );
        let cleanup = guard.cleanup();

        assert!(observed.expect("complete live-group procfs scan"));
        assert!(cleanup.is_ok(), "clean up live scan fixture: {cleanup:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reality_check_regression_linux_group_scanner_distinguishes_zombie_from_absence() {
        let child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zombie-only process-group fixture");
        let mut guard = ChildGuard::new(child);
        let process_group_id =
            i32::try_from(guard.child_mut().id()).expect("PID fits process-group range");
        let zombie_deadline = Instant::now() + Duration::from_secs(2);
        let observed_zombie = loop {
            let state = std::fs::read(format!("/proc/{process_group_id}/stat"))
                .ok()
                .and_then(|stat| linux_process_state_group_and_thread_count(&stat))
                .map(|(state, _, _)| state);
            if state.is_some_and(|state| matches!(state, 'Z' | 'X' | 'x')) {
                break true;
            }
            if Instant::now() >= zombie_deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let observed = linux_process_group_has_live_member(
            process_group_id,
            Instant::now() + Duration::from_secs(2),
        );
        let process_group = rustix::process::Pid::from_raw(process_group_id)
            .expect("positive process-group identifier");
        let strict_absence = require_owned_process_group_absent(process_group);
        let cleanup = guard.cleanup();

        assert!(
            observed_zombie,
            "fixture must reach zombie state before inspection"
        );
        assert!(!observed.expect("complete zombie-only procfs scan"));
        assert!(
            strict_absence.is_err(),
            "zombie-only observation must not weaken the identity-lost path"
        );
        assert!(
            cleanup.is_ok(),
            "reap zombie-only scan fixture: {cleanup:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reality_check_regression_anchored_cleanup_accepts_zombie_only_descendant_group() {
        let anchor = ProcessGroupAnchor::spawn().expect("spawn process-group anchor");
        let process_group_id = anchor.raw_process_group();
        let peer = Command::new("/bin/sh")
            .args(["-c", "exec /bin/sleep 60"])
            .process_group(process_group_id)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn anchored peer");
        let group_guard = ChildGuard::with_process_group(peer, anchor);
        let retained_descendant = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .process_group(process_group_id)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn retained descendant fixture");
        let retained_guard = ChildGuard::new(retained_descendant);

        let cleanup = group_guard.cleanup();
        let descendant_cleanup = retained_guard.cleanup();

        assert!(
            cleanup.is_ok(),
            "zombie-only orphan must not fail cleanup: {cleanup:?}"
        );
        assert!(
            descendant_cleanup.is_ok(),
            "reap retained descendant fixture: {descendant_cleanup:?}"
        );
    }

    fn make_closed_client_with_cx(initialized: bool, cx: Cx) -> Client {
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
        let mut command = Command::new(rustc);
        command
            .arg("--version")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().expect("spawn rustc --version");

        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        let transport = StdioTransport::new(stdout, stdin);
        let session = ClientSession::new(
            ClientInfo {
                name: "test-client".to_string(),
                version: "0.1.0".to_string(),
            },
            ClientCapabilities::default(),
            ServerInfo {
                name: "test-server".to_string(),
                version: "1.0.0".to_string(),
            },
            ServerCapabilities::default(),
            PROTOCOL_VERSION.to_string(),
        );

        if initialized {
            Client::from_parts(
                child,
                transport,
                cx,
                session,
                RequestTimeoutPolicy::new(Duration::from_millis(100), Duration::from_millis(100))
                    .unwrap(),
            )
        } else {
            Client::from_parts_uninitialized(
                child,
                transport,
                cx,
                session,
                RequestTimeoutPolicy::new(Duration::from_millis(100), Duration::from_millis(100))
                    .unwrap(),
            )
        }
    }

    fn make_closed_client(initialized: bool) -> Client {
        make_closed_client_with_cx(initialized, Cx::for_request())
    }

    #[cfg(unix)]
    fn make_shell_scripted_initialized_client(script: &str, timeout: Duration) -> Client {
        let mut command = Command::new("sh");
        command
            .args(["-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().expect("spawn scripted peer");
        let stdin = child.stdin.take().expect("scripted peer stdin");
        let stdout = child.stdout.take().expect("scripted peer stdout");
        let transport = StdioTransport::new(stdout, stdin);
        let session = ClientSession::new(
            ClientInfo {
                name: "test-client".to_string(),
                version: "0.1.0".to_string(),
            },
            ClientCapabilities::default(),
            ServerInfo {
                name: "scripted-server".to_string(),
                version: "1.0.0".to_string(),
            },
            ServerCapabilities::default(),
            PROTOCOL_VERSION.to_string(),
        );
        Client::from_parts(
            child,
            transport,
            Cx::for_request(),
            session,
            RequestTimeoutPolicy::new(timeout, timeout).unwrap(),
        )
    }

    #[cfg(unix)]
    fn make_scripted_initialized_client(response: JsonRpcMessage) -> Client {
        let response_line = serde_json::to_string(&response).expect("serialize scripted response");
        assert!(
            !response_line.contains('\''),
            "the shell fixture requires a single-quote-free JSON line"
        );
        // Keep the peer alive briefly so the client can write its request, but
        // make the fixture self-terminating without an orphanable watchdog.
        let script = format!("printf '%s\\n' '{response_line}'; exec sleep 2");
        make_shell_scripted_initialized_client(&script, Duration::from_secs(1))
    }

    #[cfg(unix)]
    fn make_peer_silent_past_deadline_client(response: JsonRpcMessage) -> Client {
        let response_line = serde_json::to_string(&response).expect("serialize scripted response");
        assert!(
            !response_line.contains('\''),
            "the shell fixture requires a single-quote-free JSON line"
        );
        // The delay is intentionally much larger than the five-millisecond
        // request deadline. The peer remains bounded even if client cleanup
        // regresses, and no background watchdog can outlive the fixture.
        let script = format!("sleep 1; printf '%s\\n' '{response_line}'; exec sleep 2");
        make_shell_scripted_initialized_client(&script, Duration::from_millis(5))
    }

    #[test]
    fn request_timeout_policy_has_distinct_validated_bounds_and_named_reset() {
        let default = RequestTimeoutPolicy::default();
        assert_eq!(default.idle_timeout(), Duration::from_secs(30));
        assert_eq!(default.absolute_timeout(), Duration::from_secs(120));
        assert!(default.resets_idle_on_matching_progress());

        for (idle, absolute) in [
            (Duration::ZERO, Duration::from_millis(1)),
            (Duration::from_nanos(999_999), Duration::from_millis(1)),
            (
                MAX_CLIENT_IDLE_TIMEOUT + Duration::from_nanos(1),
                Duration::from_millis(1),
            ),
            (Duration::from_millis(1), Duration::ZERO),
            (Duration::from_millis(1), Duration::from_nanos(999_999)),
            (
                Duration::from_millis(1),
                MAX_CLIENT_ABSOLUTE_TIMEOUT + Duration::from_nanos(1),
            ),
        ] {
            assert!(RequestTimeoutPolicy::new(idle, absolute).is_err());
        }

        let strict =
            RequestTimeoutPolicy::new(Duration::from_millis(1), MAX_CLIENT_ABSOLUTE_TIMEOUT)
                .unwrap()
                .reset_idle_on_matching_progress(false);
        assert_eq!(strict.idle_timeout(), Duration::from_millis(1));
        assert_eq!(strict.absolute_timeout(), MAX_CLIENT_ABSOLUTE_TIMEOUT);
        assert!(!strict.resets_idle_on_matching_progress());

        let exact_bounds =
            RequestTimeoutPolicy::new(MAX_CLIENT_IDLE_TIMEOUT, Duration::from_millis(1))
                .expect("the exact idle maximum and absolute minimum are valid");
        assert_eq!(exact_bounds.idle_timeout(), MAX_CLIENT_IDLE_TIMEOUT);
        assert_eq!(exact_bounds.absolute_timeout(), Duration::from_millis(1));
    }

    #[test]
    fn request_deadline_idle_reset_never_moves_absolute() {
        let committed_at = Instant::now();
        let policy =
            RequestTimeoutPolicy::new(Duration::from_millis(100), Duration::from_millis(250))
                .unwrap();
        let mut deadlines = RequestDeadlines::start_at(policy, committed_at).unwrap();
        let absolute = deadlines.absolute;

        deadlines
            .reset_idle_at(committed_at + Duration::from_millis(80))
            .unwrap();

        assert_eq!(deadlines.idle, committed_at + Duration::from_millis(180));
        assert_eq!(deadlines.absolute, absolute);
        assert_eq!(
            deadlines.expired_at(committed_at + Duration::from_millis(181)),
            Some(RequestTimeoutSource::Idle)
        );

        let mut absolute_deadlines = RequestDeadlines::start_at(policy, committed_at).unwrap();
        absolute_deadlines
            .reset_idle_at(committed_at + Duration::from_millis(200))
            .unwrap();
        assert_eq!(absolute_deadlines.absolute, absolute);
        assert_eq!(
            absolute_deadlines.expired_at(committed_at + Duration::from_millis(250)),
            Some(RequestTimeoutSource::Absolute)
        );
    }

    #[test]
    fn request_deadline_tie_selects_absolute_source() {
        let committed_at = Instant::now();
        let policy =
            RequestTimeoutPolicy::new(Duration::from_millis(100), Duration::from_millis(100))
                .unwrap();
        let deadlines = RequestDeadlines::start_at(policy, committed_at).unwrap();

        assert_eq!(deadlines.next_kind(), RequestTimeoutSource::Absolute);
        assert_eq!(
            deadlines.expired_at(committed_at + Duration::from_millis(99)),
            None
        );
        assert_eq!(
            deadlines.expired_at(committed_at + Duration::from_millis(100)),
            Some(RequestTimeoutSource::Absolute)
        );
    }

    #[cfg(unix)]
    #[test]
    fn invalid_response_timeout_is_rejected_before_request_commit() {
        let mut client =
            make_shell_scripted_initialized_client("exec sleep 2", Duration::from_millis(100));
        client.timeout_policy = RequestTimeoutPolicy {
            idle_timeout: Duration::ZERO,
            absolute_timeout: Duration::from_secs(1),
            reset_idle_on_matching_progress: true,
        };

        let result: McpResult<serde_json::Value> =
            client.send_request("test/invalid-timeout", serde_json::json!({}));
        let error = result.expect_err("invalid timeout must fail before request commitment");

        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(client.next_id.load(Ordering::SeqCst), 2);

        let mut progress_events = Vec::new();
        let mut on_progress = |progress: f64, total: Option<f64>, message: Option<&str>| {
            progress_events.push((progress, total, message.map(ToOwned::to_owned)));
        };
        let progress_error = client
            .call_tool_with_progress(
                "test/invalid-timeout",
                serde_json::json!({}),
                &mut on_progress,
            )
            .expect_err("invalid timeout must fail before progress-token allocation");
        assert_eq!(progress_error.code, McpErrorCode::InvalidParams);
        assert!(progress_events.is_empty());
        assert_eq!(client.next_id.load(Ordering::SeqCst), 2);

        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 0);
        assert!(client.responses.terminal_error().is_none());
        assert!(client.is_initialized());
        assert!(client.child.is_some());
        assert!(!client.transport.is_closed());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn silent_peer_timeout_is_request_local() {
        let response = JsonRpcMessage::Response(JsonRpcResponse::success(
            RequestId::Number(2),
            serde_json::json!({"late": true}),
        ));
        let mut client = make_peer_silent_past_deadline_client(response);

        let result: McpResult<serde_json::Value> =
            client.send_request("test/late", serde_json::json!({}));
        let error = result.expect_err("a silent peer must time out the request");

        assert!(error.message.contains("timed out"));
        assert!(client.is_initialized());
        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 1);
        assert_eq!(client.responses.cancellation_control_len(), 1);
        assert!(client.responses.terminal_error().is_none());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn silent_peer_timeout_via_progress_api_is_request_local() {
        let response = JsonRpcMessage::Response(JsonRpcResponse::success(
            RequestId::Number(2),
            serde_json::json!({"late": true}),
        ));
        let mut client = make_peer_silent_past_deadline_client(response);
        let marker = ProgressMarker::Number(2);
        let mut progress_events = Vec::new();
        let mut callback = |progress: f64, total: Option<f64>, message: Option<&str>| {
            progress_events.push((progress, total, message.map(ToOwned::to_owned)));
        };

        let result: McpResult<serde_json::Value> = client.send_request_with_progress(
            "test/late-progress",
            serde_json::json!({}),
            2,
            &marker,
            &mut callback,
        );
        let error = result.expect_err("a silent peer must time out the progress request");

        assert!(error.message.contains("timed out"));
        assert!(progress_events.is_empty());
        assert!(client.is_initialized());
        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 1);
        assert_eq!(client.responses.cancellation_control_len(), 1);
        assert!(client.responses.terminal_error().is_none());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn public_cancellation_emits_for_arbitrary_id_without_poisoning_future_registration() {
        let script = "IFS= read -r cancellation; IFS= read -r request; \
            case \"$cancellation\" in *'\"method\":\"notifications/cancelled\"'*) method_ok=true;; *) method_ok=false;; esac; \
            case \"$cancellation\" in *'\"requestId\":2'*) id_ok=true;; *) id_ok=false;; esac; \
            case \"$cancellation\" in *'\"reason\":\"pre-cancel\"'*) reason_ok=true;; *) reason_ok=false;; esac; \
            if [ \"$method_ok\" = true ] && [ \"$id_ok\" = true ] && [ \"$reason_ok\" = true ]; \
              then cancellation_ok=true; else cancellation_ok=false; fi; \
            case \"$request\" in *'\"id\":2'*) request_ok=true;; *) request_ok=false;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"cancellation\":%s,\"request\":%s}}\\n' \
              \"$cancellation_ok\" \"$request_ok\"; exec sleep 2";
        let mut client = make_shell_scripted_initialized_client(script, Duration::from_secs(2));

        client
            .cancel_request(2_i64, Some("pre-cancel".to_string()), false)
            .expect("an arbitrary peer-known ID receives one control frame");
        assert_eq!(client.responses.cancellation_control_len(), 1);
        client
            .cancel_request(2_i64, Some("duplicate".to_string()), true)
            .expect("the same arbitrary ID is an at-most-once no-op");
        assert_eq!(client.responses.cancellation_control_len(), 1);

        let evidence: serde_json::Value = client
            .send_request("test/new-generation", serde_json::json!({}))
            .expect("the later local request generation must not be poisoned");
        assert_eq!(
            evidence,
            serde_json::json!({"cancellation": true, "request": true})
        );
        assert_eq!(client.responses.cancellation_control_len(), 0);
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn public_cancellation_tombstones_once_and_uses_bounded_control() {
        let script = "IFS= read -r first; IFS= read -r cancellation; IFS= read -r second; \
            case \"$first\" in *'\"id\":20'*) first_ok=true;; *) first_ok=false;; esac; \
            case \"$cancellation\" in *'\"method\":\"notifications/cancelled\"'*) method_ok=true;; *) method_ok=false;; esac; \
            case \"$cancellation\" in *'\"requestId\":20'*) id_ok=true;; *) id_ok=false;; esac; \
            case \"$cancellation\" in *'\"reason\":\"stop\"'*) reason_ok=true;; *) reason_ok=false;; esac; \
            case \"$cancellation\" in *'\"awaitCleanup\":true'*) cleanup_ok=true;; *) cleanup_ok=false;; esac; \
            if [ \"$method_ok\" = true ] && [ \"$id_ok\" = true ] && [ \"$reason_ok\" = true ] && [ \"$cleanup_ok\" = true ]; \
              then cancellation_ok=true; else cancellation_ok=false; fi; \
            case \"$second\" in *'\"id\":2'*) second_ok=true;; *) second_ok=false;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":20,\"result\":{\"late\":true}}\\n'; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"first\":%s,\"cancellation\":%s,\"second\":%s}}\\n' \
              \"$first_ok\" \"$cancellation_ok\" \"$second_ok\"; exec sleep 2";
        let mut client = make_shell_scripted_initialized_client(script, Duration::from_secs(2));
        let request_id = RequestId::Number(20);
        let request = JsonRpcRequest::new("test/cancel", Some(serde_json::json!({})), 20);
        let mut waiter = client
            .responses
            .register(request_id.clone())
            .expect("register cancellation owner");
        client
            .transport
            .send(&client.cx, &JsonRpcMessage::Request(request))
            .expect("commit request before public cancellation");

        client
            .cancel_request(request_id.clone(), Some("stop".to_string()), true)
            .expect("first public cancellation must commit one control frame");
        client
            .cancel_request(request_id, Some("duplicate".to_string()), false)
            .expect("duplicate cancellation is an idempotent bounded no-op");

        let waiter_error = waiter
            .try_response()
            .expect_err("the request owner receives local cancellation");
        assert_eq!(waiter_error.code, McpErrorCode::RequestCancelled);
        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 1);
        assert_eq!(client.responses.cancellation_control_len(), 1);

        let evidence: serde_json::Value = client
            .send_request("test/after-cancel", serde_json::json!({}))
            .expect("late response retires the tombstone without misalignment");
        assert_eq!(
            evidence,
            serde_json::json!({
                "first": true,
                "cancellation": true,
                "second": true
            })
        );
        assert_eq!(client.responses.tombstone_len(), 0);
        assert!(client.responses.terminal_error().is_none());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn oversized_public_cancellation_is_local_first_then_connection_terminal() {
        let mut client =
            make_shell_scripted_initialized_client("exec sleep 2", Duration::from_secs(1));
        let request_id = RequestId::Number(20);
        let request = JsonRpcRequest::new("test/cancel-large", Some(serde_json::json!({})), 20);
        let mut waiter = client
            .responses
            .register(request_id.clone())
            .expect("register oversized-cancellation owner");
        client
            .transport
            .send(&client.cx, &JsonRpcMessage::Request(request))
            .expect("commit request before oversized cancellation");

        let error = client
            .cancel_request(request_id, Some("x".repeat(512)), false)
            .expect_err("oversized atomic control must fail boundedly");

        assert_eq!(error.message, CONTROL_FRAME_CAPACITY_ERROR);
        let waiter_error = waiter
            .try_response()
            .expect_err("the first request-local outcome remains cancellation");
        assert_eq!(waiter_error.code, McpErrorCode::RequestCancelled);
        assert!(!client.is_initialized());
        assert!(client.transport.is_closed());
        assert!(client.child.is_none());
        assert!(client.responses.terminal_error().is_some());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn silent_peer_timeout_has_no_progress_callback_side_effect() {
        let progress = JsonRpcMessage::Request(JsonRpcRequest::notification(
            "notifications/progress",
            Some(serde_json::json!({
                "progressToken": 2,
                "progress": 0.5,
                "total": 1.0,
                "message": "late"
            })),
        ));
        let mut client = make_peer_silent_past_deadline_client(progress);
        let marker = ProgressMarker::Number(2);
        let mut progress_events = Vec::new();
        let mut callback = |progress: f64, total: Option<f64>, message: Option<&str>| {
            progress_events.push((progress, total, message.map(ToOwned::to_owned)));
        };

        let result: McpResult<serde_json::Value> = client.send_request_with_progress(
            "test/late-progress-notification",
            serde_json::json!({}),
            2,
            &marker,
            &mut callback,
        );
        let error = result.expect_err("a silent peer must time out without progress");

        assert!(error.message.contains("timed out"));
        assert!(progress_events.is_empty());
        assert!(client.is_initialized());
        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 1);
        assert!(client.responses.terminal_error().is_none());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn exact_valid_increasing_progress_resets_only_idle() {
        let script = "IFS= read -r request; \
            sleep 0.10; printf '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":2,\"progress\":0.1,\"_meta\":{\"trace\":\"accepted\"}}}\\n'; \
            sleep 0.10; printf '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":2,\"progress\":0.2}}\\n'; \
            sleep 0.10; printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"ok\":true}}\\n'; exec sleep 2";
        let mut client = make_shell_scripted_initialized_client(script, Duration::from_secs(1));
        client.timeout_policy =
            RequestTimeoutPolicy::new(Duration::from_millis(250), Duration::from_millis(800))
                .unwrap();
        let marker = ProgressMarker::Number(2);
        let mut progress_events = Vec::new();
        let mut callback = |progress: f64, _total: Option<f64>, _message: Option<&str>| {
            progress_events.push(progress);
        };

        let result: serde_json::Value = client
            .send_request_with_progress(
                "test/progress-idle-reset",
                serde_json::json!({}),
                2,
                &marker,
                &mut callback,
            )
            .expect("matching progress must keep the request alive between idle windows");

        assert_eq!(result, serde_json::json!({"ok": true}));
        assert_eq!(progress_events, vec![0.1, 0.2]);
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn matching_progress_does_not_reset_idle_when_policy_disables_it() {
        let script = "IFS= read -r request; \
            sleep 0.20; printf '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":2,\"progress\":0.5}}\\n'; \
            sleep 0.30; printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tooLate\":true}}\\n'; exec sleep 2";
        let mut client = make_shell_scripted_initialized_client(script, Duration::from_secs(1));
        client.timeout_policy =
            RequestTimeoutPolicy::new(Duration::from_millis(400), Duration::from_millis(900))
                .unwrap()
                .reset_idle_on_matching_progress(false);
        let marker = ProgressMarker::Number(2);
        let mut progress_events = Vec::new();
        let mut callback = |progress: f64, _total: Option<f64>, _message: Option<&str>| {
            progress_events.push(progress);
        };

        let error = client
            .send_request_with_progress::<_, serde_json::Value>(
                "test/progress-reset-disabled",
                serde_json::json!({}),
                2,
                &marker,
                &mut callback,
            )
            .expect_err("accepted progress must not override a disabled idle reset");

        assert_eq!(
            error.data,
            Some(serde_json::json!({"timeoutSource": "idle"}))
        );
        assert_eq!(progress_events, vec![0.5]);
        assert_eq!(client.responses.cancellation_control_len(), 1);
        assert!(client.responses.terminal_error().is_none());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn unrelated_invalid_and_nonmonotonic_progress_do_not_reset_idle() {
        let script = "IFS= read -r request; \
            sleep 0.10; printf '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":2,\"progress\":0.5}}\\n'; \
            sleep 0.10; printf '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":999,\"progress\":0.6}}\\n'; \
            sleep 0.10; printf '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":2,\"progress\":0.7,\"unknown\":true}}\\n'; \
            sleep 0.05; printf '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":2,\"progress\":0.5}}\\n'; \
            sleep 0.20; printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tooLate\":true}}\\n'; exec sleep 2";
        let mut client = make_shell_scripted_initialized_client(script, Duration::from_secs(1));
        client.timeout_policy =
            RequestTimeoutPolicy::new(Duration::from_millis(300), Duration::from_secs(1)).unwrap();
        let marker = ProgressMarker::Number(2);
        let mut progress_events = Vec::new();
        let mut callback = |progress: f64, _total: Option<f64>, _message: Option<&str>| {
            progress_events.push(progress);
        };

        let error = client
            .send_request_with_progress::<_, serde_json::Value>(
                "test/progress-no-idle-authority",
                serde_json::json!({}),
                2,
                &marker,
                &mut callback,
            )
            .expect_err("non-authoritative progress must not extend idle");

        assert_eq!(
            error.data,
            Some(serde_json::json!({"timeoutSource": "idle"}))
        );
        assert_eq!(progress_events, vec![0.5]);
        assert!(client.responses.terminal_error().is_none());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn matching_progress_never_moves_absolute_deadline() {
        let script = "IFS= read -r request; \
            sleep 0.10; printf '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":2,\"progress\":0.1}}\\n'; \
            sleep 0.10; printf '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":2,\"progress\":0.2}}\\n'; \
            sleep 0.10; printf '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":2,\"progress\":0.3}}\\n'; \
            sleep 0.30; printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tooLate\":true}}\\n'; exec sleep 2";
        let mut client = make_shell_scripted_initialized_client(script, Duration::from_secs(1));
        client.timeout_policy =
            RequestTimeoutPolicy::new(Duration::from_millis(300), Duration::from_millis(500))
                .unwrap();
        let marker = ProgressMarker::Number(2);
        let mut progress_events = Vec::new();
        let mut callback = |progress: f64, _total: Option<f64>, _message: Option<&str>| {
            progress_events.push(progress);
        };

        let error = client
            .send_request_with_progress::<_, serde_json::Value>(
                "test/progress-absolute-bound",
                serde_json::json!({}),
                2,
                &marker,
                &mut callback,
            )
            .expect_err("progress must not keep a request alive past absolute time");

        assert_eq!(
            error.data,
            Some(serde_json::json!({"timeoutSource": "absolute"}))
        );
        assert_eq!(progress_events, vec![0.1, 0.2, 0.3]);
        assert!(client.responses.terminal_error().is_none());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn request_timeout_keeps_connection_reusable_and_discards_late_activity() {
        let late_progress = JsonRpcMessage::Request(JsonRpcRequest::notification(
            "notifications/progress",
            Some(serde_json::json!({
                "progressToken": 2,
                "progress": 0.5,
                "total": 1.0,
                "message": "late"
            })),
        ));
        let late_response = JsonRpcMessage::Response(JsonRpcResponse::success(
            RequestId::Number(2),
            serde_json::json!({"late": true}),
        ));
        let lines = [late_progress, late_response]
            .map(|message| serde_json::to_string(&message).expect("serialize scripted message"));
        assert!(
            lines.iter().all(|line| !line.contains('\'')),
            "the shell fixture requires single-quote-free JSON lines"
        );
        let script = format!(
            "IFS= read -r first; sleep 1; IFS= read -r cancellation; \
             IFS= read -r second; \
             case \"$first\" in *'\"id\":2'*) first_ok=true;; *) first_ok=false;; esac; \
             case \"$cancellation\" in *'\"method\":\"notifications/cancelled\"'*'\"requestId\":2'*) cancellation_ok=true;; *) cancellation_ok=false;; esac; \
             case \"$second\" in *'\"id\":3'*) second_ok=true;; *) second_ok=false;; esac; \
             printf '%s\\n' '{}' '{}'; \
             printf '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{\"first\":%s,\"cancellation\":%s,\"second\":%s}}}}\\n' \
             \"$first_ok\" \"$cancellation_ok\" \"$second_ok\"; exec sleep 2",
            lines[0], lines[1]
        );
        let mut client = make_shell_scripted_initialized_client(&script, Duration::from_millis(5));
        let first_marker = ProgressMarker::Number(2);
        let mut first_progress = Vec::new();
        let mut first_callback = |progress: f64, total: Option<f64>, message: Option<&str>| {
            first_progress.push((progress, total, message.map(ToOwned::to_owned)));
        };

        let first: McpResult<serde_json::Value> = client.send_request_with_progress(
            "test/first",
            serde_json::json!({}),
            2,
            &first_marker,
            &mut first_callback,
        );
        let first_error =
            first.expect_err("the first request must time out while the peer is idle");
        assert!(first_error.message.contains("timed out"));
        assert!(first_progress.is_empty());
        assert!(client.responses.terminal_error().is_none());

        client.timeout_policy =
            RequestTimeoutPolicy::new(Duration::from_secs(3), Duration::from_secs(3)).unwrap();
        let second_marker = ProgressMarker::Number(3);
        let mut second_progress = Vec::new();
        let mut second_callback = |progress: f64, total: Option<f64>, message: Option<&str>| {
            second_progress.push((progress, total, message.map(ToOwned::to_owned)));
        };
        let second: serde_json::Value = client
            .send_request_with_progress(
                "test/second",
                serde_json::json!({}),
                3,
                &second_marker,
                &mut second_callback,
            )
            .expect("the next request must use the still-aligned connection");

        assert_eq!(
            second,
            serde_json::json!({
                "first": true,
                "cancellation": true,
                "second": true
            })
        );
        assert!(second_progress.is_empty());
        assert_eq!(client.responses.uncorrelated_diagnostics, 0);
        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 0);
        assert!(client.responses.terminal_error().is_none());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn in_time_server_request_response_cannot_block_request_deadline() {
        let script = "IFS= read -r request; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":88}\\n'; \
            IFS= read -r response; \
            case \"$request\" in *'\"id\":2'*) request_ok=true;; *) request_ok=false;; esac; \
            case \"$response\" in *'\"id\":88'*) response_ok=true;; *) response_ok=false;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"request\":%s,\"response\":%s}}\\n' \
            \"$request_ok\" \"$response_ok\"; exec sleep 2";
        let mut client = make_shell_scripted_initialized_client(script, Duration::from_secs(2));

        let result: serde_json::Value = client
            .send_request("test/server-request", serde_json::json!({}))
            .expect("an in-time server request must receive its bounded response");

        assert_eq!(
            result,
            serde_json::json!({
                "request": true,
                "response": true
            })
        );
        assert!(client.is_initialized());
        assert!(!client.transport.is_closed());
        assert!(client.responses.terminal_error().is_none());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn panicked_progress_callback_cancels_and_preserves_connection_alignment() {
        let script = "IFS= read -r first; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":2,\"progress\":0.5}}\\n'; \
            IFS= read -r cancellation; IFS= read -r second; \
            case \"$first\" in *'\"id\":2'*) first_ok=true;; *) first_ok=false;; esac; \
            case \"$cancellation\" in *'\"method\":\"notifications/cancelled\"'*'\"requestId\":2'*) cancellation_ok=true;; *) cancellation_ok=false;; esac; \
            case \"$second\" in *'\"id\":3'*) second_ok=true;; *) second_ok=false;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"late\":true}}\\n'; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"first\":%s,\"cancellation\":%s,\"second\":%s}}\\n' \
            \"$first_ok\" \"$cancellation_ok\" \"$second_ok\"; exec sleep 2";
        let mut client = make_shell_scripted_initialized_client(script, Duration::from_secs(3));
        let mut callback = |_progress: f64, _total: Option<f64>, _message: Option<&str>| {
            panic!("progress callback panic canary");
        };

        let first = client.call_tool_with_progress(
            "test/panicked-progress",
            serde_json::json!({}),
            &mut callback,
        );
        let first_error = first.expect_err("the callback panic must become a fixed local error");

        assert_eq!(first_error.message, PROGRESS_CALLBACK_PANIC_ERROR);
        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 1);
        assert!(client.responses.terminal_error().is_none());

        let second: serde_json::Value = client
            .send_request("test/after-panicked-progress", serde_json::json!({}))
            .expect("the next request must remain aligned after callback cancellation");

        assert_eq!(
            second,
            serde_json::json!({
                "first": true,
                "cancellation": true,
                "second": true
            })
        );
        assert_eq!(client.responses.tombstone_len(), 0);
        assert_eq!(client.responses.uncorrelated_diagnostics, 0);
        assert!(client.responses.terminal_error().is_none());
        assert!(client.is_initialized());
        assert!(!client.transport.is_closed());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn partial_frame_timeout_is_connection_terminal() {
        let script = "printf '%s' '{\"jsonrpc\":\"2.0\",\"id\":2'; exec sleep 2";
        let mut client = make_shell_scripted_initialized_client(script, Duration::from_millis(500));
        std::thread::sleep(Duration::from_millis(50));

        let result: McpResult<serde_json::Value> =
            client.send_request("test/partial", serde_json::json!({}));
        let error = result.expect_err("a timeout after partial-frame consumption must be terminal");

        assert!(error.message.contains("timed out"));
        assert_eq!(
            error.data,
            Some(serde_json::json!({"timeoutSource": "absolute"}))
        );
        assert!(!client.is_initialized());
        assert!(client.transport.is_closed());
        assert!(client.child.is_none());
        let terminal = client
            .responses
            .terminal_error()
            .expect("the framing failure must be retained");
        assert_eq!(terminal.code, error.code);
        assert_eq!(terminal.message, error.message);
        assert_eq!(terminal.data, error.data);
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn stored_context_deadline_after_commit_is_connection_terminal() {
        let mut client =
            make_shell_scripted_initialized_client("exec sleep 2", Duration::from_secs(1));
        let request_id = RequestId::Number(2);
        let request = JsonRpcRequest::new("test/context-deadline", Some(serde_json::json!({})), 2);
        let waiter = client
            .responses
            .register(request_id.clone())
            .expect("register committed request");
        client
            .transport
            .send(&client.cx, &JsonRpcMessage::Request(request))
            .expect("commit request before expiring its stored context");
        let deadlines = RequestDeadlines::start_at(client.timeout_policy, Instant::now()).unwrap();
        client.cx = Cx::for_testing_with_budget(
            asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
        );

        let error = client
            .recv_response(waiter, deadlines)
            .expect_err("an exhausted stored context must terminate the owned connection");

        assert!(error.message.contains("timed out"));
        assert!(!client.is_initialized());
        assert!(client.transport.is_closed());
        assert!(client.child.is_none());
        assert_eq!(client.responses.tombstone_len(), 0);
        assert!(client.responses.terminal_error().is_some());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn stored_context_cancellation_after_commit_is_connection_terminal() {
        let mut client =
            make_shell_scripted_initialized_client("exec sleep 2", Duration::from_secs(1));
        let request_id = RequestId::Number(2);
        let request = JsonRpcRequest::new("test/context-cancel", Some(serde_json::json!({})), 2);
        let waiter = client
            .responses
            .register(request_id)
            .expect("register committed request");
        client
            .transport
            .send(&client.cx, &JsonRpcMessage::Request(request))
            .expect("commit request before cancelling its stored context");
        let deadlines = RequestDeadlines::start_at(client.timeout_policy, Instant::now()).unwrap();
        client.cx.set_cancel_requested(true);

        let error = client
            .recv_response(waiter, deadlines)
            .expect_err("a cancelled stored context must terminate the owned connection");

        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert!(!client.is_initialized());
        assert!(client.transport.is_closed());
        assert!(client.child.is_none());
        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 0);
        let terminal = client
            .responses
            .terminal_error()
            .expect("the cancellation must be retained as connection-terminal");
        assert_eq!(terminal.code, error.code);
        assert_eq!(terminal.message, error.message);
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn stored_context_cancellation_after_progress_commit_is_terminal() {
        let mut client =
            make_shell_scripted_initialized_client("exec sleep 2", Duration::from_secs(1));
        let request_id = RequestId::Number(2);
        let request = JsonRpcRequest::new(
            "test/context-cancel-progress",
            Some(serde_json::json!({})),
            2,
        );
        let waiter = client
            .responses
            .register(request_id)
            .expect("register committed progress request");
        client
            .transport
            .send(&client.cx, &JsonRpcMessage::Request(request))
            .expect("commit progress request before cancelling its stored context");
        let timeout_policy = client.timeout_policy;
        let deadlines = RequestDeadlines::start_at(timeout_policy, Instant::now()).unwrap();
        client.cx.set_cancel_requested(true);
        let marker = ProgressMarker::Number(2);
        let mut callback_invoked = false;
        let mut callback = |_progress: f64, _total: Option<f64>, _message: Option<&str>| {
            callback_invoked = true;
        };

        let error = client
            .recv_response_with_progress(waiter, &marker, &mut callback, timeout_policy, deadlines)
            .expect_err("a cancelled stored context must terminate the progress connection");

        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert!(!callback_invoked);
        assert!(!client.is_initialized());
        assert!(client.transport.is_closed());
        assert!(client.child.is_none());
        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 0);
        assert!(client.responses.terminal_error().is_some());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn complete_late_message_routes_unrelated_response_and_retires_tombstone() {
        let mut client =
            make_shell_scripted_initialized_client("exec sleep 2", Duration::from_secs(1));
        let timed_out_id = RequestId::Number(20);
        let unrelated_id = RequestId::Number(21);
        let mut timed_out_waiter = client
            .responses
            .register(timed_out_id.clone())
            .expect("register timed-out owner");
        let mut unrelated_waiter = client
            .responses
            .register(unrelated_id.clone())
            .expect("register unrelated owner");

        let timeout = client.finish_timeout_after_complete_message(
            &timed_out_id,
            JsonRpcMessage::Response(JsonRpcResponse::success(
                unrelated_id.clone(),
                serde_json::json!({"owner": "unrelated"}),
            )),
            RequestTimeoutSource::Idle,
        );

        assert!(timeout.message.contains("timed out"));
        let waiter_error = timed_out_waiter
            .try_response()
            .expect_err("the expired owner receives its local timeout");
        assert_eq!(waiter_error.message, timeout.message);
        let unrelated = unrelated_waiter
            .try_response()
            .expect("unrelated waiter remains valid")
            .expect("the complete unrelated response is routed");
        assert_eq!(unrelated.id, Some(unrelated_id));
        assert_eq!(client.responses.tombstone_len(), 1);
        assert_eq!(
            client.responses.route(JsonRpcResponse::success(
                timed_out_id,
                serde_json::json!({"late": true}),
            )),
            ResponseRoute::TombstoneRetired
        );
        assert_eq!(client.responses.tombstone_len(), 0);
        assert_eq!(client.responses.uncorrelated_diagnostics, 0);
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn complete_late_server_request_uses_bounded_control_writes() {
        let script = "IFS= read -r cancellation; IFS= read -r response; \
            case \"$cancellation\" in *'\"method\":\"notifications/cancelled\"'*'\"requestId\":20'*) cancellation_ok=true;; *) cancellation_ok=false;; esac; \
            case \"$response\" in *'\"id\":88'*) response_ok=true;; *) response_ok=false;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{\"cancellation\":%s,\"response\":%s}}\\n' \
            \"$cancellation_ok\" \"$response_ok\"; exec sleep 2";
        let mut client = make_shell_scripted_initialized_client(script, Duration::from_secs(1));
        let timed_out_id = RequestId::Number(20);
        let mut waiter = client
            .responses
            .register(timed_out_id.clone())
            .expect("register timeout owner");
        let late_ping =
            JsonRpcMessage::Request(JsonRpcRequest::new("ping", Some(serde_json::json!({})), 88));

        let timeout = client.finish_timeout_after_complete_message(
            &timed_out_id,
            late_ping,
            RequestTimeoutSource::Idle,
        );

        assert!(timeout.message.contains("timed out"));
        let waiter_error = waiter
            .try_response()
            .expect_err("the expired owner receives its timeout");
        assert_eq!(waiter_error.message, timeout.message);
        let evidence = client
            .transport
            .recv_until(&client.cx, Some(Instant::now() + Duration::from_secs(2)))
            .expect("the peer observes both bounded control frames");
        let JsonRpcMessage::Response(evidence) = evidence else {
            panic!("expected scripted evidence response");
        };
        assert_eq!(evidence.id, Some(RequestId::Number(99)));
        assert_eq!(
            evidence.result,
            Some(serde_json::json!({
                "cancellation": true,
                "response": true
            }))
        );
        assert!(!client.transport.is_closed());
        assert_eq!(client.responses.tombstone_len(), 1);
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn malformed_complete_late_message_times_out_owner_and_closes_connection() {
        let mut client =
            make_shell_scripted_initialized_client("exec sleep 2", Duration::from_secs(1));
        let request_id = RequestId::Number(30);
        let mut waiter = client
            .responses
            .register(request_id.clone())
            .expect("register timed-out owner");
        let malformed = JsonRpcMessage::Response(JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Owned("1.0".to_string()),
            result: Some(serde_json::Value::Null),
            error: None,
            id: Some(request_id.clone()),
        });

        let timeout = client.finish_timeout_after_complete_message(
            &request_id,
            malformed,
            RequestTimeoutSource::Idle,
        );

        assert!(timeout.message.contains("timed out"));
        let waiter_error = waiter
            .try_response()
            .expect_err("the expired owner receives its first local outcome");
        assert_eq!(waiter_error.message, timeout.message);
        assert!(!client.is_initialized());
        assert!(client.transport.is_closed());
        assert!(client.child.is_none());
        assert_eq!(client.responses.tombstone_len(), 0);
        assert!(client.responses.terminal_error().is_some());
        client.close().expect("client cleanup");
    }

    #[test]
    fn command_resolution_preserves_path_lookup_and_anchors_relative_paths() {
        assert_eq!(
            resolve_stdio_command("server-on-path", None).unwrap(),
            PathBuf::from("server-on-path")
        );

        let current = std::env::current_dir().unwrap();
        assert_eq!(
            resolve_stdio_command("./bin/server", Some(Path::new("workspace"))).unwrap(),
            current.join("workspace").join("./bin/server")
        );
    }

    #[test]
    fn cancelled_context_rejects_direct_client_before_spawn() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let error = match Client::stdio_with_cx("definitely-not-a-command", &[], cx) {
            Ok(_) => panic!("cancelled context must be rejected before spawn"),
            Err(error) => error,
        };
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
    }

    // ========================================
    // method_not_found_response tests
    // ========================================

    #[test]
    fn method_not_found_response_for_request() {
        let request = JsonRpcRequest::new("sampling/createMessage", None, "req-1");
        let response = method_not_found_response(&request);
        assert!(response.is_some());
        if let Some(JsonRpcMessage::Response(resp)) = response {
            assert!(matches!(
                resp.error.as_ref(),
                Some(error)
                    if error.code == i32::from(fastmcp_core::McpErrorCode::MethodNotFound)
            ));
            assert_eq!(resp.id, Some(RequestId::String("req-1".to_string())));
        } else {
            assert!(matches!(response, Some(JsonRpcMessage::Response(_))));
        }
    }

    #[test]
    fn method_not_found_response_for_notification() {
        let request = JsonRpcRequest::notification("notifications/message", None);
        let response = method_not_found_response(&request);
        assert!(response.is_none());
    }

    #[test]
    fn notification_only_method_with_id_is_invalid_and_has_no_side_effect_kind() {
        for method in [
            "notifications/message",
            "notifications/progress",
            "notifications/resources/updated",
            "notifications/tasks/status",
            "notifications/vendor/extension",
        ] {
            let request = JsonRpcRequest::new(method, None, "invalid-notification");
            assert_eq!(server_notification_kind(&request), None);

            let response = server_request_response(&request)
                .expect("ID-bearing notification must receive an error response");
            let JsonRpcMessage::Response(response) = response else {
                panic!("expected response");
            };
            let error = response.error.expect("expected invalid-request error");
            assert_eq!(
                error.code,
                i32::from(fastmcp_core::McpErrorCode::InvalidRequest)
            );
        }
    }

    #[test]
    fn notification_side_effect_classification_requires_an_id_less_notification() {
        let progress = JsonRpcRequest::notification("notifications/progress", None);
        assert_eq!(
            server_notification_kind(&progress),
            Some(ServerNotificationKind::Progress)
        );

        let log = JsonRpcRequest::notification("notifications/message", None);
        assert_eq!(
            server_notification_kind(&log),
            Some(ServerNotificationKind::LogMessage)
        );

        let request_only_notification = JsonRpcRequest::notification("ping", None);
        assert_eq!(server_notification_kind(&request_only_notification), None);
    }

    #[test]
    fn method_not_found_response_with_numeric_id() {
        let request = JsonRpcRequest::new("unknown/method", None, 42i64);
        let response = method_not_found_response(&request);
        assert!(response.is_some());
        if let Some(JsonRpcMessage::Response(resp)) = response {
            assert_eq!(resp.id, Some(RequestId::Number(42)));
            let error = resp.error.as_ref().unwrap();
            assert_eq!(
                error.code,
                i32::from(fastmcp_core::McpErrorCode::MethodNotFound)
            );
            assert_eq!(error.message, "Method not found");
            assert!(!error.message.contains("unknown/method"));
        }
    }

    #[test]
    fn method_not_found_response_with_params() {
        let params = serde_json::json!({"key": "value"});
        let request = JsonRpcRequest::new("roots/list", Some(params), "req-99");
        let response = method_not_found_response(&request);
        assert!(response.is_some());
        if let Some(JsonRpcMessage::Response(resp)) = response {
            let error = resp.error.as_ref().unwrap();
            assert_eq!(error.message, "Method not found");
            assert!(!error.message.contains("roots/list"));
        }
    }

    #[test]
    fn server_ping_request_receives_success_response() {
        let request = JsonRpcRequest::new("ping", None, "server-ping");
        let response = server_request_response(&request).expect("ping request has an ID");
        let JsonRpcMessage::Response(response) = response else {
            panic!("expected response");
        };

        assert_eq!(
            response.id,
            Some(RequestId::String("server-ping".to_string()))
        );
        assert_eq!(response.result, Some(serde_json::json!({})));
        assert!(response.error.is_none());
    }

    #[test]
    fn response_envelope_requires_exact_version_and_one_outcome() {
        let valid = JsonRpcResponse::success(RequestId::Number(1), serde_json::Value::Null);
        assert!(validate_response_envelope(&valid).is_ok());

        let wrong_version = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Owned("2.1".to_string()),
            ..valid.clone()
        };
        assert!(validate_response_envelope(&wrong_version).is_err());

        let both = JsonRpcResponse {
            error: Some(JsonRpcError {
                code: -32_603,
                message: "failure".to_string(),
                data: None,
            }),
            ..valid.clone()
        };
        assert!(validate_response_envelope(&both).is_err());

        let neither = JsonRpcResponse {
            result: None,
            error: None,
            ..valid
        };
        assert!(validate_response_envelope(&neither).is_err());
    }

    #[test]
    fn response_validation_diagnostics_do_not_echo_peer_values() {
        let version_canary = "PEER-VERSION-SECRET-CANARY\r\n";
        let response = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Owned(version_canary.to_string()),
            result: Some(serde_json::Value::Null),
            error: None,
            id: Some(RequestId::String("PEER-ID-SECRET-CANARY\n".to_string())),
        };

        let envelope_error =
            validate_response_envelope(&response).expect_err("an invalid version must fail closed");
        assert_eq!(envelope_error.message, INVALID_RESPONSE_ENVELOPE_ERROR);
        assert!(!envelope_error.message.contains(version_canary));

        let id_canary = "PEER-ID-SECRET-CANARY\n";
        let mismatched = JsonRpcResponse::success(
            RequestId::String(id_canary.to_string()),
            serde_json::Value::Null,
        );
        let id_error = validate_initialize_response_id(&mismatched)
            .expect_err("a mismatched initialize ID must fail closed");
        assert_eq!(id_error.message, INITIALIZE_RESPONSE_ID_ERROR);
        assert!(!id_error.message.contains(id_canary));

        let payload_canary = "PEER-PAYLOAD-SECRET-CANARY";
        let payload_error = decode_response_payload::<ListToolsResult>(serde_json::json!({
            "tools": payload_canary
        }))
        .expect_err("a malformed typed response must fail closed");
        assert_eq!(payload_error.message, INVALID_RESPONSE_PAYLOAD_ERROR);
        assert!(!payload_error.message.contains(payload_canary));
    }

    #[test]
    fn response_envelope_accepts_wire_null_result() {
        let response: JsonRpcResponse =
            serde_json::from_str(r#"{"jsonrpc":"2.0","result":null,"id":1}"#)
                .expect("deserialize wire response");

        assert_eq!(response.result, Some(serde_json::Value::Null));
        assert!(response.error.is_none());
        assert!(validate_response_envelope(&response).is_ok());
    }

    #[test]
    fn response_envelope_rejects_wire_null_result_with_error() {
        let error = serde_json::from_str::<JsonRpcResponse>(
            r#"{"jsonrpc":"2.0","result":null,"error":{"code":-32603,"message":"failure"},"id":1}"#,
        )
        .expect_err("wire response with result and error must be rejected at decode");
        assert!(error.to_string().contains("exactly one"));
    }

    #[test]
    fn json_rpc_error_conversion_preserves_code_message_and_data() {
        let error = json_rpc_error_to_mcp(JsonRpcError {
            code: -32_002,
            message: "forbidden".to_string(),
            data: Some(serde_json::json!({"reason": "policy"})),
        });

        assert_eq!(error.code, McpErrorCode::ResourceForbidden);
        assert_eq!(error.message, "forbidden");
        assert_eq!(error.data, Some(serde_json::json!({"reason": "policy"})));
    }

    #[test]
    fn initialize_response_requires_the_exact_request_id() {
        let matching = JsonRpcResponse::success(
            RequestId::Number(INITIALIZE_REQUEST_ID),
            serde_json::Value::Null,
        );
        assert!(validate_initialize_response_id(&matching).is_ok());

        for response in [
            JsonRpcResponse::success(RequestId::Number(2), serde_json::Value::Null),
            JsonRpcResponse::success(
                RequestId::String(INITIALIZE_REQUEST_ID.to_string()),
                serde_json::Value::Null,
            ),
            JsonRpcResponse::error(None, McpError::internal_error("missing correlation").into()),
        ] {
            let error = validate_initialize_response_id(&response)
                .expect_err("a mismatched initialize response must fail closed");
            assert_eq!(error.message, INITIALIZE_RESPONSE_ID_ERROR);
        }
    }

    #[test]
    fn initialize_result_rejects_an_unadvertised_protocol_version() {
        let result = InitializeResult {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ServerCapabilities::default(),
            server_info: ServerInfo {
                name: "test-server".to_string(),
                version: "1.0.0".to_string(),
            },
            instructions: None,
        };
        assert!(validate_initialize_result(&result).is_ok());

        let unsupported = InitializeResult {
            protocol_version: "2099-01-01".to_string(),
            ..result
        };
        let error = validate_initialize_result(&unsupported)
            .expect_err("an unadvertised version must not become session authority");
        assert_eq!(error.message, UNSUPPORTED_PROTOCOL_VERSION_ERROR);
        assert!(!error.message.contains("2099-01-01"));
    }

    // ========================================
    // transport_error_to_mcp tests
    // ========================================

    #[test]
    fn transport_error_cancelled_maps_to_request_cancelled() {
        let err = transport_error_to_mcp(TransportError::Cancelled);
        assert_eq!(err.code, fastmcp_core::McpErrorCode::RequestCancelled);
    }

    #[test]
    fn transport_error_closed_maps_to_internal() {
        let err = transport_error_to_mcp(TransportError::Closed);
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
        assert!(err.message.contains("closed"));
    }

    #[test]
    fn transport_error_timeout_maps_to_internal() {
        let err = transport_error_to_mcp(TransportError::Timeout);
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
        assert!(err.message.contains("timed out"));
    }

    #[test]
    fn transport_error_io_maps_to_internal() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
        let err = transport_error_to_mcp(TransportError::Io(io_err));
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
        assert!(err.message.contains("I/O error"));
    }

    #[test]
    fn transport_error_codec_maps_to_internal() {
        use fastmcp_transport::CodecError;
        let codec_err = CodecError::MessageTooLarge(999_999);
        let err = transport_error_to_mcp(TransportError::Codec(codec_err));
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
        assert_eq!(err.message, TRANSPORT_CODEC_ERROR);
    }

    #[test]
    fn transport_codec_diagnostic_never_echoes_peer_text_or_controls() {
        let canary = "PEER-CODEC-VARIANT-CANARY\r\n";
        let source =
            serde_json::from_value::<LogLevel>(serde_json::Value::String(canary.to_string()))
                .expect_err("unknown peer enum variant must fail typed decoding");
        let error = transport_error_to_mcp(TransportError::Codec(
            fastmcp_transport::CodecError::Json(source),
        ));

        assert_eq!(error.message, TRANSPORT_CODEC_ERROR);
        assert!(!error.message.contains(canary));
        assert!(!error.message.chars().any(char::is_control));
    }

    // ========================================
    // ClientProgressParams tests
    // ========================================

    #[test]
    fn client_progress_params_deserialization() {
        let json = serde_json::json!({
            "progressToken": 42,
            "progress": 0.5,
            "total": 1.0,
            "message": "Halfway done"
        });
        let params: ClientProgressParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.marker, ProgressMarker::Number(42));
        assert!((params.progress - 0.5).abs() < f64::EPSILON);
        assert!((params.total.unwrap() - 1.0).abs() < f64::EPSILON);
        assert_eq!(params.message.as_deref(), Some("Halfway done"));
    }

    #[test]
    fn client_progress_params_minimal() {
        let json = serde_json::json!({
            "progressToken": "tok-1",
            "progress": 0.0
        });
        let params: ClientProgressParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.marker, ProgressMarker::String("tok-1".to_string()));
        assert!(params.total.is_none());
        assert!(params.message.is_none());
        assert!(params.meta.is_none());
    }

    #[test]
    fn progress_timer_authority_requires_closed_finite_strictly_increasing_params() {
        let valid = serde_json::json!({
            "progressToken": 42,
            "progress": -1.5,
            "total": -10.0,
            "message": "still valid",
            "_meta": {"trace": "accepted", "nested": {"open": true}}
        });
        let first =
            parse_valid_client_progress(&valid, None).expect("first finite update is valid");
        assert_eq!(first.progress.to_bits(), (-1.5_f64).to_bits());
        assert_eq!(
            first.meta.as_ref().and_then(|meta| meta.get("trace")),
            Some(&serde_json::json!("accepted"))
        );
        assert!(parse_valid_client_progress(&valid, Some(-1.5)).is_none());
        assert!(parse_valid_client_progress(&valid, Some(0.0)).is_none());

        let increasing = serde_json::json!({"progressToken": 42, "progress": -1.0});
        assert!(parse_valid_client_progress(&increasing, Some(-1.5)).is_some());

        for invalid in [
            serde_json::json!({"progressToken": 42, "progress": 0.0, "unknown": true}),
            serde_json::json!({"progressToken": 42, "progress": 0.0, "total": null}),
            serde_json::json!({"progressToken": 42, "progress": 0.0, "message": null}),
            serde_json::json!({"progressToken": 42, "progress": 0.0, "_meta": null}),
            serde_json::json!({"progressToken": 42, "progress": 0.0, "_meta": "wrong"}),
            serde_json::json!({"progressToken": 42, "progress": "0.0"}),
        ] {
            assert!(parse_valid_client_progress(&invalid, None).is_none());
        }
    }

    #[test]
    fn remote_log_metadata_never_contains_peer_text_or_controls() {
        let canary = "REMOTE-LOG-SECRET-CANARY";
        let message = LogMessageParams {
            level: LogLevel::Warning,
            logger: Some(format!("{canary}\r\n\u{1b}[31m{}", "x".repeat(70_000))),
            data: serde_json::Value::String(format!("{canary}\n\t\u{0}{}", "y".repeat(70_000))),
        };

        let formatted = remote_log_metadata(&message).to_string();
        assert_eq!(REMOTE_LOG_TARGET, "fastmcp_rust::remote");
        assert!(!formatted.contains(canary));
        assert!(!formatted.chars().any(char::is_control));
        assert!(formatted.contains("level=warning"));
        assert!(formatted.contains("logger_bytes=oversized"));
        assert!(formatted.contains("data_kind=string"));
        assert!(formatted.contains("data_extent=oversized"));
        assert!(formatted.len() < 160, "metadata must remain bounded");
    }

    #[test]
    fn remote_log_metadata_reports_only_container_shape() {
        let canary = "OBJECT-KEY-AND-VALUE-CANARY";
        let mut object = serde_json::Map::new();
        object.insert(
            canary.to_string(),
            serde_json::json!([canary, "\r\n\u{1b}"]),
        );
        let message = LogMessageParams {
            level: LogLevel::Error,
            logger: None,
            data: serde_json::Value::Object(object),
        };

        let formatted = remote_log_metadata(&message).to_string();
        assert!(!formatted.contains(canary));
        assert!(!formatted.chars().any(char::is_control));
        assert!(formatted.contains("logger_present=false"));
        assert!(formatted.contains("data_kind=object"));
        assert!(formatted.contains("data_extent=small"));
    }

    #[test]
    fn automatic_pagination_limits_are_locked_to_the_security_budget() {
        assert_eq!(MAX_AUTO_PAGINATION_PAGES, 1_024);
        assert_eq!(MAX_AUTO_PAGINATION_ITEMS, 100_000);
        assert_eq!(MAX_AUTO_PAGINATION_SERIALIZED_BYTES, 64 * 1_024 * 1_024);
        assert_eq!(MAX_PAGINATION_CURSOR_BYTES, 4 * 1_024);
    }

    #[test]
    fn pagination_budget_rejects_oversized_and_repeated_cursors_without_echoing_them() {
        let mut budget = PaginationBudget::new();
        let exact_limit = "x".repeat(MAX_PAGINATION_CURSOR_BYTES);
        assert_eq!(
            budget
                .admit_next_cursor(Some(exact_limit.clone()))
                .expect("cursor at the byte limit is admitted"),
            Some(exact_limit)
        );

        let oversized_canary = format!(
            "OVERSIZED-CURSOR-SECRET\r\n\u{1b}{}",
            "z".repeat(MAX_PAGINATION_CURSOR_BYTES)
        );
        let oversized = budget
            .admit_next_cursor(Some(oversized_canary.clone()))
            .expect_err("oversized cursor must fail closed");
        assert_eq!(oversized.message, PAGINATION_CURSOR_LIMIT_ERROR);
        assert!(!oversized.message.contains(&oversized_canary));
        assert!(!oversized.message.contains("OVERSIZED-CURSOR-SECRET"));
        assert!(!oversized.message.chars().any(char::is_control));

        let repeated_canary = "REPEATED-CURSOR-SECRET\n\u{1b}".to_string();
        budget
            .admit_next_cursor(Some(repeated_canary.clone()))
            .expect("first cursor occurrence is admitted");
        let repeated = budget
            .admit_next_cursor(Some(repeated_canary.clone()))
            .expect_err("cursor cycle must fail closed");
        assert_eq!(repeated.message, PAGINATION_CURSOR_CYCLE_ERROR);
        assert!(!repeated.message.contains(&repeated_canary));
        assert!(!repeated.message.chars().any(char::is_control));
    }

    #[test]
    fn pagination_budget_enforces_page_item_and_byte_limits() {
        let limits = PaginationLimits {
            pages: 2,
            items: 2,
            serialized_bytes: 6,
            cursor_bytes: 16,
        };
        let mut budget = PaginationBudget::with_limits(limits);

        budget.begin_page().expect("first page");
        budget.begin_page().expect("second page");
        let page_error = budget
            .begin_page()
            .expect_err("third page exceeds the configured bound");
        assert_eq!(page_error.message, PAGINATION_PAGE_LIMIT_ERROR);

        budget
            .account_page(&[1_u8])
            .expect("the first three-byte JSON page fits");
        budget
            .account_page(&[2_u8])
            .expect("the second three-byte JSON page fits exactly");
        let item_error = budget
            .account_page(&[3_u8])
            .expect_err("the third item exceeds the configured bound");
        assert_eq!(item_error.message, PAGINATION_ITEM_LIMIT_ERROR);

        let mut byte_budget = PaginationBudget::with_limits(PaginationLimits {
            serialized_bytes: 2,
            ..limits
        });
        let byte_canary = "PAGINATION-BYTE-SECRET\r\n";
        let byte_error = byte_budget
            .account_page(&[byte_canary])
            .expect_err("serialized page above the byte bound must fail closed");
        assert_eq!(byte_error.message, PAGINATION_BYTE_LIMIT_ERROR);
        assert!(!byte_error.message.contains(byte_canary));
        assert!(!byte_error.message.chars().any(char::is_control));
    }

    #[test]
    fn pagination_budget_checked_arithmetic_fails_closed() {
        let mut page_budget = PaginationBudget::new();
        page_budget.pages = usize::MAX;
        assert_eq!(
            page_budget
                .begin_page()
                .expect_err("page counter overflow must fail closed")
                .message,
            PAGINATION_PAGE_LIMIT_ERROR
        );

        let mut item_budget = PaginationBudget::with_limits(PaginationLimits {
            items: usize::MAX,
            ..PaginationLimits::DEFAULT
        });
        item_budget.items = usize::MAX;
        assert_eq!(
            item_budget
                .account_page(&[0_u8])
                .expect_err("item counter overflow must fail closed")
                .message,
            PAGINATION_ITEM_LIMIT_ERROR
        );
    }

    #[test]
    fn bounded_list_page_suppresses_peer_cursor_after_local_item_truncation() {
        let page = bounded_list_page(
            vec![1_u8, 2, 3],
            None,
            Some("next-page".to_owned()),
            ListPageLimits::new(2, 64),
        )
        .expect("bounded page");

        assert_eq!(page.items, vec![1, 2]);
        assert!(page.next_cursor.is_none());
        assert!(page.local_truncated);
        assert!(page.peer_has_more);
    }

    #[test]
    fn bounded_list_page_preserves_advancing_peer_cursor_when_page_is_complete() {
        let page = bounded_list_page(
            vec![1_u8, 2],
            Some("current-page"),
            Some("next-page".to_owned()),
            ListPageLimits::new(2, 64),
        )
        .expect("bounded page");

        assert_eq!(page.items, vec![1, 2]);
        assert_eq!(page.next_cursor.as_deref(), Some("next-page"));
        assert!(!page.local_truncated);
        assert!(page.peer_has_more);
    }

    #[test]
    fn bounded_list_page_stops_before_serialized_byte_budget_is_exceeded() {
        let page = bounded_list_page(
            vec!["small", "this item is too large"],
            None,
            None,
            ListPageLimits::new(8, 10),
        )
        .expect("bounded page");

        assert_eq!(page.items, vec!["small"]);
        assert!(page.local_truncated);
        assert!(!page.peer_has_more);
        assert!(page.next_cursor.is_none());
        assert!(measure_serialized_bytes(&page.items, 10).is_ok());
    }

    #[test]
    fn bounded_list_page_counts_brackets_commas_and_items_in_byte_budget() {
        let empty = bounded_list_page(Vec::<u8>::new(), None, None, ListPageLimits::new(0, 2))
            .expect("empty vector exactly fits two bytes");
        assert!(empty.items.is_empty());
        assert!(!empty.local_truncated);
        assert_eq!(measure_serialized_bytes(&empty.items, 2).unwrap(), 2);

        let bracket_only_budget =
            bounded_list_page(vec![0_u8], None, None, ListPageLimits::new(1, 2))
                .expect("the retained empty vector still fits");
        assert!(bracket_only_budget.items.is_empty());
        assert!(bracket_only_budget.local_truncated);

        let single = bounded_list_page(vec![0_u8], None, None, ListPageLimits::new(1, 3))
            .expect("[0] exactly fits three bytes");
        assert_eq!(single.items, vec![0]);
        assert!(!single.local_truncated);

        let pair = bounded_list_page(vec![0_u8, 1], None, None, ListPageLimits::new(2, 5))
            .expect("[0,1] exactly fits five bytes");
        assert_eq!(pair.items, vec![0, 1]);
        assert!(!pair.local_truncated);

        let missing_comma_budget =
            bounded_list_page(vec![0_u8, 1], None, None, ListPageLimits::new(2, 4))
                .expect("the first item still fits");
        assert_eq!(missing_comma_budget.items, vec![0]);
        assert!(missing_comma_budget.local_truncated);
        assert_eq!(
            measure_serialized_bytes(&missing_comma_budget.items, 4).unwrap(),
            3
        );
    }

    #[test]
    fn bounded_list_page_accepts_zero_items_but_rejects_sub_empty_vec_byte_limits() {
        let zero_items = bounded_list_page(vec![0_u8], None, None, ListPageLimits::new(0, 2))
            .expect("zero retained items is a valid caller budget");
        assert!(zero_items.items.is_empty());
        assert!(zero_items.local_truncated);

        for byte_limit in [0, 1] {
            let limits = ListPageLimits::new(1, byte_limit);
            let error = validate_list_page_request(None, limits)
                .expect_err("a byte budget smaller than [] must be rejected");
            assert_eq!(error.code, McpErrorCode::InvalidParams);
            assert_eq!(error.message, LIST_PAGE_BYTE_LIMIT_ERROR);

            let internal_error = bounded_list_page::<u8>(Vec::new(), None, None, limits)
                .expect_err("the bounded-page helper must enforce the same contract");
            assert_eq!(internal_error.code, McpErrorCode::InvalidParams);
            assert_eq!(internal_error.message, LIST_PAGE_BYTE_LIMIT_ERROR);
        }
    }

    #[test]
    fn bounded_list_page_rejects_oversized_cursors_without_echoing_them() {
        let cursor = format!("CURSOR-SECRET{}", "x".repeat(MAX_PAGINATION_CURSOR_BYTES));
        let error = bounded_list_page::<u8>(
            Vec::new(),
            None,
            Some(cursor.clone()),
            ListPageLimits::new(1, 16),
        )
        .expect_err("oversized peer cursor must fail closed");

        assert_eq!(error.message, PAGINATION_CURSOR_LIMIT_ERROR);
        assert!(!error.message.contains(&cursor));

        let input_error = validate_list_page_request(Some(&cursor), ListPageLimits::new(1, 16))
            .expect_err("oversized caller cursor must fail before sending");
        assert_eq!(input_error.message, PAGINATION_CURSOR_LIMIT_ERROR);
        assert!(!input_error.message.contains(&cursor));
    }

    #[test]
    fn bounded_list_page_rejects_a_non_advancing_peer_cursor_without_echoing_it() {
        let cursor = "NO-PROGRESS-CURSOR-SECRET";
        let error = bounded_list_page::<u8>(
            Vec::new(),
            Some(cursor),
            Some(cursor.to_owned()),
            ListPageLimits::new(1, 16),
        )
        .expect_err("the response cursor must advance beyond the request cursor");

        assert_eq!(error.message, PAGINATION_CURSOR_NO_PROGRESS_ERROR);
        assert!(!error.message.contains(cursor));
    }

    #[test]
    fn bounded_page_methods_validate_arguments_before_auto_initialization() {
        let mut client = make_closed_client(false);
        let invalid_limits = ListPageLimits::new(1, 1);
        let oversized_cursor = "x".repeat(MAX_PAGINATION_CURSOR_BYTES + 1);

        for error in [
            client
                .list_tools_page(None, invalid_limits)
                .expect_err("tool page limits must fail locally"),
            client
                .list_resources_page(Some(&oversized_cursor), ListPageLimits::new(1, 2))
                .expect_err("resource page cursor must fail locally"),
            client
                .list_resource_templates_page(None, invalid_limits)
                .expect_err("template page limits must fail locally"),
            client
                .list_prompts_page(Some(&oversized_cursor), ListPageLimits::new(1, 2))
                .expect_err("prompt page cursor must fail locally"),
        ] {
            assert_eq!(error.code, McpErrorCode::InvalidParams);
        }

        assert!(!client.is_initialized());
        assert!(client.initialization_error.is_none());
        assert!(client.child.is_some());
    }

    #[test]
    fn panicked_tool_progress_callback_returns_fixed_safe_error() {
        let panic_canary = "PROGRESS-PANIC-SECRET\r\n\u{1b}";
        let mut callback = |_progress: f64, _total: Option<f64>, _message: Option<&str>| {
            panic!("{panic_canary}");
        };

        let callback_error = invoke_tool_progress_callback(&mut callback, 0.5, Some(1.0), None)
            .expect_err("callback panic must be contained");
        assert_eq!(callback_error.message, PROGRESS_CALLBACK_PANIC_ERROR);
        assert!(!callback_error.message.contains(panic_canary));
        assert!(!callback_error.message.chars().any(char::is_control));
    }

    #[test]
    fn panicked_task_progress_callback_returns_fixed_safe_error() {
        let panic_canary = "TASK-PROGRESS-PANIC-SECRET\n";
        let mut callback = |_progress: f64, _message: Option<&str>| {
            panic!("{panic_canary}");
        };
        let error = invoke_task_progress_callback(&mut callback, 0.25, Some("peer message"))
            .expect_err("callback panic must be contained");
        assert_eq!(error.message, PROGRESS_CALLBACK_PANIC_ERROR);
        assert!(!error.message.contains(panic_canary));
        assert!(!error.message.contains("peer message"));
    }

    // ========================================
    // Response pump correlation tests
    // ========================================

    #[test]
    fn response_registry_preserves_reordered_responses_for_exact_waiters() {
        let mut registry = ResponseRegistry::new();
        let first_id = RequestId::Number(1);
        let second_id = RequestId::Number(2);
        let mut first = registry.register(first_id.clone()).expect("first waiter");
        let mut second = registry.register(second_id.clone()).expect("second waiter");

        assert_eq!(
            registry.route(JsonRpcResponse::success(
                second_id.clone(),
                serde_json::json!({"owner": "second"}),
            )),
            ResponseRoute::Delivered
        );
        assert!(
            first
                .try_response()
                .expect("first waiter remains valid")
                .is_none(),
            "a reordered response must not wake the wrong waiter"
        );
        let second_response = second
            .try_response()
            .expect("second waiter is valid")
            .expect("second response is retained");
        assert_eq!(second_response.id, Some(second_id));
        assert_eq!(
            second_response.result,
            Some(serde_json::json!({"owner": "second"}))
        );

        assert_eq!(
            registry.route(JsonRpcResponse::success(
                first_id.clone(),
                serde_json::json!({"owner": "first"}),
            )),
            ResponseRoute::Delivered
        );
        let first_response = first
            .try_response()
            .expect("first waiter is valid")
            .expect("first response is retained");
        assert_eq!(first_response.id, Some(first_id));
        assert_eq!(
            first_response.result,
            Some(serde_json::json!({"owner": "first"}))
        );
        assert_eq!(registry.pending_len(), 0);
    }

    #[test]
    fn response_registry_unknown_id_does_not_consume_or_wake_waiter() {
        let mut registry = ResponseRegistry::new();
        let expected_id = RequestId::Number(7);
        let mut waiter = registry
            .register(expected_id.clone())
            .expect("expected waiter");

        assert_eq!(
            registry.route(JsonRpcResponse::success(
                RequestId::String("7".to_string()),
                serde_json::json!({"wrong": true}),
            )),
            ResponseRoute::UnknownId
        );
        assert_eq!(registry.pending_len(), 1);
        assert!(
            waiter
                .try_response()
                .expect("expected waiter remains valid")
                .is_none()
        );

        assert_eq!(
            registry.route(JsonRpcResponse::success(
                expected_id.clone(),
                serde_json::json!({"right": true}),
            )),
            ResponseRoute::Delivered
        );
        let response = waiter
            .try_response()
            .expect("expected waiter is valid")
            .expect("matching response arrives");
        assert_eq!(response.id, Some(expected_id));
    }

    #[test]
    fn response_registry_tombstone_consumes_exact_late_response_without_diagnostic() {
        let mut registry = ResponseRegistry::new();
        let request_id = RequestId::Number(8);
        let mut waiter = registry
            .register(request_id.clone())
            .expect("register timeout owner");
        let timeout = McpError::internal_error("Request timed out");

        assert!(
            registry
                .tombstone(&request_id, timeout.clone())
                .expect("record tombstone")
        );
        assert_eq!(registry.pending_len(), 0);
        assert_eq!(registry.tombstone_len(), 1);
        let waiter_error = waiter
            .try_response()
            .expect_err("the waiter receives its timeout outcome");
        assert_eq!(waiter_error.message, timeout.message);
        let reuse_error = registry
            .register(request_id.clone())
            .expect_err("a tombstoned ID cannot acquire a new owner");
        assert!(reuse_error.message.contains("Retired request ID"));

        assert_eq!(
            registry.route(JsonRpcResponse::success(
                request_id,
                serde_json::json!({"late": true}),
            )),
            ResponseRoute::TombstoneRetired
        );
        assert_eq!(registry.tombstone_len(), 0);
        assert_eq!(registry.uncorrelated_diagnostics, 0);
    }

    #[test]
    fn response_registry_combined_correlation_bound_includes_tombstones() {
        let mut registry = ResponseRegistry::new();
        let expires_at = Instant::now()
            .checked_add(RESPONSE_TOMBSTONE_RETENTION)
            .expect("test clock must admit the fixed retention interval");
        registry
            .tombstones
            .extend((0..MAX_RESPONSE_CORRELATIONS).map(|id| {
                (
                    RequestId::String(format!("retired-{id}"))
                        .correlation_key()
                        .expect("test IDs are valid"),
                    expires_at,
                )
            }));

        let error = registry
            .register(RequestId::String("over-capacity".to_string()))
            .expect_err("tombstones must count against correlation capacity");

        assert!(error.message.contains("correlation limit"));
        assert_eq!(registry.pending_len(), 0);
        assert_eq!(registry.tombstone_len(), MAX_RESPONSE_CORRELATIONS);
        registry.fail_all(error);
        assert_eq!(registry.tombstone_len(), 0);
    }

    #[test]
    fn response_registry_expired_tombstones_release_correlation_capacity() {
        let mut registry = ResponseRegistry::new();
        registry
            .tombstones
            .extend((0..MAX_RESPONSE_CORRELATIONS).map(|id| {
                (
                    RequestId::String(format!("expired-{id}"))
                        .correlation_key()
                        .expect("test IDs are valid"),
                    Instant::now(),
                )
            }));

        let waiter = registry
            .register(RequestId::String("new-owner".to_string()))
            .expect("expired tombstones must be pruned before admission");

        assert_eq!(registry.tombstone_len(), 0);
        assert_eq!(registry.pending_len(), 1);
        drop(waiter);
    }

    #[test]
    fn cancellation_control_marker_is_at_most_once_per_request_generation() {
        let mut registry = ResponseRegistry::new();
        let request_id = RequestId::Number(23);

        assert!(
            registry
                .claim_cancellation_control(&request_id)
                .expect("first arbitrary-ID control claim")
        );
        assert!(
            !registry
                .claim_cancellation_control(&request_id)
                .expect("duplicate arbitrary-ID claim")
        );
        assert_eq!(registry.cancellation_control_len(), 1);

        let waiter = registry
            .register(request_id.clone())
            .expect("a new waiter generation is not poisoned by the old marker");
        assert_eq!(registry.cancellation_control_len(), 0);

        assert!(
            registry
                .claim_cancellation_control(&request_id)
                .expect("the admitted generation owns one fresh control claim")
        );
        assert!(
            registry.register(request_id).is_err(),
            "duplicate waiter admission must fail before clearing the live marker"
        );
        assert_eq!(registry.cancellation_control_len(), 1);
        drop(waiter);
    }

    #[test]
    fn cancellation_control_markers_have_bounded_absolute_lifetime() {
        assert_eq!(
            CANCELLATION_CONTROL_RETENTION, MAX_CLIENT_ABSOLUTE_TIMEOUT,
            "one marker must cover the longest ordinary request generation"
        );

        let mut registry = ResponseRegistry::new();
        let expired_id = RequestId::String("expired-control".to_string());
        registry.cancellation_controls.insert(
            expired_id.correlation_key().expect("test ID is valid"),
            Instant::now(),
        );
        assert!(
            registry
                .claim_cancellation_control(&expired_id)
                .expect("an exactly expired marker releases the ID")
        );
        assert_eq!(registry.cancellation_control_len(), 1);

        let expires_at = Instant::now()
            .checked_add(CANCELLATION_CONTROL_RETENTION)
            .expect("test clock admits fixed control retention");
        registry.cancellation_controls.clear();
        registry
            .cancellation_controls
            .extend((0..MAX_CANCELLATION_CONTROL_IDS).map(|id| {
                (
                    RequestId::String(format!("control-{id}"))
                        .correlation_key()
                        .expect("test IDs are valid"),
                    expires_at,
                )
            }));
        let error = registry
            .claim_cancellation_control(&RequestId::String("overflow".to_string()))
            .expect_err("control retention has a deterministic hard bound");
        assert!(error.message.contains("retention limit"));
        assert_eq!(
            registry.cancellation_control_len(),
            MAX_CANCELLATION_CONTROL_IDS
        );
    }

    #[test]
    fn response_registry_correlates_numeric_aliases() {
        let mut registry = ResponseRegistry::new();
        let mut waiter = registry
            .register(RequestId::Number(1))
            .expect("the first numeric request claims one correlation key");

        let response = JsonRpcResponse::success(
            RequestId::Integer("1e0".to_owned()),
            serde_json::Value::Null,
        );
        assert_eq!(
            registry.route(response),
            ResponseRoute::Delivered,
            "a mathematically equivalent numeric response reaches the live waiter"
        );
        let delivered = waiter
            .try_response()
            .expect("the live waiter receives its correlated response")
            .expect("the response was delivered synchronously");
        assert_eq!(delivered.id, Some(RequestId::Integer("1e0".to_owned())));
        assert_eq!(registry.pending_len(), 0);
    }

    #[test]
    fn response_registry_rejects_invalid_direct_integer_without_mutation() {
        let mut registry = ResponseRegistry::new();
        let baseline = RequestId::Integer("1".to_owned());
        let planted_invalid = RequestId::Integer("1.5".to_owned());
        let waiter = registry
            .register(baseline)
            .expect("the baseline mathematical integer request is admitted");
        let state_before = registry.pending_len();

        let error = registry
            .register(planted_invalid)
            .expect_err("changing only the lexeme to a fractional value cannot claim a slot");
        assert!(error.message.contains("Invalid JSON-RPC request ID"));
        assert_eq!(
            registry.pending_len(),
            state_before,
            "the directly constructed rejected ID leaves the live correlation state unchanged"
        );
        drop(waiter);
    }

    #[test]
    fn response_registry_rejects_live_numeric_alias_without_mutation() {
        let mut registry = ResponseRegistry::new();
        let waiter = registry
            .register(RequestId::Number(1))
            .expect("the baseline request is admitted");
        let state_before = registry.pending_len();

        assert!(
            registry
                .register(RequestId::Integer("1.0".to_owned()))
                .is_err(),
            "an exact numeric alias cannot create a second active request"
        );
        assert_eq!(registry.pending_len(), state_before);
        drop(waiter);
    }

    #[test]
    fn response_registry_invalid_envelope_fails_all_waiters() {
        let mut registry = ResponseRegistry::new();
        let mut waiter = registry
            .register(RequestId::Number(7))
            .expect("register waiter");
        let response = JsonRpcResponse {
            jsonrpc: std::borrow::Cow::Owned("1.0".to_string()),
            result: Some(serde_json::Value::Null),
            error: None,
            id: Some(RequestId::Number(7)),
        };

        assert_eq!(registry.route(response), ResponseRoute::InvalidEnvelope);
        let error = waiter
            .try_response()
            .expect_err("invalid envelope is connection-terminal");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert_eq!(error.message, INVALID_RESPONSE_ENVELOPE_ERROR);
    }

    #[test]
    fn response_registry_missing_id_fails_every_waiter_consistently() {
        let mut registry = ResponseRegistry::new();
        let mut first = registry
            .register(RequestId::Number(10))
            .expect("first waiter");
        let mut second = registry
            .register(RequestId::Number(11))
            .expect("second waiter");
        let missing_id_response = JsonRpcResponse::error(
            None,
            McpError::internal_error("uncorrelated peer error").into(),
        );

        assert_eq!(
            registry.route(missing_id_response),
            ResponseRoute::MissingId
        );
        assert_eq!(registry.pending_len(), 0);
        let first_error = first
            .try_response()
            .expect_err("missing ID must fail first waiter");
        let second_error = second
            .try_response()
            .expect_err("missing ID must fail second waiter");
        assert_eq!(first_error.code, second_error.code);
        assert_eq!(first_error.message, second_error.message);
        assert!(first_error.message.contains("missing a request ID"));

        let future_error = registry
            .register(RequestId::Number(12))
            .expect_err("failed connection rejects new waiter");
        assert_eq!(future_error.message, first_error.message);
    }

    #[test]
    fn response_registry_connection_loss_wakes_all_waiters_with_same_error() {
        let mut registry = ResponseRegistry::new();
        let mut first = registry
            .register(RequestId::Number(20))
            .expect("first waiter");
        let mut second = registry
            .register(RequestId::Number(21))
            .expect("second waiter");
        let connection_error = McpError::internal_error("Transport closed");

        assert_eq!(registry.fail_all(connection_error.clone()), 2);
        assert_eq!(registry.fail_all(connection_error), 0);
        let first_error = first
            .try_response()
            .expect_err("connection loss wakes first waiter");
        let second_error = second
            .try_response()
            .expect_err("connection loss wakes second waiter");
        assert_eq!(first_error.message, "Transport closed");
        assert_eq!(second_error.message, first_error.message);
    }

    #[test]
    fn response_registry_keeps_a_routed_success_when_connection_later_fails() {
        let mut registry = ResponseRegistry::new();
        let completed_id = RequestId::Number(22);
        let pending_id = RequestId::Number(23);
        let mut completed = registry
            .register(completed_id.clone())
            .expect("completed waiter");
        let mut pending = registry.register(pending_id).expect("pending waiter");

        assert_eq!(
            registry.route(JsonRpcResponse::success(
                completed_id.clone(),
                serde_json::json!({"terminal": "response"}),
            )),
            ResponseRoute::Delivered
        );
        assert_eq!(
            registry.fail_all(McpError::internal_error("connection failed afterward")),
            1
        );

        let completed_response = completed
            .try_response()
            .expect("the first terminal outcome remains authoritative")
            .expect("routed response is retained");
        assert_eq!(completed_response.id, Some(completed_id));
        assert_eq!(
            pending
                .try_response()
                .expect_err("still-pending waiter receives connection failure")
                .message,
            "connection failed afterward"
        );
    }

    #[test]
    fn response_registry_request_error_wakes_only_its_owner() {
        let mut registry = ResponseRegistry::new();
        let first_id = RequestId::Number(25);
        let second_id = RequestId::Number(26);
        let mut first = registry.register(first_id.clone()).expect("first waiter");
        let mut second = registry.register(second_id.clone()).expect("second waiter");

        assert!(registry.fail(
            &first_id,
            McpError::internal_error("first request timed out")
        ));
        let first_error = first
            .try_response()
            .expect_err("request-local error wakes its owner");
        assert_eq!(first_error.message, "first request timed out");
        assert!(
            second
                .try_response()
                .expect("second waiter remains valid")
                .is_none(),
            "a request-local error must not wake a sibling waiter"
        );

        assert_eq!(
            registry.route(JsonRpcResponse::success(
                second_id.clone(),
                serde_json::json!("second"),
            )),
            ResponseRoute::Delivered
        );
        let second_response = second
            .try_response()
            .expect("second waiter remains valid")
            .expect("second waiter receives its response");
        assert_eq!(second_response.id, Some(second_id));
    }

    #[test]
    fn response_registry_duplicate_registration_preserves_original_waiter() {
        let mut registry = ResponseRegistry::new();
        let id = RequestId::Number(30);
        let mut original = registry.register(id.clone()).expect("original waiter");
        let duplicate_error = registry
            .register(id.clone())
            .expect_err("duplicate ID must be rejected");
        assert!(duplicate_error.message.contains("Duplicate in-flight"));
        assert_eq!(registry.pending_len(), 1);

        assert_eq!(
            registry.route(JsonRpcResponse::success(
                id.clone(),
                serde_json::json!("original"),
            )),
            ResponseRoute::Delivered
        );
        let response = original
            .try_response()
            .expect("original waiter remains valid")
            .expect("original waiter receives response");
        assert_eq!(response.id, Some(id.clone()));

        assert_eq!(
            registry.route(JsonRpcResponse::success(id, serde_json::json!("duplicate"),)),
            ResponseRoute::UnknownId,
            "a second terminal response is late peer activity"
        );
    }

    #[test]
    fn response_registry_dropped_waiter_cannot_be_replaced() {
        let mut registry = ResponseRegistry::new();
        let id = RequestId::Number(40);
        let waiter = registry.register(id.clone()).expect("waiter");
        drop(waiter);

        assert_eq!(
            registry.route(JsonRpcResponse::success(id, serde_json::json!(true))),
            ResponseRoute::WaiterDropped
        );
        assert_eq!(registry.pending_len(), 0);
    }

    #[test]
    fn response_registry_bounds_unknown_id_diagnostics() {
        let mut registry = ResponseRegistry::new();
        for id in 0..u16::from(MAX_UNCORRELATED_RESPONSE_DIAGNOSTICS) + 5 {
            assert_eq!(
                registry.route(JsonRpcResponse::success(
                    RequestId::Number(i64::from(id)),
                    serde_json::Value::Null,
                )),
                ResponseRoute::UnknownId
            );
        }
        assert_eq!(
            registry.uncorrelated_diagnostics,
            MAX_UNCORRELATED_RESPONSE_DIAGNOSTICS
        );
    }

    #[test]
    fn response_registry_enforces_and_releases_in_flight_bound() {
        let mut registry = ResponseRegistry::new();
        for id in 0..MAX_IN_FLIGHT_RESPONSES {
            #[allow(clippy::cast_possible_wrap)]
            let waiter = registry
                .register(RequestId::Number(id as i64))
                .expect("waiter below bound");
            drop(waiter);
        }
        assert_eq!(registry.pending_len(), MAX_IN_FLIGHT_RESPONSES);

        let capacity_error = registry
            .register(RequestId::String("over-capacity".to_string()))
            .expect_err("waiter above bound must fail");
        assert!(capacity_error.message.contains("limit reached"));

        assert_eq!(
            registry.route(JsonRpcResponse::success(
                RequestId::Number(0),
                serde_json::Value::Null,
            )),
            ResponseRoute::WaiterDropped
        );
        let replacement = registry
            .register(RequestId::String("replacement".to_string()))
            .expect("terminal cleanup releases one slot");
        drop(replacement);
        assert_eq!(registry.pending_len(), MAX_IN_FLIGHT_RESPONSES);
    }

    #[test]
    fn terminal_send_failure_wakes_all_registered_waiters() {
        let mut client = make_closed_client(true);
        let first_id = RequestId::Number(50);
        let second_id = RequestId::Number(51);
        let mut first = client
            .responses
            .register(first_id.clone())
            .expect("first waiter");
        let mut second = client.responses.register(second_id).expect("second waiter");

        let error = client.record_send_failure(
            Some(&first_id),
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "connection lost",
            )),
        );

        assert!(error.message.contains("connection lost"));
        assert!(
            !client.is_initialized(),
            "a terminal transport failure must clear initialized state"
        );
        assert_eq!(client.responses.pending_len(), 0);
        for waiter in [&mut first, &mut second] {
            let waiter_error = waiter
                .try_response()
                .expect_err("terminal send failure must wake every waiter");
            assert_eq!(waiter_error.message, error.message);
        }
        assert!(
            client.responses.register(RequestId::Number(52)).is_err(),
            "a terminal send failure permanently closes registration"
        );
        assert!(client.child.is_none(), "terminal failure reaps the child");
        let later = client
            .cancel_request(50_i64, None, false)
            .expect_err("initialized APIs must not retry a terminal connection");
        assert_eq!(later.code, error.code);
        assert_eq!(later.message, error.message);
    }

    #[test]
    fn local_task_poll_interval_has_explicit_bounds() {
        assert!(validate_task_poll_interval(Duration::ZERO).is_err());
        assert!(validate_task_poll_interval(Duration::from_nanos(1)).is_err());
        assert_eq!(
            validate_task_poll_interval(MIN_TASK_POLL_INTERVAL).unwrap(),
            MIN_TASK_POLL_INTERVAL
        );
        assert_eq!(
            validate_task_poll_interval(Duration::from_millis(25)).unwrap(),
            Duration::from_millis(25)
        );
        assert_eq!(
            validate_task_poll_interval(MAX_LOCAL_TASK_POLL_INTERVAL).unwrap(),
            MAX_LOCAL_TASK_POLL_INTERVAL
        );
        assert!(
            validate_task_poll_interval(MAX_LOCAL_TASK_POLL_INTERVAL + Duration::from_nanos(1))
                .is_err()
        );
        assert!(validate_task_poll_interval(Duration::MAX).is_err());
    }

    #[test]
    fn invalid_local_poll_interval_is_rejected_before_a_task_request() {
        let mut client = make_closed_client(true);

        let error = client
            .wait_for_task("task", Duration::ZERO)
            .expect_err("zero would permit a busy polling loop");

        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(client.next_id.load(Ordering::SeqCst), 2);
        assert!(client.is_initialized());
        assert!(client.responses.terminal_error().is_none());
    }

    #[test]
    fn task_info_validation_rejects_semantic_contradictions() {
        for invalid_progress in [f64::NAN, f64::INFINITY, -0.01, 1.01] {
            let mut task = task_info("task", TaskStatus::Running);
            task.progress = Some(invalid_progress);
            assert!(validate_task_info(&task).is_err());
        }

        let mut pending_with_start = task_info("task", TaskStatus::Pending);
        pending_with_start.started_at = Some("2026-08-01T00:00:01Z".to_string());
        assert!(validate_task_info(&pending_with_start).is_err());

        let mut active_with_completion = task_info("task", TaskStatus::Running);
        active_with_completion.completed_at = Some("2026-08-01T00:00:01Z".to_string());
        assert!(validate_task_info(&active_with_completion).is_err());

        let mut completed_with_error = task_info("task", TaskStatus::Completed);
        completed_with_error.error = Some("contradictory failure".to_string());
        assert!(validate_task_info(&completed_with_error).is_err());

        let mut failed_with_error = task_info("task", TaskStatus::Failed);
        failed_with_error.error = Some("failed".to_string());
        assert!(validate_task_info(&failed_with_error).is_ok());

        let mut cancelled_with_reason = task_info("task", TaskStatus::Cancelled);
        cancelled_with_reason.error = Some("cancelled by caller".to_string());
        assert!(validate_task_info(&cancelled_with_reason).is_ok());
    }

    #[test]
    fn task_result_validation_rejects_payload_status_contradictions() {
        let completed = task_info("task", TaskStatus::Completed);
        let success_with_error = TaskResult {
            id: completed.id.clone(),
            success: true,
            data: None,
            error: Some("contradictory error".to_string()),
        };
        assert!(validate_task_result(&completed, &success_with_error).is_err());

        let failed = task_info("task", TaskStatus::Failed);
        let failure_with_data = TaskResult {
            id: failed.id.clone(),
            success: false,
            data: Some(serde_json::json!({"partial": true})),
            error: Some("failed".to_string()),
        };
        assert!(validate_task_result(&failed, &failure_with_data).is_err());

        let mut cancelled = task_info("task", TaskStatus::Cancelled);
        cancelled.error = Some("cancelled by caller".to_string());
        let cancelled_result = TaskResult {
            id: cancelled.id.clone(),
            success: false,
            data: None,
            error: Some("cancelled by caller".to_string()),
        };
        assert!(validate_task_result(&cancelled, &cancelled_result).is_ok());
    }

    #[test]
    fn get_task_validation_rejects_cross_task_and_contradictory_results() {
        let requested = TaskId::from_string("requested");
        let wrong_task = GetTaskResult {
            task: task_info("different", TaskStatus::Completed),
            result: None,
        };
        assert!(validate_get_task_result(&requested, &wrong_task).is_err());

        let wrong_result = GetTaskResult {
            task: task_info("requested", TaskStatus::Completed),
            result: Some(TaskResult {
                id: TaskId::from_string("different"),
                success: true,
                data: None,
                error: None,
            }),
        };
        assert!(validate_get_task_result(&requested, &wrong_result).is_err());

        let premature_result = GetTaskResult {
            task: task_info("requested", TaskStatus::Running),
            result: Some(TaskResult {
                id: requested.clone(),
                success: true,
                data: None,
                error: None,
            }),
        };
        assert!(validate_get_task_result(&requested, &premature_result).is_err());

        let contradictory_success = GetTaskResult {
            task: task_info("requested", TaskStatus::Failed),
            result: Some(TaskResult {
                id: requested.clone(),
                success: true,
                data: None,
                error: Some("failed".to_string()),
            }),
        };
        assert!(validate_get_task_result(&requested, &contradictory_success).is_err());

        let completed_without_result = GetTaskResult {
            task: task_info("requested", TaskStatus::Completed),
            result: None,
        };
        assert!(validate_get_task_result(&requested, &completed_without_result).is_err());

        let failed_without_result = GetTaskResult {
            task: task_info("requested", TaskStatus::Failed),
            result: None,
        };
        assert!(validate_get_task_result(&requested, &failed_without_result).is_ok());

        let valid = GetTaskResult {
            task: task_info("requested", TaskStatus::Cancelled),
            result: Some(TaskResult {
                id: requested.clone(),
                success: false,
                data: None,
                error: Some("cancelled".to_string()),
            }),
        };
        assert!(validate_get_task_result(&requested, &valid).is_ok());
    }

    #[test]
    fn cancel_task_validation_correlates_id_without_inventing_finality() {
        let requested = TaskId::from_string("requested");
        let wrong_task = CancelTaskResult {
            cancelled: true,
            task: task_info("different", TaskStatus::Cancelled),
        };
        assert!(validate_cancel_task_result(&requested, &wrong_task).is_err());

        let false_acknowledgement = CancelTaskResult {
            cancelled: false,
            task: task_info("requested", TaskStatus::Running),
        };
        assert!(validate_cancel_task_result(&requested, &false_acknowledgement).is_ok());

        let already_cancelled = CancelTaskResult {
            cancelled: false,
            task: task_info("requested", TaskStatus::Cancelled),
        };
        assert!(validate_cancel_task_result(&requested, &already_cancelled).is_ok());

        let eventual_acknowledgement = CancelTaskResult {
            cancelled: true,
            task: task_info("requested", TaskStatus::Running),
        };
        assert!(validate_cancel_task_result(&requested, &eventual_acknowledgement).is_ok());

        let accepted = CancelTaskResult {
            cancelled: true,
            task: task_info("requested", TaskStatus::Cancelled),
        };
        assert!(validate_cancel_task_result(&requested, &accepted).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn get_task_protocol_violation_terminates_the_connection() {
        let response = JsonRpcMessage::Response(JsonRpcResponse::success(
            RequestId::Number(2),
            serde_json::to_value(GetTaskResult {
                task: task_info("requested", TaskStatus::Completed),
                result: None,
            })
            .expect("serialize invalid tasks/get result"),
        ));
        let mut client = make_scripted_initialized_client(response);

        let error = client
            .get_task("requested")
            .expect_err("a completed task without its result must fail closed");

        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(!client.is_initialized());
        assert!(client.child.is_none());
        assert!(client.responses.terminal_error().is_some());
        let later = client
            .get_task("requested")
            .expect_err("a protocol violation permanently closes the connection");
        assert_eq!(later.code, error.code);
        assert_eq!(later.message, error.message);
    }

    #[cfg(unix)]
    #[test]
    fn accepted_task_cancellation_does_not_invent_terminal_state() {
        let response = JsonRpcMessage::Response(JsonRpcResponse::success(
            RequestId::Number(2),
            serde_json::to_value(CancelTaskResult {
                cancelled: true,
                task: task_info("requested", TaskStatus::Running),
            })
            .expect("serialize invalid tasks/cancel result"),
        ));
        let mut client = make_scripted_initialized_client(response);

        let task = client
            .cancel_task("requested")
            .expect("an eventual acknowledgement may retain a running snapshot");

        assert_eq!(task.status, TaskStatus::Running);
        assert!(client.is_initialized());
        assert!(client.child.is_some());
        assert!(client.responses.terminal_error().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn rejected_task_cancellation_is_an_error_without_closing_the_connection() {
        let response = JsonRpcMessage::Response(JsonRpcResponse::success(
            RequestId::Number(2),
            serde_json::to_value(CancelTaskResult {
                cancelled: false,
                task: task_info("requested", TaskStatus::Running),
            })
            .expect("serialize rejected tasks/cancel result"),
        ));
        let mut client = make_scripted_initialized_client(response);

        let error = client
            .cancel_task("requested")
            .expect_err("a rejected cancellation cannot be returned as success");

        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(client.is_initialized());
        assert!(client.child.is_some());
        assert!(client.responses.terminal_error().is_none());
    }

    #[test]
    fn task_poll_wait_observes_preexisting_cancellation() {
        let mut client = make_closed_client(true);
        client.cx.set_cancel_requested(true);

        let error = client
            .wait_for_next_task_poll(Duration::ZERO)
            .expect_err("a cancelled client must not enter the polling delay");

        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert!(!client.is_initialized());
        assert!(client.child.is_none());
        assert!(client.responses.terminal_error().is_some());
    }

    #[test]
    fn task_poll_wait_observes_all_stored_context_budget_exhaustion() {
        for budget in [
            asupersync::Budget::new().with_poll_quota(0),
            asupersync::Budget::new().with_cost_quota(0),
        ] {
            let cx = Cx::for_testing_with_budget(budget);
            let mut client = make_closed_client_with_cx(true, cx);

            let error = client
                .wait_for_next_task_poll(Duration::from_secs(1))
                .expect_err("an exhausted client context must reject polling");

            assert_eq!(error.code, McpErrorCode::RequestCancelled);
            assert!(!client.is_initialized());
            assert!(client.child.is_none());
            assert!(client.responses.terminal_error().is_some());
        }
    }

    #[test]
    fn task_poll_wait_caps_wall_blocking_to_stored_context_deadline() {
        let clock = Cx::for_testing();
        let deadline = clock.now().saturating_add_nanos(20_000_000);
        let cx = Cx::for_testing_with_budget(asupersync::Budget::new().with_deadline(deadline));
        let mut client = make_closed_client_with_cx(true, cx);
        let started = Instant::now();

        let error = client
            .wait_for_next_task_poll(Duration::from_secs(1))
            .expect_err("the client deadline must interrupt a longer poll interval");

        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(!client.is_initialized());
    }

    #[test]
    fn task_poll_wait_observes_cross_thread_client_cancellation() {
        let cx = Cx::for_testing();
        let canceller = cx.clone();
        let mut client = make_closed_client_with_cx(true, cx);
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            canceller.set_cancel_requested(true);
        });
        let started = Instant::now();

        let error = client
            .wait_for_next_task_poll(Duration::from_secs(1))
            .expect_err("client cancellation must interrupt the poll wait");

        thread.join().expect("canceller thread");
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(!client.is_initialized());
    }

    #[test]
    fn task_poll_wait_ignores_unrelated_ambient_context() {
        let mut client = make_closed_client_with_cx(true, Cx::for_testing());
        let ambient = Cx::for_testing();
        ambient.set_cancel_requested(true);
        let _ambient_guard = Cx::set_current(Some(ambient));

        client
            .wait_for_next_task_poll(Duration::from_millis(1))
            .expect("only the stored client context controls polling");

        assert!(client.is_initialized());
        assert!(client.child.is_some());
    }

    #[test]
    fn out_of_policy_task_poll_interval_is_non_terminal_input_error() {
        let mut client = make_closed_client(true);

        let error = client
            .wait_for_next_task_poll(Duration::MAX)
            .expect_err("an excessive local fallback interval must be rejected");

        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert!(client.is_initialized());
        assert!(client.child.is_some());
        assert!(client.responses.terminal_error().is_none());
    }

    #[test]
    fn client_close_wakes_registered_waiter_before_transport_teardown() {
        let mut client = make_closed_client(true);
        let mut waiter = client
            .responses
            .register(RequestId::Number(55))
            .expect("waiter");

        client.close().expect("client cleanup");

        let error = waiter
            .try_response()
            .expect_err("close must publish a terminal waiter outcome");
        assert_eq!(error.message, "Client connection closed");
        assert!(!client.is_initialized());
        assert!(client.ping().is_err());
        client
            .close()
            .expect("repeated successful close must be idempotent");
    }

    #[test]
    fn reality_check_regression_terminal_cleanup_failure_cannot_become_later_success() {
        let mut client = make_closed_client(true);
        client.cleanup_error = Some(McpError::internal_error(
            "deterministic retained cleanup failure",
        ));

        let first = client
            .close()
            .expect_err("retained cleanup failure must be observable");
        let second = client
            .close()
            .expect_err("terminal cleanup failure must remain sticky");

        assert!(first.message.contains("cleanup failure"));
        assert!(second.message.contains("cleanup failure"));
    }

    #[test]
    fn reality_check_regression_completed_process_retry_clears_transient_failure() {
        let mut client = make_closed_client(true);
        client.pending_process_cleanup_error = Some(McpError::internal_error(
            "previous retryable process-cleanup timeout",
        ));
        client.child_cleanup_phase = ClientChildCleanupPhase::Complete;

        client
            .close()
            .expect("completed cleanup must clear a transient prior attempt");
        assert!(client.pending_process_cleanup_error.is_none());
        assert!(!client.is_initialized());
    }

    #[test]
    fn request_encoding_failure_is_isolated_to_its_registered_owner() {
        let mut client = make_closed_client(true);
        let first_id = RequestId::Number(60);
        let second_id = RequestId::Number(61);
        let mut first = client
            .responses
            .register(first_id.clone())
            .expect("first waiter");
        let mut second = client
            .responses
            .register(second_id.clone())
            .expect("second waiter");

        let error = client.record_send_failure(
            Some(&first_id),
            TransportError::Codec(fastmcp_transport::CodecError::MessageTooLarge(1_000_000)),
        );

        assert_eq!(error.message, TRANSPORT_CODEC_ERROR);
        assert_eq!(client.responses.pending_len(), 1);
        assert_eq!(
            first
                .try_response()
                .expect_err("encoding failure wakes only its owner")
                .message,
            error.message
        );
        assert!(
            second
                .try_response()
                .expect("sibling waiter remains valid")
                .is_none()
        );
        assert_eq!(
            client
                .responses
                .route(JsonRpcResponse::success(second_id, serde_json::Value::Null,)),
            ResponseRoute::Delivered
        );
        assert!(
            second
                .try_response()
                .expect("sibling waiter remains valid")
                .is_some()
        );
    }

    #[test]
    fn client_from_parts_accessors_and_request_counter() {
        let client = make_closed_client(true);
        assert!(client.is_initialized());
        assert_eq!(client.server_info().name, "test-server");
        let caps_json = serde_json::to_value(client.server_capabilities()).expect("caps json");
        assert_eq!(caps_json, serde_json::json!({}));
        assert_eq!(client.protocol_version(), PROTOCOL_VERSION);
        assert_eq!(client.next_request_id().expect("request ID"), 2);
        assert_eq!(client.next_request_id().expect("request ID"), 3);
    }

    #[test]
    fn ensure_initialized_noop_when_already_initialized() {
        let mut client = make_closed_client(true);
        assert!(client.ensure_initialized().is_ok());
        assert!(client.is_initialized());
    }

    #[test]
    fn ensure_initialized_fails_for_uninitialized_closed_transport() {
        let mut client = make_closed_client(false);
        std::thread::sleep(Duration::from_millis(50));
        let err = client
            .ensure_initialized()
            .expect_err("expected init failure");
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
        assert!(!client.is_initialized());
    }

    #[test]
    fn client_core_api_methods_error_cleanly_on_closed_transport() {
        let mut client = make_closed_client(true);
        std::thread::sleep(Duration::from_millis(50));

        let _ = client.cancel_request(7i64, Some("stop".to_string()), true);
        assert!(client.list_tools().is_err());
        assert!(
            client
                .call_tool("echo", serde_json::json!({"text": "hi"}))
                .is_err()
        );

        let mut progress_events: Vec<(f64, Option<f64>, Option<String>)> = Vec::new();
        let mut on_progress = |p: f64, total: Option<f64>, msg: Option<&str>| {
            progress_events.push((p, total, msg.map(ToString::to_string)));
        };
        assert!(
            client
                .call_tool_with_progress(
                    "echo",
                    serde_json::json!({"text": "hi"}),
                    &mut on_progress
                )
                .is_err()
        );
        assert!(progress_events.is_empty());

        assert!(client.list_resources().is_err());
        assert!(client.list_resource_templates().is_err());
        assert!(client.set_log_level(LogLevel::Debug).is_err());
        assert!(client.read_resource("resource://test").is_err());
        assert!(client.list_prompts().is_err());

        let mut args = HashMap::new();
        args.insert("name".to_string(), "world".to_string());
        assert!(client.get_prompt("greeting", args).is_err());

        assert!(
            client
                .submit_task("data_export", serde_json::json!({"batch": 1}))
                .is_err()
        );
        assert!(
            client
                .list_tasks(Some(TaskStatus::Running), Some("c1"), Some(10))
                .is_err()
        );
        assert!(client.list_tasks_all(None).is_err());
        assert!(client.get_task("task-1").is_err());
        assert!(client.cancel_task("task-1").is_err());
        assert!(
            client
                .cancel_task_with_reason("task-1", Some("no longer needed"))
                .is_err()
        );
        assert!(
            client
                .wait_for_task("task-1", Duration::from_millis(1))
                .is_err()
        );

        let mut task_progress = Vec::new();
        let mut on_task_progress = |p: f64, msg: Option<&str>| {
            task_progress.push((p, msg.map(ToString::to_string)));
        };
        assert!(
            client
                .wait_for_task_with_progress(
                    "task-1",
                    Duration::from_millis(1),
                    &mut on_task_progress
                )
                .is_err()
        );
        assert!(task_progress.is_empty());
    }

    #[test]
    fn close_handles_already_exited_subprocess() {
        let mut client = make_closed_client(true);
        std::thread::sleep(Duration::from_millis(50));
        client.close().expect("client cleanup");
    }

    // ========================================
    // Client::builder and Client::stdio error
    // ========================================

    #[test]
    fn client_builder_returns_client_builder() {
        let _builder = Client::builder();
        // builder() is a convenience method for ClientBuilder::new()
    }

    #[test]
    fn client_stdio_fails_for_nonexistent_command() {
        let result = Client::stdio("definitely-not-a-real-command-xyz", &[]);
        assert!(result.is_err());
        let err = result.err().expect("should be error");
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
        assert!(err.message.contains("spawn"));
    }

    #[test]
    fn client_stdio_with_cx_fails_when_cancelled() {
        let cx = Cx::for_request();
        cx.set_cancel_requested(true);
        let result = Client::stdio_with_cx("echo", &["hello"], cx);
        // Should fail either from cancellation or from the process not speaking MCP
        assert!(result.is_err());
    }

    // ========================================
    // Uninitialized client accessors
    // ========================================

    #[test]
    fn uninitialized_client_is_not_initialized() {
        let client = make_closed_client(false);
        assert!(!client.is_initialized());
    }

    #[test]
    fn uninitialized_client_server_info_is_empty() {
        let client = make_closed_client(false);
        assert_eq!(client.server_info().name, "test-server");
        assert_eq!(client.server_info().version, "1.0.0");
    }

    #[test]
    fn uninitialized_client_request_id_starts_at_one() {
        let client = make_closed_client(false);
        assert_eq!(client.next_request_id().expect("request ID"), 1);
        assert_eq!(client.next_request_id().expect("request ID"), 2);
    }

    #[test]
    fn initialized_client_request_id_starts_at_two() {
        let client = make_closed_client(true);
        // from_parts starts at 2 because initialize used id 1
        assert_eq!(client.next_request_id().expect("request ID"), 2);
        assert_eq!(client.next_request_id().expect("request ID"), 3);
    }

    #[cfg(unix)]
    #[test]
    fn direct_stdio_initialization_consumes_id_one_before_ordinary_requests() {
        let initialize_result = InitializeResult {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ServerCapabilities::default(),
            server_info: ServerInfo {
                name: "direct-path-test-server".to_string(),
                version: "1.0.0".to_string(),
            },
            instructions: None,
        };
        let response = JsonRpcMessage::Response(JsonRpcResponse::success(
            RequestId::Number(INITIALIZE_REQUEST_ID),
            serde_json::to_value(initialize_result).expect("serialize initialize result"),
        ));
        let response_line = serde_json::to_string(&response).expect("serialize response envelope");
        assert!(
            !response_line.contains('\''),
            "the shell fixture requires a single-quote-free JSON line"
        );
        let script = format!("printf '%s\\n' '{response_line}'; exec sleep 2");

        let mut client = Client::stdio_with_cx("sh", &["-c", script.as_str()], Cx::for_request())
            .expect("direct stdio initialization succeeds");
        assert_eq!(
            client
                .next_request_id()
                .expect("first post-initialize request ID"),
            2,
            "initialize ID 1 must never be reused"
        );
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn eager_initialization_uses_bounded_server_response_writes() {
        // The direct child control path intentionally accepts only frames that
        // fit the POSIX minimum atomic pipe-write bound. An oversized
        // peer-initiated invalid-notification response therefore gives us a
        // deterministic proof that eager initialization uses that path; the
        // ordinary blocking transport send would accept this frame and merely
        // wait for the scripted peer until the request deadline. The request
        // ID stays within its protocol bound; the long method is what makes
        // the correlated error response exceed the atomic capacity.
        let request =
            JsonRpcRequest::new(format!("notifications/{}", "x".repeat(600)), None, 7_i64);
        let response = server_request_response(&request)
            .expect("an ID-bearing notification-shaped method receives an error response");
        let response_size = serde_json::to_vec(&response)
            .expect("serialize the bounded-write response precondition")
            .len()
            .checked_add(1)
            .expect("newline cannot overflow the response size");
        assert!(
            response_size > 512,
            "fixture response must exceed the POSIX minimum atomic pipe-write bound"
        );
        let request = JsonRpcMessage::Request(request);
        let request_line = serde_json::to_string(&request).expect("serialize server request");
        assert!(
            !request_line.contains('\''),
            "the shell fixture requires a single-quote-free JSON line"
        );
        let script = format!("printf '%s\\n' '{request_line}'; exec sleep 2");

        let result = ClientBuilder::new()
            .request_timeout_policy(
                RequestTimeoutPolicy::new(Duration::from_secs(1), Duration::from_secs(1)).unwrap(),
            )
            .connect_stdio_with_cx("sh", &["-c", script.as_str()], &Cx::for_request());
        let error = result
            .err()
            .expect("oversized initialization control response must fail closed");

        assert_eq!(error.code, McpErrorCode::InternalError);
        assert_eq!(error.message, CONTROL_FRAME_CAPACITY_ERROR);
    }

    #[test]
    fn request_id_allocator_fails_closed_before_wrap_or_reuse() {
        let client = make_closed_client(true);
        client
            .next_id
            .store(REQUEST_ID_EXHAUSTION_SENTINEL - 1, Ordering::SeqCst);

        assert_eq!(
            client.next_request_id().expect("last issuable request ID"),
            REQUEST_ID_EXHAUSTION_SENTINEL - 1
        );
        let exhausted = client
            .next_request_id()
            .expect_err("sentinel and wrapped IDs must never be issued");
        assert!(exhausted.message.contains("ID space exhausted"));
        assert_eq!(
            client.next_id.load(Ordering::SeqCst),
            REQUEST_ID_EXHAUSTION_SENTINEL,
            "exhaustion is permanent and cannot wrap back to a live ID"
        );
    }

    // ========================================
    // API methods on uninitialized client
    // ========================================

    #[test]
    fn uninitialized_client_list_tools_fails_on_init() {
        let mut client = make_closed_client(false);
        std::thread::sleep(Duration::from_millis(50));
        let err = client.list_tools().expect_err("should fail");
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
    }

    #[test]
    fn uninitialized_client_call_tool_fails_on_init() {
        let mut client = make_closed_client(false);
        std::thread::sleep(Duration::from_millis(50));
        let err = client
            .call_tool("echo", serde_json::json!({"text": "hi"}))
            .expect_err("should fail");
        assert_eq!(err.code, fastmcp_core::McpErrorCode::InternalError);
    }

    #[test]
    fn uninitialized_client_list_resources_fails_on_init() {
        let mut client = make_closed_client(false);
        std::thread::sleep(Duration::from_millis(50));
        assert!(client.list_resources().is_err());
    }

    #[test]
    fn uninitialized_client_list_prompts_fails_on_init() {
        let mut client = make_closed_client(false);
        std::thread::sleep(Duration::from_millis(50));
        assert!(client.list_prompts().is_err());
    }

    #[test]
    fn failed_auto_initialization_is_terminal_for_the_connection() {
        let mut client = make_closed_client(false);
        std::thread::sleep(Duration::from_millis(50));

        let first = client
            .ensure_initialized()
            .expect_err("closed child cannot initialize");
        assert!(client.initialization_error.is_some());
        assert!(client.child.is_none());

        let second = client
            .ensure_initialized()
            .expect_err("terminal failure must not retry initialize");
        assert_eq!(second.code, first.code);
        assert_eq!(second.message, first.message);
    }

    #[test]
    fn uninitialized_client_cannot_send_cancellation_before_lifecycle_ack() {
        let mut client = make_closed_client(false);
        std::thread::sleep(Duration::from_millis(50));
        let error = client
            .cancel_request(99_i64, None, false)
            .expect_err("cancellation must initialize the session first");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);
        assert!(!client.is_initialized());
    }

    #[cfg(unix)]
    fn modern_public_client_script(discovery_response: &str) -> String {
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r second || exit 1; \
             case \"$second\" in *ping*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{}}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn legacy_public_client_script() -> &'static str {
        "IFS= read -r first || exit 1; \
         case \"$first\" in *initialize*2024-11-05*) \
         printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-server\",\"version\":\"1.0.0\"}}}' ;; *) exit 1 ;; esac; \
         IFS= read -r lifecycle || exit 1; \
         case \"$lifecycle\" in *notifications/initialized*) ;; *) exit 1 ;; esac; \
         IFS= read -r request || exit 1; \
         case \"$request\" in *ping*) \
         printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}' ;; *) exit 1 ;; esac; \
         exec sleep 2"
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_i_positive() {
        let modern_result = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersions\":[\"2026-07-28\"],\"capabilities\":{},\"serverInfo\":{\"name\":\"modern-server\",\"version\":\"1.0.0\"}}}";
        let script = modern_public_client_script(modern_result);
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern-only discovery initializes the public client");

        assert_eq!(client.protocol_policy(), ProtocolPolicy::ModernOnly);
        assert_eq!(
            client.selected_protocol_era(),
            Some(ProtocolEra::Modern2026)
        );
        assert_eq!(client.protocol_version(), MODERN_PROTOCOL_VERSION);
        client
            .ping()
            .expect("modern execution sends per-request metadata after discovery");
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_i_planted_negative() {
        // Only the discovery result's advertised version differs from the
        // accepted modern path. A malformed modern success may not turn into
        // legacy initialization or a second execution path.
        let legacy_advertisement = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersions\":[\"2024-11-05\"],\"capabilities\":{},\"serverInfo\":{\"name\":\"modern-server\",\"version\":\"1.0.0\"}}}";
        let script = modern_public_client_script(legacy_advertisement);
        let error = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .err()
        .expect("modern-only must reject a legacy-only discovery success");

        assert_eq!(error.code, McpErrorCode::InternalError);
    }

    #[cfg(unix)]
    #[test]
    fn clt_02_i_positive() {
        let modern_result = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersions\":[\"2026-07-28\"],\"capabilities\":{},\"serverInfo\":{\"name\":\"auto-modern-server\",\"version\":\"1.0.0\"}}}";
        let script = modern_public_client_script(modern_result);
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::Auto),
            Cx::for_request(),
        )
        .expect("auto retains a successful modern selection");

        assert_eq!(client.protocol_policy(), ProtocolPolicy::Auto);
        assert_eq!(
            client.selected_protocol_era(),
            Some(ProtocolEra::Modern2026)
        );
        client
            .ping()
            .expect("auto-selected modern client executes normally");
        client.close().expect("auto modern cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_02_i_planted_negative() {
        // Only the discovery result's version differs from the Auto positive.
        // An invalid modern success is not an authorized fallback signal.
        let legacy_advertisement = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersions\":[\"2024-11-05\"],\"capabilities\":{},\"serverInfo\":{\"name\":\"auto-modern-server\",\"version\":\"1.0.0\"}}}";
        let script = modern_public_client_script(legacy_advertisement);
        let error = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::Auto),
            Cx::for_request(),
        )
        .err()
        .expect("auto must not downgrade from a malformed modern discovery result");

        assert_eq!(error.code, McpErrorCode::InternalError);
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_i_positive() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_public_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy-only runs exact initialize and lifecycle acknowledgement");

        assert_eq!(client.protocol_policy(), ProtocolPolicy::LegacyOnly);
        assert_eq!(
            client.selected_protocol_era(),
            Some(ProtocolEra::Legacy2024)
        );
        assert_eq!(client.protocol_version(), PROTOCOL_VERSION);
        client
            .ping()
            .expect("legacy client executes after initialized notification");
        client.close().expect("legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_i_planted_negative() {
        // Only the immutable policy differs from the accepted legacy path.
        // The modern probe is not permitted to reuse the 2024 lifecycle.
        let error = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_public_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .err()
        .expect("modern-only must reject a legacy-only peer before initialization");

        assert_eq!(error.code, McpErrorCode::InternalError);
    }

    // ========================================
    // Drop behavior
    // ========================================

    #[test]
    fn uncertain_direct_child_probe_never_authorizes_termination() {
        let probe: std::io::Result<Option<ExitStatus>> =
            Err(std::io::Error::other("injected child-status uncertainty"));

        assert_eq!(
            direct_child_stop_decision(&probe),
            DirectChildStopDecision::DoNotSignal
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_guard_terminates_and_reaps_direct_child() {
        let (child, stdout, stdin, pid) = spawn_long_running_child();
        let guard = ChildGuard::new(child);

        drop(guard);
        drop(stdout);
        drop(stdin);
        wait_for_process_exit(pid);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn client_close_terminates_and_reaps_direct_child() {
        let (child, stdout, stdin, pid) = spawn_long_running_child();
        let transport = StdioTransport::new(stdout, stdin);
        let session = ClientSession::new(
            ClientInfo {
                name: "cleanup-test".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            ServerInfo {
                name: "direct-child".to_string(),
                version: "1.0.0".to_string(),
            },
            ServerCapabilities::default(),
            PROTOCOL_VERSION.to_string(),
        );
        let mut client = Client::from_parts(
            child,
            transport,
            Cx::for_request(),
            session,
            RequestTimeoutPolicy::default(),
        );

        client.close().expect("client cleanup");
        wait_for_process_exit(pid);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn client_drop_terminates_and_reaps_live_direct_child() {
        let (child, stdout, stdin, pid) = spawn_long_running_child();
        let transport = StdioTransport::new(stdout, stdin);
        let session = ClientSession::new(
            ClientInfo {
                name: "drop-cleanup-test".to_string(),
                version: "1.0.0".to_string(),
            },
            ClientCapabilities::default(),
            ServerInfo {
                name: "live-direct-child".to_string(),
                version: "1.0.0".to_string(),
            },
            ServerCapabilities::default(),
            PROTOCOL_VERSION.to_string(),
        );
        let client = Client::from_parts(
            child,
            transport,
            Cx::for_request(),
            session,
            RequestTimeoutPolicy::default(),
        );

        drop(client);
        wait_for_process_exit(pid);
    }

    #[test]
    fn drop_cleans_up_subprocess() {
        // Verify that dropping a client doesn't panic even for closed transport
        let client = make_closed_client(true);
        std::thread::sleep(Duration::from_millis(50));
        drop(client);
        // If we get here without panicking, the test passes
    }

    #[test]
    fn client_progress_params_debug() {
        let params = ClientProgressParams {
            marker: ProgressMarker::Number(1),
            progress: 0.5,
            total: Some(1.0),
            message: Some("half".into()),
            meta: None,
        };
        let debug = format!("{:?}", params);
        assert!(debug.contains("progress"));
    }

    #[test]
    fn transport_error_to_mcp_preserves_io_details() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "socket vanished");
        let mcp_err = transport_error_to_mcp(TransportError::Io(io_err));
        assert!(mcp_err.message.contains("socket vanished"));
    }

    #[test]
    fn method_not_found_response_error_message_redacts_method() {
        let request = JsonRpcRequest::new("totally/custom/method", None, 1i64);
        let response = method_not_found_response(&request).unwrap();
        if let JsonRpcMessage::Response(resp) = response {
            let error = resp.error.unwrap();
            assert_eq!(error.message, "Method not found");
            assert!(!error.message.contains("totally/custom/method"));
        }
    }

    #[test]
    fn client_server_capabilities_default_is_empty() {
        let client = make_closed_client(true);
        let caps = client.server_capabilities();
        // Default capabilities should have no features enabled
        assert!(caps.tools.is_none());
        assert!(caps.resources.is_none());
        assert!(caps.prompts.is_none());
    }
}
