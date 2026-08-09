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
mod cache;
mod execution;
pub mod http_auth;
pub mod http_executor;
pub mod mcp_config;
mod negotiation;
mod session;
pub mod sse;

pub use builder::ClientBuilder;
pub use cache::{
    CachePartitionKey, DEFAULT_FINAL_CACHE_CAPACITY, DEFAULT_FINAL_CACHE_MAX_BYTES,
    FinalCacheGeneration, FinalCacheInsert, FinalCacheKey, FinalCacheLookup, FinalCacheMiss,
    FinalCacheResultSet, FinalCacheStats, FinalResultCache, MAX_FINAL_CACHE_CAPACITY,
    MAX_FINAL_CACHE_MAX_BYTES,
};
pub use execution::{
    CancellationRequested, ExecutionTerminalReason, ExecutionTerminalRecord,
    ExecutionTerminalState, FinalCacheTtlDiagnostic, OpaquePagination, PaginationBounds,
    PendingRequestRecord, Request, RequestExecution, RequestExecutor, clt_01_a_manifest_digest,
    clt_01_b_manifest_digest,
};
pub use fastmcp_core::CanonicalHttpUrl;
pub use fastmcp_protocol::common_types::LoggingLevel;
pub use fastmcp_protocol::extensions::McpAppsClientSettings;
pub use fastmcp_protocol::protocol_policy::{
    HttpEndpointBundle, HttpEndpointBundleError, HttpModernProbe, HttpProbeBody, ProtocolEra,
    ProtocolPolicy, ProtocolVersion,
};
pub use fastmcp_protocol::tasks_extension::{
    CancelTaskResult as FinalCancelTaskResult, GetTaskResult as FinalGetTaskResult,
    Task as FinalTask, TaskId as FinalTaskId, TaskInputResponses as FinalTaskInputResponses,
    TaskStatusNotification as FinalTaskStatusNotification,
    UpdateTaskResult as FinalUpdateTaskResult,
};
pub use fastmcp_protocol::{
    CallToolResult, CompleteResult, CoreResult, CreateMessageParams, CreateMessageResult,
    ElicitRequestParams, ElicitResult, FinalCallToolResult,
    FinalCompletionArgument as CompletionArgument, FinalCompletionContext as CompletionContext,
    FinalCompletionReference as CompletionReference, FinalCoreResult, FinalGetPromptResult,
    FinalReadResourceResult, FinalSubscriptionsListenResult, GetPromptResult, LegacyCoreResult,
    ListRootsParams, ListRootsResult, ReadResourceResult, SubscriptionFilter,
};
pub use http_executor::{
    ClientHttpConnection, ClientHttpConnectionError, ClientHttpResponse, LegacySseHttpClient,
    LegacySseHttpClientError, ModernHttpClient, ModernHttpClientError, ModernHttpResponseStream,
    ModernHttpSubscriptionListenCollector,
};
pub use mcp_config::claude_desktop_config_path;
pub use negotiation::{
    ClientHttpNegotiation, ClientHttpNegotiationDecision, ClientHttpNegotiationError,
    ClientHttpNegotiationState,
};
pub use session::{ClientProtocolPlan, ClientProtocolPlanError, ClientSession};

use std::any::Any;
use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
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
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use asupersync::{Cx, channel::oneshot};
use fastmcp_core::{McpError, McpErrorCode, McpResult, Sha256Digest, block_on, sha256_bounded};
use fastmcp_protocol::common_types::{
    ContentBlock, EmbeddedResourceContents, OpenMetadata, RawIcon,
};
use fastmcp_protocol::extensions::{
    ExtensionLocalEnablement, OFFICIAL_TASKS_RESULT_DISCRIMINATOR, official_tasks_empty_settings,
    register_official_tasks_extension,
};
use fastmcp_protocol::methods::{Final2026Peer, final_2026_07_28_method};
use fastmcp_protocol::protocol_policy::MODERN_PROTOCOL_VERSION;
use fastmcp_protocol::tasks_extension::{
    CancelTaskParams as FinalCancelTaskParams, GetTaskParams as FinalGetTaskParams, TASK_CANCEL,
    TASK_GET, TASK_STATUS_NOTIFICATION, TASK_SUBSCRIPTION_IDS_KEY, TASK_UPDATE, TaskInputLedger,
    TaskRequestMeta, UpdateTaskParams as FinalUpdateTaskParams,
};
use fastmcp_protocol::{
    CallToolParams, CancelTaskParams, CancelTaskResult, CancelledParams, ClientCapabilities,
    ClientInfo, CoreDispatchError, CoreRequest, CorrelationKey, FINAL_CLIENT_CAPABILITIES_META_KEY,
    FINAL_SUBSCRIPTION_ID_META_KEY, FinalCoreRequest, FinalLogMessageParams,
    FinalProgressNotificationParams, FinalRequestMeta,
    FinalSubscriptionsAcknowledgedNotificationParams, GetPromptParams, GetTaskParams,
    GetTaskResult, InitializeParams, InitializeResult, JSONRPC_VERSION, JsonRpcError,
    JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, LegacyContent, LegacyPromptMessage,
    LegacyResourceContent, ListPromptsParams, ListResourceTemplatesParams, ListResourcesParams,
    ListTasksParams, ListTasksResult, ListToolsParams, LogLevel, LogMessageParams,
    PROTOCOL_VERSION, ProgressMarker, Prompt, PromptArgument, ReadResourceParams, RequestId,
    RequestMeta, Resource, ResourceTemplate, ServerCapabilities, ServerInfo, ServerNotification,
    SetLogLevelParams, SubmitTaskParams, SubmitTaskResult, TaskId, TaskInfo, TaskResult,
    TaskStatus, Tool, ToolAnnotations, decode_strict_jsonrpc_response, task_subscription_ids,
};
use fastmcp_protocol::{
    ClientExtensionDiscovery, ExtensionDescriptorRegistry, ExtensionDirection, ExtensionSettings,
    ServerExtensionDiscovery,
};
use fastmcp_protocol::{SERVER_DISCOVER_METHOD, ServerDiscoverRequest, ServerDiscoverResult};

use crate::session::resolve_mcp_apps_activation;

/// Callback for receiving progress notifications during tool execution.
///
/// The callback receives the progress value, optional total, and optional message.
pub type ProgressCallback<'a> = &'a mut dyn FnMut(f64, Option<f64>, Option<&str>);

/// Handler for a server-initiated `sampling/createMessage` request.
pub type SamplingRequestHandler =
    Box<dyn FnMut(CreateMessageParams) -> McpResult<CreateMessageResult> + Send>;

/// Handler for a server-initiated `roots/list` request.
pub type RootsRequestHandler = Box<dyn FnMut(ListRootsParams) -> McpResult<ListRootsResult> + Send>;

/// Handler for a server-initiated `elicitation/create` request.
pub type ElicitationRequestHandler =
    Box<dyn FnMut(ElicitRequestParams) -> McpResult<ElicitResult> + Send>;

/// Configurable handlers for reverse requests received from a live MCP server.
#[derive(Default)]
pub struct ReverseRequestHandlers {
    sampling_create_message: Option<SamplingRequestHandler>,
    roots_list: Option<RootsRequestHandler>,
    elicitation_create: Option<ElicitationRequestHandler>,
}

impl ReverseRequestHandlers {
    /// Creates an empty handler set. Unconfigured methods receive `MethodNotFound`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sampling_create_message: None,
            roots_list: None,
            elicitation_create: None,
        }
    }

    /// Configures handling for `sampling/createMessage`.
    #[must_use]
    pub fn with_sampling_create_message<F>(mut self, handler: F) -> Self
    where
        F: FnMut(CreateMessageParams) -> McpResult<CreateMessageResult> + Send + 'static,
    {
        self.sampling_create_message = Some(Box::new(handler));
        self
    }

    /// Configures handling for `roots/list`.
    #[must_use]
    pub fn with_roots_list<F>(mut self, handler: F) -> Self
    where
        F: FnMut(ListRootsParams) -> McpResult<ListRootsResult> + Send + 'static,
    {
        self.roots_list = Some(Box::new(handler));
        self
    }

    /// Configures handling for `elicitation/create`.
    #[must_use]
    pub fn with_elicitation_create<F>(mut self, handler: F) -> Self
    where
        F: FnMut(ElicitRequestParams) -> McpResult<ElicitResult> + Send + 'static,
    {
        self.elicitation_create = Some(Box::new(handler));
        self
    }
}
use fastmcp_transport::{StdioTransport, Transport, TransportError};

use crate::cache::{FinalCachePageLookup, final_cache_hints};
use crate::execution::{
    decode_core_result_from_source, decode_core_result_with_cache_ttl_from_source,
};

/// Completion input that retains the complete 2026-07-28 request context.
///
/// A modern session sends this shape unchanged apart from client-owned request
/// metadata. A legacy session accepts only the lossless subset: no prompt
/// title and no completion context.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionParams {
    /// Prompt or resource-template target.
    #[serde(rename = "ref")]
    pub reference: CompletionReference,
    /// Argument being completed.
    pub argument: CompletionArgument,
    /// Previously resolved prompt or resource-template variables.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<CompletionContext>,
}

impl CompletionParams {
    fn into_legacy(self) -> McpResult<fastmcp_protocol::LegacyCompletionParams> {
        if self.context.is_some() {
            return Err(McpError::invalid_params(
                "MCP 2024-11-05 completion cannot represent completion context",
            ));
        }

        let reference = match self.reference {
            CompletionReference::Prompt { name } => {
                fastmcp_protocol::LegacyCompletionReference::Prompt { name }
            }
            CompletionReference::PromptWithTitle { .. } => {
                return Err(McpError::invalid_params(
                    "MCP 2024-11-05 completion cannot represent a prompt title",
                ));
            }
            CompletionReference::Resource { uri } => {
                fastmcp_protocol::LegacyCompletionReference::Resource { uri }
            }
        };

        Ok(fastmcp_protocol::LegacyCompletionParams {
            reference,
            argument: fastmcp_protocol::LegacyCompletionArgument {
                name: self.argument.name,
                value: self.argument.value,
            },
        })
    }
}

/// The request-owned terminal record for a final subscription listener.
///
/// The acknowledgement binds the requested filter to the JSON-RPC request
/// ID. Only notifications admitted by that accepted filter are retained here;
/// unrelated final log and progress notifications remain on the ordinary
/// client path.
#[derive(Debug, Clone)]
pub struct SubscriptionListenCollector {
    /// The JSON-RPC request identity bound to this subscription stream.
    pub subscription_id: RequestId,
    /// The exact subset of requested notification categories accepted by the server.
    pub accepted_filter: SubscriptionFilter,
    /// Typed request-owned notifications received before graceful termination.
    pub notifications: Vec<ServerNotification>,
    /// Typed Tasks events admitted by the acknowledged exact `taskIds` set.
    pub task_notifications: Vec<FinalTaskStatusNotification>,
    /// The final complete result that terminated the listener.
    pub terminal: CompleteResult<FinalSubscriptionsListenResult>,
}

/// Exact modern `tools/call` outcome without projecting away result algebra.
#[derive(Debug, Clone)]
pub enum FinalToolCallOutcome {
    /// The tool completed synchronously with final content.
    Complete(CompleteResult<FinalCallToolResult>),
    /// The tool created a durable Tasks-extension task.
    Task(fastmcp_protocol::CreateTaskResult),
    /// The tool requires client input before it can complete.
    InputRequired(fastmcp_protocol::InputRequiredResult),
}

fn subscription_listener_protocol_error(message: &'static str) -> McpError {
    McpError::invalid_request(message)
}

fn validate_subscription_acknowledgement_filter(
    requested: &SubscriptionFilter,
    acknowledged: &SubscriptionFilter,
) -> McpResult<()> {
    for (requested, acknowledged) in [
        (
            requested.prompts_list_changed,
            acknowledged.prompts_list_changed,
        ),
        (
            requested.resources_list_changed,
            acknowledged.resources_list_changed,
        ),
        (
            requested.tools_list_changed,
            acknowledged.tools_list_changed,
        ),
    ] {
        match acknowledged {
            None => {}
            Some(true) if requested == Some(true) => {}
            Some(_) => {
                return Err(subscription_listener_protocol_error(
                    "Subscription acknowledgement accepts a notification category that was not requested",
                ));
            }
        }
    }

    if let Some(acknowledged_uris) = &acknowledged.resource_subscriptions {
        let Some(requested_uris) = &requested.resource_subscriptions else {
            return Err(subscription_listener_protocol_error(
                "Subscription acknowledgement accepts resource updates that were not requested",
            ));
        };
        for (index, uri) in acknowledged_uris.iter().enumerate() {
            if !requested_uris
                .iter()
                .any(|requested_uri| requested_uri == uri)
                || acknowledged_uris[..index]
                    .iter()
                    .any(|previous_uri| previous_uri == uri)
            {
                return Err(subscription_listener_protocol_error(
                    "Subscription acknowledgement contains an invalid resource update filter",
                ));
            }
        }
    }

    let requested_task_ids = task_subscription_ids(requested).map_err(|_| {
        subscription_listener_protocol_error("Requested Tasks subscription filter is invalid")
    })?;
    let acknowledged_task_ids = task_subscription_ids(acknowledged).map_err(|_| {
        subscription_listener_protocol_error(
            "Subscription acknowledgement has an invalid Tasks filter",
        )
    })?;
    match (requested_task_ids.as_ref(), acknowledged_task_ids.as_ref()) {
        (None, Some(_)) => {
            return Err(subscription_listener_protocol_error(
                "Subscription acknowledgement accepts unrequested Tasks notifications",
            ));
        }
        (Some(requested), Some(acknowledged)) => {
            for (index, task_id) in acknowledged.iter().enumerate() {
                if !requested.iter().any(|requested| requested == task_id)
                    || acknowledged[..index]
                        .iter()
                        .any(|previous| previous == task_id)
                {
                    return Err(subscription_listener_protocol_error(
                        "Subscription acknowledgement contains an invalid Tasks filter",
                    ));
                }
            }
        }
        (Some(_), None) | (None, None) => {}
    }

    if acknowledged.additional.iter().any(|(name, value)| {
        name != TASK_SUBSCRIPTION_IDS_KEY
            && requested
                .additional
                .get(name)
                .is_none_or(|requested_value| requested_value != value)
    }) {
        return Err(subscription_listener_protocol_error(
            "Subscription acknowledgement accepts an unrequested extension filter",
        ));
    }

    Ok(())
}

fn validate_subscription_acknowledgement(
    expected_id: &RequestId,
    requested: &SubscriptionFilter,
    acknowledgement: &FinalSubscriptionsAcknowledgedNotificationParams,
) -> McpResult<()> {
    let subscription_id = acknowledgement
        .meta
        .as_ref()
        .and_then(|metadata| metadata.get(FINAL_SUBSCRIPTION_ID_META_KEY))
        .ok_or_else(|| {
            subscription_listener_protocol_error(
                "Subscription acknowledgement is missing its subscription ID",
            )
        })
        .and_then(|value| {
            serde_json::from_value::<RequestId>(value.clone()).map_err(|_| {
                subscription_listener_protocol_error(
                    "Subscription acknowledgement has an invalid subscription ID",
                )
            })
        })?;
    if &subscription_id != expected_id {
        return Err(subscription_listener_protocol_error(
            "Subscription acknowledgement ID does not match the listen request",
        ));
    }
    validate_subscription_acknowledgement_filter(requested, &acknowledgement.notifications)
}

fn validate_subscription_notification_filter(
    notification: &ServerNotification,
    accepted_filter: &SubscriptionFilter,
) -> McpResult<()> {
    let accepted = match notification {
        ServerNotification::ResourcesListChanged(_) => {
            accepted_filter.resources_list_changed == Some(true)
        }
        ServerNotification::ToolsListChanged(_) => accepted_filter.tools_list_changed == Some(true),
        ServerNotification::PromptsListChanged(_) => {
            accepted_filter.prompts_list_changed == Some(true)
        }
        ServerNotification::ResourceUpdated(update) => accepted_filter
            .resource_subscriptions
            .as_ref()
            .is_some_and(|uris| uris.iter().any(|uri| uri == update.uri.as_str())),
        ServerNotification::Cancelled(_)
        | ServerNotification::Progress(_)
        | ServerNotification::Message(_)
        | ServerNotification::SubscriptionsAcknowledged(_) => false,
    };
    if accepted {
        Ok(())
    } else {
        Err(subscription_listener_protocol_error(
            "Subscription stream emitted a notification outside its accepted filter",
        ))
    }
}

fn negotiate_final_tasks_discovery(
    discovery: &ServerDiscoverResult,
) -> McpResult<(
    ExtensionDescriptorRegistry,
    fastmcp_protocol::ExtensionId,
    fastmcp_protocol::extensions::NegotiatedExtensionSet,
)> {
    let capabilities = serde_json::to_value(discovery.capabilities()).map_err(|error| {
        McpError::internal_error(format!(
            "Failed to retain final Tasks capability discovery: {error}"
        ))
    })?;
    let settings_value = capabilities
        .get("extensions")
        .and_then(serde_json::Value::as_object)
        .and_then(|extensions| extensions.get(fastmcp_protocol::TASKS_EXTENSION))
        .cloned()
        .ok_or_else(|| {
            McpError::invalid_params(
                "Server did not declare io.modelcontextprotocol/tasks capability",
            )
        })?;
    let server_settings = ExtensionSettings::new(settings_value).map_err(|_| {
        McpError::invalid_params(
            "Server io.modelcontextprotocol/tasks settings are not an admitted object",
        )
    })?;

    let mut registry = ExtensionDescriptorRegistry::new();
    let task_extension = register_official_tasks_extension(&mut registry).map_err(|error| {
        McpError::internal_error(format!(
            "Failed to register the official Tasks client surface: {error}"
        ))
    })?;
    registry.freeze().map_err(|error| {
        McpError::internal_error(format!(
            "Failed to freeze the official Tasks client surface: {error}"
        ))
    })?;

    let mut local = ExtensionLocalEnablement::default();
    local.enable(task_extension.clone());
    let client = ClientExtensionDiscovery {
        extensions: BTreeMap::from([(task_extension.clone(), official_tasks_empty_settings())]),
    };
    let server = ServerExtensionDiscovery {
        extensions: BTreeMap::from([(task_extension.clone(), server_settings)]),
    };
    let mut resolve_empty_settings =
        |_descriptor: &fastmcp_protocol::ExtensionDescriptor,
         _client: &ExtensionSettings,
         _server: &ExtensionSettings| { Ok(official_tasks_empty_settings()) };
    let negotiated = registry
        .negotiate(
            ProtocolEra::Modern2026,
            &local,
            &client,
            &server,
            &mut resolve_empty_settings,
        )
        .map_err(|_| {
            McpError::invalid_params(
                "io.modelcontextprotocol/tasks requires bilateral empty settings",
            )
        })?;
    Ok((registry, task_extension, negotiated))
}

fn admit_final_tasks_discovery_surface(
    discovery: &ServerDiscoverResult,
    name: &str,
    direction: ExtensionDirection,
) -> McpResult<()> {
    let (registry, task_extension, negotiated) = negotiate_final_tasks_discovery(discovery)?;
    let admitted = if name == TASK_STATUS_NOTIFICATION {
        negotiated
            .admit_notification(
                &registry,
                ProtocolEra::Modern2026,
                &task_extension,
                name,
                direction,
            )
            .map(|_| ())
    } else {
        negotiated
            .admit_method(
                &registry,
                ProtocolEra::Modern2026,
                &task_extension,
                name,
                direction,
            )
            .map(|_| ())
    };
    admitted.map_err(|_| {
        McpError::invalid_params(
            "Tasks surface is not admitted by the negotiated official extension",
        )
    })
}

fn admit_final_tasks_result_discriminator(
    discovery: &ServerDiscoverResult,
    discriminator: &str,
) -> McpResult<()> {
    let (registry, task_extension, negotiated) = negotiate_final_tasks_discovery(discovery)?;
    negotiated
        .admit_result_discriminator(
            &registry,
            ProtocolEra::Modern2026,
            &task_extension,
            discriminator,
        )
        .map(|_| ())
        .map_err(|_| {
            McpError::invalid_params(
                "Tasks result is not admitted by the negotiated official extension",
            )
        })
}

fn final_log_level(level: LogLevel) -> LoggingLevel {
    match level {
        LogLevel::Debug => LoggingLevel::Debug,
        LogLevel::Info => LoggingLevel::Info,
        LogLevel::Warning => LoggingLevel::Warning,
        LogLevel::Error => LoggingLevel::Error,
    }
}

fn legacy_log_level(level: LoggingLevel) -> McpResult<LogLevel> {
    match level {
        LoggingLevel::Debug => Ok(LogLevel::Debug),
        LoggingLevel::Info => Ok(LogLevel::Info),
        LoggingLevel::Warning => Ok(LogLevel::Warning),
        LoggingLevel::Error => Ok(LogLevel::Error),
        LoggingLevel::Notice
        | LoggingLevel::Critical
        | LoggingLevel::Alert
        | LoggingLevel::Emergency => Err(McpError::invalid_params(
            "MCP 2024-11-05 logging cannot represent the selected final severity",
        )),
    }
}

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

fn reverse_request_response<T>(request_id: RequestId, result: McpResult<T>) -> JsonRpcMessage
where
    T: serde::Serialize,
{
    match result.and_then(|result| {
        serde_json::to_value(result)
            .map_err(|_| McpError::internal_error("Failed to serialize reverse request result"))
    }) {
        Ok(result) => JsonRpcMessage::Response(JsonRpcResponse::success(request_id, result)),
        Err(error) => {
            JsonRpcMessage::Response(JsonRpcResponse::error(Some(request_id), error.into()))
        }
    }
}

fn decode_reverse_request_params<T>(request: &JsonRpcRequest) -> McpResult<T>
where
    T: serde::de::DeserializeOwned,
{
    let params = request
        .params
        .clone()
        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
    serde_json::from_value(params)
        .map_err(|_| McpError::invalid_params("Invalid reverse request parameters"))
}

fn invoke_reverse_request_handler<P, R>(
    handler: &mut dyn FnMut(P) -> McpResult<R>,
    params: P,
) -> McpResult<R> {
    catch_client_callback_unwind(|| handler(params))
        .map_err(|_| McpError::internal_error("Client reverse request handler failed"))?
}

fn live_server_request_response(
    handlers: &mut ReverseRequestHandlers,
    request: &JsonRpcRequest,
) -> Option<JsonRpcMessage> {
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

    let response = match request.method.as_str() {
        "sampling/createMessage" => reverse_request_response(
            id,
            handlers.sampling_create_message.as_mut().map_or_else(
                || Err(McpError::method_not_found("sampling/createMessage")),
                |handler| {
                    decode_reverse_request_params(request)
                        .and_then(|params| invoke_reverse_request_handler(handler.as_mut(), params))
                },
            ),
        ),
        "roots/list" => reverse_request_response(
            id,
            handlers.roots_list.as_mut().map_or_else(
                || Err(McpError::method_not_found("roots/list")),
                |handler| {
                    decode_reverse_request_params(request)
                        .and_then(|params| invoke_reverse_request_handler(handler.as_mut(), params))
                },
            ),
        ),
        "elicitation/create" => reverse_request_response(
            id,
            handlers.elicitation_create.as_mut().map_or_else(
                || Err(McpError::method_not_found("elicitation/create")),
                |handler| {
                    decode_reverse_request_params(request)
                        .and_then(|params| invoke_reverse_request_handler(handler.as_mut(), params))
                },
            ),
        ),
        _ => return method_not_found_response(request),
    };
    Some(response)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServerNotificationKind {
    Progress,
    LogMessage,
}

enum ModernServerNotification {
    Progress(FinalProgressNotificationParams),
    Retained,
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

/// Maximum number of non-progress final server notifications retained for a
/// modern client session before the connection fails closed.
pub const MAX_QUEUED_FINAL_SERVER_NOTIFICATIONS: usize = 64;

const FINAL_SERVER_NOTIFICATION_QUEUE_OVERFLOW_ERROR: &str =
    "Final server notification queue capacity exceeded";

fn is_final_server_notification_method(request: &JsonRpcRequest) -> bool {
    final_2026_07_28_method(&request.method)
        .is_some_and(|method| method.admits_notification_from(Final2026Peer::Server))
}

fn final_log_message_sink_projection(message: &FinalLogMessageParams) -> Option<LogMessageParams> {
    let level = match message.level {
        LoggingLevel::Debug => LogLevel::Debug,
        LoggingLevel::Info => LogLevel::Info,
        LoggingLevel::Warning => LogLevel::Warning,
        LoggingLevel::Error => LogLevel::Error,
        LoggingLevel::Notice
        | LoggingLevel::Critical
        | LoggingLevel::Alert
        | LoggingLevel::Emergency => return None,
    };
    Some(LogMessageParams {
        level,
        logger: message.logger.clone(),
        data: message.data.clone(),
    })
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

/// Reports a final field that cannot be preserved by a legacy convenience
/// projection.
fn final_projection_error(field: &str) -> McpError {
    McpError::invalid_request(format!(
        "Final {field} cannot be represented by the legacy convenience API"
    ))
}

fn ensure_absent_final_field<T>(field: &str, value: Option<T>) -> McpResult<()> {
    if value.is_some() {
        return Err(final_projection_error(field));
    }
    Ok(())
}

fn ensure_empty_final_fields(
    field: &str,
    values: &std::collections::BTreeMap<String, serde_json::Value>,
) -> McpResult<()> {
    if !values.is_empty() {
        return Err(final_projection_error(field));
    }
    Ok(())
}

/// Final catalog cache hints with an immediate, private lifetime are
/// observationally equivalent to the absence of cache hints in the legacy
/// API. Any reusable or shared cache directive would otherwise be lost.
fn ensure_legacy_cache_projection(
    ttl_ms: u64,
    cache_scope: fastmcp_protocol::CacheScope,
) -> McpResult<()> {
    if ttl_ms == 0 && cache_scope == fastmcp_protocol::CacheScope::Private {
        return Ok(());
    }
    Err(final_projection_error("cache fields"))
}

/// A final icon collection, including its theme and per-icon metadata, has no
/// exact counterpart in the legacy one-icon shape.
fn final_icons_to_legacy(icons: Option<Vec<RawIcon>>) -> McpResult<Option<fastmcp_protocol::Icon>> {
    ensure_absent_final_field("catalog icons", icons)?;
    Ok(None)
}

fn final_tool_to_legacy(tool: fastmcp_protocol::FinalTool) -> McpResult<Tool> {
    ensure_absent_final_field("catalog title", tool.title)?;
    ensure_absent_final_field("catalog metadata", tool.meta)?;
    let icon = final_icons_to_legacy(tool.icons)?;
    let annotations = match tool.annotations {
        Some(annotations) => {
            ensure_absent_final_field("catalog annotation title", annotations.title)?;
            Some(ToolAnnotations {
                destructive: annotations.destructive,
                idempotent: annotations.idempotent,
                read_only: annotations.read_only,
                open_world_hint: annotations.open_world_hint,
            })
        }
        None => None,
    };
    Ok(Tool {
        name: tool.name,
        description: tool.description,
        input_schema: tool.input_schema,
        output_schema: tool.output_schema,
        icon,
        version: None,
        tags: Vec::new(),
        annotations,
    })
}

fn final_resource_to_legacy(resource: fastmcp_protocol::FinalResource) -> McpResult<Resource> {
    ensure_absent_final_field("catalog title", resource.title)?;
    ensure_absent_final_field("catalog annotations", resource.annotations)?;
    ensure_absent_final_field("catalog size", resource.size)?;
    ensure_absent_final_field("catalog metadata", resource.meta)?;
    let icon = final_icons_to_legacy(resource.icons)?;
    Ok(Resource {
        uri: resource.uri.as_str().to_owned(),
        name: resource.name,
        description: resource.description,
        mime_type: resource.mime_type,
        icon,
        version: None,
        tags: Vec::new(),
    })
}

fn final_resource_template_to_legacy(
    template: fastmcp_protocol::FinalResourceTemplate,
) -> McpResult<ResourceTemplate> {
    ensure_absent_final_field("catalog title", template.title)?;
    ensure_absent_final_field("catalog annotations", template.annotations)?;
    ensure_absent_final_field("catalog metadata", template.meta)?;
    let icon = final_icons_to_legacy(template.icons)?;
    Ok(ResourceTemplate {
        uri_template: template.uri_template,
        name: template.name,
        description: template.description,
        mime_type: template.mime_type,
        icon,
        version: None,
        tags: Vec::new(),
    })
}

fn final_prompt_to_legacy(prompt: fastmcp_protocol::FinalPrompt) -> McpResult<Prompt> {
    ensure_absent_final_field("catalog title", prompt.title)?;
    ensure_absent_final_field("catalog metadata", prompt.meta)?;
    let icon = final_icons_to_legacy(prompt.icons)?;
    let arguments = prompt
        .arguments
        .unwrap_or_default()
        .into_iter()
        .map(|argument| {
            ensure_absent_final_field("prompt argument title", argument.title)?;
            let required = argument
                .required
                .ok_or_else(|| final_projection_error("prompt argument required state"))?;
            Ok(PromptArgument {
                name: argument.name,
                description: argument.description,
                required,
            })
        })
        .collect::<McpResult<Vec<_>>>()?;
    Ok(Prompt {
        name: prompt.name,
        description: prompt.description,
        arguments,
        icon,
        version: None,
        tags: Vec::new(),
    })
}

/// Re-homes final open fields in the exact legacy shape.
///
/// Legacy content has no typed metadata member: its schema permits `_meta` as
/// one of the flattened open members. Preserve it under that original wire
/// name, while rejecting manually-constructed open members that would shadow
/// a declared legacy field.
fn final_open_fields_to_legacy(
    field: &str,
    meta: Option<OpenMetadata>,
    mut additional: std::collections::BTreeMap<String, serde_json::Value>,
    declared_members: &[&str],
) -> McpResult<std::collections::BTreeMap<String, serde_json::Value>> {
    if additional
        .keys()
        .any(|key| key == "_meta" || declared_members.contains(&key.as_str()))
    {
        return Err(final_projection_error(field));
    }
    let Some(meta) = meta else {
        return Ok(additional);
    };
    let encoded_meta =
        serde_json::to_value(meta).map_err(|_| final_projection_error("metadata serialization"))?;
    additional.insert("_meta".to_owned(), encoded_meta);
    Ok(additional)
}

fn final_resource_content_to_legacy(
    resource: EmbeddedResourceContents,
) -> McpResult<LegacyResourceContent> {
    match resource {
        EmbeddedResourceContents::Text {
            uri,
            text,
            mime_type,
            meta,
            additional,
        } => Ok(LegacyResourceContent::Text {
            uri: uri.as_str().to_owned(),
            mime_type,
            text,
            additional: final_open_fields_to_legacy(
                "conflicting resource field",
                meta,
                additional,
                &["uri", "text", "mimeType"],
            )?,
        }),
        EmbeddedResourceContents::Blob {
            uri,
            blob,
            mime_type,
            meta,
            additional,
        } => Ok(LegacyResourceContent::Blob {
            uri: uri.as_str().to_owned(),
            mime_type,
            blob,
            additional: final_open_fields_to_legacy(
                "conflicting resource field",
                meta,
                additional,
                &["uri", "blob", "mimeType"],
            )?,
        }),
    }
}

fn final_content_to_legacy(content: ContentBlock) -> McpResult<LegacyContent> {
    match content {
        ContentBlock::Text {
            text,
            annotations,
            meta,
            additional,
        } => Ok(LegacyContent::Text {
            text,
            annotations,
            additional: final_open_fields_to_legacy(
                "conflicting content field",
                meta,
                additional,
                &["type", "text", "annotations"],
            )?,
        }),
        ContentBlock::Image {
            data,
            mime_type,
            annotations,
            meta,
            additional,
        } => Ok(LegacyContent::Image {
            data,
            mime_type,
            annotations,
            additional: final_open_fields_to_legacy(
                "conflicting content field",
                meta,
                additional,
                &["type", "data", "mimeType", "annotations"],
            )?,
        }),
        ContentBlock::Audio { .. } => Err(final_projection_error("audio content")),
        ContentBlock::Resource {
            resource,
            annotations,
            meta,
            additional,
        } => Ok(LegacyContent::Resource {
            resource: final_resource_content_to_legacy(resource)?,
            annotations,
            additional: final_open_fields_to_legacy(
                "conflicting content field",
                meta,
                additional,
                &["type", "resource", "annotations"],
            )?,
        }),
        ContentBlock::ResourceLink { .. } => Err(final_projection_error("resource_link content")),
    }
}

fn unexpected_convenience_result(method: &str) -> McpError {
    McpError::invalid_request(format!(
        "Negotiated core result was not a {method} result for the convenience API"
    ))
}

fn convenience_tools_page(result: CoreResult) -> McpResult<(Vec<Tool>, Option<String>)> {
    match result {
        CoreResult::Legacy(LegacyCoreResult::ToolsList(result)) => {
            Ok((result.tools, result.next_cursor))
        }
        CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) => {
            let fastmcp_protocol::FinalListToolsResult {
                tools,
                next_cursor,
                ttl_ms,
                cache_scope,
            } = result.payload;
            ensure_legacy_cache_projection(ttl_ms, cache_scope)?;
            Ok((
                tools
                    .into_iter()
                    .map(final_tool_to_legacy)
                    .collect::<McpResult<Vec<_>>>()?,
                next_cursor,
            ))
        }
        _ => Err(unexpected_convenience_result("tools/list")),
    }
}

fn convenience_resources_page(result: CoreResult) -> McpResult<(Vec<Resource>, Option<String>)> {
    match result {
        CoreResult::Legacy(LegacyCoreResult::ResourcesList(result)) => {
            Ok((result.resources, result.next_cursor))
        }
        CoreResult::Final(FinalCoreResult::ResourcesList { result, .. }) => {
            let fastmcp_protocol::FinalListResourcesResult {
                resources,
                next_cursor,
                ttl_ms,
                cache_scope,
            } = result.payload;
            ensure_legacy_cache_projection(ttl_ms, cache_scope)?;
            Ok((
                resources
                    .into_iter()
                    .map(final_resource_to_legacy)
                    .collect::<McpResult<Vec<_>>>()?,
                next_cursor,
            ))
        }
        _ => Err(unexpected_convenience_result("resources/list")),
    }
}

fn convenience_resource_templates_page(
    result: CoreResult,
) -> McpResult<(Vec<ResourceTemplate>, Option<String>)> {
    match result {
        CoreResult::Legacy(LegacyCoreResult::ResourceTemplatesList(result)) => {
            Ok((result.resource_templates, result.next_cursor))
        }
        CoreResult::Final(FinalCoreResult::ResourceTemplatesList { result, .. }) => {
            let fastmcp_protocol::FinalListResourceTemplatesResult {
                resource_templates,
                next_cursor,
                ttl_ms,
                cache_scope,
            } = result.payload;
            ensure_legacy_cache_projection(ttl_ms, cache_scope)?;
            Ok((
                resource_templates
                    .into_iter()
                    .map(final_resource_template_to_legacy)
                    .collect::<McpResult<Vec<_>>>()?,
                next_cursor,
            ))
        }
        _ => Err(unexpected_convenience_result("resources/templates/list")),
    }
}

fn convenience_prompts_page(result: CoreResult) -> McpResult<(Vec<Prompt>, Option<String>)> {
    match result {
        CoreResult::Legacy(LegacyCoreResult::PromptsList(result)) => {
            Ok((result.prompts, result.next_cursor))
        }
        CoreResult::Final(FinalCoreResult::PromptsList { result, .. }) => {
            let fastmcp_protocol::FinalListPromptsResult {
                prompts,
                next_cursor,
                ttl_ms,
                cache_scope,
            } = result.payload;
            ensure_legacy_cache_projection(ttl_ms, cache_scope)?;
            Ok((
                prompts
                    .into_iter()
                    .map(final_prompt_to_legacy)
                    .collect::<McpResult<Vec<_>>>()?,
                next_cursor,
            ))
        }
        _ => Err(unexpected_convenience_result("prompts/list")),
    }
}

fn convenience_tool_call(result: CoreResult) -> McpResult<CallToolResult> {
    match result {
        CoreResult::Legacy(LegacyCoreResult::ToolsCall(result)) => Ok(result),
        CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) => {
            let fastmcp_protocol::FinalCallToolResult {
                content,
                is_error,
                structured_content,
            } = result.payload;
            ensure_absent_final_field("structuredContent", structured_content)?;
            Ok(CallToolResult {
                content: content
                    .into_iter()
                    .map(final_content_to_legacy)
                    .collect::<McpResult<Vec<_>>>()?,
                is_error,
                meta: None,
                additional: std::collections::BTreeMap::new(),
            })
        }
        _ => Err(unexpected_convenience_result("tools/call")),
    }
}

fn convenience_resource_read(result: CoreResult) -> McpResult<Vec<LegacyResourceContent>> {
    match result {
        CoreResult::Legacy(LegacyCoreResult::ResourcesRead(result)) => Ok(result.contents),
        CoreResult::Final(FinalCoreResult::ResourcesRead { result, .. }) => {
            let fastmcp_protocol::FinalReadResourceResult {
                contents,
                ttl_ms,
                cache_scope,
            } = result.payload;
            ensure_legacy_cache_projection(ttl_ms, cache_scope)?;
            contents
                .into_iter()
                .map(final_resource_content_to_legacy)
                .collect()
        }
        _ => Err(unexpected_convenience_result("resources/read")),
    }
}

fn convenience_prompt_get(result: CoreResult) -> McpResult<Vec<LegacyPromptMessage>> {
    match result {
        CoreResult::Legacy(LegacyCoreResult::PromptsGet(result)) => Ok(result.messages),
        CoreResult::Final(FinalCoreResult::PromptsGet { result, .. }) => {
            let fastmcp_protocol::FinalGetPromptResult {
                description,
                messages,
            } = result.payload;
            ensure_absent_final_field("prompt description", description)?;
            messages
                .into_iter()
                .map(|message| {
                    Ok(LegacyPromptMessage {
                        role: message.role,
                        content: final_content_to_legacy(message.content)?,
                        additional: std::collections::BTreeMap::new(),
                    })
                })
                .collect()
        }
        _ => Err(unexpected_convenience_result("prompts/get")),
    }
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

#[derive(Debug, Clone)]
struct ReceivedJsonRpcResponse {
    response: JsonRpcResponse,
    raw_result: Option<String>,
}

impl std::ops::Deref for ReceivedJsonRpcResponse {
    type Target = JsonRpcResponse;

    fn deref(&self) -> &Self::Target {
        &self.response
    }
}

type CorrelatedResponse = McpResult<ReceivedJsonRpcResponse>;

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
    fn try_response(&mut self) -> McpResult<Option<ReceivedJsonRpcResponse>> {
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
        self.route_with_raw_result(response, None)
    }

    fn route_with_raw_result(
        &mut self,
        response: JsonRpcResponse,
        raw_result: Option<String>,
    ) -> ResponseRoute {
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

        match sender.send_blocking(Ok(ReceivedJsonRpcResponse {
            response,
            raw_result,
        })) {
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

/// A ready dual-era HTTP MCP client.
///
/// This composes the policy-bound HTTP connection with the legacy lifecycle
/// required after an SSE fallback. Modern connections are ready after their
/// successful `server/discover` probe; legacy connections are ready only once
/// this type has completed `initialize` and `notifications/initialized`.
pub struct HttpClient {
    connection: ClientHttpConnection,
    client_info: ClientInfo,
    client_capabilities: ClientCapabilities,
    server_info: ServerInfo,
    legacy_server_capabilities: Option<ServerCapabilities>,
    next_id: AtomicU64,
    final_result_cache: FinalResultCache,
    final_cache_ttl_diagnostics: VecDeque<FinalCacheTtlDiagnostic>,
    mcp_apps_settings: Option<McpAppsClientSettings>,
}

/// Errors raised while composing a ready public HTTP client.
#[derive(Debug)]
pub enum HttpClientError {
    /// The policy-bound HTTP connection could not be established or used.
    Connection(ClientHttpConnectionError),
    /// A modern discovery response omitted its required server identity.
    ModernDiscoveryMissingServerInfo,
    /// The legacy initialization response carried a JSON-RPC error.
    LegacyInitializationRejected,
    /// The legacy initialization response had no result payload.
    LegacyInitializationMissingResult,
    /// The legacy initialization result did not have the exact required shape.
    LegacyInitializationInvalidResult,
    /// The legacy peer selected a protocol version other than 2024-11-05.
    LegacyInitializationUnsupportedProtocolVersion { actual: String },
    /// The HTTP request-ID space was exhausted.
    RequestIdExhausted,
    /// A request or response did not match the selected core-result contract.
    CoreResult(McpError),
}

impl std::fmt::Display for HttpClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connection(error) => error.fmt(formatter),
            Self::ModernDiscoveryMissingServerInfo => {
                formatter.write_str("modern server/discover response has no server identity")
            }
            Self::LegacyInitializationRejected => {
                formatter.write_str("legacy initialize request was rejected")
            }
            Self::LegacyInitializationMissingResult => {
                formatter.write_str("legacy initialize response has no result")
            }
            Self::LegacyInitializationInvalidResult => {
                formatter.write_str("legacy initialize response has an invalid result")
            }
            Self::LegacyInitializationUnsupportedProtocolVersion { actual } => write!(
                formatter,
                "legacy initialize selected unsupported protocol version {actual}"
            ),
            Self::RequestIdExhausted => {
                formatter.write_str("HTTP client request IDs are exhausted")
            }
            Self::CoreResult(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for HttpClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connection(error) => Some(error),
            Self::ModernDiscoveryMissingServerInfo
            | Self::LegacyInitializationRejected
            | Self::LegacyInitializationMissingResult
            | Self::LegacyInitializationInvalidResult
            | Self::LegacyInitializationUnsupportedProtocolVersion { .. }
            | Self::RequestIdExhausted => None,
            Self::CoreResult(error) => Some(error),
        }
    }
}

impl HttpClient {
    /// Connects one immutable HTTP plan and completes the selected era's
    /// required lifecycle before exposing the client.
    pub async fn connect(
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
    ) -> Result<Self, HttpClientError> {
        Self::connect_with_mcp_apps(cx, protocol_plan, client_info, client_capabilities, None).await
    }

    pub(crate) async fn connect_with_mcp_apps(
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
        client_info: ClientInfo,
        client_capabilities: ClientCapabilities,
        mcp_apps_settings: Option<McpAppsClientSettings>,
    ) -> Result<Self, HttpClientError> {
        let mut connection = ClientHttpConnection::connect_with_mcp_apps(
            cx,
            protocol_plan,
            client_info.clone(),
            client_capabilities.clone(),
            mcp_apps_settings.clone(),
        )
        .await
        .map_err(HttpClientError::Connection)?;

        let (server_info, legacy_server_capabilities) = match connection.selected_protocol_era() {
            ProtocolEra::Modern2026 => {
                let server_info = connection
                    .server_discovery()
                    .and_then(ServerDiscoverResult::server_info)
                    .cloned()
                    .ok_or(HttpClientError::ModernDiscoveryMissingServerInfo)?;
                (server_info, None)
            }
            ProtocolEra::Legacy2024 => {
                let parameters = serde_json::to_value(InitializeParams {
                    protocol_version: PROTOCOL_VERSION.to_owned(),
                    capabilities: client_capabilities.clone(),
                    client_info: client_info.clone(),
                })
                .map_err(|_| HttpClientError::LegacyInitializationInvalidResult)?;
                let response = connection
                    .request(cx, "initialize", parameters, RequestId::Number(1))
                    .await
                    .map_err(HttpClientError::Connection)?;
                let ClientHttpResponse::Legacy(JsonRpcMessage::Response(response)) = response
                else {
                    return Err(HttpClientError::LegacyInitializationInvalidResult);
                };
                if response.error.is_some() {
                    return Err(HttpClientError::LegacyInitializationRejected);
                }
                let value = response
                    .result
                    .ok_or(HttpClientError::LegacyInitializationMissingResult)?;
                let initialization = serde_json::from_value::<InitializeResult>(value)
                    .map_err(|_| HttpClientError::LegacyInitializationInvalidResult)?;
                if initialization.protocol_version != PROTOCOL_VERSION {
                    return Err(
                        HttpClientError::LegacyInitializationUnsupportedProtocolVersion {
                            actual: initialization.protocol_version,
                        },
                    );
                }
                connection.record_legacy_negotiated_protocol_version(
                    initialization.protocol_version.clone(),
                );
                connection
                    .notify(cx, "notifications/initialized", None)
                    .await
                    .map_err(HttpClientError::Connection)?;
                (
                    initialization.server_info,
                    Some(initialization.capabilities),
                )
            }
        };

        Ok(Self {
            connection,
            client_info,
            client_capabilities,
            server_info,
            legacy_server_capabilities,
            next_id: AtomicU64::new(2),
            final_result_cache: FinalResultCache::default(),
            final_cache_ttl_diagnostics: VecDeque::new(),
            mcp_apps_settings,
        })
    }

    /// Returns the negotiated protocol era.
    #[must_use]
    pub const fn selected_protocol_era(&self) -> ProtocolEra {
        self.connection.selected_protocol_era()
    }

    /// Returns whether final discovery activated the official MCP Apps extension.
    #[must_use]
    pub fn mcp_apps_active(&self) -> bool {
        self.connection.mcp_apps_active()
    }

    /// Returns the immutable policy and endpoints used to create this client.
    #[must_use]
    pub const fn protocol_plan(&self) -> &ClientProtocolPlan {
        self.connection.protocol_plan()
    }

    /// Returns the identity advertised during connection setup.
    #[must_use]
    pub const fn client_info(&self) -> &ClientInfo {
        &self.client_info
    }

    /// Returns the capabilities advertised during connection setup.
    #[must_use]
    pub const fn client_capabilities(&self) -> &ClientCapabilities {
        &self.client_capabilities
    }

    /// Returns the server identity admitted by discovery or initialization.
    #[must_use]
    pub const fn server_info(&self) -> &ServerInfo {
        &self.server_info
    }

    /// Returns exact legacy capabilities when the selected peer is legacy.
    #[must_use]
    pub const fn legacy_server_capabilities(&self) -> Option<&ServerCapabilities> {
        self.legacy_server_capabilities.as_ref()
    }

    /// Returns the exact modern discovery result when the selected peer is modern.
    #[must_use]
    pub fn server_discovery(&self) -> Option<&ServerDiscoverResult> {
        self.connection.server_discovery()
    }

    /// Returns the underlying policy-bound HTTP transport.
    #[must_use]
    pub const fn connection(&self) -> &ClientHttpConnection {
        &self.connection
    }

    /// Returns mutable access to the underlying policy-bound HTTP transport.
    pub fn connection_mut(&mut self) -> &mut ClientHttpConnection {
        &mut self.connection
    }

    /// Consumes the high-level wrapper and returns its transport.
    #[must_use]
    pub fn into_connection(self) -> ClientHttpConnection {
        self.connection
    }

    fn next_request_id(&self) -> Result<RequestId, HttpClientError> {
        let id = self
            .next_id
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                (id < i64::MAX as u64).then_some(id + 1)
            })
            .map_err(|_| HttpClientError::RequestIdExhausted)?;
        Ok(RequestId::Number(id as i64))
    }

    /// Returns whether typed final complete-result caching is enabled for this
    /// HTTP client. The raw streaming [`Self::request`] API remains uncached.
    #[must_use]
    pub const fn final_result_cache_enabled(&self) -> bool {
        self.final_result_cache.is_enabled()
    }

    /// Enables or disables typed final complete-result caching for this HTTP
    /// client without discarding its local entries.
    pub fn set_final_result_cache_enabled(&mut self, enabled: bool) {
        self.final_result_cache.set_enabled(enabled);
    }

    /// Returns aggregate counters for the HTTP client's bounded final cache.
    #[must_use]
    pub const fn final_result_cache_stats(&self) -> FinalCacheStats {
        self.final_result_cache.stats()
    }

    /// Removes all retained typed final complete results for this HTTP client.
    pub fn clear_final_result_cache(&mut self) {
        self.final_result_cache.clear();
    }

    /// Drains compatibility diagnostics for final peer TTLs admitted with zero
    /// freshness by [`Self::request_final_core`].
    #[must_use]
    pub fn take_final_cache_ttl_diagnostics(&mut self) -> Vec<FinalCacheTtlDiagnostic> {
        self.final_cache_ttl_diagnostics.drain(..).collect()
    }

    /// Sends one supported core request and returns its typed result. Cacheable
    /// modern complete results use this HTTP client's bounded local cache; the
    /// raw streaming [`Self::request`] surface deliberately remains unchanged.
    pub async fn request_final_core(
        &mut self,
        cx: &Cx,
        method: impl AsRef<str>,
        parameters: serde_json::Value,
    ) -> Result<CoreResult, HttpClientError> {
        if cx.checkpoint().is_err() {
            return Err(HttpClientError::CoreResult(McpError::request_cancelled()));
        }
        let method = method.as_ref();
        let core_parameters = self.core_request_parameters(&parameters)?;
        let core_request =
            CoreRequest::decode(self.selected_protocol_era(), method, Some(&core_parameters))
                .map_err(|_| {
                    HttpClientError::CoreResult(McpError::invalid_params(
                        "HTTP core request parameters do not match the negotiated protocol era",
                    ))
                })?;
        let result_set = final_cache_result_set(&core_request);
        let key = if self.selected_protocol_era() == ProtocolEra::Modern2026 {
            result_set
                .as_ref()
                .map(|result_set| {
                    self.final_cache_key(method, parameters.clone(), result_set.clone())
                })
                .transpose()?
        } else {
            None
        };

        if let Some(key) = key.as_ref()
            && let FinalCacheLookup::Fresh(result) = self.final_result_cache.lookup(key)
        {
            if cx.checkpoint().is_err() {
                return Err(HttpClientError::CoreResult(McpError::request_cancelled()));
            }
            return Ok(result);
        }

        let generation = key
            .as_ref()
            .map(|key| self.final_result_cache.begin_fetch(key.result_set()));
        let request_id = self.next_request_id()?;
        let response = self
            .connection
            .request_json_with_result_source_at(
                cx,
                method,
                parameters,
                request_id,
                DEFAULT_FINAL_CACHE_MAX_BYTES,
            )
            .await
            .map_err(HttpClientError::Connection)?;
        let (mut response, result_source, receipt) = response;
        if let Some(error) = response.error.take() {
            return Err(HttpClientError::CoreResult(json_rpc_error_to_mcp(error)));
        }
        let raw_result = response.result.take().ok_or_else(|| {
            HttpClientError::CoreResult(McpError::invalid_request("HTTP response has no result"))
        })?;
        let (result, ttl_diagnostic) = decode_core_result_with_cache_ttl_from_source(
            &core_request,
            &raw_result,
            result_source.as_deref(),
        )
        .map_err(HttpClientError::CoreResult)?;
        if let Some(diagnostic) = ttl_diagnostic {
            if self.final_cache_ttl_diagnostics.len() >= MAX_FINAL_CACHE_TTL_DIAGNOSTICS {
                self.final_cache_ttl_diagnostics.pop_front();
            }
            self.final_cache_ttl_diagnostics.push_back(diagnostic);
        }
        if let (Some(key), Some(generation)) = (key, generation) {
            let _ = self.final_result_cache.insert_if_current_at(
                key,
                generation,
                result.clone(),
                receipt,
            );
        }
        Ok(result)
    }

    /// Collects one typed final HTTP subscription stream and invalidates this
    /// client's bounded complete-result cache for each accepted catalog or
    /// resource-change event before returning the collector.
    ///
    /// The returned collector still retains the exact ordered notifications.
    /// Only admitted `tools/list_changed`, `resources/list_changed`,
    /// `prompts/list_changed`, and `resource_updated` events alter local
    /// cache generations; progress and log events remain cache-neutral.
    pub async fn listen_subscriptions_typed(
        &mut self,
        cx: &Cx,
        notifications: SubscriptionFilter,
        limits: sse::SseLimits,
    ) -> Result<ModernHttpSubscriptionListenCollector, HttpClientError> {
        if cx.checkpoint().is_err() {
            return Err(HttpClientError::CoreResult(McpError::request_cancelled()));
        }
        let request_id = self.next_request_id()?;
        let collector = self
            .connection
            .listen_subscriptions_typed(cx, request_id, notifications, limits)
            .await
            .map_err(HttpClientError::Connection)?;
        self.apply_final_cache_subscription_invalidations(&collector.notifications);
        Ok(collector)
    }

    fn apply_final_cache_subscription_invalidations(
        &mut self,
        notifications: &[ServerNotification],
    ) {
        for notification in notifications {
            if matches!(
                notification,
                ServerNotification::ResourcesListChanged(_)
                    | ServerNotification::ToolsListChanged(_)
                    | ServerNotification::PromptsListChanged(_)
                    | ServerNotification::ResourceUpdated(_)
            ) {
                self.final_result_cache
                    .invalidate_notification(notification);
            }
        }
    }

    fn core_request_parameters(
        &self,
        parameters: &serde_json::Value,
    ) -> Result<serde_json::Value, HttpClientError> {
        if self.selected_protocol_era() != ProtocolEra::Modern2026 {
            return Ok(parameters.clone());
        }
        let mut parameters = parameters.as_object().cloned().ok_or_else(|| {
            HttpClientError::CoreResult(McpError::invalid_params(
                "HTTP modern core request parameters must be an object",
            ))
        })?;
        parameters.insert(
            "_meta".to_owned(),
            serde_json::to_value(FinalRequestMeta::new(self.client_capabilities.clone())).map_err(
                |_| {
                    HttpClientError::CoreResult(McpError::internal_error(
                        "HTTP client metadata could not form a core request",
                    ))
                },
            )?,
        );
        Ok(serde_json::Value::Object(parameters))
    }

    fn final_cache_key(
        &self,
        method: &str,
        semantic_parameters: serde_json::Value,
        result_set: FinalCacheResultSet,
    ) -> Result<FinalCacheKey, HttpClientError> {
        let normalized_capabilities =
            serde_json::to_string(&self.client_capabilities).map_err(|_| {
                HttpClientError::CoreResult(McpError::internal_error(
                    "HTTP client capabilities could not form a cache key",
                ))
            })?;
        let extension_settings = serde_json::to_string(&serde_json::json!({
            "mcpApps": self.mcp_apps_settings.as_ref().map(|settings| {
                settings.to_extension_settings().into_value()
            }),
            "descriptorRevision": FINAL_CACHE_EXTENSION_REVISION,
        }))
        .map_err(|_| {
            HttpClientError::CoreResult(McpError::internal_error(
                "HTTP client extension settings could not form a cache key",
            ))
        })?;
        let semantic_projection = serde_json::to_string(&semantic_parameters).map_err(|_| {
            HttpClientError::CoreResult(McpError::internal_error(
                "HTTP client semantic parameters could not form a cache key",
            ))
        })?;
        Ok(FinalCacheKey::new(
            self.connection
                .protocol_plan()
                .modern_post_target()
                .unwrap_or("http"),
            MODERN_PROTOCOL_VERSION,
            normalized_capabilities,
            extension_settings,
            method,
            semantic_projection,
            semantic_parameters
                .get("cursor")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
            FINAL_CACHE_POLICY_REVISION,
            FINAL_CACHE_EXTENSION_REVISION,
            FINAL_CACHE_REPRESENTATION_POLICY_REVISION,
            FINAL_CACHE_LIMITS_POLICY_REVISION,
            CachePartitionKey::new("http-client-connection"),
            result_set,
        ))
    }

    /// Sends one request with the next client-owned JSON-RPC request ID.
    pub async fn request(
        &mut self,
        cx: &Cx,
        method: impl AsRef<str>,
        parameters: serde_json::Value,
    ) -> Result<ClientHttpResponse, HttpClientError> {
        let request_id = self.next_request_id()?;
        self.connection
            .request(cx, method, parameters, request_id)
            .await
            .map_err(HttpClientError::Connection)
    }

    /// Sends one notification through the selected HTTP era.
    pub async fn notify(
        &mut self,
        cx: &Cx,
        method: impl AsRef<str>,
        parameters: Option<serde_json::Value>,
    ) -> Result<(), HttpClientError> {
        self.connection
            .notify(cx, method, parameters)
            .await
            .map_err(HttpClientError::Connection)
    }
}

fn final_cache_result_set(request: &CoreRequest) -> Option<FinalCacheResultSet> {
    let CoreRequest::Final(request) = request else {
        return None;
    };
    match request {
        FinalCoreRequest::ToolsList(_) => Some(FinalCacheResultSet::Tools),
        FinalCoreRequest::ResourcesList(_) => Some(FinalCacheResultSet::Resources),
        FinalCoreRequest::ResourceTemplatesList(_) => Some(FinalCacheResultSet::ResourceTemplates),
        FinalCoreRequest::ResourcesRead(params) => Some(FinalCacheResultSet::Resource(
            params.uri.as_str().to_owned(),
        )),
        FinalCoreRequest::PromptsList(_) => Some(FinalCacheResultSet::Prompts),
        _ => None,
    }
}

/// An MCP client instance.
///
/// Clients are built using [`ClientBuilder`] and own a stdio subprocess
/// transport. Use [`HttpClient`] for policy-bound HTTP composition.
const MAX_FINAL_CACHE_TTL_DIAGNOSTICS: usize = 64;
#[cfg(unix)]
const FINAL_CACHE_NOTIFICATION_DRAIN_WINDOW: Duration = Duration::from_millis(1);
const FINAL_CACHE_POLICY_REVISION: u64 = 1;
const FINAL_CACHE_EXTENSION_REVISION: u64 = 1;
const FINAL_CACHE_REPRESENTATION_POLICY_REVISION: u64 = 1;
const FINAL_CACHE_LIMITS_POLICY_REVISION: u64 = 1;
const FINAL_CACHE_LIST_RESTART_LIMIT_ERROR: &str =
    "Final list changed while rebuilding its cache-consistent page set";

#[derive(Clone, Copy, Debug)]
struct FinalCachePageState {
    generation: FinalCacheGeneration,
    scope: fastmcp_protocol::CacheScope,
    miss: Option<FinalCacheMiss>,
}

/// Raw response bytes paired with the monotonic instant at which the response
/// became available to this client.
struct ReceivedPreparedResult {
    result: serde_json::Value,
    raw_result: Option<String>,
    receipt: Instant,
}

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
    /// Exact non-progress notifications received from a modern server.
    final_server_notifications: VecDeque<ServerNotification>,
    /// Bounded final complete-result cache scoped to this client connection.
    final_result_cache: FinalResultCache,
    /// Bounded compatibility diagnostics for immediately-stale peer TTLs.
    final_cache_ttl_diagnostics: VecDeque<FinalCacheTtlDiagnostic>,
    /// Receipt captured as soon as a typed core response reaches this client.
    last_core_result_receipt: Option<Instant>,
    /// Per-page provenance retained only until the immediate list aggregator
    /// consumes it.
    last_final_cache_page: Option<FinalCachePageState>,
    /// Application handlers for server-initiated requests on this connection.
    reverse_request_handlers: ReverseRequestHandlers,
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
    /// Final logging configuration included in metadata of later modern
    /// requests. Exact legacy sessions send the historical RPC instead.
    final_log_level: Option<LoggingLevel>,
}

/// Successful client negotiation, kept in its protocol-native shape until it
/// is committed to session state.
enum ClientInitialization {
    /// Exact 2024-11-05 initialization response.
    Legacy(InitializeResult),
    /// Final `server/discover` response plus its required server identity.
    Modern {
        server_info: ServerInfo,
        discovery: ServerDiscoverResult,
    },
}

impl ClientInitialization {
    fn protocol_version(&self) -> &str {
        match self {
            Self::Legacy(result) => &result.protocol_version,
            Self::Modern { .. } => MODERN_PROTOCOL_VERSION,
        }
    }
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
            session: ClientSession::new_placeholder(
                client_info.clone(),
                client_capabilities.clone(),
                ServerInfo {
                    name: String::new(),
                    version: String::new(),
                },
                ServerCapabilities::default(),
            )
            .with_protocol_plan(protocol_plan.clone()),
            // `initialize()` consumes ID 1 through the same monotonic
            // allocator, leaving ID 2 as the first ordinary request ID.
            next_id: AtomicU64::new(1),
            responses: ResponseRegistry::new(),
            final_server_notifications: VecDeque::new(),
            final_result_cache: FinalResultCache::default(),
            final_cache_ttl_diagnostics: VecDeque::new(),
            last_core_result_receipt: None,
            last_final_cache_page: None,
            reverse_request_handlers: ReverseRequestHandlers::new(),
            timeout_policy: RequestTimeoutPolicy::default(),
            auto_initialize: false,
            initialized: AtomicBool::new(false),
            initialization_error: None,
            final_log_level: None,
        };

        // Perform initialization handshake
        let initialization = match client.initialize(client_info, client_capabilities) {
            Ok(result) => result,
            Err(error) => {
                let cleanup = client.close();
                return combine_operation_and_cleanup(Err(error), cleanup);
            }
        };

        let init_protocol_version = initialization.protocol_version().to_owned();
        if let Err(error) = client.replace_session_after_initialization(initialization) {
            let cleanup = client.close();
            return combine_operation_and_cleanup(Err(error), cleanup);
        }

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
        self.session.set_protocol_plan(protocol_plan);
        debug_assert!(self.session.selected_era() == selected_era);
    }

    /// Creates a new client builder.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Connects a ready high-level HTTP client from an immutable protocol plan.
    ///
    /// This is the HTTP counterpart to [`Self::stdio_with_protocol_plan`].
    /// The returned [`HttpClient`] owns policy selection and completes the
    /// legacy lifecycle before allowing ordinary application requests.
    pub fn http(protocol_plan: ClientProtocolPlan) -> Result<HttpClient, HttpClientError> {
        ClientBuilder::new()
            .protocol_plan(protocol_plan)
            .connect_http_client()
    }

    /// Connects a ready high-level HTTP client with an explicit cancellation context.
    pub async fn http_with_cx(
        protocol_plan: ClientProtocolPlan,
        cx: &Cx,
    ) -> Result<HttpClient, HttpClientError> {
        ClientBuilder::new()
            .protocol_plan(protocol_plan)
            .connect_http_client_with_cx(cx)
            .await
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
            final_server_notifications: VecDeque::new(),
            final_result_cache: FinalResultCache::default(),
            final_cache_ttl_diagnostics: VecDeque::new(),
            last_core_result_receipt: None,
            last_final_cache_page: None,
            reverse_request_handlers: ReverseRequestHandlers::new(),
            timeout_policy,
            auto_initialize: false,
            initialized: AtomicBool::new(true), // Already initialized by builder
            initialization_error: None,
            final_log_level: None,
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
            final_server_notifications: VecDeque::new(),
            final_result_cache: FinalResultCache::default(),
            final_cache_ttl_diagnostics: VecDeque::new(),
            last_core_result_receipt: None,
            last_final_cache_page: None,
            reverse_request_handlers: ReverseRequestHandlers::new(),
            timeout_policy,
            auto_initialize: true,
            initialized: AtomicBool::new(false),
            initialization_error: None,
            final_log_level: None,
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
        let initialization = match self.initialize(client_info, capabilities) {
            Ok(result) => result,
            Err(error) => return Err(self.record_initialization_failure(error)),
        };

        let init_protocol_version = initialization.protocol_version().to_owned();
        if let Err(error) = self.replace_session_after_initialization(initialization) {
            return Err(self.record_initialization_failure(error));
        }

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

    /// Admits an API that returns an exact final result payload.
    ///
    /// The selected era is immutable after initialization. Check it before
    /// constructing request parameters or allocating a request ID so a legacy
    /// session remains completely untouched by modern-only conveniences.
    fn require_modern_final_result_session(&mut self, method: &str) -> McpResult<()> {
        self.ensure_initialized()?;
        if self.session.selected_era() == Some(ProtocolEra::Modern2026) {
            return Ok(());
        }

        Err(McpError::invalid_params(format!(
            "{method} exact final result is available only for MCP 2026-07-28"
        )))
    }

    /// Admits an API that returns an exact legacy result payload.
    ///
    /// The selected era is immutable after initialization. Check it before
    /// constructing request parameters or allocating a request ID so a modern
    /// session cannot be silently projected into the legacy vocabulary.
    fn require_legacy_exact_result_session(&mut self, method: &str) -> McpResult<()> {
        self.ensure_initialized()?;
        if self.session.selected_era() == Some(ProtocolEra::Legacy2024) {
            return Ok(());
        }

        Err(McpError::invalid_params(format!(
            "{method} exact legacy result is available only for MCP 2024-11-05"
        )))
    }

    fn record_initialization_failure(&mut self, error: McpError) -> McpError {
        let error = self.terminate_connection(error);
        self.initialization_error = Some(error.clone());
        error
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
        let cleanup = combine_cleanup_results(
            self.cleanup_error.clone().map_or(Ok(()), Err),
            self.pending_process_cleanup_error
                .clone()
                .map_or(Ok(()), Err),
        );
        combine_operation_and_cleanup::<()>(Err(error), cleanup)
            .expect_err("a terminal operation error cannot become a successful cleanup result")
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

    /// Returns whether final discovery activated the official MCP Apps extension.
    #[must_use]
    pub const fn mcp_apps_active(&self) -> bool {
        self.session.mcp_apps_active()
    }

    /// Returns the server capabilities after initialization.
    #[must_use]
    pub fn server_capabilities(&self) -> &ServerCapabilities {
        self.session.server_capabilities()
    }

    /// Returns the exact final `server/discover` result for a modern session.
    ///
    /// This retains final capabilities, instructions, metadata, and cache
    /// semantics without projecting them into the legacy initialization
    /// result. Exact 2024-11-05 sessions return `None`.
    #[must_use]
    pub fn server_discovery(&self) -> Option<&ServerDiscoverResult> {
        self.session.server_discovery()
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

    /// Drains final server notifications received during modern requests.
    ///
    /// Progress notifications remain request-scoped and are delivered only to
    /// the progress callback. Exact 2024-11-05 sessions never retain values in
    /// this queue.
    #[must_use]
    pub fn take_final_server_notifications(&mut self) -> Vec<ServerNotification> {
        self.final_server_notifications.drain(..).collect()
    }

    /// Returns whether final complete-result caching is enabled for this client.
    ///
    /// Exact MCP 2024-11-05 requests bypass this cache unconditionally.
    #[must_use]
    pub const fn final_result_cache_enabled(&self) -> bool {
        self.final_result_cache.is_enabled()
    }

    /// Enables or disables final complete-result caching for this client.
    ///
    /// Disabling the cache is an opt-out: retained entries remain local and
    /// unavailable until caching is enabled again.
    pub fn set_final_result_cache_enabled(&mut self, enabled: bool) {
        self.final_result_cache.set_enabled(enabled);
    }

    /// Returns redacted aggregate final-cache counters.
    #[must_use]
    pub const fn final_result_cache_stats(&self) -> FinalCacheStats {
        self.final_result_cache.stats()
    }

    /// Removes all final complete-result cache entries for this client.
    pub fn clear_final_result_cache(&mut self) {
        self.final_result_cache.clear();
    }

    /// Drains bounded compatibility diagnostics for peer cache TTLs that were
    /// accepted with zero freshness.
    #[must_use]
    pub fn take_final_cache_ttl_diagnostics(&mut self) -> Vec<FinalCacheTtlDiagnostic> {
        self.final_cache_ttl_diagnostics.drain(..).collect()
    }

    fn retain_final_cache_ttl_diagnostic(&mut self, diagnostic: FinalCacheTtlDiagnostic) {
        if self.final_cache_ttl_diagnostics.len() >= MAX_FINAL_CACHE_TTL_DIAGNOSTICS {
            self.final_cache_ttl_diagnostics.pop_front();
        }
        self.final_cache_ttl_diagnostics.push_back(diagnostic);
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

    /// Replaces the reverse request handlers used by this live client session.
    pub fn set_reverse_request_handlers(&mut self, handlers: ReverseRequestHandlers) {
        self.reverse_request_handlers = handlers;
    }

    fn server_request_response(&mut self, request: &JsonRpcRequest) -> Option<JsonRpcMessage> {
        live_server_request_response(&mut self.reverse_request_handlers, request)
    }

    /// Verifies that the initialized server can answer an MCP ping request.
    ///
    /// # Errors
    ///
    /// Returns an error when initialization, transport, envelope validation,
    /// or the server's ping response fails.
    pub fn ping(&mut self) -> McpResult<()> {
        self.ensure_initialized()?;
        match self.session.selected_era() {
            Some(ProtocolEra::Modern2026) => {
                // Final `ping` is an ordinary JSON-RPC request, not a core
                // request/result-algebra member. It still carries final
                // request metadata, but its acknowledgement must not be
                // decoded through `FinalCoreResult`.
                let params = self.prepare_request_parameters(serde_json::json!({}))?;
                let _: serde_json::Value = self.send_prepared_request("ping", params)?.result;
                Ok(())
            }
            Some(ProtocolEra::Legacy2024) => {
                // Retain the exact legacy core admission and acknowledgement
                // decoding path. In particular, this must never gain final
                // request metadata just because a modern peer supports it.
                let _: serde_json::Value = self.send_request("ping", serde_json::json!({}))?;
                Ok(())
            }
            None => Err(McpError::internal_error(
                "Client has no negotiated protocol era for ping",
            )),
        }
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
        let mut final_metadata = final_metadata.clone();
        let advertise_mcp_apps =
            self.session.server_discovery().is_none() || self.session.mcp_apps_active();
        if let Some(settings) = advertise_mcp_apps
            .then_some(self.session.mcp_apps_settings())
            .flatten()
        {
            let capabilities = final_metadata
                .get_mut(FINAL_CLIENT_CAPABILITIES_META_KEY)
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| {
                    McpError::internal_error("Modern request metadata omitted client capabilities")
                })?;
            let mut extensions = serde_json::Map::new();
            extensions.insert(
                fastmcp_protocol::extensions::OFFICIAL_MCP_APPS_EXTENSION_ID.to_owned(),
                settings.to_extension_settings().into_value(),
            );
            capabilities.insert(
                "extensions".to_owned(),
                serde_json::Value::Object(extensions),
            );
        }
        metadata.extend(final_metadata);
        if let Some(level) = self.final_log_level {
            metadata.insert(
                "io.modelcontextprotocol/logLevel".to_owned(),
                serde_json::to_value(level).map_err(|error| {
                    McpError::internal_error(format!(
                        "Failed to serialize modern logging configuration: {error}"
                    ))
                })?,
            );
        }
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

    /// Builds the exact final `_meta` object required by a Tasks request.
    ///
    /// Tasks has no legacy projection. The shared modern metadata builder
    /// supplies the negotiated protocol version, caller capabilities, client
    /// identity, and any selected final logging preference without broadening
    /// the Tasks parameter shape.
    fn final_task_request_meta(&self) -> McpResult<TaskRequestMeta> {
        let params = self.with_final_tasks_client_capability(serde_json::json!({}))?;
        let metadata = params
            .get("_meta")
            .cloned()
            .ok_or_else(|| McpError::internal_error("Modern Tasks request metadata was omitted"))?;
        let meta = serde_json::from_value(metadata).map_err(|error| {
            McpError::internal_error(format!(
                "Modern Tasks request metadata did not retain its final shape: {error}"
            ))
        })?;
        Ok(TaskRequestMeta { meta })
    }

    fn with_final_tasks_client_capability(
        &self,
        params: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        let mut params = self.with_modern_request_metadata(params)?;
        let metadata = params
            .get_mut("_meta")
            .ok_or_else(|| McpError::internal_error("Modern Tasks request metadata was omitted"))?;
        let capabilities = metadata
            .as_object_mut()
            .and_then(|metadata| metadata.get_mut(FINAL_CLIENT_CAPABILITIES_META_KEY))
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| {
                McpError::internal_error(
                    "Modern Tasks request metadata omitted final client capabilities",
                )
            })?;
        let extensions = capabilities
            .entry("extensions")
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
            .as_object_mut()
            .ok_or_else(|| {
                McpError::internal_error("Modern Tasks client extensions must be an object")
            })?;
        extensions.insert(
            fastmcp_protocol::TASKS_EXTENSION.to_owned(),
            serde_json::json!({}),
        );
        Ok(params)
    }

    /// Admits one official final Tasks method through bilateral empty-settings
    /// negotiation before allocating a request ID or writing to the peer.
    fn admit_final_tasks_method(&mut self, method: &str) -> McpResult<()> {
        self.admit_final_tasks_direction(method, ExtensionDirection::ClientToServer)
    }

    fn admit_final_tasks_direction(
        &mut self,
        method: &str,
        direction: ExtensionDirection,
    ) -> McpResult<()> {
        self.ensure_initialized()?;
        if self.session.selected_era() != Some(ProtocolEra::Modern2026) {
            return Err(McpError::invalid_params(
                "io.modelcontextprotocol/tasks is unavailable in exact MCP 2024-11-05",
            ));
        }

        let discovery = self.server_discovery().ok_or_else(|| {
            McpError::invalid_params(
                "Modern Tasks requires the retained final server/discover response",
            )
        })?;
        admit_final_tasks_discovery_surface(discovery, method, direction)
    }

    /// Sends one already-admitted final Tasks request and decodes its exact
    /// result envelope. A malformed task response is a peer protocol
    /// contradiction and terminates this connection.
    fn send_final_task_request<P, R>(&mut self, method: &str, params: P) -> McpResult<R>
    where
        P: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let params = serde_json::to_value(params).map_err(|error| {
            McpError::internal_error(format!("Failed to serialize final Tasks request: {error}"))
        })?;
        let result = self.send_prepared_request(method, params)?;
        let result_source = result.raw_result.as_deref().ok_or_else(|| {
            self.terminate_connection(McpError::invalid_request(
                "Peer final Tasks response lost its admitted result source",
            ))
        })?;
        serde_json::from_str(result_source).map_err(|_| {
            self.terminate_connection(McpError::invalid_request(
                "Peer response does not match the admitted final Tasks result",
            ))
        })
    }

    /// Decodes a prepared supported-core request in the immutable selected era.
    ///
    /// Non-core methods continue through the ordinary response path. A core
    /// request with invalid selected-era parameters is rejected before any
    /// request ID is allocated or bytes are committed to the peer.
    fn prepared_core_request(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> McpResult<Option<CoreRequest>> {
        let Some(era) = self.session.selected_era() else {
            return Ok(None);
        };
        match CoreRequest::decode(era, method, Some(params)) {
            Ok(request) => Ok(Some(request)),
            Err(CoreDispatchError::UnsupportedMethod { .. }) => Ok(None),
            Err(_) => Err(McpError::invalid_params(
                "Client core request parameters do not match the negotiated protocol era",
            )),
        }
    }

    fn retain_modern_server_notification(
        &mut self,
        request: &JsonRpcRequest,
    ) -> McpResult<Option<ModernServerNotification>> {
        let modern_session = match self.session.selected_era() {
            Some(ProtocolEra::Modern2026) => true,
            Some(ProtocolEra::Legacy2024) => false,
            None => self.session.protocol_plan().policy() == ProtocolPolicy::ModernOnly,
        };
        if !modern_session || !is_final_server_notification_method(request) {
            return Ok(None);
        }

        let notification = ServerNotification::decode(request).map_err(|error| {
            McpError::invalid_request(format!("Invalid final server notification: {error}"))
        })?;

        // Advance the matching generation before exposing the notification or
        // accepting a late fetch completion. A fetch captures its generation
        // before send and can only fill while it remains current.
        self.final_result_cache
            .invalidate_notification(&notification);

        let ServerNotification::Progress(progress) = notification else {
            if self.final_server_notifications.len() >= MAX_QUEUED_FINAL_SERVER_NOTIFICATIONS {
                return Err(McpError::invalid_request(
                    FINAL_SERVER_NOTIFICATION_QUEUE_OVERFLOW_ERROR,
                ));
            }
            let log_message = match &notification {
                ServerNotification::Message(message) => final_log_message_sink_projection(message),
                _ => None,
            };
            self.final_server_notifications.push_back(notification);
            if let Some(message) = log_message {
                self.emit_log_message(message);
            }
            return Ok(Some(ModernServerNotification::Retained));
        };

        Ok(Some(ModernServerNotification::Progress(progress)))
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
        let core_request = self.prepared_core_request(method, &params_value)?;
        let received = self.send_prepared_request(method, params_value)?;

        if let Some(core_request) = core_request
            && let Err(error) = decode_core_result_from_source(
                &core_request,
                &received.result,
                received.raw_result.as_deref(),
            )
        {
            return Err(self.terminate_connection(error));
        }

        decode_response_payload(received.result)
    }

    /// Sends an already-prepared request and returns its raw result value.
    ///
    /// Callers that need an era-aware result must decode this value with the
    /// request that selected its method-specific response contract.
    fn send_prepared_request(
        &mut self,
        method: &str,
        params_value: serde_json::Value,
    ) -> McpResult<ReceivedPreparedResult> {
        let timeout_policy = self.timeout_policy;
        timeout_policy.validate()?;
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
        let ReceivedJsonRpcResponse {
            mut response,
            raw_result,
        } = self.recv_response(waiter, deadlines)?;
        let receipt = Instant::now();

        // Check for error response
        if let Some(error) = response.error.take() {
            return Err(json_rpc_error_to_mcp(error));
        }

        // Parse result
        let result = response
            .result
            .take()
            .ok_or_else(|| McpError::internal_error("No result in response"))?;

        Ok(ReceivedPreparedResult {
            result,
            raw_result,
            receipt,
        })
    }

    /// Sends one supported core request and retains its selected-era result.
    fn send_typed_core_request<P: serde::Serialize>(
        &mut self,
        method: &str,
        params: P,
    ) -> McpResult<CoreResult> {
        self.send_typed_core_request_with_tasks(method, params, false)
    }

    fn send_typed_core_request_with_tasks<P: serde::Serialize>(
        &mut self,
        method: &str,
        params: P,
        declare_tasks: bool,
    ) -> McpResult<CoreResult> {
        let params_value = serde_json::to_value(params)
            .map_err(|e| McpError::internal_error(format!("Failed to serialize params: {e}")))?;
        let params_value = if declare_tasks {
            self.with_final_tasks_client_capability(params_value)?
        } else {
            self.prepare_request_parameters(params_value)?
        };
        let core_request = self
            .prepared_core_request(method, &params_value)?
            .ok_or_else(|| {
                McpError::invalid_params(
                    "Method is not a supported core request in the negotiated era",
                )
            })?;
        let params_value = core_request
            .encode_params()
            .map_err(|_| {
                McpError::invalid_params(
                    "Client core request could not be encoded in the negotiated protocol era",
                )
            })?
            .ok_or_else(|| {
                McpError::invalid_params(
                    "Method has no parameter object in the negotiated protocol era",
                )
            })?;
        self.last_core_result_receipt = None;
        let received = self.send_prepared_request(method, params_value)?;
        let (result, ttl_diagnostic) = decode_core_result_with_cache_ttl_from_source(
            &core_request,
            &received.result,
            received.raw_result.as_deref(),
        )
        .map_err(|error| self.terminate_connection(error))?;
        self.last_core_result_receipt = Some(received.receipt);
        if let Some(diagnostic) = ttl_diagnostic {
            self.retain_final_cache_ttl_diagnostic(diagnostic);
        }
        Ok(result)
    }

    fn final_cache_key(
        &self,
        method: &str,
        semantic_parameters: serde_json::Value,
        cursor: Option<&str>,
        result_set: FinalCacheResultSet,
    ) -> McpResult<FinalCacheKey> {
        let normalized_capabilities = serde_json::to_string(self.session.client_capabilities())
            .map_err(|_| {
                McpError::internal_error("Client capabilities could not form a cache key")
            })?;
        let extension_settings = serde_json::to_string(&serde_json::json!({
            "mcpApps": self.session.mcp_apps_settings().map(|settings| {
                settings.to_extension_settings().into_value()
            }),
            "descriptorRevision": FINAL_CACHE_EXTENSION_REVISION,
        }))
        .map_err(|_| {
            McpError::internal_error("Client extension settings could not form a cache key")
        })?;
        let semantic_projection = serde_json::to_string(&semantic_parameters).map_err(|_| {
            McpError::internal_error("Client semantic parameters could not form a cache key")
        })?;
        let endpoint_configuration = self
            .session
            .protocol_plan()
            .modern_post_target()
            .unwrap_or("stdio")
            .to_owned();

        // This cache is owned by one client instance, so this fixed local
        // partition cannot cross a connection or credential boundary. The
        // revision fields are explicit cache-identity inputs and must change
        // when their corresponding local policies change.
        Ok(FinalCacheKey::new(
            endpoint_configuration,
            MODERN_PROTOCOL_VERSION,
            normalized_capabilities,
            extension_settings,
            method,
            semantic_projection,
            cursor.map(ToOwned::to_owned),
            FINAL_CACHE_POLICY_REVISION,
            FINAL_CACHE_EXTENSION_REVISION,
            FINAL_CACHE_REPRESENTATION_POLICY_REVISION,
            FINAL_CACHE_LIMITS_POLICY_REVISION,
            CachePartitionKey::new("stdio-client-connection"),
            result_set,
        ))
    }

    fn cached_final_core_request<F>(
        &mut self,
        method: &str,
        semantic_parameters: serde_json::Value,
        cursor: Option<&str>,
        result_set: FinalCacheResultSet,
        fetch: F,
    ) -> McpResult<CoreResult>
    where
        F: FnOnce(&mut Self) -> McpResult<CoreResult>,
    {
        self.last_final_cache_page = None;
        if self.session.selected_era() != Some(ProtocolEra::Modern2026) {
            return fetch(self);
        }

        self.drain_final_cache_invalidations()?;
        let key = self.final_cache_key(method, semantic_parameters, cursor, result_set)?;
        match self.final_result_cache.lookup_page_at(&key, Instant::now()) {
            FinalCachePageLookup::Fresh(page) => {
                self.checkpoint_task_poll()?;
                self.last_final_cache_page = Some(FinalCachePageState {
                    generation: page.generation,
                    scope: page.scope,
                    miss: None,
                });
                return Ok(page.result);
            }
            FinalCachePageLookup::Miss(miss) => {
                let generation = self.final_result_cache.begin_fetch(key.result_set());
                let result = match fetch(self) {
                    Ok(result) => result,
                    Err(error) => {
                        if cursor.is_some() && error.code == McpErrorCode::InvalidParams {
                            self.final_result_cache
                                .invalidate_result_set(key.result_set());
                        }
                        return Err(error);
                    }
                };
                let scope = final_cache_hints(&result).map(|(_, scope)| scope);
                let receipt = self
                    .last_core_result_receipt
                    .take()
                    .unwrap_or_else(Instant::now);
                let page_result_set = key.result_set().clone();
                let _ = self.final_result_cache.insert_if_current_at(
                    key,
                    generation,
                    result.clone(),
                    receipt,
                );
                let invalidated_during_fetch =
                    generation != self.final_result_cache.begin_fetch(&page_result_set);
                let miss = if invalidated_during_fetch {
                    Some(FinalCacheMiss::Invalidated)
                } else {
                    Some(miss)
                };
                if let Some(scope) = scope {
                    self.last_final_cache_page = Some(FinalCachePageState {
                        generation: self.final_result_cache.begin_fetch(&page_result_set),
                        scope,
                        miss,
                    });
                }
                Ok(result)
            }
        }
    }

    /// Drains immediately available stdio frames before a cache hit can be
    /// served, so an already-delivered list/resource invalidation wins over a
    /// fresh entry. Targets without a nonblocking child-pipe primitive discard
    /// retained entries instead of serving an unread notification stale.
    fn drain_final_cache_invalidations(&mut self) -> McpResult<()> {
        self.checkpoint_task_poll()?;

        #[cfg(unix)]
        {
            let deadline = Instant::now() + FINAL_CACHE_NOTIFICATION_DRAIN_WINDOW;
            loop {
                let (message, _) =
                    match recv_child_transport(&mut self.transport, &self.cx, Some(deadline)) {
                        Ok(received) => received,
                        Err(TransportError::ReceiveDeadlineExceeded)
                            if !self.transport.is_closed() =>
                        {
                            return Ok(());
                        }
                        Err(TransportError::Cancelled) if !self.transport.is_closed() => {
                            return Err(self.terminate_connection(McpError::request_cancelled()));
                        }
                        Err(error) => {
                            return Err(self.terminate_connection(transport_error_to_mcp(error)));
                        }
                    };
                self.process_idle_cache_invalidation_message(message)?;
            }
        }

        #[cfg(not(unix))]
        {
            self.final_result_cache.clear();
            Ok(())
        }
    }

    fn process_idle_cache_invalidation_message(
        &mut self,
        message: JsonRpcMessage,
    ) -> McpResult<()> {
        if let Err(error) = validate_inbound_typed_message(&message) {
            return Err(self.terminate_connection(error));
        }
        match message {
            JsonRpcMessage::Response(response) => {
                let route = self
                    .route_last_received_response(response)
                    .map_err(|error| self.terminate_connection(error))?;
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
                if self.retain_modern_server_notification(&request)?.is_some() {
                    return Ok(());
                }
                if let Some(response) = self.server_request_response(&request) {
                    if let Err(error) = self.send_server_response_during_receive(response) {
                        return Err(self.terminate_connection(error));
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
        Ok(())
    }

    /// Consumes the immediately preceding cacheable page provenance. A full
    /// list never combines a page invalidated during fetch or a different
    /// scope or generation with pages already accumulated for that list.
    fn final_list_restart_needed(
        &mut self,
        result_set: &FinalCacheResultSet,
        baseline: &mut Option<(FinalCacheGeneration, fastmcp_protocol::CacheScope)>,
    ) -> bool {
        let Some(page) = self.last_final_cache_page.take() else {
            return false;
        };
        let generation_drift = page.generation != self.final_result_cache.begin_fetch(result_set);
        let invalidated_during_fetch = matches!(page.miss, Some(FinalCacheMiss::Invalidated));
        let scope_drift = baseline.is_some_and(|(_, scope)| scope != page.scope);
        if generation_drift || invalidated_during_fetch || scope_drift {
            self.final_result_cache.invalidate_result_set(result_set);
            return true;
        }
        if baseline.is_none() {
            *baseline = Some((page.generation, page.scope));
        }
        false
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

    fn route_last_received_response(
        &mut self,
        response: JsonRpcResponse,
    ) -> McpResult<ResponseRoute> {
        let frame = self.transport.last_received_frame().ok_or_else(|| {
            McpError::internal_error("Successful stdio response lost its admitted source frame")
        })?;
        let admission = decode_strict_jsonrpc_response(frame, frame.len()).map_err(|_| {
            McpError::internal_error("Admitted stdio response could not retain its raw result")
        })?;
        if admission.response() != &response {
            return Err(McpError::internal_error(
                "Typed stdio response differs from its admitted source frame",
            ));
        }
        let (_, raw_result) = admission.into_parts();
        Ok(self.responses.route_with_raw_result(response, raw_result))
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
                let route = match self.route_last_received_response(response) {
                    Ok(route) => route,
                    Err(error) => {
                        let _ = self.terminate_connection(error);
                        return timeout;
                    }
                };
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
                match self.retain_modern_server_notification(&request) {
                    Ok(Some(_)) => return timeout,
                    Ok(None) => {}
                    Err(error) => {
                        let _ = self.terminate_connection(error);
                        return timeout;
                    }
                }
                if let Some(response) = self.server_request_response(&request) {
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
    ) -> McpResult<ReceivedJsonRpcResponse> {
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
                    let route = self
                        .route_last_received_response(response)
                        .map_err(|error| self.terminate_connection(error))?;
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
                    match self.retain_modern_server_notification(&request) {
                        Ok(Some(_)) => continue,
                        Ok(None) => {}
                        Err(error) => return Err(self.terminate_connection(error)),
                    }
                    if let Some(response) = self.server_request_response(&request) {
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

    /// Collects one final `subscriptions/listen` stream until its complete
    /// result. The listener owns only its acknowledgement, subscription
    /// change events, and matching cancellation. Its retained events use the
    /// same bound as the connection-wide final notification queue; a matching
    /// cancellation retires the waiter so one late terminal result is safely
    /// consumed. Ordinary final log/progress notifications keep their existing
    /// connection-wide handling.
    fn recv_subscription_listener(
        &mut self,
        mut waiter: ResponseWaiter,
        core_request: &CoreRequest,
        requested: &SubscriptionFilter,
        deadlines: RequestDeadlines,
    ) -> McpResult<SubscriptionListenCollector> {
        let expected_id = waiter.id.clone();
        let mut accepted_filter = None;
        let mut notifications = Vec::new();
        let mut task_notifications = Vec::new();

        loop {
            if let Some(response) = waiter.try_response()? {
                debug_assert_eq!(response.id.as_ref(), Some(&expected_id));
                if let Some(error) = response.error.clone() {
                    return Err(json_rpc_error_to_mcp(error));
                }
                let raw_result = response.raw_result.as_deref().ok_or_else(|| {
                    self.terminate_connection(McpError::invalid_request(
                        "Final subscriptions/listen response lost its admitted result source",
                    ))
                })?;
                let result = core_request
                    .decode_response_result(&response, raw_result)
                    .map_err(|error| {
                        self.terminate_connection(McpError::invalid_request(format!(
                            "Invalid final subscriptions/listen termination: {error}"
                        )))
                    })?;
                let CoreResult::Final(FinalCoreResult::SubscriptionsListen {
                    result: terminal,
                    subscription_id,
                    ..
                }) = result
                else {
                    return Err(
                        self.terminate_connection(subscription_listener_protocol_error(
                            "Subscription listener received a non-listen terminal result",
                        )),
                    );
                };
                if subscription_id != expected_id {
                    return Err(
                        self.terminate_connection(subscription_listener_protocol_error(
                            "Subscription listener terminal ID does not match its request",
                        )),
                    );
                }
                let Some(accepted_filter) = accepted_filter else {
                    return Err(
                        self.terminate_connection(subscription_listener_protocol_error(
                            "Subscription listener terminated before acknowledgement",
                        )),
                    );
                };
                return Ok(SubscriptionListenCollector {
                    subscription_id,
                    accepted_filter,
                    notifications,
                    task_notifications,
                    terminal,
                });
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
                    Err(TransportError::Closed) => {
                        return Err(self.terminate_connection(
                            subscription_listener_protocol_error(
                                "Subscription listener reached EOF before terminal complete result",
                            ),
                        ));
                    }
                    Err(error) => {
                        return Err(self.terminate_connection(transport_error_to_mcp(error)));
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
                    let route = self
                        .route_last_received_response(response)
                        .map_err(|error| self.terminate_connection(error))?;
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
                    if request.id.is_none() && request.method == TASK_STATUS_NOTIFICATION {
                        let Some(accepted_filter) = accepted_filter.as_ref() else {
                            return Err(self.terminate_connection(
                                subscription_listener_protocol_error(
                                    "Subscription listener received a Tasks event before acknowledgement",
                                ),
                            ));
                        };
                        let accepted_task_ids = match task_subscription_ids(accepted_filter) {
                            Ok(Some(task_ids)) => task_ids,
                            _ => {
                                return Err(self.terminate_connection(
                                    subscription_listener_protocol_error(
                                        "Subscription listener received a Tasks event without an acknowledged Tasks filter",
                                    ),
                                ));
                            }
                        };
                        let notification: FinalTaskStatusNotification = match serde_json::from_value(
                            serde_json::to_value(&request).map_err(|error| {
                                McpError::internal_error(format!(
                                    "Failed to inspect Tasks subscription event: {error}"
                                ))
                            })?,
                        ) {
                            Ok(notification) => notification,
                            Err(_) => {
                                return Err(self.terminate_connection(
                                    subscription_listener_protocol_error(
                                        "Subscription listener received an invalid Tasks event",
                                    ),
                                ));
                            }
                        };
                        let subscription_id = notification
                            .params
                            .meta
                            .as_ref()
                            .and_then(|metadata| metadata.get(FINAL_SUBSCRIPTION_ID_META_KEY))
                            .and_then(|value| {
                                serde_json::from_value::<RequestId>(value.clone()).ok()
                            });
                        if subscription_id.as_ref() != Some(&expected_id) {
                            return Err(self.terminate_connection(
                                subscription_listener_protocol_error(
                                    "Tasks event subscription ID does not match the listen request",
                                ),
                            ));
                        }
                        if !accepted_task_ids
                            .iter()
                            .any(|task_id| task_id == &notification.params.task.base().task_id)
                        {
                            return Err(self.terminate_connection(
                                subscription_listener_protocol_error(
                                    "Tasks event taskId is outside the acknowledged filter",
                                ),
                            ));
                        }
                        if task_notifications.len() >= MAX_QUEUED_FINAL_SERVER_NOTIFICATIONS {
                            return Err(self.terminate_connection(McpError::invalid_request(
                                FINAL_SERVER_NOTIFICATION_QUEUE_OVERFLOW_ERROR,
                            )));
                        }
                        task_notifications.push(notification);
                        continue;
                    }

                    if is_final_server_notification_method(&request) {
                        let notification = match ServerNotification::decode(&request) {
                            Ok(notification) => notification,
                            Err(_) => {
                                return Err(self.terminate_connection(
                                    subscription_listener_protocol_error(
                                        "Subscription listener received an invalid final notification",
                                    ),
                                ));
                            }
                        };
                        match notification {
                            ServerNotification::SubscriptionsAcknowledged(acknowledgement) => {
                                if accepted_filter.is_some() {
                                    return Err(self.terminate_connection(
                                        subscription_listener_protocol_error(
                                            "Subscription listener received a duplicate acknowledgement",
                                        ),
                                    ));
                                }
                                if let Err(error) = validate_subscription_acknowledgement(
                                    &expected_id,
                                    requested,
                                    &acknowledgement,
                                ) {
                                    return Err(self.terminate_connection(error));
                                }
                                accepted_filter = Some(acknowledgement.notifications);
                            }
                            ServerNotification::Cancelled(cancellation) => {
                                if cancellation.request_id != expected_id {
                                    return Err(self.terminate_connection(
                                        subscription_listener_protocol_error(
                                            "Subscription cancellation ID does not match the listen request",
                                        ),
                                    ));
                                }
                                let error = McpError::request_cancelled();
                                match self.responses.tombstone(&expected_id, error.clone()) {
                                    Ok(true) => {}
                                    Ok(false) => {
                                        return Err(self.terminate_connection(
                                            subscription_listener_protocol_error(
                                                "Subscription cancellation could not retire its listen request",
                                            ),
                                        ));
                                    }
                                    Err(tombstone_error) => {
                                        return Err(self.terminate_connection(tombstone_error));
                                    }
                                }
                                return Err(error);
                            }
                            notification @ (ServerNotification::ResourcesListChanged(_)
                            | ServerNotification::ToolsListChanged(_)
                            | ServerNotification::PromptsListChanged(_)
                            | ServerNotification::ResourceUpdated(_)) => {
                                let Some(accepted_filter) = accepted_filter.as_ref() else {
                                    return Err(self.terminate_connection(
                                        subscription_listener_protocol_error(
                                            "Subscription listener received an event before acknowledgement",
                                        ),
                                    ));
                                };
                                if let Err(error) = validate_subscription_notification_filter(
                                    &notification,
                                    accepted_filter,
                                ) {
                                    return Err(self.terminate_connection(error));
                                }
                                if notifications.len() >= MAX_QUEUED_FINAL_SERVER_NOTIFICATIONS {
                                    return Err(self.terminate_connection(
                                        McpError::invalid_request(
                                            FINAL_SERVER_NOTIFICATION_QUEUE_OVERFLOW_ERROR,
                                        ),
                                    ));
                                }
                                notifications.push(notification);
                            }
                            ServerNotification::Progress(_) | ServerNotification::Message(_) => {
                                if let Err(error) = self.retain_modern_server_notification(&request)
                                {
                                    return Err(self.terminate_connection(error));
                                }
                            }
                        }
                        continue;
                    }

                    if let Some(response) = self.server_request_response(&request) {
                        if let Err(error) = self.send_server_response_during_receive(response) {
                            return Err(self.terminate_connection(error));
                        }
                        continue;
                    }

                    if server_notification_kind(&request)
                        == Some(ServerNotificationKind::LogMessage)
                        && let Some(params) = request.params.as_ref()
                        && let Ok(message) =
                            serde_json::from_value::<LogMessageParams>(params.clone())
                    {
                        self.emit_log_message(message);
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
    ) -> McpResult<ClientInitialization> {
        match self.session.protocol_plan().policy() {
            ProtocolPolicy::ModernOnly => self.initialize_modern(client_info, capabilities),
            // The public Auto entry point performs its isolated modern probe
            // before constructing this legacy client. Retaining this exact
            // path here keeps deferred initialization from converting a
            // configured legacy process into a second selection attempt.
            ProtocolPolicy::Auto | ProtocolPolicy::LegacyOnly => self
                .initialize_legacy(client_info, capabilities)
                .map(ClientInitialization::Legacy),
        }
    }

    fn replace_session_after_initialization(
        &mut self,
        initialization: ClientInitialization,
    ) -> McpResult<()> {
        let client_info = self.session.client_info().clone();
        let client_capabilities = self.session.client_capabilities().clone();
        let mcp_apps_settings = self.session.mcp_apps_settings().cloned();
        let protocol_plan = self.session.protocol_plan().clone();
        let mut session = match initialization {
            ClientInitialization::Legacy(result) => ClientSession::try_new(
                client_info,
                client_capabilities,
                result.server_info,
                result.capabilities,
                result.protocol_version,
            )
            .map_err(|_| McpError::internal_error(UNSUPPORTED_PROTOCOL_VERSION_ERROR))?,
            ClientInitialization::Modern {
                server_info,
                discovery,
            } => ClientSession::try_new(
                client_info,
                client_capabilities,
                server_info,
                ServerCapabilities::default(),
                MODERN_PROTOCOL_VERSION.to_owned(),
            )
            .map_err(|_| McpError::internal_error(UNSUPPORTED_PROTOCOL_VERSION_ERROR))?
            .with_server_discovery(discovery),
        };
        session = session.with_mcp_apps_settings(mcp_apps_settings);
        let apps_active = session.server_discovery().is_some_and(|discovery| {
            resolve_mcp_apps_activation(session.mcp_apps_settings(), discovery)
        });
        session.set_mcp_apps_active(apps_active);
        self.session = session.try_with_protocol_plan(protocol_plan).map_err(|_| {
            McpError::internal_error("Configured protocol policy rejects the negotiated era")
        })?;
        Ok(())
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
    ) -> McpResult<ClientInitialization> {
        let params = serde_json::to_value(ServerDiscoverRequest::default())
            .map_err(|error| {
                McpError::internal_error(format!(
                    "Failed to serialize modern server/discover parameters: {error}"
                ))
            })
            .and_then(|params| self.with_modern_request_metadata(params))?;
        let received = self.send_prepared_request(SERVER_DISCOVER_METHOD, params)?;
        let result_source = received.raw_result.as_deref().ok_or_else(|| {
            self.terminate_connection(McpError::invalid_request(
                "Modern server/discover response lost its admitted result source",
            ))
        })?;
        let result: ServerDiscoverResult = serde_json::from_str(result_source).map_err(|_| {
            self.terminate_connection(McpError::internal_error(INVALID_RESPONSE_PAYLOAD_ERROR))
        })?;
        if !result
            .supported_versions()
            .iter()
            .any(|version| version == MODERN_PROTOCOL_VERSION)
        {
            return Err(McpError::internal_error(UNSUPPORTED_PROTOCOL_VERSION_ERROR));
        }
        let server_info = result.server_info().cloned().ok_or_else(|| {
            McpError::internal_error("Modern server/discover response has no _meta server info")
        })?;
        Ok(ClientInitialization::Modern {
            server_info,
            discovery: result,
        })
    }

    /// Lists one page of tools and returns its negotiated core result.
    ///
    /// The caller supplies the opaque peer cursor, if any. A modern session
    /// returns [`CoreResult::Final`] with [`FinalCoreResult::ToolsList`]; an
    /// exact legacy session returns [`CoreResult::Legacy`].
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or its selected-era result
    /// contract is contradicted. A contradictory core result terminates the
    /// connection.
    pub fn list_tools_typed(&mut self, cursor: Option<&str>) -> McpResult<CoreResult> {
        self.ensure_initialized()?;
        let cursor = cursor.map(ToOwned::to_owned);
        let params = ListToolsParams {
            cursor: cursor.clone(),
            ..ListToolsParams::default()
        };
        self.cached_final_core_request(
            "tools/list",
            serde_json::json!({}),
            cursor.as_deref(),
            FinalCacheResultSet::Tools,
            move |client| client.send_typed_core_request("tools/list", params),
        )
    }

    /// Lists available tools.
    ///
    /// This convenience API follows peer cursors and returns the flattened
    /// legacy-compatible tool vector. Use [`Self::list_tools_typed`] to retain
    /// the negotiated, single-page core result.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
        self.ensure_initialized()?;
        let mut restarts = 0;
        'rebuild: loop {
            let mut all = Vec::new();
            let mut cursor: Option<String> = None;
            let mut budget = PaginationBudget::new();
            let mut baseline = None;

            loop {
                budget.begin_page()?;
                let (tools, next_cursor) =
                    convenience_tools_page(self.list_tools_typed(cursor.as_deref())?)?;
                if self.final_list_restart_needed(&FinalCacheResultSet::Tools, &mut baseline) {
                    restarts += 1;
                    if restarts > 1 {
                        return Err(McpError::invalid_request(
                            FINAL_CACHE_LIST_RESTART_LIMIT_ERROR,
                        ));
                    }
                    continue 'rebuild;
                }
                budget.account_page(&tools)?;
                all.extend(tools);
                cursor = budget.admit_next_cursor(next_cursor)?;
                if cursor.is_none() {
                    return Ok(all);
                }
            }
        }
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
        let (tools, next_cursor) =
            convenience_tools_page(self.list_tools_typed(cursor_parameter.as_deref())?)?;
        bounded_list_page(tools, cursor, next_cursor, limits)
    }

    /// Calls a tool and returns its negotiated, method-aware core result.
    ///
    /// A modern session returns [`CoreResult::Final`] with a typed
    /// [`FinalCoreResult::ToolsCall`] payload. An exact legacy session returns
    /// [`CoreResult::Legacy`] with its unchanged `tools/call` result shape.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the peer result does not match
    /// the selected era and `tools/call` response contract. A contradictory
    /// core response terminates the connection.
    pub fn call_tool_typed(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<CoreResult> {
        self.ensure_initialized()?;
        let params = CallToolParams {
            name: name.to_string(),
            arguments: Some(arguments),
            meta: None,
        };
        self.send_typed_core_request("tools/call", params)
    }

    /// Calls a final tool with the official Tasks result surface enabled.
    ///
    /// Bilateral empty-settings negotiation is proved from the retained
    /// discovery response before a request ID is allocated. The request then
    /// declares Tasks explicitly and returns the exact complete, task, or
    /// input-required branch without legacy projection.
    pub fn call_tool_final_outcome(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<FinalToolCallOutcome> {
        self.require_modern_final_result_session("tools/call")?;
        let discovery = self.server_discovery().ok_or_else(|| {
            McpError::invalid_params(
                "Modern Tasks requires the retained final server/discover response",
            )
        })?;
        admit_final_tasks_result_discriminator(discovery, OFFICIAL_TASKS_RESULT_DISCRIMINATOR)?;
        let params = CallToolParams {
            name: name.to_owned(),
            arguments: Some(arguments),
            meta: None,
        };
        match self.send_typed_core_request_with_tasks("tools/call", params, true)? {
            CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) => {
                Ok(FinalToolCallOutcome::Complete(result))
            }
            CoreResult::Final(FinalCoreResult::ToolsCallTask { result }) => {
                Ok(FinalToolCallOutcome::Task(result))
            }
            CoreResult::Final(FinalCoreResult::ToolsCallInputRequired { result, .. }) => {
                Ok(FinalToolCallOutcome::InputRequired(result))
            }
            _ => Err(unexpected_convenience_result("tools/call")),
        }
    }

    /// Calls a tool and returns its exact MCP 2026-07-28 result payload.
    ///
    /// Unlike [`Self::call_tool`], this convenience API does not project final
    /// content or `structuredContent` into the legacy result vocabulary.
    ///
    /// # Errors
    ///
    /// Returns an error before request mutation unless the negotiated session
    /// is MCP 2026-07-28. It also returns an error when the request fails or
    /// the peer contradicts the final `tools/call` result contract.
    pub fn call_tool_final(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<FinalCallToolResult> {
        self.require_modern_final_result_session("tools/call")?;
        match self.call_tool_typed(name, arguments)? {
            CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) => Ok(result.payload),
            _ => Err(unexpected_convenience_result("tools/call")),
        }
    }

    /// Calls a tool and returns its exact MCP 2024-11-05 result payload.
    ///
    /// This retains legacy result metadata and all schema-legal open members
    /// without projecting them into the final result vocabulary.
    ///
    /// # Errors
    ///
    /// Returns an error before request mutation unless the negotiated session
    /// is MCP 2024-11-05. It also returns an error when the request fails or
    /// the peer contradicts the legacy `tools/call` result contract.
    pub fn call_tool_legacy(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<CallToolResult> {
        self.require_legacy_exact_result_session("tools/call")?;
        match self.call_tool_typed(name, arguments)? {
            CoreResult::Legacy(LegacyCoreResult::ToolsCall(result)) => Ok(result),
            _ => Err(unexpected_convenience_result("tools/call")),
        }
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
    ) -> McpResult<Vec<LegacyContent>> {
        self.ensure_initialized()?;
        let result = convenience_tool_call(self.call_tool_typed(name, arguments)?)?;

        if result.is_error {
            // Extract error message from content if available
            let error_msg = result
                .content
                .first()
                .and_then(|c| match c {
                    LegacyContent::Text { text, .. } => Some(text.clone()),
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
    ) -> McpResult<Vec<LegacyContent>> {
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

        let result = convenience_tool_call(self.send_typed_core_request_with_progress(
            "tools/call",
            params,
            request_id,
            &progress_marker,
            on_progress,
        )?)?;

        if result.is_error {
            // Extract error message from content if available
            let error_msg = result
                .content
                .first()
                .and_then(|c| match c {
                    LegacyContent::Text { text, .. } => Some(text.clone()),
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
        let core_request = self.prepared_core_request(method, &params_value)?;

        let received = self.send_prepared_request_with_progress(
            method,
            params_value,
            request_id,
            expected_marker,
            on_progress,
        )?;

        if let Some(core_request) = core_request
            && let Err(error) = decode_core_result_from_source(
                &core_request,
                &received.result,
                received.raw_result.as_deref(),
            )
        {
            return Err(self.terminate_connection(error));
        }

        decode_response_payload(received.result)
    }

    /// Sends one supported core request with progress handling and retains its
    /// selected-era result.
    fn send_typed_core_request_with_progress<P: serde::Serialize>(
        &mut self,
        method: &str,
        params: P,
        request_id: u64,
        expected_marker: &ProgressMarker,
        on_progress: ProgressCallback<'_>,
    ) -> McpResult<CoreResult> {
        let timeout_policy = self.timeout_policy;
        timeout_policy.validate()?;
        let params_value = serde_json::to_value(params)
            .map_err(|e| McpError::internal_error(format!("Failed to serialize params: {e}")))?;
        let params_value = self.prepare_request_parameters(params_value)?;
        let core_request = self
            .prepared_core_request(method, &params_value)?
            .ok_or_else(|| {
                McpError::invalid_params(
                    "Method is not a supported core request in the negotiated era",
                )
            })?;
        let params_value = core_request
            .encode_params()
            .map_err(|_| {
                McpError::invalid_params(
                    "Client core request could not be encoded in the negotiated protocol era",
                )
            })?
            .ok_or_else(|| {
                McpError::invalid_params(
                    "Method has no parameter object in the negotiated protocol era",
                )
            })?;
        let received = self.send_prepared_request_with_progress(
            method,
            params_value,
            request_id,
            expected_marker,
            on_progress,
        )?;
        decode_core_result_from_source(
            &core_request,
            &received.result,
            received.raw_result.as_deref(),
        )
        .map_err(|error| self.terminate_connection(error))
    }

    /// Sends an already-prepared request and waits for its response while
    /// routing matching progress notifications.
    fn send_prepared_request_with_progress(
        &mut self,
        method: &str,
        params_value: serde_json::Value,
        request_id: u64,
        expected_marker: &ProgressMarker,
        on_progress: ProgressCallback<'_>,
    ) -> McpResult<ReceivedPreparedResult> {
        let timeout_policy = self.timeout_policy;
        timeout_policy.validate()?;

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
        let ReceivedJsonRpcResponse {
            mut response,
            raw_result,
        } = self.recv_response_with_progress(
            waiter,
            expected_marker,
            on_progress,
            timeout_policy,
            deadlines,
        )?;
        let receipt = Instant::now();

        // Check for error response
        if let Some(error) = response.error.take() {
            return Err(json_rpc_error_to_mcp(error));
        }

        // Parse result
        let result = response
            .result
            .take()
            .ok_or_else(|| McpError::internal_error("No result in response"))?;

        Ok(ReceivedPreparedResult {
            result,
            raw_result,
            receipt,
        })
    }

    /// Receives a response from the transport, handling progress notifications.
    fn recv_response_with_progress(
        &mut self,
        mut waiter: ResponseWaiter,
        expected_marker: &ProgressMarker,
        on_progress: ProgressCallback<'_>,
        timeout_policy: RequestTimeoutPolicy,
        mut deadlines: RequestDeadlines,
    ) -> McpResult<ReceivedJsonRpcResponse> {
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
                    let route = self
                        .route_last_received_response(response)
                        .map_err(|error| self.terminate_connection(error))?;
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
                    match self.retain_modern_server_notification(&request) {
                        Ok(Some(ModernServerNotification::Progress(progress))) => {
                            if progress.progress.is_finite()
                                && progress.total.is_none_or(f64::is_finite)
                                && last_progress.is_none_or(|last| progress.progress > last)
                                && progress.progress_token == *expected_marker
                            {
                                if invoke_tool_progress_callback(
                                    &mut *on_progress,
                                    progress.progress,
                                    progress.total,
                                    progress.message.as_deref(),
                                )
                                .is_err()
                                {
                                    let error =
                                        McpError::internal_error(PROGRESS_CALLBACK_PANIC_ERROR);
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
                            continue;
                        }
                        Ok(Some(_)) => continue,
                        Ok(None) => {}
                        Err(error) => return Err(self.terminate_connection(error)),
                    }
                    if let Some(response) = self.server_request_response(&request) {
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

    /// Lists one page of resources and returns its negotiated core result.
    ///
    /// The caller supplies the opaque peer cursor, if any. A modern session
    /// returns [`CoreResult::Final`] with [`FinalCoreResult::ResourcesList`];
    /// an exact legacy session returns [`CoreResult::Legacy`].
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or its selected-era result
    /// contract is contradicted. A contradictory core result terminates the
    /// connection.
    pub fn list_resources_typed(&mut self, cursor: Option<&str>) -> McpResult<CoreResult> {
        self.ensure_initialized()?;
        let cursor = cursor.map(ToOwned::to_owned);
        let params = ListResourcesParams {
            cursor: cursor.clone(),
            ..ListResourcesParams::default()
        };
        self.cached_final_core_request(
            "resources/list",
            serde_json::json!({}),
            cursor.as_deref(),
            FinalCacheResultSet::Resources,
            move |client| client.send_typed_core_request("resources/list", params),
        )
    }

    /// Lists available resources.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
        self.ensure_initialized()?;
        let mut restarts = 0;
        'rebuild: loop {
            let mut all = Vec::new();
            let mut cursor: Option<String> = None;
            let mut budget = PaginationBudget::new();
            let mut baseline = None;

            loop {
                budget.begin_page()?;
                let (resources, next_cursor) =
                    convenience_resources_page(self.list_resources_typed(cursor.as_deref())?)?;
                if self.final_list_restart_needed(&FinalCacheResultSet::Resources, &mut baseline) {
                    restarts += 1;
                    if restarts > 1 {
                        return Err(McpError::invalid_request(
                            FINAL_CACHE_LIST_RESTART_LIMIT_ERROR,
                        ));
                    }
                    continue 'rebuild;
                }
                budget.account_page(&resources)?;
                all.extend(resources);
                cursor = budget.admit_next_cursor(next_cursor)?;
                if cursor.is_none() {
                    return Ok(all);
                }
            }
        }
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
        let (resources, next_cursor) =
            convenience_resources_page(self.list_resources_typed(cursor_parameter.as_deref())?)?;
        bounded_list_page(resources, cursor, next_cursor, limits)
    }

    /// Lists one page of resource templates and returns its negotiated core
    /// result.
    ///
    /// The caller supplies the opaque peer cursor, if any. A modern session
    /// returns [`CoreResult::Final`] with
    /// [`FinalCoreResult::ResourceTemplatesList`]; an exact legacy session
    /// returns [`CoreResult::Legacy`].
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or its selected-era result
    /// contract is contradicted. A contradictory core result terminates the
    /// connection.
    pub fn list_resource_templates_typed(&mut self, cursor: Option<&str>) -> McpResult<CoreResult> {
        self.ensure_initialized()?;
        let cursor = cursor.map(ToOwned::to_owned);
        let params = ListResourceTemplatesParams {
            cursor: cursor.clone(),
            ..ListResourceTemplatesParams::default()
        };
        self.cached_final_core_request(
            "resources/templates/list",
            serde_json::json!({}),
            cursor.as_deref(),
            FinalCacheResultSet::ResourceTemplates,
            move |client| client.send_typed_core_request("resources/templates/list", params),
        )
    }

    /// Lists available resource templates.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
        self.ensure_initialized()?;
        let mut restarts = 0;
        'rebuild: loop {
            let mut all = Vec::new();
            let mut cursor: Option<String> = None;
            let mut budget = PaginationBudget::new();
            let mut baseline = None;

            loop {
                budget.begin_page()?;
                let (resource_templates, next_cursor) = convenience_resource_templates_page(
                    self.list_resource_templates_typed(cursor.as_deref())?,
                )?;
                if self.final_list_restart_needed(
                    &FinalCacheResultSet::ResourceTemplates,
                    &mut baseline,
                ) {
                    restarts += 1;
                    if restarts > 1 {
                        return Err(McpError::invalid_request(
                            FINAL_CACHE_LIST_RESTART_LIMIT_ERROR,
                        ));
                    }
                    continue 'rebuild;
                }
                budget.account_page(&resource_templates)?;
                all.extend(resource_templates);
                cursor = budget.admit_next_cursor(next_cursor)?;
                if cursor.is_none() {
                    return Ok(all);
                }
            }
        }
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
        let (resource_templates, next_cursor) = convenience_resource_templates_page(
            self.list_resource_templates_typed(cursor_parameter.as_deref())?,
        )?;
        bounded_list_page(resource_templates, cursor, next_cursor, limits)
    }

    /// Configures the selected protocol era's log level behavior.
    ///
    /// A modern MCP 2026-07-28 session stores the complete RFC 5424 level and
    /// adds it as `io.modelcontextprotocol/logLevel` metadata to every later
    /// request. It never sends `logging/setLevel`. An exact 2024-11-05 session
    /// sends the historical RPC and rejects final-only severities before any
    /// bytes are committed.
    ///
    /// # Errors
    ///
    /// Returns an error if an exact legacy peer cannot represent the selected
    /// level or rejects its historical acknowledgement.
    pub fn set_log_level_typed(&mut self, level: LoggingLevel) -> McpResult<()> {
        self.ensure_initialized()?;
        match self.session.selected_era() {
            Some(ProtocolEra::Modern2026) => {
                self.final_log_level = Some(level);
                Ok(())
            }
            Some(ProtocolEra::Legacy2024) => {
                let level = legacy_log_level(level)?;
                let params = SetLogLevelParams { level };
                let _: serde_json::Value = self.send_request("logging/setLevel", params)?;
                Ok(())
            }
            None => Err(McpError::internal_error(
                "Client has no negotiated protocol era for logging configuration",
            )),
        }
    }

    /// Configures one of the severities shared by both protocol eras.
    ///
    /// Modern sessions use later request metadata; exact legacy sessions send
    /// `logging/setLevel` unchanged.
    pub fn set_log_level(&mut self, level: LogLevel) -> McpResult<()> {
        self.set_log_level_typed(final_log_level(level))
    }

    /// Reads a resource and returns its negotiated, method-aware core result.
    ///
    /// A modern session returns [`CoreResult::Final`] with
    /// [`FinalCoreResult::ResourcesRead`]. An exact legacy session returns
    /// [`CoreResult::Legacy`] with its unchanged resource result shape.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or its selected-era result
    /// contract is contradicted. A contradictory core result terminates the
    /// connection.
    pub fn read_resource_typed(&mut self, uri: &str) -> McpResult<CoreResult> {
        self.ensure_initialized()?;
        let uri = uri.to_owned();
        let params = ReadResourceParams {
            uri: uri.clone(),
            meta: None,
        };
        self.cached_final_core_request(
            "resources/read",
            serde_json::json!({"uri": uri}),
            None,
            FinalCacheResultSet::Resource(params.uri.clone()),
            move |client| client.send_typed_core_request("resources/read", params),
        )
    }

    /// Reads a resource and returns its exact MCP 2026-07-28 result payload.
    ///
    /// This retains final cache directives and resource open fields without a
    /// projection into [`LegacyResourceContent`].
    ///
    /// # Errors
    ///
    /// Returns an error before request mutation unless the negotiated session
    /// is MCP 2026-07-28. It also returns an error when the request fails or
    /// the peer contradicts the final `resources/read` result contract.
    pub fn read_resource_final(&mut self, uri: &str) -> McpResult<FinalReadResourceResult> {
        self.require_modern_final_result_session("resources/read")?;
        match self.read_resource_typed(uri)? {
            CoreResult::Final(FinalCoreResult::ResourcesRead { result, .. }) => Ok(result.payload),
            _ => Err(unexpected_convenience_result("resources/read")),
        }
    }

    /// Reads a resource and returns its exact MCP 2024-11-05 result payload.
    ///
    /// This retains legacy result metadata and all schema-legal open members
    /// without projection into the final resource result vocabulary.
    ///
    /// # Errors
    ///
    /// Returns an error before request mutation unless the negotiated session
    /// is MCP 2024-11-05. It also returns an error when the request fails or
    /// the peer contradicts the legacy `resources/read` result contract.
    pub fn read_resource_legacy(&mut self, uri: &str) -> McpResult<ReadResourceResult> {
        self.require_legacy_exact_result_session("resources/read")?;
        match self.read_resource_typed(uri)? {
            CoreResult::Legacy(LegacyCoreResult::ResourcesRead(result)) => Ok(result),
            _ => Err(unexpected_convenience_result("resources/read")),
        }
    }

    /// Reads a resource by URI.
    ///
    /// # Errors
    ///
    /// Returns an error if the resource cannot be read.
    pub fn read_resource(&mut self, uri: &str) -> McpResult<Vec<LegacyResourceContent>> {
        self.ensure_initialized()?;
        convenience_resource_read(self.read_resource_typed(uri)?)
    }

    /// Lists one page of prompts and returns its negotiated core result.
    ///
    /// The caller supplies the opaque peer cursor, if any. A modern session
    /// returns [`CoreResult::Final`] with [`FinalCoreResult::PromptsList`]; an
    /// exact legacy session returns [`CoreResult::Legacy`].
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or its selected-era result
    /// contract is contradicted. A contradictory core result terminates the
    /// connection.
    pub fn list_prompts_typed(&mut self, cursor: Option<&str>) -> McpResult<CoreResult> {
        self.ensure_initialized()?;
        let cursor = cursor.map(ToOwned::to_owned);
        let params = ListPromptsParams {
            cursor: cursor.clone(),
            ..ListPromptsParams::default()
        };
        self.cached_final_core_request(
            "prompts/list",
            serde_json::json!({}),
            cursor.as_deref(),
            FinalCacheResultSet::Prompts,
            move |client| client.send_typed_core_request("prompts/list", params),
        )
    }

    /// Lists available prompts.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails.
    pub fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
        self.ensure_initialized()?;
        let mut restarts = 0;
        'rebuild: loop {
            let mut all = Vec::new();
            let mut cursor: Option<String> = None;
            let mut budget = PaginationBudget::new();
            let mut baseline = None;

            loop {
                budget.begin_page()?;
                let (prompts, next_cursor) =
                    convenience_prompts_page(self.list_prompts_typed(cursor.as_deref())?)?;
                if self.final_list_restart_needed(&FinalCacheResultSet::Prompts, &mut baseline) {
                    restarts += 1;
                    if restarts > 1 {
                        return Err(McpError::invalid_request(
                            FINAL_CACHE_LIST_RESTART_LIMIT_ERROR,
                        ));
                    }
                    continue 'rebuild;
                }
                budget.account_page(&prompts)?;
                all.extend(prompts);
                cursor = budget.admit_next_cursor(next_cursor)?;
                if cursor.is_none() {
                    return Ok(all);
                }
            }
        }
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
        let (prompts, next_cursor) =
            convenience_prompts_page(self.list_prompts_typed(cursor_parameter.as_deref())?)?;
        bounded_list_page(prompts, cursor, next_cursor, limits)
    }

    /// Gets a prompt and returns its negotiated, method-aware core result.
    ///
    /// A modern session returns [`CoreResult::Final`] with
    /// [`FinalCoreResult::PromptsGet`]. An exact legacy session returns
    /// [`CoreResult::Legacy`] with its unchanged prompt result shape.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or its selected-era result
    /// contract is contradicted. A contradictory core result terminates the
    /// connection.
    pub fn get_prompt_typed(
        &mut self,
        name: &str,
        arguments: std::collections::HashMap<String, String>,
    ) -> McpResult<CoreResult> {
        self.ensure_initialized()?;
        let params = GetPromptParams {
            name: name.to_owned(),
            arguments: (!arguments.is_empty()).then_some(arguments),
            meta: None,
        };
        self.send_typed_core_request("prompts/get", params)
    }

    /// Gets a prompt and returns its exact MCP 2026-07-28 result payload.
    ///
    /// This retains the final prompt description, final content vocabulary,
    /// and open fields without a projection into [`LegacyPromptMessage`].
    ///
    /// # Errors
    ///
    /// Returns an error before request mutation unless the negotiated session
    /// is MCP 2026-07-28. It also returns an error when the request fails or
    /// the peer contradicts the final `prompts/get` result contract.
    pub fn get_prompt_final(
        &mut self,
        name: &str,
        arguments: std::collections::HashMap<String, String>,
    ) -> McpResult<FinalGetPromptResult> {
        self.require_modern_final_result_session("prompts/get")?;
        match self.get_prompt_typed(name, arguments)? {
            CoreResult::Final(FinalCoreResult::PromptsGet { result, .. }) => Ok(result.payload),
            _ => Err(unexpected_convenience_result("prompts/get")),
        }
    }

    /// Gets a prompt and returns its exact MCP 2024-11-05 result payload.
    ///
    /// This retains legacy descriptions, result metadata, and all
    /// schema-legal open members without projection into the final prompt
    /// result vocabulary.
    ///
    /// # Errors
    ///
    /// Returns an error before request mutation unless the negotiated session
    /// is MCP 2024-11-05. It also returns an error when the request fails or
    /// the peer contradicts the legacy `prompts/get` result contract.
    pub fn get_prompt_legacy(
        &mut self,
        name: &str,
        arguments: std::collections::HashMap<String, String>,
    ) -> McpResult<GetPromptResult> {
        self.require_legacy_exact_result_session("prompts/get")?;
        match self.get_prompt_typed(name, arguments)? {
            CoreResult::Legacy(LegacyCoreResult::PromptsGet(result)) => Ok(result),
            _ => Err(unexpected_convenience_result("prompts/get")),
        }
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
    ) -> McpResult<Vec<LegacyPromptMessage>> {
        self.ensure_initialized()?;
        convenience_prompt_get(self.get_prompt_typed(name, arguments)?)
    }

    /// Completes one prompt or resource-template argument in the selected era.
    ///
    /// Modern sessions send the full [`CompletionParams`] context plus final
    /// request metadata and return [`CoreResult::Final`] with
    /// [`FinalCoreResult::Completion`]. Exact legacy sessions losslessly map
    /// only title-free, context-free inputs and return [`CoreResult::Legacy`].
    ///
    /// # Errors
    ///
    /// Returns an error if a legacy session cannot represent the requested
    /// completion input, if the request fails, or if its result violates the
    /// method-aware contract of the negotiated era. A contradictory peer
    /// result terminates the connection.
    pub fn complete(&mut self, params: CompletionParams) -> McpResult<CoreResult> {
        self.ensure_initialized()?;
        match self.session.selected_era() {
            Some(ProtocolEra::Modern2026) => {
                self.send_typed_core_request("completion/complete", params)
            }
            Some(ProtocolEra::Legacy2024) => {
                self.send_typed_core_request("completion/complete", params.into_legacy()?)
            }
            None => Err(McpError::internal_error(
                "Client has no negotiated protocol era for completion",
            )),
        }
    }

    /// Collects one final typed subscription listener until its terminal result.
    ///
    /// The acknowledgement must bind its subscription ID to this listen
    /// request and may accept only a subset of `notifications`. The collector
    /// retains only acknowledged catalog/resource events, then returns the
    /// exact terminal [`CompleteResult`]. Exact 2024-11-05 has no equivalent
    /// listener contract and is rejected before a request ID is allocated or
    /// bytes are written.
    pub fn listen_subscriptions_typed(
        &mut self,
        notifications: SubscriptionFilter,
    ) -> McpResult<SubscriptionListenCollector> {
        self.ensure_initialized()?;
        if self.session.selected_era() != Some(ProtocolEra::Modern2026) {
            return Err(McpError::invalid_params(
                "subscriptions/listen is available only for MCP 2026-07-28",
            ));
        }
        let timeout_policy = self.timeout_policy;
        timeout_policy.validate()?;
        let requested = notifications;
        let tasks_requested = task_subscription_ids(&requested)
            .map_err(|_| McpError::invalid_params("invalid Tasks subscription filter"))?
            .is_some();
        if tasks_requested {
            self.admit_final_tasks_direction(
                TASK_STATUS_NOTIFICATION,
                ExtensionDirection::ServerToClient,
            )?;
        }
        let params_value = serde_json::to_value(serde_json::json!({
            "notifications": requested.clone(),
        }))
        .map_err(|error| {
            McpError::internal_error(format!(
                "Failed to serialize subscriptions/listen parameters: {error}"
            ))
        })?;
        let params_value = if tasks_requested {
            self.with_final_tasks_client_capability(params_value)?
        } else {
            self.prepare_request_parameters(params_value)?
        };
        let core_request = self
            .prepared_core_request("subscriptions/listen", &params_value)?
            .ok_or_else(|| {
                McpError::invalid_params(
                    "subscriptions/listen is not a supported core request in the negotiated era",
                )
            })?;
        let params_value = core_request
            .encode_params()
            .map_err(|_| {
                McpError::invalid_params(
                    "subscriptions/listen could not be encoded in the negotiated protocol era",
                )
            })?
            .ok_or_else(|| {
                McpError::invalid_params(
                    "subscriptions/listen requires a parameter object in the negotiated protocol era",
                )
            })?;

        let id = self.next_request_id()?;
        let id_i64 = i64::try_from(id).expect("request ID allocator enforces the i64 bound");
        let request_id = RequestId::Number(id_i64);
        let request = JsonRpcRequest::new("subscriptions/listen", Some(params_value), id_i64);
        let waiter = self.responses.register(request_id.clone())?;
        if let Err(error) = self
            .transport
            .send(&self.cx, &JsonRpcMessage::Request(request))
        {
            return Err(self.record_send_failure(Some(&request_id), error));
        }
        let committed_at = Instant::now();
        let deadlines = match RequestDeadlines::start_at(timeout_policy, committed_at) {
            Ok(deadlines) => deadlines,
            Err(error) => return Err(self.finish_committed_request_locally(&request_id, error)),
        };
        self.recv_subscription_listener(waiter, &core_request, &requested, deadlines)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Final Tasks extension
    // ═══════════════════════════════════════════════════════════════════════

    /// Reads one task through the negotiated official Tasks extension.
    ///
    /// Exact MCP 2024-11-05 excludes extensions, so this rejects before a
    /// request ID is allocated or any task bytes are written. Modern callers
    /// must have a bilateral `io.modelcontextprotocol/tasks` declaration with
    /// exactly empty settings in the retained discovery response.
    pub fn get_task_final(&mut self, task_id: FinalTaskId) -> McpResult<FinalGetTaskResult> {
        self.admit_final_tasks_method(TASK_GET)?;
        let params = FinalGetTaskParams {
            request: self.final_task_request_meta()?,
            task_id: task_id.clone(),
        };
        let result: FinalGetTaskResult = self.send_final_task_request(TASK_GET, params)?;
        if result.task.base().task_id != task_id {
            return Err(self.terminate_connection(McpError::invalid_request(
                "tasks/get response taskId does not match the requested final task",
            )));
        }
        Ok(result)
    }

    /// Supplies responses for the exact input requests retained by a final
    /// `input_required` task.
    ///
    /// Passing the returned [`FinalTask`] retains the task identifier and
    /// request ledger as one correlated unit. The client rejects a non-input
    /// task or a response key/kind contradiction before sending `tasks/update`.
    pub fn update_task_final(
        &mut self,
        task: &FinalTask,
        input_responses: FinalTaskInputResponses,
    ) -> McpResult<FinalUpdateTaskResult> {
        self.admit_final_tasks_method(TASK_UPDATE)?;
        let FinalTask::InputRequired {
            base,
            input_requests,
        } = task
        else {
            return Err(McpError::invalid_params(
                "tasks/update requires an input_required final task",
            ));
        };
        let ledger = TaskInputLedger::from_requests(input_requests).map_err(|_| {
            McpError::invalid_params("Final task input requests are not an admitted ledger")
        })?;
        ledger.validate_responses(&input_responses).map_err(|_| {
            McpError::invalid_params(
                "tasks/update inputResponses do not match the retained task input requests",
            )
        })?;
        let params = FinalUpdateTaskParams {
            request: self.final_task_request_meta()?,
            task_id: base.task_id.clone(),
            input_responses,
        };
        self.send_final_task_request(TASK_UPDATE, params)
    }

    /// Requests cancellation through the negotiated official Tasks extension.
    ///
    /// The exact final acknowledgement is intentionally empty; unlike the
    /// stale custom task API, it must not invent a projected task snapshot.
    pub fn cancel_task_final(&mut self, task_id: FinalTaskId) -> McpResult<FinalCancelTaskResult> {
        self.admit_final_tasks_method(TASK_CANCEL)?;
        let params = FinalCancelTaskParams {
            request: self.final_task_request_meta()?,
            task_id,
        };
        self.send_final_task_request(TASK_CANCEL, params)
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
    #[cfg(unix)]
    use std::io::{Read as _, Write as _};
    #[cfg(unix)]
    use std::net::{TcpListener, TcpStream};
    use std::process::{Command, Stdio};

    #[cfg(unix)]
    use asupersync::runtime::RuntimeBuilder;

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

    #[cfg(unix)]
    fn http_test_runtime_block_on<F: std::future::Future>(future: F) -> F::Output {
        RuntimeBuilder::current_thread()
            .build()
            .expect("HTTP cache test runtime must build")
            .block_on(future)
    }

    #[cfg(unix)]
    fn read_http_cache_test_request(stream: &mut TcpStream) -> serde_json::Value {
        let mut wire = Vec::new();
        let mut buffer = [0_u8; 4_096];
        let head_end = loop {
            let read = stream
                .read(&mut buffer)
                .expect("read HTTP cache test request");
            assert!(read > 0, "client closed before a complete HTTP request");
            wire.extend_from_slice(&buffer[..read]);
            if let Some(position) = wire.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let head = std::str::from_utf8(&wire[..head_end]).expect("HTTP request head is UTF-8");
        let content_length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length").then(|| {
                    value
                        .trim()
                        .parse::<usize>()
                        .expect("content length is numeric")
                })
            })
            .expect("HTTP cache request has a content length");
        while wire.len() < head_end + content_length {
            let read = stream
                .read(&mut buffer)
                .expect("read HTTP cache request body");
            assert!(read > 0, "client closed before the complete HTTP body");
            wire.extend_from_slice(&buffer[..read]);
        }
        serde_json::from_slice(&wire[head_end..head_end + content_length])
            .expect("HTTP cache request is JSON-RPC")
    }

    #[cfg(unix)]
    fn write_http_cache_test_response(stream: &mut TcpStream, content_type: &str, body: &[u8]) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("write HTTP cache response head");
        stream
            .write_all(body)
            .expect("write HTTP cache response body");
        stream.flush().expect("flush HTTP cache response");
    }

    #[cfg(unix)]
    fn http_cache_test_plan(modern_target: &str) -> ClientProtocolPlan {
        ClientProtocolPlan::http(
            ProtocolPolicy::ModernOnly,
            Some(
                CanonicalHttpUrl::parse(modern_target)
                    .expect("local HTTP cache target is canonical"),
            ),
            None,
            None,
            "http-cache-test-credential".to_owned(),
            "http-cache-test-security".to_owned(),
            "http-cache-test-transport".to_owned(),
            1,
            1,
            0,
        )
        .expect("modern-only HTTP cache plan is complete")
    }

    #[cfg(unix)]
    fn http_tools_list_response(id: i64, tool_name: &str, ttl_ms: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "resultType": "complete",
                "tools": [{
                    "name": tool_name,
                    "inputSchema": {"type": "object"}
                }],
                "ttlMs": ttl_ms,
                "cacheScope": "private"
            }
        }))
        .expect("HTTP cache tools/list response serializes")
    }

    #[cfg(unix)]
    fn assert_http_subscription_cache_invalidation(acknowledges_tools_list_changes: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP cache listener");
        let address = listener
            .local_addr()
            .expect("read HTTP cache listener address");
        let modern_target = format!("http://{address}/mcp");
        let discovery = modern_discovery_response(
            "http-subscription-cache-modern-server",
            &[MODERN_PROTOCOL_VERSION],
        );
        let initial = http_tools_list_response(2, "cached", 1_000);
        let refreshed = http_tools_list_response(4, "refreshed", 1_000);
        let server = std::thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept HTTP discovery");
            let probe_request = read_http_cache_test_request(&mut probe);
            assert_eq!(probe_request["id"], 1);
            assert_eq!(probe_request["method"], "server/discover");
            write_http_cache_test_response(&mut probe, "application/json", discovery.as_bytes());

            let (mut first_list, _) = listener.accept().expect("accept initial tools/list");
            let first_list_request = read_http_cache_test_request(&mut first_list);
            assert_eq!(first_list_request["id"], 2);
            assert_eq!(first_list_request["method"], "tools/list");
            write_http_cache_test_response(&mut first_list, "application/json", &initial);

            let (mut listen, _) = listener.accept().expect("accept subscriptions/listen");
            let listen_request = read_http_cache_test_request(&mut listen);
            assert_eq!(listen_request["id"], 3);
            assert_eq!(listen_request["method"], "subscriptions/listen");
            assert_eq!(
                listen_request["params"]["notifications"]["toolsListChanged"],
                true
            );
            let acknowledgement_filter = if acknowledges_tools_list_changes {
                r#"{"toolsListChanged":true}"#
            } else {
                // This differs only by the accepted tools-list change field.
                r#"{}"#
            };
            let terminal = r#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":3}}}"#;
            let sse = format!(
                "data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/subscriptions/acknowledged\",\"params\":{{\"_meta\":{{\"io.modelcontextprotocol/subscriptionId\":3}},\"notifications\":{acknowledgement_filter}}}}}\n\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}}\n\n{}",
                acknowledges_tools_list_changes
                    .then_some(format!("data: {terminal}\n\n"))
                    .unwrap_or_default(),
            );
            write_http_cache_test_response(&mut listen, "text/event-stream", sse.as_bytes());

            if acknowledges_tools_list_changes {
                let (mut second_list, _) = listener
                    .accept()
                    .expect("accepted change forces a second tools/list");
                let second_list_request = read_http_cache_test_request(&mut second_list);
                assert_eq!(second_list_request["id"], 4);
                assert_eq!(second_list_request["method"], "tools/list");
                write_http_cache_test_response(&mut second_list, "application/json", &refreshed);
            }
        });

        let cx = Cx::for_request();
        let mut client = http_test_runtime_block_on(HttpClient::connect(
            &cx,
            http_cache_test_plan(&modern_target),
            ClientInfo {
                name: "http-cache-test-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("public HTTP client completes discovery");
        let initial_result = http_test_runtime_block_on(client.request_final_core(
            &cx,
            "tools/list",
            serde_json::json!({}),
        ))
        .expect("initial public HTTP tools/list fills the cache");
        assert!(
            initial_result
                .encode()
                .expect("initial typed result re-encodes")
                .contains("cached")
        );

        let collected = http_test_runtime_block_on(client.listen_subscriptions_typed(
            &cx,
            SubscriptionFilter {
                tools_list_changed: Some(true),
                ..SubscriptionFilter::default()
            },
            sse::SseLimits::new(1_024, 8_192, 16).expect("explicit SSE bounds are nonzero"),
        ));
        if acknowledges_tools_list_changes {
            let collector = collected.expect("accepted HTTP change event is returned");
            assert!(matches!(
                collector.notifications.as_slice(),
                [ServerNotification::ToolsListChanged(None)]
            ));
            let refreshed_result = http_test_runtime_block_on(client.request_final_core(
                &cx,
                "tools/list",
                serde_json::json!({}),
            ))
            .expect("accepted change invalidates the public HTTP cache before the next hit");
            assert!(
                refreshed_result
                    .encode()
                    .expect("refreshed typed result re-encodes")
                    .contains("refreshed")
            );
            assert_eq!(client.final_result_cache_stats().hits, 0);
            assert_eq!(client.final_result_cache_stats().fills, 2);
            assert_eq!(client.final_result_cache_stats().invalidations, 1);
        } else {
            let error = collected.expect_err("one omitted accepted-filter field rejects the event");
            assert!(matches!(
                error,
                HttpClientError::Connection(ClientHttpConnectionError::SubscriptionsListen(
                    http_executor::ModernHttpSubscriptionListenError::EventOutsideAcceptedFilter
                ))
            ));
            let cached_result = http_test_runtime_block_on(client.request_final_core(
                &cx,
                "tools/list",
                serde_json::json!({}),
            ))
            .expect("rejected change leaves the public HTTP cache unchanged");
            assert!(
                cached_result
                    .encode()
                    .expect("cached typed result re-encodes")
                    .contains("cached")
            );
            assert_eq!(client.final_result_cache_stats().hits, 1);
            assert_eq!(client.final_result_cache_stats().fills, 1);
            assert_eq!(client.final_result_cache_stats().invalidations, 0);
        }
        server
            .join()
            .expect("HTTP subscription cache server must join");
    }

    #[cfg(unix)]
    #[test]
    fn cache_03_public_http_subscription_change_invalidates_the_connection_cache() {
        assert_http_subscription_cache_invalidation(true);
    }

    #[cfg(unix)]
    #[test]
    fn cache_03_public_http_subscription_rejects_one_unacknowledged_change_field() {
        assert_http_subscription_cache_invalidation(false);
    }

    #[cfg(unix)]
    #[test]
    fn cache_03_http_ttl_receipt_survives_later_result_routing() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP receipt listener");
        let address = listener
            .local_addr()
            .expect("read HTTP receipt listener address");
        let modern_target = format!("http://{address}/mcp");
        let discovery =
            modern_discovery_response("http-ttl-receipt-modern-server", &[MODERN_PROTOCOL_VERSION]);
        let list_response = http_tools_list_response(2, "receipt", 1);
        let server = std::thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept HTTP receipt discovery");
            let probe_request = read_http_cache_test_request(&mut probe);
            assert_eq!(probe_request["id"], 1);
            assert_eq!(probe_request["method"], "server/discover");
            write_http_cache_test_response(&mut probe, "application/json", discovery.as_bytes());

            let (mut list, _) = listener.accept().expect("accept HTTP receipt tools/list");
            let list_request = read_http_cache_test_request(&mut list);
            assert_eq!(list_request["id"], 2);
            assert_eq!(list_request["method"], "tools/list");
            write_http_cache_test_response(&mut list, "application/json", &list_response);
        });

        let cx = Cx::for_request();
        let mut connection = http_test_runtime_block_on(ClientHttpConnection::connect(
            &cx,
            http_cache_test_plan(&modern_target),
            ClientInfo {
                name: "http-ttl-receipt-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("public HTTP connection completes discovery");
        let (response, result_source, receipt) =
            http_test_runtime_block_on(connection.request_json_with_result_source_at(
                &cx,
                "tools/list",
                serde_json::json!({}),
                RequestId::Number(2),
                4_096,
            ))
            .expect("HTTP response retains its transport decode receipt");
        server.join().expect("HTTP receipt server must join");

        // This is deliberately after receipt capture: it represents result
        // routing work that must not extend a one-millisecond peer TTL.
        std::thread::sleep(Duration::from_millis(2));
        let core_parameters = serde_json::json!({
            "_meta": FinalRequestMeta::new(ClientCapabilities::default())
        });
        let core_request = CoreRequest::decode(
            ProtocolEra::Modern2026,
            "tools/list",
            Some(&core_parameters),
        )
        .expect("modern tools/list request admits its final metadata");
        let (result, diagnostic) = decode_core_result_with_cache_ttl_from_source(
            &core_request,
            response
                .result
                .as_ref()
                .expect("HTTP response has a result"),
            result_source.as_deref(),
        )
        .expect("later typed-result routing succeeds");
        assert!(diagnostic.is_none());

        let key = FinalCacheKey::new(
            "http-ttl-receipt-test",
            MODERN_PROTOCOL_VERSION,
            "{}",
            "{}",
            "tools/list",
            "{}",
            None,
            1,
            1,
            1,
            1,
            CachePartitionKey::new("http-ttl-receipt-test"),
            FinalCacheResultSet::Tools,
        );
        let mut cache = FinalResultCache::default();
        let generation = cache.begin_fetch(key.result_set());
        assert_eq!(
            cache.insert_if_current_at(key.clone(), generation, result, receipt),
            FinalCacheInsert::Stored
        );
        assert!(matches!(
            cache.lookup_at(&key, Instant::now()),
            FinalCacheLookup::Miss(FinalCacheMiss::Stale)
        ));
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
        let session = ClientSession::try_new(
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
        )
        .expect("test client uses the exact supported protocol version");

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
        let session = ClientSession::try_new(
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
        )
        .expect("test client uses the exact supported protocol version");
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
    fn clt_reverse_request_handlers_positive() {
        let script = "IFS= read -r request; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":41,\"params\":{\"messages\":[],\"maxTokens\":9}}\\n'; \
            IFS= read -r sampling; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"roots/list\",\"id\":42}\\n'; \
            IFS= read -r roots; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"elicitation/create\",\"id\":43,\"params\":{\"mode\":\"form\",\"message\":\"approval\",\"requestedSchema\":{\"type\":\"object\",\"properties\":{}}}}\\n'; \
            IFS= read -r elicitation; \
            case \"$sampling\" in *'\"model\":\"handler-model\"'*'\"id\":41'*) sampling_ok=true;; *) sampling_ok=false;; esac; \
            case \"$roots\" in *'file:///workspace'*'\"id\":42'*) roots_ok=true;; *) roots_ok=false;; esac; \
            case \"$elicitation\" in *'\"action\":\"decline\"'*'\"id\":43'*) elicitation_ok=true;; *) elicitation_ok=false;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"sampling\":%s,\"roots\":%s,\"elicitation\":%s}}\\n' \
            \"$sampling_ok\" \"$roots_ok\" \"$elicitation_ok\"; exec sleep 2";
        let mut client = make_shell_scripted_initialized_client(script, Duration::from_secs(2));
        let sampling_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let roots_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let elicitation_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let handlers = ReverseRequestHandlers::new()
            .with_sampling_create_message({
                let sampling_calls = std::sync::Arc::clone(&sampling_calls);
                move |params| {
                    sampling_calls.fetch_add(1, Ordering::Relaxed);
                    assert_eq!(params.max_tokens, 9);
                    Ok(CreateMessageResult::text("handled", "handler-model"))
                }
            })
            .with_roots_list({
                let roots_calls = std::sync::Arc::clone(&roots_calls);
                move |_params| {
                    roots_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(ListRootsResult::new(vec![fastmcp_protocol::Root::new(
                        "file:///workspace",
                    )]))
                }
            })
            .with_elicitation_create({
                let elicitation_calls = std::sync::Arc::clone(&elicitation_calls);
                move |params| {
                    elicitation_calls.fetch_add(1, Ordering::Relaxed);
                    assert_eq!(params.message(), "approval");
                    Ok(ElicitResult::decline())
                }
            });
        client.set_reverse_request_handlers(handlers);

        let result: serde_json::Value = client
            .send_request("test/reverse-handlers", serde_json::json!({}))
            .expect("configured reverse handlers must answer live server requests");

        assert_eq!(
            result,
            serde_json::json!({"sampling": true, "roots": true, "elicitation": true})
        );
        assert_eq!(sampling_calls.load(Ordering::Relaxed), 1);
        assert_eq!(roots_calls.load(Ordering::Relaxed), 1);
        assert_eq!(elicitation_calls.load(Ordering::Relaxed), 1);
        assert!(client.is_initialized());
        assert!(!client.transport.is_closed());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_reverse_request_handlers_missing_handler_preserves_state() {
        let script = "IFS= read -r request; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":41,\"params\":{\"messages\":[],\"maxTokens\":9}}\\n'; \
            IFS= read -r sampling; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"roots/list\",\"id\":42}\\n'; \
            IFS= read -r roots; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"elicitation/create\",\"id\":43,\"params\":{\"mode\":\"form\",\"message\":\"approval\",\"requestedSchema\":{\"type\":\"object\",\"properties\":{}}}}\\n'; \
            IFS= read -r elicitation; \
            case \"$sampling\" in *'\"model\":\"handler-model\"'*'\"id\":41'*) sampling_ok=true;; *) sampling_ok=false;; esac; \
            case \"$roots\" in *'\"code\":-32601'*'\"id\":42'*) roots_missing=true;; *) roots_missing=false;; esac; \
            case \"$elicitation\" in *'\"action\":\"decline\"'*'\"id\":43'*) elicitation_ok=true;; *) elicitation_ok=false;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"sampling\":%s,\"rootsMissing\":%s,\"elicitation\":%s}}\\n' \
            \"$sampling_ok\" \"$roots_missing\" \"$elicitation_ok\"; exec sleep 2";
        let mut client = make_shell_scripted_initialized_client(script, Duration::from_secs(2));
        let sampling_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let roots_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let elicitation_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let handlers = ReverseRequestHandlers::new()
            .with_sampling_create_message({
                let sampling_calls = std::sync::Arc::clone(&sampling_calls);
                move |_params| {
                    sampling_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(CreateMessageResult::text("handled", "handler-model"))
                }
            })
            .with_elicitation_create({
                let elicitation_calls = std::sync::Arc::clone(&elicitation_calls);
                move |_params| {
                    elicitation_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(ElicitResult::decline())
                }
            });
        client.set_reverse_request_handlers(handlers);

        let result: serde_json::Value = client
            .send_request("test/reverse-handlers", serde_json::json!({}))
            .expect("a missing reverse handler must not disturb the live session");

        assert_eq!(
            result,
            serde_json::json!({"sampling": true, "rootsMissing": true, "elicitation": true})
        );
        assert_eq!(sampling_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            roots_calls.load(Ordering::Relaxed),
            0,
            "missing handler must leave state unchanged"
        );
        assert_eq!(elicitation_calls.load(Ordering::Relaxed), 1);
        assert!(client.is_initialized());
        assert!(!client.transport.is_closed());
        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 0);
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
        let payload_error =
            decode_response_payload::<fastmcp_protocol::ListToolsResult>(serde_json::json!({
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
    fn final_log_message_sink_projection_preserves_only_lossless_levels() {
        let message = FinalLogMessageParams {
            level: LoggingLevel::Warning,
            logger: Some("server.audit".to_string()),
            data: serde_json::json!({"event": "tool-complete"}),
            meta: Some(
                OpenMetadata::try_from_entries([(
                    "com.example/trace".to_string(),
                    serde_json::json!("retained"),
                )])
                .expect("valid open final metadata"),
            ),
            additional: std::collections::BTreeMap::from([(
                "com.example/extension".to_string(),
                serde_json::json!(true),
            )]),
        };

        let projection = final_log_message_sink_projection(&message)
            .expect("warning is an exact legacy sink severity");
        assert_eq!(projection.level, LogLevel::Warning);
        assert_eq!(projection.logger.as_deref(), Some("server.audit"));
        assert_eq!(
            projection.data,
            serde_json::json!({"event": "tool-complete"})
        );
        assert_eq!(
            message
                .meta
                .as_ref()
                .and_then(|meta| meta.get("com.example/trace")),
            Some(&serde_json::json!("retained"))
        );
        assert_eq!(
            message.additional.get("com.example/extension"),
            Some(&serde_json::json!(true))
        );

        let unsupported = FinalLogMessageParams {
            level: LoggingLevel::Notice,
            ..message
        };
        assert!(final_log_message_sink_projection(&unsupported).is_none());
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
            second_response.response.result,
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
            first_response.response.result,
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
    fn initialization_failure_with_verified_cleanup_preserves_the_operation_error() {
        let mut client = make_closed_client(false);

        let error = client.record_initialization_failure(McpError::internal_error(
            "deterministic initialization failure",
        ));

        assert_eq!(error.message, "deterministic initialization failure");
        assert!(!is_cleanup_unverified(&error));
        let recorded = client
            .initialization_error
            .as_ref()
            .expect("initialization failure is retained");
        assert_eq!(recorded.code, error.code);
        assert_eq!(recorded.message, error.message);
        assert!(!is_cleanup_unverified(recorded));
    }

    #[test]
    fn initialization_failure_with_cleanup_failure_is_marked_unverified() {
        let mut client = make_closed_client(false);
        client.cleanup_error = Some(McpError::internal_error(
            "deterministic retained transport cleanup failure",
        ));

        let error = client.record_initialization_failure(McpError::internal_error(
            "deterministic initialization failure",
        ));

        assert!(is_cleanup_unverified(&error));
        assert!(error.message.contains("cleanup failed"));
        let recorded = client
            .initialization_error
            .as_ref()
            .expect("unverified initialization cleanup failure is retained");
        assert_eq!(recorded.code, error.code);
        assert_eq!(recorded.message, error.message);
        assert!(is_cleanup_unverified(recorded));
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
    fn modern_log_level_absence_client_script() -> String {
        let discovery_response =
            modern_discovery_response("logging-metadata-modern-server", &[MODERN_PROTOCOL_VERSION]);
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r request || exit 1; \
             case \"$request\" in *ping*io.modelcontextprotocol/protocolVersion*2026-07-28*) ;; *) exit 1 ;; esac; \
             case \"$request\" in *io.modelcontextprotocol/logLevel*) exit 1 ;; \
             *) printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{}}}}' ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_log_level_metadata_client_script() -> String {
        let discovery_response =
            modern_discovery_response("logging-metadata-modern-server", &[MODERN_PROTOCOL_VERSION]);
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r request || exit 1; \
             case \"$request\" in *ping*'\"io.modelcontextprotocol/logLevel\":\"notice\"'*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{}}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_typed_call_client_script(call_response: &str) -> String {
        let discovery_response =
            modern_discovery_response("typed-modern-server", &[MODERN_PROTOCOL_VERSION]);
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r second || exit 1; \
             case \"$second\" in *tools/call*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{call_response}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_final_convenience_client_script(method: &str, response: &str) -> String {
        let discovery_response = modern_discovery_response(
            "final-convenience-modern-server",
            &[MODERN_PROTOCOL_VERSION],
        );
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r second || exit 1; \
             case \"$second\" in *{method}*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{response}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_progress_client_script(call_response: &str) -> String {
        let discovery_response =
            modern_discovery_response("progress-modern-server", &[MODERN_PROTOCOL_VERSION]);
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r request || exit 1; \
             case \"$request\" in *tools/call*io.modelcontextprotocol/protocolVersion*2026-07-28*'\"progressToken\":2'*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"progressToken\":2,\"progress\":0.5,\"total\":1.0,\"message\":\"modern progress\"}}}}'; \
             printf '%s\\n' '{call_response}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_server_notification_client_script(notification: &str, call_response: &str) -> String {
        let discovery_response =
            modern_discovery_response("notification-modern-server", &[MODERN_PROTOCOL_VERSION]);
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r request || exit 1; \
             case \"$request\" in *tools/call*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{notification}'; \
             printf '%s\\n' '{call_response}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_subscriptions_listen_client_script(
        acknowledgement_subscription_id: i64,
        stream_frames: &[&str],
    ) -> String {
        let discovery_response =
            modern_discovery_response("subscriptions-modern-server", &[MODERN_PROTOCOL_VERSION]);
        let acknowledgement = format!(
            r#"{{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{{"_meta":{{"io.modelcontextprotocol/subscriptionId":{acknowledgement_subscription_id}}},"notifications":{{"toolsListChanged":true}}}}}}"#
        );
        let stream_frames = stream_frames
            .iter()
            .map(|frame| format!("printf '%s\\n' '{frame}'"))
            .collect::<Vec<_>>()
            .join("; ");
        let stream_frames = if stream_frames.is_empty() {
            String::new()
        } else {
            format!("; {stream_frames}")
        };
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r request || exit 1; \
             case \"$request\" in *subscriptions/listen*io.modelcontextprotocol/protocolVersion*2026-07-28*'\"toolsListChanged\":true'*) \
             printf '%s\\n' '{acknowledgement}'{stream_frames} ;; *) exit 1 ;; esac"
        )
    }

    #[cfg(unix)]
    fn modern_tasks_subscriptions_listen_client_script(
        task_id: &str,
        notification_task_id: &str,
    ) -> String {
        let discovery_response = modern_tasks_discovery_response(
            "tasks-subscriptions-modern-server",
            serde_json::json!({}),
        );
        let acknowledgement = format!(
            r#"{{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{{"_meta":{{"io.modelcontextprotocol/subscriptionId":2}},"notifications":{{"toolsListChanged":true,"taskIds":["{task_id}"]}}}}}}"#
        );
        let task_notification = format!(
            r#"{{"jsonrpc":"2.0","method":"notifications/tasks","params":{{"_meta":{{"io.modelcontextprotocol/subscriptionId":2}},"taskId":"{notification_task_id}","status":"working","createdAt":"2026-07-28T12:00:00.000Z","lastUpdatedAt":"2026-07-28T12:00:00.000Z","ttlMs":null}}}}"#
        );
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r request || exit 1; \
             case \"$request\" in *subscriptions/listen*) ;; *) exit 1 ;; esac; \
             case \"$request\" in *io.modelcontextprotocol/protocolVersion*2026-07-28*) ;; *) exit 1 ;; esac; \
             case \"$request\" in *'\"toolsListChanged\":true'*) ;; *) exit 1 ;; esac; \
             case \"$request\" in *'\"taskIds\":[\"{task_id}\"]'*) ;; *) exit 1 ;; esac; \
             case \"$request\" in *'\"extensions\":{{\"io.modelcontextprotocol/tasks\":{{}}}}'*) ;; *) exit 1 ;; esac; \
             printf '%s\\n' '{acknowledgement}'; \
             printf '%s\\n' '{task_notification}'; \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"resultType\":\"complete\",\"_meta\":{{\"io.modelcontextprotocol/subscriptionId\":2}}}}}}'"
        )
    }

    #[cfg(unix)]
    fn modern_subscription_cancellation_late_terminal_client_script() -> String {
        let discovery_response = modern_discovery_response(
            "subscriptions-cancellation-modern-server",
            &[MODERN_PROTOCOL_VERSION],
        );
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r listen || exit 1; \
             case \"$listen\" in *subscriptions/listen*io.modelcontextprotocol/protocolVersion*2026-07-28*'\"toolsListChanged\":true'*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/subscriptions/acknowledged\",\"params\":{{\"_meta\":{{\"io.modelcontextprotocol/subscriptionId\":2}},\"notifications\":{{\"toolsListChanged\":true}}}}}}'; \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{{\"requestId\":2}}}}'; \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"resultType\":\"complete\",\"_meta\":{{\"io.modelcontextprotocol/subscriptionId\":2}}}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r ping || exit 1; \
             case \"$ping\" in *ping*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{}}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_typed_list_client_script(list_response: &str) -> String {
        let discovery_response =
            modern_discovery_response("typed-list-modern-server", &[MODERN_PROTOCOL_VERSION]);
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r second || exit 1; \
             case \"$second\" in *tools/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{list_response}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_remaining_core_client_script() -> String {
        let discovery_response =
            modern_discovery_response("remaining-core-modern-server", &[MODERN_PROTOCOL_VERSION]);
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r tools || exit 1; \
             case \"$tools\" in *tools/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"resultType\":\"complete\",\"tools\":[],\"ttlMs\":0,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r resources || exit 1; \
             case \"$resources\" in *resources/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{\"resultType\":\"complete\",\"resources\":[],\"ttlMs\":0,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r templates || exit 1; \
             case \"$templates\" in *resources/templates/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{{\"resultType\":\"complete\",\"resourceTemplates\":[],\"ttlMs\":0,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r read_resource || exit 1; \
             case \"$read_resource\" in *resources/read*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{{\"resultType\":\"complete\",\"contents\":[],\"ttlMs\":0,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r prompts || exit 1; \
             case \"$prompts\" in *prompts/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{{\"resultType\":\"complete\",\"prompts\":[],\"ttlMs\":0,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r get_prompt || exit 1; \
             case \"$get_prompt\" in *prompts/get*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{{\"resultType\":\"complete\",\"messages\":[]}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r ping || exit 1; \
             case \"$ping\" in *ping*'\"io.modelcontextprotocol/logLevel\":\"notice\"'*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":8,\"result\":{{}}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_completion_client_script(completion_response: &str) -> String {
        let discovery_response =
            modern_discovery_response("completion-modern-server", &[MODERN_PROTOCOL_VERSION]);
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r second || exit 1; \
             case \"$second\" in *completion/complete*) ;; *) exit 1 ;; esac; \
             case \"$second\" in *io.modelcontextprotocol/protocolVersion*2026-07-28*) ;; *) exit 1 ;; esac; \
             case \"$second\" in *'\"context\":{{\"arguments\":{{\"region\":\"us-east-1\"}}}}'*) ;; *) exit 1 ;; esac; \
             case \"$second\" in *'\"title\":\"Deploy\"'*) \
             printf '%s\\n' '{completion_response}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_discovery_response(server_name: &str, supported_versions: &[&str]) -> String {
        let capabilities = fastmcp_protocol::ServerDiscoverCapabilities::from_registry(
            &fastmcp_protocol::ServerBehaviorRegistry::default(),
            std::collections::BTreeMap::new(),
        )
        .expect("an empty installed behavior registry is discoverable");
        let result = ServerDiscoverResult::new(
            capabilities,
            ServerInfo {
                name: server_name.to_owned(),
                version: "1.0.0".to_owned(),
            },
            None,
            fastmcp_protocol::DiscoveryCacheHints::private_ttl_ms(0),
        );
        let mut response = serde_json::json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 1,
            "result": result,
        });
        response["result"]["supportedVersions"] = serde_json::json!(supported_versions);
        serde_json::to_string(&response)
            .expect("typed modern discovery response serializes deterministically")
    }

    #[cfg(unix)]
    fn modern_tasks_discovery_response(server_name: &str, settings: serde_json::Value) -> String {
        let capabilities = fastmcp_protocol::ServerDiscoverCapabilities::from_registry(
            &fastmcp_protocol::ServerBehaviorRegistry::default(),
            std::collections::BTreeMap::from([(
                fastmcp_protocol::TASKS_EXTENSION.to_owned(),
                settings,
            )]),
        )
        .expect("Tasks discovery settings satisfy the generic extension envelope");
        let result = ServerDiscoverResult::new(
            capabilities,
            ServerInfo {
                name: server_name.to_owned(),
                version: "1.0.0".to_owned(),
            },
            None,
            fastmcp_protocol::DiscoveryCacheHints::private_ttl_ms(0),
        );
        let mut response = serde_json::json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 1,
            "result": result,
        });
        response["result"]["supportedVersions"] = serde_json::json!([MODERN_PROTOCOL_VERSION]);
        serde_json::to_string(&response)
            .expect("Tasks discovery response serializes deterministically")
    }

    #[cfg(unix)]
    fn modern_final_tasks_client_script(get_response: &str) -> String {
        let discovery_response =
            modern_tasks_discovery_response("tasks-modern-server", serde_json::json!({}));
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r get || exit 1; \
             case \"$get\" in *'\"method\":\"tasks/get\"'*) ;; *) exit 1 ;; esac; \
             case \"$get\" in *'\"taskId\":\"task-1\"'*) ;; *) exit 1 ;; esac; \
             case \"$get\" in *'\"extensions\":{{\"io.modelcontextprotocol/tasks\":{{}}}}'*) \
             printf '%s\\n' '{get_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r update || exit 1; \
             case \"$update\" in *'\"method\":\"tasks/update\"'*) ;; *) exit 1 ;; esac; \
             case \"$update\" in *'\"taskId\":\"task-1\"'*) ;; *) exit 1 ;; esac; \
             case \"$update\" in *'\"inputResponses\":{{}}'*) ;; *) exit 1 ;; esac; \
             case \"$update\" in *'\"extensions\":{{\"io.modelcontextprotocol/tasks\":{{}}}}'*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{\"resultType\":\"complete\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r cancel || exit 1; \
             case \"$cancel\" in *'\"method\":\"tasks/cancel\"'*) ;; *) exit 1 ;; esac; \
             case \"$cancel\" in *'\"taskId\":\"task-1\"'*) ;; *) exit 1 ;; esac; \
             case \"$cancel\" in *'\"extensions\":{{\"io.modelcontextprotocol/tasks\":{{}}}}'*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{{\"resultType\":\"complete\"}}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_final_tasks_get_client_script(get_response: &str) -> String {
        let discovery_response =
            modern_tasks_discovery_response("tasks-modern-server", serde_json::json!({}));
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r get || exit 1; \
             case \"$get\" in *'\"method\":\"tasks/get\"'*) ;; *) exit 1 ;; esac; \
             case \"$get\" in *'\"taskId\":\"task-1\"'*) ;; *) exit 1 ;; esac; \
             case \"$get\" in *'\"extensions\":{{\"io.modelcontextprotocol/tasks\":{{}}}}'*) \
             printf '%s\\n' '{get_response}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_final_tool_task_client_script(response: &str) -> String {
        let discovery_response =
            modern_tasks_discovery_response("tool-task-modern-server", serde_json::json!({}));
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r call || exit 1; \
             case \"$call\" in *'\"method\":\"tools/call\"'*) ;; *) exit 1 ;; esac; \
             case \"$call\" in *'\"name\":\"durable-tool\"'*) ;; *) exit 1 ;; esac; \
             case \"$call\" in *'\"extensions\":{{\"io.modelcontextprotocol/tasks\":{{}}}}'*) ;; *) exit 1 ;; esac; \
             printf '%s\\n' '{response}'; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_discovery_response_with_final_state(server_name: &str, cache_scope: &str) -> String {
        let capabilities = fastmcp_protocol::ServerDiscoverCapabilities::from_registry(
            &fastmcp_protocol::ServerBehaviorRegistry::from_behaviors([
                fastmcp_protocol::ServerBehavior::ToolsList,
                fastmcp_protocol::ServerBehavior::ToolsListChangedNotification,
            ]),
            std::collections::BTreeMap::from([(
                "io.fastmcp.session-state".to_owned(),
                serde_json::json!({ "mode": "lossless" }),
            )]),
        )
        .expect("the installed final behavior registry is discoverable");
        let instructions = fastmcp_protocol::ServerInstructions::new("use the final contract")
            .expect("bounded test instructions are admitted");
        let result = ServerDiscoverResult::new(
            capabilities,
            ServerInfo {
                name: server_name.to_owned(),
                version: "1.0.0".to_owned(),
            },
            Some(instructions),
            fastmcp_protocol::DiscoveryCacheHints::private_ttl_ms(73),
        );
        let mut result = serde_json::to_value(result)
            .expect("typed modern discovery result serializes deterministically");
        result["_meta"]["io.fastmcp.session-state"] = serde_json::json!({ "origin": "peer" });
        result["cacheScope"] = serde_json::json!(cache_scope);
        serde_json::to_string(&serde_json::json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": 1,
            "result": result,
        }))
        .expect("modern discovery response serializes deterministically")
    }

    #[cfg(unix)]
    fn legacy_public_client_script() -> &'static str {
        "IFS= read -r first || exit 1; \
         case \"$first\" in *initialize*2024-11-05*) \
         printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-server\",\"version\":\"1.0.0\"}}}' ;; *) exit 1 ;; esac; \
         IFS= read -r lifecycle || exit 1; \
         case \"$lifecycle\" in *notifications/initialized*) ;; *) exit 1 ;; esac; \
         IFS= read -r request || exit 1; \
         case \"$request\" in *ping*io.modelcontextprotocol/protocolVersion*|*ping*io.modelcontextprotocol/clientCapabilities*) exit 1 ;; \
         *ping*) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}' ;; *) exit 1 ;; esac; \
         exec sleep 2"
    }

    #[cfg(unix)]
    fn legacy_typed_call_client_script() -> &'static str {
        "IFS= read -r first || exit 1; \
         case \"$first\" in *initialize*2024-11-05*) \
         printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-server\",\"version\":\"1.0.0\"}}}' ;; *) exit 1 ;; esac; \
         IFS= read -r lifecycle || exit 1; \
         case \"$lifecycle\" in *notifications/initialized*) ;; *) exit 1 ;; esac; \
         IFS= read -r request || exit 1; \
         case \"$request\" in *tools/call*) ;; *) exit 1 ;; esac; \
         case \"$request\" in *io.modelcontextprotocol/protocolVersion*) exit 1 ;; \
         *) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"legacy result\",\"annotations\":{\"audience\":[\"user\"]},\"_meta\":{\"io.fastmcp.legacy\":true},\"io.fastmcp.extension\":{\"kept\":true}}],\"isError\":false,\"_meta\":{\"io.fastmcp.result\":true},\"io.fastmcp.resultExtension\":{\"kept\":true}}}' ;; esac; \
         exec sleep 2"
    }

    #[cfg(unix)]
    fn legacy_typed_list_client_script() -> &'static str {
        "IFS= read -r first || exit 1; \
         case \"$first\" in *initialize*2024-11-05*) \
         printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-server\",\"version\":\"1.0.0\"}}}' ;; *) exit 1 ;; esac; \
         IFS= read -r lifecycle || exit 1; \
         case \"$lifecycle\" in *notifications/initialized*) ;; *) exit 1 ;; esac; \
         IFS= read -r request || exit 1; \
         case \"$request\" in *tools/list*) ;; *) exit 1 ;; esac; \
         case \"$request\" in *io.modelcontextprotocol/protocolVersion*) exit 1 ;; \
         *) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}' ;; esac; \
         exec sleep 2"
    }

    #[cfg(unix)]
    fn legacy_progress_client_script(progress_token: i64) -> String {
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *initialize*2024-11-05*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{{}},\"serverInfo\":{{\"name\":\"legacy-server\",\"version\":\"1.0.0\"}}}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r lifecycle || exit 1; \
             case \"$lifecycle\" in *notifications/initialized*) ;; *) exit 1 ;; esac; \
             IFS= read -r request || exit 1; \
             case \"$request\" in *tools/call*'\"progressToken\":2'*) ;; *) exit 1 ;; esac; \
             case \"$request\" in *io.modelcontextprotocol/protocolVersion*) exit 1 ;; \
             *) printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"progressToken\":{progress_token},\"progress\":0.5,\"total\":1.0,\"message\":\"legacy progress\"}}}}'; \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"legacy result\"}}],\"isError\":false}}}}' ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn legacy_log_level_client_script() -> &'static str {
        "IFS= read -r first || exit 1; \
         case \"$first\" in *initialize*2024-11-05*) \
         printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-server\",\"version\":\"1.0.0\"}}}' ;; *) exit 1 ;; esac; \
         IFS= read -r lifecycle || exit 1; \
         case \"$lifecycle\" in *notifications/initialized*) ;; *) exit 1 ;; esac; \
         IFS= read -r request || exit 1; \
         case \"$request\" in *logging/setLevel*'\"level\":\"info\"'*) ;; *) exit 1 ;; esac; \
         case \"$request\" in *io.modelcontextprotocol/logLevel*|*io.modelcontextprotocol/protocolVersion*) exit 1 ;; \
         *) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}' ;; esac; \
         exec sleep 2"
    }

    #[cfg(unix)]
    fn auto_legacy_log_level_client_script() -> &'static str {
        "IFS= read -r first || exit 1; \
         case \"$first\" in \
         *server/discover*) \
         printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}' ;; \
         *initialize*2024-11-05*) \
         printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-server\",\"version\":\"1.0.0\"}}}'; \
         IFS= read -r lifecycle || exit 1; \
         case \"$lifecycle\" in *notifications/initialized*) ;; *) exit 1 ;; esac; \
         IFS= read -r request || exit 1; \
         case \"$request\" in *logging/setLevel*'\"level\":\"info\"'*) ;; *) exit 1 ;; esac; \
         case \"$request\" in *io.modelcontextprotocol/logLevel*|*io.modelcontextprotocol/protocolVersion*) exit 1 ;; \
         *) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}' ;; esac ;; \
         *) exit 1 ;; esac; \
         exec sleep 2"
    }

    #[cfg(unix)]
    fn legacy_completion_client_script() -> &'static str {
        "IFS= read -r first || exit 1; \
         case \"$first\" in *initialize*2024-11-05*) \
         printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-server\",\"version\":\"1.0.0\"}}}' ;; *) exit 1 ;; esac; \
         IFS= read -r lifecycle || exit 1; \
         case \"$lifecycle\" in *notifications/initialized*) ;; *) exit 1 ;; esac; \
         IFS= read -r request || exit 1; \
         case \"$request\" in *completion/complete*) ;; *) exit 1 ;; esac; \
         case \"$request\" in *io.modelcontextprotocol/protocolVersion*) exit 1 ;; \
         *) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"completion\":{\"values\":[\"staging\"],\"total\":1,\"hasMore\":false}}}' ;; esac; \
         exec sleep 2"
    }

    #[cfg(unix)]
    fn auto_legacy_completion_client_script() -> &'static str {
        "IFS= read -r first || exit 1; \
         case \"$first\" in \
         *server/discover*) \
         printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}' ;; \
         *initialize*2024-11-05*) \
         printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-server\",\"version\":\"1.0.0\"}}}'; \
         IFS= read -r lifecycle || exit 1; \
         case \"$lifecycle\" in *notifications/initialized*) ;; *) exit 1 ;; esac; \
         IFS= read -r request || exit 1; \
         case \"$request\" in *completion/complete*) ;; *) exit 1 ;; esac; \
         case \"$request\" in *io.modelcontextprotocol/protocolVersion*) exit 1 ;; \
         *) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"completion\":{\"values\":[\"staging\"],\"total\":1,\"hasMore\":false}}}' ;; esac ;; \
         *) exit 1 ;; esac; \
         exec sleep 2"
    }

    fn completion_params() -> CompletionParams {
        CompletionParams {
            reference: CompletionReference::Prompt {
                name: "deploy".to_owned(),
            },
            argument: CompletionArgument {
                name: "environment".to_owned(),
                value: "sta".to_owned(),
            },
            context: None,
        }
    }

    fn modern_completion_params() -> CompletionParams {
        CompletionParams {
            reference: CompletionReference::PromptWithTitle {
                name: "deploy".to_owned(),
                title: "Deploy".to_owned(),
            },
            argument: CompletionArgument {
                name: "environment".to_owned(),
                value: "sta".to_owned(),
            },
            context: Some(CompletionContext {
                arguments: Some(std::collections::BTreeMap::from([(
                    "region".to_owned(),
                    "us-east-1".to_owned(),
                )])),
            }),
        }
    }

    fn completion_params_with_context() -> CompletionParams {
        let mut params = completion_params();
        params.context = Some(CompletionContext {
            arguments: Some(std::collections::BTreeMap::from([(
                "region".to_owned(),
                "us-east-1".to_owned(),
            )])),
        });
        params
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_i_positive() {
        let modern_result = modern_discovery_response("modern-server", &[MODERN_PROTOCOL_VERSION]);
        let script = modern_public_client_script(&modern_result);
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
    fn clt_01_modern_ping_is_not_a_core_request() {
        let modern_result =
            modern_discovery_response("modern-ping-server", &[MODERN_PROTOCOL_VERSION]);
        let script = modern_public_client_script(&modern_result);
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the client");

        client
            .ping()
            .expect("the bare JSON-RPC acknowledgement must not decode as a final core result");
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_final_typed_client_result_positive() {
        let script = modern_typed_call_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"typed result","annotations":{"audience":["user"]},"_meta":{"io.fastmcp.retained":true},"io.fastmcp.extension":"retained"}],"isError":false,"structuredContent":{"answer":"typed result"}}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the public client");

        let result = client
            .call_tool_typed("echo", serde_json::json!({"text": "typed"}))
            .expect("a negotiated modern tool call retains its typed final result");
        let CoreResult::Final(FinalCoreResult::ToolsCall { result, diagnostic }) = result else {
            panic!("modern tools/call must not decode through the legacy result shape");
        };
        assert!(diagnostic.is_none());
        assert!(!result.payload.is_error);
        assert_eq!(
            result.payload.structured_content,
            Some(serde_json::json!({"answer": "typed result"}))
        );
        let [
            ContentBlock::Text {
                text,
                annotations,
                meta,
                additional,
            },
        ] = result.payload.content.as_slice()
        else {
            panic!("typed tools/call must retain the complete final content block");
        };
        assert_eq!(text, "typed result");
        assert!(annotations.is_some());
        assert!(meta.is_some());
        assert_eq!(
            additional.get("io.fastmcp.extension"),
            Some(&serde_json::json!("retained"))
        );
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_stdio_result_source_preserves_unknown_order_and_number_lexemes() {
        let script = modern_typed_call_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"content":[],"zeta":{"second":2,"first":1},"isError":false,"alpha":1.20e+4}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the exact-source client");

        let result = client
            .call_tool_typed("echo", serde_json::json!({}))
            .expect("an absent discriminator uses the bounded modern compatibility rule");
        let CoreResult::Final(FinalCoreResult::ToolsCall { result, diagnostic }) = result else {
            panic!("the public stdio path must return the selected final tool result");
        };
        assert_eq!(
            diagnostic,
            Some(fastmcp_protocol::ResultPeerDiagnostic::ModernMissingResultType)
        );
        let extras = result.extras.members();
        assert_eq!(
            extras
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            vec!["zeta", "alpha"],
            "unknown top-level members retain admitted order",
        );
        let fastmcp_protocol::ExactJsonValue::Object(zeta) = &extras[0].value else {
            panic!("zeta remains an exact object");
        };
        assert_eq!(
            zeta.members()
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            vec!["second", "first"],
            "nested member order survives the shipped correlation boundary",
        );
        assert_eq!(
            extras[1].value,
            fastmcp_protocol::ExactJsonValue::Number("1.20e+4".to_owned()),
            "the original number lexeme reaches exact result decoding",
        );
        client.close().expect("exact-source client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_tasks_final_get_update_cancel_positive() {
        let script = modern_final_tasks_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","taskId":"task-1","status":"input_required","createdAt":"2026-07-28T00:00:00Z","lastUpdatedAt":"2026-07-28T00:00:00Z","ttlMs":null,"inputRequests":{}}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("Tasks-capable modern discovery initializes the client");
        let task_id = FinalTaskId::parse("task-1").expect("typed final task ID");

        let task = client
            .get_task_final(task_id.clone())
            .expect("the admitted final tasks/get response retains its task");
        let FinalTask::InputRequired {
            base,
            input_requests,
        } = &task.task
        else {
            panic!("the exact task result must retain input_required state");
        };
        assert_eq!(base.task_id, task_id);
        assert!(input_requests.is_empty());

        let acknowledgement = client
            .update_task_final(&task.task, BTreeMap::new())
            .expect("an empty response map matches the exact empty input ledger");
        assert!(acknowledgement.meta.is_none());
        assert!(acknowledgement.additional.is_empty());

        let cancellation = client
            .cancel_task_final(task_id)
            .expect("the admitted final tasks/cancel acknowledgement is exact and empty");
        assert!(cancellation.meta.is_none());
        assert!(cancellation.additional.is_empty());
        client.close().expect("modern Tasks client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_tasks_final_undeclared_capability_rejects_before_request_mutation() {
        // This differs from the admitted Tasks discovery only by the absent
        // `io.modelcontextprotocol/tasks` capability declaration.
        let discovery =
            modern_discovery_response("tasks-undeclared-server", &[MODERN_PROTOCOL_VERSION]);
        let script = modern_public_client_script(&discovery);
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes before the extension gate");
        let next_id_before = client.next_id.load(Ordering::SeqCst);

        let error = client
            .get_task_final(FinalTaskId::parse("task-1").expect("typed final task ID"))
            .expect_err("an undeclared extension cannot send tasks/get");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(client.next_id.load(Ordering::SeqCst), next_id_before);
        client.close().expect("undeclared Tasks client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_tasks_final_nonempty_settings_reject_before_request_mutation() {
        // This differs from the admitted Tasks discovery only by one setting;
        // the official extension admits exactly the empty object.
        let discovery = modern_tasks_discovery_response(
            "tasks-settings-server",
            serde_json::json!({
                "mode": "unsupported"
            }),
        );
        let script = modern_public_client_script(&discovery);
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery retains extension settings before method admission");
        let next_id_before = client.next_id.load(Ordering::SeqCst);

        let error = client
            .get_task_final(FinalTaskId::parse("task-1").expect("typed final task ID"))
            .expect_err("nonempty official Tasks settings cannot admit tasks/get");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(client.next_id.load(Ordering::SeqCst), next_id_before);
        client.close().expect("rejected Tasks settings cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_tasks_final_wrong_task_id_terminates_the_connection() {
        // This differs from the admitted get response only in the returned
        // taskId. A response for another opaque ID must not be accepted.
        let script = modern_final_tasks_get_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","taskId":"task-2","status":"input_required","createdAt":"2026-07-28T00:00:00Z","lastUpdatedAt":"2026-07-28T00:00:00Z","ttlMs":null,"inputRequests":{}}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("Tasks-capable modern discovery initializes the client");

        let error = client
            .get_task_final(FinalTaskId::parse("task-1").expect("typed final task ID"))
            .expect_err("a mismatched final task ID is a peer contradiction");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(!client.is_initialized());
        client.close().expect("contradictory Tasks client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_tasks_final_tool_outcome_retains_exact_created_task() {
        let script = modern_final_tool_task_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"task","taskId":"task-73","status":"working","createdAt":"2026-07-28T12:00:00.000Z","lastUpdatedAt":"2026-07-28T12:00:00.000Z","ttlMs":null}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("Tasks-capable discovery initializes the tool client");

        let outcome = client
            .call_tool_final_outcome("durable-tool", serde_json::json!({"work": 73}))
            .expect("bilaterally negotiated tool result retains its exact task branch");
        let FinalToolCallOutcome::Task(result) = outcome else {
            panic!("Tasks-backed tools/call must not be projected into complete content");
        };
        assert_eq!(result.task.base().task_id.as_str(), "task-73");
        assert!(matches!(result.task, FinalTask::Working(_)));
        client.close().expect("final tool task client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_tasks_final_tool_outcome_rejects_one_field_result_type_change() {
        // This differs from the admitted task result only in `resultType`.
        let script = modern_final_tool_task_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","taskId":"task-73","status":"working","createdAt":"2026-07-28T12:00:00.000Z","lastUpdatedAt":"2026-07-28T12:00:00.000Z","ttlMs":null}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("Tasks-capable discovery initializes before the planted response");

        let error = client
            .call_tool_final_outcome("durable-tool", serde_json::json!({"work": 73}))
            .expect_err("one changed result discriminator must fail the connection closed");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(!client.is_initialized());
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_exact_final_conveniences_preserve_final_open_fields() {
        let script = modern_final_convenience_client_script(
            "tools/call",
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"exact tool result","_meta":{"io.fastmcp.retained":true},"io.fastmcp.extension":"retained"}],"isError":false,"structuredContent":{"answer":"exact tool result"}}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the final tool convenience client");

        let tool_result: FinalCallToolResult = client
            .call_tool_final("echo", serde_json::json!({"text": "exact"}))
            .expect("the exact final tool convenience retains structured output");
        assert_eq!(
            tool_result.structured_content,
            Some(serde_json::json!({"answer": "exact tool result"}))
        );
        let [
            ContentBlock::Text {
                text,
                meta,
                additional,
                ..
            },
        ] = tool_result.content.as_slice()
        else {
            panic!("the exact final tool convenience retains final text content");
        };
        assert_eq!(text, "exact tool result");
        assert!(meta.is_some());
        assert_eq!(
            additional.get("io.fastmcp.extension"),
            Some(&serde_json::json!("retained"))
        );
        client.close().expect("modern tool client cleanup");

        let script = modern_final_convenience_client_script(
            "resources/read",
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","contents":[{"uri":"file:///exact.txt","text":"exact resource","mimeType":"text/plain","_meta":{"io.fastmcp.retained":true},"io.fastmcp.extension":"retained"}],"ttlMs":73,"cacheScope":"public"}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the final resource convenience client");

        let resource_result: FinalReadResourceResult = client
            .read_resource_final("file:///exact.txt")
            .expect("the exact final resource convenience retains cache directives");
        assert_eq!(resource_result.ttl_ms, 73);
        assert_eq!(
            resource_result.cache_scope,
            fastmcp_protocol::CacheScope::Public
        );
        let [
            EmbeddedResourceContents::Text {
                uri,
                text,
                mime_type,
                meta,
                additional,
            },
        ] = resource_result.contents.as_slice()
        else {
            panic!("the exact final resource convenience retains final resource content");
        };
        assert_eq!(uri.as_str(), "file:///exact.txt");
        assert_eq!(text, "exact resource");
        assert_eq!(mime_type.as_deref(), Some("text/plain"));
        assert!(meta.is_some());
        assert_eq!(
            additional.get("io.fastmcp.extension"),
            Some(&serde_json::json!("retained"))
        );
        client.close().expect("modern resource client cleanup");

        let script = modern_final_convenience_client_script(
            "prompts/get",
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","description":"exact prompt","messages":[{"role":"user","content":{"type":"text","text":"exact prompt content","_meta":{"io.fastmcp.retained":true},"io.fastmcp.extension":"retained"}}]}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the final prompt convenience client");

        let prompt_result: FinalGetPromptResult = client
            .get_prompt_final("summary", HashMap::new())
            .expect("the exact final prompt convenience retains the final description");
        assert_eq!(prompt_result.description.as_deref(), Some("exact prompt"));
        let [
            fastmcp_protocol::FinalPromptMessage {
                role: fastmcp_protocol::Role::User,
                content:
                    ContentBlock::Text {
                        text,
                        meta,
                        additional,
                        ..
                    },
            },
        ] = prompt_result.messages.as_slice()
        else {
            panic!("the exact final prompt convenience retains final prompt content");
        };
        assert_eq!(text, "exact prompt content");
        assert!(meta.is_some());
        assert_eq!(
            additional.get("io.fastmcp.extension"),
            Some(&serde_json::json!("retained"))
        );
        client.close().expect("modern prompt client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_exact_final_conveniences_reject_one_field_cross_era_before_request_mutation() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_public_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy-only initializes the exact client");
        let next_id_before = client.next_id.load(Ordering::SeqCst);

        let tool_error = client
            .call_tool_final("echo", serde_json::json!({"text": "legacy"}))
            .expect_err("the exact final tool convenience must reject a legacy session");
        assert_eq!(tool_error.code, McpErrorCode::InvalidParams);

        let resource_error = client
            .read_resource_final("file:///legacy.txt")
            .expect_err("the exact final resource convenience must reject a legacy session");
        assert_eq!(resource_error.code, McpErrorCode::InvalidParams);

        let prompt_error = client
            .get_prompt_final("summary", HashMap::new())
            .expect_err("the exact final prompt convenience must reject a legacy session");
        assert_eq!(prompt_error.code, McpErrorCode::InvalidParams);

        assert_eq!(
            client.next_id.load(Ordering::SeqCst),
            next_id_before,
            "changing only the selected era must reject every final convenience before ID allocation"
        );
        client
            .ping()
            .expect("the rejected final conveniences leave the legacy request stream untouched");
        client.close().expect("legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_modern_convenience_tool_projects_final_content() {
        let script = modern_typed_call_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"convenience result"}],"isError":false}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the public client");

        let content = client
            .call_tool("echo", serde_json::json!({"text": "convenience"}))
            .expect("the convenience API projects final content instead of decoding it as legacy");
        assert!(matches!(
            content.as_slice(),
            [LegacyContent::Text { text, .. }] if text == "convenience result"
        ));
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_modern_convenience_tool_rejects_structured_content_loss() {
        // This differs from the representable convenience result only in
        // structuredContent.
        let script = modern_typed_call_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"convenience result"}],"isError":false,"structuredContent":{"answer":"convenience result"}}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("same modern discovery initializes the public client");

        let error = client
            .call_tool("echo", serde_json::json!({"text": "convenience"}))
            .expect_err("the legacy convenience API must not discard structuredContent");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(client.is_initialized());
        assert!(client.responses.terminal_error().is_none());
        client
            .close()
            .expect("local projection rejection leaves the client usable");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_modern_convenience_tool_rejects_resource_link_loss() {
        let script = modern_typed_call_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"resource_link","name":"manual","uri":"https://example.com/manual"}],"isError":false}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the public client");

        let error = client
            .call_tool("echo", serde_json::json!({"text": "convenience"}))
            .expect_err("the legacy convenience API cannot represent resource_link content");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(client.is_initialized());
        client
            .close()
            .expect("local projection rejection leaves the client usable");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_modern_convenience_tool_null_discriminator_rejected() {
        // This differs from the accepted convenience result only in `resultType`.
        let script = modern_typed_call_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":null,"content":[{"type":"text","text":"convenience result"}],"isError":false}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("same modern discovery initializes the public client");

        let error = client
            .call_tool("echo", serde_json::json!({"text": "convenience"}))
            .expect_err("an explicit null discriminator remains a terminal protocol violation");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(!client.is_initialized());
        assert!(client.responses.terminal_error().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_remaining_typed_core_methods_return_final_results() {
        let script = modern_remaining_core_client_script();
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the public client");

        assert!(matches!(
            client
                .list_tools_typed(None)
                .expect("typed tools/list returns final result"),
            CoreResult::Final(FinalCoreResult::ToolsList { .. })
        ));
        assert!(matches!(
            client
                .list_resources_typed(None)
                .expect("typed resources/list returns final result"),
            CoreResult::Final(FinalCoreResult::ResourcesList { .. })
        ));
        assert!(matches!(
            client
                .list_resource_templates_typed(None)
                .expect("typed resources/templates/list returns final result"),
            CoreResult::Final(FinalCoreResult::ResourceTemplatesList { .. })
        ));
        assert!(matches!(
            client
                .read_resource_typed("file:///typed-core-resource")
                .expect("typed resources/read returns final result"),
            CoreResult::Final(FinalCoreResult::ResourcesRead { .. })
        ));
        assert!(matches!(
            client
                .list_prompts_typed(None)
                .expect("typed prompts/list returns final result"),
            CoreResult::Final(FinalCoreResult::PromptsList { .. })
        ));
        assert!(matches!(
            client
                .get_prompt_typed("summary", HashMap::new())
                .expect("typed prompts/get returns final result"),
            CoreResult::Final(FinalCoreResult::PromptsGet { .. })
        ));
        client
            .set_log_level_typed(LoggingLevel::Notice)
            .expect("modern logging configuration is retained for later request metadata");
        client
            .ping()
            .expect("final ping remains outside the core result algebra");
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_modern_log_level_metadata_is_absent_until_configured() {
        let script = modern_log_level_absence_client_script();
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("same modern discovery initializes the public client");

        client
            .ping()
            .expect("one omitted final logging configuration remains absent on the wire");
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_auto_modern_log_level_uses_later_request_metadata() {
        let script = modern_log_level_metadata_client_script();
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::Auto),
            Cx::for_request(),
        )
        .expect("recognized final discovery selects modern under Auto");

        client
            .set_log_level_typed(LoggingLevel::Notice)
            .expect("Auto-modern stores final configuration without a logging RPC");
        client
            .ping()
            .expect("the following Auto-modern request carries the final log level");
        client.close().expect("Auto-modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_log_level_preserves_exact_legacy_rpc() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_log_level_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy-only initializes the exact client");

        client
            .set_log_level(LogLevel::Info)
            .expect("legacy logging retains its exact RPC acknowledgement");
        client.close().expect("legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_auto_legacy_log_level_preserves_exact_rpc() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", auto_legacy_log_level_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::Auto),
            Cx::for_request(),
        )
        .expect("recognized final refusal selects exact legacy under Auto");

        client
            .set_log_level(LogLevel::Info)
            .expect("Auto-legacy keeps the historical logging RPC");
        client.close().expect("Auto-legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_subscriptions_listen_collects_typed_request_owned_notifications() {
        let script = modern_subscriptions_listen_client_script(
            2,
            &[
                r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#,
                r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":2}}}"#,
            ],
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the subscription client");

        let collector = client
            .listen_subscriptions_typed(SubscriptionFilter {
                tools_list_changed: Some(true),
                ..SubscriptionFilter::default()
            })
            .expect("modern subscription listener collects its owned notification stream");
        assert_eq!(collector.subscription_id, RequestId::from(2));
        assert_eq!(collector.accepted_filter.tools_list_changed, Some(true));
        assert!(matches!(
            collector.notifications.as_slice(),
            [ServerNotification::ToolsListChanged(None)]
        ));
        assert!(matches!(
            collector.terminal.payload,
            FinalSubscriptionsListenResult {}
        ));
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_tasks_subscription_collects_only_acknowledged_exact_task_ids() {
        let task_id = FinalTaskId::parse("task-73").expect("bounded task id");
        let script =
            modern_tasks_subscriptions_listen_client_script(task_id.as_str(), task_id.as_str());
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern Tasks discovery initializes the subscription client");
        let mut filter = SubscriptionFilter {
            tools_list_changed: Some(true),
            ..SubscriptionFilter::default()
        };
        fastmcp_protocol::set_task_subscription_ids(&mut filter, vec![task_id.clone()])
            .expect("compose Tasks beside a core subscription filter");

        let collector = client
            .listen_subscriptions_typed(filter)
            .expect("negotiated Tasks event remains request-owned and typed");
        assert_eq!(collector.accepted_filter.tools_list_changed, Some(true));
        assert!(collector.notifications.is_empty());
        assert_eq!(collector.task_notifications.len(), 1);
        assert_eq!(
            collector.task_notifications[0].params.task.base().task_id,
            task_id
        );
        client.close().expect("modern Tasks client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_tasks_subscription_rejects_one_field_unacknowledged_task_id() {
        let requested = FinalTaskId::parse("task-73").expect("bounded requested task id");
        let foreign = FinalTaskId::parse("task-74").expect("bounded foreign task id");
        let script =
            modern_tasks_subscriptions_listen_client_script(requested.as_str(), foreign.as_str());
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern Tasks discovery initializes the subscription client");
        let mut filter = SubscriptionFilter {
            tools_list_changed: Some(true),
            ..SubscriptionFilter::default()
        };
        fastmcp_protocol::set_task_subscription_ids(&mut filter, vec![requested])
            .expect("compose one exact Tasks filter");

        let error = client
            .listen_subscriptions_typed(filter)
            .expect_err("one changed taskId must fail the acknowledged stream closed");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert_eq!(
            error.message,
            "Tasks event taskId is outside the acknowledged filter"
        );
        assert!(!client.is_initialized());
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_subscriptions_listen_rejects_one_field_acknowledgement_id_mismatch() {
        // This differs from the admitted stream only in the acknowledgement subscription ID.
        let script = modern_subscriptions_listen_client_script(
            3,
            &[
                r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#,
                r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":2}}}"#,
            ],
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the subscription client");

        let error = client
            .listen_subscriptions_typed(SubscriptionFilter {
                tools_list_changed: Some(true),
                ..SubscriptionFilter::default()
            })
            .expect_err("a subscription acknowledgement must bind the active listen request");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(!client.is_initialized());
        assert!(client.responses.terminal_error().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_subscriptions_listen_notification_overflow_fails_closed() {
        let stream_frames = vec![
            r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
            MAX_QUEUED_FINAL_SERVER_NOTIFICATIONS + 1
        ];
        let script = modern_subscriptions_listen_client_script(2, &stream_frames);
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the subscription client");

        let error = client
            .listen_subscriptions_typed(SubscriptionFilter {
                tools_list_changed: Some(true),
                ..SubscriptionFilter::default()
            })
            .expect_err("subscription-owned notification retention must use the final queue bound");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert_eq!(
            error.message,
            FINAL_SERVER_NOTIFICATION_QUEUE_OVERFLOW_ERROR
        );
        assert!(!client.is_initialized());
        assert!(client.responses.terminal_error().is_some());
        assert!(client.take_final_server_notifications().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_subscriptions_listen_matching_cancellation_is_request_owned() {
        let script = modern_subscriptions_listen_client_script(
            2,
            &[r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}"#],
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the subscription client");

        let error = client
            .listen_subscriptions_typed(SubscriptionFilter {
                tools_list_changed: Some(true),
                ..SubscriptionFilter::default()
            })
            .expect_err("matching final cancellation terminates only the listener");
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert!(client.is_initialized());
        assert!(client.responses.terminal_error().is_none());
        client
            .close()
            .expect("cancellation leaves the client closable");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_subscriptions_listen_cancellation_tombstones_late_terminal_response() {
        let script = modern_subscription_cancellation_late_terminal_client_script();
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the subscription client");

        let error = client
            .listen_subscriptions_typed(SubscriptionFilter {
                tools_list_changed: Some(true),
                ..SubscriptionFilter::default()
            })
            .expect_err("matching final cancellation terminates only the listener");
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 1);

        client
            .ping()
            .expect("the next request consumes the listener's late terminal response");
        assert_eq!(client.responses.tombstone_len(), 0);
        assert_eq!(client.responses.uncorrelated_diagnostics, 0);
        assert!(client.is_initialized());
        assert!(client.responses.terminal_error().is_none());
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_subscriptions_listen_rejects_eof_before_terminal_complete_result() {
        let script = modern_subscriptions_listen_client_script(2, &[]);
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the subscription client");

        let error = client
            .listen_subscriptions_typed(SubscriptionFilter {
                tools_list_changed: Some(true),
                ..SubscriptionFilter::default()
            })
            .expect_err("EOF cannot replace the final complete result");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert_eq!(
            error.message,
            "Subscription listener reached EOF before terminal complete result"
        );
        assert!(!client.is_initialized());
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_subscriptions_listen_is_rejected_without_mutating_legacy_request_state() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_public_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy-only initializes the exact client");

        let error = client
            .listen_subscriptions_typed(SubscriptionFilter {
                tools_list_changed: Some(true),
                ..SubscriptionFilter::default()
            })
            .expect_err("legacy has no final subscription listener contract");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        client
            .ping()
            .expect("the rejected listener leaves the exact legacy request state unchanged");
        client.close().expect("legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_remaining_typed_list_result_positive() {
        let script = modern_typed_list_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the public client");

        assert!(matches!(
            client
                .list_tools_typed(None)
                .expect("typed tools/list accepts a complete final result"),
            CoreResult::Final(FinalCoreResult::ToolsList { .. })
        ));
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn cache_03_final_tools_list_replays_the_complete_result_without_a_second_request() {
        let script = modern_typed_list_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[],"ttlMs":1000,"cacheScope":"private","x-retained":9007199254740993123456789}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the cache client");
        client
            .set_request_timeout_policy(
                RequestTimeoutPolicy::new(Duration::from_millis(10), Duration::from_millis(10))
                    .expect("short test policy is valid"),
            )
            .expect("cache test policy is accepted");

        let first = client
            .list_tools_typed(None)
            .expect("first tools/list response fills the final cache");
        let second = client
            .list_tools_typed(None)
            .expect("fresh final cache hit avoids a second peer request");

        assert_eq!(
            first.encode().expect("first complete result re-encodes"),
            second.encode().expect("cached complete result re-encodes"),
            "the cached result retains unknown members and their exact number spelling"
        );
        assert_eq!(client.final_result_cache_stats().hits, 1);
        assert_eq!(client.final_result_cache_stats().fills, 1);
        client.close().expect("modern cache client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn cache_03_list_change_during_fetch_discards_the_late_cache_fill() {
        let discovery = modern_discovery_response(
            "cache-invalidation-modern-server",
            &[MODERN_PROTOCOL_VERSION],
        );
        let script = format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery}' ;; *) exit 1 ;; esac; \
             IFS= read -r second || exit 1; \
             case \"$second\" in *tools/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}}'; \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"resultType\":\"complete\",\"tools\":[],\"ttlMs\":1000,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r third || exit 1; \
             case \"$third\" in *tools/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{\"resultType\":\"complete\",\"tools\":[],\"ttlMs\":1000,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the invalidation client");

        client
            .list_tools_typed(None)
            .expect("the first tools/list completes after the change notification");
        client
            .list_tools_typed(None)
            .expect("the invalidated first fill requires a fresh second request");

        assert_eq!(client.final_result_cache_stats().fills, 1);
        assert_eq!(client.final_result_cache_stats().hits, 0);
        assert!(matches!(
            client.take_final_server_notifications().as_slice(),
            [ServerNotification::ToolsListChanged(None)]
        ));
        client.close().expect("modern invalidation client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn cache_03_idle_list_change_is_drained_before_a_fresh_hit() {
        let discovery = modern_discovery_response(
            "cache-idle-invalidation-modern-server",
            &[MODERN_PROTOCOL_VERSION],
        );
        let script = format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery}' ;; *) exit 1 ;; esac; \
             IFS= read -r second || exit 1; \
             case \"$second\" in *tools/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"resultType\":\"complete\",\"tools\":[],\"ttlMs\":1000,\"cacheScope\":\"private\"}}}}'; \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}}' ;; *) exit 1 ;; esac; \
             IFS= read -r third || exit 1; \
             case \"$third\" in *tools/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{\"resultType\":\"complete\",\"tools\":[],\"ttlMs\":1000,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the idle-invalidation client");

        client
            .list_tools_typed(None)
            .expect("first tools/list fills the local cache");
        client
            .list_tools_typed(None)
            .expect("idle list-change notification forces a new tools/list request");

        assert_eq!(client.final_result_cache_stats().hits, 0);
        assert_eq!(client.final_result_cache_stats().fills, 2);
        assert!(matches!(
            client.take_final_server_notifications().as_slice(),
            [ServerNotification::ToolsListChanged(None)]
        ));
        client
            .close()
            .expect("modern idle-invalidation client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn cache_03_cached_hit_observes_client_cancellation() {
        let script = modern_typed_list_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[],"ttlMs":1000,"cacheScope":"private"}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the cancellation client");
        client
            .list_tools_typed(None)
            .expect("first tools/list fills the cache");
        client.cx.set_cancel_requested(true);

        let error = client
            .list_tools_typed(None)
            .expect_err("a cached hit must not bypass cancellation");
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert!(!client.is_initialized());
    }

    #[cfg(unix)]
    #[test]
    fn cache_03_invalid_ttls_are_immediately_stale_and_do_not_close_the_client() {
        let discovery = modern_discovery_response(
            "cache-ttl-compatibility-modern-server",
            &[MODERN_PROTOCOL_VERSION],
        );
        let script = format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery}' ;; *) exit 1 ;; esac; \
             IFS= read -r second || exit 1; \
             case \"$second\" in *tools/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"resultType\":\"complete\",\"tools\":[],\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r third || exit 1; \
             case \"$third\" in *tools/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{\"resultType\":\"complete\",\"tools\":[],\"ttlMs\":-1.5,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r fourth || exit 1; \
             case \"$fourth\" in *ping*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{{}}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the TTL compatibility client");

        client
            .list_tools_typed(None)
            .expect("a missing TTL is returned as immediately stale");
        client
            .list_tools_typed(None)
            .expect("a negative TTL is returned as immediately stale");
        client
            .ping()
            .expect("TTL compatibility leaves the modern connection usable");

        assert_eq!(
            client.take_final_cache_ttl_diagnostics(),
            vec![
                FinalCacheTtlDiagnostic::Missing,
                FinalCacheTtlDiagnostic::Negative,
            ]
        );
        assert_eq!(client.final_result_cache_stats().hits, 0);
        assert_eq!(client.final_result_cache_stats().fills, 0);
        assert!(client.is_initialized());
        client.close().expect("modern TTL compatibility cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn cache_03_cursorless_list_restarts_after_generation_drift() {
        let discovery = modern_discovery_response(
            "cache-list-restart-modern-server",
            &[MODERN_PROTOCOL_VERSION],
        );
        let script = format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery}' ;; *) exit 1 ;; esac; \
             IFS= read -r first_page || exit 1; \
             case \"$first_page\" in *tools/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"resultType\":\"complete\",\"tools\":[],\"nextCursor\":\"page-2\",\"ttlMs\":0,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r second_page || exit 1; \
             case \"$second_page\" in *tools/list*'\"cursor\":\"page-2\"'*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}}'; \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{\"resultType\":\"complete\",\"tools\":[],\"ttlMs\":0,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r restarted || exit 1; \
             case \"$restarted\" in *tools/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{{\"resultType\":\"complete\",\"tools\":[],\"ttlMs\":0,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the list-restart client");

        assert!(
            client
                .list_tools()
                .expect("a generation drift restarts from a cursorless page")
                .is_empty()
        );
        assert!(matches!(
            client.take_final_server_notifications().as_slice(),
            [ServerNotification::ToolsListChanged(None)]
        ));
        client.close().expect("modern list-restart cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn cache_03_disabled_cache_restarts_a_cursorless_list_after_generation_drift() {
        let discovery = modern_discovery_response(
            "cache-disabled-list-restart-modern-server",
            &[MODERN_PROTOCOL_VERSION],
        );
        let script = format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery}' ;; *) exit 1 ;; esac; \
             IFS= read -r first_page || exit 1; \
             case \"$first_page\" in *tools/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"resultType\":\"complete\",\"tools\":[{{\"name\":\"stale\",\"inputSchema\":{{\"type\":\"object\"}}}}],\"nextCursor\":\"page-2\",\"ttlMs\":0,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r second_page || exit 1; \
             case \"$second_page\" in *tools/list*'\"cursor\":\"page-2\"'*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}}'; \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{\"resultType\":\"complete\",\"tools\":[{{\"name\":\"mixed\",\"inputSchema\":{{\"type\":\"object\"}}}}],\"ttlMs\":0,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r restarted || exit 1; \
             case \"$restarted\" in *tools/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{{\"resultType\":\"complete\",\"tools\":[{{\"name\":\"fresh\",\"inputSchema\":{{\"type\":\"object\"}}}}],\"ttlMs\":0,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the disabled-cache list client");
        client.set_final_result_cache_enabled(false);

        let tools = client
            .list_tools()
            .expect("disabled caching still restarts the cursorless list after invalidation");
        assert!(matches!(tools.as_slice(), [Tool { name, .. }] if name == "fresh"));
        assert!(matches!(
            client.take_final_server_notifications().as_slice(),
            [ServerNotification::ToolsListChanged(None)]
        ));
        client
            .close()
            .expect("modern disabled-cache list-restart cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn cache_03_invalid_cursor_flushes_the_cached_result_set() {
        let discovery = modern_discovery_response(
            "cache-invalid-cursor-modern-server",
            &[MODERN_PROTOCOL_VERSION],
        );
        let script = format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery}' ;; *) exit 1 ;; esac; \
             IFS= read -r first_page || exit 1; \
             case \"$first_page\" in *tools/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"resultType\":\"complete\",\"tools\":[],\"nextCursor\":\"page-2\",\"ttlMs\":1000,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r rejected_page || exit 1; \
             case \"$rejected_page\" in *tools/list*'\"cursor\":\"page-2\"'*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"error\":{{\"code\":-32602,\"message\":\"invalid cursor\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r restarted || exit 1; \
             case \"$restarted\" in *tools/list*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{{\"resultType\":\"complete\",\"tools\":[],\"ttlMs\":1000,\"cacheScope\":\"private\"}}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the cursor-flush client");

        client
            .list_tools_typed(None)
            .expect("the first cursorless page enters the cache");
        let error = client
            .list_tools_typed(Some("page-2"))
            .expect_err("the server rejects the opaque cursor");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        client
            .list_tools_typed(None)
            .expect("cursor rejection flushes the earlier cached page");
        assert_eq!(client.final_result_cache_stats().hits, 0);
        client.close().expect("modern cursor-flush client cleanup");
    }

    #[test]
    fn cache_03_scope_drift_forces_a_full_list_restart() {
        let mut client = make_closed_client(false);
        let result_set = FinalCacheResultSet::Tools;
        let generation = client.final_result_cache.begin_fetch(&result_set);
        let mut baseline = Some((generation, fastmcp_protocol::CacheScope::Private));
        client.last_final_cache_page = Some(FinalCachePageState {
            generation,
            scope: fastmcp_protocol::CacheScope::Public,
            miss: None,
        });

        assert!(client.final_list_restart_needed(&result_set, &mut baseline));
        assert_ne!(
            generation,
            client.final_result_cache.begin_fetch(&result_set),
            "scope drift advances the result-set generation before restart"
        );
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_modern_convenience_list_projects_representable_catalog() {
        let script = modern_typed_list_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[{"name":"echo","description":"representable","inputSchema":{"type":"object"}}],"ttlMs":0,"cacheScope":"private"}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the public client");

        let tools = client
            .list_tools()
            .expect("neutral private cache hints and a representable catalog project exactly");
        assert!(matches!(
            tools.as_slice(),
            [Tool { name, description, icon: None, .. }]
                if name == "echo" && description.as_deref() == Some("representable")
        ));
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_modern_convenience_list_rejects_cache_scope_loss() {
        // This differs from the representable catalog only in cacheScope.
        let script = modern_typed_list_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","tools":[{"name":"echo","description":"representable","inputSchema":{"type":"object"}}],"ttlMs":0,"cacheScope":"public"}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("same modern discovery initializes the public client");

        let error = client
            .list_tools()
            .expect_err("the legacy convenience API cannot discard a public cache scope");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(client.is_initialized());
        client
            .close()
            .expect("local projection rejection leaves the client usable");
    }

    #[test]
    fn clt_01_final_catalog_projection_rejects_each_one_field_loss() {
        let representable = serde_json::json!({
            "uri": "file:///catalog.txt",
            "name": "catalog",
            "description": "representable",
        });
        let projected = final_resource_to_legacy(
            serde_json::from_value::<fastmcp_protocol::FinalResource>(representable.clone())
                .expect("representable final resource parses"),
        )
        .expect("representable final resource projects without loss");
        assert_eq!(projected.name, "catalog");

        for (field, value) in [
            ("title", serde_json::json!("Catalog")),
            ("annotations", serde_json::json!({"audience":["user"]})),
            ("size", serde_json::json!(42)),
            ("_meta", serde_json::json!({"io.fastmcp.retained":true})),
            (
                "icons",
                serde_json::json!([{
                    "src":"https://example.com/catalog.svg",
                    "theme":"dark"
                }]),
            ),
        ] {
            let mut lossy = representable.clone();
            lossy[field] = value;
            let error = final_resource_to_legacy(
                serde_json::from_value::<fastmcp_protocol::FinalResource>(lossy)
                    .expect("one final-only field still parses as a final resource"),
            )
            .expect_err("one unrepresentable final catalog field must fail closed");
            assert_eq!(error.code, McpErrorCode::InvalidRequest);
        }
    }

    #[test]
    fn clt_01_final_content_projection_preserves_legacy_open_fields() {
        let representable = serde_json::json!({
            "type": "text",
            "text": "representable",
            "annotations": {"audience": ["user"]},
            "_meta": {"io.fastmcp.retained": true},
            "io.fastmcp.extension": {"retained": true},
        });
        let projected = final_content_to_legacy(
            serde_json::from_value::<ContentBlock>(representable.clone())
                .expect("representable final content parses"),
        )
        .expect("legacy content preserves all representable open fields");
        assert_eq!(
            serde_json::to_value(projected).expect("projected text re-encodes"),
            representable
        );

        let shadowed_text = ContentBlock::Text {
            text: "representable".to_owned(),
            annotations: None,
            meta: None,
            additional: std::collections::BTreeMap::from([(
                "text".to_owned(),
                serde_json::json!("shadow"),
            )]),
        };
        let error = final_content_to_legacy(shadowed_text)
            .expect_err("an open member may not shadow a declared legacy text field");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);

        let embedded_representable = serde_json::json!({
            "type": "resource",
            "annotations": {"audience": ["assistant"]},
            "_meta": {"io.fastmcp.retained": true},
            "io.fastmcp.extension": {"retained": true},
            "resource": {
                "uri": "file:///embedded.txt",
                "text": "representable",
                "_meta": {"io.fastmcp.retained": true},
                "io.fastmcp.extension": {"retained": true},
            },
        });
        let projected = final_content_to_legacy(
            serde_json::from_value::<ContentBlock>(embedded_representable.clone())
                .expect("representable embedded resource parses"),
        )
        .expect("legacy resource content preserves all representable open fields");
        assert_eq!(
            serde_json::to_value(projected).expect("projected resource re-encodes"),
            embedded_representable
        );

        let unsupported = serde_json::json!({
            "type": "audio",
            "data": "AA==",
            "mimeType": "audio/mpeg",
            "annotations": {"audience": ["user"]},
            "_meta": {"io.fastmcp.retained": true},
            "io.fastmcp.extension": {"retained": true},
        });
        let error = final_content_to_legacy(
            serde_json::from_value::<ContentBlock>(unsupported)
                .expect("valid final audio content parses before projection"),
        )
        .expect_err("an exact legacy result cannot represent final audio content");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
    }

    #[test]
    fn leg_03_convenience_results_retain_exact_nested_open_fields() {
        let resource = LegacyResourceContent::Text {
            uri: "file:///legacy.txt".to_owned(),
            text: "legacy resource".to_owned(),
            mime_type: Some("text/plain".to_owned()),
            additional: std::collections::BTreeMap::from([
                ("_meta".to_owned(), serde_json::json!({"vendor": true})),
                (
                    "io.fastmcp.extension".to_owned(),
                    serde_json::json!({"retained": true}),
                ),
            ]),
        };
        let resources = convenience_resource_read(CoreResult::Legacy(
            LegacyCoreResult::ResourcesRead(fastmcp_protocol::ReadResourceResult {
                contents: vec![resource.clone()],
                meta: None,
                additional: std::collections::BTreeMap::new(),
            }),
        ))
        .expect("legacy resource convenience result retains its exact resource shape");
        assert_eq!(resources, vec![resource]);

        let message = LegacyPromptMessage {
            role: fastmcp_protocol::Role::User,
            content: LegacyContent::Text {
                text: "legacy prompt".to_owned(),
                annotations: None,
                additional: std::collections::BTreeMap::from([(
                    "_meta".to_owned(),
                    serde_json::json!({"vendor": true}),
                )]),
            },
            additional: std::collections::BTreeMap::from([(
                "io.fastmcp.extension".to_owned(),
                serde_json::json!({"retained": true}),
            )]),
        };
        let messages = convenience_prompt_get(CoreResult::Legacy(LegacyCoreResult::PromptsGet(
            fastmcp_protocol::GetPromptResult {
                description: None,
                messages: vec![message.clone()],
                meta: None,
                additional: std::collections::BTreeMap::new(),
            },
        )))
        .expect("legacy prompt convenience result retains its exact message shape");
        assert_eq!(messages, vec![message]);
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_remaining_typed_list_null_discriminator_rejected() {
        // This differs from the accepted typed list result only in
        // `resultType`.
        let script = modern_typed_list_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":null,"tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("same modern discovery initializes the public client");

        let error = client
            .list_tools_typed(None)
            .expect_err("an explicit null discriminator is not an omitted complete discriminator");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(!client.is_initialized());
        assert!(client.responses.terminal_error().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_final_typed_client_result_null_discriminator_rejected() {
        // This differs from the accepted modern result only in `resultType`.
        let script = modern_typed_call_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":null,"content":[{"type":"text","text":"typed result"}],"isError":false}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("same modern discovery initializes the public client");

        let error = client
            .call_tool_typed("echo", serde_json::json!({"text": "typed"}))
            .expect_err("an explicit null discriminator is not an omitted complete discriminator");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(!client.is_initialized());
        assert!(client.responses.terminal_error().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_completion_client_result_positive() {
        let script = modern_completion_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","completion":{"values":["staging"],"total":1,"hasMore":false}}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the public client");

        let result = client
            .complete(modern_completion_params())
            .expect("modern completion returns its typed final payload");
        let CoreResult::Final(FinalCoreResult::Completion { result, diagnostic }) = result else {
            panic!("modern completion must not decode through the legacy result shape");
        };
        assert!(diagnostic.is_none());
        assert_eq!(result.payload.completion.values, vec!["staging".to_owned()]);
        assert_eq!(result.payload.completion.total, Some(1));
        assert_eq!(result.payload.completion.has_more, Some(false));
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_completion_client_result_null_discriminator_rejected() {
        // This differs from the accepted completion result only in `resultType`.
        let script = modern_completion_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":null,"completion":{"values":["staging"],"total":1,"hasMore":false}}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("same modern discovery initializes the public client");

        let error = client
            .complete(modern_completion_params())
            .expect_err("an explicit null completion discriminator is rejected");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(!client.is_initialized());
        assert!(client.responses.terminal_error().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn clt_02_auto_modern_completion_retains_full_context() {
        let script = modern_completion_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","completion":{"values":["staging"],"total":1,"hasMore":false}}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::Auto),
            Cx::for_request(),
        )
        .expect("Auto retains a successful modern selection");

        let result = client
            .complete(modern_completion_params())
            .expect("Auto-modern completion transmits the full final context");
        assert_eq!(client.protocol_policy(), ProtocolPolicy::Auto);
        assert_eq!(
            client.selected_protocol_era(),
            Some(ProtocolEra::Modern2026)
        );
        assert!(matches!(
            result,
            CoreResult::Final(FinalCoreResult::Completion { .. })
        ));
        client.close().expect("auto modern cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_02_auto_legacy_completion_losslessly_maps_compatible_input() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", auto_legacy_completion_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::Auto),
            Cx::for_request(),
        )
        .expect("recognized modern refusal authorizes one exact legacy selection");

        let result = client
            .complete(completion_params())
            .expect("title-free, context-free completion maps to exact legacy");
        assert_eq!(client.protocol_policy(), ProtocolPolicy::Auto);
        assert_eq!(
            client.selected_protocol_era(),
            Some(ProtocolEra::Legacy2024)
        );
        assert!(matches!(
            result,
            CoreResult::Legacy(LegacyCoreResult::Completion(_))
        ));
        client.close().expect("auto legacy cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_02_auto_legacy_completion_rejects_unrepresentable_context_without_sending() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", auto_legacy_completion_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::Auto),
            Cx::for_request(),
        )
        .expect("recognized modern refusal authorizes one exact legacy selection");

        let error = client
            .complete(completion_params_with_context())
            .expect_err("legacy completion must not erase final-only context");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert!(client.is_initialized());

        assert!(matches!(
            client
                .complete(completion_params())
                .expect("rejection leaves the exact legacy request state unchanged"),
            CoreResult::Legacy(LegacyCoreResult::Completion(_))
        ));
        client.close().expect("auto legacy cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_progress_client_result_positive() {
        let script = modern_progress_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"progress result"}],"isError":false}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the public client");
        let mut observed_progress = Vec::new();
        let mut on_progress = |progress: f64, total: Option<f64>, message: Option<&str>| {
            observed_progress.push((progress, total, message.map(ToOwned::to_owned)));
        };

        let content = client
            .call_tool_with_progress(
                "echo",
                serde_json::json!({"text": "progress"}),
                &mut on_progress,
            )
            .expect("progress calls admit the same negotiated complete result");
        assert_eq!(content.len(), 1);
        assert_eq!(
            observed_progress,
            vec![(0.5, Some(1.0), Some("modern progress".to_owned()))]
        );
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_progress_client_result_null_discriminator_rejected() {
        // This differs from the accepted progress response only in `resultType`.
        let script = modern_progress_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":null,"content":[{"type":"text","text":"progress result"}],"isError":false}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("same modern discovery initializes the public client");
        let mut on_progress = |_progress: f64, _total: Option<f64>, _message: Option<&str>| {};

        let error = client
            .call_tool_with_progress(
                "echo",
                serde_json::json!({"text": "progress"}),
                &mut on_progress,
            )
            .expect_err("an explicit null discriminator is rejected after progress admission");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(!client.is_initialized());
        assert!(client.responses.terminal_error().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_final_server_notifications_are_typed_and_drained() {
        let script = modern_server_notification_client_script(
            r#"{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///workspace/guide.md","_meta":{"com.example/trace":"retained"}}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"notification result"}],"isError":false}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the public client");

        let content = client
            .call_tool("echo", serde_json::json!({"text": "notification"}))
            .expect("the typed notification must not consume its following response");
        assert_eq!(content.len(), 1);

        let notifications = client.take_final_server_notifications();
        assert_eq!(notifications.len(), 1);
        assert!(matches!(
            &notifications[0],
            ServerNotification::ResourceUpdated(params)
                if params.uri.as_str() == "file:///workspace/guide.md"
                    && params.meta.as_ref().and_then(|meta| meta.get("com.example/trace"))
                        == Some(&serde_json::json!("retained"))
        ));
        assert!(client.take_final_server_notifications().is_empty());
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_final_log_message_is_retained_after_sink_projection() {
        let script = modern_server_notification_client_script(
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"warning","logger":"server.audit","data":{"event":"tool-complete"},"_meta":{"com.example/trace":"retained"},"com.example/extension":true}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"notification result"}],"isError":false}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the public client");

        client
            .call_tool("echo", serde_json::json!({"text": "notification"}))
            .expect("the final log message must not consume its following response");

        let notifications = client.take_final_server_notifications();
        assert!(matches!(
            notifications.as_slice(),
            [ServerNotification::Message(message)]
                if message.level == LoggingLevel::Warning
                    && message.logger.as_deref() == Some("server.audit")
                    && message.data == serde_json::json!({"event": "tool-complete"})
                    && message.meta.as_ref().and_then(|meta| meta.get("com.example/trace"))
                        == Some(&serde_json::json!("retained"))
                    && message.additional.get("com.example/extension")
                        == Some(&serde_json::json!(true))
        ));
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_final_server_notification_null_uri_fails_closed() {
        // This differs from the accepted notification only in the required URI.
        let script = modern_server_notification_client_script(
            r#"{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":null,"_meta":{"com.example/trace":"retained"}}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"notification result"}],"isError":false}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("same modern discovery initializes the public client");

        let error = client
            .call_tool("echo", serde_json::json!({"text": "notification"}))
            .expect_err("a malformed final notification must fail the modern connection");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(!client.is_initialized());
        assert!(client.responses.terminal_error().is_some());
        assert!(client.take_final_server_notifications().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_j_positive() {
        let modern_result = modern_discovery_response_with_final_state("stateful-modern", "public");
        let script = modern_public_client_script(&modern_result);
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery retains its final session state");

        let discovery = client
            .server_discovery()
            .expect("modern session exposes the exact discovery result");
        let discovered_server = discovery
            .server_info()
            .expect("modern discovery retains server identity");
        assert_eq!(discovered_server.name, client.server_info().name);
        assert_eq!(discovered_server.version, client.server_info().version);
        assert_eq!(
            discovery
                .instructions()
                .expect("peer instructions are retained")
                .as_str(),
            "use the final contract"
        );
        assert_eq!(discovery.cache_hints().ttl_ms(), 73);
        assert!(discovery.cache_hints().is_public());
        let retained = serde_json::to_value(discovery)
            .expect("the retained final discovery result stays serializable");
        assert_eq!(
            retained["capabilities"]["extensions"]["io.fastmcp.session-state"],
            serde_json::json!({ "mode": "lossless" })
        );
        assert_eq!(
            retained["_meta"]["io.fastmcp.session-state"],
            serde_json::json!({ "origin": "peer" })
        );
        client.close().expect("stateful modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_j_planted_negative() {
        // This differs from the positive discovery response only in the final
        // cache scope. It must be rejected rather than silently replaced by
        // legacy-default cache state.
        let modern_result =
            modern_discovery_response_with_final_state("stateful-modern", "not-a-cache-scope");
        let script = modern_public_client_script(&modern_result);
        let error = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .err()
        .expect("invalid final cache semantics must reject the modern session");

        assert_eq!(error.code, McpErrorCode::InternalError);
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_i_planted_negative() {
        // Only the discovery result's advertised version differs from the
        // accepted modern path. A malformed modern success may not turn into
        // legacy initialization or a second execution path.
        let legacy_advertisement = modern_discovery_response("modern-server", &[PROTOCOL_VERSION]);
        let script = modern_public_client_script(&legacy_advertisement);
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
        let modern_result =
            modern_discovery_response("auto-modern-server", &[MODERN_PROTOCOL_VERSION]);
        let script = modern_public_client_script(&modern_result);
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
        assert!(
            client.server_discovery().is_some(),
            "Auto plan replacement retains the completed modern discovery result"
        );
        client
            .ping()
            .expect("auto-selected modern client executes normally");
        client.close().expect("auto modern cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_02_discovery_absent_result_type_selects_modern_with_diagnostic() {
        let baseline =
            modern_discovery_response("compatibility-modern-server", &[MODERN_PROTOCOL_VERSION]);
        let mut response: serde_json::Value =
            serde_json::from_str(&baseline).expect("baseline discovery response is JSON");
        response["result"]
            .as_object_mut()
            .expect("discovery result is an object")
            .remove("resultType");
        let response = serde_json::to_string(&response)
            .expect("missing-discriminator discovery response re-encodes");
        let script = modern_public_client_script(&response);
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("an otherwise-valid missing discriminator establishes modern");

        assert_eq!(
            client.selected_protocol_era(),
            Some(ProtocolEra::Modern2026)
        );
        let discovery = client
            .server_discovery()
            .expect("modern classification retains discovery evidence");
        assert_eq!(discovery.result_type(), "complete");
        assert_eq!(
            discovery.peer_diagnostic(),
            Some(fastmcp_protocol::ResultPeerDiagnostic::ModernMissingResultType)
        );
        let retained = serde_json::to_value(discovery)
            .expect("retained compatibility discovery remains serializable");
        assert!(
            retained.get("resultType").is_none(),
            "captured peer evidence remains schema-invalid instead of gaining a synthetic field"
        );
        client.close().expect("compatibility modern cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_02_discovery_null_and_wrong_type_do_not_select_an_era() {
        let baseline =
            modern_discovery_response("invalid-discriminator-server", &[MODERN_PROTOCOL_VERSION]);
        for planted_result_type in [
            serde_json::Value::Null,
            serde_json::json!({"complete": true}),
        ] {
            let mut response: serde_json::Value =
                serde_json::from_str(&baseline).expect("baseline discovery response is JSON");
            response["result"]["resultType"] = planted_result_type;
            let response = serde_json::to_string(&response)
                .expect("invalid-discriminator response remains JSON");
            let script = modern_public_client_script(&response);
            let error = Client::stdio_with_protocol_plan_with_cx(
                "sh",
                &["-c", script.as_str()],
                ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
                Cx::for_request(),
            )
            .err()
            .expect("explicit null and wrong-kind discriminators reject discovery");
            assert_eq!(error.code, McpErrorCode::InternalError);
        }
    }

    #[cfg(unix)]
    #[test]
    fn clt_02_i_planted_negative() {
        // Only the discovery result's version differs from the Auto positive.
        // An invalid modern success is not an authorized fallback signal.
        let legacy_advertisement =
            modern_discovery_response("auto-modern-server", &[PROTOCOL_VERSION]);
        let script = modern_public_client_script(&legacy_advertisement);
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
        assert!(
            client.server_discovery().is_none(),
            "exact legacy initialization never fabricates final discovery state"
        );
        client
            .ping()
            .expect("legacy client executes after initialized notification");
        client.close().expect("legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_ping_preserves_the_exact_legacy_request_path() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_public_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy initialization succeeds before the exact ping request");

        client
            .ping()
            .expect("legacy ping keeps its core acknowledgement and omits final metadata");
        client.close().expect("legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_final_tasks_rejects_exact_legacy_before_request_mutation() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_public_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy initialization succeeds before final Tasks admission");
        let next_id_before = client.next_id.load(Ordering::SeqCst);

        let error = client
            .get_task_final(FinalTaskId::parse("task-1").expect("typed final task ID"))
            .expect_err("exact 2024-11-05 excludes the final Tasks extension");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(client.next_id.load(Ordering::SeqCst), next_id_before);
        client.close().expect("legacy Tasks client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_typed_client_result_preserves_exact_legacy_decode() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_typed_call_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy-only runs exact initialize and lifecycle acknowledgement");

        let result = client
            .call_tool_typed("echo", serde_json::json!({"text": "legacy"}))
            .expect("the exact legacy tools/call response remains accepted");
        let CoreResult::Legacy(LegacyCoreResult::ToolsCall(result)) = result else {
            panic!("legacy tools/call must not require a final result discriminator");
        };
        assert!(!result.is_error);
        assert_eq!(result.content.len(), 1);
        assert_eq!(
            result
                .meta
                .as_ref()
                .and_then(|meta| meta.get("io.fastmcp.result")),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            result.additional.get("io.fastmcp.resultExtension"),
            Some(&serde_json::json!({"kept": true}))
        );
        client.close().expect("legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_exact_legacy_tool_convenience_retains_the_pinned_result() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_typed_call_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy-only runs exact initialize and lifecycle acknowledgement");

        let result = client
            .call_tool_legacy("echo", serde_json::json!({"text": "legacy"}))
            .expect("the legacy convenience retains the full exact result");
        assert_eq!(
            result
                .meta
                .as_ref()
                .and_then(|meta| meta.get("io.fastmcp.result")),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            result.additional.get("io.fastmcp.resultExtension"),
            Some(&serde_json::json!({"kept": true}))
        );
        let [LegacyContent::Text { additional, .. }] = result.content.as_slice() else {
            panic!("the exact legacy result must retain its text content");
        };
        assert_eq!(
            additional.get("io.fastmcp.extension"),
            Some(&serde_json::json!({"kept": true}))
        );
        client.close().expect("legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_exact_legacy_tool_convenience_rejects_a_modern_session_before_request_mutation() {
        let script = modern_typed_call_client_script(
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"modern result"}],"isError":false}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the final client");
        let next_id_before = client.next_id.load(Ordering::SeqCst);

        let error = client
            .call_tool_legacy("echo", serde_json::json!({"text": "modern"}))
            .expect_err("changing only the selected era cannot project a final result to legacy");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(client.next_id.load(Ordering::SeqCst), next_id_before);
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_convenience_tool_preserves_exact_legacy_decode() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_typed_call_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy-only runs exact initialize and lifecycle acknowledgement");

        let content = client
            .call_tool("echo", serde_json::json!({"text": "legacy"}))
            .expect("the convenience API retains the exact legacy result shape");
        assert!(matches!(
            content.as_slice(),
            [LegacyContent::Text { text, .. }] if text == "legacy result"
        ));
        let encoded = serde_json::to_value(content).expect("legacy content re-encodes exactly");
        assert_eq!(
            encoded[0]["annotations"]["audience"],
            serde_json::json!(["user"])
        );
        assert_eq!(
            encoded[0]["_meta"]["io.fastmcp.legacy"],
            serde_json::json!(true)
        );
        assert_eq!(
            encoded[0]["io.fastmcp.extension"],
            serde_json::json!({"kept": true})
        );
        client.close().expect("legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_remaining_typed_list_preserves_exact_legacy_decode() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_typed_list_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy-only runs exact initialize and lifecycle acknowledgement");

        assert!(matches!(
            client
                .list_tools_typed(None)
                .expect("the exact legacy tools/list response remains accepted"),
            CoreResult::Legacy(LegacyCoreResult::ToolsList(_))
        ));
        client.close().expect("legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_progress_client_result_preserves_exact_legacy_decode() {
        let script = legacy_progress_client_script(2);
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy-only runs exact initialize and lifecycle acknowledgement");
        let mut observed_progress = Vec::new();
        let mut on_progress = |progress: f64, total: Option<f64>, message: Option<&str>| {
            observed_progress.push((progress, total, message.map(ToOwned::to_owned)));
        };

        let content = client
            .call_tool_with_progress(
                "echo",
                serde_json::json!({"text": "legacy progress"}),
                &mut on_progress,
            )
            .expect("legacy progress calls do not require a final result discriminator");
        assert_eq!(content.len(), 1);
        assert_eq!(
            observed_progress,
            vec![(0.5, Some(1.0), Some("legacy progress".to_owned()))]
        );
        client.close().expect("legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_progress_nonmatching_token_leaves_callback_state_unchanged() {
        let script = legacy_progress_client_script(3);
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy-only runs exact initialize and lifecycle acknowledgement");
        let mut observed_progress = Vec::new();
        let mut on_progress = |progress: f64, total: Option<f64>, message: Option<&str>| {
            observed_progress.push((progress, total, message.map(ToOwned::to_owned)));
        };

        let content = client
            .call_tool_with_progress(
                "echo",
                serde_json::json!({"text": "legacy progress"}),
                &mut on_progress,
            )
            .expect("a nonmatching progress token does not disturb the legacy request");
        assert_eq!(content.len(), 1);
        assert!(
            observed_progress.is_empty(),
            "the callback state must remain unchanged for a nonmatching token"
        );
        assert!(client.is_initialized());
        client.close().expect("legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_completion_client_result_preserves_exact_legacy_decode() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_completion_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy-only runs exact initialize and lifecycle acknowledgement");

        let result = client
            .complete(completion_params())
            .expect("legacy completion retains its exact response shape");
        let CoreResult::Legacy(LegacyCoreResult::Completion(result)) = result else {
            panic!("legacy completion must not require a final result discriminator");
        };
        assert_eq!(result.completion.values, vec!["staging".to_owned()]);
        assert_eq!(result.completion.total, Some(1));
        assert_eq!(result.completion.has_more, Some(false));
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
        let session = ClientSession::try_new(
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
        )
        .expect("test client uses the exact supported protocol version");
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
        let session = ClientSession::try_new(
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
        )
        .expect("test client uses the exact supported protocol version");
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
