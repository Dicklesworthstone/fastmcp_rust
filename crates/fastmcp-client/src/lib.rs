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
pub mod mcp_apps;
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
    PendingRequestRecord, Request, RequestExecution, RequestExecutor, ReverseRequest,
    ReverseRequestCancellation, clt_01_a_manifest_digest, clt_01_b_manifest_digest,
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
    FinalReadResourceResult, FinalSubscriptionsListenResult, GetPromptResult, InputRequiredResult,
    LegacyCoreResult, ListRootsParams, ListRootsResult, ReadResourceResult, SubscriptionFilter,
};
pub use http_executor::{
    ClientHttpConnection, ClientHttpConnectionError, ClientHttpResponse, LegacySseHttpClient,
    LegacySseHttpClientError, ModernHttpClient, ModernHttpClientError, ModernHttpResponseStream,
    ModernHttpSubscriptionListenCollector, ModernHttpSubscriptionListenEvent,
    ModernHttpSubscriptionListener,
};
pub use mcp_apps::{
    McpAppsBridgeTransport, McpAppsClientWirePolicy, McpAppsHost, McpAppsHostConfiguration,
    McpAppsHostError, McpAppsHostPolicy, McpAppsHttpClientWirePolicy, McpAppsInMemoryHostTransport,
    McpAppsInMemoryViewTransport, McpAppsInMemoryWireHostTransport,
    McpAppsInMemoryWireViewTransport, McpAppsWireBridgeTransport, McpAppsWireHost,
    McpAppsWireHostConfiguration, McpAppsWireHostPolicy, mcp_apps_in_memory_pair,
    mcp_apps_in_memory_wire_pair,
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
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once, mpsc};
use std::time::{Duration, Instant};

use asupersync::{Cx, channel::oneshot};
use execution::{MrtrDriver, MrtrDriverLimits};
use fastmcp_core::{McpError, McpErrorCode, McpResult, Sha256Digest, block_on, sha256_bounded};
use fastmcp_protocol::common_types::{
    ContentBlock, EmbeddedResourceContents, JsonInteger, OpenMetadata, RawIcon,
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
    CallToolParams, CancellationSender, CancellationWireMessage, CancelledParams,
    ClientCapabilities, ClientInfo, CoreDispatchError, CoreRequest, CorrelationKey,
    FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_SUBSCRIPTION_ID_META_KEY,
    FinalCancelledNotificationParams, FinalCoreRequest, FinalLogMessageParams,
    FinalProgressNotificationParams, FinalRequestMeta,
    FinalSubscriptionsAcknowledgedNotificationParams, GetPromptParams, InitializeParams,
    InitializeResult, JSONRPC_VERSION, JsonRpcError, JsonRpcMessage, JsonRpcRequest,
    JsonRpcResponse, LegacyContent, LegacyPromptMessage, LegacyResourceContent, ListPromptsParams,
    ListResourceTemplatesParams, ListResourcesParams, ListToolsParams, LogLevel, LogMessageParams,
    PROTOCOL_VERSION, ProgressMarker, Prompt, PromptArgument, ReadResourceParams, RequestId,
    RequestMeta, Resource, ResourceTemplate, RootsCapability, SamplingCapability,
    ServerCapabilities, ServerInfo, ServerNotification, SetLogLevelParams, SubscribeResourceParams,
    Tool, ToolAnnotations, UnsubscribeResourceParams, decode_strict_jsonrpc_response,
    task_subscription_ids,
};
use fastmcp_protocol::{
    ClientExtensionDiscovery, ExtensionDescriptorRegistry, ExtensionDirection, ExtensionSettings,
    ServerExtensionDiscovery,
};
use fastmcp_protocol::{SERVER_DISCOVER_METHOD, ServerDiscoverRequest, ServerDiscoverResult};

use crate::session::mcp_apps_activation_receipt;

/// Callback for receiving progress notifications during tool execution.
///
/// The callback receives the progress value, optional total, and optional message.
pub type ProgressCallback<'a> = &'a mut dyn FnMut(f64, Option<f64>, Option<&str>);

/// Handler for a server-initiated `sampling/createMessage` request.
pub type SamplingRequestHandler = Box<
    dyn FnMut(ReverseRequestCancellation, CreateMessageParams) -> McpResult<CreateMessageResult>
        + Send,
>;

/// Handler for a server-initiated `roots/list` request.
pub type RootsRequestHandler = Box<
    dyn FnMut(ReverseRequestCancellation, ListRootsParams) -> McpResult<ListRootsResult> + Send,
>;

/// Configurable handlers for reverse requests received from a live MCP server.
#[derive(Clone, Default)]
pub struct ReverseRequestHandlers {
    sampling_create_message: Option<Arc<Mutex<SamplingRequestHandler>>>,
    roots_list: Option<Arc<Mutex<RootsRequestHandler>>>,
}

impl ReverseRequestHandlers {
    /// Creates an empty handler set. Unconfigured methods receive `MethodNotFound`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sampling_create_message: None,
            roots_list: None,
        }
    }

    /// Configures handling for `sampling/createMessage`.
    #[must_use]
    pub fn with_sampling_create_message<F>(mut self, handler: F) -> Self
    where
        F: FnMut(ReverseRequestCancellation, CreateMessageParams) -> McpResult<CreateMessageResult>
            + Send
            + 'static,
    {
        self.sampling_create_message = Some(Arc::new(Mutex::new(Box::new(handler))));
        self
    }

    /// Configures handling for `roots/list`.
    #[must_use]
    pub fn with_roots_list<F>(mut self, handler: F) -> Self
    where
        F: FnMut(ReverseRequestCancellation, ListRootsParams) -> McpResult<ListRootsResult>
            + Send
            + 'static,
    {
        self.roots_list = Some(Arc::new(Mutex::new(Box::new(handler))));
        self
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.sampling_create_message.is_none() && self.roots_list.is_none()
    }

    /// Adds the exact 2024-11-05 client capabilities implied by these
    /// callbacks. Roots-list-change remains disabled because registering a
    /// roots handler does not authorize the client to originate change events.
    pub(crate) fn derive_legacy_capabilities(&self, capabilities: &mut ClientCapabilities) {
        if self.sampling_create_message.is_some() {
            capabilities.sampling.get_or_insert(SamplingCapability {});
        }
        if self.roots_list.is_some() {
            capabilities.roots.get_or_insert(RootsCapability {
                list_changed: false,
            });
        }
    }

    /// Ensures that an exact-2024 callback configuration and its advertised
    /// capabilities describe precisely the same server-callable surface.
    pub(crate) fn validate_legacy_capabilities(
        &self,
        capabilities: &ClientCapabilities,
    ) -> McpResult<()> {
        if self.sampling_create_message.is_some() != capabilities.sampling.is_some() {
            return Err(McpError::invalid_params(
                "MCP 2024-11-05 sampling callback configuration must match the advertised sampling capability",
            ));
        }
        match (&self.roots_list, &capabilities.roots) {
            (Some(_), Some(roots)) if !roots.list_changed => {}
            (Some(_), Some(_)) => {
                return Err(McpError::invalid_params(
                    "MCP 2024-11-05 reverse roots callbacks cannot advertise roots.listChanged",
                ));
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(McpError::invalid_params(
                    "MCP 2024-11-05 roots callback configuration must match the advertised roots capability",
                ));
            }
            (None, None) => {}
        }
        if capabilities.elicitation.is_some() {
            return Err(McpError::invalid_params(
                "MCP 2024-11-05 does not define an elicitation client capability",
            ));
        }
        Ok(())
    }
}
use fastmcp_transport::{
    StdioRecvHalf, StdioSendHalf, StdioTransport, Transport, TransportError, TransportRecvHalf,
    TransportSendHalf,
};

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

/// Responses supplied to one final model-request tool retry (MRTR).
///
/// Keys must name input requests from the immediately preceding
/// `input_required` result. Values remain JSON because the peer owns the
/// individual embedded-request schemas.
pub type MrtrInputResponses = BTreeMap<String, serde_json::Value>;

/// Maximum input responses accepted for one MRTR continuation.
///
/// This is an individual continuation bound. The multi-round stdio driver also
/// limits cumulative entries across the complete MRTR operation.
pub const MAX_MRTR_INPUT_RESPONSES: usize = 128;
/// Maximum `input_required` continuations for one stdio MRTR operation.
pub const MAX_MRTR_CONTINUATION_ROUNDS: usize = 4;
/// Maximum response entries admitted across every continuation in one MRTR operation.
pub const MAX_MRTR_TOTAL_INPUT_RESPONSES: usize = MAX_MRTR_INPUT_RESPONSES;

fn mrtr_retry_parameters(
    mut parameters: serde_json::Value,
    input_required: &InputRequiredResult,
    input_responses: MrtrInputResponses,
) -> McpResult<serde_json::Value> {
    if input_responses.len() > MAX_MRTR_INPUT_RESPONSES {
        return Err(McpError::invalid_params(format!(
            "MRTR inputResponses must not exceed {MAX_MRTR_INPUT_RESPONSES} entries",
        )));
    }

    let input_requests = input_required.input_requests();
    if input_requests.is_none() && !input_responses.is_empty() {
        return Err(McpError::invalid_params(
            "MRTR inputResponses require peer inputRequests",
        ));
    }
    if let Some(input_requests) = input_requests {
        for key in input_responses.keys() {
            if !input_requests
                .members()
                .iter()
                .any(|request| request.name == *key)
            {
                return Err(McpError::invalid_params(
                    "MRTR inputResponses contain a key not requested by the peer",
                ));
            }
        }
    }
    if input_responses.is_empty() && input_required.request_state().is_none() {
        return Err(McpError::invalid_params(
            "MRTR retry requires inputResponses or requestState",
        ));
    }

    let parameters = parameters
        .as_object_mut()
        .ok_or_else(|| McpError::internal_error("MRTR retry parameters must remain an object"))?;
    if !input_responses.is_empty() {
        parameters.insert(
            "inputResponses".to_owned(),
            serde_json::to_value(input_responses).map_err(|error| {
                McpError::internal_error(format!(
                    "MRTR inputResponses could not serialize: {error}"
                ))
            })?,
        );
    }
    if let Some(request_state) = input_required.request_state() {
        parameters.insert(
            "requestState".to_owned(),
            serde_json::Value::String(request_state.to_owned()),
        );
    }
    Ok(serde_json::Value::Object(parameters.clone()))
}

fn mrtr_input_required_for_method<'a>(
    method: &str,
    result: &'a CoreResult,
) -> Option<&'a InputRequiredResult> {
    match (method, result) {
        (
            "tools/call",
            CoreResult::Final(FinalCoreResult::ToolsCallInputRequired { result, .. }),
        )
        | (
            "resources/read",
            CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired { result, .. }),
        )
        | (
            "prompts/get",
            CoreResult::Final(FinalCoreResult::PromptsGetInputRequired { result, .. }),
        ) => Some(result),
        _ => None,
    }
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
    if !subscription_id.correlates_with(expected_id) {
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
        LogLevel::Notice => LoggingLevel::Notice,
        LogLevel::Warning => LoggingLevel::Warning,
        LogLevel::Error => LoggingLevel::Error,
        LogLevel::Critical => LoggingLevel::Critical,
        LogLevel::Alert => LoggingLevel::Alert,
        LogLevel::Emergency => LoggingLevel::Emergency,
    }
}

fn legacy_log_level(level: LoggingLevel) -> LogLevel {
    match level {
        LoggingLevel::Debug => LogLevel::Debug,
        LoggingLevel::Info => LogLevel::Info,
        LoggingLevel::Notice => LogLevel::Notice,
        LoggingLevel::Warning => LogLevel::Warning,
        LoggingLevel::Error => LogLevel::Error,
        LoggingLevel::Critical => LogLevel::Critical,
        LoggingLevel::Alert => LogLevel::Alert,
        LoggingLevel::Emergency => LogLevel::Emergency,
    }
}

const DEFAULT_CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CLIENT_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_CLIENT_IDLE_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_CLIENT_ABSOLUTE_TIMEOUT: Duration = Duration::from_mins(15);
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

    fn cap_absolute_at(&mut self, deadline: Instant) {
        self.absolute = self.absolute.min(deadline);
    }
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
    if request.id.is_none() {
        return None;
    }
    if request.method.starts_with("notifications/") {
        return invalid_notification_request_response(request);
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
    handler: &mut dyn FnMut(ReverseRequestCancellation, P) -> McpResult<R>,
    cancellation: ReverseRequestCancellation,
    params: P,
) -> McpResult<R> {
    catch_client_callback_unwind(|| handler(cancellation, params))
        .map_err(|_| McpError::internal_error("Client reverse request handler failed"))?
}

fn invoke_locked_reverse_request_handler<P, R>(
    handler: &Arc<Mutex<Box<dyn FnMut(ReverseRequestCancellation, P) -> McpResult<R> + Send>>>,
    cancellation: ReverseRequestCancellation,
    params: P,
) -> McpResult<R> {
    let mut handler = handler
        .lock()
        .map_err(|_| McpError::internal_error("Client reverse request handler failed"))?;
    // The worker can wait behind another callback invocation. Cancellation
    // received during that wait must win before this handler gets any effect.
    cancellation.checkpoint()?;
    invoke_reverse_request_handler(handler.as_mut(), cancellation, params)
}

const MAX_REVERSE_CALLBACK_WORKERS: usize = 4;
const MAX_QUEUED_REVERSE_CALLBACKS: usize = 16;
const REVERSE_CALLBACK_POLL_SLICE: Duration = Duration::from_millis(10);
const REVERSE_CALLBACK_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(250);
const REVERSE_CALLBACK_SHUTDOWN_TIMEOUT_ERROR: &str =
    "Client reverse callback workers did not stop within the shutdown bound";

struct ActiveReverseCallback {
    request_id: RequestId,
    cancellation: ReverseRequestCancellation,
}

/// Transport-neutral ownership and cancellation registry for exact-2024
/// server-to-client callbacks.
///
/// Each transport owns its dispatch and response-write mechanics, but all of
/// them must share these admission and response-vs-cancellation rules.
#[derive(Default)]
pub(crate) struct ReverseCallbackState {
    closing: AtomicBool,
    active: Mutex<Vec<ActiveReverseCallback>>,
    terminal_error: Mutex<Option<McpError>>,
}

impl ReverseCallbackState {
    pub(crate) fn admit(&self, request_id: &RequestId) -> McpResult<ReverseRequestCancellation> {
        if let Some(error) = self.terminal_error() {
            return Err(error);
        }
        let mut active = self
            .active
            .lock()
            .map_err(|_| McpError::internal_error("Client reverse callback registry failed"))?;
        if self.closing.load(Ordering::Acquire) {
            return Err(McpError::internal_error(
                "Client reverse callback dispatcher is closed",
            ));
        }
        if active.len() >= MAX_QUEUED_REVERSE_CALLBACKS {
            return Err(McpError::internal_error(
                "Client reverse callback capacity exceeded",
            ));
        }
        if active
            .iter()
            .any(|callback| callback.request_id.correlates_with(request_id))
        {
            return Err(McpError::invalid_request(
                "Duplicate live reverse callback request ID",
            ));
        }
        let cancellation = ReverseRequestCancellation::new();
        active.push(ActiveReverseCallback {
            request_id: request_id.clone(),
            cancellation: cancellation.clone(),
        });
        Ok(cancellation)
    }

    pub(crate) fn cancel(&self, request_id: &RequestId) -> bool {
        let active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut cancelled = false;
        for callback in active.iter() {
            if callback.request_id.correlates_with(request_id) {
                callback.cancellation.cancel();
                cancelled = true;
            }
        }
        cancelled
    }

    pub(crate) fn complete(&self, request_id: &RequestId) {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        active.retain(|callback| !callback.request_id.correlates_with(request_id));
    }

    /// Claims the one response write while ordering it against a cancellation
    /// already admitted by the sole receive loop.
    ///
    /// The claim is deliberately made before a protocol-sized transport write
    /// and releases this registry lock before that write can block. This keeps
    /// cancellation reception independent of a full child-stdin pipe while
    /// preserving the response-vs-cancellation linearization point.
    pub(crate) fn claim_response_if_open(
        &self,
        request_id: &RequestId,
        cancellation: &ReverseRequestCancellation,
    ) -> bool {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.closing.load(Ordering::Acquire)
            || !active.iter().any(|callback| {
                callback.request_id.correlates_with(request_id)
                    && callback.cancellation.belongs_to_same_request(cancellation)
            })
            || !cancellation.is_open()
        {
            return false;
        }

        cancellation.record_response_sent();
        active.retain(|callback| !callback.request_id.correlates_with(request_id));
        true
    }

    pub(crate) fn cancel_all(&self) {
        let active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.closing.store(true, Ordering::Release);
        for callback in active.iter() {
            callback.cancellation.cancel();
        }
    }

    pub(crate) fn fail_connection(&self, error: McpError) {
        {
            let mut terminal_error = self
                .terminal_error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if terminal_error.is_none() {
                *terminal_error = Some(error);
            }
        }
        self.cancel_all();
    }

    pub(crate) fn terminal_error(&self) -> Option<McpError> {
        self.terminal_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

struct ReverseCallbackJob {
    request_id: RequestId,
    cancellation: ReverseRequestCancellation,
    invoke: Box<dyn FnOnce() -> JsonRpcMessage + Send>,
}

struct ReverseCallbackPool {
    state: Arc<ReverseCallbackState>,
    sender: Option<mpsc::SyncSender<ReverseCallbackJob>>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

/// Performs the elected reverse response write.
///
/// Callback frames use the ordinary framed transport path, rather than the
/// 512-byte atomic control path reserved for cancellation controls. The
/// codec's normal bounded frame limit therefore applies to full MCP sampling
/// and roots results. A failed write is terminal because framing disposition
/// is no longer recoverable.
fn commit_reverse_callback_response(
    state: &ReverseCallbackState,
    request_id: &RequestId,
    response_sender: &Arc<Mutex<StdioSendHalf<ChildStdin>>>,
    cx: &Cx,
    cancellation: &ReverseRequestCancellation,
    response: &JsonRpcMessage,
) -> Result<bool, TransportError> {
    let mut sender = response_sender.lock().map_err(|_| TransportError::Closed)?;
    if !state.claim_response_if_open(request_id, cancellation) {
        return Ok(false);
    }
    sender.send(cx, response)?;
    Ok(true)
}

impl ReverseCallbackPool {
    fn new(response_sender: Arc<Mutex<StdioSendHalf<ChildStdin>>>, cx: Cx) -> Self {
        let state = Arc::new(ReverseCallbackState::default());
        let (sender, receiver) =
            mpsc::sync_channel::<ReverseCallbackJob>(MAX_QUEUED_REVERSE_CALLBACKS);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(MAX_REVERSE_CALLBACK_WORKERS);
        for _ in 0..MAX_REVERSE_CALLBACK_WORKERS {
            let worker_state = Arc::clone(&state);
            let worker_receiver = Arc::clone(&receiver);
            let worker_sender = Arc::clone(&response_sender);
            let worker_cx = cx.clone();
            workers.push(std::thread::spawn(move || {
                loop {
                    let job = match worker_receiver
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .recv()
                    {
                        Ok(job) => job,
                        Err(_) => return,
                    };
                    if worker_state.closing.load(Ordering::Acquire)
                        || job.cancellation.is_cancel_requested()
                    {
                        worker_state.complete(&job.request_id);
                        continue;
                    }
                    let response = (job.invoke)();
                    if worker_state.closing.load(Ordering::Acquire) {
                        worker_state.complete(&job.request_id);
                        continue;
                    }
                    match commit_reverse_callback_response(
                        &worker_state,
                        &job.request_id,
                        &worker_sender,
                        &worker_cx,
                        &job.cancellation,
                        &response,
                    ) {
                        Ok(false) => {
                            worker_state.complete(&job.request_id);
                            continue;
                        }
                        Ok(true) => {}
                        Err(error) => {
                            worker_state.fail_connection(transport_error_to_mcp(error));
                            worker_state.complete(&job.request_id);
                            return;
                        }
                    }
                }
            }));
        }
        Self {
            state,
            sender: Some(sender),
            workers,
        }
    }

    fn dispatch<P, R>(
        &self,
        request_id: RequestId,
        params: P,
        handler: Arc<Mutex<Box<dyn FnMut(ReverseRequestCancellation, P) -> McpResult<R> + Send>>>,
    ) -> McpResult<()>
    where
        P: Send + 'static,
        R: serde::Serialize + Send + 'static,
    {
        let cancellation = self.state.admit(&request_id)?;
        let invoke_cancellation = cancellation.clone();
        let response_id = request_id.clone();
        let job = ReverseCallbackJob {
            request_id: request_id.clone(),
            cancellation,
            invoke: Box::new(move || {
                let result =
                    invoke_locked_reverse_request_handler(&handler, invoke_cancellation, params);
                reverse_request_response(response_id, result)
            }),
        };
        let Some(sender) = self.sender.as_ref() else {
            self.state.complete(&request_id);
            return Err(McpError::internal_error(
                "Client reverse callback dispatcher is closed",
            ));
        };
        match sender.try_send(job) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(_)) => {
                self.state.complete(&request_id);
                Err(McpError::internal_error(
                    "Client reverse callback capacity exceeded",
                ))
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.state.complete(&request_id);
                Err(McpError::internal_error(
                    "Client reverse callback dispatcher is closed",
                ))
            }
        }
    }

    fn cancel(&self, request_id: &RequestId) -> bool {
        self.state.cancel(request_id)
    }

    fn cancel_all(&self) {
        self.state.cancel_all();
    }

    /// Joins finished callback workers without permitting an uncooperative
    /// synchronous callback to make explicit connection shutdown unbounded.
    ///
    /// A timed-out worker remains owned by this pool for a later `close` retry
    /// (and for `Drop`'s definitive join); it is never detached.
    fn join_bounded(&mut self) -> McpResult<()> {
        self.sender.take();
        let deadline = Instant::now()
            .checked_add(REVERSE_CALLBACK_SHUTDOWN_TIMEOUT)
            .unwrap_or_else(Instant::now);
        loop {
            let mut unfinished = Vec::new();
            for worker in std::mem::take(&mut self.workers) {
                if worker.is_finished() {
                    let _ = worker.join();
                } else {
                    unfinished.push(worker);
                }
            }
            self.workers = unfinished;
            if self.workers.is_empty() {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(McpError::internal_error(
                    REVERSE_CALLBACK_SHUTDOWN_TIMEOUT_ERROR,
                ));
            }
            std::thread::sleep((deadline - now).min(REVERSE_CALLBACK_POLL_SLICE));
        }
    }

    fn join_unbounded(&mut self) {
        self.sender.take();
        for worker in std::mem::take(&mut self.workers) {
            let _ = worker.join();
        }
    }

    fn close_unbounded(&mut self) {
        self.cancel_all();
        self.join_unbounded();
    }
}

impl Drop for ReverseCallbackPool {
    fn drop(&mut self) {
        self.close_unbounded();
    }
}

enum LiveServerRequestDispatch {
    Immediate(JsonRpcMessage),
    CallbackAdmitted,
}

fn live_server_request_dispatch(
    selected_era: Option<ProtocolEra>,
    handlers: &ReverseRequestHandlers,
    callbacks: &ReverseCallbackPool,
    request: &JsonRpcRequest,
) -> Option<LiveServerRequestDispatch> {
    let id = request.id.clone()?;
    if request.method.starts_with("notifications/") {
        return invalid_notification_request_response(request)
            .map(LiveServerRequestDispatch::Immediate);
    }
    if request.method == "ping" && selected_era == Some(ProtocolEra::Legacy2024) {
        return Some(LiveServerRequestDispatch::Immediate(
            JsonRpcMessage::Response(JsonRpcResponse::success(id, serde_json::json!({}))),
        ));
    }

    // Sampling and roots are the only server-to-client reverse requests in
    // exact MCP 2024-11-05. A final session must not silently keep servicing
    // either method merely because a caller configured legacy callbacks on the
    // client object.
    if selected_era != Some(ProtocolEra::Legacy2024)
        && matches!(
            request.method.as_str(),
            "sampling/createMessage" | "roots/list"
        )
    {
        return method_not_found_response(request).map(LiveServerRequestDispatch::Immediate);
    }

    let dispatch = match request.method.as_str() {
        "sampling/createMessage" => match handlers.sampling_create_message.as_ref() {
            Some(handler) => match decode_reverse_request_params(request) {
                Ok(params) => callbacks
                    .dispatch(id.clone(), params, Arc::clone(handler))
                    .map_or_else(
                        |error| {
                            LiveServerRequestDispatch::Immediate(reverse_request_response::<
                                CreateMessageResult,
                            >(
                                id, Err(error)
                            ))
                        },
                        |_| LiveServerRequestDispatch::CallbackAdmitted,
                    ),
                Err(error) => {
                    LiveServerRequestDispatch::Immediate(reverse_request_response::<
                        CreateMessageResult,
                    >(id, Err(error)))
                }
            },
            None => LiveServerRequestDispatch::Immediate(reverse_request_response::<
                CreateMessageResult,
            >(
                id,
                Err(McpError::method_not_found("sampling/createMessage")),
            )),
        },
        "roots/list" => match handlers.roots_list.as_ref() {
            Some(handler) => match decode_reverse_request_params(request) {
                Ok(params) => callbacks
                    .dispatch(id.clone(), params, Arc::clone(handler))
                    .map_or_else(
                        |error| {
                            LiveServerRequestDispatch::Immediate(reverse_request_response::<
                                ListRootsResult,
                            >(
                                id, Err(error)
                            ))
                        },
                        |_| LiveServerRequestDispatch::CallbackAdmitted,
                    ),
                Err(error) => {
                    LiveServerRequestDispatch::Immediate(
                        reverse_request_response::<ListRootsResult>(id, Err(error)),
                    )
                }
            },
            None => {
                LiveServerRequestDispatch::Immediate(reverse_request_response::<ListRootsResult>(
                    id,
                    Err(McpError::method_not_found("roots/list")),
                ))
            }
        },
        _ => return method_not_found_response(request).map(LiveServerRequestDispatch::Immediate),
    };
    Some(dispatch)
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

fn raw_notification_params_from_frame(frame: &[u8]) -> McpResult<Option<String>> {
    #[derive(serde::Deserialize)]
    struct RawNotificationEnvelope {
        #[serde(default)]
        params: Option<Box<serde_json::value::RawValue>>,
    }

    serde_json::from_slice::<RawNotificationEnvelope>(frame)
        .map(|envelope| envelope.params.map(|params| params.get().to_owned()))
        .map_err(|_| McpError::invalid_request("Client could not retain raw notification params"))
}

fn decode_final_server_notification(
    request: &JsonRpcRequest,
    raw_params: Option<&str>,
) -> Result<ServerNotification, fastmcp_protocol::FinalNotificationError> {
    match raw_params {
        Some(raw_params) => ServerNotification::decode_with_raw_params(request, raw_params),
        None => ServerNotification::decode(request),
    }
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

fn final_log_message_sink_projection(message: &FinalLogMessageParams) -> LogMessageParams {
    let level = match message.level {
        LoggingLevel::Debug => LogLevel::Debug,
        LoggingLevel::Info => LogLevel::Info,
        LoggingLevel::Notice => LogLevel::Notice,
        LoggingLevel::Warning => LogLevel::Warning,
        LoggingLevel::Error => LogLevel::Error,
        LoggingLevel::Critical => LogLevel::Critical,
        LoggingLevel::Alert => LogLevel::Alert,
        LoggingLevel::Emergency => LogLevel::Emergency,
    };
    LogMessageParams {
        level,
        logger: message.logger.clone(),
        data: message.data.clone(),
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
    let peer_code = error.code;
    let local_code = peer_code.as_i32();
    let code = local_code
        .map(McpErrorCode::from)
        .unwrap_or(McpErrorCode::InternalError);
    let data = if !local_code.is_some_and(|local_code| peer_code.as_str() == local_code.to_string())
    {
        // `McpErrorCode` is deliberately an i32 surface. Keep an unbounded
        // or noncanonical peer JSON-RPC integer as a local diagnostic rather
        // than truncating it, normalizing its spelling, or silently
        // manufacturing a different custom code. Preserve the peer's own
        // error data as a distinct value even when it is not an object.
        Some(serde_json::json!({
            "jsonrpcErrorCode": peer_code,
            "jsonrpcErrorData": error.data,
        }))
    } else {
        error.data
    };
    match data {
        Some(data) => McpError::with_data(code, error.message, data),
        None => McpError::new(code, error.message),
    }
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
    ttl_ms: &fastmcp_protocol::CacheTtl,
    cache_scope: fastmcp_protocol::CacheScope,
) -> McpResult<()> {
    if ttl_ms.try_as_millis() == Ok(0) && cache_scope == fastmcp_protocol::CacheScope::Private {
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
            ensure_legacy_cache_projection(&ttl_ms, cache_scope)?;
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
            ensure_legacy_cache_projection(&ttl_ms, cache_scope)?;
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
            ensure_legacy_cache_projection(&ttl_ms, cache_scope)?;
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
            ensure_legacy_cache_projection(&ttl_ms, cache_scope)?;
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
            ensure_legacy_cache_projection(&ttl_ms, cache_scope)?;
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
    // Auto reaches this predicate only after its disposable modern
    // `server/discover` probe. A JSON-RPC MethodNotFound response is the sole
    // recognized refusal that establishes the peer does not implement that
    // method. Generic parsing or parameter errors remain peer errors and must
    // surface without starting a legacy child.
    error.code == McpErrorCode::MethodNotFound
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
    transport: &mut StdioRecvHalf<ChildStdout>,
    cx: &Cx,
    deadline: Option<Instant>,
) -> Result<(JsonRpcMessage, Instant), TransportError> {
    transport
        .recv_until_or_closed(cx, deadline)
        .map(|message| (message, Instant::now()))
}

fn recv_shared_child_transport(
    transport: &Arc<Mutex<StdioRecvHalf<ChildStdout>>>,
    cx: &Cx,
    deadline: Option<Instant>,
) -> Result<(JsonRpcMessage, Instant), TransportError> {
    let mut receiver = transport.lock().map_err(|_| TransportError::Closed)?;
    recv_child_transport(&mut receiver, cx, deadline)
}

#[cfg(unix)]
fn recv_initializing_child_transport(
    transport: &mut StdioTransport<ChildStdout, ChildStdin>,
    cx: &Cx,
    deadline: Option<Instant>,
) -> Result<(JsonRpcMessage, Instant), TransportError> {
    transport.recv_until_with_completion(cx, deadline)
}

#[cfg(not(unix))]
fn recv_initializing_child_transport(
    transport: &mut StdioTransport<ChildStdout, ChildStdin>,
    cx: &Cx,
    deadline: Option<Instant>,
) -> Result<(JsonRpcMessage, Instant), TransportError> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(TransportError::ReceiveDeadlineExceeded);
    }
    transport.recv_with_completion(cx)
}

#[cfg(not(unix))]
fn recv_child_transport(
    transport: &mut StdioRecvHalf<ChildStdout>,
    cx: &Cx,
    deadline: Option<Instant>,
) -> Result<(JsonRpcMessage, Instant), TransportError> {
    // std::process::ChildStdout exposes no portable safe readiness primitive.
    // Keep the limitation explicit: non-Unix cancellation/deadlines are
    // observed at frame boundaries, but cannot interrupt a blocking pipe read.
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(TransportError::ReceiveDeadlineExceeded);
    }
    transport.recv(cx).map(|message| (message, Instant::now()))
}

#[cfg(unix)]
fn send_child_server_response_during_receive(
    transport: &Arc<Mutex<StdioSendHalf<ChildStdin>>>,
    _cx: &Cx,
    message: &JsonRpcMessage,
) -> McpResult<()> {
    transport
        .lock()
        .map_err(|_| McpError::internal_error("Client stdio response writer failed"))?
        .try_send_control_message(message)
        .map_err(transport_error_to_mcp)
}

#[cfg(not(unix))]
fn send_child_server_response_during_receive(
    transport: &Arc<Mutex<StdioSendHalf<ChildStdin>>>,
    cx: &Cx,
    message: &JsonRpcMessage,
) -> McpResult<()> {
    // Standard child pipes expose no portable nonblocking write on this path.
    // Preserve frame-boundary behavior explicitly; the caller abandons the
    // connection if this send itself fails.
    transport
        .lock()
        .map_err(|_| McpError::internal_error("Client stdio response writer failed"))?
        .send(cx, message)
        .map_err(transport_error_to_mcp)
}

fn stdio_cancellation_control_message(
    peer_era: ProtocolEra,
    request_id: &RequestId,
) -> McpResult<JsonRpcMessage> {
    let cancellation = match peer_era {
        ProtocolEra::Legacy2024 => CancellationWireMessage::Legacy2024 {
            sender: CancellationSender::Client,
            params: CancelledParams {
                request_id: request_id.clone(),
                reason: None,
            },
        },
        ProtocolEra::Modern2026 => CancellationWireMessage::Modern2026 {
            sender: CancellationSender::Client,
            params: FinalCancelledNotificationParams {
                request_id: request_id.clone(),
                reason: None,
                meta: None,
                additional: Default::default(),
            },
        },
    };
    cancellation
        .encode()
        .map(JsonRpcMessage::Request)
        .map_err(|error| {
            McpError::invalid_params(format!("Invalid cancellation control parameters: {error}"))
        })
}

#[cfg(unix)]
fn send_initializing_child_server_response(
    transport: &mut StdioTransport<ChildStdout, ChildStdin>,
    _cx: &Cx,
    message: &JsonRpcMessage,
) -> McpResult<()> {
    transport
        .try_send_control_message(message)
        .map_err(transport_error_to_mcp)
}

#[cfg(not(unix))]
fn send_initializing_child_server_response(
    transport: &mut StdioTransport<ChildStdout, ChildStdin>,
    cx: &Cx,
    message: &JsonRpcMessage,
) -> McpResult<()> {
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
        let (message, received_at) = recv_initializing_child_transport(
            transport,
            cx,
            Some(deadlines.next()),
        )
        .map_err(|error| match error {
            TransportError::ReceiveDeadlineExceeded => request_timeout_error(deadlines.next_kind()),
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
                    send_initializing_child_server_response(transport, cx, &response)?;
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
        LogLevel::Notice => "notice",
        LogLevel::Warning => "warning",
        LogLevel::Error => "error",
        LogLevel::Critical => "critical",
        LogLevel::Alert => "alert",
        LogLevel::Emergency => "emergency",
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
    /// Live local owners whose one permitted cancellation control has been
    /// claimed. This remains distinct from response tombstones so a timeout
    /// can retain its late-response guard after its outbound control write.
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
        // A new local owner begins a fresh cancellation-control generation.
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

    /// Returns whether this client currently owns a live request ID.
    fn owns_live_request(&mut self, id: &RequestId) -> McpResult<bool> {
        self.prune_expired_retained_state(Instant::now());
        if let Some(terminal_error) = &self.terminal_error {
            return Err(terminal_error.clone());
        }
        let key = id
            .correlation_key()
            .map_err(|_| McpError::internal_error("Invalid JSON-RPC request ID"))?;
        Ok(self.pending.contains_key(&key))
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

/// Shared ownership of the one stdio response-correlation registry.
///
/// Request commitment may occur through a cloneable negotiated executor, but
/// all response delivery still belongs to the client's sole ingress arbiter.
#[derive(Clone, Default)]
struct SharedResponseRegistry(Arc<Mutex<ResponseRegistry>>);

impl std::fmt::Debug for SharedResponseRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_tuple("SharedResponseRegistry").finish()
    }
}

impl SharedResponseRegistry {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(ResponseRegistry::new())))
    }

    fn lock(&self) -> McpResult<std::sync::MutexGuard<'_, ResponseRegistry>> {
        self.0
            .lock()
            .map_err(|_| McpError::internal_error("Client response registry is unavailable"))
    }

    fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    fn register(&self, id: RequestId) -> McpResult<ResponseWaiter> {
        self.lock()?.register(id)
    }

    #[cfg(test)]
    fn route(&self, response: JsonRpcResponse) -> ResponseRoute {
        self.lock()
            .map_or(ResponseRoute::ConnectionClosed, |mut registry| {
                registry.route(response)
            })
    }

    fn route_with_raw_result(
        &self,
        response: JsonRpcResponse,
        raw_result: Option<String>,
    ) -> ResponseRoute {
        self.lock()
            .map_or(ResponseRoute::ConnectionClosed, |mut registry| {
                registry.route_with_raw_result(response, raw_result)
            })
    }

    fn fail(&self, id: &RequestId, error: McpError) -> bool {
        self.lock()
            .is_ok_and(|mut registry| registry.fail(id, error))
    }

    fn tombstone(&self, id: &RequestId, error: McpError) -> McpResult<bool> {
        self.lock()?.tombstone(id, error)
    }

    fn claim_cancellation_control(&self, id: &RequestId) -> McpResult<bool> {
        self.lock()?.claim_cancellation_control(id)
    }

    fn owns_live_request(&self, id: &RequestId) -> McpResult<bool> {
        self.lock()?.owns_live_request(id)
    }

    fn fail_all(&self, error: McpError) -> usize {
        self.lock()
            .map_or(0, |mut registry| registry.fail_all(error))
    }

    fn terminal_error(&self) -> Option<McpError> {
        self.lock()
            .ok()
            .and_then(|registry| registry.terminal_error())
    }

    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.lock().map_or(0, |registry| registry.pending_len())
    }

    #[cfg(test)]
    fn tombstone_len(&self) -> usize {
        self.lock().map_or(0, |registry| registry.tombstone_len())
    }

    #[cfg(test)]
    fn cancellation_control_len(&self) -> usize {
        self.lock()
            .map_or(0, |registry| registry.cancellation_control_len())
    }

    #[cfg(test)]
    fn uncorrelated_diagnostics(&self) -> u8 {
        self.lock()
            .map_or(0, |registry| registry.uncorrelated_diagnostics)
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

impl From<McpError> for HttpClientError {
    fn from(error: McpError) -> Self {
        Self::CoreResult(error)
    }
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

/// A live final HTTP subscription listener bound to one [`HttpClient`] cache.
///
/// Each accepted catalog or resource event advances the owning client's cache
/// generation before [`Self::next_event`] returns it. The listener holds the
/// cache borrow for its lifetime, so callers cannot issue a cacheable request
/// against the same client between receiving an event and observing its
/// invalidation.
pub struct HttpSubscriptionListener<'client> {
    listener: ModernHttpSubscriptionListener,
    final_result_cache: &'client mut FinalResultCache,
}

impl HttpSubscriptionListener<'_> {
    /// Returns the JSON-RPC request ID that owns this listener.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        self.listener.request_id()
    }

    /// Returns the acknowledged filter once the first stream record is admitted.
    #[must_use]
    pub const fn accepted_filter(&self) -> Option<&SubscriptionFilter> {
        self.listener.accepted_filter()
    }

    /// Returns the current cache counters while this listener owns the cache.
    #[must_use]
    pub const fn final_result_cache_stats(&self) -> FinalCacheStats {
        self.final_result_cache.stats()
    }

    /// Reads one live subscription record and immediately invalidates accepted
    /// catalog or resource result sets before yielding that record.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ModernHttpSubscriptionListenEvent>, HttpClientError> {
        let event = self.listener.next_event(cx).await.map_err(|error| {
            HttpClientError::Connection(ClientHttpConnectionError::SubscriptionsListen(error))
        })?;
        if let Some(ModernHttpSubscriptionListenEvent::Notification(notification)) = event.as_ref()
        {
            self.final_result_cache
                .invalidate_notification(notification);
        }
        Ok(event)
    }

    /// Collects the remaining live records into the established terminal record.
    pub async fn collect(
        mut self,
        cx: &Cx,
    ) -> Result<ModernHttpSubscriptionListenCollector, HttpClientError> {
        let mut notifications = Vec::new();
        let mut task_notifications = Vec::new();

        loop {
            let event = self.next_event(cx).await?.ok_or_else(|| {
                HttpClientError::CoreResult(McpError::invalid_request(
                    "HTTP subscriptions listener ended after its terminal result",
                ))
            })?;
            match event {
                ModernHttpSubscriptionListenEvent::Acknowledged { .. } => {}
                ModernHttpSubscriptionListenEvent::Notification(notification) => {
                    notifications.push(notification);
                }
                ModernHttpSubscriptionListenEvent::TaskNotification(notification) => {
                    task_notifications.push(notification);
                }
                ModernHttpSubscriptionListenEvent::Terminal {
                    subscription_id,
                    result: terminal,
                } => {
                    let accepted_filter =
                        self.listener.accepted_filter().cloned().ok_or_else(|| {
                            HttpClientError::CoreResult(McpError::invalid_request(
                                "HTTP subscriptions listener terminated before acknowledgement",
                            ))
                        })?;
                    return Ok(ModernHttpSubscriptionListenCollector {
                        subscription_id,
                        accepted_filter,
                        notifications,
                        task_notifications,
                        terminal,
                    });
                }
            }
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
        Self::connect_with_mcp_apps(
            cx,
            protocol_plan,
            client_info,
            client_capabilities,
            None,
            ReverseRequestHandlers::new(),
        )
        .await
    }

    pub(crate) async fn connect_with_mcp_apps(
        cx: &Cx,
        protocol_plan: ClientProtocolPlan,
        client_info: ClientInfo,
        mut client_capabilities: ClientCapabilities,
        mcp_apps_settings: Option<McpAppsClientSettings>,
        reverse_request_handlers: ReverseRequestHandlers,
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

        // Legacy callbacks are part of the capability set advertised by
        // `initialize`, so they must be installed before the lifecycle sends
        // that request. Auto reaches this same branch only after it has
        // selected the exact legacy SSE route; modern never receives these
        // legacy method handlers.
        if connection.selected_protocol_era() == ProtocolEra::Legacy2024 {
            reverse_request_handlers.derive_legacy_capabilities(&mut client_capabilities);
            connection.set_legacy_client_capabilities(client_capabilities.clone());
            if !reverse_request_handlers.is_empty() {
                connection
                    .set_legacy_reverse_request_handlers(reverse_request_handlers)
                    .map_err(HttpClientError::CoreResult)?;
            }
        }

        let (server_info, legacy_server_capabilities) = match connection.selected_protocol_era() {
            ProtocolEra::Modern2026 => {
                let server_info = connection
                    .server_discovery()
                    .and_then(|discovery| discovery.server_info().cloned())
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
                connection
                    .start_legacy_receive_pump(cx)
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

    fn current_mcp_apps_activation_receipt(
        &self,
    ) -> Option<fastmcp_protocol::extensions::McpAppsActivationReceipt> {
        self.connection.server_discovery().and_then(|discovery| {
            mcp_apps_activation_receipt(self.mcp_apps_settings.as_ref(), &discovery)
        })
    }

    /// Starts one browser-agnostic Apps Host for a negotiated modern connection.
    /// The embedder owns the View carrier and rendering policy.
    pub fn mcp_apps_host<T, P>(
        &self,
        transport: T,
        configuration: McpAppsHostConfiguration,
        policy: P,
    ) -> Result<McpAppsHost<T, P>, McpAppsHostError>
    where
        T: McpAppsBridgeTransport,
        P: McpAppsHostPolicy,
    {
        let activation_receipt = self.current_mcp_apps_activation_receipt();
        let activation_proof =
            mcp_apps::McpAppsActivationProof::from_activation_receipt(activation_receipt.as_ref())?;
        Ok(McpAppsHost::new_negotiated(
            transport,
            configuration,
            policy,
            activation_proof,
        ))
    }

    /// Starts the closed JSON-RPC Apps bridge on this ready modern HTTP
    /// connection. Reused View methods allocate fresh HTTP core request IDs.
    pub fn mcp_apps_wire_host<'client, T>(
        &'client mut self,
        transport: T,
        configuration: mcp_apps::McpAppsWireHostConfiguration,
    ) -> Result<
        mcp_apps::McpAppsWireHost<T, mcp_apps::McpAppsHttpClientWirePolicy<'client>>,
        McpAppsHostError,
    >
    where
        T: mcp_apps::McpAppsWireBridgeTransport,
    {
        let activation_receipt = self.current_mcp_apps_activation_receipt();
        let activation_proof =
            mcp_apps::McpAppsActivationProof::from_activation_receipt(activation_receipt.as_ref())?;
        Ok(mcp_apps::McpAppsWireHost::new_negotiated(
            transport,
            configuration,
            mcp_apps::McpAppsHttpClientWirePolicy::new(self),
            activation_proof,
        ))
    }

    async fn forward_mcp_apps_reused_core(
        &mut self,
        cx: &Cx,
        method: fastmcp_protocol::McpAppsRoutedMethod,
        params: Option<serde_json::Value>,
    ) -> McpResult<serde_json::Value> {
        if cx.checkpoint().is_err() {
            return Err(McpError::request_cancelled());
        }
        if !self.mcp_apps_active() {
            return Err(McpError::invalid_request(
                "MCP Apps reused methods require the current bilateral activation receipt",
            ));
        }
        let (core_method, parameters) = match method {
            fastmcp_protocol::McpAppsRoutedMethod::ToolsCall => (
                "tools/call",
                params.ok_or_else(|| {
                    McpError::invalid_params("Apps tools/call is missing parameters")
                })?,
            ),
            fastmcp_protocol::McpAppsRoutedMethod::ResourcesRead => (
                "resources/read",
                params.ok_or_else(|| {
                    McpError::invalid_params("Apps resources/read is missing parameters")
                })?,
            ),
            fastmcp_protocol::McpAppsRoutedMethod::ResourcesList => (
                "resources/list",
                params.unwrap_or_else(|| serde_json::json!({})),
            ),
            fastmcp_protocol::McpAppsRoutedMethod::ResourceTemplatesList => (
                "resources/templates/list",
                params.unwrap_or_else(|| serde_json::json!({})),
            ),
            fastmcp_protocol::McpAppsRoutedMethod::PromptsList => (
                "prompts/list",
                params.unwrap_or_else(|| serde_json::json!({})),
            ),
            _ => {
                return Err(McpError::invalid_params(
                    "Apps method is not a direction-correct standard-reused core request",
                ));
            }
        };
        let result = self
            .request_final_core(cx, core_method, parameters)
            .await
            .map_err(|error| McpError::invalid_request(error.to_string()))?;
        mcp_apps::project_reused_core_result(method, result)
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
    pub fn server_discovery(&self) -> Option<ServerDiscoverResult> {
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

    /// Pops one exact-2024 server notification received after this HTTP client
    /// became ready. The ready legacy SSE receiver drains these independently
    /// of ordinary client requests; modern HTTP has no shared legacy stream.
    #[must_use]
    pub fn take_legacy_notification(&mut self) -> Option<JsonRpcRequest> {
        self.connection.take_legacy_notification()
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

    fn next_mrtr_request_id(&self) -> McpResult<RequestId> {
        self.next_request_id().map_err(|error| match error {
            HttpClientError::RequestIdExhausted => {
                McpError::internal_error("HTTP client request IDs are exhausted")
            }
            _ => McpError::internal_error("HTTP client could not allocate an MRTR request ID"),
        })
    }

    fn require_terminal_http_mrtr_result(
        &self,
        method: &'static str,
        result: CoreResult,
    ) -> Result<FinalCoreResult, HttpClientError> {
        match (method, result) {
            ("tools/call", CoreResult::Final(result @ FinalCoreResult::ToolsCall { .. }))
            | (
                "resources/read",
                CoreResult::Final(result @ FinalCoreResult::ResourcesRead { .. }),
            )
            | ("prompts/get", CoreResult::Final(result @ FinalCoreResult::PromptsGet { .. })) => {
                Ok(result)
            }
            (
                "tools/call",
                CoreResult::Final(
                    FinalCoreResult::ToolsCallInputRequired { .. }
                    | FinalCoreResult::ToolsCallTask { .. },
                ),
            )
            | (
                "resources/read",
                CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired { .. }),
            )
            | ("prompts/get", CoreResult::Final(FinalCoreResult::PromptsGetInputRequired { .. })) => {
                Err(HttpClientError::CoreResult(McpError::invalid_request(
                    format!("ordinary HTTP MRTR {method} ended without a terminal result"),
                )))
            }
            (_, CoreResult::Legacy(_)) => Err(HttpClientError::CoreResult(
                McpError::invalid_request("ordinary HTTP MRTR requires a modern final result"),
            )),
            _ => Err(HttpClientError::CoreResult(McpError::invalid_request(
                format!("ordinary HTTP MRTR received an unexpected terminal result for {method}"),
            ))),
        }
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

    /// Calls a tool and, only when its first final result requires input,
    /// performs one MRTR retry with caller-supplied responses.
    ///
    /// This emits at most two requests. Exact MCP 2024-11-05 results and
    /// final complete or Tasks results are returned without invoking
    /// `respond`. A second `input_required` result is returned rather than
    /// retried again.
    pub async fn call_tool_with_mrtr_retry<F>(
        &mut self,
        cx: &Cx,
        name: &str,
        arguments: serde_json::Value,
        respond: F,
    ) -> Result<CoreResult, HttpClientError>
    where
        F: FnOnce(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
    {
        let parameters = serde_json::json!({
            "name": name,
            "arguments": arguments,
        });
        let result = self
            .request_final_core(cx, "tools/call", parameters.clone())
            .await?;
        let Some(input_required) = mrtr_input_required_for_method("tools/call", &result) else {
            return Ok(result);
        };
        let input_responses = respond(input_required).map_err(HttpClientError::CoreResult)?;
        let retry = mrtr_retry_parameters(parameters, input_required, input_responses)
            .map_err(HttpClientError::CoreResult)?;
        self.request_final_core(cx, "tools/call", retry).await
    }

    /// Reads a resource and, only when its first final result requires input,
    /// performs one MRTR retry with caller-supplied responses.
    ///
    /// This emits at most two requests; see [`Self::call_tool_with_mrtr_retry`]
    /// for the terminal-result behavior.
    pub async fn read_resource_with_mrtr_retry<F>(
        &mut self,
        cx: &Cx,
        uri: &str,
        respond: F,
    ) -> Result<CoreResult, HttpClientError>
    where
        F: FnOnce(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
    {
        let parameters = serde_json::json!({ "uri": uri });
        let result = self
            .request_final_core(cx, "resources/read", parameters.clone())
            .await?;
        let Some(input_required) = mrtr_input_required_for_method("resources/read", &result) else {
            return Ok(result);
        };
        let input_responses = respond(input_required).map_err(HttpClientError::CoreResult)?;
        let retry = mrtr_retry_parameters(parameters, input_required, input_responses)
            .map_err(HttpClientError::CoreResult)?;
        self.request_final_core(cx, "resources/read", retry).await
    }

    /// Gets a prompt and, only when its first final result requires input,
    /// performs one MRTR retry with caller-supplied responses.
    ///
    /// This emits at most two requests; see [`Self::call_tool_with_mrtr_retry`]
    /// for the terminal-result behavior.
    pub async fn get_prompt_with_mrtr_retry<F>(
        &mut self,
        cx: &Cx,
        name: &str,
        arguments: std::collections::HashMap<String, String>,
        respond: F,
    ) -> Result<CoreResult, HttpClientError>
    where
        F: FnOnce(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
    {
        let mut parameters = serde_json::json!({ "name": name });
        if !arguments.is_empty() {
            let parameters = parameters.as_object_mut().ok_or_else(|| {
                HttpClientError::CoreResult(McpError::internal_error(
                    "MRTR prompt parameters must remain an object",
                ))
            })?;
            parameters.insert(
                "arguments".to_owned(),
                serde_json::to_value(arguments).map_err(|error| {
                    HttpClientError::CoreResult(McpError::internal_error(format!(
                        "MRTR prompt arguments could not serialize: {error}"
                    )))
                })?,
            );
        }
        let result = self
            .request_final_core(cx, "prompts/get", parameters.clone())
            .await?;
        let Some(input_required) = mrtr_input_required_for_method("prompts/get", &result) else {
            return Ok(result);
        };
        let input_responses = respond(input_required).map_err(HttpClientError::CoreResult)?;
        let retry = mrtr_retry_parameters(parameters, input_required, input_responses)
            .map_err(HttpClientError::CoreResult)?;
        self.request_final_core(cx, "prompts/get", retry).await
    }

    /// Calls a tool through ordinary modern HTTP, following bounded MRTR
    /// continuations until one terminal tool result arrives.
    ///
    /// The supplied absolute `deadline` owns the entire operation, including
    /// the initial request and every continuation. This client allocates the
    /// initial and continuation IDs from its monotonic allocator; `respond`
    /// can therefore be invoked once for each admitted `input_required`
    /// result. Tasks are neither requested nor accepted by this operation.
    pub async fn call_tool_with_mrtr_retry_until<F>(
        &mut self,
        cx: &Cx,
        deadline: Instant,
        name: &str,
        arguments: serde_json::Value,
        sse_limits: sse::SseLimits,
        maximum_response_bytes: usize,
        respond: F,
    ) -> Result<FinalCoreResult, HttpClientError>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
    {
        let initial_request_id = self.next_request_id()?;
        let result = self
            .connection
            .call_tool_with_mrtr_retry(
                cx,
                initial_request_id,
                deadline,
                name,
                arguments,
                sse_limits,
                maximum_response_bytes,
                || self.next_mrtr_request_id(),
                respond,
            )
            .await
            .map_err(HttpClientError::Connection)?;
        self.require_terminal_http_mrtr_result("tools/call", result)
    }

    /// Reads a resource through ordinary modern HTTP, following bounded MRTR
    /// continuations until one terminal resource result arrives.
    ///
    /// See [`Self::call_tool_with_mrtr_retry_until`] for deadline, request-ID,
    /// callback, and Tasks behavior.
    pub async fn read_resource_with_mrtr_retry_until<F>(
        &mut self,
        cx: &Cx,
        deadline: Instant,
        uri: &str,
        sse_limits: sse::SseLimits,
        maximum_response_bytes: usize,
        respond: F,
    ) -> Result<FinalCoreResult, HttpClientError>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
    {
        let initial_request_id = self.next_request_id()?;
        let result = self
            .connection
            .read_resource_with_mrtr_retry(
                cx,
                initial_request_id,
                deadline,
                uri,
                sse_limits,
                maximum_response_bytes,
                || self.next_mrtr_request_id(),
                respond,
            )
            .await
            .map_err(HttpClientError::Connection)?;
        self.require_terminal_http_mrtr_result("resources/read", result)
    }

    /// Gets a prompt through ordinary modern HTTP, following bounded MRTR
    /// continuations until one terminal prompt result arrives.
    ///
    /// See [`Self::call_tool_with_mrtr_retry_until`] for deadline, request-ID,
    /// callback, and Tasks behavior.
    pub async fn get_prompt_with_mrtr_retry_until<F>(
        &mut self,
        cx: &Cx,
        deadline: Instant,
        name: &str,
        arguments: std::collections::HashMap<String, String>,
        sse_limits: sse::SseLimits,
        maximum_response_bytes: usize,
        respond: F,
    ) -> Result<FinalCoreResult, HttpClientError>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
    {
        let initial_request_id = self.next_request_id()?;
        let result = self
            .connection
            .get_prompt_with_mrtr_retry(
                cx,
                initial_request_id,
                deadline,
                name,
                arguments,
                sse_limits,
                maximum_response_bytes,
                || self.next_mrtr_request_id(),
                respond,
            )
            .await
            .map_err(HttpClientError::Connection)?;
        self.require_terminal_http_mrtr_result("prompts/get", result)
    }

    /// Opens a live final HTTP subscription listener.
    ///
    /// Accepted catalog and resource events invalidate their result sets before
    /// the listener yields them. Progress, log, and Tasks notifications remain
    /// cache-neutral.
    pub async fn open_subscriptions_listener(
        &mut self,
        cx: &Cx,
        notifications: SubscriptionFilter,
        limits: sse::SseLimits,
    ) -> Result<HttpSubscriptionListener<'_>, HttpClientError> {
        if cx.checkpoint().is_err() {
            return Err(HttpClientError::CoreResult(McpError::request_cancelled()));
        }
        let request_id = self.next_request_id()?;
        let listener = self
            .connection
            .open_subscriptions_listener(cx, request_id, notifications, limits)
            .await
            .map_err(HttpClientError::Connection)?;
        Ok(HttpSubscriptionListener {
            listener,
            final_result_cache: &mut self.final_result_cache,
        })
    }

    /// Collects one typed final HTTP subscription stream.
    pub async fn listen_subscriptions_typed(
        &mut self,
        cx: &Cx,
        notifications: SubscriptionFilter,
        limits: sse::SseLimits,
    ) -> Result<ModernHttpSubscriptionListenCollector, HttpClientError> {
        self.open_subscriptions_listener(cx, notifications, limits)
            .await?
            .collect(cx)
            .await
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

/// Shared request correlation for a negotiated stdio connection.
///
/// A cloneable request executor for the selected stdio session.
#[derive(Debug)]
struct StdioDropRetirement {
    request_id: RequestId,
    peer_era: ProtocolEra,
    requested: AtomicBool,
}

/// Bounded, client-owned retirement records for cloned stdio executions.
///
/// `StdioRequestExecution::drop` only marks its own pre-registered record.
/// The mutable client later drains that fixed set while it owns the response
/// registry and the outbound writer; Drop itself never locks or writes.
#[derive(Clone, Default, Debug)]
struct SharedStdioDropRetirements(
    Arc<Mutex<std::collections::HashMap<CorrelationKey, Arc<StdioDropRetirement>>>>,
);

impl SharedStdioDropRetirements {
    fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    fn insert(&self, retirement: Arc<StdioDropRetirement>) -> McpResult<()> {
        let key = retirement
            .request_id
            .correlation_key()
            .map_err(|_| McpError::internal_error("Invalid JSON-RPC request ID"))?;
        self.0
            .lock()
            .map_err(|_| McpError::internal_error("Stdio drop retirement registry is unavailable"))?
            .insert(key, retirement);
        Ok(())
    }

    fn take_requested(&self) -> McpResult<Vec<Arc<StdioDropRetirement>>> {
        let mut retirements = self.0.lock().map_err(|_| {
            McpError::internal_error("Stdio drop retirement registry is unavailable")
        })?;
        let requested = retirements
            .iter()
            .filter(|(_, retirement)| retirement.requested.load(Ordering::Acquire))
            .map(|(key, retirement)| (key.clone(), Arc::clone(retirement)))
            .collect::<Vec<_>>();
        for (key, _) in &requested {
            retirements.remove(key);
        }
        Ok(requested
            .into_iter()
            .map(|(_, retirement)| retirement)
            .collect())
    }

    fn remove(&self, request_id: &RequestId) {
        let Ok(key) = request_id.correlation_key() else {
            return;
        };
        if let Ok(mut retirements) = self.0.lock() {
            retirements.remove(&key);
        }
    }
}

#[derive(Clone)]
pub struct StdioRequestExecutor {
    sender: Arc<Mutex<StdioSendHalf<ChildStdin>>>,
    responses: SharedResponseRegistry,
    drop_retirements: SharedStdioDropRetirements,
    peer_era: ProtocolEra,
}

impl std::fmt::Debug for StdioRequestExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StdioRequestExecutor")
            .field("peer_era", &self.peer_era)
            .finish_non_exhaustive()
    }
}

/// One request committed through [`StdioRequestExecutor`].
#[derive(Debug)]
pub struct StdioRequestExecution {
    request_id: RequestId,
    waiter: Option<ResponseWaiter>,
    drop_retirement: Arc<StdioDropRetirement>,
    drop_retirements: SharedStdioDropRetirements,
    committed_at: Instant,
    completed: bool,
}

impl StdioRequestExecution {
    /// Returns the JSON-RPC ID committed for this request.
    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }
}

impl Drop for StdioRequestExecution {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        // A Drop implementation must not wait for either the shared response
        // registry or child stdin. The mutable Client drains this request on
        // its next owned progress point and performs the sole control write.
        self.drop_retirement
            .requested
            .store(true, Ordering::Release);
    }
}

impl StdioRequestExecutor {
    fn new(
        sender: Arc<Mutex<StdioSendHalf<ChildStdin>>>,
        responses: SharedResponseRegistry,
        drop_retirements: SharedStdioDropRetirements,
        peer_era: ProtocolEra,
    ) -> Self {
        Self {
            sender,
            responses,
            drop_retirements,
            peer_era,
        }
    }

    /// Returns the immutable era selected by the completed handshake.
    #[must_use]
    pub const fn selected_protocol_era(&self) -> ProtocolEra {
        self.peer_era
    }

    fn execute(&self, cx: &Cx, request: JsonRpcRequest) -> McpResult<StdioRequestExecution> {
        if cx.checkpoint().is_err() {
            return Err(McpError::request_cancelled());
        }
        let request_id = request
            .id
            .clone()
            .ok_or_else(|| McpError::invalid_params("Multiplexed stdio requests require an ID"))?;
        // Reserve in the same registry used by the sequential adapter before
        // the write. The sole reader can therefore route an immediate peer
        // response to this exact owner without a split-brain response path.
        let waiter = self.responses.register(request_id.clone())?;
        let send_result = self
            .sender
            .lock()
            .map_err(|_| McpError::internal_error("Multiplexed stdio writer is unavailable"))?
            .send(cx, &JsonRpcMessage::Request(request))
            .map_err(transport_error_to_mcp);
        if let Err(error) = send_result {
            let _ = self.responses.fail(&request_id, error.clone());
            return Err(error);
        }
        let drop_retirement = Arc::new(StdioDropRetirement {
            request_id: request_id.clone(),
            peer_era: self.peer_era,
            requested: AtomicBool::new(false),
        });
        if let Err(error) = self.drop_retirements.insert(Arc::clone(&drop_retirement)) {
            let _ = self.responses.fail(&request_id, error.clone());
            return Err(error);
        }
        Ok(StdioRequestExecution {
            request_id,
            waiter: Some(waiter),
            drop_retirement,
            drop_retirements: self.drop_retirements.clone(),
            committed_at: Instant::now(),
            completed: false,
        })
    }
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
    /// Independently owned stdio reader. Callback workers never borrow this
    /// half, so the sole reader can continue admitting cancellation frames.
    /// The sequential adapter and cloned multiplexed request handles share
    /// this sole ingress half. A reader turn, rather than this state lock,
    /// serializes blocking reads.
    transport: Arc<Mutex<StdioRecvHalf<ChildStdout>>>,
    /// Serializes every outbound frame, including callback completions the
    /// sole reader commits between bounded receive polls.
    response_sender: Arc<Mutex<StdioSendHalf<ChildStdin>>>,
    /// Installed only after a final stdio handshake selected its immutable
    /// peer era. Auto's disposable modern probe never reaches this field.
    multiplexed_executor: Option<StdioRequestExecutor>,
    /// Fixed retirement records owned by the client, whose request handles
    /// may be dropped from arbitrary caller contexts.
    stdio_drop_retirements: SharedStdioDropRetirements,
    /// Capability context for cancellation.
    cx: Cx,
    /// Session state after initialization.
    session: ClientSession,
    /// Request ID counter.
    next_id: AtomicU64,
    /// Strict response correlation for every in-flight request.
    responses: SharedResponseRegistry,
    /// Exact non-progress notifications received from a modern server.
    final_server_notifications: VecDeque<ServerNotification>,
    /// Exact progress notifications received from a modern server without
    /// converting their JSON numbers to legacy `f64` values.
    final_progress_notifications: VecDeque<FinalProgressNotificationParams>,
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
    /// Fixed, owned callback workers for exact-2024 reverse requests.
    reverse_callback_pool: ReverseCallbackPool,
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

        let (transport, response_sender) = transport.into_split();
        let response_sender = Arc::new(Mutex::new(response_sender));
        let reverse_callback_pool =
            ReverseCallbackPool::new(Arc::clone(&response_sender), cx.clone());

        // Create a temporary client for initialization
        let mut client = Self {
            child: Some(child_guard.disarm()),
            group_anchor: None,
            child_ownership: ChildOwnership::DirectChild,
            child_cleanup_phase: ClientChildCleanupPhase::Active,
            cleanup_error: None,
            pending_process_cleanup_error: None,
            transport: Arc::new(Mutex::new(transport)),
            response_sender,
            multiplexed_executor: None,
            stdio_drop_retirements: SharedStdioDropRetirements::default(),
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
            responses: SharedResponseRegistry::new(),
            final_server_notifications: VecDeque::new(),
            final_progress_notifications: VecDeque::new(),
            final_result_cache: FinalResultCache::default(),
            final_cache_ttl_diagnostics: VecDeque::new(),
            last_core_result_receipt: None,
            last_final_cache_page: None,
            reverse_request_handlers: ReverseRequestHandlers::new(),
            reverse_callback_pool,
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
        client.install_multiplexed_stdio_executor();

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
        let (transport, response_sender) = transport.into_split();
        let response_sender = Arc::new(Mutex::new(response_sender));
        let reverse_callback_pool =
            ReverseCallbackPool::new(Arc::clone(&response_sender), cx.clone());
        Self {
            child: Some(child),
            group_anchor,
            child_ownership,
            child_cleanup_phase: ClientChildCleanupPhase::Active,
            cleanup_error: None,
            pending_process_cleanup_error: None,
            transport: Arc::new(Mutex::new(transport)),
            response_sender,
            multiplexed_executor: None,
            stdio_drop_retirements: SharedStdioDropRetirements::default(),
            cx,
            session,
            next_id: AtomicU64::new(2), // Start at 2 since initialize used 1
            responses: SharedResponseRegistry::new(),
            final_server_notifications: VecDeque::new(),
            final_progress_notifications: VecDeque::new(),
            final_result_cache: FinalResultCache::default(),
            final_cache_ttl_diagnostics: VecDeque::new(),
            last_core_result_receipt: None,
            last_final_cache_page: None,
            reverse_request_handlers: ReverseRequestHandlers::new(),
            reverse_callback_pool,
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
        let (transport, response_sender) = transport.into_split();
        let response_sender = Arc::new(Mutex::new(response_sender));
        let reverse_callback_pool =
            ReverseCallbackPool::new(Arc::clone(&response_sender), cx.clone());
        Self {
            child: Some(child),
            group_anchor,
            child_ownership,
            child_cleanup_phase: ClientChildCleanupPhase::Active,
            cleanup_error: None,
            pending_process_cleanup_error: None,
            transport: Arc::new(Mutex::new(transport)),
            response_sender,
            multiplexed_executor: None,
            stdio_drop_retirements: SharedStdioDropRetirements::default(),
            cx,
            session,
            next_id: AtomicU64::new(1), // Start at 1 since initialize hasn't happened
            responses: SharedResponseRegistry::new(),
            final_server_notifications: VecDeque::new(),
            final_progress_notifications: VecDeque::new(),
            final_result_cache: FinalResultCache::default(),
            final_cache_ttl_diagnostics: VecDeque::new(),
            last_core_result_receipt: None,
            last_final_cache_page: None,
            reverse_request_handlers: ReverseRequestHandlers::new(),
            reverse_callback_pool,
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
        if let Err(error) = self.drain_completed_reverse_callbacks() {
            return Err(self.terminate_connection(error));
        }
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
        self.install_multiplexed_stdio_executor();

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
        self.cancel_reverse_callback_pool();
        if let Err(cleanup_error) = self.join_reverse_callback_pool() {
            // Do not attempt to lock or close stdin while a retained callback
            // worker may still own its writer lock. The worker remains owned
            // by this client and a later explicit close can retry the join.
            self.retain_cleanup_error(cleanup_error);
            return error;
        }
        if let Err(cleanup_error) = self.close_transport().map_err(transport_error_to_mcp) {
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

    /// Starts one browser-agnostic Apps Host after successful Apps negotiation.
    /// This never alters the MCP client/server RPC dispatcher.
    pub fn mcp_apps_host<T, P>(
        &self,
        transport: T,
        configuration: McpAppsHostConfiguration,
        policy: P,
    ) -> Result<McpAppsHost<T, P>, McpAppsHostError>
    where
        T: McpAppsBridgeTransport,
        P: McpAppsHostPolicy,
    {
        let activation_proof = mcp_apps::McpAppsActivationProof::from_activation_receipt(
            self.session.mcp_apps_activation_receipt(),
        )?;
        Ok(McpAppsHost::new_negotiated(
            transport,
            configuration,
            policy,
            activation_proof,
        ))
    }

    /// Starts the closed JSON-RPC Apps bridge after final discovery retained
    /// the current bilateral activation receipt. Standard-reused View methods
    /// become fresh selected-era core requests owned by this client.
    pub fn mcp_apps_wire_host<'client, T>(
        &'client mut self,
        transport: T,
        configuration: mcp_apps::McpAppsWireHostConfiguration,
    ) -> Result<
        mcp_apps::McpAppsWireHost<T, mcp_apps::McpAppsClientWirePolicy<'client>>,
        McpAppsHostError,
    >
    where
        T: mcp_apps::McpAppsWireBridgeTransport,
    {
        let activation_proof = mcp_apps::McpAppsActivationProof::from_activation_receipt(
            self.session.mcp_apps_activation_receipt(),
        )?;
        Ok(mcp_apps::McpAppsWireHost::new_negotiated(
            transport,
            configuration,
            mcp_apps::McpAppsClientWirePolicy::new(self),
            activation_proof,
        ))
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

    /// Drains non-progress final server notifications received during modern requests.
    ///
    /// Use [`Self::take_final_progress_notifications`] to retrieve final
    /// progress values without legacy `f64` conversion. Exact 2024-11-05
    /// sessions never retain values in either queue.
    #[must_use]
    pub fn take_final_server_notifications(&mut self) -> Vec<ServerNotification> {
        self.final_server_notifications.drain(..).collect()
    }

    /// Drains exact final progress notifications received during modern requests.
    ///
    /// The returned [`FinalProgressNotificationParams`] preserve the original
    /// JSON-number lexemes, so values such as `1e400` remain observable even
    /// though the legacy [`ProgressCallback`] accepts only finite `f64` values.
    #[must_use]
    pub fn take_final_progress_notifications(&mut self) -> Vec<FinalProgressNotificationParams> {
        self.final_progress_notifications.drain(..).collect()
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

    /// Clears reverse request handlers on a live client.
    ///
    /// Non-empty exact-2024 callback handlers must be configured through
    /// [`ClientBuilder::reverse_request_handlers`] before initialization so
    /// the advertised capabilities and callable methods cannot diverge.
    pub fn set_reverse_request_handlers(
        &mut self,
        handlers: ReverseRequestHandlers,
    ) -> McpResult<()> {
        if !handlers.is_empty() {
            return Err(McpError::invalid_params(
                "Configure reverse request handlers with ClientBuilder before initialization",
            ));
        }
        self.reverse_request_handlers = handlers;
        Ok(())
    }

    pub(crate) fn install_reverse_request_handlers_before_initialization(
        &mut self,
        handlers: ReverseRequestHandlers,
    ) {
        debug_assert!(!self.initialized.load(Ordering::SeqCst));
        self.reverse_request_handlers = handlers;
    }

    fn server_request_response(&mut self, request: &JsonRpcRequest) -> Option<JsonRpcMessage> {
        match live_server_request_dispatch(
            self.session.selected_era(),
            &self.reverse_request_handlers,
            &self.reverse_callback_pool,
            request,
        )? {
            LiveServerRequestDispatch::Immediate(response) => Some(response),
            LiveServerRequestDispatch::CallbackAdmitted => None,
        }
    }

    fn cancel_legacy_reverse_callback(&mut self, request: &JsonRpcRequest) -> bool {
        if self.session.selected_era() != Some(ProtocolEra::Legacy2024) {
            return false;
        }
        let Ok(CancellationWireMessage::Legacy2024 { params, .. }) =
            CancellationWireMessage::decode(
                ProtocolEra::Legacy2024,
                CancellationSender::Server,
                request,
            )
        else {
            return false;
        };

        self.reverse_callback_pool.cancel(&params.request_id)
    }

    fn drain_completed_reverse_callbacks(&mut self) -> McpResult<()> {
        self.reverse_callback_pool
            .state
            .terminal_error()
            .map_or(Ok(()), Err)
    }

    fn reverse_callback_poll_deadline(&self, deadline: Instant) -> Instant {
        deadline.min(
            Instant::now()
                .checked_add(REVERSE_CALLBACK_POLL_SLICE)
                .unwrap_or(deadline),
        )
    }

    fn cancel_reverse_callback_pool(&self) {
        self.reverse_callback_pool.cancel_all();
    }

    fn join_reverse_callback_pool(&mut self) -> McpResult<()> {
        self.reverse_callback_pool.join_bounded()
    }

    fn join_reverse_callback_pool_unbounded(&mut self) {
        self.reverse_callback_pool.join_unbounded();
    }

    fn transport_is_closed(&self) -> bool {
        self.transport
            .lock()
            .map_or(true, |transport| transport.is_closed())
    }

    fn close_transport(&mut self) -> Result<(), TransportError> {
        let receiver = self
            .transport
            .lock()
            .map_err(|_| TransportError::Closed)?
            .close();
        let sender = self
            .response_sender
            .lock()
            .map_err(|_| TransportError::Closed)?
            .close();
        receiver.and(sender)
    }

    fn send_to_server(&self, message: &JsonRpcMessage) -> Result<(), TransportError> {
        self.send_to_server_with_cx(&self.cx, message)
    }

    fn send_to_server_with_cx(
        &self,
        cx: &Cx,
        message: &JsonRpcMessage,
    ) -> Result<(), TransportError> {
        self.response_sender
            .lock()
            .map_err(|_| TransportError::Closed)?
            .send(cx, message)
    }

    fn install_multiplexed_stdio_executor(&mut self) {
        let Some(peer_era) = self.session.selected_era() else {
            return;
        };
        self.multiplexed_executor = Some(StdioRequestExecutor::new(
            Arc::clone(&self.response_sender),
            self.responses.clone(),
            self.stdio_drop_retirements.clone(),
            peer_era,
        ));
    }

    /// Drains dropped multiplexed request handles at a client-owned progress
    /// point. This is deliberately the only place a drop retirement can lock
    /// correlation state or touch child stdin.
    fn flush_stdio_drop_retirements(&mut self) -> McpResult<()> {
        for retirement in self.stdio_drop_retirements.take_requested()? {
            let retired = self
                .responses
                .tombstone(&retirement.request_id, McpError::request_cancelled())?;
            if !retired
                || !self
                    .responses
                    .claim_cancellation_control(&retirement.request_id)?
            {
                continue;
            }
            let control =
                stdio_cancellation_control_message(retirement.peer_era, &retirement.request_id)?;
            if let Err(error) = self.send_bounded_control_message(control) {
                return Err(self.terminate_connection(error));
            }
        }
        Ok(())
    }

    /// Returns the negotiated shared stdio executor.
    ///
    /// The ordinary `Client` convenience methods remain sequential adapters.
    /// Callers that need several committed requests before waiting may clone
    /// this executor and use [`Self::start_multiplexed_request`].
    pub fn multiplexed_stdio_executor(&self) -> McpResult<StdioRequestExecutor> {
        self.multiplexed_executor.clone().ok_or_else(|| {
            McpError::invalid_request(
                "Negotiated stdio multiplexing is unavailable before initialization",
            )
        })
    }

    /// Commits one raw JSON-RPC request through the negotiated shared stdio
    /// executor without waiting for its response.
    pub fn start_multiplexed_request(
        &mut self,
        cx: &Cx,
        method: impl Into<String>,
        params: Option<serde_json::Value>,
    ) -> McpResult<StdioRequestExecution> {
        self.flush_stdio_drop_retirements()?;
        let id = self.next_request_id()?;
        let request = JsonRpcRequest::new(
            method.into(),
            params,
            i64::try_from(id).expect("client request IDs are bounded to i64"),
        );
        self.multiplexed_stdio_executor()?.execute(cx, request)
    }

    /// Waits for one multiplexed request through the same sole ingress path
    /// used by the sequential convenience API. Server requests, cancellation
    /// controls, notifications, and every response ID therefore retain their
    /// normal routing semantics instead of being discarded by a parallel
    /// reader.
    pub fn wait_multiplexed_request(
        &mut self,
        cx: &Cx,
        execution: &mut StdioRequestExecution,
    ) -> McpResult<JsonRpcResponse> {
        if execution.completed
            || !self
                .stdio_drop_retirements
                .ptr_eq(&execution.drop_retirements)
        {
            return Err(McpError::invalid_request(
                "Multiplexed stdio execution belongs to a different client",
            ));
        }
        self.flush_stdio_drop_retirements()?;
        let waiter = execution.waiter.take().ok_or_else(|| {
            McpError::invalid_request("Multiplexed stdio execution was already consumed")
        })?;
        execution.completed = true;
        let deadlines = RequestDeadlines::start_at(self.timeout_policy, execution.committed_at)?;
        let response = self.recv_response_with_cx(cx, waiter, deadlines);
        self.stdio_drop_retirements.remove(&execution.request_id);
        let response = response?;
        if let Some(error) = response.error.clone() {
            return Err(json_rpc_error_to_mcp(error));
        }
        Ok(response.response)
    }

    /// Verifies that the initialized server can answer an MCP ping request.
    ///
    /// # Errors
    ///
    /// Returns an error when initialization, transport, envelope validation,
    /// or the server's ping response fails.
    pub fn ping(&mut self) -> McpResult<()> {
        self.require_legacy_exact_result_session("ping")?;
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

    /// Builds the one selected-era JSON-RPC cancellation notification.
    ///
    /// Cancellation notifications contain only their cancellation parameters.
    /// Optional final notification metadata is never required or synthesized.
    fn cancellation_control_message(
        &self,
        request_id: RequestId,
        reason: Option<String>,
    ) -> McpResult<JsonRpcMessage> {
        let cancellation = match self.session.selected_era() {
            Some(ProtocolEra::Legacy2024) => CancellationWireMessage::Legacy2024 {
                sender: CancellationSender::Client,
                params: CancelledParams { request_id, reason },
            },
            Some(ProtocolEra::Modern2026) => CancellationWireMessage::Modern2026 {
                sender: CancellationSender::Client,
                params: FinalCancelledNotificationParams {
                    request_id,
                    reason,
                    meta: None,
                    additional: Default::default(),
                },
            },
            None => {
                return Err(McpError::internal_error(
                    "Client has no negotiated protocol era for cancellation",
                ));
            }
        };
        cancellation
            .encode()
            .map(JsonRpcMessage::Request)
            .map_err(|error| {
                McpError::invalid_params(format!(
                    "Invalid cancellation control parameters: {error}"
                ))
            })
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

        if request.method == "notifications/cancelled" {
            let Ok(cancellation) = CancellationWireMessage::decode(
                ProtocolEra::Modern2026,
                CancellationSender::Server,
                request,
            ) else {
                return Ok(Some(ModernServerNotification::Retained));
            };
            if !matches!(cancellation, CancellationWireMessage::Modern2026 { .. }) {
                return Ok(Some(ModernServerNotification::Retained));
            }
            // Generic high-level receive paths have no active
            // subscriptions/listen ownership context. A server cancellation is
            // therefore retained inertly here; the dedicated stdio listener
            // validates and applies cancellation only to its own live stream.
            return Ok(Some(ModernServerNotification::Retained));
        }

        let raw_params = self.last_received_raw_notification_params(request)?;
        let notification = decode_final_server_notification(request, raw_params.as_deref())
            .map_err(|error| {
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
                ServerNotification::Message(message) => {
                    Some(final_log_message_sink_projection(message))
                }
                _ => None,
            };
            self.final_server_notifications.push_back(notification);
            if let Some(message) = log_message {
                self.emit_log_message(message);
            }
            return Ok(Some(ModernServerNotification::Retained));
        };

        if self.final_progress_notifications.len() >= MAX_QUEUED_FINAL_SERVER_NOTIFICATIONS {
            return Err(McpError::invalid_request(
                FINAL_SERVER_NOTIFICATION_QUEUE_OVERFLOW_ERROR,
            ));
        }
        self.final_progress_notifications
            .push_back(progress.clone());

        Ok(Some(ModernServerNotification::Progress(progress)))
    }

    fn last_received_raw_notification_params(
        &self,
        request: &JsonRpcRequest,
    ) -> McpResult<Option<String>> {
        if request.method != "notifications/progress" {
            return Ok(None);
        }
        let transport = self
            .transport
            .lock()
            .map_err(|_| McpError::internal_error("Client stdio reader is unavailable"))?;
        let frame = transport.last_received_frame().ok_or_else(|| {
            McpError::invalid_request("Client lost the raw final progress notification frame")
        })?;
        let raw_params = raw_notification_params_from_frame(frame)?.ok_or_else(|| {
            McpError::invalid_request("Final progress notification is missing raw params")
        })?;
        Ok(Some(raw_params))
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
        let cx = self.cx.clone();
        self.send_prepared_request_with_cx(&cx, None, method, params_value)
    }

    /// Sends one prepared request under an optional operation-wide deadline.
    ///
    /// Ordinary public requests retain their existing per-request deadline
    /// behavior. Multi-round MRTR passes one immutable operation deadline so
    /// no continuation can restart the absolute response-wait budget.
    fn send_prepared_request_with_cx(
        &mut self,
        cx: &Cx,
        operation_deadline: Option<Instant>,
        method: &str,
        params_value: serde_json::Value,
    ) -> McpResult<ReceivedPreparedResult> {
        let timeout_policy = self.timeout_policy;
        timeout_policy.validate()?;
        if cx.checkpoint().is_err() {
            return Err(McpError::request_cancelled());
        }
        if operation_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(McpError::internal_error(
                "MRTR operation absolute deadline elapsed",
            ));
        }
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

        if let Err(error) = self.send_to_server_with_cx(cx, &JsonRpcMessage::Request(request)) {
            let error = self.record_send_failure(Some(&request_id), error);
            return Err(error);
        }
        let committed_at = Instant::now();
        let mut deadlines = match RequestDeadlines::start_at(timeout_policy, committed_at) {
            Ok(deadlines) => deadlines,
            Err(error) => {
                return Err(self.finish_committed_request_locally(&request_id, error));
            }
        };
        if let Some(operation_deadline) = operation_deadline {
            deadlines.cap_absolute_at(operation_deadline);
        }

        // Receive response with ID validation
        let ReceivedJsonRpcResponse {
            mut response,
            raw_result,
        } = self.recv_response_with_cx(cx, waiter, deadlines)?;
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

    /// Forwards one admitted Apps standard-reused method through a new
    /// client-owned selected-era core request. Apps envelope IDs and transport
    /// controls never enter this request path.
    pub(crate) fn forward_mcp_apps_reused_core(
        &mut self,
        cx: &Cx,
        method: fastmcp_protocol::McpAppsRoutedMethod,
        params: Option<serde_json::Value>,
    ) -> McpResult<serde_json::Value> {
        if cx.checkpoint().is_err() {
            return Err(McpError::request_cancelled());
        }
        if !self.mcp_apps_active() {
            return Err(McpError::invalid_request(
                "MCP Apps reused methods require the current bilateral activation receipt",
            ));
        }

        let result = match method {
            fastmcp_protocol::McpAppsRoutedMethod::ToolsCall => {
                let mut params: CallToolParams =
                    serde_json::from_value(params.ok_or_else(|| {
                        McpError::invalid_params("Apps tools/call is missing parameters")
                    })?)
                    .map_err(|_| {
                        McpError::invalid_params("Apps tools/call parameters are invalid")
                    })?;
                params.meta = None;
                self.send_typed_core_request("tools/call", params)?
            }
            fastmcp_protocol::McpAppsRoutedMethod::ResourcesRead => {
                let mut params: ReadResourceParams =
                    serde_json::from_value(params.ok_or_else(|| {
                        McpError::invalid_params("Apps resources/read is missing parameters")
                    })?)
                    .map_err(|_| {
                        McpError::invalid_params("Apps resources/read parameters are invalid")
                    })?;
                params.meta = None;
                self.send_typed_core_request("resources/read", params)?
            }
            fastmcp_protocol::McpAppsRoutedMethod::ResourcesList => {
                let params: ListResourcesParams =
                    serde_json::from_value(params.unwrap_or_else(|| serde_json::json!({})))
                        .map_err(|_| {
                            McpError::invalid_params("Apps resources/list parameters are invalid")
                        })?;
                self.send_typed_core_request("resources/list", params)?
            }
            fastmcp_protocol::McpAppsRoutedMethod::ResourceTemplatesList => {
                let params: ListResourceTemplatesParams =
                    serde_json::from_value(params.unwrap_or_else(|| serde_json::json!({})))
                        .map_err(|_| {
                            McpError::invalid_params(
                                "Apps resources/templates/list parameters are invalid",
                            )
                        })?;
                self.send_typed_core_request("resources/templates/list", params)?
            }
            fastmcp_protocol::McpAppsRoutedMethod::PromptsList => {
                let params: ListPromptsParams =
                    serde_json::from_value(params.unwrap_or_else(|| serde_json::json!({})))
                        .map_err(|_| {
                            McpError::invalid_params("Apps prompts/list parameters are invalid")
                        })?;
                self.send_typed_core_request("prompts/list", params)?
            }
            _ => {
                return Err(McpError::invalid_params(
                    "Apps method is not a direction-correct standard-reused core request",
                ));
            }
        };

        mcp_apps::project_reused_core_result(method, result)
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

    /// Sends one ordinary core request under an operation-owned caller context
    /// and absolute deadline.
    ///
    /// This is intentionally separate from Tasks requests: MRTR retries carry
    /// the exact original core parameters plus only the current continuation
    /// fields, and must not synthesize an extension declaration.
    fn send_typed_core_request_with_cx_until(
        &mut self,
        cx: &Cx,
        operation_deadline: Instant,
        method: &str,
        params_value: serde_json::Value,
    ) -> McpResult<CoreResult> {
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
        self.last_core_result_receipt = None;
        let received =
            self.send_prepared_request_with_cx(cx, Some(operation_deadline), method, params_value)?;
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
                if self.cx.checkpoint().is_err() {
                    return Err(McpError::request_cancelled());
                }
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

    fn drain_final_cache_invalidations(&mut self) -> McpResult<()> {
        if self.cx.checkpoint().is_err() {
            return Err(McpError::request_cancelled());
        }

        #[cfg(unix)]
        {
            let deadline = Instant::now() + FINAL_CACHE_NOTIFICATION_DRAIN_WINDOW;
            loop {
                let receive_deadline = self.reverse_callback_poll_deadline(deadline);
                let (message, _) = match recv_shared_child_transport(
                    &self.transport,
                    &self.cx,
                    Some(receive_deadline),
                ) {
                    Ok(received) => received,
                    Err(TransportError::ReceiveDeadlineExceeded) if !self.transport_is_closed() => {
                        if receive_deadline < deadline {
                            self.drain_completed_reverse_callbacks()
                                .map_err(|error| self.terminate_connection(error))?;
                            continue;
                        }
                        return Ok(());
                    }
                    Err(TransportError::Cancelled) if !self.transport_is_closed() => {
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
                if self.cancel_legacy_reverse_callback(&request) {
                    return Ok(());
                }
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

        if let Err(error) = self.send_to_server(&JsonRpcMessage::Request(request)) {
            return Err(self.record_send_failure(None, error));
        }

        Ok(())
    }

    fn send_initialized_notification(&mut self) -> McpResult<()> {
        let notification = JsonRpcRequest::initialized_notification();
        if let Err(error) = self.send_to_server(&JsonRpcMessage::Request(notification)) {
            return Err(self.record_send_failure(None, error));
        }
        Ok(())
    }

    /// Sends a cancellation notification for a locally owned live request.
    ///
    /// Both supported wire forms contain `requestId` and an optional `reason`.
    /// Modern notification metadata remains optional and is never synthesized.
    /// The live waiter receives local cancellation first and its one late
    /// response is discarded through a tombstone.
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
    ) -> McpResult<()> {
        let request_id = request_id.into();
        self.ensure_initialized()?;
        if !self.responses.owns_live_request(&request_id)? {
            return Err(McpError::invalid_request(
                "Client cancellation requires a locally owned live request ID",
            ));
        }
        let control = self.cancellation_control_message(request_id.clone(), reason)?;

        let claimed = match self.responses.claim_cancellation_control(&request_id) {
            Ok(claimed) => claimed,
            Err(error) => return Err(self.terminate_connection(error)),
        };
        if !claimed {
            return Err(McpError::invalid_request(
                "Client cancellation was already committed for this request ID",
            ));
        }

        match self
            .responses
            .tombstone(&request_id, McpError::request_cancelled())
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(McpError::invalid_request(
                    "Client cancellation requires a locally owned live request ID",
                ));
            }
            Err(error) => return Err(self.terminate_connection(error)),
        }
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
            self.response_sender
                .lock()
                .map_err(|_| McpError::internal_error("Client stdio response writer failed"))?
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
        send_child_server_response_during_receive(&self.response_sender, &self.cx, &message)
    }

    fn send_timeout_cancellation_control(&mut self, request_id: &RequestId) -> McpResult<()> {
        let control = self.cancellation_control_message(request_id.clone(), None)?;
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
        // The typed JSON value cannot reconstruct exact numeric lexemes or
        // object spelling. Copy the retained frame before the next receive
        // invalidates the transport reuse buffer, then admit its raw result
        // sidecar alongside the already-decoded response.
        let frame = self
            .transport
            .lock()
            .map_err(|_| McpError::internal_error("Client stdio reader is unavailable"))?
            .last_received_frame()
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                McpError::internal_error("Stdio response frame is unavailable for raw admission")
            })?;
        let admission = decode_strict_jsonrpc_response(&frame, frame.len()).map_err(|_| {
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
                if self.cancel_legacy_reverse_callback(&request) {
                    return timeout;
                }
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
        waiter: ResponseWaiter,
        deadlines: RequestDeadlines,
    ) -> McpResult<ReceivedJsonRpcResponse> {
        let cx = self.cx.clone();
        self.recv_response_with_cx(&cx, waiter, deadlines)
    }

    fn recv_response_with_cx(
        &mut self,
        cx: &Cx,
        mut waiter: ResponseWaiter,
        deadlines: RequestDeadlines,
    ) -> McpResult<ReceivedJsonRpcResponse> {
        let expected_id = waiter.id.clone();

        loop {
            self.flush_stdio_drop_retirements()?;
            if let Some(response) = waiter.try_response()? {
                debug_assert!(
                    response
                        .id
                        .as_ref()
                        .is_some_and(|response_id| response_id.correlates_with(&expected_id))
                );
                return Ok(response);
            }

            if let Some(kind) = deadlines.expired_at(Instant::now()) {
                return Err(self.timeout_committed_request(&expected_id, kind));
            }

            let receive_deadline = self.reverse_callback_poll_deadline(deadlines.next());
            let (message, received_at) =
                match recv_shared_child_transport(&self.transport, cx, Some(receive_deadline)) {
                    Ok(received) => received,
                    Err(TransportError::ReceiveDeadlineExceeded) => {
                        if receive_deadline < deadlines.next() && !self.transport_is_closed() {
                            self.drain_completed_reverse_callbacks()
                                .map_err(|error| self.terminate_connection(error))?;
                            continue;
                        }
                        let kind = deadlines
                            .expired_at(Instant::now())
                            .unwrap_or_else(|| deadlines.next_kind());
                        if self.transport_is_closed() {
                            return Err(self.finish_partial_frame_timeout(&expected_id, kind));
                        }
                        return Err(self.timeout_committed_request(&expected_id, kind));
                    }
                    Err(TransportError::Timeout) if !self.transport_is_closed() => {
                        return Err(self.finish_open_context_interruption(
                            &expected_id,
                            McpError::internal_error("Request timed out"),
                        ));
                    }
                    Err(TransportError::Cancelled) if !self.transport_is_closed() => {
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
                    if self.cancel_legacy_reverse_callback(&request) {
                        continue;
                    }
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
                if !subscription_id.correlates_with(&expected_id) {
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

            let receive_deadline = self.reverse_callback_poll_deadline(deadlines.next());
            let (message, received_at) = match recv_shared_child_transport(
                &self.transport,
                &self.cx,
                Some(receive_deadline),
            ) {
                Ok(received) => received,
                Err(TransportError::ReceiveDeadlineExceeded) => {
                    if receive_deadline < deadlines.next() && !self.transport_is_closed() {
                        self.drain_completed_reverse_callbacks()
                            .map_err(|error| self.terminate_connection(error))?;
                        continue;
                    }
                    let kind = deadlines
                        .expired_at(Instant::now())
                        .unwrap_or_else(|| deadlines.next_kind());
                    if self.transport_is_closed() {
                        return Err(self.finish_partial_frame_timeout(&expected_id, kind));
                    }
                    return Err(self.timeout_committed_request(&expected_id, kind));
                }
                Err(TransportError::Timeout) if !self.transport_is_closed() => {
                    return Err(self.finish_open_context_interruption(
                        &expected_id,
                        McpError::internal_error("Request timed out"),
                    ));
                }
                Err(TransportError::Cancelled) if !self.transport_is_closed() => {
                    return Err(self.finish_open_context_interruption(
                        &expected_id,
                        McpError::request_cancelled(),
                    ));
                }
                Err(TransportError::Closed) => {
                    return Err(
                        self.terminate_connection(subscription_listener_protocol_error(
                            "Subscription listener reached EOF before terminal complete result",
                        )),
                    );
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
                    if self.cancel_legacy_reverse_callback(&request) {
                        continue;
                    }
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
                        if !subscription_id.as_ref().is_some_and(|subscription_id| {
                            subscription_id.correlates_with(&expected_id)
                        }) {
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

                    if request.method == "notifications/cancelled" {
                        let cancellation = match CancellationWireMessage::decode(
                            ProtocolEra::Modern2026,
                            CancellationSender::Server,
                            &request,
                        ) {
                            Ok(CancellationWireMessage::Modern2026 { params, .. }) => params,
                            Ok(CancellationWireMessage::Legacy2024 { .. }) | Err(_) => continue,
                        };
                        if !cancellation.request_id.correlates_with(&expected_id) {
                            continue;
                        }
                        if let Some(metadata_subscription_id) = cancellation
                            .meta
                            .as_ref()
                            .and_then(|metadata| metadata.get(FINAL_SUBSCRIPTION_ID_META_KEY))
                            .and_then(|value| {
                                serde_json::from_value::<RequestId>(value.clone()).ok()
                            })
                            && !metadata_subscription_id.correlates_with(&expected_id)
                        {
                            continue;
                        }
                        let error = McpError::request_cancelled();
                        match self.responses.tombstone(&expected_id, error.clone()) {
                            Ok(true) => {}
                            Ok(false) => continue,
                            Err(tombstone_error) => {
                                return Err(self.terminate_connection(tombstone_error));
                            }
                        }
                        return Err(error);
                    }

                    if is_final_server_notification_method(&request) {
                        let raw_params = match self.last_received_raw_notification_params(&request)
                        {
                            Ok(raw_params) => raw_params,
                            Err(_) => {
                                return Err(self.terminate_connection(
                                    subscription_listener_protocol_error(
                                        "Subscription listener lost raw final notification params",
                                    ),
                                ));
                            }
                        };
                        let notification = match decode_final_server_notification(
                            &request,
                            raw_params.as_deref(),
                        ) {
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
                            ServerNotification::Cancelled(_) => {
                                return Err(self.terminate_connection(
                                    subscription_listener_protocol_error(
                                        "Subscription cancellation bypassed the final cancellation codec",
                                    ),
                                ));
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
        let apps_activation_receipt = session.server_discovery().and_then(|discovery| {
            mcp_apps_activation_receipt(session.mcp_apps_settings(), discovery)
        });
        session.set_mcp_apps_activation_receipt(apps_activation_receipt);
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

    /// Drives one stdio MRTR operation with one caller context and one
    /// operation-wide absolute deadline.
    ///
    /// Each continuation rebuilds its parameters from `original_parameters`,
    /// adding only the latest `inputResponses` and `requestState`. This keeps
    /// prior continuation state from leaking into a later round while every
    /// committed retry still receives a fresh JSON-RPC request ID.
    fn drive_mrtr_retry<F>(
        &mut self,
        method: &str,
        original_parameters: serde_json::Value,
        mut respond: F,
    ) -> McpResult<CoreResult>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
    {
        self.ensure_initialized()?;
        let cx = self.cx.clone();
        let deadline = Instant::now()
            .checked_add(self.timeout_policy.absolute_timeout())
            .ok_or_else(|| {
                McpError::internal_error("MRTR operation deadline exceeds the clock range")
            })?;
        let limits =
            MrtrDriverLimits::new(MAX_MRTR_CONTINUATION_ROUNDS, MAX_MRTR_TOTAL_INPUT_RESPONSES)?;
        let mut driver = MrtrDriver::new(&cx, deadline, limits)?;
        let mut parameters = original_parameters.clone();

        loop {
            driver.before_request()?;
            let result = self.send_typed_core_request_with_cx_until(
                &cx,
                driver.deadline(),
                method,
                parameters,
            )?;
            let Some(input_required) = mrtr_input_required_for_method(method, &result) else {
                return Ok(result);
            };

            // Reject a peer continuation beyond the local bound before the
            // caller callback can produce an effect or another request can be
            // committed.
            driver.begin_continuation()?;
            let input_responses = respond(input_required)?;
            let input_response_count = input_responses.len();
            let retry_parameters = mrtr_retry_parameters(
                original_parameters.clone(),
                input_required,
                input_responses,
            )?;
            driver.admit_input_responses(input_response_count)?;
            parameters = retry_parameters;
        }
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

    /// Calls a tool and follows bounded final MRTR continuations with
    /// caller-supplied responses.
    ///
    /// Each continuation receives a fresh request ID and rebuilds from the
    /// original parameters. Exact MCP 2024-11-05 results and final complete or
    /// Tasks results return without invoking `respond`. The operation shares
    /// one caller context, absolute deadline, continuation-round bound, and
    /// total input-response bound.
    pub fn call_tool_with_mrtr_retry<F>(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
        respond: F,
    ) -> McpResult<CoreResult>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
    {
        self.ensure_initialized()?;
        if self.session.selected_era() == Some(ProtocolEra::Legacy2024) {
            return self.call_tool_typed(name, arguments);
        }
        let original_parameters = serde_json::json!({
            "name": name,
            "arguments": arguments,
        });
        self.drive_mrtr_retry("tools/call", original_parameters, respond)
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
        let progress_marker = ProgressMarker::Number(JsonInteger::from(
            i64::try_from(request_id).expect("request ID allocator enforces the i64 bound"),
        ));

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

        if let Err(error) = self.send_to_server(&JsonRpcMessage::Request(request)) {
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
        let mut last_final_progress = None;

        loop {
            if let Some(response) = waiter.try_response()? {
                debug_assert_eq!(response.id.as_ref(), Some(&expected_id));
                return Ok(response);
            }

            if let Some(kind) = deadlines.expired_at(Instant::now()) {
                return Err(self.timeout_committed_request(&expected_id, kind));
            }

            let receive_deadline = self.reverse_callback_poll_deadline(deadlines.next());
            let (message, received_at) = match recv_shared_child_transport(
                &self.transport,
                &self.cx,
                Some(receive_deadline),
            ) {
                Ok(received) => received,
                Err(TransportError::ReceiveDeadlineExceeded) => {
                    if receive_deadline < deadlines.next() && !self.transport_is_closed() {
                        self.drain_completed_reverse_callbacks()
                            .map_err(|error| self.terminate_connection(error))?;
                        continue;
                    }
                    let kind = deadlines
                        .expired_at(Instant::now())
                        .unwrap_or_else(|| deadlines.next_kind());
                    if self.transport_is_closed() {
                        return Err(self.finish_partial_frame_timeout(&expected_id, kind));
                    }
                    return Err(self.timeout_committed_request(&expected_id, kind));
                }
                Err(TransportError::Timeout) if !self.transport_is_closed() => {
                    return Err(self.finish_open_context_interruption(
                        &expected_id,
                        McpError::internal_error("Request timed out"),
                    ));
                }
                Err(TransportError::Cancelled) if !self.transport_is_closed() => {
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
                    if self.cancel_legacy_reverse_callback(&request) {
                        continue;
                    }
                    match self.retain_modern_server_notification(&request) {
                        Ok(Some(ModernServerNotification::Progress(progress))) => {
                            if last_final_progress
                                .as_ref()
                                .is_none_or(|last| progress.progress.cmp(last).is_gt())
                                && progress.progress_token == *expected_marker
                            {
                                last_final_progress = Some(progress.progress.clone());
                                let callback_progress = progress
                                    .progress
                                    .as_str()
                                    .parse::<f64>()
                                    .ok()
                                    .filter(|value| value.is_finite());
                                let callback_total =
                                    progress.total.as_ref().map_or(Some(None), |total| {
                                        total
                                            .as_str()
                                            .parse::<f64>()
                                            .ok()
                                            .filter(|value| value.is_finite())
                                            .map(Some)
                                    });
                                if let (Some(callback_progress), Some(callback_total)) =
                                    (callback_progress, callback_total)
                                {
                                    if invoke_tool_progress_callback(
                                        &mut *on_progress,
                                        callback_progress,
                                        callback_total,
                                        progress.message.as_deref(),
                                    )
                                    .is_err()
                                    {
                                        let error =
                                            McpError::internal_error(PROGRESS_CALLBACK_PANIC_ERROR);
                                        return Err(self.finish_committed_request_locally(
                                            &expected_id,
                                            error,
                                        ));
                                    }
                                }
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
            LogLevel::Info | LogLevel::Notice => log::Level::Info,
            LogLevel::Warning => log::Level::Warn,
            LogLevel::Error | LogLevel::Critical | LogLevel::Alert | LogLevel::Emergency => {
                log::Level::Error
            }
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
    /// sends the historical RPC with the same RFC 5424 severity.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer rejects its historical acknowledgement.
    pub fn set_log_level_typed(&mut self, level: LoggingLevel) -> McpResult<()> {
        self.ensure_initialized()?;
        match self.session.selected_era() {
            Some(ProtocolEra::Modern2026) => {
                self.final_log_level = Some(level);
                Ok(())
            }
            Some(ProtocolEra::Legacy2024) => {
                let level = legacy_log_level(level);
                let params = SetLogLevelParams { level };
                let _: serde_json::Value = self.send_request("logging/setLevel", params)?;
                Ok(())
            }
            None => Err(McpError::internal_error(
                "Client has no negotiated protocol era for logging configuration",
            )),
        }
    }

    /// Configures one of the RFC 5424 severities supported by both protocol eras.
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

    /// Reads a resource and follows bounded final MRTR continuations with
    /// caller-supplied responses.
    ///
    /// See [`Self::call_tool_with_mrtr_retry`] for the shared bounded
    /// continuation and terminal-result behavior.
    pub fn read_resource_with_mrtr_retry<F>(
        &mut self,
        uri: &str,
        respond: F,
    ) -> McpResult<CoreResult>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
    {
        self.ensure_initialized()?;
        if self.session.selected_era() == Some(ProtocolEra::Legacy2024) {
            return self.read_resource_typed(uri);
        }
        let original_parameters = serde_json::json!({ "uri": uri });
        self.drive_mrtr_retry("resources/read", original_parameters, respond)
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

    /// Subscribes to one resource through the exact MCP 2024-11-05 method.
    ///
    /// This legacy method has no final-era equivalent. A modern session is
    /// rejected before serializing parameters, allocating an ID, or sending.
    pub fn subscribe_resource_legacy(&mut self, uri: &str) -> McpResult<()> {
        self.require_legacy_exact_result_session("resources/subscribe")?;
        let _: serde_json::Value = self.send_request(
            "resources/subscribe",
            SubscribeResourceParams {
                uri: uri.to_owned(),
            },
        )?;
        Ok(())
    }

    /// Ends one resource subscription through the exact MCP 2024-11-05 method.
    ///
    /// This legacy method has no final-era equivalent. A modern session is
    /// rejected before serializing parameters, allocating an ID, or sending.
    pub fn unsubscribe_resource_legacy(&mut self, uri: &str) -> McpResult<()> {
        self.require_legacy_exact_result_session("resources/unsubscribe")?;
        let _: serde_json::Value = self.send_request(
            "resources/unsubscribe",
            UnsubscribeResourceParams {
                uri: uri.to_owned(),
            },
        )?;
        Ok(())
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

    /// Gets a prompt and follows bounded final MRTR continuations with
    /// caller-supplied responses.
    ///
    /// See [`Self::call_tool_with_mrtr_retry`] for the shared bounded
    /// continuation and terminal-result behavior.
    pub fn get_prompt_with_mrtr_retry<F>(
        &mut self,
        name: &str,
        arguments: std::collections::HashMap<String, String>,
        respond: F,
    ) -> McpResult<CoreResult>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
    {
        self.ensure_initialized()?;
        if self.session.selected_era() == Some(ProtocolEra::Legacy2024) {
            return self.get_prompt_typed(name, arguments);
        }
        let mut retry_parameters = serde_json::json!({ "name": name });
        if !arguments.is_empty() {
            let parameters = retry_parameters.as_object_mut().ok_or_else(|| {
                McpError::internal_error("MRTR prompt parameters must remain an object")
            })?;
            parameters.insert(
                "arguments".to_owned(),
                serde_json::to_value(&arguments).map_err(|error| {
                    McpError::internal_error(format!(
                        "MRTR prompt arguments could not serialize: {error}"
                    ))
                })?,
            );
        }
        self.drive_mrtr_retry("prompts/get", retry_parameters, respond)
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
        if let Err(error) = self.send_to_server(&JsonRpcMessage::Request(request)) {
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
        // A dropped final multiplexed execution has no later receive or send
        // turn to drive its retirement. Drain it before failing waiters or
        // closing child stdin so its selected-era cancellation still receives
        // exactly one bounded control-write attempt.
        let deferred_retirement_result = self.flush_stdio_drop_retirements();
        self.initialized.store(false, Ordering::SeqCst);
        self.responses
            .fail_all(McpError::internal_error("Client connection closed"));
        self.cancel_reverse_callback_pool();
        self.join_reverse_callback_pool()?;

        // Transport teardown is one-shot. Preserve any failure because a
        // consumed writer cannot make a later close prove that the earlier
        // flush/close succeeded.
        let transport_result = self.close_transport().map_err(transport_error_to_mcp);
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
        let result = combine_cleanup_results(
            deferred_retirement_result,
            combine_cleanup_results(sticky_result, retryable_process_result),
        );
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
        self.cancel_reverse_callback_pool();
        self.join_reverse_callback_pool_unbounded();
        let _ = self.close_transport();
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
    use std::collections::{BTreeMap, HashMap};
    #[cfg(all(unix, not(target_os = "linux")))]
    use std::io::Read as _;
    #[cfg(unix)]
    use std::net::{TcpListener, TcpStream};
    use std::process::{Command, Stdio};

    #[cfg(unix)]
    use asupersync::runtime::RuntimeBuilder;

    #[test]
    fn auto_legacy_fallback_authorizes_only_method_not_found() {
        for (code, authorized) in [
            (McpErrorCode::MethodNotFound, true),
            (McpErrorCode::ParseError, false),
            (McpErrorCode::InvalidRequest, false),
            (McpErrorCode::InvalidParams, false),
            (McpErrorCode::InternalError, false),
        ] {
            let error = McpError::new(code, "discovery error");
            assert_eq!(
                auto_legacy_fallback_is_authorized(&error),
                authorized,
                "{code:?} must {}authorize a legacy child",
                if authorized { "" } else { "not " }
            );
        }
    }

    #[test]
    fn reverse_callback_forced_cancellation_before_writer_election_wins() {
        let state = Arc::new(ReverseCallbackState::default());
        let request_id = RequestId::Number(41);
        let cancellation = state
            .admit(&request_id)
            .expect("test callback is admitted before its worker starts");
        let writer_turn = Arc::new(Mutex::new(()));
        let writer_hold = writer_turn
            .lock()
            .expect("test owns the writer before the callback can commit");
        let (waiting_sender, waiting_receiver) = std::sync::mpsc::sync_channel(1);
        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
        let writes = Arc::new(AtomicUsize::new(0));
        let worker_state = Arc::clone(&state);
        let worker_cancellation = cancellation.clone();
        let worker_turn = Arc::clone(&writer_turn);
        let worker_request_id = request_id.clone();
        let worker_writes = Arc::clone(&writes);

        let worker = std::thread::spawn(move || {
            waiting_sender
                .send(())
                .expect("callback worker reaches the writer election");
            let _writer = worker_turn
                .lock()
                .expect("writer election lock remains valid");
            let claimed =
                worker_state.claim_response_if_open(&worker_request_id, &worker_cancellation);
            if claimed {
                worker_writes.fetch_add(1, Ordering::AcqRel);
            }
            result_sender
                .send(claimed)
                .expect("callback worker reports its terminal election");
        });

        waiting_receiver
            .recv()
            .expect("reader processes the queued cancellation before writer ownership releases");
        assert!(state.cancel(&request_id));
        drop(writer_hold);

        assert!(
            !result_receiver
                .recv()
                .expect("callback worker reports the forced election"),
            "a cancellation observed while the response waits for writer ownership must win"
        );
        assert!(cancellation.is_cancel_requested());
        assert_eq!(
            writes.load(Ordering::Acquire),
            0,
            "a cancelled callback cannot enter its response write"
        );
        worker.join().expect("callback worker does not panic");
    }

    #[test]
    fn reverse_callback_forced_writer_election_excludes_late_cancellation() {
        let state = Arc::new(ReverseCallbackState::default());
        let request_id = RequestId::Number(41);
        let cancellation = state
            .admit(&request_id)
            .expect("test callback is admitted before its worker starts");
        let (write_started_sender, write_started_receiver) = std::sync::mpsc::sync_channel(1);
        let (release_write_sender, release_write_receiver) = std::sync::mpsc::sync_channel(1);
        let worker_state = Arc::clone(&state);
        let worker_request_id = request_id.clone();
        let worker_cancellation = cancellation.clone();

        let worker = std::thread::spawn(move || {
            let claimed =
                worker_state.claim_response_if_open(&worker_request_id, &worker_cancellation);
            // The response is linearly elected before the potentially blocked
            // protocol-sized write permits cancellation processing to race it.
            write_started_sender
                .send(())
                .expect("test observes the committed response claim");
            release_write_receiver
                .recv()
                .expect("test releases the protocol-sized write model");
            claimed
        });
        write_started_receiver
            .recv()
            .expect("test observes the response write election");
        let cancel_state = Arc::clone(&state);
        let cancel_request_id = request_id.clone();
        let cancellation_attempt =
            std::thread::spawn(move || cancel_state.cancel(&cancel_request_id));
        release_write_sender
            .send(())
            .expect("test completes the atomic write model");

        assert!(
            worker.join().expect("callback worker does not panic"),
            "the response that reaches the actual write first owns the terminal outcome"
        );
        assert!(
            !cancellation_attempt
                .join()
                .expect("cancellation observer does not panic"),
            "a later cancellation finds no live callback after the write"
        );
        assert!(!cancellation.is_cancel_requested());
    }

    #[test]
    fn unrecoverable_reverse_callback_write_failure_is_connection_terminal() {
        let state = ReverseCallbackState::default();
        let request_id = RequestId::Number(41);
        let cancellation = state
            .admit(&request_id)
            .expect("callback is live before its write fails");
        let failure =
            McpError::internal_error("reverse callback write backpressure is unrecoverable");

        state.fail_connection(failure.clone());

        let terminal = state
            .terminal_error()
            .expect("terminal callback failure is retained");
        assert_eq!(terminal.code, failure.code);
        assert_eq!(terminal.message, failure.message);
        assert_eq!(terminal.data, failure.data);
        assert!(
            cancellation.is_cancel_requested(),
            "a terminal write failure cancels every outstanding callback"
        );
        assert!(
            state.admit(&RequestId::Number(42)).is_err(),
            "a terminal write failure rejects all later callback admission"
        );
    }

    #[test]
    fn reverse_callback_admission_has_a_fixed_backpressure_bound() {
        let state = ReverseCallbackState::default();
        let mut admitted = Vec::new();
        for id in 0..MAX_QUEUED_REVERSE_CALLBACKS {
            admitted.push(
                state
                    .admit(&RequestId::Number(
                        i64::try_from(id).expect("small test ID"),
                    ))
                    .expect("admission remains available through the exact bound"),
            );
        }

        let error = state
            .admit(&RequestId::Number(
                i64::try_from(MAX_QUEUED_REVERSE_CALLBACKS).expect("small overflow test ID"),
            ))
            .expect_err("one callback beyond the bound is rejected without queue growth");
        assert_eq!(error.code, McpErrorCode::InternalError);
        assert_eq!(error.message, "Client reverse callback capacity exceeded");
        state.cancel_all();
        assert!(
            admitted
                .iter()
                .all(ReverseRequestCancellation::is_cancel_requested),
            "shutdown cancellation reaches every bounded admission"
        );
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
    #[test]
    fn public_http_mrtr_drives_tool_resource_and_prompt_to_terminal_results() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind public MRTR listener");
        let address = listener.local_addr().expect("read public MRTR address");
        let modern_target = format!("http://{address}/mcp");
        let server = std::thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept public MRTR discovery");
            let probe = read_http_cache_test_request(&mut probe);
            assert_eq!(probe["id"], 1);
            assert_eq!(probe["method"], "server/discover");
            let discovery =
                modern_discovery_response("public-http-mrtr-server", &[MODERN_PROTOCOL_VERSION]);
            write_http_cache_test_response(&mut probe, "application/json", discovery.as_bytes());

            for (method, request_id, expected_state, next_state) in [
                ("tools/call", 2, None, Some("tool-one")),
                ("tools/call", 3, Some("tool-one"), Some("tool-two")),
                ("tools/call", 4, Some("tool-two"), None),
                ("resources/read", 5, None, Some("resource-one")),
                (
                    "resources/read",
                    6,
                    Some("resource-one"),
                    Some("resource-two"),
                ),
                ("resources/read", 7, Some("resource-two"), None),
                ("prompts/get", 8, None, Some("prompt-one")),
                ("prompts/get", 9, Some("prompt-one"), Some("prompt-two")),
                ("prompts/get", 10, Some("prompt-two"), None),
            ] {
                let (mut stream, _) = listener.accept().expect("accept public MRTR round");
                let request = read_http_cache_test_request(&mut stream);
                assert_eq!(request["id"], request_id);
                assert_eq!(request["method"], method);
                assert!(
                    request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
                        .get("extensions")
                        .is_none(),
                    "ordinary MRTR must not negotiate Tasks"
                );
                match expected_state {
                    Some(state) => {
                        assert_eq!(request["params"]["requestState"], state);
                        assert!(request["params"].get("inputResponses").is_none());
                    }
                    None => {
                        assert!(request["params"].get("requestState").is_none());
                        assert!(request["params"].get("inputResponses").is_none());
                    }
                }

                let response = match next_state {
                    Some(state) => format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":{request_id},\"result\":{{\"resultType\":\"input_required\",\"requestState\":\"{state}\"}}}}"
                    ),
                    None => match method {
                        "tools/call" => format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":{request_id},\"result\":{{\"resultType\":\"complete\",\"content\":[{{\"type\":\"text\",\"text\":\"done\"}}]}}}}"
                        ),
                        "resources/read" => format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":{request_id},\"result\":{{\"resultType\":\"complete\",\"contents\":[],\"ttlMs\":0,\"cacheScope\":\"private\"}}}}"
                        ),
                        "prompts/get" => format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":{request_id},\"result\":{{\"resultType\":\"complete\",\"messages\":[]}}}}"
                        ),
                        _ => unreachable!("the test covers only MRTR core methods"),
                    },
                };
                write_http_cache_test_response(
                    &mut stream,
                    "application/json",
                    response.as_bytes(),
                );
            }
        });

        let cx = Cx::for_request();
        let mut client = http_test_runtime_block_on(HttpClient::connect(
            &cx,
            http_cache_test_plan(&modern_target),
            ClientInfo {
                name: "public-http-mrtr-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("public HTTP client completes discovery");
        let sse_limits = sse::SseLimits::new(1_024, 8_192, 8).expect("valid SSE limits");

        let mut tool_states = Vec::new();
        let tool = http_test_runtime_block_on(client.call_tool_with_mrtr_retry_until(
            &cx,
            Instant::now() + Duration::from_secs(2),
            "public-tool",
            serde_json::json!({"input": "state-only"}),
            sse_limits,
            4_096,
            |input_required| {
                tool_states.push(
                    input_required
                        .request_state()
                        .expect("tool continuation carries state")
                        .to_owned(),
                );
                Ok(BTreeMap::new())
            },
        ))
        .expect("public HTTP tool MRTR reaches a terminal result");
        assert!(matches!(tool, FinalCoreResult::ToolsCall { .. }));
        assert_eq!(tool_states, ["tool-one", "tool-two"]);

        let mut resource_states = Vec::new();
        let resource = http_test_runtime_block_on(client.read_resource_with_mrtr_retry_until(
            &cx,
            Instant::now() + Duration::from_secs(2),
            "file:///public-mrtr.txt",
            sse_limits,
            4_096,
            |input_required| {
                resource_states.push(
                    input_required
                        .request_state()
                        .expect("resource continuation carries state")
                        .to_owned(),
                );
                Ok(BTreeMap::new())
            },
        ))
        .expect("public HTTP resource MRTR reaches a terminal result");
        assert!(matches!(resource, FinalCoreResult::ResourcesRead { .. }));
        assert_eq!(resource_states, ["resource-one", "resource-two"]);

        let mut prompt_states = Vec::new();
        let prompt = http_test_runtime_block_on(client.get_prompt_with_mrtr_retry_until(
            &cx,
            Instant::now() + Duration::from_secs(2),
            "public-prompt",
            HashMap::new(),
            sse_limits,
            4_096,
            |input_required| {
                prompt_states.push(
                    input_required
                        .request_state()
                        .expect("prompt continuation carries state")
                        .to_owned(),
                );
                Ok(BTreeMap::new())
            },
        ))
        .expect("public HTTP prompt MRTR reaches a terminal result");
        assert!(matches!(prompt, FinalCoreResult::PromptsGet { .. }));
        assert_eq!(prompt_states, ["prompt-one", "prompt-two"]);

        server.join().expect("public HTTP MRTR peer joins");
    }

    #[cfg(unix)]
    fn assert_public_http_mrtr_round_bound(final_round_is_terminal: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind public MRTR bound listener");
        let address = listener
            .local_addr()
            .expect("read public MRTR bound address");
        let modern_target = format!("http://{address}/mcp");
        let server = std::thread::spawn(move || {
            let (mut probe, _) = listener
                .accept()
                .expect("accept public MRTR bound discovery");
            let probe = read_http_cache_test_request(&mut probe);
            assert_eq!(probe["id"], 1);
            let discovery = modern_discovery_response(
                "public-http-mrtr-bound-server",
                &[MODERN_PROTOCOL_VERSION],
            );
            write_http_cache_test_response(&mut probe, "application/json", discovery.as_bytes());

            for request_id in 2..=(MAX_MRTR_CONTINUATION_ROUNDS as i64 + 2) {
                let (mut stream, _) = listener.accept().expect("accept public MRTR bound round");
                let request = read_http_cache_test_request(&mut stream);
                assert_eq!(request["id"], request_id);
                assert_eq!(request["method"], "tools/call");
                assert!(
                    request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
                        .get("extensions")
                        .is_none(),
                    "ordinary MRTR must not negotiate Tasks"
                );
                let response = if final_round_is_terminal
                    && request_id == MAX_MRTR_CONTINUATION_ROUNDS as i64 + 2
                {
                    format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":{request_id},\"result\":{{\"resultType\":\"complete\",\"content\":[]}}}}"
                    )
                } else {
                    format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":{request_id},\"result\":{{\"resultType\":\"input_required\",\"requestState\":\"round-{request_id}\"}}}}"
                    )
                };
                write_http_cache_test_response(
                    &mut stream,
                    "application/json",
                    response.as_bytes(),
                );
            }

            if !final_round_is_terminal {
                listener
                    .set_nonblocking(true)
                    .expect("configure public MRTR no-contact assertion");
                let no_contact_deadline = Instant::now() + Duration::from_millis(200);
                while Instant::now() < no_contact_deadline {
                    match listener.accept() {
                        Ok(_) => panic!("MRTR round bound must reject before a sixth POST"),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("unexpected public MRTR no-contact error: {error}"),
                    }
                }
            }
        });

        let cx = Cx::for_request();
        let mut client = http_test_runtime_block_on(HttpClient::connect(
            &cx,
            http_cache_test_plan(&modern_target),
            ClientInfo {
                name: "public-http-mrtr-bound-client".to_owned(),
                version: "1.0.0".to_owned(),
            },
            ClientCapabilities::default(),
        ))
        .expect("public HTTP bound client completes discovery");
        let mut callback_count = 0_usize;
        let result = http_test_runtime_block_on(client.call_tool_with_mrtr_retry_until(
            &cx,
            Instant::now() + Duration::from_secs(2),
            "bound-tool",
            serde_json::json!({}),
            sse::SseLimits::new(1_024, 8_192, 8).expect("valid SSE limits"),
            4_096,
            |_| {
                callback_count += 1;
                Ok(BTreeMap::new())
            },
        ));

        if final_round_is_terminal {
            assert!(matches!(result, Ok(FinalCoreResult::ToolsCall { .. })));
        } else {
            assert!(matches!(
                result,
                Err(HttpClientError::Connection(ClientHttpConnectionError::Mrtr(
                    http_executor::ModernHttpMrtrError::Driver(ref error)
                ))) if error.message == "MRTR continuation-round limit exceeded"
            ));
        }
        assert_eq!(callback_count, MAX_MRTR_CONTINUATION_ROUNDS);
        server.join().expect("public HTTP MRTR bound peer joins");
    }

    #[cfg(unix)]
    #[test]
    fn public_http_mrtr_round_bound_accepts_the_terminal_fifth_response() {
        assert_public_http_mrtr_round_bound(true);
    }

    #[cfg(unix)]
    #[test]
    fn public_http_mrtr_round_bound_rejects_only_an_input_required_fifth_response_without_contact()
    {
        assert_public_http_mrtr_round_bound(false);
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

        let filter = SubscriptionFilter {
            tools_list_changed: Some(true),
            ..SubscriptionFilter::default()
        };
        let limits =
            sse::SseLimits::new(1_024, 8_192, 16).expect("explicit SSE bounds are nonzero");
        if acknowledges_tools_list_changes {
            let listener =
                http_test_runtime_block_on(client.open_subscriptions_listener(&cx, filter, limits))
                    .expect("public HTTP listener opens");
            let mut listener = listener;
            assert!(matches!(
                http_test_runtime_block_on(listener.next_event(&cx))
                    .expect("listener acknowledgement is accepted"),
                Some(ModernHttpSubscriptionListenEvent::Acknowledged { .. })
            ));
            assert!(matches!(
                http_test_runtime_block_on(listener.next_event(&cx))
                    .expect("accepted HTTP change event is yielded live"),
                Some(ModernHttpSubscriptionListenEvent::Notification(
                    ServerNotification::ToolsListChanged(None)
                ))
            ));
            assert_eq!(listener.final_result_cache_stats().invalidations, 1);
            drop(listener);
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
            let listener =
                http_test_runtime_block_on(client.open_subscriptions_listener(&cx, filter, limits))
                    .expect("public HTTP listener opens before the planted filter mismatch");
            let mut listener = listener;
            assert!(matches!(
                http_test_runtime_block_on(listener.next_event(&cx))
                    .expect("empty acknowledgement itself is admitted"),
                Some(ModernHttpSubscriptionListenEvent::Acknowledged { .. })
            ));
            let error = http_test_runtime_block_on(listener.next_event(&cx))
                .expect_err("one omitted accepted-filter field rejects the event");
            assert!(matches!(
                error,
                HttpClientError::Connection(ClientHttpConnectionError::SubscriptionsListen(
                    http_executor::ModernHttpSubscriptionListenError::EventOutsideAcceptedFilter
                ))
            ));
            assert_eq!(listener.final_result_cache_stats().invalidations, 0);
            drop(listener);
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

    #[test]
    fn internal_client_constructors_own_the_shared_response_sender() {
        let mut initialized = make_closed_client(true);
        assert!(initialized.is_initialized());
        assert!(initialized.response_sender.lock().is_ok());
        initialized
            .close()
            .expect("initialized constructor cleanup");

        let mut uninitialized = make_closed_client(false);
        assert!(!uninitialized.is_initialized());
        assert!(uninitialized.response_sender.lock().is_ok());
        uninitialized
            .close()
            .expect("uninitialized constructor cleanup");
    }

    #[cfg(unix)]
    fn make_shell_scripted_initialized_client(script: &str, timeout: Duration) -> Client {
        make_shell_scripted_initialized_client_for_version(script, timeout, PROTOCOL_VERSION)
    }

    #[cfg(unix)]
    fn make_shell_scripted_initialized_client_with_reverse_handlers(
        script: &str,
        timeout: Duration,
        handlers: ReverseRequestHandlers,
    ) -> Client {
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
        let mut capabilities = ClientCapabilities::default();
        handlers.derive_legacy_capabilities(&mut capabilities);
        handlers
            .validate_legacy_capabilities(&capabilities)
            .expect("scripted legacy callbacks retain their advertised capability contract");
        let session = ClientSession::try_new(
            ClientInfo {
                name: "test-client".to_string(),
                version: "0.1.0".to_string(),
            },
            capabilities,
            ServerInfo {
                name: "scripted-server".to_string(),
                version: "1.0.0".to_string(),
            },
            ServerCapabilities::default(),
            PROTOCOL_VERSION.to_string(),
        )
        .expect("test client uses the exact legacy protocol version");
        let mut client = Client::from_parts(
            child,
            transport,
            Cx::for_request(),
            session,
            RequestTimeoutPolicy::new(timeout, timeout).unwrap(),
        );
        client.reverse_request_handlers = handlers;
        client
    }

    #[cfg(unix)]
    fn make_shell_scripted_initialized_client_for_version(
        script: &str,
        timeout: Duration,
        protocol_version: &str,
    ) -> Client {
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
            protocol_version.to_string(),
        )
        .expect("test client uses a supported protocol version");
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
        assert!(!client.transport_is_closed());
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
        let marker = ProgressMarker::Number(JsonInteger::from(2));
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
    fn public_cancellation_rejects_non_owned_id_without_peer_contact() {
        let script = "IFS= read -r request; \
            case \"$request\" in *'\"method\":\"test/new-generation\"'*'\"id\":2'*) \
              printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"request\":true}}\\n' ;; *) exit 1 ;; esac; \
            exec sleep 2";
        let mut client = make_shell_scripted_initialized_client(script, Duration::from_secs(2));

        let error = client
            .cancel_request(2_i64, Some("pre-cancel".to_string()))
            .expect_err("a peer-known but non-owned ID cannot produce a cancellation frame");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert_eq!(client.responses.cancellation_control_len(), 0);
        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 0);

        let evidence: serde_json::Value = client
            .send_request("test/new-generation", serde_json::json!({}))
            .expect("the first peer contact is the ordinary local request");
        assert_eq!(evidence, serde_json::json!({"request": true}));
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
            case \"$cancellation\" in *'\"awaitCleanup\"'*) cleanup_ok=false;; *) cleanup_ok=true;; esac; \
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
            .send_to_server(&JsonRpcMessage::Request(request))
            .expect("commit request before public cancellation");

        client
            .cancel_request(request_id.clone(), Some("stop".to_string()))
            .expect("first public cancellation must commit one control frame");
        let duplicate = client
            .cancel_request(request_id, Some("duplicate".to_string()))
            .expect_err("a retired request is no longer a live cancellation owner");
        assert_eq!(duplicate.code, McpErrorCode::InvalidRequest);

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
    fn modern_stdio_cancellation_uses_only_exact_cancellation_members() {
        let discovery =
            modern_discovery_response("modern-cancellation-server", &[MODERN_PROTOCOL_VERSION]);
        let script = format!(
            "IFS= read -r discovery || exit 1; \
             case \"$discovery\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery}' ;; *) exit 1 ;; esac; \
             IFS= read -r first || exit 1; \
             case \"$first\" in *'\"method\":\"test/cancel\"'*'\"id\":20'*) ;; *) exit 1 ;; esac; \
             IFS= read -r cancellation || exit 1; \
             case \"$cancellation\" in *'\"method\":\"notifications/cancelled\"'*'\"requestId\":20'*'\"reason\":\"stop\"'*) ;; *) exit 1 ;; esac; \
             case \"$cancellation\" in *'\"_meta\"'*|*'\"awaitCleanup\"'*) exit 1 ;; *) ;; esac; \
             IFS= read -r ping || exit 1; \
             case \"$ping\" in *'\"method\":\"ping\"'*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{}}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the cancellation client");

        let request_id = RequestId::Number(20);
        let mut waiter = client
            .responses
            .register(request_id.clone())
            .expect("register modern cancellation owner");
        client
            .send_to_server(&JsonRpcMessage::Request(JsonRpcRequest::new(
                "test/cancel",
                Some(serde_json::json!({})),
                20,
            )))
            .expect("commit request before modern cancellation");
        client
            .cancel_request(request_id, Some("stop".to_owned()))
            .expect("modern cancellation writes one final stdio notification");
        assert_eq!(
            waiter
                .try_response()
                .expect_err("the live modern owner receives local cancellation")
                .code,
            McpErrorCode::RequestCancelled
        );
        client
            .ping()
            .expect("the scripted peer admits only the exact final cancellation wire");
        assert_eq!(client.responses.cancellation_control_len(), 1);
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn modern_stdio_peer_cancellation_ignores_non_subscription_request_ids() {
        let discovery = modern_discovery_response(
            "modern-peer-cancellation-server",
            &[MODERN_PROTOCOL_VERSION],
        );
        let script = format!(
            "IFS= read -r discovery || exit 1; \
             case \"$discovery\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery}' ;; *) exit 1 ;; esac; \
             IFS= read -r first || exit 1; \
             case \"$first\" in *'\"method\":\"ping\"'*'\"id\":2'*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{{\"requestId\":2}}}}'; \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r second || exit 1; \
             case \"$second\" in *'\"method\":\"ping\"'*'\"id\":3'*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{}}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the peer-cancellation client");

        client
            .ping()
            .expect("matching final peer cancellation must not release a ping waiter");
        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 0);

        client
            .ping()
            .expect("subsequent ordinary requests remain aligned");
        assert_eq!(client.responses.tombstone_len(), 0);
        assert!(client.is_initialized());
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
            .send_to_server(&JsonRpcMessage::Request(request))
            .expect("commit request before oversized cancellation");

        let error = client
            .cancel_request(request_id, Some("x".repeat(512)))
            .expect_err("oversized atomic control must fail boundedly");

        assert_eq!(error.message, CONTROL_FRAME_CAPACITY_ERROR);
        let waiter_error = waiter
            .try_response()
            .expect_err("the first request-local outcome remains cancellation");
        assert_eq!(waiter_error.code, McpErrorCode::RequestCancelled);
        assert!(!client.is_initialized());
        assert!(client.transport_is_closed());
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
        let marker = ProgressMarker::Number(JsonInteger::from(2));
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
        let marker = ProgressMarker::Number(JsonInteger::from(2));
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
        let marker = ProgressMarker::Number(JsonInteger::from(2));
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
        let marker = ProgressMarker::Number(JsonInteger::from(2));
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
        let marker = ProgressMarker::Number(JsonInteger::from(2));
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
        let first_marker = ProgressMarker::Number(JsonInteger::from(2));
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
        let second_marker = ProgressMarker::Number(JsonInteger::from(3));
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
        assert_eq!(client.responses.uncorrelated_diagnostics(), 0);
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
        assert!(!client.transport_is_closed());
        assert!(client.responses.terminal_error().is_none());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_legacy_reverse_request_handlers_remain_unchanged() {
        let script = "IFS= read -r request; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":41,\"params\":{\"messages\":[],\"maxTokens\":9}}\\n'; \
            IFS= read -r sampling; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"roots/list\",\"id\":42}\\n'; \
            IFS= read -r roots; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"elicitation/create\",\"id\":43,\"params\":{\"mode\":\"form\",\"message\":\"approval\",\"requestedSchema\":{\"type\":\"object\",\"properties\":{}}}}\\n'; \
            IFS= read -r elicitation; \
            case \"$sampling\" in *'\"model\":\"handler-model\"'*'\"id\":41'*) sampling_ok=true;; *) sampling_ok=false;; esac; \
            case \"$roots\" in *'file:///workspace'*'\"id\":42'*) roots_ok=true;; *) roots_ok=false;; esac; \
            case \"$elicitation\" in *'\"code\":-32601'*'\"id\":43'*) elicitation_rejected=true;; *) elicitation_rejected=false;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"sampling\":%s,\"roots\":%s,\"elicitationRejected\":%s}}\\n' \
            \"$sampling_ok\" \"$roots_ok\" \"$elicitation_rejected\"; exec sleep 2";
        let sampling_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let roots_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let handlers = ReverseRequestHandlers::new()
            .with_sampling_create_message({
                let sampling_calls = std::sync::Arc::clone(&sampling_calls);
                move |_cancellation, params| {
                    sampling_calls.fetch_add(1, Ordering::Relaxed);
                    assert_eq!(params.max_tokens, 9);
                    Ok(CreateMessageResult::text("handled", "handler-model"))
                }
            })
            .with_roots_list({
                let roots_calls = std::sync::Arc::clone(&roots_calls);
                move |_cancellation, _params| {
                    roots_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(ListRootsResult::new(vec![fastmcp_protocol::Root::new(
                        "file:///workspace",
                    )]))
                }
            });
        let mut client = make_shell_scripted_initialized_client_with_reverse_handlers(
            script,
            Duration::from_secs(2),
            handlers,
        );
        assert_eq!(
            client.selected_protocol_era(),
            Some(ProtocolEra::Legacy2024)
        );

        let result: serde_json::Value = client
            .send_request("test/reverse-handlers", serde_json::json!({}))
            .expect("configured reverse handlers must answer live server requests");

        assert_eq!(
            result,
            serde_json::json!({"sampling": true, "roots": true, "elicitationRejected": true})
        );
        assert_eq!(sampling_calls.load(Ordering::Relaxed), 1);
        assert_eq!(roots_calls.load(Ordering::Relaxed), 1);
        assert!(client.is_initialized());
        assert!(!client.transport_is_closed());
        client.close().expect("client cleanup");
    }

    #[test]
    fn reverse_callback_cancellation_after_handler_lock_prevents_invocation() {
        let invoked = Arc::new(AtomicBool::new(false));
        let handler: Arc<
            Mutex<Box<dyn FnMut(ReverseRequestCancellation, ()) -> McpResult<()> + Send>>,
        > = Arc::new(Mutex::new(Box::new({
            let invoked = Arc::clone(&invoked);
            move |_cancellation, ()| {
                invoked.store(true, Ordering::Release);
                Ok(())
            }
        })));
        let handler_lock = handler
            .lock()
            .expect("hold the handler before worker acquisition");
        let cancellation = ReverseRequestCancellation::new();
        let worker_handler = Arc::clone(&handler);
        let worker_cancellation = cancellation.clone();
        let worker = std::thread::spawn(move || {
            invoke_locked_reverse_request_handler(&worker_handler, worker_cancellation, ())
        });

        cancellation.cancel();
        drop(handler_lock);

        let error = worker
            .join()
            .expect("callback worker must not panic")
            .expect_err("cancellation admitted while waiting for the lock must win");
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert!(
            !invoked.load(Ordering::Acquire),
            "the handler must not run after cancellation wins the lock race"
        );
    }

    #[cfg(unix)]
    #[test]
    fn protocol_sized_reverse_callback_response_preserves_follow_up_alignment() {
        let script = "IFS= read -r request; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":41,\"params\":{\"messages\":[],\"maxTokens\":9}}\\n'; \
            IFS= read -r sampling; \
            case \"$sampling\" in *'\"id\":41'*'\"model\":\"large-model\"'*) shape_ok=true;; *) shape_ok=false;; esac; \
            case ${#sampling} in [0-9]|[0-9][0-9]|[0-9][0-9][0-9]|[0-9][0-9][0-9][0-9][0-9]) frame_ok=false;; *) frame_ok=true;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"request\":true,\"frame\":%s,\"shape\":%s}}\\n' \"$frame_ok\" \"$shape_ok\"; \
            IFS= read -r ping; \
            case \"$ping\" in *'\"method\":\"ping\"'*'\"id\":3'*) ping_ok=true;; *) ping_ok=false;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"aligned\":%s}}\\n' \"$ping_ok\"; exec sleep 2";
        let handlers =
            ReverseRequestHandlers::new().with_sampling_create_message(|_cancellation, _params| {
                Ok(CreateMessageResult::text("x".repeat(2_048), "large-model"))
            });
        let mut client = make_shell_scripted_initialized_client_with_reverse_handlers(
            script,
            Duration::from_secs(2),
            handlers,
        );

        let first: serde_json::Value = client
            .send_request("test/protocol-sized-callback", serde_json::json!({}))
            .expect("a protocol-sized callback response must be framed normally");
        assert_eq!(
            first,
            serde_json::json!({"request": true, "frame": true, "shape": true})
        );
        let ping: serde_json::Value = client
            .send_request("ping", serde_json::json!({}))
            .expect("the following request remains frame-aligned");
        assert_eq!(ping, serde_json::json!({"aligned": true}));
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn reverse_callback_shutdown_is_bounded_and_retains_noncooperative_worker() {
        let script = "IFS= read -r request; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":41,\"params\":{\"messages\":[],\"maxTokens\":9}}\\n'; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"request\":true}}\\n'; exec sleep 2";
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let handlers = ReverseRequestHandlers::new().with_sampling_create_message({
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            move |_cancellation, _params| {
                started.store(true, Ordering::Release);
                while !release.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                Ok(CreateMessageResult::text("released", "shutdown-test"))
            }
        });
        let mut client = make_shell_scripted_initialized_client_with_reverse_handlers(
            script,
            Duration::from_secs(2),
            handlers,
        );

        let response: serde_json::Value = client
            .send_request("test/noncooperative-callback", serde_json::json!({}))
            .expect("the peer response remains independently readable");
        assert_eq!(response, serde_json::json!({"request": true}));
        let start_deadline = Instant::now() + Duration::from_millis(250);
        while !started.load(Ordering::Acquire) && Instant::now() < start_deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            started.load(Ordering::Acquire),
            "callback must be running before shutdown"
        );

        let close_started = Instant::now();
        let error = client
            .close()
            .expect_err("a noncooperative callback must bound explicit shutdown");
        assert_eq!(error.message, REVERSE_CALLBACK_SHUTDOWN_TIMEOUT_ERROR);
        assert!(
            close_started.elapsed() < Duration::from_secs(1),
            "explicit close must return within its callback-shutdown bound"
        );
        assert!(
            !client.reverse_callback_pool.workers.is_empty(),
            "the timed-out worker remains owned for a later join"
        );
        assert!(
            !client.transport_is_closed(),
            "a retained worker must not race transport teardown"
        );

        release.store(true, Ordering::Release);
        client
            .close()
            .expect("released callback is joined before final transport teardown");
    }

    #[cfg(unix)]
    #[test]
    fn clt_legacy_reverse_callback_cancellation_is_observable_without_blocking_reader() {
        let script = "IFS= read -r request; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":41,\"params\":{\"messages\":[],\"maxTokens\":9}}\\n'; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":41}}\\n'; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"readerRemainedLive\":true}}\\n'; \
            IFS= read -r ping; \
            case \"$request\" in *'\"id\":2'*) request_ok=true;; *) request_ok=false;; esac; \
            case \"$ping\" in *'\"method\":\"ping\"'*'\"id\":3'*) ping_ok=true;; *) ping_ok=false;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"request\":%s,\"ping\":%s}}\\n' \
            \"$request_ok\" \"$ping_ok\"; exec sleep 2";
        let observed_cancellation = std::sync::Arc::new(AtomicBool::new(false));
        let handlers = ReverseRequestHandlers::new().with_sampling_create_message({
            let observed_cancellation = std::sync::Arc::clone(&observed_cancellation);
            move |cancellation, _params| {
                while !cancellation.is_cancel_requested() {
                    std::thread::yield_now();
                }
                observed_cancellation.store(true, Ordering::Release);
                cancellation.checkpoint()?;
                Ok(CreateMessageResult::text("cancelled", "cancelled"))
            }
        });
        let mut client = make_shell_scripted_initialized_client_with_reverse_handlers(
            script,
            Duration::from_secs(2),
            handlers,
        );

        let result: serde_json::Value = client
            .send_request("test/reverse-callback-cancellation", serde_json::json!({}))
            .expect("the sole reader must receive the caller response while the callback waits");
        assert_eq!(result, serde_json::json!({"readerRemainedLive": true}));

        let deadline = Instant::now() + Duration::from_millis(250);
        while !observed_cancellation.load(Ordering::Acquire) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            observed_cancellation.load(Ordering::Acquire),
            "the live callback must observe its matching server cancellation"
        );

        let ping: serde_json::Value = client
            .send_request("ping", serde_json::json!({}))
            .expect("the reader remains usable after callback cancellation");
        assert_eq!(ping, serde_json::json!({"request": true, "ping": true}));
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_legacy_reverse_callback_foreign_cancellation_does_not_cancel_callback() {
        // This differs from the admitted cancellation path only by the server
        // cancellation request ID: 42 is not the live callback's ID 41.
        let script = "IFS= read -r request; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":41,\"params\":{\"messages\":[],\"maxTokens\":9}}\\n'; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":42}}\\n'; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"readerRemainedLive\":true}}\\n'; \
            IFS= read -r ping; \
            IFS= read -r callback; \
            case \"$request\" in *'\"id\":2'*) request_ok=true;; *) request_ok=false;; esac; \
            case \"$ping\" in *'\"method\":\"ping\"'*'\"id\":3'*) ping_ok=true;; *) ping_ok=false;; esac; \
            case \"$callback\" in *'\"id\":41'*'\"model\":\"uncancelled\"'*) callback_ok=true;; *) callback_ok=false;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"request\":%s,\"ping\":%s,\"callback\":%s}}\\n' \
            \"$request_ok\" \"$ping_ok\" \"$callback_ok\"; exec sleep 2";
        let release_callback = std::sync::Arc::new(AtomicBool::new(false));
        let observed_foreign_cancellation = std::sync::Arc::new(AtomicBool::new(false));
        let handlers = ReverseRequestHandlers::new().with_sampling_create_message({
            let release_callback = std::sync::Arc::clone(&release_callback);
            let observed_foreign_cancellation =
                std::sync::Arc::clone(&observed_foreign_cancellation);
            move |cancellation, _params| {
                while !release_callback.load(Ordering::Acquire) {
                    if cancellation.is_cancel_requested() {
                        observed_foreign_cancellation.store(true, Ordering::Release);
                        return Err(McpError::request_cancelled());
                    }
                    std::thread::yield_now();
                }
                assert!(
                    !cancellation.is_cancel_requested(),
                    "a foreign cancellation ID must not affect this callback"
                );
                Ok(CreateMessageResult::text("handled", "uncancelled"))
            }
        });
        let mut client = make_shell_scripted_initialized_client_with_reverse_handlers(
            script,
            Duration::from_secs(2),
            handlers,
        );

        let result: serde_json::Value = client
            .send_request("test/reverse-callback-cancellation", serde_json::json!({}))
            .expect("a foreign cancellation must not block the caller response");
        assert_eq!(result, serde_json::json!({"readerRemainedLive": true}));
        release_callback.store(true, Ordering::Release);

        let ping: serde_json::Value = client
            .send_request("ping", serde_json::json!({}))
            .expect("the uncancelled callback response and later ping remain aligned");
        assert_eq!(
            ping,
            serde_json::json!({"request": true, "ping": true, "callback": true})
        );
        assert!(
            !observed_foreign_cancellation.load(Ordering::Acquire),
            "only the cancellation request ID differs from the admitted path"
        );
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_modern_reverse_request_handlers_are_rejected_without_callback_mutation() {
        let script = "IFS= read -r request; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"sampling/createMessage\",\"id\":41,\"params\":{\"messages\":[],\"maxTokens\":9}}\\n'; \
            IFS= read -r sampling; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"roots/list\",\"id\":42}\\n'; \
            IFS= read -r roots; \
            printf '{\"jsonrpc\":\"2.0\",\"method\":\"elicitation/create\",\"id\":43,\"params\":{\"mode\":\"form\",\"message\":\"approval\",\"requestedSchema\":{\"type\":\"object\",\"properties\":{}}}}\\n'; \
            IFS= read -r elicitation; \
            case \"$sampling\" in *'\"code\":-32601'*'\"id\":41'*) sampling_rejected=true;; *) sampling_rejected=false;; esac; \
            case \"$roots\" in *'\"code\":-32601'*'\"id\":42'*) roots_rejected=true;; *) roots_rejected=false;; esac; \
            case \"$elicitation\" in *'\"code\":-32601'*'\"id\":43'*) elicitation_rejected=true;; *) elicitation_rejected=false;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"samplingRejected\":%s,\"rootsRejected\":%s,\"elicitationRejected\":%s}}\\n' \
            \"$sampling_rejected\" \"$roots_rejected\" \"$elicitation_rejected\"; exec sleep 2";
        let mut client = make_shell_scripted_initialized_client_for_version(
            script,
            Duration::from_secs(2),
            MODERN_PROTOCOL_VERSION,
        );
        assert_eq!(
            client.selected_protocol_era(),
            Some(ProtocolEra::Modern2026)
        );
        let result: serde_json::Value = client
            .send_request("test/reverse-handlers", serde_json::json!({}))
            .expect("modern rejection of legacy reverse requests must keep the session aligned");

        assert_eq!(
            result,
            serde_json::json!({
                "samplingRejected": true,
                "rootsRejected": true,
                "elicitationRejected": true
            })
        );
        assert!(client.is_initialized());
        assert!(!client.transport_is_closed());
        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 0);
        assert!(client.responses.terminal_error().is_none());
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
            case \"$sampling\" in *'\"model\":\"handler-model\"'*'\"id\":41'*) sampling_ok=true;; *) sampling_ok=false;; esac; \
            case \"$roots\" in *'\"code\":-32601'*'\"id\":42'*) roots_missing=true;; *) roots_missing=false;; esac; \
            printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"sampling\":%s,\"rootsMissing\":%s}}\\n' \
            \"$sampling_ok\" \"$roots_missing\"; exec sleep 2";
        let sampling_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let roots_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let handlers = ReverseRequestHandlers::new().with_sampling_create_message({
            let sampling_calls = std::sync::Arc::clone(&sampling_calls);
            move |_cancellation, _params| {
                sampling_calls.fetch_add(1, Ordering::Relaxed);
                Ok(CreateMessageResult::text("handled", "handler-model"))
            }
        });
        let mut client = make_shell_scripted_initialized_client_with_reverse_handlers(
            script,
            Duration::from_secs(2),
            handlers,
        );

        let result: serde_json::Value = client
            .send_request("test/reverse-handlers", serde_json::json!({}))
            .expect("a missing reverse handler must not disturb the live session");

        assert_eq!(
            result,
            serde_json::json!({"sampling": true, "rootsMissing": true})
        );
        assert_eq!(sampling_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            roots_calls.load(Ordering::Relaxed),
            0,
            "missing handler must leave state unchanged"
        );
        assert!(client.is_initialized());
        assert!(!client.transport_is_closed());
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
        assert_eq!(client.responses.uncorrelated_diagnostics(), 0);
        assert!(client.responses.terminal_error().is_none());
        assert!(client.is_initialized());
        assert!(!client.transport_is_closed());
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
        assert!(client.transport_is_closed());
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
            .send_to_server(&JsonRpcMessage::Request(request))
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
        assert!(client.transport_is_closed());
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
            .send_to_server(&JsonRpcMessage::Request(request))
            .expect("commit request before cancelling its stored context");
        let deadlines = RequestDeadlines::start_at(client.timeout_policy, Instant::now()).unwrap();
        client.cx.set_cancel_requested(true);

        let error = client
            .recv_response(waiter, deadlines)
            .expect_err("a cancelled stored context must terminate the owned connection");

        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert!(!client.is_initialized());
        assert!(client.transport_is_closed());
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
            .send_to_server(&JsonRpcMessage::Request(request))
            .expect("commit progress request before cancelling its stored context");
        let timeout_policy = client.timeout_policy;
        let deadlines = RequestDeadlines::start_at(timeout_policy, Instant::now()).unwrap();
        client.cx.set_cancel_requested(true);
        let marker = ProgressMarker::Number(JsonInteger::from(2));
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
        assert!(client.transport_is_closed());
        assert!(client.child.is_none());
        assert_eq!(client.responses.pending_len(), 0);
        assert_eq!(client.responses.tombstone_len(), 0);
        assert!(client.responses.terminal_error().is_some());
        client.close().expect("client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn complete_late_message_routes_unrelated_response_and_retires_tombstone() {
        // The unrelated response must arrive through the real transport:
        // routing now retains each response's raw admitted source frame, so a
        // fabricated in-memory response (which no frame ever carried) is
        // correctly refused by production code.
        let mut client = make_shell_scripted_initialized_client(
            r#"printf '%s
' '{"jsonrpc":"2.0","id":21,"result":{"owner":"unrelated"}}'; exec sleep 2"#,
            Duration::from_secs(1),
        );
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

        let recv_cx = Cx::for_request();
        let unrelated_message = client
            .transport
            .lock()
            .expect("client reader lock")
            .recv(&recv_cx)
            .expect("scripted unrelated response arrives with its source frame");

        let timeout = client.finish_timeout_after_complete_message(
            &timed_out_id,
            unrelated_message,
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
        assert_eq!(client.responses.uncorrelated_diagnostics(), 0);
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
        let (evidence, _) = recv_shared_child_transport(
            &client.transport,
            &client.cx,
            Some(Instant::now() + Duration::from_secs(2)),
        )
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
        assert!(!client.transport_is_closed());
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
        assert!(client.transport_is_closed());
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
                    if error.code
                        == JsonInteger::from(i64::from(i32::from(
                            fastmcp_core::McpErrorCode::MethodNotFound,
                        )))
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
                JsonInteger::from(i64::from(i32::from(
                    fastmcp_core::McpErrorCode::InvalidRequest,
                )))
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
                JsonInteger::from(i64::from(i32::from(
                    fastmcp_core::McpErrorCode::MethodNotFound,
                )))
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
    fn initializing_server_ping_request_is_not_serviced_before_era_selection() {
        let request = JsonRpcRequest::new("ping", None, "server-ping");
        let response = server_request_response(&request).expect("ping request has an ID");
        let JsonRpcMessage::Response(response) = response else {
            panic!("expected response");
        };

        assert_eq!(
            response.id,
            Some(RequestId::String("server-ping".to_string()))
        );
        assert!(response.result.is_none());
        assert!(matches!(
            response.error,
            Some(error)
                if error.code == JsonInteger::from(i64::from(i32::from(McpErrorCode::MethodNotFound)))
        ));
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
                code: (-32_603).into(),
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
            code: (-32_002).into(),
            message: "forbidden".to_string(),
            data: Some(serde_json::json!({"reason": "policy"})),
        });

        assert_eq!(error.code, McpErrorCode::ResourceForbidden);
        assert_eq!(error.message, "forbidden");
        assert_eq!(error.data, Some(serde_json::json!({"reason": "policy"})));
    }

    #[test]
    fn json_rpc_error_conversion_retains_an_arbitrary_width_peer_code_diagnostic() {
        let peer_code = "-999999999999999999999999999999999999999999999";
        let error = json_rpc_error_to_mcp(JsonRpcError {
            code: peer_code.parse().expect("huge JSON-RPC code is an integer"),
            message: "peer rejected request".to_string(),
            data: Some(serde_json::json!(["detail", 7])),
        });

        assert_eq!(error.code, McpErrorCode::InternalError);
        assert_eq!(error.message, "peer rejected request");
        let diagnostic = error.data.expect("wide peer code remains observable");
        assert_eq!(diagnostic["jsonrpcErrorCode"].to_string(), peer_code);
        assert_eq!(
            diagnostic["jsonrpcErrorData"],
            serde_json::json!(["detail", 7])
        );
    }

    #[test]
    fn json_rpc_error_conversion_retains_a_noncanonical_integer_code_spelling() {
        let error = json_rpc_error_to_mcp(JsonRpcError {
            code: "-326e2"
                .parse()
                .expect("a mathematical-integer JSON-RPC code is valid"),
            message: "formatted peer code".to_string(),
            data: None,
        });

        assert_eq!(error.code, McpErrorCode::Custom(-32_600));
        assert_eq!(
            error
                .data
                .expect("noncanonical code spelling remains observable")["jsonrpcErrorCode"]
                .to_string(),
            "-326e2"
        );
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
        assert_eq!(params.marker, ProgressMarker::Number(JsonInteger::from(42)));
        assert!((params.progress - 0.5).abs() < f64::EPSILON);
        assert!((params.total.unwrap() - 1.0).abs() < f64::EPSILON);
        assert_eq!(params.message.as_deref(), Some("Halfway done"));
    }

    #[test]
    fn client_progress_params_preserve_lossless_numeric_marker() {
        let json =
            serde_json::from_str(r#"{"progressToken":9007199254740993123456789,"progress":0.5}"#)
                .expect("large mathematical-integer progress marker is valid JSON");
        let params: ClientProgressParams =
            serde_json::from_value(json).expect("progress marker remains typed");
        let ProgressMarker::Number(marker) = params.marker else {
            panic!("numeric marker remains numeric");
        };
        assert_eq!(marker.as_str(), "9007199254740993123456789");
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
    fn modern_progress_ingress_retains_decimal_and_exponent_lexemes() {
        let frame = br#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"exact","progress":1.20e+4,"total":12000.0}}"#;
        let request: JsonRpcRequest =
            serde_json::from_slice(frame).expect("modern progress frame decodes structurally");
        let raw_params = raw_notification_params_from_frame(frame)
            .expect("client retains the exact notification params source")
            .expect("modern progress has params");
        let notification = decode_final_server_notification(&request, Some(&raw_params))
            .expect("exact decimal and exponent progress are admitted on client ingress");
        let ServerNotification::Progress(params) = notification else {
            panic!("modern progress frame selects the exact final progress branch");
        };
        assert_eq!(params.progress.as_str(), "1.20e+4");
        assert_eq!(
            params.total.as_ref().map(|total| total.as_str()),
            Some("12000.0")
        );
    }

    #[test]
    fn modern_progress_ingress_rejects_total_below_progress() {
        let frame = br#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"exact","progress":1.20e+4,"total":11999.0}}"#;
        let request: JsonRpcRequest = serde_json::from_slice(frame)
            .expect("one-variable over-total frame decodes structurally");
        let raw_params = raw_notification_params_from_frame(frame)
            .expect("client retains the exact notification params source")
            .expect("modern progress has params");

        assert!(
            decode_final_server_notification(&request, Some(&raw_params)).is_err(),
            "changing only total below progress rejects modern final progress on ingress"
        );
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
    fn final_log_message_sink_projection_preserves_all_legacy_levels() {
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

        let projection = final_log_message_sink_projection(&message);
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

        for (level, expected) in [
            (LoggingLevel::Debug, LogLevel::Debug),
            (LoggingLevel::Info, LogLevel::Info),
            (LoggingLevel::Notice, LogLevel::Notice),
            (LoggingLevel::Warning, LogLevel::Warning),
            (LoggingLevel::Error, LogLevel::Error),
            (LoggingLevel::Critical, LogLevel::Critical),
            (LoggingLevel::Alert, LogLevel::Alert),
            (LoggingLevel::Emergency, LogLevel::Emergency),
        ] {
            let projected = final_log_message_sink_projection(&FinalLogMessageParams {
                level,
                logger: Some("server.audit".to_owned()),
                data: serde_json::json!("event"),
                meta: None,
                additional: std::collections::BTreeMap::new(),
            });
            assert_eq!(projected.level, expected);
        }
    }

    #[test]
    fn client_legacy_log_level_mappings_preserve_all_eight_severities() {
        for (legacy, final_level, wire) in [
            (LogLevel::Debug, LoggingLevel::Debug, "debug"),
            (LogLevel::Info, LoggingLevel::Info, "info"),
            (LogLevel::Notice, LoggingLevel::Notice, "notice"),
            (LogLevel::Warning, LoggingLevel::Warning, "warning"),
            (LogLevel::Error, LoggingLevel::Error, "error"),
            (LogLevel::Critical, LoggingLevel::Critical, "critical"),
            (LogLevel::Alert, LoggingLevel::Alert, "alert"),
            (LogLevel::Emergency, LoggingLevel::Emergency, "emergency"),
        ] {
            assert_eq!(final_log_level(legacy), final_level);
            assert_eq!(legacy_log_level(final_level), legacy);
            let metadata = remote_log_metadata(&LogMessageParams {
                level: legacy,
                logger: None,
                data: serde_json::Value::Null,
            })
            .to_string();
            assert!(metadata.contains(&format!("level={wire}")));
        }
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

    #[cfg(unix)]
    #[test]
    fn dropped_multiplexed_stdio_executions_retire_at_the_next_client_progress_point() {
        let mut client = make_shell_scripted_initialized_client(
            "while IFS= read -r _; do :; done",
            Duration::from_secs(2),
        );
        client.install_multiplexed_stdio_executor();
        let cx = Cx::for_request();

        for _ in 0..1_024 {
            drop(
                client
                    .start_multiplexed_request(&cx, "ping", Some(serde_json::json!({})))
                    .expect("each silent-peer request commits before its owner is dropped"),
            );
        }

        let final_execution = client
            .start_multiplexed_request(&cx, "ping", Some(serde_json::json!({})))
            .expect("dropped owners must not exhaust the live in-flight limit");
        assert_eq!(client.responses.pending_len(), 1);
        assert_eq!(client.responses.tombstone_len(), 1_024);
        assert_eq!(client.responses.cancellation_control_len(), 1_024);
        drop(final_execution);
        assert_eq!(client.responses.pending_len(), 1);
        client.close().expect("silent-peer stdio client cleanup");
    }

    #[test]
    fn completed_multiplexed_stdio_execution_does_not_request_drop_retirement() {
        let (sender, receiver) = oneshot::channel();
        let retirement = Arc::new(StdioDropRetirement {
            request_id: RequestId::Number(91),
            peer_era: ProtocolEra::Modern2026,
            requested: AtomicBool::new(false),
        });
        let execution = StdioRequestExecution {
            request_id: RequestId::Number(91),
            waiter: Some(ResponseWaiter {
                id: RequestId::Number(91),
                receiver,
            }),
            drop_retirement: Arc::clone(&retirement),
            drop_retirements: SharedStdioDropRetirements::default(),
            committed_at: Instant::now(),
            completed: true,
        };
        drop(sender);
        drop(execution);

        assert!(!retirement.requested.load(Ordering::Acquire));
    }

    #[cfg(unix)]
    #[test]
    fn multiplexed_stdio_reordered_responses_retain_their_inbound_raw_result_frames() {
        let second_raw_result = r#"{"owner":"second","exact":1.20e+4}"#;
        let first_raw_result = r#"{"owner":"first","exact":7.30e-2}"#;
        let script = format!(
            "printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{second_raw_result}}}'; \\
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{first_raw_result}}}'; \\
             exec sleep 2"
        );
        let mut client = make_shell_scripted_initialized_client(&script, Duration::from_secs(1));
        client.install_multiplexed_stdio_executor();
        let cx = Cx::for_request();
        let mut first = client
            .start_multiplexed_request(&cx, "ping", Some(serde_json::json!({})))
            .expect("first request commits");
        let mut second = client
            .start_multiplexed_request(&cx, "ping", Some(serde_json::json!({})))
            .expect("second request commits");
        assert_eq!(first.request_id(), &RequestId::Number(2));
        assert_eq!(second.request_id(), &RequestId::Number(3));

        let first_waiter = first.waiter.take().expect("first waiter remains owned");
        let deadlines = RequestDeadlines::start_at(client.timeout_policy, first.committed_at)
            .expect("test timeout policy is valid");
        let first_response = client
            .recv_response_with_cx(&cx, first_waiter, deadlines)
            .expect("the sole reader routes both out-of-order responses");
        first.completed = true;
        assert_eq!(first_response.id, Some(RequestId::Number(2)));
        assert_eq!(first_response.raw_result.as_deref(), Some(first_raw_result));

        let second_waiter = second.waiter.take().expect("second waiter remains owned");
        let deadlines = RequestDeadlines::start_at(client.timeout_policy, second.committed_at)
            .expect("test timeout policy is valid");
        let second_response = client
            .recv_response_with_cx(&cx, second_waiter, deadlines)
            .expect("the reordered second response remains in its exact waiter");
        second.completed = true;
        assert_eq!(second_response.id, Some(RequestId::Number(3)));
        assert_eq!(
            second_response.raw_result.as_deref(),
            Some(second_raw_result)
        );
        client.close().expect("reordered stdio client cleanup");
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
            .cancel_request(50_i64, None)
            .expect_err("initialized APIs must not retry a terminal connection");
        assert_eq!(later.code, error.code);
        assert_eq!(later.message, error.message);
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

        let _ = client.cancel_request(7i64, Some("stop".to_string()));
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
            .cancel_request(99_i64, None)
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
    fn modern_mrtr_retry_client_script(method: &str, complete_result: &str) -> String {
        let discovery_response =
            modern_discovery_response("mrtr-retry-modern-server", &[MODERN_PROTOCOL_VERSION]);
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r initial || exit 1; \
             case \"$initial\" in *{method}*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"resultType\":\"input_required\",\"inputRequests\":{{\"roots\":{{\"method\":\"roots/list\"}}}},\"requestState\":\"retry-1\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r retry || exit 1; \
             case \"$retry\" in *{method}*'\"inputResponses\":{{\"roots\":{{\"roots\":[]}}}}'*'\"requestState\":\"retry-1\"'*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{complete_result}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_mrtr_multi_round_client_script() -> String {
        let discovery_response =
            modern_discovery_response("mrtr-multi-round-modern-server", &[MODERN_PROTOCOL_VERSION]);
        format!(
            "IFS= read -r discover || exit 1; \
             case \"$discover\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r initial || exit 1; \
             case \"$initial\" in *'\"id\":2'*tools/call*'\"name\":\"retry-tool\"'*'\"arguments\":{{\"round\":1}}'*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"resultType\":\"input_required\",\"inputRequests\":{{\"roots\":{{\"method\":\"roots/list\"}}}},\"requestState\":\"retry-1\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r first_retry || exit 1; \
             case \"$first_retry\" in *'\"id\":3'*tools/call*'\"name\":\"retry-tool\"'*'\"arguments\":{{\"round\":1}}'*'\"inputResponses\":{{\"roots\":{{\"roots\":[]}}}}'*'\"requestState\":\"retry-1\"'*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{\"resultType\":\"input_required\",\"requestState\":\"retry-2\"}}}}' ;; *) exit 1 ;; esac; \
             IFS= read -r state_only_retry || exit 1; \
             case \"$state_only_retry\" in *'\"inputResponses\"'*) exit 1 ;; *'\"id\":4'*tools/call*'\"name\":\"retry-tool\"'*'\"arguments\":{{\"round\":1}}'*'\"requestState\":\"retry-2\"'*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{{\"resultType\":\"complete\",\"content\":[],\"isError\":false}}}}' ;; *) exit 1 ;; esac; \
             exec sleep 2"
        )
    }

    #[cfg(unix)]
    fn modern_mrtr_round_bound_client_script() -> String {
        let discovery_response =
            modern_discovery_response("mrtr-round-bound-modern-server", &[MODERN_PROTOCOL_VERSION]);
        let mut rounds = String::new();
        for request_id in 2..=(MAX_MRTR_CONTINUATION_ROUNDS + 2) {
            let continuation_response = format!(
                r#"{{"jsonrpc":"2.0","id":{request_id},"result":{{"resultType":"input_required","inputRequests":{{"roots":{{"method":"roots/list"}}}},"requestState":"retry-bound"}}}}"#,
            );
            let expected_input_responses = if request_id == 2 {
                ""
            } else {
                "*'\"inputResponses\":{\"roots\":{\"roots\":[]}}'"
            };
            rounds.push_str(&format!(
                "IFS= read -r request || exit 1; \
                 case \"$request\" in *'\"id\":{request_id}'*tools/call*'\"name\":\"retry-tool\"'*'\"arguments\":{{\"round\":1}}'{expected_input_responses}*) ;; *) exit 1 ;; esac; \
                 printf '%s\\n' '{continuation_response}'; \
                 "
            ));
        }
        format!(
            "IFS= read -r discover || exit 1; \
             case \"$discover\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             {rounds}exec sleep 2"
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
    fn modern_reverse_ping_client_script() -> String {
        let discovery_response =
            modern_discovery_response("reverse-ping-modern-server", &[MODERN_PROTOCOL_VERSION]);
        format!(
            "IFS= read -r first || exit 1; \
             case \"$first\" in *server/discover*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{discovery_response}' ;; *) exit 1 ;; esac; \
             IFS= read -r call || exit 1; \
             case \"$call\" in *tools/call*io.modelcontextprotocol/protocolVersion*2026-07-28*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":\"server-ping\",\"method\":\"ping\"}}'; \
             IFS= read -r reverse_response || exit 1; \
             case \"$reverse_response\" in *'\"id\":\"server-ping\"'*'\"code\":-32601'*) \
             printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"resultType\":\"complete\",\"content\":[{{\"type\":\"text\",\"text\":\"reverse ping rejected\"}}],\"isError\":false}}}}' ;; *) exit 1 ;; esac \
             ;; *) exit 1 ;; esac; \
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
    fn legacy_reverse_ping_client_script() -> &'static str {
        "IFS= read -r first || exit 1; \
         case \"$first\" in *initialize*2024-11-05*) \
         printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-reverse-ping-server\",\"version\":\"1.0.0\"}}}' ;; *) exit 1 ;; esac; \
         IFS= read -r lifecycle || exit 1; \
         case \"$lifecycle\" in *notifications/initialized*) ;; *) exit 1 ;; esac; \
         IFS= read -r client_ping || exit 1; \
         case \"$client_ping\" in *ping*io.modelcontextprotocol/*|*ping*io.modelcontextprotocol/clientCapabilities*) exit 1 ;; \
         *ping*) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":\"server-ping\",\"method\":\"ping\"}'; ;; *) exit 1 ;; esac; \
         IFS= read -r reverse_response || exit 1; \
         case \"$reverse_response\" in *'\"id\":\"server-ping\"'*'\"result\":{}'*) \
         printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}' ;; *) exit 1 ;; esac; \
         exec sleep 2"
    }

    #[cfg(unix)]
    fn legacy_resource_subscription_client_script() -> &'static str {
        "IFS= read -r first || exit 1; \
         case \"$first\" in *initialize*2024-11-05*) \
         printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"legacy-resource-subscriptions\",\"version\":\"1.0.0\"}}}' ;; *) exit 1 ;; esac; \
         IFS= read -r lifecycle || exit 1; \
         case \"$lifecycle\" in *notifications/initialized*) ;; *) exit 1 ;; esac; \
         IFS= read -r subscribe || exit 1; \
         case \"$subscribe\" in *resources/subscribe*'\"uri\":\"resource://test\"'*io.modelcontextprotocol/*) exit 1 ;; \
         *resources/subscribe*'\"uri\":\"resource://test\"'*) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}' ;; *) exit 1 ;; esac; \
         IFS= read -r unsubscribe || exit 1; \
         case \"$unsubscribe\" in *resources/unsubscribe*'\"uri\":\"resource://test\"'*io.modelcontextprotocol/*) exit 1 ;; \
         *resources/unsubscribe*'\"uri\":\"resource://test\"'*) printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}' ;; *) exit 1 ;; esac; \
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
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_modern_ping_rejects_before_request_mutation() {
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

        let next_id_before = client.next_id.load(Ordering::SeqCst);
        let error = client
            .ping()
            .expect_err("ping belongs exclusively to exact MCP 2024-11-05");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(client.next_id.load(Ordering::SeqCst), next_id_before);
        assert!(client.is_initialized());
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_modern_server_ping_is_rejected_during_public_request() {
        let script = modern_reverse_ping_client_script();
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the public client");

        let content = client
            .call_tool("echo", serde_json::json!({"text": "reverse ping"}))
            .expect("the modern peer observes method-not-found before its complete response");
        assert_eq!(content.len(), 1);
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
    fn clt_01_mrtr_retry_replays_tools_resources_and_prompts_once() {
        let responses =
            || BTreeMap::from([("roots".to_owned(), serde_json::json!({ "roots": [] }))]);

        let script = modern_mrtr_retry_client_script(
            "tools/call",
            r#"{"resultType":"complete","content":[],"isError":false}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the MRTR tool client");
        assert!(matches!(
            client
                .call_tool_with_mrtr_retry("retry-tool", serde_json::json!({}), |_| {
                    Ok(responses())
                })
                .expect("one final input-required tool result is retried once"),
            CoreResult::Final(FinalCoreResult::ToolsCall { .. })
        ));
        client.close().expect("MRTR tool client cleanup");

        let script = modern_mrtr_retry_client_script(
            "resources/read",
            r#"{"resultType":"complete","contents":[],"ttlMs":0,"cacheScope":"private"}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the MRTR resource client");
        assert!(matches!(
            client
                .read_resource_with_mrtr_retry("file:///retry.txt", |_| Ok(responses()))
                .expect("one final input-required resource result is retried once"),
            CoreResult::Final(FinalCoreResult::ResourcesRead { .. })
        ));
        client.close().expect("MRTR resource client cleanup");

        let script = modern_mrtr_retry_client_script(
            "prompts/get",
            r#"{"resultType":"complete","messages":[]}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the MRTR prompt client");
        assert!(matches!(
            client
                .get_prompt_with_mrtr_retry("retry-prompt", HashMap::new(), |_| Ok(responses()))
                .expect("one final input-required prompt result is retried once"),
            CoreResult::Final(FinalCoreResult::PromptsGet { .. })
        ));
        client.close().expect("MRTR prompt client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_mrtr_multi_round_rebuilds_original_params_and_allows_state_only() {
        let script = modern_mrtr_multi_round_client_script();
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the multi-round MRTR client");

        let mut callback_count = 0;
        let result = client
            .call_tool_with_mrtr_retry(
                "retry-tool",
                serde_json::json!({ "round": 1 }),
                |input_required| {
                    callback_count += 1;
                    match callback_count {
                        1 => {
                            assert_eq!(input_required.request_state(), Some("retry-1"));
                            Ok(BTreeMap::from([(
                                "roots".to_owned(),
                                serde_json::json!({ "roots": [] }),
                            )]))
                        }
                        2 => {
                            assert_eq!(input_required.request_state(), Some("retry-2"));
                            assert!(
                                input_required.input_requests().is_none(),
                                "the second continuation is intentionally state-only"
                            );
                            Ok(BTreeMap::new())
                        }
                        _ => panic!("the completed operation must not invoke another continuation"),
                    }
                },
            )
            .expect("two input-required results continue to a public final result");

        assert!(matches!(
            result,
            CoreResult::Final(FinalCoreResult::ToolsCall { .. })
        ));
        assert_eq!(callback_count, 2);
        client.close().expect("multi-round MRTR client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_mrtr_round_bound_rejects_one_extra_continuation_before_callback_or_send() {
        let script = modern_mrtr_round_bound_client_script();
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the bound MRTR client");

        let mut callback_count = 0;
        let error = client
            .call_tool_with_mrtr_retry("retry-tool", serde_json::json!({ "round": 1 }), |_| {
                callback_count += 1;
                Ok(BTreeMap::from([(
                    "roots".to_owned(),
                    serde_json::json!({ "roots": [] }),
                )]))
            })
            .expect_err("one continuation beyond the round bound must fail locally");

        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(error.message, "MRTR continuation-round limit exceeded");
        assert_eq!(callback_count, MAX_MRTR_CONTINUATION_ROUNDS);
        client.close().expect("round-bound MRTR client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_mrtr_retry_keeps_exact_legacy_tool_behavior() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_typed_call_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy initialization succeeds before the MRTR entry point");

        let mut callback_count = 0;
        let result = client
            .call_tool_with_mrtr_retry("echo", serde_json::json!({ "text": "legacy" }), |_| {
                callback_count += 1;
                Ok(BTreeMap::new())
            })
            .expect("legacy MRTR entry retains the one-request typed behavior");

        assert!(matches!(
            result,
            CoreResult::Legacy(LegacyCoreResult::ToolsCall(_))
        ));
        assert_eq!(callback_count, 0);
        client.close().expect("legacy MRTR client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_mrtr_retry_rejects_one_unrequested_response_key_before_retry() {
        let script = modern_mrtr_retry_client_script(
            "tools/call",
            r#"{"resultType":"complete","content":[],"isError":false}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes before the planted MRTR response key");

        let error = client
            .call_tool_with_mrtr_retry("retry-tool", serde_json::json!({}), |_| {
                Ok(BTreeMap::from([(
                    "other".to_owned(),
                    serde_json::json!({ "roots": [] }),
                )]))
            })
            .expect_err("changing only the response key rejects the retry before a second request");
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(
            error.message,
            "MRTR inputResponses contain a key not requested by the peer"
        );
        client.close().expect("planted MRTR response-key cleanup");
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
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","contents":[{"uri":"file:///exact.txt","text":"exact resource","mimeType":"text/plain","_meta":{"io.fastmcp.retained":true},"io.fastmcp.extension":"retained"}],"ttlMs":7.3e1,"cacheScope":"public"}}"#,
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
        assert_eq!(resource_result.ttl_ms.as_str(), "7.3e1");
        assert_eq!(
            resource_result
                .ttl_ms
                .try_as_millis()
                .expect("resource TTL fits the local duration domain"),
            73
        );
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
            &[
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2e0,"_meta":{"io.modelcontextprotocol/subscriptionId":2.0}}}"#,
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
    fn clt_01_subscriptions_listen_ignores_invalid_or_foreign_cancellation_controls() {
        let script = modern_subscriptions_listen_client_script(
            2,
            &[
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":null}}"#,
                r#"{"jsonrpc":"2.0","id":99,"method":"notifications/cancelled","params":{"requestId":2}}"#,
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2,"reason":null}}"#,
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}"#,
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2,"_meta":{"io.modelcontextprotocol/subscriptionId":3}}}"#,
                r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#,
                r#"{"jsonrpc":"2.0","id":2e0,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":2.0}}}"#,
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
            .expect("invalid and foreign controls are inert for the owned live listener");
        assert!(matches!(
            collector.notifications.as_slice(),
            [ServerNotification::ToolsListChanged(None)]
        ));
        assert!(client.is_initialized());
        assert!(client.responses.terminal_error().is_none());
        client.close().expect("modern client cleanup");
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
        assert_eq!(client.responses.uncorrelated_diagnostics(), 0);
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
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","completion":{"values":["staging"],"total":922337203685477580812345678901234567890,"hasMore":false}}}"#,
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
        let expected_total =
            serde_json::from_str::<JsonInteger>("922337203685477580812345678901234567890")
                .expect("arbitrary-precision completion total is an exact JSON integer");
        assert_eq!(result.payload.completion.total, Some(expected_total));
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
    fn clt_01_final_progress_queue_preserves_decimal_exponent_positive() {
        let script = modern_server_notification_client_script(
            r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":2,"progress":1e400,"total":1e401,"message":"exact progress"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"progress result"}],"isError":false}}"#,
        );
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes the public client");
        let mut legacy_progress = Vec::new();
        let mut on_progress = |progress: f64, total: Option<f64>, message: Option<&str>| {
            legacy_progress.push((progress, total, message.map(ToOwned::to_owned)));
        };

        client
            .call_tool_with_progress(
                "echo",
                serde_json::json!({"text": "exact progress"}),
                &mut on_progress,
            )
            .expect("an exact final progress value does not lose its following response");
        assert!(
            legacy_progress.is_empty(),
            "the legacy f64 callback must not receive an unrepresentable value"
        );

        let progress = client.take_final_progress_notifications();
        assert!(matches!(
            progress.as_slice(),
            [params]
                if params.progress.as_str() == "1e400"
                    && params.total.as_ref().is_some_and(|total| total.as_str() == "1e401")
                    && params.message.as_deref() == Some("exact progress")
        ));
        assert!(client.take_final_progress_notifications().is_empty());
        client.close().expect("modern client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn clt_01_final_progress_queue_rejects_total_below_progress() {
        // This differs from the accepted exact-progress frame only in `total`.
        let script = modern_server_notification_client_script(
            r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":2,"progress":1e400,"total":9e399,"message":"exact progress"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"progress result"}],"isError":false}}"#,
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
                serde_json::json!({"text": "exact progress"}),
                &mut on_progress,
            )
            .expect_err("final progress greater than its total must fail the public request");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(client.take_final_progress_notifications().is_empty());
        assert!(!client.is_initialized());
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
        assert_eq!(discovery.cache_hints().ttl_ms().as_str(), "73");
        assert_eq!(
            discovery
                .cache_hints()
                .ttl_ms()
                .try_as_millis()
                .expect("discovery TTL fits the local duration domain"),
            73
        );
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
    fn clt_02_discovery_non_complete_result_types_do_not_select_an_era() {
        let baseline =
            modern_discovery_response("invalid-discriminator-server", &[MODERN_PROTOCOL_VERSION]);
        for planted_result_type in [
            serde_json::json!("input_required"),
            serde_json::json!("task"),
            serde_json::json!("com.example/deferred-discovery"),
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
            .expect("every non-complete discriminator rejects discovery");
            assert_eq!(error.code, McpErrorCode::InternalError);
        }

        for (member, value) in [
            ("requestState", serde_json::json!("resume-1")),
            (
                "inputRequests",
                serde_json::json!({"roots": {"method": "roots/list"}}),
            ),
            ("taskId", serde_json::json!("task-1")),
        ] {
            let mut response: serde_json::Value =
                serde_json::from_str(&baseline).expect("baseline discovery response is JSON");
            response["result"][member] = value;
            let response = serde_json::to_string(&response)
                .expect("contradictory discovery response remains JSON");
            let script = modern_public_client_script(&response);
            let error = Client::stdio_with_protocol_plan_with_cx(
                "sh",
                &["-c", script.as_str()],
                ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
                Cx::for_request(),
            )
            .err()
            .expect("a contradictory final shape rejects discovery before negotiation");
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
    fn leg_03_server_ping_succeeds_during_public_request() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_reverse_ping_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy initialization succeeds before the reverse ping request");

        client
            .ping()
            .expect("a selected exact legacy session acknowledges server-originated ping");
        client.close().expect("legacy client cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_resource_subscriptions_use_the_exact_legacy_request_path() {
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", legacy_resource_subscription_client_script()],
            ClientProtocolPlan::stdio(ProtocolPolicy::LegacyOnly),
            Cx::for_request(),
        )
        .expect("legacy initialization succeeds before resource subscription requests");

        client
            .subscribe_resource_legacy("resource://test")
            .expect("exact legacy resources/subscribe omits final metadata");
        client
            .unsubscribe_resource_legacy("resource://test")
            .expect("exact legacy resources/unsubscribe omits final metadata");
        client
            .close()
            .expect("legacy resource subscription cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn leg_03_resource_subscriptions_reject_modern_before_request_mutation() {
        let discovery = modern_discovery_response(
            "modern-resource-subscriptions-server",
            &[MODERN_PROTOCOL_VERSION],
        );
        let script = modern_public_client_script(&discovery);
        let mut client = Client::stdio_with_protocol_plan_with_cx(
            "sh",
            &["-c", script.as_str()],
            ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly),
            Cx::for_request(),
        )
        .expect("modern discovery initializes before legacy resource rejection");
        let next_id_before = client.next_id.load(Ordering::SeqCst);

        for operation in [
            Client::subscribe_resource_legacy,
            Client::unsubscribe_resource_legacy,
        ] {
            let error = operation(&mut client, "resource://test")
                .expect_err("a legacy resource subscription must not send in the modern era");
            assert_eq!(error.code, McpErrorCode::InvalidParams);
            assert_eq!(client.next_id.load(Ordering::SeqCst), next_id_before);
            assert!(client.is_initialized());
        }
        client
            .close()
            .expect("modern resource subscription cleanup");
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
        assert_eq!(
            result.completion.total,
            Some(1),
            "legacy completion total remains a legacy machine integer"
        );
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
            marker: ProgressMarker::Number(JsonInteger::from(1)),
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
