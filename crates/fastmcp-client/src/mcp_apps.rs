//! Browser-agnostic MCP Apps Host/View runtime.
//!
//! An embedder supplies the carrier (a webview, iframe adapter, or the bounded
//! in-memory pair below). This module never renders HTML and never routes Apps
//! messages through MCP client/server RPC.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;

use crate::{CoreResult, FinalCoreResult};
use asupersync::Cx;
use asupersync::time::Sleep;
use asupersync::types::Time;
use asupersync::channel::mpsc::{self, Receiver, Sender};
use asupersync::combinator::select::{Either, Select};
use fastmcp_core::{McpError, McpRequestCancellation, McpResult};
use fastmcp_protocol::{
    MAX_MCP_APPS_BRIDGE_IN_FLIGHT, MCP_APPS_HOST_VIEW_PROTOCOL_VERSION, McpAppsBridgeAdmission,
    McpAppsBridgeDirection, McpAppsBridgeError, McpAppsBridgeImplementation,
    McpAppsBridgeLifecycle, McpAppsBridgeRequestId, McpAppsCancelledControlParams,
    McpAppsContentBlockModalities, McpAppsControlDisposition, McpAppsDisplayMode,
    McpAppsDisplayModeParams, McpAppsHostCapabilities,
    McpAppsHostContext, McpAppsHostIdAllocator, McpAppsHostNotification, McpAppsHostRequest,
    McpAppsHostResponse, McpAppsHostToView, McpAppsInitializeParams, McpAppsInitializeResult,
    McpAppsJsonRpcEnvelope, McpAppsJsonRpcError, McpAppsJsonRpcRequestId, McpAppsOperationResult,
    McpAppsPinnedHostCapabilities, McpAppsPinnedHostContext, McpAppsPinnedInitializeParams,
    McpAppsPinnedInitializeResult, McpAppsProgressControlParams, McpAppsResourceTeardownParams,
    McpAppsRoutedMethod, McpAppsViewLifecycle, McpAppsViewNotification, McpAppsViewRequest,
    McpAppsUpdateModelContextParams, McpAppsViewResponse, McpAppsViewToHost,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Aggregate encoded-data budget for this View's isolated tool catalog,
/// pagination, and retained Host request outcomes. Shared descriptors are
/// conservatively charged at every retained reference.
pub const MAX_MCP_APPS_VIEW_TOOL_STATE_BYTES: usize = 1024 * 1024;
/// Maximum tools in one complete, isolated View catalog.
pub const MAX_MCP_APPS_VIEW_TOOLS: usize = 1_024;

/// Trusted Host identity for one same-server catalog authorization. These
/// values come from the embedder's admitted View and authenticated MCP client,
/// never from an Apps request. They are retained privately and never emitted.
#[derive(Clone, PartialEq, Eq)]
pub struct McpAppsCatalogBinding {
    pub view_id: String,
    pub resource_uri: String,
    pub origin: String,
    pub principal_id: String,
    pub server_id: String,
    pub revision: String,
}

impl fmt::Debug for McpAppsCatalogBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpAppsCatalogBinding([redacted])")
    }
}

/// One admitted tool owned by exactly one Apps View. The descriptor remains
/// untrusted display/policy input and is never added to an MCP server catalog.
#[derive(Clone, Debug)]
pub struct McpAppsViewTool {
    descriptor: fastmcp_protocol::FinalTool,
    input_schema: fastmcp_protocol::schema::AdmittedSchema,
    output_schema: Option<fastmcp_protocol::schema::AdmittedSchema>,
    retained_bytes: usize,
}

impl McpAppsViewTool {
    /// The exact admitted descriptor, including untrusted hints and metadata.
    #[must_use]
    pub const fn descriptor(&self) -> &fastmcp_protocol::FinalTool {
        &self.descriptor
    }
}

/// One completely admitted page of the View's app-tool catalog.
#[derive(Clone, Debug)]
pub struct McpAppsViewToolsPage {
    pub tools: Vec<Arc<McpAppsViewTool>>,
    pub next_cursor: Option<String>,
}

/// The isolated pre-final Apps result of a Host invocation of a View tool.
/// Absence of `isError` has effective false and stays absent in the value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpAppsViewCallToolResult {
    pub content: Vec<fastmcp_protocol::common_types::ContentBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

impl McpAppsViewCallToolResult {
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.is_error.unwrap_or(false)
    }
}

/// Exactly one terminal outcome for a Host-originated Apps request. Peer
/// errors are data only: their codes cannot trigger retry or another protocol.
#[derive(Clone, Debug)]
pub enum McpAppsHostRequestOutcome {
    ToolsList(McpAppsViewToolsPage),
    ToolCall(McpAppsViewCallToolResult),
    Ping,
    PeerError(McpAppsJsonRpcError),
    /// The matching peer response failed the isolated result/schema contract.
    InvalidResponse,
    /// The Host cancelled this exact request after committing its control.
    Cancelled,
    /// The catalog changed while this request was outstanding.
    CatalogChanged,
    /// This request's original idle or absolute deadline elapsed.
    DeadlineExceeded,
    /// The View closed before this request could deliver a terminal result.
    ViewClosed,
}

/// A correlated, validated terminal result retained until the caller takes it.
#[derive(Clone, Debug)]
pub struct McpAppsWireHostResponse {
    pub request_id: McpAppsJsonRpcRequestId,
    pub method: McpAppsRoutedMethod,
    pub outcome: McpAppsHostRequestOutcome,
}

/// Immutable witness that the owning MCP client completed bilateral Apps
/// activation for the exact connection that created this Host. It cannot be
/// constructed outside this crate and is retained for the Host lifetime.
#[derive(Clone, Debug)]
pub(crate) struct McpAppsActivationProof(fastmcp_protocol::extensions::McpAppsActivationReceipt);

impl McpAppsActivationProof {
    pub(crate) fn from_activation_receipt(
        receipt: Option<&fastmcp_protocol::extensions::McpAppsActivationReceipt>,
    ) -> Result<Self, McpAppsHostError> {
        receipt
            .cloned()
            .map(Self)
            .ok_or(McpAppsHostError::NotNegotiated)
    }

    fn admission(&self) -> fastmcp_protocol::McpAppsBridgeAdmission {
        fastmcp_protocol::McpAppsBridgeAdmission::new(self.0.clone())
    }
}

/// An embedder-owned, cancellation-aware Host/View carrier.
///
/// This deliberately transports typed Apps messages instead of browser values.
/// A browser adapter can translate to JSON-RPC `postMessage`; native hosts and
/// deterministic tests can implement it without a browser dependency.
#[allow(async_fn_in_trait)]
pub trait McpAppsBridgeTransport: Send {
    /// Commits one Host-originated message to the View.
    async fn send_to_view(
        &mut self,
        cx: &Cx,
        message: McpAppsHostToView,
    ) -> Result<(), McpAppsHostError>;
    /// Receives one View-originated message, observing the caller's context.
    async fn receive_from_view(&mut self, cx: &Cx) -> Result<McpAppsViewToHost, McpAppsHostError>;
}

/// Policy hooks for View requests and notifications.
///
/// Defaults acknowledge no side effect and reject effectful requests. Embedders
/// must explicitly opt in to opening links, downloading files, sending chat
/// messages, or retaining model context.
#[allow(async_fn_in_trait)]
pub trait McpAppsHostPolicy: Send {
    async fn initialize(
        &mut self,
        _params: &McpAppsInitializeParams,
        configuration: &McpAppsHostConfiguration,
    ) -> McpAppsInitializeResult {
        configuration.initialize_result()
    }
    async fn open_link(
        &mut self,
        _params: &fastmcp_protocol::McpAppsOpenLinkParams,
    ) -> McpAppsOperationResult {
        McpAppsOperationResult { is_error: true }
    }
    async fn download_file(
        &mut self,
        _params: &fastmcp_protocol::McpAppsDownloadFileParams,
    ) -> McpAppsOperationResult {
        McpAppsOperationResult { is_error: true }
    }
    async fn message(
        &mut self,
        _params: &fastmcp_protocol::McpAppsMessageParams,
    ) -> McpAppsOperationResult {
        McpAppsOperationResult { is_error: true }
    }
    async fn update_model_context(
        &mut self,
        _params: &fastmcp_protocol::McpAppsUpdateModelContextParams,
    ) -> McpAppsOperationResult {
        McpAppsOperationResult { is_error: true }
    }
    async fn request_display_mode(
        &mut self,
        params: &McpAppsDisplayModeParams,
    ) -> McpAppsDisplayModeParams {
        *params
    }
    async fn view_notification(
        &mut self,
        _notification: &McpAppsViewNotification,
    ) -> Result<(), McpAppsHostError> {
        Ok(())
    }
    /// Whether a View-initiated teardown should begin graceful Host teardown.
    async fn approve_view_teardown(&mut self) -> bool {
        false
    }

    /// Dispatches one direction-correct standard-reused View request. A
    /// concrete client policy must create a fresh, Host-owned core request;
    /// it must never forward the Apps envelope, ID, or control values.
    /// `cancellation` is owned by the admitted View request. A policy that
    /// commits upstream work must observe it so the matching View control can
    /// stop that work without cancelling the Host's ambient context.
    async fn dispatch_reused_request(
        &mut self,
        _cx: &Cx,
        _request: McpAppsViewRequest,
    ) -> Result<McpAppsHostResponse, McpAppsHostError>;
}

/// Configuration owned by the Host before the View initializes.
#[derive(Clone, Debug, PartialEq)]
pub struct McpAppsHostConfiguration {
    pub host_info: McpAppsBridgeImplementation,
    pub host_capabilities: McpAppsHostCapabilities,
    pub host_context: McpAppsHostContext,
}

impl McpAppsHostConfiguration {
    /// Produces the stable initialize response for one admitted View.
    #[must_use]
    pub fn initialize_result(&self) -> McpAppsInitializeResult {
        McpAppsInitializeResult {
            protocol_version: MCP_APPS_HOST_VIEW_PROTOCOL_VERSION.to_owned(),
            host_info: self.host_info.clone(),
            host_capabilities: self.host_capabilities.clone(),
            host_context: self.host_context.clone(),
        }
    }
}

/// One negotiated MCP Apps Host instance for exactly one View.
pub struct McpAppsHost<T, P> {
    transport: T,
    _activation_proof: McpAppsActivationProof,
    configuration: McpAppsHostConfiguration,
    policy: P,
    lifecycle: McpAppsViewLifecycle,
    next_request_id: u64,
    pending_host_requests: BTreeMap<McpAppsBridgeRequestId, PendingHostRequest>,
    live_view_requests: BTreeSet<McpAppsBridgeRequestId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingHostRequest {
    Teardown,
    Ordinary,
}

impl<T: McpAppsBridgeTransport, P: McpAppsHostPolicy> McpAppsHost<T, P> {
    /// Constructs a Host only after client/server Apps negotiation succeeded.
    #[must_use]
    pub(crate) fn new_negotiated(
        transport: T,
        configuration: McpAppsHostConfiguration,
        policy: P,
        activation_proof: McpAppsActivationProof,
    ) -> Self {
        Self {
            transport,
            _activation_proof: activation_proof,
            configuration,
            policy,
            lifecycle: McpAppsViewLifecycle::New,
            next_request_id: 1,
            pending_host_requests: BTreeMap::new(),
            live_view_requests: BTreeSet::new(),
        }
    }

    #[must_use]
    pub const fn lifecycle(&self) -> McpAppsViewLifecycle {
        self.lifecycle
    }
    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Processes one View message and emits the matching Host response or
    /// graceful teardown request. It has no MCP server-RPC side channel.
    pub async fn process_next(&mut self, cx: &Cx) -> Result<(), McpAppsHostError> {
        let message = self.transport.receive_from_view(cx).await?;
        match message {
            McpAppsViewToHost::Request { id, request } => {
                self.handle_request(cx, id, request).await
            }
            McpAppsViewToHost::Notification(notification) => {
                self.handle_notification(cx, notification).await
            }
            McpAppsViewToHost::Response {
                id,
                response: McpAppsViewResponse,
            } => self.handle_response(id),
        }
    }

    async fn handle_request(
        &mut self,
        cx: &Cx,
        id: McpAppsBridgeRequestId,
        request: McpAppsViewRequest,
    ) -> Result<(), McpAppsHostError> {
        if self.live_view_requests.len() >= MAX_MCP_APPS_BRIDGE_IN_FLIGHT {
            return Err(McpAppsHostError::Bridge(
                McpAppsBridgeError::TooManyInFlight,
            ));
        }
        if !self.live_view_requests.insert(id) {
            return Err(McpAppsHostError::DuplicateLiveRequest(id));
        }
        let response = async {
            Ok::<_, McpAppsHostError>(match request {
                McpAppsViewRequest::Initialize(params) => {
                    if params.protocol_version != MCP_APPS_HOST_VIEW_PROTOCOL_VERSION {
                        return Err(McpAppsHostError::UnsupportedAppsProtocolVersion(
                            params.protocol_version,
                        ));
                    }
                    self.lifecycle
                        .begin_initialize()
                        .map_err(McpAppsHostError::Lifecycle)?;
                    let response = self.policy.initialize(&params, &self.configuration).await;
                    self.lifecycle
                        .initialization_succeeded()
                        .map_err(McpAppsHostError::Lifecycle)?;
                    McpAppsHostResponse::Initialize(response)
                }
                McpAppsViewRequest::OpenLink(params) => {
                    self.require_active()?;
                    let result = if self.configuration.host_capabilities.open_links {
                        self.policy.open_link(&params).await
                    } else {
                        McpAppsOperationResult { is_error: true }
                    };
                    McpAppsHostResponse::OpenLink(result)
                }
                McpAppsViewRequest::DownloadFile(params) => {
                    self.require_active()?;
                    let result = if self.configuration.host_capabilities.download_file {
                        self.policy.download_file(&params).await
                    } else {
                        McpAppsOperationResult { is_error: true }
                    };
                    McpAppsHostResponse::DownloadFile(result)
                }
                McpAppsViewRequest::Message(params) => {
                    self.require_active()?;
                    let result = if self.configuration.host_capabilities.message {
                        self.policy.message(&params).await
                    } else {
                        McpAppsOperationResult { is_error: true }
                    };
                    McpAppsHostResponse::Message(result)
                }
                McpAppsViewRequest::UpdateModelContext(params) => {
                    self.require_active()?;
                    let result = if self.configuration.host_capabilities.update_model_context {
                        self.policy.update_model_context(&params).await
                    } else {
                        McpAppsOperationResult { is_error: true }
                    };
                    McpAppsHostResponse::UpdateModelContext(result)
                }
                McpAppsViewRequest::RequestDisplayMode(params) => {
                    self.require_active()?;
                    McpAppsHostResponse::RequestDisplayMode(
                        self.policy.request_display_mode(&params).await,
                    )
                }
                McpAppsViewRequest::Ping(_) => McpAppsHostResponse::Ping,
                request @ (McpAppsViewRequest::CallTool(_)
                | McpAppsViewRequest::ResourceRead(_)
                | McpAppsViewRequest::ResourcesList(_)
                | McpAppsViewRequest::ResourceTemplatesList(_)
                | McpAppsViewRequest::PromptsList(_)) => {
                    self.require_active()?;
                    self.policy.dispatch_reused_request(cx, request).await?
                }
            })
        }
        .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                self.live_view_requests.remove(&id);
                return Err(error);
            }
        };
        let sent = self
            .transport
            .send_to_view(cx, McpAppsHostToView::Response { id, response })
            .await;
        self.live_view_requests.remove(&id);
        sent
    }

    async fn handle_notification(
        &mut self,
        cx: &Cx,
        notification: McpAppsViewNotification,
    ) -> Result<(), McpAppsHostError> {
        match notification {
            McpAppsViewNotification::Initialized => {
                self.lifecycle
                    .admit_initialized()
                    .map_err(McpAppsHostError::Lifecycle)?;
                self.policy
                    .view_notification(&McpAppsViewNotification::Initialized)
                    .await
            }
            McpAppsViewNotification::RequestTeardown
                if self.lifecycle.permits_application_traffic() =>
            {
                self.require_active()?;
                self.policy
                    .view_notification(&McpAppsViewNotification::RequestTeardown)
                    .await?;
                if self.policy.approve_view_teardown().await {
                    self.begin_teardown(cx, None).await?;
                }
                Ok(())
            }
            other if self.lifecycle.permits_application_traffic() => {
                self.policy.view_notification(&other).await
            }
            // The pinned compatibility sink admits early direction-correct View
            // notifications without application or Host-side effects.
            _ => Ok(()),
        }
    }

    fn handle_response(&mut self, id: McpAppsBridgeRequestId) -> Result<(), McpAppsHostError> {
        match self.pending_host_requests.remove(&id) {
            Some(PendingHostRequest::Teardown) => self
                .lifecycle
                .finish_closing()
                .map_err(McpAppsHostError::Lifecycle),
            Some(PendingHostRequest::Ordinary) => Ok(()),
            None => Err(McpAppsHostError::UnknownResponse(id)),
        }
    }

    /// Emits an active-phase Host→View notification.
    pub async fn send_notification(
        &mut self,
        cx: &Cx,
        notification: McpAppsHostNotification,
    ) -> Result<(), McpAppsHostError> {
        self.require_active()?;
        self.transport
            .send_to_view(cx, McpAppsHostToView::Notification(notification))
            .await
    }

    /// Sends one active-phase Host→View request and retains its independent
    /// Apps correlation until the View's response arrives. This path is for
    /// bridge-local app tools and controls, not MCP client/server RPC.
    pub async fn send_host_request(
        &mut self,
        cx: &Cx,
        request: McpAppsHostRequest,
    ) -> Result<McpAppsBridgeRequestId, McpAppsHostError> {
        self.require_active()?;
        if self.pending_host_requests.len() >= MAX_MCP_APPS_BRIDGE_IN_FLIGHT {
            return Err(McpAppsHostError::Bridge(
                McpAppsBridgeError::TooManyInFlight,
            ));
        }
        let previous_next_request_id = self.next_request_id;
        let id = McpAppsBridgeRequestId::new(previous_next_request_id)
            .map_err(McpAppsHostError::Bridge)?;
        let next_request_id =
            previous_next_request_id
                .checked_add(1)
                .ok_or(McpAppsHostError::Bridge(
                    McpAppsBridgeError::RequestIdExhausted,
                ))?;
        self.next_request_id = next_request_id;
        self.pending_host_requests
            .insert(id, PendingHostRequest::Ordinary);
        let sent = self
            .transport
            .send_to_view(cx, McpAppsHostToView::Request { id, request })
            .await;
        if sent.is_err() {
            self.pending_host_requests.remove(&id);
            self.next_request_id = previous_next_request_id;
        }
        sent.map(|()| id)
    }

    /// Starts Host-initiated graceful teardown and retains exactly one bounded
    /// correlation until the View responds.
    pub async fn begin_teardown(
        &mut self,
        cx: &Cx,
        reason: Option<String>,
    ) -> Result<(), McpAppsHostError> {
        if self.pending_host_requests.len() >= MAX_MCP_APPS_BRIDGE_IN_FLIGHT {
            return Err(McpAppsHostError::Bridge(
                McpAppsBridgeError::TooManyInFlight,
            ));
        }
        let params =
            McpAppsResourceTeardownParams::try_new(reason).map_err(McpAppsHostError::Bridge)?;
        let previous_lifecycle = self.lifecycle;
        let previous_next_request_id = self.next_request_id;
        let id = McpAppsBridgeRequestId::new(previous_next_request_id)
            .map_err(McpAppsHostError::Bridge)?;
        let next_request_id =
            previous_next_request_id
                .checked_add(1)
                .ok_or(McpAppsHostError::Bridge(
                    McpAppsBridgeError::RequestIdExhausted,
                ))?;
        self.lifecycle
            .begin_closing()
            .map_err(McpAppsHostError::Lifecycle)?;
        self.next_request_id = next_request_id;
        self.pending_host_requests
            .insert(id, PendingHostRequest::Teardown);
        let sent = self
            .transport
            .send_to_view(
                cx,
                McpAppsHostToView::Request {
                    id,
                    request: McpAppsHostRequest::ResourceTeardown(params),
                },
            )
            .await;
        if sent.is_err() {
            self.pending_host_requests.remove(&id);
            self.lifecycle = previous_lifecycle;
            self.next_request_id = previous_next_request_id;
        }
        sent
    }

    fn require_active(&self) -> Result<(), McpAppsHostError> {
        self.lifecycle
            .permits_application_traffic()
            .then_some(())
            .ok_or(McpAppsHostError::NotActive(self.lifecycle))
    }
}

/// Bridge runtime errors.
#[derive(Debug)]
pub enum McpAppsHostError {
    NotNegotiated,
    NotActive(McpAppsViewLifecycle),
    Lifecycle(fastmcp_protocol::McpAppsLifecycleError),
    Bridge(McpAppsBridgeError),
    Core(fastmcp_core::McpError),
    DuplicateLiveRequest(McpAppsBridgeRequestId),
    UnsupportedAppsProtocolVersion(String),
    UnknownResponse(McpAppsBridgeRequestId),
    DeadlineExceeded,
    TimerUnavailable,
    Transport(String),
}
impl fmt::Display for McpAppsHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotNegotiated => f.write_str("MCP Apps was not negotiated with the server"),
            Self::NotActive(phase) => write!(f, "MCP Apps View is not active ({phase:?})"),
            Self::Lifecycle(error) => error.fmt(f),
            Self::Bridge(error) => error.fmt(f),
            Self::Core(error) => error.fmt(f),
            Self::DuplicateLiveRequest(id) => {
                write!(f, "MCP Apps bridge duplicate live request {}", id.get())
            }
            Self::UnsupportedAppsProtocolVersion(version) => {
                write!(
                    f,
                    "MCP Apps View uses unsupported protocol version {version}"
                )
            }
            Self::UnknownResponse(id) => {
                write!(f, "MCP Apps bridge received unknown response {}", id.get())
            }
            Self::DeadlineExceeded => f.write_str("MCP Apps request deadline exceeded"),
            Self::TimerUnavailable => f.write_str("pending Apps operations require the caller's timer driver"),
            Self::Transport(error) => write!(f, "MCP Apps bridge transport: {error}"),
        }
    }
}
impl std::error::Error for McpAppsHostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lifecycle(error) => Some(error),
            Self::Bridge(error) => Some(error),
            Self::Core(error) => Some(error),
            Self::NotNegotiated
            | Self::NotActive(_)
            | Self::DuplicateLiveRequest(_)
            | Self::UnsupportedAppsProtocolVersion(_)
            | Self::UnknownResponse(_)
            | Self::DeadlineExceeded
            | Self::TimerUnavailable
            | Self::Transport(_) => None,
        }
    }
}

/// Host side of the bounded in-memory carrier used by tests and native embeds.
pub struct McpAppsInMemoryHostTransport {
    to_view: Sender<McpAppsHostToView>,
    from_view: Receiver<McpAppsViewToHost>,
}
/// View side of the bounded in-memory carrier.
pub struct McpAppsInMemoryViewTransport {
    to_host: Sender<McpAppsViewToHost>,
    from_host: Receiver<McpAppsHostToView>,
}

/// Creates a bounded in-memory Host/View pair. `capacity` must be non-zero.
#[must_use]
pub fn mcp_apps_in_memory_pair(
    capacity: usize,
) -> (McpAppsInMemoryHostTransport, McpAppsInMemoryViewTransport) {
    assert!(
        capacity > 0,
        "MCP Apps in-memory bridge capacity must be non-zero"
    );
    let (to_view, from_host) = mpsc::channel(capacity);
    let (to_host, from_view) = mpsc::channel(capacity);
    (
        McpAppsInMemoryHostTransport { to_view, from_view },
        McpAppsInMemoryViewTransport { to_host, from_host },
    )
}

impl McpAppsBridgeTransport for McpAppsInMemoryHostTransport {
    async fn send_to_view(
        &mut self,
        cx: &Cx,
        message: McpAppsHostToView,
    ) -> Result<(), McpAppsHostError> {
        self.to_view
            .send(cx, message)
            .await
            .map_err(|error| McpAppsHostError::Transport(error.to_string()))
    }
    async fn receive_from_view(&mut self, cx: &Cx) -> Result<McpAppsViewToHost, McpAppsHostError> {
        self.from_view
            .recv(cx)
            .await
            .map_err(|error| McpAppsHostError::Transport(error.to_string()))
    }
}
impl McpAppsInMemoryViewTransport {
    pub async fn send_to_host(
        &mut self,
        cx: &Cx,
        message: McpAppsViewToHost,
    ) -> Result<(), McpAppsHostError> {
        self.to_host
            .send(cx, message)
            .await
            .map_err(|error| McpAppsHostError::Transport(error.to_string()))
    }
    pub async fn receive_from_host(
        &mut self,
        cx: &Cx,
    ) -> Result<McpAppsHostToView, McpAppsHostError> {
        self.from_host
            .recv(cx)
            .await
            .map_err(|error| McpAppsHostError::Transport(error.to_string()))
    }
}

/// Raw JSON-RPC carrier for the closed Apps wire protocol. The carrier owns
/// browser/native delivery only; every frame is admitted by
/// [`McpAppsBridgeAdmission`] before the Host acts on it.
#[allow(async_fn_in_trait)]
pub trait McpAppsWireBridgeTransport: Send {
    async fn send_to_view(&mut self, cx: &Cx, frame: String) -> Result<(), McpAppsHostError>;
    async fn receive_from_view(&mut self, cx: &Cx) -> Result<String, McpAppsHostError>;
}

/// Host side of the bounded raw Apps JSON-RPC carrier used by deterministic
/// tests and browser-neutral native embeddings.
pub struct McpAppsInMemoryWireHostTransport {
    to_view: Sender<String>,
    from_view: Receiver<String>,
}

/// View side of [`McpAppsInMemoryWireHostTransport`].
pub struct McpAppsInMemoryWireViewTransport {
    to_host: Sender<String>,
    from_host: Receiver<String>,
}

/// Creates one bounded raw JSON-RPC Apps carrier pair.
#[must_use]
pub fn mcp_apps_in_memory_wire_pair(
    capacity: usize,
) -> (
    McpAppsInMemoryWireHostTransport,
    McpAppsInMemoryWireViewTransport,
) {
    assert!(
        capacity > 0,
        "MCP Apps in-memory bridge capacity must be non-zero"
    );
    let (to_view, from_host) = mpsc::channel(capacity);
    let (to_host, from_view) = mpsc::channel(capacity);
    (
        McpAppsInMemoryWireHostTransport { to_view, from_view },
        McpAppsInMemoryWireViewTransport { to_host, from_host },
    )
}

impl McpAppsWireBridgeTransport for McpAppsInMemoryWireHostTransport {
    async fn send_to_view(&mut self, cx: &Cx, frame: String) -> Result<(), McpAppsHostError> {
        self.to_view
            .send(cx, frame)
            .await
            .map_err(|error| McpAppsHostError::Transport(error.to_string()))
    }

    async fn receive_from_view(&mut self, cx: &Cx) -> Result<String, McpAppsHostError> {
        self.from_view
            .recv(cx)
            .await
            .map_err(|error| McpAppsHostError::Transport(error.to_string()))
    }
}

impl McpAppsInMemoryWireViewTransport {
    pub async fn send_to_host(&mut self, cx: &Cx, frame: String) -> Result<(), McpAppsHostError> {
        self.to_host
            .send(cx, frame)
            .await
            .map_err(|error| McpAppsHostError::Transport(error.to_string()))
    }

    pub async fn receive_from_host(&mut self, cx: &Cx) -> Result<String, McpAppsHostError> {
        self.from_host
            .recv(cx)
            .await
            .map_err(|error| McpAppsHostError::Transport(error.to_string()))
    }
}

/// Source-parity Host data returned by the closed `ui/initialize` wire method.
#[derive(Clone, Debug, PartialEq)]
pub struct McpAppsWireHostConfiguration {
    pub host_info: McpAppsBridgeImplementation,
    pub host_capabilities: McpAppsPinnedHostCapabilities,
    pub host_context: McpAppsPinnedHostContext,
}

impl McpAppsWireHostConfiguration {
    fn initialize_result(&self) -> McpAppsPinnedInitializeResult {
        McpAppsPinnedInitializeResult {
            protocol_version: MCP_APPS_HOST_VIEW_PROTOCOL_VERSION.to_owned(),
            host_info: self.host_info.clone(),
            host_capabilities: self.host_capabilities.clone(),
            host_context: self.host_context.clone(),
            unknown: BTreeMap::new(),
        }
    }
}

/// Browser-neutral effect policy for the closed wire Host.
///
/// The default methods deliberately perform no embedder effect. Reused core
/// methods have no default: a Host must provide fresh client-owned forwarding.
#[allow(async_fn_in_trait)]
pub trait McpAppsWireHostPolicy {
    async fn initialize(
        &mut self,
        _params: &McpAppsPinnedInitializeParams,
        configuration: &McpAppsWireHostConfiguration,
    ) -> McpAppsPinnedInitializeResult {
        configuration.initialize_result()
    }

    async fn operation(
        &mut self,
        _method: McpAppsRoutedMethod,
        _params: Option<&Value>,
    ) -> Result<Value, McpAppsHostError> {
        Ok(json!({ "isError": true }))
    }

    /// Authorizes one invocation of this View's admitted tool. The Host has
    /// checked the arguments and exact current catalog before calling this
    /// hook, but descriptor annotations and metadata grant no authority.
    /// Embedders must apply their View/origin policy and any required user
    /// confirmation here. Success authorizes only this invocation; the
    /// default refuses it. The hook must not invoke the tool itself.
    async fn approve_view_tool_call(
        &mut self,
        _cx: &Cx,
        _tool: &McpAppsViewTool,
        _params: &fastmcp_protocol::McpAppsToolCallParams,
    ) -> Result<(), McpAppsHostError> {
        Err(wire_policy_denied())
    }

    /// Reviews and atomically accepts one replacement of this View's model
    /// context. An empty request explicitly clears the previous context.
    /// The whole payload's negotiated modalities have been checked before
    /// this callback runs; its content remains untrusted application data.
    ///
    /// Success means the host accepted this replacement. Returning an error
    /// must leave host state unchanged. The future is dropped if matching View
    /// cancellation wins, so it must not detach work or leave a partial change.
    /// The bridge then retains only the last accepted replacement and replies
    /// with the pinned exact empty success object. No default grants consent.
    async fn update_model_context(
        &mut self,
        _cx: &Cx,
        _cancellation: &McpRequestCancellation,
        _params: &McpAppsUpdateModelContextParams,
    ) -> Result<(), McpAppsHostError> {
        Err(wire_policy_denied())
    }

    /// Requests an actual renderer mode change and returns the resulting mode.
    /// The requested mode has already passed both Host and View negotiation.
    /// A policy decline may return the unchanged `current` mode. A successful
    /// callback must report the actual mode, never merely echo an unperformed
    /// request. The returned mode is checked against the same negotiated set.
    ///
    /// Implementations must observe cancellation at their effect boundary and
    /// make their futures cancellation-correct on drop. The default declines
    /// the change, preserving a known current mode, or refuses when it is absent.
    async fn request_display_mode(
        &mut self,
        _cx: &Cx,
        _cancellation: &McpRequestCancellation,
        _params: McpAppsDisplayModeParams,
        current: Option<McpAppsDisplayMode>,
    ) -> Result<McpAppsDisplayModeParams, McpAppsHostError> {
        current
            .map(|mode| McpAppsDisplayModeParams { mode })
            .ok_or_else(wire_policy_denied)
    }

    async fn notification(
        &mut self,
        _method: McpAppsRoutedMethod,
        _params: Option<&Value>,
    ) -> Result<(), McpAppsHostError> {
        Ok(())
    }

    /// Observes progress for one exact Host-originated View request.
    ///
    /// The bridge calls this only after its negotiated lifecycle and the
    /// request's `_meta.progressToken` bind the notification to `request_id`.
    /// A token from another View or an already-completed request is rejected
    /// before this hook can run.
    async fn progress(
        &mut self,
        _request_id: &McpAppsJsonRpcRequestId,
        _params: &McpAppsProgressControlParams,
    ) -> Result<(), McpAppsHostError> {
        Ok(())
    }

    /// Observes one exact View-originated request cancellation.
    ///
    /// Returning success commits the bridge-side cancellation by releasing
    /// that request correlation. This is deliberately a synchronous immediate
    /// hook: the bridge has already dropped the request-owned forwarding
    /// future and must not suspend before committing its cancellation control.
    /// Implementations may perform only immediate, bounded bookkeeping here.
    /// An absent-ID cancellation remains the protocol's explicit inert no-op
    /// and never reaches this hook.
    fn cancelled(
        &mut self,
        _cx: &Cx,
        _request_id: &McpAppsJsonRpcRequestId,
        _params: &McpAppsCancelledControlParams,
    ) -> Result<(), McpAppsHostError> {
        Ok(())
    }

    async fn approve_view_teardown(&mut self) -> bool {
        false
    }

    /// Dispatches an admitted request against the same server and security
    /// partition installed by `bind_server_catalogs`. Catalog cursors here
    /// have already been unwrapped from this Host's private continuation map.
    /// Return the complete selected-era payload, including final cache fields;
    /// the Host validates, substitutes and projects list results before send.
    async fn dispatch_reused_request(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: McpAppsRoutedMethod,
        params: Option<Value>,
    ) -> Result<Value, McpAppsHostError>;
}

/// Embedder effects for a Host that already owns its MCP forwarding policy.
///
/// Attach these callbacks with [`McpAppsWireHost::with_effects`] to combine
/// renderer or consent decisions with the ready client's fresh core requests.
/// The bridge still checks lifecycle, capabilities, content and correlations
/// before invoking a callback. No callback receives the MCP client or its
/// credentials. Defaults authorize no external effect.
///
/// Callbacks have the same cancellation-correctness requirements as
/// [`McpAppsWireHostPolicy`]: pending work is dropped when its matching request
/// is cancelled, and an error must leave embedder state unchanged.
#[allow(async_fn_in_trait)]
pub trait McpAppsWireHostEffects {
    /// Performs an admitted open-link, download or message operation.
    /// A declined operation returns the pinned `isError` result.
    async fn operation(
        &mut self,
        _method: McpAppsRoutedMethod,
        _params: Option<&Value>,
    ) -> Result<Value, McpAppsHostError> {
        Ok(json!({ "isError": true }))
    }

    /// Authorizes one schema-validated Host invocation of a View-owned tool.
    /// Success grants only this invocation and must not invoke the tool itself.
    async fn approve_view_tool_call(
        &mut self,
        _cx: &Cx,
        _tool: &McpAppsViewTool,
        _params: &fastmcp_protocol::McpAppsToolCallParams,
    ) -> Result<(), McpAppsHostError> {
        Err(wire_policy_denied())
    }

    /// Atomically accepts one complete model-context replacement, including
    /// an empty replacement that clears the previous context.
    async fn update_model_context(
        &mut self,
        _cx: &Cx,
        _cancellation: &McpRequestCancellation,
        _params: &McpAppsUpdateModelContextParams,
    ) -> Result<(), McpAppsHostError> {
        Err(wire_policy_denied())
    }

    /// Changes the renderer mode and reports its actual resulting mode.
    /// The default keeps the current mode or refuses when none is known.
    async fn request_display_mode(
        &mut self,
        _cx: &Cx,
        _cancellation: &McpRequestCancellation,
        _params: McpAppsDisplayModeParams,
        current: Option<McpAppsDisplayMode>,
    ) -> Result<McpAppsDisplayModeParams, McpAppsHostError> {
        current
            .map(|mode| McpAppsDisplayModeParams { mode })
            .ok_or_else(wire_policy_denied)
    }

    /// Observes an admitted notification for this View.
    async fn notification(
        &mut self,
        _method: McpAppsRoutedMethod,
        _params: Option<&Value>,
    ) -> Result<(), McpAppsHostError> {
        Ok(())
    }

    /// Observes progress already bound to one exact Host request.
    async fn progress(
        &mut self,
        _request_id: &McpAppsJsonRpcRequestId,
        _params: &McpAppsProgressControlParams,
    ) -> Result<(), McpAppsHostError> {
        Ok(())
    }

    /// Observes matching View cancellation after the original forwarding
    /// policy has serviced its core cancellation. Only immediate, bounded
    /// bookkeeping is permitted here; absent-ID controls never reach the hook.
    fn cancelled(
        &mut self,
        _cx: &Cx,
        _request_id: &McpAppsJsonRpcRequestId,
        _params: &McpAppsCancelledControlParams,
    ) -> Result<(), McpAppsHostError> {
        Ok(())
    }

    /// Accepts a View request to begin the existing graceful teardown flow.
    async fn approve_view_teardown(&mut self) -> bool {
        false
    }
}

impl McpAppsWireHostEffects for () {}

/// Composition of an existing forwarding policy and embedder-owned effects.
///
/// Created by [`McpAppsWireHost::with_effects`]. Initialization and all reused
/// core methods retain the original policy. Effect hooks use the embedder,
/// while cancellation always services the original policy first.
pub struct McpAppsWireHostWithEffects<P, E> {
    forwarding: P,
    effects: E,
}

impl<P: McpAppsWireHostPolicy, E: McpAppsWireHostEffects> McpAppsWireHostPolicy
    for McpAppsWireHostWithEffects<P, E>
{
    async fn initialize(
        &mut self,
        params: &McpAppsPinnedInitializeParams,
        configuration: &McpAppsWireHostConfiguration,
    ) -> McpAppsPinnedInitializeResult {
        self.forwarding.initialize(params, configuration).await
    }

    async fn operation(
        &mut self,
        method: McpAppsRoutedMethod,
        params: Option<&Value>,
    ) -> Result<Value, McpAppsHostError> {
        self.effects.operation(method, params).await
    }

    async fn approve_view_tool_call(
        &mut self,
        cx: &Cx,
        tool: &McpAppsViewTool,
        params: &fastmcp_protocol::McpAppsToolCallParams,
    ) -> Result<(), McpAppsHostError> {
        self.effects.approve_view_tool_call(cx, tool, params).await
    }

    async fn update_model_context(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: &McpAppsUpdateModelContextParams,
    ) -> Result<(), McpAppsHostError> {
        self.effects
            .update_model_context(cx, cancellation, params)
            .await
    }

    async fn request_display_mode(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: McpAppsDisplayModeParams,
        current: Option<McpAppsDisplayMode>,
    ) -> Result<McpAppsDisplayModeParams, McpAppsHostError> {
        self.effects
            .request_display_mode(cx, cancellation, params, current)
            .await
    }

    async fn notification(
        &mut self,
        method: McpAppsRoutedMethod,
        params: Option<&Value>,
    ) -> Result<(), McpAppsHostError> {
        self.effects.notification(method, params).await
    }

    async fn progress(
        &mut self,
        request_id: &McpAppsJsonRpcRequestId,
        params: &McpAppsProgressControlParams,
    ) -> Result<(), McpAppsHostError> {
        self.effects.progress(request_id, params).await
    }

    fn cancelled(
        &mut self,
        cx: &Cx,
        request_id: &McpAppsJsonRpcRequestId,
        params: &McpAppsCancelledControlParams,
    ) -> Result<(), McpAppsHostError> {
        self.forwarding.cancelled(cx, request_id, params)?;
        self.effects.cancelled(cx, request_id, params)
    }

    async fn approve_view_teardown(&mut self) -> bool {
        self.effects.approve_view_teardown().await
    }

    async fn dispatch_reused_request(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: McpAppsRoutedMethod,
        params: Option<Value>,
    ) -> Result<Value, McpAppsHostError> {
        self.forwarding
            .dispatch_reused_request(cx, cancellation, method, params)
            .await
    }
}

/// A negotiated closed-wire Apps Host. It never sends Apps frames through the
/// MCP server transport; standard-reused methods are delegated to its policy.
pub struct McpAppsWireHost<T, P> {
    transport: T,
    _activation_proof: McpAppsActivationProof,
    admission: McpAppsBridgeAdmission,
    next_host_id: McpAppsHostIdAllocator,
    configuration: McpAppsWireHostConfiguration,
    policy: P,
    state: McpAppsWireHostState,
    /// Frames received while an admitted View request is still executing.
    /// They are replayed through normal admission once that request resolves.
    deferred_view_frames: VecDeque<String>,
    deferred_view_requests: BTreeSet<McpAppsJsonRpcRequestId>,
    host_requests: BTreeMap<McpAppsJsonRpcRequestId, WireHostRequest>,
    view_tools: BTreeMap<String, Arc<McpAppsViewTool>>,
    staged_view_tools: Option<StagedViewTools>,
    teardown_request: Option<(McpAppsJsonRpcRequestId, WireHostDeadline)>,
    server_catalogs: WireServerCatalogs,
    disconnected: bool,
}

const MAX_APPS_CATALOG_CURSORS: usize = 64;
const MAX_APPS_CATALOG_CURSOR_BYTES: usize = 4 * 1024;
const MAX_APPS_CATALOG_PAGES: usize = 64;

#[derive(Default)]
struct WireServerCatalogs {
    binding: Option<McpAppsCatalogBinding>,
    allow_prompts: bool,
    cursors: BTreeMap<String, WireCatalogCursor>,
    invalidated_requests: BTreeSet<McpAppsJsonRpcRequestId>,
    omitted_sizes: u64,
}

#[derive(Clone)]
struct WireCatalogCursor {
    method: McpAppsRoutedMethod,
    upstream: String,
    deadline: WireHostDeadline,
    pages: usize,
}

struct WireCatalogRequest {
    params: Value,
    previous: Option<String>,
    deadline: WireHostDeadline,
    pages: usize,
}

struct WirePreparedCatalogPage {
    result: Value,
    cursor: Option<(String, WireCatalogCursor)>,
    omitted_sizes: u64,
}

/// A carrier may commit bytes before its send future is cancelled. Such a
/// send must fence the View rather than leave a remotely visible handle with
/// no corresponding committed local owner.
struct WireCatalogSendGuard<'a> {
    disconnected: &'a mut bool,
    committed: bool,
}

impl Drop for WireCatalogSendGuard<'_> {
    fn drop(&mut self) {
        if !self.committed { *self.disconnected = true; }
    }
}

struct WireHostRequest {
    method: McpAppsRoutedMethod,
    state: WireHostRequestState,
    retained_bytes: usize,
    deadline: WireHostDeadline,
    last_progress: Option<f64>,
}

#[derive(Clone)]
struct WireHostDeadline {
    owner: Cx,
    idle: Time,
    absolute: Time,
}

impl WireHostDeadline {
    fn new(cx: &Cx) -> Self {
        let now = cx.now();
        let absolute = now.saturating_add_nanos(30 * 60 * 1_000_000_000);
        Self {
            owner: cx.clone(),
            idle: now.saturating_add_nanos(60 * 1_000_000_000),
            absolute: cx.budget().deadline.map_or(absolute, |caller| absolute.min(caller)),
        }
    }

    fn next(&self) -> Time { self.idle.min(self.absolute) }
    fn expired(&self) -> bool { self.owner.now() >= self.next() }
    fn progress(&mut self) {
        self.idle = self.owner.now().saturating_add_nanos(60 * 1_000_000_000);
    }
}

enum WireHostRequestState {
    List,
    Call(Arc<McpAppsViewTool>),
    Ping,
    Complete(McpAppsHostRequestOutcome),
}

/// A carrier send that has not returned success has not exposed its ID to the
/// caller. Dropping it retires that unobservable slot and terminally fences
/// the View, because an embedder carrier may have accepted an uncertain send.
struct WireHostSendGuard<'a> {
    admission: &'a mut McpAppsBridgeAdmission,
    requests: &'a mut BTreeMap<McpAppsJsonRpcRequestId, WireHostRequest>,
    disconnected: &'a mut bool,
    id: Option<McpAppsJsonRpcRequestId>,
}

impl Drop for WireHostSendGuard<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let _ = self.admission.complete_error(McpAppsBridgeDirection::HostToView, &id);
            self.requests.remove(&id);
            *self.disconnected = true;
        }
    }
}

#[derive(Clone)]
struct StagedViewTools {
    tools: BTreeMap<String, Arc<McpAppsViewTool>>,
    next_cursor: String,
    seen_cursors: BTreeSet<String>,
    deadline: WireHostDeadline,
}

#[derive(Default)]
struct McpAppsWireHostState {
    capabilities: Option<McpAppsPinnedHostCapabilities>,
    host_context: McpAppsPinnedHostContext,
    /// Absence leaves mode selection to the Host; a present empty declaration
    /// permits no mode. The typed initialization model alone loses this fact.
    view_display_modes: Option<Vec<McpAppsDisplayMode>>,
    model_context: Option<McpAppsUpdateModelContextParams>,
    view_tools_capability: Option<fastmcp_protocol::McpAppsAppToolsCapability>,
}

impl McpAppsWireHostState {
    fn permits_mode(&self, mode: McpAppsDisplayMode) -> bool {
        self.host_context.available_display_modes.contains(&mode)
            && self
                .view_display_modes
                .as_ref()
                .is_none_or(|modes| modes.contains(&mode))
    }
}

fn invalid_view_result() -> McpAppsHostError {
    McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams)
}

fn view_tool_bytes(tool: &McpAppsViewTool) -> usize {
    tool.retained_bytes
}

fn view_catalog_bytes(tools: &BTreeMap<String, Arc<McpAppsViewTool>>) -> usize {
    tools.iter().map(|(name, tool)| name.len() + view_tool_bytes(tool)).sum()
}

fn staged_view_tool_bytes(stage: &StagedViewTools) -> usize {
    view_catalog_bytes(&stage.tools) + stage.next_cursor.len()
        + stage.seen_cursors.iter().map(String::len).sum::<usize>()
}

fn decode_view_tool_page(result: &Value) -> Result<McpAppsViewToolsPage, McpAppsHostError> {
    admit_view_numbers(result)?;
    let object = result.as_object().ok_or_else(invalid_view_result)?;
    if object.keys().any(|key| !matches!(key.as_str(), "tools" | "nextCursor")) {
        return Err(invalid_view_result());
    }
    let next_cursor = match object.get("nextCursor") {
        None => None,
        Some(Value::String(cursor)) if !cursor.is_empty() && cursor.len() <= 4 * 1024 => {
            Some(cursor.clone())
        }
        _ => return Err(invalid_view_result()),
    };
    let raw_tools = object.get("tools").and_then(Value::as_array)
        .ok_or_else(invalid_view_result)?;
    if raw_tools.len() > MAX_MCP_APPS_VIEW_TOOLS {
        return Err(invalid_view_result());
    }
    let mut tools = Vec::with_capacity(raw_tools.len());
    let mut names = BTreeSet::new();
    for raw in raw_tools {
        // FinalTool is the strict shared descriptor vocabulary. The Apps
        // intersection adds an object-root output requirement and excludes
        // every final-core execution extension by its closed field set.
        let descriptor: fastmcp_protocol::FinalTool = serde_json::from_value(raw.clone())
            .map_err(|_| invalid_view_result())?;
        if serde_json::to_value(&descriptor).map_err(|_| invalid_view_result())? != *raw
            || descriptor.name.is_empty()
            || descriptor.name.len() > fastmcp_protocol::MAX_MCP_APPS_BRIDGE_TEXT_BYTES
            || !names.insert(descriptor.name.clone())
            || ["title", "description", "icons", "outputSchema", "annotations", "_meta"]
                .iter().any(|key| raw.get(*key).is_some_and(Value::is_null))
        {
            return Err(invalid_view_result());
        }
        let input_schema = fastmcp_protocol::schema::admit_final_schema(
            descriptor.input_schema.clone(),
        ).map_err(|_| invalid_view_result())?;
        let output_schema = descriptor.output_schema.as_ref().map(|schema| {
            if schema.get("type").and_then(Value::as_str) != Some("object") {
                return Err(invalid_view_result());
            }
            fastmcp_protocol::schema::admit_final_schema(schema.clone())
                .map_err(|_| invalid_view_result())
        }).transpose()?;
        let retained_bytes = serde_json::to_vec(raw).map_err(|_| invalid_view_result())?.len()
            + serde_json::to_vec(input_schema.schema()).map_err(|_| invalid_view_result())?.len()
            + output_schema.as_ref().map_or(Ok(0), |schema| {
                serde_json::to_vec(schema.schema()).map(|bytes| bytes.len())
                    .map_err(|_| invalid_view_result())
            })?;
        tools.push(Arc::new(McpAppsViewTool {
            descriptor, input_schema, output_schema, retained_bytes,
        }));
    }
    Ok(McpAppsViewToolsPage { tools, next_cursor })
}

fn decode_view_tool_result(
    result: &Value,
    tool: &McpAppsViewTool,
) -> Result<McpAppsViewCallToolResult, McpAppsHostError> {
    admit_view_numbers(result)?;
    if ["isError", "structuredContent"].iter()
        .any(|key| result.get(*key).is_some_and(Value::is_null))
    {
        return Err(invalid_view_result());
    }
    let response: McpAppsViewCallToolResult = serde_json::from_value(result.clone())
        .map_err(|_| invalid_view_result())?;
    if !response.is_error() {
        if let Some(schema) = &tool.output_schema {
            let structured = result.get("structuredContent").ok_or_else(invalid_view_result)?;
            schema.validate(structured).map_err(|_| invalid_view_result())?;
        }
    }
    Ok(response)
}

fn admit_view_numbers(value: &Value) -> Result<(), McpAppsHostError> {
    fn visit(value: &Value, depth: usize, nodes: &mut usize) -> bool {
        *nodes += 1;
        if depth > fastmcp_protocol::MAX_MCP_APPS_BRIDGE_JSON_DEPTH || *nodes > 65_536 { return false; }
        match value {
            Value::Number(number) => {
                let Some(binary) = number.as_f64().filter(|number| number.is_finite()) else { return false; };
                if number.to_string().len() > 4 * 1024
                    || (binary == 0.0 && binary.is_sign_negative())
                    || (binary.fract() == 0.0 && binary.abs() > fastmcp_protocol::MAX_MCP_APPS_BRIDGE_SAFE_INTEGER as f64)
                { return false; }
                let Some(projected) = serde_json::Number::from_f64(binary) else { return false; };
                // Compare exact decimal values using the existing bounded
                // schema numeric semantics, not f64 equality after rounding.
                fastmcp_protocol::schema::admit_final_schema(json!({"const": number}))
                    .is_ok_and(|schema| schema.validate(&Value::Number(projected)).is_ok())
            }
            Value::Array(values) => values.len() <= fastmcp_protocol::MAX_MCP_APPS_BRIDGE_JSON_ARRAY_ITEMS
                && values.iter().all(|value| visit(value, depth + 1, nodes)),
            Value::Object(values) => values.len() <= fastmcp_protocol::MAX_MCP_APPS_BRIDGE_JSON_OBJECT_MEMBERS
                && values.iter().all(|(key, value)| key.len() <= fastmcp_protocol::MAX_MCP_APPS_BRIDGE_TEXT_BYTES
                    && visit(value, depth + 1, nodes)),
            Value::String(value) => value.len() <= fastmcp_protocol::MAX_MCP_APPS_BRIDGE_TEXT_BYTES,
            _ => true,
        }
    }
    visit(value, 0, &mut 0).then_some(()).ok_or_else(invalid_view_result)
}

fn is_server_catalog(method: McpAppsRoutedMethod) -> bool {
    matches!(method, McpAppsRoutedMethod::ResourcesList
        | McpAppsRoutedMethod::ResourceTemplatesList | McpAppsRoutedMethod::PromptsList)
}

impl WireServerCatalogs {
    fn retained_bytes(&self) -> usize {
        self.cursors.iter().map(|(token, cursor)| token.len() + cursor.upstream.len()).sum::<usize>()
            + self.binding.as_ref().map_or(0, |binding| binding.view_id.len() + binding.resource_uri.len()
                + binding.origin.len() + binding.principal_id.len() + binding.server_id.len() + binding.revision.len())
    }

    fn prepare_request(
        &mut self,
        cx: &Cx,
        method: McpAppsRoutedMethod,
        params: Option<&Value>,
    ) -> Result<WireCatalogRequest, McpAppsHostError> {
        self.cursors.retain(|_, cursor| !cursor.deadline.expired());
        if self.binding.is_none()
            || (method == McpAppsRoutedMethod::PromptsList && !self.allow_prompts)
        {
            return Err(wire_policy_denied());
        }
        let previous = params.and_then(|params| params.get("cursor"))
            .map(|cursor| cursor.as_str().ok_or_else(invalid_view_result))
            .transpose()?;
        match previous {
            Some(token) => {
                let cursor = self.cursors.get(token)
                    .filter(|cursor| cursor.method == method && cursor.pages < MAX_APPS_CATALOG_PAGES)
                    .ok_or_else(wire_policy_denied)?;
                if cursor.deadline.owner.checkpoint().is_err() {
                    return Err(McpAppsHostError::Core(McpError::request_cancelled()));
                }
                Ok(WireCatalogRequest {
                    params: json!({"cursor": cursor.upstream}),
                    previous: Some(token.to_owned()),
                    deadline: cursor.deadline.clone(),
                    pages: cursor.pages,
                })
            }
            None => Ok(WireCatalogRequest {
                params: json!({}), previous: None, deadline: WireHostDeadline::new(cx), pages: 0,
            }),
        }
    }

    fn prepare_page(
        &self,
        cx: &Cx,
        method: McpAppsRoutedMethod,
        request: &WireCatalogRequest,
        mut result: Value,
        retained_bytes: usize,
    ) -> Result<WirePreparedCatalogPage, McpAppsHostError> {
        // Admission precedes substitution; a malformed final page cannot
        // manufacture a continuation even when its cursor happens to parse.
        validate_final_catalog_payload(method, &result)?;
        let upstream = result.get("nextCursor").map(|value| {
            value.as_str().filter(|cursor| cursor.len() <= MAX_APPS_CATALOG_CURSOR_BYTES)
                .map(ToOwned::to_owned).ok_or_else(invalid_view_result)
        }).transpose()?;
        let cursor = if let Some(upstream) = upstream {
            if request.pages + 1 >= MAX_APPS_CATALOG_PAGES
                || self.cursors.len() - usize::from(request.previous.is_some()) >= MAX_APPS_CATALOG_CURSORS
                || !cx.capabilities().entropy
            {
                return Err(wire_policy_denied());
            }
            let identifier = fastmcp_core::crypto::draw_security_identifier()
                .map_err(|_| wire_policy_denied())?;
            let token = identifier.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
            if self.cursors.contains_key(&token)
                || retained_bytes.saturating_add(token.len()).saturating_add(upstream.len())
                    > MAX_MCP_APPS_VIEW_TOOL_STATE_BYTES
            {
                return Err(McpAppsHostError::Bridge(McpAppsBridgeError::TooManyInFlight));
            }
            result["nextCursor"] = Value::String(token.clone());
            Some((token, WireCatalogCursor {
                method, upstream, deadline: request.deadline.clone(), pages: request.pages + 1,
            }))
        } else { None };
        // This is the only outward projection, after HostCursorSubstitution.
        // Keep the exact internal page and upstream cursor out of View state.
        let omitted_sizes = project_apps_catalog(method, &mut result)?;
        Ok(WirePreparedCatalogPage { result, cursor, omitted_sizes })
    }
}

fn validate_final_catalog_payload(
    method: McpAppsRoutedMethod,
    value: &Value,
) -> Result<(), McpAppsHostError> {
    fn exact<T: serde::de::DeserializeOwned + Serialize>(value: &Value) -> Result<(), McpAppsHostError> {
        let typed: T = serde_json::from_value(value.clone()).map_err(|_| invalid_view_result())?;
        let encoded = serde_json::to_value(typed).map_err(|_| invalid_view_result())?;
        (encoded == *value).then_some(()).ok_or_else(invalid_view_result)
    }
    match method {
        McpAppsRoutedMethod::ResourcesList => exact::<fastmcp_protocol::FinalListResourcesResult>(value),
        McpAppsRoutedMethod::ResourceTemplatesList => exact::<fastmcp_protocol::FinalListResourceTemplatesResult>(value),
        McpAppsRoutedMethod::PromptsList => exact::<fastmcp_protocol::FinalListPromptsResult>(value),
        _ => Err(invalid_view_result()),
    }
}

/// SDK 1.29's three list roots retain result members, but nested descriptor
/// objects strip unknown members. Reject any such loss rather than returning
/// a page that the View interprets differently. The sole omission here is the
/// plan's optional advisory Resource.size outside JavaScript's safe range.
fn project_apps_catalog(method: McpAppsRoutedMethod, page: &mut Value) -> Result<u64, McpAppsHostError> {
    fn closed(value: &Value, fields: &[&str]) -> Result<(), McpAppsHostError> {
        value.as_object().filter(|object| object.keys().all(|key| fields.contains(&key.as_str())))
            .map(|_| ()).ok_or_else(invalid_view_result)
    }
    let key = match method {
        McpAppsRoutedMethod::ResourcesList => "resources",
        McpAppsRoutedMethod::ResourceTemplatesList => "resourceTemplates",
        McpAppsRoutedMethod::PromptsList => "prompts",
        _ => return Err(invalid_view_result()),
    };
    let items = page.get_mut(key).and_then(Value::as_array_mut).ok_or_else(invalid_view_result)?;
    let mut omitted = 0;
    for item in items {
        closed(item, match method {
            McpAppsRoutedMethod::ResourcesList => &["uri", "name", "title", "description", "icons", "mimeType", "size", "annotations", "_meta"],
            McpAppsRoutedMethod::ResourceTemplatesList => &["uriTemplate", "name", "title", "description", "icons", "mimeType", "annotations", "_meta"],
            McpAppsRoutedMethod::PromptsList => &["name", "title", "description", "icons", "arguments", "_meta"],
            _ => return Err(invalid_view_result()),
        })?;
        if method == McpAppsRoutedMethod::ResourcesList
            && item.get("size").is_some_and(|size| admit_view_numbers(size).is_err())
        {
            item.as_object_mut().ok_or_else(invalid_view_result)?.remove("size");
            omitted += 1;
        }
        if let Some(icons) = item.get("icons").and_then(Value::as_array) {
            for icon in icons { closed(icon, &["src", "mimeType", "sizes", "theme"])?; }
        }
        if let Some(annotations) = item.get("annotations") {
            closed(annotations, &["audience", "priority", "lastModified"])?;
            if let Some(stamp) = annotations.get("lastModified") {
                if !stamp.as_str().is_some_and(apps_sdk29_datetime) { return Err(invalid_view_result()); }
            }
        }
        if let Some(arguments) = item.get("arguments").and_then(Value::as_array) {
            for argument in arguments { closed(argument, &["name", "description", "required"])?; }
        }
    }
    admit_view_numbers(page)?;
    Ok(omitted)
}

fn apps_sdk29_datetime(value: &str) -> bool {
    fn number(value: &str) -> Option<u32> {
        value.bytes().all(|byte| byte.is_ascii_digit()).then(|| value.parse().ok()).flatten()
    }
    if !value.is_ascii() || value.len() < 17 { return false; }
    let bytes = value.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' { return false; }
    let (Some(year), Some(month), Some(day)) = (number(&value[..4]), number(&value[5..7]), number(&value[8..10])) else { return false; };
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 29 } else { 28 },
        _ => return false,
    };
    if !(1..=days).contains(&day) { return false; }
    let clock = &value[11..];
    let clock = if let Some(clock) = clock.strip_suffix('Z') { clock } else {
        if clock.len() < 11 { return false; }
        let offset = &clock[clock.len() - 6..];
        if !matches!(offset.as_bytes()[0], b'+' | b'-') || offset.as_bytes()[3] != b':'
            || number(&offset[1..3]).is_none_or(|hour| hour > 23)
            || number(&offset[4..]).is_none_or(|minute| minute > 59) { return false; }
        &clock[..clock.len() - 6]
    };
    if clock.len() < 5 || clock.as_bytes()[2] != b':'
        || number(&clock[..2]).is_none_or(|hour| hour > 23)
        || number(&clock[3..5]).is_none_or(|minute| minute > 59) { return false; }
    if clock.len() == 5 { return true; }
    if clock.len() < 8 || clock.as_bytes()[5] != b':'
        || number(&clock[6..8]).is_none_or(|second| second > 59) { return false; }
    clock.len() == 8 || (clock.as_bytes()[8] == b'.' && clock.len() > 9
        && clock[9..].bytes().all(|byte| byte.is_ascii_digit()))
}

fn expire_wire_host_requests(
    admission: &mut McpAppsBridgeAdmission,
    requests: &mut BTreeMap<McpAppsJsonRpcRequestId, WireHostRequest>,
    staged: &mut Option<StagedViewTools>,
    teardown: &mut Option<(McpAppsJsonRpcRequestId, WireHostDeadline)>,
) -> Result<bool, McpAppsHostError> {
    let mut expired = false;
    if teardown.as_ref().is_some_and(|(_, deadline)| deadline.expired()) {
        for entry in requests.values_mut() {
            if !matches!(entry.state, WireHostRequestState::Complete(_)) {
                entry.state = WireHostRequestState::Complete(McpAppsHostRequestOutcome::ViewClosed);
                entry.retained_bytes = 0;
            }
        }
        admission.commit_teardown().map_err(McpAppsHostError::Bridge)?;
        *teardown = None;
        *staged = None;
        return Ok(true);
    }
    let stage_expired = staged.as_ref().is_some_and(|stage| stage.deadline.expired());
    for (id, entry) in requests {
        if !matches!(entry.state, WireHostRequestState::Complete(_))
            && (entry.deadline.expired() || (stage_expired && matches!(entry.state, WireHostRequestState::List)))
        {
            admission.complete_error(McpAppsBridgeDirection::HostToView, id)
                .map_err(McpAppsHostError::Bridge)?;
            if matches!(entry.state, WireHostRequestState::List) { *staged = None; }
            entry.state = WireHostRequestState::Complete(McpAppsHostRequestOutcome::DeadlineExceeded);
            entry.retained_bytes = 0;
            expired = true;
        }
    }
    if stage_expired {
        *staged = None;
        expired = true;
    }
    Ok(expired)
}

/// Await the carrier and all outstanding request clocks together. The clocks
/// retain their original caller context; replacing a wait context cannot
/// extend an already-issued request. No thread or private runtime is created.
async fn receive_wire_host_frame<T: McpAppsWireBridgeTransport>(
    cx: &Cx,
    transport: &mut T,
    requests: &BTreeMap<McpAppsJsonRpcRequestId, WireHostRequest>,
    staged: &Option<StagedViewTools>,
    teardown: &Option<(McpAppsJsonRpcRequestId, WireHostDeadline)>,
) -> Result<Option<String>, McpAppsHostError> {
    let mut timers: Vec<_> = requests.values()
        .filter(|entry| !matches!(entry.state, WireHostRequestState::Complete(_)))
        .map(|entry| (entry.deadline.owner.clone(), Box::pin(Sleep::new(entry.deadline.next()))))
        .collect();
    if let Some(stage) = staged {
        timers.push((stage.deadline.owner.clone(), Box::pin(Sleep::new(stage.deadline.next()))));
    }
    if let Some((_, deadline)) = teardown {
        timers.push((deadline.owner.clone(), Box::pin(Sleep::new(deadline.next()))));
    }
    let (_sender, mut receiver) = asupersync::channel::oneshot::channel::<()>();
    let mut cancelled = pin!(receiver.recv(cx));
    let mut caller_timer = cx.budget().deadline.map(|deadline| Box::pin(Sleep::new(deadline)));
    let mut incoming = pin!(transport.receive_from_view(cx));
    poll_fn(|task| {
        for (owner, timer) in &mut timers {
            if owner.now() >= timer.deadline() {
                return Poll::Ready(Ok(None));
            }
            if owner.timer_driver().is_some() {
                let _caller = Cx::set_current(Some(owner.clone()));
                if timer.as_mut().poll(task).is_ready() { return Poll::Ready(Ok(None)); }
            }
        }
        let _caller = Cx::set_current(Some(cx.clone()));
        if cx.checkpoint().is_err() || cancelled.as_mut().poll(task).is_ready()
            || caller_timer.as_mut().is_some_and(|timer| cx.timer_driver().is_some() && timer.as_mut().poll(task).is_ready())
        {
            return Poll::Ready(Err(McpAppsHostError::Core(McpError::request_cancelled())));
        }
        match incoming.as_mut().poll(task) {
            Poll::Ready(result) => Poll::Ready(result.map(Some)),
            Poll::Pending if timers.iter().any(|(owner, _)| owner.timer_driver().is_none())
                || (caller_timer.is_some() && cx.timer_driver().is_none()) => {
                Poll::Ready(Err(McpAppsHostError::TimerUnavailable))
            }
            Poll::Pending => Poll::Pending,
        }
    }).await
}

async fn await_wire_operation<T>(
    caller: &Cx,
    deadline: &WireHostDeadline,
    operation: impl Future<Output = Result<T, McpAppsHostError>>,
) -> Result<T, McpAppsHostError> {
    let mut operation = pin!(operation);
    let mut timer = pin!(Sleep::new(deadline.next()));
    let (_sender, mut receiver) = asupersync::channel::oneshot::channel::<()>();
    let mut cancelled = pin!(receiver.recv(&deadline.owner));
    let (_caller_sender, mut caller_receiver) = asupersync::channel::oneshot::channel::<()>();
    let mut caller_cancelled = pin!(caller_receiver.recv(caller));
    let mut caller_timer = caller.budget().deadline.map(|deadline| Box::pin(Sleep::new(deadline)));
    poll_fn(|task| {
        {
            let _current_caller = Cx::set_current(Some(caller.clone()));
            if caller.checkpoint().is_err() || caller_cancelled.as_mut().poll(task).is_ready()
                || caller_timer.as_mut().is_some_and(|timer| caller.timer_driver().is_some() && timer.as_mut().poll(task).is_ready())
            {
                return Poll::Ready(Err(McpAppsHostError::Core(McpError::request_cancelled())));
            }
        }
        let _caller = Cx::set_current(Some(deadline.owner.clone()));
        if deadline.expired() { return Poll::Ready(Err(McpAppsHostError::DeadlineExceeded)); }
        if deadline.owner.checkpoint().is_err() || cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(McpAppsHostError::Core(McpError::request_cancelled())));
        }
        if deadline.owner.timer_driver().is_some() && timer.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(McpAppsHostError::DeadlineExceeded));
        }
        match operation.as_mut().poll(task) {
            Poll::Pending if deadline.owner.timer_driver().is_none()
                || (caller_timer.is_some() && caller.timer_driver().is_none()) => Poll::Ready(Err(
                McpAppsHostError::TimerUnavailable,
            )),
            other => other,
        }
    }).await
}

fn cancel_deferred_view_request(
    admission: &mut McpAppsBridgeAdmission,
    frames: &mut VecDeque<String>,
    requests: &mut BTreeSet<McpAppsJsonRpcRequestId>,
    cancelled: &McpAppsCancelledControlParams,
) -> Result<bool, McpAppsHostError> {
    let Some(id) = cancelled.request_id.as_ref().filter(|id| requests.contains(*id)) else { return Ok(false); };
    admission.complete_error(McpAppsBridgeDirection::ViewToHost, id)
        .map_err(McpAppsHostError::Bridge)?;
    requests.remove(id);
    frames.retain(|frame| !matches!(
        McpAppsJsonRpcEnvelope::decode(McpAppsBridgeDirection::ViewToHost, frame),
        Ok(McpAppsJsonRpcEnvelope::Request { id: queued, .. }) if &queued == id
    ));
    Ok(true)
}

fn wire_policy_denied() -> McpAppsHostError {
    McpAppsHostError::Core(McpError::invalid_request("MCP Apps host policy refused the operation"))
}

fn wire_policy_checkpoint(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
) -> Result<(), McpAppsHostError> {
    if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
        return Err(McpAppsHostError::Core(McpError::request_cancelled()));
    }
    Ok(())
}

fn permits_content(
    modalities: &McpAppsContentBlockModalities,
    content: &[fastmcp_protocol::common_types::ContentBlock],
) -> bool {
    use fastmcp_protocol::common_types::ContentBlock;
    content.iter().all(|block| match block {
        ContentBlock::Text { .. } => modalities.text.is_some(),
        ContentBlock::Image { .. } => modalities.image.is_some(),
        ContentBlock::Audio { .. } => modalities.audio.is_some(),
        ContentBlock::ResourceLink { .. } => modalities.resource_link.is_some(),
        ContentBlock::Resource { .. } => modalities.resource.is_some(),
    })
}

impl<T: McpAppsWireBridgeTransport, P: McpAppsWireHostPolicy> McpAppsWireHost<T, P> {
    pub(crate) fn new_negotiated(
        transport: T,
        configuration: McpAppsWireHostConfiguration,
        policy: P,
        activation_proof: McpAppsActivationProof,
    ) -> Self {
        let admission = activation_proof.admission();
        Self {
            transport,
            _activation_proof: activation_proof,
            admission,
            next_host_id: McpAppsHostIdAllocator::default(),
            configuration,
            policy,
            state: McpAppsWireHostState::default(),
            deferred_view_frames: VecDeque::new(),
            deferred_view_requests: BTreeSet::new(),
            host_requests: BTreeMap::new(),
            view_tools: BTreeMap::new(),
            staged_view_tools: None,
            teardown_request: None,
            server_catalogs: WireServerCatalogs::default(),
            disconnected: false,
        }
    }

    /// Attaches embedder effects while retaining this Host's MCP forwarding.
    ///
    /// Use after [`crate::Client::mcp_apps_wire_host`] or
    /// [`crate::HttpClient::mcp_apps_wire_host`] to supply consent, model
    /// context and renderer hooks without reimplementing core requests. The
    /// original initialization policy, fresh core IDs, cancellation cleanup
    /// and selected-era result validation remain in force.
    ///
    /// This consumes and preserves the same Host, including its activation,
    /// lifecycle, capabilities, pending requests and catalog. It never
    /// reinitializes a View or revives a disconnected one. New callbacks apply
    /// to future effects; already accepted host state remains unchanged.
    /// When composed repeatedly, ordinary effects use the latest callbacks,
    /// while cancellation retains every prior cleanup and observer in order
    /// before invoking the new observer.
    #[must_use]
    pub fn with_effects<E: McpAppsWireHostEffects>(
        self,
        effects: E,
    ) -> McpAppsWireHost<T, McpAppsWireHostWithEffects<P, E>> {
        McpAppsWireHost {
            transport: self.transport,
            _activation_proof: self._activation_proof,
            admission: self.admission,
            next_host_id: self.next_host_id,
            configuration: self.configuration,
            policy: McpAppsWireHostWithEffects {
                forwarding: self.policy,
                effects,
            },
            state: self.state,
            deferred_view_frames: self.deferred_view_frames,
            deferred_view_requests: self.deferred_view_requests,
            host_requests: self.host_requests,
            view_tools: self.view_tools,
            staged_view_tools: self.staged_view_tools,
            teardown_request: self.teardown_request,
            server_catalogs: self.server_catalogs,
            disconnected: self.disconnected,
        }
    }

    /// Authorizes catalog forwarding for this exact admitted View and MCP
    /// security partition. List bridges are disabled until this is installed.
    /// The carrier must already enforce the bound resource/origin; these Host
    /// values describe that decision and do not authenticate browser messages.
    ///
    /// `allow_prompts` additionally asserts that the installed forwarding
    /// policy discovered and authorized this same server's prompts capability.
    /// Apps defines no `serverPrompts` capability, so none is advertised.
    ///
    /// Rebinding, even to identical strings, invalidates every old continuation.
    /// The embedder must rebind or revoke before changing origin, principal,
    /// server, authorization, connection generation, or catalog revision. The
    /// built-in forwarding policies hold an exclusive borrow of their client.
    /// This method does not discover identity or detect external policy changes.
    pub fn bind_server_catalogs(
        &mut self,
        binding: McpAppsCatalogBinding,
        allow_prompts: bool,
    ) -> Result<(), McpAppsHostError> {
        if self.disconnected || matches!(self.lifecycle(), McpAppsBridgeLifecycle::Closing | McpAppsBridgeLifecycle::Closed) {
            return Err(McpAppsHostError::Bridge(McpAppsBridgeError::InvalidLifecycle));
        }
        if [&binding.view_id, &binding.resource_uri, &binding.origin, &binding.principal_id,
            &binding.server_id, &binding.revision].iter()
            .any(|value| value.is_empty() || value.len() > MAX_APPS_CATALOG_CURSOR_BYTES)
            || fastmcp_protocol::common_types::AbsoluteUri::parse(binding.resource_uri.clone()).is_err()
        {
            return Err(invalid_view_result());
        }
        let replacement = WireServerCatalogs {
            binding: Some(binding), allow_prompts, ..WireServerCatalogs::default()
        };
        if self.retained_tool_bytes().saturating_sub(self.server_catalogs.retained_bytes())
            .saturating_add(replacement.retained_bytes()) > MAX_MCP_APPS_VIEW_TOOL_STATE_BYTES
        {
            return Err(McpAppsHostError::Bridge(McpAppsBridgeError::TooManyInFlight));
        }
        self.server_catalogs = replacement;
        self.invalidate_deferred_catalog_requests();
        Ok(())
    }

    /// Withdraws same-server catalog authorization and invalidates all its
    /// outstanding continuation handles. It does not change View-owned tools.
    pub fn revoke_server_catalogs(&mut self) {
        self.server_catalogs = WireServerCatalogs::default();
        self.invalidate_deferred_catalog_requests();
    }

    fn invalidate_deferred_catalog_requests(&mut self) {
        self.server_catalogs.invalidated_requests.retain(|id| self.deferred_view_requests.contains(id));
        for frame in &self.deferred_view_frames {
            if let Ok(McpAppsJsonRpcEnvelope::Request { id, method, .. }) =
                McpAppsJsonRpcEnvelope::decode(McpAppsBridgeDirection::ViewToHost, frame)
            {
                if is_server_catalog(method) { self.server_catalogs.invalidated_requests.insert(id); }
            }
        }
    }

    /// Bounded diagnostic count of optional unsafe resource-size hints omitted
    /// from successfully delivered catalog pages in the current binding.
    #[must_use]
    pub fn omitted_catalog_size_hints(&self) -> u64 {
        if self.disconnected { 0 } else { self.server_catalogs.omitted_sizes }
    }

    #[must_use]
    pub const fn lifecycle(&self) -> McpAppsBridgeLifecycle {
        if self.disconnected { McpAppsBridgeLifecycle::Closed } else { self.admission.lifecycle() }
    }

    /// The last context replacement accepted by this View's host policy.
    /// An accepted empty update is retained as an empty value, not a missing
    /// update. The slot is cleared when teardown begins and grants no authority.
    #[must_use]
    pub fn model_context(&self) -> Option<&McpAppsUpdateModelContextParams> {
        if self.disconnected { None } else { self.state.model_context.as_ref() }
    }

    /// The actual mode from initialization or the last accepted mode operation.
    #[must_use]
    pub const fn display_mode(&self) -> Option<McpAppsDisplayMode> {
        if self.disconnected { None } else { self.state.host_context.display_mode }
    }

    /// Reads the last complete catalog for this View only. A partial or
    /// rejected refresh never replaces the prior catalog.
    pub fn view_tools(&self) -> impl Iterator<Item = &McpAppsViewTool> {
        self.view_tools.values().filter(|_| !self.disconnected && self.lifecycle() == McpAppsBridgeLifecycle::Active)
            .map(AsRef::as_ref)
    }

    /// Takes exactly one correlated Host request outcome, releasing its
    /// retained byte and count budget. Pending and unknown IDs return `None`.
    pub fn take_host_response(
        &mut self,
        request_id: &McpAppsJsonRpcRequestId,
    ) -> Option<McpAppsWireHostResponse> {
        if self.disconnected { self.disconnect_view(); }
        if !matches!(self.host_requests.get(request_id)?.state, WireHostRequestState::Complete(_)) {
            return None;
        }
        let entry = self.host_requests.remove(request_id)?;
        let WireHostRequestState::Complete(outcome) = entry.state else {
            return None;
        };
        Some(McpAppsWireHostResponse {
            request_id: request_id.clone(),
            method: entry.method,
            outcome,
        })
    }

    /// Drives this same View until one previously issued Host request has a
    /// terminal outcome. Other request outcomes remain independently retained.
    /// Cancelling this future leaves the request owned by the Host; callers
    /// may resume waiting or explicitly send its cancellation control.
    pub async fn wait_for_host_response(
        &mut self,
        cx: &Cx,
        request_id: &McpAppsJsonRpcRequestId,
    ) -> Result<McpAppsWireHostResponse, McpAppsHostError> {
        loop {
            if let Some(response) = self.take_host_response(request_id) {
                return Ok(response);
            }
            if !self.host_requests.contains_key(request_id) {
                return Err(McpAppsHostError::Bridge(McpAppsBridgeError::UnknownCorrelation));
            }
            self.process_next(cx).await?;
        }
    }

    /// Receives, decodes, and atomically admits exactly one View frame.
    ///
    /// A View request remains request-owned while its policy work is pending:
    /// this method concurrently receives one matching cancellation and drops
    /// that work before committing the cancellation disposition. Other frames
    /// are deferred and replayed after the request reaches a terminal result.
    pub async fn process_next(&mut self, cx: &Cx) -> Result<(), McpAppsHostError> {
        if self.disconnected {
            self.disconnect_view();
            return Err(McpAppsHostError::Transport("MCP Apps View is disconnected".to_owned()));
        }
        self.server_catalogs.invalidated_requests.retain(|id| self.deferred_view_requests.contains(id));
        if self.lifecycle() != McpAppsBridgeLifecycle::Active {
            self.deferred_view_frames.clear();
            for id in std::mem::take(&mut self.deferred_view_requests) {
                let _ = self.admission.complete_error(McpAppsBridgeDirection::ViewToHost, &id);
            }
        }
        if expire_wire_host_requests(
            &mut self.admission, &mut self.host_requests, &mut self.staged_view_tools,
            &mut self.teardown_request,
        )? {
            if self.lifecycle() == McpAppsBridgeLifecycle::Closed {
                self.view_tools.clear();
                self.state = McpAppsWireHostState::default();
            }
            return Ok(());
        }
        // Policy callbacks execute serially. Preserve new View application
        // requests until outstanding Host requests settle, while continuing
        // to receive their correlated terminal/control frames immediately.
        let host_pending = self.host_requests.values()
            .any(|entry| !matches!(entry.state, WireHostRequestState::Complete(_)));
        let frame = match if host_pending { None } else { self.deferred_view_frames.pop_front() } {
            Some(frame) => frame,
            None => match receive_wire_host_frame(
                cx, &mut self.transport, &self.host_requests, &self.staged_view_tools,
                &self.teardown_request,
            ).await {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    expire_wire_host_requests(
                        &mut self.admission, &mut self.host_requests, &mut self.staged_view_tools,
                        &mut self.teardown_request,
                    )?;
                    if self.lifecycle() == McpAppsBridgeLifecycle::Closed {
                        self.view_tools.clear();
                        self.state = McpAppsWireHostState::default();
                    }
                    return Ok(());
                }
                Err(error) => {
                    if matches!(error, McpAppsHostError::Transport(_)) { self.disconnect_view(); }
                    return Err(error);
                }
            },
        };
        let envelope = McpAppsJsonRpcEnvelope::decode(McpAppsBridgeDirection::ViewToHost, &frame)
            .map_err(McpAppsHostError::Bridge)?;
        if host_pending && matches!(envelope, McpAppsJsonRpcEnvelope::Request { .. }) {
            if self.deferred_view_frames.len() >= MAX_MCP_APPS_BRIDGE_IN_FLIGHT
                || self.retained_tool_bytes() + frame.len() > MAX_MCP_APPS_VIEW_TOOL_STATE_BYTES
            {
                return Err(McpAppsHostError::Bridge(McpAppsBridgeError::TooManyInFlight));
            }
            if let McpAppsJsonRpcEnvelope::Request { id, method, progress_token, .. } = &envelope {
                self.admission.admit_request(McpAppsBridgeDirection::ViewToHost, id.clone(), *method, progress_token.clone())
                    .map_err(McpAppsHostError::Bridge)?;
                self.deferred_view_requests.insert(id.clone());
            }
            self.deferred_view_frames.push_back(frame);
            return Ok(());
        }
        match envelope {
            McpAppsJsonRpcEnvelope::Request {
                id, method, params, progress_token,
            } => {
                if !self.deferred_view_requests.remove(&id) {
                    self.admission.admit_request(
                        McpAppsBridgeDirection::ViewToHost, id.clone(), method, progress_token,
                    ).map_err(McpAppsHostError::Bridge)?;
                }
                self.handle_view_request(cx, id, method, params).await
            }
            McpAppsJsonRpcEnvelope::Notification { method, params } => {
                self.admission.admit_notification(
                    McpAppsBridgeDirection::ViewToHost, method, params.as_ref(),
                ).map_err(McpAppsHostError::Bridge)?;
                self.handle_view_notification(cx, method, params).await
            }
            McpAppsJsonRpcEnvelope::Response { id, result } => {
                self.complete_host_request(cx, id, Ok(result)).await
            }
            McpAppsJsonRpcEnvelope::Error { id, error } => {
                self.complete_host_request(cx, id, Err(error)).await
            }
        }
    }

    fn retained_tool_bytes(&self) -> usize {
        view_catalog_bytes(&self.view_tools)
            + self.staged_view_tools.as_ref().map_or(0, staged_view_tool_bytes)
            + self.host_requests.values().map(|entry| entry.retained_bytes).sum::<usize>()
            + self.deferred_view_frames.iter().map(String::len).sum::<usize>()
            + self.server_catalogs.retained_bytes()
    }

    fn disconnect_view(&mut self) {
        self.disconnected = true;
        self.view_tools.clear();
        self.staged_view_tools = None;
        self.deferred_view_frames.clear();
        self.deferred_view_requests.clear();
        self.state = McpAppsWireHostState::default();
        self.revoke_server_catalogs();
        for (id, entry) in &mut self.host_requests {
            if !matches!(entry.state, WireHostRequestState::Complete(_)) {
                let _ = self.admission.complete_error(McpAppsBridgeDirection::HostToView, id);
                entry.state = WireHostRequestState::Complete(McpAppsHostRequestOutcome::ViewClosed);
                entry.retained_bytes = 0;
            }
        }
        if self.admission.lifecycle() == McpAppsBridgeLifecycle::Active {
            let _ = self.admission.begin_teardown();
        }
        if self.admission.lifecycle() == McpAppsBridgeLifecycle::Closing {
            let _ = self.admission.commit_teardown();
        }
        self.teardown_request = None;
    }

    async fn complete_host_request(
        &mut self,
        cx: &Cx,
        id: McpAppsJsonRpcRequestId,
        result: Result<Value, McpAppsJsonRpcError>,
    ) -> Result<(), McpAppsHostError> {
        if self.teardown_request.as_ref().is_some_and(|(request_id, _)| request_id == &id) {
            match &result {
                Ok(value) => { self.admission.complete_response(McpAppsBridgeDirection::HostToView, &id, value) }
                Err(_) => { self.admission.complete_error(McpAppsBridgeDirection::HostToView, &id) }
            }.map_err(McpAppsHostError::Bridge)?;
            self.admission.commit_teardown().map_err(McpAppsHostError::Bridge)?;
            self.teardown_request = None;
            self.view_tools.clear();
            self.staged_view_tools = None;
            self.state.model_context = None;
            self.revoke_server_catalogs();
            for entry in self.host_requests.values_mut() {
                if !matches!(entry.state, WireHostRequestState::Complete(_)) {
                    entry.state = WireHostRequestState::Complete(McpAppsHostRequestOutcome::ViewClosed);
                    entry.retained_bytes = 0;
                }
            }
            return Ok(());
        }
        let entry = self.host_requests.get(&id)
            .filter(|entry| !matches!(entry.state, WireHostRequestState::Complete(_)))
            .ok_or(McpAppsHostError::Bridge(McpAppsBridgeError::UnknownCorrelation))?;
        let was_list = matches!(entry.state, WireHostRequestState::List);
        let old_bytes = entry.retained_bytes;
        let deadline = entry.deadline.clone();
        let mut prepared_catalog = None;
        let mut prepared_stage = None;
        let parsed = match &result {
            Err(error) => serde_json::to_vec(error)
                .map(|bytes| (McpAppsHostRequestOutcome::PeerError(error.clone()), bytes.len()))
                .map_err(|_| invalid_view_result()),
            Ok(value) => McpAppsJsonRpcEnvelope::validate_response_for(entry.method, value)
                .map_err(McpAppsHostError::Bridge)
                .and_then(|()| match &entry.state {
                    WireHostRequestState::List => {
                        let page = decode_view_tool_page(value)?;
                        let mut tools = self.staged_view_tools.as_ref()
                            .map_or_else(BTreeMap::new, |stage| stage.tools.clone());
                        for tool in &page.tools {
                            if tools.insert(tool.descriptor.name.clone(), Arc::clone(tool)).is_some() {
                                return Err(invalid_view_result());
                            }
                        }
                        if tools.len() > MAX_MCP_APPS_VIEW_TOOLS { return Err(invalid_view_result()); }
                        let mut seen_cursors = self.staged_view_tools.as_ref()
                            .map_or_else(BTreeSet::new, |stage| stage.seen_cursors.clone());
                        if let Some(cursor) = &page.next_cursor {
                            if !seen_cursors.insert(cursor.clone()) || seen_cursors.len() > MAX_MCP_APPS_BRIDGE_IN_FLIGHT {
                                return Err(invalid_view_result());
                            }
                            let mut cursor_deadline = self.staged_view_tools.as_ref()
                                .map_or_else(|| deadline.clone(), |stage| stage.deadline.clone());
                            cursor_deadline.progress();
                            prepared_stage = Some(StagedViewTools {
                                tools, next_cursor: cursor.clone(), seen_cursors, deadline: cursor_deadline,
                            });
                        } else {
                            prepared_catalog = Some(tools);
                        }
                        let bytes = page.tools.iter().map(|tool| view_tool_bytes(tool)).sum::<usize>()
                            + page.next_cursor.as_ref().map_or(0, String::len);
                        Ok((McpAppsHostRequestOutcome::ToolsList(page), bytes))
                    }
                    WireHostRequestState::Call(tool) => {
                        let response = decode_view_tool_result(value, tool)?;
                        let bytes = serde_json::to_vec(value).map_err(|_| invalid_view_result())?.len();
                        Ok((McpAppsHostRequestOutcome::ToolCall(response), bytes))
                    }
                    WireHostRequestState::Ping => Ok((McpAppsHostRequestOutcome::Ping, 0)),
                    WireHostRequestState::Complete(_) => Err(invalid_view_result()),
                }),
        };
        let staged_bytes = |stage: &StagedViewTools| {
            view_catalog_bytes(&stage.tools) + stage.next_cursor.len()
                + stage.seen_cursors.iter().map(String::len).sum::<usize>()
        };
        let (mut outcome, mut bytes) = parsed.unwrap_or((McpAppsHostRequestOutcome::InvalidResponse, 0));
        let mut retained = self.retained_tool_bytes().saturating_sub(old_bytes) + bytes;
        if was_list {
            retained = retained.saturating_sub(self.staged_view_tools.as_ref().map_or(0, staged_bytes));
            if let Some(tools) = &prepared_catalog {
                retained = retained.saturating_sub(view_catalog_bytes(&self.view_tools)) + view_catalog_bytes(tools);
            }
            retained += prepared_stage.as_ref().map_or(0, staged_bytes);
        }
        if retained > MAX_MCP_APPS_VIEW_TOOL_STATE_BYTES {
            outcome = McpAppsHostRequestOutcome::InvalidResponse;
            bytes = 0;
        }
        // Every correlated terminal frame retires exactly once, including a
        // malformed result. It cannot occupy a live slot forever or acquire
        // authority by sending a later replacement response.
        self.admission.complete_error(McpAppsBridgeDirection::HostToView, &id)
            .map_err(McpAppsHostError::Bridge)?;
        let commit_catalog = matches!(outcome, McpAppsHostRequestOutcome::ToolsList(_));
        if was_list { self.staged_view_tools = None; }
        let entry = self.host_requests.get_mut(&id).expect("correlation retained during validation");
        entry.state = WireHostRequestState::Complete(outcome);
        entry.retained_bytes = bytes;
        if commit_catalog {
            self.staged_view_tools = prepared_stage;
            if let Some(tools) = prepared_catalog {
                self.view_tools = tools;
                self.retire_view_tool_requests(cx, McpAppsHostRequestOutcome::CatalogChanged).await?;
            }
        }
        Ok(())
    }

    async fn retire_view_tool_requests(
        &mut self,
        cx: &Cx,
        outcome: McpAppsHostRequestOutcome,
    ) -> Result<(), McpAppsHostError> {
        let mut ids = Vec::new();
        for (id, entry) in &mut self.host_requests {
            if matches!(entry.state, WireHostRequestState::List | WireHostRequestState::Call(_)) {
                self.admission.complete_error(McpAppsBridgeDirection::HostToView, id)
                    .map_err(McpAppsHostError::Bridge)?;
                entry.state = WireHostRequestState::Complete(outcome.clone());
                entry.retained_bytes = 0;
                ids.push(id.clone());
            }
        }
        for id in ids {
            if self.lifecycle() != McpAppsBridgeLifecycle::Active { break; }
            self.send_envelope(cx, McpAppsJsonRpcEnvelope::Notification {
                method: McpAppsRoutedMethod::Cancelled,
                params: Some(json!({"requestId": id})),
            }).await?;
        }
        Ok(())
    }

    /// Revokes this View's tool authority and retires its exact pending calls
    /// and cursors. Embedders use this when consent, origin, or policy changes.
    pub async fn revoke_view_tools(&mut self, cx: &Cx) -> Result<(), McpAppsHostError> {
        self.state.view_tools_capability = None;
        self.view_tools.clear();
        self.staged_view_tools = None;
        self.retire_view_tool_requests(cx, McpAppsHostRequestOutcome::Cancelled).await
    }

    async fn handle_view_request(
        &mut self,
        cx: &Cx,
        id: McpAppsJsonRpcRequestId,
        method: McpAppsRoutedMethod,
        params: Option<Value>,
    ) -> Result<(), McpAppsHostError> {
        let catalog = if is_server_catalog(method) {
            let prepared = if self.server_catalogs.invalidated_requests.remove(&id) {
                Err(wire_policy_denied())
            } else {
                self.server_catalogs.prepare_request(cx, method, params.as_ref())
            };
            match prepared {
                Ok(prepared) => Some(prepared),
                Err(error) => return self.finish_view_request(cx, id, method, params.as_ref(), None, Err(error)).await,
            }
        } else { None };
        let cancellation = McpRequestCancellation::new();
        let mut execution = Box::pin(async {
            let operation = Self::dispatch_view_request(
                &mut self.policy, &self.configuration, &mut self.state, cx, &cancellation,
                method, catalog.as_ref().map_or(params.as_ref(), |request| Some(&request.params)),
            );
            match &catalog {
                Some(request) => await_wire_operation(cx, &request.deadline, operation).await,
                None => operation.await,
            }
        });
        let mut deferred_error = None;
        loop {
            expire_wire_host_requests(
                &mut self.admission, &mut self.host_requests, &mut self.staged_view_tools,
                &mut self.teardown_request,
            )?;
            let mut incoming = Box::pin(receive_wire_host_frame(
                cx, &mut self.transport, &self.host_requests, &self.staged_view_tools,
                &self.teardown_request,
            ));
            let selected = Select::new(&mut execution, &mut incoming)
                .await
                .map_err(|error| McpAppsHostError::Transport(error.to_string()))?;
            match selected {
                Either::Left(result) => {
                    drop(incoming);
                    drop(execution);
                    let completion = self
                        .finish_view_request(cx, id, method, params.as_ref(), catalog, result)
                        .await;
                    return match (completion, deferred_error) {
                        (Err(error), _) => Err(error),
                        (Ok(()), Some(error)) => Err(error),
                        (Ok(()), None) => Ok(()),
                    };
                }
                Either::Right(frame) => {
                    drop(incoming);
                    let frame = match frame {
                        Ok(Some(frame)) => frame,
                        Ok(None) => continue,
                        Err(error) => {
                            drop(execution);
                            if matches!(error, McpAppsHostError::Transport(_)) { self.disconnect_view(); }
                            return Err(error);
                        }
                    };
                    if let Ok(McpAppsJsonRpcEnvelope::Notification { method: McpAppsRoutedMethod::Cancelled, params }) =
                        McpAppsJsonRpcEnvelope::decode(McpAppsBridgeDirection::ViewToHost, &frame)
                    {
                        let cancelled = decode_params(params.as_ref())?;
                        if cancel_deferred_view_request(&mut self.admission, &mut self.deferred_view_frames,
                            &mut self.deferred_view_requests, &cancelled)? { continue; }
                    }
                    match Self::matching_view_cancellation(&self.admission, &id, &frame) {
                        Ok(Some(params)) => {
                            // Give the request-owned forwarding policy the
                            // cancellation it was explicitly handed before
                            // committing the Apps control.  The real stdio
                            // policy flushes the released multiplexed owner
                            // into its one upstream cancellation frame; the
                            // real HTTP policy abandons its owned response
                            // body.  Neither path may produce a local Apps
                            // response after this matching control wins.
                            cancellation.cancel();
                            // This is the request-owned cancellation boundary:
                            // dropping the in-flight future releases every
                            // resource it owns without detaching work into the
                            // ambient Host context. Do not await a policy here;
                            // a non-cooperative embedder policy must not hold
                            // the View bridge or delay this cancellation commit.
                            drop(execution);
                            self.commit_view_cancellation(cx, &id, &params)?;
                            return Ok(());
                        }
                        Ok(None) => {
                            let retained = self.deferred_view_frames.iter().map(String::len).sum::<usize>()
                                + view_catalog_bytes(&self.view_tools)
                                + self.staged_view_tools.as_ref().map_or(0, staged_view_tool_bytes)
                                + self.host_requests.values().map(|entry| entry.retained_bytes).sum::<usize>()
                                + self.server_catalogs.retained_bytes();
                            if self.deferred_view_frames.len() >= MAX_MCP_APPS_BRIDGE_IN_FLIGHT
                                || retained + frame.len() > MAX_MCP_APPS_VIEW_TOOL_STATE_BYTES
                            {
                                drop(execution);
                                self.admission
                                    .complete_error(McpAppsBridgeDirection::ViewToHost, &id)
                                    .map_err(McpAppsHostError::Bridge)?;
                                return Err(McpAppsHostError::Bridge(
                                    McpAppsBridgeError::TooManyInFlight,
                                ));
                            }
                            if let Ok(McpAppsJsonRpcEnvelope::Request { id, method, progress_token, .. }) =
                                McpAppsJsonRpcEnvelope::decode(McpAppsBridgeDirection::ViewToHost, &frame)
                            {
                                if let Err(error) = self.admission.admit_request(McpAppsBridgeDirection::ViewToHost, id.clone(), method, progress_token) {
                                    deferred_error.get_or_insert(McpAppsHostError::Bridge(error));
                                    continue;
                                }
                                self.deferred_view_requests.insert(id);
                            }
                            self.deferred_view_frames.push_back(frame);
                        }
                        Err(error) => {
                            // The malformed or unmatched control cannot affect
                            // the live request. Surface it only after that
                            // request has reached a terminal state.
                            deferred_error.get_or_insert(error);
                        }
                    }
                }
            }
        }
    }

    async fn finish_view_request(
        &mut self,
        cx: &Cx,
        id: McpAppsJsonRpcRequestId,
        method: McpAppsRoutedMethod,
        params: Option<&Value>,
        catalog: Option<WireCatalogRequest>,
        result: Result<Value, McpAppsHostError>,
    ) -> Result<(), McpAppsHostError> {
        let mut prepared_catalog = None;
        let result = result.and_then(|result| {
            let result = if let Some(request) = &catalog {
                let prepared = self.server_catalogs.prepare_page(cx, method, request, result, self.retained_tool_bytes())?;
                let result = prepared.result.clone();
                prepared_catalog = Some(prepared);
                result
            } else { result };
            McpAppsJsonRpcEnvelope::validate_response_for(method, &result)
                .map_err(McpAppsHostError::Bridge)?;
            if catalog.is_some() {
                McpAppsJsonRpcEnvelope::Response { id: id.clone(), result: result.clone() }
                    .encode(McpAppsBridgeDirection::HostToView).map_err(McpAppsHostError::Bridge)?;
            }
            Ok(result)
        });
        match result {
            Ok(result) => {
                let initialization = if method == McpAppsRoutedMethod::Initialize {
                    let response: McpAppsPinnedInitializeResult = decode_params(Some(&result))?;
                    let request: McpAppsPinnedInitializeParams = decode_params(params)?;
                    let declared_modes = params
                        .and_then(|params| params.get("appCapabilities"))
                        .and_then(|capabilities| capabilities.get("availableDisplayModes"))
                        .map(|_| request.app_capabilities.available_display_modes);
                    Some((response, declared_modes, request.app_capabilities.tools))
                } else {
                    None
                };
                let response = McpAppsJsonRpcEnvelope::Response {
                    id: id.clone(),
                    result: result.clone(),
                };
                if let (Some(request), Some(prepared)) = (catalog, prepared_catalog) {
                    // Preflight every fallible encode, quota and correlation
                    // step before entering the carrier. A dropped/failed send
                    // fences the Host; success has one synchronous commit.
                    let frame = response.encode(McpAppsBridgeDirection::HostToView)
                        .map_err(McpAppsHostError::Bridge)?;
                    let mut admission = self.admission.clone();
                    admission.complete_response(McpAppsBridgeDirection::ViewToHost, &id, &result)
                        .map_err(McpAppsHostError::Bridge)?;
                    let mut guard = WireCatalogSendGuard { disconnected: &mut self.disconnected, committed: false };
                    await_wire_operation(cx, &request.deadline, self.transport.send_to_view(cx, frame)).await?;
                    if let Some(previous) = request.previous { self.server_catalogs.cursors.remove(&previous); }
                    if let Some((token, cursor)) = prepared.cursor { self.server_catalogs.cursors.insert(token, cursor); }
                    self.server_catalogs.omitted_sizes = self.server_catalogs.omitted_sizes.saturating_add(prepared.omitted_sizes);
                    self.admission = admission;
                    guard.committed = true;
                    return Ok(());
                }
                self.send_envelope(cx, response).await?;
                if method == McpAppsRoutedMethod::Initialize {
                    self.admission
                        .initialization_response_committed()
                        .map_err(McpAppsHostError::Bridge)?;
                }
                self.admission
                    .complete_response(McpAppsBridgeDirection::ViewToHost, &id, &result)
                    .map_err(McpAppsHostError::Bridge)?;
                if let Some((response, declared_modes, view_tools_capability)) = initialization {
                    self.state.capabilities = Some(response.host_capabilities);
                    self.state.host_context = response.host_context;
                    self.state.view_display_modes = declared_modes;
                    self.state.view_tools_capability = view_tools_capability;
                }
                Ok(())
            }
            Err(error) => {
                let response = McpAppsJsonRpcEnvelope::Error {
                    id: id.clone(),
                    error: bridge_error_response(),
                };
                self.send_envelope(cx, response).await?;
                self.admission
                    .complete_error(McpAppsBridgeDirection::ViewToHost, &id)
                    .map_err(McpAppsHostError::Bridge)?;
                let _ = error;
                Ok(())
            }
        }
    }

    async fn dispatch_view_request(
        policy: &mut P,
        configuration: &McpAppsWireHostConfiguration,
        state: &mut McpAppsWireHostState,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: McpAppsRoutedMethod,
        params: Option<&Value>,
    ) -> Result<Value, McpAppsHostError> {
        match method {
            McpAppsRoutedMethod::Initialize => {
                let params: McpAppsPinnedInitializeParams = decode_params(params)?;
                serde_json::to_value(policy.initialize(&params, configuration).await)
                    .map_err(|error| McpAppsHostError::Transport(error.to_string()))
            }
            McpAppsRoutedMethod::Ping => Ok(json!({})),
            McpAppsRoutedMethod::UpdateModelContext => {
                let raw = params.ok_or(McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams))?;
                if raw.get("content").is_some_and(Value::is_null)
                    || raw.get("structuredContent").is_some_and(Value::is_null)
                {
                    return Err(McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams));
                }
                let params: McpAppsUpdateModelContextParams = decode_params(params)?;
                let modalities = state.capabilities.as_ref()
                    .and_then(|capabilities| capabilities.update_model_context.as_ref())
                    .ok_or_else(wire_policy_denied)?;
                if !permits_content(modalities, params.content.as_deref().unwrap_or(&[]))
                    || (params.structured_content.is_some() && modalities.structured_content.is_none())
                {
                    return Err(wire_policy_denied());
                }
                wire_policy_checkpoint(cx, cancellation)?;
                policy.update_model_context(cx, cancellation, &params).await?;
                // Callback success is the effect commit. Retain its accepted
                // value even if subsequent response delivery fails; a failed
                // send cannot undo a host effect or authorize its replay.
                state.model_context = Some(params);
                Ok(json!({}))
            }
            McpAppsRoutedMethod::RequestDisplayMode => {
                let params: McpAppsDisplayModeParams = decode_params(params)?;
                if !state.permits_mode(params.mode) { return Err(wire_policy_denied()); }
                wire_policy_checkpoint(cx, cancellation)?;
                let result = policy.request_display_mode(
                    cx, cancellation, params, state.host_context.display_mode,
                ).await?;
                if !state.permits_mode(result.mode) { return Err(wire_policy_denied()); }
                state.host_context.display_mode = Some(result.mode);
                encode_wire_host_request_params(result)
            }
            McpAppsRoutedMethod::OpenLink | McpAppsRoutedMethod::DownloadFile => {
                let capabilities = state.capabilities.as_ref().ok_or_else(wire_policy_denied)?;
                let permitted = if method == McpAppsRoutedMethod::OpenLink {
                    capabilities.open_links.is_some()
                } else {
                    capabilities.download_file.is_some()
                };
                if !permitted { return Err(wire_policy_denied()); }
                wire_policy_checkpoint(cx, cancellation)?;
                policy.operation(method, params).await
            }
            McpAppsRoutedMethod::Message => {
                let request: fastmcp_protocol::McpAppsMessageParams = decode_params(params)?;
                let modalities = state.capabilities.as_ref()
                    .and_then(|capabilities| capabilities.message.as_ref())
                    .ok_or_else(wire_policy_denied)?;
                if !permits_content(modalities, &request.content) { return Err(wire_policy_denied()); }
                wire_policy_checkpoint(cx, cancellation)?;
                policy.operation(method, params).await
            }
            method @ (McpAppsRoutedMethod::ToolsCall
            | McpAppsRoutedMethod::ResourcesRead
            | McpAppsRoutedMethod::ResourcesList
            | McpAppsRoutedMethod::ResourceTemplatesList
            | McpAppsRoutedMethod::PromptsList) => {
                if method != McpAppsRoutedMethod::PromptsList {
                    let capabilities = state.capabilities.as_ref().ok_or_else(wire_policy_denied)?;
                    let permitted = if method == McpAppsRoutedMethod::ToolsCall {
                        capabilities.server_tools.is_some()
                    } else {
                        capabilities.server_resources.is_some()
                    };
                    if !permitted { return Err(wire_policy_denied()); }
                }
                wire_policy_checkpoint(cx, cancellation)?;
                policy
                    .dispatch_reused_request(cx, cancellation, method, params.cloned())
                    .await
            }
            _ => Err(McpAppsHostError::Bridge(
                McpAppsBridgeError::InvalidMethodDirection,
            )),
        }
    }

    fn matching_view_cancellation(
        admission: &McpAppsBridgeAdmission,
        request_id: &McpAppsJsonRpcRequestId,
        frame: &str,
    ) -> Result<Option<McpAppsCancelledControlParams>, McpAppsHostError> {
        let McpAppsJsonRpcEnvelope::Notification {
            method: McpAppsRoutedMethod::Cancelled,
            params,
        } = McpAppsJsonRpcEnvelope::decode(McpAppsBridgeDirection::ViewToHost, frame)
            .map_err(McpAppsHostError::Bridge)?
        else {
            return Ok(None);
        };
        let disposition = admission
            .admit_control(
                McpAppsBridgeDirection::ViewToHost,
                McpAppsRoutedMethod::Cancelled,
                params.as_ref(),
            )
            .map_err(McpAppsHostError::Bridge)?;
        let McpAppsControlDisposition::Bound(bound_id) = disposition else {
            return Ok(None);
        };
        if &bound_id != request_id {
            return Ok(None);
        }
        decode_params(params.as_ref()).map(Some)
    }

    fn commit_view_cancellation(
        &mut self,
        cx: &Cx,
        request_id: &McpAppsJsonRpcRequestId,
        params: &McpAppsCancelledControlParams,
    ) -> Result<(), McpAppsHostError> {
        self.policy.cancelled(cx, request_id, params)?;
        self.admission
            .complete_error(McpAppsBridgeDirection::ViewToHost, request_id)
            .map_err(McpAppsHostError::Bridge)
            .map(|_| ())
    }

    async fn handle_view_notification(
        &mut self,
        cx: &Cx,
        method: McpAppsRoutedMethod,
        params: Option<Value>,
    ) -> Result<(), McpAppsHostError> {
        match method {
            McpAppsRoutedMethod::Progress => {
                let disposition = self
                    .admission
                    .admit_control(McpAppsBridgeDirection::ViewToHost, method, params.as_ref())
                    .map_err(McpAppsHostError::Bridge)?;
                if let McpAppsControlDisposition::Bound(request_id) = disposition {
                    let params: McpAppsProgressControlParams = decode_params(params.as_ref())?;
                    if let Some(entry) = self.host_requests.get_mut(&request_id) {
                        if entry.last_progress.is_none_or(|previous| params.progress > previous) {
                            entry.last_progress = Some(params.progress);
                            entry.deadline.progress();
                        }
                    }
                    let mut callback_deadline = WireHostDeadline::new(cx);
                    if let Some(remaining) = self.host_requests.values()
                        .filter(|entry| !matches!(entry.state, WireHostRequestState::Complete(_)))
                        .map(|entry| entry.deadline.next().as_nanos().saturating_sub(entry.deadline.owner.now().as_nanos()))
                        .min()
                    {
                        callback_deadline.absolute = callback_deadline.absolute.min(cx.now().saturating_add_nanos(remaining));
                    }
                    await_wire_operation(cx, &callback_deadline, self.policy.progress(&request_id, &params)).await?;
                }
                return Ok(());
            }
            McpAppsRoutedMethod::Cancelled => {
                let disposition = self
                    .admission
                    .admit_control(McpAppsBridgeDirection::ViewToHost, method, params.as_ref())
                    .map_err(McpAppsHostError::Bridge)?;
                if let McpAppsControlDisposition::Bound(request_id) = disposition {
                    let params = decode_params(params.as_ref())?;
                    if !cancel_deferred_view_request(&mut self.admission, &mut self.deferred_view_frames,
                        &mut self.deferred_view_requests, &params)? {
                        self.commit_view_cancellation(cx, &request_id, &params)?;
                    }
                }
                return Ok(());
            }
            _ => {}
        }
        if self.admission.lifecycle() != McpAppsBridgeLifecycle::Active {
            return Ok(());
        }
        if method == McpAppsRoutedMethod::AppToolsListChanged {
            if !self.state.view_tools_capability.as_ref().is_some_and(|capability| capability.list_changed) {
                return Err(wire_policy_denied());
            }
            self.view_tools.clear();
            self.staged_view_tools = None;
            self.retire_view_tool_requests(cx, McpAppsHostRequestOutcome::CatalogChanged).await?;
        }
        self.policy.notification(method, params.as_ref()).await?;
        if method == McpAppsRoutedMethod::RequestTeardown
            && self.policy.approve_view_teardown().await
        {
            self.begin_teardown(cx).await?;
        }
        Ok(())
    }

    /// Sends one active-phase Host-to-View request with an independent bridge
    /// correlation. `ui/resource-teardown` has stricter lifecycle handling,
    /// so callers must use [`Self::begin_teardown`] for that request.
    ///
    /// An optional progress token is bound before the frame commits. A View's
    /// matching `notifications/progress` is delivered to
    /// [`McpAppsWireHostPolicy::progress`] with this returned request ID.
    pub async fn send_host_request(
        &mut self,
        cx: &Cx,
        request: McpAppsHostRequest,
        progress_token: Option<McpAppsJsonRpcRequestId>,
    ) -> Result<McpAppsJsonRpcRequestId, McpAppsHostError> {
        expire_wire_host_requests(
            &mut self.admission, &mut self.host_requests, &mut self.staged_view_tools,
            &mut self.teardown_request,
        )?;
        if self.disconnected || self.admission.lifecycle() != McpAppsBridgeLifecycle::Active {
            return Err(McpAppsHostError::Bridge(
                McpAppsBridgeError::InvalidLifecycle,
            ));
        }
        if self.host_requests.len() >= MAX_MCP_APPS_BRIDGE_IN_FLIGHT {
            return Err(McpAppsHostError::Bridge(McpAppsBridgeError::TooManyInFlight));
        }
        let mut restart_pagination = false;
        let mut inherited_deadline = None;
        let operation_deadline = WireHostDeadline::new(cx);
        let state = match &request {
            McpAppsHostRequest::ToolsList(params) => {
                if self.state.view_tools_capability.is_none() { return Err(wire_policy_denied()); }
                if self.host_requests.values().any(|entry| matches!(entry.state, WireHostRequestState::List)) {
                    return Err(McpAppsHostError::Bridge(McpAppsBridgeError::TooManyInFlight));
                }
                match &params.cursor {
                    Some(cursor) if self.staged_view_tools.as_ref()
                        .is_some_and(|stage| &stage.next_cursor == cursor) => {
                            let mut deadline = self.staged_view_tools.as_ref()
                                .expect("matched live cursor").deadline.clone();
                            deadline.progress();
                            inherited_deadline = Some(deadline);
                        }
                    Some(_) => return Err(invalid_view_result()),
                    None => restart_pagination = true,
                }
                WireHostRequestState::List
            }
            McpAppsHostRequest::CallTool(params) => {
                if self.state.view_tools_capability.is_none() { return Err(wire_policy_denied()); }
                let tool = self.view_tools.get(&params.name).cloned().ok_or_else(wire_policy_denied)?;
                let arguments = params.arguments.as_ref().map_or_else(|| json!({}), |arguments| {
                    Value::Object(arguments.clone().into_iter().collect())
                });
                admit_view_numbers(&arguments)?;
                tool.input_schema.validate(&arguments).map_err(|_| invalid_view_result())?;
                if cx.checkpoint().is_err() { return Err(McpAppsHostError::Core(McpError::request_cancelled())); }
                await_wire_operation(cx, &operation_deadline, self.policy.approve_view_tool_call(cx, &tool, params)).await?;
                if cx.checkpoint().is_err() { return Err(McpAppsHostError::Core(McpError::request_cancelled())); }
                WireHostRequestState::Call(tool)
            }
            McpAppsHostRequest::Ping(_) => WireHostRequestState::Ping,
            McpAppsHostRequest::ResourceTeardown(_) => {
                return Err(McpAppsHostError::Bridge(McpAppsBridgeError::InvalidLifecycle));
            }
        };
        let (method, params) = wire_host_request_parts(request)?;
        let id = self
            .next_host_id
            .allocate()
            .map_err(McpAppsHostError::Bridge)?;
        let envelope = McpAppsJsonRpcEnvelope::Request {
            id: id.clone(),
            method,
            params,
            progress_token: progress_token.clone(),
        };
        let frame = envelope
            .encode(McpAppsBridgeDirection::HostToView)
            .map_err(McpAppsHostError::Bridge)?;
        let retained_bytes = frame.len() + match &state {
            WireHostRequestState::Call(tool) => view_tool_bytes(tool),
            _ => 0,
        };
        if self.retained_tool_bytes() + retained_bytes > MAX_MCP_APPS_VIEW_TOOL_STATE_BYTES {
            return Err(McpAppsHostError::Bridge(McpAppsBridgeError::MessageTooLarge));
        }
        self.admission
            .admit_request(
                McpAppsBridgeDirection::HostToView,
                id.clone(),
                method,
                progress_token,
            )
            .map_err(McpAppsHostError::Bridge)?;
        let deadline = inherited_deadline.unwrap_or(operation_deadline);
        self.host_requests.insert(id.clone(), WireHostRequest {
            method, state, retained_bytes, deadline: deadline.clone(), last_progress: None,
        });
        let mut guard = WireHostSendGuard {
            admission: &mut self.admission,
            requests: &mut self.host_requests,
            disconnected: &mut self.disconnected,
            id: Some(id.clone()),
        };
        let sent = await_wire_operation(cx, &deadline, self.transport.send_to_view(cx, frame)).await;
        if sent.is_ok() { guard.id = None; }
        drop(guard);
        if sent.is_err() { self.disconnect_view(); }
        else if restart_pagination {
            self.staged_view_tools = None;
        } else if method == McpAppsRoutedMethod::ToolsList {
            if let Some(stage) = &mut self.staged_view_tools { stage.deadline = deadline; }
        }
        sent.map(|()| id)
    }

    /// Sends one active-phase Host-to-View notification through the closed
    /// JSON-RPC carrier.
    ///
    /// The bridge encodes only the direction-correct notification vocabulary.
    /// Progress must select a live View request's token, and a bound
    /// cancellation releases only the matching Host-originated request after
    /// carrier delivery commits.
    pub async fn send_notification(
        &mut self,
        cx: &Cx,
        notification: McpAppsHostNotification,
    ) -> Result<(), McpAppsHostError> {
        if self.disconnected {
            self.disconnect_view();
            return Err(McpAppsHostError::Bridge(McpAppsBridgeError::InvalidLifecycle));
        }
        if self.admission.lifecycle() != McpAppsBridgeLifecycle::Active {
            return Err(McpAppsHostError::Bridge(
                McpAppsBridgeError::InvalidLifecycle,
            ));
        }
        let (method, params) = wire_host_notification_parts(notification)?;
        if matches!(method, McpAppsRoutedMethod::ResourcesListChanged | McpAppsRoutedMethod::PromptsListChanged) {
            // The producer has observed a new catalog revision even if the
            // subsequent notification send fails. Old handles cannot select it.
            self.server_catalogs.cursors.clear();
            self.invalidate_deferred_catalog_requests();
        }
        let merged_context = if method == McpAppsRoutedMethod::HostContextChanged {
            let mut merged = serde_json::to_value(&self.state.host_context)
                .map_err(|_| McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams))?;
            let additions = params.as_ref().and_then(Value::as_object)
                .ok_or(McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams))?;
            let target = merged.as_object_mut()
                .ok_or(McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams))?;
            target.extend(additions.iter().map(|(key, value)| (key.clone(), value.clone())));
            // Validate the bounded complete retained state, not only the
            // smaller outgoing patch. Omitted fields keep their old values.
            McpAppsJsonRpcEnvelope::Notification {
                method,
                params: Some(merged.clone()),
            }.encode(McpAppsBridgeDirection::HostToView)
                .map_err(McpAppsHostError::Bridge)?;
            Some(decode_params::<McpAppsPinnedHostContext>(Some(&merged))?)
        } else {
            None
        };
        let control = match method {
            McpAppsRoutedMethod::Progress | McpAppsRoutedMethod::Cancelled => Some(
                self.admission
                    .admit_control(McpAppsBridgeDirection::HostToView, method, params.as_ref())
                    .map_err(McpAppsHostError::Bridge)?,
            ),
            _ => None,
        };
        self.send_envelope(cx, McpAppsJsonRpcEnvelope::Notification { method, params })
            .await?;
        if let Some(context) = merged_context {
            self.state.host_context = context;
        }
        if let (
            McpAppsRoutedMethod::Cancelled,
            Some(McpAppsControlDisposition::Bound(request_id)),
        ) = (method, control)
        {
            self.admission
                .complete_error(McpAppsBridgeDirection::HostToView, &request_id)
                .map_err(McpAppsHostError::Bridge)?;
            if let Some(entry) = self.host_requests.get_mut(&request_id) {
                if matches!(entry.state, WireHostRequestState::List) { self.staged_view_tools = None; }
                entry.state = WireHostRequestState::Complete(McpAppsHostRequestOutcome::Cancelled);
                entry.retained_bytes = 0;
            }
        }
        Ok(())
    }

    /// Starts a Host-approved teardown. A failed carrier send restores the
    /// active admission state without dropping unrelated live correlations.
    pub async fn begin_teardown(&mut self, cx: &Cx) -> Result<(), McpAppsHostError> {
        if self.disconnected {
            self.disconnect_view();
            return Err(McpAppsHostError::Bridge(McpAppsBridgeError::InvalidLifecycle));
        }
        let id = self
            .next_host_id
            .allocate()
            .map_err(McpAppsHostError::Bridge)?;
        let request = McpAppsJsonRpcEnvelope::Request {
            id: id.clone(),
            method: McpAppsRoutedMethod::ResourceTeardown,
            params: Some(json!({})),
            progress_token: None,
        };
        let frame = request
            .encode(McpAppsBridgeDirection::HostToView)
            .map_err(McpAppsHostError::Bridge)?;
        self.admission
            .admit_request(
                McpAppsBridgeDirection::HostToView,
                id.clone(),
                McpAppsRoutedMethod::ResourceTeardown,
                None,
            )
            .map_err(McpAppsHostError::Bridge)?;
        self.admission
            .begin_teardown()
            .map_err(McpAppsHostError::Bridge)?;
        let deadline = WireHostDeadline::new(cx);
        self.teardown_request = Some((id.clone(), deadline.clone()));
        let sent = await_wire_operation(cx, &deadline, self.transport.send_to_view(cx, frame)).await;
        if sent.is_err() {
            self.teardown_request = None;
            self.admission
                .complete_error(McpAppsBridgeDirection::HostToView, &id)
                .map_err(McpAppsHostError::Bridge)?;
            self.admission
                .rollback_teardown()
                .map_err(McpAppsHostError::Bridge)?;
        } else {
            self.state.model_context = None;
            self.revoke_server_catalogs();
            self.deferred_view_frames.clear();
            for request_id in std::mem::take(&mut self.deferred_view_requests) {
                self.admission.complete_error(McpAppsBridgeDirection::ViewToHost, &request_id)
                    .map_err(McpAppsHostError::Bridge)?;
            }
            self.view_tools.clear();
            self.staged_view_tools = None;
            for (request_id, entry) in &mut self.host_requests {
                if !matches!(entry.state, WireHostRequestState::Complete(_)) {
                    self.admission.complete_error(McpAppsBridgeDirection::HostToView, request_id)
                        .map_err(McpAppsHostError::Bridge)?;
                    entry.state = WireHostRequestState::Complete(McpAppsHostRequestOutcome::ViewClosed);
                    entry.retained_bytes = 0;
                }
            }
        }
        sent
    }

    async fn send_envelope(
        &mut self,
        cx: &Cx,
        envelope: McpAppsJsonRpcEnvelope,
    ) -> Result<(), McpAppsHostError> {
        let frame = envelope
            .encode(McpAppsBridgeDirection::HostToView)
            .map_err(McpAppsHostError::Bridge)?;
        await_wire_operation(cx, &WireHostDeadline::new(cx), self.transport.send_to_view(cx, frame)).await
    }
}

fn wire_host_request_parts(
    request: McpAppsHostRequest,
) -> Result<(McpAppsRoutedMethod, Option<Value>), McpAppsHostError> {
    match request {
        McpAppsHostRequest::ToolsList(params) => encode_wire_host_request_params(params)
            .map(|params| (McpAppsRoutedMethod::ToolsList, Some(params))),
        McpAppsHostRequest::CallTool(params) => encode_wire_host_request_params(params)
            .map(|params| (McpAppsRoutedMethod::ToolsCall, Some(params))),
        McpAppsHostRequest::Ping(params) => encode_wire_host_request_params(params)
            .map(|params| (McpAppsRoutedMethod::Ping, Some(params))),
        McpAppsHostRequest::ResourceTeardown(_) => Err(McpAppsHostError::Bridge(
            McpAppsBridgeError::InvalidLifecycle,
        )),
    }
}

fn wire_host_notification_parts(
    notification: McpAppsHostNotification,
) -> Result<(McpAppsRoutedMethod, Option<Value>), McpAppsHostError> {
    let optional_member = |name: &str, value: Option<Value>| {
        let mut params = serde_json::Map::new();
        if let Some(value) = value {
            params.insert(name.to_owned(), value);
        }
        Some(Value::Object(params))
    };
    match notification {
        McpAppsHostNotification::ToolInput { arguments } => Ok((
            McpAppsRoutedMethod::ToolInput,
            optional_member(
                "arguments",
                arguments.map(|arguments| Value::Object(arguments.into_iter().collect())),
            ),
        )),
        McpAppsHostNotification::ToolInputPartial { arguments } => Ok((
            McpAppsRoutedMethod::ToolInputPartial,
            optional_member(
                "arguments",
                arguments.map(|arguments| Value::Object(arguments.into_iter().collect())),
            ),
        )),
        McpAppsHostNotification::ToolResult(result) => Ok((
            McpAppsRoutedMethod::ToolResult,
            Some(
                serde_json::to_value(result)
                    .map_err(|_| McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams))?,
            ),
        )),
        McpAppsHostNotification::ToolCancelled { reason } => Ok((
            McpAppsRoutedMethod::ToolCancelled,
            optional_member("reason", reason.map(Value::String)),
        )),
        McpAppsHostNotification::HostContextChanged(context) => Ok((
            McpAppsRoutedMethod::HostContextChanged,
            Some(
                serde_json::to_value(context)
                    .map_err(|_| McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams))?,
            ),
        )),
        McpAppsHostNotification::ToolsListChanged => {
            Ok((McpAppsRoutedMethod::ToolsListChanged, None))
        }
        McpAppsHostNotification::ResourcesListChanged => {
            Ok((McpAppsRoutedMethod::ResourcesListChanged, None))
        }
        McpAppsHostNotification::PromptsListChanged => {
            Ok((McpAppsRoutedMethod::PromptsListChanged, None))
        }
        McpAppsHostNotification::Progress(progress) => {
            let progress_token = serde_json::from_value(progress.progress_token)
                .map_err(|_| McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams))?;
            Ok((
                McpAppsRoutedMethod::Progress,
                Some(
                    serde_json::to_value(McpAppsProgressControlParams {
                        progress_token,
                        progress: progress.progress,
                        total: progress.total,
                        message: None,
                    })
                    .map_err(|_| McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams))?,
                ),
            ))
        }
        McpAppsHostNotification::Cancelled(cancelled) => Ok((
            McpAppsRoutedMethod::Cancelled,
            Some(
                serde_json::to_value(McpAppsCancelledControlParams {
                    request_id: cancelled
                        .request_id
                        .map(|id| McpAppsJsonRpcRequestId::new(id.get()))
                        .transpose()
                        .map_err(McpAppsHostError::Bridge)?,
                    reason: cancelled.reason,
                })
                .map_err(|_| McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams))?,
            ),
        )),
    }
}

fn encode_wire_host_request_params<T: serde::Serialize>(
    value: T,
) -> Result<Value, McpAppsHostError> {
    serde_json::to_value(value).map_err(|error| McpAppsHostError::Transport(error.to_string()))
}

fn decode_params<T: serde::de::DeserializeOwned>(
    params: Option<&Value>,
) -> Result<T, McpAppsHostError> {
    let params = params.ok_or(McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams))?;
    serde_json::from_value(params.clone())
        .map_err(|_| McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams))
}

fn bridge_error_response() -> McpAppsJsonRpcError {
    McpAppsJsonRpcError::try_new(-32_000, "MCP Apps request rejected".to_owned(), None)
        .expect("the fixed MCP Apps bridge error is bounded")
}

pub(crate) fn project_reused_core_result(
    method: McpAppsRoutedMethod,
    result: CoreResult,
) -> McpResult<Value> {
    let result = match (method, &result) {
        (
            McpAppsRoutedMethod::ToolsCall,
            CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }),
        ) => serde_json::to_value(&result.payload),
        #[cfg(feature = "tasks")]
        (
            McpAppsRoutedMethod::ToolsCall,
            CoreResult::Final(FinalCoreResult::ToolsCallTask { .. }),
        ) => {
            return Err(McpError::invalid_request(
                "MCP Apps bridge does not support Tasks or input-required results",
            ));
        }
        (
            McpAppsRoutedMethod::ToolsCall,
            CoreResult::Final(FinalCoreResult::ToolsCallInputRequired { .. }),
        )
        | (
            McpAppsRoutedMethod::ResourcesRead,
            CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired { .. }),
        ) => {
            return Err(McpError::invalid_request(
                "MCP Apps bridge does not support Tasks or input-required results",
            ));
        }
        (
            McpAppsRoutedMethod::ResourcesRead,
            CoreResult::Final(FinalCoreResult::ResourcesRead { result, .. }),
        ) => serde_json::to_value(&result.payload),
        (
            McpAppsRoutedMethod::ResourcesList,
            CoreResult::Final(FinalCoreResult::ResourcesList { result, .. }),
        ) => serde_json::to_value(&result.payload),
        (
            McpAppsRoutedMethod::ResourceTemplatesList,
            CoreResult::Final(FinalCoreResult::ResourceTemplatesList { result, .. }),
        ) => serde_json::to_value(&result.payload),
        (
            McpAppsRoutedMethod::PromptsList,
            CoreResult::Final(FinalCoreResult::PromptsList { result, .. }),
        ) => serde_json::to_value(&result.payload),
        _ => {
            return Err(McpError::invalid_request(
                "Apps reused request received a contradictory selected-era core result",
            ));
        }
    }
    .map_err(|_| McpError::internal_error("Apps core result could not form a bridge response"))?;
    Ok(result)
}

/// Concrete policy that forwards only standard-reused View methods through a
/// fresh selected-era core request on one live [`crate::Client`].
pub struct McpAppsClientWirePolicy<'client> {
    client: &'client mut crate::Client,
}

impl<'client> McpAppsClientWirePolicy<'client> {
    pub(crate) fn new(client: &'client mut crate::Client) -> Self {
        Self { client }
    }
}

impl McpAppsWireHostPolicy for McpAppsClientWirePolicy<'_> {
    fn cancelled(
        &mut self,
        cx: &Cx,
        _request_id: &McpAppsJsonRpcRequestId,
        _params: &McpAppsCancelledControlParams,
    ) -> Result<(), McpAppsHostError> {
        // `handle_view_request` drops the request-owned execution before this
        // immediate hook commits bridge cancellation. Servicing the shared
        // executor here turns that drop into its one bounded upstream
        // cancellation control without reading the stdio response stream again.
        self.client
            .service_multiplexed_stdio(cx)
            .map_err(McpAppsHostError::Core)
    }

    async fn dispatch_reused_request(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: McpAppsRoutedMethod,
        params: Option<Value>,
    ) -> Result<Value, McpAppsHostError> {
        self.client
            .forward_mcp_apps_reused_core(cx, cancellation, method, params)
            .await
            .map_err(McpAppsHostError::Core)
    }
}

/// HTTP counterpart to [`McpAppsClientWirePolicy`]. Its forwarding path uses
/// the ready connection's fresh request-ID allocator and selected-era decoder.
pub struct McpAppsHttpClientWirePolicy<'client> {
    client: &'client mut crate::HttpClient,
}

impl<'client> McpAppsHttpClientWirePolicy<'client> {
    pub(crate) fn new(client: &'client mut crate::HttpClient) -> Self {
        Self { client }
    }
}

impl McpAppsWireHostPolicy for McpAppsHttpClientWirePolicy<'_> {
    async fn dispatch_reused_request(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: McpAppsRoutedMethod,
        params: Option<Value>,
    ) -> Result<Value, McpAppsHostError> {
        self.client
            .forward_mcp_apps_reused_core(cx, cancellation, method, params)
            .await
            .map_err(McpAppsHostError::Core)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use fastmcp_core::{McpErrorCode, block_on};
    use fastmcp_protocol::extensions::{
        ClientExtensionDiscovery, ExtensionDescriptorRegistry, ExtensionLocalEnablement,
        ExtensionSettings, ServerExtensionDiscovery, official_mcp_apps_empty_server_settings,
        official_mcp_apps_negotiation_resolver, register_official_mcp_apps_extension,
    };
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use fastmcp_protocol::{
        CoreRequest, FINAL_PROTOCOL_VERSION, McpAppsBridgeImplementation,
        McpAppsDownloadFileParams, McpAppsHostNotification, McpAppsMessageParams,
        McpAppsMessageRole, McpAppsOpenLinkParams, McpAppsProgressNotification,
        McpAppsToolCallParams, McpAppsToolResult, McpAppsUpdateModelContextParams,
        McpAppsViewCapabilities,
    };
    use serde_json::json;

    fn catalog_binding() -> McpAppsCatalogBinding {
        McpAppsCatalogBinding {
            view_id: "catalog-view".into(), resource_uri: "ui://catalog/view".into(),
            origin: "https://view.example".into(), principal_id: "principal-7".into(),
            server_id: "server-9".into(), revision: "revision-1".into(),
        }
    }

    fn catalog_page(method: McpAppsRoutedMethod, cursor: Option<&str>) -> Value {
        let (key, item) = match method {
            McpAppsRoutedMethod::ResourcesList => ("resources", json!({"name":"entry", "uri":"test://entry"})),
            McpAppsRoutedMethod::ResourceTemplatesList => ("resourceTemplates", json!({"name":"entry", "uriTemplate":"test://{entry}"})),
            McpAppsRoutedMethod::PromptsList => ("prompts", json!({"name":"entry"})),
            _ => panic!("catalog fixture requires a list method"),
        };
        let mut page = json!({"ttlMs":1000,"cacheScope":"private"});
        page[key] = json!([item]);
        if let Some(cursor) = cursor { page["nextCursor"] = json!(cursor); }
        page
    }

    struct CatalogPolicy {
        observed: Vec<(McpAppsRoutedMethod, Value)>,
        responses: VecDeque<Result<Value, McpAppsHostError>>,
        pending: bool,
    }

    impl McpAppsWireHostPolicy for CatalogPolicy {
        async fn dispatch_reused_request(
            &mut self, _cx: &Cx, _cancellation: &McpRequestCancellation,
            method: McpAppsRoutedMethod, params: Option<Value>,
        ) -> Result<Value, McpAppsHostError> {
            self.observed.push((method, params.unwrap_or_else(|| json!({}))));
            if self.pending { std::future::pending().await } else {
                self.responses.pop_front().expect("unexpected downstream catalog request")
            }
        }
    }

    async fn catalog_host(cx: &Cx) -> (
        McpAppsWireHost<McpAppsInMemoryWireHostTransport, CatalogPolicy>,
        McpAppsInMemoryWireViewTransport,
    ) {
        let (transport, mut view) = mcp_apps_in_memory_wire_pair(128);
        let mut host = McpAppsWireHost::new_negotiated(transport, wire_configuration(), CatalogPolicy {
            observed: Vec::new(), responses: VecDeque::new(), pending: false,
        }, activation_proof());
        host.bind_server_catalogs(catalog_binding(), true).unwrap();
        activate_stateful_wire_host(&mut host, &mut view, cx, None).await;
        (host, view)
    }

    #[test]
    fn catalog_cursor_public_round_trip_all_methods() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = catalog_host(&cx).await;
            for (method, name, upstream) in [
                (McpAppsRoutedMethod::ResourcesList, "resources/list", " private upstream / + "),
                (McpAppsRoutedMethod::ResourceTemplatesList, "resources/templates/list", ""),
                (McpAppsRoutedMethod::PromptsList, "prompts/list", "opaque-prompt-cursor"),
            ] {
                let first = catalog_page(method, Some(upstream));
                host.policy.responses.push_back(Ok(first.clone()));
                let response = stateful_wire_request(&mut host, &mut view, &cx, "page-one", name, json!({})).await;
                assert_eq!(response["id"], "page-one");
                let token = response["result"]["nextCursor"].as_str().expect("Host issued continuation").to_owned();
                assert_eq!(token.len(), 64);
                assert_ne!(token, upstream);
                let mut expected = first;
                expected["nextCursor"] = json!(token);
                assert_eq!(response["result"], expected, "all non-cursor cache/result fields survive");
                host.policy.responses.push_back(Ok(catalog_page(method, None)));
                let response = stateful_wire_request(&mut host, &mut view, &cx, "page-two", name, json!({"cursor":token})).await;
                assert_eq!(response["result"], catalog_page(method, None));
                assert_eq!(host.policy.observed.last().unwrap(), &(method, json!({"cursor":upstream})));
                assert!(host.server_catalogs.cursors.is_empty());
            }
            assert_eq!(host.policy.observed.len(), 6);
        });
    }

    #[test]
    fn catalog_cursor_wrong_owner_method_and_replay_reject_before_forwarding() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = catalog_host(&cx).await;
            let (mut other, mut other_view) = catalog_host(&cx).await;
            host.policy.responses.push_back(Ok(catalog_page(McpAppsRoutedMethod::ResourcesList, Some("upstream-secret"))));
            let page = stateful_wire_request(&mut host, &mut view, &cx, "first", "resources/list", json!({})).await;
            let token = page["result"]["nextCursor"].as_str().unwrap().to_owned();
            for (name, candidate) in [("prompts/list", token.clone()), ("resources/list", "upstream-secret".into()),
                ("resources/list", format!("{token}0"))] {
                let response = stateful_wire_request(&mut host, &mut view, &cx, "wrong", name, json!({"cursor":candidate})).await;
                assert!(response.get("error").is_some());
                assert_eq!(host.policy.observed.len(), 1);
                assert!(host.server_catalogs.cursors.contains_key(&token));
            }
            let response = stateful_wire_request(&mut other, &mut other_view, &cx, "foreign", "resources/list", json!({"cursor":token})).await;
            assert!(response.get("error").is_some());
            assert!(other.policy.observed.is_empty(), "identical binding strings do not share a Host owner");
            host.policy.responses.push_back(Ok(catalog_page(McpAppsRoutedMethod::ResourcesList, None)));
            let response = stateful_wire_request(&mut host, &mut view, &cx, "next", "resources/list", json!({"cursor":token})).await;
            assert!(response.get("result").is_some());
            let response = stateful_wire_request(&mut host, &mut view, &cx, "replay", "resources/list", json!({"cursor":token})).await;
            assert!(response.get("error").is_some());
            assert_eq!(host.policy.observed.len(), 2);
            other.revoke_server_catalogs();
            let response = stateful_wire_request(&mut other, &mut other_view, &cx, "unbound", "resources/list", json!({})).await;
            assert!(response.get("error").is_some());
            assert!(other.policy.observed.is_empty());
            other.bind_server_catalogs(catalog_binding(), false).unwrap();
            let response = stateful_wire_request(&mut other, &mut other_view, &cx, "unapproved-prompts", "prompts/list", json!({})).await;
            assert!(response.get("error").is_some());
            assert!(other.policy.observed.is_empty());
        });
    }

    #[test]
    fn catalog_cursor_rebind_expiry_and_change_invalidate() {
        block_on(async {
            let cx = Cx::for_testing();
            for changed in ["same", "view", "resource", "origin", "principal", "server", "revision", "expiry", "notification"] {
                let (mut host, mut view) = catalog_host(&cx).await;
                host.policy.responses.push_back(Ok(catalog_page(McpAppsRoutedMethod::ResourcesList, Some("private"))));
                let response = stateful_wire_request(&mut host, &mut view, &cx, "first", "resources/list", json!({})).await;
                let token = response["result"]["nextCursor"].as_str().unwrap().to_owned();
                let mut binding = catalog_binding();
                match changed {
                    "view" => binding.view_id.push('2'),
                    "resource" => binding.resource_uri.push('2'),
                    "origin" => binding.origin.push('2'),
                    "principal" => binding.principal_id.push('2'),
                    "server" => binding.server_id.push('2'),
                    "revision" => binding.revision.push('2'),
                    "expiry" => host.server_catalogs.cursors.get_mut(&token).unwrap().deadline.absolute = Time::ZERO,
                    "notification" => {
                        host.send_notification(&cx, McpAppsHostNotification::ResourcesListChanged).await.unwrap();
                        let _ = view.receive_from_host(&cx).await.unwrap();
                    }
                    _ => {}
                }
                if !matches!(changed, "expiry" | "notification") { host.bind_server_catalogs(binding, true).unwrap(); }
                let response = stateful_wire_request(&mut host, &mut view, &cx, "stale", "resources/list", json!({"cursor":token})).await;
                assert!(response.get("error").is_some(), "{changed}");
                assert_eq!(host.policy.observed.len(), 1, "{changed}");
            }
        });
    }

    #[test]
    fn catalog_cursor_rebind_fences_deferred_page_requests() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = catalog_host(&cx).await;
            let ping = host.send_host_request(&cx,
                McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()), None).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            view.send_to_host(&cx, json!({"jsonrpc":"2.0","id":"old-page","method":"resources/list","params":{}}).to_string()).await.unwrap();
            host.process_next(&cx).await.unwrap();
            assert_eq!(host.deferred_view_requests.len(), 1);
            host.bind_server_catalogs(catalog_binding(), true).unwrap();
            view.send_to_host(&cx, json!({"jsonrpc":"2.0","id":ping,"result":{}}).to_string()).await.unwrap();
            host.process_next(&cx).await.unwrap();
            host.process_next(&cx).await.unwrap();
            let response: Value = serde_json::from_str(&view.receive_from_host(&cx).await.unwrap()).unwrap();
            assert_eq!(response["id"], "old-page");
            assert!(response.get("error").is_some());
            assert!(host.policy.observed.is_empty(), "a request admitted before rebind cannot borrow the new authority");
            assert!(host.server_catalogs.invalidated_requests.is_empty());
            host.policy.responses.push_back(Ok(catalog_page(McpAppsRoutedMethod::ResourcesList, None)));
            let response = stateful_wire_request(&mut host, &mut view, &cx, "new-page", "resources/list", json!({})).await;
            assert!(response.get("result").is_some());
            assert_eq!(host.policy.observed.len(), 1);
        });
    }

    #[test]
    fn catalog_cursor_failed_page_and_cancellation_preserve_continuation() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (mut host, mut view) = catalog_host(&cx).await;
            host.policy.responses.push_back(Ok(catalog_page(McpAppsRoutedMethod::ResourcesList, Some("private"))));
            let response = stateful_wire_request(&mut host, &mut view, &cx, "first", "resources/list", json!({})).await;
            let token = response["result"]["nextCursor"].as_str().unwrap().to_owned();
            host.policy.responses.push_back(Err(wire_policy_denied()));
            let response = stateful_wire_request(&mut host, &mut view, &cx, "failure", "resources/list", json!({"cursor":token})).await;
            assert!(response.get("error").is_some());
            assert!(host.server_catalogs.cursors.contains_key(&token));
            host.policy.pending = true;
            view.send_to_host(&cx, json!({"jsonrpc":"2.0","id":"cancelled-page","method":"resources/list","params":{"cursor":token}}).to_string()).await.unwrap();
            view.send_to_host(&cx, json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"cancelled-page"}}).to_string()).await.unwrap();
            host.process_next(&cx).await.unwrap();
            assert!(host.server_catalogs.cursors.contains_key(&token));
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
            host.policy.pending = false;
            host.policy.responses.push_back(Ok(catalog_page(McpAppsRoutedMethod::ResourcesList, None)));
            let response = stateful_wire_request(&mut host, &mut view, &cx, "retry", "resources/list", json!({"cursor":token})).await;
            assert_eq!(response["id"], "retry", "cancelled request emitted no stray response");
            assert_eq!(response["result"], catalog_page(McpAppsRoutedMethod::ResourcesList, None));
            assert!(host.server_catalogs.cursors.is_empty());
        });
    }

    #[test]
    fn catalog_cursor_projection_and_capacity_abort_without_exposure() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = catalog_host(&cx).await;
            let mut page = catalog_page(McpAppsRoutedMethod::ResourcesList, Some("private"));
            page["resources"][0]["size"] = json!(9_007_199_254_740_992_u64);
            host.policy.responses.push_back(Ok(page));
            let response = stateful_wire_request(&mut host, &mut view, &cx, "size", "resources/list", json!({})).await;
            assert!(response["result"]["resources"][0].get("size").is_none());
            assert_eq!(host.omitted_catalog_size_hints(), 1);
            let token = response["result"]["nextCursor"].as_str().unwrap().to_owned();
            for invalid in ["number", "prompt-title", "annotation", "timestamp"] {
                let method = if invalid == "prompt-title" { McpAppsRoutedMethod::PromptsList } else { McpAppsRoutedMethod::ResourcesList };
                let mut page = catalog_page(method, Some("never-exposed"));
                match invalid {
                    "number" => page["resources"][0]["_meta"] = json!({"unsafe":9_007_199_254_740_992_u64}),
                    "prompt-title" => page["prompts"][0]["arguments"] = json!([{"name":"argument","title":"SDK would strip"}]),
                    "annotation" => page["resources"][0]["annotations"] = json!({"example.com/custom":true}),
                    _ => page["resources"][0]["annotations"] = json!({"lastModified":"2026-02-29T12:34Z"}),
                }
                host.policy.responses.push_back(Ok(page));
                let name = if invalid == "prompt-title" { "prompts/list" } else { "resources/list" };
                let response = stateful_wire_request(&mut host, &mut view, &cx, "invalid", name, json!({})).await;
                assert!(response.get("error").is_some(), "{invalid}");
                assert!(!response.to_string().contains("never-exposed"));
                assert_eq!(host.server_catalogs.cursors.len(), 1);
                assert!(host.server_catalogs.cursors.contains_key(&token));
            }
            for timestamp in ["0000-02-29T00:00Z", "2024-02-29T23:59:59.123+23:59", "2026-01-01T12:34-00:00"] {
                let mut page = catalog_page(McpAppsRoutedMethod::ResourcesList, None);
                page["resources"][0]["annotations"] = json!({"lastModified":timestamp});
                host.policy.responses.push_back(Ok(page.clone()));
                let response = stateful_wire_request(&mut host, &mut view, &cx, "timestamp", "resources/list", json!({})).await;
                assert_eq!(response["result"], page);
            }
            for index in 1..MAX_APPS_CATALOG_CURSORS {
                host.policy.responses.push_back(Ok(catalog_page(McpAppsRoutedMethod::ResourcesList, Some("private"))));
                let response = stateful_wire_request(&mut host, &mut view, &cx, &format!("capacity-{index}"), "resources/list", json!({})).await;
                assert!(response.get("result").is_some());
            }
            host.policy.responses.push_back(Ok(catalog_page(McpAppsRoutedMethod::ResourcesList, Some("private"))));
            let response = stateful_wire_request(&mut host, &mut view, &cx, "overflow", "resources/list", json!({})).await;
            assert!(response.get("error").is_some());
            assert_eq!(host.server_catalogs.cursors.len(), MAX_APPS_CATALOG_CURSORS);
            host.deferred_view_frames.push_back("x".repeat(MAX_MCP_APPS_VIEW_TOOL_STATE_BYTES));
            let binding = host.server_catalogs.binding.clone();
            assert!(host.bind_server_catalogs(catalog_binding(), true).is_err());
            assert_eq!(host.server_catalogs.binding, binding);
            assert!(host.server_catalogs.cursors.contains_key(&token));
        });
    }

    #[test]
    fn catalog_cursor_failed_send_fences_host() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(4);
            let mut host = McpAppsWireHost::new_negotiated(FailableWireTransport { inner: transport, fail: false },
                wire_configuration(), CatalogPolicy { observed: Vec::new(), responses: VecDeque::new(), pending: false }, activation_proof());
            host.bind_server_catalogs(catalog_binding(), true).unwrap();
            activate_stateful_wire_host(&mut host, &mut view, &cx, None).await;
            host.policy.responses.push_back(Ok(catalog_page(McpAppsRoutedMethod::ResourcesList, Some("private"))));
            host.transport.fail = true;
            view.send_to_host(&cx, json!({"jsonrpc":"2.0","id":"page","method":"resources/list","params":{}}).to_string()).await.unwrap();
            assert!(host.process_next(&cx).await.is_err());
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Closed);
            assert!(host.server_catalogs.cursors.is_empty());
            assert!(host.bind_server_catalogs(catalog_binding(), true).is_err());
            assert!(host.process_next(&cx).await.is_err());
            assert_eq!(host.policy.observed.len(), 1);
        });
    }

    async fn public_catalog_pages<P: McpAppsWireHostPolicy>(
        cx: &Cx,
        host: &mut McpAppsWireHost<McpAppsInMemoryWireHostTransport, P>,
        view: &mut McpAppsInMemoryWireViewTransport,
    ) {
        host.bind_server_catalogs(catalog_binding(), true).unwrap();
        activate_stateful_wire_host(host, view, cx, None).await;
        for (method, name) in [
            (McpAppsRoutedMethod::ResourcesList, "resources/list"),
            (McpAppsRoutedMethod::ResourceTemplatesList, "resources/templates/list"),
            (McpAppsRoutedMethod::PromptsList, "prompts/list"),
        ] {
            let first = stateful_wire_request(host, view, cx, "view-first", name, json!({})).await;
            let token = first["result"]["nextCursor"].as_str().expect("real server page issues Host continuation").to_owned();
            assert_ne!(token, "upstream-cursor");
            assert!(!first.to_string().contains("upstream-cursor"));
            let wrong = stateful_wire_request(host, view, cx, "view-tampered", name, json!({"cursor":format!("{token}x")})).await;
            assert!(wrong.get("error").is_some(), "tampering must not create a real server request");
            let second = stateful_wire_request(host, view, cx, "view-second", name, json!({"cursor":token})).await;
            assert_eq!(second["id"], "view-second");
            assert_eq!(second["result"], catalog_page(method, None));
        }
    }

    #[cfg(unix)]
    #[test]
    fn catalog_cursor_public_stdio_round_trip() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let script = r#"
IFS= read -r discovery || exit 91
case "$discovery" in *server/discover*io.modelcontextprotocol/ui*) ;; *) exit 92 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"resources":{},"prompts":{},"extensions":{"io.modelcontextprotocol/ui":{}}},"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"catalog-peer","version":"1"}}}}'
id=2
for method in resources/list resources/templates/list prompts/list; do
    case "$method" in
        resources/list) members='"resources":[{"name":"entry","uri":"test://entry"}]' ;;
        resources/templates/list) members='"resourceTemplates":[{"name":"entry","uriTemplate":"test://{entry}"}]' ;;
        prompts/list) members='"prompts":[{"name":"entry"}]' ;;
    esac
    for page in first second; do
        IFS= read -r request || exit 93
        case "$request" in *"\"method\":\"$method\""*) ;; *) exit 94 ;; esac
        case "$request" in *"\"id\":$id"*) ;; *) exit 95 ;; esac
        case "$request" in *io.modelcontextprotocol/protocolVersion*2026-07-28*) ;; *) exit 96 ;; esac
        case "$request" in *view-first*|*view-second*|*view-tampered*) exit 97 ;; esac
        if [ "$page" = first ]; then
            case "$request" in *'"cursor"'*) exit 98 ;; esac
            cursor=',"nextCursor":"upstream-cursor"'
        else
            case "$request" in *'"cursor":"upstream-cursor"'*) ;; *) exit 99 ;; esac
            cursor=''
        fi
        printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete",%s,"ttlMs":1000,"cacheScope":"private"%s}}\n' "$id" "$members" "$cursor"
        id=$((id + 1))
    done
done
IFS= read -r ping || exit 100
case "$ping" in *'"method":"ping"'*'"id":8'*|*'"id":8'*'"method":"ping"'*) ;; *) exit 101 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":8,"result":{}}'
exec sleep 10
"#;
            let mut client = crate::ClientBuilder::new()
                .protocol_plan(crate::ClientProtocolPlan::stdio(fastmcp_protocol::protocol_policy::ProtocolPolicy::ModernOnly))
                .mcp_apps(fastmcp_protocol::extensions::McpAppsClientSettings::new(vec![fastmcp_protocol::MCP_APPS_HTML_MIME_TYPE.into()]).unwrap())
                .connect_stdio_with_cx(&cx, "sh", &["-c", script]).await.unwrap();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let mut host = client.mcp_apps_wire_host(transport, wire_configuration()).unwrap();
            public_catalog_pages(&cx, &mut host, &mut view).await;
            drop(host);
            client.ping_with_cx(&cx, &McpRequestCancellation::new()).await.unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    fn catalog_cursor_public_http_round_trip() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for index in 0..7 {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0_u8; 4096];
                let header_end = loop {
                    let count = stream.read(&mut buffer).unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buffer[..count]);
                    if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") { break end + 4; }
                };
                let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
                let length = headers.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
                }).unwrap();
                while bytes.len() < header_end + length {
                    let count = stream.read(&mut buffer).unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buffer[..count]);
                }
                let request: Value = serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap();
                assert_eq!(request["id"], index + 1);
                let result = if index == 0 {
                    assert_eq!(request["method"], "server/discover");
                    json!({"resultType":"complete","supportedVersions":["2026-07-28"],
                        "capabilities":{"resources":{},"prompts":{},"extensions":{"io.modelcontextprotocol/ui":{}}},
                        "ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"http-catalog-peer","version":"1"}}})
                } else {
                    let (method, name) = match (index - 1) / 2 {
                        0 => (McpAppsRoutedMethod::ResourcesList, "resources/list"),
                        1 => (McpAppsRoutedMethod::ResourceTemplatesList, "resources/templates/list"),
                        _ => (McpAppsRoutedMethod::PromptsList, "prompts/list"),
                    };
                    assert_eq!(request["method"], name);
                    assert_eq!(request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], "2026-07-28");
                    let first = index % 2 == 1;
                    if first { assert!(request["params"].get("cursor").is_none()); }
                    else { assert_eq!(request["params"]["cursor"], "upstream-cursor"); }
                    assert!(!request.to_string().contains("view-"));
                    let mut page = catalog_page(method, first.then_some("upstream-cursor"));
                    page["resultType"] = json!("complete");
                    page
                };
                let body = json!({"jsonrpc":"2.0","id":index + 1,"result":result}).to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
                stream.flush().unwrap();
            }
        });
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let plan = crate::ClientProtocolPlan::http(
                fastmcp_protocol::protocol_policy::ProtocolPolicy::ModernOnly,
                Some(crate::CanonicalHttpUrl::parse(&format!("http://{address}/mcp")).unwrap()),
                None, None, "credential".into(), "security".into(), "transport".into(), 1, 1, 0,
            ).unwrap();
            let mut client = crate::ClientBuilder::new().protocol_plan(plan)
                .mcp_apps(fastmcp_protocol::extensions::McpAppsClientSettings::new(vec![fastmcp_protocol::MCP_APPS_HTML_MIME_TYPE.into()]).unwrap())
                .connect_http_client_with_cx(&cx).await.unwrap();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let mut host = client.mcp_apps_wire_host(transport, wire_configuration()).unwrap();
            public_catalog_pages(&cx, &mut host, &mut view).await;
        });
        server.join().unwrap();
    }

    struct ComposedEffects {
        allow: bool,
        events: Arc<Mutex<Vec<Value>>>,
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "embedder decisions commit synchronously through async effect hooks"
    )]
    impl McpAppsWireHostEffects for ComposedEffects {
        async fn update_model_context(
            &mut self,
            cx: &Cx,
            cancellation: &McpRequestCancellation,
            params: &McpAppsUpdateModelContextParams,
        ) -> Result<(), McpAppsHostError> {
            wire_policy_checkpoint(cx, cancellation)?;
            if !self.allow {
                return Err(wire_policy_denied());
            }
            self.events.lock().unwrap().push(json!({"context": params}));
            Ok(())
        }

        async fn approve_view_tool_call(
            &mut self,
            _cx: &Cx,
            tool: &McpAppsViewTool,
            params: &McpAppsToolCallParams,
        ) -> Result<(), McpAppsHostError> {
            if !self.allow {
                return Err(wire_policy_denied());
            }
            assert_eq!(tool.descriptor().name, params.name);
            self.events
                .lock()
                .unwrap()
                .push(json!({"approved": params.name}));
            Ok(())
        }

        fn cancelled(
            &mut self,
            _cx: &Cx,
            request_id: &McpAppsJsonRpcRequestId,
            params: &McpAppsCancelledControlParams,
        ) -> Result<(), McpAppsHostError> {
            assert_eq!(params.request_id.as_ref(), Some(request_id));
            self.events
                .lock()
                .unwrap()
                .push(json!({"cancelled": request_id}));
            Ok(())
        }
    }

    #[cfg(unix)]
    async fn initialize_composed_view<P: McpAppsWireHostPolicy>(
        cx: &Cx,
        host: &mut McpAppsWireHost<McpAppsInMemoryWireHostTransport, P>,
        view: &mut McpAppsInMemoryWireViewTransport,
    ) {
        view.send_to_host(
            cx,
            json!({
                "jsonrpc": "2.0", "id": "initialize", "method": "ui/initialize",
                "params": {
                    "appInfo": {"name": "composed-effects-view", "version": "1"},
                    "appCapabilities": {},
                    "protocolVersion": MCP_APPS_HOST_VIEW_PROTOCOL_VERSION
                }
            })
            .to_string(),
        )
        .await
        .unwrap();
        host.process_next(cx).await.unwrap();
        let initialized: Value =
            serde_json::from_str(&view.receive_from_host(cx).await.unwrap()).unwrap();
        assert_eq!(initialized["id"], "initialize");
        assert_eq!(
            initialized["result"]["hostCapabilities"]["serverTools"],
            json!({})
        );
        view.send_to_host(
            cx,
            json!({
                "jsonrpc": "2.0", "method": "ui/notifications/initialized"
            })
            .to_string(),
        )
        .await
        .unwrap();
        host.process_next(cx).await.unwrap();
        assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
    }

    #[cfg(unix)]
    async fn composed_effects_stdio_client(cx: &Cx, cancel_tool: bool) -> crate::Client {
        let opening = r#"
IFS= read -r discovery || exit 91
case "$discovery" in *server/discover*io.modelcontextprotocol/ui*) ;; *) exit 92 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{},"extensions":{"io.modelcontextprotocol/ui":{}}},"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"composed-effects-peer","version":"1"}}}}'
IFS= read -r tool || exit 93
case "$tool" in *'"method":"tools/call"'*) ;; *) exit 94 ;; esac
case "$tool" in *'"id":2'*) ;; *) exit 95 ;; esac
case "$tool" in *'"name":"server_echo"'*) ;; *) exit 96 ;; esac
case "$tool" in *'"arguments":{"value":7}'*) ;; *) exit 97 ;; esac
case "$tool" in *view-call*|*ui/update-model-context*) exit 98 ;; esac
"#;
        let execution = if cancel_tool {
            r#"
IFS= read -r cancelled || exit 101
case "$cancelled" in *'"method":"notifications/cancelled"'*) ;; *) exit 102 ;; esac
case "$cancelled" in *'"requestId":2'*) ;; *) exit 103 ;; esac
"#
        } else {
            r#"
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"real core result"}]}}'
"#
        };
        let ending = r#"
IFS= read -r ping || exit 104
case "$ping" in *'"method":"ping"'*) ;; *) exit 105 ;; esac
case "$ping" in *'"id":3'*) ;; *) exit 106 ;; esac
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{}}'
exec sleep 10
"#;
        let script = format!("{opening}\n{execution}\n{ending}");
        let client = crate::ClientBuilder::new()
            .protocol_plan(crate::ClientProtocolPlan::stdio(
                fastmcp_protocol::protocol_policy::ProtocolPolicy::ModernOnly,
            ))
            .mcp_apps(
                fastmcp_protocol::extensions::McpAppsClientSettings::new(vec![
                    fastmcp_protocol::MCP_APPS_HTML_MIME_TYPE.to_owned(),
                ])
                .unwrap(),
            )
            .request_timeout_policy(
                crate::RequestTimeoutPolicy::new(
                    std::time::Duration::from_secs(5),
                    std::time::Duration::from_secs(5),
                )
                .unwrap(),
            )
            .connect_stdio_with_cx(cx, "sh", &["-c", &script])
            .await
            .expect("public discovery must negotiate Apps with the real subprocess");
        assert!(client.mcp_apps_active());
        client
    }

    #[cfg(unix)]
    async fn composed_effects_context_and_core_case(cx: &Cx, allow: bool) {
        let mut client = composed_effects_stdio_client(cx, false).await;
        let events = Arc::new(Mutex::new(Vec::new()));
        let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
        let mut configuration = wire_configuration();
        configuration.host_capabilities.update_model_context =
            Some(serde_json::from_value(json!({"text": {}})).unwrap());
        let mut host = client
            .mcp_apps_wire_host(transport, configuration)
            .unwrap()
            .with_effects(ComposedEffects {
                allow,
                events: Arc::clone(&events),
            });
        initialize_composed_view(cx, &mut host, &mut view).await;
        let replacement = json!({"content": [{"type": "text", "text": "selected row"}]});
        view.send_to_host(
            cx,
            json!({
                "jsonrpc": "2.0", "id": "context", "method": "ui/update-model-context",
                "params": replacement
            })
            .to_string(),
        )
        .await
        .unwrap();
        host.process_next(cx).await.unwrap();
        let response: Value =
            serde_json::from_str(&view.receive_from_host(cx).await.unwrap()).unwrap();
        assert_eq!(response["id"], "context");
        if allow {
            assert_eq!(response["result"], json!({}));
            assert_eq!(
                serde_json::to_value(host.model_context().unwrap()).unwrap(),
                replacement
            );
            assert_eq!(
                *events.lock().unwrap(),
                vec![json!({"context": replacement})]
            );
        } else {
            assert!(response["error"].is_object());
            assert!(host.model_context().is_none());
            assert!(
                events.lock().unwrap().is_empty(),
                "denied context must have no embedder effect"
            );
        }
        view.send_to_host(
            cx,
            json!({
                "jsonrpc": "2.0", "id": "view-call", "method": "tools/call",
                "params": {"name": "server_echo", "arguments": {"value": 7}}
            })
            .to_string(),
        )
        .await
        .unwrap();
        host.process_next(cx).await.unwrap();
        let response: Value =
            serde_json::from_str(&view.receive_from_host(cx).await.unwrap()).unwrap();
        assert_eq!(
            response,
            json!({
                "jsonrpc": "2.0", "id": "view-call",
                "result": {"content": [{"type": "text", "text": "real core result"}]}
            })
        );
        assert_eq!(host.model_context().is_some(), allow);
        assert_eq!(events.lock().unwrap().len(), usize::from(allow));
        drop(host);
        client
            .ping_with_cx(cx, &McpRequestCancellation::default())
            .await
            .expect(
                "the core client must remain usable after both effect and forwarding operations",
            );
        client.close_with_cx(cx).await.unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn composed_wire_effects_context_and_real_core_forwarding_positive() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            composed_effects_context_and_core_case(&cx, true).await;
        });
    }

    #[cfg(unix)]
    #[test]
    fn composed_wire_effects_context_and_real_core_forwarding_planted_negative() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            composed_effects_context_and_core_case(&cx, false).await;
        });
    }

    #[cfg(unix)]
    #[test]
    fn composed_wire_effects_cancellation_preserves_core_cleanup() {
        struct CancellationObserver(Arc<Mutex<Vec<Value>>>);
        impl McpAppsWireHostEffects for CancellationObserver {
            fn cancelled(
                &mut self,
                _cx: &Cx,
                request_id: &McpAppsJsonRpcRequestId,
                _params: &McpAppsCancelledControlParams,
            ) -> Result<(), McpAppsHostError> {
                self.0.lock().unwrap().push(json!({"observed": request_id}));
                Ok(())
            }
        }

        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let mut client = composed_effects_stdio_client(&cx, true).await;
            let events = Arc::new(Mutex::new(Vec::new()));
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let mut host = client
                .mcp_apps_wire_host(transport, wire_configuration())
                .unwrap()
                .with_effects(ComposedEffects {
                    allow: true,
                    events: Arc::clone(&events),
                })
                .with_effects(CancellationObserver(Arc::clone(&events)));
            initialize_composed_view(&cx, &mut host, &mut view).await;
            view.send_to_host(
                &cx,
                json!({
                    "jsonrpc": "2.0", "id": "view-call", "method": "tools/call",
                    "params": {"name": "server_echo", "arguments": {"value": 7}}
                })
                .to_string(),
            )
            .await
            .unwrap();
            view.send_to_host(
                &cx,
                json!({
                    "jsonrpc": "2.0", "method": "notifications/cancelled",
                    "params": {"requestId": "view-call"}
                })
                .to_string(),
            )
            .await
            .unwrap();
            host.process_next(&cx).await.unwrap();
            assert_eq!(
                *events.lock().unwrap(),
                vec![
                    json!({"cancelled": "view-call"}),
                    json!({"observed": "view-call"}),
                ]
            );
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
            drop(host);
            client
                .ping_with_cx(&cx, &McpRequestCancellation::default())
                .await
                .expect(
                    "the subprocess must observe exact core cancellation before its next request",
                );
            client.close_with_cx(&cx).await.unwrap();
        });
    }

    #[test]
    fn composed_wire_effects_preserve_pending_host_request_and_lifecycle() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = tool_wire_host(&cx, false).await;
            install_view_tool_catalog(&mut host, &mut view, &cx).await;
            let pending = host
                .send_host_request(
                    &cx,
                    McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()),
                    None,
                )
                .await
                .unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut host = host.with_effects(ComposedEffects {
                allow: true,
                events: Arc::clone(&events),
            });
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
            assert_eq!(host.view_tools().count(), 1);
            assert!(host.take_host_response(&pending).is_none());
            assert!(matches!(
                tool_wire_reply(&mut host, &mut view, &cx, &pending, json!({})).await,
                McpAppsHostRequestOutcome::Ping
            ));
            let called = host
                .send_host_request(&cx, view_tool_call(json!(3)), None)
                .await
                .unwrap();
            assert_ne!(
                pending, called,
                "composing effects must not reset the Host ID allocator"
            );
            let _ = view.receive_from_host(&cx).await.unwrap();
            assert!(matches!(
                tool_wire_reply(
                    &mut host,
                    &mut view,
                    &cx,
                    &called,
                    json!({"content": [], "structuredContent": {"accepted": 3}})
                )
                .await,
                McpAppsHostRequestOutcome::ToolCall(_)
            ));
            assert_eq!(
                *events.lock().unwrap(),
                vec![json!({"approved": "view_counter"})]
            );
            host.begin_teardown(&cx).await.unwrap();
            let teardown: Value =
                serde_json::from_str(&view.receive_from_host(&cx).await.unwrap()).unwrap();
            let mut host = host.with_effects(());
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Closing);
            assert_eq!(host.view_tools().count(), 0);
            view.send_to_host(
                &cx,
                json!({
                    "jsonrpc": "2.0", "id": teardown["id"], "result": {}
                })
                .to_string(),
            )
            .await
            .unwrap();
            host.process_next(&cx).await.unwrap();
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Closed);
            let mut host = host.with_effects(ComposedEffects {
                allow: true,
                events,
            });
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Closed);
            assert!(
                host.send_host_request(&cx, view_tool_call(json!(3)), None)
                    .await
                    .is_err()
            );
        });
    }

    struct AcceptTeardown(bool);
    impl McpAppsHostPolicy for AcceptTeardown {
        #[allow(
            clippy::unused_async_trait_impl,
            reason = "the public host-policy trait requires an async override"
        )]
        async fn approve_view_teardown(&mut self) -> bool {
            self.0
        }
        #[allow(
            clippy::unused_async_trait_impl,
            reason = "the public host-policy trait requires an async override"
        )]
        async fn dispatch_reused_request(
            &mut self,
            _cx: &Cx,
            _request: McpAppsViewRequest,
        ) -> Result<McpAppsHostResponse, McpAppsHostError> {
            Ok(McpAppsHostResponse::Ping)
        }
    }

    struct FailingTransport;
    impl McpAppsBridgeTransport for FailingTransport {
        #[allow(
            clippy::unused_async_trait_impl,
            reason = "the public bridge-transport trait requires an async override"
        )]
        async fn send_to_view(
            &mut self,
            _cx: &Cx,
            _message: McpAppsHostToView,
        ) -> Result<(), McpAppsHostError> {
            Err(McpAppsHostError::Transport("planted send failure".into()))
        }
        #[allow(
            clippy::unused_async_trait_impl,
            reason = "the public bridge-transport trait requires an async override"
        )]
        async fn receive_from_view(
            &mut self,
            _cx: &Cx,
        ) -> Result<McpAppsViewToHost, McpAppsHostError> {
            Err(McpAppsHostError::Transport("not used".into()))
        }
    }

    fn configuration() -> McpAppsHostConfiguration {
        McpAppsHostConfiguration {
            host_info: McpAppsBridgeImplementation {
                name: "headless-host".into(),
                version: "1".into(),
            },
            host_capabilities: McpAppsHostCapabilities {
                open_links: true,
                download_file: true,
                update_model_context: true,
                message: true,
            },
            host_context: McpAppsHostContext::default(),
        }
    }
    fn app() -> McpAppsBridgeImplementation {
        McpAppsBridgeImplementation {
            name: "view".into(),
            version: "1".into(),
        }
    }
    fn request_id(value: u64) -> McpAppsBridgeRequestId {
        McpAppsBridgeRequestId::new(value).unwrap()
    }
    fn activation_proof() -> McpAppsActivationProof {
        let mut registry = ExtensionDescriptorRegistry::new();
        let id = register_official_mcp_apps_extension(&mut registry).unwrap();
        registry.freeze().unwrap();
        let client = ClientExtensionDiscovery {
            extensions: BTreeMap::from([(
                id.clone(),
                ExtensionSettings::new(json!({
                    "mimeTypes": [fastmcp_protocol::MCP_APPS_HTML_MIME_TYPE]
                }))
                .unwrap(),
            )]),
        };
        let server = ServerExtensionDiscovery {
            extensions: BTreeMap::from([(id.clone(), official_mcp_apps_empty_server_settings())]),
        };
        let mut local = ExtensionLocalEnablement::default();
        local.enable(id);
        let mut resolver = official_mcp_apps_negotiation_resolver();
        let receipt = registry
            .negotiate(
                fastmcp_protocol::protocol_policy::ProtocolEra::Modern2026,
                &local,
                &client,
                &server,
                &mut resolver,
            )
            .unwrap()
            .mcp_apps_activation_receipt(&registry);
        McpAppsActivationProof::from_activation_receipt(receipt.as_ref()).unwrap()
    }

    fn final_tools_call_result(result: Value) -> CoreResult {
        let params = json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            },
            "name": "bridge-test"
        });
        let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params))
            .expect("final tools/call request admits its selected result algebra");
        request
            .decode_result(
                &serde_json::to_string(&result).expect("selected result serializes for decoding"),
            )
            .expect("selected final tools/call result decodes")
    }

    fn final_resources_read_result(result: Value) -> CoreResult {
        let params = json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}
            },
            "uri": "file:///bridge-test"
        });
        let request = CoreRequest::decode(ProtocolEra::Modern2026, "resources/read", Some(&params))
            .expect("final resources/read request admits its selected result algebra");
        request
            .decode_result(
                &serde_json::to_string(&result).expect("selected result serializes for decoding"),
            )
            .expect("selected final resources/read result decodes")
    }

    #[test]
    fn apps_reused_complete_tool_result_remains_bridgeable() {
        let result = final_tools_call_result(json!({
            "resultType": "complete",
            "content": [{"type": "text", "text": "ready"}]
        }));

        assert_eq!(
            project_reused_core_result(McpAppsRoutedMethod::ToolsCall, result)
                .expect("ordinary complete result remains bridgeable"),
            json!({"content": [{"type": "text", "text": "ready"}]}),
        );
    }

    #[test]
    fn apps_reused_task_result_is_rejected_without_apps_serialization() {
        let result = final_tools_call_result(json!({
            "resultType": "task",
            "taskId": "task-bridge",
            "status": "working",
            "createdAt": "2026-07-28T12:00:00.000Z",
            "lastUpdatedAt": "2026-07-28T12:00:00.000Z",
            "ttlMs": null
        }));

        let error = project_reused_core_result(McpAppsRoutedMethod::ToolsCall, result)
            .expect_err("a task result must not form an Apps response");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert_eq!(
            error.message,
            "MCP Apps bridge does not support Tasks or input-required results"
        );
    }

    #[test]
    fn apps_reused_input_required_result_is_rejected_without_apps_serialization() {
        let result = final_tools_call_result(json!({
            "resultType": "input_required",
            "requestState": "resume-bridge"
        }));

        let error = project_reused_core_result(McpAppsRoutedMethod::ToolsCall, result)
            .expect_err("an input-required result must not form an Apps response");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert_eq!(
            error.message,
            "MCP Apps bridge does not support Tasks or input-required results"
        );
    }

    #[test]
    fn apps_reused_resource_input_required_result_is_rejected_without_apps_serialization() {
        let result = final_resources_read_result(json!({
            "resultType": "input_required",
            "requestState": "resume-bridge"
        }));

        let error = project_reused_core_result(McpAppsRoutedMethod::ResourcesRead, result)
            .expect_err("an input-required resource result must not form an Apps response");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert_eq!(
            error.message,
            "MCP Apps bridge does not support Tasks or input-required results"
        );
    }

    #[test]
    fn headless_host_routes_every_apps_message_without_a_renderer() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_pair(64);
            let mut host = McpAppsHost::new_negotiated(
                transport,
                configuration(),
                AcceptTeardown(false),
                activation_proof(),
            );
            view.send_to_host(
                &cx,
                McpAppsViewToHost::Request {
                    id: request_id(1),
                    request: McpAppsViewRequest::Initialize(McpAppsInitializeParams {
                        app_info: app(),
                        app_capabilities: McpAppsViewCapabilities::default(),
                        protocol_version: MCP_APPS_HOST_VIEW_PROTOCOL_VERSION.into(),
                    }),
                },
            )
            .await
            .unwrap();
            host.process_next(&cx).await.unwrap();
            assert!(matches!(
                view.receive_from_host(&cx).await.unwrap(),
                McpAppsHostToView::Response {
                    response: McpAppsHostResponse::Initialize(_),
                    ..
                }
            ));
            view.send_to_host(
                &cx,
                McpAppsViewToHost::Notification(McpAppsViewNotification::Initialized),
            )
            .await
            .unwrap();
            host.process_next(&cx).await.unwrap();
            assert!(host.lifecycle().permits_application_traffic());

            let result = McpAppsToolResult::try_new(Vec::new(), false, None).unwrap();
            for notification in [
                McpAppsHostNotification::ToolInputPartial { arguments: None },
                McpAppsHostNotification::ToolInput { arguments: None },
                McpAppsHostNotification::ToolResult(result),
                McpAppsHostNotification::ToolCancelled { reason: None },
                McpAppsHostNotification::HostContextChanged(McpAppsHostContext::default()),
                McpAppsHostNotification::ToolsListChanged,
                McpAppsHostNotification::ResourcesListChanged,
                McpAppsHostNotification::PromptsListChanged,
                McpAppsHostNotification::Progress(McpAppsProgressNotification {
                    progress_token: json!(1),
                    progress: 1.0,
                    total: None,
                }),
                McpAppsHostNotification::Cancelled(
                    fastmcp_protocol::McpAppsCancelledNotification::default(),
                ),
            ] {
                host.send_notification(&cx, notification).await.unwrap();
                let _ = view.receive_from_host(&cx).await.unwrap();
            }

            let requests = vec![
                McpAppsViewRequest::OpenLink(McpAppsOpenLinkParams {
                    url: "https://example.test".into(),
                }),
                McpAppsViewRequest::DownloadFile(McpAppsDownloadFileParams {
                    contents: Vec::new(),
                }),
                McpAppsViewRequest::Message(McpAppsMessageParams {
                    role: McpAppsMessageRole::User,
                    content: Vec::new(),
                }),
                McpAppsViewRequest::UpdateModelContext(McpAppsUpdateModelContextParams::default()),
                McpAppsViewRequest::RequestDisplayMode(McpAppsDisplayModeParams {
                    mode: fastmcp_protocol::McpAppsDisplayMode::Inline,
                }),
                McpAppsViewRequest::CallTool(McpAppsToolCallParams {
                    name: "view-tool".into(),
                    arguments: None,
                }),
                McpAppsViewRequest::ResourceRead(fastmcp_protocol::McpAppsResourceReadParams {
                    uri: fastmcp_protocol::common_types::AbsoluteUri::parse("ui://view/resource")
                        .unwrap(),
                }),
                McpAppsViewRequest::ResourcesList(fastmcp_protocol::McpAppsListParams::default()),
                McpAppsViewRequest::ResourceTemplatesList(
                    fastmcp_protocol::McpAppsListParams::default(),
                ),
                McpAppsViewRequest::PromptsList(fastmcp_protocol::McpAppsListParams::default()),
                McpAppsViewRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()),
            ];
            for (index, request) in requests.into_iter().enumerate() {
                view.send_to_host(
                    &cx,
                    McpAppsViewToHost::Request {
                        id: request_id((index + 2) as u64),
                        request,
                    },
                )
                .await
                .unwrap();
                host.process_next(&cx).await.unwrap();
                let _ = view.receive_from_host(&cx).await.unwrap();
            }
            for notification in [
                McpAppsViewNotification::SizeChanged {
                    width: Some(1.0),
                    height: Some(1.0),
                },
                McpAppsViewNotification::ToolsListChanged,
                McpAppsViewNotification::LogMessage(
                    fastmcp_protocol::McpAppsLogMessageNotification {
                        level: "info".into(),
                        data: json!({}),
                        logger: None,
                    },
                ),
                McpAppsViewNotification::Progress(McpAppsProgressNotification {
                    progress_token: json!(0),
                    progress: 0.0,
                    total: None,
                }),
                McpAppsViewNotification::Cancelled(
                    fastmcp_protocol::McpAppsCancelledNotification::default(),
                ),
            ] {
                view.send_to_host(&cx, McpAppsViewToHost::Notification(notification))
                    .await
                    .unwrap();
                host.process_next(&cx).await.unwrap();
            }
        });
    }

    #[test]
    fn teardown_is_graceful_in_both_directions_and_pre_active_host_send_is_rejected() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_pair(8);
            let mut host = McpAppsHost::new_negotiated(
                transport,
                configuration(),
                AcceptTeardown(false),
                activation_proof(),
            );
            assert!(matches!(
                host.send_notification(&cx, McpAppsHostNotification::ToolsListChanged)
                    .await,
                Err(McpAppsHostError::NotActive(_))
            ));
            view.send_to_host(
                &cx,
                McpAppsViewToHost::Request {
                    id: request_id(1),
                    request: McpAppsViewRequest::Ping(
                        fastmcp_protocol::McpAppsPingParams::default(),
                    ),
                },
            )
            .await
            .unwrap();
            host.process_next(&cx).await.unwrap();
            assert!(matches!(
                view.receive_from_host(&cx).await.unwrap(),
                McpAppsHostToView::Response {
                    response: McpAppsHostResponse::Ping,
                    ..
                }
            ));
            view.send_to_host(
                &cx,
                McpAppsViewToHost::Request {
                    id: request_id(2),
                    request: McpAppsViewRequest::Initialize(McpAppsInitializeParams {
                        app_info: app(),
                        app_capabilities: McpAppsViewCapabilities::default(),
                        protocol_version: MCP_APPS_HOST_VIEW_PROTOCOL_VERSION.into(),
                    }),
                },
            )
            .await
            .unwrap();
            host.process_next(&cx).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            view.send_to_host(
                &cx,
                McpAppsViewToHost::Notification(McpAppsViewNotification::Initialized),
            )
            .await
            .unwrap();
            host.process_next(&cx).await.unwrap();
            host.begin_teardown(&cx, Some("host close".into()))
                .await
                .unwrap();
            let McpAppsHostToView::Request { id, .. } = view.receive_from_host(&cx).await.unwrap()
            else {
                panic!("expected teardown request")
            };
            view.send_to_host(
                &cx,
                McpAppsViewToHost::Response {
                    id,
                    response: McpAppsViewResponse,
                },
            )
            .await
            .unwrap();
            host.process_next(&cx).await.unwrap();
            assert_eq!(host.lifecycle(), McpAppsViewLifecycle::Closed);

            let (transport, mut view) = mcp_apps_in_memory_pair(8);
            let mut host = McpAppsHost::new_negotiated(
                transport,
                configuration(),
                AcceptTeardown(true),
                activation_proof(),
            );
            view.send_to_host(
                &cx,
                McpAppsViewToHost::Request {
                    id: request_id(3),
                    request: McpAppsViewRequest::Initialize(McpAppsInitializeParams {
                        app_info: app(),
                        app_capabilities: McpAppsViewCapabilities::default(),
                        protocol_version: MCP_APPS_HOST_VIEW_PROTOCOL_VERSION.into(),
                    }),
                },
            )
            .await
            .unwrap();
            host.process_next(&cx).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            view.send_to_host(
                &cx,
                McpAppsViewToHost::Notification(McpAppsViewNotification::Initialized),
            )
            .await
            .unwrap();
            host.process_next(&cx).await.unwrap();
            view.send_to_host(
                &cx,
                McpAppsViewToHost::Notification(McpAppsViewNotification::RequestTeardown),
            )
            .await
            .unwrap();
            host.process_next(&cx).await.unwrap();
            assert!(matches!(
                view.receive_from_host(&cx).await.unwrap(),
                McpAppsHostToView::Request {
                    request: McpAppsHostRequest::ResourceTeardown(_),
                    ..
                }
            ));
        });
    }

    #[test]
    fn planted_teardown_send_failure_restores_the_exact_active_state() {
        block_on(async {
            let cx = Cx::for_testing();
            let mut host = McpAppsHost::new_negotiated(
                FailingTransport,
                configuration(),
                AcceptTeardown(false),
                activation_proof(),
            );
            host.lifecycle = McpAppsViewLifecycle::Active;
            assert!(
                host.begin_teardown(&cx, Some("close".into()))
                    .await
                    .is_err()
            );
            assert_eq!(host.lifecycle(), McpAppsViewLifecycle::Active);
            assert!(host.pending_host_requests.is_empty());
            assert_eq!(host.next_request_id, 1);
        });
    }

    #[test]
    fn one_variable_wrong_apps_protocol_version_is_rejected_before_lifecycle_exposure() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_pair(4);
            let mut host = McpAppsHost::new_negotiated(
                transport,
                configuration(),
                AcceptTeardown(false),
                activation_proof(),
            );
            view.send_to_host(
                &cx,
                McpAppsViewToHost::Request {
                    id: request_id(99),
                    request: McpAppsViewRequest::Initialize(McpAppsInitializeParams {
                        app_info: app(),
                        app_capabilities: McpAppsViewCapabilities::default(),
                        protocol_version: "wrong-version".into(),
                    }),
                },
            )
            .await
            .unwrap();
            assert!(matches!(
                host.process_next(&cx).await,
                Err(McpAppsHostError::UnsupportedAppsProtocolVersion(_))
            ));
            assert_eq!(host.lifecycle(), McpAppsViewLifecycle::New);
            assert!(host.live_view_requests.is_empty());
        });
    }

    struct WirePolicy;

    struct ViewToolPolicy {
        allow: bool,
        approvals: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[allow(clippy::unused_async_trait_impl, reason = "immediate bounded policy decisions implement async embedder hooks")]
    impl McpAppsWireHostPolicy for ViewToolPolicy {
        async fn approve_view_tool_call(
            &mut self,
            _cx: &Cx,
            tool: &McpAppsViewTool,
            params: &fastmcp_protocol::McpAppsToolCallParams,
        ) -> Result<(), McpAppsHostError> {
            assert_eq!(tool.descriptor().name, params.name);
            self.approvals.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.allow { Ok(()) } else { Err(wire_policy_denied()) }
        }

        async fn dispatch_reused_request(
            &mut self,
            _cx: &Cx,
            _cancellation: &McpRequestCancellation,
            _method: McpAppsRoutedMethod,
            _params: Option<Value>,
        ) -> Result<Value, McpAppsHostError> {
            std::future::pending().await
        }
    }

    fn view_tool_descriptor(name: &str) -> Value {
        json!({
            "name": name,
            "inputSchema": {"type": "object", "properties": {"count": {"type": "integer", "minimum": 1}}, "required": ["count"]},
            "outputSchema": {"type": "object", "properties": {"accepted": {"type": "integer", "minimum": 1}}, "required": ["accepted"]},
            "annotations": {"readOnlyHint": true},
            "_meta": {"untrusted": "View hint"}
        })
    }

    fn view_tool_call(count: Value) -> McpAppsHostRequest {
        McpAppsHostRequest::CallTool(serde_json::from_value(json!({
            "name": "view_counter", "arguments": {"count": count}
        })).unwrap())
    }

    async fn tool_wire_host(
        cx: &Cx,
        allow: bool,
    ) -> (McpAppsWireHost<McpAppsInMemoryWireHostTransport, ViewToolPolicy>, McpAppsInMemoryWireViewTransport) {
        let (transport, mut view) = mcp_apps_in_memory_wire_pair(128);
        let mut host = McpAppsWireHost::new_negotiated(
            transport, wire_configuration(),
            ViewToolPolicy { allow, approvals: Arc::new(std::sync::atomic::AtomicUsize::new(0)) },
            activation_proof(),
        );
        view.send_to_host(cx, json!({
            "jsonrpc": "2.0", "id": "initialize", "method": "ui/initialize",
            "params": {"appInfo": {"name": "view", "version": "1"},
                "appCapabilities": {"tools": {"listChanged": true}},
                "protocolVersion": MCP_APPS_HOST_VIEW_PROTOCOL_VERSION}
        }).to_string()).await.unwrap();
        host.process_next(cx).await.unwrap();
        let _ = view.receive_from_host(cx).await.unwrap();
        view.send_to_host(cx, json!({"jsonrpc":"2.0","method":"ui/notifications/initialized"}).to_string()).await.unwrap();
        host.process_next(cx).await.unwrap();
        (host, view)
    }

    async fn tool_wire_reply<P: McpAppsWireHostPolicy>(
        host: &mut McpAppsWireHost<McpAppsInMemoryWireHostTransport, P>,
        view: &mut McpAppsInMemoryWireViewTransport,
        cx: &Cx,
        id: &McpAppsJsonRpcRequestId,
        result: Value,
    ) -> McpAppsHostRequestOutcome {
        view.send_to_host(cx, json!({"jsonrpc":"2.0","id":id,"result":result}).to_string()).await.unwrap();
        host.process_next(cx).await.unwrap();
        host.take_host_response(id).expect("one correlated terminal outcome").outcome
    }

    async fn install_view_tool_catalog<P: McpAppsWireHostPolicy>(
        host: &mut McpAppsWireHost<McpAppsInMemoryWireHostTransport, P>,
        view: &mut McpAppsInMemoryWireViewTransport,
        cx: &Cx,
    ) {
        let id = host.send_host_request(cx, McpAppsHostRequest::ToolsList(fastmcp_protocol::McpAppsListParams::default()), None).await.unwrap();
        let _ = view.receive_from_host(cx).await.unwrap();
        assert!(matches!(tool_wire_reply(host, view, cx, &id, json!({
            "tools": [view_tool_descriptor("view_counter")]
        })).await, McpAppsHostRequestOutcome::ToolsList(_)));
        assert_eq!(host.view_tools().count(), 1);
    }

    #[test]
    fn closed_wire_view_tools_enforce_policy_arguments_and_deliver_correlated_output() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = tool_wire_host(&cx, true).await;
            install_view_tool_catalog(&mut host, &mut view, &cx).await;
            assert!(host.send_host_request(&cx, view_tool_call(json!(0)), None).await.is_err());
            assert_eq!(host.policy.approvals.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert!(host.host_requests.is_empty());
            let id = host.send_host_request(&cx, view_tool_call(json!(3)), None).await.unwrap();
            let sent: Value = serde_json::from_str(&view.receive_from_host(&cx).await.unwrap()).unwrap();
            assert_eq!(sent["id"], serde_json::to_value(&id).unwrap());
            assert_eq!(sent["params"], json!({"name":"view_counter","arguments":{"count":3}}));
            let McpAppsHostRequestOutcome::ToolCall(result) = tool_wire_reply(
                &mut host, &mut view, &cx, &id,
                json!({"content":[{"type":"text","text":"accepted three"}],"structuredContent":{"accepted":3}}),
            ).await else { panic!("validated tool result expected"); };
            assert_eq!(result.structured_content.unwrap()["accepted"], 3);
            assert_eq!(result.is_error, None);
            assert!(host.take_host_response(&id).is_none());
            host.policy.allow = false;
            assert!(host.send_host_request(&cx, view_tool_call(json!(3)), None).await.is_err());
            assert!(host.host_requests.is_empty());
            assert_eq!(host.policy.approvals.load(std::sync::atomic::Ordering::SeqCst), 2);
            assert_eq!(host.view_tools().count(), 1);
        });
    }

    #[test]
    fn closed_wire_view_catalog_rejects_invalid_schemas_without_partial_exposure() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = tool_wire_host(&cx, true).await;
            install_view_tool_catalog(&mut host, &mut view, &cx).await;
            for (path, bad) in [
                ("inputSchema", json!({"type":"object","minimum":"not-a-number"})),
                ("inputSchema", json!({"type":"object","$ref":"#/$defs/missing"})),
                ("outputSchema", json!({"type":"array"})),
                ("execution", json!({"taskSupport":"optional"})),
                ("annotations", json!({"readOnlyHint":null})),
            ] {
                let mut malformed = view_tool_descriptor("new_tool");
                malformed[path] = bad;
                let id = host.send_host_request(&cx, McpAppsHostRequest::ToolsList(fastmcp_protocol::McpAppsListParams::default()), None).await.unwrap();
                let _ = view.receive_from_host(&cx).await.unwrap();
                assert!(matches!(tool_wire_reply(&mut host, &mut view, &cx, &id,
                    json!({"tools":[view_tool_descriptor("valid_first"), malformed]})).await,
                    McpAppsHostRequestOutcome::InvalidResponse));
                assert_eq!(host.view_tools().map(|tool| tool.descriptor().name.as_str()).collect::<Vec<_>>(), ["view_counter"]);
                assert!(host.host_requests.is_empty());
                assert!(host.staged_view_tools.is_none());
            }
        });
    }

    #[test]
    fn closed_wire_view_tool_output_errors_retire_only_the_exact_request() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = tool_wire_host(&cx, true).await;
            install_view_tool_catalog(&mut host, &mut view, &cx).await;
            for invalid in [
                json!({"content":[]}),
                json!({"content":[],"structuredContent":{"accepted":0}}),
                json!({"content":[],"structuredContent":null}),
                json!({"content":[],"structuredContent":{"accepted":1},"isError":null}),
                json!({"content":[],"structuredContent":{"accepted":1},"resultType":"complete"}),
                json!({"content":[],"structuredContent":{"accepted":1},"_meta":{}}),
            ] {
                let a = host.send_host_request(&cx, view_tool_call(json!(1)), None).await.unwrap();
                let b = host.send_host_request(&cx, view_tool_call(json!(2)), None).await.unwrap();
                let _ = view.receive_from_host(&cx).await.unwrap();
                let _ = view.receive_from_host(&cx).await.unwrap();
                assert!(matches!(tool_wire_reply(&mut host, &mut view, &cx, &a, invalid).await, McpAppsHostRequestOutcome::InvalidResponse));
                assert!(host.take_host_response(&b).is_none());
                assert!(matches!(tool_wire_reply(&mut host, &mut view, &cx, &b,
                    json!({"content":[],"isError":true})).await, McpAppsHostRequestOutcome::ToolCall(result) if result.is_error()));
            }
            let id = host.send_host_request(&cx, view_tool_call(json!(1)), None).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            view.send_to_host(&cx, json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"View refusal"}}).to_string()).await.unwrap();
            host.process_next(&cx).await.unwrap();
            assert!(matches!(host.take_host_response(&id).unwrap().outcome, McpAppsHostRequestOutcome::PeerError(error) if error.code == -32601));
            assert!(host.host_requests.is_empty());
        });
    }

    #[test]
    fn closed_wire_view_tools_page_chain_is_atomic_bound_and_expires_as_one_unit() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = tool_wire_host(&cx, true).await;
            install_view_tool_catalog(&mut host, &mut view, &cx).await;
            for expire in [false, true] {
                let first = host.send_host_request(&cx, McpAppsHostRequest::ToolsList(fastmcp_protocol::McpAppsListParams::default()), None).await.unwrap();
                let _ = view.receive_from_host(&cx).await.unwrap();
                assert!(matches!(tool_wire_reply(&mut host, &mut view, &cx, &first,
                    json!({"tools":[view_tool_descriptor("first")],"nextCursor":"page-two"})).await, McpAppsHostRequestOutcome::ToolsList(_)));
                let old = host.view_tools().map(|tool| tool.descriptor().name.clone()).collect::<Vec<_>>();
                assert!(host.send_host_request(&cx, McpAppsHostRequest::ToolsList(fastmcp_protocol::McpAppsListParams { cursor: Some("wrong-page".into()) }), None).await.is_err());
                let second = host.send_host_request(&cx, McpAppsHostRequest::ToolsList(fastmcp_protocol::McpAppsListParams { cursor: Some("page-two".into()) }), None).await.unwrap();
                let _ = view.receive_from_host(&cx).await.unwrap();
                if expire {
                    host.staged_view_tools.as_mut().unwrap().deadline.absolute = Time::ZERO;
                    host.process_next(&cx).await.unwrap();
                    assert!(matches!(host.take_host_response(&second).unwrap().outcome, McpAppsHostRequestOutcome::DeadlineExceeded));
                    assert!(host.staged_view_tools.is_none());
                    view.send_to_host(&cx, json!({"jsonrpc":"2.0","id":second,"result":{"tools":[view_tool_descriptor("suffix_only")]}}).to_string()).await.unwrap();
                    assert!(host.process_next(&cx).await.is_err());
                    assert_eq!(host.view_tools().map(|tool| tool.descriptor().name.clone()).collect::<Vec<_>>(), old);
                } else {
                    assert!(matches!(tool_wire_reply(&mut host, &mut view, &cx, &second,
                        json!({"tools":[view_tool_descriptor("second")]})).await, McpAppsHostRequestOutcome::ToolsList(_)));
                    assert_eq!(host.view_tools().map(|tool| tool.descriptor().name.as_str()).collect::<Vec<_>>(), ["first", "second"]);
                }
            }
        });
    }

    #[test]
    fn closed_wire_view_tools_reject_javascript_value_changes_before_approval() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = tool_wire_host(&cx, true).await;
            install_view_tool_catalog(&mut host, &mut view, &cx).await;
            for source in ["9007199254740993", "9007199254740992", "1.0000000000000001", "1e9999", "-0.0"] {
                let value = serde_json::from_str(source).unwrap();
                assert!(host.send_host_request(&cx, view_tool_call(value), None).await.is_err(), "{source}");
                assert!(host.host_requests.is_empty());
            }
            assert_eq!(host.policy.approvals.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert!(admit_view_numbers(&serde_json::from_str::<Value>("[0.1,1.0,1e0,9007199254740991]").unwrap()).is_ok());
            let id = host.send_host_request(&cx, view_tool_call(json!(9007199254740991u64)), None).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            assert!(matches!(tool_wire_reply(&mut host, &mut view, &cx, &id,
                json!({"content":[],"structuredContent":{"accepted":9007199254740991u64}})).await, McpAppsHostRequestOutcome::ToolCall(_)));
        });
    }

    #[test]
    fn closed_wire_host_results_are_received_while_new_view_work_is_deferred() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = tool_wire_host(&cx, true).await;
            install_view_tool_catalog(&mut host, &mut view, &cx).await;
            let a = host.send_host_request(&cx, view_tool_call(json!(1)), None).await.unwrap();
            let b = host.send_host_request(&cx, view_tool_call(json!(2)), None).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            // This policy deliberately never returns. Admitting it now would
            // prevent either already-issued Host request from receiving results.
            view.send_to_host(&cx, json!({"jsonrpc":"2.0","id":"other-direction","method":"tools/call","params":{"name":"server_tool"}}).to_string()).await.unwrap();
            host.process_next(&cx).await.unwrap();
            assert_eq!(host.deferred_view_frames.len(), 1);
            view.send_to_host(&cx, json!({"jsonrpc":"2.0","id":b,"result":{"content":[],"structuredContent":{"accepted":2}}}).to_string()).await.unwrap();
            let response = host.wait_for_host_response(&cx, &b).await.unwrap();
            assert_eq!(response.request_id, b);
            assert!(matches!(response.outcome, McpAppsHostRequestOutcome::ToolCall(_)));
            assert_eq!(host.deferred_view_frames.len(), 1);
            assert!(matches!(tool_wire_reply(&mut host, &mut view, &cx, &a,
                json!({"content":[],"structuredContent":{"accepted":1}})).await, McpAppsHostRequestOutcome::ToolCall(_)));
            assert_eq!(host.deferred_view_frames.len(), 1);
        });
    }

    #[test]
    fn closed_wire_deferred_view_request_cancellation_prevents_later_dispatch() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = tool_wire_host(&cx, true).await;
            let id = host.send_host_request(&cx, McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()), None).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            let queued = json!({"jsonrpc":"2.0","id":"queued","method":"tools/call","params":{"name":"server_tool"}}).to_string();
            view.send_to_host(&cx, queued.clone()).await.unwrap();
            host.process_next(&cx).await.unwrap();
            view.send_to_host(&cx, queued).await.unwrap();
            assert!(matches!(host.process_next(&cx).await, Err(McpAppsHostError::Bridge(McpAppsBridgeError::DuplicateLiveRequest))));
            assert_eq!(host.deferred_view_frames.len(), 1);
            view.send_to_host(&cx, json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"queued"}}).to_string()).await.unwrap();
            host.process_next(&cx).await.unwrap();
            assert!(host.deferred_view_frames.is_empty());
            assert!(host.deferred_view_requests.is_empty());
            assert!(matches!(tool_wire_reply(&mut host, &mut view, &cx, &id, json!({})).await, McpAppsHostRequestOutcome::Ping));
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
        });
    }

    #[test]
    fn closed_wire_catalog_change_and_explicit_cancel_retire_only_owned_calls() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = tool_wire_host(&cx, true).await;
            install_view_tool_catalog(&mut host, &mut view, &cx).await;
            let a = host.send_host_request(&cx, view_tool_call(json!(1)), None).await.unwrap();
            let b = host.send_host_request(&cx, view_tool_call(json!(2)), None).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            host.send_notification(&cx, McpAppsHostNotification::Cancelled(fastmcp_protocol::McpAppsCancelledNotification {
                request_id: Some(McpAppsBridgeRequestId::new(a.as_number().unwrap()).unwrap()), reason: None,
            })).await.unwrap();
            let cancel: Value = serde_json::from_str(&view.receive_from_host(&cx).await.unwrap()).unwrap();
            assert_eq!(cancel["params"]["requestId"], serde_json::to_value(&a).unwrap());
            assert!(matches!(host.take_host_response(&a).unwrap().outcome, McpAppsHostRequestOutcome::Cancelled));
            assert!(host.take_host_response(&b).is_none());
            view.send_to_host(&cx, json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"}).to_string()).await.unwrap();
            host.process_next(&cx).await.unwrap();
            let cancel: Value = serde_json::from_str(&view.receive_from_host(&cx).await.unwrap()).unwrap();
            assert_eq!(cancel["params"]["requestId"], serde_json::to_value(&b).unwrap());
            assert!(matches!(host.take_host_response(&b).unwrap().outcome, McpAppsHostRequestOutcome::CatalogChanged));
            assert_eq!(host.view_tools().count(), 0);
            assert!(host.send_host_request(&cx, view_tool_call(json!(1)), None).await.is_err());
            install_view_tool_catalog(&mut host, &mut view, &cx).await;
            host.revoke_view_tools(&cx).await.unwrap();
            assert!(host.send_host_request(&cx, McpAppsHostRequest::ToolsList(fastmcp_protocol::McpAppsListParams::default()), None).await.is_err());
            assert_eq!(host.view_tools().count(), 0);
        });
    }

    #[test]
    fn closed_wire_retained_outcomes_and_catalog_bytes_have_finite_budgets() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = tool_wire_host(&cx, true).await;
            let mut completed = Vec::new();
            for _ in 0..MAX_MCP_APPS_BRIDGE_IN_FLIGHT {
                let id = host.send_host_request(&cx, McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()), None).await.unwrap();
                let _ = view.receive_from_host(&cx).await.unwrap();
                view.send_to_host(&cx, json!({"jsonrpc":"2.0","id":id,"result":{}}).to_string()).await.unwrap();
                host.process_next(&cx).await.unwrap();
                completed.push(id);
            }
            assert!(matches!(host.send_host_request(&cx, McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()), None).await,
                Err(McpAppsHostError::Bridge(McpAppsBridgeError::TooManyInFlight))));
            assert!(matches!(host.take_host_response(&completed[0]).unwrap().outcome, McpAppsHostRequestOutcome::Ping));
            let extra = host.send_host_request(&cx, McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()), None).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            assert!(matches!(tool_wire_reply(&mut host, &mut view, &cx, &extra, json!({})).await, McpAppsHostRequestOutcome::Ping));
            for id in &completed { let _ = host.take_host_response(id); }
            install_view_tool_catalog(&mut host, &mut view, &cx).await;
            let mut large_a = view_tool_descriptor("large_a");
            large_a["description"] = json!("d".repeat(64 * 1024));
            large_a["inputSchema"]["x-large"] = json!(["a".repeat(64 * 1024), "b".repeat(64 * 1024)]);
            let mut large_b = large_a.clone();
            large_b["name"] = json!("large_b");
            let id = host.send_host_request(&cx, McpAppsHostRequest::ToolsList(fastmcp_protocol::McpAppsListParams::default()), None).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            assert!(matches!(tool_wire_reply(&mut host, &mut view, &cx, &id,
                json!({"tools":[large_a,large_b]})).await, McpAppsHostRequestOutcome::InvalidResponse));
            assert_eq!(host.view_tools().count(), 1);
            assert!(host.retained_tool_bytes() <= MAX_MCP_APPS_VIEW_TOOL_STATE_BYTES);
        });
    }

    #[test]
    fn closed_wire_host_request_timer_wakes_a_silent_view_on_the_caller_runtime() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (mut host, mut view) = tool_wire_host(&cx, true).await;
            let id = host.send_host_request(&cx, McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()), None).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            host.host_requests.get_mut(&id).unwrap().deadline.idle = cx.now().saturating_add_nanos(5_000_000);
            let response = host.wait_for_host_response(&cx, &id).await.unwrap();
            assert!(matches!(response.outcome, McpAppsHostRequestOutcome::DeadlineExceeded));
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
            let next = host.send_host_request(&cx, McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()), None).await.unwrap();
            assert_ne!(id, next);
            let _ = view.receive_from_host(&cx).await.unwrap();
            assert!(matches!(tool_wire_reply(&mut host, &mut view, &cx, &next, json!({})).await, McpAppsHostRequestOutcome::Ping));
        });
    }

    #[test]
    fn closed_wire_short_wait_deadline_wakes_without_cancelling_the_live_host_request() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (mut host, mut view) = tool_wire_host(&cx, true).await;
            let id = host.send_host_request(&cx, McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()), None).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            let limited = runtime.request_cx_with_budget(asupersync::Budget::new()
                .with_deadline(cx.now().saturating_add_nanos(5_000_000)));
            assert!(host.wait_for_host_response(&limited, &id).await.is_err());
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
            assert!(host.take_host_response(&id).is_none());
            assert!(matches!(tool_wire_reply(&mut host, &mut view, &cx, &id, json!({})).await, McpAppsHostRequestOutcome::Ping));
        });
    }

    #[test]
    fn closed_wire_wait_cancellation_and_progress_preserve_original_request_lifetimes() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = tool_wire_host(&cx, true).await;
            let token = McpAppsJsonRpcRequestId::string("request-progress".into()).unwrap();
            let id = host.send_host_request(&cx, McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()), Some(token.clone())).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            let absolute = host.host_requests[&id].deadline.absolute;
            host.host_requests.get_mut(&id).unwrap().deadline.idle = cx.now().saturating_add_nanos(1_000_000_000);
            view.send_to_host(&cx, json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":token,"progress":1}}).to_string()).await.unwrap();
            host.process_next(&cx).await.unwrap();
            let idle = host.host_requests[&id].deadline.idle;
            for progress in [1, 0] {
                view.send_to_host(&cx, json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":token,"progress":progress}}).to_string()).await.unwrap();
                host.process_next(&cx).await.unwrap();
                assert_eq!(host.host_requests[&id].deadline.idle, idle);
                assert_eq!(host.host_requests[&id].deadline.absolute, absolute);
            }
            let cancelled = Cx::for_testing_with_budget(asupersync::Budget::new().with_deadline(Time::ZERO));
            assert!(host.wait_for_host_response(&cancelled, &id).await.is_err());
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
            assert!(host.take_host_response(&id).is_none());
            assert!(matches!(tool_wire_reply(&mut host, &mut view, &cx, &id, json!({})).await, McpAppsHostRequestOutcome::Ping));
        });
    }

    struct PendingWireSend;

    impl McpAppsWireBridgeTransport for PendingWireSend {
        async fn send_to_view(&mut self, _cx: &Cx, _frame: String) -> Result<(), McpAppsHostError> {
            std::future::pending().await
        }
        async fn receive_from_view(&mut self, _cx: &Cx) -> Result<String, McpAppsHostError> {
            std::future::pending().await
        }
    }

    #[test]
    fn closed_wire_abandoned_send_releases_the_unexposed_id_and_fences_the_view() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let mut host = McpAppsWireHost::new_negotiated(PendingWireSend, wire_configuration(), WirePolicy, activation_proof());
            host.admission = active_wire_admission();
            let mut sending = Box::pin(host.send_host_request(&cx, McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()), None));
            poll_fn(|task| {
                assert!(sending.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
            drop(sending);
            assert!(host.host_requests.is_empty());
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Closed);
            assert!(host.send_notification(&cx, McpAppsHostNotification::ToolsListChanged).await.is_err());
            assert!(host.send_host_request(&cx, McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()), None).await.is_err());
        });
    }

    #[test]
    fn closed_wire_abandoned_teardown_expires_every_live_call_once() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let mut host = McpAppsWireHost::new_negotiated(PendingWireSend, wire_configuration(), WirePolicy, activation_proof());
            host.admission = active_wire_admission();
            let id = McpAppsJsonRpcRequestId::host(200).unwrap();
            host.admission.admit_request(McpAppsBridgeDirection::HostToView, id.clone(), McpAppsRoutedMethod::Ping, None).unwrap();
            host.host_requests.insert(id.clone(), WireHostRequest {
                method: McpAppsRoutedMethod::Ping, state: WireHostRequestState::Ping,
                retained_bytes: 0, deadline: WireHostDeadline::new(&cx), last_progress: None,
            });
            let queued = McpAppsJsonRpcRequestId::string("queued-before-close".into()).unwrap();
            host.admission.admit_request(McpAppsBridgeDirection::ViewToHost, queued.clone(), McpAppsRoutedMethod::ToolsCall, None).unwrap();
            host.deferred_view_requests.insert(queued.clone());
            host.deferred_view_frames.push_back(json!({"jsonrpc":"2.0","id":queued,"method":"tools/call","params":{"name":"never-dispatch"}}).to_string());
            let mut closing = Box::pin(host.begin_teardown(&cx));
            poll_fn(|task| { assert!(closing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            drop(closing);
            host.teardown_request.as_mut().unwrap().1.absolute = Time::ZERO;
            host.process_next(&cx).await.unwrap();
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Closed);
            assert!(host.deferred_view_frames.is_empty());
            assert!(host.deferred_view_requests.is_empty());
            assert!(matches!(host.take_host_response(&id).unwrap().outcome, McpAppsHostRequestOutcome::ViewClosed));
            assert!(host.take_host_response(&id).is_none());
        });
    }

    #[test]
    fn closed_wire_teardown_discards_queued_work_and_requires_its_exact_response() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut host, mut view) = tool_wire_host(&cx, true).await;
            let pending = host.send_host_request(&cx, McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()), None).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            view.send_to_host(&cx, json!({"jsonrpc":"2.0","id":"queued","method":"tools/call","params":{"name":"never-dispatch"}}).to_string()).await.unwrap();
            host.process_next(&cx).await.unwrap();
            assert_eq!(host.deferred_view_frames.len(), 1);
            host.begin_teardown(&cx).await.unwrap();
            let closing: Value = serde_json::from_str(&view.receive_from_host(&cx).await.unwrap()).unwrap();
            assert!(host.deferred_view_frames.is_empty());
            assert!(host.deferred_view_requests.is_empty());
            view.send_to_host(&cx, json!({"jsonrpc":"2.0","id":pending,"result":{}}).to_string()).await.unwrap();
            assert!(host.process_next(&cx).await.is_err());
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Closing);
            view.send_to_host(&cx, json!({"jsonrpc":"2.0","id":closing["id"],"result":{}}).to_string()).await.unwrap();
            host.process_next(&cx).await.unwrap();
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Closed);
            assert!(matches!(host.take_host_response(&pending).unwrap().outcome, McpAppsHostRequestOutcome::ViewClosed));
        });
    }

    impl McpAppsWireHostPolicy for WirePolicy {
        #[allow(
            clippy::unused_async_trait_impl,
            reason = "the public wire-host policy trait requires an async override"
        )]
        async fn dispatch_reused_request(
            &mut self,
            _cx: &Cx,
            _cancellation: &McpRequestCancellation,
            method: McpAppsRoutedMethod,
            _params: Option<Value>,
        ) -> Result<Value, McpAppsHostError> {
            Ok(if is_server_catalog(method) { catalog_page(method, None) } else { json!({"forwarded": true}) })
        }
    }

    struct ControlRecordingWirePolicy {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl McpAppsWireHostPolicy for ControlRecordingWirePolicy {
        #[allow(
            clippy::unused_async_trait_impl,
            reason = "the public wire-host policy trait requires an async override"
        )]
        async fn dispatch_reused_request(
            &mut self,
            _cx: &Cx,
            _cancellation: &McpRequestCancellation,
            _method: McpAppsRoutedMethod,
            _params: Option<Value>,
        ) -> Result<Value, McpAppsHostError> {
            Ok(json!({"forwarded": true}))
        }

        #[allow(
            clippy::unused_async_trait_impl,
            reason = "the public wire-host policy trait requires an async override"
        )]
        async fn progress(
            &mut self,
            request_id: &McpAppsJsonRpcRequestId,
            _params: &McpAppsProgressControlParams,
        ) -> Result<(), McpAppsHostError> {
            self.events
                .lock()
                .expect("test policy events lock")
                .push(format!("progress:{request_id:?}"));
            Ok(())
        }

        fn cancelled(
            &mut self,
            _cx: &Cx,
            request_id: &McpAppsJsonRpcRequestId,
            _params: &McpAppsCancelledControlParams,
        ) -> Result<(), McpAppsHostError> {
            self.events
                .lock()
                .expect("test policy events lock")
                .push(format!("cancelled:{request_id:?}"));
            Ok(())
        }
    }

    struct YieldOnceCancellationWirePolicy {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl McpAppsWireHostPolicy for YieldOnceCancellationWirePolicy {
        async fn dispatch_reused_request(
            &mut self,
            _cx: &Cx,
            cancellation: &McpRequestCancellation,
            _method: McpAppsRoutedMethod,
            _params: Option<Value>,
        ) -> Result<Value, McpAppsHostError> {
            let mut yielded = false;
            std::future::poll_fn(move |task| {
                if yielded {
                    std::task::Poll::Ready(())
                } else {
                    yielded = true;
                    task.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            })
            .await;
            if cancellation.is_cancel_requested() {
                self.events
                    .lock()
                    .expect("test policy events lock")
                    .push("forward-cancelled".to_owned());
                return Err(McpAppsHostError::Core(McpError::request_cancelled()));
            }
            Ok(json!({"forwarded": true}))
        }

        fn cancelled(
            &mut self,
            _cx: &Cx,
            request_id: &McpAppsJsonRpcRequestId,
            _params: &McpAppsCancelledControlParams,
        ) -> Result<(), McpAppsHostError> {
            self.events
                .lock()
                .expect("test policy events lock")
                .push(format!("cancelled:{request_id:?}"));
            Ok(())
        }
    }

    /// Compile- and runtime-coverage policy: its request future never
    /// completes, while cancellation observation remains an immediate hook.
    struct NeverReturnsCancellationWirePolicy {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl McpAppsWireHostPolicy for NeverReturnsCancellationWirePolicy {
        #[allow(
            clippy::unused_async_trait_impl,
            reason = "the public wire-host policy trait requires an async override"
        )]
        async fn dispatch_reused_request(
            &mut self,
            _cx: &Cx,
            _cancellation: &McpRequestCancellation,
            _method: McpAppsRoutedMethod,
            _params: Option<Value>,
        ) -> Result<Value, McpAppsHostError> {
            std::future::pending::<Result<Value, McpAppsHostError>>().await
        }

        fn cancelled(
            &mut self,
            _cx: &Cx,
            request_id: &McpAppsJsonRpcRequestId,
            _params: &McpAppsCancelledControlParams,
        ) -> Result<(), McpAppsHostError> {
            self.events
                .lock()
                .expect("test policy events lock")
                .push(format!("cancelled:{request_id:?}"));
            Ok(())
        }
    }

    fn wire_configuration() -> McpAppsWireHostConfiguration {
        McpAppsWireHostConfiguration {
            host_info: app(),
            host_capabilities: McpAppsPinnedHostCapabilities {
                server_tools: Some(fastmcp_protocol::McpAppsServerToolsCapability::default()),
                server_resources: Some(fastmcp_protocol::McpAppsServerResourcesCapability::default()),
                ..McpAppsPinnedHostCapabilities::default()
            },
            host_context: McpAppsPinnedHostContext::default(),
        }
    }

    #[derive(Clone, Copy)]
    enum ContextDecision { Accept, Refuse, YieldOnce }

    struct StateRecordingWirePolicy {
        changes: Arc<Mutex<Vec<Value>>>,
        entries: Arc<std::sync::atomic::AtomicUsize>,
        context: ContextDecision,
        display_result: Option<McpAppsDisplayMode>,
        advertised: Option<McpAppsPinnedHostCapabilities>,
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the public policy callbacks are async even for immediate test decisions"
    )]
    impl McpAppsWireHostPolicy for StateRecordingWirePolicy {
        async fn initialize(
            &mut self,
            _params: &McpAppsPinnedInitializeParams,
            configuration: &McpAppsWireHostConfiguration,
        ) -> McpAppsPinnedInitializeResult {
            let mut response = configuration.initialize_result();
            if let Some(capabilities) = &self.advertised {
                response.host_capabilities = capabilities.clone();
            }
            response
        }

        async fn update_model_context(
            &mut self,
            _cx: &Cx,
            cancellation: &McpRequestCancellation,
            params: &McpAppsUpdateModelContextParams,
        ) -> Result<(), McpAppsHostError> {
            self.entries.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match self.context {
                ContextDecision::Refuse => return Err(wire_policy_denied()),
                ContextDecision::YieldOnce => {
                    let mut yielded = false;
                    std::future::poll_fn(|task| {
                        if yielded {
                            std::task::Poll::Ready(())
                        } else {
                            yielded = true;
                            task.waker().wake_by_ref();
                            std::task::Poll::Pending
                        }
                    }).await;
                }
                ContextDecision::Accept => {}
            }
            if cancellation.is_cancel_requested() {
                return Err(McpAppsHostError::Core(McpError::request_cancelled()));
            }
            self.changes.lock().unwrap().push(json!({"context": params}));
            Ok(())
        }

        async fn request_display_mode(
            &mut self,
            _cx: &Cx,
            _cancellation: &McpRequestCancellation,
            params: McpAppsDisplayModeParams,
            current: Option<McpAppsDisplayMode>,
        ) -> Result<McpAppsDisplayModeParams, McpAppsHostError> {
            self.entries.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.changes.lock().unwrap().push(json!({"requested": params.mode, "current": current}));
            Ok(McpAppsDisplayModeParams { mode: self.display_result.unwrap_or(params.mode) })
        }

        async fn operation(
            &mut self,
            _method: McpAppsRoutedMethod,
            params: Option<&Value>,
        ) -> Result<Value, McpAppsHostError> {
            self.entries.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.changes.lock().unwrap().push(json!({"operation": params}));
            Ok(json!({}))
        }

        async fn dispatch_reused_request(
            &mut self,
            _cx: &Cx,
            _cancellation: &McpRequestCancellation,
            method: McpAppsRoutedMethod,
            params: Option<Value>,
        ) -> Result<Value, McpAppsHostError> {
            self.entries.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.changes.lock().unwrap().push(json!({"forwarded": params}));
            Ok(if is_server_catalog(method) { catalog_page(method, None) } else { json!({"forwarded": true}) })
        }
    }

    fn state_recording_policy() -> StateRecordingWirePolicy {
        StateRecordingWirePolicy {
            changes: Arc::new(Mutex::new(Vec::new())),
            entries: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            context: ContextDecision::Accept,
            display_result: None,
            advertised: None,
        }
    }

    fn stateful_wire_configuration() -> McpAppsWireHostConfiguration {
        McpAppsWireHostConfiguration {
            host_info: app(),
            host_capabilities: serde_json::from_value(json!({
                "updateModelContext": {"text": {}, "image": {}, "structuredContent": {}},
                "message": {"text": {}},
                "openLinks": {}, "downloadFile": {},
                "serverTools": {}, "serverResources": {}
            })).unwrap(),
            host_context: serde_json::from_value(json!({
                "displayMode": "inline", "availableDisplayModes": ["inline", "fullscreen", "pip"],
                "locale": "en-US"
            })).unwrap(),
        }
    }

    async fn activate_stateful_wire_host<T, P>(
        host: &mut McpAppsWireHost<T, P>,
        view: &mut McpAppsInMemoryWireViewTransport,
        cx: &Cx,
        view_modes: Option<Value>,
    ) where T: McpAppsWireBridgeTransport, P: McpAppsWireHostPolicy {
        let mut capabilities = json!({});
        if let Some(modes) = view_modes { capabilities["availableDisplayModes"] = modes; }
        view.send_to_host(cx, json!({
            "jsonrpc": "2.0", "id": "initialize", "method": "ui/initialize",
            "params": {"appInfo": {"name": "view", "version": "1"},
                "appCapabilities": capabilities,
                "protocolVersion": MCP_APPS_HOST_VIEW_PROTOCOL_VERSION}
        }).to_string()).await.unwrap();
        host.process_next(cx).await.unwrap();
        let response: Value = serde_json::from_str(&view.receive_from_host(cx).await.unwrap()).unwrap();
        assert!(response.get("result").is_some(), "{response}");
        view.send_to_host(cx, json!({
            "jsonrpc": "2.0", "method": "ui/notifications/initialized"
        }).to_string()).await.unwrap();
        host.process_next(cx).await.unwrap();
        assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
    }

    async fn stateful_wire_request<T, P>(
        host: &mut McpAppsWireHost<T, P>,
        view: &mut McpAppsInMemoryWireViewTransport,
        cx: &Cx,
        id: &str,
        method: &str,
        params: Value,
    ) -> Value where T: McpAppsWireBridgeTransport, P: McpAppsWireHostPolicy {
        view.send_to_host(cx, json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params
        }).to_string()).await.unwrap();
        host.process_next(cx).await.unwrap();
        let response: Value = serde_json::from_str(&view.receive_from_host(cx).await.unwrap()).unwrap();
        assert_eq!(response["id"], id);
        response
    }

    #[test]
    fn closed_wire_context_policy_commits_replacements_clearing_and_denial() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(4);
            let mut host = McpAppsWireHost::new_negotiated(
                transport, stateful_wire_configuration(), state_recording_policy(), activation_proof(),
            );
            activate_stateful_wire_host(&mut host, &mut view, &cx, None).await;
            let replacement = json!({"content": [
                {"type": "text", "text": "a selected region"},
                {"type": "image", "data": "YQ==", "mimeType": "image/png"}
            ], "structuredContent": {"selected": [1, 2]}});
            for (index, value) in [replacement.clone(), json!({"content": []}), json!({})].into_iter().enumerate() {
                let response = stateful_wire_request(
                    &mut host, &mut view, &cx, &format!("context-{index}"),
                    "ui/update-model-context", value.clone(),
                ).await;
                assert_eq!(response["result"], json!({}));
                assert_eq!(serde_json::to_value(host.model_context().unwrap()).unwrap(), value);
                assert_eq!(host.policy.changes.lock().unwrap().last(), Some(&json!({"context": value})));
            }
            assert_eq!(host.policy.changes.lock().unwrap().len(), 3);
            for invalid in [json!({"content": null}), json!({"structuredContent": null})] {
                let response = stateful_wire_request(
                    &mut host, &mut view, &cx, "invalid-null", "ui/update-model-context", invalid,
                ).await;
                assert!(response.get("error").is_some());
                assert_eq!(serde_json::to_value(host.model_context().unwrap()).unwrap(), json!({}));
                assert_eq!(host.policy.entries.load(std::sync::atomic::Ordering::SeqCst), 3);
                assert_eq!(host.policy.changes.lock().unwrap().len(), 3);
            }
            host.policy.context = ContextDecision::Refuse;
            let response = stateful_wire_request(
                &mut host, &mut view, &cx, "refused", "ui/update-model-context", replacement,
            ).await;
            assert!(response.get("error").is_some());
            assert_eq!(serde_json::to_value(host.model_context().unwrap()).unwrap(), json!({}));
            assert_eq!(host.policy.changes.lock().unwrap().len(), 3);
            assert_eq!(host.policy.entries.load(std::sync::atomic::Ordering::SeqCst), 4);
            host.begin_teardown(&cx).await.unwrap();
            assert!(host.model_context().is_none());
        });
    }

    #[test]
    fn closed_wire_context_admission_uses_committed_capabilities_before_any_host_effect() {
        block_on(async {
            for missing in [None, Some("method"), Some("text"), Some("image"), Some("structuredContent")] {
                let cx = Cx::for_testing();
                let (transport, mut view) = mcp_apps_in_memory_wire_pair(4);
                let configuration = stateful_wire_configuration();
                let mut advertised = serde_json::to_value(&configuration.host_capabilities).unwrap();
                if let Some(missing) = missing {
                    if missing == "method" {
                        advertised.as_object_mut().unwrap().remove("updateModelContext");
                    } else {
                        advertised["updateModelContext"].as_object_mut().unwrap().remove(missing);
                    }
                }
                let mut policy = state_recording_policy();
                policy.advertised = Some(serde_json::from_value(advertised).unwrap());
                let mut host = McpAppsWireHost::new_negotiated(transport, configuration, policy, activation_proof());
                activate_stateful_wire_host(&mut host, &mut view, &cx, None).await;
                let response = stateful_wire_request(&mut host, &mut view, &cx, "mixed",
                    "ui/update-model-context", json!({"content": [
                        {"type": "text", "text": "first allowed block"},
                        {"type": "image", "data": "YQ==", "mimeType": "image/png"}
                    ], "structuredContent": {}}),
                ).await;
                let admitted = missing.is_none();
                assert_eq!(response.get("result").is_some(), admitted, "{missing:?}: {response}");
                assert_eq!(host.model_context().is_some(), admitted);
                assert_eq!(host.policy.entries.load(std::sync::atomic::Ordering::SeqCst), usize::from(admitted));
                assert_eq!(host.policy.changes.lock().unwrap().len(), usize::from(admitted));
            }
        });
    }

    #[test]
    fn closed_wire_default_policy_refuses_context_and_returns_unchanged_display_mode() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(4);
            let mut host = McpAppsWireHost::new_negotiated(
                transport, stateful_wire_configuration(), WirePolicy, activation_proof(),
            );
            activate_stateful_wire_host(&mut host, &mut view, &cx, None).await;
            let response = stateful_wire_request(&mut host, &mut view, &cx, "context",
                "ui/update-model-context", json!({"content": [{"type": "text", "text": "unapproved"}]}),
            ).await;
            assert!(response.get("error").is_some());
            assert!(host.model_context().is_none());
            let response = stateful_wire_request(&mut host, &mut view, &cx, "display",
                "ui/request-display-mode", json!({"mode": "fullscreen"}),
            ).await;
            assert_eq!(response["result"], json!({"mode": "inline"}));
            assert_eq!(host.display_mode(), Some(McpAppsDisplayMode::Inline));
        });
    }

    #[test]
    fn closed_wire_display_policy_returns_actual_mode_and_enforces_both_negotiated_sets() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(4);
            let mut host = McpAppsWireHost::new_negotiated(
                transport, stateful_wire_configuration(), state_recording_policy(), activation_proof(),
            );
            activate_stateful_wire_host(&mut host, &mut view, &cx, Some(json!(["inline", "fullscreen"]))).await;
            let response = stateful_wire_request(&mut host, &mut view, &cx, "display",
                "ui/request-display-mode", json!({"mode": "fullscreen"}),
            ).await;
            assert_eq!(response["result"], json!({"mode": "fullscreen"}));
            assert_eq!(host.display_mode(), Some(McpAppsDisplayMode::Fullscreen));
            assert_eq!(host.policy.changes.lock().unwrap().as_slice(), &[json!({"requested": "fullscreen", "current": "inline"})]);

            let response = stateful_wire_request(&mut host, &mut view, &cx, "view-excluded",
                "ui/request-display-mode", json!({"mode": "pip"}),
            ).await;
            assert!(response.get("error").is_some());
            assert_eq!(host.policy.entries.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(host.display_mode(), Some(McpAppsDisplayMode::Fullscreen));

            host.policy.display_result = Some(McpAppsDisplayMode::Pip);
            let response = stateful_wire_request(&mut host, &mut view, &cx, "bad-host-result",
                "ui/request-display-mode", json!({"mode": "inline"}),
            ).await;
            assert!(response.get("error").is_some());
            assert_eq!(host.display_mode(), Some(McpAppsDisplayMode::Fullscreen));
            // The rejected result retires its correlation instead of stranding
            // the request ID and poisoning later permitted requests.
            host.policy.display_result = None;
            let response = stateful_wire_request(&mut host, &mut view, &cx, "bad-host-result",
                "ui/request-display-mode", json!({"mode": "inline"}),
            ).await;
            assert_eq!(response["result"], json!({"mode": "inline"}));
        });
    }

    #[test]
    fn closed_wire_context_request_cancellation_suppresses_only_its_owned_effect() {
        block_on(async {
            for matching in [true, false] {
                let cx = Cx::for_testing();
                let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
                let mut policy = state_recording_policy();
                policy.context = ContextDecision::YieldOnce;
                let mut host = McpAppsWireHost::new_negotiated(
                    transport, stateful_wire_configuration(), policy, activation_proof(),
                );
                activate_stateful_wire_host(&mut host, &mut view, &cx, None).await;
                view.send_to_host(&cx, json!({"jsonrpc": "2.0", "id": "context", "method": "ui/update-model-context",
                    "params": {"content": [{"type": "text", "text": "pending"}]}}).to_string()).await.unwrap();
                view.send_to_host(&cx, json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
                    "params": {"requestId": if matching { "context" } else { "other" }}}).to_string()).await.unwrap();
                let outcome = host.process_next(&cx).await;
                if matching {
                    outcome.unwrap();
                    assert!(host.model_context().is_none());
                    assert!(host.policy.changes.lock().unwrap().is_empty());
                } else {
                    assert!(matches!(outcome, Err(McpAppsHostError::Bridge(McpAppsBridgeError::UnknownCorrelation))));
                    assert!(host.model_context().is_some());
                    assert_eq!(host.policy.changes.lock().unwrap().len(), 1);
                    let response: Value = serde_json::from_str(&view.receive_from_host(&cx).await.unwrap()).unwrap();
                    assert_eq!(response["id"], "context");
                    assert_eq!(response["result"], json!({}));
                }
                let response = stateful_wire_request(&mut host, &mut view, &cx, "later", "ping", json!({})).await;
                assert_eq!(response["result"], json!({}));
            }
        });
    }

    struct FailableWireTransport {
        inner: McpAppsInMemoryWireHostTransport,
        fail: bool,
    }

    impl McpAppsWireBridgeTransport for FailableWireTransport {
        async fn send_to_view(&mut self, cx: &Cx, frame: String) -> Result<(), McpAppsHostError> {
            if self.fail { return Err(McpAppsHostError::Transport("test send failed".into())); }
            self.inner.send_to_view(cx, frame).await
        }

        async fn receive_from_view(&mut self, cx: &Cx) -> Result<String, McpAppsHostError> {
            self.inner.receive_from_view(cx).await
        }
    }

    #[test]
    fn closed_wire_host_context_notification_commits_partial_state_only_after_send() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(4);
            let mut host = McpAppsWireHost::new_negotiated(
                FailableWireTransport { inner: transport, fail: false },
                stateful_wire_configuration(), WirePolicy, activation_proof(),
            );
            activate_stateful_wire_host(&mut host, &mut view, &cx, None).await;
            let notification = McpAppsHostNotification::HostContextChanged(McpAppsHostContext {
                display_mode: Some(McpAppsDisplayMode::Fullscreen),
                available_display_modes: vec![McpAppsDisplayMode::Fullscreen, McpAppsDisplayMode::Pip],
                locale: None,
            });
            host.transport.fail = true;
            assert!(host.send_notification(&cx, notification.clone()).await.is_err());
            assert_eq!(host.display_mode(), Some(McpAppsDisplayMode::Inline));
            assert!(host.state.permits_mode(McpAppsDisplayMode::Inline));
            host.transport.fail = false;
            host.send_notification(&cx, notification).await.unwrap();
            let _ = view.receive_from_host(&cx).await.unwrap();
            assert_eq!(host.display_mode(), Some(McpAppsDisplayMode::Fullscreen));
            assert_eq!(host.state.host_context.locale.as_deref(), Some("en-US"));
            let response = stateful_wire_request(&mut host, &mut view, &cx, "declined",
                "ui/request-display-mode", json!({"mode": "pip"}),
            ).await;
            assert_eq!(response["result"], json!({"mode": "fullscreen"}));
            let response = stateful_wire_request(&mut host, &mut view, &cx, "withdrawn",
                "ui/request-display-mode", json!({"mode": "inline"}),
            ).await;
            assert!(response.get("error").is_some());
            assert_eq!(host.display_mode(), Some(McpAppsDisplayMode::Fullscreen));
        });
    }

    #[test]
    fn closed_wire_effect_and_forwarding_capabilities_refuse_before_callback() {
        block_on(async {
            for (capability, method, params) in [
                ("openLinks", "ui/open-link", json!({"url": "https://example.com/"})),
                ("message", "ui/message", json!({"role": "user", "content": [{"type": "text", "text": "hello"}]})),
                ("serverTools", "tools/call", json!({"name": "weather", "arguments": {}})),
                ("serverResources", "resources/list", json!({})),
            ] {
                for permitted in [true, false] {
                    let cx = Cx::for_testing();
                    let (transport, mut view) = mcp_apps_in_memory_wire_pair(4);
                    let configuration = stateful_wire_configuration();
                    let mut advertised = serde_json::to_value(&configuration.host_capabilities).unwrap();
                    if !permitted { advertised.as_object_mut().unwrap().remove(capability); }
                    let mut policy = state_recording_policy();
                    policy.advertised = Some(serde_json::from_value(advertised).unwrap());
                    let mut host = McpAppsWireHost::new_negotiated(transport, configuration, policy, activation_proof());
                    host.bind_server_catalogs(catalog_binding(), true).unwrap();
                    activate_stateful_wire_host(&mut host, &mut view, &cx, None).await;
                    let response = stateful_wire_request(&mut host, &mut view, &cx, "operation", method, params.clone()).await;
                    assert_eq!(response.get("result").is_some(), permitted, "{method}: {response}");
                    assert_eq!(host.policy.entries.load(std::sync::atomic::Ordering::SeqCst), usize::from(permitted));
                    assert_eq!(host.policy.changes.lock().unwrap().len(), usize::from(permitted));
                }
            }
        });
    }

    #[test]
    fn closed_wire_admission_commits_initialize_and_forwards_a_reused_method() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let mut host = McpAppsWireHost::new_negotiated(
                transport,
                wire_configuration(),
                WirePolicy,
                activation_proof(),
            );
            host.bind_server_catalogs(catalog_binding(), true).unwrap();
            view.send_to_host(
                &cx,
                json!({
                    "jsonrpc": "2.0",
                    "id": "initialize",
                    "method": "ui/initialize",
                    "params": {
                        "appInfo": {"name": "view", "version": "1"},
                        "appCapabilities": {},
                        "protocolVersion": MCP_APPS_HOST_VIEW_PROTOCOL_VERSION
                    }
                })
                .to_string(),
            )
            .await
            .unwrap();
            host.process_next(&cx).await.unwrap();
            let initialize = view.receive_from_host(&cx).await.unwrap();
            assert!(matches!(
                McpAppsJsonRpcEnvelope::decode(McpAppsBridgeDirection::HostToView, &initialize),
                Ok(McpAppsJsonRpcEnvelope::Response { id: McpAppsJsonRpcRequestId::String(id), .. }) if id == "initialize"
            ));
            assert_eq!(
                host.lifecycle(),
                McpAppsBridgeLifecycle::AwaitingInitialized
            );

            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","method":"ui/notifications/initialized"}"#.into(),
            )
            .await
            .unwrap();
            host.process_next(&cx).await.unwrap();
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);

            for id in [0_u64, 0_u64] {
                view.send_to_host(
                    &cx,
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "resources/list",
                        "params": {}
                    })
                    .to_string(),
                )
                .await
                .unwrap();
                host.process_next(&cx).await.unwrap();
                let response = view.receive_from_host(&cx).await.unwrap();
                let response: Value = serde_json::from_str(&response).unwrap();
                assert_eq!(response["result"], catalog_page(McpAppsRoutedMethod::ResourcesList, None));
            }

            host.begin_teardown(&cx).await.unwrap();
            let teardown = view.receive_from_host(&cx).await.unwrap();
            let McpAppsJsonRpcEnvelope::Request { id, .. } =
                McpAppsJsonRpcEnvelope::decode(McpAppsBridgeDirection::HostToView, &teardown)
                    .unwrap()
            else {
                panic!("Host teardown must be a closed request envelope");
            };
            view.send_to_host(
                &cx,
                serde_json::to_string(&json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {}
                }))
                .unwrap(),
            )
            .await
            .unwrap();
            host.process_next(&cx).await.unwrap();
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Closed);
        });
    }

    #[test]
    fn closed_wire_one_variable_invalid_list_cursor_is_rejected_before_forwarding() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(4);
            let mut host = McpAppsWireHost::new_negotiated(
                transport,
                wire_configuration(),
                WirePolicy,
                activation_proof(),
            );
            host.admission = active_wire_admission();
            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","id":"bad","method":"resources/list","params":{"cursor":1}}"#
                    .into(),
            )
            .await
            .unwrap();
            assert!(matches!(
                host.process_next(&cx).await,
                Err(McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams))
            ));
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
        });
    }

    #[test]
    fn closed_wire_host_request_initiation_binds_matching_progress_before_completion() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut host = McpAppsWireHost::new_negotiated(
                transport,
                wire_configuration(),
                ControlRecordingWirePolicy {
                    events: Arc::clone(&events),
                },
                activation_proof(),
            );
            host.admission = active_wire_admission();
            let token = McpAppsJsonRpcRequestId::string("host-progress".to_owned())
                .expect("bounded progress token");
            let request_id = host
                .send_host_request(
                    &cx,
                    McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()),
                    Some(token.clone()),
                )
                .await
                .expect("active Host may initiate a View ping");
            let request = view
                .receive_from_host(&cx)
                .await
                .expect("View receives the Host request");
            assert!(matches!(
                McpAppsJsonRpcEnvelope::decode(McpAppsBridgeDirection::HostToView, &request),
                Ok(McpAppsJsonRpcEnvelope::Request {
                    id,
                    method: McpAppsRoutedMethod::Ping,
                    progress_token: Some(progress_token),
                    ..
                }) if id == request_id && progress_token == token
            ));

            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"host-progress","progress":1.0}}"#
                    .to_owned(),
            )
            .await
            .expect("View progress reaches Host");
            host.process_next(&cx)
                .await
                .expect("bound View progress is delivered to the policy");
            assert_eq!(
                events.lock().expect("test policy events lock").as_slice(),
                ["progress:Number(1)"],
                "the progress disposition must select the Host-owned request ID"
            );

            view.send_to_host(
                &cx,
                serde_json::json!({"jsonrpc": "2.0", "id": request_id, "result": {}}).to_string(),
            )
            .await
            .expect("View response reaches Host");
            host.process_next(&cx)
                .await
                .expect("matching View response completes the Host request");
        });
    }

    #[test]
    fn closed_wire_public_host_notifications_emit_and_release_only_their_bound_request() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(16);
            let mut host = McpAppsWireHost::new_negotiated(
                transport,
                wire_configuration(),
                WirePolicy,
                activation_proof(),
            );
            host.admission = active_wire_admission();

            let view_request_id = McpAppsJsonRpcRequestId::string("view-request".to_owned())
                .expect("bounded View request ID");
            let progress_token = McpAppsJsonRpcRequestId::string("view-progress".to_owned())
                .expect("bounded View progress token");
            host.admission
                .admit_request(
                    McpAppsBridgeDirection::ViewToHost,
                    view_request_id,
                    McpAppsRoutedMethod::ToolsCall,
                    Some(progress_token),
                )
                .expect("test View request is live before Host progress");
            let host_request_id = McpAppsJsonRpcRequestId::new(1).expect("safe Host request ID");
            host.admission
                .admit_request(
                    McpAppsBridgeDirection::HostToView,
                    host_request_id.clone(),
                    McpAppsRoutedMethod::ToolsCall,
                    None,
                )
                .expect("test Host request is live before Host cancellation");

            let result = McpAppsToolResult::try_new(Vec::new(), false, None)
                .expect("empty tool result remains a valid Apps notification");
            let notifications = [
                McpAppsHostNotification::ToolInputPartial { arguments: None },
                McpAppsHostNotification::ToolInput { arguments: None },
                McpAppsHostNotification::ToolResult(result),
                McpAppsHostNotification::ToolCancelled { reason: None },
                McpAppsHostNotification::HostContextChanged(McpAppsHostContext::default()),
                McpAppsHostNotification::ToolsListChanged,
                McpAppsHostNotification::ResourcesListChanged,
                McpAppsHostNotification::PromptsListChanged,
                McpAppsHostNotification::Progress(McpAppsProgressNotification {
                    progress_token: json!("view-progress"),
                    progress: 1.0,
                    total: None,
                }),
                McpAppsHostNotification::Cancelled(
                    fastmcp_protocol::McpAppsCancelledNotification {
                        request_id: Some(request_id(1)),
                        reason: None,
                    },
                ),
            ];
            let expected_methods = [
                McpAppsRoutedMethod::ToolInputPartial,
                McpAppsRoutedMethod::ToolInput,
                McpAppsRoutedMethod::ToolResult,
                McpAppsRoutedMethod::ToolCancelled,
                McpAppsRoutedMethod::HostContextChanged,
                McpAppsRoutedMethod::ToolsListChanged,
                McpAppsRoutedMethod::ResourcesListChanged,
                McpAppsRoutedMethod::PromptsListChanged,
                McpAppsRoutedMethod::Progress,
                McpAppsRoutedMethod::Cancelled,
            ];
            for (notification, expected_method) in notifications.into_iter().zip(expected_methods) {
                host.send_notification(&cx, notification)
                    .await
                    .expect("the active public Host emits every supported notification");
                let frame = view
                    .receive_from_host(&cx)
                    .await
                    .expect("View receives the emitted notification");
                assert!(matches!(
                    McpAppsJsonRpcEnvelope::decode(McpAppsBridgeDirection::HostToView, &frame),
                    Ok(McpAppsJsonRpcEnvelope::Notification { method, .. }) if method == expected_method
                ));
            }
            assert_eq!(
                host.admission
                    .complete_error(McpAppsBridgeDirection::HostToView, &host_request_id),
                Err(McpAppsBridgeError::UnknownCorrelation),
                "only the bound Host request is released after its cancellation frame commits"
            );

            let (transport, _view) = mcp_apps_in_memory_wire_pair(1);
            let mut inactive_host = McpAppsWireHost::new_negotiated(
                transport,
                wire_configuration(),
                WirePolicy,
                activation_proof(),
            );
            assert!(matches!(
                inactive_host
                    .send_notification(&cx, McpAppsHostNotification::ToolsListChanged)
                    .await,
                Err(McpAppsHostError::Bridge(
                    McpAppsBridgeError::InvalidLifecycle
                ))
            ));
        });
    }

    #[test]
    fn closed_wire_process_next_cancels_a_yielding_view_request_without_a_response() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut host = McpAppsWireHost::new_negotiated(
                transport,
                wire_configuration(),
                YieldOnceCancellationWirePolicy {
                    events: Arc::clone(&events),
                },
                activation_proof(),
            );

            view.send_to_host(
                &cx,
                json!({
                    "jsonrpc": "2.0",
                    "id": "initialize",
                    "method": "ui/initialize",
                    "params": {
                        "appInfo": {"name": "view", "version": "1"},
                        "appCapabilities": {},
                        "protocolVersion": MCP_APPS_HOST_VIEW_PROTOCOL_VERSION,
                    },
                })
                .to_string(),
            )
            .await
            .expect("View initialize reaches the public Host runtime");
            host.process_next(&cx)
                .await
                .expect("Host commits initialize response");
            let _ = view
                .receive_from_host(&cx)
                .await
                .expect("View receives initialize response");
            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","method":"ui/notifications/initialized"}"#.to_owned(),
            )
            .await
            .expect("View initialized notification reaches Host");
            host.process_next(&cx)
                .await
                .expect("Host becomes active through the public lifecycle");
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);

            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","id":"view-call","method":"tools/call","params":{"name":"weather","arguments":{}}}"#
                    .to_owned(),
            )
            .await
            .expect("View request reaches Host");
            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"view-call"}}"#
                    .to_owned(),
            )
            .await
            .expect("matching View cancellation reaches the same live runtime");
            host.process_next(&cx)
                .await
                .expect("process_next receives cancellation while request policy work is live");
            assert_eq!(
                events.lock().expect("test policy events lock").as_slice(),
                ["cancelled:String(\"view-call\")"]
            );

            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","id":"after-cancel","method":"ping","params":{}}"#.to_owned(),
            )
            .await
            .expect("View sends a later request after cancellation");
            host.process_next(&cx)
                .await
                .expect("Host remains usable after cancellation");
            assert!(matches!(
                McpAppsJsonRpcEnvelope::decode(
                    McpAppsBridgeDirection::HostToView,
                    &view
                        .receive_from_host(&cx)
                        .await
                        .expect("the first post-cancel response is available"),
                ),
                Ok(McpAppsJsonRpcEnvelope::Response {
                    id: McpAppsJsonRpcRequestId::String(id),
                    result,
                }) if id == "after-cancel" && result == json!({})
            ));
        });
    }

    #[test]
    fn closed_wire_sync_cancellation_hook_releases_never_returning_view_request() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut host = McpAppsWireHost::new_negotiated(
                transport,
                wire_configuration(),
                NeverReturnsCancellationWirePolicy {
                    events: Arc::clone(&events),
                },
                activation_proof(),
            );

            view.send_to_host(
                &cx,
                json!({
                    "jsonrpc": "2.0",
                    "id": "initialize",
                    "method": "ui/initialize",
                    "params": {
                        "appInfo": {"name": "view", "version": "1"},
                        "appCapabilities": {},
                        "protocolVersion": MCP_APPS_HOST_VIEW_PROTOCOL_VERSION,
                    },
                })
                .to_string(),
            )
            .await
            .expect("View initialize reaches the public Host runtime");
            host.process_next(&cx)
                .await
                .expect("Host commits initialize response");
            let _ = view
                .receive_from_host(&cx)
                .await
                .expect("View receives initialize response");
            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","method":"ui/notifications/initialized"}"#.to_owned(),
            )
            .await
            .expect("View initialized notification reaches Host");
            host.process_next(&cx)
                .await
                .expect("Host becomes active through the public lifecycle");
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);

            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","id":"view-call","method":"tools/call","params":{"name":"weather","arguments":{}}}"#
                    .to_owned(),
            )
            .await
            .expect("View request reaches Host");
            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"view-call"}}"#
                    .to_owned(),
            )
            .await
            .expect("matching View cancellation reaches the never-returning policy");
            host.process_next(&cx)
                .await
                .expect("matching cancellation drops the never-returning request before commit");
            assert_eq!(
                events.lock().expect("test policy events lock").as_slice(),
                ["cancelled:String(\"view-call\")"]
            );

            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","id":"after-cancel","method":"ping","params":{}}"#.to_owned(),
            )
            .await
            .expect("View sends a later request after cancellation");
            host.process_next(&cx)
                .await
                .expect("Host remains processable after dropping non-cooperative policy work");
            assert!(matches!(
                McpAppsJsonRpcEnvelope::decode(
                    McpAppsBridgeDirection::HostToView,
                    &view
                        .receive_from_host(&cx)
                        .await
                        .expect("the post-cancel response is available"),
                ),
                Ok(McpAppsJsonRpcEnvelope::Response {
                    id: McpAppsJsonRpcRequestId::String(id),
                    result,
                }) if id == "after-cancel" && result == json!({})
            ));
        });
    }

    #[test]
    fn closed_wire_one_variable_wrong_cancellation_preserves_a_yielding_view_request() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut host = McpAppsWireHost::new_negotiated(
                transport,
                wire_configuration(),
                YieldOnceCancellationWirePolicy {
                    events: Arc::clone(&events),
                },
                activation_proof(),
            );

            view.send_to_host(
                &cx,
                json!({
                    "jsonrpc": "2.0",
                    "id": "initialize",
                    "method": "ui/initialize",
                    "params": {
                        "appInfo": {"name": "view", "version": "1"},
                        "appCapabilities": {},
                        "protocolVersion": MCP_APPS_HOST_VIEW_PROTOCOL_VERSION,
                    },
                })
                .to_string(),
            )
            .await
            .expect("View initialize reaches the public Host runtime");
            host.process_next(&cx)
                .await
                .expect("Host commits initialize response");
            let _ = view
                .receive_from_host(&cx)
                .await
                .expect("View receives initialize response");
            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","method":"ui/notifications/initialized"}"#.to_owned(),
            )
            .await
            .expect("View initialized notification reaches Host");
            host.process_next(&cx)
                .await
                .expect("Host becomes active through the public lifecycle");

            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","id":"view-call","method":"tools/call","params":{"name":"weather","arguments":{}}}"#
                    .to_owned(),
            )
            .await
            .expect("View request reaches Host");
            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"other-call"}}"#
                    .to_owned(),
            )
            .await
            .expect("only the cancellation request ID changes");
            assert!(matches!(
                host.process_next(&cx).await,
                Err(McpAppsHostError::Bridge(
                    McpAppsBridgeError::UnknownCorrelation
                ))
            ));
            assert!(events.lock().expect("test policy events lock").is_empty());
            assert!(matches!(
                McpAppsJsonRpcEnvelope::decode(
                    McpAppsBridgeDirection::HostToView,
                    &view
                        .receive_from_host(&cx)
                        .await
                        .expect("the preserved request still receives its response"),
                ),
                Ok(McpAppsJsonRpcEnvelope::Response {
                    id: McpAppsJsonRpcRequestId::String(id),
                    result,
                }) if id == "view-call" && result == json!({"forwarded": true})
            ));
        });
    }

    #[test]
    fn closed_wire_one_variable_wrong_progress_token_preserves_the_host_request() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut host = McpAppsWireHost::new_negotiated(
                transport,
                wire_configuration(),
                ControlRecordingWirePolicy {
                    events: Arc::clone(&events),
                },
                activation_proof(),
            );
            host.admission = active_wire_admission();
            let request_id = host
                .send_host_request(
                    &cx,
                    McpAppsHostRequest::Ping(fastmcp_protocol::McpAppsPingParams::default()),
                    Some(
                        McpAppsJsonRpcRequestId::string("host-progress".to_owned())
                            .expect("bounded progress token"),
                    ),
                )
                .await
                .expect("active Host may initiate a View ping");
            let _ = view
                .receive_from_host(&cx)
                .await
                .expect("View receives the Host request");

            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"other-progress","progress":1.0}}"#
                    .to_owned(),
            )
            .await
            .expect("near-identical View progress reaches Host");
            assert!(matches!(
                host.process_next(&cx).await,
                Err(McpAppsHostError::Bridge(
                    McpAppsBridgeError::UnknownProgressToken
                ))
            ));
            assert!(events.lock().expect("test policy events lock").is_empty());

            view.send_to_host(
                &cx,
                serde_json::json!({"jsonrpc": "2.0", "id": request_id, "result": {}}).to_string(),
            )
            .await
            .expect("matching View response reaches Host");
            host.process_next(&cx)
                .await
                .expect("wrong progress cannot complete the Host request");
        });
    }

    #[test]
    fn closed_wire_cancelled_control_releases_only_the_bound_view_request() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(4);
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut host = McpAppsWireHost::new_negotiated(
                transport,
                wire_configuration(),
                ControlRecordingWirePolicy {
                    events: Arc::clone(&events),
                },
                activation_proof(),
            );
            host.admission = active_wire_admission();
            let request_id = McpAppsJsonRpcRequestId::string("view-call".to_owned())
                .expect("bounded View request ID");
            host.admission
                .admit_request(
                    McpAppsBridgeDirection::ViewToHost,
                    request_id.clone(),
                    McpAppsRoutedMethod::ToolsCall,
                    None,
                )
                .expect("test View request is live before its cancellation");

            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"view-call"}}"#
                    .to_owned(),
            )
            .await
            .expect("View cancellation reaches Host");
            host.process_next(&cx)
                .await
                .expect("bound cancellation reaches policy and releases the request");

            assert_eq!(
                events.lock().expect("test policy events lock").as_slice(),
                ["cancelled:String(\"view-call\")"]
            );
            assert_eq!(
                host.admission
                    .complete_error(McpAppsBridgeDirection::ViewToHost, &request_id),
                Err(McpAppsBridgeError::UnknownCorrelation),
                "a bound cancellation must release its exact live correlation"
            );
        });
    }

    #[test]
    fn closed_wire_one_variable_wrong_cancelled_id_preserves_the_live_request() {
        block_on(async {
            let cx = Cx::for_testing();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(4);
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut host = McpAppsWireHost::new_negotiated(
                transport,
                wire_configuration(),
                ControlRecordingWirePolicy {
                    events: Arc::clone(&events),
                },
                activation_proof(),
            );
            host.admission = active_wire_admission();
            let request_id = McpAppsJsonRpcRequestId::string("view-call".to_owned())
                .expect("bounded View request ID");
            host.admission
                .admit_request(
                    McpAppsBridgeDirection::ViewToHost,
                    request_id.clone(),
                    McpAppsRoutedMethod::ToolsCall,
                    None,
                )
                .expect("test View request is live before the near-identical control");

            view.send_to_host(
                &cx,
                r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"other-call"}}"#
                    .to_owned(),
            )
            .await
            .expect("near-identical cancellation reaches Host");
            assert!(matches!(
                host.process_next(&cx).await,
                Err(McpAppsHostError::Bridge(
                    McpAppsBridgeError::UnknownCorrelation
                ))
            ));
            assert!(events.lock().expect("test policy events lock").is_empty());
            host.admission
                .complete_error(McpAppsBridgeDirection::ViewToHost, &request_id)
                .expect("the unmatched control preserves the original correlation");
        });
    }

    fn active_wire_admission() -> McpAppsBridgeAdmission {
        let mut admission = activation_proof().admission();
        let initialize = r#"{"jsonrpc":"2.0","id":"init","method":"ui/initialize","params":{"appInfo":{"name":"view","version":"1"},"appCapabilities":{},"protocolVersion":"2026-01-26"}}"#;
        admission
            .decode_and_admit(McpAppsBridgeDirection::ViewToHost, initialize)
            .unwrap();
        admission.initialization_response_committed().unwrap();
        admission
            .decode_and_admit(
                McpAppsBridgeDirection::ViewToHost,
                r#"{"jsonrpc":"2.0","method":"ui/notifications/initialized"}"#,
            )
            .unwrap();
        admission
    }
}
