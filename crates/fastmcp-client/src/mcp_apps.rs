//! Browser-agnostic MCP Apps Host/View runtime.
//!
//! An embedder supplies the carrier (a webview, iframe adapter, or the bounded
//! in-memory pair below). This module never renders HTML and never routes Apps
//! messages through MCP client/server RPC.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use crate::{CoreResult, FinalCoreResult};
use asupersync::Cx;
use asupersync::channel::mpsc::{self, Receiver, Sender};
use asupersync::combinator::select::{Either, Select};
use fastmcp_core::{McpError, McpResult};
use fastmcp_protocol::{
    MAX_MCP_APPS_BRIDGE_IN_FLIGHT, MCP_APPS_HOST_VIEW_PROTOCOL_VERSION, McpAppsBridgeAdmission,
    McpAppsBridgeDirection, McpAppsBridgeError, McpAppsBridgeImplementation,
    McpAppsBridgeLifecycle, McpAppsBridgeRequestId, McpAppsCancelledControlParams,
    McpAppsControlDisposition, McpAppsDisplayModeParams, McpAppsHostCapabilities,
    McpAppsHostContext, McpAppsHostIdAllocator, McpAppsHostNotification, McpAppsHostRequest,
    McpAppsHostResponse, McpAppsHostToView, McpAppsInitializeParams, McpAppsInitializeResult,
    McpAppsJsonRpcEnvelope, McpAppsJsonRpcError, McpAppsJsonRpcRequestId, McpAppsOperationResult,
    McpAppsPinnedHostCapabilities, McpAppsPinnedHostContext, McpAppsPinnedInitializeParams,
    McpAppsPinnedInitializeResult, McpAppsProgressControlParams, McpAppsResourceTeardownParams,
    McpAppsRoutedMethod, McpAppsViewLifecycle, McpAppsViewNotification, McpAppsViewRequest,
    McpAppsViewResponse, McpAppsViewToHost,
};
use serde_json::{Value, json};

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
    /// that request correlation. An absent-ID cancellation remains the
    /// protocol's explicit inert no-op and never reaches this hook.
    async fn cancelled(
        &mut self,
        _request_id: &McpAppsJsonRpcRequestId,
        _params: &McpAppsCancelledControlParams,
    ) -> Result<(), McpAppsHostError> {
        Ok(())
    }

    async fn approve_view_teardown(&mut self) -> bool {
        false
    }

    async fn dispatch_reused_request(
        &mut self,
        cx: &Cx,
        method: McpAppsRoutedMethod,
        params: Option<Value>,
    ) -> Result<Value, McpAppsHostError>;
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
    /// Frames received while an admitted View request is still executing.
    /// They are replayed through normal admission once that request resolves.
    deferred_view_frames: VecDeque<String>,
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
            deferred_view_frames: VecDeque::new(),
        }
    }

    #[must_use]
    pub const fn lifecycle(&self) -> McpAppsBridgeLifecycle {
        self.admission.lifecycle()
    }

    /// Receives, decodes, and atomically admits exactly one View frame.
    ///
    /// A View request remains request-owned while its policy work is pending:
    /// this method concurrently receives one matching cancellation and drops
    /// that work before committing the cancellation disposition. Other frames
    /// are deferred and replayed after the request reaches a terminal result.
    pub async fn process_next(&mut self, cx: &Cx) -> Result<(), McpAppsHostError> {
        let frame = match self.deferred_view_frames.pop_front() {
            Some(frame) => frame,
            None => self.transport.receive_from_view(cx).await?,
        };
        let was_closing = self.admission.lifecycle() == McpAppsBridgeLifecycle::Closing;
        let envelope = self
            .admission
            .decode_and_admit(McpAppsBridgeDirection::ViewToHost, &frame)
            .map_err(McpAppsHostError::Bridge)?;
        match envelope {
            McpAppsJsonRpcEnvelope::Request {
                id, method, params, ..
            } => self.handle_view_request(cx, id, method, params).await,
            McpAppsJsonRpcEnvelope::Notification { method, params } => {
                self.handle_view_notification(cx, method, params).await
            }
            McpAppsJsonRpcEnvelope::Response { .. } | McpAppsJsonRpcEnvelope::Error { .. } => {
                if was_closing {
                    self.admission
                        .commit_teardown()
                        .map_err(McpAppsHostError::Bridge)?;
                }
                Ok(())
            }
        }
    }

    async fn handle_view_request(
        &mut self,
        cx: &Cx,
        id: McpAppsJsonRpcRequestId,
        method: McpAppsRoutedMethod,
        params: Option<Value>,
    ) -> Result<(), McpAppsHostError> {
        let mut execution = Box::pin(Self::dispatch_view_request(
            &mut self.policy,
            &self.configuration,
            cx,
            method,
            params.as_ref(),
        ));
        let mut deferred_error = None;
        loop {
            let mut incoming = Box::pin(self.transport.receive_from_view(cx));
            let selected = Select::new(&mut execution, &mut incoming)
                .await
                .map_err(|error| McpAppsHostError::Transport(error.to_string()))?;
            match selected {
                Either::Left(result) => {
                    drop(incoming);
                    drop(execution);
                    let completion = self.finish_view_request(cx, id, method, result).await;
                    return match (completion, deferred_error) {
                        (Err(error), _) => Err(error),
                        (Ok(()), Some(error)) => Err(error),
                        (Ok(()), None) => Ok(()),
                    };
                }
                Either::Right(frame) => {
                    drop(incoming);
                    let frame = frame?;
                    match Self::matching_view_cancellation(&self.admission, &id, &frame) {
                        Ok(Some(params)) => {
                            // Dropping the request-owned dispatch future is
                            // its cancellation boundary. No response may race
                            // the committed `notifications/cancelled` control.
                            drop(execution);
                            self.commit_view_cancellation(&id, &params).await?;
                            return Ok(());
                        }
                        Ok(None) => {
                            if self.deferred_view_frames.len() >= MAX_MCP_APPS_BRIDGE_IN_FLIGHT {
                                drop(execution);
                                self.admission
                                    .complete_error(McpAppsBridgeDirection::ViewToHost, &id)
                                    .map_err(McpAppsHostError::Bridge)?;
                                return Err(McpAppsHostError::Bridge(
                                    McpAppsBridgeError::TooManyInFlight,
                                ));
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
        result: Result<Value, McpAppsHostError>,
    ) -> Result<(), McpAppsHostError> {
        match result {
            Ok(result) => {
                McpAppsJsonRpcEnvelope::validate_response_for(method, &result)
                    .map_err(McpAppsHostError::Bridge)?;
                let response = McpAppsJsonRpcEnvelope::Response {
                    id: id.clone(),
                    result: result.clone(),
                };
                self.send_envelope(cx, response).await?;
                if method == McpAppsRoutedMethod::Initialize {
                    self.admission
                        .initialization_response_committed()
                        .map_err(McpAppsHostError::Bridge)?;
                }
                self.admission
                    .complete_response(McpAppsBridgeDirection::ViewToHost, &id, &result)
                    .map_err(McpAppsHostError::Bridge)?;
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
        cx: &Cx,
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
            McpAppsRoutedMethod::UpdateModelContext => Ok(json!({})),
            McpAppsRoutedMethod::RequestDisplayMode => params
                .cloned()
                .ok_or(McpAppsHostError::Bridge(McpAppsBridgeError::InvalidParams)),
            McpAppsRoutedMethod::OpenLink
            | McpAppsRoutedMethod::DownloadFile
            | McpAppsRoutedMethod::Message => policy.operation(method, params).await,
            method @ (McpAppsRoutedMethod::ToolsCall
            | McpAppsRoutedMethod::ResourcesRead
            | McpAppsRoutedMethod::ResourcesList
            | McpAppsRoutedMethod::ResourceTemplatesList
            | McpAppsRoutedMethod::PromptsList) => {
                policy
                    .dispatch_reused_request(cx, method, params.cloned())
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

    async fn commit_view_cancellation(
        &mut self,
        request_id: &McpAppsJsonRpcRequestId,
        params: &McpAppsCancelledControlParams,
    ) -> Result<(), McpAppsHostError> {
        self.policy.cancelled(request_id, params).await?;
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
                    let params = decode_params(params.as_ref())?;
                    self.policy.progress(&request_id, &params).await?;
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
                    self.commit_view_cancellation(&request_id, &params).await?;
                }
                return Ok(());
            }
            _ => {}
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
        if self.admission.lifecycle() != McpAppsBridgeLifecycle::Active {
            return Err(McpAppsHostError::Bridge(
                McpAppsBridgeError::InvalidLifecycle,
            ));
        }
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
        self.admission
            .admit_request(
                McpAppsBridgeDirection::HostToView,
                id.clone(),
                method,
                progress_token,
            )
            .map_err(McpAppsHostError::Bridge)?;
        let sent = self.transport.send_to_view(cx, frame).await;
        if sent.is_err() {
            self.admission
                .complete_error(McpAppsBridgeDirection::HostToView, &id)
                .map_err(McpAppsHostError::Bridge)?;
        }
        sent.map(|()| id)
    }

    /// Starts a Host-approved teardown. A failed carrier send restores the
    /// active admission state without dropping unrelated live correlations.
    pub async fn begin_teardown(&mut self, cx: &Cx) -> Result<(), McpAppsHostError> {
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
        let sent = self.transport.send_to_view(cx, frame).await;
        if sent.is_err() {
            self.admission
                .complete_error(McpAppsBridgeDirection::HostToView, &id)
                .map_err(McpAppsHostError::Bridge)?;
            self.admission
                .rollback_teardown()
                .map_err(McpAppsHostError::Bridge)?;
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
        self.transport.send_to_view(cx, frame).await
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
        (
            McpAppsRoutedMethod::ToolsCall,
            CoreResult::Final(
                FinalCoreResult::ToolsCallTask { .. }
                | FinalCoreResult::ToolsCallInputRequired { .. },
            ),
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
    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the public wire-policy trait requires an async forwarding hook; this stdio implementation completes synchronously while the HTTP implementation awaits I/O"
    )]
    async fn dispatch_reused_request(
        &mut self,
        cx: &Cx,
        method: McpAppsRoutedMethod,
        params: Option<Value>,
    ) -> Result<Value, McpAppsHostError> {
        self.client
            .forward_mcp_apps_reused_core(cx, method, params)
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
        method: McpAppsRoutedMethod,
        params: Option<Value>,
    ) -> Result<Value, McpAppsHostError> {
        self.client
            .forward_mcp_apps_reused_core(cx, method, params)
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
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use serde_json::json;

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

    impl McpAppsWireHostPolicy for WirePolicy {
        #[allow(
            clippy::unused_async_trait_impl,
            reason = "the public wire-host policy trait requires an async override"
        )]
        async fn dispatch_reused_request(
            &mut self,
            _cx: &Cx,
            _method: McpAppsRoutedMethod,
            _params: Option<Value>,
        ) -> Result<Value, McpAppsHostError> {
            Ok(json!({"forwarded": true}))
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

        #[allow(
            clippy::unused_async_trait_impl,
            reason = "the public wire-host policy trait requires an async override"
        )]
        async fn cancelled(
            &mut self,
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
            Ok(json!({"forwarded": true}))
        }

        #[allow(
            clippy::unused_async_trait_impl,
            reason = "the public wire-host policy trait requires an async override"
        )]
        async fn cancelled(
            &mut self,
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
            host_capabilities: McpAppsPinnedHostCapabilities::default(),
            host_context: McpAppsPinnedHostContext::default(),
        }
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
                assert!(response.contains("forwarded"));
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
    fn closed_wire_process_next_cancels_the_real_live_view_request_without_a_response() {
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
    fn closed_wire_one_variable_wrong_cancellation_preserves_the_real_live_view_request() {
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
