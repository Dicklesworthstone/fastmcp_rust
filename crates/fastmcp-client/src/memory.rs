//! Modern, caller-driven request execution over a bounded memory connection.
//!
//! This is in-process integration infrastructure. It owns no runtime, reader
//! thread, background pump or network connector. Callers may start several
//! executions, then drive any handle; the one reader routes other owners'
//! responses and progress without consuming their results.
//! High-level catalog and resource reads reuse complete results under peer
//! freshness hints, bounded connection-local storage and admitted invalidation.
//! Owned execution handles and raw requests always retain direct wire behavior.

use std::collections::{BTreeMap, VecDeque};
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use fastmcp_core::{McpError, McpErrorCode, McpRequestCancellation, McpResult};
use fastmcp_protocol::extensions::{
    ClientExtensionDiscovery, ExtensionDescriptorRegistry, ExtensionSettingsCompatibilityResolver,
};
use fastmcp_protocol::protocol_policy::{MODERN_PROTOCOL_VERSION, ProtocolEra};
use fastmcp_protocol::{
    ClientCapabilities, ClientInfo, CoreRequest, CoreResult, ExtensionId, FinalCoreResult,
    FinalRequestMeta, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId,
    ServerCapabilities, ServerDiscoverResult,
};
use fastmcp_transport::memory::asynchronous::MemorySendPermit;
use fastmcp_transport::memory::{MemoryRecvHalf, MemorySendHalf, MemoryTransport};
use fastmcp_transport::{
    ReceivedTransportFrame, Transport, TransportError, TransportRecvHalf, TransportSendHalf,
};
use serde_json::Value;

use crate::cache::{FinalCachePageLookup, final_cache_hints};
use crate::execution::{
    CancellationRequested, FinalCacheTtlDiagnostic, RequestExecution, RequestExecutor,
    decode_core_result_with_cache_ttl_from_source,
};
use crate::session::{ClientExtensionResultAdmission, ClientExtensionRuntime, ClientSession};
use crate::{
    CachePartitionKey, FinalCacheKey, FinalCacheMiss, FinalCachePageState, FinalCacheStats,
    RequestTimeoutPolicy, ReverseRequestHandlers, final_cache_result_set, transport_error_to_mcp,
};

#[cfg(feature = "apps")]
mod apps;
mod catalog;
mod interaction;
mod subscriptions;

#[cfg(feature = "apps")]
pub use apps::McpAppsMemoryClientWirePolicy;
pub use subscriptions::{MemorySubscriptionEvent, MemorySubscriptionExecution};

#[cfg(feature = "tasks")]
mod tasks;

const CHECKPOINT_INTERVAL: Duration = Duration::from_millis(20);
const SEND_ADMISSION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DIAGNOSTICS: usize = 1_024;
const MAX_CACHE_INGRESS_FRAMES: usize = 64;
// This exclusion also applies when the typed Tasks implementation is absent.
const TASKS_EXTENSION_NAME: &str = "io.modelcontextprotocol/tasks";

/// The executor owns correlation, never the memory channel's actual I/O.
#[derive(Debug)]
struct ExternalMemoryTransport;

impl Transport for ExternalMemoryTransport {
    fn send(&mut self, _: &Cx, _: &JsonRpcMessage) -> Result<(), TransportError> {
        Err(TransportError::Io(std::io::Error::other(
            "memory executor writes require an owned channel permit",
        )))
    }

    fn recv(&mut self, _: &Cx) -> Result<JsonRpcMessage, TransportError> {
        Err(TransportError::Io(std::io::Error::other(
            "memory executor ingress belongs to its asynchronous driver",
        )))
    }

    fn close(&mut self, _: &Cx) -> Result<(), TransportError> {
        Ok(())
    }
}

type MemoryExecutor = RequestExecutor<ExternalMemoryTransport>;

/// One independently owned ordinary modern request on a [`MemoryClient`].
///
/// Dropping an unfinished handle elects local cancellation immediately. Its
/// bounded cancellation control is committed on the next client drive before
/// new application work; Drop itself never waits for capacity. The exact late
/// response remains owned by a tombstone and cannot complete a sibling.
#[derive(Debug)]
pub struct MemoryRequestExecution {
    owner: Arc<()>,
    inner: RequestExecution<ExternalMemoryTransport>,
    request: CoreRequest,
    notifications: VecDeque<JsonRpcRequest>,
    allow_tasks: bool,
    finished: bool,
}

impl MemoryRequestExecution {
    /// The exact monotonically allocated ID actually published to the peer.
    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        self.inner.request_id()
    }
}

/// A request-owned notification or the one typed final outcome.
#[derive(Debug)]
pub enum MemoryRequestEvent {
    /// Valid progress carrying this exact execution's advertised token.
    Notification(JsonRpcRequest),
    /// The method-specific final result, including any input-required branch
    /// and admitted open result members. No continuation is retried implicitly.
    Result(Box<CoreResult>),
}

/// One admitted extension request on a [`MemoryClient`].
///
/// The handle retains the exact extension owner and result authority installed
/// before publication. Dropping an unfinished handle cancels only that request;
/// its deferred control follows the same bounded path as ordinary core work.
#[derive(Debug)]
pub struct MemoryExtensionExecution {
    owner: Arc<()>,
    inner: RequestExecution<ExternalMemoryTransport>,
    notifications: VecDeque<JsonRpcRequest>,
    raw_result_source: Option<String>,
    finished: bool,
}

impl MemoryExtensionExecution {
    /// The exact ID actually published to the peer.
    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        self.inner.request_id()
    }

    /// The exact admitted result JSON after its successful result event.
    ///
    /// This source preserves number spellings and member order independently
    /// of the parsed result value. Errors and unfinished executions have none.
    #[must_use]
    pub fn raw_result_source(&self) -> Option<&str> {
        self.raw_result_source.as_deref()
    }
}

/// A request-owned progress notification or one admitted extension result.
#[derive(Debug)]
pub enum MemoryExtensionEvent {
    /// Progress carrying this execution's exact advertised token.
    Notification(JsonRpcRequest),
    /// A result admitted by the immutable extension authority for this request.
    Result(Value),
}

/// Configures one modern client for an already owned bounded memory endpoint.
///
/// The builder freezes extension descriptors and local settings before any
/// discovery request is published. Connection setup uses only the supplied
/// runtime context and consumes no background worker or independent runtime.
pub struct MemoryClientBuilder {
    client_info: ClientInfo,
    capabilities: ClientCapabilities,
    extension_runtime: Option<Arc<ClientExtensionRuntime>>,
    timeout_policy: RequestTimeoutPolicy,
    reverse_request_handlers: ReverseRequestHandlers,
    #[cfg(feature = "apps")]
    mcp_apps_settings: Option<crate::McpAppsClientSettings>,
    #[cfg(feature = "tasks")]
    tasks_enabled: bool,
}

impl std::fmt::Debug for MemoryClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryClientBuilder")
            .field("client_info", &self.client_info)
            .field("timeout_policy", &self.timeout_policy)
            .field(
                "has_modern_handlers",
                &self.reverse_request_handlers.has_modern_handlers(),
            )
            .finish_non_exhaustive()
    }
}

impl MemoryClientBuilder {
    /// Uses the supplied identity and default capabilities and response bounds.
    #[must_use]
    pub fn new(client_info: ClientInfo) -> Self {
        Self {
            client_info,
            capabilities: ClientCapabilities::default(),
            extension_runtime: None,
            timeout_policy: RequestTimeoutPolicy::default(),
            reverse_request_handlers: ReverseRequestHandlers::new(),
            #[cfg(feature = "apps")]
            mcp_apps_settings: None,
            #[cfg(feature = "tasks")]
            tasks_enabled: false,
        }
    }

    /// Sets ordinary client capabilities.
    ///
    /// Nonempty extension settings must exactly match the settings installed
    /// by [`Self::extension_registry`]; raw capability advertisements never
    /// grant extension execution authority. The official Tasks advertisement
    /// requires the separately selected Tasks builder policy.
    #[must_use]
    pub fn capabilities(mut self, capabilities: ClientCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Sets finite idle and absolute response bounds, including discovery.
    pub fn timeout_policy(mut self, policy: RequestTimeoutPolicy) -> McpResult<Self> {
        RequestTimeoutPolicy::new(policy.idle_timeout(), policy.absolute_timeout())?;
        self.timeout_policy = policy;
        Ok(self)
    }

    /// Installs one frozen registry and its locally configured extension settings.
    ///
    /// Every local settings owner must have a descriptor. The factory must
    /// produce an independent compatibility resolver for each negotiation;
    /// notification activation also obtains fresh current-message authority.
    /// Only methods admitted by the peer's successful discovery are executable.
    pub fn extension_registry<F, R>(
        mut self,
        descriptors: ExtensionDescriptorRegistry,
        client_discovery: ClientExtensionDiscovery,
        resolver_factory: F,
    ) -> McpResult<Self>
    where
        F: Fn() -> R + Send + Sync + 'static,
        R: ExtensionSettingsCompatibilityResolver + Send + 'static,
    {
        if self.extension_runtime.is_some() {
            return Err(McpError::invalid_params(
                "Memory client extension registry is already configured",
            ));
        }
        self.extension_runtime = Some(Arc::new(ClientExtensionRuntime::new(
            descriptors,
            client_discovery,
            resolver_factory,
        )?));
        Ok(self)
    }

    /// Connects to an exact modern peer over the supplied endpoint.
    pub async fn connect(self, cx: &Cx, transport: MemoryTransport) -> McpResult<MemoryClient> {
        self.connect_with_cancellation(cx, &McpRequestCancellation::new(), transport)
            .await
    }

    /// Connects with explicit cancellation; failed discovery releases both halves.
    pub async fn connect_with_cancellation(
        self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        transport: MemoryTransport,
    ) -> McpResult<MemoryClient> {
        MemoryClient::connect_configured(cx, cancellation, transport, self).await
    }
}

/// A modern-only asynchronous client for an existing bounded memory endpoint.
///
/// Ordinary core methods share the same typed protocol admission and request
/// executor as other clients. Configured extensions use their own admitted
/// execution and notification APIs. Independently owned subscriptions share
/// the same reader and executor, with bounded per-listener event queues.
/// Client metadata is frozen at connect and stamped on every request.
///
/// A caller timer driver is required when an operation must wait: response
/// deadlines and the 30-second send-admission bound remain observable even if
/// the peer is silent. There is no blocking-pool or reactor requirement.
///
/// [`fastmcp_core::OperatorSnapshot::capture`] observes the live executor's
/// admission state without sending, receiving, or servicing queued controls.
/// A closed client continues to report its terminal executor state.
pub struct MemoryClient {
    receiver: MemoryRecvHalf,
    sender: MemorySendHalf,
    executor: MemoryExecutor,
    owner: Arc<()>,
    session: ClientSession,
    next_id: i64,
    timeout_policy: RequestTimeoutPolicy,
    reverse_request_handlers: ReverseRequestHandlers,
    subscriptions: subscriptions::MemorySubscriptionRegistry,
    cache_diagnostics: VecDeque<FinalCacheTtlDiagnostic>,
    #[cfg(feature = "tasks")]
    tasks: Option<tasks::MemoryTaskRuntime>,
    closed: bool,
}

impl std::fmt::Debug for MemoryClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryClient")
            .field("next_id", &self.next_id)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl fastmcp_core::OperatorSnapshotSource<fastmcp_core::OperatorExecutorCapacity> for MemoryClient {
    fn operator_snapshot(
        &self,
    ) -> Result<fastmcp_core::OperatorExecutorSnapshot, fastmcp_core::OperatorSnapshotError> {
        fastmcp_core::OperatorSnapshot::capture(&self.executor)
    }
}

impl MemoryClient {
    /// Starts configuration for an owned bounded memory endpoint.
    #[must_use]
    pub fn builder(client_info: ClientInfo) -> MemoryClientBuilder {
        MemoryClientBuilder::new(client_info)
    }

    /// Discovers the exact modern peer using only the supplied runtime context.
    pub async fn connect(
        cx: &Cx,
        transport: MemoryTransport,
        client_info: ClientInfo,
        capabilities: ClientCapabilities,
    ) -> McpResult<Self> {
        Self::connect_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            transport,
            client_info,
            capabilities,
        )
        .await
    }

    /// Connects with an explicit request-cancellation token. Failed discovery
    /// closes both owned halves and never retries on this or a fresh endpoint.
    pub async fn connect_with_cancellation(
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        transport: MemoryTransport,
        client_info: ClientInfo,
        capabilities: ClientCapabilities,
    ) -> McpResult<Self> {
        Self::builder(client_info)
            .capabilities(capabilities)
            .connect_with_cancellation(cx, cancellation, transport)
            .await
    }

    async fn connect_configured(
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        transport: MemoryTransport,
        builder: MemoryClientBuilder,
    ) -> McpResult<Self> {
        checkpoint(cx, cancellation)?;
        let MemoryClientBuilder {
            client_info,
            mut capabilities,
            extension_runtime,
            timeout_policy,
            reverse_request_handlers,
            #[cfg(feature = "apps")]
            mcp_apps_settings,
            #[cfg(feature = "tasks")]
            tasks_enabled,
        } = builder;
        #[cfg(not(feature = "apps"))]
        let mcp_apps_settings = None;
        let configured = extension_runtime
            .as_ref()
            .map(|runtime| runtime.client_wire_extensions())
            .unwrap_or_default();
        if configured.contains_key(TASKS_EXTENSION_NAME) {
            return Err(McpError::invalid_params(
                "Memory Tasks requires the explicit Tasks builder policy",
            ));
        }
        #[cfg(not(feature = "apps"))]
        if configured.contains_key(
            fastmcp_protocol::extensions::official_mcp_apps_extension_id().as_str(),
        ) {
            return Err(McpError::invalid_params(
                "Memory MCP Apps requires the apps feature",
            ));
        }
        #[cfg(feature = "apps")]
        let configured = {
            let mut configured = configured;
            if !extension_runtime
                .as_ref()
                .is_some_and(|runtime| runtime.configures_mcp_apps())
                && let Some(settings) = &mcp_apps_settings
            {
                configured.insert(
                    fastmcp_protocol::extensions::official_mcp_apps_extension_id()
                        .as_str()
                        .to_owned(),
                    settings.to_extension_settings().into_value(),
                );
            }
            configured
        };
        #[cfg(feature = "tasks")]
        let (configured, tasks) = if tasks_enabled {
            let runtime = tasks::MemoryTaskRuntime::new()?;
            let mut configured = configured;
            configured.insert(TASKS_EXTENSION_NAME.to_owned(), serde_json::json!({}));
            (configured, Some(runtime))
        } else {
            (configured, None)
        };
        if capabilities
            .extensions
            .as_ref()
            .is_some_and(|advertised| !advertised.is_empty() && advertised != &configured)
        {
            return Err(McpError::invalid_params(
                "Memory client extension capabilities differ from its configured registry",
            ));
        }
        if extension_runtime.is_some() || !configured.is_empty() {
            capabilities.extensions = Some(configured);
        }
        reverse_request_handlers.derive_modern_capabilities(&mut capabilities);
        let session = ClientSession::try_new(
            client_info,
            capabilities,
            None,
            ServerCapabilities::default(),
            MODERN_PROTOCOL_VERSION.to_owned(),
        )
        .map_err(|_| McpError::internal_error("Modern memory protocol version is unavailable"))?
        .with_client_extension_runtime(extension_runtime.clone())
        .with_mcp_apps_settings(mcp_apps_settings.clone());
        let (receiver, sender) = transport.into_split();
        let mut client = Self {
            receiver,
            sender,
            executor: RequestExecutor::with_external_driver(
                ExternalMemoryTransport,
                ProtocolEra::Modern2026,
            ),
            owner: Arc::new(()),
            session,
            next_id: 1,
            timeout_policy,
            reverse_request_handlers,
            subscriptions: subscriptions::MemorySubscriptionRegistry::default(),
            cache_diagnostics: VecDeque::new(),
            #[cfg(feature = "tasks")]
            tasks,
            closed: false,
        };
        let result = client
            .request_core(cx, cancellation, "server/discover", serde_json::json!({}))
            .await?;
        let CoreResult::Final(FinalCoreResult::Discover(discovery)) = result else {
            return Err(McpError::invalid_request(
                "Memory discovery returned another method's result",
            ));
        };
        if !discovery
            .supported_versions()
            .iter()
            .any(|version| version == MODERN_PROTOCOL_VERSION)
        {
            return Err(McpError::invalid_request(
                "Memory peer does not support MCP 2026-07-28",
            ));
        }
        let server_info = discovery
            .server_info()
            .cloned()
            .or_else(|| discovery.compatibility_server_info());
        client.session = ClientSession::try_new(
            client.session.client_info().clone(),
            client.session.client_capabilities().clone(),
            server_info,
            ServerCapabilities::default(),
            MODERN_PROTOCOL_VERSION.to_owned(),
        )
        .map_err(|_| McpError::internal_error("Modern memory session could not be established"))?
        .with_client_extension_runtime(extension_runtime)
        .with_mcp_apps_settings(mcp_apps_settings)
        .with_server_discovery(discovery);
        client
            .session
            .negotiate_client_extensions_after_discovery()?;
        #[cfg(feature = "apps")]
        {
            let activation = if client.session.generic_mcp_apps_configured() {
                client.session.generic_mcp_apps_activation_receipt()
            } else {
                client.session.server_discovery().and_then(|discovery| {
                    crate::session::mcp_apps_activation_receipt(
                        client.session.mcp_apps_settings(),
                        discovery,
                    )
                })
            };
            client.session.set_mcp_apps_activation_receipt(activation);
        }
        #[cfg(feature = "tasks")]
        if let Some(tasks) = &mut client.tasks {
            tasks.negotiate(
                client
                    .session
                    .server_discovery()
                    .expect("discovery was installed before Tasks negotiation"),
            )?;
        }
        Ok(client)
    }

    /// The successfully admitted discovery snapshot retained at connection time.
    #[must_use]
    pub fn server_discovery(&self) -> &ServerDiscoverResult {
        self.session
            .server_discovery()
            .expect("public memory clients completed discovery")
    }

    /// Starts one ordinary typed core operation. The returned handle owns an
    /// actual committed request; a pending/dropped send owns no request ID,
    /// response waiter, deadline or cancellation control.
    pub async fn execute_core(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        parameters: Value,
    ) -> McpResult<MemoryRequestExecution> {
        self.execute_core_with_timeout_policy(
            cx,
            cancellation,
            method,
            parameters,
            self.timeout_policy,
        )
        .await
    }

    /// Uses stricter bounded idle and absolute response deadlines for one call.
    /// Both start at actual channel publication, never at capacity reservation.
    pub async fn execute_core_with_timeout_policy(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        parameters: Value,
        timeout_policy: RequestTimeoutPolicy,
    ) -> McpResult<MemoryRequestExecution> {
        self.execute_core_admitted(
            cx,
            cancellation,
            method,
            parameters,
            timeout_policy,
            false,
        )
        .await
    }

    async fn execute_core_admitted(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        parameters: Value,
        timeout_policy: RequestTimeoutPolicy,
        allow_tasks: bool,
    ) -> McpResult<MemoryRequestExecution> {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        RequestTimeoutPolicy::new(
            timeout_policy.idle_timeout(),
            timeout_policy.absolute_timeout(),
        )?;
        if timeout_policy.idle_timeout() > self.timeout_policy.idle_timeout()
            || timeout_policy.absolute_timeout() > self.timeout_policy.absolute_timeout()
        {
            return Err(McpError::invalid_params(
                "Memory execution timeout exceeds the client policy",
            ));
        }
        if method == "subscriptions/listen" {
            return Err(McpError::invalid_params(
                "Ordinary memory execution cannot open a subscription",
            ));
        }
        let discovery_tasks = {
            #[cfg(feature = "tasks")]
            {
                method == "server/discover" && self.tasks.is_some()
            }
            #[cfg(not(feature = "tasks"))]
            {
                false
            }
        };
        let parameters =
            self.parameters_with_tasks(parameters, allow_tasks || discovery_tasks)?;
        let request = CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&parameters))
            .map_err(|_| McpError::invalid_params("Invalid modern memory core request"))?;
        let next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| McpError::internal_error("Memory request IDs exhausted"))?;
        let wire = JsonRpcRequest::new(method, Some(parameters), self.next_id);
        // Admission/serialization errors must be observable even behind a full
        // queue. The commit permit repeats the transport's exact same check.
        fastmcp_transport::Codec::new()
            .encode_request(&wire)
            .map_err(transport_error_from_codec)?;
        let deadline = Instant::now() + SEND_ADMISSION_TIMEOUT;
        loop {
            self.flush_controls(cx, cancellation, deadline).await?;
            let permit = reserve_capacity(
                &mut self.sender,
                &mut self.receiver,
                &self.executor,
                &mut self.subscriptions,
                cx,
                cancellation,
                deadline,
            )
            .await?;
            let committed = self.executor.execute_external(
                cx,
                cancellation,
                wire.clone(),
                timeout_policy,
                |message| permit.send(message),
            )?;
            if let Some(inner) = committed {
                self.next_id = next_id;
                return Ok(MemoryRequestExecution {
                    owner: Arc::clone(&self.owner),
                    inner,
                    request,
                    notifications: VecDeque::new(),
                    allow_tasks,
                    finished: false,
                });
            }
            // A sibling dropped while capacity was pending. Its control is
            // now authoritative; the unused permit aborts before retrying.
        }
    }

    /// Publishes one negotiated client-to-server extension request.
    ///
    /// The method, direction and exact extension owner must be active before
    /// waiting for channel capacity. Local protocol metadata always replaces
    /// conflicting caller metadata. The returned handle owns the same bounded
    /// correlation, progress and cancellation machinery as ordinary requests.
    pub async fn execute_final_extension(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        extension_id: &ExtensionId,
        method: &str,
        parameters: Value,
    ) -> McpResult<MemoryExtensionExecution> {
        self.execute_final_extension_with_timeout_policy(
            cx,
            cancellation,
            extension_id,
            method,
            parameters,
            self.timeout_policy,
        )
        .await
    }

    /// Uses stricter response deadlines for one admitted extension request.
    ///
    /// Both deadlines begin at actual publication. Dropping or cancelling a
    /// capacity wait publishes nothing and consumes no request ID or waiter.
    pub async fn execute_final_extension_with_timeout_policy(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        extension_id: &ExtensionId,
        method: &str,
        parameters: Value,
        timeout_policy: RequestTimeoutPolicy,
    ) -> McpResult<MemoryExtensionExecution> {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        RequestTimeoutPolicy::new(
            timeout_policy.idle_timeout(),
            timeout_policy.absolute_timeout(),
        )?;
        if timeout_policy.idle_timeout() > self.timeout_policy.idle_timeout()
            || timeout_policy.absolute_timeout() > self.timeout_policy.absolute_timeout()
        {
            return Err(McpError::invalid_params(
                "Memory execution timeout exceeds the client policy",
            ));
        }
        let admission = self
            .session
            .admit_final_extension_method(extension_id, method)?;
        // The server revalidates its full negotiated extension set on every
        // extension request. Retain an explicitly negotiated Tasks advertisement
        // here; the separate immutable result receipt still admits only this
        // custom extension's result families, never a Task result.
        #[cfg(feature = "tasks")]
        let advertise_tasks = self.tasks_active();
        #[cfg(not(feature = "tasks"))]
        let advertise_tasks = false;
        let parameters = self.parameters_with_tasks(parameters, advertise_tasks)?;
        self.execute_admitted_extension(
            cx,
            cancellation,
            method,
            parameters,
            timeout_policy,
            admission,
        )
        .await
    }

    async fn execute_admitted_extension(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        parameters: Value,
        timeout_policy: RequestTimeoutPolicy,
        admission: ClientExtensionResultAdmission,
    ) -> McpResult<MemoryExtensionExecution> {
        self.execute_admitted_extension_checked(
            cx,
            cancellation,
            method,
            parameters,
            timeout_policy,
            admission,
            || Ok(()),
        )
        .await
    }

    /// Revalidates retained operation authority at the publication boundary.
    /// A full channel may outlive authority that was valid at initial admission.
    pub(super) async fn execute_admitted_extension_checked<F>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        parameters: Value,
        timeout_policy: RequestTimeoutPolicy,
        admission: ClientExtensionResultAdmission,
        mut before_send: F,
    ) -> McpResult<MemoryExtensionExecution>
    where
        F: FnMut() -> McpResult<()>,
    {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        before_send()?;
        let next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| McpError::internal_error("Memory request IDs exhausted"))?;
        let wire = JsonRpcRequest::new(method, Some(parameters), self.next_id);
        fastmcp_transport::Codec::new()
            .encode_request(&wire)
            .map_err(transport_error_from_codec)?;
        let deadline = Instant::now() + SEND_ADMISSION_TIMEOUT;
        loop {
            self.flush_controls(cx, cancellation, deadline).await?;
            let permit = reserve_capacity(
                &mut self.sender,
                &mut self.receiver,
                &self.executor,
                &mut self.subscriptions,
                cx,
                cancellation,
                deadline,
            )
            .await?;
            before_send()?;
            if let Some(inner) = self.executor.execute_external_extension(
                cx,
                cancellation,
                wire.clone(),
                timeout_policy,
                admission.clone(),
                |message| permit.send(message),
            )? {
                self.next_id = next_id;
                return Ok(MemoryExtensionExecution {
                    owner: Arc::clone(&self.owner),
                    inner,
                    notifications: VecDeque::new(),
                    raw_result_source: None,
                    finished: false,
                });
            }
        }
    }

    /// Publishes one extension notification with fresh local activation proof.
    ///
    /// Notification metadata remains distinct from request metadata. The
    /// configured descriptor chooses the proof field; conflicting supplied
    /// proof or malformed metadata is refused before waiting for capacity.
    /// Request-shaped open metadata remains inert and grants no authority.
    /// Successful publication allocates no request ID, response waiter or
    /// correlation slot and does not wait for a response. Pending controls
    /// retain priority, while incoming responses continue to be routed during
    /// capacity waits. Cancelling or dropping an unsent wait has no wire effect.
    pub async fn notify_final_extension(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        extension_id: &ExtensionId,
        method: &str,
        parameters: Value,
    ) -> McpResult<()> {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        let parameters =
            self.session
                .prepare_final_extension_notification(extension_id, method, parameters)?;
        let wire = JsonRpcRequest::notification(method, Some(parameters));
        fastmcp_transport::Codec::new()
            .encode_request(&wire)
            .map_err(transport_error_from_codec)?;
        let deadline = Instant::now() + SEND_ADMISSION_TIMEOUT;
        loop {
            self.flush_controls(cx, cancellation, deadline).await?;
            let permit = reserve_capacity(
                &mut self.sender,
                &mut self.receiver,
                &self.executor,
                &mut self.subscriptions,
                cx,
                cancellation,
                deadline,
            )
            .await?;
            if self.executor.send_external_notification(
                cx,
                cancellation,
                wire.clone(),
                |message| permit.send(message),
            )? {
                return Ok(());
            }
        }
    }

    /// Drives this connection until one event for the selected handle is ready.
    /// Other handles retain their correlated outcomes. Dropping this *wait*
    /// preserves the execution; dropping the execution itself cancels it.
    /// A stopped current waiter retires a pending execution before buffered
    /// events are returned. An already elected terminal outcome is preserved.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        execution: &mut MemoryRequestExecution,
    ) -> McpResult<Option<MemoryRequestEvent>> {
        self.ensure_owner(execution)?;
        if execution.finished {
            return Ok(None);
        }
        loop {
            let maintenance = self.executor.poll_timeouts_at(cx, Instant::now());
            // Reconcile this waiter's lifetime before yielding buffered events.
            // Cancellation cannot replace an already elected terminal outcome.
            if checkpoint(cx, cancellation).is_err() {
                let cancelled = self.executor.cancel(cx, &mut execution.inner);
                if execution.inner.terminal_error().is_none() {
                    cancelled?;
                }
            }
            if let Some(error) = execution.inner.terminal_error() {
                execution.notifications.clear();
                execution.finished = true;
                // Consume the selected terminal receipt exactly once.
                let _ = self.executor.try_take_response(&mut execution.inner);
                return Err(error);
            }
            if let Some(notification) = execution.notifications.pop_front() {
                return Ok(Some(MemoryRequestEvent::Notification(notification)));
            }
            execution
                .notifications
                .extend(execution.inner.take_stream_notifications()?);
            if let Some(notification) = execution.notifications.pop_front() {
                return Ok(Some(MemoryRequestEvent::Notification(notification)));
            }
            if let Some((response, source)) = self
                .executor
                .try_take_response_with_raw_result(&mut execution.inner)?
            {
                execution.finished = true;
                let result = decode_response(
                    &execution.request,
                    response,
                    source.as_deref(),
                    execution.allow_tasks,
                )?;
                if let Some(diagnostic) = result.1 {
                    if self.cache_diagnostics.len() == MAX_DIAGNOSTICS {
                        self.cache_diagnostics.pop_front();
                    }
                    self.cache_diagnostics.push_back(diagnostic);
                }
                return Ok(Some(MemoryRequestEvent::Result(Box::new(result.0))));
            }
            maintenance?;
            self.ensure_open()?;
            // One drive turn always returns after a frame or maintenance
            // tick. Even a blocked cancellation write cannot hide a result
            // or timeout already elected for this selected owner.
            if let Err(error) = self.drive_once(cx, cancellation).await {
                // A failed read/write retires owners before returning its
                // driver error. Consume this owner's elected failure above,
                // preserving an earlier cancellation and exactly-once events.
                if execution.inner.terminal_error().is_some() {
                    continue;
                }
                if error.code == McpErrorCode::RequestCancelled {
                    let cancelled = self.executor.cancel(cx, &mut execution.inner);
                    if execution.inner.terminal_error().is_none() {
                        cancelled?;
                    }
                } else {
                    return Err(error);
                }
            }
        }
    }

    /// Drives the shared connection until this extension handle has one event.
    ///
    /// Results are admitted against the authority frozen before this request's
    /// publication, including ownership of non-core result discriminators.
    /// A result or terminal error is consumed once; subsequent calls return
    /// `None`. Dropping this wait preserves the execution and sibling results.
    /// A stopped current waiter retires a pending execution before buffered
    /// events are returned. An already elected terminal outcome is preserved.
    pub async fn next_extension_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        execution: &mut MemoryExtensionExecution,
    ) -> McpResult<Option<MemoryExtensionEvent>> {
        self.ensure_extension_owner(execution)?;
        if execution.finished {
            return Ok(None);
        }
        loop {
            let maintenance = self.executor.poll_timeouts_at(cx, Instant::now());
            // Reconcile this waiter's lifetime before yielding buffered events.
            // Cancellation cannot replace an already elected terminal outcome.
            if checkpoint(cx, cancellation).is_err() {
                let cancelled = self.executor.cancel(cx, &mut execution.inner);
                if execution.inner.terminal_error().is_none() {
                    cancelled?;
                }
            }
            if let Some(error) = execution.inner.terminal_error() {
                execution.notifications.clear();
                execution.finished = true;
                let _ = self.executor.try_take_response(&mut execution.inner);
                return Err(error);
            }
            if let Some(notification) = execution.notifications.pop_front() {
                return Ok(Some(MemoryExtensionEvent::Notification(notification)));
            }
            execution
                .notifications
                .extend(execution.inner.take_stream_notifications()?);
            if let Some(notification) = execution.notifications.pop_front() {
                return Ok(Some(MemoryExtensionEvent::Notification(notification)));
            }
            if let Some((response, source)) = self
                .executor
                .try_take_response_with_raw_result(&mut execution.inner)?
            {
                execution.finished = true;
                let result = response_result(response)?;
                let source = source.ok_or_else(|| {
                    McpError::invalid_request(
                        "Memory extension response omitted exact result source",
                    )
                })?;
                execution.raw_result_source = Some(source);
                return Ok(Some(MemoryExtensionEvent::Result(result)));
            }
            maintenance?;
            self.ensure_open()?;
            if let Err(error) = self.drive_once(cx, cancellation).await {
                if execution.inner.terminal_error().is_some() {
                    continue;
                }
                if error.code == McpErrorCode::RequestCancelled {
                    let cancelled = self.executor.cancel(cx, &mut execution.inner);
                    if execution.inner.terminal_error().is_none() {
                        cancelled?;
                    }
                } else {
                    return Err(error);
                }
            }
        }
    }

    /// Completes one admitted extension call without consuming sibling results.
    ///
    /// Use execute/next_extension_event to observe progress or retain the exact
    /// result source through [`MemoryExtensionExecution::raw_result_source`].
    pub async fn request_final_extension(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        extension_id: &ExtensionId,
        method: &str,
        parameters: Value,
    ) -> McpResult<Value> {
        let mut execution = self
            .execute_final_extension(cx, cancellation, extension_id, method, parameters)
            .await?;
        loop {
            match self
                .next_extension_event(cx, cancellation, &mut execution)
                .await?
            {
                Some(MemoryExtensionEvent::Result(result)) => return Ok(result),
                Some(MemoryExtensionEvent::Notification(_)) => {}
                None => {
                    return Err(McpError::internal_error(
                        "Memory extension execution ended without its result",
                    ));
                }
            }
        }
    }

    /// Completes one core call, retaining valid progress in its owned handle
    /// until consumed. Use execute/next_event to observe progress incrementally.
    pub async fn request_core(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        parameters: Value,
    ) -> McpResult<CoreResult> {
        let mut execution = self
            .execute_core(cx, cancellation, method, parameters)
            .await?;
        loop {
            match self.next_event(cx, cancellation, &mut execution).await? {
                Some(MemoryRequestEvent::Result(result)) => return Ok(*result),
                Some(MemoryRequestEvent::Notification(_)) => {}
                None => {
                    return Err(McpError::internal_error(
                        "Memory execution ended without its result",
                    ));
                }
            }
        }
    }

    /// Lists one tools page without projecting away modern result metadata.
    pub async fn list_tools(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        cursor: Option<&str>,
    ) -> McpResult<CoreResult> {
        let parameters = cursor.map_or_else(
            || serde_json::json!({}),
            |cursor| serde_json::json!({"cursor": cursor}),
        );
        self.cached_core_request(cx, cancellation, "tools/list", parameters, true)
            .await
            .map(|(result, _)| result)
    }

    /// Calls a tool, following input-required results through installed handlers.
    ///
    /// [`MemoryClientBuilder::reverse_request_handlers`] enables continuations
    /// under one originating caller and absolute operation deadline. Without
    /// modern handlers, an input-required outcome is returned directly.
    pub async fn call_tool(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        name: &str,
        arguments: Value,
    ) -> McpResult<CoreResult> {
        self.follow_installed_mrtr(
            cx,
            cancellation,
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
        )
        .await
    }

    /// Elects local cancellation without waiting for observer/peer capacity.
    /// Its control remains bounded and owned until the next drive commits it.
    pub fn cancel(&mut self, cx: &Cx, execution: &mut MemoryRequestExecution) -> McpResult<()> {
        self.ensure_owner(execution)?;
        if !execution.finished {
            self.executor.cancel(cx, &mut execution.inner)?;
        }
        Ok(())
    }

    /// Elects cancellation for one extension request without waiting for capacity.
    pub fn cancel_extension(
        &mut self,
        cx: &Cx,
        execution: &mut MemoryExtensionExecution,
    ) -> McpResult<()> {
        self.ensure_extension_owner(execution)?;
        if !execution.finished {
            self.executor.cancel(cx, &mut execution.inner)?;
        }
        Ok(())
    }

    /// Returns connection-level notifications without guessing a request owner.
    /// In particular, identifier-free logs and unmatched progress do not become
    /// another request's callback or extend any response deadline.
    pub fn take_server_notifications(&mut self) -> Vec<JsonRpcRequest> {
        self.executor.take_notifications()
    }

    /// Takes bounded local cancellation indications; these are not wire logs.
    pub fn take_cancellation_events(&mut self) -> Vec<CancellationRequested> {
        self.executor.take_cancellation_events()
    }

    /// Reports missing/negative peer cache TTLs normalized to zero freshness.
    pub fn take_cache_ttl_diagnostics(&mut self) -> Vec<FinalCacheTtlDiagnostic> {
        self.cache_diagnostics.drain(..).collect()
    }

    /// Whether complete catalog/resource results are cached on this connection.
    ///
    /// Raw `request_core` and execution handles always send their request.
    /// Tool calls, prompt retrieval, input-required results and continuations
    /// are never cached. A peer's public hint never shares an entry with a
    /// different Memory client or connection.
    #[must_use]
    pub const fn final_result_cache_enabled(&self) -> bool {
        self.subscriptions.final_result_cache.is_enabled()
    }

    /// Enables or disables high-level complete-result caching.
    ///
    /// Disabling retains entries without pausing their original expiry or
    /// notification invalidation. Use `clear_final_result_cache` to erase them.
    pub fn set_final_result_cache_enabled(&mut self, enabled: bool) {
        self.subscriptions.final_result_cache.set_enabled(enabled);
    }

    /// Returns bounded cache counters without result or parameter labels.
    #[must_use]
    pub const fn final_result_cache_stats(&self) -> FinalCacheStats {
        self.subscriptions.final_result_cache.stats()
    }

    /// Discards every complete result retained by this live connection.
    pub fn clear_final_result_cache(&mut self) {
        self.subscriptions.final_result_cache.clear();
    }

    /// Closes both channel directions and retires every request immediately.
    /// Channel closure is the cancellation boundary; queued controls are not
    /// misreported as wire sends, and a full peer queue cannot delay teardown.
    pub fn close(&mut self, cx: &Cx) -> McpResult<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.clear_final_result_cache();
        let result = self.executor.shutdown(cx);
        let receive = self.receiver.close(cx).map_err(transport_error_to_mcp);
        let send = self.sender.close(cx).map_err(transport_error_to_mcp);
        result.and(receive).and(send)
    }

    fn ensure_open(&self) -> McpResult<()> {
        if self.closed {
            return Err(McpError::internal_error("Memory client is closed"));
        }
        self.executor.terminal_error().map_or(Ok(()), Err)
    }

    /// The caller supplies only one of the high-level methods' fixed typed
    /// parameter shapes. Raw/extension requests never enter this adapter.
    async fn cached_core_request(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        parameters: Value,
        read_cache: bool,
    ) -> McpResult<(CoreResult, Option<FinalCachePageState>)> {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        let core_parameters = self.parameters_with_tasks(parameters.clone(), false)?;
        let request = CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&core_parameters))
            .map_err(|_| McpError::invalid_params("Invalid Memory cacheable request parameters"))?;
        let Some(result_set) = final_cache_result_set(&request) else {
            return self
                .request_core(cx, cancellation, method, parameters)
                .await
                .map(|result| (result, None));
        };
        let mut semantic_parameters = parameters.clone();
        let object = semantic_parameters
            .as_object_mut()
            .ok_or_else(|| McpError::invalid_params("Memory cache parameters must be an object"))?;
        let cursor = object
            .remove("cursor")
            .and_then(|cursor| cursor.as_str().map(str::to_owned));
        // High-level callers cannot inject arbitrary metadata. The framework
        // adds only immutable capabilities/extensions and observation identity;
        // those capabilities/settings are separate key dimensions below.
        object.remove("_meta");
        let key = FinalCacheKey::new(
            "memory",
            MODERN_PROTOCOL_VERSION,
            serde_json::to_string(self.session.client_capabilities())
                .map_err(|_| McpError::internal_error("Invalid Memory cache capabilities"))?,
            serde_json::to_string(&self.session.client_extension_wire_settings())
                .map_err(|_| McpError::internal_error("Invalid Memory cache extension settings"))?,
            method,
            serde_json::to_string(&semantic_parameters)
                .map_err(|_| McpError::internal_error("Invalid Memory cache parameters"))?,
            cursor,
            crate::FINAL_CACHE_POLICY_REVISION,
            crate::FINAL_CACHE_EXTENSION_REVISION,
            crate::FINAL_CACHE_REPRESENTATION_POLICY_REVISION,
            crate::FINAL_CACHE_LIMITS_POLICY_REVISION,
            // This owner is never moved to another connection or exported.
            CachePartitionKey::new("memory-client-connection"),
            result_set.clone(),
        );
        let origin = self
            .subscriptions
            .final_result_cache
            .capture_cursor_origin(&key);
        let mut miss = Some(FinalCacheMiss::Disabled);
        if read_cache {
            // Probe without counting a hit: queued invalidations may retire
            // this candidate before its one real lookup. A cold request does
            // not need an ingress drain before ordinary send admission.
            let candidate = self
                .subscriptions
                .final_result_cache
                .has_fresh_entry_at(&key, Instant::now());
            if !candidate || self.drain_ready_cache_frames(cx, cancellation).await? {
                match self
                    .subscriptions
                    .final_result_cache
                    .lookup_page_at(&key, Instant::now())
                {
                    FinalCachePageLookup::Fresh(page) => {
                        checkpoint(cx, cancellation)?;
                        return Ok((
                            page.result,
                            Some(FinalCachePageState {
                                generation: page.generation,
                                scope: page.scope,
                                miss: None,
                            }),
                        ));
                    }
                    FinalCachePageLookup::Miss(reason) => miss = Some(reason),
                }
            }
        }
        let generation = self
            .subscriptions
            .final_result_cache
            .begin_fetch(&result_set);
        let result = match self
            .request_core(cx, cancellation, method, parameters)
            .await
        {
            Ok(result) => result,
            Err(error) => {
                if error.code == McpErrorCode::InvalidParams
                    && let Some(origin) = origin
                {
                    self.subscriptions
                        .final_result_cache
                        .invalidate_rejected_cursor(origin);
                }
                return Err(error);
            }
        };
        let receipt = Instant::now();
        checkpoint(cx, cancellation)?;
        let scope = final_cache_hints(&result).map(|(_, scope)| scope);
        self.subscriptions.final_result_cache.insert_if_current_at(
            key,
            generation,
            result.clone(),
            receipt,
        );
        Ok((
            result,
            scope.map(|scope| FinalCachePageState {
                generation,
                scope,
                miss,
            }),
        ))
    }

    /// Returns true only after observing an empty live receive queue. A busy
    /// peer is bounded and forces an ordinary request instead of a cache hit.
    async fn drain_ready_cache_frames(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<bool> {
        for _ in 0..MAX_CACHE_INGRESS_FRAMES {
            checkpoint(cx, cancellation)?;
            self.executor.poll_timeouts_at(cx, Instant::now())?;
            self.ensure_open()?;
            if self.executor.has_external_controls(cx)? {
                // The ordinary send path flushes controls under its existing
                // cancellation/deadline contract before publishing new work.
                return Ok(false);
            }
            let received = {
                let mut receiving = pin!(self.receiver.recv_with_source_async(cx));
                poll_fn(|task| Poll::Ready(receiving.as_mut().poll(task))).await
            };
            match received {
                Poll::Pending => return Ok(true),
                Poll::Ready(Ok(frame)) => {
                    admit_frame(&self.executor, &mut self.subscriptions, cx, frame)?;
                }
                Poll::Ready(Err(TransportError::Cancelled)) => {
                    return Err(McpError::request_cancelled());
                }
                Poll::Ready(Err(error)) => return Err(fail_transport(&self.executor, error)),
            }
        }
        Ok(false)
    }

    fn ensure_owner(&self, execution: &MemoryRequestExecution) -> McpResult<()> {
        if !Arc::ptr_eq(&self.owner, &execution.owner) {
            return Err(McpError::invalid_params(
                "Memory execution belongs to another client",
            ));
        }
        Ok(())
    }

    fn ensure_extension_owner(&self, execution: &MemoryExtensionExecution) -> McpResult<()> {
        if !Arc::ptr_eq(&self.owner, &execution.owner) {
            return Err(McpError::invalid_params(
                "Memory extension execution belongs to another client",
            ));
        }
        Ok(())
    }

    fn parameters_with_tasks(
        &self,
        mut parameters: Value,
        advertise_tasks: bool,
    ) -> McpResult<Value> {
        let object = parameters.as_object_mut().ok_or_else(|| {
            McpError::invalid_params("Memory request parameters must be an object")
        })?;
        let mut capabilities = self.session.client_capabilities().clone();
        if !advertise_tasks
            && let Some(extensions) = &mut capabilities.extensions
        {
            extensions.remove(TASKS_EXTENSION_NAME);
        }
        #[cfg(feature = "apps")]
        if !self.session.generic_mcp_apps_configured()
            && self.session.server_discovery().is_some()
            && !self.session.mcp_apps_active()
            && let Some(extensions) = &mut capabilities.extensions
        {
            extensions.remove(
                fastmcp_protocol::extensions::official_mcp_apps_extension_id().as_str(),
            );
        }
        let mut metadata = serde_json::to_value(FinalRequestMeta {
            protocol_version: MODERN_PROTOCOL_VERSION.to_owned(),
            client_capabilities: capabilities,
            client_info: Some(self.session.modern_client_implementation()),
            additional_metadata: BTreeMap::new(),
        })
        .map_err(|_| McpError::invalid_params("Memory client metadata is invalid"))?;
        if let Some(existing) = object.remove("_meta") {
            let existing = existing.as_object().ok_or_else(|| {
                McpError::invalid_params("Memory request metadata must be an object")
            })?;
            let generated = metadata
                .as_object_mut()
                .expect("typed metadata is an object");
            for (key, value) in existing {
                generated
                    .entry(key.clone())
                    .or_insert_with(|| value.clone());
            }
        }
        object.insert("_meta".to_owned(), metadata);
        Ok(parameters)
    }

    async fn flush_controls(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Instant,
    ) -> McpResult<()> {
        while self.executor.has_external_controls(cx)? {
            let permit = reserve_capacity(
                &mut self.sender,
                &mut self.receiver,
                &self.executor,
                &mut self.subscriptions,
                cx,
                cancellation,
                deadline,
            )
            .await?;
            if let Err(error) = self
                .executor
                .commit_external_control(|message| permit.send(message))
            {
                // A successfully reserved slot's control is fixed/validated.
                // The only remaining memory commit failure is disconnection.
                self.executor.fail_connection(error.clone());
                return Err(error);
            }
        }
        Ok(())
    }

    async fn drive_once(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<()> {
        if self.executor.has_external_controls(cx)? {
            let mut sending = pin!(self.sender.reserve_send_async(cx));
            let mut receiving = pin!(self.receiver.recv_with_source_async(cx));
            let mut progress = pin!(poll_fn(|task| {
                if let Poll::Ready(result) = sending.as_mut().poll(task) {
                    return Poll::Ready(Ok(result));
                }
                receiving.as_mut().poll(task).map(Err)
            }));
            match wait_turn(cx, cancellation, None, progress.as_mut()).await? {
                Some(Ok(Ok(permit))) => {
                    if let Err(error) = self
                        .executor
                        .commit_external_control(|message| permit.send(message))
                    {
                        self.executor.fail_connection(error.clone());
                        return Err(error);
                    }
                }
                Some(
                    Ok(Err(TransportError::Cancelled)) | Err(Err(TransportError::Cancelled)),
                ) => {
                    return Err(McpError::request_cancelled());
                }
                Some(Ok(Err(error)) | Err(Err(error))) => {
                    return Err(fail_transport(&self.executor, error));
                }
                Some(Err(Ok(frame))) => {
                    admit_frame(&self.executor, &mut self.subscriptions, cx, frame)?;
                }
                None => {}
            }
        } else {
            let mut receiving = pin!(self.receiver.recv_with_source_async(cx));
            match wait_turn(cx, cancellation, None, receiving.as_mut()).await? {
                Some(Ok(frame)) => {
                    admit_frame(&self.executor, &mut self.subscriptions, cx, frame)?;
                }
                Some(Err(TransportError::Cancelled)) => return Err(McpError::request_cancelled()),
                Some(Err(error)) => return Err(fail_transport(&self.executor, error)),
                None => {}
            }
        }
        Ok(())
    }
}

impl Drop for MemoryClient {
    fn drop(&mut self) {
        if !self.closed {
            self.executor.fail_connection(McpError::request_cancelled());
        }
        // Dropping the two actual halves releases both channel directions.
        // Request handles retain only the bounded executor state, never I/O.
    }
}

fn checkpoint(cx: &Cx, cancellation: &McpRequestCancellation) -> McpResult<()> {
    if cancellation.is_cancel_requested()
        || cx
            .budget()
            .deadline
            .is_some_and(|deadline| cx.now() >= deadline)
        || cx.checkpoint().is_err()
    {
        return Err(McpError::request_cancelled());
    }
    Ok(())
}

fn transport_error_from_codec(error: fastmcp_transport::CodecError) -> McpError {
    transport_error_to_mcp(TransportError::Codec(error))
}

fn fail_transport(executor: &MemoryExecutor, error: TransportError) -> McpError {
    let error = transport_error_to_mcp(error);
    executor.fail_connection(error.clone());
    error
}

fn admit_frame(
    executor: &MemoryExecutor,
    subscriptions: &mut subscriptions::MemorySubscriptionRegistry,
    cx: &Cx,
    frame: ReceivedTransportFrame,
) -> McpResult<()> {
    executor.poll_timeouts_at(cx, Instant::now())?;
    if subscriptions.route(executor, cx, &frame)? {
        return Ok(());
    }
    subscriptions.observe_unowned_catalog_frame(&frame);
    if let Err(error) = executor.drive_frame(cx, frame) {
        executor.fail_connection(error.clone());
        return Err(error);
    }
    Ok(())
}

/// Capacity waits keep ingress live, including when both capacity-one queues
/// are full and the peer must finish sending before it can consume our write.
async fn reserve_capacity<'a>(
    sender: &'a mut MemorySendHalf,
    receiver: &mut MemoryRecvHalf,
    executor: &MemoryExecutor,
    subscriptions: &mut subscriptions::MemorySubscriptionRegistry,
    cx: &'a Cx,
    cancellation: &McpRequestCancellation,
    deadline: Instant,
) -> McpResult<MemorySendPermit<'a>> {
    let mut sending = pin!(sender.reserve_send_async(cx));
    loop {
        executor.poll_timeouts_at(cx, Instant::now())?;
        if let Some(error) = executor.terminal_error() {
            return Err(error);
        }
        let mut receiving = pin!(receiver.recv_with_source_async(cx));
        let mut progress = pin!(poll_fn(|task| {
            if let Poll::Ready(result) = sending.as_mut().poll(task) {
                return Poll::Ready(Ok(result));
            }
            receiving.as_mut().poll(task).map(Err)
        }));
        match wait_turn(cx, cancellation, Some(deadline), progress.as_mut()).await? {
            Some(Ok(Ok(permit))) => return Ok(permit),
            Some(Ok(Err(TransportError::Cancelled)) | Err(Err(TransportError::Cancelled))) => {
                return Err(McpError::request_cancelled());
            }
            Some(Ok(Err(error)) | Err(Err(error))) => {
                return Err(fail_transport(executor, error));
            }
            Some(Err(Ok(frame))) => admit_frame(executor, subscriptions, cx, frame)?,
            None => {}
        }
    }
}

/// Returns after one operation or a bounded maintenance tick. The operation
/// remains pinned by its caller across ticks, preserving channel waiter order.
async fn wait_turn<F: Future>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    deadline: Option<Instant>,
    mut operation: Pin<&mut F>,
) -> McpResult<Option<F::Output>> {
    let mut cancelled = pin!(cancellation.cancelled());
    let mut timer = None;
    poll_fn(|task| {
        if let Err(error) = checkpoint(cx, cancellation) {
            return Poll::Ready(Err(error));
        }
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(McpError::request_cancelled()));
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Err(McpError::request_cancelled()));
        }
        // Ready is an atomic channel commitment. Never turn it into a local
        // cancellation after publication or after consuming an ingress frame.
        if let Poll::Ready(result) = operation.as_mut().poll(task) {
            return Poll::Ready(Ok(Some(result)));
        }
        if cx.timer_driver().is_none()
            || !cx.capabilities().time
            || Cx::current().is_some_and(|ambient| !ambient.capabilities().time)
        {
            return Poll::Ready(Err(McpError::invalid_params(
                "Pending memory client execution requires caller time capability and timer driver",
            )));
        }
        let delay = deadline.map_or(CHECKPOINT_INTERVAL, |deadline| {
            CHECKPOINT_INTERVAL.min(deadline.saturating_duration_since(Instant::now()))
        });
        let delay = cx.budget().deadline.map_or(delay, |deadline| {
            delay.min(Duration::from_nanos(deadline.duration_since(cx.now())))
        });
        let _current = Cx::set_current(Some(cx.clone()));
        let timer = timer.get_or_insert_with(|| asupersync::time::sleep(cx.now(), delay));
        if Pin::new(timer).poll(task).is_ready() {
            return Poll::Ready(Ok(None));
        }
        Poll::Pending
    })
    .await
}

fn decode_response(
    request: &CoreRequest,
    response: JsonRpcResponse,
    source: Option<&str>,
    allow_tasks: bool,
) -> McpResult<(CoreResult, Option<FinalCacheTtlDiagnostic>)> {
    let result = response_result(response)?;
    if !allow_tasks && result.get("resultType").and_then(Value::as_str) == Some("task") {
        return Err(McpError::invalid_request(
            "Memory Task result requires an explicitly admitted Tasks tool call",
        ));
    }
    decode_core_result_with_cache_ttl_from_source(request, &result, source)
}

fn response_result(response: JsonRpcResponse) -> McpResult<Value> {
    if let Some(error) = response.error {
        let code = error
            .code
            .as_i32()
            .map(McpErrorCode::from)
            .unwrap_or(McpErrorCode::InternalError);
        return Err(match error.data {
            Some(data) => McpError::with_data(code, error.message, data),
            None => McpError::new(code, error.message),
        });
    }
    response
        .result
        .ok_or_else(|| McpError::invalid_request("Memory response omitted its result"))
}

#[cfg(test)]
mod extension_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::runtime::RuntimeBuilder;
    use fastmcp_protocol::ExactJsonValue;
    use fastmcp_transport::memory::create_memory_transport_pair_with_capacity;
    use serde_json::json;

    fn run<F: Future<Output = ()>>(test: impl FnOnce(Cx) -> F) {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            assert!(cx.blocking_pool_handle().is_none());
            asupersync::time::timeout(cx.now(), Duration::from_secs(5), test(cx))
                .await
                .expect("memory client must progress on its caller runtime");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    fn info() -> ClientInfo {
        ClientInfo {
            name: "typed-memory-client".to_owned(),
            version: "1".to_owned(),
        }
    }

    fn discovery() -> Value {
        json!({"resultType":"complete", "supportedVersions":["2026-07-28"],
            "capabilities":{}, "ttlMs":0, "cacheScope":"private"})
    }

    fn tools() -> Value {
        json!({"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"})
    }

    fn complete() -> Value {
        json!({"resultType":"complete", "content":[]})
    }

    fn response(id: i64, result: Value) -> JsonRpcMessage {
        JsonRpcMessage::Response(JsonRpcResponse::success(RequestId::Number(id), result))
    }

    async fn receive(
        cx: &Cx,
        peer: &mut MemoryTransport,
        method: &str,
        id: Option<i64>,
    ) -> JsonRpcRequest {
        let JsonRpcMessage::Request(request) = peer.recv_async(cx).await.unwrap() else {
            panic!("expected a client request");
        };
        assert_eq!(request.method, method);
        assert_eq!(request.id, id.map(RequestId::Number));
        request
    }

    async fn connected(cx: &Cx) -> (MemoryClient, MemoryTransport) {
        let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
        peer.send_async(cx, &response(1, discovery()))
            .await
            .unwrap();
        let client = MemoryClient::connect(cx, transport, info(), ClientCapabilities::default())
            .await
            .unwrap();
        let request = receive(cx, &mut peer, "server/discover", Some(1)).await;
        assert_eq!(
            request.params.unwrap()["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
            "typed-memory-client"
        );
        assert!(
            client
                .server_discovery()
                .supported_versions()
                .iter()
                .any(|version| version == "2026-07-28")
        );
        (client, peer)
    }

    async fn result(
        cx: &Cx,
        client: &mut MemoryClient,
        execution: &mut MemoryRequestExecution,
    ) -> CoreResult {
        loop {
            match client
                .next_event(cx, &McpRequestCancellation::new(), execution)
                .await
                .unwrap()
            {
                Some(MemoryRequestEvent::Result(result)) => return *result,
                Some(MemoryRequestEvent::Notification(_)) => {}
                None => panic!("execution lost its result"),
            }
        }
    }

    #[test]
    fn memory_client_operator_snapshot_uses_live_executor_and_retains_shutdown() {
        use fastmcp_core::{
            OperatorExecutorSnapshot, OperatorLifecycle, OperatorProfile, OperatorReadiness,
            OperatorReason, OperatorSnapshot,
        };

        run(|cx| async move {
            for peer_failure in [false, true] {
                let (mut client, mut peer) = connected(&cx).await;
                let initial = OperatorSnapshot::capture(&client).unwrap();
                let _: &OperatorExecutorSnapshot = &initial;
                assert_eq!(initial.profile(), OperatorProfile::Modern);
                assert_eq!(initial.lifecycle(), OperatorLifecycle::Running);
                assert_eq!(initial.readiness(), OperatorReadiness::Ready);
                assert_eq!(initial.requests().pending, 0);
                assert_eq!(initial.correlations().pending, 0);
                assert_eq!(initial.correlations().retained_terminals, 0);

                let cancellation = McpRequestCancellation::new();
                let mut first = client
                    .execute_core(&cx, &cancellation, "tools/list", json!({}))
                    .await
                    .unwrap();
                receive(&cx, &mut peer, "tools/list", Some(2)).await;
                peer.send_async(&cx, &response(2, tools())).await.unwrap();

                // The result is physically queued. Observation must leave it
                // unread and preserve the live request's admission charge.
                let queued = OperatorSnapshot::capture(&client).unwrap();
                assert_eq!(queued.requests().pending, 1);
                assert_eq!(queued.correlations().pending, 1);
                assert_eq!(queued.requests().deferred_controls, 0);
                assert!(matches!(
                    result(&cx, &mut client, &mut first).await,
                    CoreResult::Final(FinalCoreResult::ToolsList { .. })
                ));
                let completed = OperatorSnapshot::capture(&client).unwrap();
                assert_eq!(completed.requests().pending, 0);
                assert_eq!(completed.correlations().pending, 0);
                assert_eq!(completed.correlations().retained_terminals, 0);
                assert_eq!(
                    completed.correlations().tombstones,
                    initial.correlations().tombstones + 1
                );

                let mut pending = client
                    .execute_core(&cx, &cancellation, "tools/list", json!({}))
                    .await
                    .unwrap();
                receive(&cx, &mut peer, "tools/list", Some(3)).await;
                assert_eq!(
                    OperatorSnapshot::capture(&client).unwrap().requests().pending,
                    1
                );
                if peer_failure {
                    peer.close(&cx).unwrap();
                    assert!(
                        client
                            .next_event(&cx, &cancellation, &mut pending)
                            .await
                            .is_err()
                    );
                }
                client.close(&cx).unwrap();
                if !peer_failure {
                    assert!(
                        client
                            .next_event(&cx, &cancellation, &mut pending)
                            .await
                            .is_err()
                    );
                }
                assert!(
                    client
                        .next_event(&cx, &cancellation, &mut pending)
                        .await
                        .unwrap()
                        .is_none()
                );

                let stopped = OperatorSnapshot::capture(&client).unwrap();
                assert_eq!(stopped.lifecycle(), OperatorLifecycle::Stopped);
                assert_eq!(stopped.readiness(), OperatorReadiness::NotReady);
                assert_eq!(stopped.requests().pending, 0);
                assert_eq!(
                    stopped.reasons()[0],
                    Some(if peer_failure {
                        OperatorReason::ExecutorFailed
                    } else {
                        OperatorReason::ExecutorStopped
                    })
                );
                assert_eq!(
                    stopped.configuration_generation(),
                    initial.configuration_generation()
                );
                assert_eq!(initial.readiness(), OperatorReadiness::Ready);
                assert!(
                    client
                        .execute_core(&cx, &cancellation, "tools/list", json!({}))
                        .await
                        .is_err()
                );
            }
        });
    }

    #[test]
    fn memory_client_correlates_reordered_results_and_exact_request_progress() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let mut server = cx
                .spawn(move |peer_cx| async move {
                    let call = receive(&peer_cx, &mut peer, "tools/call", Some(2)).await;
                    assert_eq!(
                        call.params.unwrap()["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
                        "typed-memory-client"
                    );
                    receive(&peer_cx, &mut peer, "tools/list", Some(3)).await;
                    peer.send_async(&peer_cx, &response(3, tools()))
                        .await
                        .unwrap();
                    for token in ["foreign", "owned"] {
                        peer.send_async(
                            &peer_cx,
                            &JsonRpcMessage::Request(JsonRpcRequest::notification(
                                "notifications/progress",
                                Some(json!({"progressToken":token,"progress":1})),
                            )),
                        )
                        .await
                        .unwrap();
                    }
                    let mut payload = complete();
                    for (name, exact) in [
                        ("x-number", "1.20e+4"),
                        ("x-zero", "-0"),
                        ("x-large", "123456789012345678901234567890"),
                    ] {
                        payload[name] = Value::Number(serde_json::Number::from_string_unchecked(
                            exact.to_owned(),
                        ));
                    }
                    peer.send_async(&peer_cx, &response(2, payload))
                        .await
                        .unwrap();
                    peer
                })
                .unwrap();
            let cancellation = McpRequestCancellation::new();
            let mut call = client.execute_core(&cx, &cancellation, "tools/call", json!({
                "name":"echo", "arguments":{}, "_meta":{"progressToken":"owned", "io.modelcontextprotocol/clientInfo":{"name":"spoof","version":"9"}}
            })).await.unwrap();
            let mut list = client
                .execute_core(&cx, &cancellation, "tools/list", json!({}))
                .await
                .unwrap();
            let Some(MemoryRequestEvent::Notification(progress)) = client
                .next_event(&cx, &cancellation, &mut call)
                .await
                .unwrap()
            else {
                panic!("matching progress precedes its final result");
            };
            assert_eq!(progress.params.unwrap()["progressToken"], "owned");
            assert!(matches!(
                result(&cx, &mut client, &mut list).await,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            let CoreResult::Final(FinalCoreResult::ToolsCall {
                result: call_result,
                ..
            }) = result(&cx, &mut client, &mut call).await
            else {
                panic!("typed tool result");
            };
            for (name, exact) in [
                ("x-number", "1.20e+4"),
                ("x-zero", "-0"),
                ("x-large", "123456789012345678901234567890"),
            ] {
                assert_eq!(
                    call_result
                        .extras
                        .members()
                        .iter()
                        .find(|member| member.name == name)
                        .unwrap()
                        .value,
                    ExactJsonValue::Number(exact.to_owned())
                );
            }
            let unmatched = client.take_server_notifications();
            assert_eq!(unmatched.len(), 1);
            assert_eq!(
                unmatched[0].params.as_ref().unwrap()["progressToken"],
                "foreign"
            );
            assert!(
                client
                    .next_event(&cx, &cancellation, &mut call)
                    .await
                    .unwrap()
                    .is_none()
            );
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_drains_ingress_while_both_capacity_one_directions_are_full() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let cancellation = McpRequestCancellation::new();
            let mut first = client
                .execute_core(&cx, &cancellation, "tools/list", json!({}))
                .await
                .unwrap();
            // Client-to-peer now holds request 2; peer-to-client holds a log.
            peer.send_async(
                &cx,
                &JsonRpcMessage::Request(JsonRpcRequest::notification(
                    "notifications/message",
                    Some(json!({"level":"info","data":"before read"})),
                )),
            )
            .await
            .unwrap();
            let mut server = cx
                .spawn(move |peer_cx| async move {
                    // Deliberately finish writing before reading another request.
                    // A send-only capacity waiter deadlocks this exact peer.
                    peer.send_async(&peer_cx, &response(2, tools()))
                        .await
                        .unwrap();
                    receive(&peer_cx, &mut peer, "tools/list", Some(2)).await;
                    receive(&peer_cx, &mut peer, "tools/list", Some(3)).await;
                    peer.send_async(&peer_cx, &response(3, tools()))
                        .await
                        .unwrap();
                    peer
                })
                .unwrap();
            let mut second = client
                .execute_core(&cx, &cancellation, "tools/list", json!({}))
                .await
                .unwrap();
            assert!(matches!(
                result(&cx, &mut client, &mut second).await,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            assert!(matches!(
                result(&cx, &mut client, &mut first).await,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            assert_eq!(client.take_server_notifications().len(), 1);
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_rejects_reverse_requests_after_real_capacity_without_losing_owners() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let live = McpRequestCancellation::new();
            let mut first = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            let original = client.executor.pending_records();
            // The peer's opposite-direction ID has the same mathematical
            // value as our active ID, but its exact spelling must be echoed.
            let reverse_id = RequestId::Integer("2.00".to_owned());
            peer.send_async(
                &cx,
                &JsonRpcMessage::Request(JsonRpcRequest::new(
                    "roots/list",
                    Some(json!({})),
                    reverse_id.clone(),
                )),
            )
            .await
            .unwrap();
            {
                // The actual outbound slot still holds request 2. Dropping
                // this capacity-blocked wait must preserve the queued reply.
                let mut waiting = pin!(client.next_event(&cx, &live, &mut first));
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
            }
            assert_eq!(client.executor.pending_records(), original);
            assert!(client.executor.has_external_controls(&cx).unwrap());
            assert!(client.executor.terminal_error().is_none());
            assert_eq!(client.next_id, 3);
            assert!(client.take_cancellation_events().is_empty());

            let mut server = cx
                .spawn(move |peer_cx| async move {
                    receive(&peer_cx, &mut peer, "tools/list", Some(2)).await;
                    let JsonRpcMessage::Response(rejection) =
                        peer.recv_async(&peer_cx).await.unwrap()
                    else {
                        panic!("the reverse request receives an error response before new work");
                    };
                    assert_eq!(rejection.id, Some(reverse_id));
                    assert!(rejection.result.is_none());
                    assert_eq!(
                        rejection.error.as_ref().unwrap().code.as_i32(),
                        Some(-32601)
                    );
                    // A duplicate rejection or cancellation would fail this read.
                    receive(&peer_cx, &mut peer, "tools/list", Some(3)).await;
                    peer.send_async(&peer_cx, &response(3, tools()))
                        .await
                        .unwrap();
                    peer.send_async(&peer_cx, &response(2, tools()))
                        .await
                        .unwrap();
                    peer
                })
                .unwrap();
            let mut sibling = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            assert_eq!(sibling.request_id(), &RequestId::Number(3));
            assert!(matches!(
                result(&cx, &mut client, &mut first).await,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            assert!(matches!(
                result(&cx, &mut client, &mut sibling).await,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            assert!(!client.executor.has_external_controls(&cx).unwrap());
            assert!(client.executor.terminal_error().is_none());
            assert!(client.take_cancellation_events().is_empty());
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_unsent_cancellation_drop_and_invalid_input_spend_no_ids() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let live = McpRequestCancellation::new();
            let mut first = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            let original = client.executor.pending_records();
            for (method, parameters) in [
                ("initialize", json!({})),
                ("tools/list", json!({"_meta":[]})),
            ] {
                assert_eq!(
                    client
                        .execute_core(&cx, &live, method, parameters)
                        .await
                        .unwrap_err()
                        .code,
                    McpErrorCode::InvalidParams
                );
                assert_eq!(client.next_id, 3);
                assert_eq!(client.executor.pending_records(), original);
            }
            for drop_wait in [false, true] {
                let cancellation = McpRequestCancellation::new();
                {
                    let mut sending =
                        pin!(client.execute_core(&cx, &cancellation, "tools/list", json!({})));
                    poll_fn(|task| {
                        assert!(sending.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    if !drop_wait {
                        cancellation.cancel();
                        assert_eq!(
                            sending.await.unwrap_err().code,
                            McpErrorCode::RequestCancelled
                        );
                    }
                }
                assert_eq!(client.next_id, 3);
                assert_eq!(client.executor.pending_records(), original);
                assert!(!client.executor.has_external_controls(&cx).unwrap());
            }
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            peer.send_async(&cx, &response(2, tools())).await.unwrap();
            assert!(matches!(
                result(&cx, &mut client, &mut first).await,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            let mut next = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(3)).await;
            peer.send_async(&cx, &response(3, tools())).await.unwrap();
            result(&cx, &mut client, &mut next).await;
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_dropped_and_original_token_cancelled_owners_do_not_poison_siblings() {
        run(|cx| async move {
            for mode in ["drop", "token", "explicit"] {
                let (mut client, mut peer) = connected(&cx).await;
                let first_token = McpRequestCancellation::new();
                let mut first = Some(
                    client
                        .execute_core(&cx, &first_token, "tools/list", json!({}))
                        .await
                        .unwrap(),
                );
                match mode {
                    "drop" => {
                        drop(first.take());
                    }
                    "token" => {
                        first_token.cancel();
                    }
                    _ => {
                        client.cancel(&cx, first.as_mut().unwrap()).unwrap();
                    }
                }
                // Attempting a new send must retain the unsent cancellation
                // control when the real outbound queue is still full.
                let live = McpRequestCancellation::new();
                {
                    let mut sending =
                        pin!(client.execute_core(&cx, &live, "tools/list", json!({})));
                    poll_fn(|task| {
                        assert!(sending.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                }
                assert_eq!(client.next_id, 3);
                assert!(client.executor.has_external_controls(&cx).unwrap());
                let mut server = cx
                    .spawn(move |peer_cx| async move {
                        receive(&peer_cx, &mut peer, "tools/list", Some(2)).await;
                        let cancel =
                            receive(&peer_cx, &mut peer, "notifications/cancelled", None).await;
                        assert_eq!(cancel.params.unwrap()["requestId"], 2);
                        receive(&peer_cx, &mut peer, "tools/list", Some(3)).await;
                        peer.send_async(&peer_cx, &response(2, tools()))
                            .await
                            .unwrap();
                        peer.send_async(&peer_cx, &response(3, tools()))
                            .await
                            .unwrap();
                        peer
                    })
                    .unwrap();
                let mut sibling = client
                    .execute_core(&cx, &live, "tools/list", json!({}))
                    .await
                    .unwrap();
                result(&cx, &mut client, &mut sibling).await;
                if let Some(first) = first.as_mut() {
                    // A new wait token cannot revive the old creating token.
                    assert_eq!(
                        client.next_event(&cx, &live, first).await.unwrap_err().code,
                        McpErrorCode::RequestCancelled
                    );
                }
                assert_eq!(client.take_cancellation_events().len(), 1);
                assert!(!client.executor.has_external_controls(&cx).unwrap());
                let _peer = server.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_client_response_timeout_is_observable_without_peer_or_watchdog_wake() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let live = McpRequestCancellation::new();
            let mut silent = client
                .execute_core_with_timeout_policy(
                    &cx,
                    &live,
                    "tools/list",
                    json!({}),
                    RequestTimeoutPolicy::new(
                        Duration::from_millis(40),
                        Duration::from_millis(100),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            let started = Instant::now();
            assert_eq!(
                client
                    .next_event(&cx, &live, &mut silent)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::RequestCancelled
            );
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "outer watchdog cannot supply the missing wake"
            );
            assert!(!live.is_cancel_requested());
            assert_eq!(
                client.take_cancellation_events()[0].reason,
                crate::ExecutionTerminalReason::IdleTimeout
            );
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_original_token_cancels_while_an_already_committed_sibling_is_driven() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let original = McpRequestCancellation::new();
            let live = McpRequestCancellation::new();
            let mut first = client
                .execute_core(&cx, &original, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            let mut sibling = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(3)).await;
            original.cancel();
            let mut server = cx
                .spawn(move |peer_cx| async move {
                    // The late response races cancellation while a different
                    // handle, with a different token, owns the read operation.
                    peer.send_async(&peer_cx, &response(2, tools()))
                        .await
                        .unwrap();
                    peer.send_async(&peer_cx, &response(3, tools()))
                        .await
                        .unwrap();
                    let cancelled =
                        receive(&peer_cx, &mut peer, "notifications/cancelled", None).await;
                    assert_eq!(cancelled.params.unwrap()["requestId"], 2);
                    peer
                })
                .unwrap();
            result(&cx, &mut client, &mut sibling).await;
            assert_eq!(
                client
                    .next_event(&cx, &live, &mut first)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::RequestCancelled
            );
            assert!(!live.is_cancel_requested());
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_returns_input_required_and_only_sends_an_explicit_continuation() {
        run(|cx| async move {
            let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
            peer.send_async(&cx, &response(1, discovery()))
                .await
                .unwrap();
            let capabilities: ClientCapabilities =
                serde_json::from_value(json!({"roots":{}})).unwrap();
            let mut client = MemoryClient::connect(&cx, transport, info(), capabilities)
                .await
                .unwrap();
            receive(&cx, &mut peer, "server/discover", Some(1)).await;
            let live = McpRequestCancellation::new();
            let mut call = client
                .execute_core(
                    &cx,
                    &live,
                    "tools/call",
                    json!({"name":"interactive","arguments":{}}),
                )
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/call", Some(2)).await;
            peer.send_async(&cx, &response(2, json!({"resultType":"input_required", "inputRequests":{"roots":{"method":"roots/list"}}, "requestState":"round-1"}))).await.unwrap();
            let CoreResult::Final(FinalCoreResult::ToolsCallInputRequired {
                result: required, ..
            }) = result(&cx, &mut client, &mut call).await
            else {
                panic!("caller receives the typed continuation branch");
            };
            assert_eq!(required.request_state(), Some("round-1"));
            assert_eq!(
                client.next_id, 3,
                "input-required does not cause an implicit retry"
            );
            assert!(client.executor.pending_records().is_empty());
            let mut continuation = client.execute_core(&cx, &live, "tools/call", json!({
                "name":"interactive", "arguments":{}, "requestState":"round-1", "inputResponses":{"roots":{"roots":[]}}
            })).await.unwrap();
            let retry = receive(&cx, &mut peer, "tools/call", Some(3)).await;
            assert_eq!(
                retry.params.unwrap()["inputResponses"],
                json!({"roots":{"roots":[]}})
            );
            peer.send_async(&cx, &response(3, complete()))
                .await
                .unwrap();
            assert!(matches!(
                result(&cx, &mut client, &mut continuation).await,
                CoreResult::Final(FinalCoreResult::ToolsCall { .. })
            ));
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_caller_deadline_interrupts_full_queue_before_publication() {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            // The current-thread root is a registered obligation holder;
            // a request-only Cx cannot commit the setup messages.
            let healthy = Cx::current().unwrap();
            asupersync::time::timeout(healthy.now(), Duration::from_secs(3), async {
                let (mut client, mut peer) = connected(&healthy).await;
                let live = McpRequestCancellation::new();
                let first = client
                    .execute_core(&healthy, &live, "tools/list", json!({}))
                    .await
                    .unwrap();
                let before = client.executor.pending_records();
                let limited = runtime.request_cx_with_budget(
                    asupersync::Budget::INFINITE
                        .with_deadline(healthy.now().saturating_add_nanos(40_000_000)),
                );
                let started = Instant::now();
                assert_eq!(
                    client
                        .execute_core(&limited, &live, "tools/list", json!({}))
                        .await
                        .unwrap_err()
                        .code,
                    McpErrorCode::RequestCancelled
                );
                assert!(started.elapsed() < Duration::from_secs(1));
                assert!(!live.is_cancel_requested());
                assert_eq!(client.next_id, 3);
                assert_eq!(client.executor.pending_records(), before);
                receive(&healthy, &mut peer, "tools/list", Some(2)).await;
                client.close(&healthy).unwrap();
                drop(first);
            })
            .await
            .unwrap();
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn memory_client_bad_typed_result_and_foreign_handle_leave_healthy_owner_usable() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let (mut other, _other_peer) = connected(&cx).await;
            let live = McpRequestCancellation::new();
            let mut bad = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            assert_eq!(
                other
                    .next_event(&cx, &live, &mut bad)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::InvalidParams
            );
            assert_eq!(
                other.cancel(&cx, &mut bad).unwrap_err().code,
                McpErrorCode::InvalidParams
            );
            assert_eq!(client.executor.pending_records().len(), 1);
            peer.send_async(&cx, &response(2, json!({"resultType":"complete","tools":"wrong","ttlMs":0,"cacheScope":"private"}))).await.unwrap();
            assert_eq!(
                client
                    .next_event(&cx, &live, &mut bad)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::InvalidRequest
            );
            let mut good = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(3)).await;
            peer.send_async(&cx, &response(3, tools())).await.unwrap();
            result(&cx, &mut client, &mut good).await;
            client.close(&cx).unwrap();
            other.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_closed_peer_releases_all_handles_and_close_never_waits_for_capacity() {
        run(|cx| async move {
            for local_close in [false, true] {
                let (mut client, mut peer) = connected(&cx).await;
                let live = McpRequestCancellation::new();
                let mut first = client
                    .execute_core(&cx, &live, "tools/list", json!({}))
                    .await
                    .unwrap();
                receive(&cx, &mut peer, "tools/list", Some(2)).await;
                let mut second = client
                    .execute_core(&cx, &live, "tools/list", json!({}))
                    .await
                    .unwrap();
                let started = Instant::now();
                if local_close {
                    client.close(&cx).unwrap();
                    assert!(started.elapsed() < Duration::from_millis(100));
                } else {
                    peer.close(&cx).unwrap();
                }
                assert!(client.next_event(&cx, &live, &mut first).await.is_err());
                assert!(
                    client
                        .next_event(&cx, &live, &mut first)
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(client.next_event(&cx, &live, &mut second).await.is_err());
                assert!(
                    client
                        .next_event(&cx, &live, &mut second)
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(client.executor.pending_records().is_empty());
                let next = client.next_id;
                assert!(
                    client
                        .execute_core(&cx, &live, "tools/list", json!({}))
                        .await
                        .is_err()
                );
                assert_eq!(client.next_id, next);
            }
        });
    }

    #[test]
    fn memory_client_original_cancellation_wins_peer_loss_and_is_consumed_once() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let original = McpRequestCancellation::new();
            let live = McpRequestCancellation::new();
            let mut execution = client
                .execute_core(&cx, &original, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            {
                let mut waiting = pin!(client.next_event(&cx, &live, &mut execution));
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
                // The live observer is already inside the read operation.
                // Connection failure must inspect the original owner's token,
                // then report its cancellation instead of the raw read error.
                original.cancel();
                peer.close(&cx).unwrap();
                assert_eq!(
                    waiting.await.unwrap_err().code,
                    McpErrorCode::RequestCancelled
                );
            }
            assert!(!live.is_cancel_requested());
            assert!(execution.inner.terminal_error().is_none());
            assert!(client.executor.terminal_error().is_some());
            assert!(client.executor.pending_records().is_empty());
            for _ in 0..2 {
                assert!(
                    client
                        .next_event(&cx, &live, &mut execution)
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_current_waiter_cancellation_precedes_buffered_progress() {
        run(|cx| async move {
            for handle_buffered in [false, true] {
                for terminal_before_wait in [false, true] {
                    for cause in ["live", "token", "caller", "deadline"] {
                        let (mut client, mut peer) = connected(&cx).await;
                        let original = McpRequestCancellation::new();
                        let live = McpRequestCancellation::new();
                        let observer = McpRequestCancellation::new();
                        let mut owner = client
                            .execute_core(
                                &cx,
                                &original,
                                "tools/list",
                                json!({"_meta":{"progressToken":"buffered"}}),
                            )
                            .await
                            .unwrap();
                        receive(&cx, &mut peer, "tools/list", Some(2)).await;
                        let mut sibling = client
                            .execute_core(&cx, &live, "tools/list", json!({}))
                            .await
                            .unwrap();
                        receive(&cx, &mut peer, "tools/list", Some(3)).await;
                        for progress in [1, 2] {
                            peer.send_async(
                                &cx,
                                &JsonRpcMessage::Request(JsonRpcRequest::notification(
                                    "notifications/progress",
                                    Some(json!({"progressToken":"buffered","progress":progress})),
                                )),
                            )
                            .await
                            .unwrap();
                            client.drive_once(&cx, &live).await.unwrap();
                        }
                        if handle_buffered {
                            assert!(matches!(
                                client.next_event(&cx, &live, &mut owner).await.unwrap(),
                                Some(MemoryRequestEvent::Notification(_))
                            ));
                        }
                        if terminal_before_wait {
                            peer.send_async(&cx, &response(2, tools())).await.unwrap();
                            client.drive_once(&cx, &live).await.unwrap();
                        }
                        let waiter = match cause {
                            "caller" => {
                                let stopped = Cx::for_testing();
                                stopped.set_cancel_requested(true);
                                stopped
                            }
                            "deadline" => Cx::for_testing_with_budget(
                                asupersync::Budget::new().with_deadline(asupersync::Time::ZERO),
                            ),
                            _ => cx.clone(),
                        };
                        if cause == "token" {
                            assert!(observer.cancel());
                        }
                        let event = client.next_event(&waiter, &observer, &mut owner).await;
                        if cause == "live" || terminal_before_wait {
                            assert!(matches!(
                                event.unwrap(),
                                Some(MemoryRequestEvent::Notification(_))
                            ));
                            if !terminal_before_wait {
                                peer.send_async(&cx, &response(2, tools())).await.unwrap();
                            }
                            assert!(matches!(
                                result(&cx, &mut client, &mut owner).await,
                                CoreResult::Final(FinalCoreResult::ToolsList { .. })
                            ));
                            assert!(client.take_cancellation_events().is_empty());
                        } else {
                            assert_eq!(
                                event.unwrap_err().code,
                                McpErrorCode::RequestCancelled,
                                "{cause}"
                            );
                            assert!(
                                client
                                    .next_event(&waiter, &observer, &mut owner)
                                    .await
                                    .unwrap()
                                    .is_none()
                            );
                            assert!(owner.notifications.is_empty());
                            let events = client.take_cancellation_events();
                            assert_eq!(events.len(), 1);
                            assert_eq!(events[0].request_id, RequestId::Number(2));
                            assert_eq!(
                                events[0].reason,
                                crate::ExecutionTerminalReason::CallerCancelled
                            );
                            client.drive_once(&cx, &live).await.unwrap();
                            let control =
                                receive(&cx, &mut peer, "notifications/cancelled", None).await;
                            assert_eq!(control.params.unwrap()["requestId"], 2);
                        }
                        peer.send_async(&cx, &response(3, tools())).await.unwrap();
                        assert!(matches!(
                            result(&cx, &mut client, &mut sibling).await,
                            CoreResult::Final(FinalCoreResult::ToolsList { .. })
                        ));
                        assert!(!original.is_cancel_requested());
                        assert!(!live.is_cancel_requested());
                        assert!(cx.checkpoint().is_ok());
                        assert!(client.executor.terminal_error().is_none());
                        client.close(&cx).unwrap();
                    }
                }
            }
        });
    }

    #[test]
    fn memory_client_control_saturation_preserves_and_consumes_elected_cancellation() {
        run(|cx| async move {
            for mode in ["original", "observer-before-wait", "observer-after-pending"] {
                let (mut client, _peer) = connected(&cx).await;
                let original = McpRequestCancellation::new();
                let observer = McpRequestCancellation::new();
                let mut execution = client
                    .execute_core(&cx, &original, "tools/list", json!({}))
                    .await
                    .unwrap();
                let source = serde_json::to_vec(&JsonRpcMessage::Request(JsonRpcRequest::new(
                    "roots/list",
                    Some(json!({})),
                    2,
                )))
                .unwrap();
                // Fill only the bounded external rejection allowance, leaving
                // the ordinary owner active and the actual send queue untouched.
                for _ in 0..crate::execution::DEFAULT_MAX_IN_FLIGHT_EXECUTIONS {
                    client
                        .executor
                        .drive_frame(&cx, ReceivedTransportFrame::admit(source.clone()).unwrap())
                        .unwrap();
                }
                assert!(client.executor.terminal_error().is_none());
                assert_eq!(client.executor.pending_records().len(), 1);
                let error = if mode == "observer-after-pending" {
                    let mut waiting = pin!(client.next_event(&cx, &observer, &mut execution));
                    poll_fn(|task| {
                        assert!(waiting.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    observer.cancel();
                    waiting.await.unwrap_err()
                } else {
                    if mode == "original" {
                        original.cancel();
                    } else {
                        observer.cancel();
                    }
                    client
                        .next_event(&cx, &observer, &mut execution)
                        .await
                        .unwrap_err()
                };
                // Each cancellation path elects the owner's outcome before
                // its additional control overflows the shared queue.
                assert_eq!(error.code, McpErrorCode::RequestCancelled, "{mode}");
                assert_eq!(original.is_cancel_requested(), mode == "original");
                assert!(client.executor.terminal_error().is_some());
                assert!(execution.inner.terminal_error().is_none());
                assert!(
                    client
                        .next_event(&cx, &observer, &mut execution)
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(!client.executor.has_external_controls(&cx).unwrap());
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_client_retained_success_wins_sibling_cancellation_control_overflow() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let live = McpRequestCancellation::new();
            let stopped = McpRequestCancellation::new();
            let mut completed = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            let mut sibling = client
                .execute_core(&cx, &stopped, "tools/list", json!({}))
                .await
                .unwrap();
            // Model a successful response already routed while a sibling
            // drove ingress, but not yet consumed by its selected owner.
            let completed_source = serde_json::to_vec(&response(2, tools())).unwrap();
            client
                .executor
                .drive_frame(
                    &cx,
                    ReceivedTransportFrame::admit(completed_source).unwrap(),
                )
                .unwrap();
            let rejection_source = serde_json::to_vec(&JsonRpcMessage::Request(
                JsonRpcRequest::new("roots/list", Some(json!({})), 2),
            ))
            .unwrap();
            for _ in 0..crate::execution::DEFAULT_MAX_IN_FLIGHT_EXECUTIONS {
                client
                    .executor
                    .drive_frame(
                        &cx,
                        ReceivedTransportFrame::admit(rejection_source.clone()).unwrap(),
                    )
                    .unwrap();
            }
            stopped.cancel();
            assert!(matches!(
                result(&cx, &mut client, &mut completed).await,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            assert!(
                client
                    .next_event(&cx, &live, &mut completed)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(client.executor.terminal_error().is_some());
            assert_eq!(
                client
                    .next_event(&cx, &live, &mut sibling)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::RequestCancelled
            );
            assert!(
                client
                    .next_event(&cx, &live, &mut sibling)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(client.executor.pending_records().is_empty());
            assert!(!client.executor.has_external_controls(&cx).unwrap());
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_discovery_rejects_legacy_without_sending_initialize() {
        run(|cx| async move {
            let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
            let mut peer_discovery = discovery();
            peer_discovery["supportedVersions"] = json!(["2024-11-05"]);
            peer.send_async(&cx, &response(1, peer_discovery))
                .await
                .unwrap();
            assert!(
                MemoryClient::connect(&cx, transport, info(), ClientCapabilities::default())
                    .await
                    .is_err()
            );
            receive(&cx, &mut peer, "server/discover", Some(1)).await;
            assert!(matches!(
                peer.recv_async(&cx).await,
                Err(TransportError::Closed)
            ));
        });
    }
}
