//! Handler traits for tools, resources, and prompts.
//!
//! Handlers support both synchronous and asynchronous execution patterns:
//!
//! - **Sync handlers**: Implement `call()`, `read()`, or `get()` directly
//! - **Async handlers**: Override `call_async()`, `read_async()`, or `get_async()`
//!
//! The router always calls the async variants, which by default delegate to
//! the sync versions. This allows gradual migration to async without breaking
//! existing code.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::{
    McpContext, McpError, McpOutcome, McpResult, NotificationSender, Outcome, ProgressReporter,
    SessionState,
};
use fastmcp_protocol::common_types::ExactNonNegativeJsonNumber;
use fastmcp_protocol::common_types::{
    AbsoluteUri, Annotations, ContentBlock, EmbeddedResourceContents, OpenMetadata, RawIcon,
};
use fastmcp_protocol::{
    CacheScope, CacheTtl, CompleteResult, CompletionValues, Content, CoreResultDiscriminatorPolicy,
    DecodedResult, FinalCallToolResult, FinalCompletionParams, FinalCompletionValues,
    FinalGetPromptResult, FinalProgressNotificationParams, FinalPrompt, FinalPromptMessage,
    FinalReadResourceResult, FinalResource, FinalResourceTemplate, FinalTool, Icon,
    InputRequiredResult, JsonRpcRequest, LegacyCompletionParams, ProgressMarker, ProgressParams,
    Prompt, PromptMessage, Resource, ResourceContent, ResourceTemplate, ResultMeta, ResultPeerEra,
    Tool, ToolAnnotations, decode_peer_result, encode_result,
};

use crate::bidirectional::MrtrCompletedInputs;
#[cfg(feature = "proxy")]
use crate::proxy::ProxyClient;
#[cfg(feature = "tasks")]
use crate::tasks::FinalTaskWorkDescriptor;

// ============================================================================
// Final resource URI-use admission
// ============================================================================

/// The final server emission site for one locally authored resource identity.
///
/// This is deliberately narrower than structural [`AbsoluteUri`] admission:
/// a syntactically valid URI does not by itself grant authority to advertise
/// it as a client-direct resource or embed it as server-mediated content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinalResourceUriUse {
    /// A resource identity in `resources/list`.
    CatalogResource,
    /// A resource-template identity in `resources/templates/list`.
    CatalogTemplate,
    /// The target of a locally handled `resources/read` request.
    ResourceReadTarget,
    /// One embedded resource identity in a `resources/read` complete result.
    ResourceReadContents,
    /// A `resource_link` authored in a final prompt result.
    PromptResourceLink,
    /// An embedded resource authored in a final prompt result.
    PromptEmbeddedResource,
}

/// Policy governing locally authored final resource identities.
///
/// The default keeps every URI server-mediated. An application must opt in
/// explicitly before an HTTPS identity can be advertised as a client-direct
/// resource or linked from a prompt. HTTPS identities are never admitted for
/// server-side `resources/read` handling or embedded resource payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ResourceUriUsePolicy {
    client_direct_https: bool,
}

impl ResourceUriUsePolicy {
    /// Creates the safe default policy for server-mediated resource identities.
    #[must_use]
    pub(crate) const fn server_mediated() -> Self {
        Self {
            client_direct_https: false,
        }
    }

    /// Builds the policy from the public handler declaration.
    #[must_use]
    pub(crate) const fn from_client_direct_https(client_direct_https: bool) -> Self {
        Self {
            client_direct_https,
        }
    }

    /// Returns whether one final URI is admitted at this exact local use site.
    #[must_use]
    pub(crate) fn admits(self, uri: &AbsoluteUri, use_site: FinalResourceUriUse) -> bool {
        if !uri.has_scheme("https") {
            return true;
        }
        self.client_direct_https
            && matches!(
                use_site,
                FinalResourceUriUse::CatalogResource
                    | FinalResourceUriUse::CatalogTemplate
                    | FinalResourceUriUse::PromptResourceLink
            )
    }

    /// Returns whether a final resource template is admitted at its catalog
    /// use site. Template syntax is validated separately before this policy
    /// check; only the RFC 3986 scheme classification is relevant here.
    #[must_use]
    pub(crate) fn admits_template(self, uri_template: &str) -> bool {
        let uses_https = uri_template
            .split_once(':')
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"));
        !uses_https || self.client_direct_https
    }
}

// ============================================================================
// Progress Notification Sender
// ============================================================================

/// One request-owned final-progress staging runtime.
///
/// The runtime fixes its progress marker at construction, remembers the
/// greatest admitted exact progress value, and retains at most one newer
/// notification until a transport-owned rate tick or terminal response calls
/// [`Self::flush_pending`] or [`Self::finalize`]. It intentionally does not
/// elect the request's transport terminal: that authority remains with the
/// outer server dispatch path.
pub(crate) struct FinalProgressRuntime<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    marker: ProgressMarker,
    send_fn: F,
    state: Mutex<FinalProgressRuntimeState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FinalProgressRuntimePhase {
    Open,
    Finalizing,
    Cancelled,
}

struct FinalProgressRuntimeState {
    phase: FinalProgressRuntimePhase,
    last_accepted_progress: Option<ExactNonNegativeJsonNumber>,
    pending: Option<JsonRpcRequest>,
}

impl Default for FinalProgressRuntimeState {
    fn default() -> Self {
        Self {
            phase: FinalProgressRuntimePhase::Open,
            last_accepted_progress: None,
            pending: None,
        }
    }
}

impl<F> FinalProgressRuntime<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    /// Creates an open runtime for one admitted final request marker.
    #[must_use]
    pub(crate) fn new(marker: ProgressMarker, send_fn: F) -> Self {
        Self {
            marker,
            send_fn,
            state: Mutex::new(FinalProgressRuntimeState::default()),
        }
    }

    /// Creates the handler-facing reporter while retaining the runtime in the
    /// outer request owner for later flushing or terminal finalization.
    pub(crate) fn into_reporter(self: Arc<Self>) -> ProgressReporter
    where
        Self: 'static,
    {
        ProgressReporter::new(self)
    }

    /// Emits the newest pending progress notification, if the request remains
    /// open. A future transport rate timer owns when to invoke this primitive.
    ///
    /// Returns `true` only when a queued notification was committed to the
    /// callback. Cancellation and finalization discard no additional frames.
    pub(crate) fn flush_pending(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.phase != FinalProgressRuntimePhase::Open {
            return false;
        }
        self.emit_pending_locked(&mut state)
    }

    /// Claims this runtime's terminal side of the final-progress race.
    ///
    /// The winner flushes its one coalesced pending update before the outer
    /// request owner writes the JSON-RPC terminal response. Returns `false`
    /// when cancellation had already won.
    pub(crate) fn finalize(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.phase != FinalProgressRuntimePhase::Open {
            return false;
        }
        state.phase = FinalProgressRuntimePhase::Finalizing;
        self.emit_pending_locked(&mut state);
        true
    }

    /// Cancels this progress runtime and discards its coalesced notification.
    ///
    /// Returns `true` only when cancellation won before finalization.
    pub(crate) fn cancel(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.phase != FinalProgressRuntimePhase::Open {
            return false;
        }
        state.phase = FinalProgressRuntimePhase::Cancelled;
        state.pending = None;
        true
    }

    fn enqueue_exact(
        &self,
        progress: ExactNonNegativeJsonNumber,
        total: Option<ExactNonNegativeJsonNumber>,
        message: Option<&str>,
    ) {
        let params = FinalProgressNotificationParams {
            progress_token: self.marker.clone(),
            progress: progress.clone(),
            total,
            message: message.map(str::to_owned),
            meta: None,
            additional: BTreeMap::new(),
        };
        let Ok(serialized_params) = serde_json::to_value(params) else {
            log::warn!(
                target: "fastmcp_rust::handler",
                "final progress notification rejected; reason=serialization_failure"
            );
            return;
        };
        let notification =
            JsonRpcRequest::notification("notifications/progress", Some(serialized_params));

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.phase != FinalProgressRuntimePhase::Open {
            return;
        }
        if state
            .last_accepted_progress
            .as_ref()
            .is_some_and(|last| progress.cmp(last).is_le())
        {
            log::debug!(
                target: "fastmcp_rust::handler",
                "final progress notification rejected; reason=non_monotonic_progress"
            );
            return;
        }
        state.last_accepted_progress = Some(progress);
        // A newer admissible value replaces, rather than grows, the one-slot
        // queue. The latest value is therefore what rate flush/finalization
        // observes.
        state.pending = Some(notification);
    }

    fn emit_pending_locked(&self, state: &mut FinalProgressRuntimeState) -> bool {
        let Some(notification) = state.pending.take() else {
            return false;
        };
        if crate::catch_extension_unwind(|| (self.send_fn)(notification)).is_err() {
            log::error!(
                target: "fastmcp_rust::handler",
                "progress notification callback terminated unexpectedly; detail=panic_payload_redacted"
            );
        }
        true
    }
}

impl<F> NotificationSender for FinalProgressRuntime<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    fn send_progress_exact(
        &self,
        progress: serde_json::Number,
        total: Option<serde_json::Number>,
        message: Option<&str>,
    ) {
        let progress = match ExactNonNegativeJsonNumber::try_from_number(progress) {
            Ok(progress) => progress,
            Err(_) => {
                log::warn!(
                    target: "fastmcp_rust::handler",
                    "final progress notification rejected; reason=invalid_finite_numeric_value"
                );
                return;
            }
        };
        let total = match total {
            Some(total) => match ExactNonNegativeJsonNumber::try_from_number(total) {
                Ok(total) => Some(total),
                Err(_) => {
                    log::warn!(
                        target: "fastmcp_rust::handler",
                        "final progress notification rejected; reason=invalid_finite_numeric_value"
                    );
                    return;
                }
            },
            None => None,
        };
        self.enqueue_exact(progress, total, message);
    }

    fn send_progress(&self, progress: f64, total: Option<f64>, message: Option<&str>) {
        let Some(progress) = exact_finite_progress_from_f64(progress) else {
            log::warn!(
                target: "fastmcp_rust::handler",
                "final progress notification rejected; reason=invalid_finite_numeric_value"
            );
            return;
        };
        let total = match total {
            Some(total) => match exact_finite_progress_from_f64(total) {
                Some(total) => Some(total),
                None => {
                    log::warn!(
                        target: "fastmcp_rust::handler",
                        "final progress notification rejected; reason=invalid_finite_numeric_value"
                    );
                    return;
                }
            },
            None => None,
        };
        self.enqueue_exact(progress, total, message);
    }
}

impl<F> std::fmt::Debug for FinalProgressRuntime<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinalProgressRuntime")
            .finish_non_exhaustive()
    }
}

/// A notification sender that sends progress notifications via a callback.
///
/// This is the server-side implementation used to send notifications back
/// to the client during handler execution. It rejects non-finite numeric
/// fields and serialization failures, and contains callback panics so a
/// reporting failure cannot unwind through the request handler.
///
/// The exact-2024 path remains immediate. Final request-owned dispatch can
/// instead install [`FinalProgressRuntime`] and retain its explicit flush and
/// terminal-finalization primitives in the outer transport owner.
pub struct ProgressNotificationSender<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    /// The progress marker from the original request.
    marker: ProgressMarker,
    /// Whether this sender emits the exact final progress model rather than
    /// the exact-2024 `f64` model.
    final_protocol: bool,
    /// Callback to send notifications.
    send_fn: F,
}

impl<F> ProgressNotificationSender<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    /// Creates a new progress notification sender.
    pub fn new(marker: ProgressMarker, send_fn: F) -> Self {
        Self {
            marker,
            final_protocol: false,
            send_fn,
        }
    }

    /// Creates a progress sender for MCP 2026-07-28 handler dispatch.
    ///
    /// Calls made through the ordinary [`ProgressReporter`] bridge are
    /// admitted as exact finite JSON numbers and emitted with
    /// [`FinalProgressNotificationParams`]. The exact-2024 constructor
    /// [`Self::new`] deliberately retains its `f64` wire model.
    pub fn new_final(marker: ProgressMarker, send_fn: F) -> Self {
        Self {
            marker,
            final_protocol: true,
            send_fn,
        }
    }

    /// Creates a progress reporter from this sender.
    pub fn into_reporter(self) -> ProgressReporter
    where
        Self: 'static,
    {
        ProgressReporter::with_marker(
            serde_json::to_value(&self.marker).unwrap_or(serde_json::Value::Null),
            Arc::new(self),
        )
    }

    fn send_progress_with_serializer<E>(
        &self,
        progress: f64,
        total: Option<f64>,
        message: Option<&str>,
        serialize: impl FnOnce(&ProgressParams) -> Result<serde_json::Value, E>,
    ) {
        if !progress.is_finite() || total.is_some_and(|value| !value.is_finite()) {
            log::warn!(
                target: "fastmcp_rust::handler",
                "progress notification rejected; reason=non_finite_numeric_value"
            );
            return;
        }

        let params = match total {
            Some(value) => ProgressParams::with_total(self.marker.clone(), progress, value),
            None => ProgressParams::new(self.marker.clone(), progress),
        };

        let params = if let Some(value) = message {
            params.with_message(value)
        } else {
            params
        };

        let Ok(serialized_params) = serialize(&params) else {
            log::warn!(
                target: "fastmcp_rust::handler",
                "progress notification rejected; reason=serialization_failure"
            );
            return;
        };

        let notification =
            JsonRpcRequest::notification("notifications/progress", Some(serialized_params));
        if crate::catch_extension_unwind(|| (self.send_fn)(notification)).is_err() {
            log::error!(
                target: "fastmcp_rust::handler",
                "progress notification callback terminated unexpectedly; detail=panic_payload_redacted"
            );
        }
    }

    /// Emits an exact-final progress notification after final-era admission.
    ///
    /// Callers use the public [`NotificationSender::send_progress_exact`]
    /// capability; this raw-model helper is intentionally private so a legacy
    /// sender cannot bypass its protocol-era gate.
    fn send_final_progress_exact(
        &self,
        progress: ExactNonNegativeJsonNumber,
        total: Option<ExactNonNegativeJsonNumber>,
        message: Option<&str>,
    ) {
        if !self.final_protocol {
            log::warn!(
                target: "fastmcp_rust::handler",
                "final progress notification rejected; reason=legacy_sender"
            );
            return;
        }
        let params = FinalProgressNotificationParams {
            progress_token: self.marker.clone(),
            progress,
            total,
            message: message.map(str::to_owned),
            meta: None,
            additional: BTreeMap::new(),
        };
        let Ok(serialized_params) = serde_json::to_value(params) else {
            log::warn!(
                target: "fastmcp_rust::handler",
                "final progress notification rejected; reason=serialization_failure"
            );
            return;
        };
        let notification =
            JsonRpcRequest::notification("notifications/progress", Some(serialized_params));
        if crate::catch_extension_unwind(|| (self.send_fn)(notification)).is_err() {
            log::error!(
                target: "fastmcp_rust::handler",
                "progress notification callback terminated unexpectedly; detail=panic_payload_redacted"
            );
        }
    }
}

impl<F> NotificationSender for ProgressNotificationSender<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    fn send_progress_exact(
        &self,
        progress: serde_json::Number,
        total: Option<serde_json::Number>,
        message: Option<&str>,
    ) {
        if !self.final_protocol {
            log::warn!(
                target: "fastmcp_rust::handler",
                "final progress notification rejected; reason=legacy_sender"
            );
            return;
        }
        let progress = match ExactNonNegativeJsonNumber::try_from_number(progress) {
            Ok(progress) => progress,
            Err(_) => {
                log::warn!(
                    target: "fastmcp_rust::handler",
                    "final progress notification rejected; reason=invalid_finite_numeric_value"
                );
                return;
            }
        };
        let total = match total {
            Some(total) => match ExactNonNegativeJsonNumber::try_from_number(total) {
                Ok(total) => Some(total),
                Err(_) => {
                    log::warn!(
                        target: "fastmcp_rust::handler",
                        "final progress notification rejected; reason=invalid_finite_numeric_value"
                    );
                    return;
                }
            },
            None => None,
        };
        self.send_final_progress_exact(progress, total, message);
    }

    fn send_progress(&self, progress: f64, total: Option<f64>, message: Option<&str>) {
        if self.final_protocol {
            let Some(progress) = exact_finite_progress_from_f64(progress) else {
                log::warn!(
                    target: "fastmcp_rust::handler",
                    "final progress notification rejected; reason=invalid_finite_numeric_value"
                );
                return;
            };
            let total = match total {
                Some(total) => match exact_finite_progress_from_f64(total) {
                    Some(total) => Some(total),
                    None => {
                        log::warn!(
                            target: "fastmcp_rust::handler",
                            "final progress notification rejected; reason=invalid_finite_numeric_value"
                        );
                        return;
                    }
                },
                None => None,
            };
            self.send_final_progress_exact(progress, total, message);
            return;
        }
        self.send_progress_with_serializer(progress, total, message, |params| {
            serde_json::to_value(params)
        });
    }
}

fn exact_finite_progress_from_f64(value: f64) -> Option<ExactNonNegativeJsonNumber> {
    value
        .is_finite()
        .then(|| ExactNonNegativeJsonNumber::parse(&value.to_string()).ok())
        .flatten()
}

impl<F> std::fmt::Debug for ProgressNotificationSender<F>
where
    F: Fn(JsonRpcRequest) + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressNotificationSender")
            .finish_non_exhaustive()
    }
}

/// Configuration for bidirectional senders to attach to context.
#[derive(Clone, Default)]
pub struct BidirectionalSenders {
    /// Optional sampling sender for LLM completions.
    pub sampling: Option<Arc<dyn fastmcp_core::SamplingSender>>,
    /// Optional elicitation sender for user input requests.
    pub elicitation: Option<Arc<dyn fastmcp_core::ElicitationSender>>,
    /// Optional roots provider for filesystem boundaries exposed by the client.
    pub roots: Option<Arc<dyn fastmcp_core::RootsProvider>>,
}

impl BidirectionalSenders {
    /// Creates empty senders (no bidirectional features).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the sampling sender.
    #[must_use]
    pub fn with_sampling(mut self, sender: Arc<dyn fastmcp_core::SamplingSender>) -> Self {
        self.sampling = Some(sender);
        self
    }

    /// Sets the elicitation sender.
    #[must_use]
    pub fn with_elicitation(mut self, sender: Arc<dyn fastmcp_core::ElicitationSender>) -> Self {
        self.elicitation = Some(sender);
        self
    }

    /// Sets the roots provider.
    #[must_use]
    pub fn with_roots(mut self, provider: Arc<dyn fastmcp_core::RootsProvider>) -> Self {
        self.roots = Some(provider);
        self
    }
}

impl std::fmt::Debug for BidirectionalSenders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BidirectionalSenders")
            .field("sampling", &self.sampling.is_some())
            .field("elicitation", &self.elicitation.is_some())
            .field("roots", &self.roots.is_some())
            .finish()
    }
}

/// Helper to create an McpContext with optional progress reporting and session state.
pub fn create_context_with_progress<F>(
    cx: asupersync::Cx,
    request_id: u64,
    progress_marker: Option<ProgressMarker>,
    state: Option<SessionState>,
    send_fn: F,
) -> McpContext
where
    F: Fn(JsonRpcRequest) + Send + Sync + 'static,
{
    create_context_with_progress_and_senders(cx, request_id, progress_marker, state, send_fn, None)
}

/// Helper to create an McpContext with optional progress reporting, session state, and bidirectional senders.
pub fn create_context_with_progress_and_senders<F>(
    cx: asupersync::Cx,
    request_id: u64,
    progress_marker: Option<ProgressMarker>,
    state: Option<SessionState>,
    send_fn: F,
    senders: Option<&BidirectionalSenders>,
) -> McpContext
where
    F: Fn(JsonRpcRequest) + Send + Sync + 'static,
{
    let mut ctx = match (progress_marker, state) {
        (Some(marker), Some(state)) => {
            let sender = ProgressNotificationSender::new(marker, send_fn);
            McpContext::with_state_and_progress(cx, request_id, state, sender.into_reporter())
        }
        (Some(marker), None) => {
            let sender = ProgressNotificationSender::new(marker, send_fn);
            McpContext::with_progress(cx, request_id, sender.into_reporter())
        }
        (None, Some(state)) => McpContext::with_state(cx, request_id, state),
        (None, None) => McpContext::new(cx, request_id),
    };

    // Attach bidirectional senders if provided
    if let Some(senders) = senders {
        if let Some(ref sampling) = senders.sampling {
            ctx = ctx.with_sampling(sampling.clone());
        }
        if let Some(ref elicitation) = senders.elicitation {
            ctx = ctx.with_elicitation(elicitation.clone());
        }
        if let Some(ref roots) = senders.roots {
            ctx = ctx.with_roots_provider(roots.clone());
        }
    }

    ctx
}

/// A boxed future for async handler results.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One application-authored result of a final method that may require input.
///
/// The `InputRequired` branch lets a handler describe its embedded input map.
/// The router validates those descriptors, discards any handler-authored
/// request state or open result members, and mints the only retry state it
/// will later accept. Legacy handler defaults continue to produce only the
/// exact legacy projection promoted as [`Self::Complete`](FinalMethodOutcome::Complete).
#[derive(Debug, Clone)]
pub enum FinalMethodOutcome<T> {
    /// Complete the request with its method-specific final payload.
    Complete(CompleteResult<T>),
    /// Ask the final peer for additional input before retrying the request.
    InputRequired(InputRequiredResult),
}

impl<T> From<CompleteResult<T>> for FinalMethodOutcome<T> {
    fn from(result: CompleteResult<T>) -> Self {
        Self::Complete(result)
    }
}

/// Identifies who selected a complete final resource-read cache policy.
///
/// The legacy-to-final bridge asks the router to install its configured
/// policy. A direct final handler or exact proxy result owns its wire cache
/// hints, even if those values happen to equal a router default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalResourceReadCacheHintProvenance {
    /// The result came from the legacy bridge and needs the router policy.
    RouterPolicy,
    /// The handler or upstream peer supplied explicit final cache hints.
    Explicit,
}

/// One application-authored outcome of a final `tools/call` handler.
///
/// `CreateTask` is deliberately a request for the router to create durable
/// state, not a pre-created task result. The router can therefore enforce the
/// peer's negotiated Tasks capability before the application-owned store is
/// mutated.
pub enum FinalToolOutcome {
    /// Complete this tool call synchronously through the final result algebra.
    Complete(CompleteResult<FinalCallToolResult>),
    /// Ask the final peer for additional input before retrying this tool call.
    ///
    /// The router extracts and validates its input descriptors, then mints the
    /// retry state without coercing the result into a legacy projection.
    InputRequired(InputRequiredResult),
    /// Create one durable working task after negotiated capability admission.
    #[cfg(feature = "tasks")]
    CreateTask {
        /// Non-null opaque application work persisted with the new task.
        ///
        /// [`FinalTaskWorkDescriptor::new`] is the only public constructor for
        /// this type and rejects a null descriptor, so a task-capable handler
        /// cannot request creation of inert work.
        work_descriptor: FinalTaskWorkDescriptor,
        /// Optional initial status message retained by the task state machine.
        status_message: Option<String>,
    },
}

impl From<CompleteResult<FinalCallToolResult>> for FinalToolOutcome {
    fn from(result: CompleteResult<FinalCallToolResult>) -> Self {
        Self::Complete(result)
    }
}

impl From<InputRequiredResult> for FinalToolOutcome {
    fn from(result: InputRequiredResult) -> Self {
        Self::InputRequired(result)
    }
}

#[cfg(feature = "tasks")]
const UNDECLARED_FINAL_TASK_OUTCOME_ERROR: &str =
    "tool returned CreateTask without declaring final Tasks capability";

#[cfg(feature = "tasks")]
fn admit_declared_final_tool_outcome(
    declares_final_tasks: bool,
    outcome: FinalToolOutcome,
) -> McpResult<FinalToolOutcome> {
    if matches!(&outcome, FinalToolOutcome::CreateTask { .. }) && !declares_final_tasks {
        return Err(McpError::invalid_request(
            UNDECLARED_FINAL_TASK_OUTCOME_ERROR,
        ));
    }
    Ok(outcome)
}

/// URI template parameters extracted from a matched resource URI.
pub type UriParams = HashMap<String, String>;

/// Encodes a router-produced modern success through the final result contract.
///
/// Legacy dispatch continues to serialize its method-specific result structs
/// directly. The stateless router, by contrast, calls this helper after a
/// shipped handler has completed so every successful modern response carries
/// the explicit `resultType: "complete"` discriminator and is admitted by the
/// same bounded protocol codec used for peer results. Method-specific payloads
/// may not pre-populate the discriminator; only this boundary selects it.
pub(crate) fn encode_final_complete_result<T: serde::Serialize>(
    payload: T,
) -> McpResult<serde_json::Value> {
    let serde_json::Value::Object(mut members) =
        serde_json::to_value(payload).map_err(McpError::from)?
    else {
        return Err(McpError::internal_error(
            "modern complete result payload must serialize as an object",
        ));
    };

    if members.contains_key("resultType") {
        return Err(McpError::internal_error(
            "modern complete result payload must not select a result type",
        ));
    }
    members.insert(
        "resultType".to_string(),
        serde_json::Value::String("complete".to_string()),
    );

    let encoded = serde_json::to_string(&members).map_err(McpError::from)?;
    let (decoded, diagnostic) = decode_peer_result(
        &encoded,
        ResultPeerEra::Modern,
        &CoreResultDiscriminatorPolicy,
    )
    .map_err(|_| McpError::internal_error("modern complete result violates the final contract"))?;

    if diagnostic.is_some() || !matches!(decoded, DecodedResult::Complete(_)) {
        return Err(McpError::internal_error(
            "modern complete result violates the final contract",
        ));
    }

    serde_json::from_str(&encode_result(&decoded)).map_err(McpError::from)
}

/// Returns empty metadata for a server-authored final complete result.
///
/// Final method codecs reject a synthesized `serverInfo`. The protocol result
/// algebra exposes metadata through decoded complete results, so obtain the
/// canonical empty instance through that same bounded decoder.
pub(crate) fn empty_final_result_meta() -> McpResult<ResultMeta> {
    let (decoded, diagnostic) = decode_peer_result(
        r#"{"resultType":"complete"}"#,
        ResultPeerEra::Modern,
        &CoreResultDiscriminatorPolicy,
    )
    .map_err(|_| McpError::internal_error("empty final result metadata is invalid"))?;
    if diagnostic.is_some() {
        return Err(McpError::internal_error(
            "empty final result metadata must select the complete discriminator",
        ));
    }
    let DecodedResult::Complete(empty_result) = decoded else {
        return Err(McpError::internal_error(
            "empty final result metadata must select the complete result",
        ));
    };
    Ok(empty_result.meta)
}

/// Promotes an exact legacy tool payload into the final complete-result algebra.
///
/// This is the compatibility direction used by legacy-only tool handlers when
/// a final request reaches the router. Every legacy content variant is mapped
/// without discarding information; malformed legacy embedded resources are
/// refused rather than authored as a different final resource.
pub(crate) fn promote_legacy_tool_content(
    content: Vec<Content>,
) -> McpResult<CompleteResult<FinalCallToolResult>> {
    let content = content
        .into_iter()
        .map(|content| match content {
            Content::Text { text } => Ok(ContentBlock::Text {
                text,
                annotations: None,
                meta: None,
                additional: BTreeMap::new(),
            }),
            Content::Image { data, mime_type } => Ok(ContentBlock::Image {
                data,
                mime_type,
                annotations: None,
                meta: None,
                additional: BTreeMap::new(),
            }),
            Content::Audio { data, mime_type } => Ok(ContentBlock::Audio {
                data,
                mime_type,
                annotations: None,
                meta: None,
                additional: BTreeMap::new(),
            }),
            Content::Resource { resource } => {
                let uri = AbsoluteUri::parse(resource.uri).map_err(|error| {
                    McpError::internal_error(format!(
                        "legacy tool resource cannot be promoted to the final handler result: {error}",
                    ))
                })?;
                let embedded = match (resource.text, resource.blob) {
                    (Some(text), None) => EmbeddedResourceContents::Text {
                        uri,
                        text,
                        mime_type: resource.mime_type,
                        meta: None,
                        additional: BTreeMap::new(),
                    },
                    (None, Some(blob)) => EmbeddedResourceContents::Blob {
                        uri,
                        blob,
                        mime_type: resource.mime_type,
                        meta: None,
                        additional: BTreeMap::new(),
                    },
                    _ => {
                        return Err(McpError::internal_error(
                            "legacy tool resource cannot be promoted without exactly one text or blob payload",
                        ));
                    }
                };
                Ok(ContentBlock::Resource {
                    resource: embedded,
                    annotations: None,
                    meta: None,
                    additional: BTreeMap::new(),
                })
            }
        })
        .collect::<McpResult<Vec<_>>>()?;

    Ok(CompleteResult::new(
        FinalCallToolResult {
            content,
            is_error: false,
            structured_content: None,
        },
        empty_final_result_meta()?,
    ))
}

pub(crate) const DEFAULT_FINAL_RESOURCE_TTL_MS: u64 = 60 * 60 * 1_000;

/// Promotes legacy resource contents for a final handler default.
///
/// The trait default uses the same private one-hour cache policy as the
/// router's default legacy projection. Direct final handlers can override it
/// and author their selected cache policy without this conversion.
fn promote_legacy_resource_contents(
    contents: Vec<ResourceContent>,
) -> McpResult<CompleteResult<FinalReadResourceResult>> {
    let contents = contents
        .into_iter()
        .map(|resource| {
            let promoted = promote_legacy_tool_content(vec![Content::Resource { resource }])?;
            let Some(ContentBlock::Resource { resource, .. }) =
                promoted.payload.content.into_iter().next()
            else {
                return Err(McpError::internal_error(
                    "legacy resource content did not promote to a final embedded resource",
                ));
            };
            Ok(resource)
        })
        .collect::<McpResult<Vec<_>>>()?;

    Ok(CompleteResult::new(
        FinalReadResourceResult {
            contents,
            ttl_ms: CacheTtl::milliseconds(DEFAULT_FINAL_RESOURCE_TTL_MS),
            cache_scope: CacheScope::Private,
        },
        empty_final_result_meta()?,
    ))
}

/// Promotes legacy prompt messages for a final handler default.
///
/// Direct final prompt handlers bypass this conversion and keep their final
/// common content, including open fields, intact.
fn promote_legacy_prompt_messages(
    messages: Vec<PromptMessage>,
) -> McpResult<CompleteResult<FinalGetPromptResult>> {
    let messages = messages
        .into_iter()
        .map(|PromptMessage { role, content }| {
            let promoted = promote_legacy_tool_content(vec![content])?;
            let Some(content) = promoted.payload.content.into_iter().next() else {
                return Err(McpError::internal_error(
                    "legacy prompt content did not promote to a final content block",
                ));
            };
            Ok(FinalPromptMessage { role, content })
        })
        .collect::<McpResult<Vec<_>>>()?;

    Ok(CompleteResult::new(
        FinalGetPromptResult {
            description: None,
            messages,
        },
        empty_final_result_meta()?,
    ))
}

/// Closed framework error classes that an output-schema tool must represent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolErrorKind {
    /// The structurally valid call arguments failed the registered input schema.
    InputValidation,
    /// The admitted handler returned a non-terminal tool-execution error.
    Handler,
}

/// Legacy diagnostic label for an exact-final tool's schema ownership.
///
/// This value no longer grants admission authority. A normal handler can
/// report `Upstream`, so the router accepts bypasses only through the sealed
/// [`UpstreamFinalToolSchemaRegistration`] token issued to exact proxy
/// registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalToolSchemaAuthority {
    /// The local router owns final schema admission and framework error mapping.
    Local,
    /// The exact-final upstream owns final schema admission and result shaping.
    Upstream,
}

/// Unforgeable registration proving that an exact proxy owns final schemas.
///
/// The constructor is crate-private and only proxy registration can mint this
/// value. Public handlers may observe the type in [`ToolHandler`], but cannot
/// manufacture one to bypass local schema admission.
#[derive(Debug)]
pub struct UpstreamFinalToolSchemaRegistration {
    _proxy_registration: (),
}

impl UpstreamFinalToolSchemaRegistration {
    pub(crate) const fn exact_proxy() -> Self {
        Self {
            _proxy_registration: (),
        }
    }
}

/// Handler for a tool.
///
/// This trait is typically implemented via the `#[tool]` macro.
///
/// # Sync vs Async
///
/// By default, implement `call()` for synchronous execution. For async tools,
/// override `call_async()` instead. The router always calls `call_async()`,
/// which defaults to running `call()` in an async block.
///
/// # Return Type
///
/// Async handlers return `McpOutcome<Vec<Content>>`, a 4-valued type supporting:
/// - `Ok(content)` - Successful result
/// - `Err(McpError)` - Recoverable error
/// - `Cancelled` - Request was cancelled
/// - `Panicked` - Unrecoverable failure
pub trait ToolHandler: Send + Sync {
    /// Returns the tool definition.
    fn definition(&self) -> Tool;

    /// Returns the tool's icon, if any.
    ///
    /// Default implementation returns `None`. Override to provide an icon.
    /// Note: Icons can also be set directly in `definition()`.
    fn icon(&self) -> Option<&Icon> {
        None
    }

    /// Returns the tool's version, if any.
    ///
    /// Default implementation returns `None`. Override to provide a version.
    /// Note: Version can also be set directly in `definition()`.
    fn version(&self) -> Option<&str> {
        None
    }

    /// Returns the tool's tags for filtering and organization.
    ///
    /// Default implementation returns an empty slice. Override to provide tags.
    /// Note: Tags can also be set directly in `definition()`.
    fn tags(&self) -> &[String] {
        &[]
    }

    /// Returns the tool's annotations providing behavioral hints.
    ///
    /// Default implementation returns `None`. Override to provide annotations
    /// like `destructive`, `idempotent`, `read_only`, or `open_world_hint`.
    /// Note: Annotations can also be set directly in `definition()`.
    fn annotations(&self) -> Option<&ToolAnnotations> {
        None
    }

    /// Returns the tool's output schema (JSON Schema).
    ///
    /// Default implementation returns `None`. Override to provide a schema
    /// that describes the structure of the tool's output.
    /// Note: Output schema can also be set directly in `definition()`.
    fn output_schema(&self) -> Option<serde_json::Value> {
        None
    }

    /// Returns the final display title for this tool.
    ///
    /// This final-only field is deliberately separate from the legacy tool
    /// definition so modern catalog projection never synthesizes or leaks a
    /// legacy version/tag field.
    fn final_title(&self) -> Option<&str> {
        None
    }

    /// Returns the validated final icon set for this tool.
    ///
    /// A legacy singular icon is not projected automatically because its
    /// optional source and scalar size hint do not form an exact final icon.
    fn final_icons(&self) -> Option<&[RawIcon]> {
        None
    }

    /// Returns final open metadata for this tool's catalog entry.
    fn final_metadata(&self) -> Option<&OpenMetadata> {
        None
    }

    /// Returns an exact final catalog definition when this handler owns one.
    ///
    /// Legacy-first handlers normally leave this as `None`; the router then
    /// freezes the ordinary [`Self::definition`] plus the individual final
    /// metadata hooks into a final definition. A native final handler or proxy
    /// should override this hook so title-bearing annotations, the complete
    /// icon collection, and open metadata are never projected through the
    /// narrower legacy [`Tool`] model.
    fn final_definition(&self) -> Option<FinalTool> {
        None
    }

    /// Returns the legacy diagnostic label for this handler's exact-final schemas.
    ///
    /// Ordinary and legacy-backed handlers keep local schema admission. The
    /// router does not use this forgeable label for admission; exact proxy
    /// registration supplies a sealed token through
    /// [`Self::upstream_final_tool_schema_registration`] instead.
    fn final_tool_schema_authority(&self) -> FinalToolSchemaAuthority {
        FinalToolSchemaAuthority::Local
    }

    /// Returns a sealed upstream-schema registration for an exact proxy.
    ///
    /// Ordinary handlers must use the default. The token has no public
    /// constructor, so only server-owned proxy registration can opt out of
    /// local input/output validation and framework-error synthesis.
    fn upstream_final_tool_schema_registration(
        &self,
    ) -> Option<UpstreamFinalToolSchemaRegistration> {
        None
    }

    /// Maps a framework-authored tool error into this tool's structured output.
    ///
    /// A handler that declares `outputSchema` must return a truthful value for
    /// both closed error kinds. Registration invokes this hook once for each
    /// kind, bounds and validates the returned JSON, and stores immutable
    /// copies beside the admitted schemas. Returning `None`, an over-limit
    /// value, or a value rejected by `outputSchema` rejects registration
    /// before any catalog mutation.
    fn final_tool_error_structured_content(
        &self,
        _kind: ToolErrorKind,
    ) -> Option<serde_json::Value> {
        None
    }

    /// Returns the tool's custom timeout duration.
    ///
    /// Default implementation returns `None`, meaning no additional handler
    /// ceiling is added. Override to specify a per-handler timeout.
    ///
    /// A non-zero value tightens the ambient/request/server budget. It never
    /// replaces or relaxes an earlier absolute deadline. A zero value is
    /// treated like `None` and therefore cannot disable an outer timeout.
    /// Pending async work is dropped when the legacy synchronous dispatcher's
    /// timer observes a comparable deadline, and a late completion is rejected.
    /// The dispatcher does not drive a caller's foreign virtual clock. This
    /// cannot preempt a blocking synchronous `call()` or guarantee child-work
    /// drain; handlers must still cooperate with [`McpContext::checkpoint`].
    fn timeout(&self) -> Option<Duration> {
        None
    }

    /// Calls the tool synchronously with the given arguments.
    ///
    /// This is the default implementation point. Override this for simple
    /// synchronous tools. Returns `McpResult` which is converted to `McpOutcome`
    /// by the async wrapper.
    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>>;

    /// Calls the tool asynchronously with the given arguments.
    ///
    /// Override this for tools that need true async execution (e.g., I/O-bound
    /// operations, database queries, HTTP requests).
    ///
    /// Returns `McpOutcome` to properly represent all four states: success,
    /// error, cancellation, and panic.
    ///
    /// The default implementation delegates to the sync `call()` method and
    /// converts the `McpResult` to `McpOutcome`.
    fn call_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
        Box::pin(async move {
            match self.call(ctx, arguments) {
                Ok(v) => Outcome::Ok(v),
                Err(e) => Outcome::Err(e),
            }
        })
    }

    /// Calls the tool through the final MCP 2026-07-28 result surface.
    ///
    /// Legacy-only handlers retain their exact [`Self::call`] result and are
    /// promoted without loss into a complete final result. Handlers that
    /// author final-only metadata, annotations, resource links, or a tool
    /// error result should override this method (or its async counterpart) so
    /// the router can preserve the supplied final result algebra exactly.
    fn call_final(
        &self,
        ctx: &McpContext,
        arguments: serde_json::Value,
    ) -> McpResult<CompleteResult<FinalCallToolResult>> {
        promote_legacy_tool_content(self.call(ctx, arguments)?)
    }

    /// Asynchronously calls the tool through the final result surface.
    ///
    /// The default delegates to [`Self::call_final`].
    fn call_final_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalCallToolResult>>> {
        Box::pin(async move {
            match self.call_final(ctx, arguments) {
                Ok(value) => Outcome::Ok(value),
                Err(error) => Outcome::Err(error),
            }
        })
    }

    /// Calls the tool from a request-owned structured child.
    ///
    /// Modern router dispatch supplies the child [`Cx`] that owns this handler
    /// invocation. Implementations that spawn or otherwise coordinate nested
    /// work must use this context so cancellation and completion remain within
    /// the request's structured lifetime. Existing handlers keep their exact
    /// behavior through the default delegation to [`Self::call_async`].
    fn call_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
        self.call_async(ctx, arguments)
    }

    /// Calls the tool's final result hook from a request-owned child.
    ///
    /// Existing final async handlers keep their behavior through the default
    /// delegation to [`Self::call_final_async`].
    fn call_final_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalCallToolResult>>> {
        self.call_final_async(ctx, arguments)
    }

    /// Declares whether this handler can return a final Tasks `CreateTask` outcome.
    ///
    /// The router verifies this declaration only if the handler actually
    /// returns [`FinalToolOutcome::CreateTask`], then admits negotiated Tasks
    /// capability and runtime readiness before mutating task state. Handlers
    /// that return [`FinalToolOutcome::CreateTask`] must override this to
    /// return `true`.
    fn declares_final_tasks(&self) -> bool {
        false
    }

    /// Calls the tool through the final complete, input-required, or task-creation surface.
    ///
    /// Existing handlers remain complete-only. A task-capable handler
    /// overrides this method, or its async/request-owned counterpart, and
    /// returns [`FinalToolOutcome::CreateTask`] without mutating task state.
    fn call_final_outcome(
        &self,
        ctx: &McpContext,
        arguments: serde_json::Value,
    ) -> McpResult<FinalToolOutcome> {
        self.call_final(ctx, arguments)
            .map(FinalToolOutcome::Complete)
    }

    /// Asynchronously calls the final complete, input-required, or task-creation surface.
    fn call_final_outcome_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
        Box::pin(async move {
            match self.call_final_outcome(ctx, arguments) {
                Ok(value) => {
                    match admit_declared_final_tool_outcome(self.declares_final_tasks(), value) {
                        Ok(value) => Outcome::Ok(value),
                        Err(error) => Outcome::Err(error),
                    }
                }
                Err(error) => Outcome::Err(error),
            }
        })
    }

    /// Calls the disjoint final outcome from a request-owned structured child.
    fn call_final_outcome_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
        Box::pin(async move {
            match self.call_final_outcome_async(ctx, arguments).await {
                Outcome::Ok(value) => {
                    match admit_declared_final_tool_outcome(self.declares_final_tasks(), value) {
                        Ok(value) => Outcome::Ok(value),
                        Err(error) => Outcome::Err(error),
                    }
                }
                Outcome::Err(error) => Outcome::Err(error),
                Outcome::Cancelled(cancelled) => Outcome::Cancelled(cancelled),
                Outcome::Panicked(panic) => Outcome::Panicked(panic),
            }
        })
    }

    /// Resumes a final tool invocation after framework-admitted MRTR input.
    ///
    /// `resume_inputs` exists only after the router consumed a
    /// framework-minted request state bound to the original modern operation.
    /// Handlers inspect its typed accessors rather than decoding client wire
    /// values. `#[tool]` exposes this as an
    /// `Option<&MrtrCompletedInputs>` user-function parameter: initial calls
    /// receive `None` and admitted retries receive `Some`. Existing handlers
    /// preserve their normal final hook by default.
    fn call_final_outcome_async_resuming_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: serde_json::Value,
        _resume_inputs: Option<&'a MrtrCompletedInputs>,
    ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
        self.call_final_outcome_async_in_request(ctx, request_cx, arguments)
    }
}

/// Handler for a resource.
///
/// This trait is typically implemented via the `#[resource]` macro.
///
/// # Sync vs Async
///
/// By default, implement `read()` for synchronous execution. For async resources,
/// override `read_async()` instead. The router uses `read_async_with_uri()` so
/// implementations can access matched URI parameters when needed; its default
/// implementation delegates to `read_async()` or `read_with_uri()`.
///
/// # Return Type
///
/// Async handlers return `McpOutcome<Vec<ResourceContent>>`, a 4-valued type.
pub trait ResourceHandler: Send + Sync {
    /// Returns the resource definition.
    fn definition(&self) -> Resource;

    /// Returns whether locally authored final resource identities may use HTTPS
    /// at client-direct use sites. Exact MCP 2024-11-05 dispatch never consults
    /// this declaration.
    fn final_client_direct_https(&self) -> bool {
        false
    }

    /// Returns the resource template definition, if this resource uses a URI template.
    fn template(&self) -> Option<ResourceTemplate> {
        None
    }

    /// Returns an exact final resource catalog definition, when this handler
    /// owns one. This bypasses lossy projection through [`Resource`], retaining
    /// final-only fields such as `size`, full icons, annotations, and `_meta`.
    fn final_definition(&self) -> Option<FinalResource> {
        None
    }

    /// Returns an exact final resource-template catalog definition, when this
    /// handler owns a template. This keeps final metadata immutable at router
    /// registration rather than reconstructing it from the legacy template.
    fn final_template_definition(&self) -> Option<FinalResourceTemplate> {
        None
    }

    /// Returns the final display title for this concrete resource.
    fn final_title(&self) -> Option<&str> {
        None
    }

    /// Returns the final icon set for this concrete resource.
    fn final_icons(&self) -> Option<&[RawIcon]> {
        None
    }

    /// Returns the final annotations for this concrete resource.
    fn final_annotations(&self) -> Option<&Annotations> {
        None
    }

    /// Returns final open metadata for this concrete resource.
    fn final_metadata(&self) -> Option<&OpenMetadata> {
        None
    }

    /// Returns the final display title for this resource template.
    ///
    /// This is used only when [`Self::template`] returns `Some`.
    fn final_template_title(&self) -> Option<&str> {
        None
    }

    /// Returns the final icon set for this resource template.
    ///
    /// This is used only when [`Self::template`] returns `Some`.
    fn final_template_icons(&self) -> Option<&[RawIcon]> {
        None
    }

    /// Returns the final annotations for this resource template.
    ///
    /// This is used only when [`Self::template`] returns `Some`.
    fn final_template_annotations(&self) -> Option<&Annotations> {
        None
    }

    /// Returns final open metadata for this resource template.
    ///
    /// This is used only when [`Self::template`] returns `Some`.
    fn final_template_metadata(&self) -> Option<&OpenMetadata> {
        None
    }

    /// Returns the resource's icon, if any.
    ///
    /// Default implementation returns `None`. Override to provide an icon.
    /// Note: Icons can also be set directly in `definition()`.
    fn icon(&self) -> Option<&Icon> {
        None
    }

    /// Returns the resource's version, if any.
    ///
    /// Default implementation returns `None`. Override to provide a version.
    /// Note: Version can also be set directly in `definition()`.
    fn version(&self) -> Option<&str> {
        None
    }

    /// Returns the resource's tags for filtering and organization.
    ///
    /// Default implementation returns an empty slice. Override to provide tags.
    /// Note: Tags can also be set directly in `definition()`.
    fn tags(&self) -> &[String] {
        &[]
    }

    /// Returns the resource's custom timeout duration.
    ///
    /// Default implementation returns `None`, meaning no additional handler
    /// ceiling is added. A non-zero value only tightens outer budgets; zero
    /// cannot disable an ambient, request, or server deadline.
    /// A blocking synchronous `read()` cannot be preempted; if it returns
    /// after the deadline, its result is rejected.
    fn timeout(&self) -> Option<Duration> {
        None
    }

    /// Reads the resource content synchronously.
    ///
    /// This is the default implementation point. Override this for simple
    /// synchronous resources. Returns `McpResult` which is converted to `McpOutcome`
    /// by the async wrapper.
    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>>;

    /// Reads the resource content synchronously with the matched URI and parameters.
    ///
    /// Default implementation ignores URI params and delegates to `read()`.
    fn read_with_uri(
        &self,
        ctx: &McpContext,
        _uri: &str,
        _params: &UriParams,
    ) -> McpResult<Vec<ResourceContent>> {
        self.read(ctx)
    }

    /// Reads the resource content asynchronously with the matched URI and parameters.
    ///
    /// Default implementation delegates to the sync `read_with_uri()` method.
    fn read_async_with_uri<'a>(
        &'a self,
        ctx: &'a McpContext,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
        Box::pin(async move {
            if params.is_empty() {
                self.read_async(ctx).await
            } else {
                match self.read_with_uri(ctx, uri, params) {
                    Ok(v) => Outcome::Ok(v),
                    Err(e) => Outcome::Err(e),
                }
            }
        })
    }

    /// Reads the resource content asynchronously.
    ///
    /// Override this for resources that need true async execution (e.g., file I/O,
    /// database queries, remote fetches).
    ///
    /// Returns `McpOutcome` to properly represent all four states.
    ///
    /// The default implementation delegates to the sync `read()` method.
    fn read_async<'a>(
        &'a self,
        ctx: &'a McpContext,
    ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
        Box::pin(async move {
            match self.read(ctx) {
                Ok(v) => Outcome::Ok(v),
                Err(e) => Outcome::Err(e),
            }
        })
    }

    /// Reads the resource through the final MCP 2026-07-28 result surface.
    ///
    /// Legacy-only handlers retain their exact [`Self::read`] behavior and
    /// receive the standard private one-hour final cache policy. Handlers that
    /// author final embedded-resource metadata or a different cache policy
    /// should override this method (or its async counterpart).
    fn read_final(&self, ctx: &McpContext) -> McpResult<CompleteResult<FinalReadResourceResult>> {
        promote_legacy_resource_contents(self.read(ctx)?)
    }

    /// Returns the provenance of complete final resource-read cache hints.
    ///
    /// The default is the legacy bridge, whose fixed wire values are only a
    /// temporary projection until the router applies its configured policy.
    /// Handlers that override [`Self::read_final`] to author a final result,
    /// including exact proxies, must return [`FinalResourceReadCacheHintProvenance::Explicit`].
    fn final_resource_read_cache_hint_provenance(&self) -> FinalResourceReadCacheHintProvenance {
        FinalResourceReadCacheHintProvenance::RouterPolicy
    }

    /// Reads the resource through the final result surface with URI parameters.
    fn read_final_with_uri(
        &self,
        ctx: &McpContext,
        uri: &str,
        params: &UriParams,
    ) -> McpResult<CompleteResult<FinalReadResourceResult>> {
        promote_legacy_resource_contents(self.read_with_uri(ctx, uri, params)?)
    }

    /// Reads the resource through the complete-or-input-required final algebra.
    ///
    /// The default preserves the exact legacy projection by promoting
    /// [`Self::read_final`] into the complete branch. A final-only handler may
    /// override this method to return `input_required` without coercing that
    /// state into a legacy resource result.
    fn read_final_outcome(
        &self,
        ctx: &McpContext,
    ) -> McpResult<FinalMethodOutcome<FinalReadResourceResult>> {
        self.read_final(ctx).map(FinalMethodOutcome::Complete)
    }

    /// Reads the resource through the complete-or-input-required final algebra
    /// with URI parameters.
    fn read_final_outcome_with_uri(
        &self,
        ctx: &McpContext,
        uri: &str,
        params: &UriParams,
    ) -> McpResult<FinalMethodOutcome<FinalReadResourceResult>> {
        if params.is_empty() {
            self.read_final_outcome(ctx)
        } else {
            self.read_final_with_uri(ctx, uri, params)
                .map(FinalMethodOutcome::Complete)
        }
    }

    /// Asynchronously reads the resource through the final result surface.
    fn read_final_async<'a>(
        &'a self,
        ctx: &'a McpContext,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalReadResourceResult>>> {
        Box::pin(async move {
            match self.read_final(ctx) {
                Ok(value) => Outcome::Ok(value),
                Err(error) => Outcome::Err(error),
            }
        })
    }

    /// Asynchronously reads the resource through the final result surface with URI parameters.
    fn read_final_async_with_uri<'a>(
        &'a self,
        ctx: &'a McpContext,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalReadResourceResult>>> {
        Box::pin(async move {
            if params.is_empty() {
                self.read_final_async(ctx).await
            } else {
                match self.read_final_with_uri(ctx, uri, params) {
                    Ok(value) => Outcome::Ok(value),
                    Err(error) => Outcome::Err(error),
                }
            }
        })
    }

    /// Asynchronously reads the resource through the complete-or-input-required
    /// final algebra.
    fn read_final_outcome_async<'a>(
        &'a self,
        ctx: &'a McpContext,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalReadResourceResult>>> {
        Box::pin(async move {
            match self.read_final_outcome(ctx) {
                Ok(value) => Outcome::Ok(value),
                Err(error) => Outcome::Err(error),
            }
        })
    }

    /// Asynchronously reads the resource through the complete-or-input-required
    /// final algebra with URI parameters.
    fn read_final_outcome_async_with_uri<'a>(
        &'a self,
        ctx: &'a McpContext,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalReadResourceResult>>> {
        Box::pin(async move {
            if params.is_empty() {
                self.read_final_outcome_async(ctx).await
            } else {
                match self.read_final_outcome_with_uri(ctx, uri, params) {
                    Ok(value) => Outcome::Ok(value),
                    Err(error) => Outcome::Err(error),
                }
            }
        })
    }

    /// Reads the resource from a request-owned structured child.
    ///
    /// Modern router dispatch supplies the child [`Cx`] that owns this read.
    /// Implementations with nested asynchronous work must retain this context
    /// rather than creating detached work. Existing handlers preserve their
    /// exact behavior through the default delegation.
    fn read_async_with_uri_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
        self.read_async_with_uri(ctx, uri, params)
    }

    /// Reads the resource's final result from a request-owned structured child.
    fn read_final_async_with_uri_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalReadResourceResult>>> {
        self.read_final_async_with_uri(ctx, uri, params)
    }

    /// Reads the resource's complete-or-input-required final outcome from a
    /// request-owned structured child.
    fn read_final_outcome_async_with_uri_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalReadResourceResult>>> {
        self.read_final_outcome_async_with_uri(ctx, uri, params)
    }

    /// Resumes a final resource read after framework-admitted MRTR input.
    ///
    /// `#[resource]` maps an `Option<&MrtrCompletedInputs>` user-function
    /// parameter to this hook, keeping it out of URI-template parameters.
    fn read_final_outcome_async_with_uri_resuming_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        uri: &'a str,
        params: &'a UriParams,
        _resume_inputs: Option<&'a MrtrCompletedInputs>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalReadResourceResult>>> {
        self.read_final_outcome_async_with_uri_in_request(ctx, request_cx, uri, params)
    }
}

/// Handler for a prompt.
///
/// This trait is typically implemented via the `#[prompt]` macro.
///
/// # Sync vs Async
///
/// By default, implement `get()` for synchronous execution. For async prompts,
/// override `get_async()` instead. The router always calls `get_async()`,
/// which defaults to running `get()` in an async block.
///
/// # Return Type
///
/// Async handlers return `McpOutcome<Vec<PromptMessage>>`, a 4-valued type.
pub trait PromptHandler: Send + Sync {
    /// Returns the prompt definition.
    fn definition(&self) -> Prompt;

    /// Returns whether resource links authored by this prompt's final result
    /// may use client-direct HTTPS. Exact MCP 2024-11-05 dispatch never
    /// consults this declaration.
    fn final_client_direct_https(&self) -> bool {
        false
    }

    /// Returns an exact final prompt catalog definition, when this handler
    /// owns one. In particular, argument titles and absent-vs-present
    /// `required` values must not be projected through legacy prompt args.
    fn final_definition(&self) -> Option<FinalPrompt> {
        None
    }

    /// Returns the final display title for this prompt.
    fn final_title(&self) -> Option<&str> {
        None
    }

    /// Returns the final icon set for this prompt.
    fn final_icons(&self) -> Option<&[RawIcon]> {
        None
    }

    /// Returns final open metadata for this prompt.
    fn final_metadata(&self) -> Option<&OpenMetadata> {
        None
    }

    /// Returns the prompt's icon, if any.
    ///
    /// Default implementation returns `None`. Override to provide an icon.
    /// Note: Icons can also be set directly in `definition()`.
    fn icon(&self) -> Option<&Icon> {
        None
    }

    /// Returns the prompt's version, if any.
    ///
    /// Default implementation returns `None`. Override to provide a version.
    /// Note: Version can also be set directly in `definition()`.
    fn version(&self) -> Option<&str> {
        None
    }

    /// Returns the prompt's tags for filtering and organization.
    ///
    /// Default implementation returns an empty slice. Override to provide tags.
    /// Note: Tags can also be set directly in `definition()`.
    fn tags(&self) -> &[String] {
        &[]
    }

    /// Returns the prompt's custom timeout duration.
    ///
    /// Default implementation returns `None`, meaning no additional handler
    /// ceiling is added. A non-zero value only tightens outer budgets; zero
    /// cannot disable an ambient, request, or server deadline.
    /// A blocking synchronous `get()` cannot be preempted; if it returns
    /// after the deadline, its result is rejected.
    fn timeout(&self) -> Option<Duration> {
        None
    }

    /// Gets the prompt messages synchronously with the given arguments.
    ///
    /// This is the default implementation point. Override this for simple
    /// synchronous prompts. Returns `McpResult` which is converted to `McpOutcome`
    /// by the async wrapper.
    fn get(
        &self,
        ctx: &McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>>;

    /// Gets the prompt messages asynchronously with the given arguments.
    ///
    /// Override this for prompts that need true async execution (e.g., template
    /// fetching, dynamic content generation).
    ///
    /// Returns `McpOutcome` to properly represent all four states.
    ///
    /// The default implementation delegates to the sync `get()` method.
    fn get_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<Vec<PromptMessage>>> {
        Box::pin(async move {
            match self.get(ctx, arguments) {
                Ok(v) => Outcome::Ok(v),
                Err(e) => Outcome::Err(e),
            }
        })
    }

    /// Gets the prompt through the final MCP 2026-07-28 result surface.
    ///
    /// Legacy-only handlers retain their exact [`Self::get`] behavior. Direct
    /// final handlers can override this method to keep final common content
    /// and its open fields without a legacy projection.
    fn get_final(
        &self,
        ctx: &McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> McpResult<CompleteResult<FinalGetPromptResult>> {
        promote_legacy_prompt_messages(self.get(ctx, arguments)?)
    }

    /// Gets the prompt through the complete-or-input-required final algebra.
    ///
    /// The default preserves the exact legacy projection by promoting
    /// [`Self::get_final`] into the complete branch. A final-only handler may
    /// override this method to return `input_required` without coercing that
    /// state into a legacy prompt result.
    fn get_final_outcome(
        &self,
        ctx: &McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> McpResult<FinalMethodOutcome<FinalGetPromptResult>> {
        self.get_final(ctx, arguments)
            .map(FinalMethodOutcome::Complete)
    }

    /// Asynchronously gets the prompt through the final result surface.
    fn get_final_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalGetPromptResult>>> {
        Box::pin(async move {
            match self.get_final(ctx, arguments) {
                Ok(value) => Outcome::Ok(value),
                Err(error) => Outcome::Err(error),
            }
        })
    }

    /// Asynchronously gets the prompt through the complete-or-input-required
    /// final algebra.
    fn get_final_outcome_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalGetPromptResult>>> {
        Box::pin(async move {
            match self.get_final_outcome(ctx, arguments) {
                Ok(value) => Outcome::Ok(value),
                Err(error) => Outcome::Err(error),
            }
        })
    }

    /// Gets the prompt from a request-owned structured child.
    ///
    /// Modern router dispatch supplies the child [`Cx`] that owns this prompt
    /// evaluation. Existing handlers preserve their exact behavior through the
    /// default delegation to [`Self::get_async`].
    fn get_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<Vec<PromptMessage>>> {
        self.get_async(ctx, arguments)
    }

    /// Gets the prompt's final result from a request-owned structured child.
    fn get_final_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalGetPromptResult>>> {
        self.get_final_async(ctx, arguments)
    }

    /// Gets the prompt's complete-or-input-required final outcome from a
    /// request-owned structured child.
    fn get_final_outcome_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalGetPromptResult>>> {
        self.get_final_outcome_async(ctx, arguments)
    }

    /// Resumes a final prompt invocation after framework-admitted MRTR input.
    ///
    /// `#[prompt]` maps an `Option<&MrtrCompletedInputs>` user-function
    /// parameter to this hook, keeping it out of prompt arguments.
    fn get_final_outcome_async_resuming_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: std::collections::HashMap<String, String>,
        _resume_inputs: Option<&'a MrtrCompletedInputs>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalGetPromptResult>>> {
        self.get_final_outcome_async_in_request(ctx, request_cx, arguments)
    }
}

/// Handler for `completion/complete` in both supported protocol eras.
///
/// The two request parameter types deliberately remain distinct: the final
/// form carries required request metadata and optional completion context,
/// while the exact legacy form does not. Each callback returns its exact
/// era-specific completion payload; the router selects the matching result
/// envelope and final `resultType` contract.
pub trait CompletionHandler: Send + Sync {
    /// Returns an optional handler-specific timeout.
    ///
    /// A non-zero timeout tightens the request budget and cannot relax an
    /// existing deadline. Zero is treated as no handler-specific timeout.
    fn timeout(&self) -> Option<Duration> {
        None
    }

    /// Completes one exact MCP 2024-11-05 request.
    fn complete_legacy(
        &self,
        ctx: &McpContext,
        params: LegacyCompletionParams,
    ) -> McpResult<CompletionValues>;

    /// Completes one final MCP 2026-07-28 request.
    fn complete_final(
        &self,
        ctx: &McpContext,
        params: FinalCompletionParams,
    ) -> McpResult<FinalCompletionValues>;

    /// Asynchronously completes one exact legacy request.
    ///
    /// The default delegates to [`Self::complete_legacy`].
    fn complete_legacy_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        params: LegacyCompletionParams,
    ) -> BoxFuture<'a, McpOutcome<CompletionValues>> {
        Box::pin(async move {
            match self.complete_legacy(ctx, params) {
                Ok(values) => Outcome::Ok(values),
                Err(error) => Outcome::Err(error),
            }
        })
    }

    /// Asynchronously completes one final request.
    ///
    /// The default delegates to [`Self::complete_final`].
    fn complete_final_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        params: FinalCompletionParams,
    ) -> BoxFuture<'a, McpOutcome<FinalCompletionValues>> {
        Box::pin(async move {
            match self.complete_final(ctx, params) {
                Ok(values) => Outcome::Ok(values),
                Err(error) => Outcome::Err(error),
            }
        })
    }

    /// Completes one final request from its request-owned structured child.
    ///
    /// Implementations with nested asynchronous work must use `request_cx`
    /// so cancellation remains owned by the originating modern request.
    fn complete_final_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        _request_cx: &'a Cx,
        params: FinalCompletionParams,
    ) -> BoxFuture<'a, McpOutcome<FinalCompletionValues>> {
        self.complete_final_async(ctx, params)
    }
}

/// A boxed tool handler.
pub type BoxedToolHandler = Box<dyn ToolHandler>;

/// A boxed resource handler.
pub type BoxedResourceHandler = Box<dyn ResourceHandler>;

/// A boxed prompt handler.
pub type BoxedPromptHandler = Box<dyn PromptHandler>;

/// A boxed completion handler.
pub type BoxedCompletionHandler = Box<dyn CompletionHandler>;

/// Proxy adapter for an upstream exact-final resource catalog entry.
///
/// The legacy definition is deliberately only a dispatch fallback. The router
/// reads [`Self::final_definition`] during admission, so final discovery keeps
/// the upstream `size`, annotations, icon collection, and metadata verbatim.
#[cfg(feature = "proxy")]
pub(crate) struct FinalProxyResourceHandler {
    legacy: Resource,
    final_definition: FinalResource,
    external_uri: String,
    client: ProxyClient,
}

#[cfg(feature = "proxy")]
impl FinalProxyResourceHandler {
    pub(crate) fn new(final_definition: FinalResource, client: ProxyClient) -> Self {
        let external_uri = final_definition.uri.as_str().to_owned();
        let legacy = Resource {
            uri: external_uri.clone(),
            name: final_definition.name.clone(),
            description: final_definition.description.clone(),
            mime_type: final_definition.mime_type.clone(),
            icon: None,
            version: None,
            tags: Vec::new(),
        };
        Self {
            legacy,
            final_definition,
            external_uri,
            client,
        }
    }
}

#[cfg(feature = "proxy")]
impl ResourceHandler for FinalProxyResourceHandler {
    fn definition(&self) -> Resource {
        self.legacy.clone()
    }

    fn final_definition(&self) -> Option<FinalResource> {
        Some(self.final_definition.clone())
    }

    fn final_resource_read_cache_hint_provenance(&self) -> FinalResourceReadCacheHintProvenance {
        FinalResourceReadCacheHintProvenance::Explicit
    }

    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        self.client.read_resource(ctx, &self.external_uri)
    }

    fn read_final(&self, ctx: &McpContext) -> McpResult<CompleteResult<FinalReadResourceResult>> {
        self.client.read_resource_final(ctx, &self.external_uri)
    }
}

/// Proxy adapter for an upstream exact-final resource-template catalog entry.
#[cfg(feature = "proxy")]
pub(crate) struct FinalProxyResourceTemplateHandler {
    legacy_template: ResourceTemplate,
    final_definition: FinalResourceTemplate,
    external_uri_template: String,
    client: ProxyClient,
}

#[cfg(feature = "proxy")]
impl FinalProxyResourceTemplateHandler {
    pub(crate) fn new(final_definition: FinalResourceTemplate, client: ProxyClient) -> Self {
        let external_uri_template = final_definition.uri_template.clone();
        let legacy_template = ResourceTemplate {
            uri_template: external_uri_template.clone(),
            name: final_definition.name.clone(),
            description: final_definition.description.clone(),
            mime_type: final_definition.mime_type.clone(),
            icon: None,
            version: None,
            tags: Vec::new(),
        };
        Self {
            legacy_template,
            final_definition,
            external_uri_template,
            client,
        }
    }
}

#[cfg(feature = "proxy")]
impl ResourceHandler for FinalProxyResourceTemplateHandler {
    fn definition(&self) -> Resource {
        Resource {
            uri: self.legacy_template.uri_template.clone(),
            name: self.legacy_template.name.clone(),
            description: self.legacy_template.description.clone(),
            mime_type: self.legacy_template.mime_type.clone(),
            icon: None,
            version: None,
            tags: Vec::new(),
        }
    }

    fn template(&self) -> Option<ResourceTemplate> {
        Some(self.legacy_template.clone())
    }

    fn final_template_definition(&self) -> Option<FinalResourceTemplate> {
        Some(self.final_definition.clone())
    }

    fn final_resource_read_cache_hint_provenance(&self) -> FinalResourceReadCacheHintProvenance {
        FinalResourceReadCacheHintProvenance::Explicit
    }

    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        self.client.read_resource(ctx, &self.external_uri_template)
    }

    fn read_with_uri(
        &self,
        ctx: &McpContext,
        uri: &str,
        _params: &UriParams,
    ) -> McpResult<Vec<ResourceContent>> {
        self.client.read_resource(ctx, uri)
    }

    fn read_final(&self, ctx: &McpContext) -> McpResult<CompleteResult<FinalReadResourceResult>> {
        self.client
            .read_resource_final(ctx, &self.external_uri_template)
    }

    fn read_final_with_uri(
        &self,
        ctx: &McpContext,
        uri: &str,
        _params: &UriParams,
    ) -> McpResult<CompleteResult<FinalReadResourceResult>> {
        self.client.read_resource_final(ctx, uri)
    }
}

/// Proxy adapter for an upstream exact-final prompt catalog entry.
#[cfg(feature = "proxy")]
pub(crate) struct FinalProxyPromptHandler {
    legacy: Prompt,
    final_definition: FinalPrompt,
    external_name: String,
    client: ProxyClient,
}

#[cfg(feature = "proxy")]
impl FinalProxyPromptHandler {
    pub(crate) fn new(final_definition: FinalPrompt, client: ProxyClient) -> Self {
        let external_name = final_definition.name.clone();
        let legacy = Prompt {
            name: external_name.clone(),
            description: final_definition.description.clone(),
            arguments: final_definition
                .arguments
                .as_ref()
                .map(|arguments| {
                    arguments
                        .iter()
                        .map(|argument| fastmcp_protocol::PromptArgument {
                            name: argument.name.clone(),
                            description: argument.description.clone(),
                            required: argument.required.unwrap_or(false),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            icon: None,
            version: None,
            tags: Vec::new(),
        };
        Self {
            legacy,
            final_definition,
            external_name,
            client,
        }
    }

    /// Exposes a final prompt below a builder namespace while retaining the
    /// original upstream name for forwarding. Prompt names are opaque labels,
    /// unlike final resource URIs, so this rewrite remains exact.
    pub(crate) fn with_prefix(
        mut final_definition: FinalPrompt,
        prefix: &str,
        client: ProxyClient,
    ) -> Self {
        let external_name = final_definition.name.clone();
        final_definition.name = format!("{prefix}/{}", final_definition.name);
        let mut handler = Self::new(final_definition, client);
        handler.external_name = external_name;
        handler
    }
}

#[cfg(feature = "proxy")]
impl PromptHandler for FinalProxyPromptHandler {
    fn definition(&self) -> Prompt {
        self.legacy.clone()
    }

    fn final_definition(&self) -> Option<FinalPrompt> {
        Some(self.final_definition.clone())
    }

    fn get(
        &self,
        ctx: &McpContext,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        self.client.get_prompt(ctx, &self.external_name, arguments)
    }

    fn get_final(
        &self,
        ctx: &McpContext,
        arguments: HashMap<String, String>,
    ) -> McpResult<CompleteResult<FinalGetPromptResult>> {
        self.client
            .get_prompt_final(ctx, &self.external_name, arguments)
    }
}

// ============================================================================
// Mounted Handler Wrappers
// ============================================================================

/// A wrapper for a tool handler that overrides its name.
///
/// Used by `mount()` to prefix tool names when mounting from another server.
pub struct MountedToolHandler {
    inner: BoxedToolHandler,
    mounted_name: String,
}

impl MountedToolHandler {
    /// Creates a new mounted tool handler with the given name.
    pub fn new(inner: BoxedToolHandler, mounted_name: String) -> Self {
        Self {
            inner,
            mounted_name,
        }
    }
}

impl ToolHandler for MountedToolHandler {
    fn definition(&self) -> Tool {
        let mut def = self.inner.definition();
        def.name.clone_from(&self.mounted_name);
        def
    }

    fn icon(&self) -> Option<&Icon> {
        self.inner.icon()
    }

    fn version(&self) -> Option<&str> {
        self.inner.version()
    }

    fn tags(&self) -> &[String] {
        self.inner.tags()
    }

    fn annotations(&self) -> Option<&ToolAnnotations> {
        self.inner.annotations()
    }

    fn output_schema(&self) -> Option<serde_json::Value> {
        self.inner.output_schema()
    }

    fn final_title(&self) -> Option<&str> {
        self.inner.final_title()
    }

    fn final_icons(&self) -> Option<&[RawIcon]> {
        self.inner.final_icons()
    }

    fn final_metadata(&self) -> Option<&OpenMetadata> {
        self.inner.final_metadata()
    }

    fn final_definition(&self) -> Option<FinalTool> {
        let mut definition = self.inner.final_definition()?;
        definition.name.clone_from(&self.mounted_name);
        Some(definition)
    }

    fn final_tool_schema_authority(&self) -> FinalToolSchemaAuthority {
        self.inner.final_tool_schema_authority()
    }

    fn upstream_final_tool_schema_registration(
        &self,
    ) -> Option<UpstreamFinalToolSchemaRegistration> {
        self.inner.upstream_final_tool_schema_registration()
    }

    fn final_tool_error_structured_content(
        &self,
        kind: ToolErrorKind,
    ) -> Option<serde_json::Value> {
        self.inner.final_tool_error_structured_content(kind)
    }

    fn declares_final_tasks(&self) -> bool {
        self.inner.declares_final_tasks()
    }

    fn timeout(&self) -> Option<Duration> {
        self.inner.timeout()
    }

    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        self.inner.call(ctx, arguments)
    }

    fn call_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
        self.inner.call_async(ctx, arguments)
    }

    fn call_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
        self.inner.call_async_in_request(ctx, request_cx, arguments)
    }

    fn call_final(
        &self,
        ctx: &McpContext,
        arguments: serde_json::Value,
    ) -> McpResult<CompleteResult<FinalCallToolResult>> {
        self.inner.call_final(ctx, arguments)
    }

    fn call_final_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalCallToolResult>>> {
        self.inner.call_final_async(ctx, arguments)
    }

    fn call_final_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalCallToolResult>>> {
        self.inner
            .call_final_async_in_request(ctx, request_cx, arguments)
    }

    fn call_final_outcome(
        &self,
        ctx: &McpContext,
        arguments: serde_json::Value,
    ) -> McpResult<FinalToolOutcome> {
        self.inner.call_final_outcome(ctx, arguments)
    }

    fn call_final_outcome_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
        self.inner.call_final_outcome_async(ctx, arguments)
    }

    fn call_final_outcome_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
        self.inner
            .call_final_outcome_async_in_request(ctx, request_cx, arguments)
    }

    fn call_final_outcome_async_resuming_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: serde_json::Value,
        resume_inputs: Option<&'a MrtrCompletedInputs>,
    ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
        self.inner.call_final_outcome_async_resuming_in_request(
            ctx,
            request_cx,
            arguments,
            resume_inputs,
        )
    }
}

/// A wrapper for a resource handler that overrides its URI.
///
/// Used by `mount()` to prefix resource URIs when mounting from another server.
pub struct MountedResourceHandler {
    inner: BoxedResourceHandler,
    source_uri: String,
    mounted_uri: String,
    mount_prefix: Option<String>,
    mounted_template: Option<ResourceTemplate>,
}

impl MountedResourceHandler {
    /// Creates a mounted resource handler from authoritative source and
    /// destination registry keys.
    pub fn new(inner: BoxedResourceHandler, source_uri: String, mounted_uri: String) -> Self {
        let mount_prefix = Self::infer_mount_prefix(&source_uri, &mounted_uri);
        Self {
            inner,
            source_uri,
            mounted_uri,
            mount_prefix,
            mounted_template: None,
        }
    }

    /// Creates a new mounted resource handler with a mounted template.
    pub fn with_template(
        inner: BoxedResourceHandler,
        source_uri: String,
        mounted_uri: String,
        mounted_template: ResourceTemplate,
    ) -> Self {
        let mount_prefix = Self::infer_mount_prefix(&source_uri, &mounted_uri);
        Self {
            inner,
            source_uri,
            mounted_uri,
            mount_prefix,
            mounted_template: Some(mounted_template),
        }
    }

    fn infer_mount_prefix(source_uri: &str, mounted_uri: &str) -> Option<String> {
        mounted_uri
            .strip_suffix(source_uri)
            .filter(|prefix| !prefix.is_empty())
            .map(str::to_string)
    }

    fn translate_incoming_uri(&self, uri: &str) -> McpResult<String> {
        if uri == self.mounted_uri {
            return Ok(self.source_uri.clone());
        }
        match &self.mount_prefix {
            Some(prefix) => uri.strip_prefix(prefix).map(str::to_string).ok_or_else(|| {
                McpError::invalid_params("Resource URI does not match the mounted namespace")
            }),
            None if self.mounted_uri == self.source_uri => Ok(uri.to_string()),
            None => Err(McpError::invalid_params(
                "Resource URI does not match the mounted resource",
            )),
        }
    }

    fn translate_outgoing_contents(
        &self,
        mut contents: Vec<ResourceContent>,
    ) -> Vec<ResourceContent> {
        for content in &mut contents {
            if let Some(prefix) = &self.mount_prefix {
                content.uri = format!("{prefix}{}", content.uri);
            } else if content.uri == self.source_uri {
                content.uri.clone_from(&self.mounted_uri);
            }
        }
        contents
    }

    fn translate_outgoing_final_uri(&self, uri: AbsoluteUri) -> McpResult<AbsoluteUri> {
        let translated = if let Some(prefix) = &self.mount_prefix {
            format!("{prefix}{}", uri.as_str())
        } else if uri.as_str() == self.source_uri.as_str() {
            self.mounted_uri.clone()
        } else {
            uri.as_str().to_owned()
        };
        AbsoluteUri::parse(translated).map_err(|error| {
            McpError::internal_error(format!(
                "mounted final resource URI is invalid after translation: {error}",
            ))
        })
    }

    fn translate_outgoing_final_contents(
        &self,
        contents: Vec<EmbeddedResourceContents>,
    ) -> McpResult<Vec<EmbeddedResourceContents>> {
        contents
            .into_iter()
            .map(|content| match content {
                EmbeddedResourceContents::Text {
                    uri,
                    text,
                    mime_type,
                    meta,
                    additional,
                } => Ok(EmbeddedResourceContents::Text {
                    uri: self.translate_outgoing_final_uri(uri)?,
                    text,
                    mime_type,
                    meta,
                    additional,
                }),
                EmbeddedResourceContents::Blob {
                    uri,
                    blob,
                    mime_type,
                    meta,
                    additional,
                } => Ok(EmbeddedResourceContents::Blob {
                    uri: self.translate_outgoing_final_uri(uri)?,
                    blob,
                    mime_type,
                    meta,
                    additional,
                }),
            })
            .collect()
    }

    fn translate_outgoing_final_result(
        &self,
        mut result: CompleteResult<FinalReadResourceResult>,
    ) -> McpResult<CompleteResult<FinalReadResourceResult>> {
        result.payload.contents =
            self.translate_outgoing_final_contents(result.payload.contents)?;
        Ok(result)
    }

    fn translate_outgoing_final_method_outcome(
        &self,
        outcome: FinalMethodOutcome<FinalReadResourceResult>,
    ) -> McpResult<FinalMethodOutcome<FinalReadResourceResult>> {
        match outcome {
            FinalMethodOutcome::Complete(result) => self
                .translate_outgoing_final_result(result)
                .map(FinalMethodOutcome::Complete),
            FinalMethodOutcome::InputRequired(result) => {
                Ok(FinalMethodOutcome::InputRequired(result))
            }
        }
    }

    fn translate_outgoing_final_outcome(
        &self,
        outcome: McpOutcome<CompleteResult<FinalReadResourceResult>>,
    ) -> McpOutcome<CompleteResult<FinalReadResourceResult>> {
        match outcome {
            Outcome::Ok(result) => match self.translate_outgoing_final_result(result) {
                Ok(result) => Outcome::Ok(result),
                Err(error) => Outcome::Err(error),
            },
            Outcome::Err(error) => Outcome::Err(error),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    fn translate_outgoing_final_method_outcome_async(
        &self,
        outcome: McpOutcome<FinalMethodOutcome<FinalReadResourceResult>>,
    ) -> McpOutcome<FinalMethodOutcome<FinalReadResourceResult>> {
        match outcome {
            Outcome::Ok(result) => match self.translate_outgoing_final_method_outcome(result) {
                Ok(result) => Outcome::Ok(result),
                Err(error) => Outcome::Err(error),
            },
            Outcome::Err(error) => Outcome::Err(error),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }
}

impl ResourceHandler for MountedResourceHandler {
    fn definition(&self) -> Resource {
        let mut def = self.inner.definition();
        def.uri.clone_from(&self.mounted_uri);
        def
    }

    fn final_client_direct_https(&self) -> bool {
        self.inner.final_client_direct_https()
    }

    fn template(&self) -> Option<ResourceTemplate> {
        self.mounted_template.clone()
    }

    fn final_title(&self) -> Option<&str> {
        self.inner.final_title()
    }

    fn final_icons(&self) -> Option<&[RawIcon]> {
        self.inner.final_icons()
    }

    fn final_annotations(&self) -> Option<&Annotations> {
        self.inner.final_annotations()
    }

    fn final_metadata(&self) -> Option<&OpenMetadata> {
        self.inner.final_metadata()
    }

    fn final_template_title(&self) -> Option<&str> {
        self.inner.final_template_title()
    }

    fn final_template_icons(&self) -> Option<&[RawIcon]> {
        self.inner.final_template_icons()
    }

    fn final_template_annotations(&self) -> Option<&Annotations> {
        self.inner.final_template_annotations()
    }

    fn final_template_metadata(&self) -> Option<&OpenMetadata> {
        self.inner.final_template_metadata()
    }

    fn icon(&self) -> Option<&Icon> {
        self.inner.icon()
    }

    fn version(&self) -> Option<&str> {
        self.inner.version()
    }

    fn tags(&self) -> &[String] {
        self.inner.tags()
    }

    fn timeout(&self) -> Option<Duration> {
        self.inner.timeout()
    }

    fn final_resource_read_cache_hint_provenance(&self) -> FinalResourceReadCacheHintProvenance {
        self.inner.final_resource_read_cache_hint_provenance()
    }

    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
        self.inner
            .read(ctx)
            .map(|contents| self.translate_outgoing_contents(contents))
    }

    fn read_with_uri(
        &self,
        ctx: &McpContext,
        uri: &str,
        params: &UriParams,
    ) -> McpResult<Vec<ResourceContent>> {
        let source_uri = self.translate_incoming_uri(uri)?;
        self.inner
            .read_with_uri(ctx, &source_uri, params)
            .map(|contents| self.translate_outgoing_contents(contents))
    }

    fn read_async_with_uri<'a>(
        &'a self,
        ctx: &'a McpContext,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
        Box::pin(async move {
            let source_uri = match self.translate_incoming_uri(uri) {
                Ok(source_uri) => source_uri,
                Err(error) => return Outcome::Err(error),
            };
            self.inner
                .read_async_with_uri(ctx, &source_uri, params)
                .await
                .map(|contents| self.translate_outgoing_contents(contents))
        })
    }

    fn read_async<'a>(
        &'a self,
        ctx: &'a McpContext,
    ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
        Box::pin(async move {
            self.inner
                .read_async(ctx)
                .await
                .map(|contents| self.translate_outgoing_contents(contents))
        })
    }

    fn read_final(&self, ctx: &McpContext) -> McpResult<CompleteResult<FinalReadResourceResult>> {
        self.inner
            .read_final(ctx)
            .and_then(|result| self.translate_outgoing_final_result(result))
    }

    fn read_final_with_uri(
        &self,
        ctx: &McpContext,
        uri: &str,
        params: &UriParams,
    ) -> McpResult<CompleteResult<FinalReadResourceResult>> {
        let source_uri = self.translate_incoming_uri(uri)?;
        self.inner
            .read_final_with_uri(ctx, &source_uri, params)
            .and_then(|result| self.translate_outgoing_final_result(result))
    }

    fn read_final_outcome(
        &self,
        ctx: &McpContext,
    ) -> McpResult<FinalMethodOutcome<FinalReadResourceResult>> {
        self.inner
            .read_final_outcome(ctx)
            .and_then(|result| self.translate_outgoing_final_method_outcome(result))
    }

    fn read_final_outcome_with_uri(
        &self,
        ctx: &McpContext,
        uri: &str,
        params: &UriParams,
    ) -> McpResult<FinalMethodOutcome<FinalReadResourceResult>> {
        let source_uri = self.translate_incoming_uri(uri)?;
        self.inner
            .read_final_outcome_with_uri(ctx, &source_uri, params)
            .and_then(|result| self.translate_outgoing_final_method_outcome(result))
    }

    fn read_final_async<'a>(
        &'a self,
        ctx: &'a McpContext,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalReadResourceResult>>> {
        Box::pin(async move {
            self.translate_outgoing_final_outcome(self.inner.read_final_async(ctx).await)
        })
    }

    fn read_final_async_with_uri<'a>(
        &'a self,
        ctx: &'a McpContext,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalReadResourceResult>>> {
        Box::pin(async move {
            let source_uri = match self.translate_incoming_uri(uri) {
                Ok(source_uri) => source_uri,
                Err(error) => return Outcome::Err(error),
            };
            self.translate_outgoing_final_outcome(
                self.inner
                    .read_final_async_with_uri(ctx, &source_uri, params)
                    .await,
            )
        })
    }

    fn read_final_outcome_async<'a>(
        &'a self,
        ctx: &'a McpContext,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalReadResourceResult>>> {
        Box::pin(async move {
            self.translate_outgoing_final_method_outcome_async(
                self.inner.read_final_outcome_async(ctx).await,
            )
        })
    }

    fn read_final_outcome_async_with_uri<'a>(
        &'a self,
        ctx: &'a McpContext,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalReadResourceResult>>> {
        Box::pin(async move {
            let source_uri = match self.translate_incoming_uri(uri) {
                Ok(source_uri) => source_uri,
                Err(error) => return Outcome::Err(error),
            };
            self.translate_outgoing_final_method_outcome_async(
                self.inner
                    .read_final_outcome_async_with_uri(ctx, &source_uri, params)
                    .await,
            )
        })
    }

    fn read_async_with_uri_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
        Box::pin(async move {
            let source_uri = match self.translate_incoming_uri(uri) {
                Ok(source_uri) => source_uri,
                Err(error) => return Outcome::Err(error),
            };
            self.inner
                .read_async_with_uri_in_request(ctx, request_cx, &source_uri, params)
                .await
                .map(|contents| self.translate_outgoing_contents(contents))
        })
    }

    fn read_final_async_with_uri_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalReadResourceResult>>> {
        Box::pin(async move {
            let source_uri = match self.translate_incoming_uri(uri) {
                Ok(source_uri) => source_uri,
                Err(error) => return Outcome::Err(error),
            };
            self.translate_outgoing_final_outcome(
                self.inner
                    .read_final_async_with_uri_in_request(ctx, request_cx, &source_uri, params)
                    .await,
            )
        })
    }

    fn read_final_outcome_async_with_uri_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        uri: &'a str,
        params: &'a UriParams,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalReadResourceResult>>> {
        Box::pin(async move {
            let source_uri = match self.translate_incoming_uri(uri) {
                Ok(source_uri) => source_uri,
                Err(error) => return Outcome::Err(error),
            };
            self.translate_outgoing_final_method_outcome_async(
                self.inner
                    .read_final_outcome_async_with_uri_in_request(
                        ctx,
                        request_cx,
                        &source_uri,
                        params,
                    )
                    .await,
            )
        })
    }

    fn read_final_outcome_async_with_uri_resuming_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        uri: &'a str,
        params: &'a UriParams,
        resume_inputs: Option<&'a MrtrCompletedInputs>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalReadResourceResult>>> {
        Box::pin(async move {
            let source_uri = match self.translate_incoming_uri(uri) {
                Ok(source_uri) => source_uri,
                Err(error) => return Outcome::Err(error),
            };
            self.translate_outgoing_final_method_outcome_async(
                self.inner
                    .read_final_outcome_async_with_uri_resuming_in_request(
                        ctx,
                        request_cx,
                        &source_uri,
                        params,
                        resume_inputs,
                    )
                    .await,
            )
        })
    }
}

/// A wrapper for a prompt handler that overrides its name.
///
/// Used by `mount()` to prefix prompt names when mounting from another server.
pub struct MountedPromptHandler {
    inner: BoxedPromptHandler,
    mounted_name: String,
}

impl MountedPromptHandler {
    /// Creates a new mounted prompt handler with the given name.
    pub fn new(inner: BoxedPromptHandler, mounted_name: String) -> Self {
        Self {
            inner,
            mounted_name,
        }
    }
}

impl PromptHandler for MountedPromptHandler {
    fn definition(&self) -> Prompt {
        let mut def = self.inner.definition();
        def.name.clone_from(&self.mounted_name);
        def
    }

    fn final_client_direct_https(&self) -> bool {
        self.inner.final_client_direct_https()
    }

    fn final_title(&self) -> Option<&str> {
        self.inner.final_title()
    }

    fn final_icons(&self) -> Option<&[RawIcon]> {
        self.inner.final_icons()
    }

    fn final_metadata(&self) -> Option<&OpenMetadata> {
        self.inner.final_metadata()
    }

    fn icon(&self) -> Option<&Icon> {
        self.inner.icon()
    }

    fn version(&self) -> Option<&str> {
        self.inner.version()
    }

    fn tags(&self) -> &[String] {
        self.inner.tags()
    }

    fn timeout(&self) -> Option<Duration> {
        self.inner.timeout()
    }

    fn get(
        &self,
        ctx: &McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        self.inner.get(ctx, arguments)
    }

    fn get_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<Vec<PromptMessage>>> {
        self.inner.get_async(ctx, arguments)
    }

    fn get_final(
        &self,
        ctx: &McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> McpResult<CompleteResult<FinalGetPromptResult>> {
        self.inner.get_final(ctx, arguments)
    }

    fn get_final_outcome(
        &self,
        ctx: &McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> McpResult<FinalMethodOutcome<FinalGetPromptResult>> {
        self.inner.get_final_outcome(ctx, arguments)
    }

    fn get_final_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalGetPromptResult>>> {
        self.inner.get_final_async(ctx, arguments)
    }

    fn get_final_outcome_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalGetPromptResult>>> {
        self.inner.get_final_outcome_async(ctx, arguments)
    }

    fn get_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<Vec<PromptMessage>>> {
        self.inner.get_async_in_request(ctx, request_cx, arguments)
    }

    fn get_final_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<CompleteResult<FinalGetPromptResult>>> {
        self.inner
            .get_final_async_in_request(ctx, request_cx, arguments)
    }

    fn get_final_outcome_async_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalGetPromptResult>>> {
        self.inner
            .get_final_outcome_async_in_request(ctx, request_cx, arguments)
    }

    fn get_final_outcome_async_resuming_in_request<'a>(
        &'a self,
        ctx: &'a McpContext,
        request_cx: &'a Cx,
        arguments: std::collections::HashMap<String, String>,
        resume_inputs: Option<&'a MrtrCompletedInputs>,
    ) -> BoxFuture<'a, McpOutcome<FinalMethodOutcome<FinalGetPromptResult>>> {
        self.inner.get_final_outcome_async_resuming_in_request(
            ctx,
            request_cx,
            arguments,
            resume_inputs,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::Cx;
    use std::sync::{
        Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    };

    fn input_required_result(request_state: &str) -> InputRequiredResult {
        let input = format!(
            r#"{{"resultType":"input_required","inputRequests":{{"confirmation":{{"type":"boolean"}}}},"requestState":"{request_state}"}}"#
        );
        let (decoded, diagnostic) = decode_peer_result(
            &input,
            ResultPeerEra::Modern,
            &CoreResultDiscriminatorPolicy,
        )
        .expect("final input-required result is admitted");
        assert_eq!(diagnostic, None);
        let DecodedResult::InputRequired(result) = decoded else {
            panic!("input-required discriminator selects its final result branch");
        };
        result
    }

    fn encode_input_required(result: &InputRequiredResult) -> String {
        encode_result(&DecodedResult::InputRequired(result.clone()))
    }

    #[test]
    fn handler_final_complete_contract_positive() {
        let payload = serde_json::json!({
            "content": [{"type": "text", "text": "shipped handler result"}],
            "isError": false,
        });

        let encoded = encode_final_complete_result(payload.clone())
            .expect("a complete handler payload is admitted by the final result contract");

        assert_eq!(
            encoded.get("resultType"),
            Some(&serde_json::json!("complete"))
        );
        assert_eq!(encoded.get("content"), payload.get("content"));
        assert_eq!(encoded.get("isError"), payload.get("isError"));
    }

    #[test]
    fn handler_final_complete_contract_planted_negative() {
        let baseline = serde_json::json!({
            "content": [{"type": "text", "text": "shipped handler result"}],
            "isError": false,
        });
        let mut planted = baseline.clone();
        planted
            .as_object_mut()
            .expect("complete payload is an object")
            .insert(
                "resultType".to_string(),
                serde_json::json!("input_required"),
            );

        assert_eq!(
            baseline.get("content"),
            planted.get("content"),
            "the discriminator is the sole planted dimension"
        );
        assert_eq!(baseline.get("isError"), planted.get("isError"));
        let planted_before = planted.clone();

        encode_final_complete_result(baseline)
            .expect("the baseline must remain a valid complete payload");
        let error = encode_final_complete_result(planted.clone())
            .expect_err("a handler cannot preselect a different final result discriminator");

        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);
        assert_eq!(
            planted, planted_before,
            "the rejected payload remains unchanged for callers that retry or log it"
        );
    }

    fn custom_icon() -> &'static Icon {
        static ICON: OnceLock<Icon> = OnceLock::new();
        ICON.get_or_init(|| Icon::new("https://example.test/component.svg"))
    }

    // ── ProgressNotificationSender ───────────────────────────────────

    #[test]
    fn progress_sender_sends_notification_without_total() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender = ProgressNotificationSender::new(ProgressMarker::from("tok-1"), move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        sender.send_progress(0.5, None, None);

        let messages = sent.lock().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].method, "notifications/progress");
        let params = messages[0].params.as_ref().unwrap();
        assert_eq!(params["progress"], 0.5);
        assert!(params.get("total").is_none() || params["total"].is_null());
    }

    #[test]
    fn progress_sender_sends_notification_with_total() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender = ProgressNotificationSender::new(ProgressMarker::from("tok-2"), move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        sender.send_progress(3.0, Some(10.0), None);

        let messages = sent.lock().unwrap();
        let params = messages[0].params.as_ref().unwrap();
        assert_eq!(params["progress"], 3.0);
        assert_eq!(params["total"], 10.0);
    }

    #[test]
    fn public_final_context_progress_preserves_beyond_f64_number_lexemes() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let reporter = ProgressNotificationSender::new_final(
            ProgressMarker::from("final-progress"),
            move |request| {
                sent_clone
                    .lock()
                    .expect("notification collection is not poisoned")
                    .push(request);
            },
        )
        .into_reporter();
        let context = McpContext::with_progress(Cx::for_testing(), 2715, reporter);
        let progress: serde_json::Number =
            serde_json::from_str("1e400").expect("arbitrary-precision progress parses");
        let total: serde_json::Number =
            serde_json::from_str("1e400").expect("arbitrary-precision total parses");
        context.report_progress_exact(progress, Some(total), Some("retained"));

        let notifications = sent
            .lock()
            .expect("notification collection is not poisoned");
        assert_eq!(notifications.len(), 1);
        let wire = serde_json::to_string(
            notifications[0]
                .params
                .as_ref()
                .expect("notification has parameters"),
        )
        .expect("final progress parameters serialize");
        assert!(wire.contains("\"progressToken\":\"final-progress\""));
        // The pinned serde_json normalizes the exponent spelling AT PARSE
        // ("1e400" -> "1e+400"), before the reporter ever sees the number;
        // what this test proves is that the beyond-f64 VALUE survives without
        // an IEEE-754 conversion (which would be "inf"/an error, not 1e+400).
        assert!(wire.contains("\"progress\":1e+400"));
        assert!(wire.contains("\"total\":1e+400"));
    }

    #[test]
    fn public_legacy_context_exact_progress_emits_nothing() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let reporter = ProgressNotificationSender::new(
            ProgressMarker::from("ordinary-final-progress"),
            move |request| {
                sent_clone
                    .lock()
                    .expect("notification collection is not poisoned")
                    .push(request);
            },
        )
        .into_reporter();
        let context = McpContext::with_progress(Cx::for_testing(), 2766, reporter);
        context.report_progress_exact(
            serde_json::from_str("1e400").expect("arbitrary-precision progress parses"),
            Some(serde_json::from_str("1e400").expect("arbitrary-precision total parses")),
            Some("complete"),
        );
        assert!(
            sent.lock()
                .expect("notification collection is not poisoned")
                .is_empty(),
            "the otherwise identical exact progress must not cross a legacy sender"
        );
    }

    #[test]
    fn public_final_context_exact_progress_admits_signed_and_greater_than_total_values() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let reporter = ProgressNotificationSender::new_final(
            ProgressMarker::from("unconstrained-final-progress"),
            move |request| {
                sent_clone
                    .lock()
                    .expect("notification collection is not poisoned")
                    .push(request);
            },
        )
        .into_reporter();
        let context = McpContext::with_progress(Cx::for_testing(), 2804, reporter);

        context.report_progress_exact(
            serde_json::from_str("1e400").expect("unchanged progress parses"),
            Some(serde_json::from_str("1e399").expect("one-variable smaller total parses")),
            Some("complete"),
        );
        context.report_progress_exact(
            serde_json::from_str("-1").expect("negative progress parses"),
            Some(serde_json::from_str("-2").expect("negative total parses")),
            Some("rollback"),
        );

        let notifications = sent
            .lock()
            .expect("notification collection is not poisoned");
        assert_eq!(notifications.len(), 2);
        let first = serde_json::to_string(
            notifications[0]
                .params
                .as_ref()
                .expect("first notification has parameters"),
        )
        .expect("first final progress parameters serialize");
        let second = serde_json::to_string(
            notifications[1]
                .params
                .as_ref()
                .expect("second notification has parameters"),
        )
        .expect("second final progress parameters serialize");
        assert!(first.contains("\"progress\":1e+400"));
        assert!(first.contains("\"total\":1e+399"));
        assert!(second.contains("\"progress\":-1"));
        assert!(second.contains("\"total\":-2"));
    }

    fn final_progress_number(source: &str) -> serde_json::Number {
        serde_json::from_str(source).expect("finite JSON number parses")
    }

    #[test]
    fn final_progress_runtime_accepts_negative_and_greater_than_total_values() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let runtime = Arc::new(FinalProgressRuntime::new(
            ProgressMarker::from("runtime-progress"),
            move |request| {
                sent_clone
                    .lock()
                    .expect("notification collection is not poisoned")
                    .push(request);
            },
        ));

        runtime.send_progress_exact(
            final_progress_number("-2"),
            Some(final_progress_number("-3")),
            Some("negative"),
        );
        assert!(runtime.flush_pending());
        runtime.send_progress_exact(
            final_progress_number("12000"),
            Some(final_progress_number("11999")),
            Some("beyond total"),
        );
        assert!(runtime.finalize());

        let sent = sent
            .lock()
            .expect("notification collection is not poisoned");
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].params.as_ref().unwrap()["progress"], -2);
        assert_eq!(sent[0].params.as_ref().unwrap()["total"], -3);
        assert_eq!(sent[1].params.as_ref().unwrap()["progress"], 12_000);
        assert_eq!(sent[1].params.as_ref().unwrap()["total"], 11_999);
    }

    #[test]
    fn final_progress_runtime_rejects_regression_without_replacing_pending_value() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let runtime =
            FinalProgressRuntime::new(ProgressMarker::from("runtime-regression"), move |request| {
                sent_clone
                    .lock()
                    .expect("notification collection is not poisoned")
                    .push(request);
            });

        runtime.send_progress_exact(
            final_progress_number("12"),
            Some(final_progress_number("11")),
            Some("accepted"),
        );
        // This differs only in the forbidden monotonic dimension. The total
        // remains smaller than progress in both frames.
        runtime.send_progress_exact(
            final_progress_number("11"),
            Some(final_progress_number("10")),
            Some("regression"),
        );
        assert!(runtime.finalize());

        let sent = sent
            .lock()
            .expect("notification collection is not poisoned");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].params.as_ref().unwrap()["progress"], 12);
        assert_eq!(sent[0].params.as_ref().unwrap()["total"], 11);
        assert_eq!(
            sent[0].params.as_ref().unwrap()["message"],
            "accepted",
            "the rejected frame leaves the pending observable unchanged"
        );
    }

    #[test]
    fn final_progress_runtime_coalesces_increasing_updates_to_the_latest_value() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let runtime =
            FinalProgressRuntime::new(ProgressMarker::from("runtime-coalesce"), move |request| {
                sent_clone
                    .lock()
                    .expect("notification collection is not poisoned")
                    .push(request);
            });

        for progress in [1, 2, 3] {
            runtime.send_progress_exact(
                final_progress_number(&progress.to_string()),
                None,
                Some("coalesced"),
            );
        }
        assert!(runtime.flush_pending());
        assert!(!runtime.flush_pending());

        let sent = sent
            .lock()
            .expect("notification collection is not poisoned");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].params.as_ref().unwrap()["progress"], 3);
    }

    #[test]
    fn final_progress_runtime_cancellation_discards_pending_while_finalization_flushes_it() {
        let finalized = Arc::new(Mutex::new(Vec::new()));
        let finalized_clone = Arc::clone(&finalized);
        let finalizing_runtime =
            FinalProgressRuntime::new(ProgressMarker::from("runtime-finalize"), move |request| {
                finalized_clone
                    .lock()
                    .expect("notification collection is not poisoned")
                    .push(request);
            });
        finalizing_runtime.send_progress_exact(final_progress_number("1"), None, None);
        finalizing_runtime.send_progress_exact(final_progress_number("2"), None, None);
        assert!(finalizing_runtime.finalize());
        assert!(!finalizing_runtime.cancel());
        assert_eq!(
            finalized
                .lock()
                .expect("notification collection is not poisoned")
                .as_slice()[0]
                .params
                .as_ref()
                .unwrap()["progress"],
            2
        );

        let cancelled = Arc::new(Mutex::new(Vec::new()));
        let cancelled_clone = Arc::clone(&cancelled);
        let cancelled_runtime =
            FinalProgressRuntime::new(ProgressMarker::from("runtime-cancel"), move |request| {
                cancelled_clone
                    .lock()
                    .expect("notification collection is not poisoned")
                    .push(request);
            });
        cancelled_runtime.send_progress_exact(final_progress_number("1"), None, None);
        cancelled_runtime.send_progress_exact(final_progress_number("2"), None, None);
        assert!(cancelled_runtime.cancel());
        assert!(!cancelled_runtime.finalize());
        assert!(!cancelled_runtime.flush_pending());
        assert!(
            cancelled
                .lock()
                .expect("notification collection is not poisoned")
                .is_empty(),
            "cancellation differs only in winning the terminal race"
        );
    }

    #[test]
    fn progress_sender_sends_notification_with_message() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender = ProgressNotificationSender::new(ProgressMarker::from("tok-3"), move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        sender.send_progress(1.0, Some(5.0), Some("loading"));

        let messages = sent.lock().unwrap();
        let params = messages[0].params.as_ref().unwrap();
        assert_eq!(params["message"], "loading");
    }

    #[test]
    fn progress_sender_rejects_non_finite_progress_and_total() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender =
            ProgressNotificationSender::new(ProgressMarker::from("finite-check"), move |request| {
                sent_clone.lock().unwrap().push(request);
            });

        for (progress, total) in [
            (f64::NAN, None),
            (f64::INFINITY, None),
            (f64::NEG_INFINITY, None),
            (1.0, Some(f64::NAN)),
            (1.0, Some(f64::INFINITY)),
            (1.0, Some(f64::NEG_INFINITY)),
        ] {
            sender.send_progress(progress, total, Some("must not be sent"));
        }

        assert!(sent.lock().unwrap().is_empty());
    }

    #[test]
    fn progress_sender_rejects_serialization_failure() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender = ProgressNotificationSender::new(
            ProgressMarker::from("serialization-check"),
            move |request| {
                sent_clone.lock().unwrap().push(request);
            },
        );

        sender.send_progress_with_serializer(1.0, Some(2.0), None, |_| {
            Result::<serde_json::Value, ()>::Err(())
        });

        assert!(sent.lock().unwrap().is_empty());
    }

    #[test]
    fn progress_sender_contains_callback_panic() {
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let callback_attempts = Arc::clone(&attempts);
        let sender =
            ProgressNotificationSender::new(ProgressMarker::from("panic-check"), move |_request| {
                callback_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                panic!("progress callback panic payload");
            });

        sender.send_progress(1.0, Some(2.0), None);

        assert_eq!(attempts.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn progress_sender_debug_redacts_marker() {
        let canary = "progress-marker-debug-canary";
        let sender = ProgressNotificationSender::new(ProgressMarker::from(canary), |_| {});
        let debug = format!("{:?}", sender);

        assert!(debug.contains("ProgressNotificationSender"));
        assert!(!debug.contains(canary));
        assert!(!debug.contains("marker"));
    }

    #[test]
    fn progress_sender_into_reporter() {
        let sender = ProgressNotificationSender::new(ProgressMarker::from("tok-rpt"), |_| {});
        let _reporter = sender.into_reporter();
    }

    // ── BidirectionalSenders ─────────────────────────────────────────

    #[test]
    fn bidirectional_senders_default_is_empty() {
        let senders = BidirectionalSenders::new();
        assert!(senders.sampling.is_none());
        assert!(senders.elicitation.is_none());
        assert!(senders.roots.is_none());
    }

    #[test]
    fn bidirectional_senders_debug_shows_presence() {
        let senders = BidirectionalSenders::new();
        let debug = format!("{:?}", senders);
        assert!(debug.contains("sampling: false"));
        assert!(debug.contains("elicitation: false"));
        assert!(debug.contains("roots: false"));
    }

    // ── create_context_with_progress ─────────────────────────────────

    #[test]
    fn create_context_no_progress_no_state() {
        let cx = Cx::for_testing();
        let ctx = create_context_with_progress(cx, 42, None, None, |_| {});
        assert_eq!(ctx.request_id(), 42);
    }

    #[test]
    fn create_context_with_progress_marker() {
        let cx = Cx::for_testing();
        let marker = ProgressMarker::from("ctx-pm");
        let ctx = create_context_with_progress(cx, 7, Some(marker), None, |_| {});
        assert_eq!(ctx.request_id(), 7);
    }

    #[test]
    fn create_context_with_state_only() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        state.set("k", &"v");
        let ctx = create_context_with_progress(cx, 10, None, Some(state), |_| {});
        let val: Option<String> = ctx.get_state("k");
        assert_eq!(val.as_deref(), Some("v"));
    }

    #[test]
    fn create_context_with_progress_and_state() {
        let cx = Cx::for_testing();
        let marker = ProgressMarker::from("both");
        let state = SessionState::new();
        let ctx = create_context_with_progress(cx, 99, Some(marker), Some(state), |_| {});
        assert_eq!(ctx.request_id(), 99);
    }

    // ── Minimal ToolHandler impl for testing ─────────────────────────

    struct StubTool;

    impl ToolHandler for StubTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "stub".to_string(),
                description: Some("a stub tool".to_string()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text(format!("echo: {args}"))])
        }
    }

    #[test]
    fn tool_handler_defaults_return_none() {
        let tool = StubTool;
        assert!(tool.icon().is_none());
        assert!(tool.version().is_none());
        assert!(tool.tags().is_empty());
        assert!(tool.annotations().is_none());
        assert!(tool.output_schema().is_none());
        assert_eq!(
            tool.final_tool_schema_authority(),
            FinalToolSchemaAuthority::Local
        );
        assert!(tool.timeout().is_none());
    }

    #[test]
    fn tool_handler_call_sync() {
        let tool = StubTool;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let result = tool.call(&ctx, serde_json::json!({"x": 1})).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn tool_handler_final_surface_promotes_legacy_content_without_changing_legacy_call() {
        let tool = StubTool;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let legacy = tool
            .call(&ctx, serde_json::json!({"x": 1}))
            .expect("legacy handler result");
        let final_result = tool
            .call_final(&ctx, serde_json::json!({"x": 1}))
            .expect("legacy handler promotes into the final result algebra");

        assert!(matches!(legacy.as_slice(), [Content::Text { .. }]));
        assert!(matches!(
            final_result.payload.content.as_slice(),
            [ContentBlock::Text { .. }]
        ));
        assert!(final_result.meta.server_info.is_none());
    }

    #[test]
    fn tool_handler_default_final_outcome_is_complete_and_preserves_legacy_adapter() {
        let tool = StubTool;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);

        let final_outcome = tool
            .call_final_outcome(&ctx, serde_json::json!({"x": 1}))
            .expect("default final outcome promotes the legacy result");
        let FinalToolOutcome::Complete(final_result) = final_outcome else {
            panic!("a default tool handler must select the final complete branch");
        };
        assert!(matches!(
            final_result.payload.content.as_slice(),
            [ContentBlock::Text { text, .. }] if text == "echo: {\"x\":1}"
        ));

        let legacy = tool
            .call(&ctx, serde_json::json!({"x": 1}))
            .expect("legacy adapter remains callable after the final outcome");
        assert!(matches!(
            legacy.as_slice(),
            [Content::Text { text }] if text == "echo: {\"x\":1}"
        ));
    }

    #[test]
    fn tool_handler_task_creation_outcome_preserves_legacy_adapter() {
        struct TaskCreatingTool {
            legacy_calls: AtomicUsize,
        }

        impl ToolHandler for TaskCreatingTool {
            fn definition(&self) -> Tool {
                StubTool.definition()
            }

            fn declares_final_tasks(&self) -> bool {
                true
            }

            fn call(
                &self,
                _ctx: &McpContext,
                _arguments: serde_json::Value,
            ) -> McpResult<Vec<Content>> {
                self.legacy_calls.fetch_add(1, Ordering::Relaxed);
                Ok(vec![Content::text("exact legacy completion")])
            }

            fn call_final_outcome(
                &self,
                _ctx: &McpContext,
                _arguments: serde_json::Value,
            ) -> McpResult<FinalToolOutcome> {
                Ok(FinalToolOutcome::CreateTask {
                    work_descriptor: FinalTaskWorkDescriptor::new(serde_json::json!({
                        "operation": "durable-tool-work",
                    }))?,
                    status_message: Some("awaiting durable work".to_owned()),
                })
            }
        }

        let tool = TaskCreatingTool {
            legacy_calls: AtomicUsize::new(0),
        };
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let request_cx = Cx::for_testing();

        let Outcome::Ok(final_outcome) = fastmcp_core::block_on(
            tool.call_final_outcome_async_in_request(&ctx, &request_cx, serde_json::json!({})),
        ) else {
            panic!("declared task-capable handler selects a router-owned task creation");
        };
        let FinalToolOutcome::CreateTask {
            work_descriptor,
            status_message: Some(status_message),
        } = final_outcome
        else {
            panic!("task-capable handler must retain non-null initial work and its status");
        };
        assert_eq!(
            work_descriptor.as_value(),
            &serde_json::json!({"operation": "durable-tool-work"})
        );
        assert_eq!(status_message, "awaiting durable work");
        assert_eq!(tool.legacy_calls.load(Ordering::Relaxed), 0);

        let legacy = tool
            .call(&ctx, serde_json::json!({}))
            .expect("legacy adapter remains exact for a task-capable handler");
        assert!(
            matches!(legacy.as_slice(), [Content::Text { text }] if text == "exact legacy completion")
        );
        assert_eq!(tool.legacy_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn tool_handler_undeclared_task_creation_fails_closed_and_preserves_legacy_adapter() {
        struct UndeclaredTaskCreatingTool {
            legacy_calls: AtomicUsize,
        }

        impl ToolHandler for UndeclaredTaskCreatingTool {
            fn definition(&self) -> Tool {
                StubTool.definition()
            }

            fn call(
                &self,
                _ctx: &McpContext,
                _arguments: serde_json::Value,
            ) -> McpResult<Vec<Content>> {
                self.legacy_calls.fetch_add(1, Ordering::Relaxed);
                Ok(vec![Content::text("exact legacy completion")])
            }

            fn call_final_outcome(
                &self,
                _ctx: &McpContext,
                _arguments: serde_json::Value,
            ) -> McpResult<FinalToolOutcome> {
                Ok(FinalToolOutcome::CreateTask {
                    work_descriptor: FinalTaskWorkDescriptor::new(serde_json::json!({
                        "operation": "must-not-run-without-declaration",
                    }))?,
                    status_message: None,
                })
            }
        }

        let tool = UndeclaredTaskCreatingTool {
            legacy_calls: AtomicUsize::new(0),
        };
        assert!(
            !tool.declares_final_tasks(),
            "the declaration is opt-in and defaults to false"
        );
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let request_cx = Cx::for_testing();

        let outcome = fastmcp_core::block_on(tool.call_final_outcome_async_in_request(
            &ctx,
            &request_cx,
            serde_json::json!({}),
        ));
        let Outcome::Err(error) = outcome else {
            panic!("an undeclared task outcome must fail closed");
        };
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidRequest);
        assert_eq!(error.message, UNDECLARED_FINAL_TASK_OUTCOME_ERROR);

        let legacy = tool
            .call(&ctx, serde_json::json!({}))
            .expect("legacy adapter remains exact when final task outcome is rejected");
        assert!(
            matches!(legacy.as_slice(), [Content::Text { text }] if text == "exact legacy completion")
        );
        assert_eq!(tool.legacy_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn task_creation_work_descriptor_rejects_null_before_an_outcome_can_be_constructed() {
        let error = FinalTaskWorkDescriptor::new(serde_json::Value::Null)
            .expect_err("a task-capable handler must not request inert null work");

        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidParams);
        assert_eq!(
            error.message,
            "Final task work descriptor must identify an application operation"
        );
    }

    #[test]
    fn declared_task_capable_handler_preserves_input_required_algebra() {
        struct InputRequiredTool {
            result: InputRequiredResult,
            legacy_calls: AtomicUsize,
        }

        impl ToolHandler for InputRequiredTool {
            fn definition(&self) -> Tool {
                StubTool.definition()
            }

            fn declares_final_tasks(&self) -> bool {
                true
            }

            fn call(
                &self,
                _ctx: &McpContext,
                _arguments: serde_json::Value,
            ) -> McpResult<Vec<Content>> {
                self.legacy_calls.fetch_add(1, Ordering::Relaxed);
                Ok(vec![Content::text("legacy projection")])
            }

            fn call_final_outcome(
                &self,
                _ctx: &McpContext,
                _arguments: serde_json::Value,
            ) -> McpResult<FinalToolOutcome> {
                Ok(FinalToolOutcome::InputRequired(self.result.clone()))
            }
        }

        let tool = InputRequiredTool {
            result: input_required_result("retry-tool-7"),
            legacy_calls: AtomicUsize::new(0),
        };
        let expected = encode_input_required(&tool.result);
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);

        let outcome = tool
            .call_final_outcome(&ctx, serde_json::json!({}))
            .expect("task-capable final handler may select input_required");

        let FinalToolOutcome::InputRequired(result) = outcome else {
            panic!("final handler must preserve the input-required result branch");
        };
        assert_eq!(encode_input_required(&result), expected);
        assert_eq!(tool.legacy_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn tool_handler_legacy_projection_leaves_unprojectable_input_state_unchanged() {
        struct InputRequiredTool {
            result: InputRequiredResult,
            legacy_calls: AtomicUsize,
        }

        impl ToolHandler for InputRequiredTool {
            fn definition(&self) -> Tool {
                StubTool.definition()
            }

            fn call(
                &self,
                _ctx: &McpContext,
                _arguments: serde_json::Value,
            ) -> McpResult<Vec<Content>> {
                self.legacy_calls.fetch_add(1, Ordering::Relaxed);
                Ok(vec![Content::text("legacy projection")])
            }

            fn call_final_outcome(
                &self,
                _ctx: &McpContext,
                _arguments: serde_json::Value,
            ) -> McpResult<FinalToolOutcome> {
                Ok(FinalToolOutcome::InputRequired(self.result.clone()))
            }
        }

        let tool = InputRequiredTool {
            result: input_required_result("retry-tool-7"),
            legacy_calls: AtomicUsize::new(0),
        };
        let original = encode_input_required(&tool.result);
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);

        let legacy = tool
            .call(&ctx, serde_json::json!({}))
            .expect("legacy handler result remains exact");

        assert!(
            matches!(legacy.as_slice(), [Content::Text { text }] if text == "legacy projection")
        );
        assert_eq!(tool.legacy_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            encode_input_required(&tool.result),
            original,
            "legacy projection must not coerce or mutate final-only requestState"
        );
    }

    #[test]
    fn tool_handler_final_catalog_accessors_preserve_final_only_fields() {
        struct FinalCatalogTool {
            metadata: OpenMetadata,
            icons: Vec<RawIcon>,
        }

        impl ToolHandler for FinalCatalogTool {
            fn definition(&self) -> Tool {
                (StubTool).definition()
            }

            fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
                Ok(vec![Content::text("final catalog")])
            }

            fn final_title(&self) -> Option<&str> {
                Some("Final Title")
            }

            fn final_icons(&self) -> Option<&[RawIcon]> {
                Some(&self.icons)
            }

            fn final_metadata(&self) -> Option<&OpenMetadata> {
                Some(&self.metadata)
            }
        }

        let metadata = OpenMetadata::try_from_entries([(
            "com.example/catalog".to_owned(),
            serde_json::json!({"preserve": true}),
        )])
        .expect("final metadata");
        let icons = vec![RawIcon::try_new("https://example.test/icon.png").expect("final icon")];
        let tool = FinalCatalogTool { metadata, icons };

        assert_eq!(tool.final_title(), Some("Final Title"));
        assert_eq!(tool.final_icons().map(<[RawIcon]>::len), Some(1));
        assert_eq!(
            tool.final_metadata()
                .and_then(|metadata| metadata.get("com.example/catalog")),
            Some(&serde_json::json!({"preserve": true}))
        );
        assert!(tool.output_schema().is_none());
    }

    #[test]
    fn tool_handler_call_sync_error() {
        struct FailTool;
        impl ToolHandler for FailTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "fail".to_string(),
                    description: None,
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                    annotations: None,
                }
            }
            fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
                Err(McpError::internal_error("boom"))
            }
        }

        let tool = FailTool;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let err = tool.call(&ctx, serde_json::json!({})).unwrap_err();
        assert!(err.message.contains("boom"));
    }

    // ── Minimal ResourceHandler impl for testing ─────────────────────

    struct StubResource;

    impl ResourceHandler for StubResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "file:///stub".to_string(),
                name: "stub".to_string(),
                description: None,
                mime_type: Some("text/plain".to_string()),
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![ResourceContent {
                uri: "file:///stub".to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("hello".to_string()),
                blob: None,
            }])
        }
    }

    #[test]
    fn resource_handler_defaults_return_none() {
        let res = StubResource;
        assert!(res.template().is_none());
        assert!(res.icon().is_none());
        assert!(res.version().is_none());
        assert!(res.tags().is_empty());
        assert!(res.timeout().is_none());
    }

    #[test]
    fn resource_handler_read_with_uri_delegates_to_read() {
        let res = StubResource;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let params = UriParams::new();
        let result = res.read_with_uri(&ctx, "file:///stub", &params).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn resource_handler_final_surface_promotes_legacy_content_without_changing_legacy_read() {
        let resource = StubResource;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let legacy = resource.read(&ctx).expect("legacy handler result");
        let final_result = resource
            .read_final(&ctx)
            .expect("legacy resource promotes into the final result algebra");

        assert_eq!(legacy[0].uri, "file:///stub");
        assert!(matches!(
            final_result.payload.contents.as_slice(),
            [EmbeddedResourceContents::Text { uri, text, .. }]
                if uri.as_str() == "file:///stub" && text == "hello"
        ));
        assert_eq!(
            final_result.payload.ttl_ms.as_str(),
            DEFAULT_FINAL_RESOURCE_TTL_MS.to_string()
        );
        assert_eq!(final_result.payload.cache_scope, CacheScope::Private);
    }

    #[test]
    fn final_resource_default_preserves_uri_without_template_params() {
        struct UriAwareResource;

        impl ResourceHandler for UriAwareResource {
            fn definition(&self) -> Resource {
                StubResource.definition()
            }

            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                Err(McpError::internal_error(
                    "final URI dispatch must not fall back to read",
                ))
            }

            fn read_with_uri(
                &self,
                _ctx: &McpContext,
                uri: &str,
                _params: &UriParams,
            ) -> McpResult<Vec<ResourceContent>> {
                Ok(vec![ResourceContent {
                    uri: uri.to_owned(),
                    mime_type: Some("text/plain".to_owned()),
                    text: Some("matched URI".to_owned()),
                    blob: None,
                }])
            }
        }

        let resource = UriAwareResource;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let result = resource
            .read_final_with_uri(&ctx, "file:///requested", &UriParams::new())
            .expect("final resource dispatch preserves its URI without template parameters");

        assert!(matches!(
            result.payload.contents.as_slice(),
            [EmbeddedResourceContents::Text { uri, text, .. }]
                if uri.as_str() == "file:///requested" && text == "matched URI"
        ));
    }

    // ── Minimal PromptHandler impl for testing ───────────────────────

    struct StubPrompt;

    impl PromptHandler for StubPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "stub".to_string(),
                description: Some("a stub prompt".to_string()),
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _arguments: HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Ok(vec![])
        }
    }

    #[test]
    fn prompt_handler_defaults_return_none() {
        let prompt = StubPrompt;
        assert!(prompt.icon().is_none());
        assert!(prompt.version().is_none());
        assert!(prompt.tags().is_empty());
        assert!(prompt.timeout().is_none());
    }

    #[test]
    fn prompt_handler_final_surface_promotes_legacy_messages_without_changing_legacy_get() {
        let prompt = StubPrompt;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let legacy = prompt
            .get(&ctx, HashMap::new())
            .expect("legacy handler result");
        let final_result = prompt
            .get_final(&ctx, HashMap::new())
            .expect("legacy prompt promotes into the final result algebra");

        assert!(legacy.is_empty());
        assert!(final_result.payload.messages.is_empty());
        assert!(final_result.payload.description.is_none());
        assert!(final_result.meta.server_info.is_none());
    }

    // ── MountedToolHandler ───────────────────────────────────────────

    #[test]
    fn mounted_tool_handler_overrides_name() {
        let inner = Box::new(StubTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "prefix_stub".to_string());
        let def = mounted.definition();
        assert_eq!(def.name, "prefix_stub");
        assert_eq!(def.description.as_deref(), Some("a stub tool"));
    }

    #[test]
    fn mounted_tool_handler_delegates_defaults() {
        let inner = Box::new(StubTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "m_stub".to_string());
        assert!(mounted.tags().is_empty());
        assert!(mounted.annotations().is_none());
        assert!(mounted.output_schema().is_none());
        assert_eq!(
            mounted.final_tool_schema_authority(),
            FinalToolSchemaAuthority::Local
        );
        assert!(mounted.timeout().is_none());
    }

    #[test]
    fn mounted_tool_handler_preserves_upstream_schema_authority() {
        struct UpstreamSchemaTool;

        impl ToolHandler for UpstreamSchemaTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "upstream-schema".to_string(),
                    description: None,
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: Some(serde_json::json!({"type": "string"})),
                    icon: None,
                    version: None,
                    tags: Vec::new(),
                    annotations: None,
                }
            }

            fn final_definition(&self) -> Option<FinalTool> {
                Some(
                    serde_json::from_value(serde_json::json!({
                        "name": "upstream-schema",
                        "inputSchema": {"type": "object"},
                        "outputSchema": {"type": "string"},
                        "_meta": {"com.example/proxy": {"retained": true}}
                    }))
                    .expect("the exact-final mounted fixture is valid"),
                )
            }

            fn final_tool_schema_authority(&self) -> FinalToolSchemaAuthority {
                FinalToolSchemaAuthority::Upstream
            }

            fn upstream_final_tool_schema_registration(
                &self,
            ) -> Option<UpstreamFinalToolSchemaRegistration> {
                Some(UpstreamFinalToolSchemaRegistration::exact_proxy())
            }

            fn call(
                &self,
                _ctx: &McpContext,
                _arguments: serde_json::Value,
            ) -> McpResult<Vec<Content>> {
                Ok(Vec::new())
            }
        }

        let mounted = MountedToolHandler::new(
            Box::new(UpstreamSchemaTool) as BoxedToolHandler,
            "m_upstream".to_string(),
        );
        assert_eq!(
            mounted.final_tool_schema_authority(),
            FinalToolSchemaAuthority::Upstream,
            "mounting must not turn an exact-final proxy into a locally validated handler"
        );
        assert!(
            mounted.upstream_final_tool_schema_registration().is_some(),
            "mounting must retain the sealed upstream-schema registration"
        );
        assert_eq!(
            mounted
                .final_definition()
                .expect("mounted handler retains the exact final definition")
                .output_schema,
            Some(serde_json::json!({"type": "string"}))
        );
    }

    #[test]
    fn mounted_tool_handler_delegates_call() {
        let inner = Box::new(StubTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "m_stub".to_string());
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let result = mounted.call(&ctx, serde_json::json!({})).unwrap();
        assert!(!result.is_empty());
    }

    // ── MountedResourceHandler ───────────────────────────────────────

    #[test]
    fn mounted_resource_handler_overrides_uri() {
        let inner = Box::new(StubResource) as BoxedResourceHandler;
        let mounted = MountedResourceHandler::new(
            inner,
            "file:///stub".to_string(),
            "file:///mounted".to_string(),
        );
        let def = mounted.definition();
        assert_eq!(def.uri, "file:///mounted");
        assert_eq!(def.name, "stub");
    }

    #[test]
    fn mounted_resource_handler_template_none_by_default() {
        let inner = Box::new(StubResource) as BoxedResourceHandler;
        let mounted =
            MountedResourceHandler::new(inner, "file:///stub".to_string(), "file:///m".to_string());
        assert!(mounted.template().is_none());
    }

    #[test]
    fn mounted_resource_handler_with_template() {
        let inner = Box::new(StubResource) as BoxedResourceHandler;
        let tmpl = ResourceTemplate {
            uri_template: "file:///items/{id}".to_string(),
            name: "items".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let mounted = MountedResourceHandler::with_template(
            inner,
            "file:///items/{id}".to_string(),
            "file:///items/{id}".to_string(),
            tmpl,
        );
        let t = mounted.template().expect("template set");
        assert_eq!(t.uri_template, "file:///items/{id}");
    }

    #[test]
    fn mounted_resource_handler_delegates_read() {
        let inner = Box::new(StubResource) as BoxedResourceHandler;
        let mounted =
            MountedResourceHandler::new(inner, "file:///stub".to_string(), "file:///m".to_string());
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let result = mounted.read(&ctx).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].uri, "file:///m");
    }

    #[test]
    fn mounted_resource_handler_delegates_tags() {
        let inner = Box::new(StubResource) as BoxedResourceHandler;
        let mounted =
            MountedResourceHandler::new(inner, "file:///stub".to_string(), "file:///m".to_string());
        assert!(mounted.tags().is_empty());
    }

    // ── MountedPromptHandler ─────────────────────────────────────────

    #[test]
    fn mounted_prompt_handler_overrides_name() {
        let inner = Box::new(StubPrompt) as BoxedPromptHandler;
        let mounted = MountedPromptHandler::new(inner, "ns_stub".to_string());
        let def = mounted.definition();
        assert_eq!(def.name, "ns_stub");
        assert_eq!(def.description.as_deref(), Some("a stub prompt"));
    }

    #[test]
    fn mounted_prompt_handler_delegates_defaults() {
        let inner = Box::new(StubPrompt) as BoxedPromptHandler;
        let mounted = MountedPromptHandler::new(inner, "ns_stub".to_string());
        assert!(mounted.tags().is_empty());
        assert!(mounted.timeout().is_none());
    }

    #[test]
    fn mounted_prompt_handler_delegates_get() {
        let inner = Box::new(StubPrompt) as BoxedPromptHandler;
        let mounted = MountedPromptHandler::new(inner, "ns_stub".to_string());
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let result = mounted.get(&ctx, HashMap::new()).unwrap();
        assert!(result.is_empty());
    }

    // ── BidirectionalSenders builders ────────────────────────────────

    struct DummySamplingSender;
    impl fastmcp_core::SamplingSender for DummySamplingSender {
        fn create_message(
            &self,
            _request: fastmcp_core::SamplingRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = McpResult<fastmcp_core::SamplingResponse>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Err(McpError::internal_error("stub")) })
        }
    }

    struct DummyElicitationSender;
    impl fastmcp_core::ElicitationSender for DummyElicitationSender {
        fn elicit(
            &self,
            _request: fastmcp_core::ElicitationRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = McpResult<fastmcp_core::ElicitationResponse>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Err(McpError::internal_error("stub")) })
        }
    }

    struct DummyRootsProvider;
    impl fastmcp_core::RootsProvider for DummyRootsProvider {
        fn list_roots(
            &self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = McpResult<Vec<fastmcp_core::ClientRoot>>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Ok(vec![fastmcp_core::ClientRoot::new("file:///workspace")]) })
        }
    }

    #[test]
    fn bidirectional_senders_with_sampling() {
        let senders =
            BidirectionalSenders::new().with_sampling(Arc::new(DummySamplingSender) as Arc<_>);
        assert!(senders.sampling.is_some());
        assert!(senders.elicitation.is_none());
    }

    #[test]
    fn bidirectional_senders_with_elicitation() {
        let senders = BidirectionalSenders::new()
            .with_elicitation(Arc::new(DummyElicitationSender) as Arc<_>);
        assert!(senders.sampling.is_none());
        assert!(senders.elicitation.is_some());
        assert!(senders.roots.is_none());
    }

    #[test]
    fn bidirectional_senders_with_roots() {
        let senders =
            BidirectionalSenders::new().with_roots(Arc::new(DummyRootsProvider) as Arc<_>);
        assert!(senders.sampling.is_none());
        assert!(senders.elicitation.is_none());
        assert!(senders.roots.is_some());
    }

    #[test]
    fn bidirectional_senders_with_both() {
        let senders = BidirectionalSenders::new()
            .with_sampling(Arc::new(DummySamplingSender) as Arc<_>)
            .with_elicitation(Arc::new(DummyElicitationSender) as Arc<_>);
        assert!(senders.sampling.is_some());
        assert!(senders.elicitation.is_some());
    }

    #[test]
    fn bidirectional_senders_clone() {
        let senders =
            BidirectionalSenders::new().with_sampling(Arc::new(DummySamplingSender) as Arc<_>);
        let cloned = senders.clone();
        assert!(cloned.sampling.is_some());
    }

    #[test]
    fn bidirectional_senders_debug_with_present() {
        let senders = BidirectionalSenders::new()
            .with_sampling(Arc::new(DummySamplingSender) as Arc<_>)
            .with_elicitation(Arc::new(DummyElicitationSender) as Arc<_>);
        let debug = format!("{:?}", senders);
        assert!(debug.contains("sampling: true"));
        assert!(debug.contains("elicitation: true"));
    }

    // ── create_context_with_progress_and_senders ─────────────────────

    #[test]
    fn create_context_with_senders_sampling() {
        let cx = Cx::for_testing();
        let senders =
            BidirectionalSenders::new().with_sampling(Arc::new(DummySamplingSender) as Arc<_>);
        let ctx =
            create_context_with_progress_and_senders(cx, 1, None, None, |_| {}, Some(&senders));
        assert_eq!(ctx.request_id(), 1);
    }

    #[test]
    fn create_context_with_senders_elicitation() {
        let cx = Cx::for_testing();
        let senders = BidirectionalSenders::new()
            .with_elicitation(Arc::new(DummyElicitationSender) as Arc<_>);
        let ctx =
            create_context_with_progress_and_senders(cx, 2, None, None, |_| {}, Some(&senders));
        assert_eq!(ctx.request_id(), 2);
    }

    #[test]
    fn create_context_with_senders_roots_attaches_context_authority() {
        let senders =
            BidirectionalSenders::new().with_roots(Arc::new(DummyRootsProvider) as Arc<_>);
        let ctx = create_context_with_progress_and_senders(
            Cx::for_testing(),
            7,
            None,
            None,
            |_| {},
            Some(&senders),
        );

        assert!(ctx.can_list_roots());
        let roots = fastmcp_core::block_on(ctx.list_roots())
            .expect("attached roots provider reaches the context");
        assert_eq!(
            roots,
            vec![fastmcp_core::ClientRoot::new("file:///workspace")]
        );
    }

    #[test]
    fn create_context_with_senders_and_progress() {
        let cx = Cx::for_testing();
        let marker = ProgressMarker::from("sp");
        let senders =
            BidirectionalSenders::new().with_sampling(Arc::new(DummySamplingSender) as Arc<_>);
        let ctx = create_context_with_progress_and_senders(
            cx,
            3,
            Some(marker),
            None,
            |_| {},
            Some(&senders),
        );
        assert_eq!(ctx.request_id(), 3);
    }

    #[test]
    fn create_context_with_senders_and_state() {
        let cx = Cx::for_testing();
        let state = SessionState::new();
        state.set("key", &"val");
        let senders = BidirectionalSenders::new()
            .with_elicitation(Arc::new(DummyElicitationSender) as Arc<_>);
        let ctx = create_context_with_progress_and_senders(
            cx,
            4,
            None,
            Some(state),
            |_| {},
            Some(&senders),
        );
        let val: Option<String> = ctx.get_state("key");
        assert_eq!(val.as_deref(), Some("val"));
    }

    #[test]
    fn create_context_with_all_options() {
        let cx = Cx::for_testing();
        let marker = ProgressMarker::from("all");
        let state = SessionState::new();
        let senders = BidirectionalSenders::new()
            .with_sampling(Arc::new(DummySamplingSender) as Arc<_>)
            .with_elicitation(Arc::new(DummyElicitationSender) as Arc<_>);
        let ctx = create_context_with_progress_and_senders(
            cx,
            5,
            Some(marker),
            Some(state),
            |_| {},
            Some(&senders),
        );
        assert_eq!(ctx.request_id(), 5);
    }

    #[test]
    fn create_context_with_senders_none() {
        let cx = Cx::for_testing();
        let ctx = create_context_with_progress_and_senders(cx, 6, None, None, |_| {}, None);
        assert_eq!(ctx.request_id(), 6);
        assert!(!ctx.can_list_roots());
    }

    // ── ToolHandler with overrides ───────────────────────────────────

    struct CustomTool;
    impl ToolHandler for CustomTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "custom".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn icon(&self) -> Option<&Icon> {
            Some(custom_icon())
        }

        fn version(&self) -> Option<&str> {
            Some("2.0")
        }

        fn timeout(&self) -> Option<Duration> {
            Some(Duration::from_secs(60))
        }

        fn output_schema(&self) -> Option<serde_json::Value> {
            Some(serde_json::json!({"type": "string"}))
        }

        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text("custom")])
        }
    }

    #[test]
    fn tool_handler_custom_version() {
        assert_eq!(CustomTool.version(), Some("2.0"));
    }

    #[test]
    fn tool_handler_custom_icon() {
        assert_eq!(
            CustomTool.icon().and_then(|icon| icon.src.as_deref()),
            Some("https://example.test/component.svg")
        );
    }

    #[test]
    fn tool_handler_custom_timeout() {
        assert_eq!(CustomTool.timeout(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn tool_handler_custom_output_schema() {
        let schema = CustomTool.output_schema().unwrap();
        assert_eq!(schema["type"], "string");
    }

    // ── ResourceHandler with overrides ───────────────────────────────

    struct CustomResource;
    impl ResourceHandler for CustomResource {
        fn definition(&self) -> Resource {
            Resource {
                uri: "file:///custom".to_string(),
                name: "custom".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn version(&self) -> Option<&str> {
            Some("1.5")
        }

        fn icon(&self) -> Option<&Icon> {
            Some(custom_icon())
        }

        fn timeout(&self) -> Option<Duration> {
            Some(Duration::from_secs(30))
        }

        fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
            Ok(vec![ResourceContent {
                uri: "file:///custom".to_string(),
                mime_type: None,
                text: Some("data".to_string()),
                blob: None,
            }])
        }

        fn read_with_uri(
            &self,
            _ctx: &McpContext,
            uri: &str,
            params: &UriParams,
        ) -> McpResult<Vec<ResourceContent>> {
            let id = params.get("id").cloned().unwrap_or_default();
            Ok(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: None,
                text: Some(format!("item:{id}")),
                blob: None,
            }])
        }
    }

    #[test]
    fn resource_handler_custom_version() {
        assert_eq!(CustomResource.version(), Some("1.5"));
    }

    #[test]
    fn resource_handler_custom_icon() {
        assert_eq!(
            CustomResource.icon().and_then(|icon| icon.src.as_deref()),
            Some("https://example.test/component.svg")
        );
    }

    #[test]
    fn resource_handler_custom_timeout() {
        assert_eq!(CustomResource.timeout(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn resource_handler_read_with_uri_custom() {
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let mut params = UriParams::new();
        params.insert("id".to_string(), "42".to_string());
        let result = CustomResource
            .read_with_uri(&ctx, "file:///items/42", &params)
            .unwrap();
        assert_eq!(result[0].text.as_deref(), Some("item:42"));
    }

    // ── PromptHandler with overrides ─────────────────────────────────

    struct CustomPrompt;
    impl PromptHandler for CustomPrompt {
        fn definition(&self) -> Prompt {
            Prompt {
                name: "custom".to_string(),
                description: None,
                arguments: vec![],
                icon: None,
                version: None,
                tags: vec![],
            }
        }

        fn version(&self) -> Option<&str> {
            Some("3.0")
        }

        fn icon(&self) -> Option<&Icon> {
            Some(custom_icon())
        }

        fn timeout(&self) -> Option<Duration> {
            Some(Duration::from_secs(10))
        }

        fn get(
            &self,
            _ctx: &McpContext,
            _args: HashMap<String, String>,
        ) -> McpResult<Vec<PromptMessage>> {
            Ok(vec![])
        }
    }

    #[test]
    fn prompt_handler_custom_version() {
        assert_eq!(CustomPrompt.version(), Some("3.0"));
    }

    #[test]
    fn prompt_handler_custom_icon() {
        assert_eq!(
            CustomPrompt.icon().and_then(|icon| icon.src.as_deref()),
            Some("https://example.test/component.svg")
        );
    }

    #[test]
    fn prompt_handler_custom_timeout() {
        assert_eq!(CustomPrompt.timeout(), Some(Duration::from_secs(10)));
    }

    // ── MountedToolHandler icon/version delegation ───────────────────

    #[test]
    fn mounted_tool_handler_delegates_icon_and_version() {
        let inner = Box::new(CustomTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "m_custom".to_string());
        assert_eq!(mounted.version(), Some("2.0"));
        assert_eq!(
            mounted.icon().and_then(|icon| icon.src.as_deref()),
            Some("https://example.test/component.svg")
        );
    }

    #[test]
    fn mounted_tool_handler_delegates_timeout() {
        let inner = Box::new(CustomTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "m_custom".to_string());
        assert_eq!(mounted.timeout(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn mounted_tool_handler_delegates_output_schema() {
        let inner = Box::new(CustomTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "m_custom".to_string());
        let schema = mounted.output_schema().unwrap();
        assert_eq!(schema["type"], "string");
    }

    // ── MountedResourceHandler delegates ─────────────────────────────

    #[test]
    fn mounted_resource_handler_delegates_icon_and_version() {
        let inner = Box::new(CustomResource) as BoxedResourceHandler;
        let mounted = MountedResourceHandler::new(
            inner,
            "file:///custom".to_string(),
            "ns/file:///custom".to_string(),
        );
        assert_eq!(mounted.version(), Some("1.5"));
        assert_eq!(
            mounted.icon().and_then(|icon| icon.src.as_deref()),
            Some("https://example.test/component.svg")
        );
    }

    #[test]
    fn mounted_resource_handler_delegates_read_with_uri() {
        let inner = Box::new(CustomResource) as BoxedResourceHandler;
        let mounted = MountedResourceHandler::new(
            inner,
            "file:///custom".to_string(),
            "ns/file:///custom".to_string(),
        );
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let mut params = UriParams::new();
        params.insert("id".to_string(), "99".to_string());
        let result = mounted
            .read_with_uri(&ctx, "ns/file:///items/99", &params)
            .unwrap();
        assert_eq!(result[0].text.as_deref(), Some("item:99"));
        assert_eq!(result[0].uri, "ns/file:///items/99");
        assert!(
            mounted
                .read_with_uri(&ctx, "other/file:///items/99", &params)
                .is_err()
        );
    }

    #[test]
    fn mounted_resource_handler_delegates_timeout() {
        let inner = Box::new(CustomResource) as BoxedResourceHandler;
        let mounted = MountedResourceHandler::new(
            inner,
            "file:///custom".to_string(),
            "file:///m".to_string(),
        );
        assert_eq!(mounted.timeout(), Some(Duration::from_secs(30)));
    }

    // ── MountedPromptHandler delegates ───────────────────────────────

    #[test]
    fn mounted_prompt_handler_delegates_icon_and_version() {
        let inner = Box::new(CustomPrompt) as BoxedPromptHandler;
        let mounted = MountedPromptHandler::new(inner, "ns_custom".to_string());
        assert_eq!(mounted.version(), Some("3.0"));
        assert_eq!(
            mounted.icon().and_then(|icon| icon.src.as_deref()),
            Some("https://example.test/component.svg")
        );
    }

    #[test]
    fn mounted_prompt_handler_delegates_timeout() {
        let inner = Box::new(CustomPrompt) as BoxedPromptHandler;
        let mounted = MountedPromptHandler::new(inner, "ns_custom".to_string());
        assert_eq!(mounted.timeout(), Some(Duration::from_secs(10)));
    }

    #[test]
    fn mounted_prompt_handler_delegates_get_with_args() {
        let inner = Box::new(StubPrompt) as BoxedPromptHandler;
        let mounted = MountedPromptHandler::new(inner, "ns".to_string());
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let mut args = HashMap::new();
        args.insert("key".to_string(), "value".to_string());
        let result = mounted.get(&ctx, args).unwrap();
        assert!(result.is_empty());
    }

    // ── ProgressNotificationSender multiple sends ────────────────────

    #[test]
    fn progress_sender_multiple_notifications() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender = ProgressNotificationSender::new(ProgressMarker::from("multi"), move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        sender.send_progress(0.0, Some(100.0), Some("starting"));
        sender.send_progress(50.0, Some(100.0), None);
        sender.send_progress(100.0, Some(100.0), Some("done"));

        let messages = sent.lock().unwrap();
        assert_eq!(messages.len(), 3);
    }

    // ── ToolHandler with custom tags and annotations ────────────────

    struct TaggedTool;
    impl ToolHandler for TaggedTool {
        fn definition(&self) -> Tool {
            Tool {
                name: "tagged".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec!["db".to_string(), "read".to_string()],
                annotations: Some(ToolAnnotations {
                    destructive: Some(false),
                    idempotent: Some(true),
                    read_only: Some(true),
                    open_world_hint: None,
                }),
            }
        }
        fn tags(&self) -> &[String] {
            // Return from definition for consistency
            &[]
        }
        fn annotations(&self) -> Option<&ToolAnnotations> {
            None
        }
        fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::text("tagged")])
        }
    }

    #[test]
    fn tool_definition_includes_tags_and_annotations() {
        let def = TaggedTool.definition();
        assert_eq!(def.tags, vec!["db".to_string(), "read".to_string()]);
        let ann = def.annotations.unwrap();
        assert_eq!(ann.destructive, Some(false));
        assert_eq!(ann.idempotent, Some(true));
        assert_eq!(ann.read_only, Some(true));
    }

    // ── Async delegation via block_on ───────────────────────────────

    #[test]
    fn tool_call_async_delegates_to_sync() {
        let tool = StubTool;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(tool.call_async(&ctx, serde_json::json!({"x": 1})));
        match outcome {
            Outcome::Ok(content) => assert!(!content.is_empty()),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn resource_read_async_delegates_to_sync() {
        let res = StubResource;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(res.read_async(&ctx));
        match outcome {
            Outcome::Ok(content) => {
                assert_eq!(content.len(), 1);
                assert_eq!(content[0].text.as_deref(), Some("hello"));
            }
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn resource_read_async_with_uri_empty_params_uses_read_async() {
        let res = StubResource;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let params = UriParams::new(); // empty
        let outcome =
            fastmcp_core::block_on(res.read_async_with_uri(&ctx, "file:///stub", &params));
        match outcome {
            Outcome::Ok(content) => assert_eq!(content[0].text.as_deref(), Some("hello")),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn resource_read_async_with_uri_nonempty_params_uses_read_with_uri() {
        let res = CustomResource;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let mut params = UriParams::new();
        params.insert("id".to_string(), "7".to_string());
        let outcome =
            fastmcp_core::block_on(res.read_async_with_uri(&ctx, "file:///items/7", &params));
        match outcome {
            Outcome::Ok(content) => assert_eq!(content[0].text.as_deref(), Some("item:7")),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn prompt_get_async_delegates_to_sync() {
        let prompt = StubPrompt;
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(prompt.get_async(&ctx, HashMap::new()));
        match outcome {
            Outcome::Ok(messages) => assert!(messages.is_empty()),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    // ── Async error delegation ──────────────────────────────────────

    #[test]
    fn tool_call_async_propagates_error() {
        struct ErrTool;
        impl ToolHandler for ErrTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "err".to_string(),
                    description: None,
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                    annotations: None,
                }
            }
            fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
                Err(McpError::internal_error("async-err"))
            }
        }
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(ErrTool.call_async(&ctx, serde_json::json!({})));
        match outcome {
            Outcome::Err(e) => assert!(e.message.contains("async-err")),
            other => panic!("expected Err, got {:?}", other),
        }
    }

    // ── MountedToolHandler async delegation ──────────────────────────

    #[test]
    fn mounted_tool_handler_delegates_call_async() {
        let inner = Box::new(StubTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "m_stub".to_string());
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(mounted.call_async(&ctx, serde_json::json!({})));
        match outcome {
            Outcome::Ok(content) => assert!(!content.is_empty()),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    // ── MountedResourceHandler async delegation ─────────────────────

    #[test]
    fn mounted_resource_handler_delegates_read_async() {
        let inner = Box::new(StubResource) as BoxedResourceHandler;
        let mounted =
            MountedResourceHandler::new(inner, "file:///stub".to_string(), "file:///m".to_string());
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(mounted.read_async(&ctx));
        match outcome {
            Outcome::Ok(content) => {
                assert_eq!(content.len(), 1);
                assert_eq!(content[0].uri, "file:///m");
            }
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn mounted_resource_handler_delegates_read_async_with_uri() {
        let inner = Box::new(CustomResource) as BoxedResourceHandler;
        let mounted = MountedResourceHandler::new(
            inner,
            "file:///custom".to_string(),
            "ns/file:///custom".to_string(),
        );
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let mut params = UriParams::new();
        params.insert("id".to_string(), "5".to_string());
        let outcome = fastmcp_core::block_on(mounted.read_async_with_uri(
            &ctx,
            "ns/file:///items/5",
            &params,
        ));
        match outcome {
            Outcome::Ok(content) => {
                assert_eq!(content[0].text.as_deref(), Some("item:5"));
                assert_eq!(content[0].uri, "ns/file:///items/5");
            }
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    #[test]
    fn mounted_resource_template_translates_true_async_request_and_result_uri() {
        struct AsyncTemplateResource;

        impl ResourceHandler for AsyncTemplateResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "db://placeholder".to_string(),
                    name: "async-template".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }

            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                panic!("the true-async override must be used")
            }

            fn read_async_with_uri<'a>(
                &'a self,
                _ctx: &'a McpContext,
                uri: &'a str,
                params: &'a UriParams,
            ) -> BoxFuture<'a, McpOutcome<Vec<ResourceContent>>> {
                Box::pin(async move {
                    Outcome::Ok(vec![ResourceContent {
                        uri: uri.to_string(),
                        mime_type: None,
                        text: params.get("table").cloned(),
                        blob: None,
                    }])
                })
            }
        }

        let mounted = MountedResourceHandler::with_template(
            Box::new(AsyncTemplateResource),
            "db://{table}".to_string(),
            "ns/db://{table}".to_string(),
            ResourceTemplate {
                uri_template: "ns/db://{table}".to_string(),
                name: "async-template".to_string(),
                description: None,
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            },
        );
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let params = UriParams::from([("table".to_string(), "users".to_string())]);

        let outcome =
            fastmcp_core::block_on(mounted.read_async_with_uri(&ctx, "ns/db://users", &params));
        match outcome {
            Outcome::Ok(contents) => {
                assert_eq!(contents[0].uri, "ns/db://users");
                assert_eq!(contents[0].text.as_deref(), Some("users"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    // ── MountedPromptHandler async delegation ────────────────────────

    #[test]
    fn mounted_prompt_handler_delegates_get_async() {
        let inner = Box::new(StubPrompt) as BoxedPromptHandler;
        let mounted = MountedPromptHandler::new(inner, "ns".to_string());
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(mounted.get_async(&ctx, HashMap::new()));
        match outcome {
            Outcome::Ok(messages) => assert!(messages.is_empty()),
            other => panic!("expected Ok, got {:?}", other),
        }
    }

    // ── Additional coverage ─────────────────────────────────────────

    #[test]
    fn progress_sender_with_message_but_no_total() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender = ProgressNotificationSender::new(ProgressMarker::from("tok-msg"), move |req| {
            sent_clone.lock().unwrap().push(req);
        });

        sender.send_progress(2.0, None, Some("processing"));

        let messages = sent.lock().unwrap();
        let params = messages[0].params.as_ref().unwrap();
        assert_eq!(params["progress"], 2.0);
        assert_eq!(params["message"], "processing");
        assert!(params.get("total").is_none() || params["total"].is_null());
    }

    #[test]
    fn progress_notification_includes_progress_token() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sent_clone = Arc::clone(&sent);
        let sender =
            ProgressNotificationSender::new(ProgressMarker::from("my-token"), move |req| {
                sent_clone.lock().unwrap().push(req);
            });

        sender.send_progress(1.0, None, None);

        let messages = sent.lock().unwrap();
        let params = messages[0].params.as_ref().unwrap();
        assert_eq!(params["progressToken"], "my-token");
    }

    #[test]
    fn resource_read_async_propagates_error() {
        struct ErrResource;
        impl ResourceHandler for ErrResource {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "file:///err".to_string(),
                    name: "err".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }
            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                Err(McpError::internal_error("read-fail"))
            }
        }

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(ErrResource.read_async(&ctx));
        match outcome {
            Outcome::Err(e) => assert!(e.message.contains("read-fail")),
            other => panic!("expected Err, got {:?}", other),
        }
    }

    #[test]
    fn prompt_get_async_propagates_error() {
        struct ErrPrompt;
        impl PromptHandler for ErrPrompt {
            fn definition(&self) -> Prompt {
                Prompt {
                    name: "err".to_string(),
                    description: None,
                    arguments: vec![],
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }
            fn get(
                &self,
                _ctx: &McpContext,
                _args: HashMap<String, String>,
            ) -> McpResult<Vec<PromptMessage>> {
                Err(McpError::internal_error("get-fail"))
            }
        }

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let outcome = fastmcp_core::block_on(ErrPrompt.get_async(&ctx, HashMap::new()));
        match outcome {
            Outcome::Err(e) => assert!(e.message.contains("get-fail")),
            other => panic!("expected Err, got {:?}", other),
        }
    }

    #[test]
    fn resource_read_async_with_uri_nonempty_params_propagates_error() {
        struct ErrWithUri;
        impl ResourceHandler for ErrWithUri {
            fn definition(&self) -> Resource {
                Resource {
                    uri: "file:///err".to_string(),
                    name: "err".to_string(),
                    description: None,
                    mime_type: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                }
            }
            fn read(&self, _ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
                Ok(vec![])
            }
            fn read_with_uri(
                &self,
                _ctx: &McpContext,
                _uri: &str,
                _params: &UriParams,
            ) -> McpResult<Vec<ResourceContent>> {
                Err(McpError::internal_error("uri-fail"))
            }
        }

        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let mut params = UriParams::new();
        params.insert("id".to_string(), "1".to_string());
        let outcome =
            fastmcp_core::block_on(ErrWithUri.read_async_with_uri(&ctx, "file:///err", &params));
        match outcome {
            Outcome::Err(e) => assert!(e.message.contains("uri-fail")),
            other => panic!("expected Err, got {:?}", other),
        }
    }

    #[test]
    fn mounted_tool_definition_preserves_inner_fields() {
        let inner = Box::new(StubTool) as BoxedToolHandler;
        let mounted = MountedToolHandler::new(inner, "renamed".to_string());
        let def = mounted.definition();
        assert_eq!(def.name, "renamed");
        assert_eq!(def.description.as_deref(), Some("a stub tool"));
        assert_eq!(def.input_schema, serde_json::json!({"type": "object"}));
    }
}
