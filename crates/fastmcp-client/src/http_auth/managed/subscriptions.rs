//! Authenticated subscriptions over one owned HTTP POST.
//!
//! SUB-03/TASK-03 consume the existing native subscription validator: there is
//! no second acknowledgement, filter, JSON-RPC or terminal-result parser here.
//! The managed owner adds token expiry, token-local revocation, session closure,
//! caller cancellation and finite whole-listen bounds around that validator.
//!
//! `subscribe_core` never activates extensions. With the Tasks feature,
//! `subscribe_tasks` first negotiates official Tasks through live discovery
//! using the same credential as the listen POST. Task and core catalog/resource
//! filters may coexist on that explicitly selected stream. Other extensions
//! are not negotiated here. Neither API reconnects, replays missed events, nor
//! extends a stream after token renewal. After a gap callers must explicitly
//! subscribe again and reconcile snapshots; a new ACK does not recover history.

use std::fmt;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    CompleteResult, CoreRequest, FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION,
    FinalSubscriptionsListenResult, JsonInteger, RequestId, ServerNotification, SubscriptionFilter,
};
#[cfg(feature = "tasks")]
use fastmcp_protocol::tasks_extension::{
    TASKS_EXTENSION, TASK_STATUS_NOTIFICATION, TASK_SUBSCRIPTION_IDS_KEY,
    TaskStatusNotification, task_subscription_ids,
};
#[cfg(feature = "tasks")]
use fastmcp_protocol::{CoreResult, ExtensionDirection, FinalCoreResult, decode_strict_jsonrpc_response};

use super::{ManagedOAuthResponse, ManagedOAuthSession, OAuthSessionError, deadline_after};
#[cfg(feature = "tasks")]
use super::OAuthCredentialSnapshot;
use crate::http_executor::{
    ModernHttpRequest, ModernHttpResponseKind, ModernHttpSubscriptionListenError,
    ModernHttpSubscriptionListenEvent, ModernHttpSubscriptionListener,
};
use crate::sse::SseLimits;

/// Finite admission and lifetime bounds for one subscription.
/// Native HTTP idle/absolute deadlines and pending-event budgets still apply
/// and may be tighter. No event queue grows with the lifetime of the stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedSubscriptionLimits {
    request_bytes: usize,
    frame_bytes: usize,
    records: usize,
    timeout: Duration,
}

impl Default for ManagedSubscriptionLimits {
    fn default() -> Self {
        Self {
            request_bytes: 64 * 1024,
            frame_bytes: 64 * 1024,
            records: 1024,
            timeout: Duration::from_mins(15),
        }
    }
}

impl ManagedSubscriptionLimits {
    /// `records` includes the acknowledgement and terminal result, not just
    /// change notifications. Reaching the limit without a terminal is failure,
    /// never successful EOF. `frame_bytes` bounds the native SSE line/event
    /// representation including framing overhead as well as its JSON payload.
    /// Credential acquisition, Tasks discovery, and caller pauses are included
    /// in the one deadline. Discovery uses the same per-document byte bounds.
    pub fn new(
        request_bytes: usize,
        frame_bytes: usize,
        records: usize,
        timeout: Duration,
    ) -> Result<Self, ManagedSubscriptionError> {
        if !(1..=64 * 1024).contains(&request_bytes)
            || !(1..=64 * 1024).contains(&frame_bytes)
            || !(2..=4096).contains(&records)
            || timeout.is_zero()
            || timeout > Duration::from_secs(3600)
        {
            return Err(ManagedSubscriptionError::InvalidLimits);
        }
        Ok(Self { request_bytes, frame_bytes, records, timeout })
    }
}

/// Failures contain no peer error message, subscription ID, filter, or body.
/// The protocol decoder's detailed peer diagnostics are deliberately not
/// retained by this authenticated convenience API.
#[derive(Debug)]
pub enum ManagedSubscriptionError {
    InvalidLimits,
    InvalidRequest,
    UnsupportedExtension,
    Negotiation,
    RequestTooLarge,
    InvalidResponse,
    MissingTerminal,
    RecordLimit,
    Closed,
    Remote { code: JsonInteger },
    Session(OAuthSessionError),
}

impl fmt::Display for ManagedSubscriptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid managed subscription limits"),
            Self::InvalidRequest => f.write_str("invalid final subscription request"),
            Self::UnsupportedExtension => f.write_str("subscription contains an extension outside its selected profile"),
            Self::Negotiation => f.write_str("resource did not admit the official Tasks notification surface"),
            Self::RequestTooLarge => f.write_str("managed subscription request exceeds its byte limit"),
            Self::InvalidResponse => f.write_str("managed subscription response failed admission"),
            Self::MissingTerminal => f.write_str("managed subscription ended without a complete terminal result"),
            Self::RecordLimit => f.write_str("managed subscription record limit exceeded"),
            Self::Closed => f.write_str("managed subscription is closed"),
            Self::Remote { code } => write!(f, "managed subscription failed with JSON-RPC {code}"),
            Self::Session(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ManagedSubscriptionError {}

impl From<OAuthSessionError> for ManagedSubscriptionError {
    fn from(error: OAuthSessionError) -> Self { Self::Session(error) }
}

/// Incrementally delivered records. The existing native decoder enforces the
/// first acknowledgement, its requested-filter subset, subsequent event
/// categories/resource/task IDs, and the correlated terminal's subscription ID.
pub enum ManagedSubscriptionEvent {
    Acknowledged { accepted_filter: SubscriptionFilter },
    Notification(Box<ServerNotification>),
    /// Only the live-discovery-authorized Tasks path can yield this variant.
    /// Task completion is not subscription completion: only the correlated
    /// terminal result completes a listen, which may watch several tasks.
    #[cfg(feature = "tasks")]
    TaskNotification(Box<TaskStatusNotification>),
    Terminal {
        subscription_id: RequestId,
        result: Box<CompleteResult<FinalSubscriptionsListenResult>>,
    },
}

/// Local selection alone is not authority: only subscribe_tasks can install
/// the Tasks variant in a live stream, after credential-bound discovery.
#[derive(Clone, Copy)]
enum SubscriptionProfile {
    Core,
    #[cfg(feature = "tasks")]
    Tasks,
}

impl ManagedOAuthSession {
    /// Starts one explicitly selected modern core `subscriptions/listen` POST.
    /// The caller supplies a typed request with final per-request metadata.
    /// Request/profile/size checks finish before any renewal or network contact.
    /// This does not add a legacy session or perform implicit discovery.
    pub async fn subscribe_core(
        &self,
        cx: &Cx,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedSubscriptionLimits,
    ) -> Result<ManagedSubscription, ManagedSubscriptionError> {
        self.subscribe_core_with_cancellation(
            cx, &McpRequestCancellation::new(), request, request_id, limits,
        ).await
    }

    /// Retains one request-local cancellation domain through the entire listen.
    /// Cancellation closes only this POST; it never sends a cancellation
    /// notification, cancels the ambient Cx, or resubmits the request.
    pub async fn subscribe_core_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedSubscriptionLimits,
    ) -> Result<ManagedSubscription, ManagedSubscriptionError> {
        self.check(cx, cancellation)?;
        let deadline = deadline_after(cx, limits.timeout)?;
        let (wire, requested) = prepare(self.resource().as_str(), request, &request_id, limits)?;
        let response = self.await_active(cx, cancellation, deadline, None, async {
            self.execute_with_cancellation(cx, cancellation, &wire).await
        }).await?;
        ManagedSubscription::from_response(response, request_id, requested, limits, deadline, SubscriptionProfile::Core)
    }

    /// Opens an official Tasks listen, optionally composed with core filters.
    /// The typed request must advertise exactly `io.modelcontextprotocol/tasks`
    /// with empty settings and contain a present `taskIds` filter. Empty and
    /// duplicate ID selections retain their wire meaning. The shared Tasks
    /// codec bounds and validates every ID before credential acquisition.
    ///
    /// One fresh authenticated server/discover precedes this listen, using a
    /// distinct request ID and the exact same credential snapshot. Neither
    /// failure can trigger a retry or downgrade. Other extension filters and
    /// advertisements are rejected. After an interruption, explicitly fetch
    /// Task snapshots and open a fresh listen; no missed-event replay is implied.
    #[cfg(feature = "tasks")]
    pub async fn subscribe_tasks(
        &self,
        cx: &Cx,
        request: CoreRequest,
        discovery_id: RequestId,
        request_id: RequestId,
        limits: ManagedSubscriptionLimits,
    ) -> Result<ManagedSubscription, ManagedSubscriptionError> {
        self.subscribe_tasks_with_cancellation(
            cx, &McpRequestCancellation::new(), request, discovery_id, request_id, limits,
        ).await
    }

    /// The cancellation handle spans discovery, listen admission and all reads.
    /// Refreshing this login never extends the lifetime of an existing listen.
    #[cfg(feature = "tasks")]
    pub async fn subscribe_tasks_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        discovery_id: RequestId,
        request_id: RequestId,
        limits: ManagedSubscriptionLimits,
    ) -> Result<ManagedSubscription, ManagedSubscriptionError> {
        self.check(cx, cancellation)?;
        let deadline = deadline_after(cx, limits.timeout)?;
        discovery_id.validate().map_err(|_| ManagedSubscriptionError::InvalidRequest)?;
        if discovery_id.correlates_with(&request_id) {
            return Err(ManagedSubscriptionError::InvalidRequest);
        }
        // Prepare both bounded documents before a credential refresh or POST.
        let params = request.encode_params().map_err(|_| ManagedSubscriptionError::InvalidRequest)?
            .ok_or(ManagedSubscriptionError::InvalidRequest)?;
        let (wire, requested) = prepare_profile(
            self.resource().as_str(), request, &request_id, limits, SubscriptionProfile::Tasks,
        )?;
        let discovery = CoreRequest::decode(ProtocolEra::Modern2026, "server/discover", Some(
            &serde_json::json!({"_meta": params["_meta"]}),
        )).map_err(|_| ManagedSubscriptionError::InvalidRequest)?;
        let discovery_wire = encode_wire(self.resource().as_str(), &discovery, &discovery_id, limits.request_bytes)?;
        let credential = self.await_active(cx, cancellation, deadline, None, async {
            self.credential_with_cancellation(cx, cancellation).await
        }).await?;
        let response = self.execute_subscription_snapshot(
            cx, cancellation, deadline, &credential, &discovery_wire,
        ).await?;
        if response.metadata().kind() != ModernHttpResponseKind::Json {
            return Err(ManagedSubscriptionError::InvalidResponse);
        }
        let bytes = self.await_active(cx, cancellation, deadline, Some(credential.expires_at), async {
            response.read_to_end(cx, limits.frame_bytes).await
        }).await?;
        admit_tasks_discovery(&discovery, &bytes, &discovery_id, limits.frame_bytes)?;
        // No intervening credential lookup: discovery cannot authorize a POST
        // under a different token even when a sibling concurrently renews.
        let response = self.execute_subscription_snapshot(
            cx, cancellation, deadline, &credential, &wire,
        ).await?;
        ManagedSubscription::from_response(response, request_id, requested, limits, deadline, SubscriptionProfile::Tasks)
    }

    #[cfg(feature = "tasks")]
    async fn execute_subscription_snapshot(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Time,
        credential: &OAuthCredentialSnapshot,
        wire: &ModernHttpRequest,
    ) -> Result<ManagedOAuthResponse, ManagedSubscriptionError> {
        self.check(cx, cancellation)?;
        // All callers construct this wire against this session's exact resource.
        super::admit_target(self.resource(), wire.target())?;
        // Both discovery and listen require the selected live credential;
        // withholding its header must not silently dispatch anonymously.
        let wire = credential.authorize_request(wire)?;
        let head_deadline = deadline.min(deadline_after(cx, self.inner.policy.response_head_timeout)?);
        let executor = self.inner.client.resource_http_executor();
        let response = self.await_credential(cx, cancellation, head_deadline,
            credential.expires_at, &credential.credential.revoked, async {
                executor.execute_with_cancellation(cx, cancellation, &wire).await.map_err(OAuthSessionError::Http)
            },
        ).await?;
        if matches!(response.metadata().status(), 401 | 403) {
            return Err(OAuthSessionError::AuthorizationRejected { status: response.metadata().status() }.into());
        }
        if response.metadata().status() != 200 {
            return Err(ManagedSubscriptionError::InvalidResponse);
        }
        Ok(ManagedOAuthResponse::from_snapshot(
            response, self.clone(), cancellation.clone(), credential,
        ))
    }
}

/// One authenticated, incremental subscription. Renewal of the shared login
/// never extends this owner's original credential lifetime. The stream is not
/// Clone, and its raw transport cannot be extracted without the guards.
/// Drop/close releases the socket; an unpolled retained owner is released on
/// its next poll or drop, not by an unowned background task.
pub struct ManagedSubscription {
    listener: Option<Box<ModernHttpSubscriptionListener>>,
    session: ManagedOAuthSession,
    cancellation: McpRequestCancellation,
    request_id: RequestId,
    accepted_filter: Option<SubscriptionFilter>,
    profile: SubscriptionProfile,
    expires_at: Instant,
    generation: u64,
    revocation: McpRequestCancellation,
    deadline: Time,
    limits: ManagedSubscriptionLimits,
    records: usize,
    finished: bool,
}

impl ManagedSubscription {
    fn from_response(
        response: ManagedOAuthResponse,
        request_id: RequestId,
        requested: SubscriptionFilter,
        limits: ManagedSubscriptionLimits,
        deadline: Time,
        profile: SubscriptionProfile,
    ) -> Result<Self, ManagedSubscriptionError> {
        if response.metadata().status() != 200 || response.metadata().kind() != ModernHttpResponseKind::Sse {
            return Err(ManagedSubscriptionError::InvalidResponse);
        }
        let ManagedOAuthResponse { response, session, cancellation, expires_at, generation, revocation } = response;
        let framing = SseLimits::new(limits.frame_bytes, limits.frame_bytes, 64)
            .ok_or(ManagedSubscriptionError::InvalidLimits)?;
        let listener = response.into_final_subscriptions_listener(request_id.clone(), requested, framing)
            .map_err(admission_error)?;
        Ok(Self {
            listener: Some(Box::new(listener)), session, cancellation, request_id,
            accepted_filter: None, profile, expires_at, generation, revocation, deadline, limits,
            records: 0, finished: false,
        })
    }

    pub fn request_id(&self) -> &RequestId { &self.request_id }

    /// Session-local generation, not a cross-session identity or replay cursor.
    pub fn credential_generation(&self) -> u64 { self.generation }

    pub fn accepted_filter(&self) -> Option<&SubscriptionFilter> { self.accepted_filter.as_ref() }

    /// Immediately releases this owned response without closing sibling calls.
    pub fn close(&mut self) { self.listener = None; }

    /// `None` is possible only after a complete terminal was already delivered.
    /// A polled read owns the socket until it yields a validated record. If the
    /// read is abandoned, its parser/socket are dropped and cannot be reused.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ManagedSubscriptionEvent>, ManagedSubscriptionError> {
        if self.finished { return Ok(None); }
        let mut listener = self.listener.take().ok_or(ManagedSubscriptionError::Closed)?;
        self.session.check(cx, &self.cancellation)?;
        if self.records >= self.limits.records {
            return Err(ManagedSubscriptionError::RecordLimit);
        }
        let record = self.session.await_credential(
            cx, &self.cancellation, self.deadline, self.expires_at, &self.revocation, async {
                // Keep protocol failures distinct without exposing their raw
                // peer diagnostics through OAuthSessionError.
                Ok(listener.next_event(cx).await)
            },
        ).await?.map_err(admission_error)?.ok_or(ManagedSubscriptionError::MissingTerminal)?;
        let record = select_record(record, self.profile)?;
        self.session.check(cx, &self.cancellation)?;
        if self.revocation.is_cancel_requested() { return Err(OAuthSessionError::LoginRequired.into()); }
        if Instant::now() >= self.expires_at {
            return Err(OAuthSessionError::LoginRequired.into());
        }
        if cx.now() >= self.deadline {
            return Err(OAuthSessionError::TimedOut.into());
        }
        // Publication follows the final lifetime checks. A decoded ACK that
        // loses to cancellation/expiry must not become caller-visible state.
        if let ManagedSubscriptionEvent::Acknowledged { accepted_filter } = &record {
            self.accepted_filter = Some(accepted_filter.clone());
        }
        self.records += 1;
        if matches!(record, ManagedSubscriptionEvent::Terminal { .. }) {
            self.finished = true;
        } else {
            self.listener = Some(listener);
        }
        Ok(Some(record))
    }
}

// The Result is the refusal of a task notification on a core listener. Without
// `tasks`, Core is the only profile and no record can fall outside it, so only
// that build compiles to an unconditional `Ok`.
#[cfg_attr(not(feature = "tasks"), allow(clippy::unnecessary_wraps))]
fn select_record(
    record: ModernHttpSubscriptionListenEvent,
    profile: SubscriptionProfile,
) -> Result<ManagedSubscriptionEvent, ManagedSubscriptionError> {
    // `profile` is read only by the `tasks`-gated arm below. Discarding it in
    // the other configuration keeps the name unprefixed -- an `_profile` that
    // IS read trips used_underscore_binding under --all-features, while a bare
    // `profile` that is not read trips unused_variables without `tasks`. Both
    // are fatal under the gate's -D warnings, so neither name works alone.
    #[cfg(not(feature = "tasks"))]
    let _ = profile;
    match record {
        ModernHttpSubscriptionListenEvent::Acknowledged { accepted_filter } => {
            Ok(ManagedSubscriptionEvent::Acknowledged { accepted_filter })
        }
        ModernHttpSubscriptionListenEvent::Notification(notification) => {
            Ok(ManagedSubscriptionEvent::Notification(Box::new(notification)))
        }
        ModernHttpSubscriptionListenEvent::Terminal { subscription_id, result } => {
            Ok(ManagedSubscriptionEvent::Terminal { subscription_id, result: Box::new(result) })
        }
        #[cfg(feature = "tasks")]
        ModernHttpSubscriptionListenEvent::TaskNotification(notification) => {
            if !matches!(profile, SubscriptionProfile::Tasks) {
                return Err(ManagedSubscriptionError::UnsupportedExtension);
            }
            Ok(ManagedSubscriptionEvent::TaskNotification(Box::new(notification)))
        }
    }
}

fn admission_error(error: ModernHttpSubscriptionListenError) -> ManagedSubscriptionError {
    match error {
        ModernHttpSubscriptionListenError::RemoteError { code, .. } => ManagedSubscriptionError::Remote { code },
        ModernHttpSubscriptionListenError::EndOfStream { .. } => ManagedSubscriptionError::MissingTerminal,
        ModernHttpSubscriptionListenError::CallerCancelled { .. } => OAuthSessionError::Cancelled.into(),
        ModernHttpSubscriptionListenError::Executor(error) => OAuthSessionError::Http(error).into(),
        _ => ManagedSubscriptionError::InvalidResponse,
    }
}

fn prepare(
    target: &str,
    request: CoreRequest,
    request_id: &RequestId,
    limits: ManagedSubscriptionLimits,
) -> Result<(ModernHttpRequest, SubscriptionFilter), ManagedSubscriptionError> {
    prepare_profile(target, request, request_id, limits, SubscriptionProfile::Core)
}

fn prepare_profile(
    target: &str,
    request: CoreRequest,
    request_id: &RequestId,
    limits: ManagedSubscriptionLimits,
    profile: SubscriptionProfile,
) -> Result<(ModernHttpRequest, SubscriptionFilter), ManagedSubscriptionError> {
    if request.era() != ProtocolEra::Modern2026 || request.method() != "subscriptions/listen" {
        return Err(ManagedSubscriptionError::InvalidRequest);
    }
    request_id.validate().map_err(|_| ManagedSubscriptionError::InvalidRequest)?;
    let params = request.encode_params().map_err(|_| ManagedSubscriptionError::InvalidRequest)?
        .ok_or(ManagedSubscriptionError::InvalidRequest)?;
    let metadata = params.get("_meta").and_then(serde_json::Value::as_object)
        .ok_or(ManagedSubscriptionError::InvalidRequest)?;
    let extensions = metadata.get(FINAL_CLIENT_CAPABILITIES_META_KEY)
        .and_then(|capabilities| capabilities.get("extensions"));
    let filter: SubscriptionFilter = serde_json::from_value(
        params.get("notifications").cloned().ok_or(ManagedSubscriptionError::InvalidRequest)?,
    ).map_err(|_| ManagedSubscriptionError::InvalidRequest)?;
    match profile {
        SubscriptionProfile::Core => {
            if extensions.is_some_and(|value| !value.as_object().is_some_and(serde_json::Map::is_empty))
                || !filter.additional.is_empty()
            {
                return Err(ManagedSubscriptionError::UnsupportedExtension);
            }
        }
        #[cfg(feature = "tasks")]
        SubscriptionProfile::Tasks => {
            if !extensions.and_then(serde_json::Value::as_object).is_some_and(|extensions| {
                extensions.len() == 1 && extensions.get(TASKS_EXTENSION)
                    .and_then(serde_json::Value::as_object).is_some_and(serde_json::Map::is_empty)
            }) || filter.additional.keys().any(|key| key != TASK_SUBSCRIPTION_IDS_KEY) {
                return Err(ManagedSubscriptionError::UnsupportedExtension);
            }
            if task_subscription_ids(&filter).map_err(|_| ManagedSubscriptionError::InvalidRequest)?.is_none() {
                return Err(ManagedSubscriptionError::InvalidRequest);
            }
        }
    }
    Ok((encode_wire(target, &request, request_id, limits.request_bytes)?, filter))
}

fn encode_wire(
    target: &str,
    request: &CoreRequest,
    request_id: &RequestId,
    maximum: usize,
) -> Result<ModernHttpRequest, ManagedSubscriptionError> {
    let params = request.encode_params().map_err(|_| ManagedSubscriptionError::InvalidRequest)?
        .ok_or(ManagedSubscriptionError::InvalidRequest)?;
    let envelope = serde_json::json!({
        "jsonrpc": "2.0", "id": request_id, "method": request.method(), "params": params,
    });
    let mut writer = BoundedRequest { bytes: Vec::new(), maximum };
    serde_json::to_writer(&mut writer, &envelope).map_err(|_| ManagedSubscriptionError::RequestTooLarge)?;
    ModernHttpRequest::new(target, writer.bytes, FINAL_PROTOCOL_VERSION, request.method(), None)
        .map_err(|_| ManagedSubscriptionError::InvalidRequest)
}

#[cfg(feature = "tasks")]
fn admit_tasks_discovery(
    request: &CoreRequest,
    bytes: &[u8],
    request_id: &RequestId,
    maximum: usize,
) -> Result<(), ManagedSubscriptionError> {
    let (response, source) = decode_strict_jsonrpc_response(bytes, maximum)
        .map_err(|_| ManagedSubscriptionError::InvalidResponse)?.into_parts();
    if !response.id.as_ref().is_some_and(|id| id.correlates_with(request_id)) {
        return Err(ManagedSubscriptionError::InvalidResponse);
    }
    if let Some(error) = &response.error {
        return Err(ManagedSubscriptionError::Remote { code: error.code.clone() });
    }
    let source = source.ok_or(ManagedSubscriptionError::InvalidResponse)?;
    let CoreResult::Final(FinalCoreResult::Discover(discovered)) = request.decode_response_result(&response, &source)
        .map_err(|_| ManagedSubscriptionError::InvalidResponse)? else {
        return Err(ManagedSubscriptionError::InvalidResponse);
    };
    if !discovered.supported_versions().iter().any(|version| version == FINAL_PROTOCOL_VERSION) {
        return Err(ManagedSubscriptionError::Negotiation);
    }
    crate::admit_final_tasks_discovery_surface(
        &discovered, TASK_STATUS_NOTIFICATION, ExtensionDirection::ServerToClient,
    ).map_err(|_| ManagedSubscriptionError::Negotiation)
}

struct BoundedRequest { bytes: Vec<u8>, maximum: usize }

impl Write for BoundedRequest {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("managed subscription request limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use serde_json::json;

    fn request(notifications: serde_json::Value, extensions: serde_json::Value) -> CoreRequest {
        let mut meta = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        meta[FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"] = extensions;
        CoreRequest::decode(ProtocolEra::Modern2026, "subscriptions/listen", Some(&json!({
            "_meta": meta, "notifications": notifications,
        }))).unwrap()
    }

    #[test]
    fn prepared_subscription_preserves_correlation_metadata_and_core_filter() {
        let request = request(json!({"toolsListChanged": true}), json!({}));
        let (wire, filter) = prepare("https://mcp.example/mcp", request, &RequestId::Number(0), ManagedSubscriptionLimits::default()).unwrap();
        assert_eq!(filter.tools_list_changed, Some(true));
        assert!(filter.additional.is_empty());
        let value: serde_json::Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(value["id"], 0);
        assert_eq!(value["method"], "subscriptions/listen");
        assert_eq!(value["params"]["notifications"]["toolsListChanged"], true);
        assert!(wire.headers().iter().any(|(name, value)| name == "Mcp-Method" && value == "subscriptions/listen"));
        assert!(!wire.headers().iter().any(|(name, _)| name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("last-event-id")));
    }

    #[test]
    fn core_subscription_rejects_unnegotiated_extensions_before_dispatch() {
        for (filter, extensions) in [
            (json!({"toolsListChanged": true, "taskIds": ["private-task"]}), json!({})),
            (json!({"toolsListChanged": true}), json!({"io.modelcontextprotocol/tasks": {}})),
            (json!({"tools/list_changed": true}), json!({})),
        ] {
            assert!(matches!(prepare("https://mcp.example/mcp", request(filter, extensions), &RequestId::Number(1), ManagedSubscriptionLimits::default()), Err(ManagedSubscriptionError::UnsupportedExtension)));
        }
    }

    #[test]
    fn filter_presence_is_preserved_without_inventing_subscription_authority() {
        for filter in [json!({}), json!({"toolsListChanged": false}), json!({"resourceSubscriptions": []})] {
            let (wire, _) = prepare("https://mcp.example/mcp", request(filter.clone(), json!({})), &RequestId::Number(1), ManagedSubscriptionLimits::default()).unwrap();
            let value: serde_json::Value = serde_json::from_slice(wire.body()).unwrap();
            assert_eq!(value["params"]["notifications"], filter);
        }
    }

    #[test]
    fn subscription_request_limit_refuses_without_partial_output() {
        let mut limits = ManagedSubscriptionLimits::default();
        limits.request_bytes = 1;
        assert!(matches!(prepare("https://mcp.example/mcp", request(json!({}), json!({})), &RequestId::Number(1), limits), Err(ManagedSubscriptionError::RequestTooLarge)));
        let mut writer = BoundedRequest { bytes: b"ok".to_vec(), maximum: 2 };
        assert!(writer.write_all(b"x").is_err());
        assert_eq!(writer.bytes, b"ok");
    }

    #[test]
    fn subscription_limits_and_errors_do_not_hide_unbounded_work_or_peer_text() {
        let second = Duration::from_secs(1);
        assert!(ManagedSubscriptionLimits::new(1024, 1024, 2, second).is_ok());
        for (request, frame, records, timeout) in [
            (0, 1024, 2, second), (1024, 0, 2, second),
            (1024, 1024, 1, second), (1024, 1024, 4097, second),
            (1024, 1024, 2, Duration::ZERO), (1024, 1024, 2, Duration::from_secs(3601)),
        ] {
            assert!(ManagedSubscriptionLimits::new(request, frame, records, timeout).is_err());
        }
        let error = admission_error(ModernHttpSubscriptionListenError::RemoteError {
            code: JsonInteger::from(-32603_i64), message: "peer-secret-canary".to_owned(),
        });
        assert!(!format!("{error:?} {error}").contains("peer-secret-canary"));
    }

    #[cfg(feature = "tasks")]
    #[test]
    fn task_and_core_filters_compose_only_in_the_explicit_tasks_profile() {
        for ids in [json!([]), json!(["task-one", "task-one", " task-two "])] {
            let filter = json!({"toolsListChanged":true, "taskIds":ids});
            let requested = request(filter.clone(), json!({TASKS_EXTENSION:{}}));
            assert!(matches!(prepare("https://mcp.example/mcp", requested.clone(), &RequestId::Number(2), ManagedSubscriptionLimits::default()), Err(ManagedSubscriptionError::UnsupportedExtension)));
            let (wire, admitted) = prepare_profile("https://mcp.example/mcp", requested, &RequestId::Number(2), ManagedSubscriptionLimits::default(), SubscriptionProfile::Tasks).unwrap();
            let wire: serde_json::Value = serde_json::from_slice(wire.body()).unwrap();
            assert_eq!(wire["params"]["notifications"], filter);
            assert_eq!(wire["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"], json!({TASKS_EXTENSION:{}}));
            assert_eq!(admitted.tools_list_changed, Some(true));
        }
    }

    #[cfg(feature = "tasks")]
    #[test]
    fn tasks_profile_rejects_invalid_ids_settings_and_unselected_extensions() {
        for (filter, extensions) in [
            (json!({"taskIds":[""]}), json!({TASKS_EXTENSION:{}})),
            (json!({"taskIds":["line\nbreak"]}), json!({TASKS_EXTENSION:{}})),
            (json!({"taskIds":vec!["one";129]}), json!({TASKS_EXTENSION:{}})),
            (json!({}), json!({TASKS_EXTENSION:{}})),
            (json!({"taskIds":["one"]}), json!({})),
            (json!({"taskIds":["one"]}), json!({TASKS_EXTENSION:{"extra":true}})),
            (json!({"taskIds":["one"]}), json!({TASKS_EXTENSION:{},"com.example/extra":{}})),
            (json!({"taskIds":["one"],"extraFilter":true}), json!({TASKS_EXTENSION:{}})),
        ] {
            let requested = request(filter, extensions);
            assert!(prepare_profile("https://mcp.example/mcp", requested, &RequestId::Number(2), ManagedSubscriptionLimits::default(), SubscriptionProfile::Tasks).is_err());
        }
    }

    #[cfg(feature = "tasks")]
    #[test]
    fn compiled_task_notification_codec_does_not_authorize_core_delivery() {
        let event: TaskStatusNotification = serde_json::from_value(json!({
            "jsonrpc":"2.0", "method":"notifications/tasks", "params":{
                "_meta":{"io.modelcontextprotocol/subscriptionId":2},
                "taskId":"one", "status":"working", "createdAt":"2026-09-16T00:00:00Z",
                "lastUpdatedAt":"2026-09-16T00:00:00Z", "ttlMs":60000
            }
        })).unwrap();
        assert!(matches!(select_record(ModernHttpSubscriptionListenEvent::TaskNotification(event.clone()), SubscriptionProfile::Core), Err(ManagedSubscriptionError::UnsupportedExtension)));
        assert!(matches!(select_record(ModernHttpSubscriptionListenEvent::TaskNotification(event), SubscriptionProfile::Tasks), Ok(ManagedSubscriptionEvent::TaskNotification(_))));
    }

    #[cfg(feature = "tasks")]
    #[test]
    fn task_discovery_requires_the_exact_version_extension_and_response_owner() {
        let listen = request(json!({"taskIds":["one"]}), json!({TASKS_EXTENSION:{}}));
        let params = listen.encode_params().unwrap().unwrap();
        let discovery = CoreRequest::decode(ProtocolEra::Modern2026, "server/discover", Some(&json!({"_meta":params["_meta"]}))).unwrap();
        let valid = json!({"jsonrpc":"2.0","id":1,"result":{
            "resultType":"complete", "supportedVersions":[FINAL_PROTOCOL_VERSION],
            "capabilities":{"extensions":{TASKS_EXTENSION:{}}},"ttlMs":0,"cacheScope":"private"
        }});
        assert!(admit_tasks_discovery(&discovery, &serde_json::to_vec(&valid).unwrap(), &RequestId::Number(1), 4096).is_ok());
        for dimension in 0..4 {
            let mut changed = valid.clone();
            match dimension {
                0 => changed["id"] = json!(2),
                1 => changed["result"]["supportedVersions"] = json!(["2024-11-05"]),
                2 => changed["result"]["capabilities"]["extensions"] = json!({}),
                _ => changed["result"]["capabilities"]["extensions"][TASKS_EXTENSION] = json!({"extra":true}),
            }
            assert!(admit_tasks_discovery(&discovery, &serde_json::to_vec(&changed).unwrap(), &RequestId::Number(1), 4096).is_err());
        }
        let error = admit_tasks_discovery(&discovery, br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"private-peer-detail"}}"#, &RequestId::Number(1), 4096).err().unwrap();
        assert!(matches!(error, ManagedSubscriptionError::Remote { .. }));
        assert!(!format!("{error:?} {error}").contains("private-peer-detail"));
    }

    #[cfg(feature = "tasks")]
    #[test]
    fn subscription_dispatch_refuses_revoked_credentials_on_its_first_poll() {
        use std::future::{Future, poll_fn};
        use std::sync::{Arc, atomic::AtomicUsize};
        use std::task::Poll;
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        use asupersync::sync::Mutex;
        use crate::http_auth::{BoundBearerCredential, CanonicalHttpUrl};
        use crate::http_auth::managed::{OAuthSessionPolicy, SessionInner};
        use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration};

        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let url = |value| CanonicalHttpUrl::parse(value).unwrap();
                let resource = url("https://mcp.example/mcp");
                let config = OAuthClientConfiguration::from_trusted_endpoints(
                    "https://issuer.example", url("https://issuer.example/authorize"),
                    url("https://issuer.example/token"), resource.clone(), "native-client", vec![],
                ).unwrap();
                let session = ManagedOAuthSession {
                    inner: Arc::new(SessionInner {
                        client: OAuthClient::new(config), resource: resource.clone(),
                        policy: OAuthSessionPolicy::default(), state: Arc::new(Mutex::new(None)),
                        closed: McpRequestCancellation::new(), logout_handoff: std::sync::atomic::AtomicBool::new(false), pending: AtomicUsize::new(0),
                    }),
                };
                let expiry = Instant::now() + Duration::from_secs(60);
                let bearer = BoundBearerCredential::bind_with_expiry(resource.clone(), "secret", expiry).unwrap();
                let credential = OAuthCredentialSnapshot::new(&bearer, &[], 1, expiry, &session.inner.closed).unwrap();
                let cancellation = McpRequestCancellation::new();
                bearer.revoke();
                for method in ["server/discover", "subscriptions/listen"] {
                    let wire = ModernHttpRequest::new(resource.as_str(), b"{}".to_vec(), FINAL_PROTOCOL_VERSION, method, None).unwrap();
                    let mut dispatch = std::pin::pin!(session.execute_subscription_snapshot(
                        &cx, &cancellation, Time::from_nanos(u64::MAX), &credential, &wire,
                    ));
                    poll_fn(|task| match dispatch.as_mut().poll(task) {
                        Poll::Ready(Err(ManagedSubscriptionError::Session(OAuthSessionError::LoginRequired))) => Poll::Ready(()),
                        _ => panic!("revoked subscription credentials must fail locally before any network wait"),
                    }).await;
                }
                assert!(cx.checkpoint().is_ok());
                assert!(!session.inner.closed.is_cancel_requested());
            });
    }
}
