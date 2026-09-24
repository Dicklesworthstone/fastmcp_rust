//! One authenticated Tasks subscription, optionally composed with core filters.
//!
//! Both official extensions are admitted by fresh discovery using the exact
//! credential that opens the listen POST. The existing native subscription
//! decoder owns ACK ordering, filter narrowing, event ownership and terminal
//! correlation. This layer adds machine-credential lifetime and finite budgets;
//! it never reconnects, replays missed events or cancels a remote task.

/// Notification-driven snapshots for an explicitly acknowledged Task selection.
pub mod watch;

use std::time::Duration;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::tasks_extension::{
    TASK_STATUS_NOTIFICATION, TASK_SUBSCRIPTION_IDS_KEY, task_subscription_ids,
};
use fastmcp_protocol::{
    CoreRequest, CoreResult, ExtensionDirection, FinalCoreResult, RequestId,
    SubscriptionFilter,
};
use serde_json::{Value, json};

use super::{
    ClientCredentialsTasksClient, ClientCredentialsTasksError, ManagedTasksError,
    encode, require_success, response_source,
};
use super::super::{
    ClientCredentialsError, ClientCredentialsSnapshot, active, admit_resource,
    authorize, discovery_deadline,
};
use crate::http_executor::{
    ModernHttpExecutorError, ModernHttpRequest, ModernHttpResponseKind,
    ModernHttpSubscriptionListenError, ModernHttpSubscriptionListenEvent,
    ModernHttpSubscriptionListener,
};
use crate::sse::SseLimits;

/// Bounds the complete acquisition/discovery/listen operation and later reads.
/// Native transport bounds and the machine client's configured timeout still
/// apply and can be tighter. Record count includes ACK and terminal records.
#[derive(Clone, Copy, Debug)]
pub struct ClientCredentialsSubscriptionLimits {
    request_bytes: usize,
    frame_bytes: usize,
    records: usize,
    timeout: Duration,
}

impl Default for ClientCredentialsSubscriptionLimits {
    fn default() -> Self {
        Self {
            request_bytes: 64 * 1024,
            frame_bytes: 64 * 1024,
            records: 1024,
            timeout: Duration::from_mins(15),
        }
    }
}

impl ClientCredentialsSubscriptionLimits {
    pub fn new(
        request_bytes: usize,
        frame_bytes: usize,
        records: usize,
        timeout: Duration,
    ) -> Result<Self, ClientCredentialsTasksError> {
        if !(1..=64 * 1024).contains(&request_bytes)
            || !(1..=64 * 1024).contains(&frame_bytes)
            || !(2..=4096).contains(&records)
            || timeout.is_zero()
            || timeout > Duration::from_secs(3600)
        {
            return Err(ManagedTasksError::InvalidLimits.into());
        }
        Ok(Self { request_bytes, frame_bytes, records, timeout })
    }
}

impl ClientCredentialsTasksClient {
    /// Opens an explicitly selected Tasks listen, with optional core catalog
    /// and resource filters. `taskIds` must be present; an empty selection and
    /// duplicate IDs retain their protocol meaning. Unknown extension filters
    /// are rejected before credential acquisition or any network operation.
    ///
    /// The first read delivers the ACK and its actually accepted filter. A
    /// narrowed ACK is valid, but callers must not treat omitted selections as
    /// watched. No snapshot or event-history recovery is implied by that ACK.
    pub async fn subscribe(
        &self,
        cx: &Cx,
        discovery_id: RequestId,
        request_id: RequestId,
        filter: SubscriptionFilter,
        limits: ClientCredentialsSubscriptionLimits,
    ) -> Result<ClientCredentialsTaskSubscription, ClientCredentialsTasksError> {
        self.subscribe_with_cancellation(
            cx, &McpRequestCancellation::new(), discovery_id, request_id, filter, limits,
        ).await
    }

    /// One cancellation domain spans acquisition, discovery, listen and reads.
    /// The opening credential is never replaced by a concurrent renewal. Owner
    /// closure wakes pending reads; explicit token revocation is checked before
    /// and after each poll. Already-delivered records cannot be recalled.
    #[allow(clippy::too_many_arguments)]
    pub async fn subscribe_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        discovery_id: RequestId,
        request_id: RequestId,
        filter: SubscriptionFilter,
        limits: ClientCredentialsSubscriptionLimits,
    ) -> Result<ClientCredentialsTaskSubscription, ClientCredentialsTasksError> {
        self.subscribe_with_binding(
            cx, cancellation, discovery_id, request_id, filter, limits, None,
        ).await
    }

    // A recovering input driver must never acquire new input authority. Both
    // modes share preparation, discovery and the exact same listen decoder;
    // the pinned mode differs ONLY in how the opening snapshot is obtained.
    // Kept private so a caller cannot import arbitrary credential custody.
    #[allow(clippy::too_many_arguments)]
    async fn subscribe_with_binding(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        discovery_id: RequestId,
        request_id: RequestId,
        filter: SubscriptionFilter,
        limits: ClientCredentialsSubscriptionLimits,
        binding: Option<&ClientCredentialsSnapshot>,
    ) -> Result<ClientCredentialsTaskSubscription, ClientCredentialsTasksError> {
        let prepared = prepare_subscription(
            self.client.resource().as_str(), &self.metadata, &discovery_id,
            &request_id, filter, limits,
        )?;
        let deadline = discovery_deadline(cx, limits.timeout.min(self.client.inner.timeout))
            .map_err(ClientCredentialsError::from)?;
        let owner = &self.client.inner.closed;
        active(cx, deadline, owner, cancellation, binding, async {
            Ok(async {
                let snapshot = match binding {
                    Some(binding) => ClientCredentialsSnapshot {
                        bearer: binding.bearer.clone(), scopes: binding.scopes.clone(),
                        expires_at: binding.expires_at, generation: binding.generation,
                    },
                    None => self.client.credential_with_cancellation(cx, cancellation).await?,
                };
                let executor = self.client.resource_http_executor();
                let discovery_wire = authorize(&snapshot, prepared.discovery_wire)?;
                let response = active(cx, deadline, owner, cancellation, Some(&snapshot), async {
                    executor.execute_with_cancellation(cx, cancellation, &discovery_wire).await
                        .map_err(|error| match error {
                            // Only a 3xx is preserved: it is the one executor
                            // failure whose identity a caller acts on, and the
                            // status IS the failure. Everything else stays
                            // Transport because ClientCredentialsError has no
                            // carrier for it -- narrowed deliberately, not swept.
                            ModernHttpExecutorError::Redirect { status } => {
                                ClientCredentialsError::Redirect { status }
                            }
                            _ => ClientCredentialsError::Transport,
                        })
                }).await?;
                require_success(&response)?;
                if response.metadata().kind() != ModernHttpResponseKind::Json {
                    return Err(ManagedTasksError::Negotiation.into());
                }
                let bytes = active(cx, deadline, owner, cancellation, Some(&snapshot), async {
                    response.read_to_end_with_cancellation(cx, cancellation, limits.frame_bytes).await
                        .map_err(|_| ClientCredentialsError::UnexpectedResponse)
                }).await?;
                admit_subscription_discovery(
                    &prepared.discovery, &discovery_id, &bytes, limits.frame_bytes,
                )?;
                // This is the SAME snapshot used for discovery, not a fresh
                // acquisition which could change authorization mid-operation.
                let wire = authorize(&snapshot, prepared.listen_wire)?;
                let response = active(cx, deadline, owner, cancellation, Some(&snapshot), async {
                    executor.execute_with_cancellation(cx, cancellation, &wire).await
                        .map_err(|error| match error {
                            // Only a 3xx is preserved: it is the one executor
                            // failure whose identity a caller acts on, and the
                            // status IS the failure. Everything else stays
                            // Transport because ClientCredentialsError has no
                            // carrier for it -- narrowed deliberately, not swept.
                            ModernHttpExecutorError::Redirect { status } => {
                                ClientCredentialsError::Redirect { status }
                            }
                            _ => ClientCredentialsError::Transport,
                        })
                }).await?;
                require_success(&response)?;
                if response.metadata().kind() != ModernHttpResponseKind::Sse {
                    return Err(ManagedTasksError::InvalidResponse.into());
                }
                let framing = SseLimits::new(limits.frame_bytes, limits.frame_bytes, 64)
                    .ok_or(ManagedTasksError::InvalidLimits)?;
                let listener = response.into_final_subscriptions_listener(
                    request_id.clone(), prepared.filter, framing,
                ).map_err(subscription_error)?;
                Ok(ClientCredentialsTaskSubscription {
                    listener: Some(Box::new(listener)), snapshot,
                    owner: owner.clone(), cancellation: cancellation.clone(), request_id,
                    accepted_filter: None, deadline, limits, records: 0, finished: false,
                })
            }.await)
        }).await?
    }
}

/// A caller-owned, non-Clone subscription. Retain the machine client while
/// reading: the last machine owner's drop revokes its issued credentials.
/// Pending-read abandonment closes the stream instead of leaving partially
/// consumed framing reusable. An unpolled owner is released on close or drop.
pub struct ClientCredentialsTaskSubscription {
    listener: Option<Box<ModernHttpSubscriptionListener>>,
    snapshot: ClientCredentialsSnapshot,
    owner: McpRequestCancellation,
    cancellation: McpRequestCancellation,
    request_id: RequestId,
    accepted_filter: Option<SubscriptionFilter>,
    deadline: Time,
    limits: ClientCredentialsSubscriptionLimits,
    records: usize,
    finished: bool,
}

impl ClientCredentialsTaskSubscription {
    pub fn request_id(&self) -> &RequestId { &self.request_id }
    pub fn credential_generation(&self) -> u64 { self.snapshot.generation() }
    pub fn accepted_filter(&self) -> Option<&SubscriptionFilter> { self.accepted_filter.as_ref() }

    /// Releases only this listen. This is not remote Tasks cancellation, and
    /// does not cancel the supplied domain or close other calls on the client.
    pub fn close(&mut self) { self.listener = None; }

    /// Delivers a validated ACK, core/Task notification or correlated terminal.
    /// `None` is returned only after delivery of a terminal; disconnected or
    /// truncated bodies do not become successful completion. Task completion
    /// notifications do not complete a subscription that can watch many tasks.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ModernHttpSubscriptionListenEvent>, ClientCredentialsTasksError> {
        if self.finished { return Ok(None); }
        let mut listener = self.listener.take().ok_or(ManagedTasksError::Closed)?;
        let event = active(
            cx, self.deadline, &self.owner, &self.cancellation, Some(&self.snapshot), async {
                Ok(async {
                    if self.records >= self.limits.records {
                        return Err(ManagedTasksError::RecordLimit);
                    }
                    listener.next_event(cx).await.map_err(subscription_error)?
                        .ok_or(ManagedTasksError::MissingTerminal)
                }.await)
            },
        ).await??;
        // active rechecks the owner, token and caller lifetime after decoding.
        // Only then can the acknowledged-filter state or a record be published.
        if let ModernHttpSubscriptionListenEvent::Acknowledged { accepted_filter } = &event {
            self.accepted_filter = Some(accepted_filter.clone());
        }
        self.records += 1;
        if matches!(&event, ModernHttpSubscriptionListenEvent::Terminal { .. }) {
            self.finished = true;
        } else {
            self.listener = Some(listener);
        }
        Ok(Some(event))
    }
}

struct PreparedSubscription {
    discovery: CoreRequest,
    discovery_wire: ModernHttpRequest,
    listen_wire: ModernHttpRequest,
    filter: SubscriptionFilter,
}

fn prepare_subscription(
    target: &str,
    metadata: &Value,
    discovery_id: &RequestId,
    request_id: &RequestId,
    filter: SubscriptionFilter,
    limits: ClientCredentialsSubscriptionLimits,
) -> Result<PreparedSubscription, ManagedTasksError> {
    discovery_id.validate().map_err(|_| ManagedTasksError::InvalidRequest)?;
    request_id.validate().map_err(|_| ManagedTasksError::InvalidRequest)?;
    if discovery_id.correlates_with(request_id)
        || filter.additional.keys().any(|key| key != TASK_SUBSCRIPTION_IDS_KEY)
        || task_subscription_ids(&filter).map_err(|_| ManagedTasksError::InvalidRequest)?.is_none()
    {
        return Err(ManagedTasksError::InvalidRequest);
    }
    let discovery = CoreRequest::decode(
        ProtocolEra::Modern2026, "server/discover", Some(&json!({"_meta": metadata})),
    ).map_err(|_| ManagedTasksError::InvalidRequest)?;
    let listen = CoreRequest::decode(
        ProtocolEra::Modern2026, "subscriptions/listen",
        Some(&json!({"_meta": metadata, "notifications": filter})),
    ).map_err(|_| ManagedTasksError::InvalidRequest)?;
    let params = |request: &CoreRequest| request.encode_params()
        .map_err(|_| ManagedTasksError::InvalidRequest)?
        .ok_or(ManagedTasksError::InvalidRequest);
    let discovery_wire = encode(target, "server/discover", discovery_id, params(&discovery)?, None, limits.request_bytes)?;
    let listen_wire = encode(target, "subscriptions/listen", request_id, params(&listen)?, None, limits.request_bytes)?;
    Ok(PreparedSubscription { discovery, discovery_wire, listen_wire, filter })
}

fn admit_subscription_discovery(
    discovery: &CoreRequest,
    id: &RequestId,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), ClientCredentialsTasksError> {
    // This validates the auth extension and the supported protocol version.
    admit_resource(discovery, id, bytes)?;
    let (response, source) = response_source(bytes, id, maximum)?;
    let CoreResult::Final(FinalCoreResult::Discover(result)) =
        discovery.decode_response_result(&response, &source)
            .map_err(|_| ManagedTasksError::InvalidResponse)?
    else { return Err(ManagedTasksError::Negotiation.into()); };
    crate::admit_final_tasks_discovery_surface(
        &result, TASK_STATUS_NOTIFICATION, ExtensionDirection::ServerToClient,
    ).map_err(|_| ManagedTasksError::Negotiation)?;
    Ok(())
}

fn subscription_error(error: ModernHttpSubscriptionListenError) -> ManagedTasksError {
    match error {
        ModernHttpSubscriptionListenError::RemoteError { code, .. } => ManagedTasksError::Remote { code },
        ModernHttpSubscriptionListenError::EndOfStream { .. } => ManagedTasksError::MissingTerminal,
        _ => ManagedTasksError::InvalidResponse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, JsonInteger, FINAL_CLIENT_CAPABILITIES_META_KEY};
    use fastmcp_protocol::tasks_extension::TASKS_EXTENSION;
    use super::super::super::CLIENT_CREDENTIALS_EXTENSION;

    fn metadata() -> Value {
        let mut metadata = FinalRequestMeta::new(ClientCapabilities::default());
        metadata.client_capabilities = serde_json::from_value(json!({
            "extensions": {TASKS_EXTENSION: {}, CLIENT_CREDENTIALS_EXTENSION: {}}
        })).unwrap();
        let mut value = super::super::task_metadata(metadata).unwrap();
        value["com.example/tenant"] = json!("preserved");
        value
    }
    fn filter(value: Value) -> SubscriptionFilter { serde_json::from_value(value).unwrap() }
    fn prepare(filter: SubscriptionFilter) -> Result<PreparedSubscription, ManagedTasksError> {
        prepare_subscription("https://mcp.example/mcp", &metadata(), &RequestId::Number(1),
            &RequestId::Number(2), filter, ClientCredentialsSubscriptionLimits::default())
    }
    fn discovery_result() -> Value {
        json!({"jsonrpc":"2.0", "id":1, "result":{
            "resultType":"complete", "supportedVersions":["2026-07-28"],
            "capabilities":{"extensions":{TASKS_EXTENSION:{}, CLIENT_CREDENTIALS_EXTENSION:{}}},
            "ttlMs":0, "cacheScope":"private"
        }})
    }

    #[test]
    fn subscription_stamps_both_extensions_and_preserves_the_exact_selection() {
        for ids in [json!([]), json!(["one", "one", " two "])] {
            let selection = json!({"taskIds":ids, "toolsListChanged":true, "resourceSubscriptions":["file:///watched"]});
            let prepared = prepare(filter(selection.clone())).unwrap();
            for (wire, id) in [(&prepared.discovery_wire, 1), (&prepared.listen_wire, 2)] {
                let body: Value = serde_json::from_slice(wire.body()).unwrap();
                assert_eq!(body["id"], id);
                assert_eq!(body["params"]["_meta"]["com.example/tenant"], "preserved");
                assert_eq!(body["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
                    json!({TASKS_EXTENSION:{}, CLIENT_CREDENTIALS_EXTENSION:{}}));
                assert!(!wire.headers().iter().any(|(name, _)| name.eq_ignore_ascii_case("authorization")
                    || name.eq_ignore_ascii_case("mcp-session-id") || name.eq_ignore_ascii_case("last-event-id")));
            }
            let body: Value = serde_json::from_slice(prepared.listen_wire.body()).unwrap();
            assert_eq!(body["params"]["notifications"], selection);
            assert_eq!(serde_json::to_value(prepared.filter).unwrap(), selection);
        }
    }

    #[test]
    fn subscription_preflight_rejects_missing_invalid_or_unselected_task_filters() {
        assert!(prepare(filter(json!({"taskIds":["one"]}))).is_ok());
        for value in [json!({}), json!({"taskIds":[""]}), json!({"taskIds":["line\nbreak"]}),
            json!({"taskIds":null}), json!({"taskIds":vec!["one";129]}),
            json!({"taskIds":["one"], "com.example/extra":true})]
        {
            assert!(prepare(filter(value)).is_err());
        }
        assert!(prepare(filter(json!({"taskIds":["one"]}))).is_ok());
    }

    #[test]
    fn subscription_ids_and_encoded_bytes_are_bounded_before_dispatch() {
        let meta = metadata();
        let selected = filter(json!({"taskIds":["one"]}));
        let limits = ClientCredentialsSubscriptionLimits::default();
        let numeric_alias = serde_json::from_str::<RequestId>("1e0").unwrap();
        assert!(prepare_subscription("https://mcp.example/mcp", &meta, &RequestId::Number(1),
            &numeric_alias, selected.clone(), limits).is_err());
        assert!(prepare_subscription("https://mcp.example/mcp", &meta, &RequestId::Number(1),
            &RequestId::String("1".to_owned()), selected.clone(), limits).is_ok());
        let tiny = ClientCredentialsSubscriptionLimits::new(1, 4096, 2, Duration::from_secs(1)).unwrap();
        assert!(matches!(prepare_subscription("https://mcp.example/mcp", &meta, &RequestId::Number(1),
            &RequestId::Number(2), selected, tiny), Err(ManagedTasksError::RequestTooLarge)));
        assert_eq!(meta, metadata(), "preflight cannot rewrite client metadata");
    }

    #[test]
    fn subscription_requires_both_advertisements_and_the_exact_discovery_owner() {
        let prepared = prepare(filter(json!({"taskIds":["one"]}))).unwrap();
        let valid = discovery_result();
        assert!(admit_subscription_discovery(&prepared.discovery, &RequestId::Number(1),
            &serde_json::to_vec(&valid).unwrap(), 4096).is_ok());
        for dimension in 0..6 {
            let mut changed = valid.clone();
            match dimension {
                0 => { changed["result"]["capabilities"]["extensions"].as_object_mut().unwrap().remove(TASKS_EXTENSION); }
                1 => { changed["result"]["capabilities"]["extensions"].as_object_mut().unwrap().remove(CLIENT_CREDENTIALS_EXTENSION); }
                2 => changed["result"]["capabilities"]["extensions"][TASKS_EXTENSION] = json!({"invented":true}),
                3 => changed["result"]["capabilities"]["extensions"][CLIENT_CREDENTIALS_EXTENSION] = json!({"invented":true}),
                4 => changed["result"]["supportedVersions"] = json!(["2024-11-05"]),
                _ => changed["id"] = json!("1"),
            }
            assert!(admit_subscription_discovery(&prepared.discovery, &RequestId::Number(1),
                &serde_json::to_vec(&changed).unwrap(), 4096).is_err());
        }
        assert!(admit_subscription_discovery(&prepared.discovery, &RequestId::Number(1),
            &serde_json::to_vec(&valid).unwrap(), 4096).is_ok());
    }

    #[test]
    fn subscription_limits_and_errors_cannot_hide_unbounded_work_or_peer_text() {
        let second = Duration::from_secs(1);
        assert!(ClientCredentialsSubscriptionLimits::new(1, 1, 2, second).is_ok());
        for (bytes, frame, records, time) in [(0, 1, 2, second), (1, 65537, 2, second),
            (1, 1, 1, second), (1, 1, 4097, second), (1, 1, 2, Duration::ZERO),
            (1, 1, 2, Duration::from_secs(3601))]
        {
            assert!(ClientCredentialsSubscriptionLimits::new(bytes, frame, records, time).is_err());
        }
        let error = subscription_error(ModernHttpSubscriptionListenError::RemoteError {
            code: JsonInteger::from(-32603_i64), message: "private-peer-secret".to_owned(),
        });
        assert!(matches!(error, ManagedTasksError::Remote { .. }));
        assert!(!format!("{error:?} {error}").contains("private-peer-secret"));
    }
}
