//! Live official Tasks notifications on the existing DPoP HTTPS stream owner.
//!
//! Discovery and listen share one credential, original deadline and payload
//! budget. The protocol's core/Tasks codecs own the wire vocabulary; this
//! adapter owns only explicit negotiation, exact-ID selection and accounting.

/// Event-driven observation with authoritative post-acknowledgement snapshots.
pub mod watch;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::tasks_extension::{
    MAX_TASK_SUBSCRIPTION_IDS, TASK_STATUS_NOTIFICATION, TASK_SUBSCRIPTION_IDS_KEY,
    TASKS_EXTENSION, TaskId, TaskStatusNotification, set_task_subscription_ids,
    task_subscription_ids,
};
use fastmcp_protocol::{
    CoreRequest, CoreResult, ExtensionDirection, FINAL_CLIENT_CAPABILITIES_META_KEY,
    FINAL_PROTOCOL_VERSION, FINAL_SUBSCRIPTION_ID_META_KEY, FinalCoreResult,
    FinalRequestMeta, FinalSubscriptionsAcknowledgedNotificationParams, JsonRpcMessage,
    RequestId, ServerNotification, SubscriptionFilter, decode_strict_jsonrpc_message,
    decode_strict_jsonrpc_response,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    CoreDecoder, DpopCredential, DpopHttpClient, DpopStreamError, DpopStreamLimits,
    Idle, Lifetime, ManagedCoreError, ManagedCoreLimits, ModernHttpRequest,
    PreparedStream, StreamDecoder, StreamEvent, StreamNotification, WaitBounds, with_caller,
};
use super::subscription_end::{SubscriptionEnd, admit_cancelled};
use super::super::{BoundedWriter, DpopHttpResponse, decode_response};
use super::super::tasks::{DpopTasksError, ManagedTasksError};
use crate::http_auth::rpc::subscription::json_subscription_error;

/// One explicit, non-replayable Tasks listen selection. IDs are JSON-RPC
/// correlation identities, not task IDs or idempotency keys. Construction does
/// no signing or I/O. Each new explicit listen needs a fresh pair of IDs.
pub struct DpopTaskSubscription {
    discovery_id: RequestId,
    subscription_id: RequestId,
    metadata: FinalRequestMeta,
    task_ids: Vec<TaskId>,
}

impl DpopTaskSubscription {
    /// Retains 1..=128 exact task IDs, including their order and duplicates.
    /// An acknowledgement may narrow this set but cannot duplicate or widen it.
    /// Nonempty extension offers in metadata are refused during preparation:
    /// this explicit operation selects only Tasks, never replaces other offers.
    pub fn new(
        discovery_id: RequestId,
        subscription_id: RequestId,
        metadata: FinalRequestMeta,
        task_ids: Vec<TaskId>,
    ) -> Result<Self, ManagedCoreError> {
        discovery_id.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
        subscription_id.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
        if discovery_id.correlates_with(&subscription_id)
            || !(1..=MAX_TASK_SUBSCRIPTION_IDS).contains(&task_ids.len())
        {
            return Err(ManagedCoreError::InvalidRequest);
        }
        Ok(Self { discovery_id, subscription_id, metadata, task_ids })
    }
}

/// Admitted observations in wire order. The acknowledgement includes its exact
/// accepted filter and metadata; Tasks retain the protocol's lossless inlined
/// result representation. These values are peer-controlled application data,
/// not diagnostics, and the observer owns their disclosure policy.
#[derive(Debug, Clone)]
pub enum DpopTaskSubscriptionEvent {
    Acknowledged(FinalSubscriptionsAcknowledgedNotificationParams),
    Task(TaskStatusNotification),
}

// Neither a Task status nor an acknowledgement is request-scoped progress.
impl StreamNotification for DpopTaskSubscriptionEvent {}

struct Prepared {
    discovery_wire: ModernHttpRequest,
    discovery_decoder: CoreDecoder,
    wire: ModernHttpRequest,
    decoder: TaskSubscriptionDecoder,
}

fn negotiation_error() -> DpopStreamError {
    DpopTasksError::Task(ManagedTasksError::Negotiation).into()
}

fn encode(
    target: &str,
    request: &CoreRequest,
    id: &RequestId,
    maximum: usize,
) -> Result<ModernHttpRequest, ManagedCoreError> {
    let params = request.encode_params()
        .map_err(|_| ManagedCoreError::InvalidRequest)?
        .ok_or(ManagedCoreError::InvalidRequest)?;
    let mut writer = BoundedWriter { bytes: Vec::new(), maximum };
    serde_json::to_writer(&mut writer, &json!({
        "jsonrpc":"2.0", "id":id, "method":request.method(), "params":params,
    })).map_err(|_| ManagedCoreError::RequestTooLarge)?;
    ModernHttpRequest::new(target, writer.bytes, FINAL_PROTOCOL_VERSION, request.method(), None)
        .map_err(|_| ManagedCoreError::InvalidRequest)
}

impl Prepared {
    fn new(
        target: &str,
        selection: DpopTaskSubscription,
        limits: ManagedCoreLimits,
        native_maximum: usize,
    ) -> Result<Self, DpopStreamError> {
        if limits.notifications() == 0 {
            return Err(ManagedCoreError::InvalidLimits.into());
        }
        let mut metadata = serde_json::to_value(selection.metadata)
            .map_err(|_| ManagedCoreError::InvalidRequest)?;
        let capabilities = metadata.get_mut(FINAL_CLIENT_CAPABILITIES_META_KEY)
            .and_then(Value::as_object_mut).ok_or(ManagedCoreError::InvalidRequest)?;
        if capabilities.get("extensions")
            .is_some_and(|value| !value.as_object().is_some_and(serde_json::Map::is_empty))
        {
            return Err(negotiation_error());
        }
        capabilities.insert("extensions".to_owned(), json!({TASKS_EXTENSION:{}}));
        let discovery = CoreRequest::decode(
            ProtocolEra::Modern2026, "server/discover", Some(&json!({"_meta":metadata})),
        ).map_err(|_| ManagedCoreError::InvalidRequest)?;
        let mut filter = SubscriptionFilter::default();
        set_task_subscription_ids(&mut filter, selection.task_ids.clone())
            .map_err(|_| ManagedCoreError::InvalidRequest)?;
        let request = CoreRequest::decode(
            ProtocolEra::Modern2026, "subscriptions/listen",
            Some(&json!({"_meta":metadata,"notifications":filter})),
        ).map_err(|_| ManagedCoreError::InvalidRequest)?;
        // Admit BOTH bounded request bodies before discovery, signing or I/O.
        let maximum = limits.request_bytes().min(native_maximum);
        let discovery_wire = encode(target, &discovery, &selection.discovery_id, maximum)?;
        let wire = encode(target, &request, &selection.subscription_id, maximum)?;
        let discovery_decoder = CoreDecoder::for_request(discovery, selection.discovery_id, limits)?;
        Ok(Self {
            discovery_wire,
            discovery_decoder,
            wire,
            decoder: TaskSubscriptionDecoder {
                request,
                id: selection.subscription_id,
                requested: selection.task_ids,
                accepted: None,
                limits,
                bytes: 0,
                notifications: 0,
                terminal: false,
                end: SubscriptionEnd::default(),
            },
        })
    }

    fn admit(mut self, response: DpopHttpResponse)
        -> Result<(ModernHttpRequest, TaskSubscriptionDecoder), DpopStreamError>
    {
        let result = decode_response(&mut self.discovery_decoder, response)?;
        let CoreResult::Final(FinalCoreResult::Discover(discovery)) = result else {
            return Err(ManagedCoreError::InvalidResult.into());
        };
        if !discovery.supported_versions().iter().any(|version| version == FINAL_PROTOCOL_VERSION) {
            return Err(negotiation_error());
        }
        // The existing official descriptor/negotiation gate, not key presence
        // alone, grants authority to receive notifications/tasks on this listen.
        crate::admit_final_tasks_discovery_surface(
            &discovery, TASK_STATUS_NOTIFICATION, ExtensionDirection::ServerToClient,
        ).map_err(|_| negotiation_error())?;
        self.decoder.bytes = self.discovery_decoder.usage().0;
        if self.decoder.bytes >= self.decoder.limits.total_bytes() {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        Ok((self.wire, self.decoder))
    }
}

impl DpopHttpClient {
    /// Discovers Tasks support with this credential, then opens one live,
    /// exact-ID `subscriptions/listen` POST. The observer receives the admitted
    /// acknowledgement first, then only Task statuses in its accepted subset.
    /// A Task's terminal status is an observation, not the listen's completion.
    /// The returned core subscriptions/listen result requires clean HTTP EOF.
    ///
    /// Peer cancellation after acknowledgement also requires clean EOF and
    /// returns `DpopStreamError::SubscriptionCancelled`, not a fabricated result
    /// or a cancelled Task. The first terminal wins: one matching cancellation
    /// after completion, or one correlated response after cancellation, is
    /// consumed without another outcome. Other post-terminal records still fail.
    ///
    /// No task polling, updates, cancellation POSTs, reconnect, login, refresh,
    /// redirect or bearer fallback occurs. A finite JSON body can report a
    /// correlated refusal, never establish a subscription. Premature EOF,
    /// incomplete SSE tails, duplicate terminals, unselected events and foreign
    /// subscription/task IDs fail without publishing a provisional completion.
    ///
    /// Discovery and listen share the original native/core/caller/token bounds
    /// and aggregate JSON payload budget. The acknowledgement counts against
    /// the notification allowance; teardown signals do not, but their bytes do.
    /// Native raw-body limits apply independently to each POST, including all
    /// SSE syntax. Neither statuses nor keepalives reset idle time. The observer
    /// must be brief and nonblocking; true continues and false yields
    /// ObserverStopped, not success. Prior side effects cannot be recalled.
    ///
    /// Cancellation, revocation, observer refusal/panic and abandoning the
    /// future release this owned exchange without cancelling the remote Tasks
    /// or the caller's context. All publication uses the shared stream guards.
    pub async fn listen_tasks_with_events<N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        selection: DpopTaskSubscription,
        limits: DpopStreamLimits,
        mut observer: N,
    ) -> Result<CoreResult, DpopStreamError>
    where
        N: FnMut(&DpopTaskSubscriptionEvent) -> bool,
    {
        let bounds = WaitBounds::new(cx, self.policy.timeout.min(limits.core.timeout()), credential)?;
        let idle = Idle::new(cx.now(), limits.idle);
        let prepared = with_caller(cx, || -> Result<_, DpopStreamError> {
            let life = Lifetime { cx, cancellation, session: &self.session, credential, bounds };
            life.check(&idle)?;
            let prepared = Prepared::new(
                self.resource().as_str(), selection, limits.core, self.policy.max_body_bytes,
            );
            life.check(&idle)?;
            prepared
        })?;
        let response = self.post_resource_with_bounds(
            cx, cancellation, credential, &prepared.discovery_wire, idle.bounds(bounds),
        ).await?;
        let (wire, decoder) = with_caller(cx, || -> Result<_, DpopStreamError> {
            let life = Lifetime { cx, cancellation, session: &self.session, credential, bounds };
            life.check(&idle)?;
            let admitted = prepared.admit(response);
            life.check(&idle)?;
            admitted
        })?;
        self.execute_prepared_core_stream(
            cx, cancellation, credential,
            PreparedStream { wire, decoder, limits, bounds, idle }, &mut observer,
        ).await?.result
    }
}

// An admitted remote cancellation is a provisional terminal, not a parsing
// error. The reader must still validate the complete HTTP/SSE response before
// publishing it. Outer errors retain transport, protocol and quota failures.
type TaskSubscriptionResult = Result<CoreResult, DpopStreamError>;

struct TaskSubscriptionDecoder {
    request: CoreRequest,
    id: RequestId,
    requested: Vec<TaskId>,
    accepted: Option<Vec<TaskId>>,
    limits: ManagedCoreLimits,
    bytes: usize,
    notifications: usize,
    terminal: bool,
    end: SubscriptionEnd,
}

fn accepted_ids(filter: &SubscriptionFilter, requested: &[TaskId])
    -> Result<Vec<TaskId>, ManagedCoreError>
{
    if filter.tools_list_changed == Some(true)
        || filter.resources_list_changed == Some(true)
        || filter.prompts_list_changed == Some(true)
        || filter.resource_subscriptions.as_ref().is_some_and(|uris| !uris.is_empty())
        || filter.additional.keys().any(|key| key != TASK_SUBSCRIPTION_IDS_KEY)
    {
        return Err(ManagedCoreError::UnexpectedNotification);
    }
    let accepted = task_subscription_ids(filter)
        .map_err(|_| ManagedCoreError::UnexpectedNotification)?.unwrap_or_default();
    for (index, id) in accepted.iter().enumerate() {
        if !requested.contains(id) || accepted[..index].contains(id) {
            return Err(ManagedCoreError::UnexpectedNotification);
        }
    }
    Ok(accepted)
}

impl StreamDecoder<DpopTaskSubscriptionEvent> for TaskSubscriptionDecoder {
    type Terminal = TaskSubscriptionResult;

    fn admit(
        &mut self,
        frame: &[u8],
        allow_notification: bool,
    ) -> Result<StreamEvent<TaskSubscriptionResult, DpopTaskSubscriptionEvent>, DpopStreamError> {
        if self.terminal {
            return Err(ManagedCoreError::InvalidResponse.into());
        }
        let maximum = self.limits.frame_bytes().min(
            self.limits.total_bytes().saturating_sub(self.bytes),
        );
        if frame.len() > maximum {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        if !allow_notification {
            return Err(json_subscription_error(frame, &self.id, self.limits).into());
        }
        let message = decode_strict_jsonrpc_message(frame, maximum)
            .map_err(|_| ManagedCoreError::InvalidResponse)?;
        let mut accepted = None;
        let event = match message {
            JsonRpcMessage::Response(response) => {
                if !response.id.as_ref().is_some_and(|id| id.correlates_with(&self.id)) {
                    return Err(ManagedCoreError::ResponseIdMismatch.into());
                }
                if let Some(error) = response.error {
                    return Err(ManagedCoreError::Remote { code: error.code }.into());
                }
                if self.accepted.is_none() {
                    return Err(ManagedCoreError::UnexpectedNotification.into());
                }
                let (response, source) = decode_strict_jsonrpc_response(frame, maximum)
                    .map_err(|_| ManagedCoreError::InvalidResponse)?.into_parts();
                let source = source.ok_or(ManagedCoreError::InvalidResult)?;
                let result = self.request.decode_response_result(&response, &source)
                    .map_err(|_| ManagedCoreError::InvalidResult)?;
                if !matches!(&result, CoreResult::Final(FinalCoreResult::SubscriptionsListen { .. })) {
                    return Err(ManagedCoreError::InvalidResult.into());
                }
                StreamEvent::Result(Ok(result))
            }
            JsonRpcMessage::Request(request) => {
                if request.id.is_some() {
                    return Err(ManagedCoreError::UnexpectedNotification.into());
                }
                if request.method == "notifications/cancelled" {
                    if self.accepted.is_none() {
                        return Err(ManagedCoreError::UnexpectedNotification.into());
                    }
                    admit_cancelled(frame, &self.id, maximum)?;
                    self.end.cancel();
                    self.terminal = true;
                    self.bytes += frame.len();
                    return Ok(StreamEvent::Result(Err(DpopStreamError::SubscriptionCancelled)));
                }
                if self.notifications >= self.limits.notifications() {
                    return Err(ManagedCoreError::NotificationLimit.into());
                }
                let id = request.params.as_ref()
                    .and_then(|params| params.get("_meta"))
                    .and_then(|meta| meta.get(FINAL_SUBSCRIPTION_ID_META_KEY))
                    .and_then(|id| serde_json::from_value::<RequestId>(id.clone()).ok())
                    .ok_or(ManagedCoreError::ResponseIdMismatch)?;
                if !id.correlates_with(&self.id) {
                    return Err(ManagedCoreError::ResponseIdMismatch.into());
                }
                let event = if request.method == TASK_STATUS_NOTIFICATION {
                    let selected = self.accepted.as_ref()
                        .ok_or(ManagedCoreError::UnexpectedNotification)?;
                    // Decode the ORIGINAL envelope, not a Value round-trip:
                    // inlined Task results preserve exact numeric lexemes.
                    let notification: TaskStatusNotification = serde_json::from_slice(frame)
                        .map_err(|_| ManagedCoreError::InvalidResponse)?;
                    if !selected.contains(&notification.params.task.base().task_id) {
                        return Err(ManagedCoreError::UnexpectedNotification.into());
                    }
                    DpopTaskSubscriptionEvent::Task(notification)
                } else {
                    #[derive(Deserialize)]
                    struct RawNotification { params: Box<serde_json::value::RawValue> }
                    let raw: RawNotification = serde_json::from_slice(frame)
                        .map_err(|_| ManagedCoreError::InvalidResponse)?;
                    let notification = ServerNotification::decode_with_raw_params(
                        &request, raw.params.get(),
                    ).map_err(|_| ManagedCoreError::UnexpectedNotification)?;
                    let ServerNotification::SubscriptionsAcknowledged(ack) = notification else {
                        return Err(ManagedCoreError::UnexpectedNotification.into());
                    };
                    if self.accepted.is_some() {
                        return Err(ManagedCoreError::UnexpectedNotification.into());
                    }
                    accepted = Some(accepted_ids(&ack.notifications, &self.requested)?);
                    DpopTaskSubscriptionEvent::Acknowledged(ack)
                };
                StreamEvent::Notification(Box::new(event))
            }
        };
        // Commit selection and quotas atomically after all admission succeeds.
        if let Some(accepted) = accepted { self.accepted = Some(accepted); }
        match &event {
            StreamEvent::Notification(_) => self.notifications += 1,
            StreamEvent::Result(_) => {
                self.terminal = true;
                self.end.complete();
            }
        }
        self.bytes += frame.len();
        Ok(event)
    }

    fn admit_terminal_tail(&mut self, frame: &[u8]) -> Result<(), DpopStreamError> {
        if !self.terminal {
            return Err(ManagedCoreError::InvalidResponse.into());
        }
        let maximum = self.limits.frame_bytes().min(
            self.limits.total_bytes().saturating_sub(self.bytes),
        );
        if frame.len() > maximum {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        self.end.admit_tail(frame, &self.id, maximum)?;
        self.bytes += frame.len();
        Ok(())
    }

    fn usage(&self) -> (usize, usize) { (self.bytes, self.notifications) }
}

#[cfg(test)]
mod tests;
