//! Official Tasks operations over the managed OAuth transport.
//!
//! Each operation first discovers the exact resource using the same access
//! credential that will authenticate its Task POST. Discovery is deliberately
//! not cached: credential renewal or a different principal cannot inherit an
//! earlier advertisement. There is no retry of a task-creating or mutating POST.
//! The existing protocol codecs, Tasks negotiation, input ledger and managed
//! native SSE framing remain the authorities for their respective layers.

use std::fmt;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::common_types::ExactNonNegativeJsonNumber;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::tasks_extension::{
    CancelTaskParams, CancelTaskResult, GetTaskParams, GetTaskResult, Task,
    TaskId, TaskInputLedger, TaskInputResponses, TaskMethodRequest, TaskRequestMeta,
    UpdateTaskParams, UpdateTaskResult, TASK_CANCEL, TASK_GET, TASK_UPDATE, TASKS_EXTENSION,
};
use fastmcp_protocol::{
    CoreRequest, CoreResult, ExtensionDirection, FinalCoreResult, FinalRequestMeta,
    JsonInteger, JsonRpcMessage, JsonRpcResponse, ProgressMarker, RequestId, ServerDiscoverResult,
    ServerNotification, FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION,
    decode_strict_jsonrpc_message, decode_strict_jsonrpc_response,
};
use serde::Deserialize;
use serde_json::Value;

use super::{
    ManagedOAuthResponse, ManagedOAuthSession, ManagedOAuthSseStream,
    OAuthCredentialSnapshot, OAuthSessionError, deadline_after,
};
use crate::http_executor::{ModernHttpExecutor, ModernHttpRequest, ModernHttpResponseKind};
use crate::sse::SseLimits;

/// Opt-in bounded Task polling and host input resolution.
pub mod driver;
/// Notification-driven multi-task observation with authenticated reconciliation.
pub mod watch;

/// Independent wire and lifetime bounds for discovery plus one Task operation.
/// Native HTTP body/idle bounds still apply and may be tighter. Record count
/// includes the terminal; it bounds total streamed work without collecting it.
#[derive(Clone, Copy, Debug)]
pub struct ManagedTasksLimits {
    request_bytes: usize,
    frame_bytes: usize,
    records: usize,
    timeout: Duration,
}

impl Default for ManagedTasksLimits {
    fn default() -> Self {
        Self { request_bytes: 64 * 1024, frame_bytes: 64 * 1024, records: 64, timeout: Duration::from_secs(120) }
    }
}

impl ManagedTasksLimits {
    pub fn new(request_bytes: usize, frame_bytes: usize, records: usize, timeout: Duration) -> Result<Self, ManagedTasksError> {
        if !(1..=1024 * 1024).contains(&request_bytes)
            || !(1..=1024 * 1024).contains(&frame_bytes)
            || !(1..=1024).contains(&records)
            || timeout.is_zero() || timeout > Duration::from_mins(15)
        { return Err(ManagedTasksError::InvalidLimits); }
        Ok(Self { request_bytes, frame_bytes, records, timeout })
    }
}

/// Distinct correlation identities for the discovery and operation POSTs.
/// Neither value is a task ID, idempotency key or authority to replay a POST.
#[derive(Clone, Debug)]
pub struct ManagedTaskRequestIds {
    discovery: RequestId,
    operation: RequestId,
}

impl ManagedTaskRequestIds {
    pub fn new(discovery: RequestId, operation: RequestId) -> Result<Self, ManagedTasksError> {
        discovery.validate().map_err(|_| ManagedTasksError::InvalidRequest)?;
        operation.validate().map_err(|_| ManagedTasksError::InvalidRequest)?;
        if discovery.correlates_with(&operation) { return Err(ManagedTasksError::InvalidRequest); }
        Ok(Self { discovery, operation })
    }
}

/// Typed operations. Tool calls may complete immediately, request input, or
/// return a Task; Tasks negotiation does not force the server to create one.
/// A task update takes a previously observed input-required snapshot. The
/// server remains responsible for current ownership and stale-state checks.
pub enum ManagedTaskRequest {
    CallTool { name: String, arguments: Option<Value> },
    Get(TaskId),
    Update { task: Box<Task>, input_responses: TaskInputResponses },
    Cancel(TaskId),
}

/// Sanitized failures, excluding peer messages, input answers and task IDs.
#[derive(Debug)]
pub enum ManagedTasksError {
    InvalidLimits,
    InvalidRequest,
    RequestTooLarge,
    Negotiation,
    InvalidResponse,
    ResponseIdMismatch,
    TaskIdMismatch,
    InvalidInputResponses,
    UpdateRequiresInput,
    InvalidProgress,
    MissingTerminal,
    RecordLimit,
    Closed,
    HttpStatus { status: u16 },
    Remote { code: JsonInteger },
    Session(OAuthSessionError),
}

impl fmt::Display for ManagedTasksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpStatus { status } => write!(f, "managed Task request rejected with HTTP {status}"),
            Self::Remote { code } => write!(f, "managed Task request failed with JSON-RPC {code}"),
            Self::Session(error) => fmt::Display::fmt(error, f),
            other => f.write_str(match other {
                Self::InvalidLimits => "invalid managed Tasks limits",
                Self::InvalidRequest => "invalid managed Task request",
                Self::RequestTooLarge => "managed Task request exceeds its byte limit",
                Self::Negotiation => "resource did not admit the exact official Tasks surface",
                Self::InvalidResponse => "managed Task response failed protocol admission",
                Self::ResponseIdMismatch => "Task response does not match the request identity",
                Self::TaskIdMismatch => "Task response identifies a different task",
                Self::InvalidInputResponses => "Task answers do not match the observed input ledger",
                Self::UpdateRequiresInput => "Task update requires an input-required snapshot",
                Self::InvalidProgress => "Task progress is uncorrelated or not increasing",
                Self::MissingTerminal => "Task stream ended without its terminal result",
                Self::RecordLimit => "managed Task response record limit exceeded",
                Self::Closed => "managed Task call is closed",
                Self::HttpStatus { .. } | Self::Remote { .. } | Self::Session(_) => unreachable!(),
            }),
        }
    }
}

impl std::error::Error for ManagedTasksError {}
impl From<OAuthSessionError> for ManagedTasksError {
    fn from(error: OAuthSessionError) -> Self { Self::Session(error) }
}

/// Incremental tool-call activity or the selected method's terminal result.
/// Update/cancel acknowledge the operation; they do not invent a task snapshot.
pub enum ManagedTaskEvent {
    Notification(Box<ServerNotification>),
    ToolResult(Box<FinalCoreResult>),
    Snapshot(Box<GetTaskResult>),
    Updated(UpdateTaskResult),
    Cancelled(CancelTaskResult),
}

/// Explicit Tasks-capable view of a managed login. Creating this view is local;
/// every operation performs fresh resource discovery before its Task POST.
/// Other extension settings must use their own negotiated clients.
#[derive(Clone)]
pub struct ManagedTasksClient {
    session: ManagedOAuthSession,
    metadata: Value,
    limits: ManagedTasksLimits,
}

impl ManagedTasksClient {
    pub fn new(session: ManagedOAuthSession, metadata: FinalRequestMeta, limits: ManagedTasksLimits) -> Result<Self, ManagedTasksError> {
        let metadata = tasks_metadata(metadata)?;
        Ok(Self { session, metadata, limits })
    }

    pub async fn request(&self, cx: &Cx, ids: ManagedTaskRequestIds, request: ManagedTaskRequest) -> Result<ManagedTaskCall, ManagedTasksError> {
        self.request_with_cancellation(cx, &McpRequestCancellation::new(), ids, request).await
    }

    /// Validates before renewal/discovery, then dispatches one Task operation.
    /// The single deadline includes credential acquisition, discovery, response
    /// reads and caller pauses. No HTTP failure causes a retry or a downgrade.
    pub async fn request_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        ids: ManagedTaskRequestIds, request: ManagedTaskRequest,
    ) -> Result<ManagedTaskCall, ManagedTasksError> {
        self.session.check(cx, cancellation)?;
        let deadline = deadline_after(cx, self.limits.timeout)?;
        let prepared = prepare(self.session.resource().as_str(), &self.metadata, &ids.operation, request, self.limits)?;
        let discovery = discovery_request(&self.metadata)?;
        let params = discovery.encode_params().map_err(|_| ManagedTasksError::InvalidRequest)?.ok_or(ManagedTasksError::InvalidRequest)?;
        let discover_wire = encode_request(self.session.resource().as_str(), "server/discover", &ids.discovery, params, None, self.limits.request_bytes)?;
        let credential = self.session.await_active(cx, cancellation, deadline, None, async {
            self.session.credential_with_cancellation(cx, cancellation).await
        }).await?;
        let response = self.execute_bound(cx, cancellation, deadline, &credential, &discover_wire).await?;
        require_json(&response)?;
        let bytes = self.session.await_active(cx, cancellation, deadline, Some(credential.expires_at), async {
            response.read_to_end(cx, self.limits.frame_bytes).await
        }).await?;
        let (envelope, source) = response_source(&bytes, &ids.discovery, self.limits.frame_bytes)?;
        let CoreResult::Final(FinalCoreResult::Discover(discovered)) = discovery.decode_response_result(&envelope, &source)
            .map_err(|_| ManagedTasksError::InvalidResponse)? else { return Err(ManagedTasksError::InvalidResponse) };
        admit_discovery(&discovered, &prepared.decoder)?;
        // No credential acquisition occurs between discovery and the operation:
        // a concurrent refresh may create a newer snapshot, never replace this one.
        let response = self.execute_bound(cx, cancellation, deadline, &credential, &prepared.wire).await?;
        ManagedTaskCall::from_response(response, prepared, ids.operation, self.limits, deadline)
    }

    async fn execute_bound(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, deadline: Time,
        credential: &OAuthCredentialSnapshot, wire: &ModernHttpRequest,
    ) -> Result<ManagedOAuthResponse, ManagedTasksError> {
        self.session.check(cx, cancellation)?;
        // Discovery and the subsequent mutation both require this same live
        // snapshot; withholding its header must never become anonymous dispatch.
        let wire = credential.authorize_request(wire)?;
        let head_deadline = deadline.min(deadline_after(cx, self.session.inner.policy.response_head_timeout)?);
        let executor = ModernHttpExecutor::new();
        let response = self.session.await_active(cx, cancellation, head_deadline, Some(credential.expires_at), async {
            executor.execute_with_cancellation(cx, cancellation, &wire).await.map_err(OAuthSessionError::Http)
        }).await?;
        if response.metadata().status() != 200 { return Err(ManagedTasksError::HttpStatus { status: response.metadata().status() }); }
        Ok(ManagedOAuthResponse {
            response, session: self.session.clone(), cancellation: cancellation.clone(),
            expires_at: credential.expires_at, generation: credential.generation,
        })
    }
}

// Keep large protocol vocabularies and body ownership off the async stack.
enum TaskDecoder { Tool(Box<CoreRequest>), Get(TaskId), Update, Cancel }
struct PreparedTask { wire: ModernHttpRequest, decoder: TaskDecoder, progress: Option<ProgressMarker> }
enum TaskBody { Json(Box<ManagedOAuthResponse>), Sse(Box<ManagedOAuthSseStream>) }

/// One owned response. Pending reads take socket ownership before suspension;
/// abandonment, error, cancellation or expiry cannot leave a reusable parser.
pub struct ManagedTaskCall {
    body: Option<TaskBody>,
    decoder: TaskDecoder,
    session: ManagedOAuthSession,
    cancellation: McpRequestCancellation,
    request_id: RequestId,
    progress: Option<ProgressMarker>,
    last_progress: Option<ExactNonNegativeJsonNumber>,
    deadline: Time,
    expires_at: Instant,
    generation: u64,
    limits: ManagedTasksLimits,
    records: usize,
    finished: bool,
}

impl ManagedTaskCall {
    fn from_response(response: ManagedOAuthResponse, prepared: PreparedTask, request_id: RequestId, limits: ManagedTasksLimits, deadline: Time) -> Result<Self, ManagedTasksError> {
        let session = response.session.clone();
        let cancellation = response.cancellation.clone();
        let expires_at = response.expires_at;
        let generation = response.generation;
        let body = match response.metadata().kind() {
            ModernHttpResponseKind::Json => TaskBody::Json(Box::new(response)),
            ModernHttpResponseKind::Sse => {
                if !matches!(prepared.decoder, TaskDecoder::Tool(_)) { return Err(ManagedTasksError::InvalidResponse); }
                let framing = SseLimits::new(limits.frame_bytes, limits.frame_bytes, 64).ok_or(ManagedTasksError::InvalidLimits)?;
                TaskBody::Sse(Box::new(response.into_sse_stream(framing)?))
            }
            _ => return Err(ManagedTasksError::InvalidResponse),
        };
        Ok(Self {
            body: Some(body), decoder: prepared.decoder, session, cancellation, request_id,
            progress: prepared.progress, last_progress: None, deadline, expires_at, generation,
            limits, records: 0, finished: false,
        })
    }

    pub fn request_id(&self) -> &RequestId { &self.request_id }
    pub fn credential_generation(&self) -> u64 { self.generation }
    pub fn close(&mut self) { self.body = None; }

    /// Results are delivered once. EOF without a result is an error. Session
    /// renewal never lengthens the credential lifetime of this response.
    /// SSE terminals remain provisional until clean body EOF. Trailing records
    /// or a failed final read withhold the result rather than starting a Task
    /// polling/continuation workflow from an incompletely validated response.
    pub async fn next_event(&mut self, cx: &Cx) -> Result<Option<ManagedTaskEvent>, ManagedTasksError> {
        if self.finished { return Ok(None); }
        let body = self.body.take().ok_or(ManagedTasksError::Closed)?;
        self.session.check(cx, &self.cancellation)?;
        if self.records >= self.limits.records { return Err(ManagedTasksError::RecordLimit); }
        let (event, remaining) = match body {
            TaskBody::Json(response) => {
                let bytes = self.session.await_active(cx, &self.cancellation, self.deadline, Some(self.expires_at), async {
                    (*response).read_to_end(cx, self.limits.frame_bytes).await
                }).await?;
                (decode_result(&self.decoder, &bytes, &self.request_id, self.limits.frame_bytes)?, None)
            }
            TaskBody::Sse(mut stream) => {
                let payload = self.session.await_active(cx, &self.cancellation, self.deadline, Some(self.expires_at), async {
                    stream.next_event(cx).await
                }).await?.ok_or(ManagedTasksError::MissingTerminal)?;
                let event = decode_stream_record(
                    &self.decoder, payload.as_bytes(), &self.request_id, self.limits.frame_bytes,
                    self.progress.as_ref(), &mut self.last_progress,
                )?;
                (event, Some(TaskBody::Sse(stream)))
            }
        };
        self.session.check(cx, &self.cancellation)?;
        if Instant::now() >= self.expires_at { return Err(OAuthSessionError::LoginRequired.into()); }
        if cx.now() >= self.deadline { return Err(OAuthSessionError::TimedOut.into()); }
        let event = if matches!(&event, ManagedTaskEvent::Notification(_)) {
            self.body = remaining;
            event
        } else {
            let event = match remaining {
                Some(TaskBody::Sse(mut stream)) => {
                    self.finish_terminal(cx, event, async { stream.next_event(cx).await }).await?
                }
                _ => event,
            };
            self.finished = true;
            event
        };
        self.records += 1;
        Ok(Some(event))
    }

    // A task ID or input-required state is not publishable until the finite
    // response body ends cleanly. Keep both the result and the read owned by
    // this future, including while a peer withholds EOF. The original login
    // expiry, operation deadline, session closure and cancellation all remain
    // active; renewal must never extend this response's authority.
    async fn finish_terminal(
        &mut self,
        cx: &Cx,
        event: ManagedTaskEvent,
        next: impl std::future::Future<Output = Result<Option<String>, OAuthSessionError>>,
    ) -> Result<ManagedTaskEvent, ManagedTasksError> {
        let trailing = self.session.await_active(
            cx, &self.cancellation, self.deadline, Some(self.expires_at), next,
        ).await?;
        if trailing.is_some() { return Err(ManagedTasksError::InvalidResponse); }
        self.session.check(cx, &self.cancellation)?;
        if Instant::now() >= self.expires_at { return Err(OAuthSessionError::LoginRequired.into()); }
        if cx.now() >= self.deadline { return Err(OAuthSessionError::TimedOut.into()); }
        Ok(event)
    }
}

fn tasks_metadata(metadata: FinalRequestMeta) -> Result<Value, ManagedTasksError> {
    let mut metadata = serde_json::to_value(metadata).map_err(|_| ManagedTasksError::InvalidRequest)?;
    let _ = discovery_request(&metadata)?;
    let capabilities = metadata.get_mut(FINAL_CLIENT_CAPABILITIES_META_KEY).and_then(Value::as_object_mut)
        .ok_or(ManagedTasksError::InvalidRequest)?;
    if capabilities.get("extensions").is_some_and(|value| !value.as_object().is_some_and(serde_json::Map::is_empty)) {
        return Err(ManagedTasksError::Negotiation);
    }
    // Explicit Tasks-client construction establishes the local selection.
    // Advertise it on discovery as well as every subsequent operation POST.
    capabilities.insert("extensions".to_owned(), serde_json::json!({TASKS_EXTENSION:{}}));
    Ok(metadata)
}

fn discovery_request(metadata: &Value) -> Result<CoreRequest, ManagedTasksError> {
    CoreRequest::decode(ProtocolEra::Modern2026, "server/discover", Some(&serde_json::json!({"_meta": metadata})))
        .map_err(|_| ManagedTasksError::InvalidRequest)
}

fn admit_discovery(discovery: &ServerDiscoverResult, decoder: &TaskDecoder) -> Result<(), ManagedTasksError> {
    if !discovery.supported_versions().iter().any(|version| version == FINAL_PROTOCOL_VERSION) {
        return Err(ManagedTasksError::Negotiation);
    }
    match decoder {
        TaskDecoder::Tool(_) => crate::admit_final_tasks_result_discriminator(discovery, "task"),
        TaskDecoder::Get(_) => crate::admit_final_tasks_discovery_surface(discovery, TASK_GET, ExtensionDirection::ClientToServer),
        TaskDecoder::Update => crate::admit_final_tasks_discovery_surface(discovery, TASK_UPDATE, ExtensionDirection::ClientToServer),
        TaskDecoder::Cancel => crate::admit_final_tasks_discovery_surface(discovery, TASK_CANCEL, ExtensionDirection::ClientToServer),
    }.map_err(|_| ManagedTasksError::Negotiation)
}

fn prepare(target: &str, metadata: &Value, id: &RequestId, request: ManagedTaskRequest, limits: ManagedTasksLimits) -> Result<PreparedTask, ManagedTasksError> {
    let mut metadata = metadata.clone();
    let capabilities = metadata.get_mut(FINAL_CLIENT_CAPABILITIES_META_KEY).and_then(Value::as_object_mut)
        .ok_or(ManagedTasksError::InvalidRequest)?;
    capabilities.insert("extensions".to_owned(), serde_json::json!({TASKS_EXTENSION: {}}));
    let request_meta = TaskRequestMeta { meta: serde_json::from_value(metadata.clone()).map_err(|_| ManagedTasksError::InvalidRequest)? };
    let progress = metadata.get("progressToken").map(|value| serde_json::from_value(value.clone()).map_err(|_| ManagedTasksError::InvalidRequest)).transpose()?;
    let (method, parameters, name, decoder) = match request {
        ManagedTaskRequest::CallTool { name, arguments } => {
            let mut params = serde_json::json!({"_meta": metadata, "name": name});
            if let Some(arguments) = arguments { params["arguments"] = arguments; }
            let core = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).map_err(|_| ManagedTasksError::InvalidRequest)?;
            ("tools/call", params, Some(name), TaskDecoder::Tool(Box::new(core)))
        }
        ManagedTaskRequest::Get(task_id) => {
            let wire = TaskMethodRequest::new(id.clone(), TASK_GET, GetTaskParams { request: request_meta, task_id: task_id.clone() });
            let wire = TaskMethodRequest::decode(serde_json::to_value(wire).map_err(|_| ManagedTasksError::InvalidRequest)?)
                .map_err(|_| ManagedTasksError::InvalidRequest)?;
            (TASK_GET, serde_json::to_value(wire.params).map_err(|_| ManagedTasksError::InvalidRequest)?, None, TaskDecoder::Get(task_id))
        }
        ManagedTaskRequest::Update { task, input_responses } => {
            let Task::InputRequired { base, input_requests } = *task else { return Err(ManagedTasksError::UpdateRequiresInput) };
            let ledger = TaskInputLedger::from_requests(&input_requests).map_err(|_| ManagedTasksError::InvalidInputResponses)?;
            ledger.validate_responses(&input_responses).map_err(|_| ManagedTasksError::InvalidInputResponses)?;
            let wire = TaskMethodRequest::new(id.clone(), TASK_UPDATE, UpdateTaskParams { request: request_meta, task_id: base.task_id, input_responses });
            let wire = TaskMethodRequest::decode_update(serde_json::to_value(wire).map_err(|_| ManagedTasksError::InvalidRequest)?, &ledger)
                .map_err(|_| ManagedTasksError::InvalidInputResponses)?;
            (TASK_UPDATE, serde_json::to_value(wire.params).map_err(|_| ManagedTasksError::InvalidRequest)?, None, TaskDecoder::Update)
        }
        ManagedTaskRequest::Cancel(task_id) => {
            let wire = TaskMethodRequest::new(id.clone(), TASK_CANCEL, CancelTaskParams { request: request_meta, task_id });
            let wire = TaskMethodRequest::decode_cancel(serde_json::to_value(wire).map_err(|_| ManagedTasksError::InvalidRequest)?)
                .map_err(|_| ManagedTasksError::InvalidRequest)?;
            (TASK_CANCEL, serde_json::to_value(wire.params).map_err(|_| ManagedTasksError::InvalidRequest)?, None, TaskDecoder::Cancel)
        }
    };
    let wire = encode_request(target, method, id, parameters, name, limits.request_bytes)?;
    Ok(PreparedTask { wire, decoder, progress })
}

fn encode_request(target: &str, method: &str, id: &RequestId, params: Value, name: Option<String>, maximum: usize) -> Result<ModernHttpRequest, ManagedTasksError> {
    id.validate().map_err(|_| ManagedTasksError::InvalidRequest)?;
    let envelope = serde_json::json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params});
    let mut writer = BoundedWriter { bytes: Vec::new(), maximum };
    serde_json::to_writer(&mut writer, &envelope).map_err(|_| ManagedTasksError::RequestTooLarge)?;
    ModernHttpRequest::new(target, writer.bytes, FINAL_PROTOCOL_VERSION, method, name).map_err(|_| ManagedTasksError::InvalidRequest)
}

fn require_json(response: &ManagedOAuthResponse) -> Result<(), ManagedTasksError> {
    if response.metadata().kind() == ModernHttpResponseKind::Json { Ok(()) } else { Err(ManagedTasksError::InvalidResponse) }
}

fn response_source(bytes: &[u8], id: &RequestId, maximum: usize) -> Result<(JsonRpcResponse, String), ManagedTasksError> {
    let admitted = decode_strict_jsonrpc_response(bytes, maximum).map_err(|_| ManagedTasksError::InvalidResponse)?;
    let (response, source) = admitted.into_parts();
    if !response.id.as_ref().is_some_and(|actual| actual.correlates_with(id)) { return Err(ManagedTasksError::ResponseIdMismatch); }
    if let Some(error) = &response.error { return Err(ManagedTasksError::Remote { code: error.code.clone() }); }
    Ok((response, source.ok_or(ManagedTasksError::InvalidResponse)?))
}

fn decode_result(decoder: &TaskDecoder, bytes: &[u8], id: &RequestId, maximum: usize) -> Result<ManagedTaskEvent, ManagedTasksError> {
    let (response, source) = response_source(bytes, id, maximum)?;
    match decoder {
        TaskDecoder::Tool(core) => {
            let CoreResult::Final(result) = core.decode_response_result(&response, &source).map_err(|_| ManagedTasksError::InvalidResponse)? else { return Err(ManagedTasksError::InvalidResponse) };
            tool_result(result)
        }
        TaskDecoder::Get(expected) => {
            let result: GetTaskResult = serde_json::from_str(&source).map_err(|_| ManagedTasksError::InvalidResponse)?;
            if &result.task.base().task_id != expected { return Err(ManagedTasksError::TaskIdMismatch); }
            Ok(ManagedTaskEvent::Snapshot(Box::new(result)))
        }
        TaskDecoder::Update => serde_json::from_str(&source).map(ManagedTaskEvent::Updated).map_err(|_| ManagedTasksError::InvalidResponse),
        TaskDecoder::Cancel => serde_json::from_str(&source).map(ManagedTaskEvent::Cancelled).map_err(|_| ManagedTasksError::InvalidResponse),
    }
}

fn decode_stream_record(
    decoder: &TaskDecoder, bytes: &[u8], id: &RequestId, maximum: usize,
    progress: Option<&ProgressMarker>, last_progress: &mut Option<ExactNonNegativeJsonNumber>,
) -> Result<ManagedTaskEvent, ManagedTasksError> {
    let message = decode_strict_jsonrpc_message(bytes, maximum).map_err(|_| ManagedTasksError::InvalidResponse)?;
    match message {
        JsonRpcMessage::Response(_) => decode_result(decoder, bytes, id, maximum),
        JsonRpcMessage::Request(request) => {
            if request.id.is_some() { return Err(ManagedTasksError::InvalidResponse); }
            // The protocol's notification codec owns field/direction admission;
            // pass the retained params substring to preserve exact progress.
            #[derive(Deserialize)]
            struct RawParams { params: Option<Box<serde_json::value::RawValue>> }
            let raw: RawParams = serde_json::from_slice(bytes).map_err(|_| ManagedTasksError::InvalidResponse)?;
            let notification = match raw.params {
                Some(raw) => ServerNotification::decode_with_raw_params(&request, raw.get()),
                None => ServerNotification::decode(&request),
            }.map_err(|_| ManagedTasksError::InvalidResponse)?;
            match &notification {
                ServerNotification::Cancelled(_) | ServerNotification::SubscriptionsAcknowledged(_) => {
                    return Err(ManagedTasksError::InvalidResponse);
                }
                ServerNotification::Progress(update) => {
                    if progress != Some(&update.progress_token)
                        || last_progress.as_ref().is_some_and(|last| update.progress.cmp(last).is_le())
                    { return Err(ManagedTasksError::InvalidProgress); }
                    *last_progress = Some(update.progress.clone());
                }
                _ => {},
            }
            Ok(ManagedTaskEvent::Notification(Box::new(notification)))
        }
    }
}

fn tool_result(result: FinalCoreResult) -> Result<ManagedTaskEvent, ManagedTasksError> {
    match result {
        FinalCoreResult::ToolsCall { .. } | FinalCoreResult::ToolsCallTask { .. } | FinalCoreResult::ToolsCallInputRequired { .. } => Ok(ManagedTaskEvent::ToolResult(Box::new(result))),
        _ => Err(ManagedTasksError::InvalidResponse),
    }
}

struct BoundedWriter { bytes: Vec<u8>, maximum: usize }
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) { return Err(io::Error::other("managed Tasks request limit")); }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::ClientCapabilities;
    use serde_json::json;

    fn meta() -> Value { serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap() }
    fn task_id() -> TaskId { TaskId::parse("task-one").unwrap() }
    fn input_task() -> Task {
        serde_json::from_value(json!({
            "taskId":"task-one", "status":"input_required", "createdAt":"2026-09-16T00:00:00Z",
            "lastUpdatedAt":"2026-09-16T00:00:00Z", "ttlMs":60000,
            "inputRequests":{"roots":{"method":"roots/list"}}
        })).unwrap()
    }
    fn envelope(result: &str) -> Vec<u8> { format!(r#"{{"jsonrpc":"2.0","id":2,"result":{result}}}"#).into_bytes() }

    #[test]
    fn task_requests_use_the_shared_codec_and_exact_empty_settings() {
        for request in [ManagedTaskRequest::Get(task_id()), ManagedTaskRequest::Cancel(task_id()), ManagedTaskRequest::CallTool { name:"echo".to_owned(), arguments:None }] {
            let prepared = prepare("https://mcp.example/mcp", &meta(), &RequestId::Number(2), request, ManagedTasksLimits::default()).unwrap();
            let wire: Value = serde_json::from_slice(prepared.wire.body()).unwrap();
            assert_eq!(wire["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"], json!({TASKS_EXTENSION:{}}));
            assert_eq!(wire["id"], 2);
            assert!(!prepared.wire.headers().iter().any(|(name, _)| name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("mcp-session-id")));
        }
    }

    #[test]
    fn update_requires_the_current_input_ledger_not_a_syntactically_valid_map() {
        let answers = |key: &str| serde_json::from_value::<TaskInputResponses>(json!({key:{"roots":[]}})).unwrap();
        assert!(prepare("https://mcp.example/mcp", &meta(), &RequestId::Number(2), ManagedTaskRequest::Update { task:Box::new(input_task()), input_responses:answers("roots") }, ManagedTasksLimits::default()).is_ok());
        let wrong_kind = serde_json::from_value(json!({"roots":{"action":"accept"}})).unwrap();
        assert!(matches!(prepare("https://mcp.example/mcp", &meta(), &RequestId::Number(2), ManagedTaskRequest::Update { task:Box::new(input_task()), input_responses:wrong_kind }, ManagedTasksLimits::default()), Err(ManagedTasksError::InvalidInputResponses)));
    }

    #[test]
    fn response_identity_and_task_identity_are_independently_checked() {
        let task = r#"{"resultType":"complete","taskId":"task-one","status":"working","createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z","ttlMs":60000}"#;
        assert!(matches!(decode_result(&TaskDecoder::Get(task_id()), &envelope(task), &RequestId::Number(2), 4096), Ok(ManagedTaskEvent::Snapshot(_))));
        assert!(matches!(decode_result(&TaskDecoder::Get(task_id()), &envelope(task), &RequestId::String("2".to_owned()), 4096), Err(ManagedTasksError::ResponseIdMismatch)));
        assert!(matches!(decode_result(&TaskDecoder::Get(TaskId::parse("task-two").unwrap()), &envelope(task), &RequestId::Number(2), 4096), Err(ManagedTasksError::TaskIdMismatch)));
    }

    #[test]
    fn bounded_requests_and_ambiguous_ids_fail_locally() {
        let tiny = ManagedTasksLimits::new(1, 4096, 1, Duration::from_secs(1)).unwrap();
        assert!(matches!(prepare("https://mcp.example/mcp", &meta(), &RequestId::Number(2), ManagedTaskRequest::Get(task_id()), tiny), Err(ManagedTasksError::RequestTooLarge)));
        let equivalent: RequestId = serde_json::from_str("2e0").unwrap();
        assert!(ManagedTaskRequestIds::new(RequestId::Number(2), equivalent).is_err());
        assert!(ManagedTaskRequestIds::new(RequestId::Number(2), RequestId::String("2".to_owned())).is_ok());
    }

    #[test]
    fn raw_task_response_rejects_duplicate_fields_batches_and_secret_diagnostics() {
        for raw in [br#"{"jsonrpc":"2.0","id":2,"id":2,"result":{"resultType":"complete"}}"#.as_slice(), br#"[{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete"}}]"#.as_slice()] {
            assert!(response_source(raw, &RequestId::Number(2), 4096).is_err());
        }
        let error = response_source(br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"secret-canary","data":"secret-canary"}}"#, &RequestId::Number(2), 4096).err().unwrap();
        assert!(matches!(error, ManagedTasksError::Remote { .. }));
        assert!(!format!("{error:?} {error}").contains("secret-canary"));
    }

    #[test]
    fn explicit_tasks_selection_is_advertised_on_discovery_without_other_extensions() {
        let metadata = tasks_metadata(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        let request = discovery_request(&metadata).unwrap().encode_params().unwrap().unwrap();
        assert_eq!(request["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"], json!({TASKS_EXTENSION:{}}));
        let mut conflicting = FinalRequestMeta::new(ClientCapabilities::default());
        conflicting.client_capabilities = serde_json::from_value(json!({"extensions":{"com.example/other":{}}})).unwrap();
        assert!(matches!(tasks_metadata(conflicting), Err(ManagedTasksError::Negotiation)));
    }

    #[test]
    fn streamed_progress_and_task_terminal_use_the_same_protocol_boundaries() {
        let prepared = prepare("https://mcp.example/mcp", &meta(), &RequestId::Number(2), ManagedTaskRequest::CallTool { name:"echo".to_owned(), arguments:None }, ManagedTasksLimits::default()).unwrap();
        let owned = ProgressMarker::String("owned".to_owned());
        let mut last = None;
        let progress = |token: &str, n: u64| serde_json::to_vec(&json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":token,"progress":n}})).unwrap();
        assert!(matches!(decode_stream_record(&prepared.decoder, &progress("owned", 1), &RequestId::Number(2), 4096, Some(&owned), &mut last), Ok(ManagedTaskEvent::Notification(_))));
        for (token, n) in [("other", 2), ("owned", 1)] {
            assert!(matches!(decode_stream_record(&prepared.decoder, &progress(token, n), &RequestId::Number(2), 4096, Some(&owned), &mut last), Err(ManagedTasksError::InvalidProgress)));
        }
        let result = envelope(r#"{"resultType":"task","taskId":"task-one","status":"working","createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z","ttlMs":60000}"#);
        assert!(matches!(decode_stream_record(&prepared.decoder, &result, &RequestId::Number(2), 4096, Some(&owned), &mut last), Ok(ManagedTaskEvent::ToolResult(_))));
    }

    #[test]
    fn task_dispatch_refuses_revoked_credentials_on_its_first_poll() {
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
                let client = ManagedTasksClient::new(session, FinalRequestMeta::new(ClientCapabilities::default()), ManagedTasksLimits::default()).unwrap();
                let wire = ModernHttpRequest::new(resource.as_str(), b"{}".to_vec(), FINAL_PROTOCOL_VERSION, TASK_GET, None).unwrap();
                assert!(credential.authorize_request(&wire).is_ok());
                bearer.revoke();
                let cancellation = McpRequestCancellation::new();
                let mut dispatch = std::pin::pin!(client.execute_bound(
                    &cx, &cancellation, Time::from_nanos(u64::MAX), &credential, &wire,
                ));
                poll_fn(|task| match dispatch.as_mut().poll(task) {
                    Poll::Ready(Err(ManagedTasksError::Session(OAuthSessionError::LoginRequired))) => Poll::Ready(()),
                    _ => panic!("revoked Tasks credentials must fail locally before any network wait"),
                }).await;
                assert!(cx.checkpoint().is_ok());
                assert!(!client.session.inner.closed.is_cancel_requested());
            });
    }

    fn finite_task_call() -> ManagedTaskCall {
        use std::sync::{Arc, atomic::AtomicUsize};
        use asupersync::sync::Mutex;
        use crate::http_auth::CanonicalHttpUrl;
        use crate::http_auth::managed::{OAuthSessionPolicy, SessionInner};
        use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration};

        let url = |value| CanonicalHttpUrl::parse(value).unwrap();
        let resource = url("https://mcp.example/mcp");
        let config = OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example", url("https://issuer.example/authorize"),
            url("https://issuer.example/token"), resource.clone(), "native-client", vec![],
        ).unwrap();
        let session = ManagedOAuthSession {
            inner: Arc::new(SessionInner {
                client: OAuthClient::new(config), resource,
                policy: OAuthSessionPolicy::default(), state: Arc::new(Mutex::new(None)),
                closed: McpRequestCancellation::new(), logout_handoff: std::sync::atomic::AtomicBool::new(false), pending: AtomicUsize::new(0),
            }),
        };
        let prepared = prepare(
            session.resource().as_str(), &meta(), &RequestId::Number(2),
            ManagedTaskRequest::CallTool { name: "echo".to_owned(), arguments: None },
            ManagedTasksLimits::default(),
        ).unwrap();
        ManagedTaskCall {
            body: None, decoder: prepared.decoder, session,
            cancellation: McpRequestCancellation::new(), request_id: RequestId::Number(2),
            progress: None, last_progress: None, deadline: Time::from_nanos(u64::MAX),
            expires_at: Instant::now() + Duration::from_secs(60), generation: 1,
            limits: ManagedTasksLimits::default(), records: 0, finished: false,
        }
    }

    fn complete_task_event(call: &ManagedTaskCall) -> ManagedTaskEvent {
        decode_result(&call.decoder, &envelope(r#"{"resultType":"complete","content":[]}"#), &call.request_id, 4096).unwrap()
    }

    #[test]
    fn finite_task_terminal_withholds_every_result_family_until_eof() {
        use std::future::{Future, poll_fn};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::Poll;
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};

        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            for result in [
                r#"{"resultType":"complete","content":[]}"#,
                r#"{"resultType":"task","taskId":"task-one","status":"working","createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z","ttlMs":60000}"#,
                r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"opaque-state"}"#,
            ] {
                let mut call = finite_task_call();
                let event = decode_result(&call.decoder, &envelope(result), &call.request_id, 4096).unwrap();
                let eof = AtomicBool::new(false);
                let mut finishing = Box::pin(call.finish_terminal(&cx, event, poll_fn(|_| {
                    if eof.load(Ordering::Acquire) { Poll::Ready(Ok(None)) } else { Poll::Pending }
                })));
                poll_fn(|task| {
                    assert!(finishing.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                eof.store(true, Ordering::Release);
                assert!(matches!(finishing.await, Ok(ManagedTaskEvent::ToolResult(_))));
                assert!(!call.cancellation.is_cancel_requested());
                assert!(!call.session.inner.closed.is_cancel_requested());
            }
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn finite_task_terminal_rejects_trailing_records_and_preserves_read_errors() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let mut call = finite_task_call();
            for trailing in [
                r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[]}}"#,
                r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#,
                r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32603,"message":"secret-canary"}}"#,
                "malformed-secret-canary",
                "",
            ] {
                let error = call.finish_terminal(&cx, complete_task_event(&call), async {
                    Ok(Some(trailing.to_owned()))
                }).await.err().unwrap();
                assert!(matches!(error, ManagedTasksError::InvalidResponse));
                assert!(!format!("{error:?} {error}").contains("secret-canary"));
            }
            let failed = call.finish_terminal(&cx, complete_task_event(&call), async {
                Err(OAuthSessionError::StateUnavailable)
            }).await;
            assert!(matches!(failed, Err(ManagedTasksError::Session(OAuthSessionError::StateUnavailable))));
            assert!(call.finish_terminal(&cx, complete_task_event(&call), async { Ok(None) }).await.is_ok());
        });
    }

    #[test]
    fn finite_task_terminal_keeps_expiry_deadline_and_owner_checks_live() {
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let mut expired = finite_task_call();
            expired.expires_at = Instant::now();
            assert!(matches!(expired.finish_terminal(&cx, complete_task_event(&expired), async { Ok(None) }).await,
                Err(ManagedTasksError::Session(OAuthSessionError::LoginRequired))));

            let mut timed = finite_task_call();
            timed.deadline = deadline_after(&cx, Duration::from_millis(20)).unwrap();
            assert!(matches!(timed.finish_terminal(&cx, complete_task_event(&timed), std::future::pending()).await,
                Err(ManagedTasksError::Session(OAuthSessionError::TimedOut))));

            let mut cancelled = finite_task_call();
            let request_cancel = cancelled.cancellation.clone();
            assert!(matches!(cancelled.finish_terminal(&cx, complete_task_event(&cancelled), async {
                request_cancel.cancel();
                Ok(None)
            }).await, Err(ManagedTasksError::Session(OAuthSessionError::Cancelled))));
            assert!(!cancelled.session.inner.closed.is_cancel_requested());

            let mut closed = finite_task_call();
            let session_close = closed.session.inner.closed.clone();
            assert!(matches!(closed.finish_terminal(&cx, complete_task_event(&closed), async {
                session_close.cancel();
                Ok(None)
            }).await, Err(ManagedTasksError::Session(OAuthSessionError::Closed))));
            assert!(!closed.cancellation.is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn dropping_finite_task_terminal_drops_the_owned_read_without_cancelling_siblings() {
        use std::future::{Future, poll_fn};
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
        use std::task::Poll;
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        struct OwnedRead(Arc<AtomicBool>);
        impl Future for OwnedRead {
            type Output = Result<Option<String>, OAuthSessionError>;
            fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Self::Output> { Poll::Pending }
        }
        impl Drop for OwnedRead {
            fn drop(&mut self) { self.0.store(true, Ordering::Release); }
        }
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let mut call = finite_task_call();
            let dropped = Arc::new(AtomicBool::new(false));
            let mut finishing = Box::pin(call.finish_terminal(
                &cx, complete_task_event(&call), OwnedRead(Arc::clone(&dropped)),
            ));
            poll_fn(|task| { assert!(finishing.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            drop(finishing);
            assert!(dropped.load(Ordering::Acquire));
            assert!(!call.cancellation.is_cancel_requested());
            assert!(!call.session.inner.closed.is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
        });
    }
}
