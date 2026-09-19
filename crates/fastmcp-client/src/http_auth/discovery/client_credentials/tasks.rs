//! Explicit composition of machine OAuth and the official Tasks extension.
//!
//! Reuses the browser-managed client's public command/event vocabulary and the
//! protocol crate's authoritative Tasks codecs. Each operation negotiates BOTH
//! extensions using the exact token that authenticates its operation POST. No
//! failed discovery, grant, tool call, update or cancel is automatically retried.
//! This is process-local client orchestration, not durable task storage.

/// Authenticated Tasks subscriptions, optionally composed with core filters.
pub mod subscriptions;
/// Bounded lifecycle polling with machine-owner and caller cancellation.
pub mod driver;

use std::fmt;
use std::io::{self, Write};
use std::time::Duration;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::common_types::ExactNonNegativeJsonNumber;
use fastmcp_protocol::tasks_extension::{
    CancelTaskParams, GetTaskParams, GetTaskResult, Task, TaskId, TaskInputLedger,
    TaskMethodRequest, TaskRequestMeta, UpdateTaskParams,
    TASK_CANCEL, TASK_GET, TASK_UPDATE, TASKS_EXTENSION,
};
use fastmcp_protocol::{
    CoreRequest, CoreResult, ExtensionDirection, FinalCoreResult, FinalRequestMeta,
    JsonRpcMessage, JsonRpcResponse, ProgressMarker, RequestId, ServerDiscoverResult,
    ServerNotification, FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION,
    decode_strict_jsonrpc_message, decode_strict_jsonrpc_response,
};
use serde::Deserialize;
use serde_json::{Value, json};

pub use crate::http_auth::managed::tasks::{ManagedTaskEvent, ManagedTaskRequest, ManagedTasksError};
use crate::http_executor::{
    ModernHttpExecutor, ModernHttpRequest, ModernHttpResponseKind, ModernHttpResponseStream,
    ModernHttpSseResponseStream,
};
use crate::sse::SseLimits;
use super::{
    ClientCredentialsClient, ClientCredentialsError, ClientCredentialsSnapshot,
    CLIENT_CREDENTIALS_EXTENSION, active, admit_resource, authorize,
    discovery_deadline,
};

/// Bounds discovery plus one operation, including acquisition and caller pauses.
/// Native HTTP/SSE limits still apply and may be tighter. Records include the
/// terminal result, not merely notifications; reaching the bound is not EOF.
#[derive(Clone, Copy, Debug)]
pub struct ClientCredentialsTasksLimits {
    request_bytes: usize,
    frame_bytes: usize,
    records: usize,
    timeout: Duration,
}

impl Default for ClientCredentialsTasksLimits {
    fn default() -> Self {
        Self { request_bytes: 64 * 1024, frame_bytes: 64 * 1024, records: 64, timeout: Duration::from_secs(120) }
    }
}

impl ClientCredentialsTasksLimits {
    pub fn new(request_bytes: usize, frame_bytes: usize, records: usize, timeout: Duration)
        -> Result<Self, ClientCredentialsTasksError>
    {
        if !(1..=1024 * 1024).contains(&request_bytes)
            || !(1..=1024 * 1024).contains(&frame_bytes)
            || !(1..=1024).contains(&records)
            || timeout.is_zero() || timeout > Duration::from_mins(15)
        { return Err(ManagedTasksError::InvalidLimits.into()); }
        Ok(Self { request_bytes, frame_bytes, records, timeout })
    }
}

/// Fixed authentication diagnostics or the existing sanitized Tasks failures.
/// No raw peer message, task ID, input answer, token or client secret is retained.
#[derive(Debug)]
pub enum ClientCredentialsTasksError {
    Authentication(ClientCredentialsError),
    Protocol(ManagedTasksError),
}
impl fmt::Display for ClientCredentialsTasksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(error) => fmt::Display::fmt(error, f),
            Self::Protocol(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ClientCredentialsTasksError {}
impl From<ClientCredentialsError> for ClientCredentialsTasksError {
    fn from(error: ClientCredentialsError) -> Self {
        match error {
            // A refused redirect is a PROTOCOL outcome, not an authentication
            // one, and carries the same status `require_success` would have
            // produced had the executor returned a response instead of an error.
            ClientCredentialsError::Redirect { status } => {
                Self::Protocol(ManagedTasksError::HttpStatus { status })
            }
            // Correct TODAY because every remaining variant genuinely is an
            // authentication-domain failure. A future PROTOCOL-outcome variant
            // added to ClientCredentialsError would be misclassified here
            // silently, with no compile error to catch it -- this arm accepts
            // anything. Add it above this line, not below.
            other => Self::Authentication(other),
        }
    }
}
impl From<ManagedTasksError> for ClientCredentialsTasksError {
    fn from(error: ManagedTasksError) -> Self { Self::Protocol(error) }
}

/// Explicit, immutable Tasks + client-credentials profile. The ordinary
/// `ClientCredentialsClient::execute_core` remains core-only; constructing this
/// view does not widen any sibling client's profile or contact a peer.
#[derive(Clone)]
pub struct ClientCredentialsTasksClient {
    client: ClientCredentialsClient,
    metadata: Value,
    limits: ClientCredentialsTasksLimits,
}

impl ClientCredentialsTasksClient {
    pub fn new(client: ClientCredentialsClient, metadata: FinalRequestMeta, limits: ClientCredentialsTasksLimits)
        -> Result<Self, ClientCredentialsTasksError>
    {
        Ok(Self { client, metadata: task_metadata(metadata)?, limits })
    }

    pub async fn request(
        &self, cx: &Cx, discovery_id: RequestId, request_id: RequestId, request: ManagedTaskRequest,
    ) -> Result<ClientCredentialsTaskCall, ClientCredentialsTasksError> {
        self.request_with_cancellation(cx, &McpRequestCancellation::new(), discovery_id, request_id, request).await
    }

    /// Validates both documents before any grant or network operation. Fresh
    /// same-token MCP discovery authorizes precisely this operation, never a
    /// later operation under a renewed token. Distinct correlation IDs are not
    /// idempotency keys and do not authorize replay after a lost response.
    pub async fn request_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        discovery_id: RequestId, request_id: RequestId, request: ManagedTaskRequest,
    ) -> Result<ClientCredentialsTaskCall, ClientCredentialsTasksError> {
        discovery_id.validate().map_err(|_| ManagedTasksError::InvalidRequest)?;
        request_id.validate().map_err(|_| ManagedTasksError::InvalidRequest)?;
        if discovery_id.correlates_with(&request_id) { return Err(ManagedTasksError::InvalidRequest.into()); }
        let prepared = prepare(self.client.resource().as_str(), &self.metadata, &request_id, request, self.limits)?;
        let discovery = CoreRequest::decode(
            fastmcp_protocol::protocol_policy::ProtocolEra::Modern2026,
            "server/discover", Some(&json!({"_meta": self.metadata})),
        ).map_err(|_| ManagedTasksError::InvalidRequest)?;
        let params = discovery.encode_params().map_err(|_| ManagedTasksError::InvalidRequest)?
            .ok_or(ManagedTasksError::InvalidRequest)?;
        let discovery_wire = encode(self.client.resource().as_str(), "server/discover", &discovery_id, params, None, self.limits.request_bytes)?;
        let deadline = discovery_deadline(cx, self.limits.timeout.min(self.client.inner.timeout))
            .map_err(ClientCredentialsError::from)?;
        let owner = &self.client.inner.closed;
        // The outer bound includes acquisition. Inner bounds retain the opening
        // token's expiry during both network exchanges and all response reads.
        active(cx, deadline, owner, cancellation, None, async {
            Ok(async {
                let snapshot = self.client.credential_with_cancellation(cx, cancellation).await?;
                let executor = ModernHttpExecutor::new();
                let discovery_wire = authorize(&snapshot, discovery_wire)?;
                let response = active(cx, deadline, owner, cancellation, Some(&snapshot), async {
                    executor.execute_with_cancellation(cx, cancellation, &discovery_wire).await
                        .map_err(|_| ClientCredentialsError::Transport)
                }).await?;
                require_success(&response)?;
                if response.metadata().kind() != ModernHttpResponseKind::Json {
                    return Err(ManagedTasksError::Negotiation.into());
                }
                let bytes = active(cx, deadline, owner, cancellation, Some(&snapshot), async {
                    response.read_to_end_with_cancellation(cx, cancellation, self.limits.frame_bytes).await
                        .map_err(|_| ClientCredentialsError::UnexpectedResponse)
                }).await?;
                admit_composition(&discovery, &discovery_id, &bytes, &prepared.decoder, self.limits.frame_bytes)?;
                let wire = authorize(&snapshot, prepared.wire)?;
                let response = active(cx, deadline, owner, cancellation, Some(&snapshot), async {
                    executor.execute_with_cancellation(cx, cancellation, &wire).await
                        .map_err(|_| ClientCredentialsError::Transport)
                }).await?;
                require_success(&response)?;
                ClientCredentialsTaskCall::new(
                    response, prepared.decoder, prepared.progress, snapshot, owner.clone(),
                    cancellation.clone(), request_id, deadline, self.limits,
                )
            }.await)
        }).await?
    }
}

fn require_success(response: &ModernHttpResponseStream) -> Result<(), ManagedTasksError> {
    if response.metadata().status() == 200 { Ok(()) }
    else { Err(ManagedTasksError::HttpStatus { status: response.metadata().status() }) }
}

enum Decoder { Tool(Box<CoreRequest>), Get(TaskId), Update, Cancel }
struct Prepared { wire: ModernHttpRequest, decoder: Decoder, progress: Option<ProgressMarker> }
enum Body { Json(ModernHttpResponseStream), Sse(ModernHttpSseResponseStream) }

/// Caller-owned response with typed incremental notifications and one terminal.
/// Retain the machine client while consuming it: dropping the last machine
/// owner revokes outstanding snapshots. Drop/cancel stops local observation;
/// it does not claim that a dispatched remote task or mutation was undone.
pub struct ClientCredentialsTaskCall {
    body: Option<Box<Body>>,
    decoder: Decoder,
    snapshot: ClientCredentialsSnapshot,
    owner: McpRequestCancellation,
    cancellation: McpRequestCancellation,
    request_id: RequestId,
    progress: Option<ProgressMarker>,
    last_progress: Option<ExactNonNegativeJsonNumber>,
    deadline: Time,
    limits: ClientCredentialsTasksLimits,
    records: usize,
    finished: bool,
}
impl ClientCredentialsTaskCall {
    #[allow(clippy::too_many_arguments)]
    fn new(
        response: ModernHttpResponseStream, decoder: Decoder, progress: Option<ProgressMarker>,
        snapshot: ClientCredentialsSnapshot, owner: McpRequestCancellation,
        cancellation: McpRequestCancellation, request_id: RequestId, deadline: Time,
        limits: ClientCredentialsTasksLimits,
    ) -> Result<Self, ClientCredentialsTasksError> {
        let body = match response.metadata().kind() {
            ModernHttpResponseKind::Json => Body::Json(response),
            ModernHttpResponseKind::Sse if matches!(&decoder, Decoder::Tool(_)) => {
                let framing = SseLimits::new(limits.frame_bytes, limits.frame_bytes, 64)
                    .ok_or(ManagedTasksError::InvalidLimits)?;
                Body::Sse(response.into_sse_stream(framing).map_err(|_| ManagedTasksError::InvalidResponse)?)
            }
            _ => return Err(ManagedTasksError::InvalidResponse.into()),
        };
        Ok(Self {
            body: Some(Box::new(body)), decoder, snapshot, owner, cancellation, request_id,
            progress, last_progress: None, deadline, limits, records: 0, finished: false,
        })
    }

    pub fn request_id(&self) -> &RequestId { &self.request_id }
    pub fn credential_generation(&self) -> u64 { self.generation() }
    fn generation(&self) -> u64 { self.snapshot.generation() }
    pub fn close(&mut self) { self.body = None; }

    /// A polled read takes socket custody before suspension. Error or drop
    /// permanently removes the parser; partially consumed bytes are not reused.
    /// EOF without a correlated final result fails. A final result is delivered
    /// once, and only then do later reads return `None`.
    pub async fn next_event(&mut self, cx: &Cx) -> Result<Option<ManagedTaskEvent>, ClientCredentialsTasksError> {
        if self.finished { return Ok(None); }
        let body = self.body.take().ok_or(ManagedTasksError::Closed)?;
        let mut progress = self.last_progress.clone();
        let (event, remaining) = active(cx, self.deadline, &self.owner, &self.cancellation, Some(&self.snapshot), async {
            Ok(async {
                if self.records >= self.limits.records { return Err(ManagedTasksError::RecordLimit); }
                match *body {
                    Body::Json(response) => {
                        let bytes = response.read_to_end_with_cancellation(cx, &self.cancellation, self.limits.frame_bytes).await
                            .map_err(|_| ManagedTasksError::InvalidResponse)?;
                        Ok((decode_result(&self.decoder, &bytes, &self.request_id, self.limits.frame_bytes)?, None))
                    }
                    Body::Sse(mut stream) => {
                        let frame = stream.next_event(cx).await.map_err(|_| ManagedTasksError::InvalidResponse)?
                            .ok_or(ManagedTasksError::MissingTerminal)?;
                        let event = decode_record(&self.decoder, frame.as_bytes(), &self.request_id,
                            self.limits.frame_bytes, self.progress.as_ref(), &mut progress)?;
                        Ok((event, Some(Box::new(Body::Sse(stream)))))
                    }
                }
            }.await)
        }).await??;
        // active checks context, closure, cancellation and token again AFTER
        // decoding, before either the progress ledger or event is published.
        self.last_progress = progress;
        self.records += 1;
        if matches!(&event, ManagedTaskEvent::Notification(_)) { self.body = remaining; }
        else { self.finished = true; }
        Ok(Some(event))
    }
}

fn task_metadata(metadata: FinalRequestMeta) -> Result<Value, ManagedTasksError> {
    let mut meta = serde_json::to_value(metadata).map_err(|_| ManagedTasksError::InvalidRequest)?;
    let caps = meta.get_mut(FINAL_CLIENT_CAPABILITIES_META_KEY).and_then(Value::as_object_mut)
        .ok_or(ManagedTasksError::InvalidRequest)?;
    if let Some(extensions) = caps.get("extensions") {
        let extensions = extensions.as_object().ok_or(ManagedTasksError::Negotiation)?;
        if extensions.iter().any(|(name, value)|
            (name != TASKS_EXTENSION && name != CLIENT_CREDENTIALS_EXTENSION)
                || !value.as_object().is_some_and(serde_json::Map::is_empty))
        { return Err(ManagedTasksError::Negotiation); }
    }
    caps.insert("extensions".to_owned(), json!({TASKS_EXTENSION:{}, CLIENT_CREDENTIALS_EXTENSION:{}}));
    CoreRequest::decode(fastmcp_protocol::protocol_policy::ProtocolEra::Modern2026,
        "server/discover", Some(&json!({"_meta":meta}))).map_err(|_| ManagedTasksError::InvalidRequest)?;
    Ok(meta)
}

fn prepare(target: &str, metadata: &Value, id: &RequestId, request: ManagedTaskRequest, limits: ClientCredentialsTasksLimits)
    -> Result<Prepared, ManagedTasksError>
{
    let request_meta = TaskRequestMeta { meta: serde_json::from_value(metadata.clone()).map_err(|_| ManagedTasksError::InvalidRequest)? };
    let progress = metadata.get("progressToken").map(|value| serde_json::from_value(value.clone())
        .map_err(|_| ManagedTasksError::InvalidRequest)).transpose()?;
    let (method, params, name, decoder) = match request {
        ManagedTaskRequest::CallTool { name, arguments } => {
            let mut params = json!({"_meta":metadata, "name":name});
            if let Some(arguments) = arguments { params["arguments"] = arguments; }
            let request = CoreRequest::decode(fastmcp_protocol::protocol_policy::ProtocolEra::Modern2026,
                "tools/call", Some(&params)).map_err(|_| ManagedTasksError::InvalidRequest)?;
            ("tools/call", params, Some(name), Decoder::Tool(Box::new(request)))
        }
        ManagedTaskRequest::Get(id_to_get) => {
            let request = TaskMethodRequest::new(id.clone(), TASK_GET, GetTaskParams { request:request_meta, task_id:id_to_get.clone() });
            let request = TaskMethodRequest::decode(serde_json::to_value(request).map_err(|_| ManagedTasksError::InvalidRequest)?)
                .map_err(|_| ManagedTasksError::InvalidRequest)?;
            (TASK_GET, serde_json::to_value(request.params).map_err(|_| ManagedTasksError::InvalidRequest)?, None, Decoder::Get(id_to_get))
        }
        ManagedTaskRequest::Update { task, input_responses } => {
            let Task::InputRequired { base, input_requests } = *task else { return Err(ManagedTasksError::UpdateRequiresInput) };
            let ledger = TaskInputLedger::from_requests(&input_requests).map_err(|_| ManagedTasksError::InvalidInputResponses)?;
            ledger.validate_responses(&input_responses).map_err(|_| ManagedTasksError::InvalidInputResponses)?;
            let request = TaskMethodRequest::new(id.clone(), TASK_UPDATE,
                UpdateTaskParams { request:request_meta, task_id:base.task_id, input_responses });
            let request = TaskMethodRequest::decode_update(serde_json::to_value(request).map_err(|_| ManagedTasksError::InvalidRequest)?, &ledger)
                .map_err(|_| ManagedTasksError::InvalidInputResponses)?;
            (TASK_UPDATE, serde_json::to_value(request.params).map_err(|_| ManagedTasksError::InvalidRequest)?, None, Decoder::Update)
        }
        ManagedTaskRequest::Cancel(task_id) => {
            let request = TaskMethodRequest::new(id.clone(), TASK_CANCEL, CancelTaskParams { request:request_meta, task_id });
            let request = TaskMethodRequest::decode_cancel(serde_json::to_value(request).map_err(|_| ManagedTasksError::InvalidRequest)?)
                .map_err(|_| ManagedTasksError::InvalidRequest)?;
            (TASK_CANCEL, serde_json::to_value(request.params).map_err(|_| ManagedTasksError::InvalidRequest)?, None, Decoder::Cancel)
        }
    };
    Ok(Prepared { wire:encode(target, method, id, params, name, limits.request_bytes)?, decoder, progress })
}

fn encode(target: &str, method: &str, id: &RequestId, params: Value, name: Option<String>, maximum: usize)
    -> Result<ModernHttpRequest, ManagedTasksError>
{
    id.validate().map_err(|_| ManagedTasksError::InvalidRequest)?;
    let mut body = BoundedBody { bytes:Vec::new(), maximum };
    serde_json::to_writer(&mut body, &json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}))
        .map_err(|_| ManagedTasksError::RequestTooLarge)?;
    ModernHttpRequest::new(target, body.bytes, FINAL_PROTOCOL_VERSION, method, name).map_err(|_| ManagedTasksError::InvalidRequest)
}
struct BoundedBody { bytes: Vec<u8>, maximum: usize }
impl Write for BoundedBody {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) { return Err(io::Error::other("machine Tasks request limit")); }
        self.bytes.extend_from_slice(bytes); Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn response_source(bytes: &[u8], id: &RequestId, maximum: usize) -> Result<(JsonRpcResponse, String), ManagedTasksError> {
    let (response, source) = decode_strict_jsonrpc_response(bytes, maximum).map_err(|_| ManagedTasksError::InvalidResponse)?.into_parts();
    if !response.id.as_ref().is_some_and(|actual| actual.correlates_with(id)) { return Err(ManagedTasksError::ResponseIdMismatch); }
    if let Some(error) = &response.error { return Err(ManagedTasksError::Remote { code:error.code.clone() }); }
    Ok((response, source.ok_or(ManagedTasksError::InvalidResponse)?))
}
fn admit_composition(discovery: &CoreRequest, id: &RequestId, bytes: &[u8], decoder: &Decoder, maximum: usize)
    -> Result<(), ClientCredentialsTasksError>
{
    admit_resource(discovery, id, bytes)?;
    let (response, source) = response_source(bytes, id, maximum)?;
    let CoreResult::Final(FinalCoreResult::Discover(result)) = discovery.decode_response_result(&response, &source)
        .map_err(|_| ManagedTasksError::InvalidResponse)? else { return Err(ManagedTasksError::Negotiation.into()) };
    admit_tasks(&result, decoder)?;
    Ok(())
}
fn admit_tasks(discovery: &ServerDiscoverResult, decoder: &Decoder) -> Result<(), ManagedTasksError> {
    match decoder {
        Decoder::Tool(_) => crate::admit_final_tasks_result_discriminator(discovery, "task"),
        Decoder::Get(_) => crate::admit_final_tasks_discovery_surface(discovery, TASK_GET, ExtensionDirection::ClientToServer),
        Decoder::Update => crate::admit_final_tasks_discovery_surface(discovery, TASK_UPDATE, ExtensionDirection::ClientToServer),
        Decoder::Cancel => crate::admit_final_tasks_discovery_surface(discovery, TASK_CANCEL, ExtensionDirection::ClientToServer),
    }.map_err(|_| ManagedTasksError::Negotiation)
}
fn decode_result(decoder: &Decoder, bytes: &[u8], id: &RequestId, maximum: usize) -> Result<ManagedTaskEvent, ManagedTasksError> {
    let (response, source) = response_source(bytes, id, maximum)?;
    match decoder {
        Decoder::Tool(request) => {
            let CoreResult::Final(result) = request.decode_response_result(&response, &source).map_err(|_| ManagedTasksError::InvalidResponse)?
                else { return Err(ManagedTasksError::InvalidResponse) };
            match result {
                FinalCoreResult::ToolsCall { .. } | FinalCoreResult::ToolsCallTask { .. } | FinalCoreResult::ToolsCallInputRequired { .. } =>
                    Ok(ManagedTaskEvent::ToolResult(Box::new(result))),
                _ => Err(ManagedTasksError::InvalidResponse),
            }
        }
        Decoder::Get(expected) => {
            let result: GetTaskResult = serde_json::from_str(&source).map_err(|_| ManagedTasksError::InvalidResponse)?;
            if &result.task.base().task_id != expected { return Err(ManagedTasksError::TaskIdMismatch); }
            Ok(ManagedTaskEvent::Snapshot(Box::new(result)))
        }
        Decoder::Update => serde_json::from_str(&source).map(ManagedTaskEvent::Updated).map_err(|_| ManagedTasksError::InvalidResponse),
        Decoder::Cancel => serde_json::from_str(&source).map(ManagedTaskEvent::Cancelled).map_err(|_| ManagedTasksError::InvalidResponse),
    }
}
fn decode_record(
    decoder: &Decoder, bytes: &[u8], id: &RequestId, maximum: usize,
    progress: Option<&ProgressMarker>, last_progress: &mut Option<ExactNonNegativeJsonNumber>,
) -> Result<ManagedTaskEvent, ManagedTasksError> {
    match decode_strict_jsonrpc_message(bytes, maximum).map_err(|_| ManagedTasksError::InvalidResponse)? {
        JsonRpcMessage::Response(_) => decode_result(decoder, bytes, id, maximum),
        JsonRpcMessage::Request(request) => {
            if request.id.is_some() { return Err(ManagedTasksError::InvalidResponse); }
            #[derive(Deserialize)]
            struct Raw { params: Option<Box<serde_json::value::RawValue>> }
            let raw: Raw = serde_json::from_slice(bytes).map_err(|_| ManagedTasksError::InvalidResponse)?;
            let notification = match raw.params {
                Some(params) => ServerNotification::decode_with_raw_params(&request, params.get()),
                None => ServerNotification::decode(&request),
            }.map_err(|_| ManagedTasksError::InvalidResponse)?;
            match &notification {
                ServerNotification::Cancelled(_) | ServerNotification::SubscriptionsAcknowledged(_) => return Err(ManagedTasksError::InvalidResponse),
                ServerNotification::Progress(update) => {
                    if progress != Some(&update.progress_token) || last_progress.as_ref().is_some_and(|last| update.progress.cmp(last).is_le()) {
                        return Err(ManagedTasksError::InvalidProgress);
                    }
                    *last_progress = Some(update.progress.clone());
                }
                _ => {},
            }
            Ok(ManagedTaskEvent::Notification(Box::new(notification)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::ClientCapabilities;

    fn metadata() -> Value { task_metadata(FinalRequestMeta::new(ClientCapabilities::default())).unwrap() }
    fn id() -> TaskId { TaskId::parse("owned-task").unwrap() }
    fn task() -> Task {
        serde_json::from_value(json!({"taskId":"owned-task", "status":"input_required",
            "createdAt":"2026-09-17T00:00:00Z", "lastUpdatedAt":"2026-09-17T00:00:00Z", "ttlMs":60000,
            "inputRequests":{"roots":{"method":"roots/list"}}})).unwrap()
    }
    fn envelope(result: Value) -> Vec<u8> { serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":2, "result":result})).unwrap() }
    fn prepared(request: ManagedTaskRequest) -> Prepared {
        prepare("https://resource.example/mcp", &metadata(), &RequestId::Number(2), request, ClientCredentialsTasksLimits::default()).unwrap()
    }
    #[test]
    fn both_extensions_are_explicit_and_other_profiles_cannot_be_smuggled_in() {
        let meta = metadata();
        assert_eq!(meta[FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"], json!({TASKS_EXTENSION:{},CLIENT_CREDENTIALS_EXTENSION:{}}));
        for extensions in [json!({TASKS_EXTENSION:{"extra":true}}), json!({CLIENT_CREDENTIALS_EXTENSION:{"extra":true}}), json!({"com.example/other":{}})] {
            let mut value = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
            value[FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"] = extensions;
            assert!(task_metadata(serde_json::from_value(value).unwrap()).is_err());
        }
    }
    #[test]
    fn commands_preserve_the_composed_profile_and_use_the_official_wire_verbs() {
        for (request, method) in [
            (ManagedTaskRequest::CallTool { name:"compute".to_owned(), arguments:Some(json!({"input":1})) }, "tools/call"),
            (ManagedTaskRequest::Get(id()), TASK_GET), (ManagedTaskRequest::Cancel(id()), TASK_CANCEL),
            (ManagedTaskRequest::Update { task:Box::new(task()), input_responses:serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap() }, TASK_UPDATE),
        ] {
            let request = prepared(request);
            let body: Value = serde_json::from_slice(request.wire.body()).unwrap();
            assert_eq!(body["method"], method);
            assert_eq!(body["id"], 2);
            assert_eq!(body["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"], json!({TASKS_EXTENSION:{},CLIENT_CREDENTIALS_EXTENSION:{}}));
            assert!(!request.wire.headers().iter().any(|(name,_)| name.eq_ignore_ascii_case("authorization")));
        }
    }
    #[test]
    fn discovery_requires_both_extensions_and_the_same_response_owner() {
        let discovery = CoreRequest::decode(fastmcp_protocol::protocol_policy::ProtocolEra::Modern2026,
            "server/discover", Some(&json!({"_meta":metadata()}))).unwrap();
        let base = json!({"resultType":"complete", "supportedVersions":[FINAL_PROTOCOL_VERSION], "ttlMs":0, "cacheScope":"private",
            "capabilities":{"extensions":{TASKS_EXTENSION:{},CLIENT_CREDENTIALS_EXTENSION:{}}}});
        assert!(admit_composition(&discovery, &RequestId::Number(2), &envelope(base.clone()), &Decoder::Get(id()), 65536).is_ok());
        for key in [TASKS_EXTENSION, CLIENT_CREDENTIALS_EXTENSION] {
            let mut changed = base.clone();
            changed["capabilities"]["extensions"].as_object_mut().unwrap().remove(key);
            assert!(admit_composition(&discovery, &RequestId::Number(2), &envelope(changed), &Decoder::Get(id()), 65536).is_err());
        }
        assert!(admit_composition(&discovery, &RequestId::Number(3), &envelope(base), &Decoder::Get(id()), 65536).is_err());
    }
    #[test]
    fn task_and_response_identities_are_independent_and_updates_validate_the_ledger() {
        let mut result = serde_json::to_value(task()).unwrap();
        result["resultType"] = json!("complete");
        assert!(matches!(decode_result(&Decoder::Get(id()), &envelope(result.clone()), &RequestId::Number(2), 65536), Ok(ManagedTaskEvent::Snapshot(_))));
        assert!(matches!(decode_result(&Decoder::Get(TaskId::parse("other").unwrap()), &envelope(result.clone()), &RequestId::Number(2), 65536), Err(ManagedTasksError::TaskIdMismatch)));
        assert!(matches!(decode_result(&Decoder::Get(id()), &envelope(result), &RequestId::String("2".to_owned()), 65536), Err(ManagedTasksError::ResponseIdMismatch)));
        let invalid = ManagedTaskRequest::Update { task:Box::new(task()), input_responses:serde_json::from_value(json!({"roots":{"action":"accept"}})).unwrap() };
        assert!(matches!(prepare("https://resource.example/mcp", &metadata(), &RequestId::Number(2), invalid, ClientCredentialsTasksLimits::default()), Err(ManagedTasksError::InvalidInputResponses)));
    }
    #[test]
    fn streaming_uses_exact_progress_without_mutating_state_on_rejection() {
        let request = prepared(ManagedTaskRequest::CallTool { name:"compute".to_owned(), arguments:None });
        let token = ProgressMarker::String("owned".to_owned());
        let mut last = None;
        let frame = |token, number| serde_json::to_vec(&json!({"jsonrpc":"2.0", "method":"notifications/progress", "params":{"progressToken":token,"progress":number}})).unwrap();
        assert!(decode_record(&request.decoder, &frame("owned",1), &RequestId::Number(2), 4096, Some(&token), &mut last).is_ok());
        let before = last.clone();
        for bytes in [frame("other",2), frame("owned",1)] {
            assert!(matches!(decode_record(&request.decoder, &bytes, &RequestId::Number(2), 4096, Some(&token), &mut last), Err(ManagedTasksError::InvalidProgress)));
            assert_eq!(last, before);
        }
    }
    #[test]
    fn tool_results_may_be_immediate_input_required_or_a_task_without_coercion() {
        let request = prepared(ManagedTaskRequest::CallTool { name:"compute".to_owned(), arguments:None });
        let mut task_result = serde_json::to_value(task()).unwrap();
        task_result["resultType"] = json!("task");
        for result in [json!({"resultType":"complete", "content":[]}),
            json!({"resultType":"input_required", "requestState":"opaque-state"}), task_result] {
            assert!(matches!(decode_result(&request.decoder, &envelope(result), &RequestId::Number(2), 65536), Ok(ManagedTaskEvent::ToolResult(_))));
        }
        assert!(decode_result(&Decoder::Update, &envelope(json!({"resultType":"complete"})), &RequestId::Number(2), 65536).is_ok());
        assert!(decode_result(&Decoder::Cancel, &envelope(json!({"resultType":"complete"})), &RequestId::Number(2), 65536).is_ok());
    }
    #[test]
    fn bounds_and_peer_errors_do_not_hide_unbounded_work_or_leak_diagnostics() {
        assert!(ClientCredentialsTasksLimits::new(1, 1, 1, Duration::from_secs(1)).is_ok());
        assert!(ClientCredentialsTasksLimits::new(0, 1, 1, Duration::from_secs(1)).is_err());
        assert!(ClientCredentialsTasksLimits::new(1, 1, 1025, Duration::from_secs(1)).is_err());
        let tiny = ClientCredentialsTasksLimits::new(1, 4096, 1, Duration::from_secs(1)).unwrap();
        assert!(matches!(prepare("https://resource.example/mcp", &metadata(), &RequestId::Number(2), ManagedTaskRequest::Get(id()), tiny), Err(ManagedTasksError::RequestTooLarge)));
        let error = response_source(br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"secret-canary","data":"secret-canary"}}"#, &RequestId::Number(2), 4096).err().unwrap();
        assert!(matches!(error, ManagedTasksError::Remote { .. }));
        assert!(!format!("{error:?} {error}").contains("secret-canary"));
        for bytes in [br#"[{"jsonrpc":"2.0","id":2,"result":{}}]"#.as_slice(), br#"{"jsonrpc":"2.0","id":2,"id":2,"result":{}}"#.as_slice()] {
            assert!(response_source(bytes, &RequestId::Number(2), 4096).is_err());
        }
    }
}
