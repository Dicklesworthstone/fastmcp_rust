//! Explicit official Tasks operations over DPoP-authenticated HTTPS.
//!
//! Each call discovers and admits the exact Tasks surface before sending its
//! operation. The same credential, resource and deadline own both POSTs. This
//! adapter uses the existing protocol method codecs, input ledger and shared
//! Tasks discovery admission; it does not install a second Tasks wire schema.

use std::fmt;
use std::sync::Arc;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::tasks_extension::{
    CancelTaskParams, GetTaskParams, GetTaskResult, TASK_CANCEL, TASK_GET, TASK_UPDATE,
    TASKS_EXTENSION, Task, TaskId, TaskInputLedger, TaskMethodRequest, TaskRequestMeta,
    UpdateTaskParams,
};
use fastmcp_protocol::{
    CoreRequest, CoreResult, ExtensionDirection, FinalCoreResult, FinalRequestMeta,
    RequestId, decode_strict_jsonrpc_response,
};
use serde_json::{Value, json};

use super::{
    BoundedWriter, CoreDecoder, DpopCoreError, DpopCredential, DpopHttpClient,
    DpopHttpError, DpopHttpResponse, FINAL_CLIENT_CAPABILITIES_META_KEY,
    FINAL_PROTOCOL_VERSION, ManagedCoreError, ManagedCoreLimits, ModernHttpRequest,
    WaitBounds, check_live, decode_response,
};
use crate::http_auth::managed::tasks::validate_task_input_shapes;
use crate::http_executor::parameter_headers::{ReviewedToolHeaders, ToolHeaderDispatchError};
pub use crate::http_auth::managed::tasks::{ManagedTaskEvent, ManagedTaskRequest, ManagedTasksError};

/// Bounded polling and explicit host input under one original credential.
pub mod driver;

/// Incremental Task operation replies over the shared DPoP JSON/SSE executor.
pub mod stream;

/// Bounded Task observation under one original credential and deadline.
pub mod wait;

/// One explicit operation with two distinct correlation identities.
///
/// Neither identity is a task ID or an idempotency key. Construct a new value
/// for each explicit call; this owner is deliberately not Clone. Construction
/// performs no network or cryptographic work. Input-ledger and byte-bound
/// validation occur before discovery when the operation is polled.
/// Tool calls may explicitly retain a resource-bound disclosure review through
/// [`Self::with_reviewed_tool_headers`]; ordinary operations stay header-free.
pub struct DpopTaskOperation {
    discovery_id: RequestId,
    operation_id: RequestId,
    request: ManagedTaskRequest,
    reviewed_headers: Option<Arc<ReviewedToolHeaders>>,
}

impl DpopTaskOperation {
    pub fn new(
        discovery_id: RequestId,
        operation_id: RequestId,
        request: ManagedTaskRequest,
    ) -> Result<Self, ManagedTasksError> {
        discovery_id.validate().map_err(|_| ManagedTasksError::InvalidRequest)?;
        operation_id.validate().map_err(|_| ManagedTasksError::InvalidRequest)?;
        if discovery_id.correlates_with(&operation_id) {
            return Err(ManagedTasksError::InvalidRequest);
        }
        Ok(Self { discovery_id, operation_id, request, reviewed_headers: None })
    }

    /// Selects one already-reviewed tool-argument disclosure plan.
    ///
    /// Only a tool call with this exact name can retain the review; get, update
    /// and cancel never acquire tool parameter headers. The review cannot be
    /// replaced. Its exact resource and projection types are checked against
    /// the final encoded operation before discovery, proof signing or I/O.
    ///
    /// Both JSON and streaming Task APIs consume this same preparation. Only
    /// the tool POST receives mirrors; discovery and body-only secrets remain
    /// untouched. Failure rejects the operation, without unreviewed fallback,
    /// schema repair, automatic retry or permission inferred from Tasks support.
    /// Sharing the immutable review does not share invocation arguments.
    pub fn with_reviewed_tool_headers(
        mut self,
        reviewed: Arc<ReviewedToolHeaders>,
    ) -> Result<Self, ToolHeaderDispatchError> {
        if self.reviewed_headers.is_some() {
            return Err(ToolHeaderDispatchError::AlreadyProjected);
        }
        if !matches!(&self.request, ManagedTaskRequest::CallTool { name, .. }
            if name == reviewed.tool_name())
        {
            return Err(ToolHeaderDispatchError::OperationMismatch);
        }
        self.reviewed_headers = Some(reviewed);
        Ok(self)
    }
}

/// Redacted protocol and transport failures. Peer messages, IDs, tokens,
/// proofs and input answers are not retained in error diagnostics.
#[derive(Debug)]
pub enum DpopTasksError {
    Core(DpopCoreError),
    Task(ManagedTasksError),
    Header(ToolHeaderDispatchError),
}

impl fmt::Display for DpopTasksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => error.fmt(f),
            Self::Task(error) => error.fmt(f),
            Self::Header(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for DpopTasksError {}
impl From<DpopCoreError> for DpopTasksError {
    fn from(error: DpopCoreError) -> Self { Self::Core(error) }
}
impl From<DpopHttpError> for DpopTasksError {
    fn from(error: DpopHttpError) -> Self { Self::Core(error.into()) }
}
impl From<ManagedCoreError> for DpopTasksError {
    fn from(error: ManagedCoreError) -> Self { Self::Core(error.into()) }
}
impl From<ManagedTasksError> for DpopTasksError {
    fn from(error: ManagedTasksError) -> Self { Self::Task(error) }
}
impl From<ToolHeaderDispatchError> for DpopTasksError {
    fn from(error: ToolHeaderDispatchError) -> Self { Self::Header(error) }
}

// Method-owned reply state. No response discriminator alone can choose a
// decoder, and a Get retains its expected task identity independently of the
// JSON-RPC identity. No Clone or Debug can export this preparation's custody.
enum Reply {
    Tool(Box<CoreRequest>),
    Get(TaskId),
    Update,
    Cancel,
}

struct Prepared {
    discovery_wire: ModernHttpRequest,
    discovery_decoder: CoreDecoder,
    operation_wire: ModernHttpRequest,
    operation_id: RequestId,
    reply: Reply,
    limits: ManagedCoreLimits,
}

// Only successful authenticated discovery can construct this state. The
// public method consumes it once, after one operation POST; there is no retry
// or reusable discovery receipt to outlive a credential or endpoint change.
struct Admitted {
    wire: ModernHttpRequest,
    id: RequestId,
    reply: Reply,
    maximum: usize,
}

fn wire(
    target: &str,
    method: &str,
    id: &RequestId,
    params: Value,
    mut name: Option<String>,
    maximum: usize,
) -> Result<ModernHttpRequest, DpopTasksError> {
    // Task IDs are opaque routing data, not request IDs or network targets.
    // Derive the mandatory mirror from the same typed params we serialize;
    // a caller-supplied mirror cannot disagree with the actual operation.
    if matches!(method, TASK_GET | TASK_UPDATE | TASK_CANCEL) {
        let task_id = params.get("taskId").and_then(Value::as_str)
            .filter(|value| !value.is_empty()).ok_or(ManagedTasksError::InvalidRequest)?;
        if name.as_deref().is_some_and(|value| value != task_id) {
            return Err(ManagedTasksError::InvalidRequest.into());
        }
        name = Some(task_id.to_owned());
    }
    let mut writer = BoundedWriter { bytes: Vec::new(), maximum };
    serde_json::to_writer(&mut writer, &json!({
        "jsonrpc":"2.0", "id":id, "method":method, "params":params,
    })).map_err(|_| ManagedTasksError::RequestTooLarge)?;
    ModernHttpRequest::new(target, writer.bytes, FINAL_PROTOCOL_VERSION, method, name)
        .map_err(|_| ManagedTasksError::InvalidRequest.into())
}

impl Prepared {
    fn new(
        target: &str,
        metadata: FinalRequestMeta,
        operation: DpopTaskOperation,
        limits: ManagedCoreLimits,
        native_maximum: usize,
    ) -> Result<Self, DpopTasksError> {
        let maximum = limits.request_bytes().min(native_maximum);
        let mut metadata = serde_json::to_value(metadata)
            .map_err(|_| ManagedTasksError::InvalidRequest)?;
        let capabilities = metadata.get_mut(FINAL_CLIENT_CAPABILITIES_META_KEY)
            .and_then(Value::as_object_mut).ok_or(ManagedTasksError::InvalidRequest)?;
        // Like the existing managed Tasks view, this explicit selection adds
        // only Tasks. It cannot silently replace another extension's settings.
        if capabilities.get("extensions")
            .is_some_and(|value| !value.as_object().is_some_and(serde_json::Map::is_empty))
        {
            return Err(ManagedTasksError::Negotiation.into());
        }
        capabilities.insert("extensions".to_owned(), json!({TASKS_EXTENSION:{}}));
        let discovery = CoreRequest::decode(
            ProtocolEra::Modern2026, "server/discover", Some(&json!({"_meta":metadata})),
        ).map_err(|_| ManagedTasksError::InvalidRequest)?;
        let discovery_params = discovery.encode_params()
            .map_err(|_| ManagedTasksError::InvalidRequest)?
            .ok_or(ManagedTasksError::InvalidRequest)?;
        let discovery_wire = wire(target, "server/discover", &operation.discovery_id,
            discovery_params, None, maximum)?;
        let discovery_decoder = CoreDecoder::for_request(discovery, operation.discovery_id, limits)?;
        let request_meta = TaskRequestMeta {
            meta: serde_json::from_value(metadata.clone())
                .map_err(|_| ManagedTasksError::InvalidRequest)?,
        };
        let id = operation.operation_id;
        let (method, params, name, reply) = match operation.request {
            ManagedTaskRequest::CallTool { name, arguments } => {
                let mut params = json!({"_meta":metadata,"name":name});
                if let Some(arguments) = arguments { params["arguments"] = arguments; }
                let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params))
                    .map_err(|_| ManagedTasksError::InvalidRequest)?;
                ("tools/call", params, Some(name), Reply::Tool(Box::new(request)))
            }
            ManagedTaskRequest::Get(task_id) => {
                let request = TaskMethodRequest::new(id.clone(), TASK_GET,
                    GetTaskParams { request: request_meta, task_id: task_id.clone() });
                let request = TaskMethodRequest::decode(serde_json::to_value(request)
                    .map_err(|_| ManagedTasksError::InvalidRequest)?)
                    .map_err(|_| ManagedTasksError::InvalidRequest)?;
                (TASK_GET, serde_json::to_value(request.params)
                    .map_err(|_| ManagedTasksError::InvalidRequest)?, None, Reply::Get(task_id))
            }
            ManagedTaskRequest::Update { task, input_responses } => {
                let Task::InputRequired { base, input_requests } = *task else {
                    return Err(ManagedTasksError::UpdateRequiresInput.into());
                };
                let ledger = TaskInputLedger::from_requests(&input_requests)
                    .map_err(|_| ManagedTasksError::InvalidInputResponses)?;
                ledger.validate_responses(&input_responses)
                    .map_err(|_| ManagedTasksError::InvalidInputResponses)?;
                let request = TaskMethodRequest::new(id.clone(), TASK_UPDATE, UpdateTaskParams {
                    request: request_meta, task_id: base.task_id, input_responses,
                });
                let request = TaskMethodRequest::decode_update(serde_json::to_value(request)
                    .map_err(|_| ManagedTasksError::InvalidRequest)?, &ledger)
                    .map_err(|_| ManagedTasksError::InvalidInputResponses)?;
                (TASK_UPDATE, serde_json::to_value(request.params)
                    .map_err(|_| ManagedTasksError::InvalidRequest)?, None, Reply::Update)
            }
            ManagedTaskRequest::Cancel(task_id) => {
                let request = TaskMethodRequest::new(id.clone(), TASK_CANCEL,
                    CancelTaskParams { request: request_meta, task_id });
                let request = TaskMethodRequest::decode_cancel(serde_json::to_value(request)
                    .map_err(|_| ManagedTasksError::InvalidRequest)?)
                    .map_err(|_| ManagedTasksError::InvalidRequest)?;
                (TASK_CANCEL, serde_json::to_value(request.params)
                    .map_err(|_| ManagedTasksError::InvalidRequest)?, None, Reply::Cancel)
            }
        };
        let operation_wire = wire(target, method, &id, params, name, maximum)?;
        // Use the shared exact-body projection after metadata and byte admission,
        // but before either POST. Discovery never inherits argument disclosures.
        let operation_wire = match operation.reviewed_headers {
            Some(reviewed) => operation_wire.with_reviewed_tool_headers(&reviewed)?,
            None => operation_wire,
        };
        Ok(Self { discovery_wire, discovery_decoder, operation_wire,
            operation_id: id, reply, limits })
    }

    fn admit(mut self, response: DpopHttpResponse) -> Result<Admitted, DpopTasksError> {
        let result = decode_response(&mut self.discovery_decoder, response)?;
        let CoreResult::Final(FinalCoreResult::Discover(discovery)) = result else {
            return Err(ManagedTasksError::InvalidResponse.into());
        };
        if !discovery.supported_versions().iter().any(|version| version == FINAL_PROTOCOL_VERSION) {
            return Err(ManagedTasksError::Negotiation.into());
        }
        // These are the same official descriptor/negotiation admission gates
        // used by managed Tasks, not a local test for the presence of a key.
        match &self.reply {
            Reply::Tool(_) => crate::admit_final_tasks_result_discriminator(&discovery, "task"),
            Reply::Get(_) => crate::admit_final_tasks_discovery_surface(
                &discovery, TASK_GET, ExtensionDirection::ClientToServer),
            Reply::Update => crate::admit_final_tasks_discovery_surface(
                &discovery, TASK_UPDATE, ExtensionDirection::ClientToServer),
            Reply::Cancel => crate::admit_final_tasks_discovery_surface(
                &discovery, TASK_CANCEL, ExtensionDirection::ClientToServer),
        }.map_err(|_| ManagedTasksError::Negotiation)?;
        let remaining = self.limits.total_bytes()
            .checked_sub(self.discovery_decoder.usage().0)
            .filter(|remaining| *remaining > 0)
            .ok_or(ManagedCoreError::ResponseByteLimit)?;
        Ok(Admitted { wire: self.operation_wire, id: self.operation_id,
            reply: self.reply, maximum: self.limits.frame_bytes().min(remaining) })
    }
}

impl Admitted {
    fn finish(self, response: DpopHttpResponse) -> Result<ManagedTaskEvent, DpopTasksError> {
        if response.status() != 200 {
            return Err(ManagedTasksError::HttpStatus { status: response.status() }.into());
        }
        self.reply.decode(&self.id, response.body(), self.maximum)
    }
}

impl Reply {
    // JSON collectors and SSE operations use the same method-owned terminal
    // admission. The transport must still establish HTTP success and clean EOF
    // before publishing this decoded value; a discriminator is not authority.
    fn decode(
        &self,
        id: &RequestId,
        body: &[u8],
        maximum: usize,
    ) -> Result<ManagedTaskEvent, DpopTasksError> {
        if body.len() > maximum {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        let admitted = decode_strict_jsonrpc_response(body, maximum)
            .map_err(|_| ManagedTasksError::InvalidResponse)?;
        let (response, source) = admitted.into_parts();
        if !response.id.as_ref().is_some_and(|actual| actual.correlates_with(id)) {
            return Err(ManagedTasksError::ResponseIdMismatch.into());
        }
        if let Some(error) = &response.error {
            return Err(ManagedTasksError::Remote { code: error.code.clone() }.into());
        }
        let source = source.ok_or(ManagedTasksError::InvalidResponse)?;
        let result = match self {
            Self::Tool(request) => {
                if response.result.as_ref().and_then(|result| result.get("resultType"))
                    .and_then(Value::as_str) == Some("task")
                {
                    validate_task_input_shapes(&response)?;
                }
                match request.decode_response_result(&response, &source)
                    .map_err(|_| ManagedTasksError::InvalidResponse)?
                {
                    CoreResult::Final(result @ (FinalCoreResult::ToolsCall { .. }
                        | FinalCoreResult::ToolsCallTask { .. }
                        | FinalCoreResult::ToolsCallInputRequired { .. })) => {
                        ManagedTaskEvent::ToolResult(Box::new(result))
                    }
                    _ => return Err(ManagedTasksError::InvalidResponse.into()),
                }
            }
            Self::Get(expected) => {
                validate_task_input_shapes(&response)?;
                let result: GetTaskResult = serde_json::from_str(&source)
                    .map_err(|_| ManagedTasksError::InvalidResponse)?;
                if &result.task.base().task_id != expected {
                    return Err(ManagedTasksError::TaskIdMismatch.into());
                }
                ManagedTaskEvent::Snapshot(Box::new(result))
            }
            Self::Update => ManagedTaskEvent::Updated(serde_json::from_str(&source)
                .map_err(|_| ManagedTasksError::InvalidResponse)?),
            Self::Cancel => ManagedTaskEvent::Cancelled(serde_json::from_str(&source)
                .map_err(|_| ManagedTasksError::InvalidResponse)?),
        };
        Ok(result)
    }
}

impl DpopHttpClient {
    /// Performs fresh authenticated Tasks discovery followed by one operation.
    ///
    /// This is an explicit modern Tasks path, not a change to `request_core`.
    /// The ordinary core-only decoder continues to reject unnegotiated Tasks.
    /// Supply otherwise extension-free final metadata; this call advertises
    /// only the official Tasks settings and verifies the server's matching offer.
    /// The existing typed request supports tool calls, get, update and cancel.
    /// A tool may return complete, input-required or task; negotiation does not
    /// force Task creation. Update validates answers against its supplied
    /// input-required snapshot, which does not replace server authorization.
    ///
    /// Both POSTs have fresh DPoP proofs, distinct caller-selected IDs, the
    /// exact same resource and credential, and one deadline fixed BEFORE
    /// preparation. `limits` bounds each request and frame; its total payload
    /// budget covers discovery plus the operation. Native body bounds also
    /// apply. Its notification allowance is unused on this JSON-only path.
    ///
    /// No caching, refresh, automatic challenge retry, polling, continuation,
    /// subscription or remote cancellation is introduced. An HTTP error or
    /// uncertain mutation is returned, never replayed. Returned Task state is
    /// data for explicit subsequent operations, not a durable resume authority.
    /// Cancellation/drop cannot undo a POST that already committed remotely.
    pub async fn request_task(
        &mut self,
        cx: &Cx,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        operation: DpopTaskOperation,
        limits: ManagedCoreLimits,
    ) -> Result<ManagedTaskEvent, DpopTasksError> {
        self.request_task_with_cancellation(cx, &McpRequestCancellation::new(),
            credential, metadata, operation, limits).await
    }

    /// Local cancellation stops discovery/dispatch/reading without cancelling
    /// the shared caller or DPoP session. A mutating `tasks/cancel` is sent only
    /// when that is the explicitly selected, freshly negotiated operation.
    pub async fn request_task_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        operation: DpopTaskOperation,
        limits: ManagedCoreLimits,
    ) -> Result<ManagedTaskEvent, DpopTasksError> {
        let bounds = WaitBounds::new(cx, self.policy.timeout.min(limits.timeout()), credential)?;
        self.request_task_with_bounds(cx, cancellation, credential, metadata, operation,
            limits, bounds).await.map(|(event, _)| event)
    }

    // Shared by a single explicit operation and the observation-only waiter.
    // Returning actual response-body usage lets a logical wait charge every
    // discovery and get without re-encoding snapshots or resetting its budget.
    #[allow(clippy::too_many_arguments)]
    async fn request_task_with_bounds(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        metadata: FinalRequestMeta,
        operation: DpopTaskOperation,
        limits: ManagedCoreLimits,
        bounds: WaitBounds,
    ) -> Result<(ManagedTaskEvent, usize), DpopTasksError> {
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let prepared = Prepared::new(self.resource().as_str(), metadata, operation,
            limits, self.policy.max_body_bytes);
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let prepared = prepared?;
        let response = self.post_resource_with_bounds(cx, cancellation, credential,
            &prepared.discovery_wire, bounds).await?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let discovery_bytes = response.body().len();
        let admitted = prepared.admit(response);
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let admitted = admitted?;
        let response = self.post_resource_with_bounds(cx, cancellation, credential,
            &admitted.wire, bounds).await?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let payload_bytes = discovery_bytes.checked_add(response.body().len())
            .ok_or(ManagedCoreError::ResponseByteLimit)?;
        let result = admitted.finish(response);
        // Failed decoding and remote errors cannot bypass the final lifetime
        // check any more than successful task results can.
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        result.map(|event| (event, payload_bytes))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod routing_tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalHttpRequestMetadata, RequestVersionMetadata,
        admit_final_http_request};

    fn header<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
        fields.iter().find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn every_task_operation_satisfies_the_actual_server_routing_contract() {
        let target = "https://mcp.example/mcp?tenant=one";
        let task_id = TaskId::parse("opaque-task-one").unwrap();
        let task: Task = serde_json::from_value(json!({
            "taskId":"opaque-task-one", "status":"input_required",
            "createdAt":"2026-09-16T00:00:00Z", "lastUpdatedAt":"2026-09-16T00:00:00Z",
            "ttlMs":60000, "inputRequests":{"roots":{"method":"roots/list"}}
        })).unwrap();
        for request in [
            ManagedTaskRequest::Get(task_id.clone()),
            ManagedTaskRequest::Cancel(task_id),
            ManagedTaskRequest::Update { task: Box::new(task),
                input_responses: serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap() },
        ] {
            let prepared = Prepared::new(target, FinalRequestMeta::new(ClientCapabilities::default()),
                DpopTaskOperation::new(RequestId::Number(11), RequestId::Number(12), request).unwrap(),
                ManagedCoreLimits::default(), 8192).unwrap();
            let fields = prepared.operation_wire.headers();
            let body: Value = serde_json::from_slice(prepared.operation_wire.body()).unwrap();
            let mirror = header(&fields, "mcp-name").unwrap();
            assert_eq!(fields.iter().filter(|(key, _)| key.eq_ignore_ascii_case("mcp-name")).count(), 1);
            assert_eq!(body["params"]["taskId"], "opaque-task-one");
            assert_eq!(body["id"], 12);
            assert_eq!(prepared.operation_wire.target(), target);
            assert_eq!(fastmcp_protocol::http_headers::decode_mcp_header_value(mirror.as_bytes()).unwrap(),
                "opaque-task-one");
            let admit = |name: Option<&str>| admit_final_http_request(FinalHttpRequestMetadata {
                version: RequestVersionMetadata {
                    header_version: header(&fields, "mcp-protocol-version"),
                    body_version: body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"].as_str(),
                },
                header_method: header(&fields, "mcp-method"), body_method: body["method"].as_str(),
                header_name: name, body_name: body["params"]["taskId"].as_str(),
            }).is_ok();
            assert!(admit(Some(mirror)));
            assert!(!admit(None));
            assert!(!admit(Some("another-task")));
            assert!(header(&prepared.discovery_wire.headers(), "mcp-name").is_none());
            assert!(header(&fields, "authorization").is_none());
            assert!(header(&fields, "dpop").is_none());
        }
    }

    #[test]
    fn task_mirrors_cannot_be_substituted_and_encoding_is_lossless() {
        for method in [TASK_GET, TASK_UPDATE, TASK_CANCEL] {
            for id in ["opaque%2Fone", "=?base64?YWJj?=", "task 雪"] {
                let params = json!({"taskId":id});
                let request = wire("https://mcp.example/mcp", method, &RequestId::Number(2),
                    params.clone(), None, 8192).unwrap();
                let fields = request.headers();
                assert_eq!(fastmcp_protocol::http_headers::decode_mcp_header_value(
                    header(&fields, "mcp-name").unwrap().as_bytes()).unwrap(), id);
                let body: Value = serde_json::from_slice(request.body()).unwrap();
                assert_eq!(body["params"], params);
                assert!(wire("https://mcp.example/mcp", method, &RequestId::Number(2),
                    params, Some("different".to_owned()), 8192).is_err());
            }
            for params in [json!({}), json!({"taskId":null}), json!({"taskId":2}), json!({"taskId":""})] {
                assert!(wire("https://mcp.example/mcp", method, &RequestId::Number(2),
                    params, None, 8192).is_err());
            }
        }
    }
}

#[cfg(test)]
mod header_tests {
    use super::*;
    use fastmcp_core::CanonicalHttpUrl;
    use fastmcp_protocol::ClientCapabilities;
    use fastmcp_protocol::http_headers::{McpHeaderError, decode_mcp_header_value};

    const TARGET: &str = "https://mcp.example/mcp?tenant=one";

    fn review(target: &str, tool: &str) -> Arc<ReviewedToolHeaders> {
        Arc::new(ReviewedToolHeaders::new(
            CanonicalHttpUrl::parse(target).unwrap(),
            tool,
            json!({"type":"object","properties":{
                "region":{"type":"string","x-mcp-header":"Region"},
                "private":{"type":"string","writeOnly":true}
            }}),
            |_| true,
        ).unwrap())
    }

    fn call(arguments: Value) -> DpopTaskOperation {
        DpopTaskOperation::new(RequestId::Number(1), RequestId::Number(2),
            ManagedTaskRequest::CallTool { name: "echo".to_owned(), arguments: Some(arguments) })
            .unwrap()
    }

    fn prepare_call(operation: DpopTaskOperation, maximum: usize) -> Result<Prepared, DpopTasksError> {
        Prepared::new(TARGET, FinalRequestMeta::new(ClientCapabilities::default()),
            operation, ManagedCoreLimits::default(), maximum)
    }

    fn fields(wire: &ModernHttpRequest) -> Vec<(String, String)> {
        wire.headers().into_iter()
            .filter(|(name, _)| name.starts_with("Mcp-Param-"))
            .collect()
    }

    #[test]
    fn reviewed_task_projection_preserves_both_bodies_and_keeps_discovery_private() {
        let reviewed = review(TARGET, "echo");
        for region in ["eu", " 雪 ", "=?base64?YWJj?="] {
            let arguments = json!({"region":region,"private":"body-only-canary"});
            let plain = prepare_call(call(arguments.clone()), 8192).unwrap();
            let selected = call(arguments.clone()).with_reviewed_tool_headers(Arc::clone(&reviewed))
                .unwrap();
            let selected = prepare_call(selected, 8192).unwrap();
            assert_eq!(selected.operation_wire.body(), plain.operation_wire.body());
            assert_eq!(selected.discovery_wire.body(), plain.discovery_wire.body());
            assert_eq!(selected.operation_wire.target(), TARGET);
            assert!(fields(&plain.operation_wire).is_empty());
            assert!(fields(&selected.discovery_wire).is_empty());
            let projected = fields(&selected.operation_wire);
            assert_eq!(projected.len(), 1);
            assert_eq!(projected[0].0, "Mcp-Param-Region");
            assert_eq!(decode_mcp_header_value(projected[0].1.as_bytes()).unwrap(), region);
            let body: Value = serde_json::from_slice(selected.operation_wire.body()).unwrap();
            assert_eq!(body["params"]["arguments"], arguments);
            assert_eq!(body["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
                json!({TASKS_EXTENSION:{}}));
            assert!(!selected.operation_wire.headers().iter().any(|(name, value)|
                name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("dpop")
                    || value.contains("body-only-canary")));
        }
    }

    #[test]
    fn tool_reviews_cannot_cross_operations_or_replace_an_existing_selection() {
        let reviewed = review(TARGET, "echo");
        let task: Task = serde_json::from_value(json!({
            "taskId":"task-one","status":"input_required",
            "createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z",
            "ttlMs":60000,"inputRequests":{"roots":{"method":"roots/list"}}
        })).unwrap();
        for request in [
            ManagedTaskRequest::Get(TaskId::parse("task-one").unwrap()),
            ManagedTaskRequest::Cancel(TaskId::parse("task-one").unwrap()),
            ManagedTaskRequest::Update { task: Box::new(task),
                input_responses: serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap() },
        ] {
            let operation = DpopTaskOperation::new(RequestId::Number(1), RequestId::Number(2), request)
                .unwrap();
            assert!(matches!(operation.with_reviewed_tool_headers(Arc::clone(&reviewed)),
                Err(ToolHeaderDispatchError::OperationMismatch)));
        }
        assert!(matches!(call(json!({})).with_reviewed_tool_headers(review(TARGET, "other")),
            Err(ToolHeaderDispatchError::OperationMismatch)));
        let operation = call(json!({})).with_reviewed_tool_headers(Arc::clone(&reviewed)).unwrap();
        assert!(matches!(operation.with_reviewed_tool_headers(reviewed),
            Err(ToolHeaderDispatchError::AlreadyProjected)));
    }

    #[test]
    fn reviewed_task_preflight_refuses_foreign_resources_and_never_drops_a_bad_plan() {
        for target in ["https://other.example/mcp", "https://mcp.example/other?tenant=one",
            "https://mcp.example/mcp?tenant=two"]
        {
            let operation = call(json!({"region":"eu"}))
                .with_reviewed_tool_headers(review(target, "echo")).unwrap();
            assert!(matches!(prepare_call(operation, 8192),
                Err(DpopTasksError::Header(ToolHeaderDispatchError::TargetMismatch))));
        }
        let arguments = json!({"region":7,"private":"body-only-canary"});
        assert!(prepare_call(call(arguments.clone()), 8192).is_ok());
        let operation = call(arguments).with_reviewed_tool_headers(review(TARGET, "echo")).unwrap();
        let error = prepare_call(operation, 8192).err().unwrap();
        assert!(matches!(&error, DpopTasksError::Header(ToolHeaderDispatchError::Projection(
            McpHeaderError::InvalidParameter))));
        assert!(!format!("{error:?} {error}").contains("body-only-canary"));
    }

    #[test]
    fn header_selection_does_not_relax_the_original_request_byte_limits() {
        let arguments = json!({"region":"eu","private":"body-only-canary"});
        let plain = prepare_call(call(arguments.clone()), 8192).unwrap();
        let needed = plain.discovery_wire.body().len().max(plain.operation_wire.body().len());
        for selected in [false, true] {
            for exact in [false, true] {
                let mut operation = call(arguments.clone());
                if selected {
                    operation = operation.with_reviewed_tool_headers(review(TARGET, "echo")).unwrap();
                }
                let result = prepare_call(operation, needed - usize::from(!exact));
                if exact {
                    assert!(result.is_ok());
                } else {
                    assert!(matches!(result, Err(DpopTasksError::Task(ManagedTasksError::RequestTooLarge))));
                }
            }
        }
    }
}
