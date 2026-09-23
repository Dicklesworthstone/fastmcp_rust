//! Schema-bound tool execution over managed OAuth.
//!
//! A client binds one immutable, admitted tool contract to one managed login.
//! Arguments are checked before credential renewal or HTTP dispatch; successful
//! structured output is checked before publication. Protocol admission,
//! correlation, incremental notifications and finite-response EOF checks remain
//! owned by the existing managed core call. No failed call is retried.
//!
//! A definition is a contract, not permission to execute a tool. The host must
//! approve the invocation and invalidate this client when its catalog or policy
//! changes. Server annotations never grant consent, retry or header-disclosure
//! authority. This module does not add parameter-header projection.

use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{AdmittedSchema, CoreRequest, CoreResult, FinalTool, RequestId, admit_final_schema};
use serde_json::Value;

use super::managed::ManagedOAuthSession;
use super::rpc::{ManagedCoreCall, ManagedCoreError, ManagedCoreEvent, ManagedCoreLimits};

/// Explicit multi-round tool operations retaining this same schema contract.
pub mod interaction;

/// Combined encoded-byte ceiling for one retained input/output schema pair.
pub const MAX_MANAGED_TOOL_SCHEMA_BYTES: usize = 512 * 1024;
/// Maximum UTF-8 bytes retained for a tool's exact, case-sensitive name.
pub const MAX_MANAGED_TOOL_NAME_BYTES: usize = 1024;

/// Fixed diagnostics never retain argument values, schema paths or peer output.
#[derive(Debug)]
pub enum ManagedToolError {
    InvalidDefinition,
    SchemaTooLarge,
    InvalidInputSchema,
    InvalidOutputSchema,
    RequestMismatch,
    InvalidArguments,
    InvalidResult,
    MissingStructuredOutput,
    InvalidStructuredOutput,
    Invalidated,
    Closed,
    Core(ManagedCoreError),
}

impl fmt::Display for ManagedToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidDefinition => "invalid managed tool definition",
            Self::SchemaTooLarge => "managed tool schemas exceed the retained-byte limit",
            Self::InvalidInputSchema => "managed tool input schema failed admission",
            Self::InvalidOutputSchema => "managed tool output schema failed admission",
            Self::RequestMismatch => "request does not match the bound modern tool",
            Self::InvalidArguments => "tool arguments do not satisfy the admitted input schema",
            Self::InvalidResult => "managed tool result failed protocol admission",
            Self::MissingStructuredOutput => "successful tool result omitted required structured output",
            Self::InvalidStructuredOutput => "tool structured output does not satisfy its admitted schema",
            Self::Invalidated => "managed tool contract has been invalidated",
            Self::Closed => "managed tool call is closed",
            Self::Core(error) => return fmt::Display::fmt(error, f),
        })
    }
}

impl std::error::Error for ManagedToolError {}

impl From<ManagedCoreError> for ManagedToolError {
    fn from(error: ManagedCoreError) -> Self {
        Self::Core(error)
    }
}

struct ToolContract {
    name: String,
    input: AdmittedSchema,
    output: Option<AdmittedSchema>,
    invalidated: AtomicBool,
}

impl ToolContract {
    fn admit(tool: FinalTool) -> Result<Self, ManagedToolError> {
        if tool.name.is_empty()
            || tool.name.len() > MAX_MANAGED_TOOL_NAME_BYTES
            || tool.name.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(ManagedToolError::InvalidDefinition);
        }
        // FinalTool has public fields: constructing it in Rust must not bypass
        // the root-shape checks otherwise performed by its wire deserializer.
        if tool.input_schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err(ManagedToolError::InvalidInputSchema);
        }
        if tool.output_schema.as_ref().is_some_and(|schema| !schema.is_object()) {
            return Err(ManagedToolError::InvalidOutputSchema);
        }
        let input = admit_final_schema(tool.input_schema)
            .map_err(|_| ManagedToolError::InvalidInputSchema)?;
        let output = tool.output_schema.map(admit_final_schema).transpose()
            .map_err(|_| ManagedToolError::InvalidOutputSchema)?;
        // Shared admission bounds nesting/nodes before serialization. Counting
        // does not allocate another copy of potentially large schema strings.
        let mut bytes = SchemaBytes(0);
        serde_json::to_writer(&mut bytes, input.schema())
            .map_err(|_| ManagedToolError::SchemaTooLarge)?;
        if let Some(output) = &output {
            serde_json::to_writer(&mut bytes, output.schema())
                .map_err(|_| ManagedToolError::SchemaTooLarge)?;
        }
        Ok(Self { name: tool.name, input, output, invalidated: AtomicBool::new(false) })
    }

    fn check(&self) -> Result<(), ManagedToolError> {
        if self.invalidated.load(Ordering::Acquire) {
            Err(ManagedToolError::Invalidated)
        } else {
            Ok(())
        }
    }

    fn validate_request(&self, request: &CoreRequest) -> Result<(), ManagedToolError> {
        self.check()?;
        if request.era() != ProtocolEra::Modern2026 || request.method() != "tools/call" {
            return Err(ManagedToolError::RequestMismatch);
        }
        let params = request.encode_params().map_err(|_| ManagedToolError::InvalidArguments)?
            .ok_or(ManagedToolError::InvalidArguments)?;
        if params.get("name").and_then(Value::as_str) != Some(self.name.as_str()) {
            return Err(ManagedToolError::RequestMismatch);
        }
        // Omission means no arguments, not permission to skip required fields.
        // Do not rewrite the request: absent and explicit-empty retain their
        // original wire representation, including continuation metadata.
        let empty = Value::Object(serde_json::Map::new());
        let arguments = params.get("arguments").unwrap_or(&empty);
        if !arguments.is_object() {
            return Err(ManagedToolError::InvalidArguments);
        }
        self.input.validate(arguments).map_err(|_| ManagedToolError::InvalidArguments)?;
        self.check()
    }

    fn validate_result(&self, result: &CoreResult) -> Result<(), ManagedToolError> {
        self.check()?;
        let Some(output) = &self.output else { return Ok(()); };
        // This is called only on the method-owned result produced by the
        // bound call's protocol decoder, never on an arbitrary result supplied
        // by the application. Keep and return that original lossless result.
        let encoded = result.encode().map_err(|_| ManagedToolError::InvalidResult)?;
        let value: Value = serde_json::from_str(&encoded)
            .map_err(|_| ManagedToolError::InvalidResult)?;
        match value.get("resultType").and_then(Value::as_str) {
            // A suspended invocation has not produced the tool's output yet.
            Some("input_required") => return self.check(),
            Some("complete") => {},
            _ => return Err(ManagedToolError::InvalidResult),
        }
        // A tool-level execution error is not successful structured output.
        // Preserve it as a typed tool result, not a client validation failure.
        if value.get("isError").and_then(Value::as_bool) == Some(true) {
            return self.check();
        }
        let structured = value.get("structuredContent")
            .ok_or(ManagedToolError::MissingStructuredOutput)?;
        output.validate(structured).map_err(|_| ManagedToolError::InvalidStructuredOutput)?;
        self.check()
    }
}

struct SchemaBytes(usize);

impl Write for SchemaBytes {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > MAX_MANAGED_TOOL_SCHEMA_BYTES.saturating_sub(self.0) {
            return Err(io::Error::other("managed tool schema byte limit"));
        }
        self.0 += buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

/// One tool definition bound to one managed login. Clones share the same
/// immutable schemas and irreversible invalidation state, not active requests.
/// Definitions/annotations are not treated as authorization or retry policy.
#[derive(Clone)]
pub struct ManagedToolClient {
    session: ManagedOAuthSession,
    contract: Arc<ToolContract>,
}

impl fmt::Debug for ManagedToolClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedToolClient")
            .field("has_output_schema", &self.contract.output.is_some())
            .field("invalidated", &self.is_invalidated())
            .finish_non_exhaustive()
    }
}

impl ManagedToolClient {
    /// Admits both schemas before retaining a tool binding. There is no
    /// discovery, credential acquisition, network schema resolution or I/O.
    /// The host is responsible for obtaining this definition from the intended
    /// server and approving its use with this exact managed login.
    pub fn new(session: ManagedOAuthSession, tool: FinalTool) -> Result<Self, ManagedToolError> {
        let contract = Arc::new(ToolContract::admit(tool)?);
        Ok(Self { session, contract })
    }

    pub fn tool_name(&self) -> &str { &self.contract.name }

    /// Refuses newly started calls and later publication through every clone.
    /// Calls admitted before invalidation may already be dispatching.
    /// Already-delivered events and server side effects cannot be recalled.
    /// This does not wake an idle HTTP read: use the request's cancellation
    /// handle for prompt abort. A new definition requires a new client.
    pub fn invalidate(&self) { self.contract.invalidated.store(true, Ordering::Release); }

    pub fn is_invalidated(&self) -> bool { self.contract.invalidated.load(Ordering::Acquire) }

    /// Validates an invocation without acquiring credentials or dispatching it.
    /// The exact name, protocol era and full argument schema must match.
    pub fn validate_request(&self, request: &CoreRequest) -> Result<(), ManagedToolError> {
        self.contract.validate_request(request)
    }

    /// Opens one schema-checked tool call. `input_required` is returned intact;
    /// it is not treated as a successful output or as an automatic retry.
    pub async fn request(
        &self,
        cx: &Cx,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedCoreLimits,
    ) -> Result<ManagedToolCall, ManagedToolError> {
        self.request_with_cancellation(cx, &McpRequestCancellation::new(), request, request_id, limits).await
    }

    pub async fn request_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedCoreLimits,
    ) -> Result<ManagedToolCall, ManagedToolError> {
        check_tool_call(cx, cancellation, &self.contract)?;
        self.contract.validate_request(&request)?;
        check_tool_call(cx, cancellation, &self.contract)?;
        let call = self.session.request_core_with_cancellation(
            cx, cancellation, request, request_id, limits,
        ).await?;
        check_tool_call(cx, cancellation, &self.contract)?;
        Ok(ManagedToolCall {
            call: Some(call), contract: self.contract.clone(),
            cancellation: cancellation.clone(), finished: false,
        })
    }
}

/// Incremental schema-checked call. Failed validation closes only this call;
/// malformed output never becomes a published success. Dropping an in-progress
/// read drops its owned response rather than making partial framing reusable.
pub struct ManagedToolCall {
    call: Option<ManagedCoreCall>,
    contract: Arc<ToolContract>,
    cancellation: McpRequestCancellation,
    finished: bool,
}

impl ManagedToolCall {
    pub fn close(&mut self) { self.call = None; }

    pub async fn next_event(&mut self, cx: &Cx) -> Result<Option<ManagedCoreEvent>, ManagedToolError> {
        if self.finished { return Ok(None); }
        let mut call = self.call.take().ok_or(ManagedToolError::Closed)?;
        check_tool_call(cx, &self.cancellation, &self.contract)?;
        let event = call.next_event(cx).await?.ok_or(ManagedCoreError::MissingTerminal)?;
        check_tool_call(cx, &self.cancellation, &self.contract)?;
        match &event {
            ManagedCoreEvent::Result(result) => {
                self.contract.validate_result(result)?;
                check_tool_call(cx, &self.cancellation, &self.contract)?;
                self.finished = true;
            }
            ManagedCoreEvent::Notification(_) => self.call = Some(call),
        }
        Ok(Some(event))
    }
}

// Recheck the retained request-local domain around synchronous schema work,
// not just the caller Cx. The transport still owns its original time budgets.
fn check_tool_call(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    contract: &ToolContract,
) -> Result<(), ManagedToolError> {
    if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
        return Err(ManagedCoreError::Cancelled.into());
    }
    contract.check()
}

#[cfg(test)]
mod tests;
