//! One-shot repair of a trusted, pre-dispatch tool-header rejection.
//!
//! A missing reply is not evidence that a tool did not execute. This module
//! creates repair custody only from a complete, strictly admitted HTTP 400 JSON
//! error with code -32020 and the exact attempted request ID, received through
//! the managed session for an independently trusted endpoint. A 200 error, an
//! opaque body, a redirect, malformed data, or interrupted I/O never qualifies.
//!
//! The host explicitly consumes that custody to refresh the complete uncached
//! catalog, approve the new definition and every disclosed path, and send the
//! original invocation once with a fresh ID. There is no third tool attempt,
//! automatic input resolution, durable recovery, or mutation of old tool handles.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Write};

use asupersync::{Cx, types::Time};
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::http_headers::ParameterHeaderBinding;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    ClientCapabilities, CoreRequest, CoreResult, FinalCoreRequest, FinalCoreResult,
    FinalRequestMeta, FinalTool, HEADER_MISMATCH_ERROR_CODE, JsonInteger, RequestId,
    decode_strict_jsonrpc_response,
};
use serde_json::json;

use super::{
    ManagedCoreCall, ManagedCoreError, ManagedCoreLimits, ManagedOAuthSession,
    ManagedToolHeaderError, ReviewedToolHeaders, ToolHeaderDispatchError,
    bounded_wait, call_deadline, prepare_optional,
};
use super::super::check_call;
use super::super::catalog::{ManagedCatalogClient, ManagedCatalogError, ManagedCatalogLimits};
use crate::http_executor::ModernHttpErrorBodyAdmission;

const MAX_REPAIR_PAGES: usize = 64;
const MAX_REPAIR_TOOLS: usize = 4096;
const MAX_REPAIR_ID_BYTES: usize = 64 * 1024;

/// Trusted deployment configuration, never a server-advertised retry hint.
///
/// Construct only when the endpoint guarantees that HTTP 400/-32020 is emitted
/// before any tool handler, continuation consumption, or application effect.
/// This client verifies the wire response, not the remote implementation. A
/// misconfigured or dishonest endpoint can repeat effects. TLS authenticity,
/// an idempotent annotation, or the error code alone does not prove this contract.
pub struct ToolHeaderRepairContract {
    resource: CanonicalHttpUrl,
}

impl ToolHeaderRepairContract {
    pub fn for_configured_endpoint(resource: CanonicalHttpUrl) -> Result<Self, ToolHeaderRepairError> {
        if resource.scheme() != "https" || resource.has_userinfo() || resource.fragment().is_some() {
            return Err(ToolHeaderRepairError::InvalidContract);
        }
        Ok(Self { resource })
    }

    fn admit_endpoint(&self, resource: &CanonicalHttpUrl) -> Result<(), ToolHeaderRepairError> {
        if &self.resource != resource { return Err(ToolHeaderRepairError::EndpointMismatch); }
        Ok(())
    }
}

impl fmt::Debug for ToolHeaderRepairContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolHeaderRepairContract").finish_non_exhaustive()
    }
}

/// A single lifetime and response-byte budget spanning rejection, refresh and retry.
///
/// The entire `catalog_bytes` allowance is conservatively charged to the final
/// call, even when the catalog uses less. The original rejection is charged at
/// its actual byte size. Configuration leaves room for both full tool frames,
/// so repair cannot start a side effect with no remaining reply capacity.
#[derive(Clone, Copy, Debug)]
pub struct ToolHeaderRepairLimits {
    core: ManagedCoreLimits,
    catalog_bytes: usize,
    catalog_pages: usize,
    catalog_tools: usize,
}

impl Default for ToolHeaderRepairLimits {
    fn default() -> Self {
        Self { core: ManagedCoreLimits::default(), catalog_bytes: 4 * 1024 * 1024,
            catalog_pages: 16, catalog_tools: 1024 }
    }
}

impl ToolHeaderRepairLimits {
    pub fn new(core: ManagedCoreLimits, catalog_bytes: usize, catalog_pages: usize, catalog_tools: usize)
        -> Result<Self, ToolHeaderRepairError>
    {
        if !(1..=32 * 1024 * 1024).contains(&catalog_bytes)
            || !(1..=MAX_REPAIR_PAGES).contains(&catalog_pages)
            || !(1..=MAX_REPAIR_TOOLS).contains(&catalog_tools)
            || core.frame_bytes.checked_mul(2).and_then(|n| n.checked_add(catalog_bytes))
                .is_none_or(|n| n > core.total_bytes)
        {
            return Err(ToolHeaderRepairError::InvalidLimits);
        }
        Ok(Self { core, catalog_bytes, catalog_pages, catalog_tools })
    }

    fn catalog(self) -> Result<ManagedCatalogLimits, ManagedCatalogError> {
        let mut core = self.core;
        core.frame_bytes = core.frame_bytes.min(self.catalog_bytes);
        core.total_bytes = self.catalog_bytes;
        // Refresh has no observer side effects and accepts no notifications.
        // Observed catalog mutation therefore refuses the whole replacement.
        core.notifications = 0;
        ManagedCatalogLimits::new(core, self.catalog_pages, self.catalog_tools, MAX_REPAIR_ID_BYTES)
    }

    fn retry_charge(self, rejected_bytes: usize) -> Result<usize, ManagedCoreError> {
        let charged = rejected_bytes.checked_add(self.catalog_bytes)
            .ok_or(ManagedCoreError::ResponseByteLimit)?;
        if self.core.frame_bytes > self.core.total_bytes.saturating_sub(charged) {
            return Err(ManagedCoreError::ResponseByteLimit);
        }
        Ok(charged)
    }
}

/// Fixed diagnostics contain no peer error messages, names, schemas or values.
#[derive(Debug)]
pub enum ToolHeaderRepairError {
    InvalidContract,
    EndpointMismatch,
    InvalidLimits,
    InitialToolCallRequired,
    ToolUnavailable,
    DuplicateTool,
    DefinitionDeclined,
    Headers(ToolHeaderDispatchError),
    Catalog(ManagedCatalogError),
    Core(ManagedCoreError),
}

impl fmt::Display for ToolHeaderRepairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidContract => "invalid configured tool-header repair contract",
            Self::EndpointMismatch => "tool-header repair contract names another endpoint",
            Self::InvalidLimits => "invalid tool-header repair limits",
            Self::InitialToolCallRequired => "header repair requires an initial modern tool call",
            Self::ToolUnavailable => "refreshed catalog no longer contains the requested tool",
            Self::DuplicateTool => "refreshed catalog contains duplicate tool names",
            Self::DefinitionDeclined => "host declined the refreshed tool definition",
            Self::Headers(error) => return error.fmt(f),
            Self::Catalog(error) => return error.fmt(f),
            Self::Core(error) => return error.fmt(f),
        })
    }
}

impl std::error::Error for ToolHeaderRepairError {}
impl From<ManagedCoreError> for ToolHeaderRepairError {
    fn from(error: ManagedCoreError) -> Self { Self::Core(error) }
}
impl From<ManagedCatalogError> for ToolHeaderRepairError {
    fn from(error: ManagedCatalogError) -> Self { Self::Catalog(error) }
}
impl From<ToolHeaderDispatchError> for ToolHeaderRepairError {
    fn from(error: ToolHeaderDispatchError) -> Self { Self::Headers(error) }
}
impl From<ManagedToolHeaderError> for ToolHeaderRepairError {
    fn from(error: ManagedToolHeaderError) -> Self {
        match error { ManagedToolHeaderError::Headers(error) => Self::Headers(error),
            ManagedToolHeaderError::Core(error) => Self::Core(error) }
    }
}

/// Success owns the ordinary incremental core call. Only `Rejected` permits
/// the separate, explicit refresh action; dropping it sends nothing further.
#[must_use = "drive the call or explicitly decide whether to repair its rejection"]
pub enum ToolHeaderRepairOutcome {
    Call(ManagedCoreCall),
    Rejected(RejectedToolHeaders),
}

/// Unforgeable, non-Clone custody of one actual pre-dispatch rejection.
/// No response bytes or error message are retained. The host cannot replace
/// the invocation, resource, login, cancellation domain or original deadline.
pub struct RejectedToolHeaders {
    session: ManagedOAuthSession,
    original: CoreRequest,
    tool_name: String,
    cancellation: McpRequestCancellation,
    deadline: Time,
    limits: ToolHeaderRepairLimits,
    ids: IdLedger,
    rejected_bytes: usize,
}

impl fmt::Debug for RejectedToolHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RejectedToolHeaders").field("rejected_bytes", &self.rejected_bytes)
            .finish_non_exhaustive()
    }
}

impl ManagedOAuthSession {
    /// Attempts one initial tool call under an explicitly trusted rejection contract.
    /// This is the core header API: projection does not apply whole-instance
    /// input validation, so annotated nulls remain body data with no mirror.
    /// It does not replace or silently refresh a schema-bound `ManagedToolClient`.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_tool_with_header_repair(
        &self, cx: &Cx, request: CoreRequest, request_id: RequestId,
        reviewed: &ReviewedToolHeaders, contract: ToolHeaderRepairContract,
        limits: ToolHeaderRepairLimits,
    ) -> Result<ToolHeaderRepairOutcome, ToolHeaderRepairError> {
        Box::pin(self.request_tool_with_header_repair_and_cancellation(
            cx, &McpRequestCancellation::new(), request, request_id, reviewed, contract, limits,
        )).await
    }

    /// No HTTP/network/authorization failure triggers a refresh. Only a full
    /// correlated HTTP 400 JSON -32020 response yields single-use repair custody.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_tool_with_header_repair_and_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        request: CoreRequest, request_id: RequestId, reviewed: &ReviewedToolHeaders,
        contract: ToolHeaderRepairContract, limits: ToolHeaderRepairLimits,
    ) -> Result<ToolHeaderRepairOutcome, ToolHeaderRepairError> {
        let deadline = call_deadline(cx, cancellation, limits.core.timeout)?;
        contract.admit_endpoint(self.resource())?;
        admit_initial(&request)?;
        let mut ids = IdLedger::default();
        ids.reserve(&request_id)?;
        let (wire, decoder) = prepare_optional(self.resource().as_str(), request.clone(),
            request_id.clone(), limits.core, Some(reviewed))?;
        let response = Box::pin(bounded_wait(cx, cancellation, deadline, async {
            self.execute_with_cancellation(cx, cancellation, &wire).await.map_err(ManagedCoreError::from)
        })).await?;
        if response.metadata().status() == 200 {
            return Ok(ToolHeaderRepairOutcome::Call(ManagedCoreCall::from_response(
                response, decoder, cancellation.clone(), deadline,
            )?));
        }
        admit_rejection_head(response.metadata().status(), response.metadata().error_body_admission())?;
        let frame = Box::pin(bounded_wait(cx, cancellation, deadline, async {
            response.read_to_end(cx, limits.core.frame_bytes).await.map_err(ManagedCoreError::from)
        })).await?;
        admit_rejection_body(&frame, &request_id, limits.core.frame_bytes)?;
        check_call(cx, cancellation, deadline)?;
        Ok(ToolHeaderRepairOutcome::Rejected(RejectedToolHeaders {
            session: self.clone(), original: request, tool_name: reviewed.tool_name().to_owned(),
            cancellation: cancellation.clone(), deadline, limits, ids, rejected_bytes: frame.len(),
        }))
    }
}

impl RejectedToolHeaders {
    /// Refreshes the entire uncached tools catalog and explicitly retries once.
    /// `approve` must authorize the changed definition, including the same
    /// original arguments' use with it. `review` separately approves every new
    /// header binding. Even an unannotated replacement needs definition approval.
    /// Both callbacks are synchronous host code and must cooperate.
    ///
    /// The ID supplier covers every catalog page and the one retry. IDs cannot
    /// alias the rejected request or any earlier page. All invocation parameters
    /// are retained exactly; only its RPC ID and reviewed mirrors change.
    /// A second rejection, interrupted retry, callback error, cancellation, or
    /// dropped future is terminal. No further repair owner is returned.
    ///
    /// Returns the ordinary core call, including incremental notifications and
    /// typed input-required results. It grants no automatic continuation/replay
    /// permission and does not mutate or resurrect previously invalidated tools.
    pub async fn refresh_and_retry<I, A, R>(
        mut self, cx: &Cx, mut next_id: I, approve: A, mut review: R,
    ) -> Result<ManagedCoreCall, ToolHeaderRepairError>
    where
        I: FnMut() -> Result<RequestId, ManagedCatalogError>,
        A: FnOnce(&FinalTool) -> bool,
        R: FnMut(&ParameterHeaderBinding) -> bool,
    {
        // A caller may narrow the original budget when authorizing repair.
        // Retain that narrower bound in the returned call, not only in this
        // method's temporary wait, so later reads cannot regain the old time.
        self.deadline = cx.budget().deadline.map_or(self.deadline, |parent| parent.min(self.deadline));
        check_call(cx, &self.cancellation, self.deadline)?;
        let charged = self.limits.retry_charge(self.rejected_bytes)?;
        let collector = ManagedCatalogClient::new(self.session.clone(), self.limits.catalog()?);
        // Catalog metadata is local, minimal and never copied from the rejected
        // invocation's private observation fields or extension advertisements.
        let list = CoreRequest::decode(ProtocolEra::Modern2026, "tools/list", Some(&json!({
            "_meta": FinalRequestMeta::new(ClientCapabilities::default()),
        }))).map_err(|_| ManagedCoreError::InvalidRequest)?;
        Box::pin(bounded_wait(cx, &self.cancellation, self.deadline, async {
            Ok(async {
                let catalog = Box::pin(collector.collect_with_cancellation(cx, &self.cancellation, list,
                    || { let id = next_id()?; self.ids.reserve(&id)?; Ok(id) },
                    |_| Err(ManagedCatalogError::AbortedByHost),
                )).await?;
                check_call(cx, &self.cancellation, self.deadline)?;
                let tool = select_tool(catalog.into_pages(), &self.tool_name, self.limits.catalog_tools)?;
                let reviewed = approve_replacement(cx, &self.cancellation, self.deadline,
                    self.session.resource(), &tool, approve, &mut review)?;
                check_call(cx, &self.cancellation, self.deadline)?;
                let id = next_id()?;
                self.ids.reserve(&id)?;
                check_call(cx, &self.cancellation, self.deadline)?;
                let (wire, mut decoder) = prepare_optional(self.session.resource().as_str(),
                    self.original, id, self.limits.core, Some(&reviewed))?;
                decoder.resume_usage(charged, 0)?;
                check_call(cx, &self.cancellation, self.deadline)?;
                let response = Box::pin(self.session.execute_with_cancellation(cx, &self.cancellation, &wire))
                    .await.map_err(ManagedCoreError::from)?;
                check_call(cx, &self.cancellation, self.deadline)?;
                // Intentionally NOT the repair entrypoint: a second 400 can
                // only fail. Returned reads retain the original absolute bound.
                ManagedCoreCall::from_response(response, decoder, self.cancellation.clone(), self.deadline)
                    .map_err(ToolHeaderRepairError::from)
            }.await)
        })).await?
    }
}

fn admit_initial(request: &CoreRequest) -> Result<(), ToolHeaderRepairError> {
    match request {
        CoreRequest::Final(FinalCoreRequest::ToolsCall(params))
            if params.request_state.is_none() && params.input_responses.is_none() => Ok(()),
        _ => Err(ToolHeaderRepairError::InitialToolCallRequired),
    }
}

fn admit_rejection_head(status: u16, admission: Option<ModernHttpErrorBodyAdmission>)
    -> Result<(), ManagedCoreError>
{
    if status != 400 || admission != Some(ModernHttpErrorBodyAdmission::JsonRpcError) {
        return Err(ManagedCoreError::HttpStatus { status });
    }
    Ok(())
}

fn admit_rejection_body(frame: &[u8], id: &RequestId, maximum: usize) -> Result<(), ManagedCoreError> {
    let admitted = decode_strict_jsonrpc_response(frame, maximum)
        .map_err(|_| ManagedCoreError::InvalidResponse)?;
    let response = admitted.response();
    if !response.id.as_ref().is_some_and(|received| received.correlates_with(id)) {
        return Err(ManagedCoreError::ResponseIdMismatch);
    }
    let error = response.error.as_ref().ok_or(ManagedCoreError::InvalidResponse)?;
    if error.code != JsonInteger::from(HEADER_MISMATCH_ERROR_CODE) {
        return Err(ManagedCoreError::Remote { code: error.code.clone() });
    }
    Ok(())
}

fn select_tool(pages: Vec<CoreResult>, name: &str, maximum: usize) -> Result<FinalTool, ToolHeaderRepairError> {
    let mut names = HashSet::new();
    let mut selected = None;
    for page in pages {
        let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = page else {
            return Err(ManagedCatalogError::InvalidPage.into());
        };
        for tool in result.payload.tools {
            if names.len() >= maximum { return Err(ManagedCatalogError::ItemLimit.into()); }
            if !names.insert(tool.name.clone()) { return Err(ToolHeaderRepairError::DuplicateTool); }
            if tool.name == name { selected = Some(tool); }
        }
    }
    selected.ok_or(ToolHeaderRepairError::ToolUnavailable)
}

#[allow(clippy::too_many_arguments)]
fn approve_replacement<A, R>(
    cx: &Cx, cancellation: &McpRequestCancellation, deadline: Time,
    resource: &CanonicalHttpUrl, tool: &FinalTool, approve: A, review: &mut R,
) -> Result<ReviewedToolHeaders, ToolHeaderRepairError>
where
    A: FnOnce(&FinalTool) -> bool,
    R: FnMut(&ParameterHeaderBinding) -> bool,
{
    check_call(cx, cancellation, deadline)?;
    let approved = approve(tool);
    check_call(cx, cancellation, deadline)?;
    if !approved { return Err(ToolHeaderRepairError::DefinitionDeclined); }
    let reviewed = ReviewedToolHeaders::new(resource.clone(), tool.name.clone(), tool.input_schema.clone(), |binding| {
        if check_call(cx, cancellation, deadline).is_err() { return false; }
        let approved = review(binding);
        approved && check_call(cx, cancellation, deadline).is_ok()
    });
    // Cancellation/deadline errors take precedence over a callback's denial.
    check_call(cx, cancellation, deadline)?;
    reviewed.map_err(ToolHeaderRepairError::from)
}

#[derive(Default)]
struct IdLedger { ids: Vec<RequestId>, bytes: usize }

impl IdLedger {
    fn reserve(&mut self, id: &RequestId) -> Result<(), ManagedCatalogError> {
        id.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
        if self.ids.iter().any(|used| used.correlates_with(id)) {
            return Err(ManagedCatalogError::RepeatedRequestId);
        }
        if self.ids.len() >= MAX_REPAIR_PAGES + 2 { return Err(ManagedCatalogError::StateLimit); }
        let mut counter = IdBytes(self.bytes);
        serde_json::to_writer(&mut counter, id).map_err(|_| ManagedCatalogError::StateLimit)?;
        self.ids.push(id.clone());
        self.bytes = counter.0;
        Ok(())
    }
}

struct IdBytes(usize);
impl Write for IdBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_REPAIR_ID_BYTES.saturating_sub(self.0) {
            return Err(io::Error::other("tool-header repair ID budget"));
        }
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[cfg(test)]
mod tests;
