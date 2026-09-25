//! Schema-bound use of the explicitly configured one-shot header-repair path.
//!
//! The core repair owner proves only its configured pre-dispatch rejection,
//! preserves the invocation, collects the catalog, reviews disclosure and sends
//! at most one retry. This adapter admits the replacement input/output contract
//! before host approval, validates the unchanged invocation against it, and
//! validates successful output before publication. It never changes the original
//! client, revives a retired catalog, or manufactures another repair attempt.
//!
//! The original tool's validity remains necessary throughout, including while
//! refreshing and reading a repaired result. A schema change accepted here is
//! private to this call, not an update to an old catalog snapshot or its handles.

use std::fmt;
use std::sync::Arc;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::http_headers::ParameterHeaderBinding;
use fastmcp_protocol::{CoreRequest, FinalTool, RequestId};

use super::super::{
    ManagedToolCall, ManagedToolClient, ManagedToolError, ToolContract,
    await_validity, check_tool_call,
};
use crate::http_auth::rpc::{ManagedCoreCall, ManagedCoreEvent};
use crate::http_auth::rpc::catalog::ManagedCatalogError;
use super::super::interaction::ManagedToolInteraction;
use crate::http_auth::rpc::tool_headers::repair::{
    RejectedToolHeaders, RepairedToolCall, ToolHeaderRepairContract, ToolHeaderRepairError,
    ToolHeaderRepairLimits, ToolHeaderRepairOutcome,
};

/// Fixed diagnostics do not retain schema, argument or peer-response content.
#[derive(Debug)]
pub enum ManagedToolRepairError {
    HeaderReviewRequired,
    Tool(ManagedToolError),
    Repair(ToolHeaderRepairError),
}

impl fmt::Display for ManagedToolRepairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderReviewRequired => f.write_str("schema-bound header repair requires an installed disclosure review"),
            Self::Tool(error) => fmt::Display::fmt(error, f),
            Self::Repair(error) => fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for ManagedToolRepairError {}
impl From<ManagedToolError> for ManagedToolRepairError {
    fn from(error: ManagedToolError) -> Self { Self::Tool(error) }
}
impl From<ToolHeaderRepairError> for ManagedToolRepairError {
    fn from(error: ToolHeaderRepairError) -> Self { Self::Repair(error) }
}

/// Only an admitted rejection permits the separate, consuming refresh action.
#[must_use = "drive the checked call or explicitly decide whether to repair its rejection"]
pub enum ManagedToolHeaderRepairOutcome {
    Call(ManagedToolRepairCall),
    Rejected(RejectedManagedToolHeaders),
}

/// Single-use repair custody with the original schema-bound validity owner.
/// Dropping this value performs no refresh, retry or shared-session cancellation.
pub struct RejectedManagedToolHeaders {
    rejected: RejectedToolHeaders,
    original: CoreRequest,
    contract: Arc<ToolContract>,
    cancellation: McpRequestCancellation,
}

impl fmt::Debug for RejectedManagedToolHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RejectedManagedToolHeaders")
            .field("invalidated", &self.contract.is_invalidated()).finish_non_exhaustive()
    }
}

/// Incremental output checked against the approved replacement (or initial)
/// schema. The original client/catalog validity remains a separate requirement.
/// Neither the unchecked core call nor a replacement reusable client is exposed.
pub struct ManagedToolRepairCall {
    call: ManagedToolCall,
    source: Arc<ToolContract>,
}

impl ManagedToolRepairCall {
    pub fn close(&mut self) { self.call.close(); }

    /// Invalidation wakes a pending read and refuses even a simultaneously ready
    /// result. A failed or abandoned read closes the owned call, not the login.
    /// An input-required result is returned intact, never automatically resumed.
    pub async fn next_event(&mut self, cx: &Cx) -> Result<Option<ManagedCoreEvent>, ManagedToolError> {
        if self.call.finished { return Ok(None); }
        let cancellation = self.call.cancellation.clone();
        let outcome = Box::pin(await_validity(cx, &cancellation, &self.source,
            self.call.next_event(cx),
        )).await;
        match outcome {
            Ok(result) => result,
            Err(error) => {
                self.call.close();
                // The inner call may have completed in the same poll that
                // invalidated the source. Its result was not published here.
                self.call.finished = false;
                Err(error)
            }
        }
    }
}

impl ManagedToolClient {
    /// Attempts one schema-checked initial call with explicit header-repair
    /// eligibility. The installed header review and original input schema are
    /// checked before any credential acquisition or POST. Ordinary `request`
    /// and interaction APIs do not gain retries by using this module.
    ///
    /// The endpoint contract is independently trusted deployment configuration;
    /// authenticated TLS or a peer error code alone cannot prove non-execution.
    /// This opt-in schema-bound API intentionally validates complete arguments.
    /// Use the core header API for transport-only null-omission semantics.
    pub async fn request_with_header_repair(
        &self, cx: &Cx, request: CoreRequest, request_id: RequestId,
        endpoint: ToolHeaderRepairContract, limits: ToolHeaderRepairLimits,
    ) -> Result<ManagedToolHeaderRepairOutcome, ManagedToolRepairError> {
        Box::pin(self.request_with_header_repair_and_cancellation(cx,
            &McpRequestCancellation::new(), request, request_id, endpoint, limits,
        )).await
    }

    /// Request-local cancellation and tool/catalog invalidation both fence the
    /// initial exchange and its later repair custody. No caller or sibling is
    /// cancelled. Abandoning credential renewal retains the managed session's
    /// existing fail-closed treatment of an uncertain refresh-token lineage.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_with_header_repair_and_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        request: CoreRequest, request_id: RequestId,
        endpoint: ToolHeaderRepairContract, limits: ToolHeaderRepairLimits,
    ) -> Result<ManagedToolHeaderRepairOutcome, ManagedToolRepairError> {
        check_tool_call(cx, cancellation, &self.contract)?;
        let reviewed = self.header_review.as_deref().ok_or(ManagedToolRepairError::HeaderReviewRequired)?;
        self.contract.validate_request(&request)?;
        self.contract.admit_headers(self.session.resource(), reviewed)?;
        check_tool_call(cx, cancellation, &self.contract)?;
        let original = request.clone();
        let outcome = Box::pin(await_validity(cx, cancellation, &self.contract,
            self.session.request_tool_with_header_repair_and_cancellation(cx, cancellation,
                request, request_id, reviewed, endpoint, limits,
            ),
        )).await??;
        check_tool_call(cx, cancellation, &self.contract)?;
        Ok(match outcome {
            ToolHeaderRepairOutcome::Call(call) => ManagedToolHeaderRepairOutcome::Call(bind_call(
                call, Arc::clone(&self.contract), Arc::clone(&self.contract), cancellation.clone(),
            )),
            ToolHeaderRepairOutcome::Rejected(rejected) => ManagedToolHeaderRepairOutcome::Rejected(
                RejectedManagedToolHeaders { rejected, original,
                    contract: Arc::clone(&self.contract), cancellation: cancellation.clone() },
            ),
        })
    }
}

impl RejectedManagedToolHeaders {
    /// Collects and approves a complete replacement, then retries the unchanged
    /// invocation once. The new input/output schemas must be admitted and the
    /// original arguments must satisfy the new input schema before `approve`
    /// runs. Returning true authorizes that new definition for this call only.
    /// `review` separately approves each newly projected header binding.
    ///
    /// Every callback is guarded before and after entry. Invalidation inside a
    /// ready callback prevents subsequent host callbacks and the retry POST in
    /// that same poll. Pending refresh, dispatch and output reads also wake on
    /// invalidation. Failure, cancellation or dropping this future is terminal.
    ///
    /// The core owner retains one ID ledger, the original/narrowed deadline and
    /// cumulative byte accounting. A second rejection never creates another
    /// repair owner. Old clients remain unchanged and are never reactivated.
    pub async fn refresh_and_retry<I, A, R>(
        self, cx: &Cx, next_id: I, approve: A, review: R,
    ) -> Result<ManagedToolRepairCall, ManagedToolRepairError>
    where
        I: FnMut() -> Result<RequestId, ManagedCatalogError>,
        A: FnOnce(&FinalTool) -> bool,
        R: FnMut(&ParameterHeaderBinding) -> bool,
    {
        let bound = Box::pin(self.refresh_bound(cx, next_id, approve, review)).await?;
        Ok(bind_call(bound.call.into_call(), bound.contract, bound.source, bound.cancellation))
    }

    /// Repairs once and retains the actual retry response as a schema-bound
    /// interaction. Its first event is still unread; making it resumable sends
    /// no additional request. Use the ordinary next_event/resume/drive APIs.
    ///
    /// The approved replacement schemas and header review govern every later
    /// round. Original tool/catalog invalidation remains effective during host
    /// callbacks, pending reads and explicit continuation recovery, even after
    /// the original client handle is dropped. This does not revive that client.
    ///
    /// Only continuation and answer counts are newly configured. Original
    /// request IDs, cancellation, deadline and charged bytes cannot be reset.
    #[allow(clippy::too_many_arguments)]
    pub async fn refresh_and_start_interaction<I, A, R>(
        self, cx: &Cx, maximum_continuations: usize, maximum_input_responses: usize,
        next_id: I, approve: A, review: R,
    ) -> Result<ManagedToolInteraction, ManagedToolRepairError>
    where
        I: FnMut() -> Result<RequestId, ManagedCatalogError>,
        A: FnOnce(&FinalTool) -> bool,
        R: FnMut(&ParameterHeaderBinding) -> bool,
    {
        check_tool_call(cx, &self.cancellation, &self.contract)?;
        self.rejected.admit_interaction_limits(maximum_continuations, maximum_input_responses)?;
        let bound = Box::pin(self.refresh_bound(cx, next_id, approve, review)).await?;
        let operation = bound.call.into_interaction(cx, maximum_continuations, maximum_input_responses)?;
        Ok(ManagedToolInteraction::from_repaired_call(cx, operation, bound.contract, bound.cancellation)?)
    }

    async fn refresh_bound<I, A, R>(
        self, cx: &Cx, mut next_id: I, approve: A, mut review: R,
    ) -> Result<BoundRepairedCall, ManagedToolRepairError>
    where
        I: FnMut() -> Result<RequestId, ManagedCatalogError>,
        A: FnOnce(&FinalTool) -> bool,
        R: FnMut(&ParameterHeaderBinding) -> bool,
    {
        let Self { rejected, original, contract, cancellation } = self;
        check_tool_call(cx, &cancellation, &contract)?;
        let mut replacement = None;
        let mut admission_error = None;
        let guarded_approve = |definition: &FinalTool| {
            match approve_definition(cx, &cancellation, &contract, &original, definition, approve) {
                Ok(Some(admitted)) => { replacement = Some(admitted); true }
                Ok(None) => false,
                Err(error) => { admission_error = Some(error); false }
            }
        };
        let guarded_id = || supply_id(cx, &cancellation, &contract, &mut next_id);
        let guarded_review = |binding: &ParameterHeaderBinding| {
            review_binding(cx, &cancellation, &contract, &mut review, binding)
        };
        let outcome = Box::pin(await_validity(cx, &cancellation, &contract,
            rejected.refresh_owned(cx, guarded_id, guarded_approve, guarded_review),
        )).await?;
        check_tool_call(cx, &cancellation, &contract)?;
        // A core policy refusal is only the internal stop signal for failed
        // schema admission. Preserve the actual fixed validation error.
        if let Some(error) = admission_error { return Err(error.into()); }
        let call = outcome?;
        let replacement = replacement.ok_or(ManagedToolError::InvalidDefinition)?;
        let replacement = inherit_source(replacement, &contract)?;
        Ok(BoundRepairedCall { call, contract: replacement, source: contract, cancellation })
    }
}

struct BoundRepairedCall {
    call: RepairedToolCall,
    contract: Arc<ToolContract>,
    source: Arc<ToolContract>,
    cancellation: McpRequestCancellation,
}

fn inherit_source(mut replacement: Arc<ToolContract>, source: &Arc<ToolContract>)
    -> Result<Arc<ToolContract>, ManagedToolError>
{
    source.check()?;
    // Only a freshly admitted per-operation contract may inherit. This also
    // excludes self-cycles, shared mutation, and unbounded validity chains.
    let unique = Arc::get_mut(&mut replacement).ok_or(ManagedToolError::InvalidDefinition)?;
    if source.source_contract.is_some() || unique.source_contract.is_some() {
        return Err(ManagedToolError::InvalidDefinition);
    }
    unique.source_contract = Some(Arc::clone(source));
    unique.invalidation = source.invalidation.clone();
    replacement.check()?;
    Ok(replacement)
}

fn bind_call(
    call: ManagedCoreCall, contract: Arc<ToolContract>, source: Arc<ToolContract>,
    cancellation: McpRequestCancellation,
) -> ManagedToolRepairCall {
    ManagedToolRepairCall {
        call: ManagedToolCall { call: Some(call), contract, cancellation, finished: false }, source,
    }
}

fn approve_definition<A>(
    cx: &Cx, cancellation: &McpRequestCancellation, source: &ToolContract,
    original: &CoreRequest, definition: &FinalTool, approve: A,
) -> Result<Option<Arc<ToolContract>>, ManagedToolError>
where A: FnOnce(&FinalTool) -> bool,
{
    check_tool_call(cx, cancellation, source)?;
    let replacement = Arc::new(ToolContract::admit(definition.clone())?);
    replacement.validate_request(original)?;
    check_tool_call(cx, cancellation, source)?;
    let approved = approve(definition);
    check_tool_call(cx, cancellation, source)?;
    Ok(approved.then_some(replacement))
}

fn supply_id<I>(
    cx: &Cx, cancellation: &McpRequestCancellation, source: &ToolContract, next: &mut I,
) -> Result<RequestId, ManagedCatalogError>
where I: FnMut() -> Result<RequestId, ManagedCatalogError>,
{
    check_tool_call(cx, cancellation, source).map_err(|_| ManagedCatalogError::AbortedByHost)?;
    let id = next();
    check_tool_call(cx, cancellation, source).map_err(|_| ManagedCatalogError::AbortedByHost)?;
    id
}

fn review_binding<R>(
    cx: &Cx, cancellation: &McpRequestCancellation, source: &ToolContract,
    review: &mut R, binding: &ParameterHeaderBinding,
) -> bool
where R: FnMut(&ParameterHeaderBinding) -> bool,
{
    if check_tool_call(cx, cancellation, source).is_err() { return false; }
    let approved = review(binding);
    approved && check_tool_call(cx, cancellation, source).is_ok()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod interaction_contract_tests {
    use super::*;
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Waker};
    use serde_json::json;

    fn contract() -> Arc<ToolContract> {
        Arc::new(ToolContract::admit(serde_json::from_value(json!({
            "name":"lookup", "inputSchema":{"type":"object"}
        })).unwrap()).unwrap())
    }

    #[test]
    fn inherited_invalidation_wakes_waiters_and_retains_weak_catalog_targets() {
        let source = contract();
        let weak = Arc::downgrade(&source);
        let replacement = inherit_source(contract(), &source).unwrap();
        let mut wait = std::pin::pin!(replacement.invalidation.cancelled());
        let mut task = Context::from_waker(Waker::noop());
        assert!(wait.as_mut().poll(&mut task).is_pending());
        drop(source);
        let retained = weak.upgrade().expect("catalog's weak target must stay alive");
        retained.invalidate();
        assert!(wait.as_mut().poll(&mut task).is_ready());
        assert!(matches!(replacement.check(), Err(ManagedToolError::Invalidated)));
        assert!(replacement.is_invalidated());
    }

    #[test]
    fn inherited_checks_observe_catalog_and_same_poll_source_retirement() {
        let flag = Arc::new(AtomicBool::new(false));
        let mut source = contract();
        Arc::get_mut(&mut source).unwrap().catalog_invalidated = Some(Arc::clone(&flag));
        let replacement = inherit_source(contract(), &source).unwrap();
        flag.store(true, Ordering::Release);
        assert!(matches!(replacement.check(), Err(ManagedToolError::Invalidated)));
        let source = contract();
        let replacement = inherit_source(contract(), &source).unwrap();
        source.invalidated.store(true, Ordering::Release);
        assert!(matches!(replacement.check(), Err(ManagedToolError::Invalidated)));
    }

    #[test]
    fn inheritance_refuses_shared_replacements_cycles_chains_and_stale_sources() {
        let source = contract();
        assert!(matches!(inherit_source(Arc::clone(&source), &source), Err(ManagedToolError::InvalidDefinition)));
        let first = inherit_source(contract(), &source).unwrap();
        assert!(matches!(inherit_source(contract(), &first), Err(ManagedToolError::InvalidDefinition)));
        source.invalidate();
        assert!(matches!(inherit_source(contract(), &source), Err(ManagedToolError::Invalidated)));
        let independent = contract();
        independent.check().unwrap();
        assert!(!independent.invalidation.is_cancel_requested());
    }
}
