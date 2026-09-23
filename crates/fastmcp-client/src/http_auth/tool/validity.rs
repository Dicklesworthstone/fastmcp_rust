//! A caller-polled lifetime fence for schema-bound work, not a second runtime.
//!
//! Register invalidation before polling the owned operation, then recheck after
//! every poll. This closes the pending-renewal/read/resume window without
//! retrying a request, extending a deadline or cancelling the shared login.
//! Already-dispatched side effects cannot be recalled. Dropping a renewal that
//! may have consumed its refresh token retains the session's existing refusal
//! to reuse that uncertain lineage.

use std::future::{Future, poll_fn};
use std::task::Poll;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;

use super::{ManagedCoreError, ManagedToolError, ToolContract, check_tool_call};

// T deliberately includes the inner Result. Interaction-local answer refusals
// must retain their original type and challenge; invalidation is terminal and
// must not enter that correctable-input branch or restore the owned operation.
pub(super) async fn await_validity<T>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    contract: &ToolContract,
    future: impl Future<Output = T>,
) -> Result<T, ManagedToolError> {
    let mut invalidated = std::pin::pin!(contract.invalidation.cancelled());
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    let mut future = std::pin::pin!(future);
    poll_fn(|task| {
        check_tool_call(cx, cancellation, contract)?;
        if invalidated.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(ManagedToolError::Invalidated));
        }
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(ManagedCoreError::Cancelled.into()));
        }
        let outcome = future.as_mut().poll(task);
        // Refuse even a simultaneously ready result. Owned response state is
        // dropped on this error; partially read work cannot become reusable.
        check_tool_call(cx, cancellation, contract)?;
        outcome.map(Ok)
    }).await
}

#[cfg(test)]
mod tests;
