//! Host-driven input workflows without leaving the original tool contract.
//!
//! The core driver owns challenge admission, answer correlation, immutable
//! arguments and reviewed headers, deadlines, and cumulative round/input/byte
//! budgets. This adapter adds contract checks around host callbacks and final
//! publication; it does not implement a second continuation state machine.

use std::future::Future;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{CoreResult, InputRequiredResult, ServerNotification};

use super::{ManagedInteractionError, ManagedToolInteraction, ManagedToolInteractionError};
use super::super::{ManagedToolError, ToolContract, await_validity, check_tool_call};
use crate::http_auth::rpc::interaction::ManagedInputReply;

impl ManagedToolInteraction {
    /// Resolves every admitted input challenge through explicit host callbacks.
    /// The resolver returns a fresh request ID and a complete, typed answer map,
    /// or absence for a state-only round. No default model, roots, browser, or
    /// approval policy is supplied. Notifications remain incremental.
    ///
    /// The core operation retains its original deadline and cumulative limits,
    /// including time spent in the resolver. Tool/catalog invalidation wakes a
    /// pending resolver or transport wait, prevents later callback entry, and
    /// withholds a concurrently ready result. Successful structured output must
    /// satisfy the same schema admitted before the initial request.
    ///
    /// Consumes this interaction. Callback errors, invalid answers, transport
    /// loss, cancellation, and dropping this future are terminal; none trigger
    /// another resolver call or a replay. Use manual resume/recovery custody to
    /// retain their explicit correction/recovery choices. Already-completed host
    /// or server effects cannot be undone. Host callbacks must cooperate and
    /// their returned futures must be cancellation-correct when dropped.
    ///
    /// An already-observed pending challenge can be handed to this method. An
    /// already-delivered terminal result is never delivered a second time.
    pub async fn drive<R, F, N>(
        self,
        cx: &Cx,
        resolve: R,
        notify: N,
    ) -> Result<Box<CoreResult>, ManagedToolInteractionError>
    where
        R: FnMut(Box<InputRequiredResult>) -> F,
        F: Future<Output = Result<ManagedInputReply, ManagedInteractionError>>,
        N: FnMut(Box<ServerNotification>) -> Result<(), ManagedInteractionError>,
    {
        Box::pin(self.drive_selected(cx, resolve, notify, false)).await
    }

    /// Like `drive`, but explicitly permits a nonempty proper subset of answers
    /// when the server supplies nonempty continuation state. Unanswered inputs
    /// receive no fabricated response and no implicit host action. Only the new
    /// challenge is presented on the next round; original arguments, approved
    /// headers, and all operation-wide budgets remain unchanged.
    pub async fn drive_partial<R, F, N>(
        self,
        cx: &Cx,
        resolve: R,
        notify: N,
    ) -> Result<Box<CoreResult>, ManagedToolInteractionError>
    where
        R: FnMut(Box<InputRequiredResult>) -> F,
        F: Future<Output = Result<ManagedInputReply, ManagedInteractionError>>,
        N: FnMut(Box<ServerNotification>) -> Result<(), ManagedInteractionError>,
    {
        Box::pin(self.drive_selected(cx, resolve, notify, true)).await
    }

    async fn drive_selected<R, F, N>(
        mut self,
        cx: &Cx,
        mut resolve: R,
        mut notify: N,
        partial: bool,
    ) -> Result<Box<CoreResult>, ManagedToolInteractionError>
    where
        R: FnMut(Box<InputRequiredResult>) -> F,
        F: Future<Output = Result<ManagedInputReply, ManagedInteractionError>>,
        N: FnMut(Box<ServerNotification>) -> Result<(), ManagedInteractionError>,
    {
        check_tool_call(cx, &self.cancellation, &self.contract)?;
        if self.finished { return Err(ManagedToolError::Closed.into()); }
        let operation = self.operation.take().ok_or(ManagedToolError::Closed)?;
        let contract = self.contract.as_ref();
        let cancellation = &self.cancellation;
        let guarded_resolve = |input| {
            // Guard construction, not only polling: FnMut may itself perform
            // host effects before returning its future. The core driver calls
            // this inside its original deadline/cancellation guard.
            let future = begin_resolution(cx, cancellation, contract, &mut resolve, input);
            finish_resolution(cx, cancellation, contract, future)
        };
        let guarded_notify = |notification| {
            deliver_notification(cx, cancellation, contract, &mut notify, notification)
        };
        let result = Box::pin(await_validity(cx, cancellation, contract, async {
            if partial {
                operation.drive_partial(cx, guarded_resolve, guarded_notify).await
            } else {
                operation.drive(cx, guarded_resolve, guarded_notify).await
            }
        })).await?;
        check_tool_call(cx, cancellation, contract)?;
        let result = result?;
        contract.validate_result(&result)?;
        check_tool_call(cx, cancellation, contract)?;
        Ok(result)
    }
}

fn begin_resolution<R, F>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    contract: &ToolContract,
    resolve: &mut R,
    input: Box<InputRequiredResult>,
) -> Result<F, ManagedToolError>
where
    R: FnMut(Box<InputRequiredResult>) -> F,
{
    check_tool_call(cx, cancellation, contract)?;
    Ok(resolve(input))
}

async fn finish_resolution<F>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    contract: &ToolContract,
    future: Result<F, ManagedToolError>,
) -> Result<ManagedInputReply, ManagedInteractionError>
where
    F: Future<Output = Result<ManagedInputReply, ManagedInteractionError>>,
{
    let future = future.map_err(|_| ManagedInteractionError::AbortedByHost)?;
    // An outer poll fence alone is insufficient: the core driver can resolve
    // input and start a continuation in the same poll. Refuse an answer here
    // before the core driver can consume it. The outer fence preserves the
    // actual Invalidated/Cancelled error instead of this internal stop signal.
    await_validity(cx, cancellation, contract, future).await
        .map_err(|_| ManagedInteractionError::AbortedByHost)?
}

fn deliver_notification<N>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    contract: &ToolContract,
    notify: &mut N,
    notification: Box<ServerNotification>,
) -> Result<(), ManagedInteractionError>
where
    N: FnMut(Box<ServerNotification>) -> Result<(), ManagedInteractionError>,
{
    check_tool_call(cx, cancellation, contract).map_err(|_| ManagedInteractionError::AbortedByHost)?;
    let outcome = notify(notification);
    check_tool_call(cx, cancellation, contract).map_err(|_| ManagedInteractionError::AbortedByHost)?;
    outcome
}

#[cfg(test)]
mod tests;
