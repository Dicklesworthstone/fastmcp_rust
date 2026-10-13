//! Bounded overlap of host-approved sampling tools, without spawning tasks.
//!
//! Installing this executor is an explicit host policy decision: a model's
//! batch is not evidence that its tools are independent or safe to overlap.
//! Approval still covers the complete admitted batch before any execution.
//! On failure, pending siblings are dropped and queued callbacks never start.
//! Effects already committed by a sibling cannot be rolled back or retried.

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::task::Poll;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{AdmittedSchema, common_types::SamplingContentBlock};

use super::{
    SamplingHostFuture, SamplingRunError, SamplingStage, SamplingToolLoopError, check, cooperate,
    encoded_size, validate_output, within,
};

/// A shared host boundary for independently executable tools. Implementations
/// must recheck revocable authority at their own effect boundary, honor the
/// supplied caller/cancellation domain, and retire pending work on drop.
/// Blocking calls and detached tasks defeat these guarantees and are forbidden
/// by this contract. Concurrent polling does not make blocking work parallel.
pub trait ParallelSamplingToolExecutor: Send + Sync {
    /// Execute one approved call. The result must retain its exact toolUseId;
    /// this factory is invoked only when a concurrency slot is first polled.
    fn execute_tool<'a>(
        &'a self,
        cx: &'a Cx,
        cancellation: &'a McpRequestCancellation,
        call: &'a SamplingContentBlock,
    ) -> SamplingHostFuture<'a, SamplingContentBlock>;
}

/// A borrowed, explicitly bounded executor selected by `SamplingHost::parallel_tools`.
/// Model access and whole-batch approval remain owned by that SamplingHost.
/// No tool future or host callback is constructed by this configuration value.
pub struct ParallelSamplingTools<'a> {
    executor: &'a dyn ParallelSamplingToolExecutor,
    maximum_in_flight: usize,
}

impl<'a> ParallelSamplingTools<'a> {
    /// Allows 1..=64 in-flight tools per batch. One preserves sequential effect
    /// admission; larger limits are appropriate only for independent tools.
    /// The run's existing cumulative tool-call, result-byte and time limits
    /// still apply, and are never multiplied by the concurrency limit.
    pub fn new(
        executor: &'a dyn ParallelSamplingToolExecutor,
        maximum_in_flight: usize,
    ) -> Result<Self, SamplingRunError> {
        if !(1..=64).contains(&maximum_in_flight) {
            return Err(SamplingRunError::InvalidLimits);
        }
        Ok(Self {
            executor,
            maximum_in_flight,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute(
        self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Time,
        calls: &[SamplingContentBlock],
        outputs: &BTreeMap<String, AdmittedSchema>,
        maximum_bytes: usize,
        consumed_bytes: &mut usize,
    ) -> Result<Vec<SamplingContentBlock>, SamplingRunError> {
        check(cx, cancellation, deadline)?;
        let width = self.maximum_in_flight.min(calls.len());
        let mut slots: Vec<_> = calls
            .iter()
            .take(width)
            .enumerate()
            .map(|(index, call)| {
                Some((index, deferred_call(self.executor, cx, cancellation, call)))
            })
            .collect();
        let mut results: Vec<Option<SamplingContentBlock>> =
            (0..calls.len()).map(|_| None).collect();
        let mut next = width;
        let mut completed = 0;

        // No callback is invoked until the caller has crossed a cooperative
        // boundary and the guarded batch is polled with its own Cx installed.
        cooperate(cx, cancellation, deadline).await?;
        within(
            cx,
            cancellation,
            deadline,
            poll_fn(|task| {
                for slot in &mut slots {
                    let Some((index, future)) = slot.as_mut() else {
                        continue;
                    };
                    check(cx, cancellation, deadline)?;
                    let polled = std::future::Future::poll(future.as_mut(), task);
                    check(cx, cancellation, deadline)?;
                    let Poll::Ready(result) = polled else {
                        continue;
                    };
                    let index = *index;
                    // Retire the completed future before admitting any refill.
                    *slot = None;
                    check(cx, cancellation, deadline)?;
                    let result = result.map_err(|reason| SamplingRunError::Host {
                        stage: SamplingStage::Tool,
                        reason,
                    })?;
                    let remaining = maximum_bytes
                        .checked_sub(*consumed_bytes)
                        .ok_or(SamplingRunError::ToolResultByteLimit)?;
                    let bytes = encoded_size(&result, remaining)?;
                    validate_output(&calls[index], &result, outputs)?;
                    *consumed_bytes += bytes;
                    results[index] = Some(result);
                    completed += 1;
                }
                if completed == calls.len() {
                    let ordered = std::mem::take(&mut results)
                        .into_iter()
                        .collect::<Option<Vec<_>>>()
                        .ok_or(SamplingToolLoopError::WrongPhase)?;
                    return Poll::Ready(Ok(ordered));
                }

                // Scan ALL currently active slots for errors before filling
                // vacancies. A fast success cannot start new effects while an
                // already-ready sibling failure is waiting in a later slot.
                let mut refilled = false;
                for slot in &mut slots {
                    if next == calls.len() {
                        break;
                    }
                    if slot.is_none() {
                        *slot = Some((
                            next,
                            deferred_call(self.executor, cx, cancellation, &calls[next]),
                        ));
                        next += 1;
                        refilled = true;
                    }
                }
                if refilled {
                    // New futures have not registered a waker yet. Yield before
                    // polling them, bounding one turn even for all-ready hosts.
                    task.waker().wake_by_ref();
                }
                Poll::Pending
            }),
        )
        .await
    }
}

// Defer even the host's future factory: constructing a queued slot must never
// execute host code before its own cancellation/deadline admission checkpoint.
fn deferred_call<'a>(
    executor: &'a dyn ParallelSamplingToolExecutor,
    cx: &'a Cx,
    cancellation: &'a McpRequestCancellation,
    call: &'a SamplingContentBlock,
) -> SamplingHostFuture<'a, SamplingContentBlock> {
    Box::pin(async move { executor.execute_tool(cx, cancellation, call).await })
}

#[cfg(test)]
mod tests;
