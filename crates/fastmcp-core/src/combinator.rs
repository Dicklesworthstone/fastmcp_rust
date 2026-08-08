//! Parallel combinator helpers for MCP handlers.
//!
//! This module provides combinators adapted for MCP's error model. They poll
//! caller-owned futures directly and do not spawn independent tasks.
//!
//! # Available Combinators
//!
//! | Function | Pattern | Description |
//! |----------|---------|-------------|
//! | [`join_all`] | N-of-N | Wait for all futures to complete |
//! | [`join_all_results`] | N-of-N | Wait for all, collect `McpResult<T>` |
//! | [`race`] | 1-of-N | Return first to complete |
//! | [`race_timeout`] | 1-of-N | Race with timeout |
//! | [`quorum`] | M-of-N | Wait for M successes out of N |
//! | [`quorum_timeout`] | M-of-N | Quorum with timeout |
//! | [`first_ok`] | 1-of-N | Return first successful result |
//!
//! # Cancellation behavior
//!
//! Losing futures are either retained until the documented completion
//! condition or dropped in the same combinator future. Callers remain
//! responsible for the cancellation behavior of work spawned elsewhere.
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_core::combinator::{join_all, race, quorum, first_ok};
//!
//! // Wait for all to complete
//! let results = join_all(ctx.cx(), vec![fut1, fut2, fut3]).await;
//!
//! // Return first to complete
//! let winner = race(ctx.cx(), vec![fut1, fut2, fut3]).await?;
//!
//! // Wait for 2 of 3 to succeed
//! let quorum_result = quorum(ctx.cx(), 2, vec![fut1, fut2, fut3]).await?;
//!
//! // Return first success (skip failures)
//! let result = first_ok(ctx.cx(), vec![try1, try2, try3]).await?;
//! ```

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use asupersync::time::{BudgetTimeExt, Sleep};
use asupersync::types::CancelReason;
use asupersync::{Cx, Outcome};

use crate::error::{McpError, McpErrorCode, McpOutcome, McpResult};

// ============================================================================
// Type Aliases
// ============================================================================

/// A boxed, pinned, sendable future for use with combinators.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The exact result branch selected by a dual-era request.
///
/// `Modern` carries the caller's final typed result, while `Legacy` carries
/// the exact legacy result representation. The variant is intentionally kept
/// until the request outcome is consumed; callers must not normalize one era
/// into the other at this boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DualEraFinalResult<TypedResult, LegacyResult> {
    /// A final result decoded under the modern protocol era.
    Modern(TypedResult),
    /// A final result retained under the legacy protocol era.
    Legacy(LegacyResult),
}

/// A final dual-era result bound to the terminal reason selected by its owner.
///
/// `TerminalReason` is intentionally generic so a transport or executor can
/// retain its own precise terminal classifier instead of translating it into a
/// core-owned approximation. Cancellation and panic remain the corresponding
/// four-valued [`McpOutcome`] variants and are never encoded as this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalRequestResult<TypedResult, LegacyResult, TerminalReason> {
    result: DualEraFinalResult<TypedResult, LegacyResult>,
    terminal_reason: TerminalReason,
}

impl<TypedResult, LegacyResult, TerminalReason>
    FinalRequestResult<TypedResult, LegacyResult, TerminalReason>
{
    /// Binds a modern typed final result to its exact terminal reason.
    #[must_use]
    pub const fn modern(terminal_reason: TerminalReason, result: TypedResult) -> Self {
        Self {
            result: DualEraFinalResult::Modern(result),
            terminal_reason,
        }
    }

    /// Binds a legacy final result to its exact terminal reason.
    #[must_use]
    pub const fn legacy(terminal_reason: TerminalReason, result: LegacyResult) -> Self {
        Self {
            result: DualEraFinalResult::Legacy(result),
            terminal_reason,
        }
    }

    /// Returns the retained dual-era result branch.
    #[must_use]
    pub const fn result(&self) -> &DualEraFinalResult<TypedResult, LegacyResult> {
        &self.result
    }

    /// Returns the caller-owned terminal reason without translating it.
    #[must_use]
    pub const fn terminal_reason(&self) -> &TerminalReason {
        &self.terminal_reason
    }

    /// Splits the result branch from its terminal reason without conversion.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        DualEraFinalResult<TypedResult, LegacyResult>,
        TerminalReason,
    ) {
        (self.result, self.terminal_reason)
    }
}

/// Adapts a completed dual-era final result into a four-valued MCP outcome.
///
/// The caller-owned [`Cx`] is observed without creating a runtime. A pending
/// cancellation wins over a newly completed final result and retains the
/// runtime's exact [`CancelReason`] when it is available. The companion
/// [`adapt_final_request_outcome`] preserves already-terminal cancellation,
/// error, and panic outcomes without replacing them from the context.
#[must_use]
pub fn final_result_outcome<TypedResult, LegacyResult, TerminalReason>(
    cx: &Cx,
    result: FinalRequestResult<TypedResult, LegacyResult, TerminalReason>,
) -> McpOutcome<FinalRequestResult<TypedResult, LegacyResult, TerminalReason>> {
    if cx.is_cancel_requested() {
        return Outcome::Cancelled(cx.cancel_reason().unwrap_or_else(|| {
            CancelReason::user("caller context cancelled without an attributed reason")
        }));
    }
    Outcome::Ok(result)
}

/// Preserves every terminal variant while admitting an otherwise-complete final result.
///
/// In particular, an existing [`Outcome::Cancelled`] retains its exact
/// [`CancelReason`] and an existing [`Outcome::Panicked`] retains its exact
/// panic payload, even when the caller context is also cancelled.
#[must_use]
pub fn adapt_final_request_outcome<TypedResult, LegacyResult, TerminalReason>(
    cx: &Cx,
    outcome: McpOutcome<FinalRequestResult<TypedResult, LegacyResult, TerminalReason>>,
) -> McpOutcome<FinalRequestResult<TypedResult, LegacyResult, TerminalReason>> {
    match outcome {
        Outcome::Ok(result) => final_result_outcome(cx, result),
        Outcome::Err(error) => Outcome::Err(error),
        Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
        Outcome::Panicked(payload) => Outcome::Panicked(payload),
    }
}

// ============================================================================
// Internal: poll a BoxFuture stored in an Option slot
// ============================================================================

/// Attempt to poll `slot`. If the future resolves, `slot` is set to `None`
/// and `Some(output)` is returned. Otherwise returns `None`.
fn poll_slot<T>(slot: &mut Option<BoxFuture<'_, T>>, cx: &mut Context<'_>) -> Option<T> {
    let fut = slot.as_mut()?;
    match fut.as_mut().poll(cx) {
        Poll::Ready(val) => {
            *slot = None; // drop the completed future
            Some(val)
        }
        Poll::Pending => None,
    }
}

/// Creates a native asupersync timer bounded by both the requested timeout and
/// the caller's remaining deadline budget.
fn timeout_sleep(cx: &Cx, requested: Duration) -> Sleep {
    let now = cx.now();
    let remaining = BudgetTimeExt::remaining_duration(&cx.budget(), now);
    let effective = if let Some(remaining) = remaining {
        requested.min(remaining)
    } else {
        requested
    };

    Sleep::after(now, effective)
}

// ============================================================================
// Join Combinator
// ============================================================================

/// Waits for all futures to complete and returns their results.
///
/// This is the N-of-N combinator: all futures must complete before
/// returning. Results are returned in the same order as input futures.
///
/// Futures are polled concurrently — each poll cycle round-robins
/// through all incomplete futures, ensuring fair progress.
///
/// # Cancellation behavior
///
/// This function awaits each supplied future to completion. A panic from a
/// supplied future unwinds normally; this function does not catch panics or
/// continue polling after an unwind.
///
/// # Example
///
/// ```ignore
/// let futures = vec![
///     Box::pin(fetch_user(1)),
///     Box::pin(fetch_user(2)),
///     Box::pin(fetch_user(3)),
/// ];
/// let users = join_all(ctx.cx(), futures).await;
/// ```
pub async fn join_all<T: Send + 'static>(_cx: &Cx, futures: Vec<BoxFuture<'_, T>>) -> Vec<T> {
    let len = futures.len();
    if len == 0 {
        return Vec::new();
    }
    // Single future: no concurrency overhead needed.
    if len == 1 {
        let mut futs = futures;
        return vec![futs.remove(0).await];
    }
    let mut state = JoinAllState {
        futures: futures.into_iter().map(Some).collect(),
        results: (0..len).map(|_| None).collect(),
        remaining: len,
    };
    // Use std::future::poll_fn for safe self-referential polling.
    std::future::poll_fn(move |cx| state.poll(cx)).await
}

/// Internal state for join_all concurrent polling.
struct JoinAllState<'a, T> {
    futures: Vec<Option<BoxFuture<'a, T>>>,
    results: Vec<Option<T>>,
    remaining: usize,
}

impl<T> JoinAllState<'_, T> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Vec<T>> {
        for i in 0..self.futures.len() {
            if let Some(val) = poll_slot(&mut self.futures[i], cx) {
                self.results[i] = Some(val);
                self.remaining -= 1;
            }
        }

        if self.remaining == 0 {
            let results: Vec<T> = self
                .results
                .iter_mut()
                .map(|slot| slot.take().expect("all futures completed"))
                .collect();
            Poll::Ready(results)
        } else {
            Poll::Pending
        }
    }
}

/// Waits for all futures to complete, returning Results.
///
/// Similar to `join_all`, but each future returns a `McpResult<T>`.
/// If any future fails, the error is captured in the result vector.
///
/// # Example
///
/// ```ignore
/// let futures = vec![
///     Box::pin(async { Ok::<_, McpError>(1) }),
///     Box::pin(async { Err(McpError::internal_error("failed")) }),
///     Box::pin(async { Ok::<_, McpError>(3) }),
/// ];
/// let results = join_all_results(ctx.cx(), futures).await;
/// // results = [Ok(1), Err(...), Ok(3)]
/// ```
pub async fn join_all_results<T: Send + 'static>(
    cx: &Cx,
    futures: Vec<BoxFuture<'_, McpResult<T>>>,
) -> Vec<McpResult<T>> {
    join_all(cx, futures).await
}

// ============================================================================
// Race Combinator
// ============================================================================

/// Races multiple futures, returning the first to complete.
///
/// This is the 1-of-N combinator: the first future to complete wins,
/// and all other supplied futures are dropped.
///
/// Futures are polled concurrently — each poll cycle round-robins
/// through all futures. The first to resolve wins; remaining futures
/// are dropped immediately. Dropping a future does not cancel or drain
/// work that it spawned independently; callers that spawn work must keep
/// that work in an explicitly cancelled and joined structured scope.
///
/// # Errors
///
/// Returns an error if no futures are provided.
///
/// # Note
///
/// This function takes futures returning `T` directly, not `McpResult<T>`.
/// Use [`first_ok`] when your futures return `McpResult<T>` and you want
/// to skip failures and return the first success.
///
/// # Example
///
/// ```ignore
/// let futures = vec![
///     Box::pin(fetch_from_primary()),
///     Box::pin(fetch_from_replica()),
/// ];
/// let result = race(ctx.cx(), futures).await?;
/// ```
pub async fn race<T: Send + 'static>(_cx: &Cx, futures: Vec<BoxFuture<'_, T>>) -> McpResult<T> {
    if futures.is_empty() {
        return Err(McpError::new(
            McpErrorCode::InvalidParams,
            "race requires at least one future",
        ));
    }
    // Single future: no concurrency overhead needed.
    if futures.len() == 1 {
        let mut futs = futures;
        return Ok(futs.remove(0).await);
    }
    let mut state = RaceAllState {
        futures: futures.into_iter().map(Some).collect(),
    };
    Ok(std::future::poll_fn(move |cx| state.poll(cx)).await)
}

/// Internal state for race_all concurrent polling.
struct RaceAllState<'a, T> {
    futures: Vec<Option<BoxFuture<'a, T>>>,
}

impl<T> RaceAllState<'_, T> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<T> {
        for i in 0..self.futures.len() {
            if let Some(val) = poll_slot(&mut self.futures[i], cx) {
                // Drop all remaining futures (cancellation).
                self.futures.clear();
                return Poll::Ready(val);
            }
        }
        Poll::Pending
    }
}

/// Races multiple futures with a timeout.
///
/// Like `race`, but returns an error if no future completes within
/// the specified duration. The effective deadline is the earlier of the
/// requested timeout and the caller context's budget deadline. Cancellation
/// and budget exhaustion are checked before polling supplied futures. After
/// that checkpoint, an otherwise-ready supplied future wins over a local timer
/// that becomes ready in the same poll.
///
/// # Example
///
/// ```ignore
/// let futures = vec![
///     Box::pin(slow_operation()),
///     Box::pin(slower_operation()),
/// ];
/// let result = race_timeout(ctx.cx(), Duration::from_secs(5), futures).await?;
/// ```
pub async fn race_timeout<T: Send + 'static>(
    cx: &Cx,
    timeout: Duration,
    futures: Vec<BoxFuture<'_, T>>,
) -> McpResult<T> {
    if futures.is_empty() {
        return Err(McpError::new(
            McpErrorCode::InvalidParams,
            "race requires at least one future",
        ));
    }

    let mut state = RaceTimeoutState {
        futures: futures.into_iter().map(Some).collect(),
        timeout: timeout_sleep(cx, timeout),
        request_cx: cx,
    };
    std::future::poll_fn(move |task_cx| state.poll(task_cx)).await
}

/// Internal state for race with timeout enforcement.
struct RaceTimeoutState<'future, 'cx, T> {
    futures: Vec<Option<BoxFuture<'future, T>>>,
    timeout: Sleep,
    request_cx: &'cx Cx,
}

impl<T> RaceTimeoutState<'_, '_, T> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<McpResult<T>> {
        // Caller cancellation and every budget dimension take precedence over
        // both a ready child and the local timeout.
        if self.request_cx.checkpoint().is_err() {
            self.futures.clear();
            return Poll::Ready(Err(McpError::request_cancelled()));
        }

        for i in 0..self.futures.len() {
            if let Some(val) = poll_slot(&mut self.futures[i], cx) {
                self.futures.clear();
                return Poll::Ready(Ok(val));
            }
        }

        // Polling the native timer registers this task's waker with the
        // asupersync timer driver. It does not self-wake or busy-spin.
        if Pin::new(&mut self.timeout).poll(cx).is_ready() {
            self.futures.clear();
            Poll::Ready(Err(McpError::new(
                McpErrorCode::RequestCancelled,
                "operation timed out",
            )))
        } else {
            Poll::Pending
        }
    }
}

// ============================================================================
// Quorum Combinator
// ============================================================================

/// Result of a quorum operation.
#[derive(Debug)]
pub struct QuorumResult<T> {
    /// The successful results (in completion order).
    pub successes: Vec<T>,
    /// Whether the quorum was achieved.
    pub quorum_met: bool,
    /// Number of futures that failed.
    pub failure_count: usize,
}

impl<T> QuorumResult<T> {
    /// Returns true if the quorum was achieved.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.quorum_met
    }

    /// Returns the successful results if quorum was met.
    #[must_use]
    pub fn into_results(self) -> Option<Vec<T>> {
        if self.quorum_met {
            Some(self.successes)
        } else {
            None
        }
    }
}

/// Waits for M of N futures to complete successfully.
///
/// This is the M-of-N combinator: returns when `required` futures
/// have completed successfully. Remaining futures are cancelled (dropped).
///
/// Futures are polled concurrently — each poll cycle round-robins
/// through all incomplete futures. Once quorum is reached or becomes
/// impossible, remaining futures are dropped.
///
/// # Arguments
///
/// * `cx` - The capability context
/// * `required` - Number of successes required (M)
/// * `futures` - The futures to run (N total)
///
/// # Cancellation behavior
///
/// Once quorum is reached (or impossible), remaining supplied futures are
/// dropped. Dropping them does not cancel work they may have spawned
/// independently.
///
/// # Special Cases
///
/// - `quorum(0, N)`: Returns immediately with empty results
/// - `quorum(N, N)`: Equivalent to `join_all` (all must succeed)
/// - `quorum(1, N)`: Equivalent to `race` (first success wins)
/// - `quorum(M, N) where M > N`: Returns error (impossible quorum)
///
/// # Example
///
/// ```ignore
/// // Wait for 2 of 3 replicas to acknowledge
/// let futures = vec![
///     Box::pin(write_to_replica(1)),
///     Box::pin(write_to_replica(2)),
///     Box::pin(write_to_replica(3)),
/// ];
/// let result = quorum(ctx.cx(), 2, futures).await?;
/// if result.quorum_met {
///     println!("Write committed to {} replicas", result.successes.len());
/// }
/// ```
pub async fn quorum<T: Send + 'static>(
    _cx: &Cx,
    required: usize,
    futures: Vec<BoxFuture<'_, McpResult<T>>>,
) -> McpResult<QuorumResult<T>> {
    let total = futures.len();

    // Validate quorum parameters
    if required > total {
        return Err(McpError::new(
            McpErrorCode::InvalidParams,
            format!("quorum requires {required} successes but only {total} futures provided"),
        ));
    }

    // Handle trivial case
    if required == 0 {
        return Ok(QuorumResult {
            successes: Vec::new(),
            quorum_met: true,
            failure_count: 0,
        });
    }

    let mut state = QuorumState {
        futures: futures.into_iter().map(Some).collect(),
        successes: Vec::with_capacity(required),
        failures: 0,
        required,
        total,
    };
    std::future::poll_fn(move |cx| state.poll(cx)).await
}

/// Internal state for quorum concurrent polling.
struct QuorumState<'a, T> {
    futures: Vec<Option<BoxFuture<'a, McpResult<T>>>>,
    successes: Vec<T>,
    failures: usize,
    required: usize,
    total: usize,
}

impl<T> QuorumState<'_, T> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<McpResult<QuorumResult<T>>> {
        for i in 0..self.futures.len() {
            if let Some(result) = poll_slot(&mut self.futures[i], cx) {
                match result {
                    Ok(val) => self.successes.push(val),
                    Err(_) => self.failures += 1,
                }
            }
        }

        let max_allowed_failures = self.total - self.required;

        // Quorum met: early exit, drop remaining futures.
        if self.successes.len() >= self.required {
            self.futures.clear();
            let successes = std::mem::take(&mut self.successes);
            return Poll::Ready(Ok(QuorumResult {
                successes,
                quorum_met: true,
                failure_count: self.failures,
            }));
        }

        // Quorum impossible: too many failures.
        if self.failures > max_allowed_failures {
            self.futures.clear();
            let successes = std::mem::take(&mut self.successes);
            return Poll::Ready(Ok(QuorumResult {
                successes,
                quorum_met: false,
                failure_count: self.failures,
            }));
        }

        // All futures done but quorum not met.
        let still_pending = self.futures.iter().any(Option::is_some);
        if !still_pending {
            let successes = std::mem::take(&mut self.successes);
            let quorum_met = successes.len() >= self.required;
            return Poll::Ready(Ok(QuorumResult {
                successes,
                quorum_met,
                failure_count: self.failures,
            }));
        }

        Poll::Pending
    }
}

/// Waits for M of N futures with a timeout.
///
/// Like `quorum`, but if the timeout fires before quorum is reached,
/// the result reflects whatever successes have accumulated so far
/// (with `quorum_met` likely `false`). The effective deadline is the earlier
/// of the requested timeout and the caller context's budget deadline. Caller
/// cancellation or budget exhaustion returns `RequestCancelled` instead of a
/// partial timeout result.
///
/// # Example
///
/// ```ignore
/// let result = quorum_timeout(
///     ctx.cx(),
///     2,
///     Duration::from_secs(10),
///     futures,
/// ).await?;
/// ```
pub async fn quorum_timeout<T: Send + 'static>(
    cx: &Cx,
    required: usize,
    timeout: Duration,
    futures: Vec<BoxFuture<'_, McpResult<T>>>,
) -> McpResult<QuorumResult<T>> {
    let total = futures.len();

    // Validate quorum parameters
    if required > total {
        return Err(McpError::new(
            McpErrorCode::InvalidParams,
            format!("quorum requires {required} successes but only {total} futures provided"),
        ));
    }

    if required == 0 {
        return Ok(QuorumResult {
            successes: Vec::new(),
            quorum_met: true,
            failure_count: 0,
        });
    }

    let mut state = QuorumTimeoutState {
        futures: futures.into_iter().map(Some).collect(),
        successes: Vec::with_capacity(required),
        failures: 0,
        required,
        total,
        timeout: timeout_sleep(cx, timeout),
        request_cx: cx,
    };
    std::future::poll_fn(move |task_cx| state.poll(task_cx)).await
}

/// Internal state for quorum with timeout enforcement.
struct QuorumTimeoutState<'future, 'cx, T> {
    futures: Vec<Option<BoxFuture<'future, McpResult<T>>>>,
    successes: Vec<T>,
    failures: usize,
    required: usize,
    total: usize,
    timeout: Sleep,
    request_cx: &'cx Cx,
}

impl<T> QuorumTimeoutState<'_, '_, T> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<McpResult<QuorumResult<T>>> {
        if self.request_cx.checkpoint().is_err() {
            self.futures.clear();
            return Poll::Ready(Err(McpError::request_cancelled()));
        }

        for i in 0..self.futures.len() {
            if let Some(result) = poll_slot(&mut self.futures[i], cx) {
                match result {
                    Ok(val) => self.successes.push(val),
                    Err(_) => self.failures += 1,
                }
            }
        }

        let max_allowed_failures = self.total - self.required;

        if self.successes.len() >= self.required {
            self.futures.clear();
            let successes = std::mem::take(&mut self.successes);
            return Poll::Ready(Ok(QuorumResult {
                successes,
                quorum_met: true,
                failure_count: self.failures,
            }));
        }

        if self.failures > max_allowed_failures {
            self.futures.clear();
            let successes = std::mem::take(&mut self.successes);
            return Poll::Ready(Ok(QuorumResult {
                successes,
                quorum_met: false,
                failure_count: self.failures,
            }));
        }

        let still_pending = self.futures.iter().any(Option::is_some);
        if !still_pending {
            let successes = std::mem::take(&mut self.successes);
            return Poll::Ready(Ok(QuorumResult {
                quorum_met: successes.len() >= self.required,
                successes,
                failure_count: self.failures,
            }));
        }

        if Pin::new(&mut self.timeout).poll(cx).is_ready() {
            self.futures.clear();
            let successes = std::mem::take(&mut self.successes);
            Poll::Ready(Ok(QuorumResult {
                quorum_met: successes.len() >= self.required,
                successes,
                failure_count: self.failures,
            }))
        } else {
            Poll::Pending
        }
    }
}

// ============================================================================
// First-Success Combinator
// ============================================================================

/// Races futures and returns the first successful result.
///
/// This function takes futures that return `McpResult<T>` and polls them
/// concurrently, returning the first `Ok` value. If all futures return
/// `Err`, the last error is returned.
///
/// Use this for fallback patterns where you want to try multiple sources
/// and take the first success. After a success, the remaining supplied
/// futures are dropped. Work those futures spawned independently is not
/// cancelled or drained by this combinator.
///
/// # Example
///
/// ```ignore
/// let futures = vec![
///     Box::pin(try_primary()),
///     Box::pin(try_fallback_1()),
///     Box::pin(try_fallback_2()),
/// ];
/// let result = first_ok(ctx.cx(), futures).await?;
/// ```
pub async fn first_ok<T: Send + 'static>(
    _cx: &Cx,
    futures: Vec<BoxFuture<'_, McpResult<T>>>,
) -> McpResult<T> {
    if futures.is_empty() {
        return Err(McpError::new(
            McpErrorCode::InvalidParams,
            "first_ok requires at least one future",
        ));
    }

    let mut state = FirstOkState {
        futures: futures.into_iter().map(Some).collect(),
        last_error: None,
    };
    std::future::poll_fn(move |cx| state.poll(cx)).await
}

/// Internal state for first-success concurrent polling.
struct FirstOkState<'a, T> {
    futures: Vec<Option<BoxFuture<'a, McpResult<T>>>>,
    last_error: Option<McpError>,
}

impl<T> FirstOkState<'_, T> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<McpResult<T>> {
        for i in 0..self.futures.len() {
            if let Some(result) = poll_slot(&mut self.futures[i], cx) {
                match result {
                    Ok(val) => {
                        // Found a success — drop all remaining futures.
                        self.futures.clear();
                        return Poll::Ready(Ok(val));
                    }
                    Err(e) => {
                        self.last_error = Some(e);
                    }
                }
            }
        }

        let still_pending = self.futures.iter().any(Option::is_some);
        if !still_pending {
            let err = self.last_error.take().unwrap_or_else(|| {
                McpError::new(McpErrorCode::InternalError, "all futures failed")
            });
            return Poll::Ready(Err(err));
        }

        Poll::Pending
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    #[derive(Default)]
    struct WakeCounter {
        wakes: AtomicUsize,
    }

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            let _ = self.wakes.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            let _ = self.wakes.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn make_cx() -> Cx {
        Cx::for_testing()
    }

    #[test]
    fn test_join_all_empty() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, i32>> = vec![];
        let results = block_on(join_all(&cx, futures));
        assert!(results.is_empty());
    }

    #[test]
    fn test_join_all_single() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, i32>> = vec![Box::pin(async { 42 })];
        let results = block_on(join_all(&cx, futures));
        assert_eq!(results, vec![42]);
    }

    #[test]
    fn test_join_all_multiple() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, i32>> = vec![
            Box::pin(async { 1 }),
            Box::pin(async { 2 }),
            Box::pin(async { 3 }),
        ];
        let results = block_on(join_all(&cx, futures));
        assert_eq!(results, vec![1, 2, 3]);
    }

    #[test]
    fn test_race_empty() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, i32>> = vec![];
        let result = block_on(race(&cx, futures));
        assert!(result.is_err());
    }

    #[test]
    fn test_race_single() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, i32>> = vec![Box::pin(async { 42 })];
        let result = block_on(race(&cx, futures));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_quorum_trivial() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> =
            vec![Box::pin(async { Ok(1) }), Box::pin(async { Ok(2) })];
        let result = block_on(quorum(&cx, 0, futures));
        assert!(result.is_ok());
        let qr = result.unwrap();
        assert!(qr.quorum_met);
        assert!(qr.successes.is_empty());
    }

    #[test]
    fn test_quorum_all() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> = vec![
            Box::pin(async { Ok(1) }),
            Box::pin(async { Ok(2) }),
            Box::pin(async { Ok(3) }),
        ];
        let result = block_on(quorum(&cx, 3, futures));
        assert!(result.is_ok());
        let qr = result.unwrap();
        assert!(qr.quorum_met);
        assert_eq!(qr.successes.len(), 3);
    }

    #[test]
    fn test_quorum_partial() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> = vec![
            Box::pin(async { Ok(1) }),
            Box::pin(async { Err(McpError::internal_error("fail")) }),
            Box::pin(async { Ok(3) }),
        ];
        let result = block_on(quorum(&cx, 2, futures));
        assert!(result.is_ok());
        let qr = result.unwrap();
        assert!(qr.quorum_met);
        assert_eq!(qr.successes.len(), 2);
    }

    #[test]
    fn test_quorum_impossible() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> = vec![Box::pin(async { Ok(1) })];
        let result = block_on(quorum(&cx, 5, futures));
        assert!(result.is_err());
    }

    #[test]
    fn test_quorum_insufficient() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> = vec![
            Box::pin(async { Ok(1) }),
            Box::pin(async { Err(McpError::internal_error("fail 1")) }),
            Box::pin(async { Err(McpError::internal_error("fail 2")) }),
        ];
        let result = block_on(quorum(&cx, 2, futures));
        assert!(result.is_ok());
        let qr = result.unwrap();
        assert!(!qr.quorum_met);
        assert_eq!(qr.successes.len(), 1);
    }

    #[test]
    fn test_first_ok_empty() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> = vec![];
        let result = block_on(first_ok(&cx, futures));
        assert!(result.is_err());
    }

    #[test]
    fn test_first_ok_first_succeeds() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> =
            vec![Box::pin(async { Ok(1) }), Box::pin(async { Ok(2) })];
        let result = block_on(first_ok(&cx, futures));
        assert_eq!(result.unwrap(), 1);
    }

    #[test]
    fn test_first_ok_fallback() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> = vec![
            Box::pin(async { Err(McpError::internal_error("fail 1")) }),
            Box::pin(async { Ok(2) }),
            Box::pin(async { Ok(3) }),
        ];
        let result = block_on(first_ok(&cx, futures));
        assert_eq!(result.unwrap(), 2);
    }

    #[test]
    fn test_first_ok_all_fail() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> = vec![
            Box::pin(async { Err(McpError::internal_error("fail 1")) }),
            Box::pin(async { Err(McpError::internal_error("fail 2")) }),
        ];
        let result = block_on(first_ok(&cx, futures));
        assert!(result.is_err());
    }

    // =========================================================================
    // Additional coverage tests (bd-1msb)
    // =========================================================================

    #[test]
    fn join_all_results_collects_ok_and_err() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> = vec![
            Box::pin(async { Ok(1) }),
            Box::pin(async { Err(McpError::internal_error("oops")) }),
            Box::pin(async { Ok(3) }),
        ];
        let results = block_on(join_all_results(&cx, futures));
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].as_ref().unwrap(), &1);
        assert!(results[1].is_err());
        assert_eq!(results[2].as_ref().unwrap(), &3);
    }

    #[test]
    fn race_multiple_returns_first_ready() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, i32>> = vec![
            Box::pin(async { 10 }),
            Box::pin(async { 20 }),
            Box::pin(async { 30 }),
        ];
        let result = block_on(race(&cx, futures));
        // With concurrent polling, the first immediately-ready future wins.
        assert_eq!(result.unwrap(), 10);
    }

    #[test]
    fn race_timeout_succeeds_within_deadline() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, i32>> = vec![Box::pin(async { 42 })];
        let result = block_on(race_timeout(&cx, Duration::from_secs(5), futures));
        assert_eq!(result.unwrap(), 42);

        // Empty vec still errors
        let empty: Vec<BoxFuture<'_, i32>> = vec![];
        let err = block_on(race_timeout(&cx, Duration::from_secs(5), empty));
        assert!(err.is_err());
    }

    #[test]
    fn race_timeout_expires_pending_future_at_zero_duration() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, i32>> = vec![Box::pin(std::future::pending())];

        let error = block_on(race_timeout(&cx, Duration::ZERO, futures)).unwrap_err();

        assert_eq!(error.code, McpErrorCode::RequestCancelled);
        assert_eq!(error.message, "operation timed out");

        let futures: Vec<BoxFuture<'_, i32>> = vec![Box::pin(async { 42 })];
        let result = block_on(race_timeout(&cx, Duration::ZERO, futures));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn timeout_combinators_observe_caller_cancellation_after_start() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, i32>> = vec![Box::pin(std::future::pending())];
        let mut future = Box::pin(race_timeout(&cx, Duration::MAX, futures));
        let waker = Waker::noop();
        let mut task_cx = Context::from_waker(waker);

        assert!(future.as_mut().poll(&mut task_cx).is_pending());
        cx.set_cancel_requested(true);

        let Poll::Ready(result) = future.as_mut().poll(&mut task_cx) else {
            panic!("cancelled timeout race remained pending");
        };
        assert_eq!(result.unwrap_err().code, McpErrorCode::RequestCancelled);

        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> =
            vec![Box::pin(async { Ok(7) }), Box::pin(std::future::pending())];
        let mut future = Box::pin(quorum_timeout(&cx, 2, Duration::MAX, futures));
        assert!(future.as_mut().poll(&mut task_cx).is_pending());
        cx.set_cancel_requested(true);

        let Poll::Ready(result) = future.as_mut().poll(&mut task_cx) else {
            panic!("cancelled timeout quorum remained pending");
        };
        assert_eq!(result.unwrap_err().code, McpErrorCode::RequestCancelled);
    }

    #[test]
    fn timeout_combinators_honor_exhausted_caller_budget() {
        let cx = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
        let race_futures: Vec<BoxFuture<'_, i32>> = vec![Box::pin(async { 42 })];
        let race_error = block_on(race_timeout(&cx, Duration::MAX, race_futures)).unwrap_err();
        assert_eq!(race_error.code, McpErrorCode::RequestCancelled);

        let cx = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
        let quorum_futures: Vec<BoxFuture<'_, McpResult<i32>>> = vec![Box::pin(async { Ok(42) })];
        let quorum_error =
            block_on(quorum_timeout(&cx, 1, Duration::MAX, quorum_futures)).unwrap_err();
        assert_eq!(quorum_error.code, McpErrorCode::RequestCancelled);
    }

    #[test]
    fn timeout_combinators_accept_duration_max_without_panicking() {
        let cx = make_cx();
        let race_futures: Vec<BoxFuture<'_, i32>> = vec![Box::pin(async { 42 })];
        let race_result = block_on(race_timeout(&cx, Duration::MAX, race_futures));
        assert_eq!(race_result.unwrap(), 42);

        let quorum_futures: Vec<BoxFuture<'_, McpResult<i32>>> = vec![Box::pin(async { Ok(42) })];
        let quorum_result = block_on(quorum_timeout(&cx, 1, Duration::MAX, quorum_futures));
        assert!(quorum_result.unwrap().quorum_met);
    }

    #[test]
    fn timeout_combinators_do_not_self_wake_while_pending() {
        let cx = make_cx();
        let counter = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut task_cx = Context::from_waker(&waker);

        {
            let futures: Vec<BoxFuture<'_, i32>> = vec![Box::pin(std::future::pending())];
            let mut future = Box::pin(race_timeout(&cx, Duration::from_secs(60), futures));
            assert!(future.as_mut().poll(&mut task_cx).is_pending());
            assert_eq!(counter.wakes.load(Ordering::Relaxed), 0);
        }

        {
            let futures: Vec<BoxFuture<'_, McpResult<i32>>> =
                vec![Box::pin(std::future::pending())];
            let mut future = Box::pin(quorum_timeout(&cx, 1, Duration::from_secs(60), futures));
            assert!(future.as_mut().poll(&mut task_cx).is_pending());
            assert_eq!(counter.wakes.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn quorum_timeout_succeeds_within_deadline() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> =
            vec![Box::pin(async { Ok(1) }), Box::pin(async { Ok(2) })];
        let result = block_on(quorum_timeout(&cx, 2, Duration::from_secs(5), futures));
        let qr = result.unwrap();
        assert!(qr.quorum_met);
        assert_eq!(qr.successes.len(), 2);
    }

    #[test]
    fn quorum_timeout_returns_partial_result_at_zero_duration() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> =
            vec![Box::pin(async { Ok(7) }), Box::pin(std::future::pending())];

        let result = block_on(quorum_timeout(&cx, 2, Duration::ZERO, futures)).unwrap();

        assert!(!result.quorum_met);
        assert_eq!(result.successes, vec![7]);
        assert_eq!(result.failure_count, 0);
    }

    #[test]
    fn quorum_result_is_success_and_into_results() {
        let met = QuorumResult {
            successes: vec![1, 2],
            quorum_met: true,
            failure_count: 1,
        };
        assert!(met.is_success());
        let values = met.into_results().unwrap();
        assert_eq!(values, vec![1, 2]);

        let not_met = QuorumResult {
            successes: vec![1],
            quorum_met: false,
            failure_count: 2,
        };
        assert!(!not_met.is_success());
        assert!(not_met.into_results().is_none());
    }

    #[test]
    fn quorum_result_debug() {
        let qr = QuorumResult {
            successes: vec![42],
            quorum_met: true,
            failure_count: 0,
        };
        let debug = format!("{qr:?}");
        assert!(debug.contains("QuorumResult"));
        assert!(debug.contains("42"));
        assert!(debug.contains("quorum_met: true"));
    }

    #[test]
    fn quorum_all_failures() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> = vec![
            Box::pin(async { Err(McpError::internal_error("fail 1")) }),
            Box::pin(async { Err(McpError::internal_error("fail 2")) }),
            Box::pin(async { Err(McpError::internal_error("fail 3")) }),
        ];
        let result = block_on(quorum(&cx, 2, futures));
        let qr = result.unwrap();
        assert!(!qr.quorum_met);
        assert!(qr.successes.is_empty());
        assert!(qr.failure_count >= 2);
    }

    #[test]
    fn first_ok_all_fail_returns_last_error_message() {
        let cx = make_cx();
        let futures: Vec<BoxFuture<'_, McpResult<i32>>> = vec![
            Box::pin(async { Err(McpError::internal_error("first")) }),
            Box::pin(async { Err(McpError::internal_error("last")) }),
        ];
        let err = block_on(first_ok(&cx, futures)).unwrap_err();
        assert!(err.message.contains("last"));
    }
}
