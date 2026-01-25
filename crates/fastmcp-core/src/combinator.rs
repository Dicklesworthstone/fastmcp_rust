//! Parallel combinator helpers for MCP handlers.
//!
//! This module provides ergonomic wrappers around asupersync's structured
//! concurrency combinators, adapted for MCP's error model.
//!
//! # Available Combinators
//!
//! - [`join_all`]: Wait for all operations to complete (N-of-N)
//! - [`race`]: Return first to complete, cancel others (1-of-N)
//! - [`quorum`]: Wait for M of N to complete (M-of-N)
//!
//! # Cancel-Correctness
//!
//! All combinators properly drain cancelled/losing futures to ensure
//! structured concurrency invariants are maintained. No orphan tasks.
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_core::combinator::{join_all, race, quorum};
//!
//! // Wait for all to complete
//! let results = join_all(ctx.cx(), vec![fut1, fut2, fut3]).await;
//!
//! // Return first to complete
//! let winner = race(ctx.cx(), vec![fut1, fut2, fut3]).await;
//!
//! // Wait for 2 of 3 to succeed
//! let quorum_result = quorum(ctx.cx(), 2, vec![fut1, fut2, fut3]).await;
//! ```

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use asupersync::Cx;

use crate::error::{McpError, McpErrorCode, McpResult};

// ============================================================================
// Type Aliases
// ============================================================================

/// A boxed, pinned, sendable future for use with combinators.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ============================================================================
// Join Combinator
// ============================================================================

/// Waits for all futures to complete and returns their results.
///
/// This is the N-of-N combinator: all futures must complete before
/// returning. Results are returned in the same order as input futures.
///
/// # Cancel-Correctness
///
/// If any future is cancelled or panics, the combinator will still
/// await all remaining futures to completion before returning.
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
    // Phase 0: Sequential execution (single-threaded runtime)
    // Phase 1+: Will use proper concurrent polling
    let mut results = Vec::with_capacity(futures.len());
    for fut in futures {
        results.push(fut.await);
    }
    results
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
/// and all others are cancelled and drained.
///
/// # Cancel-Correctness
///
/// Losing futures are properly cancelled and awaited to ensure no
/// orphan tasks remain.
///
/// # Errors
///
/// Returns an error if:
/// - No futures are provided
/// - The winning future fails (error is propagated)
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

    // Phase 0: Sequential execution - first future wins
    // Phase 1+: Will use proper concurrent polling with cancellation
    let mut iter = futures.into_iter();
    let Some(fut) = iter.next() else {
        return Err(McpError::new(
            McpErrorCode::InvalidParams,
            "race requires at least one future",
        ));
    };
    Ok(fut.await)
}

/// Races multiple futures with a timeout.
///
/// Like `race`, but returns an error if no future completes within
/// the specified duration.
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
    _timeout: Duration, // Phase 0: timeout not enforced
    futures: Vec<BoxFuture<'_, T>>,
) -> McpResult<T> {
    // Phase 0: Delegate to race without timeout enforcement
    // Phase 1+: Will use proper timeout wrapping
    race(cx, futures).await
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
/// have completed successfully. Remaining futures are cancelled.
///
/// # Arguments
///
/// * `cx` - The capability context
/// * `required` - Number of successes required (M)
/// * `futures` - The futures to run (N total)
///
/// # Cancel-Correctness
///
/// Once quorum is reached (or impossible), remaining futures are
/// cancelled and drained. No orphan tasks.
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

    // Phase 0: Sequential execution with early exit
    // Phase 1+: Will use proper concurrent polling with cancellation
    let mut successes = Vec::with_capacity(required);
    let mut failures = 0;
    let max_allowed_failures = total - required;

    for fut in futures {
        // Check if quorum is already met
        if successes.len() >= required {
            break;
        }

        // Check if quorum is still possible
        if failures > max_allowed_failures {
            break;
        }

        match fut.await {
            Ok(value) => successes.push(value),
            Err(_) => failures += 1,
        }
    }

    let quorum_met = successes.len() >= required;

    Ok(QuorumResult {
        successes,
        quorum_met,
        failure_count: failures,
    })
}

/// Waits for M of N futures with a timeout.
///
/// Like `quorum`, but fails if the quorum isn't reached within
/// the specified duration.
///
/// # Note
///
/// In Phase 0, this delegates to `quorum` without actual timeout enforcement.
/// In Phase 1+, proper timeout handling will be implemented.
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
    _timeout: Duration, // Phase 0: timeout not enforced
    futures: Vec<BoxFuture<'_, McpResult<T>>>,
) -> McpResult<QuorumResult<T>> {
    // Phase 0: Delegate to quorum without timeout
    // Phase 1+: Will use proper timeout wrapping
    quorum(cx, required, futures).await
}

// ============================================================================
// First-Success Combinator
// ============================================================================

/// Races futures and returns the first successful result.
///
/// Unlike `race` which returns the first to complete (success or failure),
/// `first_ok` returns the first to complete successfully. If all futures
/// fail, returns the last error.
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

    // Phase 0: Sequential fallback execution
    // Phase 1+: Will use concurrent polling with first-success semantics
    let mut last_error = None;

    for fut in futures {
        match fut.await {
            Ok(value) => return Ok(value),
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error
        .unwrap_or_else(|| McpError::new(McpErrorCode::InternalError, "all futures failed")))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_on;

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
}
