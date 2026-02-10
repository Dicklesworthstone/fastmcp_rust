//! Minimal runtime helpers for FastMCP.
//!
//! This module provides a small `block_on` utility used by macros to
//! execute async handlers in a sync context without adding new deps.

use std::future::Future;
use std::sync::OnceLock;

use asupersync::runtime::RuntimeBuilder;

static RUNTIME: OnceLock<asupersync::runtime::Runtime> = OnceLock::new();

/// Blocks the current thread on the provided future.
///
/// Uses a lazily initialized, single-thread asupersync runtime.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let runtime = RUNTIME.get_or_init(|| {
        RuntimeBuilder::current_thread()
            .build()
            .expect("failed to build asupersync runtime")
    });

    runtime.block_on(future)
}

#[cfg(test)]
mod tests {
    use super::block_on;

    #[test]
    fn block_on_runs_async_blocks() {
        let out = block_on(async { 1 + 1 });
        assert_eq!(out, 2);
    }

    #[test]
    fn block_on_can_be_called_multiple_times() {
        let a = block_on(async { "a" });
        let b = block_on(async { "b" });
        assert_eq!(a, "a");
        assert_eq!(b, "b");
    }
}
