//! Minimal runtime helpers for FastMCP.
//!
//! This module provides a small `block_on` utility used by macros to
//! execute async handlers in a sync context without adding new deps.
//!
//! The runtime is configured with a platform I/O reactor (epoll on Linux,
//! kqueue on macOS, IOCP on Windows) so that async network I/O works
//! correctly inside `block_on`. `Runtime::block_on` itself installs an
//! ambient `Cx` (backed by the runtime's drivers — including the reactor
//! we attach below) before polling, so asupersync networking primitives
//! can discover the I/O driver via `Cx::current()` without us having to
//! build a context out of band.

use std::future::Future;
use std::sync::OnceLock;

use asupersync::runtime::Runtime;
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::reactor::create_reactor;

/// Lazily initialized single-thread runtime with a platform I/O reactor.
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Blocks the current thread on the provided future.
///
/// Uses a lazily initialized, single-thread asupersync runtime that has a
/// platform I/O reactor enabled. The runtime's own `block_on` installs an
/// ambient `Cx` carrying the runtime drivers (I/O, timer, blocking pool,
/// entropy, observability) for the duration of the poll, so asupersync
/// networking primitives that look up the driver via `Cx::current()` work
/// correctly. Because we attach the reactor via [`RuntimeBuilder::with_reactor`],
/// that ambient `Cx`'s I/O driver is backed by this reactor.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let runtime = RUNTIME.get_or_init(|| {
        // Create the platform reactor (epoll/kqueue/IOCP). The runtime
        // derives its I/O driver from this reactor, and `Runtime::block_on`
        // installs an ambient `Cx` carrying that driver for each poll.
        let reactor = create_reactor().expect("failed to create platform I/O reactor");

        RuntimeBuilder::current_thread()
            .with_reactor(reactor)
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
