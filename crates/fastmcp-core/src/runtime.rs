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

use std::cell::OnceCell;
use std::future::Future;

use asupersync::runtime::Runtime;
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::reactor::create_reactor;

/// Upper bound on on-demand blocking threads for the shared bridge runtime.
///
/// The bridge hosts a transport receive pump and any handler the embedder puts
/// on `Cx::spawn_blocking`; it is not a general-purpose worker pool, so the
/// ceiling stays small, host-independent and deterministic. Threads are created
/// only when blocking work is admitted and retire when idle.
const MAX_BLOCKING_THREADS: usize = 16;

thread_local! {
    /// Lazily initialized single-thread runtime with a platform I/O reactor.
    ///
    /// The bridge is thread-local because `Runtime::block_on` polls its future
    /// on the calling thread. Sharing one current-thread runtime across
    /// concurrent blocking adapters can couple an adapter to a reactor being
    /// driven by another thread and starve sibling tasks on that runtime.
    static RUNTIME: OnceCell<Runtime> = const { OnceCell::new() };
}

/// Blocks the current thread on the provided future.
///
/// Uses a lazily initialized, per-thread asupersync runtime that has a platform
/// I/O reactor enabled. The runtime's own `block_on` installs an ambient `Cx`
/// carrying the runtime drivers (I/O, timer, blocking pool, entropy,
/// observability) for the duration of the poll, so asupersync networking
/// primitives that look up the driver via `Cx::current()` work correctly.
/// Because we attach the reactor via [`RuntimeBuilder::with_reactor`], that
/// ambient `Cx`'s I/O driver is backed by the calling thread's reactor.
pub fn block_on<F: Future>(future: F) -> F::Output {
    RUNTIME.with(|runtime| {
        let runtime = runtime.get_or_init(|| {
            // Create the platform reactor (epoll/kqueue/IOCP). The runtime
            // derives its I/O driver from this reactor, and `Runtime::block_on`
            // installs an ambient `Cx` carrying that driver for each poll.
            let reactor = create_reactor().expect("failed to create platform I/O reactor");

            RuntimeBuilder::current_thread()
                .with_reactor(reactor)
                // A blocking pool is REQUIRED, not an optimization.
                // `Cx::spawn_blocking` falls back to running its closure INLINE
                // when the ambient runtime has none, and the default pool
                // configuration is `max_threads = 0` — no pool at all. A server
                // that puts its receive pump on `Cx::spawn_blocking` (the stdio
                // transport does) would then run that pump on the single worker
                // thread, so the worker can never poll the request-owned child
                // the router spawns for an ordinary request: the first request
                // that admits a child never completes and the process stops
                // answering (GitHub #65).
                //
                // `min_threads = 0` keeps the pool on-demand, so a process that
                // never blocks still starts no extra thread.
                .blocking_threads(0, MAX_BLOCKING_THREADS)
                .build()
                .expect("failed to build asupersync runtime")
        });

        runtime.block_on(future)
    })
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
