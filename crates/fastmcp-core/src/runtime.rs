//! Minimal runtime helpers for FastMCP.
//!
//! This module provides a small `block_on` utility used by macros to
//! execute async handlers in a sync context without adding new deps.
//!
//! The runtime is configured with a platform I/O reactor (epoll on Linux,
//! kqueue on macOS, IOCP on Windows) so that async network I/O works
//! correctly inside `block_on`. Asupersync's runtime installs a thread-local
//! `Cx` before polling so networking primitives can discover the I/O driver
//! via `Cx::current()`.

use std::future::Future;
use std::sync::OnceLock;

use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::reactor::create_reactor;

/// Lazily initialized runtime with a platform I/O reactor.
struct RuntimeWithIo {
    runtime: asupersync::runtime::Runtime,
}

static RUNTIME: OnceLock<RuntimeWithIo> = OnceLock::new();

/// Blocks the current thread on the provided future.
///
/// Uses a lazily initialized, single-thread asupersync runtime that has a
/// platform I/O reactor enabled. The runtime installs an ambient `Cx` while
/// polling so asupersync networking primitives can find the reactor.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let rt = RUNTIME.get_or_init(|| {
        // Create the platform reactor (epoll/kqueue/IOCP).
        let reactor = create_reactor().expect("failed to create platform I/O reactor");

        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("failed to build asupersync runtime");

        RuntimeWithIo { runtime }
    });

    rt.runtime.block_on(future)
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
