//! Minimal runtime helpers for FastMCP.
//!
//! This module provides a small `block_on` utility used by macros to
//! execute async handlers in a sync context without adding new deps.
//!
//! The runtime is configured with a platform I/O reactor (epoll on Linux,
//! kqueue on macOS, IOCP on Windows) so that async network I/O works
//! correctly inside `block_on`. A thread-local `Cx` context is installed
//! before polling so that asupersync networking primitives can discover
//! the I/O driver via `Cx::current()`.

use std::future::Future;
use std::sync::{Arc, OnceLock};

use asupersync::cx::Cx;
use asupersync::runtime::reactor::create_reactor;
use asupersync::runtime::{IoDriverHandle, RuntimeBuilder};
use asupersync::types::{Budget, RegionId, TaskId};

/// Lazily initialized runtime paired with its I/O driver handle.
///
/// We store the `IoDriverHandle` alongside the runtime so that each call
/// to `block_on` can install a `Cx` that carries the driver, allowing
/// async socket operations to find the reactor.
struct RuntimeWithIo {
    runtime: asupersync::runtime::Runtime,
    io_driver: IoDriverHandle,
}

static RUNTIME: OnceLock<RuntimeWithIo> = OnceLock::new();

/// Blocks the current thread on the provided future.
///
/// Uses a lazily initialized, single-thread asupersync runtime that has a
/// platform I/O reactor enabled. Before polling, a `Cx` context carrying
/// the I/O driver is installed on the current thread so that asupersync
/// networking primitives (which look up the driver via `Cx::current()`)
/// work correctly.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let rt = RUNTIME.get_or_init(|| {
        // Create the platform reactor (epoll/kqueue/IOCP).
        let reactor = create_reactor().expect("failed to create platform I/O reactor");
        let io_driver = IoDriverHandle::new(Arc::clone(&reactor));

        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("failed to build asupersync runtime");

        RuntimeWithIo { runtime, io_driver }
    });

    // Install a Cx on the current thread so that futures polled inside
    // block_on can discover the I/O driver via Cx::current().
    // The guard restores the previous Cx (if any) on drop.
    let cx = Cx::new_with_observability(
        RegionId::new_for_test(0, 0),
        TaskId::new_for_test(0, 0),
        Budget::INFINITE,
        None, // observability
        Some(rt.io_driver.clone()),
        None, // entropy
    );
    let _cx_guard = Cx::set_current(Some(cx));

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
