//! Caller-owned asynchronous application initialization and cleanup.
//!
//! Admission precedes startup. One runtime-owned custodian retains the child
//! region opening, the application task, and region close, even if the serve
//! future disappears. Shutdown is authorized separately, after serving work
//! has quiesced; abandoning a serve never invokes cleanup over live handlers.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use asupersync::cx::ChildRegionSpec;
use asupersync::runtime::TaskHandle;
use asupersync::sync::Notify;
use asupersync::types::CapabilityBudgetRequirements;
use asupersync::{CancelReason, Cx};
use fastmcp_core::runtime::{CallerContextFuture, with_caller_context};
use fastmcp_core::{McpError, McpResult};

use crate::{Server, catch_extension_unwind, extension_panic_error};

/// An application lifecycle future, owned by the server's caller runtime.
pub type AsyncLifespanFuture = Pin<Box<dyn Future<Output = McpResult<()>> + Send>>;

/// An asynchronous lifecycle callback receiving its admitted task context.
pub type AsyncLifespanHook = Box<dyn FnOnce(Cx) -> AsyncLifespanFuture + Send>;

const WAITING: u8 = 0;
const SHUTDOWN: u8 = 1;
const ABANDONED: u8 = 2;
const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
struct LifespanSignal {
    startup: Mutex<Option<McpResult<()>>>,
    startup_entered: AtomicBool,
    command: AtomicU8,
    changed: Notify,
}

impl LifespanSignal {
    fn publish_startup(&self, result: McpResult<()>) {
        *self
            .startup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
        self.changed.notify_waiters();
    }

    fn startup_result(&self) -> Option<McpResult<()>> {
        self.startup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn command(&self, command: u8) {
        // Abandonment dominates an earlier shutdown signal. A lost observer
        // must not leave an indefinitely pending callback outside its region.
        self.command.fetch_max(command, Ordering::AcqRel);
        self.changed.notify_waiters();
    }
}

/// Retained observation and shutdown authority for one native serve.
/// The task itself belongs to the caller's region, never a private runtime.
pub(crate) struct AsyncLifespanOwner {
    signal: Arc<LifespanSignal>,
    custodian: TaskHandle<McpResult<()>>,
    result: Option<McpResult<()>>,
}

impl AsyncLifespanOwner {
    fn admit(
        cx: &Cx,
        startup: Option<AsyncLifespanHook>,
        shutdown: Option<AsyncLifespanHook>,
        timeout: Duration,
    ) -> McpResult<Self> {
        with_caller_context(cx, || {
            let caller = Cx::current().ok_or_else(|| lifecycle_error("caller is unavailable"))?;
            caller
                .checkpoint()
                .map_err(|_| McpError::request_cancelled())?;
            if !caller.capabilities().time || caller.timer_driver().is_none() {
                return Err(lifecycle_error(
                    "requires the caller's time capability and timer",
                ));
            }
            let signal = Arc::new(LifespanSignal::default());
            let task_signal = Arc::clone(&signal);
            let custodian = caller
                .spawn(move |custodian_cx| async move {
                    let outcome = run_region(
                        &custodian_cx,
                        Arc::clone(&task_signal),
                        startup,
                        shutdown,
                        timeout,
                    )
                    .await;
                    if task_signal.startup_result().is_none() {
                        task_signal.publish_startup(Err(lifecycle_error(
                            "could not start its owned region",
                        )));
                    }
                    outcome
                })
                .map_err(|_| lifecycle_error("requires caller-owned task admission"))?;
            Ok(Self {
                signal,
                custodian,
                result: None,
            })
        })
    }

    async fn ready(&mut self) -> McpResult<()> {
        loop {
            if let Some(result) = self.signal.startup_result() {
                return result;
            }
            if let Some(result) = self.poll_result() {
                return result.and(Err(lifecycle_error("ended before startup completed")));
            }
            self.signal
                .changed
                .wait_until(|| {
                    self.signal.startup_result().is_some() || self.custodian.is_finished()
                })
                .await;
        }
    }

    pub(crate) fn request_shutdown(&self) {
        self.signal.command(SHUTDOWN);
    }

    /// Nonblocking observation; a pending shutdown future stays in its task.
    pub(crate) fn poll_result(&mut self) -> Option<McpResult<()>> {
        if self.result.is_none() {
            self.result = match self.custodian.try_join() {
                Ok(Some(result)) => Some(result),
                Ok(None) => None,
                Err(_) => Some(Err(lifecycle_error("custodian did not settle normally"))),
            };
        }
        self.result.clone()
    }

    /// Waits for actual callback and region settlement. The hook's thirty
    /// second work bound does not turn non-cooperative descendants into a
    /// successful cleanup receipt. Dropping this observer requests abandonment.
    pub(crate) async fn finish(&mut self) -> McpResult<()> {
        self.request_shutdown();
        if let Some(result) = self.result.clone() {
            return result;
        }
        let result = poll_fn(|task| self.custodian.poll_join(task))
            .await
            .unwrap_or_else(|_| Err(lifecycle_error("custodian did not settle normally")));
        self.result = Some(result.clone());
        result
    }
}

impl Drop for AsyncLifespanOwner {
    fn drop(&mut self) {
        if self.result.is_none() {
            self.signal.command(ABANDONED);
        }
    }
}

async fn run_region(
    cx: &Cx,
    signal: Arc<LifespanSignal>,
    startup: Option<AsyncLifespanHook>,
    shutdown: Option<AsyncLifespanHook>,
    timeout: Duration,
) -> McpResult<()> {
    // The custodian owns this raw opening until it publishes an owned region.
    // Dropping a public serve/settlement future cannot strand the mint.
    let capability_budget = cx.capability_budget();
    let mut specification = ChildRegionSpec::inherit().with_budget(cx.budget());
    specification.capability_budget = Some(capability_budget);
    let region = cx
        .open_child_region(specification)
        .await
        .map_err(|_| lifecycle_error("could not open its child region"))?;
    let worker_signal = Arc::clone(&signal);
    let worker = region
        .cx()
        .scope_with_budget_and_capability_budget(
            region.cx().budget(),
            capability_budget,
            CapabilityBudgetRequirements::NONE,
        )
        .map_err(|_| lifecycle_error("could not retain its capability budget"))
        .and_then(|scope| {
            cx.spawn_in(&scope, move |worker_cx| async move {
                let has_startup = startup.is_some();
                let startup_result =
                    run_hook(&worker_cx, &worker_signal, startup, false, timeout).await;
                worker_signal.publish_startup(startup_result.clone());
                worker_signal
                    .changed
                    .wait_until(|| worker_signal.command.load(Ordering::Acquire) != WAITING)
                    .await;
                if worker_signal.command.load(Ordering::Acquire) == ABANDONED {
                    return Err(lifecycle_error("was abandoned before cleanup completed"));
                }
                if has_startup && !worker_signal.startup_entered.load(Ordering::Acquire) {
                    return Ok(());
                }
                let shutdown_result =
                    run_hook(&worker_cx, &worker_signal, shutdown, true, timeout).await;
                shutdown_result
            })
            .map_err(|_| lifecycle_error("could not schedule its application task"))
        });
    let result = match worker {
        Ok(mut worker) => poll_fn(|task| worker.poll_join(task))
            .await
            .unwrap_or_else(|_| Err(lifecycle_error("application task did not finish normally"))),
        Err(error) => Err(error),
    };
    let cancelled = region.cancel(CancelReason::user("Server lifespan finished"));
    let closed = region.close().await;
    closed.map_err(|_| lifecycle_error("child-region quiescence could not be verified"))?;
    cancelled.map_err(|_| lifecycle_error("child-region cancellation could not be requested"))?;
    result
}

async fn run_hook(
    cx: &Cx,
    signal: &LifespanSignal,
    hook: Option<AsyncLifespanHook>,
    shutdown: bool,
    timeout: Duration,
) -> McpResult<()> {
    let Some(hook) = hook else {
        return Ok(());
    };
    if signal.command.load(Ordering::Acquire) == ABANDONED {
        return Err(lifecycle_error("was abandoned before callback invocation"));
    }
    let deadline = cx
        .budget()
        .deadline
        .map_or(cx.now() + timeout, |bound| bound.min(cx.now() + timeout));
    if cx.now() >= deadline {
        return Err(lifecycle_error("hook deadline expired before invocation"));
    }
    if !shutdown {
        cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
    }
    let make = || {
        catch_extension_unwind(|| {
            if !shutdown {
                signal.startup_entered.store(true, Ordering::Release);
            }
            with_caller_context(cx, || hook(cx.clone()))
        })
        .map_err(|_| extension_panic_error("async_lifespan_factory"))
    };
    // Only cleanup may continue under attributed serve cancellation. This
    // mask covers one factory/poll, never an await or the original deadline.
    let future = if shutdown { cx.masked(make) } else { make() }?;
    let mut future = Box::pin(CallerContextFuture::new(cx, future));
    let mut timer = Box::pin(asupersync::time::sleep_until(deadline));
    let mut cancellation_poll =
        Box::pin(asupersync::time::sleep(cx.now(), Duration::from_millis(25)));
    let mut abandoned = Box::pin(
        signal
            .changed
            .wait_until(|| signal.command.load(Ordering::Acquire) == ABANDONED),
    );
    poll_fn(|task| {
        if abandoned.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(lifecycle_error(
                "was abandoned before cleanup completed",
            )));
        }
        if cx.now() >= deadline {
            return Poll::Ready(Err(lifecycle_error("hook exceeded its deadline")));
        }
        if !shutdown && cx.checkpoint().is_err() {
            return Poll::Ready(Err(McpError::request_cancelled()));
        }
        let mut poll = || {
            catch_extension_unwind(|| future.as_mut().poll(task))
                .unwrap_or_else(|_| Poll::Ready(Err(extension_panic_error("async_lifespan_poll"))))
        };
        let result = if shutdown { cx.masked(poll) } else { poll() };
        if cx.now() >= deadline {
            return Poll::Ready(Err(lifecycle_error("hook exceeded its deadline")));
        }
        if !shutdown && cx.checkpoint().is_err() {
            return Poll::Ready(Err(McpError::request_cancelled()));
        }
        if result.is_ready() {
            return result;
        }
        // A cancelled ambient context must not make a pending cleanup timer
        // spin. Its own fixed deadline remains checked on every poll.
        let _ = cx.masked(|| timer.as_mut().poll(task));
        if cx
            .masked(|| cancellation_poll.as_mut().poll(task))
            .is_ready()
        {
            cancellation_poll =
                Box::pin(asupersync::time::sleep(cx.now(), Duration::from_millis(25)));
            let _ = cx.masked(|| cancellation_poll.as_mut().poll(task));
        }
        Poll::Pending
    })
    .await
}

fn lifecycle_error(detail: &'static str) -> McpError {
    McpError::internal_error(format!("Asynchronous server lifespan {detail}"))
}

impl Server {
    /// Admits native lifecycle ownership before any application startup.
    pub(crate) async fn start_native_lifespan(
        &self,
        cx: &Cx,
    ) -> McpResult<Option<AsyncLifespanOwner>> {
        let (startup, shutdown) = {
            let mut guard = self
                .lifespan
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.async_lifespan_claimed.load(Ordering::Acquire) {
                return Err(lifecycle_error("was already claimed by another serve"));
            }
            match guard.as_mut() {
                Some(hooks) => {
                    self.async_lifespan_claimed.store(
                        hooks.on_startup_async.is_some() || hooks.on_shutdown_async.is_some(),
                        Ordering::Release,
                    );
                    (
                        hooks.on_startup_async.take(),
                        hooks.on_shutdown_async.take(),
                    )
                }
                None => (None, None),
            }
        };
        let mut owner = if startup.is_some() || shutdown.is_some() {
            Some(AsyncLifespanOwner::admit(
                cx,
                startup,
                shutdown,
                HOOK_TIMEOUT,
            )?)
        } else {
            None
        };
        if let Some(owner) = owner.as_mut() {
            if let Err(error) = owner.ready().await {
                return match owner.finish().await {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(McpError::internal_error(format!(
                        "Asynchronous server startup failed: {}; cleanup failed: {}",
                        error.message, cleanup.message,
                    ))),
                };
            }
        }
        if !self.run_startup_hook() {
            if let Some(owner) = owner.as_mut() {
                owner.finish().await?;
            }
            return Err(lifecycle_error("startup hook failed"));
        }
        Ok(owner)
    }

    pub(crate) fn has_async_lifespan(&self) -> bool {
        self.async_lifespan_claimed.load(Ordering::Acquire)
            || self
                .lifespan
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .is_some_and(|hooks| {
                    hooks.on_startup_async.is_some() || hooks.on_shutdown_async.is_some()
                })
    }

    pub(crate) fn admit_blocking_lifespan(&self) -> McpResult<()> {
        if self.has_async_lifespan() {
            Err(lifecycle_error(
                "requires native serve_http, serve_websocket, serve_memory, or serve_stdio_io",
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
