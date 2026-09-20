//! Explicit, caller-owned blocking execution for synchronous MCP handlers.
//!
//! Register `BlockingTool::new(handler, lane.clone())?` through the ordinary
//! server/router API. The adapter is async to the router, but invokes the
//! synchronous hook exactly once on the supplied Cx's blocking pool. It never
//! creates a runtime, starts a thread, or accepts the runtime's inline fallback.
//!
//! Share one lane across handlers to bound queued AND executing work. Dropping
//! a request cancels its worker, not its caller or siblings. A running syscall
//! cannot be preempted: its reservation remains charged until the closure really
//! returns. The caller's runtime region retains ownership of that worker.

use std::fmt;
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use asupersync::{Cx, channel::oneshot, runtime::TaskHandle, sync::Notify, time::Sleep};
use fastmcp_core::runtime::{ProcessBoundToken, ProcessGenerationGuard};
use fastmcp_core::{McpContext, McpError, McpOutcome, McpResult, Outcome};
use fastmcp_protocol::common_types::{OpenMetadata, RawIcon};
use fastmcp_protocol::{CompleteResult, Content, FinalCallToolResult, FinalTool, Icon, Tool, ToolAnnotations};
use serde_json::Value;

use crate::bidirectional::MrtrCompletedInputs;
use crate::handler::{BoxFuture, FinalToolOutcome, ToolErrorKind, ToolExecutionMode, ToolHandler};

/// One shared admission domain, not a thread pool. All clones share shutdown
/// and capacity. Keep a host clone to close admission and observe unfinished
/// work during server shutdown. Metadata/registration hooks must remain cheap;
/// only execution hooks run in the blocking pool.
#[derive(Clone)]
pub struct BlockingHandlerLane {
    inner: Arc<LaneInner>,
}

struct LaneInner {
    process: ProcessBoundToken,
    limit: usize,
    state: Mutex<LaneState>,
    changed: Notify,
}

#[derive(Default)]
struct LaneState {
    closed: bool,
    in_flight: usize,
}

impl BlockingHandlerLane {
    /// Bounds running jobs, queued jobs, and results still owned by a call.
    /// Limits are explicit and finite; creating another lane creates another
    /// domain, so applications should share one rather than make one per call.
    pub fn new(max_in_flight: usize) -> McpResult<Self> {
        if !(1..=1024).contains(&max_in_flight) {
            return Err(McpError::invalid_params("blocking handler limit must be in 1..=1024"));
        }
        let guard = ProcessGenerationGuard::install()
            .map_err(|_| unavailable("blocking handler process guard unavailable"))?;
        guard.verify_current().map_err(|_| unavailable("blocking handler process changed"))?;
        Ok(Self { inner: Arc::new(LaneInner {
            process: guard.token(), limit: max_in_flight,
            state: Mutex::new(LaneState::default()), changed: Notify::new(),
        }) })
    }

    fn verify(&self) -> McpResult<()> {
        self.inner.process.verify().map_err(|_| unavailable("blocking handler process changed"))
    }

    /// Stops new admission without pretending that running synchronous work
    /// has stopped. Existing calls may complete normally. This is irreversible.
    pub fn close(&self) -> McpResult<()> {
        self.verify()?;
        self.inner.state.lock().map_err(|_| unavailable("blocking handler lane unavailable"))?.closed = true;
        Ok(())
    }

    /// Reservations include abandoned calls whose synchronous work still runs.
    pub fn in_flight(&self) -> McpResult<usize> {
        self.verify()?;
        Ok(self.inner.state.lock().map_err(|_| unavailable("blocking handler lane unavailable"))?.in_flight)
    }

    /// Waits for actual closure/result custody to be released, with the host's
    /// cancellation and deadline. A cancelled wait is retryable and does not
    /// reopen admission or cancel unrelated work. Close the lane first for a
    /// shutdown barrier. This is not a substitute for joining the host region.
    pub async fn wait_idle(&self, ctx: &McpContext) -> McpResult<()> {
        self.verify()?;
        wait(ctx, async {
            self.inner.changed.wait_until(|| self.in_flight().map_or(true, |count| count == 0)).await;
            self.in_flight().map(|_| ())
        }).await
    }

    fn reserve(&self) -> McpResult<Arc<Charge>> {
        self.verify()?;
        let mut state = self.inner.state.lock().map_err(|_| unavailable("blocking handler lane unavailable"))?;
        if state.closed { return Err(unavailable("blocking handler lane is closed")); }
        if state.in_flight == self.inner.limit {
            return Err(unavailable("blocking handler capacity exhausted"));
        }
        state.in_flight += 1;
        Ok(Arc::new(Charge(Arc::clone(&self.inner))))
    }

    async fn execute<T, F>(&self, ctx: &McpContext, request_cx: &Cx, work: F) -> McpResult<T>
    where T: Send + 'static, F: FnOnce(&McpContext) -> McpResult<T> + Send + 'static,
    {
        self.verify()?;
        // Rebind a CLONE: authentication, request lease, operation deadline,
        // cancellation and consumed quota must not become a fresh request.
        let context = ctx.clone().with_request_cx(request_cx.clone());
        context.checkpoint().map_err(|_| McpError::request_cancelled())?;
        let capabilities = request_cx.capabilities();
        if !capabilities.spawn || !capabilities.time || request_cx.timer_driver().is_none() {
            return Err(unavailable("blocking handlers require caller-owned spawn and timers"));
        }
        if request_cx.blocking_pool_handle().is_none() {
            return Err(unavailable("blocking handlers require an installed caller-owned blocking pool"));
        }
        let charge = self.reserve()?;
        let worker_charge = Arc::clone(&charge);
        let worker_context = context.clone();
        let worker = request_cx.spawn_blocking(move |worker_cx| {
            // This reservation outlives user work, unwinding, and disposal of a
            // result that can no longer be delivered. Aborting the wait cannot
            // release it while the synchronous closure remains on the stack.
            let _charge = worker_charge;
            _charge.0.process.verify().map_err(|_| unavailable("blocking handler process changed"))?;
            let context = worker_context.with_request_cx(worker_cx);
            let _current = Cx::set_current(Some(context.cx().clone()));
            context.checkpoint().map_err(|_| McpError::request_cancelled())?;
            let result = catch_unwind(AssertUnwindSafe(|| work(&context)))
                .map_err(|_| unavailable("blocking handler panicked; payload redacted"))?;
            context.ensure_live().map_err(|_| McpError::request_cancelled())?;
            result
        }).map_err(|_| unavailable("blocking handler admission to caller runtime failed"))?;
        let mut owner = WorkerOwner { worker: Some(worker), _charge: charge };
        let result = wait(&context, async {
            // Keep the handle inside its RAII owner while join is suspended.
            // An abandoned join therefore aborts this worker and no sibling.
            owner.worker.as_mut().expect("worker is present until join completes")
                .join(request_cx).await
                .map_err(|_| unavailable("blocking handler worker did not complete"))?
        }).await;
        if result.is_ok() { owner.worker = None; }
        result
    }
}

impl fmt::Debug for BlockingHandlerLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingHandlerLane").field("limit", &self.inner.limit).finish_non_exhaustive()
    }
}

struct Charge(Arc<LaneInner>);
impl Drop for Charge {
    fn drop(&mut self) {
        // Do not touch an inherited mutex after fork. This process cannot
        // settle the original process's work or grant its capacity anew.
        if self.0.process.verify().is_err() { return; }
        let mut state = self.0.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.in_flight -= 1;
        drop(state);
        // Wakers are application code; their panic must not escape cleanup.
        let _ = catch_unwind(AssertUnwindSafe(|| self.0.changed.notify_waiters()));
    }
}

struct WorkerOwner<T: Send + 'static> {
    worker: Option<TaskHandle<McpResult<T>>>,
    _charge: Arc<Charge>,
}
impl<T: Send + 'static> Drop for WorkerOwner<T> {
    fn drop(&mut self) {
        if self._charge.0.process.verify().is_ok() {
            if let Some(worker) = &self.worker { worker.abort(); }
        }
    }
}

fn unavailable(message: &'static str) -> McpError { McpError::internal_error(message) }

// One owned wait, not a retry loop. Request-local cancellation and runtime
// cancellation each register a wake. The periodic check observes lease closure
// and shared budget tightening even if no worker or socket makes progress.
async fn wait<T>(ctx: &McpContext, operation: impl Future<Output = McpResult<T>>) -> McpResult<T> {
    ctx.ensure_live().map_err(|_| McpError::request_cancelled())?;
    let cx = ctx.cx();
    if !cx.capabilities().time || cx.timer_driver().is_none() {
        return Err(unavailable("blocking handler wait requires caller-owned timers"));
    }
    let mut deadline = ctx.budget().deadline.map(|time| Box::pin(Sleep::new(time)));
    let mut tick = Box::pin(Sleep::new(cx.now().saturating_add_nanos(10_000_000)));
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut runtime_cancelled = std::pin::pin!(receiver.recv(cx));
    let mut request_cancelled = std::pin::pin!(ctx.request_cancelled());
    let mut operation = std::pin::pin!(operation);
    poll_fn(|task| {
        let _current = Cx::set_current(Some(cx.clone()));
        ctx.ensure_live().map_err(|_| McpError::request_cancelled())?;
        if request_cancelled.as_mut().poll(task).is_ready()
            || runtime_cancelled.as_mut().poll(task).is_ready()
            || deadline.as_mut().is_some_and(|timer| timer.as_mut().poll(task).is_ready())
        { return Poll::Ready(Err(McpError::request_cancelled())); }
        let result = operation.as_mut().poll(task);
        ctx.ensure_live().map_err(|_| McpError::request_cancelled())?;
        if result.is_ready() { return result; }
        if tick.as_mut().poll(task).is_ready() {
            tick = Box::pin(Sleep::new(cx.now().saturating_add_nanos(10_000_000)));
            let _ = tick.as_mut().poll(task);
        }
        Poll::Pending
    }).await
}

/// Opt-in offload for a synchronous `ToolHandler`, including exact final
/// complete results and declared Tasks creation descriptors. Catalog, schema,
/// authorization and output-validation boundaries remain the ordinary router's.
///
/// Async handlers and MRTR-resuming handlers are rejected at construction: their
/// async/resume hooks cannot be silently replaced with a synchronous hook.
/// Synchronous trait entry points refuse rather than introduce an inline path.
/// Invoke through async router/server dispatch. Registration hooks and handler
/// destructors must not block; this adapter offloads execution, not registration.
pub struct BlockingTool<H> {
    handler: Arc<H>,
    lane: BlockingHandlerLane,
    tasks: bool,
}
impl<H: ToolHandler + 'static> BlockingTool<H> {
    /// Wraps synchronous local execution without changing catalog or schema
    /// admission. The shared lane must be supplied explicitly by the host.
    pub fn new(handler: H, lane: BlockingHandlerLane) -> McpResult<Self> {
        if handler.execution_mode() != ToolExecutionMode::Blocking || handler.declares_final_mrtr() {
            return Err(McpError::invalid_params("blocking tool requires synchronous non-resuming hooks"));
        }
        if handler.upstream_final_tool_schema_registration().is_some() {
            return Err(McpError::invalid_params("blocking tool cannot replace an upstream proxy executor"));
        }
        let tasks = handler.declares_final_tasks();
        Ok(Self { handler: Arc::new(handler), lane, tasks })
    }

    fn legacy<'a>(&'a self, ctx: &'a McpContext, cx: &'a Cx, arguments: Value)
        -> BoxFuture<'a, McpOutcome<Vec<Content>>>
    {
        let handler = Arc::clone(&self.handler);
        Box::pin(async move { outcome(self.lane.execute(ctx, cx, move |ctx| handler.call(ctx, arguments)).await) })
    }
    fn complete<'a>(&'a self, ctx: &'a McpContext, cx: &'a Cx, arguments: Value)
        -> BoxFuture<'a, McpOutcome<CompleteResult<FinalCallToolResult>>>
    {
        let handler = Arc::clone(&self.handler);
        Box::pin(async move { outcome(self.lane.execute(ctx, cx, move |ctx| handler.call_final(ctx, arguments)).await) })
    }
    fn final_outcome<'a>(&'a self, ctx: &'a McpContext, cx: &'a Cx, arguments: Value)
        -> BoxFuture<'a, McpOutcome<FinalToolOutcome>>
    {
        let handler = Arc::clone(&self.handler);
        #[cfg(feature = "tasks")]
        let declares_tasks = self.tasks;
        Box::pin(async move {
            outcome(self.lane.execute(ctx, cx, move |ctx| {
                let result = handler.call_final_outcome(ctx, arguments)?;
                if matches!(&result, FinalToolOutcome::InputRequired(_)) {
                    return Err(McpError::invalid_request("blocking tool has no synchronous resume hook"));
                }
                #[cfg(feature = "tasks")]
                if matches!(&result, FinalToolOutcome::CreateTask { .. }) && !declares_tasks {
                    return Err(McpError::invalid_request("blocking tool returned an undeclared Tasks outcome"));
                }
                Ok(result)
            }).await)
        })
    }
}

fn outcome<T>(result: McpResult<T>) -> McpOutcome<T> {
    match result { Ok(value) => Outcome::Ok(value), Err(error) => Outcome::Err(error) }
}

impl<H: ToolHandler + 'static> ToolHandler for BlockingTool<H> {
    fn definition(&self) -> Tool { self.handler.definition() }
    fn icon(&self) -> Option<&Icon> { self.handler.icon() }
    fn version(&self) -> Option<&str> { self.handler.version() }
    fn tags(&self) -> &[String] { self.handler.tags() }
    fn annotations(&self) -> Option<&ToolAnnotations> { self.handler.annotations() }
    fn output_schema(&self) -> Option<Value> { self.handler.output_schema() }
    fn final_title(&self) -> Option<&str> { self.handler.final_title() }
    fn final_icons(&self) -> Option<&[RawIcon]> { self.handler.final_icons() }
    fn final_metadata(&self) -> Option<&OpenMetadata> { self.handler.final_metadata() }
    fn final_definition(&self) -> Option<FinalTool> { self.handler.final_definition() }
    fn final_tool_error_structured_content(&self, kind: ToolErrorKind) -> Option<Value> {
        self.handler.final_tool_error_structured_content(kind)
    }
    fn timeout(&self) -> Option<Duration> { self.handler.timeout() }
    fn execution_mode(&self) -> ToolExecutionMode { ToolExecutionMode::Async }
    fn declares_final_tasks(&self) -> bool { self.tasks }

    fn call(&self, _ctx: &McpContext, _arguments: Value) -> McpResult<Vec<Content>> {
        Err(McpError::invalid_request("blocking tool requires asynchronous caller-owned dispatch"))
    }
    fn call_async<'a>(&'a self, ctx: &'a McpContext, arguments: Value) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
        self.legacy(ctx, ctx.cx(), arguments)
    }
    fn call_async_in_request<'a>(&'a self, ctx: &'a McpContext, cx: &'a Cx, arguments: Value)
        -> BoxFuture<'a, McpOutcome<Vec<Content>>>
    { self.legacy(ctx, cx, arguments) }
    fn call_final_async<'a>(&'a self, ctx: &'a McpContext, arguments: Value)
        -> BoxFuture<'a, McpOutcome<CompleteResult<FinalCallToolResult>>>
    { self.complete(ctx, ctx.cx(), arguments) }
    fn call_final_async_in_request<'a>(&'a self, ctx: &'a McpContext, cx: &'a Cx, arguments: Value)
        -> BoxFuture<'a, McpOutcome<CompleteResult<FinalCallToolResult>>>
    { self.complete(ctx, cx, arguments) }
    fn call_final_outcome_async<'a>(&'a self, ctx: &'a McpContext, arguments: Value)
        -> BoxFuture<'a, McpOutcome<FinalToolOutcome>>
    { self.final_outcome(ctx, ctx.cx(), arguments) }
    fn call_final_outcome_async_in_request<'a>(&'a self, ctx: &'a McpContext, cx: &'a Cx, arguments: Value)
        -> BoxFuture<'a, McpOutcome<FinalToolOutcome>>
    { self.final_outcome(ctx, cx, arguments) }
    fn call_final_outcome_async_resuming_in_request<'a>(
        &'a self, ctx: &'a McpContext, cx: &'a Cx, arguments: Value, resume: Option<&'a MrtrCompletedInputs>,
    ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
        if resume.is_some() {
            return Box::pin(async { Outcome::Err(McpError::invalid_request("blocking tool has no synchronous resume hook")) });
        }
        self.final_outcome(ctx, cx, arguments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use serde_json::json;

    struct Echo { calls: Arc<AtomicUsize>, poller: std::thread::ThreadId }
    impl ToolHandler for Echo {
        fn definition(&self) -> Tool {
            Tool { name: "blocking_echo".into(), description: None,
                input_schema: json!({"type":"object"}), output_schema: None,
                icon: None, version: None, tags: vec![], annotations: None }
        }
        fn call(&self, ctx: &McpContext, arguments: Value) -> McpResult<Vec<Content>> {
            assert_ne!(std::thread::current().id(), self.poller, "user hook must not run on the poller");
            assert_eq!(ctx.request_id(), 7);
            assert_eq!(Cx::current().unwrap().task_id(), ctx.task_id());
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![Content::Text { text: arguments.to_string() }])
        }
    }
    fn runtime(pool: bool) -> asupersync::runtime::Runtime {
        let builder = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap());
        if pool { builder.blocking_threads(0, 2).build().unwrap() } else { builder.build().unwrap() }
    }

    #[test]
    fn blocking_tool_executes_legacy_and_final_hooks_on_the_caller_pool() {
        runtime(true).block_on(async {
            let cx = Cx::current().unwrap();
            let context = McpContext::new(cx.clone(), 7);
            let calls = Arc::new(AtomicUsize::new(0));
            let lane = BlockingHandlerLane::new(2).unwrap();
            let tool = BlockingTool::new(Echo { calls: Arc::clone(&calls), poller: std::thread::current().id() }, lane.clone()).unwrap();
            assert_eq!(tool.execution_mode(), ToolExecutionMode::Async);
            assert!(tool.call(&context, json!({})).is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(matches!(tool.call_async(&context, json!({"value":1})).await, Outcome::Ok(_)));
            let Outcome::Ok(FinalToolOutcome::Complete(result)) = tool.call_final_outcome_async_in_request(
                &context, &cx, json!({"value":2}),
            ).await else { panic!("final hook must produce a real complete result"); };
            let fastmcp_protocol::common_types::ContentBlock::Text { text, .. } = &result.payload.content[0]
                else { panic!("legacy content must retain its final text form"); };
            assert_eq!(text, r#"{"value":2}"#);
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(lane.in_flight().unwrap(), 0);
        });
    }

    #[test]
    fn missing_pool_and_closed_lane_never_invoke_the_handler() {
        for pool in [false, true] {
            runtime(pool).block_on(async {
                let cx = Cx::current().unwrap();
                let context = McpContext::new(cx, 7);
                let calls = Arc::new(AtomicUsize::new(0));
                let lane = BlockingHandlerLane::new(1).unwrap();
                if pool { lane.close().unwrap(); }
                else { assert!(context.cx().blocking_pool_handle().is_none()); }
                let tool = BlockingTool::new(Echo { calls: Arc::clone(&calls), poller: std::thread::current().id() }, lane.clone()).unwrap();
                assert!(matches!(tool.call_async(&context, json!({})).await, Outcome::Err(_)));
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert_eq!(lane.in_flight().unwrap(), 0);
            });
        }
    }

    #[test]
    fn cancelled_call_keeps_capacity_until_the_running_closure_really_returns() {
        runtime(true).block_on(async {
            let cx = Cx::current().unwrap();
            let context = McpContext::new(cx.clone(), 7);
            let sibling = McpContext::new(cx, 8);
            let lane = BlockingHandlerLane::new(1).unwrap();
            let (started, mut entered) = oneshot::channel::<()>();
            let (release, blocked) = std::sync::mpsc::sync_channel::<()>(1);
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&calls);
            let mut call = Box::pin(lane.execute(&context, context.cx(), move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                let _ = started.send_blocking(());
                blocked.recv_timeout(Duration::from_secs(5)).expect("test releases its blocking worker");
                Ok(41)
            }));
            poll_fn(|task| { assert!(call.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
            entered.recv(context.cx()).await.unwrap();
            context.request_cancellation().cancel();
            assert!(call.await.is_err());
            assert_eq!(lane.in_flight().unwrap(), 1, "cancel does not manufacture free worker capacity");
            assert!(lane.execute(&sibling, sibling.cx(), |_| Ok(42)).await.is_err());
            assert!(sibling.ensure_live().is_ok());
            release.send(()).unwrap();
            let shutdown = sibling.clone().with_operation_deadline(Some(sibling.cx().now().saturating_add_nanos(5_000_000_000)));
            lane.wait_idle(&shutdown).await.unwrap();
            assert_eq!(lane.execute(&sibling, sibling.cx(), |_| Ok(42)).await.unwrap(), 42);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            lane.close().unwrap();
            assert!(lane.execute(&sibling, sibling.cx(), |_| Ok(43)).await.is_err());
        });
    }

    #[test]
    fn worker_panic_releases_capacity_without_exposing_its_payload() {
        runtime(true).block_on(async {
            let context = McpContext::new(Cx::current().unwrap(), 7);
            let lane = BlockingHandlerLane::new(1).unwrap();
            let error = lane.execute::<(), _>(&context, context.cx(), |_| panic!("private-handler-panic-canary")).await.unwrap_err();
            assert!(!format!("{error:?}").contains("private-handler-panic-canary"));
            assert_eq!(lane.in_flight().unwrap(), 0);
            assert_eq!(lane.execute(&context, context.cx(), |_| Ok(9)).await.unwrap(), 9);
        });
    }

    #[test]
    fn lane_reservations_are_shared_bounded_and_shutdown_is_irreversible() {
        assert!(BlockingHandlerLane::new(0).is_err());
        assert!(BlockingHandlerLane::new(1025).is_err());
        let lane = BlockingHandlerLane::new(1).unwrap();
        let clone = lane.clone();
        let charge = lane.reserve().unwrap();
        let worker = Arc::clone(&charge);
        assert!(clone.reserve().is_err());
        drop(charge);
        assert_eq!(clone.in_flight().unwrap(), 1);
        drop(worker);
        assert_eq!(clone.in_flight().unwrap(), 0);
        clone.close().unwrap();
        assert!(lane.reserve().is_err());
    }
}
