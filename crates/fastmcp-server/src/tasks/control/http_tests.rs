// Public ingress coverage for caller-owned asynchronous Task store controls.
// The fixture delegates atomic state to the real in-memory store. It claims
// neither filesystem persistence nor asynchronous worker/creation support.
use super::*;
use fastmcp_protocol::tasks_extension::{
    Task as ControlTask, TaskInputResponses as ControlInputs,
    TaskStatusNotification as ControlNotification,
};
use std::future::poll_fn;
use std::task::{Context as TaskContext, Poll as TaskPoll, Waker};

struct AsyncControlHttpStore {
    inner: InMemoryFinalTaskStore,
    require_no_blocking_pool: bool,
    constructed: AtomicUsize,
    synchronous: AtomicUsize,
    metadata_polls: AtomicUsize,
    snapshot_reads: AtomicUsize,
    updates: AtomicUsize,
    cancellations: AtomicUsize,
    blocked: AtomicBool,
    entered: AtomicBool,
    waiter: Mutex<Option<Waker>>,
    write_blocked: AtomicBool,
    write_entered: AtomicBool,
    write_waiter: Mutex<Option<Waker>>,
    cancel_after_metadata: AtomicBool,
    cancel_after_commit: AtomicBool,
}

impl AsyncControlHttpStore {
    fn new() -> Self {
        Self {
            inner: InMemoryFinalTaskStore::new(4).unwrap(),
            require_no_blocking_pool: true,
            constructed: AtomicUsize::new(0),
            synchronous: AtomicUsize::new(0),
            metadata_polls: AtomicUsize::new(0),
            snapshot_reads: AtomicUsize::new(0),
            updates: AtomicUsize::new(0),
            cancellations: AtomicUsize::new(0),
            blocked: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            waiter: Mutex::new(None),
            write_blocked: AtomicBool::new(false),
            write_entered: AtomicBool::new(false),
            write_waiter: Mutex::new(None),
            cancel_after_metadata: AtomicBool::new(false),
            cancel_after_commit: AtomicBool::new(false),
        }
    }

    fn seed(&self, task: ControlTask) {
        self.inner
            .create_task(task.clone(), crate::tasks::final_task_notification(&task))
            .unwrap();
    }

    fn release(&self) {
        self.blocked.store(false, Ordering::Release);
        if let Some(waiter) = self.waiter.lock().unwrap().take() {
            waiter.wake();
        }
    }

    fn release_write(&self) {
        self.write_blocked.store(false, Ordering::Release);
        if let Some(waiter) = self.write_waiter.lock().unwrap().take() {
            waiter.wake();
        }
    }

    async fn wait_for_write(&self, ctx: &McpContext) -> McpResult<()> {
        self.write_entered.store(true, Ordering::Release);
        poll_fn(|task| {
            if ctx.checkpoint().is_err() {
                return TaskPoll::Ready(Err(McpError::request_cancelled()));
            }
            let mut waiter = self.write_waiter.lock().unwrap();
            if self.write_blocked.load(Ordering::Acquire) {
                *waiter = Some(task.waker().clone());
                TaskPoll::Pending
            } else {
                TaskPoll::Ready(Ok(()))
            }
        })
        .await
    }
}

impl FinalTaskStore for AsyncControlHttpStore {
    fn get_task_access_metadata_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        id: &'a fastmcp_protocol::FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskAccessMetadata>> {
        self.constructed.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if self.require_no_blocking_pool {
                assert!(
                    ctx.cx().blocking_pool_handle().is_none(),
                    "the native control route must work without a blocking pool"
                );
            }
            self.entered.store(true, Ordering::Release);
            poll_fn(|task| {
                self.metadata_polls.fetch_add(1, Ordering::SeqCst);
                if ctx.checkpoint().is_err() {
                    return TaskPoll::Ready(Err(McpError::request_cancelled()));
                }
                let mut waiter = self.waiter.lock().unwrap();
                if self.blocked.load(Ordering::Acquire) {
                    *waiter = Some(task.waker().clone());
                    TaskPoll::Pending
                } else {
                    TaskPoll::Ready(Ok(()))
                }
            })
            .await?;
            let result = self.inner.get_task_access_metadata(id);
            if self.cancel_after_metadata.swap(false, Ordering::SeqCst) {
                assert!(ctx.request_cancellation().cancel());
            }
            result
        })
    }

    fn get_task_snapshot_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        id: &'a fastmcp_protocol::FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.constructed.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            ctx.checkpoint().map_err(|_| McpError::request_cancelled())?;
            self.snapshot_reads.fetch_add(1, Ordering::SeqCst);
            self.inner.get_task_snapshot(id)
        })
    }

    fn expire_task_execution_if_current_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        expected: &'a FinalTaskSnapshot,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.constructed.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            ctx.checkpoint().map_err(|_| McpError::request_cancelled())?;
            self.inner.expire_task_execution_if_current(expected)
        })
    }

    fn replace_task_and_append_input_if_current_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        expected: &'a FinalTaskSnapshot,
        task: ControlTask,
        notification: ControlNotification,
        inputs: ControlInputs,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.constructed.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            self.wait_for_write(ctx).await?;
            let result = self.inner.replace_task_and_append_input_if_current(
                expected,
                task,
                notification,
                inputs,
            )?;
            if result.is_some() {
                self.updates.fetch_add(1, Ordering::SeqCst);
                if self.cancel_after_commit.load(Ordering::Acquire) {
                    assert!(ctx.request_cancellation().cancel());
                }
            }
            Ok(result)
        })
    }

    fn request_cancellation_and_clear_input_if_current_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        expected: &'a FinalTaskSnapshot,
        task: ControlTask,
        notification: ControlNotification,
    ) -> FinalTaskStoreFuture<'a, Option<FinalTaskSnapshot>> {
        self.constructed.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            self.wait_for_write(ctx).await?;
            let result = self
                .inner
                .request_cancellation_and_clear_input_if_current(expected, task, notification)?;
            if result.is_some() {
                self.cancellations.fetch_add(1, Ordering::SeqCst);
                if self.cancel_after_commit.load(Ordering::Acquire) {
                    assert!(ctx.request_cancellation().cancel());
                }
            }
            Ok(result)
        })
    }

    fn is_cancellation_requested_with_context<'a>(
        &'a self,
        ctx: &'a McpContext,
        id: &'a fastmcp_protocol::FinalTaskId,
    ) -> FinalTaskStoreFuture<'a, bool> {
        self.constructed.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            ctx.checkpoint().map_err(|_| McpError::request_cancelled())?;
            self.inner.is_cancellation_requested(id)
        })
    }

    fn create_task(&self, task: ControlTask, notification: ControlNotification) -> McpResult<()> {
        self.inner.create_task(task, notification)
    }

    fn get_task_access_metadata(
        &self,
        id: &fastmcp_protocol::FinalTaskId,
    ) -> McpResult<Option<FinalTaskAccessMetadata>> {
        self.synchronous.fetch_add(1, Ordering::SeqCst);
        self.inner.get_task_access_metadata(id)
    }

    fn get_task(&self, id: &fastmcp_protocol::FinalTaskId) -> McpResult<Option<ControlTask>> {
        self.synchronous.fetch_add(1, Ordering::SeqCst);
        self.inner.get_task(id)
    }

    fn get_task_snapshot(
        &self,
        id: &fastmcp_protocol::FinalTaskId,
    ) -> McpResult<Option<FinalTaskSnapshot>> {
        self.synchronous.fetch_add(1, Ordering::SeqCst);
        self.inner.get_task_snapshot(id)
    }

    fn replace_task(&self, task: ControlTask, notification: ControlNotification) -> McpResult<()> {
        self.synchronous.fetch_add(1, Ordering::SeqCst);
        self.inner.replace_task(task, notification)
    }

    fn replace_task_if_current(
        &self,
        expected: &FinalTaskSnapshot,
        task: ControlTask,
        notification: ControlNotification,
    ) -> McpResult<bool> {
        self.synchronous.fetch_add(1, Ordering::SeqCst);
        self.inner.replace_task_if_current(expected, task, notification)
    }

    fn request_cancellation(&self, id: &fastmcp_protocol::FinalTaskId) -> McpResult<()> {
        self.synchronous.fetch_add(1, Ordering::SeqCst);
        self.inner.request_cancellation(id)
    }

    fn request_cancellation_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<bool> {
        self.synchronous.fetch_add(1, Ordering::SeqCst);
        self.inner.request_cancellation_if_current(expected)
    }

    fn is_cancellation_requested(&self, id: &fastmcp_protocol::FinalTaskId) -> McpResult<bool> {
        self.synchronous.fetch_add(1, Ordering::SeqCst);
        self.inner.is_cancellation_requested(id)
    }

    fn retention_clock_now(&self) -> Instant {
        self.inner.retention_clock_now()
    }

    fn task_retention_deadline_if_current(
        &self,
        id: &fastmcp_protocol::FinalTaskId,
        generation: u64,
    ) -> McpResult<Option<FinalTaskRetentionDeadline>> {
        self.inner.task_retention_deadline_if_current(id, generation)
    }
}

fn async_control_input_task() -> ControlTask {
    serde_json::from_value(serde_json::json!({
        "taskId": "async-control-input",
        "status": "input_required",
        "createdAt": "2026-07-28T12:00:00Z",
        "lastUpdatedAt": "2026-07-28T12:00:00Z",
        "ttlMs": 60_000,
        "inputRequests": {"roots": {"method": "roots/list"}}
    }))
    .unwrap()
}

fn async_control_request(method: &str, id: i64) -> JsonRpcRequest {
    let task_id = fastmcp_protocol::FinalTaskId::parse("async-control-input").unwrap();
    let mut params = final_tasks_params(&task_id, serde_json::json!({}));
    if method == fastmcp_protocol::tasks_extension::TASK_UPDATE {
        params["inputResponses"] = serde_json::json!({"roots": {"roots": []}});
    }
    JsonRpcRequest::new(method, Some(params), id)
}

async fn async_control_http_rpc(
    address: SocketAddr,
    request: JsonRpcRequest,
) -> Result<(JsonRpcResponse, Vec<u8>), String> {
    let mut headers = vec![
        ("Accept", "application/json"),
        ("MCP-Protocol-Version", MODERN_PROTOCOL_VERSION),
        ("Mcp-Method", request.method.as_str()),
    ];
    if let Some(id) = request
        .params
        .as_ref()
        .and_then(|params| params.get("taskId"))
        .and_then(serde_json::Value::as_str)
    {
        headers.push(("Mcp-Name", id));
    }
    let body = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
    let frame = live_http_exchange(address, live_http_post("/mcp", &body, &headers)).await?;
    let response = serde_json::from_slice(live_http_response_body(&frame)?)
        .map_err(|error| error.to_string())?;
    Ok((response, frame))
}

#[test]
fn public_http_async_task_store_controls_preserve_results_and_sibling_progress() {
    run_live_http_test_with_blocking_capacity(
        |cx| async move {
            let store = Arc::new(AsyncControlHttpStore::new());
            let initial = async_control_input_task();
            let task_id = initial.base().task_id.clone();
            store.seed(initial.clone());
            let completed: ControlTask = serde_json::from_str(&format!(
                r#"{{"taskId":"async-control-completed","status":"completed","createdAt":"2026-07-28T12:00:00Z","lastUpdatedAt":"2026-07-28T12:00:00Z","ttlMs":60000,"result":{AUTH_TASK_COMPLETED_RESULT_SOURCE}}}"#
            ))
            .unwrap();
            store.seed(completed);
            store.blocked.store(true, Ordering::Release);
            let emitted = Arc::new(Mutex::new(Vec::new()));
            let notifications = Arc::clone(&emitted);
            let runtime = FinalTaskRuntime::new(
                store.clone(),
                FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
                Arc::new(move |notification| notifications.lock().unwrap().push(notification)),
            );
            let bound = Server::new("async-task-controls", "1")
                .protocol_policy(ProtocolPolicy::ModernOnly)
                .unwrap()
                .final_tasks(runtime)
                .unwrap()
                .build()
                .bind_http(&cx, "127.0.0.1:0")
                .await
                .map_err(|error| error.to_string())?;
            let address = bound.local_addr().map_err(|error| error.to_string())?;
            let caller = cx.clone();
            let mut client = cx
                .spawn(move |client_cx| async move {
                    struct StopServer(Cx);
                    impl Drop for StopServer {
                        fn drop(&mut self) {
                            self.0.cancel_with(
                                CancelKind::User,
                                Some("asynchronous Task control probe finished"),
                            );
                        }
                    }
                    let _stop = StopServer(caller);
                    let mut get = client_cx
                        .spawn(move |_| async move {
                            async_control_http_rpc(
                                address,
                                async_control_request(fastmcp_protocol::TASK_GET, 71),
                            )
                            .await
                        })
                        .map_err(|error| error.to_string())?;
                    let deadline = client_cx
                        .now()
                        .saturating_add_nanos(LIVE_HTTP_TEST_TIMEOUT_NANOS);
                    while !store.entered.load(Ordering::Acquire) {
                        if client_cx.now() >= deadline {
                            return Err("Task metadata future was not polled".to_owned());
                        }
                        asupersync::time::sleep(client_cx.now(), Duration::from_millis(1)).await;
                    }
                    let discover = JsonRpcRequest::new(
                        SERVER_DISCOVER_METHOD,
                        Some(serde_json::json!({
                            "_meta": {
                                "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                                "io.modelcontextprotocol/clientCapabilities": {}
                            }
                        })),
                        72_i64,
                    );
                    let (sibling, _) = async_control_http_rpc(address, discover).await?;
                    assert!(sibling.error.is_none(), "{:?}", sibling.error);
                    assert!(sibling.result.is_some());
                    assert!(store.blocked.load(Ordering::Acquire));
                    assert!(store.metadata_polls.load(Ordering::SeqCst) > 0);
                    assert_eq!(
                        store.snapshot_reads.load(Ordering::SeqCst),
                        0,
                        "payload access waits for metadata admission"
                    );
                    store.release();
                    let (read, _) = get
                        .join(&client_cx)
                        .await
                        .map_err(|error| format!("Task read child failed: {error:?}"))??;
                    assert!(read.error.is_none(), "{:?}", read.error);
                    let mut expected = serde_json::to_value(&initial).unwrap();
                    expected["resultType"] = serde_json::json!("complete");
                    assert_eq!(read.result, Some(expected));

                    let completed_id =
                        fastmcp_protocol::FinalTaskId::parse("async-control-completed").unwrap();
                    let completed_get = JsonRpcRequest::new(
                        fastmcp_protocol::TASK_GET,
                        Some(final_tasks_params(&completed_id, serde_json::json!({}))),
                        73_i64,
                    );
                    let (read, frame) = async_control_http_rpc(address, completed_get).await?;
                    assert!(read.error.is_none(), "{:?}", read.error);
                    let envelope: BTreeMap<String, Box<serde_json::value::RawValue>> =
                        serde_json::from_slice(live_http_response_body(&frame)?).unwrap();
                    let result: BTreeMap<String, Box<serde_json::value::RawValue>> =
                        serde_json::from_str(envelope["result"].get()).unwrap();
                    assert_eq!(
                        result["result"].get().as_bytes(),
                        AUTH_TASK_COMPLETED_RESULT_SOURCE.as_bytes(),
                        "asynchronous storage must preserve the exact completed result source"
                    );

                    let (updated, _) = async_control_http_rpc(
                        address,
                        async_control_request(fastmcp_protocol::tasks_extension::TASK_UPDATE, 74),
                    )
                    .await?;
                    assert!(updated.error.is_none(), "{:?}", updated.error);
                    assert_eq!(
                        updated.result,
                        Some(serde_json::json!({"resultType": "complete"}))
                    );
                    assert!(matches!(
                        store.inner.get_task(&task_id).unwrap().unwrap(),
                        ControlTask::Working(_)
                    ));
                    let (cancelled, _) = async_control_http_rpc(
                        address,
                        async_control_request(fastmcp_protocol::TASK_CANCEL, 75),
                    )
                    .await?;
                    assert!(cancelled.error.is_none(), "{:?}", cancelled.error);
                    assert_eq!(
                        cancelled.result,
                        Some(serde_json::json!({"resultType": "complete"}))
                    );
                    assert!(matches!(
                        store.inner.get_task(&task_id).unwrap().unwrap(),
                        ControlTask::Cancelled(_)
                    ));
                    assert!(!store.inner.is_cancellation_requested(&task_id).unwrap());
                    assert_eq!(store.updates.load(Ordering::SeqCst), 1);
                    assert_eq!(store.cancellations.load(Ordering::SeqCst), 1);
                    assert_eq!(
                        store.synchronous.load(Ordering::SeqCst),
                        0,
                        "public Task controls must not fall back to synchronous storage"
                    );
                    let delivered = emitted.lock().unwrap();
                    assert_eq!(delivered.len(), 2);
                    assert!(matches!(&delivered[0].params.task, ControlTask::Working(_)));
                    assert!(matches!(&delivered[1].params.task, ControlTask::Cancelled(_)));
                    Ok::<(), String>(())
                })
                .map_err(|error| error.to_string())?;
            let serve = bound.serve(&cx).await;
            let client_result = client
                .join(&cx)
                .await
                .map_err(|error| format!("Task control client failed: {error:?}"))?;
            client_result?;
            require_quiescent_http_shutdown(
                serve.map_err(|error| error.to_string())?,
                "asynchronous Task controls",
            )
            .await
        },
        0,
    );
}

#[test]
fn public_task_control_cancelled_before_poll_never_constructs_store_operations() {
    for method in [
        fastmcp_protocol::TASK_GET,
        fastmcp_protocol::tasks_extension::TASK_UPDATE,
        fastmcp_protocol::TASK_CANCEL,
    ] {
        let store = Arc::new(AsyncControlHttpStore::new());
        let task = async_control_input_task();
        let id = task.base().task_id.clone();
        store.seed(task);
        let before = store.inner.get_task_snapshot(&id).unwrap().unwrap();
        let notification = serde_json::to_vec(&store.inner.latest_notification(&id)).unwrap();
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
            Arc::new(|_| panic!("cancelled ingress cannot emit a Task transition")),
        );
        let server = Server::new("cancelled-async-task-controls", "1")
            .protocol_policy(ProtocolPolicy::ModernOnly)
            .unwrap()
            .final_tasks(runtime)
            .unwrap()
            .build();
        let cx = Cx::for_testing();
        let inbound =
            InboundRequestContext::new(cx.clone(), 77, InboundRequestTransport::Memory);
        let request = async_control_request(method, 77);
        let mut future = Box::pin(server.dispatch_stateless(&inbound, &request));
        assert_eq!(store.constructed.load(Ordering::SeqCst), 0);
        cx.set_cancel_requested(true);
        let TaskPoll::Ready(response) =
            future.as_mut().poll(&mut TaskContext::from_waker(Waker::noop()))
        else {
            panic!("cancelled Task ingress must settle without polling storage");
        };
        let response = response.expect("a cancelled request retains its JSON-RPC response");
        assert!(response.result.is_none());
        assert!(response.error.is_some());
        drop(future);
        assert_eq!(store.constructed.load(Ordering::SeqCst), 0);
        assert_eq!(store.metadata_polls.load(Ordering::SeqCst), 0);
        assert_eq!(store.snapshot_reads.load(Ordering::SeqCst), 0);
        assert_eq!(store.synchronous.load(Ordering::SeqCst), 0);
        assert_eq!(store.updates.load(Ordering::SeqCst), 0);
        assert_eq!(store.cancellations.load(Ordering::SeqCst), 0);
        let after = store.inner.get_task_snapshot(&id).unwrap().unwrap();
        assert_eq!(after.generation(), before.generation());
        assert_eq!(
            serde_json::to_vec(after.task()).unwrap(),
            serde_json::to_vec(before.task()).unwrap()
        );
        assert_eq!(
            serde_json::to_vec(&store.inner.latest_notification(&id)).unwrap(),
            notification
        );
    }
}

#[test]
fn public_http_task_write_receipts_survive_request_cancellation_without_unfencing_reads() {
    for method in [
        fastmcp_protocol::TASK_GET,
        fastmcp_protocol::tasks_extension::TASK_UPDATE,
        fastmcp_protocol::TASK_CANCEL,
    ] {
        run_live_http_test_with_blocking_capacity(
            move |cx| async move {
                let reading = method == fastmcp_protocol::TASK_GET;
                let store = Arc::new(AsyncControlHttpStore::new());
                let task = async_control_input_task();
                let task_id = task.base().task_id.clone();
                store.seed(task.clone());
                let before = store.inner.get_task_snapshot(&task_id).unwrap().unwrap();
                if reading {
                    store.blocked.store(true, Ordering::Release);
                    store.cancel_after_metadata.store(true, Ordering::Release);
                } else {
                    store.write_blocked.store(true, Ordering::Release);
                    store.cancel_after_commit.store(true, Ordering::Release);
                }
                let emitted = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&emitted);
                let runtime = FinalTaskRuntime::new(
                    store.clone(),
                    FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
                    Arc::new(move |_| {
                        observed.fetch_add(1, Ordering::SeqCst);
                    }),
                );
                let bound = Server::new("task-control-receipt-race", "1")
                    .protocol_policy(ProtocolPolicy::ModernOnly)
                    .unwrap()
                    .mask_error_details(true)
                    .final_tasks(runtime)
                    .unwrap()
                    .build()
                    .bind_http(&cx, "127.0.0.1:0")
                    .await
                    .map_err(|error| error.to_string())?;
                let address = bound.local_addr().map_err(|error| error.to_string())?;
                let caller = cx.clone();
                let mut client = cx
                    .spawn(move |client_cx| async move {
                        struct StopServer(Cx);
                        impl Drop for StopServer {
                            fn drop(&mut self) {
                                self.0.cancel_with(
                                    CancelKind::User,
                                    Some("Task mutation receipt probe finished"),
                                );
                            }
                        }
                        let _stop = StopServer(caller);
                        let mut pending = client_cx
                            .spawn(move |_| async move {
                                async_control_http_rpc(
                                    address,
                                    async_control_request(method, 81),
                                )
                                .await
                            })
                            .map_err(|error| error.to_string())?;
                        let deadline = client_cx
                            .now()
                            .saturating_add_nanos(LIVE_HTTP_TEST_TIMEOUT_NANOS);
                        while if reading {
                            !store.entered.load(Ordering::Acquire)
                        } else {
                            !store.write_entered.load(Ordering::Acquire)
                        } {
                            if client_cx.now() >= deadline {
                                return Err("Task control storage did not suspend".to_owned());
                            }
                            asupersync::time::sleep(
                                client_cx.now(),
                                Duration::from_millis(1),
                            )
                            .await;
                        }
                        assert_eq!(
                            store
                                .inner
                                .get_task_snapshot(&task_id)
                                .unwrap()
                                .unwrap()
                                .generation(),
                            before.generation(),
                            "the pending storage operation has not committed early"
                        );
                        if reading {
                            store.release();
                        } else {
                            store.release_write();
                        }
                        let (response, _) = pending
                            .join(&client_cx)
                            .await
                            .map_err(|error| format!("Task race child failed: {error:?}"))??;
                        assert!(response.result.is_none());
                        let error = response.error.expect("the request ended before response");
                        let retained = store.inner.get_task_snapshot(&task_id).unwrap().unwrap();
                        if reading {
                            assert_eq!(
                                error.code.as_i32(),
                                Some(i32::from(McpErrorCode::RequestCancelled)),
                                "read cancellation has no mutation receipt exemption"
                            );
                            assert!(error.data.is_none());
                            assert_eq!(store.snapshot_reads.load(Ordering::SeqCst), 0);
                            assert_eq!(retained.generation(), before.generation());
                            assert_eq!(
                                serde_json::to_vec(retained.task()).unwrap(),
                                serde_json::to_vec(&task).unwrap()
                            );
                            assert_eq!(store.updates.load(Ordering::SeqCst), 0);
                            assert_eq!(store.cancellations.load(Ordering::SeqCst), 0);
                        } else {
                            assert_eq!(
                                error.code.as_i32(),
                                Some(i32::from(McpErrorCode::InternalError)),
                                "a committed mutation cannot become ordinary cancellation"
                            );
                            assert_eq!(
                                error.data,
                                Some(serde_json::json!({"reason": "TaskStateUnknown"})),
                                "fixed uncertainty survives enabled error-detail masking"
                            );
                            assert_eq!(
                                error.message,
                                "Task mutation may have committed; its outcome could not be verified. Reconcile Task state before retrying."
                            );
                            assert!(retained.generation() > before.generation());
                            if method == fastmcp_protocol::tasks_extension::TASK_UPDATE {
                                assert!(matches!(retained.task(), ControlTask::Working(_)));
                                assert_eq!(store.updates.load(Ordering::SeqCst), 1);
                                assert_eq!(store.cancellations.load(Ordering::SeqCst), 0);
                            } else {
                                assert!(matches!(retained.task(), ControlTask::Cancelled(_)));
                                assert_eq!(store.updates.load(Ordering::SeqCst), 0);
                                assert_eq!(store.cancellations.load(Ordering::SeqCst), 1);
                            }
                        }
                        assert_eq!(store.synchronous.load(Ordering::SeqCst), 0);
                        assert_eq!(
                            emitted.load(Ordering::SeqCst),
                            0,
                            "late request authority cannot publish callbacks"
                        );

                        // A fresh request may reconcile the record. Neither
                        // cancellation nor the private receipt leaks to it.
                        let (reconciled, _) = async_control_http_rpc(
                            address,
                            async_control_request(fastmcp_protocol::TASK_GET, 82),
                        )
                        .await?;
                        assert!(reconciled.error.is_none(), "{:?}", reconciled.error);
                        let mut expected = serde_json::to_value(retained.task()).unwrap();
                        expected["resultType"] = serde_json::json!("complete");
                        assert_eq!(reconciled.result, Some(expected));
                        Ok::<(), String>(())
                    })
                    .map_err(|error| error.to_string())?;
                let serve = bound.serve(&cx).await;
                let client_result = client
                    .join(&cx)
                    .await
                    .map_err(|error| format!("Task receipt client failed: {error:?}"))?;
                client_result?;
                require_quiescent_http_shutdown(
                    serve.map_err(|error| error.to_string())?,
                    "Task mutation receipt race",
                )
                .await
            },
            0,
        );
    }
}

#[test]
fn live_stdio_task_write_receipt_survives_writer_finalization() {
    for policy in [
        ProtocolPolicy::ModernOnly,
        #[cfg(feature = "legacy-2024-11-05")]
        ProtocolPolicy::Auto,
    ] {
        for method in [
            fastmcp_protocol::tasks_extension::TASK_UPDATE,
            fastmcp_protocol::TASK_CANCEL,
        ] {
            let mut fixture = AsyncControlHttpStore::new();
            // The existing pump harness owns a blocking receive worker. The
            // separate real HTTP tests still require a runtime with no pool.
            fixture.require_no_blocking_pool = false;
            let store = Arc::new(fixture);
            let initial = async_control_input_task();
            let task_id = initial.base().task_id.clone();
            store.seed(initial);
            store.cancel_after_commit.store(true, Ordering::Release);
            let emitted = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&emitted);
            let runtime = FinalTaskRuntime::new(
                store.clone(),
                FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
                Arc::new(move |_| {
                    observed.fetch_add(1, Ordering::SeqCst);
                }),
            );
            let responses = Arc::new(LiveModernResponses::default());
            let observed_responses = Arc::clone(&responses);
            let mut phase = 0;
            let exit_code = run_live_modern_pump(
                Server::new("task-control-writer-receipt", "1")
                    .protocol_policy(policy)
                    .unwrap()
                    .mask_error_details(true)
                    .final_tasks(runtime)
                    .unwrap()
                    .build(),
                move |_cx, _worker_failed| {
                    let current = phase;
                    phase += 1;
                    match current {
                        0 => Ok(modern_discovery_opening_request()),
                        1 => Ok(JsonRpcMessage::Request(async_control_request(method, 91))),
                        2 => {
                            if observed_responses
                                .wait_for_responses(&[91], Duration::from_secs(10))
                            {
                                Ok(JsonRpcMessage::Request(async_control_request(
                                    fastmcp_protocol::TASK_GET,
                                    92,
                                )))
                            } else {
                                Err(TransportError::Timeout)
                            }
                        }
                        3 => {
                            if observed_responses
                                .wait_for_responses(&[91, 92], Duration::from_secs(10))
                            {
                                Err(TransportError::Closed)
                            } else {
                                Err(TransportError::Timeout)
                            }
                        }
                        _ => Err(TransportError::Closed),
                    }
                },
                Arc::clone(&responses),
            );
            assert_eq!(exit_code, 0);
            let retained = store.inner.get_task_snapshot(&task_id).unwrap().unwrap();
            if method == fastmcp_protocol::tasks_extension::TASK_UPDATE {
                assert!(matches!(retained.task(), ControlTask::Working(_)));
                assert_eq!(store.updates.load(Ordering::SeqCst), 1);
                assert_eq!(store.cancellations.load(Ordering::SeqCst), 0);
            } else {
                assert!(matches!(retained.task(), ControlTask::Cancelled(_)));
                assert_eq!(store.updates.load(Ordering::SeqCst), 0);
                assert_eq!(store.cancellations.load(Ordering::SeqCst), 1);
            }
            assert_eq!(store.synchronous.load(Ordering::SeqCst), 0);
            assert_eq!(emitted.load(Ordering::SeqCst), 0);
            assert_eq!(responses.response_count(91), 1);
            let error = responses
                .response(91)
                .expect("the server-owned cancellation still has a usable writer")
                .error
                .expect("the late writer retains explicit mutation uncertainty");
            assert_eq!(
                error.code.as_i32(),
                Some(i32::from(McpErrorCode::InternalError))
            );
            assert_eq!(
                error.data,
                Some(serde_json::json!({"reason": "TaskStateUnknown"}))
            );
            assert_eq!(
                error.message,
                "Task mutation may have committed; its outcome could not be verified. Reconcile Task state before retrying."
            );
            assert_eq!(responses.response_count(92), 1);
            let reconciled = responses
                .response(92)
                .expect("the next request does not inherit the receipt");
            assert!(reconciled.error.is_none(), "{:?}", reconciled.error);
            let mut expected = serde_json::to_value(retained.task()).unwrap();
            expected["resultType"] = serde_json::json!("complete");
            assert_eq!(reconciled.result, Some(expected));
        }
    }
}
