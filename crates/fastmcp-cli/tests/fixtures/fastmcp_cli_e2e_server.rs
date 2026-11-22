//! Compiled framework-level server fixture for CLI interoperability tests.

#![recursion_limit = "256"]
#![allow(clippy::needless_pass_by_value)]

use fastmcp_rust::{auto::ServerBuilder, prelude::*};

#[tool]
fn echo(ctx: &McpContext, message: String) -> String {
    ctx.report_progress(0.5, Some(&message));
    message
}

#[tool]
fn sized_output(_ctx: &McpContext, bytes: usize) -> String {
    const MAX_FIXTURE_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
    "x".repeat(bytes.min(MAX_FIXTURE_OUTPUT_BYTES))
}

#[resource(uri = "test://status")]
fn status(_ctx: &McpContext) -> String {
    "ready".to_owned()
}

#[prompt]
fn greeting(_ctx: &McpContext, name: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("Hello, {name}!"),
        },
    }]
}

fn main() {
    #[cfg(any(feature = "tasks", feature = "websocket-experimental"))]
    let websocket_ready = (std::env::args().nth(1).as_deref() == Some("--websocket-ready")).then(|| {
        std::env::args()
            .nth(2)
            .expect("--websocket-ready requires an output path")
    });
    let http_ready = (std::env::args().nth(1).as_deref() == Some("--http-ready")).then(|| {
        std::env::args()
            .nth(2)
            .expect("--http-ready requires an output path")
    });
    let builder = ServerBuilder::new("fastmcp-cli-e2e-server", "1.0.0")
        .tool(Echo)
        .tool(SizedOutput)
        .resource(StatusResource)
        .prompt(GreetingPrompt);
    #[cfg(feature = "websocket-experimental")]
    let builder = if let Some(ready) = websocket_ready.as_ref() {
        builder
            .tool(DelayedEcho)
            .middleware(WebSocketObservations {
                path: std::path::Path::new(ready).with_extension("requests.jsonl"),
            })
    } else {
        builder
    };
    #[cfg(feature = "tasks")]
    let (builder, runner) = if http_ready.is_some() {
        (builder, None)
    } else if websocket_ready.is_some() {
        #[cfg(feature = "websocket-experimental")]
        {
            install_websocket_task_fixture(builder)
        }
        #[cfg(not(feature = "websocket-experimental"))]
        {
            (builder, None)
        }
    } else {
        install_task_fixture(builder)
    };
    let server = builder.build();
    #[cfg(feature = "tasks")]
    let http_ready = http_ready.or_else(|| std::env::args().nth(3));
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().expect("fixture reactor"))
        .blocking_threads(0, 16)
        .build()
        .expect("fixture-owned runtime");
    runtime.block_on(async move {
        let cx = asupersync::Cx::current().expect("fixture caller context");
        #[cfg(feature = "tasks")]
        let _service_task = runner.map(|mut r| {
            cx.spawn(move |task_cx| async move {
                if let Err(error) = r.run_service(&task_cx).await {
                    if !task_cx.is_cancel_requested() {
                        eprintln!("fastmcp_cli_e2e_server task service failed: {error}");
                        std::process::exit(99);
                    }
                }
            })
            .expect("spawn task service runner")
        });
        #[cfg(feature = "websocket-experimental")]
        if let Some(ready_file) = websocket_ready {
            #[cfg(feature = "tasks")]
            {
                let task_runtime = server
                    .final_task_runtime()
                    .expect("WebSocket fixture installs its Task runtime");
                asupersync::time::timeout(cx.now(), std::time::Duration::from_secs(5), async {
                    while !task_runtime.is_task_service_ready() {
                        cx.checkpoint().expect("Task fixture startup was cancelled");
                        asupersync::time::sleep(cx.now(), std::time::Duration::from_millis(10))
                            .await;
                    }
                })
                .await
                .expect("WebSocket Task service must enter its region before readiness");
            }
            let bound = server
                .bind_websocket(&cx, "127.0.0.1:0")
                .await
                .expect("bind real WebSocket server");
            std::fs::write(
                ready_file,
                format!("ws://{}/mcp", bound.local_addr().expect("bound address")),
            )
            .expect("publish runtime-selected WebSocket endpoint");
            if let fastmcp_server::WebSocketServerShutdown::Nonquiescent(shutdown) =
                bound.serve(&cx).await.expect("serve real WebSocket clients")
            {
                shutdown.settle(&cx).await.expect("settle WebSocket children");
            }
            return;
        }
        if let Some(ready_file) = http_ready {
            let bound = server
                .bind_http(&cx, "127.0.0.1:0")
                .await
                .expect("bind real HTTP server");
            std::fs::write(
                ready_file,
                format!("http://{}/mcp", bound.local_addr().expect("bound address")),
            )
            .expect("publish runtime-selected endpoint");
            if let fastmcp_rust::HttpServerShutdown::Nonquiescent(shutdown) =
                bound.serve(&cx).await.expect("serve real HTTP clients")
            {
                shutdown.settle(&cx).await.expect("settle HTTP children");
            }
        } else {
            server.run_stdio_with_cx(&cx).await;
        }
    });
}

#[cfg(feature = "websocket-experimental")]
#[tool]
async fn delayed_echo(ctx: &McpContext, message: String, delay_ms: u64) -> String {
    asupersync::time::sleep(
        ctx.cx().now(),
        std::time::Duration::from_millis(delay_ms.min(10_000)),
    )
    .await;
    message
}

#[cfg(feature = "websocket-experimental")]
struct WebSocketObservations {
    path: std::path::PathBuf,
}

#[cfg(feature = "websocket-experimental")]
impl fastmcp_rust::Middleware for WebSocketObservations {
    fn on_request(
        &self,
        _ctx: &McpContext,
        request: &fastmcp_protocol::JsonRpcRequest,
    ) -> McpResult<fastmcp_rust::MiddlewareDecision> {
        use std::io::Write as _;
        let mut output = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .expect("open public WebSocket request observations");
        writeln!(
            output,
            "{}",
            serde_json::json!({"method": request.method, "id": request.id, "params": request.params}),
        )
        .expect("retain public WebSocket request observation");
        Ok(fastmcp_rust::MiddlewareDecision::Continue)
    }
}

#[cfg(all(feature = "tasks", feature = "websocket-experimental"))]
#[tool(tasks)]
fn background(message: String, is_error: bool, delay_ms: u64) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    Ok(fastmcp_rust::FinalToolOutcome::CreateTask {
        work_descriptor: fastmcp_rust::FinalTaskWorkDescriptor::new(serde_json::json!({
            "message": message, "is_error": is_error, "delay_ms": delay_ms,
        }))?,
        status_message: None,
    })
}

#[cfg(all(feature = "tasks", feature = "websocket-experimental"))]
struct WebSocketTaskSupervisor;

#[cfg(all(feature = "tasks", feature = "websocket-experimental"))]
impl fastmcp_rust::ApplicationTaskSupervisor for WebSocketTaskSupervisor {
    fn resume<'a>(
        &'a self,
        cx: &'a asupersync::Cx,
        handoff: fastmcp_rust::FinalTaskSupervisorHandoff,
    ) -> fastmcp_rust::FinalTaskSupervisorFuture<'a> {
        Box::pin(async move {
            let fastmcp_rust::FinalTaskSupervisorHandoff::Initial(work) = handoff else {
                return Err(McpError::invalid_params("fixture work does not request input"));
            };
            let descriptor = work.work_descriptor().as_value().clone();
            let delay_ms = descriptor["delay_ms"].as_u64().unwrap().min(10_000);
            asupersync::time::sleep(cx.now(), std::time::Duration::from_millis(delay_ms)).await;
            let result = serde_json::from_value(serde_json::json!({
                "content": [{"type": "text", "text": descriptor["message"]}],
                "isError": descriptor["is_error"],
            }))
            .expect("typed fixture task result");
            work.complete_task(result, None)?;
            Ok(())
        })
    }
}

#[cfg(all(feature = "tasks", feature = "websocket-experimental"))]
fn install_websocket_task_fixture(
    builder: ServerBuilder,
) -> (ServerBuilder, Option<fastmcp_rust::AuthorizedTaskServiceRunner>) {
    use std::sync::Arc;
    let runtime = fastmcp_rust::FinalTaskRuntime::new(
        Arc::new(fastmcp_rust::InMemoryFinalTaskStore::default()),
        fastmcp_rust::FinalTaskRuntimeConfig::new(60_000, Some(100)).unwrap(),
        Arc::new(|_| {}),
    );
    let runner = runtime.install_task_service(16, Arc::new(WebSocketTaskSupervisor)).unwrap();
    let builder = builder.tool(Background).final_tasks(runtime).unwrap();
    (builder, Some(runner))
}

#[cfg(feature = "tasks")]
struct FixtureTaskSupervisor {
    dir: std::path::PathBuf,
}

#[cfg(feature = "tasks")]
impl fastmcp_rust::ApplicationTaskSupervisor for FixtureTaskSupervisor {
    fn resume<'a>(
        &'a self,
        cx: &'a asupersync::Cx,
        handoff: fastmcp_rust::FinalTaskSupervisorHandoff,
    ) -> fastmcp_rust::FinalTaskSupervisorFuture<'a> {
        let dir = self.dir.clone();
        Box::pin(async move {
            let complete_marker = dir.join("transition_to_completed");
            let fail_marker = dir.join("transition_to_failed");
            let watch_ready_marker = dir.join("watch_ready");
            loop {
                let cancellation_requested = match &handoff {
                    fastmcp_rust::FinalTaskSupervisorHandoff::Initial(initial) => {
                        initial.is_cancellation_requested()?
                    }
                    fastmcp_rust::FinalTaskSupervisorHandoff::Resumed(accepted) => {
                        accepted.is_cancellation_requested()?
                    }
                };
                if cancellation_requested {
                    match handoff {
                        fastmcp_rust::FinalTaskSupervisorHandoff::Initial(initial) => {
                            initial
                                .honor_cancellation(Some("cancelled by supervisor".to_owned()))?;
                        }
                        fastmcp_rust::FinalTaskSupervisorHandoff::Resumed(accepted) => {
                            accepted
                                .honor_cancellation(Some("cancelled by supervisor".to_owned()))?;
                        }
                    }
                    return Ok(());
                }
                let is_initial = matches!(
                    &handoff,
                    fastmcp_rust::FinalTaskSupervisorHandoff::Initial(_)
                );
                if !is_initial || watch_ready_marker.exists() {
                    if complete_marker.exists() {
                        let result: fastmcp_rust::FinalTaskCallToolResult =
                            serde_json::from_value(serde_json::json!({"content": []}))
                                .expect("valid task result");
                        match handoff {
                            fastmcp_rust::FinalTaskSupervisorHandoff::Initial(initial) => {
                                initial.complete_task(
                                    result,
                                    Some("completed by supervisor".to_owned()),
                                )?;
                            }
                            fastmcp_rust::FinalTaskSupervisorHandoff::Resumed(accepted) => {
                                accepted.complete_task(
                                    result,
                                    Some("completed by supervisor".to_owned()),
                                )?;
                            }
                        }
                        return Ok(());
                    }
                    if fail_marker.exists() {
                        let error: fastmcp_rust::FinalTaskError =
                            serde_json::from_value(serde_json::json!({
                                "code": -32603,
                                "message": "failed by supervisor",
                            }))
                            .expect("valid task error");
                        match handoff {
                            fastmcp_rust::FinalTaskSupervisorHandoff::Initial(initial) => {
                                initial
                                    .fail_task(error, Some("failed by supervisor".to_owned()))?;
                            }
                            fastmcp_rust::FinalTaskSupervisorHandoff::Resumed(accepted) => {
                                accepted
                                    .fail_task(error, Some("failed by supervisor".to_owned()))?;
                            }
                        }
                        return Ok(());
                    }
                }
                cx.checkpoint()
                    .map_err(|_| fastmcp_core::McpError::request_cancelled())?;
                asupersync::time::sleep(cx.now(), std::time::Duration::from_millis(20)).await;
            }
        })
    }
}

/// Seed real application-owned state supplied by the test at runtime. All
/// discovery, wire decoding, task controls, and notifications use the shipped
/// framework. This fixture does not claim to exercise application task creation.
#[cfg(feature = "tasks")]
fn install_task_fixture(
    builder: ServerBuilder,
) -> (
    ServerBuilder,
    Option<fastmcp_rust::AuthorizedTaskServiceRunner>,
) {
    use fastmcp_rust::tasks_extension::{
        Task, TaskStatusNotification, TaskStatusNotificationParams,
    };
    use fastmcp_rust::{
        FinalTaskRuntime, FinalTaskRuntimeConfig, FinalTaskStore, InMemoryFinalTaskStore,
    };
    use std::sync::Arc;

    let Some(path) = std::env::args().nth(1) else {
        return (builder, None);
    };
    let dir = std::path::Path::new(&path)
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let task: Task =
        serde_json::from_slice(&std::fs::read(&path).expect("read runtime task fixture"))
            .expect("decode runtime task fixture");
    let task_id = task.base().task_id.clone();
    let watch_gap = dir.join("watch_gap").exists().then(|| dir.clone());
    let store = Arc::new(InMemoryFinalTaskStore::default());
    let supervisor_requested =
        dir.join("transition_to_completed").exists() || dir.join("transition_to_failed").exists();
    if supervisor_requested && matches!(task, Task::Working(_) | Task::InputRequired { .. }) {
        // Seed the originating work before projecting a persisted input wait.
        // A resumed handoff must retain that descriptor; a bare InputRequired
        // record cannot supply application work to the real service runner.
        let mut initial_base = task.base().clone();
        initial_base.status = fastmcp_rust::tasks_extension::TaskStatus::Working;
        let initial_task = Task::Working(initial_base);
        store
            .create_task_with_work(
                initial_task.clone(),
                TaskStatusNotification::new(TaskStatusNotificationParams {
                    task: initial_task,
                    meta: None,
                    additional: std::collections::BTreeMap::new(),
                }),
                fastmcp_rust::FinalTaskWorkDescriptor::new(serde_json::json!({}))
                    .expect("valid fixture work descriptor"),
            )
            .expect("seed real task store with work");
        if matches!(task, Task::InputRequired { .. }) {
            store
                .replace_task(
                    task.clone(),
                    TaskStatusNotification::new(TaskStatusNotificationParams {
                        task,
                        meta: None,
                        additional: std::collections::BTreeMap::new(),
                    }),
                )
                .expect("persist input wait while retaining the originating work");
        }
    } else {
        store
            .create_task(
                task.clone(),
                TaskStatusNotification::new(TaskStatusNotificationParams {
                    task,
                    meta: None,
                    additional: std::collections::BTreeMap::new(),
                }),
            )
            .expect("seed real task store");
    }
    let state_output = std::env::args().nth(2);
    // Peer-error observations must not overwrite the task-transition evidence.
    let error_output = state_output
        .as_ref()
        .map(|path| std::path::Path::new(path).with_extension("error.json"));
    let runtime = FinalTaskRuntime::new(
        store.clone(),
        FinalTaskRuntimeConfig::new(60_000, Some(100)).expect("task retention policy"),
        Arc::new(move |notification| {
            if let Some(path) = &state_output {
                std::fs::write(
                    path,
                    serde_json::to_vec(&notification.params.task).expect("encode changed task"),
                )
                .expect("retain observed task transition");
            }
        }),
    );
    let runner = if supervisor_requested {
        Some(
            runtime
                .install_task_service(16, Arc::new(FixtureTaskSupervisor { dir }))
                .expect("install fixture task service"),
        )
    } else {
        None
    };
    let builder = builder
        .final_tasks(runtime)
        .expect("install official Tasks runtime")
        .middleware(TaskErrorExitData {
            error_output,
            watch_gap,
            store,
            task_id,
            reads: std::sync::atomic::AtomicUsize::new(0),
            first_read_instant: std::sync::Mutex::new(None),
        })
        .mask_error_details(false);
    (builder, runner)
}

#[cfg(feature = "tasks")]
struct TaskErrorExitData {
    error_output: Option<std::path::PathBuf>,
    watch_gap: Option<std::path::PathBuf>,
    store: std::sync::Arc<fastmcp_rust::InMemoryFinalTaskStore>,
    task_id: fastmcp_rust::FinalTaskId,
    reads: std::sync::atomic::AtomicUsize,
    first_read_instant: std::sync::Mutex<Option<std::time::Instant>>,
}

#[cfg(feature = "tasks")]
impl fastmcp_rust::Middleware for TaskErrorExitData {
    fn on_request(
        &self,
        _ctx: &McpContext,
        request: &fastmcp_protocol::JsonRpcRequest,
    ) -> McpResult<fastmcp_rust::MiddlewareDecision> {
        use fastmcp_rust::FinalTaskStore;
        use fastmcp_rust::tasks_extension::{
            Task, TaskStatus, TaskStatusNotification, TaskStatusNotificationParams,
        };
        use std::sync::atomic::Ordering;

        if let Some(dir) = &self.watch_gap {
            if request.method == "tasks/get" {
                let reads = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
                std::fs::write(dir.join("watch_gap_reads"), reads.to_string())
                    .expect("retain real task read count");
                if reads == 1 {
                    if let Ok(delay_str) =
                        std::fs::read_to_string(dir.join("initial_read_delay_ms"))
                    {
                        if let Ok(ms) = delay_str.trim().parse::<u64>() {
                            std::thread::sleep(std::time::Duration::from_millis(ms));
                        }
                    }
                }
                let mut first = self.first_read_instant.lock().unwrap();
                if let Some(first_instant) = *first {
                    let elapsed_ms = first_instant.elapsed().as_millis();
                    std::fs::write(
                        dir.join("watch_gap_read_interval_ms"),
                        elapsed_ms.to_string(),
                    )
                    .expect("retain real task read interval");
                } else {
                    *first = Some(std::time::Instant::now());
                }
            } else if request.method == "subscriptions/listen" {
                assert_eq!(self.reads.load(Ordering::SeqCst), 1);
                let task = self
                    .store
                    .get_task(&self.task_id)?
                    .expect("task retained before listener admission");
                assert!(matches!(task, Task::Working(_)));
                let scenario = std::fs::read_to_string(dir.join("watch_gap"))
                    .expect("read runtime-selected gap scenario");
                let after = if scenario == "complete" {
                    let mut base = task.base().clone();
                    base.status = TaskStatus::Completed;
                    let completed = Task::Completed {
                        base,
                        result: serde_json::from_value(serde_json::json!({
                            "content": [{"type": "text", "text": "completed before listen"}]
                        }))
                        .expect("typed completed result"),
                    };
                    self.store.replace_task(
                        completed.clone(),
                        TaskStatusNotification::new(TaskStatusNotificationParams {
                            task: completed.clone(),
                            meta: None,
                            additional: std::collections::BTreeMap::new(),
                        }),
                    )?;
                    completed
                } else if scenario == "changed" {
                    let mut base = task.base().clone();
                    base.status_message = Some("reconciled working snapshot".to_owned());
                    let changed = Task::Working(base);
                    self.store.replace_task(
                        changed.clone(),
                        TaskStatusNotification::new(TaskStatusNotificationParams {
                            task: changed.clone(),
                            meta: None,
                            additional: std::collections::BTreeMap::new(),
                        }),
                    )?;
                    changed
                } else {
                    task
                };
                std::fs::write(
                    dir.join("watch_gap_state"),
                    serde_json::to_vec(&after).expect("encode state at listener admission"),
                )
                .expect("retain state at listener admission");
            }
        }
        Ok(fastmcp_rust::MiddlewareDecision::Continue)
    }

    fn on_error(
        &self,
        _ctx: &McpContext,
        request: &fastmcp_protocol::JsonRpcRequest,
        mut error: McpError,
    ) -> McpError {
        if request.method == "tasks/get" {
            error.data = Some(serde_json::json!({"exit_code": 0}));
            if let Some(path) = &self.error_output {
                std::fs::write(path, serde_json::to_vec(&error).expect("encode peer error"))
                    .expect("retain peer error observation");
            }
        }
        error
    }
}
