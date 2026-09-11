//! Compiled framework-level server fixture for CLI interoperability tests.

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
    #[cfg(feature = "tasks")]
    let (builder, runner) = if http_ready.is_some() {
        (builder, None)
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
                                initial.fail_task(error, Some("failed by supervisor".to_owned()))?;
                            }
                            fastmcp_rust::FinalTaskSupervisorHandoff::Resumed(accepted) => {
                                accepted.fail_task(error, Some("failed by supervisor".to_owned()))?;
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
    let store = Arc::new(InMemoryFinalTaskStore::default());
    let supervisor_requested =
        dir.join("transition_to_completed").exists() || dir.join("transition_to_failed").exists();
    if matches!(task, Task::Working(_)) && supervisor_requested {
        store
            .create_task_with_work(
                task.clone(),
                TaskStatusNotification::new(TaskStatusNotificationParams {
                    task,
                    meta: None,
                    additional: std::collections::BTreeMap::new(),
                }),
                fastmcp_rust::FinalTaskWorkDescriptor::new(serde_json::json!({})),
            )
            .expect("seed real task store with work");
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
    let error_output = state_output.clone();
    let runtime = FinalTaskRuntime::new(
        store,
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
        .middleware(TaskErrorExitData(error_output))
        .mask_error_details(false);
    (builder, runner)
}

#[cfg(feature = "tasks")]
struct TaskErrorExitData(Option<String>);

#[cfg(feature = "tasks")]
impl fastmcp_rust::Middleware for TaskErrorExitData {
    fn on_error(
        &self,
        _ctx: &McpContext,
        request: &fastmcp_protocol::JsonRpcRequest,
        mut error: McpError,
    ) -> McpError {
        if request.method == "tasks/get" {
            error.data = Some(serde_json::json!({"exit_code": 0}));
            if let Some(path) = &self.0 {
                std::fs::write(path, serde_json::to_vec(&error).expect("encode peer error"))
                    .expect("retain peer error observation");
            }
        }
        error
    }
}
