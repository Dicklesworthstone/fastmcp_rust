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
    let builder = ServerBuilder::new("fastmcp-cli-e2e-server", "1.0.0")
        .tool(Echo)
        .tool(SizedOutput)
        .resource(StatusResource)
        .prompt(GreetingPrompt);
    #[cfg(feature = "tasks")]
    let builder = install_task_fixture(builder);
    let server = builder.build();
    #[cfg(feature = "tasks")]
    if let Some(ready_file) = std::env::args().nth(3) {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().expect("HTTP reactor"))
            .blocking_threads(0, 16)
            .build()
            .expect("fixture-owned runtime");
        runtime.block_on(async move {
            let cx = asupersync::Cx::current().expect("fixture caller context");
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
        });
        return;
    }
    server.run_stdio();
}

/// Seed real application-owned state supplied by the test at runtime. All
/// discovery, wire decoding, task controls, and notifications use the shipped
/// framework. This fixture does not claim to exercise application task creation.
#[cfg(feature = "tasks")]
fn install_task_fixture(builder: ServerBuilder) -> ServerBuilder {
    use fastmcp_rust::tasks_extension::{
        Task, TaskStatusNotification, TaskStatusNotificationParams,
    };
    use fastmcp_rust::{
        FinalTaskRuntime, FinalTaskRuntimeConfig, FinalTaskStore, InMemoryFinalTaskStore,
    };
    use std::sync::Arc;

    let Some(path) = std::env::args().nth(1) else {
        return builder;
    };
    let task: Task =
        serde_json::from_slice(&std::fs::read(path).expect("read runtime task fixture"))
            .expect("decode runtime task fixture");
    let store = Arc::new(InMemoryFinalTaskStore::default());
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
    builder
        .final_tasks(runtime)
        .expect("install official Tasks runtime")
        .middleware(TaskErrorExitData(error_output))
        .mask_error_details(false)
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
