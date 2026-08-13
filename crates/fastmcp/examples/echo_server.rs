//! Example: Echo Server
//!
//! A simple MCP server demonstrating tools, resources, and prompts.
//!
//! Run with:
//! ```bash
//! cargo run -p fastmcp-rust --example echo_server
//! ```
//!
//! Test with MCP Inspector:
//! ```bash
//! npx @modelcontextprotocol/inspector cargo run -p fastmcp-rust --example echo_server
//! ```

// MCP handlers receive String from JSON deserialization, so this is intentional.
#![allow(clippy::needless_pass_by_value)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fastmcp_rust::modern::{FinalMethodOutcome, MrtrCompletedInputs};
use fastmcp_rust::prelude::*;
use fastmcp_rust::{
    ApplicationTaskSupervisor, AuthorizedTaskServiceRunner, CacheScope, EmbeddedResourceContents,
    FinalAbsoluteUri, FinalCompletionParams, FinalCompletionReference, FinalCompletionValues,
    FinalPromptMessage, FinalTaskInputRequests, FinalTaskRuntime, FinalTaskRuntimeConfig,
    FinalTaskSupervisorFuture, FinalTaskSupervisorHandoff, FinalTaskWorkDescriptor,
    FinalToolOutcome, InputRequiredResult, ResultMeta, StdioTransport, ToolHandler,
};
use fastmcp_server::ServerBuilder;

// ============================================================================
// Tools
// ============================================================================

/// Echo the input message back.
#[tool]
fn echo(ctx: &McpContext, message: String) -> String {
    // Check for cancellation (optional but recommended)
    if ctx.is_cancelled() {
        return "Cancelled".to_string();
    }
    message
}

/// Add two numbers together.
#[tool(description = "Calculate the sum of two numbers")]
fn add(_ctx: &McpContext, a: i64, b: i64) -> String {
    format!("{}", a + b)
}

/// Reverse a string.
#[tool]
fn reverse(_ctx: &McpContext, text: String) -> String {
    text.chars().rev().collect()
}

/// Count words in text.
#[tool(name = "word_count", description = "Count the number of words in text")]
fn count_words(_ctx: &McpContext, text: String) -> String {
    let count = text.split_whitespace().count();
    format!("{count}")
}

/// Returns the first filesystem root exposed by the connected client.
#[tool]
async fn client_root_uri(ctx: &McpContext) -> McpResult<String> {
    let roots = ctx.list_roots().await?;
    Ok(roots
        .first()
        .map(|root| root.uri.clone())
        .unwrap_or_else(|| "<no client roots>".to_string()))
}

// ============================================================================
// Resources
// ============================================================================

/// Returns server information.
#[resource(uri = "info://server")]
fn server_info(_ctx: &McpContext) -> String {
    r#"{
    "name": "echo-server",
    "version": "1.0.0",
    "description": "A simple example MCP server"
}"#
    .to_string()
}

/// Returns current timestamp.
#[resource(
    uri = "info://time",
    name = "Current Time",
    description = "Returns the current Unix timestamp"
)]
fn current_time(_ctx: &McpContext) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{timestamp}")
}

fn mrtr_roots_input_required(
    keys: impl IntoIterator<Item = String>,
) -> McpResult<InputRequiredResult> {
    let mut input_requests = serde_json::Map::new();
    for key in keys {
        input_requests.insert(key, serde_json::json!({"method": "roots/list"}));
    }
    let exact_input_requests =
        fastmcp_rust::exact_json_from_serde(&serde_json::Value::Object(input_requests))
            .map_err(|error| McpError::invalid_params(error.to_string()))?;
    let fastmcp_rust::ExactJsonValue::Object(exact_input_requests) = exact_input_requests else {
        return Err(McpError::internal_error(
            "MRTR input requests must encode as an object",
        ));
    };
    InputRequiredResult::new(Some(exact_input_requests), None, ResultMeta::empty())
        .map_err(|error| McpError::invalid_params(error.to_string()))
}

fn completed_mrtr_roots_len(completed_inputs: &MrtrCompletedInputs, key: &str) -> McpResult<usize> {
    completed_inputs
        .roots(key)?
        .map(|roots| roots.roots.len())
        .ok_or_else(|| McpError::internal_error("MRTR roots input was not preserved"))
}

fn mrtr_resource_complete(roots_len: usize) -> CompleteResult<FinalReadResourceResult> {
    CompleteResult::new(
        FinalReadResourceResult {
            contents: vec![EmbeddedResourceContents::Text {
                uri: FinalAbsoluteUri::parse("info://mrtr-resource/result")
                    .expect("the shipped MRTR resource URI is absolute"),
                text: format!("typed resource roots={roots_len}"),
                mime_type: Some("text/plain".to_owned()),
                meta: None,
                additional: BTreeMap::new(),
            }],
            ttl_ms: CacheTtl::milliseconds(7),
            cache_scope: CacheScope::Private,
        },
        ResultMeta::empty(),
    )
}

/// Requires one typed embedded roots result before returning a final resource.
/// A sentinel root asks for another round so the public client can prove its
/// continuation bound without changing server configuration.
#[resource(uri = "info://mrtr-resource")]
fn mrtr_resource(
    completed_inputs: Option<&MrtrCompletedInputs>,
) -> McpResult<FinalMethodOutcome<FinalReadResourceResult>> {
    let Some(completed_inputs) = completed_inputs else {
        return Ok(FinalMethodOutcome::InputRequired(
            mrtr_roots_input_required(["roots".to_owned()])?,
        ));
    };
    let roots_len = completed_mrtr_roots_len(completed_inputs, "roots")?;
    let repeats = completed_inputs
        .roots("roots")?
        .expect("the checked MRTR roots result remains available")
        .roots
        .iter()
        .any(|root| root.uri == "file:///mrtr/retry");
    if repeats {
        return Ok(FinalMethodOutcome::InputRequired(
            mrtr_roots_input_required(["roots".to_owned()])?,
        ));
    }
    Ok(FinalMethodOutcome::Complete(mrtr_resource_complete(
        roots_len,
    )))
}

// ============================================================================
// Prompts
// ============================================================================

/// A simple greeting prompt.
#[prompt(description = "Generate a friendly greeting")]
fn greeting(_ctx: &McpContext, name: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("Please greet {name} in a friendly way."),
        },
    }]
}

/// A code review prompt.
#[prompt(name = "review_code")]
fn code_review_prompt(_ctx: &McpContext, code: String, language: String) -> Vec<PromptMessage> {
    let lang_hint = if language.is_empty() {
        String::new()
    } else {
        format!(" (written in {language})")
    };

    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!(
                "Please review the following code{lang_hint} and provide feedback:\n\n```\n{code}\n```"
            ),
        },
    }]
}

fn mrtr_prompt_complete(roots_len: usize) -> CompleteResult<FinalGetPromptResult> {
    CompleteResult::new(
        FinalGetPromptResult {
            description: Some("typed MRTR prompt result".to_owned()),
            messages: vec![FinalPromptMessage {
                role: Role::Assistant,
                content: ContentBlock::Text {
                    text: format!("typed prompt roots={roots_len}"),
                    annotations: None,
                    meta: None,
                    additional: BTreeMap::new(),
                },
            }],
        },
        ResultMeta::empty(),
    )
}

/// Uses a terminal mode for the exact typed-result proof and bounded modes
/// for public client cancellation, round, and total-input guards.
#[prompt(name = "mrtr_prompt")]
fn mrtr_prompt(
    completed_inputs: Option<&MrtrCompletedInputs>,
    mode: String,
) -> McpResult<FinalMethodOutcome<FinalGetPromptResult>> {
    let keys = match mode.as_str() {
        "terminal" | "round-bound" => vec!["roots".to_owned()],
        "input-bound" => (0..128).map(|index| format!("roots-{index}")).collect(),
        _ => return Err(McpError::invalid_params("unknown MRTR prompt mode")),
    };

    if let Some(completed_inputs) = completed_inputs {
        match mode.as_str() {
            "terminal" => {
                return Ok(FinalMethodOutcome::Complete(mrtr_prompt_complete(
                    completed_mrtr_roots_len(completed_inputs, "roots")?,
                )));
            }
            "round-bound" => {
                completed_mrtr_roots_len(completed_inputs, "roots")?;
            }
            "input-bound" => {
                for key in &keys {
                    completed_mrtr_roots_len(completed_inputs, key)?;
                }
            }
            _ => unreachable!("the mode was admitted above"),
        }
    }

    Ok(FinalMethodOutcome::InputRequired(
        mrtr_roots_input_required(keys)?,
    ))
}

// ============================================================================
// Completion
// ============================================================================

static GREETING_COMPLETION_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Completion provider for the public modern stdio integration path.
struct GreetingCompletion;

impl CompletionHandler for GreetingCompletion {
    fn complete_legacy(
        &self,
        _ctx: &McpContext,
        _params: fastmcp_rust::legacy_2024::LegacyCompletionParams,
    ) -> McpResult<fastmcp_rust::legacy_2024::CompletionValues> {
        Ok(fastmcp_rust::legacy_2024::CompletionValues {
            values: vec!["stdio-completion-legacy".to_owned()],
            total: Some(1),
            has_more: Some(false),
        })
    }

    fn complete_final(
        &self,
        _ctx: &McpContext,
        params: FinalCompletionParams,
    ) -> McpResult<FinalCompletionValues> {
        let call_count = GREETING_COMPLETION_CALLS.fetch_add(1, Ordering::SeqCst) + 1;
        if !matches!(
            &params.reference,
            FinalCompletionReference::PromptWithTitle { name, title }
                if name == "greeting" && title == "Greeting"
        ) || params.argument.name != "name"
            || params.argument.value != "co"
            || params
                .context
                .as_ref()
                .and_then(|context| context.arguments.as_ref())
                .and_then(|arguments| arguments.get("locale"))
                .map(String::as_str)
                != Some("en-US")
        {
            return Err(McpError::invalid_params(
                "greeting completion requires the exact modern request shape",
            ));
        }

        Ok(FinalCompletionValues {
            values: vec![format!("stdio-completion-{call_count}")],
            total: Some(JsonInteger::from(
                u64::try_from(call_count).expect("the process-local call counter fits in u64"),
            )),
            has_more: Some(false),
        })
    }
}

// ============================================================================
// Caller-owned Tasks service
// ============================================================================

static DURABLE_TASK_TOOL_CALLS: AtomicUsize = AtomicUsize::new(0);

/// A task-capable tool whose durable work is advanced by the embedding-owned
/// service below. Its exact-2024 implementation remains an ordinary tool.
struct DurableTaskTool;

impl ToolHandler for DurableTaskTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "durable_task".to_owned(),
            description: Some("Creates one caller-supervised modern Task".to_owned()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text("exact-2024 Tasks are unavailable")])
    }

    fn declares_final_tasks(&self) -> bool {
        true
    }

    fn call_final_outcome(
        &self,
        _ctx: &McpContext,
        _arguments: serde_json::Value,
    ) -> McpResult<FinalToolOutcome> {
        let call = DURABLE_TASK_TOOL_CALLS.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(FinalToolOutcome::CreateTask {
            work_descriptor: FinalTaskWorkDescriptor::new(serde_json::json!({
                "operation": "echo-stdio-durable-task",
                "call": call,
            }))?,
            status_message: Some(format!("durable stdio task call {call}")),
        })
    }
}

/// Advances initial Task work to `input_required`, then waits for caller
/// input or cancellation. The framework never creates this service or its
/// runtime; the embedding owns both in `run_tasks_stdio`.
struct DurableTaskSupervisor;

impl ApplicationTaskSupervisor for DurableTaskSupervisor {
    fn resume<'a>(
        &'a self,
        cx: &'a Cx,
        handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a> {
        Box::pin(async move {
            match handoff {
                FinalTaskSupervisorHandoff::Initial(initial) => {
                    let requests: FinalTaskInputRequests = serde_json::from_value(
                        serde_json::json!({"roots": {"method": "roots/list"}}),
                    )
                    .map_err(|_| McpError::internal_error("Task input descriptor is invalid"))?;
                    initial.require_input(
                        requests,
                        Some("awaiting roots from the caller-owned stdio service".to_owned()),
                    )?;
                }
                FinalTaskSupervisorHandoff::Resumed(accepted) => loop {
                    if accepted.is_cancellation_requested()? {
                        accepted.honor_cancellation(Some(
                            "cancelled by the caller-owned stdio service".to_owned(),
                        ))?;
                        break;
                    }
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                },
            }
            Ok(())
        })
    }
}

const TASK_SERVICE_STARTUP_BOUND: Duration = Duration::from_secs(2);
const TASK_SERVICE_SETTLEMENT_BOUND: Duration = Duration::from_secs(4);

async fn run_tasks_stdio(
    server: fastmcp_server::Server,
    runtime: FinalTaskRuntime,
    runner: AuthorizedTaskServiceRunner,
    cx: &Cx,
) -> McpResult<()> {
    let mut service = cx
        .spawn(move |service_cx| async move { runner.run(&service_cx).await })
        .map_err(|error| {
            McpError::internal_error(format!("Task service admission failed: {error}"))
        })?;
    let readiness_deadline = cx.now() + TASK_SERVICE_STARTUP_BOUND;
    while !runtime.is_task_service_ready() {
        if service.is_finished() {
            return Err(McpError::internal_error(
                "Caller-owned Task service stopped before publishing readiness",
            ));
        }
        asupersync::time::timeout_at(
            readiness_deadline,
            asupersync::time::sleep(cx.now(), Duration::from_millis(1)),
        )
        .await
        .map_err(|_| {
            McpError::internal_error("Caller-owned Task service did not become ready within bound")
        })?;
    }

    let mut stdio = cx
        .spawn_blocking(move |stdio_cx| {
            server.run_transport_returning_with_cx(&stdio_cx, StdioTransport::stdio())
        })
        .map_err(|error| {
            McpError::internal_error(format!("stdio service admission failed: {error}"))
        })?;
    let server_result = stdio.join(cx).await.map_err(|error| {
        McpError::internal_error(format!("stdio service join failed: {error:?}"))
    })?;

    service.abort();
    match asupersync::time::timeout(cx.now(), TASK_SERVICE_SETTLEMENT_BOUND, service.join(cx)).await
    {
        Ok(Ok(result)) => result?,
        Ok(Err(asupersync::runtime::JoinError::Cancelled(_))) => {}
        Ok(Err(error)) => {
            return Err(McpError::internal_error(format!(
                "Task service join failed: {error:?}"
            )));
        }
        Err(_) => {
            return Err(McpError::internal_error(
                "Task service did not settle within bound",
            ));
        }
    }
    server_result
}

async fn run_stdio(server: fastmcp_server::Server, cx: &Cx) -> McpResult<()> {
    let mut stdio = cx
        .spawn_blocking(move |stdio_cx| {
            server.run_transport_returning_with_cx(&stdio_cx, StdioTransport::stdio())
        })
        .map_err(|error| {
            McpError::internal_error(format!("stdio service admission failed: {error}"))
        })?;
    stdio.join(cx).await.map_err(|error| {
        McpError::internal_error(format!("stdio service join failed: {error:?}"))
    })?
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let task_runtime = FinalTaskRuntime::in_memory_with_capacity(
        1,
        FinalTaskRuntimeConfig::new(60_000, Some(1_000))
            .expect("the example Task retention policy is finite"),
        std::sync::Arc::new(|_| {}),
    )
    .expect("the example Task store has a positive capacity");
    let task_runner = task_runtime
        .install_task_service(1, std::sync::Arc::new(DurableTaskSupervisor))
        .expect("the caller-owned example Task service installs once");

    let server = ServerBuilder::new("echo-server", "1.0.0")
        // Register tools
        .tool(Echo)
        .tool(Add)
        .tool(Reverse)
        .tool(CountWords)
        .tool(ClientRootUri)
        // Register resources
        .resource(ServerInfoResource)
        .resource(CurrentTimeResource)
        .resource(MrtrResourceResource)
        // Register prompts
        .prompt(GreetingPrompt)
        .prompt(CodeReviewPromptPrompt)
        .prompt(MrtrPromptPrompt)
        .prompt_completion_handler("greeting", GreetingCompletion)
        // Set timeout (30 seconds per request)
        .request_timeout(30)
        // Set server instructions
        .instructions(
            "A simple echo server for testing FastMCP. Try calling the 'echo' tool with a message!",
        )
        .tool(DurableTaskTool)
        .final_tasks(task_runtime.clone())
        .expect("the official Tasks extension installs on the modern-capable example server")
        .build();
    let protocol_policy = server.protocol_policy();

    let application_runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(
            asupersync::runtime::reactor::create_reactor()
                .expect("the example caller runtime reactor initializes"),
        )
        .blocking_threads(4, 64)
        .build()
        .expect("the example caller runtime initializes");
    application_runtime
        .block_on(async move {
            let cx = Cx::current().expect("the example caller runtime installs its Cx");
            match protocol_policy {
                // The component builder read FASTMCP_PROTOCOL_POLICY before
                // registration. Exact 2024 gets no Task service and its
                // dispatch remains blind to the modern Tasks extension.
                ProtocolPolicy::LegacyOnly => run_stdio(server, &cx).await,
                ProtocolPolicy::Auto | ProtocolPolicy::ModernOnly => {
                    run_tasks_stdio(server, task_runtime, task_runner, &cx).await
                }
            }
        })
        .expect("the caller-owned stdio server and Task service settle cleanly");
}
