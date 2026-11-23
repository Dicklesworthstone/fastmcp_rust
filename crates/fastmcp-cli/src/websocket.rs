//! Explicit ModernOnly WebSocket CLI operations on the native client.
//!
//! Upgrade, discovery and every request share the command's original budget.
//! The connection remains owned until explicit close, including when a request
//! times out. No connection reconnect or application replay is part of this path.

use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::net::TcpStream;
use asupersync::tls::TlsStream;
use fastmcp_client::WebSocketClient;
use fastmcp_core::{McpError, McpRequestCancellation};
use fastmcp_protocol::CoreResult;
use fastmcp_transport::websocket::AsyncWsClientTransport;

use super::*;

pub(super) enum Connection {
    Plain(Box<WebSocketClient<TcpStream>>),
    Tls(Box<WebSocketClient<TlsStream<TcpStream>>>),
}

impl Connection {
    async fn connect(cx: &Cx, url: &str, budget: OperationBudget) -> McpResult<Self> {
        let remaining = budget.remaining(cx)?;
        let policy = OperationBudget::request_policy(remaining)?;
        asupersync::time::timeout(
            cx.now(),
            remaining,
            Box::pin(Self::connect_with_policy(cx, url, policy)),
        )
        .await
        .map_err(|_| OperationBudget::timeout_error())?
    }

    // The caller owns the single setup deadline so it can retain typed local
    // timeout provenance without inspecting any peer-controlled McpError data.
    async fn connect_with_policy(
        cx: &Cx,
        url: &str,
        policy: fastmcp_client::RequestTimeoutPolicy,
    ) -> McpResult<Self> {
        if url.len() > 8192
            || url.chars().any(char::is_control)
            || !(url.starts_with("ws://") || url.starts_with("wss://"))
        {
            return Err(McpError::invalid_params(
                "--websocket-url must be a ws:// or wss:// URL of at most 8192 bytes",
            ));
        }
        // Validate before opening any socket; never include a URL or parser
        // error in diagnostics because its path/query may contain secrets.
        let endpoint = asupersync::net::websocket::WsUrl::parse(url).map_err(|_| {
            McpError::invalid_params("--websocket-url must be a valid ws:// or wss:// URL")
        })?;
        if endpoint.tls {
            let transport = AsyncWsClientTransport::connect_wss(cx, url)
                .await
                .map_err(|_| {
                    McpError::internal_error("could not establish the TLS WebSocket transport")
                })?;
            Ok(Self::Tls(Box::new(
                connect_client(cx, transport, policy).await?,
            )))
        } else {
            let transport = AsyncWsClientTransport::connect(cx, url)
                .await
                .map_err(|_| McpError::internal_error("could not establish the WebSocket transport"))?;
            Ok(Self::Plain(Box::new(
                connect_client(cx, transport, policy).await?,
            )))
        }
    }

    fn session(&self) -> &fastmcp_client::ClientSession {
        match self {
            Self::Plain(client) => client.session(),
            Self::Tls(client) => client.session(),
        }
    }

    async fn close(&mut self, cx: &Cx) -> McpResult<()> {
        match self {
            Self::Plain(client) => client.close(cx).await,
            Self::Tls(client) => client.close(cx).await,
        }
        .map_err(|error| operation_failure(error, "WebSocket connection cleanup failed"))
    }

    pub(super) async fn page(
        &mut self,
        cx: &Cx,
        method: &'static str,
        parameters: serde_json::Value,
    ) -> McpResult<CoreResult> {
        match self {
            Self::Plain(client) => {
                client.clear_final_result_cache();
                Box::pin(client.list_catalog_page(cx, method, parameters)).await
            }
            Self::Tls(client) => {
                client.clear_final_result_cache();
                Box::pin(client.list_catalog_page(cx, method, parameters)).await
            }
        }
        .map_err(|error| operation_failure(error, "WebSocket catalog request failed"))
    }
}

async fn connect_client<IO>(
    cx: &Cx,
    transport: AsyncWsClientTransport<IO>,
    policy: fastmcp_client::RequestTimeoutPolicy,
) -> McpResult<WebSocketClient<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Box::pin(
        ClientBuilder::new()
            .protocol_plan(ClientProtocolPlan::websocket(ProtocolPolicy::ModernOnly))
            .request_timeout_policy(policy)
            .connect_websocket_with_cx(cx, transport),
    )
    .await
    .map_err(|error| operation_failure(error, "WebSocket MCP discovery failed"))
}

pub(super) async fn operation(
    cx: &Cx,
    url: &str,
    connection: &OperationConnection,
    operation: CoreOperation<'_>,
    parameters: serde_json::Value,
    budget: OperationBudget,
    wait: bool,
) -> McpResult<Option<CoreResult>> {
    let mut client = Connection::connect(cx, url, budget).await?;
    let acquisition = match &mut client {
        Connection::Plain(client) => {
            Box::pin(execute(
                cx, client, connection, operation, parameters, budget, wait,
            ))
            .await
        }
        Connection::Tls(client) => {
            Box::pin(execute(
                cx, client, connection, operation, parameters, budget, wait,
            ))
            .await
        }
    };
    finish_inspect_acquisition_async(acquisition, client.close(cx)).await
}

async fn execute<IO>(
    cx: &Cx,
    client: &mut WebSocketClient<IO>,
    connection: &OperationConnection,
    operation: CoreOperation<'_>,
    parameters: serde_json::Value,
    budget: OperationBudget,
    wait: bool,
) -> McpResult<Option<CoreResult>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let cancellation = McpRequestCancellation::new();
    #[cfg(feature = "tasks")]
    if wait {
        return waiting_tool_call(cx, client, connection, parameters, budget, &cancellation).await;
    }
    #[cfg(not(feature = "tasks"))]
    {
        let _ = connection;
        debug_assert!(!wait);
    }
    let request = async {
        match operation {
            CoreOperation::Call(name) => {
                client
                    .call_tool_with_cancellation(
                        cx,
                        &cancellation,
                        name,
                        parameters
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({})),
                    )
                    .await
            }
            CoreOperation::Read(uri) => {
                client
                    .read_resource_with_cancellation(cx, &cancellation, uri)
                    .await
            }
            CoreOperation::Prompt(name) => {
                let arguments = parameters
                    .get("arguments")
                    .cloned()
                    .map(serde_json::from_value::<HashMap<String, String>>)
                    .transpose()
                    .map_err(|_| McpError::invalid_params("prompt arguments must contain strings"))?
                    .unwrap_or_default();
                client
                    .get_prompt_with_cancellation(cx, &cancellation, name, arguments)
                    .await
            }
        }
    };
    asupersync::time::timeout(cx.now(), budget.remaining(cx)?, Box::pin(request))
        .await
        .map_err(|_| OperationBudget::timeout_error())?
        .map(Some)
        .map_err(|error| {
            operation_failure(error, "MCP WebSocket request failed; no action was retried")
        })
}

#[cfg(feature = "tasks")]
async fn waiting_tool_call<IO>(
    cx: &Cx,
    client: &mut WebSocketClient<IO>,
    connection: &OperationConnection,
    parameters: serde_json::Value,
    budget: OperationBudget,
    cancellation: &McpRequestCancellation,
) -> McpResult<Option<CoreResult>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let name = parameters
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| McpError::invalid_params("task observation requires a tool name"))?;
    let arguments = parameters
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let created = asupersync::time::timeout(
        cx.now(),
        budget.remaining(cx)?,
        Box::pin(client.call_tool_final_outcome_with_cancellation(
            cx,
            cancellation,
            name,
            arguments,
        )),
    )
    .await
    .map_err(|_| OperationBudget::timeout_error())?
    .map_err(|error| {
        operation_failure(error, "MCP WebSocket request failed; no action was retried")
    })?;
    let result = operation_final_tool_result(created);
    let Some(mut task) = prepare_operation_task_wait(connection, &result)? else {
        return Ok(Some(result));
    };
    if !matches!(
        task.task(),
        fastmcp_protocol::tasks_extension::Task::Working(_)
    ) {
        return emitted_operation_task_outcome(task.task()).map(|()| None);
    }
    let remaining = budget.remaining(cx)?;
    let outcome = asupersync::time::timeout(
        cx.now(),
        remaining,
        Box::pin(task.wait_with_websocket(
            cx,
            client,
            cancellation,
            operation_task_wait_policy(remaining)?,
        )),
    )
    .await
    .map_err(|_| OperationBudget::timeout_error())
    .and_then(|result| {
        result.map_err(|error| {
            operation_failure(error, "task observation failed; no action was retried")
        })
    });
    finish_operation_task_wait(connection, task.task(), outcome)?;
    Ok(None)
}

pub(super) async fn inspect(
    cx: &Cx,
    url: &str,
    format: InspectFormat,
    output: Option<&Path>,
    max_pages: u32,
    timeout: u64,
) -> McpResult<()> {
    let budget = OperationBudget::new(timeout)?;
    let mut client = Connection::connect(cx, url, budget).await?;
    let acquisition = async {
        let session = client.session();
        let discovery = session.server_discovery().ok_or_else(|| {
            McpError::internal_error("WebSocket inspect has no admitted modern discovery")
        })?;
        let info = InspectIdentity::from_discovery(session.server_info(), Some(discovery));
        let capabilities = InspectCapabilities::final_from_discovery(&discovery.capabilities);
        let status =
            InspectProtocolStatus::new(CliProtocolPolicy::ModernOnly, session.protocol_version())?;
        let catalogs = asupersync::time::timeout(
            cx.now(),
            budget.remaining(cx)?,
            Box::pin(inspect_catalogs(
                cx,
                &mut InspectClient::WebSocket(&mut client),
                &capabilities,
                max_pages,
            )),
        )
        .await
        .map_err(|_| OperationBudget::timeout_error())??;
        Ok((info, capabilities, status, catalogs))
    }
    .await;
    let (info, capabilities, status, (truncated, tools, resources, templates, prompts)) =
        finish_inspect_acquisition_async(acquisition, client.close(cx)).await?;
    write_inspect_report(
        info.as_ref(),
        &capabilities,
        &tools,
        &resources,
        &templates,
        &prompts,
        truncated,
        status,
        format,
        output,
    )
}

/// Tests the same native connection users inspect and call. The handshake and
/// each probe have their own absolute bound; the native response waits retain
/// the selected idle policy. Cleanup settles before any final report is written.
pub(super) async fn test(
    cx: &Cx,
    url: &str,
    idle_timeout_secs: u64,
    absolute_timeout_secs: u64,
    verbose: bool,
    json_output: bool,
) -> McpResult<()> {
    use std::time::{Duration, Instant};

    let total_start = Instant::now();
    let absolute_timeout = Duration::from_secs(absolute_timeout_secs);
    let policy = fastmcp_client::RequestTimeoutPolicy::new(
        Duration::from_secs(idle_timeout_secs),
        absolute_timeout,
    )?;
    let budget = OperationBudget::new(absolute_timeout_secs)?;
    if !json_output {
        write_stdout(
            &format!("Testing server: {}", sanitize_peer_text(url, PEER_FIELD_LIMIT)),
            "test output",
            true,
        )?;
    }
    let init_start = Instant::now();
    let connection = bounded_websocket_test(
        cx,
        budget.remaining(cx)?,
        Connection::connect_with_policy(cx, url, policy),
    )
    .await;
    let mut client = match connection {
        Ok(client) => client,
        Err(mut error) => {
            let result = failed_test_result("initialize", init_start.elapsed(), &error);
            if !json_output {
                if let Err(output_error) = print_test_result(&result, verbose) {
                    return Err(combine_test_failure_with_output(error, output_error));
                }
            }
            let report = TestReport {
                server: url.to_owned(),
                success: false,
                tests: vec![result],
                total_duration_ms: total_start.elapsed().as_secs_f64() * 1000.0,
            };
            if let Err(output_error) = write_test_report(&report, json_output) {
                error = combine_test_failure_with_output(error, output_error);
            }
            return Err(error);
        }
    };
    let mut results = vec![TestResult {
        name: "initialize".to_owned(),
        success: true,
        skipped: false,
        duration_ms: init_start.elapsed().as_secs_f64() * 1000.0,
        details: Some(format!(
            "protocol {} over WebSocket",
            client.session().protocol_version()
        )),
        error: None,
        timeout_source: None,
        mutation: OutputMutationMetadata::default(),
        machine_text: None,
    }];
    let probes = match &mut client {
        Connection::Plain(client) => test_probes(cx, client, absolute_timeout).await,
        Connection::Tls(client) => test_probes(cx, client, absolute_timeout).await,
    };
    results.extend(probes);
    results.push(
        run_test(cx, "cleanup", async |cx| {
            client.close(cx).await?;
            Ok("WebSocket connection closed".to_owned())
        })
        .await,
    );
    let all_passed = results.iter().all(|result| result.success);
    let report = TestReport {
        server: url.to_owned(),
        success: all_passed,
        tests: results,
        total_duration_ms: total_start.elapsed().as_secs_f64() * 1000.0,
    };
    if !json_output {
        for result in &report.tests {
            print_test_result(result, verbose)?;
        }
    }
    write_test_report(&report, json_output)?;
    if all_passed {
        Ok(())
    } else {
        Err(McpError::internal_error("Some tests failed"))
    }
}

/// Only this locally owned deadline grants a timeout-source classification.
/// Native MCP errors may contain arbitrary peer data, so their text and data
/// are replaced rather than treating a forged timeout tuple as local evidence.
async fn bounded_websocket_test<T>(
    cx: &Cx,
    absolute_timeout: std::time::Duration,
    operation: impl std::future::Future<Output = McpResult<T>>,
) -> McpResult<T> {
    asupersync::time::timeout(cx.now(), absolute_timeout, Box::pin(operation))
        .await
        .map_err(|_| http_test_timeout_error(fastmcp_client::RequestTimeoutSource::Absolute))?
        .map_err(|error| McpError::new(error.code, "WebSocket MCP probe failed"))
}

async fn test_probes<IO>(
    cx: &Cx,
    client: &mut WebSocketClient<IO>,
    absolute_timeout: std::time::Duration,
) -> Vec<TestResult>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(discovery) = client.session().server_discovery() else {
        return vec![failed_test_result(
            "capabilities",
            std::time::Duration::ZERO,
            &McpError::internal_error("WebSocket test has no admitted modern discovery"),
        )];
    };
    let capabilities = InspectCapabilities::final_from_discovery(&discovery.capabilities);
    let mut results = vec![
        run_test(cx, "ping", async |cx| {
            // Modern MCP liveness is a fresh server/discover round-trip; the
            // removed ping method must never be sent on this ModernOnly path.
            bounded_websocket_test(cx, absolute_timeout, client.ping(cx)).await?;
            Ok("server responded".to_owned())
        })
        .await,
    ];
    for (name, capability, method) in [
        ("list_tools", "tools", "tools/list"),
        ("list_resources", "resources", "resources/list"),
        ("list_prompts", "prompts", "prompts/list"),
    ] {
        let result = if capabilities.advertises(capability) {
            run_test(cx, name, async |cx| {
                client.clear_final_result_cache();
                let response = bounded_websocket_test(
                    cx,
                    absolute_timeout,
                    client.list_catalog_page(cx, method, serde_json::json!({})),
                )
                .await?;
                let (count, truncated) = match capability {
                    "tools" => {
                        let (items, truncated) = inspect_tools_result(response)?;
                        (items.len(), truncated)
                    }
                    "resources" => {
                        let (items, truncated) = inspect_resources_result(response)?;
                        (items.len(), truncated)
                    }
                    _ => {
                        let (items, truncated) = inspect_prompts_result(response)?;
                        (items.len(), truncated)
                    }
                };
                let qualifier = if truncated {
                    " in the bounded first page; more were omitted"
                } else {
                    ""
                };
                Ok(format!("{count} {capability}{qualifier}"))
            })
            .await
        } else {
            skipped_test(name, &format!("server did not advertise {capability}"))
        };
        results.push(result);
    }
    results
}

/// Runs an explicit control command for an already accepted Task. Discovery,
/// every RPC, subscription and output retain the original Tasks deadline.
/// A timeout ends observation; only the Cancel action sends `tasks/cancel`.
#[cfg(feature = "tasks")]
pub(super) async fn tasks(
    cx: &Cx,
    url: &str,
    output: &TaskOutput,
    budget: TaskCommandBudget,
    action: &TaskAction,
    task_id: fastmcp_protocol::FinalTaskId,
    inputs: Option<fastmcp_protocol::TaskInputResponses>,
) -> McpResult<()> {
    let operation_budget = OperationBudget {
        deadline: budget.deadline,
    };
    let mut client = Connection::connect(cx, url, operation_budget).await?;
    // Keep the connection outside the timeout future so cleanup still runs
    // when an in-flight RPC, output or subscription wait is abandoned.
    let acquisition = async {
        let remaining = operation_budget.remaining(cx)?;
        let request = async {
            match &mut client {
                Connection::Plain(client) => {
                    Box::pin(execute_task(
                        cx, client, output, budget, action, task_id, inputs,
                    ))
                    .await
                }
                Connection::Tls(client) => {
                    Box::pin(execute_task(
                        cx, client, output, budget, action, task_id, inputs,
                    ))
                    .await
                }
            }
        };
        asupersync::time::timeout(cx.now(), remaining, Box::pin(request))
            .await
            .map_err(|_| OperationBudget::timeout_error())?
    }
    .await;
    finish_inspect_acquisition_async(acquisition, client.close(cx)).await
}

#[cfg(feature = "tasks")]
async fn execute_task<IO>(
    cx: &Cx,
    client: &mut WebSocketClient<IO>,
    output: &TaskOutput,
    budget: TaskCommandBudget,
    action: &TaskAction,
    task_id: fastmcp_protocol::FinalTaskId,
    inputs: Option<fastmcp_protocol::TaskInputResponses>,
) -> McpResult<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let cancellation = McpRequestCancellation::new();
    budget.remaining()?;
    if matches!(action, TaskAction::Cancel { .. }) {
        let result = client
            .cancel_task_final(cx, task_id)
            .await
            .map_err(|error| {
                operation_failure(
                    error,
                    "WebSocket Task cancellation failed; no action was retried",
                )
            })?;
        return output.write_event(cx, "cancellation-acknowledged", &result);
    }
    let mut handle = client
        .attach_final_task(cx, &cancellation, task_id)
        .await
        .map_err(|error| operation_failure(error, "WebSocket Task read failed"))?;
    match action {
        TaskAction::Get { .. } => output.write_event(cx, "snapshot", handle.task()),
        TaskAction::Update { .. } => {
            budget.remaining()?;
            let result = handle
                .resume_input_with_websocket(
                    cx,
                    client,
                    &cancellation,
                    inputs.ok_or_else(|| McpError::invalid_params("missing input responses"))?,
                )
                .await
                .map_err(|error| {
                    operation_failure(error, "WebSocket Task update failed; no action was retried")
                })?;
            output.write_event(cx, "update-acknowledged", &result)
        }
        TaskAction::Watch { max_events, .. } => {
            watch_task(
                cx,
                client,
                output,
                budget,
                &mut handle,
                *max_events,
                &cancellation,
            )
            .await
        }
        TaskAction::Cancel { .. } => unreachable!("cancel returned before reading a snapshot"),
    }
}

#[cfg(feature = "tasks")]
async fn watch_task<IO>(
    cx: &Cx,
    client: &mut WebSocketClient<IO>,
    output: &TaskOutput,
    budget: TaskCommandBudget,
    handle: &mut fastmcp_client::FinalTaskHandle,
    max_events: u64,
    cancellation: &McpRequestCancellation,
) -> McpResult<()>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use fastmcp_client::StdioTaskSubscriptionEvent;

    let mut latest_task = handle.task().clone();
    // Task timestamps retain their wire spelling; equivalent UTC offsets or
    // fractional precision must not look like a changed identity.
    let created_at = chrono::DateTime::parse_from_rfc3339(latest_task.base().created_at.as_str())
        .map_err(|_| {
        McpError::invalid_request("task watch returned an invalid creation timestamp")
    })?;
    let mut last_poll = std::time::Instant::now();
    output.write_event(cx, "snapshot", &latest_task)?;
    if is_terminal_task_status(latest_task.base().status) {
        return output.write_event(
            cx,
            "watch-ended",
            &serde_json::json!({"reason": "task-terminal", "updates": 0}),
        );
    }
    let task_id = handle.task_id().clone();
    let mut filter = fastmcp_protocol::SubscriptionFilter::default();
    fastmcp_protocol::set_task_subscription_ids(&mut filter, vec![task_id.clone()])
        .map_err(|_| McpError::invalid_params("invalid task watch filter"))?;
    budget.remaining()?;
    client
        .open_final_task_subscription_listener(cx, filter.clone())
        .await
        .map_err(|error| operation_failure(error, "WebSocket Task watch could not start"))?;
    let mut updates = 0;
    let mut reconnects = 0;
    let mut reconnect_ack_pending = false;
    loop {
        budget.remaining()?;
        let event = client
            .next_final_task_subscription_event(cx, cancellation)
            .await
            .map_err(|error| operation_failure(error, "WebSocket Task watch failed"))?;
        let reconnect = match event {
            StdioTaskSubscriptionEvent::Acknowledged(accepted) => {
                validate_task_watch_acknowledgement(&accepted, &task_id)?;
                output.write_event(cx, "watch-acknowledged", &accepted)?;
                false
            }
            StdioTaskSubscriptionEvent::Notification(notification) => {
                let task = notification.params.task;
                let observed_created_at = chrono::DateTime::parse_from_rfc3339(
                    task.base().created_at.as_str(),
                )
                .map_err(|_| {
                    McpError::invalid_request("task watch returned an invalid creation timestamp")
                })?;
                if task.base().task_id != task_id || observed_created_at != created_at {
                    return Err(McpError::invalid_request(
                        "task watch returned a different task identity",
                    ));
                }
                let previous = serde_json::to_vec(&latest_task)
                    .map_err(|_| McpError::internal_error("could not compare task snapshots"))?;
                let observed = serde_json::to_vec(&task)
                    .map_err(|_| McpError::internal_error("could not compare task snapshots"))?;
                if previous == observed {
                    asupersync::runtime::yield_now().await;
                    continue;
                }
                let previous_update = chrono::DateTime::parse_from_rfc3339(
                    latest_task.base().last_updated_at.as_str(),
                )
                .map_err(|_| {
                    McpError::invalid_request("task watch returned an invalid update timestamp")
                })?;
                let observed_update =
                    chrono::DateTime::parse_from_rfc3339(task.base().last_updated_at.as_str())
                        .map_err(|_| {
                            McpError::invalid_request(
                                "task watch returned an invalid update timestamp",
                            )
                        })?;
                if observed_update > previous_update {
                    if reconcile_task_snapshot(
                        cx,
                        output,
                        &latest_task,
                        &task,
                        &mut updates,
                        max_events,
                    )? {
                        return Ok(());
                    }
                    latest_task = task;
                    last_poll = std::time::Instant::now();
                    continue;
                }
                // Reads may queue notifications from before their authoritative
                // response. Changed equal/older instants require a fresh read;
                // never regress emitted state or consume max-events for them.
                // The timestamp is only a notification hint: an authoritative
                // read below is admitted even when the server clock regresses.
                false
            }
            StdioTaskSubscriptionEvent::Terminal => true,
        };
        // The listener remains active during the read after acknowledgement:
        // this closes the initial read/listen race without losing later events.
        if let Some(delay) =
            task_poll_delay(last_poll, latest_task.base().poll_interval_ms.as_ref())?
        {
            wait_for_task_poll_delay(cx, budget, delay).await?;
        }
        budget.remaining()?;
        let task = handle
            .poll_with_websocket(cx, client, cancellation)
            .await
            .map_err(|error| operation_failure(error, "WebSocket Task reconciliation failed"))?
            .clone();
        last_poll = std::time::Instant::now();
        if reconnect_ack_pending && !reconnect {
            output.write_event(
                cx,
                "watch-reconnected",
                &serde_json::json!({"attempt": reconnects, "task": task}),
            )?;
            reconnect_ack_pending = false;
        }
        if reconcile_task_snapshot(cx, output, &latest_task, &task, &mut updates, max_events)? {
            return Ok(());
        }
        latest_task = task;
        if reconnect {
            if reconnects >= MAX_TASK_WATCH_RECONNECTS {
                return Err(McpError::internal_error(
                    "task watch stream ended before terminal task state; reconnect budget exhausted",
                ));
            }
            reconnects += 1;
            budget.remaining()?;
            client
                .open_final_task_subscription_listener(cx, filter.clone())
                .await
                .map_err(|error| {
                    operation_failure(error, "WebSocket Task watch could not resume")
                })?;
            reconnect_ack_pending = true;
        }
    }
}

#[cfg(all(test, feature = "tasks"))]
mod tests {
    use super::*;
    use asupersync::net::tcp::VirtualTcpStream;
    use fastmcp_protocol::{
        DiscoveryCacheHints, JsonRpcMessage, RequestId, ServerBehavior, ServerBehaviorRegistry,
        ServerDiscoverCapabilities, ServerDiscoverResult, ServerInfo,
    };
    use fastmcp_transport::websocket::AsyncWsServerTransport;
    use serde_json::{Value, json};

    fn task(updated: &str, message: &str, completed: bool) -> Value {
        let mut task = json!({
            "taskId": "cli-watch-task",
            "status": if completed { "completed" } else { "working" },
            "createdAt": "2026-07-28T00:00:00Z",
            "lastUpdatedAt": updated,
            "statusMessage": message,
            "ttlMs": null,
        });
        if completed {
            task["result"] = json!({"content": [{"type": "text", "text": "finished"}]});
        }
        task
    }

    fn task_response(id: i64, task: &Value) -> Value {
        let mut result = task.clone();
        result["resultType"] = json!("complete");
        json!({"jsonrpc": "2.0", "id": id, "result": result})
    }

    fn task_notification(task: &Value) -> Value {
        let mut params = task.clone();
        params["_meta"] = json!({"io.modelcontextprotocol/subscriptionId": 3});
        json!({"jsonrpc": "2.0", "method": "notifications/tasks", "params": params})
    }

    /// Exercises the real native framing, dispatcher queue, Task handle, and
    /// CLI watch loop. A stale queued event must not consume max-events before
    /// the required authoritative read or the later terminal notification.
    #[test]
    fn websocket_task_watch_reconciles_queued_notifications() {
        RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                for (notification_time, clock_regresses) in [
                    ("2026-07-28T00:00:01Z", false),
                    ("2026-07-28T00:00:02Z", false),
                    ("2026-07-28T00:00:02.000000000Z", false),
                    ("2026-07-28T02:00:02+02:00", false),
                    ("2026-07-27T19:00:02-05:00", false),
                    ("2026-07-28T00:00:02Z", true),
                ] {
                    let (client_io, peer_io) = VirtualTcpStream::pair(
                        "127.0.0.1:45251".parse().unwrap(),
                        "127.0.0.1:45252".parse().unwrap(),
                    );
                    let mut peer = AsyncWsServerTransport::from_upgraded(peer_io);
                    let capabilities = ServerDiscoverCapabilities::from_registry(
                        &ServerBehaviorRegistry::from_behaviors([
                            ServerBehavior::ToolsList,
                            ServerBehavior::SubscriptionsListen,
                        ]),
                        std::collections::BTreeMap::from([(
                            fastmcp_protocol::TASKS_EXTENSION.to_owned(),
                            json!({}),
                        )]),
                    )
                    .unwrap();
                    let discovery = ServerDiscoverResult::new(
                        capabilities,
                        ServerInfo { name: "queued-task-peer".to_owned(), version: "1".to_owned() },
                        None,
                        DiscoveryCacheHints::private_ttl_ms(0),
                    );
                    let mut discovery = json!({"jsonrpc": "2.0", "id": 1, "result": discovery});
                    discovery["result"]["supportedVersions"] = json!(["2026-07-28"]);
                    let initial = task("2026-07-28T00:00:00Z", "initial", false);
                    let authoritative = task("2026-07-28T00:00:02Z", "authoritative", false);
                    let reconciled = if clock_regresses {
                        task("2026-07-28T00:00:00Z", "authoritative after clock change", false)
                    } else {
                        authoritative.clone()
                    };
                    let mut frames = vec![
                        discovery,
                        task_response(2, &initial),
                        json!({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged", "params": {
                            "_meta": {"io.modelcontextprotocol/subscriptionId": 3},
                            "notifications": {"taskIds": ["cli-watch-task"]},
                        }}),
                        task_notification(&task(notification_time, "queued before the read", false)),
                    ];
                    if !clock_regresses {
                        frames.push(task_notification(&authoritative));
                    }
                    frames.extend([
                        task_response(4, &authoritative),
                        task_response(5, &reconciled),
                        task_notification(&task("2026-07-28T00:00:03Z", "completed", true)),
                    ]);
                    for frame in frames {
                        peer.send(&cx, &serde_json::from_value(frame).unwrap()).await.unwrap();
                    }
                    let mut client = ClientBuilder::new()
                        .protocol_plan(ClientProtocolPlan::websocket(ProtocolPolicy::ModernOnly))
                        .connect_websocket_with_cx(&cx, AsyncWsClientTransport::from_upgraded(client_io))
                        .await
                        .unwrap();
                    let cancellation = McpRequestCancellation::new();
                    let mut handle = client
                        .attach_final_task(
                            &cx,
                            &cancellation,
                            fastmcp_protocol::FinalTaskId::parse("cli-watch-task").unwrap(),
                        )
                        .await
                        .unwrap();
                    let budget = TaskCommandBudget {
                        deadline: std::time::Instant::now() + std::time::Duration::from_secs(3),
                    };
                    let output = TaskOutput { json: true, budget };
                    asupersync::time::timeout(
                        cx.now(),
                        budget.remaining().unwrap(),
                        Box::pin(watch_task(
                            &cx,
                            &mut client,
                            &output,
                            budget,
                            &mut handle,
                            if clock_regresses { 3 } else { 2 },
                            &cancellation,
                        )),
                    )
                    .await
                    .expect("queued notifications must not strand the watch")
                    .unwrap();
                    assert_eq!(serde_json::to_value(handle.task()).unwrap(), reconciled);
                    client.close(&cx).await.unwrap();
                    for (method, id) in [
                        ("server/discover", 1),
                        ("tasks/get", 2),
                        ("subscriptions/listen", 3),
                        ("tasks/get", 4),
                        ("tasks/get", 5),
                    ] {
                        let message = asupersync::time::timeout(
                            cx.now(),
                            std::time::Duration::from_secs(1),
                            Box::pin(peer.recv(&cx)),
                        )
                        .await
                        .expect("CLI must send the required reconciliation read")
                        .unwrap();
                        let JsonRpcMessage::Request(request) = message else {
                            panic!("expected native CLI request");
                        };
                        assert_eq!(request.method, method);
                        assert_eq!(request.id, Some(RequestId::Number(id)));
                    }
                }
            });
    }
}
