//! Explicit ModernOnly WebSocket CLI operations on the native client.
//!
//! Upgrade, discovery and every request share the command's original budget.
//! The connection remains owned until explicit close, including when a request
//! times out. No reconnect or application replay is part of this command path.

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
            let transport = asupersync::time::timeout(
                cx.now(),
                budget.remaining(cx)?,
                AsyncWsClientTransport::connect_wss(cx, url),
            )
            .await
            .map_err(|_| OperationBudget::timeout_error())?
            .map_err(|_| {
                McpError::internal_error("could not establish the TLS WebSocket transport")
            })?;
            Ok(Self::Tls(Box::new(
                connect_client(cx, transport, budget).await?,
            )))
        } else {
            let transport = asupersync::time::timeout(
                cx.now(),
                budget.remaining(cx)?,
                AsyncWsClientTransport::connect(cx, url),
            )
            .await
            .map_err(|_| OperationBudget::timeout_error())?
            .map_err(|_| McpError::internal_error("could not establish the WebSocket transport"))?;
            Ok(Self::Plain(Box::new(
                connect_client(cx, transport, budget).await?,
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
    budget: OperationBudget,
) -> McpResult<WebSocketClient<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let remaining = budget.remaining(cx)?;
    asupersync::time::timeout(
        cx.now(),
        remaining,
        Box::pin(
            ClientBuilder::new()
                .protocol_plan(ClientProtocolPlan::websocket(ProtocolPolicy::ModernOnly))
                .request_timeout_policy(OperationBudget::request_policy(remaining)?)
                .connect_websocket_with_cx(cx, transport),
        ),
    )
    .await
    .map_err(|_| OperationBudget::timeout_error())?
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
