//! Active downstream consumer for the facade's experimental WebSocket APIs.

use fastmcp_rust::{
    AsyncWsClientTransport, AsyncWsServerTransport, Cx, McpError, McpResult, prelude, server,
    transport,
};

async fn composes_actual_async_websocket_client(cx: &Cx) -> McpResult<()> {
    let transport = AsyncWsClientTransport::connect(cx, "ws://127.0.0.1:9000/mcp")
        .await
        .map_err(|error| McpError::internal_error(error.to_string()))?;
    let mut client = fastmcp_rust::ClientBuilder::new()
        .connect_websocket_with_cx(cx, transport)
        .await?;
    let _ = client.session();
    let _ = client.final_result_cache_enabled();
    let _: fastmcp_rust::FinalCacheStats = client.final_result_cache_stats();
    client.set_final_result_cache_enabled(false);
    client.clear_final_result_cache();

    #[cfg(feature = "tasks")]
    {
        let cancellation = fastmcp_rust::McpRequestCancellation::new();
        retain_tool_outcome(
            client
                .call_tool_final_outcome_with_handlers(
                    cx,
                    &cancellation,
                    "interactive-task",
                    fastmcp_rust::json!({"value": "native client"}),
                )
                .await?,
        )?;
        retain_tool_outcome(
            client
                .call_tool_final_outcome_with_mrtr_retry(
                    cx,
                    &cancellation,
                    std::time::Instant::now() + std::time::Duration::from_secs(30),
                    "interactive-task",
                    fastmcp_rust::json!({"value": "native client"}),
                    answer_roots,
                )
                .await?,
        )?;
    }

    let modern_transport = AsyncWsClientTransport::connect(cx, "ws://127.0.0.1:9001/mcp")
        .await
        .map_err(|error| McpError::internal_error(error.to_string()))?;
    let modern_handlers = fastmcp_rust::modern::ReverseRequestHandlers::new()
        .with_modern_roots_list(|_, _, _| {
            Box::pin(async {
                Ok(fastmcp_rust::modern::FinalEmbeddedRootsListResult { roots: Vec::new() })
            })
        });
    let mut modern_client = fastmcp_rust::modern::ClientBuilder::new()
        .modern_reverse_request_handlers(modern_handlers)
        .connect_websocket_with_cx(cx, modern_transport)
        .await?;
    let _ = modern_client.session();
    let _ = modern_client.final_result_cache_enabled();
    let _: fastmcp_rust::FinalCacheStats = modern_client.final_result_cache_stats();
    modern_client.set_final_result_cache_enabled(false);
    modern_client.clear_final_result_cache();

    #[cfg(feature = "tasks")]
    {
        let cancellation = fastmcp_rust::McpRequestCancellation::new();
        retain_tool_outcome(
            modern_client
                .call_tool_outcome_with_handlers(
                    cx,
                    &cancellation,
                    "interactive-task",
                    fastmcp_rust::json!({"value": "modern facade"}),
                )
                .await?,
        )?;
        retain_tool_outcome(
            modern_client
                .call_tool_outcome_with_mrtr_retry(
                    cx,
                    &cancellation,
                    std::time::Instant::now() + std::time::Duration::from_secs(30),
                    "interactive-task",
                    fastmcp_rust::json!({"value": "modern facade"}),
                    answer_roots,
                )
                .await?,
        )?;
    }

    let modern_listener = fastmcp_rust::modern::server_builder("modern-ws", "1.0")
        .build()
        .bind_websocket(cx, "127.0.0.1:0")
        .await?;
    let _ = modern_listener.local_addr()?;

    #[cfg(feature = "legacy-2024-11-05")]
    {
        let legacy_transport = AsyncWsClientTransport::connect(cx, "ws://127.0.0.1:9002/mcp")
            .await
            .map_err(|error| McpError::internal_error(error.to_string()))?;
        let legacy_client = fastmcp_rust::legacy_2024::ClientBuilder::new()
            .connect_websocket_with_cx(cx, legacy_transport)
            .await?;
        let _ = legacy_client.protocol_policy();
        let _ = legacy_client.protocol_version();

        let mut auto_client = fastmcp_rust::auto::ClientBuilder::new()
            .connect_websocket_auto_with_cx(cx, move |_| async move {
                AsyncWsClientTransport::connect(cx, "ws://127.0.0.1:9003/mcp")
                    .await
                    .map_err(|error| McpError::internal_error(error.to_string()))
            })
            .await?;
        let _ = auto_client.session();
        let _ = auto_client.final_result_cache_enabled();
        let _: fastmcp_rust::FinalCacheStats = auto_client.final_result_cache_stats();
        auto_client.set_final_result_cache_enabled(false);
        auto_client.clear_final_result_cache();

        #[cfg(feature = "tasks")]
        {
            let cancellation = fastmcp_rust::McpRequestCancellation::new();
            retain_tool_outcome(
                auto_client
                    .call_tool_outcome_with_handlers(
                        cx,
                        &cancellation,
                        "interactive-task",
                        fastmcp_rust::json!({"value": "auto facade"}),
                    )
                    .await?,
            )?;
            retain_tool_outcome(
                auto_client
                    .call_tool_outcome_with_mrtr_retry(
                        cx,
                        &cancellation,
                        std::time::Instant::now() + std::time::Duration::from_secs(30),
                        "interactive-task",
                        fastmcp_rust::json!({"value": "auto facade"}),
                        answer_roots,
                    )
                    .await?,
            )?;
        }

        let legacy_listener = fastmcp_rust::legacy_2024::server_builder("legacy-ws", "1.0")
            .build()
            .bind_websocket(cx, "127.0.0.1:0")
            .await?;
        let _ = legacy_listener.local_addr()?;
    }

    Ok(())
}

#[cfg(feature = "tasks")]
fn answer_roots(
    input: &fastmcp_rust::modern::InputRequiredResult,
) -> McpResult<fastmcp_rust::modern::MrtrInputResponses> {
    Ok(input
        .input_requests()
        .into_iter()
        .flat_map(|requests| requests.members())
        .map(|member| (member.name.clone(), fastmcp_rust::json!({"roots": []})))
        .collect())
}

/// The sealed facades retain all outcomes and expose enough public types to
/// adopt created work without another tools/call or an internal-type escape.
#[cfg(feature = "tasks")]
fn retain_tool_outcome(outcome: fastmcp_rust::modern::FinalToolCallOutcome) -> McpResult<()> {
    match outcome {
        fastmcp_rust::modern::FinalToolCallOutcome::Task(receipt) => {
            let handle = fastmcp_rust::modern::FinalTaskHandle::from_created(&receipt)?;
            let _: &fastmcp_rust::modern::FinalTaskId = handle.task_id();
        }
        fastmcp_rust::modern::FinalToolCallOutcome::Complete(result) => {
            let _ = result.payload.content;
        }
        fastmcp_rust::modern::FinalToolCallOutcome::InputRequired(input) => {
            let _: Option<&str> = input.request_state();
        }
    }
    Ok(())
}

fn exposes_async_websocket_types<IO>() {
    let _: Option<AsyncWsClientTransport<IO>> = None;
    let _: Option<AsyncWsServerTransport<()>> = None;
    let _: Option<server::BoundWebSocketServer> = None;
    let _: Option<server::WebSocketServerShutdown> = None;
    let _: Option<transport::websocket::WebSocketListener> = None;
    let _: Option<transport::websocket::WebSocketUpgradeAdmission> = None;
    let _: Option<prelude::WebSocketResponse> = None;
    let _: Option<prelude::BoundWebSocketServer> = None;
    let _: Option<prelude::WebSocketServerShutdown> = None;
}

fn main() {
    let _ = composes_actual_async_websocket_client;
    let _ = exposes_async_websocket_types::<()>;
}
