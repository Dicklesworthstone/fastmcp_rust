//! Active downstream consumer for the facade's experimental WebSocket APIs.

use fastmcp_rust::{
    AsyncWsClientTransport, AsyncWsServerTransport, Cx, McpError, McpResult, prelude, server,
    transport,
};

async fn composes_actual_async_websocket_client(cx: &Cx) -> McpResult<()> {
    let transport = AsyncWsClientTransport::connect(cx, "ws://127.0.0.1:9000/mcp")
        .await
        .map_err(|error| McpError::internal_error(error.to_string()))?;
    let client = fastmcp_rust::ClientBuilder::new()
        .connect_websocket_with_cx(cx, transport)
        .await?;
    let _ = client.session();

    let modern_transport = AsyncWsClientTransport::connect(cx, "ws://127.0.0.1:9001/mcp")
        .await
        .map_err(|error| McpError::internal_error(error.to_string()))?;
    let modern_client = fastmcp_rust::modern::ClientBuilder::new()
        .connect_websocket_with_cx(cx, modern_transport)
        .await?;
    let _ = modern_client.session();

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

        let auto_client = fastmcp_rust::auto::ClientBuilder::new()
            .connect_websocket_auto_with_cx(cx, move |_| async move {
                AsyncWsClientTransport::connect(cx, "ws://127.0.0.1:9003/mcp")
                    .await
                    .map_err(|error| McpError::internal_error(error.to_string()))
            })
            .await?;
        let _ = auto_client.session();

        let legacy_listener = fastmcp_rust::legacy_2024::server_builder("legacy-ws", "1.0")
            .build()
            .bind_websocket(cx, "127.0.0.1:0")
            .await?;
        let _ = legacy_listener.local_addr()?;
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
