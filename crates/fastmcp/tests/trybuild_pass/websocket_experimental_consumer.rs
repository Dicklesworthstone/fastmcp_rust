//! Active downstream consumer for the facade's experimental WebSocket APIs.

use fastmcp_rust::{
    AsyncWsClientTransport, AsyncWsServerTransport, ClientTransportRecvHalf, TransportSendHalf,
    WebSocketClient, WebSocketClientTransport, client::websocket_experimental, prelude, server,
    transport,
};

fn consumes_websocket_surface<R, S>()
where
    R: ClientTransportRecvHalf,
    S: TransportSendHalf,
{
    let _: Option<AsyncWsClientTransport<R>> = None;
    let _: Option<AsyncWsServerTransport<()>> = None;
    let _: Option<websocket_experimental::AsyncWsClientTransport<R>> = None;
    let _: Option<server::BoundWebSocketServer> = None;
    let _: Option<server::WebSocketServerShutdown> = None;
    let _: Option<transport::websocket::WebSocketListener> = None;
    let _: Option<transport::websocket::WebSocketUpgradeAdmission> = None;
    let _: Option<WebSocketClient<R, S>> = None;
    let _: Option<WebSocketClientTransport<R, S>> = None;
    let _: Option<prelude::WebSocketClient<R, S>> = None;
    let _: Option<prelude::BoundWebSocketServer> = None;
    let _ = fastmcp_rust::ClientBuilder::connect_websocket::<R, S>;
    let _ = fastmcp_rust::modern::ClientBuilder::connect_websocket::<R, S>;
    let _ = fastmcp_rust::modern::Server::bind_websocket;
    #[cfg(feature = "legacy-2024-11-05")]
    {
        let _ = fastmcp_rust::auto::ClientBuilder::connect_websocket::<R, S>;
        let _ = fastmcp_rust::legacy_2024::ClientBuilder::connect_websocket::<R, S>;
        let _ = fastmcp_rust::legacy_2024::Server::bind_websocket;
    }
}

fn main() {}
