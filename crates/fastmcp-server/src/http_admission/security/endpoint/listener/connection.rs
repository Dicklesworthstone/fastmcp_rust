//! Secured connection dispatch using native authentication, JSON and SSE owners.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use asupersync::Cx;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::stream::StreamExt;
use fastmcp_core::McpRequestCancellation;
use fastmcp_transport::{TransportError, http::{HttpRequest, HttpResponse, HttpStatus}};

use super::{SecuredHttpIoLimits, ingress::{Ingress, SecuredCodec}};
use super::super::super::{CorsResponseHeaders, HttpSecurityPolicy};
use crate::{
    AsyncTcpStream, AuthDispatchCustody, DualEraHttpEndpointError, DualEraHttpSseResponse,
    FinalSubscriptionTerminalDelivery, Framed, HTTP_ACCEPT_CANCEL_POLL, HttpListenerShutdown,
    InboundRequestContext, InboundRequestTransport, JsonRpcRequest, LiveModernHttpSession,
    LiveModernHttpSessionRegistry, ModernSseDispatchElection, ModernSseOutcomeGate,
    NativeHttp1Codec, OwnedModernHttpDispatch, Server, ServerHttpEndpoint, ServerHttpEndpointError,
    TransportAuthorization, admit_modern_http_post, await_modern_sse_dispatch_election,
    close_detached_modern_http_session, dispatch_modern_http_request_with_cancellation_and_transport_authorization,
    final_subscription_terminal_event, final_subscription_terminal_response_event,
    h1_request_to_transport, h1_transport_authorization, http_endpoint_error_response,
    http_endpoint_response_to_static, http_request_accepts_sse, native_http1_codec,
    next_live_modern_http_response_body_generation, next_modern_http_stream_generation,
    request_id_to_u64, send_h1_bad_request_response, send_h1_response,
    spawn_modern_sse_dispatch, sse_response_head,
};

pub(super) async fn serve(
    cx: &Cx,
    stream: AsyncTcpStream,
    endpoint: Arc<ServerHttpEndpoint>,
    sessions: LiveModernHttpSessionRegistry,
    shutdown: HttpListenerShutdown,
    policy: Arc<HttpSecurityPolicy>,
    io: SecuredHttpIoLimits,
) {
    let body_limit = endpoint.server.http_config.handler_config.max_body_size;
    let mut framed = Framed::new(stream, SecuredCodec::new(policy, body_limit));
    let read = async {
        loop {
            if shutdown.is_requested() || cx.checkpoint().is_err() { return None; }
            if let Ok(request) = asupersync::time::timeout(cx.now(), HTTP_ACCEPT_CANCEL_POLL, framed.next()).await {
                return request;
            }
        }
    };
    let incoming = asupersync::time::timeout(cx.now(), io.request_timeout, read).await;
    let pipelined = !framed.read_buffer().is_empty();
    let mut framed = Framed::new(framed.into_inner(), native_http1_codec(&endpoint));
    let incoming = match incoming {
        Ok(Some(Ok(incoming))) => incoming,
        Ok(None) => return,
        Ok(Some(Err(_))) => {
            buffered(cx, &shutdown, &mut framed, HttpResponse::bad_request(), None, io).await;
            return;
        }
        Err(_) => {
            buffered(cx, &shutdown, &mut framed, HttpResponse::new(HttpStatus(408)), None, io).await;
            return;
        }
    };
    let (request, cors) = match incoming {
        Ingress::Immediate(response) => {
            buffered(cx, &shutdown, &mut framed, response, None, io).await;
            return;
        }
        Ingress::Request { request, cors } => (request, cors),
    };
    if pipelined {
        buffered(cx, &shutdown, &mut framed, HttpResponse::bad_request(), Some(&cors), io).await;
        return;
    }
    let raw_path = request.uri.split_once('?').map_or(request.uri.as_str(), |(path, _)| path);
    // Raw security fields have already passed before body allocation. Retain
    // their cardinality through the existing protocol/header mirror boundary.
    if let Err(response) = admit_modern_http_post(
        &endpoint.server.http_config.handler_config, "POST", raw_path, &request.headers, &request.body,
    ) {
        buffered(cx, &shutdown, &mut framed, response, Some(&cors), io).await;
        return;
    }
    let authorization = match h1_transport_authorization(&request) {
        Ok(authorization) => authorization,
        Err(response) => {
            buffered(cx, &shutdown, &mut framed, response, Some(&cors), io).await;
            return;
        }
    };
    let request = match h1_request_to_transport(&request) {
        Ok(request) => request,
        Err(response) => {
            buffered(cx, &shutdown, &mut framed, response, Some(&cors), io).await;
            return;
        }
    };
    if !http_request_accepts_sse(&request) {
        json(cx, framed.into_inner(), endpoint, sessions, shutdown, request, authorization, cors, io).await;
        return;
    }
    if request.header("mcp-session-id").is_some() {
        buffered(cx, &shutdown, &mut framed, HttpResponse::bad_request(), Some(&cors), io).await;
        return;
    }
    let mut session = match endpoint.open_session(cx) {
        Ok(session) => session,
        Err(_) => {
            buffered(cx, &shutdown, &mut framed, HttpResponse::internal_error(), Some(&cors), io).await;
            return;
        }
    };
    let opened = match session.begin_modern_sse(cx, request.clone(), authorization.clone()).await {
        Ok(Ok((request, response, raw_params, receipt))) => Ok(Ok((
            InboundRequestContext::with_modern_connection_and_transport_authorization(
                cx.clone(), request_id_to_u64(request.id.as_ref()), InboundRequestTransport::Http,
                &session.modern_connection, authorization,
            ), request, raw_params, receipt, response,
        ))),
        Ok(Err(response)) => Ok(Err(response)),
        Err(error) => Err(ServerHttpEndpointError::from_internal(error)),
    };
    let live = Arc::new(LiveModernHttpSession::new(session));
    match opened {
        Ok(Ok((inbound, request, raw_params, receipt, response))) => {
            let generation = next_live_modern_http_response_body_generation();
            if let Err(live) = sessions.register_response_body(generation, Arc::clone(&live)) {
                close_detached_modern_http_session(&sessions, live);
                buffered(cx, &shutdown, &mut framed, HttpResponse::new(HttpStatus::SERVICE_UNAVAILABLE), Some(&cors), io).await;
                return;
            }
            let _ = sse(cx, &shutdown, framed.into_inner(), Arc::clone(&endpoint.server), &live,
                &sessions, next_modern_http_stream_generation(), inbound, request, raw_params,
                Some(receipt), response, &cors, io).await;
            if let Some(live) = sessions.take_response_body(generation) {
                close_detached_modern_http_session(&sessions, live);
            }
        }
        Ok(Err(response)) => {
            buffered(cx, &shutdown, &mut framed, http_endpoint_response_to_static(cx, response), Some(&cors), io).await;
            close_detached_modern_http_session(&sessions, live);
        }
        Err(error) => {
            buffered(cx, &shutdown, &mut framed, http_endpoint_error_response(&request, error, body_limit), Some(&cors), io).await;
            close_detached_modern_http_session(&sessions, live);
        }
    }
}

async fn buffered<T: asupersync::io::AsyncWrite + Unpin>(
    cx: &Cx, shutdown: &HttpListenerShutdown, framed: &mut Framed<T, NativeHttp1Codec>,
    mut response: HttpResponse, cors: Option<&CorsResponseHeaders>, io: SecuredHttpIoLimits,
) {
    if let Some(cors) = cors { cors.apply_to(&mut response); }
    let _ = asupersync::time::timeout(cx.now(), io.write_timeout,
        send_h1_response(cx, shutdown, framed, response)).await;
}

#[allow(clippy::too_many_arguments)]
async fn json(
    cx: &Cx, stream: AsyncTcpStream, endpoint: Arc<ServerHttpEndpoint>,
    sessions: LiveModernHttpSessionRegistry, shutdown: HttpListenerShutdown,
    request: HttpRequest, authorization: TransportAuthorization,
    cors: CorsResponseHeaders, io: SecuredHttpIoLimits,
) {
    let (mut reader, writer) = stream.into_split();
    let cancellation = McpRequestCancellation::new();
    let peer_cancellation = cancellation.clone();
    let mut peer = match cx.spawn(move |peer_cx| async move {
        let mut byte = [0_u8; 1];
        match reader.read(&mut byte).await {
            Ok(0) => {}, // Write-half EOF does not cancel the response.
            Ok(_) => { peer_cancellation.cancel(); },
            Err(_) if !peer_cx.is_cancel_requested() => { peer_cancellation.cancel(); },
            Err(_) => {},
        }
    }) {
        Ok(peer) => peer,
        Err(_) => return,
    };
    let dispatch_endpoint = Arc::clone(&endpoint);
    let dispatch_cancellation = cancellation.clone();
    let dispatch = cx.spawn(move |request_cx| async move {
        dispatch_modern_http_request_with_cancellation_and_transport_authorization(
            &request_cx, &dispatch_endpoint, &sessions, request, authorization, Some(dispatch_cancellation),
        ).await
    });
    let response = match dispatch {
        Ok(mut dispatch) => dispatch.join(cx).await.unwrap_or_else(|_| HttpResponse::internal_error()),
        Err(_) => {
            cancellation.cancel();
            HttpResponse::new(HttpStatus::SERVICE_UNAVAILABLE)
        }
    };
    peer.abort();
    let _ = peer.join(cx).await;
    let mut framed = Framed::new(writer, native_http1_codec(&endpoint));
    buffered(cx, &shutdown, &mut framed, response, Some(&cors), io).await;
}

// Keep the native representation election, dispatch custody and terminal
// receipts. The intentional differences from the ordinary native writer are
// request-local CORS decoration and finite head/frame writes. In particular,
// an error elected before SSE admission must still be an HTTP JSON error.
#[allow(clippy::too_many_arguments)]
async fn sse(
    cx: &Cx, shutdown: &HttpListenerShutdown, stream: AsyncTcpStream,
    server: Arc<Server>, live: &LiveModernHttpSession, sessions: &LiveModernHttpSessionRegistry,
    generation: u64, inbound: InboundRequestContext, request: JsonRpcRequest,
    raw_params: Option<Arc<str>>, receipt: Option<AuthDispatchCustody>,
    response: DualEraHttpSseResponse, cors: &CorsResponseHeaders, io: SecuredHttpIoLimits,
) -> Result<(), ()> {
    let sender = response.sender();
    let cancellation = sender.request_cancellation();
    let terminal = Arc::new(FinalSubscriptionTerminalDelivery::default());
    let (gate, mut election) = ModernSseOutcomeGate::new();
    let (_reader, mut writer) = stream.into_split();
    let task = spawn_modern_sse_dispatch(cx, Arc::clone(&server), generation, inbound, request,
        raw_params, receipt, sender, Arc::clone(&terminal), Some(gate)).map_err(|_| ())?;
    let dispatch = OwnedModernHttpDispatch {
        owner_generation: generation, request_cancellation: cancellation.clone(), task,
    };
    if let Err(dispatch) = live.register_modern_dispatch(dispatch) {
        server.final_subscriptions.cancel_modern_http_owner(dispatch.owner_generation);
        dispatch.request_cancellation.cancel();
        dispatch.task.abort();
        sessions.retain_retired_dispatches(vec![dispatch.task]);
        return Err(());
    }
    let result = async {
        match await_modern_sse_dispatch_election(cx, &cancellation, &mut election).await? {
            ModernSseDispatchElection::Stream => {},
            ModernSseDispatchElection::Immediate(mut response) => {
                cors.apply_to(&mut response);
                return asupersync::time::timeout(cx.now(), io.write_timeout,
                    send_h1_bad_request_response(cx, shutdown, &mut writer, &response)).await.map_err(|_| ())?;
            }
            ModernSseDispatchElection::Failed => return Err(()),
        }
        let mut head = response.response().clone();
        cors.apply_to(&mut head);
        let head = sse_response_head(&head)?;
        write_parts(cx, &mut writer, &[&head], io).await?;
        loop {
            if terminal.is_settled() { return Err(()); }
            match response.pop_event() {
                Ok(Some(event)) => {
                    let control = final_subscription_terminal_event(&event);
                    let complete = final_subscription_terminal_response_event(&event);
                    let bytes = event.to_bytes().map_err(|_| ())?;
                    let prefix = format!("{:X}\r\n", bytes.len());
                    write_parts(cx, &mut writer, &[prefix.as_bytes(), &bytes, b"\r\n"], io).await?;
                    if control { terminal.mark_drained(); }
                    if complete { terminal.mark_completion_drained(); }
                    if terminal.is_settled() { break; }
                }
                Ok(None) if response.is_finished() => break,
                Ok(None) if cancellation.is_cancel_requested() && !terminal.is_committed() => {
                    terminal.mark_failed();
                    break;
                }
                Ok(None) if cx.checkpoint().is_err() => {
                    terminal.mark_failed();
                    break;
                }
                Ok(None) => asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await,
                Err(DualEraHttpEndpointError::Transport(TransportError::Closed)) if response.is_finished() => break,
                Err(_) => return Err(()),
            }
        }
        write_parts(cx, &mut writer, &[b"0\r\n\r\n"], io).await
    }.await;
    if result.is_err() {
        terminal.mark_failed();
        sessions.retain_retired_dispatches(live.cancel_modern_dispatch(generation));
    } else if !terminal.is_settled() {
        terminal.mark_failed();
    }
    live.reap_modern_dispatches();
    result
}

async fn write_parts<W: asupersync::io::AsyncWrite + Unpin>(
    cx: &Cx, writer: &mut W, parts: &[&[u8]], io: SecuredHttpIoLimits,
) -> Result<(), ()> {
    asupersync::time::timeout(cx.now(), io.write_timeout, async {
        for part in parts { writer.write_all(part).await.map_err(|_| ())?; }
        writer.flush().await.map_err(|_| ())
    }).await.map_err(|_| ())?
}
