//! Live transport coverage for the restricted extension authoring facade.
//! These tests use the shipped server pump on an application-owned runtime.

#![cfg(feature = "extension-authoring")]
#![recursion_limit = "512"]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use asupersync::runtime::RuntimeBuilder;
use fastmcp_rust::extensions::authoring::{
    ExtensionBuilder, ExtensionContext, ExtensionNotificationContext, ExtensionNotificationHandler,
    ExtensionRegistration,
};
use fastmcp_rust::memory::{MemoryTransport, create_memory_transport_pair_with_capacity};
use fastmcp_rust::serde::{Deserialize, Serialize};
use fastmcp_rust::{
    Cx, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, JsonSchema, McpError, McpResult,
    RequestId, TransportError, extension, json, modern,
};

const EXTENSION: &str = "com.example/typed-math";
const METHOD: &str = "com.example/scale";

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ClientSettings {
    version: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ServerSettings {
    version: u32,
    multiplier: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct Settings {
    multiplier: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ScaleRequest {
    value: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ScaleResponse {
    value: u32,
}

fn builder() -> ExtensionBuilder<ClientSettings, ServerSettings, Settings> {
    ExtensionBuilder::new(
        EXTENSION,
        1,
        "typed-math-client-v1",
        "typed-math-server-v1",
        ServerSettings {
            version: 1,
            multiplier: 3,
        },
        |client: ClientSettings, server: ServerSettings| {
            if client.version != server.version {
                return Err(McpError::invalid_params("incompatible math version"));
            }
            Ok(Settings {
                multiplier: server.multiplier,
            })
        },
    )
    .expect("admitted typed settings")
}

fn registration(calls: Arc<AtomicUsize>) -> ExtensionRegistration {
    builder()
        .typed_request_sync(
            METHOD,
            "scale-params-v1",
            "scale-result-v1",
            move |context: ExtensionContext<'_, Settings>, request: ScaleRequest| {
                context.checkpoint()?;
                assert_eq!(context.descriptor().id(), EXTENSION);
                assert_eq!(context.descriptor().version(), 1);
                assert_eq!(context.method(), METHOD);
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(ScaleResponse {
                    value: request.value * context.settings().multiplier,
                })
            },
        )
        .expect("typed method installs")
        .build()
        .expect("sealed registration")
}

#[extension(
    method = "com.example/scale",
    params_schema = "scale-params-v1",
    result_schema = "scale-result-v1"
)]
async fn scale(
    context: ExtensionContext<'_, Settings>,
    request: ScaleRequest,
) -> McpResult<ScaleResponse> {
    // Yield on the caller's executor without obtaining or constructing a Cx.
    let mut yielded = false;
    std::future::poll_fn(|task| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            task.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await;
    context.checkpoint()?;
    Ok(ScaleResponse {
        value: request.value * context.settings().multiplier,
    })
}

fn request(
    id: i64,
    settings: Option<fastmcp_rust::JsonValue>,
    value: fastmcp_rust::JsonValue,
) -> JsonRpcMessage {
    // Tasks is ALWAYS advertised, including when this request omits the typed
    // extension's own settings. The facade's default feature set includes
    // `tasks`, so ServerBuilder auto-installs the official Tasks extension,
    // whose descriptor is RejectOneSided. A client that advertises any
    // extensions object without Tasks is therefore refused for THAT reason,
    // which would make every negative below pass on an unintended dimension.
    let mut capabilities = json!({
        "extensions": {"io.modelcontextprotocol/tasks": {}}
    });
    if let Some(settings) = settings {
        capabilities["extensions"][EXTENSION] = settings;
    }
    JsonRpcMessage::Request(JsonRpcRequest::new(
        METHOD,
        Some(json!({
            "value": value,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": capabilities
            }
        })),
        id,
    ))
}

async fn response(cx: &Cx, peer: &mut MemoryTransport, id: i64) -> JsonRpcResponse {
    let JsonRpcMessage::Response(response) = peer.recv_async(cx).await.expect("server response")
    else {
        panic!("extension request must return a response");
    };
    assert_eq!(response.id, Some(RequestId::Number(id)));
    response
}

fn run_exchange(
    registration: ExtensionRegistration,
    requests: Vec<JsonRpcMessage>,
) -> Vec<JsonRpcResponse> {
    let server = modern::ServerBuilder::new("typed-extension", "1.0")
        .extension(registration)
        .expect("installation before freeze")
        .try_build()
        .expect("immutable server");
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .expect("application-owned runtime");
    let responses = runtime.block_on(async move {
        let cx = Cx::current().expect("caller context");
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
            let (mut peer, transport) = create_memory_transport_pair_with_capacity(1);
            let mut serving = cx
                .spawn(move |cx| async move { server.serve_memory(&cx, transport).await })
                .expect("owned server task");
            let mut responses = Vec::new();
            for (index, request) in requests.iter().enumerate() {
                peer.send_async(&cx, request)
                    .await
                    .expect("request admitted");
                responses.push(response(&cx, &mut peer, index as i64 + 1).await);
            }
            let (mut input, output) = peer.into_split();
            drop(output);
            assert!(matches!(
                input.recv_async(&cx).await,
                Err(TransportError::Closed)
            ));
            serving
                .join(&cx)
                .await
                .expect("server task settled")
                .expect("server closed");
            responses
        })
        .await
        .expect("bounded exchange and cleanup")
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    responses
}

#[test]
fn typed_extension_settings_and_schema_are_enforced_per_request() {
    let calls = Arc::new(AtomicUsize::new(0));
    let registration = registration(Arc::clone(&calls));
    assert_eq!(registration.descriptor().id(), EXTENSION);
    assert_eq!(registration.descriptor().version(), 1);
    let responses = run_exchange(
        registration,
        vec![
            request(1, Some(json!({"version": 1})), json!(7)),
            request(2, None, json!(7)),
            request(3, Some(json!({"version": 2})), json!(7)),
            request(4, Some(json!({"version": "bad"})), json!(7)),
            request(5, Some(json!({"version": 1})), json!("bad")),
            request(6, Some(json!({"version": 1})), json!(11)),
        ],
    );
    assert!(responses[0].error.is_none(), "{:?}", responses[0]);
    assert_eq!(responses[0].result.as_ref().unwrap()["value"], 21);
    for response in &responses[1..5] {
        assert!(
            response.error.is_some(),
            "rejected request had a successful result: {response:?}"
        );
        assert!(response.result.is_none());
    }
    assert!(responses[5].error.is_none(), "{:?}", responses[5]);
    assert_eq!(responses[5].result.as_ref().unwrap()["value"], 33);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "only admitted requests run handlers"
    );
}

#[test]
fn attribute_extension_yields_on_caller_runtime_and_returns_typed_result() {
    let registration = ScaleExtension
        .register(builder())
        .expect("attribute-generated registration")
        .build()
        .unwrap();
    let responses = run_exchange(
        registration,
        vec![
            request(1, Some(json!({"version": 1})), json!(9)),
            request(2, Some(json!({"version": 2})), json!(9)),
        ],
    );
    assert!(responses[0].error.is_none(), "{:?}", responses[0]);
    assert_eq!(responses[0].result.as_ref().unwrap()["value"], 27);
    assert!(responses[1].error.is_some());
}

#[test]
fn sealed_extension_installation_preserves_existing_registration() {
    let first = registration(Arc::new(AtomicUsize::new(0)));
    let second = registration(Arc::new(AtomicUsize::new(0)));
    let builder = modern::ServerBuilder::new("typed-extension", "1.0")
        .extension(first)
        .unwrap();
    assert!(
        builder.extension(second).is_err(),
        "installation cannot silently replace a registry"
    );
}

const NOTIFICATION: &str = "com.example/scaled";
const ACTIVATION: &str = "com.example/activation";

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ScaleNotification {
    value: u32,
    hold: bool,
}

#[derive(Default)]
struct NotificationObservations {
    authorized: AtomicUsize,
    started: AtomicUsize,
    completed: AtomicUsize,
    abandoned: AtomicUsize,
    total: AtomicUsize,
}

struct NotificationGuard {
    observations: Arc<NotificationObservations>,
    completed: bool,
}

impl Drop for NotificationGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.observations.abandoned.fetch_add(1, Ordering::SeqCst);
        }
    }
}

struct ScaleNotificationHandler(Arc<NotificationObservations>);

impl ExtensionNotificationHandler<ScaleNotification, Settings> for ScaleNotificationHandler {
    fn handle<'a>(
        &'a self,
        context: ExtensionNotificationContext<'a, Settings>,
        notification: ScaleNotification,
    ) -> fastmcp_rust::BoxFuture<'a, McpResult<()>> {
        Box::pin(async move {
            let mut guard = NotificationGuard {
                observations: Arc::clone(&self.0),
                completed: false,
            };
            self.0.started.fetch_add(1, Ordering::SeqCst);
            assert_eq!(context.descriptor().id(), EXTENSION);
            assert_eq!(context.method(), NOTIFICATION);
            assert_eq!(
                context.notification_descriptor().activation_metadata_key(),
                ACTIVATION
            );
            if notification.hold {
                std::future::pending::<()>().await;
            }
            asupersync::runtime::yield_now().await;
            context.checkpoint()?;
            self.0.total.fetch_add(
                usize::try_from(notification.value).expect("bounded fixture input")
                    * usize::try_from(context.settings().multiplier).expect("bounded multiplier"),
                Ordering::SeqCst,
            );
            self.0.completed.fetch_add(1, Ordering::SeqCst);
            guard.completed = true;
            Ok(())
        })
    }
}

fn notification_registration(observations: Arc<NotificationObservations>) -> ExtensionRegistration {
    let authorization = Arc::clone(&observations);
    builder()
        .typed_notification(
            NOTIFICATION,
            "scaled-notification-v1",
            ACTIVATION,
            move |notification: &ScaleNotification| {
                authorization.authorized.fetch_add(1, Ordering::SeqCst);
                if notification.value == 13 {
                    return Err(McpError::new(
                        fastmcp_rust::McpErrorCode::ResourceForbidden,
                        "notification operation denied",
                    ));
                }
                Ok(())
            },
            ScaleNotificationHandler(observations),
        )
        .expect("typed notification registers without raw descriptor authority")
        .build()
        .expect("notification-only extension seals")
}

fn notification(value: u32, hold: bool) -> fastmcp_rust::JsonValue {
    json!({
        "jsonrpc": "2.0",
        "method": NOTIFICATION,
        "params": {
            "value": value,
            "hold": hold,
            "_meta": { (ACTIVATION): { "version": 1 } }
        }
    })
}

async fn notification_http_exchange(
    address: std::net::SocketAddr,
    message: fastmcp_rust::JsonValue,
    authorization: bool,
) -> std::io::Result<Vec<u8>> {
    use asupersync::io::{AsyncReadExt, AsyncWriteExt};

    let body = fastmcp_rust::serde_json::to_vec(&message).map_err(std::io::Error::other)?;
    let authorization = if authorization {
        "Authorization: Bearer typed-notification-secret\r\n"
    } else {
        ""
    };
    let headers = format!(
        "POST /mcp HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nAccept-Encoding: identity\r\nConnection: close\r\n{authorization}Content-Length: {}\r\n\r\n",
        body.len()
    );
    let mut socket = asupersync::net::TcpStream::connect(address).await?;
    socket.write_all(headers.as_bytes()).await?;
    socket.write_all(&body).await?;
    socket.flush().await?;
    let mut response = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let count = socket.read(&mut buffer).await?;
        if count == 0 {
            return Ok(response);
        }
        assert!(response.len() + count <= 64 * 1024, "bounded wire response");
        response.extend_from_slice(&buffer[..count]);
    }
}

fn with_notification_http<F, Fut>(exercise: F) -> Arc<NotificationObservations>
where
    F: FnOnce(Cx, Cx, std::net::SocketAddr, Arc<NotificationObservations>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let observations = Arc::new(NotificationObservations::default());
    let retained = Arc::clone(&observations);
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().expect("caller reactor"))
        .build()
        .expect("caller-owned HTTP runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("caller context");
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
            let verifier = fastmcp_rust::StaticTokenVerifier::new([(
                "typed-notification-secret",
                fastmcp_rust::AuthContext::with_subject("notification-owner"),
            )])
            .expect("bounded test credential");
            let server = modern::ServerBuilder::new("typed-notifications", "1.0")
                .extension(notification_registration(Arc::clone(&observations)))
                .expect("public facade extension installation")
                .auth_provider(fastmcp_rust::TokenAuthProvider::new(verifier))
                .try_build()
                .expect("frozen modern server");
            let bound = server
                .bind_http(&cx, "127.0.0.1:0")
                .await
                .expect("live native listener");
            let address = bound.local_addr().unwrap();
            let (sender, mut receiver) = asupersync::channel::oneshot::channel();
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    sender
                        .send(&server_cx, server_cx.clone())
                        .expect("live parent retains listener context");
                    bound.serve(&server_cx).await
                })
                .expect("owned listener task");
            let server_cx = receiver.recv(&cx).await.expect("listener owner ready");
            exercise(cx.clone(), server_cx.clone(), address, observations).await;
            server_cx.cancel_with(
                asupersync::types::CancelKind::Shutdown,
                Some("notification test complete"),
            );
            let shutdown = serving
                .join(&cx)
                .await
                .expect("owned listener joins")
                .expect("listener shutdown");
            assert!(
                matches!(shutdown, fastmcp_rust::HttpServerShutdown::Quiescent),
                "all connection children settle"
            );
        })
        .await
        .expect("bounded notification exchange and cleanup");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    retained
}

#[test]
fn typed_notification_http_completes_and_revalidates_activation() {
    let observations =
        with_notification_http(|_cx, _server_cx, address, observations| async move {
            let valid = notification(7, false);
            let unauthenticated = notification_http_exchange(address, valid.clone(), false)
                .await
                .unwrap();
            assert!(unauthenticated.starts_with(b"HTTP/1.1 401"));
            assert_eq!(
                observations.authorized.load(Ordering::SeqCst),
                0,
                "authentication precedes the extension policy"
            );
            assert_eq!(observations.started.load(Ordering::SeqCst), 0);

            let accepted = notification_http_exchange(address, valid.clone(), true)
                .await
                .unwrap();
            assert!(
                accepted.starts_with(b"HTTP/1.1 202"),
                "{}",
                String::from_utf8_lossy(&accepted)
            );
            assert!(
                accepted.ends_with(b"\r\n\r\n"),
                "notification acknowledgement has no JSON-RPC result"
            );
            assert_eq!(
                observations.completed.load(Ordering::SeqCst),
                1,
                "completion precedes HTTP acknowledgement"
            );
            assert_eq!(observations.total.load(Ordering::SeqCst), 21);

            let mut missing = valid.clone();
            missing["params"]["_meta"]
                .as_object_mut()
                .unwrap()
                .remove(ACTIVATION);
            let mut incompatible = valid.clone();
            incompatible["params"]["_meta"][ACTIVATION]["version"] = json!(2);
            let mut malformed = valid.clone();
            malformed["params"]["value"] = json!("wrong-type");
            let mut unexpected = valid.clone();
            unexpected["params"]["unexpected"] = json!(true);
            let mut request_shaped = valid.clone();
            request_shaped["id"] = json!(9);
            let mut unknown = valid.clone();
            unknown["method"] = json!("com.example/unregistered");
            for (rejected, status) in [
                (missing, 400),
                (incompatible, 400),
                (malformed, 400),
                (unexpected, 400),
                (request_shaped, 400),
                (unknown, 400),
                (notification(13, false), 403),
            ] {
                let response = notification_http_exchange(address, rejected, true)
                    .await
                    .unwrap();
                assert!(
                    response.starts_with(format!("HTTP/1.1 {status}").as_bytes()),
                    "{}",
                    String::from_utf8_lossy(&response)
                );
                assert_eq!(
                    observations.started.load(Ordering::SeqCst),
                    1,
                    "refusal precedes the handler"
                );
                assert_eq!(observations.completed.load(Ordering::SeqCst), 1);
                assert_eq!(observations.total.load(Ordering::SeqCst), 21);
            }
            let mut fresh = notification(11, false);
            fresh["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] =
                json!("2025-11-25");
            fresh["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
                json!({"extensions":{(EXTENSION):{"version":2}}});
            let accepted = notification_http_exchange(address, fresh, true)
                .await
                .unwrap();
            assert!(
                accepted.starts_with(b"HTTP/1.1 202"),
                "only the descriptor-owned proof can activate a notification"
            );
            assert_eq!(observations.total.load(Ordering::SeqCst), 54);
        });
    assert_eq!(observations.completed.load(Ordering::SeqCst), 2);
    assert_eq!(observations.abandoned.load(Ordering::SeqCst), 0);
}

#[test]
fn typed_notification_http_cancellation_prevents_late_effects() {
    use std::future::Future;
    use std::task::Poll;

    let observations = with_notification_http(|_cx, server_cx, address, observations| async move {
        let mut exchange = Box::pin(notification_http_exchange(
            address,
            notification(7, true),
            true,
        ));
        while observations.started.load(Ordering::SeqCst) == 0 {
            assert!(
                std::future::poll_fn(|task| Poll::Ready(exchange.as_mut().poll(task)))
                    .await
                    .is_pending(),
                "uncompleted notification cannot be acknowledged"
            );
            asupersync::runtime::yield_now().await;
        }
        server_cx.cancel_with(
            asupersync::types::CancelKind::Shutdown,
            Some("cancel pending typed notification"),
        );
        if let Ok(response) = exchange.await {
            assert!(
                !response.starts_with(b"HTTP/1.1 202"),
                "cancelled work is not acknowledged as complete"
            );
        }
    });
    assert_eq!(observations.started.load(Ordering::SeqCst), 1);
    assert_eq!(observations.completed.load(Ordering::SeqCst), 0);
    assert_eq!(observations.total.load(Ordering::SeqCst), 0);
    assert_eq!(observations.abandoned.load(Ordering::SeqCst), 1);
}

#[test]
fn typed_notification_http_shutdown_settles_pending_work_after_sibling_completion() {
    use std::future::Future;
    use std::task::Poll;

    let observations = with_notification_http(|cx, server_cx, address, observations| async move {
        let mut pending = Box::pin(notification_http_exchange(
            address,
            notification(7, true),
            true,
        ));
        while observations.started.load(Ordering::SeqCst) == 0 {
            assert!(
                std::future::poll_fn(|task| Poll::Ready(pending.as_mut().poll(task)))
                    .await
                    .is_pending(),
                "pending notification must retain its response"
            );
            asupersync::runtime::yield_now().await;
        }

        let completed = notification_http_exchange(address, notification(11, false), true)
            .await
            .expect("independent notification completes while its sibling is pending");
        assert!(completed.starts_with(b"HTTP/1.1 202"));
        assert_eq!(observations.started.load(Ordering::SeqCst), 2);
        assert_eq!(observations.completed.load(Ordering::SeqCst), 1);
        assert_eq!(observations.total.load(Ordering::SeqCst), 33);

        server_cx.cancel_with(
            asupersync::types::CancelKind::Shutdown,
            Some("stop listener with one pending and one completed notification"),
        );
        if let Ok(response) = asupersync::time::timeout(cx.now(), Duration::from_secs(2), pending)
            .await
            .expect("listener shutdown closes pending notification without its 60-second deadline")
        {
            assert!(
                !response.starts_with(b"HTTP/1.1 202"),
                "incomplete notification cannot publish a success acknowledgement"
            );
        }
        assert!(cx.checkpoint().is_ok(), "the application caller stays live");
    });
    assert_eq!(observations.started.load(Ordering::SeqCst), 2);
    assert_eq!(observations.completed.load(Ordering::SeqCst), 1);
    assert_eq!(observations.total.load(Ordering::SeqCst), 33);
    assert_eq!(observations.abandoned.load(Ordering::SeqCst), 1);
}
