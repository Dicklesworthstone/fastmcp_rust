//! Live transport coverage for the restricted extension authoring facade.
//! These tests use the shipped server pump on an application-owned runtime.

#![cfg(feature = "extension-authoring")]
#![recursion_limit = "512"]

#[path = "extension_authoring/result_client.rs"]
mod result_client;

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
    // Advertise Tasks in the shared baseline so each negative below isolates
    // the typed extension's settings or schema. The composition test explicitly
    // removes Tasks to exercise its per-request inactivity, and corrupts its
    // settings separately to verify the frozen bilateral validator still runs.
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
#[cfg(feature = "tasks")]
fn typed_extension_requests_compose_with_optional_default_tasks() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut requests = vec![
        request(1, Some(json!({"version": 1})), json!(7)),
        request(2, Some(json!({"version": 1})), json!(11)),
        request(3, Some(json!({"version": 1})), json!(13)),
        request(4, None, json!(13)),
        request(5, Some(json!({"version": 1})), json!(17)),
    ];
    for (index, settings) in [
        (0, None),
        (1, Some(json!({}))),
        (2, Some(json!({"unexpected": true}))),
        (3, Some(json!({}))),
        (4, None),
    ] {
        let JsonRpcMessage::Request(request) = &mut requests[index] else {
            panic!("fixture is an extension request");
        };
        let extensions =
            request.params.as_mut().unwrap()["_meta"]["io.modelcontextprotocol/clientCapabilities"]
                ["extensions"]
                .as_object_mut()
                .unwrap();
        match settings {
            Some(settings) => {
                extensions.insert("io.modelcontextprotocol/tasks".to_owned(), settings);
            }
            None => {
                extensions.remove("io.modelcontextprotocol/tasks");
            }
        }
    }
    let responses = run_exchange(registration(Arc::clone(&calls)), requests);
    for (index, expected) in [(0, 21), (1, 33), (4, 51)] {
        assert!(responses[index].error.is_none(), "{:?}", responses[index]);
        assert_eq!(responses[index].result.as_ref().unwrap()["value"], expected);
    }
    for response in &responses[2..4] {
        assert!(response.error.is_some(), "{response:?}");
        assert!(response.result.is_none());
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "absent Tasks is optional; malformed Tasks and absent typed settings cannot reach the handler",
    );
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

#[test]
fn typed_notification_stdio_authenticates_and_drains_without_notification_responses() {
    exercise_notification_stdio(false);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn typed_notification_stdio_auto_selects_modern_before_current_message_activation() {
    exercise_notification_stdio(true);
}

fn exercise_notification_stdio(auto: bool) {
    use asupersync::net::{TcpListener, TcpStream};
    use fastmcp_rust::AsyncStdioTransport;

    const TOKEN: &str = "stdio-notification-owner";
    const FOREIGN_TOKEN: &str = "stdio-notification-foreign";

    let observations = Arc::new(NotificationObservations::default());
    let observed = Arc::clone(&observations);
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().expect("caller reactor"))
        .blocking_threads(0, 0)
        .build()
        .expect("caller-owned native stdio runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("caller context");
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
            let verifier = fastmcp_rust::StaticTokenVerifier::new([
                (TOKEN, fastmcp_rust::AuthContext::with_subject("owner")),
                (
                    FOREIGN_TOKEN,
                    fastmcp_rust::AuthContext::with_subject("foreign"),
                ),
            ])
            .expect("bounded test credentials");
            let registration = notification_registration(Arc::clone(&observations));
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("native NDJSON listener");
            let address = listener.local_addr().unwrap();
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    let (socket, _) = listener.accept().await.expect("native peer accepts");
                    let (input, output) = socket.into_split();
                    #[cfg(feature = "legacy-2024-11-05")]
                    if auto {
                        let server =
                            fastmcp_rust::auto::ServerBuilder::new("stdio-notifications", "1.0")
                                .extension(registration)
                                .expect("public Auto facade extension installation")
                                .auth_provider(fastmcp_rust::TokenAuthProvider::new(verifier))
                                .try_build()
                                .expect("frozen Auto server");
                        return server.serve_stdio_io(&server_cx, input, output).await;
                    }
                    #[cfg(not(feature = "legacy-2024-11-05"))]
                    assert!(!auto, "Auto requires the exact legacy adapter feature");
                    let server = modern::ServerBuilder::new("stdio-notifications", "1.0")
                        .extension(registration)
                        .expect("public modern facade extension installation")
                        .auth_provider(fastmcp_rust::TokenAuthProvider::new(verifier))
                        .try_build()
                        .expect("frozen modern server");
                    server.serve_stdio_io(&server_cx, input, output).await
                })
                .expect("owned stdio server task");
            let socket = TcpStream::connect(address)
                .await
                .expect("native peer connects");
            let (input, output) = socket.split();
            let mut peer = AsyncStdioTransport::from_io(input, output);
            let frame = |mut value: fastmcp_rust::JsonValue, token: Option<&str>| {
                if let Some(token) = token {
                    value["params"]["_meta"]["token"] = json!(token);
                }
                fastmcp_rust::serde_json::from_value::<JsonRpcMessage>(value)
                    .expect("valid JSON-RPC fixture")
            };
            let discovery = |id| {
                frame(
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "server/discover",
                        "params": {"_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {}
                        }}
                    }),
                    Some(TOKEN),
                )
            };
            peer.send_async(&cx, &discovery(81_i64)).await.unwrap();
            let JsonRpcMessage::Response(response) = peer.recv_async(&cx).await.unwrap() else {
                panic!("discovery returns its ordinary request response");
            };
            assert_eq!(response.id, Some(RequestId::Number(81)));
            assert!(response.error.is_none(), "{response:?}");

            let valid = notification(7, false);
            for token in [None, Some(FOREIGN_TOKEN)] {
                peer.send_async(&cx, &frame(valid.clone(), token))
                    .await
                    .unwrap();
            }
            peer.send_async(&cx, &frame(valid.clone(), Some(TOKEN)))
                .await
                .unwrap();
            while observations.completed.load(Ordering::SeqCst) == 0 {
                asupersync::runtime::yield_now().await;
            }
            assert_eq!(
                observations.authorized.load(Ordering::SeqCst),
                1,
                "missing credentials and a different connection principal fail before policy"
            );
            assert_eq!(observations.started.load(Ordering::SeqCst), 1);
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
            let mut unknown = valid;
            unknown["method"] = json!("com.example/unregistered");
            for rejected in [
                missing,
                incompatible,
                malformed,
                unexpected,
                unknown,
                notification(13, false),
            ] {
                peer.send_async(&cx, &frame(rejected, Some(TOKEN)))
                    .await
                    .unwrap();
            }
            let mut fresh = notification(11, false);
            fresh["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] =
                json!("2025-11-25");
            fresh["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
                json!({"extensions": {(EXTENSION): {"version": 2}}});
            peer.send_async(&cx, &frame(fresh, Some(TOKEN)))
                .await
                .unwrap();
            // Input EOF cancels still-running id-less children. Discovery is
            // allowed to overtake a notification, so wait for the callbacks
            // themselves before using EOF to verify complete wire silence.
            while observations.authorized.load(Ordering::SeqCst) < 5
                || observations.completed.load(Ordering::SeqCst) < 2
            {
                asupersync::runtime::yield_now().await;
            }
            peer.send_async(&cx, &discovery(82_i64)).await.unwrap();

            // Half-close the actual socket, preserving the peer's reader.
            // Closing the transport itself would latch its terminal locally
            // and could hide an illegal notification response still on wire.
            socket
                .shutdown(std::net::Shutdown::Write)
                .expect("peer input EOF starts the server's accepted-work drain");
            let JsonRpcMessage::Response(response) = peer.recv_async(&cx).await.unwrap() else {
                panic!("only the explicit discovery request produces a response");
            };
            assert_eq!(response.id, Some(RequestId::Number(82)));
            assert!(response.error.is_none(), "{response:?}");
            assert!(
                matches!(peer.recv_async(&cx).await, Err(TransportError::Closed)),
                "successful and rejected notifications remain silent through actual wire EOF"
            );
            serving
                .join(&cx)
                .await
                .expect("owned stdio server joins")
                .expect("EOF drains every accepted notification");
            assert!(cx.checkpoint().is_ok(), "the application caller stays live");
        })
        .await
        .expect("bounded native NDJSON exchange and complete notification drain");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    assert_eq!(observed.authorized.load(Ordering::SeqCst), 5);
    assert_eq!(observed.started.load(Ordering::SeqCst), 2);
    assert_eq!(observed.completed.load(Ordering::SeqCst), 2);
    assert_eq!(observed.total.load(Ordering::SeqCst), 54);
    assert_eq!(observed.abandoned.load(Ordering::SeqCst), 0);
}

fn memory_notification_frame(
    mut value: fastmcp_rust::JsonValue,
    token: Option<&str>,
) -> JsonRpcMessage {
    if let Some(token) = token {
        value["params"]["_meta"]["token"] = json!(token);
    }
    fastmcp_rust::serde_json::from_value(value).expect("valid JSON-RPC fixture")
}

fn notification_discovery(id: i64) -> JsonRpcMessage {
    memory_notification_frame(
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "server/discover",
            "params": {"_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }}
        }),
        Some("memory-notification-owner"),
    )
}

fn memory_notification_server(observations: Arc<NotificationObservations>) -> modern::Server {
    let verifier = fastmcp_rust::StaticTokenVerifier::new([
        (
            "memory-notification-owner",
            fastmcp_rust::AuthContext::with_subject("owner"),
        ),
        (
            "memory-notification-foreign",
            fastmcp_rust::AuthContext::with_subject("foreign"),
        ),
    ])
    .unwrap();
    modern::ServerBuilder::new("memory-notifications", "1.0")
        .extension(notification_registration(observations))
        .unwrap()
        .auth_provider(fastmcp_rust::TokenAuthProvider::new(verifier))
        .try_build()
        .unwrap()
}

#[test]
fn typed_notification_memory_authenticates_each_frame_and_revalidates_activation() {
    let observations = Arc::new(NotificationObservations::default());
    let observed = Arc::clone(&observations);
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
            let server = memory_notification_server(Arc::clone(&observations));
            let (mut peer, transport) = create_memory_transport_pair_with_capacity(1);
            let mut serving = cx
                .spawn(move |cx| async move { server.serve_memory(&cx, transport).await })
                .unwrap();
            peer.send_async(&cx, &notification_discovery(1))
                .await
                .unwrap();
            assert!(response(&cx, &mut peer, 1).await.error.is_none());

            let valid = notification(7, false);
            for token in [None, Some("memory-notification-foreign")] {
                peer.send_async(&cx, &memory_notification_frame(valid.clone(), token))
                    .await
                    .unwrap();
            }
            peer.send_async(
                &cx,
                &memory_notification_frame(valid.clone(), Some("memory-notification-owner")),
            )
            .await
            .unwrap();

            let mut missing = valid.clone();
            missing["params"]["_meta"]
                .as_object_mut()
                .unwrap()
                .remove(ACTIVATION);
            let mut incompatible = valid.clone();
            incompatible["params"]["_meta"][ACTIVATION]["version"] = json!(2);
            let mut malformed = valid.clone();
            malformed["params"]["value"] = json!("wrong-type");
            let mut extra_parameter = valid.clone();
            extra_parameter["params"]["unexpected"] = json!(true);
            let mut unknown = valid;
            unknown["method"] = json!("com.example/unregistered");
            for rejected in [
                missing,
                incompatible,
                malformed,
                extra_parameter,
                unknown,
                notification(13, false),
            ] {
                peer.send_async(
                    &cx,
                    &memory_notification_frame(rejected, Some("memory-notification-owner")),
                )
                .await
                .unwrap();
            }
            let mut fresh = notification(11, false);
            fresh["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] =
                json!("2025-11-25");
            fresh["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
                json!({"extensions": {(EXTENSION): {"version": 2}}});
            peer.send_async(
                &cx,
                &memory_notification_frame(fresh, Some("memory-notification-owner")),
            )
            .await
            .unwrap();
            // Input EOF cancels still-running id-less children. Discovery is
            // allowed to overtake a notification, so wait for the callbacks
            // themselves before using EOF to verify complete wire silence.
            while observations.authorized.load(Ordering::SeqCst) < 5
                || observations.completed.load(Ordering::SeqCst) < 2
            {
                asupersync::runtime::yield_now().await;
            }
            peer.send_async(&cx, &notification_discovery(2))
                .await
                .unwrap();
            let (mut input, output) = peer.into_split();
            drop(output);
            let JsonRpcMessage::Response(response) = input.recv_async(&cx).await.unwrap() else {
                panic!("only the explicit discovery request produces a response");
            };
            assert_eq!(response.id, Some(RequestId::Number(2)));
            assert!(response.error.is_none(), "{response:?}");
            assert!(matches!(
                input.recv_async(&cx).await,
                Err(TransportError::Closed)
            ));
            serving.join(&cx).await.unwrap().unwrap();
            assert!(cx.checkpoint().is_ok());
        })
        .await
        .expect("bounded native memory exchange and full notification drain");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    assert_eq!(observed.authorized.load(Ordering::SeqCst), 5);
    assert_eq!(observed.started.load(Ordering::SeqCst), 2);
    assert_eq!(observed.completed.load(Ordering::SeqCst), 2);
    assert_eq!(observed.total.load(Ordering::SeqCst), 54);
    assert_eq!(observed.abandoned.load(Ordering::SeqCst), 0);
}

#[test]
fn typed_notification_memory_shutdown_cancels_pending_work_without_blocking_siblings() {
    let observations = Arc::new(NotificationObservations::default());
    let observed = Arc::clone(&observations);
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
            let server = memory_notification_server(Arc::clone(&observations));
            let (mut peer, transport) = create_memory_transport_pair_with_capacity(1);
            let (sender, mut receiver) = asupersync::channel::oneshot::channel();
            let mut serving = cx
                .spawn(move |server_cx| async move {
                    sender.send(&server_cx, server_cx.clone()).unwrap();
                    server.serve_memory(&server_cx, transport).await
                })
                .unwrap();
            let server_cx = receiver.recv(&cx).await.unwrap();
            peer.send_async(
                &cx,
                &memory_notification_frame(
                    notification(7, true),
                    Some("memory-notification-owner"),
                ),
            )
            .await
            .unwrap();
            while observations.started.load(Ordering::SeqCst) == 0 {
                asupersync::runtime::yield_now().await;
            }
            peer.send_async(&cx, &notification_discovery(1))
                .await
                .unwrap();
            assert!(response(&cx, &mut peer, 1).await.error.is_none());
            peer.send_async(
                &cx,
                &memory_notification_frame(
                    notification(11, false),
                    Some("memory-notification-owner"),
                ),
            )
            .await
            .unwrap();
            while observations.completed.load(Ordering::SeqCst) == 0 {
                asupersync::runtime::yield_now().await;
            }
            assert_eq!(observations.started.load(Ordering::SeqCst), 2);
            assert_eq!(observations.total.load(Ordering::SeqCst), 33);
            server_cx.cancel_with(
                asupersync::types::CancelKind::Shutdown,
                Some("stop pending native extension notification"),
            );
            assert!(matches!(
                asupersync::time::timeout(cx.now(), Duration::from_secs(2), peer.recv_async(&cx))
                    .await
                    .expect("shutdown does not wait for the notification deadline"),
                Err(TransportError::Closed)
            ));
            serving.join(&cx).await.unwrap().unwrap();
            assert!(cx.checkpoint().is_ok(), "caller authority stays live");
        })
        .await
        .expect("bounded native notification cancellation and cleanup");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    assert_eq!(observed.started.load(Ordering::SeqCst), 2);
    assert_eq!(observed.completed.load(Ordering::SeqCst), 1);
    assert_eq!(observed.total.load(Ordering::SeqCst), 33);
    assert_eq!(observed.abandoned.load(Ordering::SeqCst), 1);
}
