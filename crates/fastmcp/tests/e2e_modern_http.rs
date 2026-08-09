//! Public modern HTTP round trip: shipped client against shipped server.
//!
//! Both ends of these tests are real shipped-facade surfaces — the turnkey
//! `Server::bind_http`/`serve` lifecycle on one side and
//! `auto::client_builder()` connection lifecycle on the other — joined over
//! one real localhost socket. No scripted peer, fixture transcript, mock, or
//! direct FastMCP component-crate import stands in for either endpoint.
//!
//! What this proves (and only this): the shipped dual-era HTTP server and
//! facade clients can complete Auto classification and a round trip against
//! each other — modern discovery plus `ping` over the live modern lane,
//! then exact 2024-11-05 HTTP+SSE fallback after an eligible live modern-route
//! refusal. It is not an aggregate MCP 2026-07-28 conformance claim.

use std::net::SocketAddr;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use asupersync::CancelKind;
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::reactor::create_reactor;
use fastmcp_rust::{
    CanonicalHttpUrl, ClientHttpResponse, ClientProtocolPlan, Cx, JsonRpcMessage,
    ModernHttpResponseKind, ModernHttpResponseStream, ProtocolEra, ProtocolPolicy, Server,
    SseLimits, auto,
};
use serde_json::json;

fn runtime_block_on<F: std::future::Future>(future: F) -> F::Output {
    RuntimeBuilder::current_thread()
        .build()
        .expect("native runtime must build")
        .block_on(future)
}

const HTTP_SERVER_STARTUP_BOUND: Duration = Duration::from_secs(2);
const HTTP_SERVER_TEARDOWN_BOUND: Duration = Duration::from_secs(2);
/// Hard ceiling for the server task itself. This bounds the owned thread even
/// if cancellation is not observed by a future regression in server teardown.
const HTTP_SERVER_THREAD_BOUND: Duration = Duration::from_secs(4);

/// Owns one real public HTTP server composition and proves its teardown.
///
/// The fixture deliberately uses the minimal `Server::new(...).build()`
/// composition published in the facade examples, rather than a test-local
/// handler. Its only client request is `ping`, which every shipped server
/// implements without a bespoke test tool.
struct HttpServerFixture {
    address: SocketAddr,
    shutdown: mpsc::SyncSender<()>,
    finished: mpsc::Receiver<Result<(), String>>,
    join: Option<JoinHandle<()>>,
}

impl HttpServerFixture {
    fn spawn() -> Self {
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(1);
        let (shutdown_tx, shutdown_rx) = mpsc::sync_channel::<()>(1);
        let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let mut join = Some(thread::spawn(move || {
            let ready_for_spawn_failure = ready_tx.clone();
            let finished_for_spawn_failure = finished_tx.clone();
            let (task_done_tx, task_done_rx) = mpsc::channel::<()>();
            let (server_cx_tx, server_cx_rx) = mpsc::sync_channel::<Cx>(1);
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(create_reactor().expect("server reactor initializes"))
                .blocking_threads(4, 64)
                .build()
                .expect("server runtime builds");
            let server_task = runtime.handle().try_spawn_with_cx(move |cx| {
                let server_cx_tx = server_cx_tx;
                async move {
                    if server_cx_tx.send(cx.clone()).is_err() {
                        cx.cancel_with(
                            CancelKind::User,
                            Some("HTTP E2E server control receiver went away"),
                        );
                        let _ = finished_tx
                            .send(Err("HTTP E2E server control receiver went away".to_owned()));
                        let _ = task_done_tx.send(());
                        return;
                    }
                    let outcome =
                        match asupersync::time::timeout(cx.now(), HTTP_SERVER_THREAD_BOUND, async {
                            let bound = match Server::new("facade-http-example", "1.0.0")
                                .protocol_policy(ProtocolPolicy::Auto)
                                .build()
                                .bind_http(&cx, "127.0.0.1:0")
                                .await
                            {
                                Ok(bound) => bound,
                                Err(error) => {
                                    let message =
                                        format!("facade HTTP server bind failed: {error}");
                                    let _ = ready_tx.send(Err(message.clone()));
                                    return Err(message);
                                }
                            };
                            let address = match bound.local_addr() {
                                Ok(address) => address,
                                Err(error) => {
                                    let message =
                                        format!("facade HTTP server address failed: {error}");
                                    let _ = ready_tx.send(Err(message.clone()));
                                    return Err(message);
                                }
                            };
                            if ready_tx.send(Ok(address)).is_err() {
                                cx.cancel_with(
                                    CancelKind::User,
                                    Some("HTTP E2E startup receiver went away"),
                                );
                                return Err("HTTP E2E startup receiver went away".to_owned());
                            }
                            bound.serve(&cx).await.map_err(|error| {
                                format!("facade HTTP server stopped unexpectedly: {error}")
                            })
                        })
                        .await
                        {
                            Ok(outcome) => outcome,
                            Err(_) => {
                                cx.cancel_with(
                                    CancelKind::User,
                                    Some("HTTP E2E server task hard deadline exceeded"),
                                );
                                Err("facade HTTP server exceeded its hard task deadline".to_owned())
                            }
                        };
                    let _ = finished_tx.send(outcome);
                    let _ = task_done_tx.send(());
                }
            });
            if let Err(error) = server_task {
                let message = format!("facade HTTP server task was not admitted: {error}");
                let _ = ready_for_spawn_failure.send(Err(message.clone()));
                let _ = finished_for_spawn_failure.send(Err(message));
                return;
            }
            runtime.block_on(async move {
                let mut server_cx = None;
                let mut shutdown_requested = false;
                loop {
                    match shutdown_rx.try_recv() {
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                            shutdown_requested = true;
                        }
                        Err(mpsc::TryRecvError::Empty) => {}
                    }
                    if server_cx.is_none() {
                        if let Ok(cx) = server_cx_rx.try_recv() {
                            server_cx = Some(cx);
                        }
                    }
                    if shutdown_requested {
                        if let Some(cx) = server_cx.as_ref() {
                            cx.cancel_with(
                                CancelKind::User,
                                Some("HTTP E2E fixture shutdown requested"),
                            );
                        }
                    }
                    match task_done_rx.try_recv() {
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                        Err(mpsc::TryRecvError::Empty) => {
                            let cx = Cx::current().expect("server runtime installs an ambient Cx");
                            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                        }
                    }
                }
            });
        }));

        let address = match ready_rx.recv_timeout(HTTP_SERVER_STARTUP_BOUND) {
            Ok(Ok(address)) => address,
            Ok(Err(error)) => {
                let settlement = settle_http_server(
                    &shutdown_tx,
                    &finished_rx,
                    join.take()
                        .expect("HTTP server fixture retains its join handle"),
                );
                panic!(
                    "public HTTP server failed to start: {error}; {settlement:?} after thread settlement"
                );
            }
            Err(error) => {
                drop(ready_rx);
                let settlement = settle_http_server(
                    &shutdown_tx,
                    &finished_rx,
                    join.take()
                        .expect("HTTP server fixture retains its join handle"),
                );
                panic!(
                    "public HTTP server startup exceeded its bound: {error}; {settlement:?} after thread settlement"
                );
            }
        };

        Self {
            address,
            shutdown: shutdown_tx,
            finished: finished_rx,
            join,
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn settle(&mut self) -> Result<(), String> {
        settle_http_server(
            &self.shutdown,
            &self.finished,
            self.join
                .take()
                .expect("HTTP server fixture retains its join handle"),
        )
    }

    fn shutdown(mut self) {
        self.settle()
            .unwrap_or_else(|error| panic!("public HTTP server teardown failed: {error}"));
    }
}

impl Drop for HttpServerFixture {
    fn drop(&mut self) {
        if self.join.is_none() {
            return;
        }
        let settlement = self.settle();
        if !std::thread::panicking() {
            settlement
                .unwrap_or_else(|error| panic!("public HTTP server fixture drop failed: {error}"));
        }
    }
}

/// Signals shutdown without blocking and joins the owned server thread before
/// returning any startup or teardown failure to the test.
fn settle_http_server(
    shutdown: &mpsc::SyncSender<()>,
    finished: &mpsc::Receiver<Result<(), String>>,
    join: JoinHandle<()>,
) -> Result<(), String> {
    settle_http_server_with_bound(shutdown, finished, join, HTTP_SERVER_TEARDOWN_BOUND)
}

/// This helper is separately bounded so the planted timeout test can prove
/// that a reported timeout follows, rather than replaces, joining the owner.
fn settle_http_server_with_bound(
    shutdown: &mpsc::SyncSender<()>,
    finished: &mpsc::Receiver<Result<(), String>>,
    join: JoinHandle<()>,
    completion_bound: Duration,
) -> Result<(), String> {
    match shutdown.try_send(()) {
        Ok(()) | Err(mpsc::TrySendError::Full(())) | Err(mpsc::TrySendError::Disconnected(())) => {}
    }
    let completion = finished
        .recv_timeout(completion_bound)
        .map_err(|error| format!("public HTTP server teardown exceeded its bound: {error}"));
    let joined = join
        .join()
        .map_err(|_| "HTTP server thread panicked during settlement".to_owned());

    joined?;
    completion?.map_err(|error| format!("public HTTP server teardown failed: {error}"))
}

#[test]
fn e2e_http_fixture_planted_teardown_timeout_joins_before_failure() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (shutdown_tx, shutdown_rx) = mpsc::sync_channel::<()>(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let joined = Arc::new(AtomicBool::new(false));
    let joined_by_server = Arc::clone(&joined);
    let server = thread::spawn(move || {
        shutdown_rx
            .recv()
            .expect("the bounded settlement path sends one shutdown signal");
        joined_by_server.store(true, Ordering::SeqCst);
    });

    let settlement =
        settle_http_server_with_bound(&shutdown_tx, &finished_rx, server, Duration::ZERO);

    assert!(
        joined.load(Ordering::SeqCst),
        "the planted timeout is reported only after the owned server thread joined"
    );
    assert!(matches!(settlement, Err(error) if error.contains("exceeded its bound")));
    drop(finished_tx);
}

fn plan(addr: SocketAddr, policy: ProtocolPolicy) -> ClientProtocolPlan {
    plan_with_modern_post_path(addr, policy, "/mcp")
}

/// Builds one immutable public endpoint plan while allowing the Auto probe to
/// target a live server route that is intentionally not mounted as modern.
/// This lets the fallback test observe the real 404 response required by the
/// public negotiation contract without substituting a scripted HTTP peer.
fn plan_with_modern_post_path(
    addr: SocketAddr,
    policy: ProtocolPolicy,
    modern_post_path: &str,
) -> ClientProtocolPlan {
    let modern_target = CanonicalHttpUrl::parse(&format!("http://{addr}{modern_post_path}"))
        .expect("local modern target must be canonical");
    let legacy_sse = CanonicalHttpUrl::parse(&format!("http://{addr}/sse"))
        .expect("legacy SSE target must be canonical");
    let legacy_message = CanonicalHttpUrl::parse(&format!("http://{addr}/messages"))
        .expect("legacy message target must be canonical");
    ClientProtocolPlan::http(
        policy,
        (!matches!(policy, ProtocolPolicy::LegacyOnly)).then_some(modern_target),
        (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_sse),
        (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_message),
        "credential-partition-e2e-http".to_owned(),
        "security-partition-e2e-http".to_owned(),
        "native-h1-e2e-http".to_owned(),
        1,
        1,
        0,
    )
    .expect("the complete HTTP plan must be accepted")
}

/// Consumes whichever response lane the real server selected and returns the
/// final correlated JSON-RPC response document.
fn final_response_document(cx: &Cx, response: ModernHttpResponseStream) -> serde_json::Value {
    match response.metadata().kind() {
        ModernHttpResponseKind::Json => {
            let bytes = runtime_block_on(response.read_to_end(cx, 1 << 20))
                .expect("immediate JSON body reads to end");
            serde_json::from_slice(&bytes).expect("immediate JSON response parses")
        }
        ModernHttpResponseKind::Sse => {
            let mut stream = response
                .into_sse_stream(SseLimits::new(65_536, 1 << 20, 64).expect("nonzero SSE limits"))
                .expect("SSE response admits the shipped parser");
            let mut terminal = None;
            while let Some(event) =
                runtime_block_on(stream.next_event(cx)).expect("SSE stream stays readable")
            {
                let value: serde_json::Value =
                    serde_json::from_str(&event).expect("SSE payload is one JSON document");
                if value.get("id").is_some() {
                    terminal = Some(value);
                }
            }
            terminal.expect("SSE stream carried a final correlated response")
        }
        ModernHttpResponseKind::EmptyAcknowledgement => {
            panic!("a correlated request cannot complete with an empty acknowledgement")
        }
        ModernHttpResponseKind::HttpFailure => panic!(
            "unexpected HTTP failure status {} from the shipped server",
            response.metadata().status()
        ),
    }
}

#[test]
fn e2e_public_http_auto_selects_modern_on_the_shipped_facade_server() {
    let server = HttpServerFixture::spawn();
    let cx = Cx::for_request();
    let builder = auto::client_builder()
        .client_info("e2e-modern-http-client", "1.0.0")
        .protocol_plan(plan(server.address(), ProtocolPolicy::Auto));
    assert_eq!(
        builder.selected_protocol_plan().policy(),
        ProtocolPolicy::Auto
    );

    let mut client = runtime_block_on(builder.connect_http_client_with_cx(&cx))
        .expect("the public Auto facade client completes live modern discovery");
    assert_eq!(
        client.selected_protocol_era(),
        ProtocolEra::Modern2026,
        "a live modern discovery response must never downgrade Auto"
    );
    assert_eq!(client.protocol_plan().policy(), ProtocolPolicy::Auto);
    assert!(
        client.server_discovery().is_some(),
        "modern selection exposes the public discovery result"
    );
    assert_eq!(
        client.connection().protocol_version(),
        Some(fastmcp_rust::modern::PROTOCOL_VERSION),
        "the public HTTP connection reports the exact modern negotiated version"
    );

    let response = runtime_block_on(client.request(&cx, "ping", json!({})))
        .expect("the Auto-selected modern connection serves requests");
    let ClientHttpResponse::Modern(response) = response else {
        panic!("the selected modern HTTP client must retain the modern response lane");
    };
    let document = final_response_document(&cx, response);
    assert_eq!(document["id"], json!(2));
    assert!(
        document.get("error").is_none(),
        "ping over the Auto-selected connection must not fail: {document}"
    );
    drop(client);
    server.shutdown();
}

#[test]
fn e2e_public_http_auto_falls_back_to_exact_legacy_on_live_eligible_refusal() {
    let server = HttpServerFixture::spawn();
    let cx = Cx::for_request();

    // `/modern-unavailable` is a real but unmounted route on the shipped
    // server. Its live 404 is an eligible Auto fallback signal; the complete
    // legacy SSE and message targets remain explicitly configured.
    let builder = auto::client_builder()
        .client_info("e2e-legacy-http-client", "1.0.0")
        .protocol_plan(plan_with_modern_post_path(
            server.address(),
            ProtocolPolicy::Auto,
            "/modern-unavailable",
        ));
    assert_eq!(
        builder.selected_protocol_plan().policy(),
        ProtocolPolicy::Auto
    );
    let mut client = runtime_block_on(builder.connect_http_client_with_cx(&cx))
        .expect("an eligible live modern-route refusal completes the exact legacy lifecycle");
    assert_eq!(
        client.selected_protocol_era(),
        ProtocolEra::Legacy2024,
        "Auto must expose exact legacy selection only after its eligible live refusal"
    );
    assert_eq!(client.protocol_plan().policy(), ProtocolPolicy::Auto);
    assert!(
        client.server_discovery().is_none(),
        "exact legacy fallback cannot expose modern discovery state"
    );
    assert_eq!(
        client.connection().protocol_version(),
        Some(fastmcp_rust::legacy_2024::PROTOCOL_VERSION),
        "the public HTTP connection retains the exact validated legacy initialize wire version"
    );
    assert_eq!(
        client.server_info().name,
        "facade-http-example",
        "the legacy initialization result comes from the shipped facade server composition"
    );
    let ping = runtime_block_on(client.request(&cx, "ping", json!({})))
        .expect("the initialized exact-legacy fallback remains usable");
    let ClientHttpResponse::Legacy(JsonRpcMessage::Response(ping)) = ping else {
        panic!("the exact-legacy fallback must answer ping through its legacy response lane");
    };
    assert!(ping.error.is_none(), "legacy ping must not fail: {ping:?}");
    drop(client);
    server.shutdown();
}
