//! Issue #76: real TCP disconnects must reach a synchronous handler's context.
//!
//! These tests use the shipped secured listener, Bearer admission and blocking
//! dispatch on a caller-owned runtime. No mock transport or client library can
//! synthesize cancellation. The FIN-only case also pins the native listener's
//! policy: write-half-closing before the response is complete abandons a request.
#![recursion_limit = "256"]

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use asupersync::{Cx, types::CancelKind};
use fastmcp_core::{AuthContext, McpContext, McpResult};
use fastmcp_protocol::{Content, FINAL_PROTOCOL_VERSION, Tool, protocol_policy::ProtocolPolicy};
use fastmcp_server::http_admission::security::HttpSecurityPolicy;
use fastmcp_server::http_admission::security::scope_policy::request::ScopeRequestPolicy;
use fastmcp_server::http_admission::security::scope_policy::{
    RequiredScopes, ScopeImplicationPolicy,
};
use fastmcp_server::http_admission::{HttpAdmissionLimits, HttpEndpointConfig};
use fastmcp_server::{
    HttpServerShutdown, Server, StaticTokenVerifier, TokenAuthProvider, ToolHandler,
};
use serde_json::{Value, json};

const BOUND: Duration = Duration::from_secs(5);
const SERVER_TIMEOUT_SECS: u64 = 60;
const HANDLER_WATCHDOG: Duration = Duration::from_secs(20);
const ACCEPTS: [&str; 2] = ["application/json", "application/json, text/event-stream"];
const TOKEN: &str = "http-disconnect-regression-token";
const LOST: &str = "disconnect_wait";
const SURVIVOR: &str = "survivor_wait";

#[derive(Default)]
struct Probe {
    context: Mutex<Option<McpContext>>,
    release: AtomicBool,
    observed_cancel: AtomicBool,
    exited: AtomicBool,
    watchdog_expired: AtomicBool,
}

struct BlockingTool {
    name: &'static str,
    probe: Arc<Probe>,
}

impl ToolHandler for BlockingTool {
    fn definition(&self) -> Tool {
        Tool {
            name: self.name.to_owned(),
            description: None,
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        }
    }

    // Deliberately implement only the synchronous hook. On a single-thread
    // network executor this must not prevent the peer monitor from running.
    fn call(&self, ctx: &McpContext, _: Value) -> McpResult<Vec<Content>> {
        let started = Instant::now();
        *self.probe.context.lock().unwrap() = Some(ctx.clone());
        while !self.probe.release.load(Ordering::Acquire) {
            if ctx.is_cancelled() {
                self.probe.observed_cancel.store(true, Ordering::Release);
                break;
            }
            if started.elapsed() >= HANDLER_WATCHDOG {
                self.probe.watchdog_expired.store(true, Ordering::Release);
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        self.probe.exited.store(true, Ordering::Release);
        Ok(vec![Content::text(format!("{}-finished", self.name))])
    }
}

#[derive(Default)]
struct ListenerControl {
    stopping: bool,
    cx: Option<Cx>,
}

// Cleanup is armed before startup can time out. Every failing assertion releases
// synchronous work, stops only the listener child and joins the owning runtime.
struct RunningServer {
    address: Option<SocketAddr>,
    control: Arc<Mutex<ListenerControl>>,
    thread: Option<JoinHandle<()>>,
    lost: Arc<Probe>,
    survivor: Arc<Probe>,
}

impl RunningServer {
    fn start(scoped: bool) -> Self {
        let control = Arc::new(Mutex::new(ListenerControl::default()));
        let lost = Arc::new(Probe::default());
        let survivor = Arc::new(Probe::default());
        let worker_control = Arc::clone(&control);
        let worker_lost = Arc::clone(&lost);
        let worker_survivor = Arc::clone(&survivor);
        let (started, startup) = mpsc::channel();
        let worker = thread::spawn(move || {
            asupersync::runtime::RuntimeBuilder::current_thread()
                .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
                .blocking_threads(2, 4)
                .build()
                .unwrap()
                .block_on(async move {
                    let cx = Cx::current().unwrap();
                    let mut serving = cx
                        .spawn(move |server_cx| async move {
                            {
                                let mut control = worker_control.lock().unwrap();
                                control.cx = Some(server_cx.clone());
                                if control.stopping {
                                    return None;
                                }
                            }
                            let mut facts = AuthContext::with_subject("disconnect-test");
                            facts.scopes = vec!["execute".to_owned()];
                            let verifier =
                                StaticTokenVerifier::new([(TOKEN.to_owned(), facts)]).unwrap();
                            let server = Server::new("disconnect-regression", "1")
                                .protocol_policy(ProtocolPolicy::ModernOnly)
                                .unwrap()
                                .request_timeout(SERVER_TIMEOUT_SECS)
                                .auth_provider(TokenAuthProvider::new(verifier))
                                .tool(BlockingTool {
                                    name: LOST,
                                    probe: worker_lost,
                                })
                                .tool(BlockingTool {
                                    name: SURVIVOR,
                                    probe: worker_survivor,
                                })
                                .build();
                            let mut policy = HttpSecurityPolicy::new(
                                HttpEndpointConfig::new(
                                    "/mcp",
                                    HttpAdmissionLimits::new(32, 8192, 65536).unwrap(),
                                )
                                .unwrap(),
                                "https://disconnect.example",
                                vec![],
                            )
                            .unwrap();
                            if scoped {
                                let scopes = ScopeRequestPolicy::new(
                                    1,
                                    ScopeImplicationPolicy::exact(1).unwrap(),
                                    vec![(
                                        "tools/call".to_owned(),
                                        RequiredScopes::new(vec!["execute".to_owned()]).unwrap(),
                                    )],
                                )
                                .unwrap();
                                policy = policy.with_scope_authorization(scopes).unwrap();
                            }
                            let bound = Box::pin(server.bind_secured_http(
                                &server_cx,
                                "127.0.0.1:0",
                                policy,
                            ))
                            .await
                            .unwrap();
                            if started.send(bound.local_addr().unwrap()).is_err() {
                                return None;
                            }
                            Some(Box::pin(bound.serve(&server_cx)).await)
                        })
                        .unwrap();
                    if let Some(shutdown) = serving.join(&cx).await.unwrap() {
                        if let HttpServerShutdown::Nonquiescent(shutdown) = shutdown.unwrap() {
                            shutdown.settle(&cx).await.unwrap();
                        }
                    }
                    assert!(
                        cx.checkpoint().is_ok(),
                        "listener shutdown must not cancel its parent"
                    );
                });
        });
        let mut server = Self {
            address: None,
            control,
            thread: Some(worker),
            lost,
            survivor,
        };
        server.address = Some(
            startup
                .recv_timeout(BOUND)
                .expect("bounded listener startup"),
        );
        server
    }

    fn request(&self, name: &str, accept: &str) -> TcpStream {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {
                "name": name, "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        }))
        .unwrap();
        // Both sockets intentionally use the same JSON-RPC ID. Ownership is
        // the admitted request domain, not a global map keyed by that ID.
        let head = format!(
            "POST /mcp HTTP/1.1\r\nHost: disconnect.example\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nAccept: {accept}\r\nMCP-Protocol-Version: {FINAL_PROTOCOL_VERSION}\r\nMcp-Method: tools/call\r\nMcp-Name: {name}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len(),
        );
        let mut peer = TcpStream::connect_timeout(&self.address.unwrap(), BOUND).unwrap();
        peer.set_read_timeout(Some(BOUND)).unwrap();
        peer.set_write_timeout(Some(BOUND)).unwrap();
        peer.write_all(head.as_bytes()).unwrap();
        peer.write_all(&body).unwrap();
        peer.flush().unwrap();
        peer
    }

    fn assert_listener_live(&self) {
        let control = self.control.lock().unwrap();
        assert!(control.cx.as_ref().unwrap().checkpoint().is_ok());
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.lost.release.store(true, Ordering::Release);
        self.survivor.release.store(true, Ordering::Release);
        let cx = {
            let mut control = self.control.lock().unwrap();
            control.stopping = true;
            control.cx.clone()
        };
        if let Some(cx) = cx {
            cx.cancel_with(CancelKind::User, Some("disconnect regression complete"));
        }
        if let Some(worker) = self.thread.take()
            && worker.join().is_err()
            && !thread::panicking()
        {
            panic!("listener runtime failed");
        }
    }
}

fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ready() {
        assert!(start.elapsed() < BOUND, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(2));
    }
}

fn entered(probe: &Probe) -> McpContext {
    wait_for("synchronous handler entry", || {
        probe.context.lock().unwrap().is_some()
    });
    probe.context.lock().unwrap().as_ref().unwrap().clone()
}

fn assert_success(mut peer: TcpStream, name: &str) {
    let mut bytes = Vec::new();
    Read::by_ref(&mut peer)
        .take(65537)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 65536, "bounded response");
    let response = String::from_utf8(bytes).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains(&format!("{name}-finished")), "{response}");
    assert!(!response.contains("\"error\":"), "{response}");
}

#[test]
fn raw_tcp_drop_cancels_sync_handler_before_deadline_and_preserves_sibling() {
    for scoped in [false, true] {
        for accept in ACCEPTS {
            let server = RunningServer::start(scoped);
            let peer = server.request(LOST, accept);
            let context = entered(&server.lost);
            let sibling_peer = server.request(SURVIVOR, accept);
            let sibling = entered(&server.survivor);
            assert!(!context.is_cancelled());
            assert!(!sibling.is_cancelled());
            let disconnected = Instant::now();
            drop(peer); // Actual socket drop, not an injected cancellation/error.
            wait_for("handler observing peer disconnect", || {
                server.lost.observed_cancel.load(Ordering::Acquire)
            });
            assert!(disconnected.elapsed() < Duration::from_secs(SERVER_TIMEOUT_SECS));
            assert!(context.is_cancelled());
            assert!(
                context.request_cancellation().is_cancel_requested(),
                "request-local cancellation, not just a Cx abort"
            );
            assert!(!server.lost.watchdog_expired.load(Ordering::Acquire));
            assert!(!server.lost.release.load(Ordering::Acquire));
            wait_for("cooperative handler exit", || {
                server.lost.exited.load(Ordering::Acquire)
            });
            assert!(!sibling.is_cancelled());
            assert!(!server.survivor.exited.load(Ordering::Acquire));
            server.assert_listener_live();

            server.survivor.release.store(true, Ordering::Release);
            assert_success(sibling_peer, SURVIVOR);
            // A finalized context's capability lease is closed. Inspect its
            // cancellation domain, not is_cancelled(), after normal completion.
            assert!(sibling.request_cancellation().is_finalizing());
            assert!(!sibling.request_cancellation().is_cancel_requested());
            assert!(!server.survivor.observed_cancel.load(Ordering::Acquire));
            assert!(!server.survivor.watchdog_expired.load(Ordering::Acquire));
            assert_success(server.request(SURVIVOR, "application/json"), SURVIVOR);
            server.assert_listener_live();
        }
    }
}

#[test]
fn raw_tcp_fin_without_reset_cancels_pending_sync_work() {
    for accept in ACCEPTS {
        let server = RunningServer::start(false);
        let peer = server.request(LOST, accept);
        let context = entered(&server.lost);
        assert!(!context.is_cancelled());
        // Keep the receive half alive: the kernel must deliver FIN/EOF rather
        // than a reset caused by closing a socket with unread response bytes.
        peer.shutdown(Shutdown::Write).unwrap();
        wait_for("handler observing FIN", || {
            server.lost.observed_cancel.load(Ordering::Acquire)
        });
        assert!(context.is_cancelled());
        assert!(context.request_cancellation().is_cancel_requested());
        assert!(!server.lost.watchdog_expired.load(Ordering::Acquire));
        server.assert_listener_live();
        drop(peer);
    }
}

#[test]
fn raw_tcp_normal_completion_does_not_cancel_the_request_domain() {
    for accept in ACCEPTS {
        let server = RunningServer::start(false);
        let peer = server.request(LOST, accept);
        let context = entered(&server.lost);
        assert!(!context.is_cancelled());
        server.lost.release.store(true, Ordering::Release);
        assert_success(peer, LOST);
        assert!(context.request_cancellation().is_finalizing());
        assert!(!context.request_cancellation().is_cancel_requested());
        assert!(!server.lost.observed_cancel.load(Ordering::Acquire));
        assert!(!server.lost.watchdog_expired.load(Ordering::Acquire));
        server.assert_listener_live();
    }
}
