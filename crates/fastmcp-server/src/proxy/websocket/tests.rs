//! Native cancellation writes must outlive an individual downstream wait.

use std::io;
use std::pin::Pin;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Waker};
use std::time::Duration;

use asupersync::io::ReadBuf;
use asupersync::net::tcp::VirtualTcpStream;
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_client::ClientProtocolPlan;
use fastmcp_protocol::protocol_policy::ProtocolPolicy;
use fastmcp_protocol::{ClientInfo, JsonRpcMessage, JsonRpcResponse, RequestId};
use fastmcp_transport::websocket::{AsyncWsClientTransport, AsyncWsServerTransport};
use serde_json::json;

use super::*;
use crate::proxy::{MultiplexedProxyCatalogListener, finish_proxy_catalog_listener};

#[derive(Default)]
struct ControlGate {
    armed: AtomicBool,
    accepted: AtomicUsize,
    parked: AtomicBool,
    released: AtomicBool,
    waker: StdMutex<Option<Waker>>,
}

impl ControlGate {
    fn park(&self, cx: &Context<'_>) {
        *self.waker.lock().unwrap() = Some(cx.waker().clone());
        self.parked.store(true, Ordering::Release);
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}

/// Accepts one real frame byte before parking the native control write. The
/// gate is armed only after discovery and the listen send have committed.
struct GatedIo {
    inner: VirtualTcpStream,
    gate: Arc<ControlGate>,
}

impl AsyncRead for GatedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for GatedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.gate.armed.load(Ordering::Acquire) && !this.gate.released.load(Ordering::Acquire) {
            if this.gate.accepted.load(Ordering::Acquire) != 0 {
                this.gate.park(cx);
                return Poll::Pending;
            }
            let result = Pin::new(&mut this.inner).poll_write(cx, &bytes[..bytes.len().min(1)]);
            if let Poll::Ready(Ok(written)) = result {
                this.gate.accepted.fetch_add(written, Ordering::AcqRel);
            }
            return result;
        }
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.gate.armed.load(Ordering::Acquire)
            && this.gate.accepted.load(Ordering::Acquire) != 0
            && !this.gate.released.load(Ordering::Acquire)
        {
            this.gate.park(cx);
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn run<F, Fut>(scenario: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let parent = Cx::current().unwrap();
        let mut task = parent
            .spawn(move |cx| async move {
                asupersync::time::timeout(cx.now(), Duration::from_secs(5), scenario(cx))
                    .await
                    .expect("owned cleanup completes without a blocking worker");
            })
            .unwrap();
        task.join(&parent).await.unwrap();
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
}

#[test]
fn cancelled_proxy_wait_retains_partial_native_control_until_epilogue() {
    run(|cx| async move {
        let (client_io, peer_io) = VirtualTcpStream::pair(
            "127.0.0.1:45101".parse().unwrap(),
            "127.0.0.1:45102".parse().unwrap(),
        );
        let mut peer = AsyncWsServerTransport::from_upgraded(peer_io);
        peer.send(
            &cx,
            &JsonRpcMessage::Response(JsonRpcResponse::success(
                RequestId::Number(1),
                json!({
                    "resultType": "complete", "supportedVersions": ["2026-07-28"],
                    "capabilities": {"tools": {}}, "ttlMs": 0, "cacheScope": "private",
                    "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "peer", "version": "1"}}
                }),
            )),
        )
        .await
        .unwrap();
        let gate = Arc::new(ControlGate::default());
        let mut native = WebSocketClient::connect_with_cx(
            &cx,
            ClientProtocolPlan::websocket(ProtocolPolicy::ModernOnly),
            ClientInfo {
                name: "proxy".to_owned(),
                version: "1".to_owned(),
            },
            ClientCapabilities::default(),
            AsyncWsClientTransport::from_upgraded(GatedIo {
                inner: client_io,
                gate: Arc::clone(&gate),
            }),
        )
        .await
        .unwrap();
        let filter = SubscriptionFilter {
            tools_list_changed: Some(true),
            ..SubscriptionFilter::default()
        };
        let owner = native
            .open_owned_subscriptions_listener(
                &cx,
                filter.clone(),
                FinalRequestMeta::new(ClientCapabilities::default()),
            )
            .await
            .unwrap();
        peer.send(
            &cx,
            &serde_json::from_value(json!({
                "jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
                "params": {"notifications": {"toolsListChanged": true},
                    "_meta": {"io.modelcontextprotocol/subscriptionId": 2}}
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        assert!(matches!(
            native
                .next_subscription_event(&cx, &McpRequestCancellation::new())
                .await,
            Ok(StdioSubscriptionEvent::Acknowledged(_))
        ));
        let shared = Arc::new(Mutex::new(native));
        let listener = WebSocketCatalogListener {
            client: Arc::clone(&shared),
            _owner: owner,
        };
        let mut mux = MultiplexedProxyCatalogListener::new(vec![Box::new(listener)], filter);
        let outer = McpRequestCancellation::new();
        assert!(matches!(
            mux.next_async(&cx, &outer).await,
            Ok(ProxyCatalogListenerEvent::Acknowledged(_))
        ));
        {
            let mut wait = Box::pin(mux.next_async(&cx, &outer));
            assert!(
                std::future::poll_fn(|task_cx| Poll::Ready(wait.as_mut().poll(task_cx)))
                    .await
                    .is_pending()
            );
        }
        // Elect native cancellation while the outer request is still live.
        // This selects the same control-write ownership as a listener timeout,
        // without relying on a wall-clock race to enter the critical phase.
        gate.armed.store(true, Ordering::Release);
        mux.turns[0].as_ref().unwrap().cancellation.cancel();
        {
            let mut wait = Box::pin(mux.next_async(&cx, &outer));
            std::future::poll_fn(|task_cx| {
                assert!(wait.as_mut().poll(task_cx).is_pending());
                if gate.parked.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            assert_eq!(gate.accepted.load(Ordering::Acquire), 1);
            outer.cancel();
            assert!(
                std::future::poll_fn(|task_cx| Poll::Ready(wait.as_mut().poll(task_cx)))
                    .await
                    .is_pending(),
                "ordinary downstream cancellation must retain the partial control write"
            );
        }
        assert!(
            mux.native_cleanup().is_some(),
            "the dropped wait leaves an owned cleanup receipt"
        );
        {
            let mut cleanup = Box::pin(finish_proxy_catalog_listener(&mut mux));
            assert!(
                std::future::poll_fn(|task_cx| Poll::Ready(cleanup.as_mut().poll(task_cx)))
                    .await
                    .is_pending()
            );
        }
        gate.release();
        finish_proxy_catalog_listener(&mut mux).await;
        peer.send(
            &cx,
            &JsonRpcMessage::Response(JsonRpcResponse::success(
                RequestId::Number(3),
                json!({"resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private"}),
            )),
        )
        .await
        .unwrap();
        let mut native = OwnedMutexGuard::lock(shared, &cx).await.unwrap();
        native
            .list_tools(&cx, None)
            .await
            .expect("completed cleanup leaves ordinary requests usable");
        assert!(!native.is_closed());
        for method in [
            "server/discover",
            "subscriptions/listen",
            "notifications/cancelled",
            "tools/list",
        ] {
            let JsonRpcMessage::Request(request) = peer.recv(&cx).await.unwrap() else {
                panic!("expected native request");
            };
            assert_eq!(
                request.method, method,
                "one cancellation precedes the ordinary request"
            );
            if method == "notifications/cancelled" {
                assert_eq!(request.params.unwrap()["requestId"], json!(2));
            }
        }
        native.close(&cx).await.unwrap();
    });
}

#[derive(Default)]
struct CustomState {
    token: StdMutex<Option<McpRequestCancellation>>,
    dropped: AtomicBool,
    cancelled_before_drop: AtomicBool,
    cleanup_called: AtomicBool,
}

struct PendingCustom(Arc<CustomState>);

impl ProxyCatalogListener for PendingCustom {
    fn next_async<'a>(
        &'a mut self,
        _cx: &'a Cx,
        cancellation: &'a McpRequestCancellation,
    ) -> BoxFuture<'a, McpResult<ProxyCatalogListenerEvent>> {
        *self.0.token.lock().unwrap() = Some(cancellation.clone());
        Box::pin(std::future::pending())
    }

    fn finish_native_cleanup(&mut self) -> BoxFuture<'_, ()> {
        self.0.cleanup_called.store(true, Ordering::Release);
        Box::pin(std::future::pending())
    }
}

impl Drop for PendingCustom {
    fn drop(&mut self) {
        self.0.cancelled_before_drop.store(
            self.0
                .token
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(McpRequestCancellation::is_cancel_requested),
            Ordering::Release,
        );
        self.0.dropped.store(true, Ordering::Release);
    }
}

#[test]
fn arbitrary_catalog_backend_cancellation_stays_prompt_and_signals_owner() {
    run(|cx| async move {
        let state = Arc::new(CustomState::default());
        let mut mux = MultiplexedProxyCatalogListener::new(
            vec![Box::new(PendingCustom(Arc::clone(&state)))],
            SubscriptionFilter::default(),
        );
        let cancellation = McpRequestCancellation::new();
        assert!(matches!(
            mux.next_async(&cx, &cancellation).await,
            Ok(ProxyCatalogListenerEvent::Acknowledged(_))
        ));
        {
            let mut wait = Box::pin(mux.next_async(&cx, &cancellation));
            assert!(
                std::future::poll_fn(|task_cx| Poll::Ready(wait.as_mut().poll(task_cx)))
                    .await
                    .is_pending()
            );
            cancellation.cancel();
            let result =
                std::future::poll_fn(|task_cx| Poll::Ready(wait.as_mut().poll(task_cx))).await;
            assert!(
                matches!(result, Poll::Ready(Err(error)) if error.code == McpErrorCode::RequestCancelled)
            );
        }
        finish_proxy_catalog_listener(&mut mux).await;
        assert!(state.dropped.load(Ordering::Acquire));
        assert!(state.cancelled_before_drop.load(Ordering::Acquire));
        assert!(
            !state.cleanup_called.load(Ordering::Acquire),
            "custom backends cannot opt into the sealed native wait"
        );
    });
}
