use super::*;

use std::sync::atomic::AtomicUsize;

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::types::CancelKind;
use fastmcp_protocol::protocol_policy::ProtocolPolicy;
use fastmcp_protocol::{
    FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION, FINAL_PROTOCOL_VERSION_META_KEY,
    JsonRpcMessage, JsonRpcRequest,
};

#[derive(Default)]
struct Gate {
    entered: AtomicUsize,
    released: AtomicBool,
    changed: Notify,
}

impl Gate {
    async fn enter(&self) {
        self.entered.fetch_add(1, Ordering::AcqRel);
        self.changed.notify_waiters();
        self.changed
            .wait_until(|| self.released.load(Ordering::Acquire))
            .await;
    }

    async fn started(&self) {
        self.changed
            .wait_until(|| self.entered.load(Ordering::Acquire) > 0)
            .await;
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}

fn run<F: Future<Output = ()>>(test: impl FnOnce(Cx) -> F) {
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), test(cx))
            .await
            .expect("async lifespan must make progress on the caller runtime");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
}

fn gated_server(startup: &Arc<Gate>, shutdown: &Arc<Gate>) -> Server {
    let start = Arc::clone(startup);
    let stop = Arc::clone(shutdown);
    Server::new("async-lifespan", "1")
        .protocol_policy(ProtocolPolicy::ModernOnly)
        .unwrap()
        .on_startup_async(move |cx| async move {
            assert!(cx.checkpoint().is_ok());
            assert!(cx.blocking_pool_handle().is_none());
            start.enter().await;
            Ok(())
        })
        .on_shutdown_async(move |_| async move {
            stop.enter().await;
            Ok(())
        })
        .build()
}

fn discover() -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest::new(
        "server/discover",
        Some(serde_json::json!({
            "_meta": {
                FINAL_PROTOCOL_VERSION_META_KEY: FINAL_PROTOCOL_VERSION,
                FINAL_CLIENT_CAPABILITIES_META_KEY: {},
            },
        })),
        1_i64,
    ))
}

fn assert_discovery(message: JsonRpcMessage) {
    let JsonRpcMessage::Response(response) = message else {
        panic!("expected discovery response")
    };
    assert!(response.error.is_none(), "{response:?}");
    assert_eq!(response.result.as_ref().unwrap()["resultType"], "complete");
}

#[test]
fn async_lifespan_claim_is_not_startup_success_and_cleanup_is_retained() {
    run(|cx| async move {
        let startup = Arc::new(Gate::default());
        let shutdown = Arc::new(Gate::default());
        let server = Arc::new(gated_server(&startup, &shutdown));
        let starting_server = Arc::clone(&server);
        let mut starting = cx
            .spawn(move |owned| async move { starting_server.start_native_lifespan(&owned).await })
            .unwrap();
        startup.started().await;
        assert!(!starting.is_finished());
        assert!(
            server
                .start_native_lifespan(&cx)
                .await
                .err()
                .unwrap()
                .message
                .contains("already claimed")
        );
        let sibling = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&sibling);
        let mut task = cx
            .spawn(move |_| async move {
                observed.store(true, Ordering::Release);
            })
            .unwrap();
        task.join(&cx).await.unwrap();
        assert!(sibling.load(Ordering::Acquire));
        startup.release();
        let mut owner = starting.join(&cx).await.unwrap().unwrap().unwrap();
        owner.request_shutdown();
        shutdown.started().await;
        assert!(owner.poll_result().is_none());
        assert!(owner.poll_result().is_none());
        shutdown.release();
        owner.finish().await.unwrap();
        owner.finish().await.unwrap();
        assert_eq!(startup.entered.load(Ordering::Acquire), 1);
        assert_eq!(shutdown.entered.load(Ordering::Acquire), 1);
    });
}

#[test]
fn async_lifespan_partial_startup_failure_awaits_cleanup_and_cannot_restart() {
    run(|cx| async move {
        let cleanup = Arc::new(Gate::default());
        let stop = Arc::clone(&cleanup);
        let entered = Arc::new(AtomicBool::new(false));
        let initialized = Arc::clone(&entered);
        let server = Arc::new(
            Server::new("partial-startup", "1")
                .on_startup_async(move |_| async move {
                    initialized.store(true, Ordering::Release);
                    Err(McpError::internal_error("planted initialization failure"))
                })
                .on_shutdown_async(move |_| async move {
                    stop.enter().await;
                    Ok(())
                })
                .build(),
        );
        let serving = Arc::clone(&server);
        let mut start = cx
            .spawn(move |owned| async move { serving.start_native_lifespan(&owned).await })
            .unwrap();
        cleanup.started().await;
        assert!(entered.load(Ordering::Acquire));
        assert!(
            !start.is_finished(),
            "failed initialization still owns pending cleanup"
        );
        cleanup.release();
        assert!(
            start
                .join(&cx)
                .await
                .unwrap()
                .err()
                .unwrap()
                .message
                .contains("planted initialization failure")
        );
        assert!(server.start_native_lifespan(&cx).await.is_err());
        assert_eq!(cleanup.entered.load(Ordering::Acquire), 1);
    });
}

#[test]
fn async_lifespan_factory_and_poll_panics_are_contained_and_cleaned() {
    run(|cx| async move {
        for factory in [true, false] {
            let cleaned = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&cleaned);
            let server = Server::new("panic-startup", "1")
                .on_startup_async(move |_| {
                    assert!(!factory, "secret factory panic must remain redacted");
                    async {
                        panic!("secret poll panic must remain redacted");
                        #[allow(unreachable_code)]
                        Ok(())
                    }
                })
                .on_shutdown_async(move |_| async move {
                    observed.store(true, Ordering::Release);
                    Ok(())
                })
                .build();
            let error = server.start_native_lifespan(&cx).await.err().unwrap();
            assert!(!error.message.contains("secret"));
            assert!(cleaned.load(Ordering::Acquire));
        }
    });
}

#[test]
fn async_lifespan_startup_cancellation_in_final_poll_cannot_open_ingress() {
    run(|cx| async move {
        let cleanup = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&cleanup);
        let server = Server::new("cancel-at-return", "1")
            .on_startup_async(|owned| async move {
                owned.cancel_with(CancelKind::User, Some("startup cancelled itself"));
                Ok(())
            })
            .on_shutdown_async(move |_| async move {
                observed.store(true, Ordering::Release);
                Ok(())
            })
            .build();
        assert!(server.start_native_lifespan(&cx).await.is_err());
        assert!(cleanup.load(Ordering::Acquire));
        assert!(
            cx.checkpoint().is_ok(),
            "lifecycle cancellation must not cancel its parent"
        );
    });
}

#[test]
fn async_lifespan_shutdown_deadline_is_fixed_and_reports_failure() {
    run(|cx| async move {
        let shutdown = Arc::new(Gate::default());
        let stop = Arc::clone(&shutdown);
        let mut owner = AsyncLifespanOwner::admit(
            &cx,
            None,
            Some(Box::new(move |_| {
                Box::pin(async move {
                    stop.enter().await;
                    Ok(())
                })
            })),
            Duration::from_millis(30),
        )
        .unwrap();
        owner.ready().await.unwrap();
        owner.request_shutdown();
        shutdown.started().await;
        for _ in 0..4 {
            assert!(owner.poll_result().is_none());
            asupersync::time::sleep(cx.now(), Duration::from_millis(2)).await;
        }
        let error = owner.finish().await.unwrap_err();
        assert!(error.message.contains("deadline"));
        assert!(owner.finish().await.is_err());
        assert_eq!(shutdown.entered.load(Ordering::Acquire), 1);
    });
}

#[test]
fn async_lifespan_cleanup_cannot_extend_original_caller_deadline() {
    run(|cx| async move {
        let original = cx.now() + Duration::from_millis(40);
        let region = cx
            .open_child_region(
                ChildRegionSpec::inherit()
                    .with_budget(asupersync::Budget::INFINITE.with_deadline(original)),
            )
            .await
            .unwrap();
        let entered = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&entered);
        let mut owner = AsyncLifespanOwner::admit(
            region.cx(),
            None,
            Some(Box::new(move |owned| {
                Box::pin(async move {
                    assert_eq!(owned.budget().deadline, Some(original));
                    observed.store(true, Ordering::Release);
                    std::future::pending::<McpResult<()>>().await
                })
            })),
            Duration::from_secs(3),
        )
        .unwrap();
        owner.ready().await.unwrap();
        let started = std::time::Instant::now();
        assert!(owner.finish().await.is_err());
        assert!(entered.load(Ordering::Acquire));
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(owner);
        region.close().await.unwrap();
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn async_lifespan_cancelled_admission_never_invokes_callbacks() {
    run(|cx| async move {
        let calls = Arc::new(AtomicUsize::new(0));
        let startup = Arc::clone(&calls);
        let shutdown = Arc::clone(&calls);
        let region = cx
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .unwrap();
        region
            .cancel(CancelReason::user("refuse before lifecycle admission"))
            .unwrap();
        assert!(
            AsyncLifespanOwner::admit(
                region.cx(),
                Some(Box::new(move |_| {
                    startup.fetch_add(1, Ordering::AcqRel);
                    Box::pin(async { Ok(()) })
                })),
                Some(Box::new(move |_| {
                    shutdown.fetch_add(1, Ordering::AcqRel);
                    Box::pin(async { Ok(()) })
                })),
                Duration::from_secs(1)
            )
            .is_err()
        );
        region.close().await.unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn async_lifespan_retains_host_capability_ceiling_through_both_callbacks() {
    use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
    run(|cx| async move {
        let calls = Arc::new(AtomicUsize::new(0));
        let start = Arc::clone(&calls);
        let stop = Arc::clone(&calls);
        let mut owner = {
            let _restriction = Cx::push_restriction(CapSet::<true, true, true, true, false>::MASK);
            AsyncLifespanOwner::admit(
                &cx,
                Some(Box::new(move |owned| {
                    Box::pin(async move {
                        assert!(!owned.capabilities().remote);
                        assert!(!Cx::current().unwrap().capabilities().remote);
                        asupersync::runtime::yield_now().await;
                        assert!(!Cx::current().unwrap().capabilities().remote);
                        start.fetch_add(1, Ordering::AcqRel);
                        Ok(())
                    })
                })),
                Some(Box::new(move |owned| {
                    Box::pin(async move {
                        assert!(!owned.capabilities().remote);
                        assert!(!Cx::current().unwrap().capabilities().remote);
                        stop.fetch_add(1, Ordering::AcqRel);
                        Ok(())
                    })
                })),
                Duration::from_secs(1),
            )
            .unwrap()
        };
        owner.ready().await.unwrap();
        owner.finish().await.unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 2);
    });
}

#[test]
fn async_lifespan_blocking_runners_refuse_before_transport_or_hook_effects() {
    use fastmcp_transport::{Transport, TransportError, TransportRecvHalf, TransportSendHalf};
    struct Contact(Arc<AtomicUsize>);
    impl Transport for Contact {
        fn send(&mut self, _: &Cx, _: &JsonRpcMessage) -> Result<(), TransportError> {
            self.0.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
        fn recv(&mut self, _: &Cx) -> Result<JsonRpcMessage, TransportError> {
            self.0.fetch_add(1, Ordering::AcqRel);
            Err(TransportError::Closed)
        }
        fn close(&mut self, _: &Cx) -> Result<(), TransportError> {
            self.0.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }
    impl TransportRecvHalf for Contact {
        fn recv(&mut self, cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
            Transport::recv(self, cx)
        }
        fn close(&mut self, cx: &Cx) -> Result<(), TransportError> {
            Transport::close(self, cx)
        }
    }
    impl TransportSendHalf for Contact {
        fn send(&mut self, cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
            Transport::send(self, cx, message)
        }
        fn close(&mut self, cx: &Cx) -> Result<(), TransportError> {
            Transport::close(self, cx)
        }
    }
    let effects = Arc::new(AtomicUsize::new(0));
    for split in [false, true] {
        let called = Arc::clone(&effects);
        let server = Server::new("blocking-refusal", "1")
            .on_startup_async(move |_| async move {
                called.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
            .build();
        let result = if split {
            server.run_split_transport_returning_with_cx(
                &Cx::for_testing(),
                Contact(Arc::clone(&effects)),
                Contact(Arc::clone(&effects)),
            )
        } else {
            server
                .run_transport_returning_with_cx(&Cx::for_testing(), Contact(Arc::clone(&effects)))
        };
        assert!(result.unwrap_err().message.contains("requires native"));
        assert_eq!(
            effects.load(Ordering::Acquire),
            0,
            "refusal must precede receive, send, close, and callback entry"
        );
    }
}

#[test]
fn async_lifespan_abandonment_retains_descendants_without_premature_shutdown() {
    run(|cx| async move {
        let child = Arc::new(Gate::default());
        let child_work = Arc::clone(&child);
        let stopped = Arc::new(AtomicBool::new(false));
        let child_stopped = Arc::clone(&stopped);
        let shutdown = Arc::new(AtomicBool::new(false));
        let cleanup = Arc::clone(&shutdown);
        let mut owner = AsyncLifespanOwner::admit(
            &cx,
            Some(Box::new(move |owned| {
                Box::pin(async move {
                    let _descendant = owned
                        .spawn(move |_| async move {
                            child_work.enter().await;
                            child_stopped.store(true, Ordering::Release);
                        })
                        .unwrap();
                    Ok(())
                })
            })),
            Some(Box::new(move |_| {
                Box::pin(async move {
                    cleanup.store(true, Ordering::Release);
                    Ok(())
                })
            })),
            Duration::from_secs(1),
        )
        .unwrap();
        owner.ready().await.unwrap();
        child.started().await;
        drop(owner);
        asupersync::time::sleep(cx.now(), Duration::from_millis(20)).await;
        assert!(!stopped.load(Ordering::Acquire));
        assert!(!shutdown.load(Ordering::Acquire));
        child.release();
        while !stopped.load(Ordering::Acquire) {
            asupersync::runtime::yield_now().await;
        }
        assert!(!shutdown.load(Ordering::Acquire));
    });
}

#[cfg(unix)]
#[test]
fn async_lifespan_native_stdio_gates_real_discovery_and_eof_cleanup() {
    run(|cx| async move {
        let startup = Arc::new(Gate::default());
        let shutdown = Arc::new(Gate::default());
        let server = gated_server(&startup, &shutdown);
        let (server_in, peer_out) = fastmcp_transport::create_native_pipe(&cx).unwrap();
        let (peer_in, server_out) = fastmcp_transport::create_native_pipe(&cx).unwrap();
        let mut serving = cx
            .spawn(move |owned| async move {
                server.serve_stdio_io(&owned, server_in, server_out).await
            })
            .unwrap();
        let (mut receive, mut send) =
            fastmcp_transport::AsyncStdioTransport::from_io(peer_in, peer_out).into_split();
        send.send_async(&cx, &discover()).await.unwrap();
        startup.started().await;
        let mut response = Box::pin(receive.recv_async(&cx));
        assert!(
            poll_fn(|task| Poll::Ready(response.as_mut().poll(task)))
                .await
                .is_pending()
        );
        startup.release();
        assert_discovery(response.await.unwrap());
        send.close_async(&cx).await.unwrap();
        shutdown.started().await;
        assert!(!serving.is_finished());
        shutdown.release();
        serving.join(&cx).await.unwrap().unwrap();
        assert_eq!(startup.entered.load(Ordering::Acquire), 1);
        assert_eq!(shutdown.entered.load(Ordering::Acquire), 1);
    });
}

async fn http_discovery(address: std::net::SocketAddr) -> Vec<u8> {
    let body = serde_json::to_vec(&discover()).unwrap();
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nAccept: application/json\r\nMCP-Protocol-Version: {FINAL_PROTOCOL_VERSION}\r\nMCP-Method: server/discover\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    );
    let mut stream = asupersync::net::TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    stream.flush().await.unwrap();
    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let count = stream.read(&mut chunk).await.unwrap();
        if count == 0 {
            break;
        }
        assert!(response.len() + count <= 128 * 1024);
        response.extend_from_slice(&chunk[..count]);
    }
    response
}

#[test]
fn async_lifespan_native_http_retains_cleanup_in_bounded_settlement() {
    run(|cx| async move {
        let startup = Arc::new(Gate::default());
        let shutdown = Arc::new(Gate::default());
        let bound = gated_server(&startup, &shutdown)
            .bind_http(&cx, "127.0.0.1:0")
            .await
            .unwrap();
        let address = bound.local_addr().unwrap();
        let (sender, mut receiver) = asupersync::channel::oneshot::channel();
        let mut serving = cx
            .spawn(move |owned| async move {
                sender.send_blocking(owned.clone()).unwrap();
                bound.serve(&owned).await
            })
            .unwrap();
        let control = receiver.recv(&cx).await.unwrap();
        let mut request = cx
            .spawn(move |_| async move { http_discovery(address).await })
            .unwrap();
        startup.started().await;
        assert!(!request.is_finished());
        startup.release();
        let response = request.join(&cx).await.unwrap();
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        assert!(String::from_utf8_lossy(&response).contains("\"resultType\":\"complete\""));
        control.cancel_with(CancelKind::User, Some("HTTP lifecycle test stopping"));
        shutdown.started().await;
        let outcome = serving.join(&cx).await.unwrap().unwrap();
        let crate::HttpServerShutdown::Nonquiescent(mut retained) = outcome else {
            panic!("pending cleanup must remain caller-owned after the observation bound")
        };
        assert!(matches!(
            retained.poll_settlement(),
            crate::HttpShutdownSettlement::Pending { .. }
        ));
        assert!(matches!(
            retained.settle_for(Duration::from_millis(5)).await,
            crate::HttpShutdownSettlement::Pending { .. }
        ));
        shutdown.release();
        retained.settle(&cx).await.unwrap();
        assert_eq!(shutdown.entered.load(Ordering::Acquire), 1);
        assert!(cx.checkpoint().is_ok());
    });
}

#[cfg(feature = "websocket")]
#[test]
fn async_lifespan_native_websocket_gates_upgrade_and_awaits_cleanup() {
    run(|cx| async move {
        let startup = Arc::new(Gate::default());
        let shutdown = Arc::new(Gate::default());
        let bound = gated_server(&startup, &shutdown)
            .bind_websocket(&cx, "127.0.0.1:0")
            .await
            .unwrap();
        let address = bound.local_addr().unwrap();
        let (sender, mut receiver) = asupersync::channel::oneshot::channel();
        let mut serving = cx
            .spawn(move |owned| async move {
                sender.send_blocking(owned.clone()).unwrap();
                bound.serve(&owned).await
            })
            .unwrap();
        let control = receiver.recv(&cx).await.unwrap();
        let mut request = cx
            .spawn(move |peer_cx| async move {
                let mut peer = fastmcp_transport::websocket::AsyncWsClientTransport::connect(
                    &peer_cx,
                    &format!("ws://{address}/mcp"),
                )
                .await
                .unwrap();
                peer.send(&peer_cx, &discover()).await.unwrap();
                let response = peer.recv(&peer_cx).await.unwrap();
                peer.close(&peer_cx).await.unwrap();
                response
            })
            .unwrap();
        startup.started().await;
        assert!(!request.is_finished());
        startup.release();
        assert_discovery(request.join(&cx).await.unwrap());
        control.cancel_with(CancelKind::User, Some("WebSocket lifecycle test stopping"));
        shutdown.started().await;
        assert!(!serving.is_finished());
        shutdown.release();
        if let crate::WebSocketServerShutdown::Nonquiescent(retained) =
            serving.join(&cx).await.unwrap().unwrap()
        {
            retained.settle(&cx).await.unwrap();
        }
        assert_eq!(startup.entered.load(Ordering::Acquire), 1);
        assert_eq!(shutdown.entered.load(Ordering::Acquire), 1);
    });
}
