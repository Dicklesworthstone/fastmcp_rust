//! Public asynchronous lifespan hooks run inside the caller's native runtime.

#![recursion_limit = "512"]
#![forbid(unsafe_code)]

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use asupersync::runtime::RuntimeBuilder;
use fastmcp_rust::memory::create_memory_transport_pair_with_capacity;
use fastmcp_rust::{ClientCapabilities, ClientInfo, Cx, McpError, modern};

#[derive(Default)]
struct Hooks {
    startup_entered: AtomicUsize,
    startup_release: AtomicBool,
    shutdown_entered: AtomicUsize,
    shutdown_release: AtomicBool,
    shutdown_completed: AtomicUsize,
}

async fn wait_for(cx: &Cx, condition: impl Fn() -> bool) {
    while !condition() {
        cx.checkpoint().expect("test caller must remain live");
        asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
    }
}

async fn assert_pending<F: Future>(mut future: Pin<&mut F>) {
    assert!(
        poll_fn(|task| Poll::Ready(future.as_mut().poll(task)))
            .await
            .is_pending()
    );
}

fn run_lifespan(startup_fails: bool) {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
            let hooks = Arc::new(Hooks::default());
            let startup_hooks = Arc::clone(&hooks);
            let shutdown_hooks = Arc::clone(&hooks);
            let server = modern::ServerBuilder::new("public-async-lifespan", "1")
                .on_startup_async(move |hook_cx| async move {
                    assert!(hook_cx.blocking_pool_handle().is_none());
                    assert!(hook_cx.timer_driver().is_some());
                    assert_eq!(
                        startup_hooks.startup_entered.fetch_add(1, Ordering::AcqRel),
                        0
                    );
                    wait_for(&hook_cx, || {
                        startup_hooks.startup_release.load(Ordering::Acquire)
                    })
                    .await;
                    if startup_fails {
                        Err(McpError::internal_error("deliberate startup failure"))
                    } else {
                        Ok(())
                    }
                })
                .on_shutdown_async(move |hook_cx| async move {
                    assert!(hook_cx.blocking_pool_handle().is_none());
                    assert!(hook_cx.timer_driver().is_some());
                    assert_eq!(
                        shutdown_hooks
                            .shutdown_entered
                            .fetch_add(1, Ordering::AcqRel),
                        0
                    );
                    wait_for(&hook_cx, || {
                        shutdown_hooks.shutdown_release.load(Ordering::Acquire)
                    })
                    .await;
                    shutdown_hooks
                        .shutdown_completed
                        .fetch_add(1, Ordering::Release);
                    Ok(())
                })
                .build();
            let (transport, server_transport) = create_memory_transport_pair_with_capacity(1);
            let mut serving = cx
                .spawn(move |serve_cx| async move {
                    server.serve_memory(&serve_cx, server_transport).await
                })
                .unwrap();

            wait_for(&cx, || hooks.startup_entered.load(Ordering::Acquire) == 1).await;
            let mut connecting = Box::pin(modern::MemoryClient::connect(
                &cx,
                transport,
                ClientInfo {
                    name: "lifespan-client".to_owned(),
                    version: "1".to_owned(),
                },
                ClientCapabilities::default(),
            ));
            assert_pending(connecting.as_mut()).await;
            let mut sibling = cx
                .spawn(|sibling_cx| async move {
                    asupersync::time::sleep(sibling_cx.now(), Duration::from_millis(2)).await;
                    sibling_cx.checkpoint().unwrap();
                })
                .unwrap();
            sibling.join(&cx).await.unwrap();
            // An awaited startup hook yields to siblings without admitting discovery.
            assert_pending(connecting.as_mut()).await;
            assert_eq!(hooks.shutdown_entered.load(Ordering::Acquire), 0);
            hooks.startup_release.store(true, Ordering::Release);

            if !startup_fails {
                let mut client = connecting.as_mut().await.unwrap();
                assert!(
                    client
                        .server_discovery()
                        .supported_versions()
                        .iter()
                        .any(|version| version == modern::PROTOCOL_VERSION)
                );
                assert_eq!(hooks.shutdown_entered.load(Ordering::Acquire), 0);
                client.close(&cx).unwrap();
            }

            wait_for(&cx, || hooks.shutdown_entered.load(Ordering::Acquire) == 1).await;
            let mut joined = Box::pin(serving.join(&cx));
            assert_pending(joined.as_mut()).await;
            asupersync::time::sleep(cx.now(), Duration::from_millis(2)).await;
            assert_eq!(hooks.shutdown_completed.load(Ordering::Acquire), 0);
            assert_pending(joined.as_mut()).await;
            // Neither ordinary shutdown nor partial startup failure may abandon cleanup.
            hooks.shutdown_release.store(true, Ordering::Release);
            let result = joined.await.unwrap();
            if startup_fails {
                assert!(
                    result
                        .unwrap_err()
                        .message
                        .contains("deliberate startup failure")
                );
                assert!(connecting.await.is_err());
            } else {
                result.unwrap();
            }
            assert_eq!(hooks.startup_entered.load(Ordering::Acquire), 1);
            assert_eq!(hooks.shutdown_entered.load(Ordering::Acquire), 1);
            assert_eq!(hooks.shutdown_completed.load(Ordering::Acquire), 1);
            assert!(cx.checkpoint().is_ok());
        })
        .await
        .expect("native startup and cleanup must settle on the caller runtime");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn async_lifespan_gates_real_discovery_and_retains_pending_cleanup() {
    run_lifespan(false);
}

#[test]
fn failed_async_startup_finishes_partial_initialization_cleanup_before_returning() {
    run_lifespan(true);
}
