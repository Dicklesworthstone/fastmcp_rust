//! Keep native request-region admission owned when its connection disappears.
//!
//! In asupersync 0.5, dropping `ChildRegionOpening` does not reclaim an
//! admitted-but-unobserved region. The short task below owns that opening
//! through publication. It never runs application work. An abandoned result
//! is an owned `ChildRegion`, whose Drop requests structured close.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use asupersync::cx::{ChildRegion, ChildRegionError, ChildRegionSpec};
use asupersync::runtime::TaskHandle;
use asupersync::{Budget, Cx};
use fastmcp_core::{McpError, McpResult};

use super::server_run_error;

/// Observation of a parent-region-owned admission task, not ownership of that
/// task. Dropping this handle must NOT abort its producer or drop a pending
/// raw region opening. The producer retains custody until the runtime has
/// either refused the mint or returned the owned region.
pub(super) struct RequestRegionOpening {
    admission: TaskHandle<Result<ChildRegion, ChildRegionError>>,
}

pub(super) fn open(cx: &Cx, budget: Budget) -> McpResult<RequestRegionOpening> {
    // Preserve a caller's ambient capability restriction as well as its
    // explicit identity. Never obtain a spawn gateway from a foreign runtime.
    let _caller = Cx::set_current(Some(cx.clone()));
    let caller = Cx::current().ok_or_else(|| {
        server_run_error(
            "dispatch",
            "region_open",
            "Request region caller is unavailable",
        )
    })?;
    caller
        .checkpoint()
        .map_err(|_| McpError::request_cancelled())?;
    let admission = caller
        .spawn(move |admission_cx| async move {
            admission_cx
                .open_child_region(ChildRegionSpec::inherit().with_budget(budget))
                .await
        })
        .map_err(|_| {
            server_run_error(
                "dispatch",
                "region_open",
                "Request region admission could not be scheduled",
            )
        })?;
    Ok(RequestRegionOpening { admission })
}

impl Future for RequestRegionOpening {
    type Output = McpResult<ChildRegion>;

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        // A borrowed `join()` future aborts its task on Drop. `poll_join`
        // deliberately does not: connection abandonment must still let the
        // producer consume the mint result. The task's result channel drops
        // an undeliverable ChildRegion, requesting its ordinary close protocol.
        // This preserves custody both before and after result publication.
        self.get_mut()
            .admission
            .poll_join(task)
            .map(|result| match result {
                Ok(Ok(region)) => Ok(region),
                Ok(Err(_)) | Err(_) => {
                    // Cancellation or runtime loss is not a quiescence receipt.
                    // Retain the connection's conservative failure path rather
                    // than running shutdown over unverified region cleanup.
                    Err(server_run_error(
                        "dispatch",
                        "region_open",
                        "Request region could not be opened",
                    ))
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use asupersync::channel::oneshot;
    use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
    use asupersync::observability::diagnostics::{Diagnostics, Reason};
    use asupersync::record::region::RegionState;
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::sync::Notify;
    use asupersync::types::RegionId;
    use fastmcp_protocol::protocol_policy::ProtocolPolicy;

    fn run<F, Fut>(test: F)
    where
        F: FnOnce(Cx, Diagnostics) -> Fut,
        Fut: Future<Output = ()>,
    {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        let diagnostics = runtime.diagnostics();
        runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            assert!(cx.blocking_pool_handle().is_none());
            asupersync::time::timeout(cx.now(), Duration::from_secs(8), test(cx, diagnostics))
                .await
                .expect("native admission custody must make bounded progress");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    fn children(diagnostics: &Diagnostics, parent: RegionId) -> Vec<RegionId> {
        let mut children = diagnostics
            .explain_region_open(parent)
            .reasons
            .into_iter()
            .filter_map(|reason| match reason {
                Reason::ChildRegionOpen { child_id, .. } => Some(child_id),
                _ => None,
            })
            .collect::<Vec<_>>();
        children.sort();
        children
    }

    async fn poll_once<F: Future + ?Sized>(mut future: Pin<&mut F>) -> Poll<F::Output> {
        std::future::poll_fn(|task| Poll::Ready(future.as_mut().poll(task))).await
    }

    async fn until(cx: &Cx, predicate: impl Fn() -> bool) {
        asupersync::time::timeout(cx.now(), Duration::from_secs(3), async {
            while !predicate() {
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("region observation did not arrive while its parent stayed live");
    }

    fn parent_is_live(diagnostics: &Diagnostics, parent: &ChildRegion) {
        assert_eq!(
            diagnostics
                .explain_region_open(parent.region_id())
                .region_state,
            Some(RegionState::Open),
        );
        assert!(parent.cx().checkpoint().is_ok());
    }

    #[test]
    fn native_admission_returns_owned_region_with_the_requested_budget() {
        run(|cx, diagnostics| async move {
            let parent = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let deadline = cx.now().saturating_add_nanos(30_000_000_000);
            let region = open(parent.cx(), Budget::INFINITE.with_deadline(deadline))
                .unwrap()
                .await
                .unwrap();
            assert_ne!(region.region_id(), parent.region_id());
            assert_eq!(region.cx().budget().deadline, Some(deadline));
            assert_eq!(
                children(&diagnostics, parent.region_id()),
                vec![region.region_id()],
            );
            region.close().await.unwrap();
            assert!(children(&diagnostics, parent.region_id()).is_empty());
            parent_is_live(&diagnostics, &parent);
            parent.close().await.unwrap();
        });
    }

    #[test]
    fn native_admission_abandoned_published_result_reaps_only_its_region() {
        run(|cx, diagnostics| async move {
            let parent = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let sibling = parent
                .cx()
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let opening = open(parent.cx(), Budget::INFINITE).unwrap();
            // Publication has finished, but the observer has never consumed
            // the ChildRegion from its result channel. This is not a test
            // that cancels the parent and credits its broad cleanup instead.
            until(&cx, || opening.admission.is_finished()).await;
            let admitted = children(&diagnostics, parent.region_id());
            assert_eq!(admitted.len(), 2);
            assert!(admitted.contains(&sibling.region_id()));
            drop(opening);
            until(&cx, || {
                children(&diagnostics, parent.region_id()) == vec![sibling.region_id()]
            })
            .await;
            parent_is_live(&diagnostics, &parent);
            parent_is_live(&diagnostics, &sibling);
            sibling.close().await.unwrap();
            parent.close().await.unwrap();
        });
    }

    #[test]
    fn native_admission_pending_mint_survives_observer_abandonment() {
        run(|cx, diagnostics| async move {
            let parent = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let released = Arc::new(AtomicBool::new(false));
            let release = Arc::new(Notify::new());
            let worker_released = Arc::clone(&released);
            let worker_release = Arc::clone(&release);
            let (started, mut started_rx) = oneshot::channel();
            let (consumed, mut consumed_rx) = oneshot::channel();
            // Pause the real producer after its first raw mint poll. The
            // injected gate controls timing only; the production observation
            // future and real runtime mint/result/Drop paths are unchanged.
            let admission = parent
                .cx()
                .spawn(move |owner| async move {
                    let mut raw = Box::pin(owner.open_child_region(ChildRegionSpec::inherit()));
                    assert!(poll_once(raw.as_mut()).await.is_pending());
                    started.send_blocking(()).unwrap();
                    worker_release
                        .wait_until(|| worker_released.load(Ordering::Acquire))
                        .await;
                    assert!(
                        owner.checkpoint().is_ok(),
                        "dropping observation aborted its custodian",
                    );
                    let result = raw.await;
                    consumed.send_blocking(()).unwrap();
                    result
                })
                .unwrap();
            let mut opening = Box::pin(RequestRegionOpening { admission });
            assert!(poll_once(opening.as_mut()).await.is_pending());
            started_rx.recv(&cx).await.unwrap();
            until(&cx, || children(&diagnostics, parent.region_id()).len() == 1).await;
            assert!(!opening.admission.is_finished());
            drop(opening);
            // The raw outcome is already published in the runtime slot. The
            // custodian must still consume it and release the owned region.
            released.store(true, Ordering::Release);
            release.notify_waiters();
            consumed_rx.recv(&cx).await.unwrap();
            until(&cx, || children(&diagnostics, parent.region_id()).is_empty()).await;
            parent_is_live(&diagnostics, &parent);
            parent.close().await.unwrap();
        });
    }

    struct Reader {
        bytes: Vec<u8>,
        offset: usize,
        dropped: Arc<AtomicBool>,
    }

    impl AsyncRead for Reader {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if output.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if this.offset == this.bytes.len() {
                // The peer remains connected and sends no additional bytes.
                return Poll::Pending;
            }
            let count = output.remaining().min(this.bytes.len() - this.offset);
            output.put_slice(&this.bytes[this.offset..this.offset + count]);
            this.offset += count;
            Poll::Ready(Ok(()))
        }
    }

    impl Drop for Reader {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    struct Writer {
        writes: Arc<AtomicUsize>,
        dropped: Arc<AtomicBool>,
    }

    impl AsyncWrite for Writer {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.fetch_add(1, Ordering::AcqRel);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Drop for Writer {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    #[test]
    fn native_serve_drop_during_admission_reaps_before_parent_shutdown() {
        run(|cx, diagnostics| async move {
            let parent = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            let input_dropped = Arc::new(AtomicBool::new(false));
            let output_dropped = Arc::new(AtomicBool::new(false));
            let writes = Arc::new(AtomicUsize::new(0));
            let mut bytes = serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0", "id": 91, "method": "server/discover", "params": {
                    "_meta": {
                        fastmcp_protocol::FINAL_PROTOCOL_VERSION_META_KEY: fastmcp_protocol::FINAL_PROTOCOL_VERSION,
                        fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY: {},
                    }
                }
            }))
            .unwrap();
            bytes.push(b'\n');
            let service = crate::Server::new("native-admission-drop", "1")
                .protocol_policy(ProtocolPolicy::ModernOnly)
                .unwrap()
                .build();
            let mut serving = Box::pin(service.serve_stdio_io(
                parent.cx(),
                Reader {
                    bytes,
                    offset: 0,
                    dropped: Arc::clone(&input_dropped),
                },
                Writer {
                    writes: Arc::clone(&writes),
                    dropped: Arc::clone(&output_dropped),
                },
            ));
            asupersync::time::timeout(cx.now(), Duration::from_secs(3), async {
                loop {
                    assert!(poll_once(serving.as_mut()).await.is_pending());
                    // Run the scheduler without polling the serving future
                    // again. The mint can publish; dispatch cannot consume it.
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                    if !children(&diagnostics, parent.region_id()).is_empty() {
                        break;
                    }
                }
            })
            .await
            .expect("public serving never admitted the request region");
            assert_eq!(children(&diagnostics, parent.region_id()).len(), 1);
            assert_eq!(writes.load(Ordering::Acquire), 0);
            drop(serving);
            assert!(input_dropped.load(Ordering::Acquire));
            assert!(output_dropped.load(Ordering::Acquire));
            until(&cx, || children(&diagnostics, parent.region_id()).is_empty()).await;
            // The old direct ChildRegionOpening await leaves the mint open
            // here. Closing the parent before this assertion would hide it.
            parent_is_live(&diagnostics, &parent);
            parent.close().await.unwrap();
        });
    }

    #[test]
    fn native_admission_refuses_missing_runtime_and_restricted_spawn() {
        let detached = Cx::for_testing();
        assert!(open(&detached, Budget::INFINITE).is_err());
        run(|cx, diagnostics| async move {
            let parent = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            {
                let _caller = Cx::set_current(Some(parent.cx().clone()));
                let _restriction = Cx::push_restriction(asupersync::cx::cap::CapMask::none());
                assert!(open(parent.cx(), Budget::INFINITE).is_err());
            }
            assert!(children(&diagnostics, parent.region_id()).is_empty());
            parent_is_live(&diagnostics, &parent);
            parent.close().await.unwrap();
        });
    }
}
