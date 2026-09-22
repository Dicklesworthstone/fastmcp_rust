//! Public protected-state consumer tests. Identity facts below are explicitly
//! supplied provider fixtures, not a proof of HTTP authentication or full MRTR.
use std::time::Duration;
use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_core::ingress::{
    SecurityPartitionDescriptor, VerifiedAudienceBinding, VerifiedIdentityFacts,
    VerifiedIngressAuthentication,
};
use fastmcp_core::partition::{ContinuationPartitionKey, DurableOwnerKey, PartitionAuthorization};
use fastmcp_core::runtime::{ProcessGenerationGuard, SnapshotCloneStance};
use fastmcp_core::runtime::envelope::{EnvelopeBinding, EnvelopePolicy};
use fastmcp_core::runtime::envelope::continuations::{
    ContinuationHandle, ContinuationStoreError, ContinuationStorePolicy, EphemeralContinuationStore,
};

fn identity(subject: &str, operation: &str, epoch: u64) -> (ContinuationPartitionKey, PartitionAuthorization) {
    let ingress = VerifiedIngressAuthentication::from_verified_provider_output(VerifiedIdentityFacts {
        provider: "fixture-provider", configuration_generation: 7,
        issuer: "https://issuer.example", canonical_resource: "https://mcp.example/mcp",
        verified_audience_binding: VerifiedAudienceBinding::OAuth {
            canonical_resource: "https://mcp.example/mcp".to_owned(),
            validated_audience: "https://mcp.example/mcp".to_owned(),
            audience_policy_id: "fixture-policy".to_owned(), audience_policy_revision: 3,
            provider: "fixture-provider".to_owned(), configuration_generation: 7,
        },
        tenant: "tenant-one", subject_or_principal: subject, authorized_party_or_client: "client-one",
        verified_claims: &[], auth_policy_revision: 4, trust_generation: 2,
    }).unwrap();
    let descriptor = SecurityPartitionDescriptor::from_verified_ingress(&ingress).to_partition_descriptor().unwrap();
    let key = ContinuationPartitionKey::derive(&descriptor, &["tools:call"], operation,
        "client-capabilities", "continuation-policy", "continuation-domain").unwrap();
    let owner = DurableOwnerKey::derive(&descriptor, epoch).unwrap();
    (key, PartitionAuthorization::current(&descriptor, &owner))
}
fn store(limits: ContinuationStorePolicy) -> EphemeralContinuationStore {
    EphemeralContinuationStore::new(&Cx::for_testing(), ProcessGenerationGuard::install().unwrap(),
        SnapshotCloneStance::NoLiveMemoryCloning, "checkout",
        EnvelopePolicy::new(1024, Duration::from_secs(60), 4).unwrap(), limits).unwrap()
}
fn ttl() -> Duration { Duration::from_secs(60) }

#[test]
fn protected_continuation_round_trip_consumes_wire_aliases_once() {
    let cx = Cx::for_testing();
    let (key, auth) = identity("alice", "tools/call:checkout", 1);
    let mut store = store(ContinuationStorePolicy::default());
    let handle = store.put(&cx, &key, &auth, &McpRequestCancellation::new(), b"private state\0\xff", ttl()).unwrap();
    let replay = ContinuationHandle::from_wire(&handle.to_wire()).unwrap();
    assert_eq!(handle.to_wire().len(), 80);
    assert_eq!(store.len(), 1);
    assert_eq!(store.take(&cx, &key, &auth, &handle).unwrap().as_bytes(), b"private state\0\xff");
    assert!(store.is_empty());
    assert_eq!(store.retained_bytes(), 0);
    assert!(matches!(store.take(&cx, &key, &auth, &replay), Err(ContinuationStoreError::Unavailable)));
}

#[test]
fn protected_continuation_foreign_principal_operation_or_epoch_cannot_consume() {
    let cx = Cx::for_testing();
    let (key, auth) = identity("alice", "tools/call:checkout", 1);
    let mut store = store(ContinuationStorePolicy::default());
    let handle = store.put(&cx, &key, &auth, &McpRequestCancellation::new(), b"private", ttl()).unwrap();
    let bytes = store.retained_bytes();
    for (other_key, other_auth) in [identity("bob", "tools/call:checkout", 1),
        identity("alice", "tools/call:refund", 1), identity("alice", "tools/call:checkout", 2)] {
        assert!(matches!(store.take(&cx, &other_key, &other_auth, &handle), Err(ContinuationStoreError::Unavailable)));
        assert_eq!(store.len(), 1);
        assert_eq!(store.retained_bytes(), bytes);
    }
    assert_eq!(store.take(&cx, &key, &auth, &handle).unwrap().as_bytes(), b"private");
}

#[test]
fn protected_continuation_wrong_authorization_cannot_use_a_copied_partition_key() {
    let cx = Cx::for_testing();
    let (key, auth) = identity("alice", "tools/call:checkout", 1);
    let (_, foreign_auth) = identity("bob", "tools/call:checkout", 1);
    let mut store = store(ContinuationStorePolicy::default());
    let handle = store.put(&cx, &key, &auth, &McpRequestCancellation::new(), b"private", ttl()).unwrap();
    assert!(matches!(store.take(&cx, &key, &foreign_auth, &handle), Err(ContinuationStoreError::Unavailable)));
    assert_eq!(store.take(&cx, &key, &auth, &handle).unwrap().as_bytes(), b"private");
}

#[test]
fn protected_continuation_capacity_never_evicts_live_work() {
    let cx = Cx::for_testing();
    let (key, auth) = identity("alice", "tools/call:checkout", 1);
    let mut store = store(ContinuationStorePolicy::new(1, 4096).unwrap());
    let owner = McpRequestCancellation::new();
    let first = store.put(&cx, &key, &auth, &owner, b"first", ttl()).unwrap();
    let bytes = store.retained_bytes();
    assert!(matches!(store.put(&cx, &key, &auth, &owner, b"second", ttl()), Err(ContinuationStoreError::Capacity)));
    assert_eq!(store.retained_bytes(), bytes);
    assert_eq!(store.prune(&cx).unwrap(), 0);
    assert_eq!(store.take(&cx, &key, &auth, &first).unwrap().as_bytes(), b"first");
    let second = store.put(&cx, &key, &auth, &owner, b"second", ttl()).unwrap();
    assert_ne!(first.to_wire(), second.to_wire());
    assert!(matches!(store.take(&cx, &key, &auth, &first), Err(ContinuationStoreError::Unavailable)));
    assert_eq!(store.take(&cx, &key, &auth, &second).unwrap().as_bytes(), b"second");
}

#[test]
fn protected_continuation_byte_budget_applies_before_retention() {
    let cx = Cx::for_testing();
    let (key, auth) = identity("alice", "tools/call:checkout", 1);
    let mut store = store(ContinuationStorePolicy::new(8, 1).unwrap());
    assert!(matches!(store.put(&cx, &key, &auth, &McpRequestCancellation::new(), b"", ttl()), Err(ContinuationStoreError::Capacity)));
    assert!(store.is_empty());
    assert_eq!(store.retained_bytes(), 0);
}

#[test]
fn protected_continuation_owner_cancellation_revokes_and_prunes_only_owned_entries() {
    let cx = Cx::for_testing();
    let (key, auth) = identity("alice", "tools/call:checkout", 1);
    let mut store = store(ContinuationStorePolicy::default());
    let cancelled = McpRequestCancellation::new();
    let live = McpRequestCancellation::new();
    let old = store.put(&cx, &key, &auth, &cancelled, b"old", ttl()).unwrap();
    let current = store.put(&cx, &key, &auth, &live, b"current", ttl()).unwrap();
    cancelled.cancel();
    assert!(matches!(store.take(&cx, &key, &auth, &old), Err(ContinuationStoreError::Unavailable)));
    assert!(matches!(store.put(&cx, &key, &auth, &cancelled, b"new", ttl()), Err(ContinuationStoreError::Unavailable)));
    assert_eq!(store.prune(&cx).unwrap(), 1);
    assert!(!live.is_cancel_requested());
    assert_eq!(store.take(&cx, &key, &auth, &current).unwrap().as_bytes(), b"current");
    assert_eq!(store.retained_bytes(), 0);
}

#[test]
fn protected_continuation_rotation_preserves_pending_handles_and_close_is_terminal() {
    let cx = Cx::for_testing();
    let (key, auth) = identity("alice", "tools/call:checkout", 1);
    let mut store = store(ContinuationStorePolicy::default());
    let owner = McpRequestCancellation::new();
    let old = store.put(&cx, &key, &auth, &owner, b"old", ttl()).unwrap();
    assert_eq!(store.rotate(&cx).unwrap(), 2);
    let new = store.put(&cx, &key, &auth, &owner, b"new", ttl()).unwrap();
    assert_eq!(store.take(&cx, &key, &auth, &old).unwrap().as_bytes(), b"old");
    store.close();
    assert!(store.is_empty());
    assert_eq!(store.retained_bytes(), 0);
    assert!(store.take(&cx, &key, &auth, &new).is_err());
    assert!(store.put(&cx, &key, &auth, &owner, b"more", ttl()).is_err());
    assert!(!owner.is_cancel_requested());
}

#[test]
fn protected_continuation_independent_store_cannot_adopt_an_old_handle() {
    let cx = Cx::for_testing();
    let (key, auth) = identity("alice", "tools/call:checkout", 1);
    let mut old = store(ContinuationStorePolicy::default());
    let mut replacement = store(ContinuationStorePolicy::default());
    let handle = old.put(&cx, &key, &auth, &McpRequestCancellation::new(), b"private", ttl()).unwrap();
    assert!(matches!(replacement.take(&cx, &key, &auth, &handle), Err(ContinuationStoreError::Unavailable)));
    assert_eq!(old.take(&cx, &key, &auth, &handle).unwrap().as_bytes(), b"private");
}

#[test]
fn protected_continuation_binding_namespaces_and_wire_encoding_are_strict() {
    let (key, auth) = identity("alice", "tools/call:checkout", 1);
    assert_ne!(EnvelopeBinding::continuation(&key, &auth, "one").unwrap(),
        EnvelopeBinding::continuation(&key, &auth, "two").unwrap());
    for namespace in ["".to_owned(), "x".repeat(129), "line\nbreak".to_owned()] {
        assert!(EnvelopeBinding::continuation(&key, &auth, &namespace).is_err());
    }
    for wire in ["".to_owned(), "0".repeat(79), "0".repeat(81), "A".repeat(80), "g".repeat(80), "é".repeat(40)] {
        assert!(matches!(ContinuationHandle::from_wire(&wire), Err(ContinuationStoreError::Unavailable)));
    }
    let wire = "ab".repeat(40);
    let handle = ContinuationHandle::from_wire(&wire).unwrap();
    assert_eq!(handle.to_wire(), wire);
    assert!(!format!("{handle:?}").contains(&wire));
}

#[test]
fn protected_continuation_competing_wire_replays_have_one_successful_consumer() {
    let (key, auth) = identity("alice", "tools/call:checkout", 1);
    let mut store = store(ContinuationStorePolicy::default());
    let handle = store.put(&Cx::for_testing(), &key, &auth, &McpRequestCancellation::new(), b"once", ttl()).unwrap();
    let store = std::sync::Mutex::new(store);
    let wire = handle.to_wire();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let consume = || {
            let handle = ContinuationHandle::from_wire(&wire).unwrap();
            barrier.wait();
            match store.lock().unwrap().take(&Cx::for_testing(), &key, &auth, &handle) {
                Ok(state) => { assert_eq!(state.as_bytes(), b"once"); true }
                Err(ContinuationStoreError::Unavailable) => false,
                Err(error) => panic!("unexpected continuation error: {error}"),
            }
        };
        let first = scope.spawn(consume);
        let second = scope.spawn(consume);
        assert_ne!(first.join().unwrap(), second.join().unwrap());
    });
    assert!(store.lock().unwrap().is_empty());
}

// ===========================================================================
// bd-f2ndd UPSTREAM ISOLATION
//
// These two exercise asupersync's task/scope/join machinery and NOTHING of
// ours, so a failure here places the defect upstream and a pass places it in
// how fastmcp-server uses the API. They live in this file rather than a new
// one because `crates` is a closed_scan_root and a new path widens the
// unlisted-file count. This file already imports `asupersync::Cx`, which
// makes it the least incongruous host -- note its own `scope.spawn`/`join`
// are `std::thread::scope`, not asupersync's, so the two machineries below
// are unrelated to the ones above.
//
// Both are POLL-bounded rather than TIME-bounded on purpose. A time bound
// would need a timer driver, and whether a timer driver is present is one of
// the things under suspicion -- a repro that depends on the mechanism it is
// testing proves nothing. Neither can hang: both terminate after a fixed
// number of polls and fail with a message.
// ===========================================================================

fn f2ndd_runtime() -> asupersync::runtime::Runtime {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(
            asupersync::runtime::reactor::create_reactor().expect("bd-f2ndd repro reactor"),
        )
        .build()
        .expect("bd-f2ndd repro runtime")
}

/// Outcome of a bounded join attempt. Three values because a green is only
/// meaningful if the joiner actually PARKED -- "woke promptly" and "never
/// waited" produce identical output and identical wall clocks otherwise.
#[derive(Debug)]
enum F2nddJoin<T> {
    /// poll_join was Ready on the first poll: the joiner never parked, so no
    /// wakeup was exercised. VACUOUS -- not a pass.
    NeverParked(T),
    /// Parked, then woken by asupersync before the watchdog fired. The only
    /// outcome unreachable under the missed-wakeup hypothesis.
    WokenBeforeWatchdog(T),
    /// Parked and released only by the watchdog: a missed wakeup.
    OnlyWatchdog,
}

/// Parks on `poll_join`, releasing `release` on the first park so the task under
/// test completes only AFTER the joiner is committed to waiting -- which is the
/// mechanism `serve` exercises and which a body that finishes first cannot test.
///
/// `poll_join` rather than `try_join`: it keeps the waiter registered across
/// polls, where `try_join` registers nothing and so can never miss a wakeup.
/// The bound is a real std::thread on a real wall clock, deliberately outside
/// asupersync's timer, because that timer is among the suspects and a
/// self-waking loop reintroduces busy-poll blindness.
async fn f2ndd_bounded_join<T>(
    handle: &mut asupersync::runtime::TaskHandle<T>,
    release: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> F2nddJoin<Result<T, asupersync::runtime::JoinError>> {
    use std::sync::atomic::Ordering::SeqCst;
    let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut armed = false;
    std::future::poll_fn(move |task| match handle.poll_join(task) {
        std::task::Poll::Ready(result) => std::task::Poll::Ready(if !armed {
            F2nddJoin::NeverParked(result)
        } else if fired.load(SeqCst) {
            F2nddJoin::OnlyWatchdog
        } else {
            F2nddJoin::WokenBeforeWatchdog(result)
        }),
        std::task::Poll::Pending => {
            if !armed {
                armed = true;
                release.store(true, SeqCst);
                let waker = task.waker().clone();
                let flag = std::sync::Arc::clone(&fired);
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_secs(2));
                    flag.store(true, SeqCst);
                    waker.wake();
                });
            } else if fired.load(SeqCst) {
                return std::task::Poll::Ready(F2nddJoin::OnlyWatchdog);
            }
            std::task::Poll::Pending
        }
    })
    .await
}

/// The FOUR: the joiner parks, THEN the task completes. Must the joiner be woken?
#[test]
fn f2ndd_join_is_woken_when_the_task_completes_while_it_waits() {
    f2ndd_runtime().block_on(async {
        use std::sync::atomic::Ordering::SeqCst;
        let cx = Cx::current().expect("bd-f2ndd repro ambient Cx");
        let scope = cx.scope();
        let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let child_release = std::sync::Arc::clone(&release);
        let mut handle = cx
            .spawn_in(&scope, move |child| async move {
                // Stay alive until the joiner has parked, so the join cannot be
                // Ready on its first poll.
                while !child_release.load(SeqCst) {
                    asupersync::runtime::yield_now().await;
                }
                let _ = child.checkpoint();
            })
            .expect("bd-f2ndd repro spawn_in must be admitted");

        handle.abort();
        match f2ndd_bounded_join(&mut handle, release).await {
            F2nddJoin::WokenBeforeWatchdog(_) => {}
            F2nddJoin::NeverParked(_) => {
                panic!("bd-f2ndd repro VACUOUS: the joiner never parked, so no wakeup was tested")
            }
            F2nddJoin::OnlyWatchdog => panic!(
                "bd-f2ndd: the joiner parked and was released ONLY by the watchdog -- the task \
                 completed while it waited and nothing woke it, with nothing of ours involved"
            ),
        }
    });
}

/// The FIFTH: a task parked in sleep, aborted. Is the joiner woken?
#[test]
fn f2ndd_abort_wakes_the_joiner_of_a_task_parked_in_sleep() {
    f2ndd_runtime().block_on(async {
        let cx = Cx::current().expect("bd-f2ndd repro ambient Cx");
        let scope = cx.scope();
        let mut handle = cx
            .spawn_in(&scope, move |child| async move {
                loop {
                    asupersync::time::sleep(child.now(), Duration::from_millis(100)).await;
                    if child.checkpoint().is_err() {
                        break;
                    }
                }
            })
            .expect("bd-f2ndd repro spawn_in must be admitted");

        for _ in 0..1_000 {
            asupersync::runtime::yield_now().await;
        }
        handle.abort();
        // No release flag: this task's liveness comes from its own sleep loop.
        let unused = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        match f2ndd_bounded_join(&mut handle, unused).await {
            F2nddJoin::WokenBeforeWatchdog(_) => {}
            F2nddJoin::NeverParked(_) => panic!(
                "bd-f2ndd repro VACUOUS: the joiner never parked, so the sleeping task had \
                 already settled and no wakeup was tested"
            ),
            F2nddJoin::OnlyWatchdog => panic!(
                "bd-f2ndd: abort did NOT wake the joiner of a task parked in sleep() -- released \
                 only by the watchdog"
            ),
        }
    });
}

/// The SERVER's actual shape: the joiner's OWN cx is cancelled before it joins.
///
/// `serve` reaches the reaper join only by breaking its accept loop at
/// `lib.rs:7063` -- `if cx.checkpoint().is_err() { break Ok(()); }` -- so its cx
/// is provably cancelled at that point. The two tests above join on a LIVE cx,
/// which is the one dimension separating them from the failing path.
///
/// Ordering is deterministic and mirrors serve: the cx is cancelled first, the
/// child stays alive on the release flag, the joiner parks, the release fires,
/// and only then does the child observe cancellation and complete. So the
/// joiner is parked on a cancelled cx while the task it waits for finishes.
#[test]
fn f2ndd_join_is_woken_on_a_cancelled_cx_when_the_task_completes_while_it_waits() {
    f2ndd_runtime().block_on(async {
        use std::sync::atomic::Ordering::SeqCst;
        let cx = Cx::current().expect("bd-f2ndd repro ambient Cx");
        let scope = cx.scope();
        let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let child_release = std::sync::Arc::clone(&release);
        let mut handle = cx
            .spawn_in(&scope, move |child| async move {
                while !child_release.load(SeqCst) {
                    asupersync::runtime::yield_now().await;
                }
                let _ = child.checkpoint();
            })
            .expect("bd-f2ndd repro spawn_in must be admitted");

        // Cancel the JOINER's own cx, as serve's break condition proves happened.
        cx.cancel_with(
            asupersync::CancelKind::User,
            Some("bd-f2ndd repro: cancel the joiner's cx, as serve's accept-loop break implies"),
        );
        handle.abort();

        match f2ndd_bounded_join(&mut handle, release).await {
            F2nddJoin::WokenBeforeWatchdog(_) => {}
            F2nddJoin::NeverParked(_) => panic!(
                "bd-f2ndd repro VACUOUS: the joiner never parked -- cancelling the cx settled the \
                 child before the join, so this shape did not reproduce and must be restructured"
            ),
            F2nddJoin::OnlyWatchdog => panic!(
                "bd-f2ndd: a joiner on a CANCELLED cx was released only by the watchdog, while the \
                 same shape on a live cx is woken -- the cancelled cx is the differing variable"
            ),
        }
    });
}
