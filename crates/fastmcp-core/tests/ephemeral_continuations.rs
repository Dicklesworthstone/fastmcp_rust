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

/// The last provable difference: serve's scope has HOSTED AND REAPED other
/// children before the reaper join. `lib.rs:7011` creates one `connection_scope`;
/// `:7015` spawns the reaper into it and `:7100` spawns every connection into the
/// SAME scope. By the time the reaper is joined those connections have run and
/// been reaped -- stage 32 recorded ZERO live children, so this is about a scope
/// that has hosted them, not one still holding them.
///
/// Every earlier revision joined in a scope that had only ever held one task.
#[test]
fn f2ndd_join_is_woken_in_a_scope_that_has_hosted_and_reaped_children() {
    f2ndd_runtime().block_on(async {
        use std::sync::atomic::Ordering::SeqCst;
        let cx = Cx::current().expect("bd-f2ndd repro ambient Cx");
        let scope = cx.scope();

        // Host and reap three children first, so the scope is not pristine.
        for index in 0..3 {
            let mut prior = cx
                .spawn_in(&scope, move |_child| async move {
                    asupersync::runtime::yield_now().await;
                    index
                })
                .expect("bd-f2ndd repro prior child must be admitted");
            let mut settled = false;
            for _ in 0..10_000 {
                if !matches!(prior.try_join(), Ok(None)) {
                    settled = true;
                    break;
                }
                asupersync::runtime::yield_now().await;
            }
            assert!(
                settled,
                "bd-f2ndd repro SETUP FAILED: prior child {index} never settled, so the scope was \
                 not left in the hosted-and-reaped state this test exists to model"
            );
        }

        // Now the same shape the other tests use, in a scope that has history.
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

        handle.abort();
        match f2ndd_bounded_join(&mut handle, release).await {
            F2nddJoin::WokenBeforeWatchdog(_) => {}
            F2nddJoin::NeverParked(_) => {
                panic!("bd-f2ndd repro VACUOUS: the joiner never parked, so no wakeup was tested")
            }
            F2nddJoin::OnlyWatchdog => panic!(
                "bd-f2ndd: in a scope that has HOSTED AND REAPED children, the joiner was released \
                 only by the watchdog -- while the identical shape in a pristine scope is woken. \
                 The scope's history is the differing variable"
            ),
        }
    });
}

// ===========================================================================
// bd-6rfrg G5: the DIAGNOSIS, demonstrated without the TRAP.
//
// WHY THESE LIVE HERE AND NOT IN THE END-TO-END FIXTURE. The public-API
// reproduction in crates/fastmcp/tests/e2e_modern_http.rs shows the hazard, but
// it cannot show the diagnosis today: the framework bridges its own HTTP
// dispatch at fastmcp-server/src/lib.rs:11465, so a user's `block_on` is a
// NESTED bridge, `BridgeEntry::enter`'s pre-existing assert fires before
// `ctx.sample` is ever polled, and the router redacts the panic. Removing that
// framework bridge is bd-fnd04-b7-4rkp9's work, and the orchestrator has gated
// it on this bead having a diagnostic that survives the removal.
//
// That gate is circular if the only evidence is end-to-end: the diagnosis
// cannot be demonstrated through the trap until the bridge is gone, and the
// bridge may not go until the diagnosis is demonstrated. It is not circular if
// the diagnosis is demonstrated DIRECTLY -- by putting the code in the position
// the predicate names and asserting the disposition. That needs no HTTP, no
// reverse request, and no framework bridge, so it runs today and keeps running
// after 4rkp9 lands.
//
// THE POSITION, stated exactly: `bridge_would_starve_its_driver` is true when a
// task context was already installed at bridge entry AND the thread is not a
// declared blocking lane. `Cx::set_current` installs that context here, which is
// the same ambient-Cx condition a handler polled inside a runtime task has. The
// predicate does NOT test for a nested bridge, which is why the diagnosis is
// bridge-INDEPENDENT and why bfd4008a satisfies the gate's property rather than
// merely postponing it.
// ===========================================================================

/// A context with sampling configured, so the capability-absent branch of
/// `sample_with_request` cannot be what answers.
fn bd_6rfrg_sampling_context() -> fastmcp_core::McpContext {
    fastmcp_core::McpContext::new(Cx::for_testing(), 6_001)
        .with_sampling(std::sync::Arc::new(fastmcp_core::NoOpSamplingSender))
}

/// bd-6rfrg G3/G5. In the starving position the failure is NAMED.
#[test]
fn bd_6rfrg_sampling_bridged_from_a_task_position_is_diagnosed() {
    let ctx = bd_6rfrg_sampling_context();
    // The one variable: a task context installed before the bridge is entered.
    let _ambient = Cx::set_current(Some(Cx::for_testing()));
    // NOTE: the predicate is deliberately NOT asserted here. It reads state that
    // `block_on` records at bridge ENTRY, so outside the bridge it is false by
    // construction and an assertion on it would pin the wrong moment. The first
    // draft of this test asserted `p() || !p()` to show it was publicly
    // callable -- a tautology that cannot fail, which is the exact defect class
    // this bead's own G5 was written to forbid. Public callability is proven by
    // this file compiling, not by an assert.
    let error = fastmcp_core::block_on(ctx.sample("bd-6rfrg probe", 16))
        .expect_err("sampling bridged from a task position must not report success");
    assert!(
        error.message.contains("block_on"),
        "G3: the diagnosis must name the bridge the user reached for: {error:?}"
    );
    assert!(
        error.message.contains("ToolExecutionMode::Async"),
        "G3: naming the problem without naming the remedy leaves the user as stuck as the \
         hang did: {error:?}"
    );
}

/// bd-6rfrg G5's PLANTED NEGATIVE, and it is the same call one position over.
///
/// No task context is installed, so the bridge is not occupying anyone's driver
/// and the diagnosis must NOT fire. If this arm were also diagnosed, the
/// predicate would be rejecting every bridge rather than discriminating by
/// position, and the assertion above would be worthless. RH-5.
#[test]
fn bd_6rfrg_the_same_bridge_outside_a_task_position_is_not_diagnosed() {
    let ctx = bd_6rfrg_sampling_context();
    let error = fastmcp_core::block_on(ctx.sample("bd-6rfrg probe", 16))
        .expect_err("the no-op sampling sender always reports an error");
    assert!(
        !error.message.contains("block_on"),
        "G5 NEGATIVE FAILED: a bridge with no task context was diagnosed as starving a driver, \
         so the predicate does not discriminate by position and the positive arm proves \
         nothing: {error:?}"
    );
}

// bd-6rfrg: elicitation and roots reach the peer through the same reverse
// request, so the obvious sync-tool bridge hangs the same way. Each pair below
// differs only in whether a task context is installed before the bridge, and
// counts peer contacts so the diagnosed arm proves it never sent anything.

struct CountingRoots(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl fastmcp_core::RootsProvider for CountingRoots {
    fn list_roots(
        &self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = fastmcp_core::McpResult<Vec<fastmcp_core::ClientRoot>>>
                + Send
                + '_,
        >,
    > {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Ok(Vec::new()) })
    }
}

struct CountingElicitation(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl fastmcp_core::ElicitationSender for CountingElicitation {
    fn elicit(
        &self,
        _request: fastmcp_core::ElicitationRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = fastmcp_core::McpResult<fastmcp_core::ElicitationResponse>,
                > + Send
                + '_,
        >,
    > {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async {
            Err(fastmcp_core::McpError::new(
                fastmcp_core::McpErrorCode::InvalidRequest,
                "counting elicitation peer",
            ))
        })
    }
}

fn bd_6rfrg_roots_list(task_position: bool) -> (fastmcp_core::McpResult<usize>, usize) {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ctx = fastmcp_core::McpContext::new(Cx::for_testing(), 6_002).with_roots_provider(
        std::sync::Arc::new(CountingRoots(std::sync::Arc::clone(&calls))),
    );
    let _ambient = task_position.then(|| Cx::set_current(Some(Cx::for_testing())));
    let result = fastmcp_core::block_on(ctx.list_roots()).map(|roots| roots.len());
    (result, calls.load(std::sync::atomic::Ordering::SeqCst))
}

fn bd_6rfrg_elicitation(task_position: bool) -> (fastmcp_core::McpError, usize) {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ctx = fastmcp_core::McpContext::new(Cx::for_testing(), 6_003).with_elicitation(
        std::sync::Arc::new(CountingElicitation(std::sync::Arc::clone(&calls))),
    );
    let _ambient = task_position.then(|| Cx::set_current(Some(Cx::for_testing())));
    let error = fastmcp_core::block_on(ctx.elicit_form("bd-6rfrg probe", serde_json::json!({})))
        .expect_err("both arms end in an error");
    (error, calls.load(std::sync::atomic::Ordering::SeqCst))
}

#[test]
fn bd_6rfrg_roots_bridged_from_a_task_position_is_diagnosed() {
    let (result, calls) = bd_6rfrg_roots_list(true);
    let error = result.expect_err("roots bridged from a task position must not report success");
    assert!(
        error
            .message
            .starts_with("Listing roots cannot complete from here"),
        "{error:?}"
    );
    assert!(
        error.message.contains("ToolExecutionMode::Async"),
        "{error:?}"
    );
    assert_eq!(calls, 0, "the diagnosed bridge must not contact the peer");
}

#[test]
fn bd_6rfrg_the_same_roots_bridge_outside_a_task_position_reaches_the_peer() {
    let (result, calls) = bd_6rfrg_roots_list(false);
    assert_eq!(
        result.expect("an undiagnosed bridge lists the peer's roots"),
        0
    );
    assert_eq!(calls, 1);
}

#[test]
fn bd_6rfrg_elicitation_bridged_from_a_task_position_is_diagnosed() {
    let (error, calls) = bd_6rfrg_elicitation(true);
    assert!(
        error
            .message
            .starts_with("Elicitation cannot complete from here"),
        "{error:?}"
    );
    assert!(
        error.message.contains("ToolExecutionMode::Async"),
        "{error:?}"
    );
    assert_eq!(calls, 0, "the diagnosed bridge must not contact the peer");
}

#[test]
fn bd_6rfrg_the_same_elicitation_bridge_outside_a_task_position_reaches_the_peer() {
    let (error, calls) = bd_6rfrg_elicitation(false);
    assert_eq!(error.message, "counting elicitation peer");
    assert_eq!(calls, 1);
}
