//! These fixtures exercise real HMAC and the shipped facade. Their process-local
//! keys are test data, never evidence of a qualified persistent deployment.
use super::*;
use crate::crypto::{HmacSha256Key, HmacSha256Tag};
use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

fn hash(byte: u8) -> Sha256Digest { Sha256Digest::from_bytes([byte; 32]) }
fn key(generation: u64) -> PersistentMacKeyGeneration {
    PersistentMacKeyGeneration::new(&format!("k{generation}"), generation).unwrap()
}
fn provider() -> PersistentMacProviderIdentity {
    PersistentMacProviderIdentity::new("fixture-mac-v1", hash(1), hash(2)).unwrap()
}
fn configuration(active: u64, previous: &[u64]) -> PersistentReplayConfiguration {
    PersistentReplayConfiguration::new(provider(), active, key(active), previous.iter().copied().map(key).collect()).unwrap()
}
fn lane(limits: ReplayDigestLimits) -> Arc<ReplayMacLane> { Arc::new(ReplayMacLane::new(limits).unwrap()) }
fn facade(backend: &Arc<FixtureBackend>, lane: &Arc<ReplayMacLane>, active: u64, previous: &[u64]) -> PersistentReplayDigest {
    PersistentReplayDigest::new(configuration(active, previous), backend.clone(), lane.clone()).unwrap()
}
fn deadline(cx: &Cx) -> Time { cx.now().saturating_add_nanos(5_000_000_000) }
fn rejected<T>(result: Result<T, ReplayDigestError>) -> ReplayDigestError {
    match result { Ok(_) => panic!("operation unexpectedly succeeded"), Err(error) => error }
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn aliases(set: &PersistentReplayAliasSet) -> Vec<(String, u64, [u8; 32])> {
    set.aliases().iter().map(|alias| (alias.key_id().to_owned(), alias.generation(), *alias.tag())).collect()
}
fn fixture_key(generation: u64) -> HmacSha256Key {
    HmacSha256Key::from_bytes([(generation as u8).wrapping_mul(17); 32])
}

#[derive(Clone, Copy)]
enum Mode {
    Honest,
    FailGeneration(u64, PersistentMacDispatch),
    SuccessDispatch(PersistentMacDispatch),
    Corrupt(u8),
    Pending,
    CancelDuringPoll,
    PanicDuringPoll,
}
#[derive(Clone)]
struct Seen { operation: [u8; 16], generation: u64, input: Vec<u8> }
#[derive(Clone, Copy, Debug)]
struct Effects { stage: &'static str, ambient_io: bool, explicit_io: bool, task_matches: bool }
struct FixtureBackend {
    mode: Mode,
    calls: AtomicUsize,
    verifications: AtomicUsize,
    drops: AtomicUsize,
    seen: Mutex<Vec<Seen>>,
    effects: Mutex<Vec<Effects>>,
}
impl FixtureBackend {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self { mode, calls: AtomicUsize::new(0), verifications: AtomicUsize::new(0), drops: AtomicUsize::new(0), seen: Mutex::new(Vec::new()), effects: Mutex::new(Vec::new()) })
    }
    fn observe(&self, stage: &'static str, cx: &Cx) {
        let ambient = Cx::current().expect("provider must execute under explicit caller");
        self.effects.lock().unwrap().push(Effects { stage, ambient_io: ambient.capabilities().io, explicit_io: cx.capabilities().io, task_matches: ambient.task_id() == cx.task_id() });
    }
}
struct MacProbe<'a> { backend: &'a FixtureBackend, cx: &'a Cx, request: Option<PersistentMacRequest> }
impl Future for MacProbe<'_> {
    type Output = Result<PersistentMacReply, PersistentMacFailure>;
    fn poll(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.backend.observe("poll", this.cx);
        match this.backend.mode {
            Mode::Pending => return Poll::Pending,
            Mode::PanicDuringPoll => panic!("fixture provider panic"),
            Mode::CancelDuringPoll => this.cx.set_cancel_requested(true),
            _ => {}
        }
        let request = this.request.take().expect("only one completion");
        let mut receipt = PersistentMacReceipt::reported_for(&request, PersistentMacDispatch::Dispatched);
        if let Mode::FailGeneration(generation, dispatch) = this.backend.mode {
            if request.generation() == generation {
                receipt.dispatch = dispatch;
                return Poll::Ready(Err(PersistentMacFailure::new(receipt)));
            }
        }
        if let Mode::SuccessDispatch(dispatch) = this.backend.mode { receipt.dispatch = dispatch; }
        if let Mode::Corrupt(field) = this.backend.mode {
            match field {
                0 => receipt.operation_id[0] ^= 1,
                1 => receipt.provider_digest = hash(91),
                2 => receipt.ring_digest = hash(92),
                3 => receipt.key.key_id.push('x'),
                4 => receipt.key.generation += 1,
                5 => receipt.purpose = ReplayPurpose::EnterpriseIdJagJtiReplay,
                6 => receipt.input_digest = hash(93),
                _ => panic!("unknown corruption fixture"),
            }
        }
        let tag = fixture_key(request.generation()).authenticate_bounded(request.input(), MAX_INPUT_BYTES).unwrap().into_bytes();
        Poll::Ready(Ok(PersistentMacReply::new(receipt, tag)))
    }
}
impl Drop for MacProbe<'_> {
    fn drop(&mut self) { self.backend.observe("drop", self.cx); self.backend.drops.fetch_add(1, Ordering::Relaxed); }
}
impl PersistentHmacSha256Backend for FixtureBackend {
    fn mac<'a>(&'a self, cx: &'a Cx, request: PersistentMacRequest, _deadline: Time) -> BoxFuture<'a, Result<PersistentMacReply, PersistentMacFailure>> {
        self.observe("construct", cx);
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.seen.lock().unwrap().push(Seen { operation: request.operation_id(), generation: request.generation(), input: request.input().to_vec() });
        Box::pin(MacProbe { backend: self, cx, request: Some(request) })
    }
    fn verify<'a>(&'a self, cx: &'a Cx, request: PersistentMacRequest, tag: [u8; 32], _deadline: Time) -> BoxFuture<'a, Result<PersistentMacVerification, PersistentMacFailure>> {
        self.observe("verify-construct", cx);
        self.verifications.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            let verified = fixture_key(request.generation()).verify_bounded(request.input(), MAX_INPUT_BYTES, &HmacSha256Tag::from_bytes(tag)).is_ok();
            Ok(PersistentMacVerification::new(PersistentMacReceipt::reported_for(&request, PersistentMacDispatch::Dispatched), verified))
        })
    }
}

#[test]
fn exact_context_input_and_hmac_known_answer() {
    let compact = Sha256Digest::from_bytes(std::array::from_fn(|index| index as u8));
    let tuple = ReplayTuple::IdentityAssertion("x", &compact);
    let context = tuple.encode(tuple.length(MAX_CONTEXT_BYTES).unwrap()).unwrap();
    assert_eq!(hex(&context), "464d43505343580000010002000102000000017800020100000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let generation = PersistentMacKeyGeneration::new("v1", 7).unwrap();
    let input = encode_mac(tuple.purpose(), &generation, &context, MAX_INPUT_BYTES).unwrap();
    assert_eq!(input.len(), 87);
    assert_eq!(hex(&input), "464d435052504c00000100010002763100000000000000070000003b464d43505343580000010002000102000000017800020100000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    // Independently generated HMAC-SHA-256 fixture; its generator was checked
    // against RFC 4231 test case 1, not generated by this implementation.
    let tag = HmacSha256Key::from_bytes([0x11; 32]).authenticate_bounded(&input, MAX_INPUT_BYTES).unwrap();
    assert_eq!(hex(tag.as_bytes()), "f2aa4423689d88421c682c105224830869b9307c68f82161e074b6d7a682cb89");
}

#[test]
fn exact_bytes_segmentation_and_purpose_are_not_interchangeable() {
    let compact = hash(42);
    let identity = ReplayTuple::IdentityAssertion("https://idp.example", &compact);
    let jti = ReplayTuple::IdJagJti("https://idp.example", compact.as_bytes());
    let a = identity.encode(identity.length(MAX_CONTEXT_BYTES).unwrap()).unwrap();
    let b = jti.encode(jti.length(MAX_CONTEXT_BYTES).unwrap()).unwrap();
    assert_eq!(a.as_slice(), b.as_slice());
    assert_ne!(encode_mac(identity.purpose(), &key(1), &a, MAX_INPUT_BYTES).unwrap().as_slice(), encode_mac(jti.purpose(), &key(1), &b, MAX_INPUT_BYTES).unwrap().as_slice());
    let left = ReplayTuple::IdJagJti("ab", b"c");
    let right = ReplayTuple::IdJagJti("a", b"bc");
    assert_ne!(left.encode(left.length(MAX_CONTEXT_BYTES).unwrap()).unwrap().as_slice(), right.encode(right.length(MAX_CONTEXT_BYTES).unwrap()).unwrap().as_slice());
    let slash = ReplayTuple::IdentityAssertion("https://idp.example/", &compact);
    assert_ne!(a.as_slice(), slash.encode(slash.length(MAX_CONTEXT_BYTES).unwrap()).unwrap().as_slice());
}

#[test]
fn ring_configuration_is_canonical_bounded_and_sensitive_to_active_generation() {
    let a = configuration(3, &[2, 1]);
    let b = configuration(3, &[1, 2]);
    assert_eq!(a.digest(), b.digest());
    assert_ne!(a.digest(), configuration(2, &[3, 1]).digest());
    assert!(matches!(PersistentReplayConfiguration::new(provider(), 1, key(1), vec![key(1)]), Err(ReplayDigestError::InvalidConfiguration)));
    assert!(matches!(PersistentReplayConfiguration::new(provider(), 1, key(1), (2..=9).map(key).collect()), Err(ReplayDigestError::InvalidConfiguration)));
    for id in ["", "spaces forbidden", "path/selector", "unicode-\u{00e9}"] { assert!(PersistentMacKeyGeneration::new(id, 1).is_err()); }
}

#[test]
fn all_three_generations_produce_real_aliases_and_verify_through_public_facade() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        let backend = FixtureBackend::new(Mode::Honest);
        let lane = lane(ReplayDigestLimits::default());
        let engine = facade(&backend, &lane, 3, &[2, 1]);
        let set = engine.derive_identity_assertion(&cx, "https://idp.example", &hash(42), deadline(&cx)).await.unwrap();
        assert_eq!(set.purpose(), ReplayPurpose::EnterpriseIdentityAssertionReplay);
        assert_eq!(set.ring_digest(), engine.ring_digest());
        assert_eq!(set.aliases().iter().map(|alias| alias.generation()).collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(backend.calls.load(Ordering::Relaxed), 3);
        let seen = backend.seen.lock().unwrap().clone();
        for (index, alias) in set.aliases().iter().enumerate() {
            assert_eq!(seen[index].generation, alias.generation());
            let tag = fixture_key(alias.generation()).authenticate_bounded(&seen[index].input, MAX_INPUT_BYTES).unwrap();
            assert_eq!(alias.tag(), tag.as_bytes());
            engine.verify_identity_assertion_alias(&cx, "https://idp.example", &hash(42), alias, deadline(&cx)).await.unwrap();
        }
        assert!(seen.iter().enumerate().all(|(index, entry)| seen.iter().skip(index + 1).all(|other| entry.operation != other.operation)));
        assert_eq!(backend.verifications.load(Ordering::Relaxed), 3);
        assert_eq!(backend.drops.load(Ordering::Relaxed), 3);
        assert_eq!(lane.snapshot().unwrap(), ReplayMacSnapshot::default());
    });
}

#[test]
fn repeated_derivation_is_stable_while_operation_ids_change() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        let backend = FixtureBackend::new(Mode::Honest);
        let lane = lane(ReplayDigestLimits::default());
        let engine = facade(&backend, &lane, 2, &[1]);
        let first = engine.derive_id_jag_jti(&cx, "https://idp.example", b"signed-jti", deadline(&cx)).await.unwrap();
        let second = engine.derive_id_jag_jti(&cx, "https://idp.example", b"signed-jti", deadline(&cx)).await.unwrap();
        assert_eq!(aliases(&first), aliases(&second));
        assert_eq!(first.digest(), second.digest());
        let seen = backend.seen.lock().unwrap();
        assert_ne!(seen[0].operation, seen[2].operation);
        assert_ne!(seen[1].operation, seen[3].operation);
    });
}

#[test]
fn rotation_preserves_every_old_alias_and_changes_the_complete_ring_binding() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        let backend = FixtureBackend::new(Mode::Honest);
        let lane = lane(ReplayDigestLimits::default());
        let old = facade(&backend, &lane, 2, &[1]);
        let expanded = facade(&backend, &lane, 3, &[1, 2]);
        let first = old.derive_identity_assertion(&cx, "https://idp.example", &hash(8), deadline(&cx)).await.unwrap();
        let second = expanded.derive_identity_assertion(&cx, "https://idp.example", &hash(8), deadline(&cx)).await.unwrap();
        assert_eq!(aliases(&first), aliases(&second)[..2]);
        assert_ne!(first.ring_digest(), second.ring_digest());
        assert_ne!(first.digest(), second.digest());
        assert_eq!(second.aliases().len(), 3);
        // This verifies overlap, not permission to roll out the expanded ring.
    });
}

#[test]
fn every_receipt_correlation_field_is_checked_before_publication() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        for field in 0..7 {
            let backend = FixtureBackend::new(Mode::Corrupt(field));
            let lane = lane(ReplayDigestLimits::default());
            let engine = facade(&backend, &lane, 2, &[1]);
            assert_eq!(rejected(engine.derive_identity_assertion(&cx, "https://idp.example", &hash(8), deadline(&cx)).await), ReplayDigestError::ReceiptMismatch);
            assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
            assert_eq!(lane.snapshot().unwrap(), ReplayMacSnapshot::default());
        }
    });
}

#[test]
fn unknown_or_not_dispatched_success_never_releases_an_alias_set() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        for dispatch in [PersistentMacDispatch::Unknown, PersistentMacDispatch::NotDispatched] {
            let backend = FixtureBackend::new(Mode::SuccessDispatch(dispatch));
            let lane = lane(ReplayDigestLimits::default());
            let engine = facade(&backend, &lane, 2, &[1]);
            assert_eq!(rejected(engine.derive_identity_assertion(&cx, "https://idp.example", &hash(8), deadline(&cx)).await), ReplayDigestError::ProviderRejected(dispatch));
            assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
            assert_eq!(lane.snapshot().unwrap(), ReplayMacSnapshot::default());
        }
    });
}

#[test]
fn a_later_generation_failure_discards_prior_success_without_a_partial_set() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        for dispatch in [PersistentMacDispatch::NotDispatched, PersistentMacDispatch::Dispatched, PersistentMacDispatch::Unknown] {
            let backend = FixtureBackend::new(Mode::FailGeneration(2, dispatch));
            let lane = lane(ReplayDigestLimits::default());
            let engine = facade(&backend, &lane, 3, &[1, 2]);
            assert_eq!(rejected(engine.derive_identity_assertion(&cx, "https://idp.example", &hash(8), deadline(&cx)).await), ReplayDigestError::ProviderRejected(dispatch));
            assert_eq!(backend.calls.load(Ordering::Relaxed), 2);
            assert_eq!(backend.drops.load(Ordering::Relaxed), 2);
            assert_eq!(lane.snapshot().unwrap(), ReplayMacSnapshot::default());
        }
    });
}

#[test]
fn constant_time_backend_verification_rejects_changed_tag_and_changed_tuple() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        let backend = FixtureBackend::new(Mode::Honest);
        let lane = lane(ReplayDigestLimits::default());
        let engine = facade(&backend, &lane, 1, &[]);
        let set = engine.derive_identity_assertion(&cx, "https://idp.example", &hash(7), deadline(&cx)).await.unwrap();
        let alias = &set.aliases()[0];
        let mut tag = *alias.tag(); tag[31] ^= 1;
        let changed = PersistentReplayAlias::from_persisted(alias.purpose(), alias.key_id(), alias.generation(), tag).unwrap();
        assert_eq!(rejected(engine.verify_identity_assertion_alias(&cx, "https://idp.example", &hash(7), &changed, deadline(&cx)).await), ReplayDigestError::VerificationRejected);
        assert_eq!(rejected(engine.verify_identity_assertion_alias(&cx, "https://idp.example/", &hash(7), alias, deadline(&cx)).await), ReplayDigestError::VerificationRejected);
        assert_eq!(rejected(engine.verify_identity_assertion_alias(&cx, "https://idp.example", &hash(8), alias, deadline(&cx)).await), ReplayDigestError::VerificationRejected);
        assert_eq!(backend.verifications.load(Ordering::Relaxed), 3);
    });
}

#[test]
fn unknown_generation_and_wrong_purpose_refuse_before_provider_dispatch() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        let backend = FixtureBackend::new(Mode::Honest);
        let lane = lane(ReplayDigestLimits::default());
        let engine = facade(&backend, &lane, 1, &[]);
        let unknown = PersistentReplayAlias::from_persisted(ReplayPurpose::EnterpriseIdentityAssertionReplay, "unconfigured", 99, [0; 32]).unwrap();
        assert_eq!(rejected(engine.verify_identity_assertion_alias(&cx, "https://idp.example", &hash(7), &unknown, deadline(&cx)).await), ReplayDigestError::UnknownGeneration);
        let wrong = PersistentReplayAlias::from_persisted(ReplayPurpose::EnterpriseIdJagJtiReplay, "k1", 1, [0; 32]).unwrap();
        assert_eq!(rejected(engine.verify_identity_assertion_alias(&cx, "https://idp.example", &hash(7), &wrong, deadline(&cx)).await), ReplayDigestError::PurposeMismatch);
        assert_eq!(backend.verifications.load(Ordering::Relaxed), 0);
        assert_eq!(lane.snapshot().unwrap(), ReplayMacSnapshot::default());
    });
}

#[test]
fn nested_and_aggregate_limits_are_checked_before_admission_or_provider_call() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        let backend = FixtureBackend::new(Mode::Honest);
        let limits = ReplayDigestLimits::new(64, 218, 3, 2, 8192, Duration::from_secs(1)).unwrap();
        let lane = lane(limits);
        let engine = facade(&backend, &lane, 1, &[]);
        assert_eq!(rejected(engine.derive_identity_assertion(&cx, "1234567", &hash(1), deadline(&cx)).await), ReplayDigestError::InputTooLarge);
        assert_eq!(rejected(engine.derive_identity_assertion(&cx, "", &hash(1), deadline(&cx)).await), ReplayDigestError::InvalidTuple);
        assert_eq!(rejected(engine.derive_id_jag_jti(&cx, "idp", b"", deadline(&cx)).await), ReplayDigestError::InvalidTuple);
        assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
        assert_eq!(lane.snapshot().unwrap(), ReplayMacSnapshot::default());
        assert!(ReplayDigestLimits::new(64, 217, 3, 2, 8192, Duration::from_secs(1)).is_err());
        assert!(ReplayDigestLimits::new(MAX_CONTEXT_BYTES + 1, MAX_INPUT_BYTES, 3, 2, 8192, Duration::from_secs(1)).is_err());
    });
}

#[test]
fn simultaneous_maximum_fields_fit_the_prechecked_mac_bound() {
    let issuer = "x".repeat(MAX_ISSUER_BYTES);
    let jti = vec![0xa5; MAX_JTI_BYTES];
    let tuple = ReplayTuple::IdJagJti(&issuer, &jti);
    let size = tuple.length(MAX_CONTEXT_BYTES).unwrap();
    let context = tuple.encode(size).unwrap();
    let generation = PersistentMacKeyGeneration::new(&"k".repeat(MAX_KEY_ID_BYTES), u64::MAX).unwrap();
    let exact = size + MAC_FRAMING + MAX_KEY_ID_BYTES;
    assert_eq!(encode_mac(tuple.purpose(), &generation, &context, exact).unwrap().len(), exact);
    assert_eq!(rejected(encode_mac(tuple.purpose(), &generation, &context, exact - 1)), ReplayDigestError::InputTooLarge);
}

#[test]
fn pending_work_holds_shared_capacity_and_drop_releases_it() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        let backend = FixtureBackend::new(Mode::Pending);
        let limits = ReplayDigestLimits::new(64 * 1024, 512 * 1024, 3, 1, 16 * 1024 * 1024, Duration::from_secs(10)).unwrap();
        let lane = lane(limits);
        let first = facade(&backend, &lane, 1, &[]);
        let second = facade(&backend, &lane, 1, &[]);
        let compact = hash(1);
        let mut pending = Box::pin(first.derive_identity_assertion(&cx, "idp", &compact, deadline(&cx)));
        let mut task = Context::from_waker(Waker::noop());
        assert!(pending.as_mut().poll(&mut task).is_pending());
        assert_eq!(lane.snapshot().unwrap().active_operations, 1);
        assert!(lane.snapshot().unwrap().reserved_input_bytes > 0);
        assert_eq!(rejected(second.derive_identity_assertion(&cx, "idp", &compact, deadline(&cx)).await), ReplayDigestError::CapacityExceeded);
        assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
        drop(pending);
        assert_eq!(backend.drops.load(Ordering::Relaxed), 1);
        assert_eq!(lane.snapshot().unwrap(), ReplayMacSnapshot::default());
    });
}

#[derive(Default)]
struct WakeCounter(AtomicUsize);
impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::Relaxed); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::Relaxed); }
}
#[test]
fn cancellation_wakes_a_non_waking_provider_and_discards_its_owner() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        let backend = FixtureBackend::new(Mode::Pending);
        let lane = lane(ReplayDigestLimits::default());
        let engine = facade(&backend, &lane, 1, &[]);
        let compact = hash(1);
        let wake = Arc::new(WakeCounter::default());
        let waker = Waker::from(wake.clone());
        let mut task = Context::from_waker(&waker);
        let mut pending = Box::pin(engine.derive_identity_assertion(&cx, "idp", &compact, deadline(&cx)));
        assert!(pending.as_mut().poll(&mut task).is_pending());
        cx.set_cancel_requested(true);
        assert!(wake.0.load(Ordering::Relaxed) > 0);
        let Poll::Ready(result) = pending.as_mut().poll(&mut task) else { panic!("cancelled provider remained pending"); };
        assert_eq!(rejected(result), ReplayDigestError::Cancelled);
        assert_eq!(backend.drops.load(Ordering::Relaxed), 1);
        assert_eq!(lane.snapshot().unwrap(), ReplayMacSnapshot::default());
    });
}

#[test]
fn a_result_returned_after_mid_poll_cancellation_is_never_published() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        let backend = FixtureBackend::new(Mode::CancelDuringPoll);
        let lane = lane(ReplayDigestLimits::default());
        let engine = facade(&backend, &lane, 2, &[1]);
        assert_eq!(rejected(engine.derive_identity_assertion(&cx, "idp", &hash(1), deadline(&cx)).await), ReplayDigestError::Cancelled);
        assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
        assert_eq!(backend.drops.load(Ordering::Relaxed), 1);
        assert_eq!(lane.snapshot().unwrap(), ReplayMacSnapshot::default());
    });
}

#[test]
fn caller_timer_ends_a_provider_that_never_wakes() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        let backend = FixtureBackend::new(Mode::Pending);
        let lane = lane(ReplayDigestLimits::default());
        let engine = facade(&backend, &lane, 1, &[]);
        let timeout = cx.now().saturating_add_nanos(20_000_000);
        assert_eq!(rejected(engine.derive_identity_assertion(&cx, "idp", &hash(1), timeout).await), ReplayDigestError::DeadlineExceeded);
        assert_eq!(lane.snapshot().unwrap(), ReplayMacSnapshot::default());
    });
}

#[test]
fn provider_construction_poll_and_drop_preserve_explicit_and_ambient_effect_limits() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        let backend = FixtureBackend::new(Mode::Pending);
        let lane = lane(ReplayDigestLimits::default());
        let engine = facade(&backend, &lane, 1, &[]);
        let compact = hash(1);
        let mut pending = Box::pin(engine.derive_identity_assertion(&cx, "idp", &compact, deadline(&cx)));
        let mut task = Context::from_waker(Waker::noop());
        {
            let _restricted = Cx::push_restriction(CapSet::<true, true, true, false, true>::MASK);
            assert!(pending.as_mut().poll(&mut task).is_pending());
        }
        // Drop after the ambient frame has become more permissive. The
        // provider must retain the restriction it received at construction.
        drop(pending);
        let effects = backend.effects.lock().unwrap();
        assert_eq!(effects.iter().map(|effect| effect.stage).collect::<Vec<_>>(), vec!["construct", "poll", "drop"]);
        for effect in effects.iter() { assert!(!effect.ambient_io); assert!(!effect.explicit_io); assert!(effect.task_matches); }
        assert_eq!(lane.snapshot().unwrap(), ReplayMacSnapshot::default());
    });
}

#[test]
fn denied_time_or_entropy_refuses_before_provider_construction() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        let backend = FixtureBackend::new(Mode::Honest);
        let lane = lane(ReplayDigestLimits::default());
        let engine = facade(&backend, &lane, 1, &[]);
        for mask in [CapSet::<true, false, true, true, true>::MASK, CapSet::<true, true, false, true, true>::MASK] {
            let _restricted = Cx::push_restriction(mask);
            assert_eq!(rejected(engine.derive_identity_assertion(&cx, "idp", &hash(1), deadline(&cx)).await), ReplayDigestError::CapabilityUnavailable);
        }
        assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
        assert_eq!(lane.snapshot().unwrap(), ReplayMacSnapshot::default());
    });
}

#[test]
fn provider_panic_drops_owner_and_releases_admission() {
    crate::runtime::block_on(async {
        let cx = Cx::current().unwrap();
        let backend = FixtureBackend::new(Mode::PanicDuringPoll);
        let lane = lane(ReplayDigestLimits::default());
        let engine = facade(&backend, &lane, 1, &[]);
        let compact = hash(1);
        let mut pending = Box::pin(engine.derive_identity_assertion(&cx, "idp", &compact, deadline(&cx)));
        let mut task = Context::from_waker(Waker::noop());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pending.as_mut().poll(&mut task))).is_err());
        drop(pending);
        assert_eq!(backend.drops.load(Ordering::Relaxed), 1);
        assert_eq!(lane.snapshot().unwrap(), ReplayMacSnapshot::default());
    });
}
