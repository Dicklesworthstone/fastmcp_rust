use super::*;
use crate::partition::{DurableOwnerKey, PartitionDescriptor};
use crate::runtime::{ProcessBoundToken, ProcessGeneration};

// Public provider construction is exercised by tests/ephemeral_continuations.rs.
// These private tests target corrupted storage, counters and process/clock state.
fn identity() -> (ContinuationPartitionKey, PartitionAuthorization) {
    let descriptor = PartitionDescriptor::from_verified_facts(
        "provider", 1, "https://issuer.example", "https://mcp.example/mcp",
        "tenant", "subject", "client", 1, 1, &[b"fixture-audience"],
    ).unwrap();
    let key = ContinuationPartitionKey::derive(&descriptor, &["read"], "operation",
        "capabilities", "policy", "domain").unwrap();
    let owner = DurableOwnerKey::derive(&descriptor, 1).unwrap();
    (key, PartitionAuthorization::current(&descriptor, &owner))
}
fn store() -> EphemeralContinuationStore {
    EphemeralContinuationStore::new(&Cx::for_testing(), ProcessGenerationGuard::install().unwrap(),
        SnapshotCloneStance::NoLiveMemoryCloning, "fixture", EnvelopePolicy::default(),
        ContinuationStorePolicy::default()).unwrap()
}
fn put(store: &mut EphemeralContinuationStore, value: &[u8]) -> ContinuationHandle {
    let (key, auth) = identity();
    store.put(&Cx::for_testing(), &key, &auth, &McpRequestCancellation::new(), value, Duration::from_secs(60)).unwrap()
}

#[test]
fn continuation_store_swapped_ciphertexts_cannot_cross_handles_within_one_partition() {
    let cx = Cx::for_testing();
    let (key, auth) = identity();
    let mut store = store();
    let one = put(&mut store, b"first");
    let two = put(&mut store, b"other");
    let original = store.entries[&one.0].envelope.clone();
    let swapped = store.entries[&two.0].envelope.clone();
    store.entries.get_mut(&one.0).unwrap().envelope = swapped;
    assert!(matches!(store.take(&cx, &key, &auth, &one), Err(ContinuationStoreError::Unavailable)));
    assert_eq!(store.len(), 2);
    store.entries.get_mut(&one.0).unwrap().envelope = original;
    assert_eq!(store.take(&cx, &key, &auth, &one).unwrap().as_bytes(), b"first");
    assert_eq!(store.take(&cx, &key, &auth, &two).unwrap().as_bytes(), b"other");
}

#[test]
fn continuation_store_corrupt_ciphertext_is_not_returned_or_consumed() {
    let cx = Cx::for_testing();
    let (key, auth) = identity();
    let mut store = store();
    let handle = put(&mut store, b"private");
    let charged = store.retained_bytes();
    store.entries.get_mut(&handle.0).unwrap().envelope[HEADER_BYTES] ^= 1;
    assert!(matches!(store.take(&cx, &key, &auth, &handle), Err(ContinuationStoreError::Unavailable)));
    assert_eq!(store.retained_bytes(), charged);
    assert_eq!(store.len(), 1);
}

#[test]
fn continuation_store_retains_ciphertext_not_raw_state() {
    let mut store = store();
    let plaintext = b"DISTINCTIVE-PRIVATE-STATE-0123456789";
    let handle = put(&mut store, plaintext);
    let ciphertext = &store.entries[&handle.0].envelope;
    assert!(!ciphertext.windows(plaintext.len()).any(|window| window == plaintext));
    assert!(!format!("{store:?} {handle:?}").contains("DISTINCTIVE"));
}

#[test]
fn continuation_store_expiry_pruning_releases_quota_without_reusing_handles() {
    let cx = Cx::for_testing();
    let (key, auth) = identity();
    let mut store = store();
    let old = put(&mut store, b"old");
    store.protector.started = store.protector.started.checked_sub(Duration::from_secs(61)).unwrap();
    assert!(matches!(store.take(&cx, &key, &auth, &old), Err(ContinuationStoreError::Unavailable)));
    assert_eq!(store.prune(&cx).unwrap(), 1);
    assert_eq!(store.retained_bytes(), 0);
    let current = put(&mut store, b"new");
    assert_eq!(u64::from_be_bytes(old.0[32..].try_into().unwrap()), 1);
    assert_eq!(u64::from_be_bytes(current.0[32..].try_into().unwrap()), 2);
    assert!(matches!(store.take(&cx, &key, &auth, &old), Err(ContinuationStoreError::Unavailable)));
    assert_eq!(store.take(&cx, &key, &auth, &current).unwrap().as_bytes(), b"new");
}

#[test]
fn continuation_store_handle_exhaustion_preserves_pending_state() {
    let cx = Cx::for_testing();
    let (key, auth) = identity();
    let mut store = store();
    let handle = put(&mut store, b"old");
    let charged = store.retained_bytes();
    store.sequence = u64::MAX;
    assert!(matches!(store.put(&cx, &key, &auth, &McpRequestCancellation::new(), b"new", Duration::from_secs(60)),
        Err(ContinuationStoreError::HandleExhausted)));
    assert_eq!(store.sequence, u64::MAX);
    assert_eq!(store.retained_bytes(), charged);
    assert_eq!(store.take(&cx, &key, &auth, &handle).unwrap().as_bytes(), b"old");
}

#[test]
fn continuation_store_failed_seal_burns_handle_sequence_without_retaining_entry() {
    let cx = Cx::for_testing();
    let (key, auth) = identity();
    let mut store = store();
    store.protector.keys.last_mut().unwrap().next_nonce = u64::MAX;
    assert!(matches!(store.put(&cx, &key, &auth, &McpRequestCancellation::new(), b"private", Duration::from_secs(60)),
        Err(ContinuationStoreError::Protection(EnvelopeError::NonceExhausted))));
    assert_eq!(store.sequence, 1);
    assert!(store.is_empty());
    assert_eq!(store.retained_bytes(), 0);
    store.rotate(&cx).unwrap();
    let next = put(&mut store, b"new");
    assert_eq!(u64::from_be_bytes(next.0[32..].try_into().unwrap()), 2);
}

#[test]
fn continuation_store_process_change_rejects_before_lookup_or_retention_changes() {
    let cx = Cx::for_testing();
    let (key, auth) = identity();
    let mut store = store();
    let handle = put(&mut store, b"private");
    let charged = store.retained_bytes();
    let installed = ProcessGenerationGuard::installed().unwrap().generation();
    store.protector.process = ProcessBoundToken { minted_in: ProcessGeneration::observed(
        installed.pid().wrapping_add(1), *installed.nonce(), installed.generation()) };
    assert!(matches!(store.take(&cx, &key, &auth, &handle),
        Err(ContinuationStoreError::Protection(EnvelopeError::ProcessChanged))));
    assert!(store.prune(&cx).is_err());
    assert_eq!(store.len(), 1);
    assert_eq!(store.retained_bytes(), charged);
}

#[test]
fn continuation_store_limits_are_finite() {
    assert!(ContinuationStorePolicy::new(1, 1).is_ok());
    for (entries, bytes) in [(0, 1), (4097, 1), (1, 0), (1, 64 * 1024 * 1024 + 1)] {
        assert!(matches!(ContinuationStorePolicy::new(entries, bytes), Err(ContinuationStoreError::InvalidPolicy)));
    }
}

#[test]
fn continuation_store_put_reclaims_expired_entry_capacity_without_explicit_prune() {
    let cx = Cx::for_testing();
    let (key, auth) = identity();
    let mut store = store();
    store.policy = ContinuationStorePolicy::new(2, 4096).unwrap();
    let expired = put(&mut store, b"expired");
    let live = put(&mut store, b"live");
    // Plant expiry at the inclusive boundary without sleeps or wall-clock races.
    store.entries.get_mut(&expired.0).unwrap().expires_at = 0;
    let replacement = put(&mut store, b"replacement");
    assert_eq!(store.len(), 2);
    assert_eq!(store.sequence, 3);
    assert_eq!(store.retained_bytes(), store.entries.values().map(Entry::charge).sum::<usize>());
    assert!(matches!(store.take(&cx, &key, &auth, &expired), Err(ContinuationStoreError::Unavailable)));
    assert_eq!(store.take(&cx, &key, &auth, &live).unwrap().as_bytes(), b"live");
    assert_eq!(store.take(&cx, &key, &auth, &replacement).unwrap().as_bytes(), b"replacement");
    assert_eq!(store.retained_bytes(), 0);
}

#[test]
fn continuation_store_put_reclaims_cancelled_byte_capacity_without_eviction() {
    let cx = Cx::for_testing();
    let (key, auth) = identity();
    let mut store = store();
    let cancelled = McpRequestCancellation::new();
    let old = store.put(&cx, &key, &auth, &cancelled, b"old", Duration::from_secs(60)).unwrap();
    let live = put(&mut store, b"live");
    // Plenty of entry slots: only the encrypted-byte budget forces reclamation.
    let limit = store.retained_bytes();
    store.policy = ContinuationStorePolicy::new(8, limit).unwrap();
    cancelled.cancel();
    let replacement = put(&mut store, b"new");
    assert_eq!(store.len(), 2);
    assert_eq!(store.retained_bytes(), limit);
    assert_ne!(old.to_wire(), replacement.to_wire());
    assert!(matches!(store.take(&cx, &key, &auth, &old), Err(ContinuationStoreError::Unavailable)));
    assert_eq!(store.take(&cx, &key, &auth, &live).unwrap().as_bytes(), b"live");
    assert_eq!(store.take(&cx, &key, &auth, &replacement).unwrap().as_bytes(), b"new");
    assert_eq!(store.retained_bytes(), 0);
}

#[test]
fn continuation_store_put_rechecks_quota_after_insufficient_reclamation() {
    let cx = Cx::for_testing();
    let (key, auth) = identity();
    let mut store = store();
    let expired = put(&mut store, b"old");
    let live = put(&mut store, b"live");
    let live_charge = store.entries[&live.0].charge();
    store.policy = ContinuationStorePolicy::new(8, store.retained_bytes()).unwrap();
    store.entries.get_mut(&expired.0).unwrap().expires_at = 0;
    // Fits alone, but not alongside the still-live continuation.
    assert!(matches!(store.put(&cx, &key, &auth, &McpRequestCancellation::new(),
        b"larger than old", Duration::from_secs(60)), Err(ContinuationStoreError::Capacity)));
    assert_eq!(store.sequence, 2);
    assert_eq!(store.len(), 1);
    assert_eq!(store.retained_bytes(), live_charge);
    assert_eq!(store.take(&cx, &key, &auth, &live).unwrap().as_bytes(), b"live");
}

#[test]
fn continuation_store_live_capacity_refusal_does_not_burn_identity() {
    let cx = Cx::for_testing();
    let (key, auth) = identity();
    let mut store = store();
    store.policy = ContinuationStorePolicy::new(1, 4096).unwrap();
    let live = put(&mut store, b"live");
    let charged = store.retained_bytes();
    assert!(matches!(store.put(&cx, &key, &auth, &McpRequestCancellation::new(),
        b"new", Duration::from_secs(60)), Err(ContinuationStoreError::Capacity)));
    assert_eq!(store.sequence, 1);
    assert_eq!(store.len(), 1);
    assert_eq!(store.retained_bytes(), charged);
    assert_eq!(store.take(&cx, &key, &auth, &live).unwrap().as_bytes(), b"live");
}

#[test]
fn continuation_store_invalid_put_does_not_reclaim_or_reserve_identity() {
    let cx = Cx::for_testing();
    let (key, auth) = identity();
    let mut store = store();
    store.policy = ContinuationStorePolicy::new(1, 4096).unwrap();
    let expired = put(&mut store, b"expired");
    store.entries.get_mut(&expired.0).unwrap().expires_at = 0;
    let charged = store.retained_bytes();
    assert!(matches!(store.put(&cx, &key, &auth, &McpRequestCancellation::new(), b"new", Duration::ZERO),
        Err(ContinuationStoreError::Protection(EnvelopeError::InvalidLifetime))));
    let cancelled = McpRequestCancellation::new();
    cancelled.cancel();
    assert!(matches!(store.put(&cx, &key, &auth, &cancelled, b"new", Duration::from_secs(60)),
        Err(ContinuationStoreError::Unavailable)));
    assert_eq!(store.sequence, 1);
    assert_eq!(store.len(), 1);
    assert_eq!(store.retained_bytes(), charged);
}
