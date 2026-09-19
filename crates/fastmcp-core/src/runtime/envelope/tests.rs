use super::*;
use crate::runtime::{ExternalEpoch, ProcessGeneration};

fn context() -> Cx { Cx::for_testing() }
fn binding(value: u8) -> EnvelopeBinding {
    EnvelopeBinding { purpose: EnvelopePurpose::Continuation, digest: [value; 32] }
}
fn owner(policy: EnvelopePolicy) -> EphemeralEnvelopeProtector {
    EphemeralEnvelopeProtector::new(&context(), ProcessGenerationGuard::install().unwrap(),
        SnapshotCloneStance::NoLiveMemoryCloning, EnvelopePurpose::Continuation, policy).unwrap()
}
fn ttl() -> Duration { Duration::from_secs(60) }

#[test]
fn ephemeral_envelope_round_trip_includes_binary_and_empty_payloads() {
    let cx = context();
    let mut owner = owner(EnvelopePolicy::default());
    for payload in [b"".as_slice(), b"private credential material".as_slice(), &[0, 1, 255, 0, 128]] {
        let sealed = owner.seal(&cx, &binding(1), payload, ttl()).unwrap();
        let opened = owner.open(&cx, &binding(1), &sealed).unwrap();
        assert_eq!(opened.as_bytes(), payload);
        assert_eq!(sealed.len(), HEADER_BYTES + payload.len() + TAG_BYTES);
    }
}

#[test]
fn ephemeral_envelope_tampered_header_ciphertext_or_tag_never_opens() {
    let cx = context();
    let mut owner = owner(EnvelopePolicy::default());
    let sealed = owner.seal(&cx, &binding(1), b"confidential", ttl()).unwrap();
    for index in 0..sealed.len() {
        let mut changed = sealed.clone();
        changed[index] ^= 1;
        assert!(matches!(owner.open(&cx, &binding(1), &changed), Err(EnvelopeError::InvalidEnvelope)),
            "changed byte {index} must not authenticate");
    }
    assert_eq!(owner.open(&cx, &binding(1), &sealed).unwrap().as_bytes(), b"confidential");
}

#[test]
fn ephemeral_envelope_rejects_truncation_extension_and_forged_lengths() {
    let cx = context();
    let mut owner = owner(EnvelopePolicy::default());
    let sealed = owner.seal(&cx, &binding(1), b"private", ttl()).unwrap();
    for end in 0..sealed.len() { assert!(owner.open(&cx, &binding(1), &sealed[..end]).is_err()); }
    let mut changed = sealed.clone();
    changed.push(0);
    assert!(owner.open(&cx, &binding(1), &changed).is_err());
    let mut changed = sealed;
    changed[66..70].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(owner.open(&cx, &binding(1), &changed).is_err());
}

#[test]
fn ephemeral_envelope_owner_purpose_and_authorization_binding_are_separate() {
    let cx = context();
    let mut one = owner(EnvelopePolicy::default());
    let two = owner(EnvelopePolicy::default());
    let sealed = one.seal(&cx, &binding(1), b"private", ttl()).unwrap();
    assert!(two.open(&cx, &binding(1), &sealed).is_err());
    assert!(one.open(&cx, &binding(2), &sealed).is_err());
    let other_purpose = EnvelopeBinding { purpose: EnvelopePurpose::Credential, digest: [1; 32] };
    assert!(one.open(&cx, &other_purpose, &sealed).is_err());
    assert!(matches!(one.seal(&cx, &other_purpose, b"private", ttl()), Err(EnvelopeError::InvalidBinding)));
    assert_eq!(one.open(&cx, &binding(1), &sealed).unwrap().as_bytes(), b"private");
}

#[test]
fn ephemeral_envelope_nonce_allocation_is_unique_and_never_wraps() {
    let cx = context();
    let mut owner = owner(EnvelopePolicy::default());
    let a = owner.seal(&cx, &binding(1), b"same", ttl()).unwrap();
    let b = owner.seal(&cx, &binding(1), b"same", ttl()).unwrap();
    assert_eq!(u64::from_be_bytes(a[50..58].try_into().unwrap()), 0);
    assert_eq!(u64::from_be_bytes(b[50..58].try_into().unwrap()), 1);
    assert_ne!(a[HEADER_BYTES..], b[HEADER_BYTES..]);
    owner.keys.last_mut().unwrap().next_nonce = u64::MAX;
    assert!(matches!(owner.seal(&cx, &binding(1), b"next", ttl()), Err(EnvelopeError::NonceExhausted)));
    assert_eq!(owner.keys.last().unwrap().next_nonce, u64::MAX);
    assert_eq!(owner.open(&cx, &binding(1), &a).unwrap().as_bytes(), b"same");
}

#[test]
fn ephemeral_envelope_rotates_without_invalidating_live_previous_generations() {
    let cx = context();
    let mut owner = owner(EnvelopePolicy::new(64, ttl(), 2).unwrap());
    let previous = owner.seal(&cx, &binding(1), b"old", ttl()).unwrap();
    assert_eq!(owner.rotate(&cx).unwrap(), 2);
    let current = owner.seal(&cx, &binding(1), b"new", ttl()).unwrap();
    assert_eq!(owner.open(&cx, &binding(1), &previous).unwrap().as_bytes(), b"old");
    assert_eq!(owner.open(&cx, &binding(1), &current).unwrap().as_bytes(), b"new");
    assert!(matches!(owner.rotate(&cx), Err(EnvelopeError::KeyCapacity)));
    assert_eq!(owner.generation(), 2);
    assert_eq!(owner.keys.len(), 2);
    assert_eq!(owner.open(&cx, &binding(1), &previous).unwrap().as_bytes(), b"old");
}

#[test]
fn ephemeral_envelope_expired_generations_can_be_retired_without_sleeping() {
    let cx = context();
    let mut owner = owner(EnvelopePolicy::new(64, ttl(), 1).unwrap());
    let previous = owner.seal(&cx, &binding(1), b"old", ttl()).unwrap();
    // The same monotonic age check as production, with only its origin moved
    // for this unit scenario. No wall-clock or sleep-based expiry oracle.
    owner.started = owner.started.checked_sub(Duration::from_secs(61)).unwrap();
    assert!(matches!(owner.open(&cx, &binding(1), &previous), Err(EnvelopeError::InvalidEnvelope)));
    assert_eq!(owner.rotate(&cx).unwrap(), 2);
    assert_eq!(owner.keys.len(), 1);
    let current = owner.seal(&cx, &binding(1), b"new", ttl()).unwrap();
    assert_eq!(owner.open(&cx, &binding(1), &current).unwrap().as_bytes(), b"new");
}

#[test]
fn ephemeral_envelope_rejected_input_does_not_consume_a_nonce_or_mutate_keys() {
    let cx = context();
    let mut owner = owner(EnvelopePolicy::new(4, ttl(), 2).unwrap());
    assert!(matches!(owner.seal(&cx, &binding(1), b"large", ttl()), Err(EnvelopeError::TooLarge)));
    assert!(matches!(owner.seal(&cx, &binding(1), b"four", Duration::ZERO), Err(EnvelopeError::InvalidLifetime)));
    assert!(matches!(owner.seal(&cx, &binding(1), b"four", ttl() + Duration::from_secs(1)), Err(EnvelopeError::InvalidLifetime)));
    assert_eq!(owner.keys[0].next_nonce, 0);
    assert_eq!(owner.keys[0].latest_expiry, 0);
    let exact = owner.seal(&cx, &binding(1), b"four", ttl()).unwrap();
    assert_eq!(owner.open(&cx, &binding(1), &exact).unwrap().as_bytes(), b"four");
}

#[test]
fn ephemeral_envelope_generation_exhaustion_keeps_existing_material() {
    let cx = context();
    let mut owner = owner(EnvelopePolicy::default());
    let sealed = owner.seal(&cx, &binding(1), b"private", ttl()).unwrap();
    owner.generation = u64::MAX;
    assert!(matches!(owner.rotate(&cx), Err(EnvelopeError::GenerationExhausted)));
    assert_eq!(owner.keys.len(), 1);
    assert_eq!(owner.open(&cx, &binding(1), &sealed).unwrap().as_bytes(), b"private");
}

#[test]
fn ephemeral_envelope_close_is_terminal_and_retires_keys() {
    let cx = context();
    let mut owner = owner(EnvelopePolicy::default());
    let sealed = owner.seal(&cx, &binding(1), b"private", ttl()).unwrap();
    owner.close();
    assert!(owner.keys.is_empty());
    assert!(matches!(owner.open(&cx, &binding(1), &sealed), Err(EnvelopeError::Closed)));
    assert!(matches!(owner.seal(&cx, &binding(1), b"private", ttl()), Err(EnvelopeError::Closed)));
    assert!(matches!(owner.rotate(&cx), Err(EnvelopeError::Closed)));
}

#[test]
fn ephemeral_envelope_process_change_precedes_nonce_or_key_access() {
    let cx = context();
    let mut owner = owner(EnvelopePolicy::default());
    let installed = ProcessGenerationGuard::installed().unwrap().generation();
    owner.process = ProcessBoundToken { minted_in: ProcessGeneration::observed(
        installed.pid().wrapping_add(1), *installed.nonce(), installed.generation()) };
    assert!(matches!(owner.seal(&cx, &binding(1), b"private", ttl()), Err(EnvelopeError::ProcessChanged)));
    assert_eq!(owner.keys[0].next_nonce, 0);
    assert!(matches!(owner.rotate(&cx), Err(EnvelopeError::ProcessChanged)));
    assert_eq!(owner.generation(), 1);
}

#[test]
fn ephemeral_envelope_cannot_claim_external_epoch_or_live_clone_support() {
    let cx = context();
    let guard = ProcessGenerationGuard::install().unwrap();
    for external_epoch in [None, Some(ExternalEpoch::new(true, true))] {
        for ephemeral_protected_state_disabled in [false, true] {
            let result = EphemeralEnvelopeProtector::new(&cx, guard,
                SnapshotCloneStance::LiveMemoryCloningPermitted { ephemeral_protected_state_disabled, external_epoch },
                EnvelopePurpose::Continuation, EnvelopePolicy::default());
            assert!(matches!(result, Err(EnvelopeError::CloningUnsupported)));
        }
    }
}

#[test]
fn ephemeral_envelope_policy_has_finite_hard_ceilings() {
    assert!(EnvelopePolicy::new(1, Duration::from_secs(1), 1).is_ok());
    for (bytes, lifetime, keys) in [(0, ttl(), 1), (MAX_PLAINTEXT+1, ttl(), 1),
        (1, Duration::ZERO, 1), (1, MAX_LIFETIME+Duration::from_secs(1), 1),
        (1, ttl(), 0), (1, ttl(), 9)] {
        assert!(matches!(EnvelopePolicy::new(bytes, lifetime, keys), Err(EnvelopeError::InvalidPolicy)));
    }
}

#[test]
fn ephemeral_envelope_diagnostics_contain_no_secret_or_binding_bytes() {
    let owner = owner(EnvelopePolicy::default());
    let diagnostics = format!("{owner:?} {:?} {}", binding(7), EnvelopeError::InvalidEnvelope);
    assert!(!diagnostics.contains("private"));
    assert!(!diagnostics.contains("[7, 7"));
    assert!(!diagnostics.contains("nonce"));
}
