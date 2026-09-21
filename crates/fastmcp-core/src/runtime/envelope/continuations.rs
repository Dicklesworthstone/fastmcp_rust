//! Encrypted, one-use continuation custody for one live process.
//!
//! A wire handle is neither authorization nor ciphertext. Retrieval requires
//! the original continuation partition and current matching authorization.
//! Successful take retires the entry before returning zeroizing plaintext.
//! Restart loses all entries; this is not durable MRTR or remote exactly-once.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use asupersync::Cx;
use crate::McpRequestCancellation;
use crate::crypto::{draw_security_identifier, sha256_bounded};
use crate::partition::{ContinuationPartitionKey, PartitionAuthorization};
use super::{
    EnvelopeBinding, EnvelopeError, EnvelopePolicy, EnvelopePurpose,
    EphemeralEnvelopeProtector, OpenedState, ProcessGenerationGuard, SnapshotCloneStance,
    HEADER_BYTES, TAG_BYTES,
};

const HANDLE_BYTES: usize = 40;
const ENTRY_IDENTITY_BYTES: usize = HANDLE_BYTES + 32 + 8;

/// An opaque 80-character lowercase-hex wire handle. Parsing checks only its
/// representation, not existence or permission. Copies made through the wire
/// representation still share the same single-use entry.
pub struct ContinuationHandle([u8; HANDLE_BYTES]);
impl ContinuationHandle {
    pub fn from_wire(wire: &str) -> Result<Self, ContinuationStoreError> {
        if wire.len() != HANDLE_BYTES * 2 { return Err(ContinuationStoreError::Unavailable); }
        fn digit(byte: u8) -> Result<u8, ContinuationStoreError> {
            match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err(ContinuationStoreError::Unavailable),
            }
        }
        let mut bytes = [0; HANDLE_BYTES];
        // `as_chunks` yields `[u8; 2]` rather than a slice, so the pair indexing
        // below is checked at compile time. The length test above makes the
        // remainder provably empty, so nothing is discarded that was not before.
        for (output, pair) in bytes.iter_mut().zip(wire.as_bytes().as_chunks::<2>().0) {
            *output = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        Ok(Self(bytes))
    }

    /// Explicit wire disclosure for a framework-owned requestState field.
    /// Do not log this value or use it as a principal identity.
    pub fn to_wire(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut wire = String::with_capacity(HANDLE_BYTES * 2);
        for byte in self.0 {
            wire.push(char::from(HEX[usize::from(byte >> 4)]));
            wire.push(char::from(HEX[usize::from(byte & 15)]));
        }
        wire
    }
}
impl fmt::Debug for ContinuationHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("ContinuationHandle(<redacted>)") }
}

/// Limits encrypted bytes plus retained identity fields. Collection and
/// cancellation-handle overhead is bounded separately by the entry count.
#[derive(Clone, Copy, Debug)]
pub struct ContinuationStorePolicy { maximum_entries: usize, maximum_bytes: usize }
impl Default for ContinuationStorePolicy {
    fn default() -> Self { Self { maximum_entries: 1024, maximum_bytes: 8 * 1024 * 1024 } }
}
impl ContinuationStorePolicy {
    pub fn new(maximum_entries: usize, maximum_bytes: usize) -> Result<Self, ContinuationStoreError> {
        if !(1..=4096).contains(&maximum_entries)
            || !(1..=64 * 1024 * 1024).contains(&maximum_bytes)
        { return Err(ContinuationStoreError::InvalidPolicy); }
        Ok(Self { maximum_entries, maximum_bytes })
    }
}

/// Missing, replayed, wrong-owner, expired and damaged entries share one error
/// class. This is not a constant-time lookup guarantee. Local policy/lifecycle
/// errors remain distinct; no variant retains a handle or plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuationStoreError {
    InvalidPolicy, Capacity, HandleExhausted, Unavailable, Protection(EnvelopeError),
}
impl From<EnvelopeError> for ContinuationStoreError {
    fn from(error: EnvelopeError) -> Self {
        match error {
            EnvelopeError::InvalidEnvelope => Self::Unavailable,
            error => Self::Protection(error),
        }
    }
}
impl fmt::Display for ContinuationStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => f.write_str("invalid continuation store policy"),
            Self::Capacity => f.write_str("continuation store capacity exhausted"),
            Self::HandleExhausted => f.write_str("continuation handle sequence exhausted"),
            Self::Unavailable => f.write_str("continuation is unavailable"),
            Self::Protection(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for ContinuationStoreError {}

struct Entry {
    binding: [u8; 32],
    envelope: Vec<u8>,
    expires_at: u64,
    owner: McpRequestCancellation,
}
impl Entry {
    fn charge(&self) -> usize { self.envelope.len() + ENTRY_IDENTITY_BYTES }
}

/// A concrete consumer of the ephemeral envelope protector. No plaintext or
/// externally usable envelope is retained/exposed by this store. The caller
/// serializes shared access using its own owned mutex; exclusive Rust borrowing
/// makes take atomic without a private runtime, worker or blocking lock.
///
/// Authorization must be freshly supplied by the embedding application's
/// authenticated ingress on EVERY operation. Key derivation must include the
/// original method/arguments/capability policy; handles cannot supply it.
pub struct EphemeralContinuationStore {
    protector: EphemeralEnvelopeProtector,
    namespace: String,
    policy: ContinuationStorePolicy,
    entries: BTreeMap<[u8; HANDLE_BYTES], Entry>,
    retained_bytes: usize,
    sequence: u64,
}
impl EphemeralContinuationStore {
    pub fn new(
        cx: &Cx, guard: &ProcessGenerationGuard, stance: SnapshotCloneStance,
        namespace: &str, protection: EnvelopePolicy, policy: ContinuationStorePolicy,
    ) -> Result<Self, ContinuationStoreError> {
        if namespace.is_empty() || namespace.len() > 128
            || !namespace.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
        { return Err(EnvelopeError::InvalidBinding.into()); }
        Ok(Self {
            protector: EphemeralEnvelopeProtector::new(cx, guard, stance, EnvelopePurpose::Continuation, protection)?,
            namespace: namespace.to_owned(), policy, entries: BTreeMap::new(), retained_bytes: 0, sequence: 0,
        })
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn retained_bytes(&self) -> usize { self.retained_bytes }

    /// Retains encrypted state without evicting any live entry. On capacity
    /// pressure, expired and explicitly cancelled entries are reclaimed before
    /// refusing new work; no background cleanup worker is required for progress.
    /// A unique non-wrapping sequence is combined with 256 OS-random bits,
    /// preventing handle reuse even after entries are consumed/pruned.
    /// Failed sealing burns its reserved sequence; no partial entry is stored.
    /// `owner` is the application's continuation lifetime, not necessarily the
    /// one POST that produced an input-required result.
    pub fn put(
        &mut self, cx: &Cx, key: &ContinuationPartitionKey, authorization: &PartitionAuthorization,
        owner: &McpRequestCancellation, plaintext: &[u8], lifetime: Duration,
    ) -> Result<ContinuationHandle, ContinuationStoreError> {
        self.protector.check(cx)?;
        if owner.is_cancel_requested() { return Err(ContinuationStoreError::Unavailable); }
        let binding = EnvelopeBinding::continuation(key, authorization, &self.namespace)?;
        if plaintext.len() > self.protector.policy.plaintext_limit { return Err(EnvelopeError::TooLarge.into()); }
        if lifetime.is_zero() || lifetime > self.protector.policy.lifetime_bound {
            return Err(EnvelopeError::InvalidLifetime.into());
        }
        let charge = HEADER_BYTES + TAG_BYTES + plaintext.len() + ENTRY_IDENTITY_BYTES;
        // A single impossible entry must not trigger cleanup or reserve an ID.
        // Admission/authentication above also precede every retention mutation.
        if charge > self.policy.maximum_bytes { return Err(ContinuationStoreError::Capacity); }
        if self.entries.len() >= self.policy.maximum_entries
            || self.retained_bytes.checked_add(charge)
                .is_none_or(|total| total > self.policy.maximum_bytes)
        {
            // Only the pressure path scans the bounded collection. Recheck both
            // quotas afterwards: pruning is not permission to evict live work.
            self.prune(cx)?;
        }
        let retained = self.retained_bytes.checked_add(charge)
            .filter(|total| *total <= self.policy.maximum_bytes).ok_or(ContinuationStoreError::Capacity)?;
        if self.entries.len() >= self.policy.maximum_entries { return Err(ContinuationStoreError::Capacity); }
        let sequence = self.sequence.checked_add(1).ok_or(ContinuationStoreError::HandleExhausted)?;
        let expires_at = self.protector.elapsed()?.checked_add(
            u64::try_from(lifetime.as_nanos()).map_err(|_| EnvelopeError::InvalidLifetime)?)
            .ok_or(EnvelopeError::InvalidLifetime)?;
        let random = draw_security_identifier().map_err(|_| EnvelopeError::EntropyUnavailable)?;
        let mut handle = ContinuationHandle([0; HANDLE_BYTES]);
        handle.0[..32].copy_from_slice(random.as_bytes());
        handle.0[32..].copy_from_slice(&sequence.to_be_bytes());
        if self.entries.contains_key(&handle.0) { return Err(ContinuationStoreError::HandleExhausted); }
        self.sequence = sequence;
        let sealed_binding = bind_handle(binding, &handle)?;
        let envelope = self.protector.seal(cx, &sealed_binding, plaintext, lifetime)?;
        self.protector.check(cx)?;
        if owner.is_cancel_requested() || self.protector.elapsed()? >= expires_at {
            return Err(ContinuationStoreError::Unavailable);
        }
        debug_assert_eq!(envelope.len() + ENTRY_IDENTITY_BYTES, charge);
        self.entries.insert(handle.0, Entry { binding: binding.digest, envelope, expires_at, owner: owner.clone() });
        self.retained_bytes = retained;
        Ok(handle)
    }

    /// Decrypts, checks the live owner and retires the exact entry before
    /// returning plaintext. Wrong authorization cannot consume or invalidate
    /// the legitimate owner's entry. No fallible work follows consumption.
    /// A later application failure does NOT make the handle reusable.
    pub fn take(
        &mut self, cx: &Cx, key: &ContinuationPartitionKey,
        authorization: &PartitionAuthorization, handle: &ContinuationHandle,
    ) -> Result<OpenedState, ContinuationStoreError> {
        self.protector.check(cx)?;
        let binding = EnvelopeBinding::continuation(key, authorization, &self.namespace)?;
        let entry = self.entries.get(&handle.0).ok_or(ContinuationStoreError::Unavailable)?;
        if entry.binding != binding.digest || entry.owner.is_cancel_requested()
            || self.protector.elapsed()? >= entry.expires_at
        { return Err(ContinuationStoreError::Unavailable); }
        let opened = self.protector.open(cx, &bind_handle(binding, handle)?, &entry.envelope)?;
        self.protector.check(cx)?;
        if entry.owner.is_cancel_requested() || self.protector.elapsed()? >= entry.expires_at {
            return Err(ContinuationStoreError::Unavailable);
        }
        let retired = self.entries.remove(&handle.0).ok_or(ContinuationStoreError::Unavailable)?;
        self.retained_bytes -= retired.charge();
        Ok(opened)
    }

    /// Reclaims only expired or explicitly cancelled entries, without decrypting
    /// them or evicting live work. The caller may drive eager cleanup; `put`
    /// also invokes this on capacity pressure. No timer or worker is spawned.
    pub fn prune(&mut self, cx: &Cx) -> Result<usize, ContinuationStoreError> {
        self.protector.check(cx)?;
        let now = self.protector.elapsed()?;
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            let keep = entry.expires_at > now && !entry.owner.is_cancel_requested();
            if !keep { self.retained_bytes -= entry.charge(); }
            keep
        });
        Ok(before - self.entries.len())
    }

    /// Rotates protection without changing or consuming pending handles.
    pub fn rotate(&mut self, cx: &Cx) -> Result<u64, ContinuationStoreError> {
        Ok(self.protector.rotate(cx)?)
    }

    /// Irreversible closure destroys keys and retained ciphertext. It does not
    /// cancel any caller-owned cancellation domain or sibling store.
    pub fn close(&mut self) {
        self.protector.close();
        self.entries.clear();
        self.retained_bytes = 0;
    }
}
impl fmt::Debug for EphemeralContinuationStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralContinuationStore").field("entries", &self.entries.len())
            .field("retained_bytes", &self.retained_bytes).finish_non_exhaustive()
    }
}

fn bind_handle(binding: EnvelopeBinding, handle: &ContinuationHandle) -> Result<EnvelopeBinding, EnvelopeError> {
    let mut input = Vec::with_capacity(128);
    input.extend_from_slice(b"fastmcp/continuation-handle/v1\0");
    input.extend_from_slice(&binding.digest);
    input.extend_from_slice(&handle.0);
    Ok(EnvelopeBinding { purpose: EnvelopePurpose::Continuation,
        digest: sha256_bounded(&input, 128).map_err(|_| EnvelopeError::InvalidBinding)?.into_bytes() })
}

#[cfg(test)]
mod tests;
