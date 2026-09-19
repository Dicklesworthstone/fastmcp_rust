//! Bounded authenticated encryption for process-owned protected state.
//!
//! Keys never leave this owner. Nonces are an OS-generated 128-bit domain
//! followed by a non-wrapping counter, with independent material for each key
//! generation. There is no caller-selected key, nonce, algorithm or RNG.
//!
//! This is deliberately **ephemeral**. It cannot reopen after restart and must
//! not be used as a durable credential-store protector. Forked owners fail
//! before touching key state. Live-memory cloning is unsupported; a declaration
//! that an external epoch exists is not an implemented epoch check here.

/// Encrypted, one-use, authorization-bound continuation custody.
pub mod continuations;

use std::fmt;
use std::time::{Duration, Instant};

use asupersync::Cx;
use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::{AeadInOut, KeyInit}};
use zeroize::Zeroizing;

use crate::crypto::{
    EphemeralKeyMaterial, NonceDomainMaterial, draw_ephemeral_key_material,
    draw_nonce_domain_material, draw_security_identifier, sha256_bounded,
};
use crate::partition::{ContinuationPartitionKey, CredentialStoreKey, PartitionAuthorization};
use super::{ProcessBoundToken, ProcessGenerationGuard, SnapshotCloneStance};

const MAGIC: &[u8; 8] = b"FCPEPH01";
const HEADER_BYTES: usize = 102;
const TAG_BYTES: usize = 16;
const MAX_PLAINTEXT: usize = 1024 * 1024;
const MAX_LIFETIME: Duration = Duration::from_secs(3600);

/// Fixed, domain-separated owner purpose. Selecting a purpose does not confer
/// authentication or permission to act on a principal's behalf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EnvelopePurpose { Continuation = 1, Credential = 2 }

/// Binding derived from the caller's verified partition authorization. These
/// digests are identities, not independent authorization grants. Callers must
/// obtain current authorization from their normal authenticated ingress.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EnvelopeBinding { purpose: EnvelopePurpose, digest: [u8; 32] }
impl EnvelopeBinding {
    pub fn continuation(
        key: &ContinuationPartitionKey, authorization: &PartitionAuthorization,
        namespace: &str,
    ) -> Result<Self, EnvelopeError> {
        Self::derive(EnvelopePurpose::Continuation, key.as_bytes(), authorization, namespace, 0)
    }

    /// Binds both the store identity and exact credential generation. The
    /// ephemeral protector still cannot grant persistent key/nonce custody.
    pub fn credential(
        key: &CredentialStoreKey, authorization: &PartitionAuthorization,
        namespace: &str, generation: u64,
    ) -> Result<Self, EnvelopeError> {
        if generation == 0 { return Err(EnvelopeError::InvalidBinding); }
        Self::derive(EnvelopePurpose::Credential, key.as_bytes(), authorization, namespace, generation)
    }

    fn derive(
        purpose: EnvelopePurpose, key: &[u8; 32], authorization: &PartitionAuthorization,
        namespace: &str, generation: u64,
    ) -> Result<Self, EnvelopeError> {
        if namespace.is_empty() || namespace.len() > 128
            || !namespace.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
        { return Err(EnvelopeError::InvalidBinding); }
        let mut aad = Vec::with_capacity(256);
        aad.extend_from_slice(b"fastmcp/ephemeral-binding/v1\0");
        aad.push(purpose as u8);
        aad.extend_from_slice(&(namespace.len() as u16).to_be_bytes());
        aad.extend_from_slice(namespace.as_bytes());
        aad.extend_from_slice(key);
        aad.extend_from_slice(authorization.as_bytes());
        aad.extend_from_slice(&generation.to_be_bytes());
        let digest = sha256_bounded(&aad, 256).map_err(|_| EnvelopeError::InvalidBinding)?.into_bytes();
        Ok(Self { purpose, digest })
    }
}
impl fmt::Debug for EnvelopeBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvelopeBinding").field("purpose", &self.purpose).finish_non_exhaustive()
    }
}

/// Every accepted plaintext and its ciphertext has a finite allocation bound.
/// Retained generations are bounded independently; rotation cannot evict a key
/// that still protects live state merely to make room for a new key.
#[derive(Clone, Copy, Debug)]
pub struct EnvelopePolicy { maximum_plaintext: usize, maximum_lifetime: Duration, maximum_keys: usize }
impl Default for EnvelopePolicy {
    fn default() -> Self {
        Self { maximum_plaintext: 64 * 1024, maximum_lifetime: Duration::from_secs(900), maximum_keys: 4 }
    }
}
impl EnvelopePolicy {
    pub fn new(maximum_plaintext: usize, maximum_lifetime: Duration, maximum_keys: usize) -> Result<Self, EnvelopeError> {
        if maximum_plaintext == 0 || maximum_plaintext > MAX_PLAINTEXT
            || maximum_lifetime.is_zero() || maximum_lifetime > MAX_LIFETIME
            || !(1..=8).contains(&maximum_keys)
        { return Err(EnvelopeError::InvalidPolicy); }
        Ok(Self { maximum_plaintext, maximum_lifetime, maximum_keys })
    }
}

/// Uniform envelope refusal does not expose key selectors, plaintext, binding
/// bytes, or peer-supplied diagnostics. Local lifecycle failures are separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    InvalidPolicy, InvalidBinding, TooLarge, InvalidLifetime, InvalidEnvelope,
    Cancelled, Deadline, ProcessChanged, CloningUnsupported, EntropyUnavailable,
    NonceExhausted, GenerationExhausted, KeyCapacity, Closed,
}
impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid ephemeral envelope policy",
            Self::InvalidBinding => "invalid protected-state binding",
            Self::TooLarge => "protected state exceeds its byte limit",
            Self::InvalidLifetime => "invalid protected-state lifetime",
            Self::InvalidEnvelope => "protected state is unavailable or invalid",
            Self::Cancelled => "protected-state operation cancelled",
            Self::Deadline => "protected-state operation deadline exceeded",
            Self::ProcessChanged => "protected-state process generation changed",
            Self::CloningUnsupported => "ephemeral protected state does not support live-memory cloning",
            Self::EntropyUnavailable => "protected-state entropy unavailable",
            Self::NonceExhausted => "protected-state nonce sequence exhausted",
            Self::GenerationExhausted => "protected-state key generations exhausted",
            Self::KeyCapacity => "live protected-state key capacity exhausted",
            Self::Closed => "protected-state owner is closed",
        })
    }
}
impl std::error::Error for EnvelopeError {}

/// Authenticated plaintext in zeroizing custody. No Clone, serialization,
/// Debug, or non-zeroizing ownership conversion is exposed.
pub struct OpenedState(Zeroizing<Vec<u8>>);
impl OpenedState { pub fn as_bytes(&self) -> &[u8] { &self.0 } }

struct Generation {
    id: u64,
    key: EphemeralKeyMaterial,
    domain: NonceDomainMaterial,
    next_nonce: u64,
    latest_expiry: u64,
}
impl Generation {
    fn fresh(id: u64) -> Result<Self, EnvelopeError> {
        Ok(Self { id,
            key: draw_ephemeral_key_material().map_err(|_| EnvelopeError::EntropyUnavailable)?,
            domain: draw_nonce_domain_material().map_err(|_| EnvelopeError::EntropyUnavailable)?,
            next_nonce: 0, latest_expiry: 0 })
    }
    fn nonce(&self, counter: u64) -> [u8; 24] {
        let mut nonce = [0; 24];
        nonce[..16].copy_from_slice(self.domain.as_bytes());
        nonce[16..].copy_from_slice(&counter.to_be_bytes());
        nonce
    }
}

/// Process-owned XChaCha20-Poly1305 protector. Exclusive seal/rotate access
/// serializes nonce allocation without a hidden worker, lock, or async runtime.
/// Independent owners cannot open each other's envelopes, even for one binding.
/// All lifetimes use this owner's monotonic clock rather than peer wall time.
pub struct EphemeralEnvelopeProtector {
    process: ProcessBoundToken,
    purpose: EnvelopePurpose,
    policy: EnvelopePolicy,
    identity: [u8; 32],
    started: Instant,
    keys: Vec<Generation>,
    generation: u64,
    closed: bool,
}
impl EphemeralEnvelopeProtector {
    /// The application installs its process guard before constructing owners.
    /// No declared external-epoch boolean can enable cloning on this provider.
    pub fn new(
        cx: &Cx, guard: &ProcessGenerationGuard, stance: SnapshotCloneStance,
        purpose: EnvelopePurpose, policy: EnvelopePolicy,
    ) -> Result<Self, EnvelopeError> {
        checkpoint(cx)?;
        guard.verify_current().map_err(|_| EnvelopeError::ProcessChanged)?;
        if !matches!(stance, SnapshotCloneStance::NoLiveMemoryCloning) {
            return Err(EnvelopeError::CloningUnsupported);
        }
        let identity = *draw_security_identifier().map_err(|_| EnvelopeError::EntropyUnavailable)?.as_bytes();
        let first = Generation::fresh(1)?;
        checkpoint(cx)?;
        guard.verify_current().map_err(|_| EnvelopeError::ProcessChanged)?;
        Ok(Self { process: guard.token(), purpose, policy, identity, started: Instant::now(),
            keys: vec![first], generation: 1, closed: false })
    }

    pub fn maximum_plaintext_bytes(&self) -> usize { self.policy.maximum_plaintext }
    pub fn maximum_envelope_bytes(&self) -> usize { HEADER_BYTES + self.policy.maximum_plaintext + TAG_BYTES }
    pub fn generation(&self) -> u64 { self.generation }

    /// Irreversible local revocation. All retained keys are zeroized on drop;
    /// ciphertext held by callers becomes unusable through this owner.
    pub fn close(&mut self) { self.closed = true; self.keys.clear(); }

    /// Installs independent key/domain material, retaining every unexpired old
    /// generation. Failed admission/entropy does not evict existing keys.
    pub fn rotate(&mut self, cx: &Cx) -> Result<u64, EnvelopeError> {
        self.check(cx)?;
        let now = self.elapsed()?;
        if self.keys.iter().filter(|key| key.latest_expiry > now).count() >= self.policy.maximum_keys {
            return Err(EnvelopeError::KeyCapacity);
        }
        let next = self.generation.checked_add(1).ok_or(EnvelopeError::GenerationExhausted)?;
        let fresh = Generation::fresh(next)?;
        self.check(cx)?;
        self.keys.retain(|key| key.latest_expiry > now);
        self.keys.push(fresh);
        self.generation = next;
        Ok(next)
    }

    /// Seals once. A reserved nonce remains consumed on encryption failure or
    /// late cancellation; neither failure permits reusing its counter.
    pub fn seal(&mut self, cx: &Cx, binding: &EnvelopeBinding, plaintext: &[u8], lifetime: Duration)
        -> Result<Vec<u8>, EnvelopeError>
    {
        self.check(cx)?;
        if binding.purpose != self.purpose { return Err(EnvelopeError::InvalidBinding); }
        if plaintext.len() > self.policy.maximum_plaintext { return Err(EnvelopeError::TooLarge); }
        if lifetime.is_zero() || lifetime > self.policy.maximum_lifetime { return Err(EnvelopeError::InvalidLifetime); }
        let expiry = self.elapsed()?.checked_add(u64::try_from(lifetime.as_nanos()).map_err(|_| EnvelopeError::InvalidLifetime)?)
            .ok_or(EnvelopeError::InvalidLifetime)?;
        let key = self.keys.last_mut().ok_or(EnvelopeError::Closed)?;
        let counter = key.next_nonce;
        key.next_nonce = counter.checked_add(1).ok_or(EnvelopeError::NonceExhausted)?;
        key.latest_expiry = key.latest_expiry.max(expiry);
        let mut header = Vec::with_capacity(HEADER_BYTES);
        header.extend_from_slice(MAGIC);
        header.push(1); // fixed format, not an algorithm-negotiation field
        header.push(self.purpose as u8);
        header.extend_from_slice(&self.identity);
        header.extend_from_slice(&key.id.to_be_bytes());
        header.extend_from_slice(&counter.to_be_bytes());
        header.extend_from_slice(&expiry.to_be_bytes());
        header.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
        header.extend_from_slice(&binding.digest);
        debug_assert_eq!(header.len(), HEADER_BYTES);
        let nonce = XNonce::from(key.nonce(counter));
        let cipher = XChaCha20Poly1305::new_from_slice(key.key.as_bytes())
            .map_err(|_| EnvelopeError::InvalidEnvelope)?;
        let mut payload = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_BYTES));
        payload.extend_from_slice(plaintext);
        cipher.encrypt_in_place(&nonce, &header, &mut *payload)
            .map_err(|_| EnvelopeError::InvalidEnvelope)?;
        self.check(cx)?;
        if self.elapsed()? >= expiry { return Err(EnvelopeError::InvalidLifetime); }
        header.extend_from_slice(&payload);
        Ok(header)
    }

    /// Opens only this owner, purpose, and exact expected binding. Frame length
    /// is admitted before allocation; the complete header is authenticated.
    /// Successful opening is not consumption: replay-sensitive consumers must
    /// additionally retire their one-use handle.
    pub fn open(&self, cx: &Cx, binding: &EnvelopeBinding, envelope: &[u8]) -> Result<OpenedState, EnvelopeError> {
        self.check(cx)?;
        if binding.purpose != self.purpose || envelope.len() < HEADER_BYTES + TAG_BYTES
            || envelope.len() > self.maximum_envelope_bytes()
        { return Err(EnvelopeError::InvalidEnvelope); }
        let header = &envelope[..HEADER_BYTES];
        if &header[..8] != MAGIC || header[8] != 1 || header[9] != self.purpose as u8
            || header[10..42] != self.identity || header[70..102] != binding.digest
        { return Err(EnvelopeError::InvalidEnvelope); }
        let number = |offset| -> Result<u64, EnvelopeError> {
            Ok(u64::from_be_bytes(header[offset..offset+8].try_into().map_err(|_| EnvelopeError::InvalidEnvelope)?))
        };
        let generation = number(42)?;
        let counter = number(50)?;
        let expiry = number(58)?;
        let length = u32::from_be_bytes(header[66..70].try_into().map_err(|_| EnvelopeError::InvalidEnvelope)?) as usize;
        if length > self.policy.maximum_plaintext || envelope.len() != HEADER_BYTES + length + TAG_BYTES {
            return Err(EnvelopeError::InvalidEnvelope);
        }
        let key = self.keys.iter().find(|key| key.id == generation).ok_or(EnvelopeError::InvalidEnvelope)?;
        let nonce = XNonce::from(key.nonce(counter));
        let cipher = XChaCha20Poly1305::new_from_slice(key.key.as_bytes())
            .map_err(|_| EnvelopeError::InvalidEnvelope)?;
        let mut payload = Zeroizing::new(envelope[HEADER_BYTES..].to_vec());
        cipher.decrypt_in_place(&nonce, header, &mut *payload)
            .map_err(|_| EnvelopeError::InvalidEnvelope)?;
        self.check(cx)?;
        if self.elapsed()? >= expiry { return Err(EnvelopeError::InvalidEnvelope); }
        Ok(OpenedState(payload))
    }

    fn check(&self, cx: &Cx) -> Result<(), EnvelopeError> {
        self.process.verify().map_err(|_| EnvelopeError::ProcessChanged)?;
        if self.closed { return Err(EnvelopeError::Closed); }
        checkpoint(cx)
    }
    fn elapsed(&self) -> Result<u64, EnvelopeError> {
        u64::try_from(self.started.elapsed().as_nanos()).map_err(|_| EnvelopeError::InvalidLifetime)
    }
}
impl fmt::Debug for EphemeralEnvelopeProtector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralEnvelopeProtector").field("purpose", &self.purpose)
            .field("generation", &self.generation).field("closed", &self.closed).finish_non_exhaustive()
    }
}
fn checkpoint(cx: &Cx) -> Result<(), EnvelopeError> {
    cx.checkpoint().map_err(|_| EnvelopeError::Cancelled)?;
    if cx.budget().deadline.is_some_and(|deadline| cx.now() >= deadline) { return Err(EnvelopeError::Deadline); }
    Ok(())
}

#[cfg(test)]
mod tests;
