//! Provider-backed persistent custody of native OAuth refresh grants.
//!
//! The existing credential-slot coordinator supplies atomic replacement,
//! independent rollback-anchor reconciliation, and at-most-once take. This
//! adapter supplies the OAuth binding, bounded secret encoding, and renewal
//! handoff. Access tokens and process-local `Instant`s are NEVER stored:
//! resuming requires a new issuer exchange before any MCP authorization header
//! can be produced.
//!
//! A deployment must supply an authenticated-encryption provider with durable
//! key/nonce/epoch custody through `OAuthGrantProtector`, and a qualified
//! independent `CredentialCommitAnchor`. There is no plaintext, ephemeral-key,
//! in-memory-anchor, or same-directory rollback-anchor production fallback.
//! This implements their consumer, not their deployment qualification.
//!
//! File and provider methods are synchronous. Run them in the caller's owned
//! blocking-I/O lane. `OAuthClient::refresh_grant` is separately asynchronous,
//! uses the caller's Cx, and performs no file I/O or automatic exchange retry.

use std::fmt;
use std::io::Write;
use std::time::Instant;

use asupersync::Cx;
use fastmcp_core::crypto::sha256_bounded;
use fastmcp_core::partition::{CredentialStoreKey, PartitionAuthorization};

use super::{
    OAuthClient, OAuthClientConfiguration, OAuthCredentials, OAuthError,
    TOKEN_TIMEOUT, admit_token_response, encode_form, operation_deadline,
    valid_opaque, validate_scopes,
};
use crate::http_auth::secure_file::SecureAtomicFile;
use crate::http_auth::secure_file::slot::{SlotRecoveryOutcome, SlotRevision};
use crate::http_auth::secure_file::slot::coordinator::{
    CoordinatedCredentialSlot, CoordinatedSlotError, CredentialAnchorBinding,
    CredentialCommitAnchor,
};

const MAGIC: &[u8; 8] = b"FCPORF01";
const MAX_CONFIGURATION_BYTES: usize = 256 * 1024;
/// Maximum canonical plaintext accepted from a protection provider.
pub const MAX_ENCODED_REFRESH_GRANT_BYTES: usize = 16 * 1024;
/// Fixed envelope ceiling, further restricted by the configured credential slot.
pub const MAX_PROTECTED_REFRESH_GRANT_BYTES: usize = 64 * 1024;

/// Authentication context for one exact stored generation. This is associated
/// data, NOT a key or authorization grant. Providers must authenticate all 32
/// bytes and must not derive routing or key selection from an envelope alone.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OAuthGrantBinding([u8; 32]);

impl OAuthGrantBinding {
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

impl fmt::Debug for OAuthGrantBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthGrantBinding").finish_non_exhaustive()
    }
}

/// Sanitized protection failures. Provider diagnostics must never retain a
/// token, plaintext, ciphertext, remote error body, key identifier, or path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthGrantProtectionError {
    Unavailable,
    InvalidEnvelope,
    Cancelled,
    TooLarge,
    EncodingFailed,
}

/// A borrowed, bounded encoding available only during provider sealing.
/// No access token, bearer header, client secret, or cached expiry is included.
/// This type has no Clone, Debug, serde, or owning plaintext conversion.
pub struct OAuthGrantEncoding<'a> {
    binding: OAuthGrantBinding,
    refresh_token: &'a str,
    scopes: &'a [String],
}

impl OAuthGrantEncoding<'_> {
    /// Exact byte count. Inputs were admitted before this view was constructed.
    pub fn encoded_len(&self) -> usize {
        8 + 32 + 4 + self.refresh_token.len() + 1
            + self.scopes.iter().map(|scope| 2 + scope.len()).sum::<usize>()
    }

    /// Streams the canonical record into provider-owned confidential storage.
    /// The provider must zeroize that storage after encryption, including on
    /// errors. The framework does not create a second serialized secret buffer.
    pub fn write_to(&self, writer: &mut dyn Write) -> Result<(), OAuthGrantProtectionError> {
        let write = |writer: &mut dyn Write, bytes: &[u8]| {
            writer.write_all(bytes).map_err(|_| OAuthGrantProtectionError::EncodingFailed)
        };
        write(writer, MAGIC)?;
        write(writer, self.binding.as_bytes())?;
        write(writer, &(self.refresh_token.len() as u32).to_be_bytes())?;
        write(writer, self.refresh_token.as_bytes())?;
        write(writer, &[self.scopes.len() as u8])?;
        for scope in self.scopes {
            write(writer, &(scope.len() as u16).to_be_bytes())?;
            write(writer, scope.as_bytes())?;
        }
        Ok(())
    }
}

/// Deployment-owned authenticated encryption with persistent key custody.
///
/// `seal` encrypts the bounded encoding and authenticates the exact binding.
/// `open` verifies that binding before releasing any plaintext. The associated
/// Plaintext owner must erase its confidential buffer on drop. Both operations
/// must be finite, observe the supplied Cx, and never detach work. Bound remote
/// replies before allocation, not merely after receiving them.
///
/// Providers must remain usable across the deployment's supported restarts,
/// enforce their key/nonce/restore-epoch policy, and refuse unsupported restores.
/// An ephemeral process-local protector does NOT satisfy this contract. Neither
/// implementing this trait nor a successful round trip proves that contract.
pub trait OAuthGrantProtector: Send {
    type Plaintext: AsRef<[u8]>;

    fn seal(
        &mut self,
        cx: &Cx,
        binding: &OAuthGrantBinding,
        grant: &OAuthGrantEncoding<'_>,
    ) -> Result<Vec<u8>, OAuthGrantProtectionError>;

    fn open(
        &mut self,
        cx: &Cx,
        binding: &OAuthGrantBinding,
        protected: &[u8],
    ) -> Result<Self::Plaintext, OAuthGrantProtectionError>;
}

/// An exclusively owned renewal lineage, not an access credential. It cannot
/// construct authorization headers and has no Clone, Debug or serde surface.
/// Obtain it by taking stored custody or transferring a live native grant.
/// Consume it with `OAuthClient::refresh_grant`; failures do not restore it.
pub struct OAuthRefreshGrant {
    configuration: OAuthClientConfiguration,
    refresh_token: String,
    scopes: Vec<String>,
}

impl OAuthRefreshGrant {
    pub fn scopes(&self) -> &[String] { &self.scopes }
}

impl OAuthCredentials {
    /// Transfers renewal ownership while leaving the current access token and
    /// its ORIGINAL expiry unchanged. A second transfer cannot replay it.
    pub fn take_refresh_grant(&mut self) -> Result<OAuthRefreshGrant, OAuthError> {
        let refresh = self.refresh_token.as_deref().ok_or(OAuthError::RefreshUnavailable)?;
        validate_refresh(refresh, &self.scopes, &self.configuration)
            .map_err(|_| OAuthError::InvalidTokenResponse)?;
        let configuration = self.configuration.clone();
        let scopes = self.scopes.clone();
        let refresh_token = self.refresh_token.take().ok_or(OAuthError::RefreshUnavailable)?;
        Ok(OAuthRefreshGrant { configuration, refresh_token, scopes })
    }
}

impl OAuthClient {
    /// Exchanges an exclusively owned refresh grant for a newly admitted pair.
    /// No cached access token or expiry is reconstructed from persistent state.
    /// The original issuer, resource, registration, scope ceiling, private CA,
    /// and policy must match exactly. No redirects, proxy, cookies, or retries
    /// are enabled by this path.
    ///
    /// Cancellation, rejection, malformed replies, and lost responses consume
    /// the handoff. Never restore its old protected bytes to retry a token that
    /// the issuer may already have rotated. An omitted replacement refresh
    /// token retains the old token only after successful response admission.
    pub async fn refresh_grant(
        &self,
        cx: &Cx,
        grant: OAuthRefreshGrant,
    ) -> Result<OAuthCredentials, OAuthError> {
        let deadline = operation_deadline(cx, TOKEN_TIMEOUT)?;
        if grant.configuration != self.configuration {
            return Err(OAuthError::CredentialBindingMismatch);
        }
        let scope = grant.scopes.join(" ");
        let mut fields = vec![
            ("grant_type", "refresh_token"),
            ("client_id", self.configuration.client_id.as_str()),
            ("refresh_token", grant.refresh_token.as_str()),
            ("resource", self.configuration.resource.as_str()),
        ];
        if !scope.is_empty() { fields.push(("scope", scope.as_str())); }
        let body = encode_form(&fields)?;
        let started = Instant::now();
        let response = self.exchange(cx, deadline, body).await?;
        if cx.checkpoint().is_err() { return Err(OAuthError::Cancelled); }
        if cx.now() >= deadline { return Err(OAuthError::TimedOut); }
        let mut credentials = admit_token_response(
            &self.configuration, &grant.scopes, &response, started,
        )?;
        if credentials.refresh_token.is_none() {
            credentials.refresh_token = Some(grant.refresh_token);
        }
        if cx.checkpoint().is_err() { return Err(OAuthError::Cancelled); }
        if cx.now() >= deadline { return Err(OAuthError::TimedOut); }
        Ok(credentials)
    }

    /// Whether a typed grant was admitted under this exact immutable client
    /// policy. This checks binding only, not token liveness or authorization.
    pub fn accepts_credentials(&self, credentials: &OAuthCredentials) -> bool {
        credentials.configuration == self.configuration
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthRefreshStoreError {
    ContextStopped,
    ConfigurationMismatch,
    RefreshUnavailable,
    InvalidGrant,
    TooLarge,
    GenerationExhausted,
    RevisionMismatch,
    Protection(OAuthGrantProtectionError),
    Storage(CoordinatedSlotError),
}

impl fmt::Display for OAuthRefreshStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContextStopped => f.write_str("OAuth refresh custody context stopped"),
            Self::ConfigurationMismatch => f.write_str("OAuth refresh custody configuration mismatch"),
            Self::RefreshUnavailable => f.write_str("OAuth grant has no transferable refresh token"),
            Self::InvalidGrant => f.write_str("stored OAuth refresh grant is invalid"),
            Self::TooLarge => f.write_str("stored OAuth refresh grant exceeds its bound"),
            Self::GenerationExhausted => f.write_str("OAuth refresh custody generation exhausted"),
            Self::RevisionMismatch => f.write_str("OAuth refresh custody revision mismatch"),
            Self::Protection(_) => f.write_str("OAuth refresh grant protection failed"),
            Self::Storage(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for OAuthRefreshStoreError {}
impl From<CoordinatedSlotError> for OAuthRefreshStoreError {
    fn from(error: CoordinatedSlotError) -> Self { Self::Storage(error) }
}
impl From<OAuthGrantProtectionError> for OAuthRefreshStoreError {
    fn from(error: OAuthGrantProtectionError) -> Self { Self::Protection(error) }
}

/// One exact native OAuth binding over the existing anchored credential slot.
/// Exclusive ownership serializes store/take/invalidate. The slot's file lock
/// also serializes separate processes; the independent anchor detects rollback.
/// No public accessor exposes the slot, protector, or an unconsumed plaintext.
pub struct OAuthRefreshStore<A, P> {
    slot: CoordinatedCredentialSlot<A>,
    protector: P,
    configuration: OAuthClientConfiguration,
    configuration_digest: [u8; 32],
    anchor_binding: CredentialAnchorBinding,
}

impl<A: CredentialCommitAnchor, P: OAuthGrantProtector> OAuthRefreshStore<A, P> {
    /// Opens/reconciles independently anchored custody before accepting grants.
    /// The same trusted client configuration and provider custody must be used
    /// after restart. A configuration change never silently migrates credentials.
    pub fn open(
        cx: &Cx,
        file: SecureAtomicFile,
        key: &CredentialStoreKey,
        authorization: &PartitionAuthorization,
        namespace: &str,
        anchor: A,
        protector: P,
        client: &OAuthClient,
    ) -> Result<(Self, Option<SlotRecoveryOutcome>), OAuthRefreshStoreError> {
        checkpoint(cx)?;
        let configuration_digest = configuration_digest(&client.configuration)?;
        let anchor_binding = CredentialAnchorBinding::for_store(namespace, key, authorization)?;
        let (slot, recovery) = CoordinatedCredentialSlot::open(
            cx, file, key, authorization, namespace, anchor,
        )?;
        Ok((Self {
            slot, protector, configuration: client.configuration.clone(),
            configuration_digest, anchor_binding,
        }, recovery))
    }

    pub fn revision(&self) -> Option<SlotRevision> { self.slot.revision() }
    pub fn requires_recovery(&self) -> bool { self.slot.requires_recovery() }

    /// Seals and transfers the live refresh token into persistent custody.
    /// The access token/expiry remain usable in `credentials`, but successful
    /// handoff removes its refresh token. The caller must name the exact prior
    /// revision; replacing a different lineage is never an implicit overwrite.
    ///
    /// Binding, authorization, encoding and provider preflight failures leave
    /// the source grant untouched. Immediately before storage mutation becomes
    /// possible, its refresh token is removed. ANY later failure leaves it
    /// removed, including an uncertain commit, to prevent two usable copies.
    /// Reopen/reconcile custody rather than restoring the old live token.
    pub fn store_refresh(
        &mut self,
        cx: &Cx,
        authorization: &PartitionAuthorization,
        expected: Option<SlotRevision>,
        credentials: &mut OAuthCredentials,
    ) -> Result<SlotRevision, OAuthRefreshStoreError> {
        checkpoint(cx)?;
        if credentials.configuration != self.configuration {
            return Err(OAuthRefreshStoreError::ConfigurationMismatch);
        }
        if expected != self.slot.revision() { return Err(OAuthRefreshStoreError::RevisionMismatch); }
        let refresh_token = credentials.refresh_token.as_deref()
            .ok_or(OAuthRefreshStoreError::RefreshUnavailable)?;
        validate_refresh(refresh_token, &credentials.scopes, &self.configuration)?;
        let generation = expected.map_or(0, SlotRevision::generation)
            .checked_add(1).ok_or(OAuthRefreshStoreError::GenerationExhausted)?;
        // Authorize and revalidate the independent anchor BEFORE a provider
        // can receive the grant. This read releases no plaintext to callers.
        drop(self.slot.load(cx, authorization)?);
        let binding = self.binding(generation)?;
        let encoding = OAuthGrantEncoding { binding, refresh_token, scopes: &credentials.scopes };
        let protected = self.protector.seal(cx, &binding, &encoding)?;
        self.admit_protected(&protected)?;
        checkpoint(cx)?;
        // Do not put this back on error: a storage reply can be lost after the
        // write is durable. The coordinator owns the only safe reconciliation.
        let _transferred = credentials.refresh_token.take()
            .ok_or(OAuthRefreshStoreError::RefreshUnavailable)?;
        Ok(self.slot.replace(cx, authorization, expected, &protected)?)
    }

    /// Validates the encrypted grant, then durably consumes and settles its
    /// slot BEFORE releasing renewal ownership. Wrong keys/configuration or
    /// malformed records cannot consume a valid stored grant. No access token
    /// is released; the returned handoff still requires an issuer exchange.
    ///
    /// A crash/uncertain result after take may lose the handoff, but recovery
    /// never redelivers it. This is at-most-once custody, not exactly-once OAuth.
    pub fn take_refresh(
        &mut self,
        cx: &Cx,
        authorization: &PartitionAuthorization,
    ) -> Result<Option<OAuthRefreshGrant>, OAuthRefreshStoreError> {
        checkpoint(cx)?;
        let Some(protected) = self.slot.load(cx, authorization)? else { return Ok(None); };
        self.admit_protected(&protected)?;
        let revision = self.slot.revision().ok_or(OAuthRefreshStoreError::InvalidGrant)?;
        let binding = self.binding(revision.generation())?;
        let plaintext = self.protector.open(cx, &binding, &protected)?;
        let grant = decode_grant(&self.configuration, binding, plaintext.as_ref())?;
        drop(plaintext);
        checkpoint(cx)?;
        let committed = self.slot.take(cx, authorization, revision)?;
        let consumed = committed.into_consumed().ok_or(OAuthRefreshStoreError::InvalidGrant)?;
        if consumed != protected { return Err(OAuthRefreshStoreError::InvalidGrant); }
        Ok(Some(grant))
    }

    /// Local durable logout. This cannot recall a previously handed-out grant
    /// or revoke issuer-side tokens; close live sessions and revoke separately.
    pub fn invalidate(
        &mut self,
        cx: &Cx,
        authorization: &PartitionAuthorization,
    ) -> Result<SlotRevision, OAuthRefreshStoreError> {
        Ok(self.slot.invalidate(cx, authorization)?)
    }

    fn binding(&self, generation: u64) -> Result<OAuthGrantBinding, OAuthRefreshStoreError> {
        grant_binding(self.configuration_digest, self.anchor_binding.as_bytes(), generation)
    }

    fn admit_protected(&self, protected: &[u8]) -> Result<(), OAuthRefreshStoreError> {
        if protected.is_empty() || protected.len() > MAX_PROTECTED_REFRESH_GRANT_BYTES
            || protected.len() > self.slot.maximum_payload_bytes()
        { return Err(OAuthRefreshStoreError::TooLarge); }
        Ok(())
    }
}

fn checkpoint(cx: &Cx) -> Result<(), OAuthRefreshStoreError> {
    cx.checkpoint().map_err(|_| OAuthRefreshStoreError::ContextStopped)
}

fn validate_refresh(
    token: &str, scopes: &[String], configuration: &OAuthClientConfiguration,
) -> Result<(), OAuthRefreshStoreError> {
    if !valid_opaque(token, super::MAX_CODE_BYTES) {
        return Err(OAuthRefreshStoreError::InvalidGrant);
    }
    validate_scopes(scopes).map_err(|_| OAuthRefreshStoreError::InvalidGrant)?;
    if scopes.iter().any(|scope| !configuration.scopes.contains(scope)) {
        return Err(OAuthRefreshStoreError::InvalidGrant);
    }
    Ok(())
}

fn field(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), OAuthRefreshStoreError> {
    let length = u32::try_from(bytes.len()).map_err(|_| OAuthRefreshStoreError::TooLarge)?;
    let total = output.len().checked_add(4).and_then(|n| n.checked_add(bytes.len()))
        .ok_or(OAuthRefreshStoreError::TooLarge)?;
    if total > MAX_CONFIGURATION_BYTES { return Err(OAuthRefreshStoreError::TooLarge); }
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn configuration_digest(configuration: &OAuthClientConfiguration) -> Result<[u8; 32], OAuthRefreshStoreError> {
    if configuration.resource_tls.is_some() != configuration.resource_tls_fingerprint.is_some() {
        return Err(OAuthRefreshStoreError::ConfigurationMismatch);
    }
    let mut bytes = b"fastmcp/oauth-refresh-configuration/v1\0".to_vec();
    for value in [
        configuration.issuer.as_str(), configuration.authorization_endpoint.as_str(),
        configuration.token_endpoint.as_str(), configuration.resource.as_str(),
        configuration.client_id.as_str(),
    ] { field(&mut bytes, value.as_bytes())?; }
    field(&mut bytes, &[u8::from(configuration.revocation_endpoint.is_some())])?;
    if let Some(endpoint) = &configuration.revocation_endpoint { field(&mut bytes, endpoint.as_str().as_bytes())?; }
    field(&mut bytes, &configuration.authorization_timeout.as_nanos().to_be_bytes())?;
    field(&mut bytes, &configuration.max_access_token_lifetime.as_nanos().to_be_bytes())?;
    field(&mut bytes, &(configuration.scopes.len() as u32).to_be_bytes())?;
    for scope in &configuration.scopes { field(&mut bytes, scope.as_bytes())?; }
    field(&mut bytes, &(configuration.extra_root_certificates.len() as u32).to_be_bytes())?;
    for certificate in &configuration.extra_root_certificates { field(&mut bytes, certificate)?; }
    field(&mut bytes, &[u8::from(configuration.resource_tls_fingerprint.is_some())])?;
    if let Some(fingerprint) = configuration.resource_tls_fingerprint { field(&mut bytes, &fingerprint)?; }
    sha256_bounded(&bytes, MAX_CONFIGURATION_BYTES)
        .map(|digest| digest.into_bytes()).map_err(|_| OAuthRefreshStoreError::TooLarge)
}

fn grant_binding(
    configuration: [u8; 32], anchor: &[u8; 32], generation: u64,
) -> Result<OAuthGrantBinding, OAuthRefreshStoreError> {
    if generation == 0 { return Err(OAuthRefreshStoreError::InvalidGrant); }
    let mut bytes = b"fastmcp/oauth-refresh-custody/v1\0".to_vec();
    bytes.extend_from_slice(&configuration);
    bytes.extend_from_slice(anchor);
    bytes.extend_from_slice(&generation.to_be_bytes());
    sha256_bounded(&bytes, 128).map(|digest| OAuthGrantBinding(digest.into_bytes()))
        .map_err(|_| OAuthRefreshStoreError::InvalidGrant)
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], OAuthRefreshStoreError> {
    if count > input.len() { return Err(OAuthRefreshStoreError::InvalidGrant); }
    let (head, tail) = input.split_at(count);
    *input = tail;
    Ok(head)
}

fn decode_grant(
    configuration: &OAuthClientConfiguration, binding: OAuthGrantBinding, mut input: &[u8],
) -> Result<OAuthRefreshGrant, OAuthRefreshStoreError> {
    if input.len() > MAX_ENCODED_REFRESH_GRANT_BYTES { return Err(OAuthRefreshStoreError::TooLarge); }
    if take(&mut input, 8)? != MAGIC || take(&mut input, 32)? != binding.as_bytes() {
        return Err(OAuthRefreshStoreError::InvalidGrant);
    }
    let length = u32::from_be_bytes(take(&mut input, 4)?.try_into()
        .map_err(|_| OAuthRefreshStoreError::InvalidGrant)?) as usize;
    if length > super::MAX_CODE_BYTES { return Err(OAuthRefreshStoreError::InvalidGrant); }
    let token = std::str::from_utf8(take(&mut input, length)?)
        .map_err(|_| OAuthRefreshStoreError::InvalidGrant)?;
    let count = usize::from(take(&mut input, 1)?[0]);
    if count > 32 { return Err(OAuthRefreshStoreError::InvalidGrant); }
    let mut scopes = Vec::with_capacity(count);
    for _ in 0..count {
        let length = usize::from(u16::from_be_bytes(take(&mut input, 2)?.try_into()
            .map_err(|_| OAuthRefreshStoreError::InvalidGrant)?));
        if length > 256 { return Err(OAuthRefreshStoreError::InvalidGrant); }
        let scope = std::str::from_utf8(take(&mut input, length)?)
            .map_err(|_| OAuthRefreshStoreError::InvalidGrant)?;
        scopes.push(scope.to_owned());
    }
    if !input.is_empty() { return Err(OAuthRefreshStoreError::InvalidGrant); }
    validate_refresh(token, &scopes, configuration)?;
    Ok(OAuthRefreshGrant {
        configuration: configuration.clone(), refresh_token: token.to_owned(), scopes,
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod resource_trust_tests {
    use super::*;
    use super::super::tests as native;

    #[test]
    fn persistent_binding_distinguishes_resource_ca_from_issuer_only_trust() {
        let plain = native::config();
        let resource = plain.clone().with_resource_root_certificate(native::test_root()).unwrap();
        let same = plain.clone().with_resource_root_certificate(native::test_root()).unwrap();
        let issuer = plain.clone().with_extra_root_certificate(native::test_root()).unwrap();
        assert_eq!(configuration_digest(&resource).unwrap(), configuration_digest(&same).unwrap());
        assert_ne!(configuration_digest(&resource).unwrap(), configuration_digest(&plain).unwrap());
        assert_ne!(configuration_digest(&resource).unwrap(), configuration_digest(&issuer).unwrap());
        let scopes = vec!["tools:read".to_owned()];
        let binding = grant_binding(configuration_digest(&resource).unwrap(), &[8; 32], 1).unwrap();
        let encoding = OAuthGrantEncoding { binding, refresh_token: "private-resource-refresh", scopes: &scopes };
        let mut bytes = Vec::new();
        encoding.write_to(&mut bytes).unwrap();
        let changed = grant_binding(configuration_digest(&issuer).unwrap(), &[8; 32], 1).unwrap();
        assert!(decode_grant(&issuer, changed, &bytes).is_err());
        assert!(decode_grant(&resource, binding, &bytes).is_ok());
    }

    #[test]
    fn inconsistent_resource_trust_fingerprint_refuses_custody_binding() {
        let mut configuration = native::config().with_resource_root_certificate(native::test_root()).unwrap();
        assert!(configuration_digest(&configuration).is_ok());
        configuration.resource_tls_fingerprint = None;
        assert_eq!(configuration_digest(&configuration), Err(OAuthRefreshStoreError::ConfigurationMismatch));
    }
}
