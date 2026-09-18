//! AUTH-00 A: verified principal and security-partition types.
//!
//! This module owns the first AUTH-00 capability slice: the bounded verified
//! facts that ingress authentication produces, and the secret-fingerprint,
//! replay-purpose, and rotation/revalidation types derived from them.
//!
//! # The construction rule
//!
//! Every value here records something a provider *verified*. None of these
//! types can be built from a self-reported claim, a request field, or an
//! arbitrary caller string: each constructor either takes already-verified
//! provider output or takes key material the caller must already hold, and
//! each one bounds and validates what it is given. A type that could be minted
//! from a request field would let a caller name another principal's partition,
//! which is the whole failure this package exists to prevent.
//!
//! # The redaction rule
//!
//! Raw credentials and introspection handles never appear in a public value,
//! `Debug` output, `Clone`, a serialized form, a log line, a receipt, or a
//! replay lookup key. [`SecretFingerprint`] is the sanctioned way to name a
//! secret without carrying one: it retains a full-width MAC tag over the
//! secret, never the secret. None of the secret-bearing types in this module
//! implement `Serialize`, and their `Debug` implementations are redacting.
//!
//! # No-claim boundary
//!
//! This leaf proves verified-principal ingress and partition-type
//! construction. It does not prove partition admission or lookup — those are
//! AUTH-00 B's, in [`crate::partition`] — nor the AUTH-00 aggregate, nor any
//! aggregate MCP capability.

use std::fmt;
use std::time::Duration;

use crate::crypto::{HMAC_SHA256_TAG_BYTES, HmacSha256Key, HmacSha256Tag};

/// Smallest admissible secret key identifier, in ASCII bytes.
pub const SECRET_FINGERPRINT_KEY_ID_MIN_BYTES: usize = 1;

/// Largest admissible secret key identifier, in ASCII bytes.
pub const SECRET_FINGERPRINT_KEY_ID_MAX_BYTES: usize = 128;

/// Exact width of a secret fingerprint tag.
///
/// The tag is retained at full width deliberately. A truncated MAC would make
/// two distinct secrets collide more easily, and a fingerprint whose whole
/// purpose is to distinguish key instances must not invite that.
pub const SECRET_FINGERPRINT_TAG_BYTES: usize = HMAC_SHA256_TAG_BYTES;

/// Upper bound on the material a fingerprint may be taken over.
const SECRET_FINGERPRINT_INPUT_LIMIT_BYTES: usize = 64 * 1024;

/// Domain separator, so a fingerprint can never collide with another MAC use.
const SECRET_FINGERPRINT_DOMAIN: &[u8] = b"auth-00-secret-fingerprint-v1";

/// Default maximum staleness for a revalidated authorization.
pub const DEFAULT_MAXIMUM_STALENESS: Duration = Duration::from_secs(30);

/// Hard ceiling on configured maximum staleness.
///
/// Beyond this a "revalidated" authorization is an assertion about the past,
/// not about now, so the ceiling is enforced rather than advisory.
pub const HARD_MAXIMUM_STALENESS: Duration = Duration::from_mins(5);

/// Maximum UTF-8 bytes in one verified identity, audience, or claim field.
pub const MAX_VERIFIED_IDENTITY_FIELD_BYTES: usize = 8 * 1024;

/// Maximum presented claims, counted before sorting and deduplication.
pub const MAX_VERIFIED_IDENTITY_CLAIMS: usize = 256;

/// Maximum aggregate UTF-8 bytes admitted from one provider identity.
///
/// Identity fields, OAuth binding fields, and every presented claim name and
/// value consume this budget before the framework clones or sorts them.
pub const MAX_VERIFIED_IDENTITY_BYTES: usize = 64 * 1024;

// ===========================================================================
// Errors
// ===========================================================================

/// Refusal while constructing a verified ingress fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressFactsError {
    /// A secret key identifier was empty.
    KeyIdEmpty,
    /// A secret key identifier exceeded [`SECRET_FINGERPRINT_KEY_ID_MAX_BYTES`].
    KeyIdTooLong,
    /// A secret key identifier contained a non-ASCII or non-printable byte.
    KeyIdNotPrintableAscii,
    /// Fingerprint material exceeded the audited input bound.
    FingerprintMaterialTooLong,
    /// The material did not reproduce the fingerprint's tag.
    FingerprintMismatch,
    /// A configured maximum staleness exceeded [`HARD_MAXIMUM_STALENESS`].
    MaximumStalenessAboveCeiling,
    /// A configured maximum staleness was zero, which no provider can satisfy.
    MaximumStalenessZero,
    /// An identity, audience, or claim field exceeded its individual byte bound.
    IdentityFieldTooLong,
    /// The presented claim count exceeded its bound before deduplication.
    TooManyVerifiedClaims,
    /// The aggregate verified-identity byte budget was exhausted.
    IdentityTooLarge,
    /// A verified claim had an empty name.
    InvalidVerifiedClaim,
    /// OAuth audience facts were empty or contradicted their enclosing identity.
    InvalidAudienceBinding,
}

impl fmt::Display for IngressFactsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyIdEmpty => formatter.write_str("secret key identifier must be nonempty"),
            Self::KeyIdTooLong => write!(
                formatter,
                "secret key identifier exceeds {SECRET_FINGERPRINT_KEY_ID_MAX_BYTES} ASCII bytes"
            ),
            Self::KeyIdNotPrintableAscii => formatter.write_str(
                "secret key identifier must be printable ASCII; a non-ASCII identifier cannot be \
                 compared or logged unambiguously",
            ),
            Self::FingerprintMaterialTooLong => write!(
                formatter,
                "secret fingerprint material exceeds {SECRET_FINGERPRINT_INPUT_LIMIT_BYTES} bytes"
            ),
            Self::FingerprintMismatch => {
                formatter.write_str("material does not reproduce the secret fingerprint")
            }
            Self::MaximumStalenessAboveCeiling => write!(
                formatter,
                "configured maximum staleness exceeds the {}s hard ceiling",
                HARD_MAXIMUM_STALENESS.as_secs()
            ),
            Self::MaximumStalenessZero => {
                formatter.write_str("configured maximum staleness must be nonzero")
            }
            Self::IdentityFieldTooLong => {
                formatter.write_str("verified identity field exceeds its byte bound")
            }
            Self::TooManyVerifiedClaims => {
                formatter.write_str("verified identity exceeds its claim-count bound")
            }
            Self::IdentityTooLarge => {
                formatter.write_str("verified identity exceeds its aggregate byte bound")
            }
            Self::InvalidVerifiedClaim => {
                formatter.write_str("verified claim name must be nonempty")
            }
            Self::InvalidAudienceBinding => {
                formatter.write_str("verified audience binding is inconsistent or incomplete")
            }
        }
    }
}

impl std::error::Error for IngressFactsError {}

// ===========================================================================
// Secret fingerprint
// ===========================================================================

/// A non-secret, full-width name for a secret key instance.
///
/// Records which key, at which generation, was in force — without carrying the
/// key. The tag is a domain-separated HMAC over caller-supplied material using
/// the key itself, so two generations of the same key identifier, or two keys
/// sharing an identifier across deployments, produce different fingerprints.
///
/// The key material is used and dropped; it is never stored, so no accessor,
/// `Debug`, or future `Serialize` impl can leak it.
pub struct SecretFingerprint {
    key_id: String,
    generation: u64,
    tag: HmacSha256Tag,
}

impl Clone for SecretFingerprint {
    /// Hand-written because [`HmacSha256Tag`] deliberately derives nothing.
    ///
    /// Cloning is not a timing hazard, so it is safe to provide here; deriving
    /// it on the tag itself would be a change to a type this module does not
    /// own, for a need only this module has.
    fn clone(&self) -> Self {
        Self {
            key_id: self.key_id.clone(),
            generation: self.generation,
            tag: HmacSha256Tag::from_bytes(*self.tag.as_bytes()),
        }
    }
}

impl SecretFingerprint {
    /// Derives a fingerprint for `key_id` at `generation` over `material`.
    ///
    /// # Errors
    ///
    /// Returns [`IngressFactsError::KeyIdEmpty`],
    /// [`IngressFactsError::KeyIdTooLong`], or
    /// [`IngressFactsError::KeyIdNotPrintableAscii`] for an inadmissible
    /// identifier, and [`IngressFactsError::FingerprintMaterialTooLong`] when
    /// the material exceeds the audited bound.
    pub fn derive(
        key_id: &str,
        generation: u64,
        key: &HmacSha256Key,
        material: &[u8],
    ) -> Result<Self, IngressFactsError> {
        Self::check_key_id(key_id)?;
        if material.len() > SECRET_FINGERPRINT_INPUT_LIMIT_BYTES {
            return Err(IngressFactsError::FingerprintMaterialTooLong);
        }

        // Length-prefixed so no two distinct field splittings can produce the
        // same preimage.
        let preimage = Self::preimage(key_id, generation, material);

        let tag = key
            .authenticate_bounded(&preimage, SECRET_FINGERPRINT_INPUT_LIMIT_BYTES * 2)
            .map_err(|_| IngressFactsError::FingerprintMaterialTooLong)?;

        Ok(Self {
            key_id: key_id.to_owned(),
            generation,
            tag,
        })
    }

    /// Validates a key identifier against the frozen floors.
    fn check_key_id(key_id: &str) -> Result<(), IngressFactsError> {
        if key_id.len() < SECRET_FINGERPRINT_KEY_ID_MIN_BYTES {
            return Err(IngressFactsError::KeyIdEmpty);
        }
        if key_id.len() > SECRET_FINGERPRINT_KEY_ID_MAX_BYTES {
            return Err(IngressFactsError::KeyIdTooLong);
        }
        if !key_id
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        {
            return Err(IngressFactsError::KeyIdNotPrintableAscii);
        }
        Ok(())
    }

    /// The key identifier this fingerprint names.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The key generation in force when this fingerprint was taken.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The full-width tag.
    ///
    /// This is a MAC over the material, not the secret, and is safe to record
    /// in a manifest or receipt.
    ///
    /// # Comparison
    ///
    /// Do not compare these bytes with `==`. A tag is an authenticator: an
    /// attacker who can submit candidate fingerprints and measure how long the
    /// comparison takes recovers it byte by byte, because `==` on a byte array
    /// short-circuits at the first difference. That is why
    /// [`HmacSha256Tag`] deliberately implements no equality at all, why this
    /// type does not derive `PartialEq`, and why
    /// [`Self::verify_material`] exists. Use it.
    #[must_use]
    pub const fn tag(&self) -> &[u8; SECRET_FINGERPRINT_TAG_BYTES] {
        self.tag.as_bytes()
    }

    /// Verifies in constant time that this fingerprint names `material` under `key`.
    ///
    /// This is the only sanctioned way to decide whether a fingerprint
    /// matches. It recomputes the MAC and delegates the comparison to
    /// [`HmacSha256Key::verify_bounded`], which is constant time.
    ///
    /// # Errors
    ///
    /// Returns [`IngressFactsError::FingerprintMismatch`] when the material,
    /// key identifier, generation, or key does not reproduce this tag, and
    /// [`IngressFactsError::FingerprintMaterialTooLong`] when the material
    /// exceeds the audited bound. The two are distinguishable because an
    /// over-long input is refused before any MAC work and therefore leaks
    /// nothing about the tag.
    pub fn verify_material(
        &self,
        key: &HmacSha256Key,
        material: &[u8],
    ) -> Result<(), IngressFactsError> {
        if material.len() > SECRET_FINGERPRINT_INPUT_LIMIT_BYTES {
            return Err(IngressFactsError::FingerprintMaterialTooLong);
        }
        let preimage = Self::preimage(&self.key_id, self.generation, material);
        key.verify_bounded(
            &preimage,
            SECRET_FINGERPRINT_INPUT_LIMIT_BYTES * 2,
            &self.tag,
        )
        .map_err(|_| IngressFactsError::FingerprintMismatch)
    }

    /// Builds the length-prefixed, domain-separated preimage.
    ///
    /// Shared by derivation and verification so the two can never drift; a
    /// verifier that hashed a different preimage than the deriver would reject
    /// every genuine match.
    fn preimage(key_id: &str, generation: u64, material: &[u8]) -> Vec<u8> {
        let mut preimage = Vec::with_capacity(material.len() + key_id.len() + 48);
        for part in [
            SECRET_FINGERPRINT_DOMAIN,
            key_id.as_bytes(),
            &generation.to_be_bytes(),
            material,
        ] {
            preimage.extend_from_slice(&(part.len() as u64).to_be_bytes());
            preimage.extend_from_slice(part);
        }
        preimage
    }
}

impl fmt::Debug for SecretFingerprint {
    /// Shows the key identifier and generation; never the tag.
    ///
    /// The tag is not a secret, but it is a stable cross-request correlator,
    /// so it stays out of incidental log output and is reachable only through
    /// the explicit [`SecretFingerprint::tag`] accessor.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretFingerprint")
            .field("key_id", &self.key_id)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

// ===========================================================================
// Replay purposes
// ===========================================================================

/// The exactly two enterprise replay-protection purposes AUTH-00 defines.
///
/// Purposes are distinct domains, not labels. A reservation taken for one
/// purpose must never satisfy a lookup for the other, so the discriminant is
/// mixed into every derived replay key rather than being carried alongside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReplayPurpose {
    /// Replay protection for a whole enterprise identity assertion.
    EnterpriseIdentityAssertionReplay,
    /// Replay protection for an enterprise ID-JAG `jti`.
    EnterpriseIdJagJtiReplay,
}

impl ReplayPurpose {
    /// Every defined purpose, in frozen order.
    ///
    /// The acceptance criteria freeze this set at exactly two; an evaluator
    /// asserts against this constant so adding a third is a visible change
    /// rather than a silent one.
    pub const ALL: [Self; 2] = [
        Self::EnterpriseIdentityAssertionReplay,
        Self::EnterpriseIdJagJtiReplay,
    ];

    /// The stable domain separator for this purpose.
    #[must_use]
    pub fn domain(self) -> &'static [u8] {
        match self {
            Self::EnterpriseIdentityAssertionReplay => {
                b"auth-00-replay-enterprise-identity-assertion-v1"
            }
            Self::EnterpriseIdJagJtiReplay => b"auth-00-replay-enterprise-id-jag-jti-v1",
        }
    }

    /// The stable name for this purpose.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EnterpriseIdentityAssertionReplay => "EnterpriseIdentityAssertionReplay",
            Self::EnterpriseIdJagJtiReplay => "EnterpriseIdJagJtiReplay",
        }
    }
}

impl fmt::Display for ReplayPurpose {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

// ===========================================================================
// Rotation and revalidation facts
// ===========================================================================

/// Whether a revalidation attempt reached the provider.
///
/// `Unknown` is a first-class outcome, not an error case to be collapsed into
/// failure: a dispatched call whose result never arrived may or may not have
/// taken effect upstream, and a caller that treats that as a clean denial will
/// eventually treat a live authorization as revoked, or the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevalidationDispatch {
    /// The attempt was never dispatched to the provider.
    NotDispatched,
    /// The attempt reached the provider and its verdict was received.
    Dispatched,
    /// The attempt may or may not have reached the provider.
    Unknown,
}

impl fmt::Display for RevalidationDispatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotDispatched => "NotDispatched",
            Self::Dispatched => "Dispatched",
            Self::Unknown => "Unknown",
        })
    }
}

/// A configured, validated staleness bound.
///
/// Wrapping the bound in a type means the ceiling is enforced once, at
/// construction, rather than at each of the sites that later consult it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MaximumStaleness {
    bound: Duration,
}

impl MaximumStaleness {
    /// The default bound, [`DEFAULT_MAXIMUM_STALENESS`].
    #[must_use]
    pub const fn default_bound() -> Self {
        Self {
            bound: DEFAULT_MAXIMUM_STALENESS,
        }
    }

    /// Validates a configured bound against the frozen floor and ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`IngressFactsError::MaximumStalenessZero`] for a zero bound and
    /// [`IngressFactsError::MaximumStalenessAboveCeiling`] above
    /// [`HARD_MAXIMUM_STALENESS`].
    pub const fn new(bound: Duration) -> Result<Self, IngressFactsError> {
        if bound.is_zero() {
            return Err(IngressFactsError::MaximumStalenessZero);
        }
        if bound.as_nanos() > HARD_MAXIMUM_STALENESS.as_nanos() {
            return Err(IngressFactsError::MaximumStalenessAboveCeiling);
        }
        Ok(Self { bound })
    }

    /// The validated bound.
    #[must_use]
    pub const fn bound(self) -> Duration {
        self.bound
    }
}

impl Default for MaximumStaleness {
    fn default() -> Self {
        Self::default_bound()
    }
}

// ===========================================================================
// Verified audience binding
// ===========================================================================

/// Where a verified audience binding came from, or why there is none.
///
/// The OAuth variant is not a default with the others as exceptions: a
/// provider that does not do OAuth audience validation must say which other
/// thing it did, so that "no audience was checked" can never be mistaken for
/// "an audience was checked and matched". The explicit non-OAuth variants
/// carry no audience fields at all, so they cannot collide with an OAuth
/// binding under comparison or in a derived key.
#[derive(Clone, PartialEq, Eq)]
pub enum VerifiedAudienceBinding {
    /// The provider validated an OAuth audience against an accepted-audience
    /// policy.
    ///
    /// Wire- and JOSE-neutral by construction: these are the *outcomes* of
    /// validation, not the token, header, or claim set it was read from.
    OAuth {
        /// Exact canonical resource the principal was verified against.
        canonical_resource: String,
        /// Exact audience string that validated.
        validated_audience: String,
        /// Identity of the accepted-audience policy that accepted it.
        audience_policy_id: String,
        /// Revision of that policy.
        audience_policy_revision: u64,
        /// Provider that performed the validation.
        provider: String,
        /// Provider configuration generation in force at validation.
        configuration_generation: u64,
    },
    /// The provider authenticates by mutual TLS; no audience applies.
    MutualTlsPeer,
    /// The provider authenticates a pre-shared static credential; no audience
    /// applies.
    StaticCredential,
}

impl VerifiedAudienceBinding {
    /// Whether this binding carries a validated OAuth audience.
    #[must_use]
    pub const fn is_oauth(&self) -> bool {
        matches!(self, Self::OAuth { .. })
    }

    /// The accepted-audience policy identity, when OAuth applies.
    #[must_use]
    pub fn audience_policy_id(&self) -> Option<&str> {
        match self {
            Self::OAuth {
                audience_policy_id, ..
            } => Some(audience_policy_id),
            Self::MutualTlsPeer | Self::StaticCredential => None,
        }
    }

    /// The accepted-audience policy revision, when OAuth applies.
    #[must_use]
    pub const fn audience_policy_revision(&self) -> Option<u64> {
        match self {
            Self::OAuth {
                audience_policy_revision,
                ..
            } => Some(*audience_policy_revision),
            Self::MutualTlsPeer | Self::StaticCredential => None,
        }
    }

    /// A stable, domain-separated encoding for digesting and key derivation.
    ///
    /// The variant discriminant leads, so an OAuth binding and a non-OAuth one
    /// can never produce the same bytes even if every other field were to
    /// coincide.
    #[must_use]
    pub fn canonical_parts(&self) -> Vec<Vec<u8>> {
        match self {
            Self::OAuth {
                canonical_resource,
                validated_audience,
                audience_policy_id,
                audience_policy_revision,
                provider,
                configuration_generation,
            } => vec![
                b"oauth".to_vec(),
                canonical_resource.as_bytes().to_vec(),
                validated_audience.as_bytes().to_vec(),
                audience_policy_id.as_bytes().to_vec(),
                audience_policy_revision.to_be_bytes().to_vec(),
                provider.as_bytes().to_vec(),
                configuration_generation.to_be_bytes().to_vec(),
            ],
            Self::MutualTlsPeer => vec![b"mutual-tls-peer".to_vec()],
            Self::StaticCredential => vec![b"static-credential".to_vec()],
        }
    }
}

impl fmt::Debug for VerifiedAudienceBinding {
    /// Names the variant and policy identity; never the validated audience.
    ///
    /// The audience string can carry deployment topology a log reader should
    /// not automatically receive, so it stays behind the typed accessors.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OAuth {
                audience_policy_id,
                audience_policy_revision,
                ..
            } => formatter
                .debug_struct("VerifiedAudienceBinding::OAuth")
                .field("audience_policy_id", audience_policy_id)
                .field("audience_policy_revision", audience_policy_revision)
                .finish_non_exhaustive(),
            Self::MutualTlsPeer => formatter.write_str("VerifiedAudienceBinding::MutualTlsPeer"),
            Self::StaticCredential => {
                formatter.write_str("VerifiedAudienceBinding::StaticCredential")
            }
        }
    }
}

// ===========================================================================
// Verified ingress authentication facts
// ===========================================================================

/// The bounded verified identity an ingress authenticator produced.
///
/// # What constructing one asserts
///
/// Building this value asserts that a provider *verified* every field. The
/// type cannot police that on its own — a provider is the thing that decides
/// what verified means — so the enforcement lives one level up: only facts
/// returned from a registered `IngressAuthenticator` are admitted into the
/// opaque `AuthenticatedTransportIngress` that downstream code consumes. A
/// caller who constructs this directly holds a value no framework entrypoint
/// will accept.
///
/// Deliberately not `Serialize`: these facts name a principal, and a type that
/// can be written to a log or a cache by default will be.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedIngressAuthentication {
    provider: String,
    configuration_generation: u64,
    issuer: String,
    canonical_resource: String,
    verified_audience_binding: VerifiedAudienceBinding,
    tenant: String,
    subject_or_principal: String,
    authorized_party_or_client: String,
    verified_claims: Vec<(String, String)>,
    auth_policy_revision: u64,
    trust_generation: u64,
}

impl VerifiedIngressAuthentication {
    /// Records verified provider output.
    ///
    /// `verified_claims` are normalized to a deterministic order so two
    /// authenticators that verified the same claim set produce byte-identical
    /// canonical bytes regardless of the order they happened to emit them in.
    /// Admission bounds the original claim list, including duplicates, before
    /// cloning the identity. OAuth binding facts must name the same resource,
    /// provider, and configuration generation as the enclosing identity.
    /// The validated audience may differ from the resource when the provider's
    /// accepted-audience policy explicitly permits that alias.
    ///
    /// # Errors
    ///
    /// Returns [`IngressFactsError::KeyIdEmpty`] when any required identity
    /// field is empty. An empty identity field is not a benign default: it
    /// would let two distinct principals derive one partition.
    /// Oversized fields, claim counts, and aggregate input return their fixed
    /// bound errors. Empty claim names return
    /// [`IngressFactsError::InvalidVerifiedClaim`]; incomplete or contradictory
    /// OAuth facts return [`IngressFactsError::InvalidAudienceBinding`].
    pub fn from_verified_provider_output(
        facts: VerifiedIdentityFacts<'_>,
    ) -> Result<Self, IngressFactsError> {
        if facts.verified_claims.len() > MAX_VERIFIED_IDENTITY_CLAIMS {
            return Err(IngressFactsError::TooManyVerifiedClaims);
        }
        let mut identity_bytes = 0;
        for field in [
            facts.provider,
            facts.issuer,
            facts.canonical_resource,
            facts.tenant,
            facts.subject_or_principal,
            facts.authorized_party_or_client,
        ] {
            if field.is_empty() {
                return Err(IngressFactsError::KeyIdEmpty);
            }
            charge_identity_field(field, &mut identity_bytes)?;
        }

        if let VerifiedAudienceBinding::OAuth {
            canonical_resource,
            validated_audience,
            audience_policy_id,
            provider,
            configuration_generation,
            ..
        } = &facts.verified_audience_binding
        {
            for field in [
                canonical_resource,
                validated_audience,
                audience_policy_id,
                provider,
            ] {
                if field.is_empty() {
                    return Err(IngressFactsError::InvalidAudienceBinding);
                }
                charge_identity_field(field, &mut identity_bytes)?;
            }
            if canonical_resource.as_str() != facts.canonical_resource
                || provider.as_str() != facts.provider
                || *configuration_generation != facts.configuration_generation
            {
                return Err(IngressFactsError::InvalidAudienceBinding);
            }
        }

        for (name, value) in facts.verified_claims {
            if name.is_empty() {
                return Err(IngressFactsError::InvalidVerifiedClaim);
            }
            charge_identity_field(name, &mut identity_bytes)?;
            charge_identity_field(value, &mut identity_bytes)?;
        }

        let mut verified_claims: Vec<(String, String)> = facts
            .verified_claims
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        verified_claims.sort();
        verified_claims.dedup();

        Ok(Self {
            provider: facts.provider.to_owned(),
            configuration_generation: facts.configuration_generation,
            issuer: facts.issuer.to_owned(),
            canonical_resource: facts.canonical_resource.to_owned(),
            verified_audience_binding: facts.verified_audience_binding,
            tenant: facts.tenant.to_owned(),
            subject_or_principal: facts.subject_or_principal.to_owned(),
            authorized_party_or_client: facts.authorized_party_or_client.to_owned(),
            verified_claims,
            auth_policy_revision: facts.auth_policy_revision,
            trust_generation: facts.trust_generation,
        })
    }

    /// The verifying provider.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// The provider configuration generation these facts were verified under.
    #[must_use]
    pub const fn configuration_generation(&self) -> u64 {
        self.configuration_generation
    }

    /// The verified issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The canonical resource the principal was verified against.
    #[must_use]
    pub fn canonical_resource(&self) -> &str {
        &self.canonical_resource
    }

    /// The verified audience binding.
    #[must_use]
    pub const fn verified_audience_binding(&self) -> &VerifiedAudienceBinding {
        &self.verified_audience_binding
    }

    /// The verified tenant.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The verified subject or principal.
    #[must_use]
    pub fn subject_or_principal(&self) -> &str {
        &self.subject_or_principal
    }

    /// The verified authorized party or client.
    #[must_use]
    pub fn authorized_party_or_client(&self) -> &str {
        &self.authorized_party_or_client
    }

    /// The verified claims, in deterministic order.
    #[must_use]
    pub fn verified_claims(&self) -> &[(String, String)] {
        &self.verified_claims
    }

    /// The authorization-policy revision in force at verification.
    #[must_use]
    pub const fn auth_policy_revision(&self) -> u64 {
        self.auth_policy_revision
    }

    /// The trust generation in force at verification.
    #[must_use]
    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation
    }
}

fn charge_identity_field(field: &str, total: &mut usize) -> Result<(), IngressFactsError> {
    if field.len() > MAX_VERIFIED_IDENTITY_FIELD_BYTES {
        return Err(IngressFactsError::IdentityFieldTooLong);
    }
    *total = total
        .checked_add(field.len())
        .ok_or(IngressFactsError::IdentityTooLarge)?;
    if *total > MAX_VERIFIED_IDENTITY_BYTES {
        return Err(IngressFactsError::IdentityTooLarge);
    }
    Ok(())
}

impl fmt::Debug for VerifiedIngressAuthentication {
    /// Names the provider and generations; never the principal.
    ///
    /// Subject, tenant, client, issuer and claims identify a specific human or
    /// workload. A `Debug` that prints them turns any incidental log line into
    /// an identity disclosure, so they are reachable only through the typed
    /// accessors a caller had to deliberately choose.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedIngressAuthentication")
            .field("provider", &self.provider)
            .field("configuration_generation", &self.configuration_generation)
            .field("auth_policy_revision", &self.auth_policy_revision)
            .field("trust_generation", &self.trust_generation)
            .field("verified_claim_count", &self.verified_claims.len())
            .finish_non_exhaustive()
    }
}

/// Borrowed verified identity fields, passed to
/// [`VerifiedIngressAuthentication::from_verified_provider_output`].
///
/// A struct rather than eleven positional parameters: at this arity a
/// positional call is one transposition away from swapping tenant and subject,
/// and that transposition would be a cross-tenant identity bug that still
/// compiles.
#[derive(Clone)]
pub struct VerifiedIdentityFacts<'a> {
    /// The verifying provider.
    pub provider: &'a str,
    /// Provider configuration generation.
    pub configuration_generation: u64,
    /// Verified issuer.
    pub issuer: &'a str,
    /// Canonical resource verified against.
    pub canonical_resource: &'a str,
    /// Verified audience binding.
    pub verified_audience_binding: VerifiedAudienceBinding,
    /// Verified tenant.
    pub tenant: &'a str,
    /// Verified subject or principal.
    pub subject_or_principal: &'a str,
    /// Verified authorized party or client.
    pub authorized_party_or_client: &'a str,
    /// Verified claims as name/value pairs.
    pub verified_claims: &'a [(&'a str, &'a str)],
    /// Authorization-policy revision.
    pub auth_policy_revision: u64,
    /// Trust generation.
    pub trust_generation: u64,
}

impl fmt::Debug for VerifiedIdentityFacts<'_> {
    /// Provider inputs are not yet admitted: redact all strings, including
    /// the provider and audience-policy identifiers, not only the subject.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedIdentityFacts")
            .field("configuration_generation", &self.configuration_generation)
            .field("auth_policy_revision", &self.auth_policy_revision)
            .field("trust_generation", &self.trust_generation)
            .field("verified_claim_count", &self.verified_claims.len())
            .finish_non_exhaustive()
    }
}

// ===========================================================================
// Security partition descriptor
// ===========================================================================

/// The immutable verified descriptor every partition key is derived from.
///
/// Derived **only** from [`VerifiedIngressAuthentication`] — there is no
/// constructor taking loose strings, so a descriptor cannot be assembled from
/// request fields or self-reported claims. Its identity digest binds all
/// twelve verified identity facts, including the audience binding and policy
/// identity, so two principals differing in any one of them are different
/// partitions.
///
/// This is AUTH-00 A's type. [`crate::partition::PartitionDescriptor`] is
/// AUTH-00 B's admission input; [`Self::to_partition_descriptor`] is the
/// production path between them.
#[derive(Clone, PartialEq, Eq)]
pub struct SecurityPartitionDescriptor {
    facts: VerifiedIngressAuthentication,
    identity: [u8; 32],
}

impl SecurityPartitionDescriptor {
    /// Derives the descriptor from verified ingress authentication.
    #[must_use]
    pub fn from_verified_ingress(facts: &VerifiedIngressAuthentication) -> Self {
        // Length-prefixed, domain-separated, and inclusive of every identity
        // fact. Omitting a field here would silently merge two principals that
        // differ only in that field into one partition.
        let mut parts: Vec<Vec<u8>> = vec![
            b"auth-00-security-partition-descriptor-v1".to_vec(),
            facts.provider.as_bytes().to_vec(),
            facts.configuration_generation.to_be_bytes().to_vec(),
            facts.issuer.as_bytes().to_vec(),
            facts.canonical_resource.as_bytes().to_vec(),
            facts.tenant.as_bytes().to_vec(),
            facts.subject_or_principal.as_bytes().to_vec(),
            facts.authorized_party_or_client.as_bytes().to_vec(),
            facts.auth_policy_revision.to_be_bytes().to_vec(),
            facts.trust_generation.to_be_bytes().to_vec(),
        ];
        parts.extend(facts.verified_audience_binding.canonical_parts());
        // Claims are already sorted and deduplicated at fact construction.
        parts.push((facts.verified_claims.len() as u64).to_be_bytes().to_vec());
        for (name, value) in &facts.verified_claims {
            parts.push(name.as_bytes().to_vec());
            parts.push(value.as_bytes().to_vec());
        }

        let borrowed: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        Self {
            facts: facts.clone(),
            identity: crate::limits::opaque_admission_digest(&borrowed),
        }
    }

    /// The verified facts this descriptor was derived from.
    #[must_use]
    pub const fn verified_ingress(&self) -> &VerifiedIngressAuthentication {
        &self.facts
    }

    /// The opaque identity digest binding every verified fact.
    #[must_use]
    pub const fn identity(&self) -> &[u8; 32] {
        &self.identity
    }

    /// Projects this descriptor onto AUTH-00 B's admission input.
    ///
    /// The audience binding crosses the seam **structurally**, as its
    /// discriminant-led canonical parts, rather than collapsed into a single
    /// revision number. An earlier version projected a `u64` and reserved
    /// sentinels for the non-OAuth variants; that worked, but it made a
    /// cross-principal cache collision depend on two modules keeping a
    /// convention neither type expressed, and it left an OAuth deployment
    /// whose revision reached `u64::MAX` aliasing mutual TLS. B validates the
    /// binding parts like any other sealed field, so a caller who omits them
    /// now gets `EmptyField` instead of a silent merge.
    ///
    /// `auth_policy_revision` crosses too. Without it, revising the
    /// authorization policy — tightening required grants, say — would leave
    /// every record cached under the old policy still reachable, which is the
    /// exact failure `PartitionAuthorization` exists to prevent.
    ///
    /// `verified_claims` is deliberately **not** projected, and that is a
    /// decision rather than an omission: claims change on ordinary token
    /// rotation, so binding them into admission identity would relocate every
    /// partition on each refresh and cost a principal their own continuation
    /// records. They stay bound in [`Self::identity`], which is A's full
    /// twelve-fact identity.
    ///
    /// This is the only production path from verified ingress to an admission
    /// descriptor.
    ///
    /// # Errors
    ///
    /// Propagates [`crate::limits::SealedAdmissionKeyError`] when a verified
    /// field is empty or outside the sealed-key bound.
    pub fn to_partition_descriptor(
        &self,
    ) -> Result<crate::partition::PartitionDescriptor, crate::limits::SealedAdmissionKeyError> {
        let binding = self.facts.verified_audience_binding.canonical_parts();
        let binding_parts: Vec<&[u8]> = binding.iter().map(Vec::as_slice).collect();
        crate::partition::PartitionDescriptor::from_verified_facts(
            &self.facts.provider,
            self.facts.configuration_generation,
            &self.facts.issuer,
            &self.facts.canonical_resource,
            &self.facts.tenant,
            &self.facts.subject_or_principal,
            &self.facts.authorized_party_or_client,
            self.facts.trust_generation,
            self.facts.auth_policy_revision,
            &binding_parts,
        )
    }
}

impl fmt::Debug for SecurityPartitionDescriptor {
    /// Redacts every identity field; shows nothing but the type.
    ///
    /// Matches the redaction posture of AUTH-00 B's `PartitionDescriptor`, so
    /// neither side of the seam is the weak one.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecurityPartitionDescriptor")
            .finish_non_exhaustive()
    }
}

// ===========================================================================
// Rotation and revalidation facts
// ===========================================================================

/// A provider-owned reference that names a credential without carrying one.
///
/// The provider chooses the reference; the framework only compares and digests
/// it. It must not be a bearer value, and the type gives no way to recover one
/// — there is no accessor returning the raw reference, only its fingerprint.
#[derive(Clone)]
pub struct SealedProviderReference {
    fingerprint: SecretFingerprint,
}

impl SealedProviderReference {
    /// Seals a provider reference behind its fingerprint.
    ///
    /// # Errors
    ///
    /// Propagates [`SecretFingerprint::derive`] failures.
    pub fn seal(
        key_id: &str,
        generation: u64,
        key: &HmacSha256Key,
        reference: &[u8],
    ) -> Result<Self, IngressFactsError> {
        Ok(Self {
            fingerprint: SecretFingerprint::derive(key_id, generation, key, reference)?,
        })
    }

    /// The fingerprint naming this reference.
    #[must_use]
    pub const fn fingerprint(&self) -> &SecretFingerprint {
        &self.fingerprint
    }

    /// Verifies in constant time that this reference names `reference`.
    ///
    /// # Errors
    ///
    /// See [`SecretFingerprint::verify_material`].
    pub fn verify_reference(
        &self,
        key: &HmacSha256Key,
        reference: &[u8],
    ) -> Result<(), IngressFactsError> {
        self.fingerprint.verify_material(key, reference)
    }
}

impl fmt::Debug for SealedProviderReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedProviderReference")
            .finish_non_exhaustive()
    }
}

/// Rotation and revalidation facts for an authorization that outlives ingress.
///
/// Deliberately not `Serialize`: a persisted revalidation fact is a stale
/// assertion the moment it is written, and the one legitimate durable form is
/// AUTH-00's separate durable-execution authorization, not this.
#[derive(Clone)]
pub struct AuthorizationRotationFacts {
    provider_reference: SealedProviderReference,
    token_instance: SealedProviderReference,
    required_grants: Vec<String>,
    trust_generation: u64,
    expiry: Duration,
    maximum_staleness: MaximumStaleness,
    dispatch: RevalidationDispatch,
}

impl AuthorizationRotationFacts {
    /// Records the rotation and revalidation state of one authorization.
    ///
    /// Required grants are sorted and deduplicated so an equal grant set
    /// compares and digests equal regardless of the order it arrived in.
    #[must_use]
    pub fn new(
        provider_reference: SealedProviderReference,
        token_instance: SealedProviderReference,
        required_grants: &[&str],
        trust_generation: u64,
        expiry: Duration,
        maximum_staleness: MaximumStaleness,
        dispatch: RevalidationDispatch,
    ) -> Self {
        let mut grants: Vec<String> = required_grants
            .iter()
            .map(|grant| (*grant).to_owned())
            .collect();
        grants.sort();
        grants.dedup();
        Self {
            provider_reference,
            token_instance,
            required_grants: grants,
            trust_generation,
            expiry,
            maximum_staleness,
            dispatch,
        }
    }

    /// The sealed provider reference.
    #[must_use]
    pub const fn provider_reference(&self) -> &SealedProviderReference {
        &self.provider_reference
    }

    /// The sealed token instance reference.
    #[must_use]
    pub const fn token_instance(&self) -> &SealedProviderReference {
        &self.token_instance
    }

    /// The required grants, in deterministic order.
    #[must_use]
    pub fn required_grants(&self) -> &[String] {
        &self.required_grants
    }

    /// The trust generation these facts were captured under.
    #[must_use]
    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation
    }

    /// Time remaining before the authorization expires.
    #[must_use]
    pub const fn expiry(&self) -> Duration {
        self.expiry
    }

    /// The configured maximum staleness bound.
    #[must_use]
    pub const fn maximum_staleness(&self) -> MaximumStaleness {
        self.maximum_staleness
    }

    /// Whether the last revalidation attempt reached the provider.
    #[must_use]
    pub const fn dispatch(&self) -> RevalidationDispatch {
        self.dispatch
    }

    /// Whether these facts may still be relied on after `elapsed`.
    ///
    /// Fails closed on [`RevalidationDispatch::Unknown`]: an attempt that may
    /// or may not have reached the provider has not established freshness, and
    /// treating it as if it had is how a revoked authorization keeps working.
    /// Token expiry is an independent, exclusive deadline: a fresh provider
    /// verdict must never extend a shorter token lifetime, and a zero-lifetime
    /// authorization is already expired even at `elapsed == Duration::ZERO`.
    #[must_use]
    pub fn is_fresh_after(&self, elapsed: Duration) -> bool {
        match self.dispatch {
            RevalidationDispatch::Dispatched => {
                elapsed < self.expiry && elapsed <= self.maximum_staleness.bound()
            }
            RevalidationDispatch::NotDispatched | RevalidationDispatch::Unknown => false,
        }
    }
}

impl fmt::Debug for AuthorizationRotationFacts {
    /// Shows generations, counts and dispatch; never a reference or grant.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRotationFacts")
            .field("trust_generation", &self.trust_generation)
            .field("required_grant_count", &self.required_grants.len())
            .field("maximum_staleness", &self.maximum_staleness)
            .field("dispatch", &self.dispatch)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HMAC_SHA256_KEY_BYTES;

    fn identity<'a>(claims: &'a [(&'a str, &'a str)]) -> VerifiedIdentityFacts<'a> {
        VerifiedIdentityFacts {
            provider: "provider",
            configuration_generation: 7,
            issuer: "https://issuer.example",
            canonical_resource: "https://resource.example/mcp",
            verified_audience_binding: VerifiedAudienceBinding::OAuth {
                canonical_resource: "https://resource.example/mcp".to_owned(),
                validated_audience: "urn:approved-resource-alias".to_owned(),
                audience_policy_id: "accepted-audiences".to_owned(),
                audience_policy_revision: 3,
                provider: "provider".to_owned(),
                configuration_generation: 7,
            },
            tenant: "tenant",
            subject_or_principal: "subject",
            authorized_party_or_client: "client",
            verified_claims: claims,
            auth_policy_revision: 11,
            trust_generation: 13,
        }
    }

    #[test]
    fn admitted_claim_normalization_preserves_partition_identity() {
        let first = VerifiedIngressAuthentication::from_verified_provider_output(identity(&[
            ("scope", "write"),
            ("scope", "read"),
            ("scope", "write"),
        ]))
        .unwrap();
        let second = VerifiedIngressAuthentication::from_verified_provider_output(identity(&[
            ("scope", "read"),
            ("scope", "write"),
        ]))
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.verified_claims().len(), 2);
        assert_eq!(
            SecurityPartitionDescriptor::from_verified_ingress(&first).identity(),
            SecurityPartitionDescriptor::from_verified_ingress(&second).identity()
        );
    }

    #[test]
    fn identity_fields_admit_exact_byte_bounds_and_reject_one_byte_more() {
        let boundary = "x".repeat(MAX_VERIFIED_IDENTITY_FIELD_BYTES);
        let oversized = format!("{boundary}x");
        for index in 0..6 {
            for (value, accepted) in [(boundary.as_str(), true), (oversized.as_str(), false)] {
                let mut facts = identity(&[]);
                facts.verified_audience_binding = VerifiedAudienceBinding::StaticCredential;
                match index {
                    0 => facts.provider = value,
                    1 => facts.issuer = value,
                    2 => facts.canonical_resource = value,
                    3 => facts.tenant = value,
                    4 => facts.subject_or_principal = value,
                    _ => facts.authorized_party_or_client = value,
                }
                let result = VerifiedIngressAuthentication::from_verified_provider_output(facts);
                if accepted {
                    assert!(result.is_ok(), "field {index}");
                } else {
                    assert_eq!(result, Err(IngressFactsError::IdentityFieldTooLong));
                }
            }
        }
        let unicode = "é".repeat(MAX_VERIFIED_IDENTITY_FIELD_BYTES / 2 + 1);
        let mut facts = identity(&[]);
        facts.subject_or_principal = &unicode;
        assert_eq!(
            VerifiedIngressAuthentication::from_verified_provider_output(facts),
            Err(IngressFactsError::IdentityFieldTooLong)
        );
    }

    #[test]
    fn claim_limits_apply_before_deduplication_and_include_names_and_values() {
        let claims = vec![("scope", "read"); MAX_VERIFIED_IDENTITY_CLAIMS];
        let admitted =
            VerifiedIngressAuthentication::from_verified_provider_output(identity(&claims)).unwrap();
        assert_eq!(admitted.verified_claims().len(), 1);
        let mut too_many = claims;
        too_many.push(("scope", "read"));
        assert_eq!(
            VerifiedIngressAuthentication::from_verified_provider_output(identity(&too_many)),
            Err(IngressFactsError::TooManyVerifiedClaims)
        );

        let boundary = "x".repeat(MAX_VERIFIED_IDENTITY_FIELD_BYTES);
        let oversized = format!("{boundary}x");
        for pair in [(boundary.as_str(), ""), ("scope", boundary.as_str())] {
            assert!(
                VerifiedIngressAuthentication::from_verified_provider_output(identity(&[pair]))
                    .is_ok()
            );
        }
        for pair in [(oversized.as_str(), ""), ("scope", oversized.as_str())] {
            assert_eq!(
                VerifiedIngressAuthentication::from_verified_provider_output(identity(&[pair])),
                Err(IngressFactsError::IdentityFieldTooLong)
            );
        }
        assert_eq!(
            VerifiedIngressAuthentication::from_verified_provider_output(identity(&[("", "value")])),
            Err(IngressFactsError::InvalidVerifiedClaim)
        );
    }

    #[test]
    fn aggregate_identity_budget_counts_duplicate_claims_before_allocation() {
        let mut values = vec!["v".repeat(MAX_VERIFIED_IDENTITY_FIELD_BYTES); 7];
        // Six one-byte identity fields plus eight one-byte claim names.
        let last = MAX_VERIFIED_IDENTITY_BYTES - 14 - 7 * MAX_VERIFIED_IDENTITY_FIELD_BYTES;
        values.push("v".repeat(last));
        for accepted in [true, false] {
            let claims: Vec<(&str, &str)> =
                values.iter().map(|value| ("k", value.as_str())).collect();
            let mut facts = identity(&claims);
            facts.provider = "p";
            facts.issuer = "i";
            facts.canonical_resource = "r";
            facts.tenant = "t";
            facts.subject_or_principal = "s";
            facts.authorized_party_or_client = "c";
            facts.verified_audience_binding = VerifiedAudienceBinding::StaticCredential;
            let result = VerifiedIngressAuthentication::from_verified_provider_output(facts);
            if accepted {
                assert!(result.is_ok());
            } else {
                assert_eq!(result, Err(IngressFactsError::IdentityTooLarge));
            }
            values[7].push('v');
        }
    }

    #[test]
    fn oauth_binding_rejects_each_contradiction_without_rejecting_approved_aliases() {
        assert!(VerifiedIngressAuthentication::from_verified_provider_output(identity(&[])).is_ok());
        for mutation in 0..5 {
            let mut facts = identity(&[]);
            let VerifiedAudienceBinding::OAuth {
                canonical_resource,
                validated_audience,
                audience_policy_id,
                provider,
                configuration_generation,
                ..
            } = &mut facts.verified_audience_binding
            else {
                panic!("OAuth fixture");
            };
            match mutation {
                0 => canonical_resource.push_str("/other"),
                1 => provider.push_str("-other"),
                2 => *configuration_generation += 1,
                3 => validated_audience.clear(),
                _ => audience_policy_id.clear(),
            }
            assert_eq!(
                VerifiedIngressAuthentication::from_verified_provider_output(facts),
                Err(IngressFactsError::InvalidAudienceBinding)
            );
        }
        for binding in [
            VerifiedAudienceBinding::MutualTlsPeer,
            VerifiedAudienceBinding::StaticCredential,
        ] {
            let mut facts = identity(&[]);
            facts.verified_audience_binding = binding;
            assert!(VerifiedIngressAuthentication::from_verified_provider_output(facts).is_ok());
        }
    }

    #[test]
    fn oauth_audience_and_policy_strings_are_bounded() {
        for policy in [false, true] {
            let mut facts = identity(&[]);
            let VerifiedAudienceBinding::OAuth {
                validated_audience,
                audience_policy_id,
                ..
            } = &mut facts.verified_audience_binding
            else {
                panic!("OAuth fixture");
            };
            let field = if policy {
                audience_policy_id
            } else {
                validated_audience
            };
            *field = "x".repeat(MAX_VERIFIED_IDENTITY_FIELD_BYTES);
            assert!(
                VerifiedIngressAuthentication::from_verified_provider_output(facts.clone()).is_ok()
            );
            let VerifiedAudienceBinding::OAuth {
                validated_audience,
                audience_policy_id,
                ..
            } = &mut facts.verified_audience_binding
            else {
                panic!("OAuth fixture");
            };
            let field = if policy {
                audience_policy_id
            } else {
                validated_audience
            };
            field.push('x');
            assert_eq!(
                VerifiedIngressAuthentication::from_verified_provider_output(facts),
                Err(IngressFactsError::IdentityFieldTooLong)
            );
        }
    }

    #[test]
    fn borrowed_identity_debug_redacts_even_unadmitted_provider_input() {
        let canary = "IDENTITY-SECRET-CANARY";
        let claims = [(canary, canary)];
        let mut facts = identity(&claims);
        facts.provider = canary;
        facts.issuer = canary;
        facts.canonical_resource = canary;
        facts.tenant = canary;
        facts.subject_or_principal = canary;
        facts.authorized_party_or_client = canary;
        facts.verified_audience_binding = VerifiedAudienceBinding::OAuth {
            canonical_resource: canary.to_owned(),
            validated_audience: canary.to_owned(),
            audience_policy_id: canary.to_owned(),
            audience_policy_revision: 1,
            provider: canary.to_owned(),
            configuration_generation: 7,
        };
        let diagnostic = format!("{facts:?}");
        assert!(!diagnostic.contains(canary));
        assert!(diagnostic.contains("verified_claim_count: 1"));
    }

    fn rotation(expiry: Duration, dispatch: RevalidationDispatch) -> AuthorizationRotationFacts {
        let key = HmacSha256Key::from_bytes([42; HMAC_SHA256_KEY_BYTES]);
        let provider = SealedProviderReference::seal("test-key", 1, &key, b"provider").unwrap();
        let token = SealedProviderReference::seal("test-key", 1, &key, b"token").unwrap();
        AuthorizationRotationFacts::new(
            provider,
            token,
            &["mcp.read"],
            1,
            expiry,
            MaximumStaleness::default(),
            dispatch,
        )
    }

    #[test]
    fn authorization_expiry_is_independent_of_revalidation_staleness() {
        let expiry = Duration::from_secs(5);
        let facts = rotation(expiry, RevalidationDispatch::Dispatched);
        assert!(facts.is_fresh_after(expiry - Duration::from_nanos(1)));
        assert!(!facts.is_fresh_after(expiry));
        assert!(!facts.is_fresh_after(expiry + Duration::from_nanos(1)));
        assert!(
            !rotation(Duration::ZERO, RevalidationDispatch::Dispatched)
                .is_fresh_after(Duration::ZERO)
        );

        let long_lived = rotation(Duration::from_secs(600), RevalidationDispatch::Dispatched);
        assert!(long_lived.is_fresh_after(DEFAULT_MAXIMUM_STALENESS));
        assert!(!long_lived.is_fresh_after(DEFAULT_MAXIMUM_STALENESS + Duration::from_nanos(1)));
        assert!(!long_lived.is_fresh_after(Duration::MAX));
        for dispatch in [
            RevalidationDispatch::Unknown,
            RevalidationDispatch::NotDispatched,
        ] {
            assert!(!rotation(Duration::from_secs(600), dispatch).is_fresh_after(Duration::ZERO));
        }
    }
}
