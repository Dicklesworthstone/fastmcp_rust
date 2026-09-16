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
pub const HARD_MAXIMUM_STALENESS: Duration = Duration::from_secs(5 * 60);

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
    /// A configured maximum staleness exceeded [`HARD_MAXIMUM_STALENESS`].
    MaximumStalenessAboveCeiling,
    /// A configured maximum staleness was zero, which no provider can satisfy.
    MaximumStalenessZero,
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
            Self::MaximumStalenessAboveCeiling => write!(
                formatter,
                "configured maximum staleness exceeds the {}s hard ceiling",
                HARD_MAXIMUM_STALENESS.as_secs()
            ),
            Self::MaximumStalenessZero => {
                formatter.write_str("configured maximum staleness must be nonzero")
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
#[derive(Clone, PartialEq, Eq)]
pub struct SecretFingerprint {
    key_id: String,
    generation: u64,
    tag: HmacSha256Tag,
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

        // Length-prefix every part so no two distinct field splittings can
        // produce the same preimage.
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
    #[must_use]
    pub const fn tag(&self) -> &[u8; SECRET_FINGERPRINT_TAG_BYTES] {
        self.tag.as_bytes()
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
    pub const fn domain(self) -> &'static [u8] {
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
