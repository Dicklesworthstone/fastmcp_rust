//! Wire-neutral cryptographic primitives.
//!
//! This module centralizes the small cryptographic surface shared by the
//! FastMCP crates:
//!
//! - bounded SHA-256;
//! - fixed-key, full-tag HMAC-SHA-256; and
//! - fallible, purpose-specific operating-system random draws.
//!
//! Callers remain responsible for constructing canonical input bytes and
//! selecting fixed, audited input limits. This module does not serialize or
//! canonicalize higher-level values.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Width of a SHA-256 digest in bytes.
pub const SHA256_DIGEST_BYTES: usize = 32;

/// Required width of a built-in HMAC-SHA-256 key in bytes.
pub const HMAC_SHA256_KEY_BYTES: usize = 32;

/// Width of a full HMAC-SHA-256 tag in bytes.
pub const HMAC_SHA256_TAG_BYTES: usize = 32;

/// Width of a framework security-identifier draw in bytes.
pub const SECURITY_IDENTIFIER_BYTES: usize = 32;

/// Width of an ephemeral-key-material draw in bytes.
pub const EPHEMERAL_KEY_MATERIAL_BYTES: usize = 32;

/// Width of a nonce-domain-material draw in bytes.
pub const NONCE_DOMAIN_MATERIAL_BYTES: usize = 16;

/// Width of a WebSocket masking-key draw in bytes.
pub const WEBSOCKET_MASK_BYTES: usize = 4;

/// Error returned when a cryptographic input exceeds its caller-owned bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoInputTooLongError {
    /// Actual input width in bytes.
    pub input_bytes: usize,
    /// Maximum admitted input width in bytes.
    pub max_input_bytes: usize,
}

impl fmt::Display for CryptoInputTooLongError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cryptographic input is {} bytes, exceeding the {}-byte limit",
            self.input_bytes, self.max_input_bytes
        )
    }
}

impl std::error::Error for CryptoInputTooLongError {}

/// Error returned when the operating-system random source fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomDrawError {
    source: getrandom::Error,
}

impl RandomDrawError {
    fn new(source: getrandom::Error) -> Self {
        Self { source }
    }
}

impl fmt::Display for RandomDrawError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cryptographic random draw failed: {}", self.source)
    }
}

impl std::error::Error for RandomDrawError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Error returned when bounded HMAC-SHA-256 verification fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacVerificationError {
    /// The authenticated input exceeded its caller-owned bound.
    InputTooLong(CryptoInputTooLongError),
    /// The full 32-byte authentication tag did not match.
    TagMismatch,
}

impl fmt::Display for HmacVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong(error) => error.fmt(f),
            Self::TagMismatch => f.write_str("HMAC-SHA-256 authentication failed"),
        }
    }
}

impl std::error::Error for HmacVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InputTooLong(error) => Some(error),
            Self::TagMismatch => None,
        }
    }
}

impl From<CryptoInputTooLongError> for HmacVerificationError {
    fn from(error: CryptoInputTooLongError) -> Self {
        Self::InputTooLong(error)
    }
}

/// A typed, fixed-width SHA-256 digest.
///
/// Its sole core encoding is the exact `[u8; 32]` binary representation
/// exposed by [`Self::from_bytes`], [`Self::as_bytes`], and
/// [`Self::into_bytes`]. Textual or protocol-specific encodings belong to the
/// caller.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest {
    bytes: [u8; SHA256_DIGEST_BYTES],
}

impl Sha256Digest {
    /// Constructs a digest from its exact 32-byte representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SHA256_DIGEST_BYTES]) -> Self {
        Self { bytes }
    }

    /// Borrows the exact 32-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHA256_DIGEST_BYTES] {
        &self.bytes
    }

    /// Returns the exact 32-byte representation.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; SHA256_DIGEST_BYTES] {
        self.bytes
    }
}

/// Computes SHA-256 after enforcing a caller-owned byte limit.
///
/// The length check occurs before the SHA-256 implementation receives the
/// input. Callers must supply a fixed, audited limit appropriate to their
/// canonical input.
pub fn sha256_bounded(
    input: &[u8],
    max_input_bytes: usize,
) -> Result<Sha256Digest, CryptoInputTooLongError> {
    sha256_bounded_with(input, max_input_bytes, sha256_exact)
}

fn sha256_bounded_with<F>(
    input: &[u8],
    max_input_bytes: usize,
    hash: F,
) -> Result<Sha256Digest, CryptoInputTooLongError>
where
    F: FnOnce(&[u8]) -> Sha256Digest,
{
    enforce_input_limit(input, max_input_bytes)?;
    Ok(hash(input))
}

fn sha256_exact(input: &[u8]) -> Sha256Digest {
    let output = Sha256::digest(input);
    let mut bytes = [0_u8; SHA256_DIGEST_BYTES];
    bytes.copy_from_slice(&output);
    Sha256Digest::from_bytes(bytes)
}

fn enforce_input_limit(
    input: &[u8],
    max_input_bytes: usize,
) -> Result<(), CryptoInputTooLongError> {
    if input.len() > max_input_bytes {
        return Err(CryptoInputTooLongError {
            input_bytes: input.len(),
            max_input_bytes,
        });
    }

    Ok(())
}

type HmacSha256 = Hmac<Sha256>;

/// A sealed, exactly 256-bit HMAC-SHA-256 key.
///
/// The key has no byte accessor, equality implementation, serialization
/// implementation, or algorithm selector. Its storage is zeroized on drop.
///
/// This is a wire-neutral foundation primitive, not a universal keyed-state
/// service or a purpose registry. A higher-layer facade must assign one key
/// instance to one fixed purpose, construct that purpose's canonical framing,
/// and enforce its audited bound. In particular, AUTH-00's later
/// `MacAuthenticator` and its purpose-specific APIs own domain separation,
/// key identity and rotation; they wrap this primitive rather than exposing it
/// as their public domain API.
#[repr(transparent)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HmacSha256Key {
    bytes: [u8; HMAC_SHA256_KEY_BYTES],
}

impl HmacSha256Key {
    /// Constructs a key from an exact 32-byte representation.
    ///
    /// The importing facade remains responsible for assigning the key to one
    /// fixed purpose and preventing cross-purpose reuse.
    #[must_use]
    pub fn from_bytes(bytes: [u8; HMAC_SHA256_KEY_BYTES]) -> Self {
        Self { bytes }
    }

    /// Computes a full HMAC-SHA-256 tag after enforcing an input limit.
    ///
    /// This low-level operation must be called behind a higher-layer facade
    /// that fixes the purpose, canonical framing, key custody, and bound.
    pub fn authenticate_bounded(
        &self,
        input: &[u8],
        max_input_bytes: usize,
    ) -> Result<HmacSha256Tag, CryptoInputTooLongError> {
        enforce_input_limit(input, max_input_bytes)?;

        let mut mac = self.new_mac();
        mac.update(input);
        let output = mac.finalize().into_bytes();
        let mut bytes = [0_u8; HMAC_SHA256_TAG_BYTES];
        bytes.copy_from_slice(&output);
        Ok(HmacSha256Tag::from_bytes(bytes))
    }

    /// Verifies a full HMAC-SHA-256 tag in constant time.
    ///
    /// The input limit is checked before HMAC work. Tag comparison is delegated
    /// exclusively to [`Mac::verify_slice`], whose fixed-output implementation
    /// rejects non-full-length inputs and performs constant-time equality.
    /// This low-level operation has the same fixed-purpose facade requirement
    /// as [`Self::authenticate_bounded`].
    pub fn verify_bounded(
        &self,
        input: &[u8],
        max_input_bytes: usize,
        tag: &HmacSha256Tag,
    ) -> Result<(), HmacVerificationError> {
        enforce_input_limit(input, max_input_bytes)?;

        let mut mac = self.new_mac();
        mac.update(input);
        mac.verify_slice(tag.as_bytes())
            .map_err(|_| HmacVerificationError::TagMismatch)
    }

    fn new_mac(&self) -> HmacSha256 {
        <HmacSha256 as KeyInit>::new_from_slice(&self.bytes)
            .expect("HMAC-SHA-256 accepts every fixed-width key")
    }
}

impl fmt::Debug for HmacSha256Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacSha256Key([redacted; 32 bytes])")
    }
}

/// A sealed, full-width HMAC-SHA-256 authentication tag.
///
/// This type intentionally has no equality implementation. Verification must
/// go through [`HmacSha256Key::verify_bounded`].
#[repr(transparent)]
pub struct HmacSha256Tag {
    bytes: [u8; HMAC_SHA256_TAG_BYTES],
}

impl HmacSha256Tag {
    /// Constructs a tag from its exact 32-byte representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HMAC_SHA256_TAG_BYTES]) -> Self {
        Self { bytes }
    }

    /// Borrows the exact, full-width tag representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HMAC_SHA256_TAG_BYTES] {
        &self.bytes
    }

    /// Returns the exact, full-width tag representation.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; HMAC_SHA256_TAG_BYTES] {
        self.bytes
    }
}

impl fmt::Debug for HmacSha256Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacSha256Tag([redacted; 32 bytes])")
    }
}

/// A purpose-specific 256-bit security-identifier draw.
///
/// The bytes are zeroized on drop and are not interchangeable with any other
/// random-purpose type. This is the FND-01 random category boundary, not a
/// protocol token type: each higher-layer domain wraps a fresh draw and owns
/// its textual encoding. HMAC keys, ephemeral keys, nonce domains, and
/// WebSocket masks cannot be produced through this API.
#[repr(transparent)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecurityIdentifier {
    bytes: [u8; SECURITY_IDENTIFIER_BYTES],
}

impl SecurityIdentifier {
    /// Borrows the exact 32-byte representation for caller-owned encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SECURITY_IDENTIFIER_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for SecurityIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityIdentifier([redacted; 32 bytes])")
    }
}

/// Purpose-specific 256-bit ephemeral key material.
///
/// The bytes are zeroized on drop and are not interchangeable with security
/// identifiers, nonce-domain material, HMAC keys, or WebSocket masks.
#[repr(transparent)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralKeyMaterial {
    bytes: [u8; EPHEMERAL_KEY_MATERIAL_BYTES],
}

impl EphemeralKeyMaterial {
    /// Borrows the exact 32-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; EPHEMERAL_KEY_MATERIAL_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for EphemeralKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EphemeralKeyMaterial([redacted; 32 bytes])")
    }
}

/// Purpose-specific 128-bit nonce-domain material.
///
/// This is a non-secret identifier intended to remain stable while its owning
/// higher-layer store combines it with checked per-use sequence values.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NonceDomainMaterial {
    bytes: [u8; NONCE_DOMAIN_MATERIAL_BYTES],
}

impl NonceDomainMaterial {
    /// Borrows the exact 16-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_DOMAIN_MATERIAL_BYTES] {
        &self.bytes
    }

    /// Returns the exact 16-byte representation.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; NONCE_DOMAIN_MATERIAL_BYTES] {
        self.bytes
    }
}

impl fmt::Debug for NonceDomainMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NonceDomainMaterial([redacted; 16 bytes])")
    }
}

/// Purpose-specific 32-bit WebSocket masking material.
///
/// This value is deliberately non-`Clone` and non-`Copy` to discourage
/// accidental reuse across frames.
#[repr(transparent)]
pub struct WebSocketMask {
    bytes: [u8; WEBSOCKET_MASK_BYTES],
}

impl WebSocketMask {
    /// Borrows the exact four-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; WEBSOCKET_MASK_BYTES] {
        &self.bytes
    }

    /// Returns the exact four-byte representation.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; WEBSOCKET_MASK_BYTES] {
        self.bytes
    }
}

impl fmt::Debug for WebSocketMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebSocketMask([redacted; 4 bytes])")
    }
}

trait RandomSource {
    fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error>;
}

#[derive(Debug, Clone, Copy)]
struct OsRandomSource;

impl RandomSource for OsRandomSource {
    fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error> {
        getrandom::fill(destination)
    }
}

fn draw_bytes<const N: usize>(source: &impl RandomSource) -> Result<[u8; N], RandomDrawError> {
    let mut bytes = [0_u8; N];
    if let Err(error) = source.fill(&mut bytes) {
        bytes.zeroize();
        return Err(RandomDrawError::new(error));
    }
    Ok(bytes)
}

/// Draws a fresh, exactly 256-bit HMAC-SHA-256 key.
///
/// This draw is for process-local ephemeral keyed state. Durable or
/// distributed keyed state requires a qualified, rotation-aware key provider.
pub fn draw_hmac_sha256_key() -> Result<HmacSha256Key, RandomDrawError> {
    draw_hmac_sha256_key_with(&OsRandomSource)
}

fn draw_hmac_sha256_key_with(source: &impl RandomSource) -> Result<HmacSha256Key, RandomDrawError> {
    draw_bytes(source).map(HmacSha256Key::from_bytes)
}

/// Draws a fresh, purpose-specific 256-bit security identifier.
pub fn draw_security_identifier() -> Result<SecurityIdentifier, RandomDrawError> {
    draw_security_identifier_with(&OsRandomSource)
}

fn draw_security_identifier_with(
    source: &impl RandomSource,
) -> Result<SecurityIdentifier, RandomDrawError> {
    draw_bytes(source).map(|bytes| SecurityIdentifier { bytes })
}

/// Draws fresh, purpose-specific 256-bit ephemeral key material.
pub fn draw_ephemeral_key_material() -> Result<EphemeralKeyMaterial, RandomDrawError> {
    draw_ephemeral_key_material_with(&OsRandomSource)
}

fn draw_ephemeral_key_material_with(
    source: &impl RandomSource,
) -> Result<EphemeralKeyMaterial, RandomDrawError> {
    draw_bytes(source).map(|bytes| EphemeralKeyMaterial { bytes })
}

/// Draws fresh, purpose-specific 128-bit nonce-domain material.
pub fn draw_nonce_domain_material() -> Result<NonceDomainMaterial, RandomDrawError> {
    draw_nonce_domain_material_with(&OsRandomSource)
}

fn draw_nonce_domain_material_with(
    source: &impl RandomSource,
) -> Result<NonceDomainMaterial, RandomDrawError> {
    draw_bytes(source).map(|bytes| NonceDomainMaterial { bytes })
}

/// Draws a fresh, purpose-specific four-byte WebSocket mask.
pub fn draw_websocket_mask() -> Result<WebSocketMask, RandomDrawError> {
    draw_websocket_mask_with(&OsRandomSource)
}

fn draw_websocket_mask_with(source: &impl RandomSource) -> Result<WebSocketMask, RandomDrawError> {
    draw_bytes(source).map(|bytes| WebSocketMask { bytes })
}

#[cfg(test)]
mod tests {
    use std::any::TypeId;
    use std::cell::Cell;
    use std::mem::{size_of, size_of_val};

    use super::*;

    const SHA256_EMPTY: [u8; SHA256_DIGEST_BYTES] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    const SHA256_ABC: [u8; SHA256_DIGEST_BYTES] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    struct FixedRandom {
        byte: u8,
        calls: Cell<usize>,
    }

    impl FixedRandom {
        fn new(byte: u8) -> Self {
            Self {
                byte,
                calls: Cell::new(0),
            }
        }
    }

    impl RandomSource for FixedRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error> {
            self.calls.set(self.calls.get() + 1);
            destination.fill(self.byte);
            Ok(())
        }
    }

    struct FailingRandom {
        calls: Cell<usize>,
    }

    impl FailingRandom {
        fn new() -> Self {
            Self {
                calls: Cell::new(0),
            }
        }
    }

    impl RandomSource for FailingRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error> {
            self.calls.set(self.calls.get() + 1);
            destination.fill(0xa5);
            Err(getrandom::Error::UNEXPECTED)
        }
    }

    #[test]
    fn sha256_matches_nist_empty_and_abc_vectors() {
        assert_eq!(
            sha256_bounded(b"", 0).expect("empty input is within the bound"),
            Sha256Digest::from_bytes(SHA256_EMPTY)
        );
        assert_eq!(
            sha256_bounded(b"abc", 3).expect("abc is within the bound"),
            Sha256Digest::from_bytes(SHA256_ABC)
        );
    }

    #[test]
    fn sha256_accepts_exact_limit_and_rejects_one_byte_over() {
        let at_limit = sha256_bounded(b"abc", 3).expect("exact limit must be admitted");
        assert_eq!(at_limit.as_bytes(), &SHA256_ABC);

        let error = sha256_bounded(b"abc", 2).expect_err("oversized input must be rejected");
        assert_eq!(
            error,
            CryptoInputTooLongError {
                input_bytes: 3,
                max_input_bytes: 2,
            }
        );
    }

    #[test]
    fn sha256_rejects_before_invoking_hash_implementation() {
        let hash_called = Cell::new(false);
        let result = sha256_bounded_with(b"too long", 3, |_| {
            hash_called.set(true);
            Sha256Digest::from_bytes([0_u8; SHA256_DIGEST_BYTES])
        });

        assert_eq!(
            result,
            Err(CryptoInputTooLongError {
                input_bytes: 8,
                max_input_bytes: 3,
            })
        );
        assert!(!hash_called.get());
    }

    #[test]
    fn sha256_fixed_width_bytes_round_trip() {
        let digest = Sha256Digest::from_bytes(SHA256_ABC);
        assert_eq!(digest.as_bytes(), &SHA256_ABC);
        assert_eq!(digest.into_bytes(), SHA256_ABC);
        assert_eq!(size_of::<Sha256Digest>(), SHA256_DIGEST_BYTES);
    }

    #[test]
    fn input_limit_error_is_actionable() {
        let error = CryptoInputTooLongError {
            input_bytes: 17,
            max_input_bytes: 16,
        };
        assert!(error.to_string().contains("17"));
        assert!(error.to_string().contains("16"));
        let _: &dyn std::error::Error = &error;
    }

    #[test]
    fn hmac_sha256_matches_nist_full_tag_vector() {
        // NIST HMAC-SHA-256 example, key length 32 and tag length 32:
        // https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/hmac_sha256.pdf
        let key = HmacSha256Key::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);
        let input = b"Sample message for keylen<blocklen";
        let expected = [
            0xa2, 0x8c, 0xf4, 0x31, 0x30, 0xee, 0x69, 0x6a, 0x98, 0xf1, 0x4a, 0x37, 0x67, 0x8b,
            0x56, 0xbc, 0xfc, 0xbd, 0xd9, 0xe5, 0xcf, 0x69, 0x71, 0x7f, 0xec, 0xf5, 0x48, 0x0f,
            0x0e, 0xbd, 0xf7, 0x90,
        ];

        let tag = key
            .authenticate_bounded(input, input.len())
            .expect("NIST input is within its exact bound");
        assert_eq!(tag.as_bytes(), &expected);
        assert_eq!(key.verify_bounded(input, input.len(), &tag), Ok(()));
    }

    #[test]
    fn hmac_verification_rejects_changed_message_and_full_tag() {
        let key = HmacSha256Key::from_bytes([0x42; HMAC_SHA256_KEY_BYTES]);
        let input = b"authenticated input";
        let tag = key
            .authenticate_bounded(input, input.len())
            .expect("input is within its exact bound");

        assert_eq!(
            key.verify_bounded(b"authenticated inpuu", input.len(), &tag),
            Err(HmacVerificationError::TagMismatch)
        );

        let mut changed_bytes = tag.into_bytes();
        changed_bytes[HMAC_SHA256_TAG_BYTES - 1] ^= 1;
        let changed_tag = HmacSha256Tag::from_bytes(changed_bytes);
        assert_eq!(
            key.verify_bounded(input, input.len(), &changed_tag),
            Err(HmacVerificationError::TagMismatch)
        );
    }

    #[test]
    fn hmac_enforces_input_limit_before_authentication() {
        let key = HmacSha256Key::from_bytes([0x24; HMAC_SHA256_KEY_BYTES]);
        let error = key
            .authenticate_bounded(b"four", 3)
            .expect_err("oversized input must be rejected");
        assert_eq!(
            error,
            CryptoInputTooLongError {
                input_bytes: 4,
                max_input_bytes: 3,
            }
        );

        let tag = HmacSha256Tag::from_bytes([0_u8; HMAC_SHA256_TAG_BYTES]);
        assert_eq!(
            key.verify_bounded(b"four", 3, &tag),
            Err(HmacVerificationError::InputTooLong(error))
        );
    }

    #[test]
    fn hmac_key_and_tag_are_exact_width_and_redacted() {
        let key = HmacSha256Key::from_bytes([0xa5; HMAC_SHA256_KEY_BYTES]);
        let tag = HmacSha256Tag::from_bytes([0x5a; HMAC_SHA256_TAG_BYTES]);

        assert_eq!(size_of::<HmacSha256Key>(), HMAC_SHA256_KEY_BYTES);
        assert_eq!(size_of::<HmacSha256Tag>(), HMAC_SHA256_TAG_BYTES);
        assert_eq!(tag.as_bytes(), &[0x5a; HMAC_SHA256_TAG_BYTES]);
        assert_eq!(format!("{key:?}"), "HmacSha256Key([redacted; 32 bytes])");
        assert_eq!(format!("{tag:?}"), "HmacSha256Tag([redacted; 32 bytes])");
        assert_eq!(tag.into_bytes(), [0x5a; HMAC_SHA256_TAG_BYTES]);
    }

    #[test]
    fn secret_key_material_can_be_zeroized() {
        let mut hmac_key = HmacSha256Key::from_bytes([0xa5; HMAC_SHA256_KEY_BYTES]);
        let mut identifier = SecurityIdentifier {
            bytes: [0xa5; SECURITY_IDENTIFIER_BYTES],
        };
        let mut ephemeral = EphemeralKeyMaterial {
            bytes: [0xa5; EPHEMERAL_KEY_MATERIAL_BYTES],
        };

        hmac_key.zeroize();
        identifier.zeroize();
        ephemeral.zeroize();

        assert_eq!(hmac_key.bytes, [0_u8; HMAC_SHA256_KEY_BYTES]);
        assert_eq!(identifier.bytes, [0_u8; SECURITY_IDENTIFIER_BYTES]);
        assert_eq!(ephemeral.bytes, [0_u8; EPHEMERAL_KEY_MATERIAL_BYTES]);
    }

    #[test]
    fn each_random_purpose_uses_one_fresh_fixed_width_draw() {
        let source = FixedRandom::new(0x5a);

        let hmac_key = draw_hmac_sha256_key_with(&source).expect("fixed source must produce a key");
        let identifier = draw_security_identifier_with(&source)
            .expect("fixed source must produce an identifier");
        let ephemeral = draw_ephemeral_key_material_with(&source)
            .expect("fixed source must produce ephemeral material");
        let nonce = draw_nonce_domain_material_with(&source)
            .expect("fixed source must produce nonce material");
        let mask = draw_websocket_mask_with(&source).expect("fixed source must produce a mask");

        assert_eq!(hmac_key.bytes, [0x5a; HMAC_SHA256_KEY_BYTES]);
        assert_eq!(identifier.as_bytes(), &[0x5a; SECURITY_IDENTIFIER_BYTES]);
        assert_eq!(ephemeral.as_bytes(), &[0x5a; EPHEMERAL_KEY_MATERIAL_BYTES]);
        assert_eq!(nonce.into_bytes(), [0x5a; NONCE_DOMAIN_MATERIAL_BYTES]);
        assert_eq!(mask.into_bytes(), [0x5a; WEBSOCKET_MASK_BYTES]);
        assert_eq!(source.calls.get(), 5);
    }

    #[test]
    fn random_purposes_are_distinct_fixed_width_types() {
        assert_ne!(
            TypeId::of::<SecurityIdentifier>(),
            TypeId::of::<EphemeralKeyMaterial>()
        );
        assert_ne!(
            TypeId::of::<SecurityIdentifier>(),
            TypeId::of::<NonceDomainMaterial>()
        );
        assert_ne!(
            TypeId::of::<SecurityIdentifier>(),
            TypeId::of::<WebSocketMask>()
        );
        assert_ne!(
            TypeId::of::<HmacSha256Key>(),
            TypeId::of::<EphemeralKeyMaterial>()
        );

        assert_eq!(size_of::<SecurityIdentifier>(), SECURITY_IDENTIFIER_BYTES);
        assert_eq!(
            size_of::<EphemeralKeyMaterial>(),
            EPHEMERAL_KEY_MATERIAL_BYTES
        );
        assert_eq!(
            size_of::<NonceDomainMaterial>(),
            NONCE_DOMAIN_MATERIAL_BYTES
        );
        assert_eq!(size_of::<WebSocketMask>(), WEBSOCKET_MASK_BYTES);
    }

    #[test]
    fn forced_random_failure_is_terminal_for_every_purpose() {
        let source = FailingRandom::new();

        assert!(draw_hmac_sha256_key_with(&source).is_err());
        assert!(draw_security_identifier_with(&source).is_err());
        assert!(draw_ephemeral_key_material_with(&source).is_err());
        assert!(draw_nonce_domain_material_with(&source).is_err());
        assert!(draw_websocket_mask_with(&source).is_err());
        assert_eq!(source.calls.get(), 5);
    }

    #[test]
    fn random_failure_preserves_the_operating_system_error() {
        let source = FailingRandom::new();
        let error = draw_security_identifier_with(&source)
            .expect_err("forced random failure must be returned");

        assert!(error.to_string().contains("random draw failed"));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn random_values_have_only_fixed_width_byte_access() {
        let source = FixedRandom::new(0x3c);
        let identifier = draw_security_identifier_with(&source)
            .expect("fixed source must produce an identifier");
        let ephemeral = draw_ephemeral_key_material_with(&source)
            .expect("fixed source must produce ephemeral material");
        let nonce = draw_nonce_domain_material_with(&source)
            .expect("fixed source must produce nonce material");
        let mask = draw_websocket_mask_with(&source).expect("fixed source must produce a mask");

        assert_eq!(identifier.as_bytes(), &[0x3c; SECURITY_IDENTIFIER_BYTES]);
        assert_eq!(ephemeral.as_bytes(), &[0x3c; EPHEMERAL_KEY_MATERIAL_BYTES]);
        assert_eq!(nonce.as_bytes(), &[0x3c; NONCE_DOMAIN_MATERIAL_BYTES]);
        assert_eq!(mask.as_bytes(), &[0x3c; WEBSOCKET_MASK_BYTES]);
    }

    #[test]
    fn operating_system_random_path_returns_typed_widths() {
        let hmac_key = draw_hmac_sha256_key().expect("operating-system key draw");
        let identifier = draw_security_identifier().expect("operating-system identifier draw");
        let ephemeral = draw_ephemeral_key_material().expect("operating-system ephemeral-key draw");
        let nonce = draw_nonce_domain_material().expect("operating-system nonce-domain draw");
        let mask = draw_websocket_mask().expect("operating-system mask draw");

        assert_eq!(size_of_val(&hmac_key), HMAC_SHA256_KEY_BYTES);
        assert_eq!(identifier.as_bytes().len(), SECURITY_IDENTIFIER_BYTES);
        assert_eq!(ephemeral.as_bytes().len(), EPHEMERAL_KEY_MATERIAL_BYTES);
        assert_eq!(nonce.as_bytes().len(), NONCE_DOMAIN_MATERIAL_BYTES);
        assert_eq!(mask.as_bytes().len(), WEBSOCKET_MASK_BYTES);
    }

    fn production_source() -> &'static str {
        parsed_production_source(include_str!("crypto.rs"))
            .expect("crypto.rs must end at one parsed #[cfg(test)] tests module")
    }

    const SEALED_EXTERNAL_CALLABLES: [&str; 33] = [
        "pub fn sha256_bounded ( input : & [ u8 ] , max_input_bytes : usize ) -> Result < Sha256Digest , CryptoInputTooLongError >",
        "pub fn draw_hmac_sha256_key ( ) -> Result < HmacSha256Key , RandomDrawError >",
        "pub fn draw_security_identifier ( ) -> Result < SecurityIdentifier , RandomDrawError >",
        "pub fn draw_ephemeral_key_material ( ) -> Result < EphemeralKeyMaterial , RandomDrawError >",
        "pub fn draw_nonce_domain_material ( ) -> Result < NonceDomainMaterial , RandomDrawError >",
        "pub fn draw_websocket_mask ( ) -> Result < WebSocketMask , RandomDrawError >",
        "Sha256Digest :: pub const fn from_bytes ( bytes : [ u8 ; SHA256_DIGEST_BYTES ] ) -> Self",
        "Sha256Digest :: pub const fn as_bytes ( & self ) -> & [ u8 ; SHA256_DIGEST_BYTES ]",
        "Sha256Digest :: pub const fn into_bytes ( self ) -> [ u8 ; SHA256_DIGEST_BYTES ]",
        "HmacSha256Key :: pub fn from_bytes ( bytes : [ u8 ; HMAC_SHA256_KEY_BYTES ] ) -> Self",
        "HmacSha256Key :: pub fn authenticate_bounded ( & self , input : & [ u8 ] , max_input_bytes : usize ) -> Result < HmacSha256Tag , CryptoInputTooLongError >",
        "HmacSha256Key :: pub fn verify_bounded ( & self , input : & [ u8 ] , max_input_bytes : usize , tag : & HmacSha256Tag ) -> Result < ( ) , HmacVerificationError >",
        "HmacSha256Tag :: pub const fn from_bytes ( bytes : [ u8 ; HMAC_SHA256_TAG_BYTES ] ) -> Self",
        "HmacSha256Tag :: pub const fn as_bytes ( & self ) -> & [ u8 ; HMAC_SHA256_TAG_BYTES ]",
        "HmacSha256Tag :: pub const fn into_bytes ( self ) -> [ u8 ; HMAC_SHA256_TAG_BYTES ]",
        "SecurityIdentifier :: pub const fn as_bytes ( & self ) -> & [ u8 ; SECURITY_IDENTIFIER_BYTES ]",
        "EphemeralKeyMaterial :: pub const fn as_bytes ( & self ) -> & [ u8 ; EPHEMERAL_KEY_MATERIAL_BYTES ]",
        "NonceDomainMaterial :: pub const fn as_bytes ( & self ) -> & [ u8 ; NONCE_DOMAIN_MATERIAL_BYTES ]",
        "NonceDomainMaterial :: pub const fn into_bytes ( self ) -> [ u8 ; NONCE_DOMAIN_MATERIAL_BYTES ]",
        "WebSocketMask :: pub const fn as_bytes ( & self ) -> & [ u8 ; WEBSOCKET_MASK_BYTES ]",
        "WebSocketMask :: pub const fn into_bytes ( self ) -> [ u8 ; WEBSOCKET_MASK_BYTES ]",
        "fmt :: Display for CryptoInputTooLongError :: fn fmt ( & self , f : & mut fmt :: Formatter < ' _ > ) -> fmt :: Result",
        "fmt :: Display for RandomDrawError :: fn fmt ( & self , f : & mut fmt :: Formatter < ' _ > ) -> fmt :: Result",
        "std :: error :: Error for RandomDrawError :: fn source ( & self ) -> Option < & ( dyn std :: error :: Error + ' static ) >",
        "fmt :: Display for HmacVerificationError :: fn fmt ( & self , f : & mut fmt :: Formatter < ' _ > ) -> fmt :: Result",
        "std :: error :: Error for HmacVerificationError :: fn source ( & self ) -> Option < & ( dyn std :: error :: Error + ' static ) >",
        "From < CryptoInputTooLongError > for HmacVerificationError :: fn from ( error : CryptoInputTooLongError ) -> Self",
        "fmt :: Debug for HmacSha256Key :: fn fmt ( & self , f : & mut fmt :: Formatter < ' _ > ) -> fmt :: Result",
        "fmt :: Debug for HmacSha256Tag :: fn fmt ( & self , f : & mut fmt :: Formatter < ' _ > ) -> fmt :: Result",
        "fmt :: Debug for SecurityIdentifier :: fn fmt ( & self , f : & mut fmt :: Formatter < ' _ > ) -> fmt :: Result",
        "fmt :: Debug for EphemeralKeyMaterial :: fn fmt ( & self , f : & mut fmt :: Formatter < ' _ > ) -> fmt :: Result",
        "fmt :: Debug for NonceDomainMaterial :: fn fmt ( & self , f : & mut fmt :: Formatter < ' _ > ) -> fmt :: Result",
        "fmt :: Debug for WebSocketMask :: fn fmt ( & self , f : & mut fmt :: Formatter < ' _ > ) -> fmt :: Result",
    ];

    const PRIVATE_WITH_SEAMS: [&str; 6] = [
        "sha256_bounded_with",
        "draw_hmac_sha256_key_with",
        "draw_security_identifier_with",
        "draw_ephemeral_key_material_with",
        "draw_nonce_domain_material_with",
        "draw_websocket_mask_with",
    ];

    const SEALED_PUBLIC_CONSTANTS: [&str; 7] = [
        "const SHA256_DIGEST_BYTES : usize = 32",
        "const HMAC_SHA256_KEY_BYTES : usize = 32",
        "const HMAC_SHA256_TAG_BYTES : usize = 32",
        "const SECURITY_IDENTIFIER_BYTES : usize = 32",
        "const EPHEMERAL_KEY_MATERIAL_BYTES : usize = 32",
        "const NONCE_DOMAIN_MATERIAL_BYTES : usize = 16",
        "const WEBSOCKET_MASK_BYTES : usize = 4",
    ];

    #[derive(Debug, PartialEq, Eq)]
    enum RandomDrawApiDenyError {
        MalformedSource(&'static str),
        MissingSealedExternalCallable(String),
        UnexpectedTopLevelPublicFunction(String),
        UnexpectedExternalCallable(String),
        UnexpectedVisibleItem(String),
        PublicTrait(String),
        PublicEntropyExport(String),
        MacroGeneratedPublicEntropy(String),
        UnresolvedExpansionRoute(String),
        ForbiddenExternCrateGetrandom(String),
        GetrandomFillCount(usize),
        GetrandomFillOutsideOsRandomSource,
        PublicRawRandomSurface(String),
    }

    impl std::fmt::Display for RandomDrawApiDenyError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::MalformedSource(reason) => {
                    write!(formatter, "random draw API denial: malformed source: {reason}")
                }
                Self::MissingSealedExternalCallable(signature) => write!(
                    formatter,
                    "random draw API denial: missing sealed external callable `{signature}`"
                ),
                Self::UnexpectedTopLevelPublicFunction(signature) => write!(
                    formatter,
                    "random draw API denial: unexpected top-level public function `{signature}`"
                ),
                Self::UnexpectedExternalCallable(signature) => write!(
                    formatter,
                    "random draw API denial: unexpected external callable `{signature}`"
                ),
                Self::UnexpectedVisibleItem(item) => {
                    write!(formatter, "random draw API denial: unexpected visible item `{item}`")
                }
                Self::PublicTrait(name) => {
                    write!(formatter, "random draw API denial: public trait `{name}`")
                }
                Self::PublicEntropyExport(surface) => write!(
                    formatter,
                    "random draw API denial: public entropy export `{surface}`"
                ),
                Self::MacroGeneratedPublicEntropy(macro_name) => write!(
                    formatter,
                    "random draw API denial: macro-generated public entropy `{macro_name}`"
                ),
                Self::UnresolvedExpansionRoute(route) => write!(
                    formatter,
                    "random draw API denial: unresolved expansion route `{route}`"
                ),
                Self::ForbiddenExternCrateGetrandom(route) => write!(
                    formatter,
                    "random draw API denial: forbidden extern crate route `{route}`"
                ),
                Self::GetrandomFillCount(count) => write!(
                    formatter,
                    "random draw API denial: expected exactly one getrandom::fill reference, found {count}"
                ),
                Self::GetrandomFillOutsideOsRandomSource => formatter.write_str(
                    "random draw API denial: getrandom::fill is not owned by the private OsRandomSource implementation",
                ),
                Self::PublicRawRandomSurface(surface) => write!(
                    formatter,
                    "random draw API denial: public raw random surface `{surface}`"
                ),
            }
        }
    }

    #[derive(Clone, Copy)]
    struct SourceToken<'a> {
        text: &'a str,
        start: usize,
    }

    fn is_identifier_start(byte: u8) -> bool {
        byte.is_ascii_alphabetic() || byte == b'_'
    }

    fn is_identifier_continue(byte: u8) -> bool {
        is_identifier_start(byte) || byte.is_ascii_digit()
    }

    fn skip_quoted_literal(
        source: &str,
        quote_index: usize,
    ) -> Result<usize, RandomDrawApiDenyError> {
        let bytes = source.as_bytes();
        let quote = bytes[quote_index];
        let mut index = quote_index + 1;
        while index < bytes.len() {
            if bytes[index] == b'\\' {
                index += 2;
            } else if bytes[index] == quote {
                return Ok(index + 1);
            } else {
                index += 1;
            }
        }
        Err(RandomDrawApiDenyError::MalformedSource(
            "unterminated quoted literal",
        ))
    }

    fn skip_char_literal(source: &str, quote_index: usize) -> Option<usize> {
        let bytes = source.as_bytes();
        let mut index = quote_index + 1;
        if bytes.get(index) == Some(&b'\\') {
            index += 1;
            while let Some(byte) = bytes.get(index) {
                index += 1;
                if *byte == b'\'' {
                    return Some(index);
                }
                if *byte == b'\n' {
                    return None;
                }
            }
            return None;
        }
        let character = source.get(index..)?.chars().next()?;
        index += character.len_utf8();
        (bytes.get(index) == Some(&b'\'')).then_some(index + 1)
    }

    fn raw_literal_end(
        source: &str,
        index: usize,
    ) -> Result<Option<usize>, RandomDrawApiDenyError> {
        let bytes = source.as_bytes();
        let prefix_width = match bytes.get(index..index + 2) {
            Some(b"br" | b"cr") => 2,
            _ if bytes.get(index) == Some(&b'r') => 1,
            _ => return Ok(None),
        };
        let mut quote_index = index + prefix_width;
        while bytes.get(quote_index) == Some(&b'#') {
            quote_index += 1;
        }
        if bytes.get(quote_index) != Some(&b'"') {
            return Ok(None);
        }
        let hash_count = quote_index - index - prefix_width;
        let mut cursor = quote_index + 1;
        while cursor < bytes.len() {
            if bytes[cursor] == b'"'
                && bytes
                    .get(cursor + 1..cursor + 1 + hash_count)
                    .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
            {
                return Ok(Some(cursor + 1 + hash_count));
            }
            cursor += 1;
        }
        Err(RandomDrawApiDenyError::MalformedSource(
            "unterminated raw literal",
        ))
    }

    fn lex_source(source: &str) -> Result<Vec<SourceToken<'_>>, RandomDrawApiDenyError> {
        let bytes = source.as_bytes();
        let mut tokens = Vec::new();
        let mut index = 0_usize;
        while index < bytes.len() {
            if bytes[index].is_ascii_whitespace() {
                index += 1;
                continue;
            }
            if bytes.get(index..index + 2) == Some(b"//") {
                index = source[index..]
                    .find('\n')
                    .map_or(bytes.len(), |offset| index + offset + 1);
                continue;
            }
            if bytes.get(index..index + 2) == Some(b"/*") {
                let mut cursor = index + 2;
                let mut depth = 1_usize;
                while cursor + 1 < bytes.len() {
                    match &bytes[cursor..cursor + 2] {
                        b"/*" => {
                            depth += 1;
                            cursor += 2;
                        }
                        b"*/" => {
                            depth -= 1;
                            cursor += 2;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => cursor += 1,
                    }
                }
                if depth != 0 {
                    return Err(RandomDrawApiDenyError::MalformedSource(
                        "unterminated block comment",
                    ));
                }
                index = cursor;
                continue;
            }
            if let Some(end) = raw_literal_end(source, index)? {
                index = end;
                continue;
            }
            if bytes.get(index..index + 2) == Some(b"r#")
                && bytes
                    .get(index + 2)
                    .is_some_and(|byte| is_identifier_start(*byte))
            {
                let start = index;
                index += 3;
                while bytes
                    .get(index)
                    .is_some_and(|byte| is_identifier_continue(*byte))
                {
                    index += 1;
                }
                tokens.push(SourceToken {
                    text: &source[start..index],
                    start,
                });
                continue;
            }
            if bytes.get(index) == Some(&b'"') {
                index = skip_quoted_literal(source, index)?;
                continue;
            }
            if matches!(bytes.get(index..index + 2), Some(b"b\"" | b"c\"")) {
                index = skip_quoted_literal(source, index + 1)?;
                continue;
            }
            if bytes.get(index) == Some(&b'\'') {
                if let Some(end) = skip_char_literal(source, index) {
                    index = end;
                    continue;
                }
            }
            if matches!(bytes.get(index..index + 2), Some(b"b'" | b"c'")) {
                if let Some(end) = skip_char_literal(source, index + 1) {
                    index = end;
                    continue;
                }
            }
            let start = index;
            if is_identifier_start(bytes[index]) {
                index += 1;
                while bytes
                    .get(index)
                    .is_some_and(|byte| is_identifier_continue(*byte))
                {
                    index += 1;
                }
            } else if bytes[index].is_ascii_digit() {
                index += 1;
                while bytes
                    .get(index)
                    .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'_')
                {
                    index += 1;
                }
            } else {
                index += match bytes.get(index..index + 3) {
                    Some(b"..=") => 3,
                    _ => match bytes.get(index..index + 2) {
                        Some(
                            b"::" | b"->" | b"=>" | b".." | b"==" | b"!=" | b"<=" | b">=" | b"&&"
                            | b"||",
                        ) => 2,
                        _ => source[index..]
                            .chars()
                            .next()
                            .expect("lexer index is in bounds")
                            .len_utf8(),
                    },
                };
            }
            tokens.push(SourceToken {
                text: &source[start..index],
                start,
            });
        }
        Ok(tokens)
    }

    fn parsed_production_source(source: &str) -> Result<&str, RandomDrawApiDenyError> {
        let tokens = lex_source(source)?;
        let mut brace_depth = 0_usize;
        let mut test_module = None;
        let mut test_module_end = None;
        for index in 0..tokens.len() {
            match tokens[index].text {
                "{" => brace_depth += 1,
                "}" => {
                    brace_depth = brace_depth.checked_sub(1).ok_or(
                        RandomDrawApiDenyError::MalformedSource("unbalanced module braces"),
                    )?;
                }
                "#" if brace_depth == 0 => {
                    if tokens
                        .get(index + 2)
                        .is_some_and(|token| token.text == "cfg_attr")
                    {
                        return Err(RandomDrawApiDenyError::MalformedSource(
                            "top-level cfg_attr is forbidden",
                        ));
                    }
                    let is_tests_module = tokens
                        .get(index + 2)
                        .is_some_and(|token| token.text == "cfg")
                        && tokens.get(index + 3).is_some_and(|token| token.text == "(")
                        && tokens
                            .get(index + 4)
                            .is_some_and(|token| token.text == "test")
                        && tokens.get(index + 5).is_some_and(|token| token.text == ")")
                        && tokens.get(index + 6).is_some_and(|token| token.text == "]")
                        && tokens
                            .get(index + 7)
                            .is_some_and(|token| token.text == "mod")
                        && tokens
                            .get(index + 8)
                            .is_some_and(|token| token.text == "tests")
                        && tokens.get(index + 9).is_some_and(|token| token.text == "{");
                    if is_tests_module {
                        if test_module.replace(index).is_some() {
                            return Err(RandomDrawApiDenyError::MalformedSource(
                                "multiple top-level cfg(test) modules",
                            ));
                        }
                        let closing = matching_brace(&tokens, index + 9).ok_or(
                            RandomDrawApiDenyError::MalformedSource("unterminated tests module"),
                        )?;
                        test_module_end = Some(closing);
                    }
                }
                _ => {}
            }
        }
        let boundary = test_module.ok_or(RandomDrawApiDenyError::MalformedSource(
            "missing top-level cfg(test) tests module",
        ))?;
        if test_module_end.is_none_or(|closing| closing + 1 != tokens.len()) {
            return Err(RandomDrawApiDenyError::MalformedSource(
                "items follow the cfg(test) tests module",
            ));
        }
        Ok(&source[..tokens[boundary].start])
    }

    fn matching_brace(tokens: &[SourceToken<'_>], opening_brace: usize) -> Option<usize> {
        let mut depth = 0_usize;
        for (index, token) in tokens.iter().enumerate().skip(opening_brace) {
            match token.text {
                "{" => depth += 1,
                "}" => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(index);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn after_visibility(tokens: &[SourceToken<'_>], pub_index: usize) -> Option<usize> {
        let mut index = pub_index + 1;
        if tokens.get(index)?.text != "(" {
            return Some(index);
        }
        let closing = matching_paren(tokens, index)?;
        index = closing + 1;
        Some(index)
    }

    fn matching_paren(tokens: &[SourceToken<'_>], opening_paren: usize) -> Option<usize> {
        let mut depth = 0_usize;
        for (index, token) in tokens.iter().enumerate().skip(opening_paren) {
            match token.text {
                "(" => depth += 1,
                ")" => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(index);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn visible_item_after(tokens: &[SourceToken<'_>], pub_index: usize) -> Option<(usize, usize)> {
        let mut index = after_visibility(tokens, pub_index)?;
        while matches!(
            tokens.get(index)?.text,
            "async" | "const" | "unsafe" | "extern"
        ) {
            index += 1;
        }
        matches!(tokens.get(index)?.text, "fn" | "trait" | "struct").then_some((index, index + 1))
    }

    fn canonical_tokens(tokens: &[SourceToken<'_>]) -> Vec<String> {
        tokens
            .iter()
            .enumerate()
            .filter(|(index, token)| {
                !(token.text == "," && tokens.get(index + 1).is_some_and(|next| next.text == ")"))
            })
            .map(|(_, token)| token.text.to_owned())
            .collect()
    }

    fn matches_token_sequence(tokens: &[String], expected: &str) -> bool {
        tokens
            .iter()
            .map(String::as_str)
            .eq(expected.split_ascii_whitespace())
    }

    fn bare_identifier(token: &str) -> &str {
        token.strip_prefix("r#").unwrap_or(token)
    }

    fn render_tokens(tokens: &[String]) -> String {
        let mut rendered = String::new();
        let mut previous = None;
        for token in tokens {
            let no_space_before = matches!(
                token.as_str(),
                "(" | ")" | "]" | "," | ";" | ":" | ">" | "<" | "::"
            ) || matches!(previous, Some("(" | "[" | "<" | "::" | "&"))
                || (token == "[" && previous != Some("->"));
            if !rendered.is_empty() && !no_space_before {
                rendered.push(' ');
            }
            rendered.push_str(token);
            previous = Some(token.as_str());
        }
        rendered
    }

    struct ExternalCallable {
        is_module_function: bool,
        tokens: Vec<String>,
    }

    fn function_header_end(tokens: &[SourceToken<'_>], fn_index: usize) -> Option<usize> {
        // Track nesting so the `;` inside array types such as `[u8; N]` is not
        // mistaken for the end of a function signature.
        let mut angle = 0_usize;
        let mut paren = 0_usize;
        let mut square = 0_usize;
        for (index, token) in tokens.iter().enumerate().skip(fn_index + 1) {
            match token.text {
                "<" => angle = angle.saturating_add(1),
                ">" => angle = angle.saturating_sub(1),
                "(" => paren = paren.saturating_add(1),
                ")" => paren = paren.saturating_sub(1),
                "[" => square = square.saturating_add(1),
                "]" => square = square.saturating_sub(1),
                "{" | ";" if angle == 0 && paren == 0 && square == 0 => return Some(index),
                _ => {}
            }
        }
        None
    }

    fn enclosing_braces(tokens: &[SourceToken<'_>], before: usize) -> Option<Vec<usize>> {
        let mut braces = Vec::new();
        for (index, token) in tokens.iter().enumerate().take(before) {
            match token.text {
                "{" => braces.push(index),
                "}" => {
                    braces.pop()?;
                }
                _ => {}
            }
        }
        Some(braces)
    }

    fn opening_brace_after(tokens: &[SourceToken<'_>], index: usize) -> Option<usize> {
        (index + 1..tokens.len()).find(|candidate| tokens[*candidate].text == "{")
    }

    fn impl_owner_at_brace<'a>(tokens: &[SourceToken<'a>], brace: usize) -> Option<&'a str> {
        for index in 0..brace {
            if tokens[index].text != "impl" || opening_brace_after(tokens, index)? != brace {
                continue;
            }
            let header = &tokens[index + 1..brace];
            if let Some(for_index) = header.iter().position(|token| token.text == "for") {
                return header
                    .get(for_index + 1)
                    .map(|token| bare_identifier(token.text));
            }
            return header
                .iter()
                .find(|token| is_identifier_start(token.text.as_bytes()[0]))
                .map(|token| bare_identifier(token.text));
        }
        None
    }

    fn public_trait_impl_prefix_at_brace(
        tokens: &[SourceToken<'_>],
        brace: usize,
    ) -> Option<Vec<String>> {
        for index in 0..brace {
            if tokens[index].text != "impl" || opening_brace_after(tokens, index)? != brace {
                continue;
            }
            let header = &tokens[index + 1..brace];
            if !header.iter().any(|token| token.text == "for") {
                return None;
            }
            if header
                .first()
                .is_some_and(|token| bare_identifier(token.text) == "RandomSource")
            {
                return None;
            }
            let mut prefix = canonical_tokens(header);
            prefix.push("::".to_owned());
            return Some(prefix);
        }
        None
    }

    fn visible_trait_at_brace<'a>(tokens: &[SourceToken<'a>], brace: usize) -> Option<&'a str> {
        for pub_index in 0..brace {
            let Some((keyword_index, name_index)) = visible_item_after(tokens, pub_index) else {
                continue;
            };
            if tokens[pub_index].text == "pub"
                && tokens[keyword_index].text == "trait"
                && opening_brace_after(tokens, keyword_index)? == brace
            {
                return tokens
                    .get(name_index)
                    .map(|token| bare_identifier(token.text));
            }
        }
        None
    }

    fn external_callables(
        tokens: &[SourceToken<'_>],
    ) -> Result<(Vec<ExternalCallable>, Vec<String>), RandomDrawApiDenyError> {
        let mut callables = Vec::new();
        let mut public_traits = Vec::new();
        for (index, token) in tokens.iter().enumerate() {
            if token.text == "pub" {
                let Some((keyword_index, name_index)) = visible_item_after(tokens, index) else {
                    continue;
                };
                if tokens[keyword_index].text == "trait" {
                    public_traits.push(
                        tokens
                            .get(name_index)
                            .ok_or(RandomDrawApiDenyError::MalformedSource(
                                "visible trait has no name",
                            ))?
                            .text
                            .to_owned(),
                    );
                    continue;
                }
                if tokens[keyword_index].text != "fn" {
                    continue;
                }
                let header_end = function_header_end(tokens, keyword_index).ok_or(
                    RandomDrawApiDenyError::MalformedSource("visible function has no header end"),
                )?;
                let braces = enclosing_braces(tokens, index).ok_or(
                    RandomDrawApiDenyError::MalformedSource("unbalanced brace nesting"),
                )?;
                let owner = braces
                    .last()
                    .and_then(|brace| impl_owner_at_brace(tokens, *brace));
                let mut signature = owner
                    .map(|owner| vec![owner.to_owned(), "::".to_owned()])
                    .unwrap_or_default();
                signature.extend(canonical_tokens(&tokens[index..header_end]));
                callables.push(ExternalCallable {
                    is_module_function: owner.is_none(),
                    tokens: signature,
                });
                continue;
            }
            if token.text != "fn" {
                continue;
            }
            let braces = enclosing_braces(tokens, index).ok_or(
                RandomDrawApiDenyError::MalformedSource("unbalanced brace nesting"),
            )?;
            let Some(trait_name) = braces
                .last()
                .and_then(|brace| visible_trait_at_brace(tokens, *brace))
            else {
                continue;
            };
            let header_end = function_header_end(tokens, index).ok_or(
                RandomDrawApiDenyError::MalformedSource("public trait method has no header end"),
            )?;
            let mut signature = vec![trait_name.to_owned(), "::".to_owned()];
            signature.extend(canonical_tokens(&tokens[index..header_end]));
            callables.push(ExternalCallable {
                is_module_function: false,
                tokens: signature,
            });
            continue;
        }
        for (index, token) in tokens.iter().enumerate() {
            if token.text != "fn" {
                continue;
            }
            let braces = enclosing_braces(tokens, index).ok_or(
                RandomDrawApiDenyError::MalformedSource("unbalanced brace nesting"),
            )?;
            let Some(prefix) = braces
                .last()
                .and_then(|brace| public_trait_impl_prefix_at_brace(tokens, *brace))
            else {
                continue;
            };
            let header_end = function_header_end(tokens, index).ok_or(
                RandomDrawApiDenyError::MalformedSource(
                    "trait implementation method has no header end",
                ),
            )?;
            let mut signature = prefix;
            signature.extend(canonical_tokens(&tokens[index..header_end]));
            callables.push(ExternalCallable {
                is_module_function: false,
                tokens: signature,
            });
        }
        Ok((callables, public_traits))
    }

    fn private_random_source_impl_span(tokens: &[SourceToken<'_>]) -> Option<(usize, usize)> {
        let mut brace_depth = 0_usize;
        for index in 0..tokens.len() {
            match tokens[index].text {
                "{" => brace_depth += 1,
                "}" => brace_depth = brace_depth.checked_sub(1)?,
                "impl"
                    if brace_depth == 0
                        && tokens.get(index + 1)?.text == "RandomSource"
                        && tokens.get(index + 2)?.text == "for"
                        && tokens.get(index + 3)?.text == "OsRandomSource" =>
                {
                    let body_start = (index + 4..tokens.len())
                        .find(|candidate| tokens[*candidate].text == "{")?;
                    return matching_brace(tokens, body_start)
                        .map(|body_end| (body_start, body_end));
                }
                _ => {}
            }
        }
        None
    }

    fn reject_visible_private_random_surfaces(
        tokens: &[SourceToken<'_>],
    ) -> Result<(), RandomDrawApiDenyError> {
        for (pub_index, token) in tokens.iter().enumerate() {
            if token.text != "pub" {
                continue;
            }
            let Some((keyword_index, name_index)) = visible_item_after(tokens, pub_index) else {
                continue;
            };
            let Some(name) = tokens
                .get(name_index)
                .map(|token| bare_identifier(token.text))
            else {
                return Err(RandomDrawApiDenyError::MalformedSource(
                    "visible item has no name",
                ));
            };
            if matches!(
                (tokens[keyword_index].text, name),
                ("trait", "RandomSource") | ("struct", "OsRandomSource") | ("fn", "draw_bytes")
            ) || (tokens[keyword_index].text == "fn" && name.ends_with("_with"))
            {
                return Err(RandomDrawApiDenyError::PublicRawRandomSurface(
                    name.to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn reject_public_associated_entropy_delegation(
        tokens: &[SourceToken<'_>],
    ) -> Result<(), RandomDrawApiDenyError> {
        for (pub_index, token) in tokens.iter().enumerate() {
            if token.text != "pub" {
                continue;
            }
            let Some((keyword_index, name_index)) = visible_item_after(tokens, pub_index) else {
                continue;
            };
            if tokens[keyword_index].text != "fn" {
                continue;
            }
            let braces = enclosing_braces(tokens, pub_index).ok_or(
                RandomDrawApiDenyError::MalformedSource("unbalanced brace nesting"),
            )?;
            let Some(owner) = braces
                .last()
                .and_then(|brace| impl_owner_at_brace(tokens, *brace))
            else {
                continue;
            };
            let body_start = function_header_end(tokens, keyword_index)
                .filter(|index| tokens[*index].text == "{");
            let delegates_entropy = body_start
                .and_then(|opening| {
                    matching_brace(tokens, opening).map(|closing| (opening, closing))
                })
                .is_some_and(|(opening, closing)| {
                    tokens[opening..=closing].iter().any(|token| {
                        matches!(bare_identifier(token.text), "draw_bytes" | "OsRandomSource")
                    })
                });
            if delegates_entropy {
                let name =
                    tokens
                        .get(name_index)
                        .ok_or(RandomDrawApiDenyError::MalformedSource(
                            "public associated function has no name",
                        ))?;
                return Err(RandomDrawApiDenyError::PublicRawRandomSurface(format!(
                    "{owner}::{}",
                    bare_identifier(name.text)
                )));
            }
        }
        Ok(())
    }

    fn is_identifier_token(token: &str) -> bool {
        let token = bare_identifier(token);
        token
            .as_bytes()
            .first()
            .is_some_and(|byte| is_identifier_start(*byte))
            && token
                .as_bytes()
                .iter()
                .all(|byte| is_identifier_continue(*byte))
    }

    fn statement_end(tokens: &[SourceToken<'_>], start: usize) -> usize {
        // Ignore `,` / `;` nested inside type arguments (`Result<(), E>`,
        // `[u8; N]`) so binding statements can be scanned to their real end.
        let mut angle = 0_usize;
        let mut paren = 0_usize;
        let mut square = 0_usize;
        for (index, token) in tokens.iter().enumerate().skip(start) {
            match token.text {
                "<" => angle = angle.saturating_add(1),
                ">" => angle = angle.saturating_sub(1),
                "(" => paren = paren.saturating_add(1),
                ")" => paren = paren.saturating_sub(1),
                "[" => square = square.saturating_add(1),
                "]" => square = square.saturating_sub(1),
                ";" if angle == 0 && paren == 0 && square == 0 => return index,
                // Top-level commas still terminate multi-item declarations, but
                // never those nested inside type/argument lists.
                "," if angle == 0 && paren == 0 && square == 0 => return index,
                _ => {}
            }
        }
        tokens.len()
    }

    fn use_statement_end(tokens: &[SourceToken<'_>], start: usize) -> usize {
        (start..tokens.len())
            .find(|index| tokens[*index].text == ";")
            .unwrap_or(tokens.len())
    }

    fn reject_visible_value_routes(
        tokens: &[SourceToken<'_>],
    ) -> Result<(), RandomDrawApiDenyError> {
        for (pub_index, token) in tokens.iter().enumerate() {
            if token.text != "pub" {
                continue;
            }
            let item_index = after_visibility(tokens, pub_index).ok_or(
                RandomDrawApiDenyError::MalformedSource("unterminated restricted visibility"),
            )?;
            let end = statement_end(tokens, item_index);
            let surface = &tokens[item_index..end];
            let item = surface
                .first()
                .ok_or(RandomDrawApiDenyError::MalformedSource(
                    "visible item is empty",
                ))?;
            if item.text == "use" {
                return Err(RandomDrawApiDenyError::PublicEntropyExport(render_tokens(
                    &canonical_tokens(surface),
                )));
            }
            if matches!(item.text, "type" | "mod" | "extern") {
                return Err(RandomDrawApiDenyError::UnexpectedVisibleItem(
                    render_tokens(&canonical_tokens(surface)),
                ));
            }
            let callable_value = surface
                .iter()
                .any(|token| matches!(token.text, "fn" | "Fn" | "FnMut" | "FnOnce"));
            if item.text == "static" {
                return Err(RandomDrawApiDenyError::PublicEntropyExport(render_tokens(
                    &canonical_tokens(surface),
                )));
            }
            if matches!(item.text, "fn" | "trait" | "struct" | "enum" | "impl") {
                // Callables, traits, and type items are validated by the sealed
                // external-callable / public-trait allowlists later. Truncating
                // their surfaces at type-list commas would misclassify them as
                // ambient entropy exports.
                continue;
            }
            if item.text == "const" {
                // Associated `pub const fn` methods are checked by the callable
                // allowlist below. Every exported value is otherwise a manifest
                // entry; this rejects function pointers hidden behind neutral
                // aliases without relying on an entropy-shaped token.
                if surface.get(1).is_some_and(|token| token.text == "fn") {
                    continue;
                }
                let module_value =
                    enclosing_braces(tokens, pub_index).is_some_and(|braces| braces.is_empty());
                let canonical = canonical_tokens(surface);
                if !module_value
                    || !SEALED_PUBLIC_CONSTANTS
                        .iter()
                        .any(|expected| matches_token_sequence(&canonical, expected))
                {
                    return Err(RandomDrawApiDenyError::PublicEntropyExport(render_tokens(
                        &canonical,
                    )));
                }
            }
            if callable_value && item.text != "const" {
                return Err(RandomDrawApiDenyError::PublicEntropyExport(render_tokens(
                    &canonical_tokens(surface),
                )));
            }
            // A public struct/enum field can carry a callable even without a
            // `const`/`static` item keyword. Scalar fields in the sealed
            // production types remain allowed, while callable fields fail closed.
            if is_identifier_token(item.text)
                && surface.get(1).is_some_and(|token| token.text == ":")
                && callable_value
            {
                return Err(RandomDrawApiDenyError::PublicEntropyExport(render_tokens(
                    &canonical_tokens(surface),
                )));
            }
        }
        Ok(())
    }

    fn reject_extern_crate_getrandom(
        tokens: &[SourceToken<'_>],
    ) -> Result<(), RandomDrawApiDenyError> {
        for index in 0..tokens.len() {
            if tokens[index].text == "extern"
                && tokens
                    .get(index + 1)
                    .is_some_and(|token| token.text == "crate")
                && tokens
                    .get(index + 2)
                    .is_some_and(|token| bare_identifier(token.text) == "getrandom")
            {
                let end = use_statement_end(tokens, index);
                return Err(RandomDrawApiDenyError::ForbiddenExternCrateGetrandom(
                    render_tokens(&canonical_tokens(&tokens[index..end])),
                ));
            }
        }
        Ok(())
    }

    fn reject_unresolved_expansion_routes(
        tokens: &[SourceToken<'_>],
    ) -> Result<(), RandomDrawApiDenyError> {
        const INERT_DERIVES: &[&str] = &[
            "Clone",
            "Copy",
            "Debug",
            "Eq",
            "Hash",
            "PartialEq",
            "Zeroize",
            "ZeroizeOnDrop",
        ];

        for index in 0..tokens.len() {
            if tokens[index].text == "#"
                && tokens.get(index + 1).is_some_and(|token| token.text == "[")
            {
                let attribute =
                    tokens
                        .get(index + 2)
                        .ok_or(RandomDrawApiDenyError::MalformedSource(
                            "attribute has no route",
                        ))?;
                if matches!(attribute.text, "cfg_attr" | "path") {
                    return Err(RandomDrawApiDenyError::UnresolvedExpansionRoute(
                        attribute.text.to_owned(),
                    ));
                }
                if attribute.text == "derive" {
                    let opening = index + 3;
                    let closing = matching_paren(tokens, opening).ok_or(
                        RandomDrawApiDenyError::MalformedSource("unterminated derive route"),
                    )?;
                    if tokens.get(opening).is_none_or(|token| token.text != "(")
                        || tokens
                            .get(closing + 1)
                            .is_none_or(|token| token.text != "]")
                    {
                        return Err(RandomDrawApiDenyError::MalformedSource(
                            "malformed derive route",
                        ));
                    }
                    for token in &tokens[opening + 1..closing] {
                        if is_identifier_token(token.text)
                            && !INERT_DERIVES.contains(&bare_identifier(token.text))
                        {
                            return Err(RandomDrawApiDenyError::UnresolvedExpansionRoute(
                                "derive".to_owned(),
                            ));
                        }
                    }
                }
            }
            if !(is_identifier_token(tokens[index].text)
                && tokens.get(index + 1).is_some_and(|token| token.text == "!"))
            {
                continue;
            }
            let name = bare_identifier(tokens[index].text);
            if name == "write" {
                continue;
            }
            return Err(RandomDrawApiDenyError::UnresolvedExpansionRoute(
                name.to_owned(),
            ));
        }
        Ok(())
    }

    fn is_entropy_token(token: &str) -> bool {
        matches!(
            bare_identifier(token),
            "getrandom" | "fill" | "RandomSource" | "OsRandomSource" | "draw_bytes"
        ) || bare_identifier(token).ends_with("_with")
    }

    fn reject_ambient_entropy_exports(
        tokens: &[SourceToken<'_>],
    ) -> Result<(), RandomDrawApiDenyError> {
        for (pub_index, token) in tokens.iter().enumerate() {
            if token.text != "pub" {
                continue;
            }
            let Some(item_index) = after_visibility(tokens, pub_index) else {
                return Err(RandomDrawApiDenyError::MalformedSource(
                    "unterminated restricted visibility",
                ));
            };
            // `pub fn` / `pub const fn` callables are allowlisted by
            // `SEALED_EXTERNAL_CALLABLES`. Traits/structs/enums are checked by
            // the public-trait / raw-surface scanners. Do not treat any of them
            // as ambient entropy exports.
            if matches!(
                tokens[item_index].text,
                "fn" | "trait" | "struct" | "enum" | "impl"
            ) || (tokens[item_index].text == "const"
                && tokens
                    .get(item_index + 1)
                    .is_some_and(|token| token.text == "fn"))
            {
                continue;
            }
            let end = (item_index..tokens.len())
                .find(|index| matches!(tokens[*index].text, ";" | ","))
                .unwrap_or(tokens.len());
            let surface = &tokens[item_index..end];
            let exposes_entropy = surface.iter().any(|token| is_entropy_token(token.text));
            let callable_value = surface
                .iter()
                .any(|token| matches!(token.text, "fn" | "Fn" | "FnMut" | "FnOnce"));
            if tokens[item_index].text == "use" && exposes_entropy
                || matches!(tokens[item_index].text, "const" | "static")
                    && (exposes_entropy || callable_value)
                || callable_value && exposes_entropy
            {
                return Err(RandomDrawApiDenyError::PublicEntropyExport(render_tokens(
                    &canonical_tokens(surface),
                )));
            }
        }
        for index in 0..tokens.len().saturating_sub(1) {
            if (tokens[index].text == "macro_rules"
                && tokens.get(index + 1).is_some_and(|token| token.text == "!"))
                || (is_identifier_start(tokens[index].text.as_bytes()[0])
                    && tokens.get(index + 1).is_some_and(|token| token.text == "!"))
            {
                let macro_name = if tokens[index].text == "macro_rules" {
                    tokens
                        .get(index + 2)
                        .map(|token| bare_identifier(token.text))
                } else {
                    Some(bare_identifier(tokens[index].text))
                };
                let Some(macro_name) = macro_name else {
                    return Err(RandomDrawApiDenyError::MalformedSource("macro has no name"));
                };
                let body_end = opening_brace_after(tokens, index)
                    .and_then(|opening| matching_brace(tokens, opening));
                let emits_public_entropy = body_end.is_some_and(|end| {
                    tokens[index..=end].iter().any(|token| token.text == "pub")
                        && tokens[index..=end]
                            .iter()
                            .any(|token| is_entropy_token(token.text))
                });
                let unknown_can_emit_entropy = tokens[index].text != "macro_rules"
                    && (is_entropy_token(macro_name)
                        || matches!(macro_name, "include" | "include_str" | "include_bytes"));
                if emits_public_entropy || unknown_can_emit_entropy {
                    return Err(RandomDrawApiDenyError::MacroGeneratedPublicEntropy(
                        macro_name.to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    #[derive(Default)]
    struct FillAliases<'a> {
        functions: Vec<&'a str>,
        modules: Vec<&'a str>,
    }

    fn push_alias<'a>(aliases: &mut Vec<&'a str>, alias: &'a str) {
        let alias = bare_identifier(alias);
        // Never treat `_` as a named fill alias; wildcard bindings would otherwise
        // make every underscore token look like a getrandom::fill reference.
        if alias == "_" || alias.is_empty() {
            return;
        }
        if !aliases.contains(&alias) {
            aliases.push(alias);
        }
    }

    fn path_to_fill_end(
        tokens: &[SourceToken<'_>],
        index: usize,
        module_aliases: &[&str],
    ) -> Option<usize> {
        let root = if tokens.get(index)?.text == "::" {
            index + 1
        } else if index > 0
            && tokens
                .get(index - 1)
                .is_some_and(|token| token.text == "::")
        {
            return None;
        } else {
            index
        };
        let is_getrandom = bare_identifier(tokens.get(root)?.text) == "getrandom"
            || module_aliases.contains(&bare_identifier(tokens.get(root)?.text));
        (is_getrandom
            && tokens.get(root + 1)?.text == "::"
            && bare_identifier(tokens.get(root + 2)?.text) == "fill")
            .then_some(root + 3)
    }

    fn is_invoked_after(tokens: &[SourceToken<'_>], mut index: usize) -> bool {
        while tokens.get(index).is_some_and(|token| token.text == ")") {
            index += 1;
        }
        tokens.get(index).is_some_and(|token| token.text == "(")
    }

    fn source_expression_start(tokens: &[SourceToken<'_>], mut index: usize) -> usize {
        while tokens.get(index).is_some_and(|token| token.text == "(") {
            index += 1;
        }
        index
    }

    fn getrandom_roots_after_use(
        tokens: &[SourceToken<'_>],
        use_index: usize,
        use_end: usize,
    ) -> Vec<usize> {
        // A Rust use tree may start with a grouped root (`use { getrandom as
        // alias }`) and can nest further groups or an absolute prefix. Resolve
        // every `getrandom` branch in the semicolon-bounded tree instead of
        // assuming the first token after `use` is the root.
        (use_index + 1..use_end)
            .filter(|index| bare_identifier(tokens[*index].text) == "getrandom")
            .collect()
    }

    fn fill_aliases<'a>(tokens: &[SourceToken<'a>]) -> FillAliases<'a> {
        let mut aliases = FillAliases::default();
        for index in 0..tokens.len() {
            if tokens[index].text == "extern"
                && tokens
                    .get(index + 1)
                    .is_some_and(|token| token.text == "crate")
                && tokens
                    .get(index + 2)
                    .is_some_and(|token| bare_identifier(token.text) == "getrandom")
                && tokens
                    .get(index + 3)
                    .is_some_and(|token| token.text == "as")
            {
                if let Some(alias) = tokens.get(index + 4) {
                    push_alias(&mut aliases.modules, alias.text);
                }
            }
        }
        for index in 0..tokens.len() {
            if tokens[index].text != "use" {
                continue;
            }
            let end = use_statement_end(tokens, index);
            let statement = &tokens[index..end];
            let roots = getrandom_roots_after_use(tokens, index, end);
            if roots.is_empty() {
                continue;
            }
            for root in roots {
                if tokens.get(root + 1).is_some_and(|token| token.text == "as") {
                    if let Some(alias) = tokens.get(root + 2) {
                        push_alias(&mut aliases.modules, alias.text);
                    }
                }
            }
            for self_index in 0..statement.len() {
                if bare_identifier(statement[self_index].text) == "self"
                    && statement
                        .get(self_index + 1)
                        .is_some_and(|token| token.text == "as")
                {
                    if let Some(alias) = statement.get(self_index + 2) {
                        push_alias(&mut aliases.modules, alias.text);
                    }
                }
            }
            for fill_index in 0..statement.len() {
                if bare_identifier(statement[fill_index].text) == "fill"
                    && statement
                        .get(fill_index + 1)
                        .is_some_and(|token| token.text == "as")
                {
                    push_alias(&mut aliases.functions, statement[fill_index + 2].text);
                }
                if bare_identifier(statement[fill_index].text) == "fill"
                    && statement
                        .get(fill_index + 1)
                        .is_some_and(|token| matches!(token.text, "}" | ";"))
                {
                    push_alias(&mut aliases.functions, statement[fill_index].text);
                }
            }
        }

        let mut changed = true;
        while changed {
            changed = false;
            for index in 0..tokens.len() {
                if !matches!(tokens[index].text, "let" | "const" | "static")
                    || !tokens
                        .get(index + 1)
                        .is_some_and(|token| is_identifier_token(token.text))
                {
                    continue;
                }
                let end = statement_end(tokens, index);
                let Some(equals) =
                    (index + 2..end).find(|candidate| tokens[*candidate].text == "=")
                else {
                    continue;
                };
                let expression = source_expression_start(tokens, equals + 1);
                let points_at_fill = path_to_fill_end(tokens, expression, &aliases.modules)
                    .is_some()
                    || aliases.functions.contains(&bare_identifier(
                        tokens.get(expression).map_or("", |token| token.text),
                    ));
                if points_at_fill {
                    let before = aliases.functions.len();
                    push_alias(&mut aliases.functions, tokens[index + 1].text);
                    changed |= aliases.functions.len() != before;
                }
            }
        }
        aliases
    }

    fn is_alias_definition(tokens: &[SourceToken<'_>], index: usize) -> bool {
        tokens
            .get(index.checked_sub(1).unwrap_or(tokens.len()))
            .is_some_and(|token| matches!(token.text, "as" | "let" | "const" | "static"))
    }

    fn token_is_inside_use_tree(tokens: &[SourceToken<'_>], index: usize) -> bool {
        let mut depth = 0_isize;
        for candidate in (0..=index).rev() {
            match tokens[candidate].text {
                "}" => depth += 1,
                "{" => depth -= 1,
                ";" if depth == 0 => return false,
                "use" if depth == 0 => return true,
                _ => {}
            }
        }
        false
    }

    fn semantic_fill_references(tokens: &[SourceToken<'_>]) -> Vec<usize> {
        let aliases = fill_aliases(tokens);
        (0..tokens.len())
            .filter(|index| {
                // Import trees name `getrandom::fill` without invoking it; those
                // paths are alias definitions, not executable fill references.
                if token_is_inside_use_tree(tokens, *index) {
                    return false;
                }
                let direct = path_to_fill_end(tokens, *index, &aliases.modules).is_some();
                let alias = aliases
                    .functions
                    .contains(&bare_identifier(tokens[*index].text))
                    && !is_alias_definition(tokens, *index);
                direct || alias
            })
            .collect()
    }

    fn os_random_source_fill_calls(tokens: &[SourceToken<'_>]) -> Vec<usize> {
        (0..tokens.len())
            .filter(|index| {
                bare_identifier(tokens[*index].text) == "OsRandomSource"
                    && tokens.get(index + 1).is_some_and(|token| token.text == ".")
                    && tokens
                        .get(index + 2)
                        .is_some_and(|token| bare_identifier(token.text) == "fill")
                    && is_invoked_after(tokens, index + 3)
            })
            .collect()
    }

    fn random_source_trait_aliases<'a>(tokens: &'a [SourceToken<'a>]) -> Vec<&'a str> {
        let mut aliases = Vec::new();
        for index in 0..tokens.len() {
            if tokens[index].text != "use" {
                continue;
            }
            let end = use_statement_end(tokens, index);
            for trait_index in index + 1..end {
                if !(bare_identifier(tokens[trait_index].text) == "RandomSource"
                    && tokens
                        .get(trait_index + 1)
                        .is_some_and(|token| token.text == "as"))
                {
                    continue;
                }
                if let Some(alias) = tokens.get(trait_index + 2) {
                    push_alias(&mut aliases, alias.text);
                }
            }
        }
        aliases
    }

    fn random_source_fill_calls(tokens: &[SourceToken<'_>]) -> Vec<usize> {
        let aliases = random_source_trait_aliases(tokens);
        (0..tokens.len())
            .filter(|index| {
                let direct_ufcs = (bare_identifier(tokens[*index].text) == "RandomSource"
                    || aliases.contains(&bare_identifier(tokens[*index].text)))
                    && tokens
                        .get(index + 1)
                        .is_some_and(|token| token.text == "::")
                    && tokens
                        .get(index + 2)
                        .is_some_and(|token| bare_identifier(token.text) == "fill")
                    && is_invoked_after(tokens, index + 3);
                let qualified_ufcs = tokens[*index].text == "<"
                    && (index + 1..tokens.len())
                        .find(|&candidate| tokens[candidate].text == ">")
                        .is_some_and(|closing| {
                            tokens[index + 1..closing].iter().any(|token| {
                                bare_identifier(token.text) == "RandomSource"
                                    || aliases.contains(&bare_identifier(token.text))
                            }) && tokens
                                .get(closing + 1)
                                .is_some_and(|token| token.text == "::")
                                && tokens
                                    .get(closing + 2)
                                    .is_some_and(|token| bare_identifier(token.text) == "fill")
                                && is_invoked_after(tokens, closing + 3)
                        });
                direct_ufcs || qualified_ufcs
            })
            .collect()
    }

    fn validate_random_draw_api(source: &str) -> Result<(), RandomDrawApiDenyError> {
        let tokens = lex_source(source)?;
        reject_unresolved_expansion_routes(&tokens)?;
        reject_extern_crate_getrandom(&tokens)?;
        reject_visible_value_routes(&tokens)?;
        reject_ambient_entropy_exports(&tokens)?;
        reject_visible_private_random_surfaces(&tokens)?;
        reject_public_associated_entropy_delegation(&tokens)?;
        let (callables, public_traits) = external_callables(&tokens)?;
        for expected in SEALED_EXTERNAL_CALLABLES {
            if !callables
                .iter()
                .any(|callable| matches_token_sequence(&callable.tokens, expected))
            {
                return Err(RandomDrawApiDenyError::MissingSealedExternalCallable(
                    render_tokens(
                        &expected
                            .split_ascii_whitespace()
                            .map(str::to_owned)
                            .collect::<Vec<_>>(),
                    ),
                ));
            }
        }
        for callable in callables {
            if !SEALED_EXTERNAL_CALLABLES
                .iter()
                .any(|expected| matches_token_sequence(&callable.tokens, expected))
            {
                let signature = render_tokens(&callable.tokens);
                return Err(if callable.is_module_function {
                    RandomDrawApiDenyError::UnexpectedTopLevelPublicFunction(signature)
                } else {
                    RandomDrawApiDenyError::UnexpectedExternalCallable(signature)
                });
            }
        }
        if let Some(name) = public_traits.first() {
            return Err(RandomDrawApiDenyError::PublicTrait(name.to_owned()));
        }

        let fill_references = semantic_fill_references(&tokens);
        let fill_count = fill_references.len();
        if fill_count != 1 {
            return Err(RandomDrawApiDenyError::GetrandomFillCount(fill_count));
        }

        let (owner_start, owner_end) = private_random_source_impl_span(&tokens)
            .ok_or(RandomDrawApiDenyError::GetrandomFillOutsideOsRandomSource)?;
        if !(owner_start < fill_references[0] && fill_references[0] < owner_end) {
            return Err(RandomDrawApiDenyError::GetrandomFillOutsideOsRandomSource);
        }
        if os_random_source_fill_calls(&tokens)
            .into_iter()
            .any(|call| !(owner_start < call && call < owner_end))
        {
            return Err(RandomDrawApiDenyError::GetrandomFillOutsideOsRandomSource);
        }
        if random_source_fill_calls(&tokens)
            .into_iter()
            .any(|call| !(owner_start < call && call < owner_end))
        {
            return Err(RandomDrawApiDenyError::GetrandomFillOutsideOsRandomSource);
        }

        Ok(())
    }

    fn assert_random_draw_denial_with(
        source: &str,
        expected: RandomDrawApiDenyError,
        diagnostic: &str,
        validator: fn(&str) -> Result<(), RandomDrawApiDenyError>,
    ) {
        let actual =
            validator(source).expect_err("the planted random-draw API escape must be rejected");
        assert_eq!(actual, expected);
        assert_eq!(actual.to_string(), diagnostic);
        let baseline = production_source();
        let baseline_digest = sha256_bounded(baseline.as_bytes(), baseline.len())
            .expect("baseline source is within its caller-owned hash bound");
        validate_random_draw_api(baseline)
            .expect("baseline must revalidate after every independent planted denial");
        assert_eq!(
            sha256_bounded(baseline.as_bytes(), baseline.len())
                .expect("revalidated baseline is within its caller-owned hash bound"),
            baseline_digest,
        );
    }

    fn assert_random_draw_denial(source: &str, expected: RandomDrawApiDenyError, diagnostic: &str) {
        assert_random_draw_denial_with(source, expected, diagnostic, validate_random_draw_api);
    }

    fn validate_test_module_boundary(source: &str) -> Result<(), RandomDrawApiDenyError> {
        parsed_production_source(source).map(|_| ())
    }

    fn replace_required(source: &str, pattern: &str, replacement: &str) -> String {
        assert!(
            source.contains(pattern),
            "missing mutation anchor: {pattern}"
        );
        source.replacen(pattern, replacement, 1)
    }

    #[test]
    fn api_deny_implementation_is_concrete_and_wire_neutral() {
        let production = production_source();

        assert_eq!(production.matches("getrandom::fill").count(), 1);
        assert_eq!(production.matches("Sha256::digest").count(), 1);
        assert_eq!(production.matches("Sha256::").count(), 1);
        assert!(production.contains("mac.verify_slice(tag.as_bytes())"));

        for prohibited in [
            "verify_truncated",
            "verify_slice_reset",
            "subtle::",
            "constant_time_eq",
            "pub trait RandomSource",
            "pub fn draw_bytes",
            "serde::",
            "serde_json",
            "base64::",
            "url::",
            "hex::",
            "SystemTime",
            "Instant",
            "process::id",
            "thread::current",
            "thread_rng",
            "rand::",
            "Atomic",
            "fetch_add",
            "as_ptr",
            "addr_of",
            "Sha256::new",
            "Sha256::new_with_prefix",
            "<Sha256 as",
        ] {
            assert!(
                !production.contains(prohibited),
                "prohibited production surface found: {prohibited}"
            );
        }
    }

    #[test]
    fn api_deny_hmac_surface_has_no_raw_key_or_equality_escape() {
        let production = production_source();
        let tag_surface_start = production
            .find("/// A sealed, full-width HMAC-SHA-256 authentication tag.")
            .expect("tag surface marker");
        let tag_surface_end = production[tag_surface_start..]
            .find("/// A purpose-specific 256-bit security-identifier draw.")
            .map(|offset| tag_surface_start + offset)
            .expect("next public surface marker");
        let tag_surface = &production[tag_surface_start..tag_surface_end];
        assert!(!tag_surface.contains("PartialEq"));
        assert!(!tag_surface.contains("impl Eq"));
        assert!(!tag_surface.contains("fn eq("));

        let key_surface_start = production
            .find("impl HmacSha256Key")
            .expect("key implementation marker");
        let key_surface_end = production[key_surface_start..]
            .find("impl fmt::Debug for HmacSha256Key")
            .map(|offset| key_surface_start + offset)
            .expect("key debug marker");
        let key_surface = &production[key_surface_start..key_surface_end];
        assert_eq!(key_surface.matches("pub fn ").count(), 3);
        assert!(!key_surface.contains("fn as_bytes("));
        assert!(!key_surface.contains("fn into_bytes("));
        assert!(!key_surface.contains("pub bytes:"));
        assert!(!key_surface.contains("=="));
        assert!(!key_surface.contains(".eq("));
        assert!(!key_surface.contains("Sha256::"));
        assert!(!key_surface.contains("Digest::"));
        assert!(!key_surface.contains("sha256_exact"));
    }

    #[test]
    fn api_deny_sensitive_values_are_not_implicitly_duplicable_or_serializable() {
        let production = production_source();
        let non_cloneable_surface_markers = [
            (
                "HMAC key",
                "/// A sealed, exactly 256-bit HMAC-SHA-256 key.",
                "/// A sealed, full-width HMAC-SHA-256 authentication tag.",
            ),
            (
                "HMAC tag",
                "/// A sealed, full-width HMAC-SHA-256 authentication tag.",
                "/// A purpose-specific 256-bit security-identifier draw.",
            ),
            (
                "security identifier",
                "/// A purpose-specific 256-bit security-identifier draw.",
                "/// Purpose-specific 256-bit ephemeral key material.",
            ),
            (
                "ephemeral key material",
                "/// Purpose-specific 256-bit ephemeral key material.",
                "/// Purpose-specific 128-bit nonce-domain material.",
            ),
            (
                "WebSocket mask",
                "/// Purpose-specific 32-bit WebSocket masking material.",
                "trait RandomSource",
            ),
        ];
        for (name, start_marker, end_marker) in non_cloneable_surface_markers {
            let start = production.find(start_marker).expect("surface start marker");
            let end = production[start..]
                .find(end_marker)
                .map(|offset| start + offset)
                .expect("surface end marker");
            let surface = &production[start..end];

            for prohibited_trait in [
                "#[derive(Clone",
                ", Clone",
                "#[derive(Copy",
                ", Copy",
                "PartialEq",
                ", Eq",
                "Eq,",
                "#[derive(Hash",
                ", Hash",
                "Serialize",
                "Deserialize",
            ] {
                assert!(
                    !surface.contains(prohibited_trait),
                    "{name} must not expose trait surface {prohibited_trait}"
                );
            }
        }
    }

    #[test]
    fn api_deny_random_draws_have_only_fixed_purposes() {
        let production = production_source();
        let production_digest = sha256_bounded(production.as_bytes(), production.len())
            .expect("production source is within its caller-owned hash bound");
        validate_random_draw_api(production)
            .expect("current production source must expose only sealed random-draw APIs");

        let arbitrary_free_function = format!(
            "{production}\n\npub fn arbitrary_random_bytes() -> [u8; 32] {{ draw_bytes::<32>(&OsRandomSource).expect(\"operating-system random draw\") }}\n"
        );
        assert_random_draw_denial(
            &arbitrary_free_function,
            RandomDrawApiDenyError::UnexpectedTopLevelPublicFunction(
                "pub fn arbitrary_random_bytes() -> [u8; 32]".to_owned(),
            ),
            "random draw API denial: unexpected top-level public function `pub fn arbitrary_random_bytes() -> [u8; 32]`",
        );

        let implicit_public_trait_method = format!(
            "{production}\n\npub trait ArbitraryEntropy {{ fn arbitrary<const N: usize>(&self) -> [u8; N] {{ draw_bytes::<N>(&OsRandomSource).expect(\"operating-system random draw\") }} }}\n"
        );
        assert_random_draw_denial(
            &implicit_public_trait_method,
            RandomDrawApiDenyError::UnexpectedExternalCallable(
                "ArbitraryEntropy::fn arbitrary<const N: usize>(&self) -> [u8; N]".to_owned(),
            ),
            "random draw API denial: unexpected external callable `ArbitraryEntropy::fn arbitrary<const N: usize>(&self) -> [u8; N]`",
        );

        let associated_fill_escape = format!(
            "{production}\n\nimpl Sha256Digest {{ pub fn arbitrary_fill(destination: &mut [u8]) -> Result<(), getrandom::Error> {{ OsRandomSource.fill(destination) }} }}\n"
        );
        assert_random_draw_denial(
            &associated_fill_escape,
            RandomDrawApiDenyError::PublicRawRandomSurface(
                "Sha256Digest::arbitrary_fill".to_owned(),
            ),
            "random draw API denial: public raw random surface `Sha256Digest::arbitrary_fill`",
        );

        let missing_sealed_callable =
            replace_required(production, "pub fn sha256_bounded(", "fn sha256_bounded(");
        assert_random_draw_denial(
            &missing_sealed_callable,
            RandomDrawApiDenyError::MissingSealedExternalCallable(
                "pub fn sha256_bounded(input: &[u8], max_input_bytes: usize) -> Result<Sha256Digest, CryptoInputTooLongError>".to_owned(),
            ),
            "random draw API denial: missing sealed external callable `pub fn sha256_bounded(input: &[u8], max_input_bytes: usize) -> Result<Sha256Digest, CryptoInputTooLongError>`",
        );

        let public_trait_without_methods = format!("{production}\n\npub trait EmptyEntropy {{}}\n");
        assert_random_draw_denial(
            &public_trait_without_methods,
            RandomDrawApiDenyError::PublicTrait("EmptyEntropy".to_owned()),
            "random draw API denial: public trait `EmptyEntropy`",
        );

        let second_semantic_fill = format!(
            "{production}\n\nfn second_semantic_fill(destination: &mut [u8]) -> Result<(), getrandom::Error> {{ getrandom::fill(destination) }}\n"
        );
        assert_random_draw_denial(
            &second_semantic_fill,
            RandomDrawApiDenyError::GetrandomFillCount(2),
            "random draw API denial: expected exactly one getrandom::fill reference, found 2",
        );

        for function_item_reference in [
            format!(
                "{production}\n\nfn block_wrapped_fill(destination: &mut [u8]) -> Result<(), getrandom::Error> {{ let hidden = {{ getrandom::fill }}; hidden(destination) }}\n"
            ),
            format!(
                "use ::getrandom as absolute_rng;\n{production}\n\nfn array_fill_reference() {{ let _ = [absolute_rng::fill]; }}\n"
            ),
            format!(
                "use getrandom as module_rng;\n{production}\n\nfn tuple_fill_reference() {{ let _ = (module_rng::r#fill,); }}\n"
            ),
            format!(
                "use getrandom::{{self as grouped_rng}};\n{production}\n\nfn return_fill_reference() -> fn(&mut [u8]) -> Result<(), getrandom::Error> {{ return grouped_rng::fill; }}\n"
            ),
        ] {
            assert_random_draw_denial(
                &function_item_reference,
                RandomDrawApiDenyError::GetrandomFillCount(2),
                "random draw API denial: expected exactly one getrandom::fill reference, found 2",
            );
        }

        for grouped_root_reference in [
            format!(
                "use {{ getrandom as grouped_root_rng }};\n{production}\n\nfn grouped_root_fill_outside_owner(d: &mut [u8]) -> Result<(), getrandom::Error> {{ grouped_root_rng::fill(d) }}\n"
            ),
            format!(
                "use {{ getrandom::{{self as nested_root_rng}} }};\n{production}\n\nfn nested_grouped_root_fill_reference() {{ let _ = [nested_root_rng::r#fill]; }}\n"
            ),
            format!(
                "use ::{{ getrandom as absolute_grouped_root_rng }};\n{production}\n\nfn absolute_grouped_root_fill_reference() {{ let _ = (absolute_grouped_root_rng::fill,); }}\n"
            ),
            format!(
                "use {{ r#getrandom as r#raw_grouped_root_rng }};\n{production}\n\nfn raw_grouped_root_fill_reference() -> fn(&mut [u8]) -> Result<(), getrandom::Error> {{ r#raw_grouped_root_rng::r#fill }}\n"
            ),
        ] {
            assert_random_draw_denial(
                &grouped_root_reference,
                RandomDrawApiDenyError::GetrandomFillCount(2),
                "random draw API denial: expected exactly one getrandom::fill reference, found 2",
            );
        }

        let grouped_root_fill_owner_escape = replace_required(
            &format!("use {{ getrandom as grouped_root_rng }};\n{production}"),
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        getrandom::fill(destination)\n    }\n}",
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, _destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        Err(getrandom::Error::UNEXPECTED)\n    }\n}\n\nfn grouped_root_fill_owner_escape(destination: &mut [u8]) -> Result<(), getrandom::Error> {\n    grouped_root_rng::fill(destination)\n}",
        );
        assert_random_draw_denial(
            &grouped_root_fill_owner_escape,
            RandomDrawApiDenyError::GetrandomFillOutsideOsRandomSource,
            "random draw API denial: getrandom::fill is not owned by the private OsRandomSource implementation",
        );

        for (plant, reason) in [
            (format!("{production}\n/*"), "unterminated block comment"),
            (format!("{production}\n\""), "unterminated quoted literal"),
            (format!("{production}\nr#\""), "unterminated raw literal"),
        ] {
            assert_random_draw_denial(
                &plant,
                RandomDrawApiDenyError::MalformedSource(reason),
                &format!("random draw API denial: malformed source: {reason}"),
            );
        }

        for (plant, surface) in [
            (
                format!("{production}\n\npub use getrandom::fill;\n"),
                "use getrandom::fill",
            ),
            (
                format!("{production}\n\npub(crate) use getrandom::r#fill as raw_fill;\n"),
                "use getrandom::r#fill as raw_fill",
            ),
        ] {
            assert_random_draw_denial(
                &plant,
                RandomDrawApiDenyError::PublicEntropyExport(surface.to_owned()),
                &format!("random draw API denial: public entropy export `{surface}`"),
            );
        }

        let macro_generated_entropy = format!(
            "{production}\n\nmacro_rules! export_entropy {{ () => {{ pub fn expanded_entropy() -> [u8; 32] {{ draw_bytes::<32>(&OsRandomSource).expect(\"operating-system random draw\") }} }} }}\nexport_entropy!();\n"
        );
        assert_random_draw_denial(
            &macro_generated_entropy,
            RandomDrawApiDenyError::UnresolvedExpansionRoute("macro_rules".to_owned()),
            "random draw API denial: unresolved expansion route `macro_rules`",
        );

        let neutral_type_alias = format!("{production}\n\npub type NeutralSeal = Sha256Digest;\n");
        assert_random_draw_denial(
            &neutral_type_alias,
            RandomDrawApiDenyError::UnexpectedVisibleItem(
                "type NeutralSeal = Sha256Digest".to_owned(),
            ),
            "random draw API denial: unexpected visible item `type NeutralSeal = Sha256Digest`",
        );

        let opaque_fill_through_public_static = format!(
            "{production}\n\nfn opaque_fill(destination: &mut [u8]) {{ OsRandomSource.fill(destination).expect(\"operating-system random draw\"); }}\npub static SEALED_DRAW: fn(&mut [u8]) = opaque_fill;\n"
        );
        assert_random_draw_denial(
            &opaque_fill_through_public_static,
            RandomDrawApiDenyError::PublicEntropyExport(
                "static SEALED_DRAW: fn(&mut[u8]) = opaque_fill".to_owned(),
            ),
            "random draw API denial: public entropy export `static SEALED_DRAW: fn(&mut[u8]) = opaque_fill`",
        );

        let neutral_alias_public_static_ufcs = format!(
            "{production}\n\ntype NeutralDraw = fn(&mut [u8]) -> Result<(), getrandom::Error>;\nfn ufcs_fill(destination: &mut [u8]) -> Result<(), getrandom::Error> {{ RandomSource::fill(&OsRandomSource, destination) }}\npub static SEALED_DRAW: NeutralDraw = ufcs_fill;\n"
        );
        assert_random_draw_denial(
            &neutral_alias_public_static_ufcs,
            RandomDrawApiDenyError::PublicEntropyExport(
                "static SEALED_DRAW: NeutralDraw = ufcs_fill".to_owned(),
            ),
            "random draw API denial: public entropy export `static SEALED_DRAW: NeutralDraw = ufcs_fill`",
        );

        let neutral_alias_public_const_ufcs = format!(
            "{production}\n\ntype NeutralDraw = fn(&mut [u8]) -> Result<(), getrandom::Error>;\nfn ufcs_fill(destination: &mut [u8]) -> Result<(), getrandom::Error> {{ RandomSource::fill(&OsRandomSource, destination) }}\npub const SEALED_DRAW: NeutralDraw = ufcs_fill;\n"
        );
        assert_random_draw_denial(
            &neutral_alias_public_const_ufcs,
            RandomDrawApiDenyError::PublicEntropyExport(
                "const SEALED_DRAW: NeutralDraw = ufcs_fill".to_owned(),
            ),
            "random draw API denial: public entropy export `const SEALED_DRAW: NeutralDraw = ufcs_fill`",
        );

        for private_ufcs_delegate in [
            format!(
                "{production}\n\nfn private_ufcs_delegate(destination: &mut [u8]) -> Result<(), getrandom::Error> {{ RandomSource::fill(&OsRandomSource, destination) }}\n"
            ),
            format!(
                "{production}\n\nfn private_qualified_ufcs_delegate(destination: &mut [u8]) -> Result<(), getrandom::Error> {{ <OsRandomSource as RandomSource>::r#fill(&OsRandomSource, destination) }}\n"
            ),
        ] {
            assert_random_draw_denial(
                &private_ufcs_delegate,
                RandomDrawApiDenyError::GetrandomFillOutsideOsRandomSource,
                "random draw API denial: getrandom::fill is not owned by the private OsRandomSource implementation",
            );
        }

        let private_os_random_source_delegate = format!(
            "{production}\n\nfn private_os_random_source_delegate(destination: &mut [u8]) {{ OsRandomSource.fill(destination).expect(\"operating-system random draw\"); }}\n"
        );
        assert_random_draw_denial(
            &private_os_random_source_delegate,
            RandomDrawApiDenyError::GetrandomFillOutsideOsRandomSource,
            "random draw API denial: getrandom::fill is not owned by the private OsRandomSource implementation",
        );

        let aliased_fill_outside_owner = replace_required(
            &format!("use getrandom::fill as aliased_fill;\n{production}"),
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        getrandom::fill(destination)\n    }\n}",
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, _destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        Err(getrandom::Error::UNEXPECTED)\n    }\n}\n\nfn aliased_fill_outside_owner(destination: &mut [u8]) -> Result<(), getrandom::Error> {\n    aliased_fill(destination)\n}",
        );
        assert_random_draw_denial(
            &aliased_fill_outside_owner,
            RandomDrawApiDenyError::GetrandomFillOutsideOsRandomSource,
            "random draw API denial: getrandom::fill is not owned by the private OsRandomSource implementation",
        );

        let grouped_fill_outside_owner = replace_required(
            &format!("use getrandom::{{fill as grouped_fill}};\n{production}"),
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        getrandom::fill(destination)\n    }\n}",
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, _destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        Err(getrandom::Error::UNEXPECTED)\n    }\n}\n\nfn grouped_fill_outside_owner(destination: &mut [u8]) -> Result<(), getrandom::Error> {\n    grouped_fill(destination)\n}",
        );
        assert_random_draw_denial(
            &grouped_fill_outside_owner,
            RandomDrawApiDenyError::GetrandomFillOutsideOsRandomSource,
            "random draw API denial: getrandom::fill is not owned by the private OsRandomSource implementation",
        );

        let grouped_getrandom_self_alias_outside_owner = replace_required(
            &format!("use getrandom::{{self as grouped_rng}};\n{production}"),
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        getrandom::fill(destination)\n    }\n}",
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, _destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        Err(getrandom::Error::UNEXPECTED)\n    }\n}\n\nfn grouped_getrandom_self_alias_outside_owner(destination: &mut [u8]) -> Result<(), getrandom::Error> {\n    grouped_rng::r#fill(destination)\n}",
        );
        assert_random_draw_denial(
            &grouped_getrandom_self_alias_outside_owner,
            RandomDrawApiDenyError::GetrandomFillOutsideOsRandomSource,
            "random draw API denial: getrandom::fill is not owned by the private OsRandomSource implementation",
        );

        let absolute_getrandom_alias_outside_owner = replace_required(
            &format!("use ::getrandom as absolute_rng;\n{production}"),
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        getrandom::fill(destination)\n    }\n}",
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, _destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        Err(getrandom::Error::UNEXPECTED)\n    }\n}\n\nfn absolute_getrandom_alias_outside_owner(destination: &mut [u8]) -> Result<(), getrandom::Error> {\n    absolute_rng::fill(destination)\n}",
        );
        assert_random_draw_denial(
            &absolute_getrandom_alias_outside_owner,
            RandomDrawApiDenyError::GetrandomFillOutsideOsRandomSource,
            "random draw API denial: getrandom::fill is not owned by the private OsRandomSource implementation",
        );

        for (extern_crate_alias_outside_owner, route) in [
            (
                format!("extern crate getrandom;\n{production}"),
                "extern crate getrandom",
            ),
            (
                format!("extern crate getrandom as extern_rng;\n{production}"),
                "extern crate getrandom as extern_rng",
            ),
            (
                format!("extern crate getrandom as r#extern_rng;\n{production}"),
                "extern crate getrandom as r#extern_rng",
            ),
            (
                format!("pub extern crate getrandom as public_extern_rng;\n{production}"),
                "extern crate getrandom as public_extern_rng",
            ),
            (
                format!("pub extern crate getrandom;\n{production}"),
                "extern crate getrandom",
            ),
            (
                format!("pub(crate) extern crate getrandom as r#crate_extern_rng;\n{production}"),
                "extern crate getrandom as r#crate_extern_rng",
            ),
            (
                format!("pub(crate) extern crate getrandom;\n{production}"),
                "extern crate getrandom",
            ),
            (
                format!(
                    "extern crate getrandom;\nuse self::getrandom as self_rng;\n{production}\nfn self_realias(destination: &mut [u8]) -> Result<(), getrandom::Error> {{ self_rng::fill(destination) }}\n"
                ),
                "extern crate getrandom",
            ),
            (
                format!(
                    "extern crate getrandom;\nuse crate::getrandom as crate_rng;\n{production}\nfn crate_realias(destination: &mut [u8]) -> Result<(), getrandom::Error> {{ crate_rng::fill(destination) }}\n"
                ),
                "extern crate getrandom",
            ),
        ] {
            assert_random_draw_denial(
                &extern_crate_alias_outside_owner,
                RandomDrawApiDenyError::ForbiddenExternCrateGetrandom(route.to_owned()),
                &format!("random draw API denial: forbidden extern crate route `{route}`"),
            );
        }

        let grouped_absolute_getrandom_self_alias_outside_owner = replace_required(
            &format!("use ::getrandom::{{self as absolute_grouped_rng}};\n{production}"),
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        getrandom::fill(destination)\n    }\n}",
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, _destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        Err(getrandom::Error::UNEXPECTED)\n    }\n}\n\nfn grouped_absolute_getrandom_self_alias_outside_owner(destination: &mut [u8]) -> Result<(), getrandom::Error> {\n    absolute_grouped_rng::r#fill(destination)\n}",
        );
        assert_random_draw_denial(
            &grouped_absolute_getrandom_self_alias_outside_owner,
            RandomDrawApiDenyError::GetrandomFillOutsideOsRandomSource,
            "random draw API denial: getrandom::fill is not owned by the private OsRandomSource implementation",
        );

        let grouped_random_source_trait_alias_outside_owner = format!(
            "use self::{{RandomSource as GroupedRandomSource}};\n{production}\n\nfn grouped_random_source_trait_alias_outside_owner(destination: &mut [u8]) -> Result<(), getrandom::Error> {{ GroupedRandomSource::r#fill(&OsRandomSource, destination) }}\n"
        );
        assert_random_draw_denial(
            &grouped_random_source_trait_alias_outside_owner,
            RandomDrawApiDenyError::GetrandomFillOutsideOsRandomSource,
            "random draw API denial: getrandom::fill is not owned by the private OsRandomSource implementation",
        );

        let module_local_pointer_outside_owner = replace_required(
            &format!("use getrandom as gr;\n{production}"),
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        getrandom::fill(destination)\n    }\n}",
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, _destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        Err(getrandom::Error::UNEXPECTED)\n    }\n}\n\nfn module_local_pointer_outside_owner(destination: &mut [u8]) -> Result<(), getrandom::Error> {\n    let r#local_fill: fn(&mut [u8]) -> Result<(), getrandom::Error> = (((gr::r#fill)));\n    (r#local_fill)(destination)\n}",
        );
        assert_random_draw_denial(
            &module_local_pointer_outside_owner,
            RandomDrawApiDenyError::GetrandomFillCount(2),
            "random draw API denial: expected exactly one getrandom::fill reference, found 2",
        );

        for (plant, reason) in [
            (
                format!(
                    "{}\npub fn after_tests_boundary() -> [u8; 32] {{ [0_u8; 32] }}\n",
                    include_str!("crypto.rs")
                ),
                "items follow the cfg(test) tests module",
            ),
            (
                production.to_owned(),
                "missing top-level cfg(test) tests module",
            ),
            (
                format!("{production}\n#[cfg(test)] mod tests {{}}\n#[cfg(test)] mod tests {{}}\n"),
                "multiple top-level cfg(test) modules",
            ),
            (
                format!("{production}\n#[cfg(not(test))] mod tests {{}}\n"),
                "missing top-level cfg(test) tests module",
            ),
            (
                format!("{production}\n#[cfg(test)] mod tests {{\n"),
                "unterminated tests module",
            ),
            (format!("{production}\n}}\n"), "unbalanced module braces"),
            (
                format!("{production}\n#[cfg_attr(test, must_use)]\n"),
                "top-level cfg_attr is forbidden",
            ),
        ] {
            let expected = RandomDrawApiDenyError::MalformedSource(reason);
            assert_random_draw_denial_with(
                &plant,
                expected,
                &format!("random draw API denial: malformed source: {reason}"),
                validate_test_module_boundary,
            );
        }

        for (plant, route) in [
            (
                format!("{production}\n#[path = \"crypto.rs\"] mod opaque;\n"),
                "path",
            ),
            (format!("{production}\nopaque!();\n"), "opaque"),
            (
                format!("{production}\n#[derive(UnknownExpansion)] struct Opaque;\n"),
                "derive",
            ),
            (
                format!("{production}\n#[cfg_attr(any(), derive(Clone))] struct Opaque;\n"),
                "cfg_attr",
            ),
        ] {
            assert_random_draw_denial(
                &plant,
                RandomDrawApiDenyError::UnresolvedExpansionRoute(route.to_owned()),
                &format!("random draw API denial: unresolved expansion route `{route}`"),
            );
        }

        for (pattern, replacement, surface) in [
            (
                "trait RandomSource {",
                "pub trait RandomSource {",
                "RandomSource",
            ),
            (
                "struct OsRandomSource;",
                "pub struct OsRandomSource;",
                "OsRandomSource",
            ),
            (
                "fn draw_bytes<const N: usize>",
                "pub fn draw_bytes<const N: usize>",
                "draw_bytes",
            ),
            (
                "fn draw_bytes<const N: usize>",
                "pub fn r#draw_bytes<const N: usize>",
                "draw_bytes",
            ),
        ] {
            let visibility_promotion = replace_required(production, pattern, replacement);
            assert_random_draw_denial(
                &visibility_promotion,
                RandomDrawApiDenyError::PublicRawRandomSurface(surface.to_owned()),
                &format!("random draw API denial: public raw random surface `{surface}`"),
            );
        }

        for seam in PRIVATE_WITH_SEAMS {
            let pattern = format!("fn {seam}");
            let replacement = format!("pub fn {seam}");
            let visibility_promotion = replace_required(production, &pattern, &replacement);
            assert_random_draw_denial(
                &visibility_promotion,
                RandomDrawApiDenyError::PublicRawRandomSurface(seam.to_owned()),
                &format!("random draw API denial: public raw random surface `{seam}`"),
            );
        }

        let moved_fill = replace_required(
            production,
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        getrandom::fill(destination)\n    }\n}",
            "impl RandomSource for OsRandomSource {\n    fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error> {\n        os_random_source_fill(destination)\n    }\n}\n\nfn os_random_source_fill(destination: &mut [u8]) -> Result<(), getrandom::Error> {\n    getrandom::fill(destination)\n}",
        );
        assert_random_draw_denial(
            &moved_fill,
            RandomDrawApiDenyError::GetrandomFillOutsideOsRandomSource,
            "random draw API denial: getrandom::fill is not owned by the private OsRandomSource implementation",
        );

        validate_random_draw_api(production)
            .expect("unchanged production source must validate again after the planted rejection");
        assert_eq!(
            sha256_bounded(production.as_bytes(), production.len())
                .expect("unchanged production source is within its caller-owned hash bound"),
            production_digest,
        );
    }
}
