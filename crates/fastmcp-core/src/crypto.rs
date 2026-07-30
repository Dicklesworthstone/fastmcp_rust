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

use hmac::{Hmac, Mac};
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
        <HmacSha256 as Mac>::new_from_slice(&self.bytes)
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

    use zeroize::Zeroize as _;

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
        let source = include_str!("crypto.rs");
        source
            .split_once("\n#[cfg(test)]")
            .map_or(source, |(production, _)| production)
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
        assert_eq!(production.matches("pub fn draw_").count(), 5);
        for required_signature in [
            "pub fn draw_hmac_sha256_key()",
            "pub fn draw_security_identifier()",
            "pub fn draw_ephemeral_key_material()",
            "pub fn draw_nonce_domain_material()",
            "pub fn draw_websocket_mask()",
        ] {
            assert!(
                production.contains(required_signature),
                "missing sealed draw: {required_signature}"
            );
        }
    }
}
