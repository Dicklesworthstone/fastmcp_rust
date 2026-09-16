//! FND-01 A: enforcement for the authoritative closed-child source freeze.
//!
//! This module is the shipped, non-`cfg(test)` public surface that makes a
//! declared closed-child binding *checkable*. Each binding in
//! `evidence/fnd-01/dependency-verification.toml` names an owned source path,
//! the scope that closed over it, and the byte length and SHA-256 that were
//! authoritative when it was recorded.
//!
//! # Why this exists
//!
//! Those rows were, until this module, read by no code anywhere in the
//! workspace. A freeze that nothing checks is not a freeze: a declared binding
//! can drift arbitrarily far from the file it claims to bind and no evaluator
//! notices. Enforcement is the missing capability, not fresher numbers —
//! recomputing the recorded digests to make them agree would destroy the only
//! evidence that drift occurred.
//!
//! # What this module does and does not decide
//!
//! It answers one question per row: *does this declared binding match these
//! actual bytes?* It is a pure function of `(declaration, bytes)`. It performs
//! no filesystem access, reads no ambient state, and takes no position on what
//! a drifted binding should cost — repairing or re-issuing a binding belongs
//! to the integration scope that owns the receipt, and deciding whether a
//! drifted campaign may proceed belongs to independent verification.
//!
//! Both checked fields are reported independently and neither short-circuits
//! the other, because the two drift shapes are diagnostically different. A
//! same-length, different-content edit is exactly the case a length-only
//! comparison misses, so the digest is always evaluated even when the length
//! already disagrees.

use fastmcp_core::sha256_bounded;

/// Maximum bytes this module will digest for one bound source file.
///
/// Bounded before hashing so an oversized or truncated input is a typed
/// refusal rather than unbounded work. The largest currently bound source is
/// well under this ceiling.
pub const MAX_BOUND_SOURCE_BYTES: usize = 8 * 1024 * 1024;

/// SHA-256 digests are recorded as 64 lowercase hex characters.
pub const SHA256_HEX_LENGTH: usize = 64;

/// A closed-child binding exactly as the evidence document declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedChildBinding {
    path: String,
    owner_scope: String,
    byte_length: usize,
    sha256: String,
}

/// A malformed declaration, refused before any comparison is attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingDeclarationError {
    /// The bound path was empty.
    EmptyPath,
    /// The owning scope was empty.
    EmptyOwnerScope,
    /// The recorded digest was not exactly 64 characters.
    DigestLength,
    /// The recorded digest contained a character outside `0-9a-f`.
    ///
    /// Uppercase is refused deliberately: the digest is compared as recorded,
    /// so admitting two spellings of one value would make equality depend on
    /// how the document happened to be written.
    DigestNotLowercaseHex,
}

impl std::fmt::Display for BindingDeclarationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPath => formatter.write_str("closed-child binding path must be nonempty"),
            Self::EmptyOwnerScope => {
                formatter.write_str("closed-child binding owner scope must be nonempty")
            }
            Self::DigestLength => {
                formatter.write_str("closed-child binding digest must be 64 hex characters")
            }
            Self::DigestNotLowercaseHex => {
                formatter.write_str("closed-child binding digest must be lowercase hex")
            }
        }
    }
}

impl std::error::Error for BindingDeclarationError {}

/// Why a digest could not be computed for the supplied bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundSourceError {
    /// The supplied bytes exceeded [`MAX_BOUND_SOURCE_BYTES`].
    TooLarge {
        /// Bytes supplied.
        supplied: usize,
        /// The configured ceiling.
        ceiling: usize,
    },
}

impl std::fmt::Display for BoundSourceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { supplied, ceiling } => write!(
                formatter,
                "bound source of {supplied} bytes exceeds the {ceiling}-byte hashing bound"
            ),
        }
    }
}

impl std::error::Error for BoundSourceError {}

impl ClosedChildBinding {
    /// Records a declared binding, refusing a malformed one.
    ///
    /// # Errors
    ///
    /// Returns [`BindingDeclarationError`] when a field is empty or the digest
    /// is not exactly 64 lowercase hex characters.
    pub fn declare(
        path: &str,
        owner_scope: &str,
        byte_length: usize,
        sha256: &str,
    ) -> Result<Self, BindingDeclarationError> {
        if path.is_empty() {
            return Err(BindingDeclarationError::EmptyPath);
        }
        if owner_scope.is_empty() {
            return Err(BindingDeclarationError::EmptyOwnerScope);
        }
        if sha256.len() != SHA256_HEX_LENGTH {
            return Err(BindingDeclarationError::DigestLength);
        }
        if !sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(BindingDeclarationError::DigestNotLowercaseHex);
        }
        Ok(Self {
            path: path.to_owned(),
            owner_scope: owner_scope.to_owned(),
            byte_length,
            sha256: sha256.to_owned(),
        })
    }

    /// The bound source path, exactly as declared.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The scope that closed over this source.
    #[must_use]
    pub fn owner_scope(&self) -> &str {
        &self.owner_scope
    }

    /// The authoritative byte length recorded for this source.
    #[must_use]
    pub const fn byte_length(&self) -> usize {
        self.byte_length
    }

    /// The authoritative SHA-256, as 64 lowercase hex characters.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Evaluates this declaration against the actual bytes of the bound file.
    ///
    /// # Errors
    ///
    /// Returns [`BoundSourceError::TooLarge`] when the supplied bytes exceed
    /// [`MAX_BOUND_SOURCE_BYTES`]; the declaration is neither accepted nor
    /// refused in that case, because no digest was computed.
    pub fn evaluate(&self, actual: &[u8]) -> Result<BindingOutcome, BoundSourceError> {
        let digest = sha256_bounded(actual, MAX_BOUND_SOURCE_BYTES).map_err(|_| {
            BoundSourceError::TooLarge {
                supplied: actual.len(),
                ceiling: MAX_BOUND_SOURCE_BYTES,
            }
        })?;
        let actual_sha256 = lowercase_hex(digest.as_bytes());
        // Both fields are always evaluated. A same-length, different-content
        // edit is precisely the drift a length-only comparison misses.
        Ok(BindingOutcome {
            declared_byte_length: self.byte_length,
            actual_byte_length: actual.len(),
            digest_matches: actual_sha256 == self.sha256,
            actual_sha256,
        })
    }
}

/// Renders a digest as 64 lowercase hex characters.
fn lowercase_hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = String::with_capacity(SHA256_HEX_LENGTH);
    for &byte in bytes {
        rendered.push(char::from(DIGITS[usize::from(byte >> 4)]));
        rendered.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    rendered
}

/// The observed relationship between one declaration and one file's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingOutcome {
    declared_byte_length: usize,
    actual_byte_length: usize,
    actual_sha256: String,
    digest_matches: bool,
}

impl BindingOutcome {
    /// The byte length the declaration recorded.
    #[must_use]
    pub const fn declared_byte_length(&self) -> usize {
        self.declared_byte_length
    }

    /// The byte length actually supplied.
    #[must_use]
    pub const fn actual_byte_length(&self) -> usize {
        self.actual_byte_length
    }

    /// The digest actually computed, as 64 lowercase hex characters.
    #[must_use]
    pub fn actual_sha256(&self) -> &str {
        &self.actual_sha256
    }

    /// Whether the recorded length matches the supplied bytes.
    #[must_use]
    pub const fn length_matches(&self) -> bool {
        self.declared_byte_length == self.actual_byte_length
    }

    /// Whether the recorded digest matches the supplied bytes.
    #[must_use]
    pub const fn digest_matches(&self) -> bool {
        self.digest_matches
    }

    /// Whether the binding holds: both recorded fields match.
    #[must_use]
    pub const fn is_bound(&self) -> bool {
        self.length_matches() && self.digest_matches()
    }

    /// The drift classification for this row.
    #[must_use]
    pub const fn drift(&self) -> BindingDrift {
        match (self.length_matches(), self.digest_matches()) {
            (true, true) => BindingDrift::Bound,
            (true, false) => BindingDrift::ContentOnly,
            (false, true) => BindingDrift::LengthOnly,
            (false, false) => BindingDrift::LengthAndContent,
        }
    }
}

/// How a declared binding relates to the bytes it claims to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingDrift {
    /// Length and digest both match; the freeze holds for this row.
    Bound,
    /// The length matches but the content changed.
    ///
    /// This is the case a length-only comparison cannot see, which is why the
    /// digest is evaluated unconditionally.
    ContentOnly,
    /// The digest matches but the recorded length does not.
    ///
    /// Only reachable from a mis-recorded declaration, since equal content
    /// implies equal length.
    LengthOnly,
    /// Neither recorded field matches.
    LengthAndContent,
}

impl BindingDrift {
    /// Whether this classification means the binding holds.
    #[must_use]
    pub const fn is_bound(self) -> bool {
        matches!(self, Self::Bound)
    }
}
