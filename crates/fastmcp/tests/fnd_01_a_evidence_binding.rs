//! FND-01 A: closed-child source-freeze enforcement, proven from outside.
//!
//! External consumer of the packaged `fastmcp-rust` facade: it reaches the
//! capability the way a downstream crate does, via `use fastmcp_rust::...`,
//! never through `use super` and never under `cfg(test)` inside the library
//! (PL-3).
//!
//! The positive binds a declaration to bytes whose length and digest are
//! **computed live in the test** from a real checked-in source file, so no
//! assertion is anchored to a constant copied from the artifact under test
//! (RH-5). The planted negatives each change exactly one variable — one hex
//! character of the digest, or one byte of the recorded length — and prove the
//! typed refusal plus that every other observed field is unchanged.
//!
//! No-claim boundary: this proves the enforcement mechanism. It does not
//! repair, re-issue or re-freeze any binding, and it takes no position on
//! whether the campaign's currently recorded bindings hold.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use fastmcp_rust::evidence_binding::{
    BindingDeclarationError, BindingDrift, ClosedChildBinding, MAX_BOUND_SOURCE_BYTES,
    SHA256_HEX_LENGTH,
};

/// A real checked-in source file, used so the positive binds actual bytes
/// rather than a synthetic buffer.
const SUBJECT_PATH: &str = "crates/fastmcp-core/src/crypto.rs";
const SUBJECT_OWNER_SCOPE: &str = "bd-mcp-2026-07-28-support-ahet.1.9";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root exists above crates/fastmcp")
        .to_path_buf()
}

fn subject_bytes() -> Vec<u8> {
    fs::read(workspace_root().join(SUBJECT_PATH)).expect("bound source file is readable")
}

/// Renders a digest the way the evidence document records one, computed here
/// rather than copied, so the positive cannot be satisfied by a stale constant.
fn live_sha256_hex(bytes: &[u8]) -> String {
    let digest = fastmcp_rust::sha256_bounded(bytes, MAX_BOUND_SOURCE_BYTES)
        .expect("subject stays inside the hashing bound");
    let mut rendered = String::with_capacity(SHA256_HEX_LENGTH);
    for byte in digest.as_bytes() {
        rendered.push_str(&format!("{byte:02x}"));
    }
    rendered
}

/// Flips exactly one hex character of a digest, leaving its length and every
/// other character identical.
fn flip_one_digest_character(digest: &str) -> String {
    let mut characters: Vec<char> = digest.chars().collect();
    let last = characters.len() - 1;
    characters[last] = if characters[last] == '0' { '1' } else { '0' };
    characters.into_iter().collect()
}

#[test]
fn fnd_01_a_closed_child_binding_positive() {
    let bytes = subject_bytes();
    let live_digest = live_sha256_hex(&bytes);

    let binding =
        ClosedChildBinding::declare(SUBJECT_PATH, SUBJECT_OWNER_SCOPE, bytes.len(), &live_digest)
            .expect("a well-formed declaration is admitted");

    assert_eq!(binding.path(), SUBJECT_PATH);
    assert_eq!(binding.owner_scope(), SUBJECT_OWNER_SCOPE);
    assert_eq!(binding.byte_length(), bytes.len());
    assert_eq!(binding.sha256(), live_digest);

    let outcome = binding
        .evaluate(&bytes)
        .expect("the subject is inside the hashing bound");

    // The binding holds, and every observed field says why.
    assert!(outcome.is_bound(), "a live-computed binding must hold");
    assert!(outcome.length_matches());
    assert!(outcome.digest_matches());
    assert_eq!(outcome.drift(), BindingDrift::Bound);
    assert!(BindingDrift::Bound.is_bound());
    assert_eq!(outcome.declared_byte_length(), bytes.len());
    assert_eq!(outcome.actual_byte_length(), bytes.len());
    assert_eq!(outcome.actual_sha256(), live_digest);
    assert_eq!(outcome.actual_sha256().len(), SHA256_HEX_LENGTH);

    // Evaluation is a pure function of the bytes: repeating it is identical.
    assert_eq!(
        binding
            .evaluate(&bytes)
            .expect("second evaluation succeeds"),
        outcome,
        "evaluation must not depend on anything but the supplied bytes"
    );

    // Independence of the two checked fields, proven positively: a
    // same-length edit still fails the digest. This is the drift shape a
    // length-only comparison cannot see.
    let mut same_length = bytes.clone();
    let last = same_length.len() - 1;
    same_length[last] ^= 0x01;
    let same_length_outcome = binding
        .evaluate(&same_length)
        .expect("the mutated subject is inside the hashing bound");
    assert!(same_length_outcome.length_matches());
    assert!(!same_length_outcome.digest_matches());
    assert_eq!(same_length_outcome.drift(), BindingDrift::ContentOnly);
    assert!(!same_length_outcome.is_bound());
}

#[test]
fn fnd_01_a_closed_child_binding_planted_negative() {
    let bytes = subject_bytes();
    let live_digest = live_sha256_hex(&bytes);

    let control =
        ClosedChildBinding::declare(SUBJECT_PATH, SUBJECT_OWNER_SCOPE, bytes.len(), &live_digest)
            .expect("the unmutated declaration is admitted");
    let control_outcome = control.evaluate(&bytes).expect("the control evaluates");
    assert!(control_outcome.is_bound(), "the control must hold");

    // --- Mutation 1: exactly one hex character of the digest -------------
    let mutated_digest = flip_one_digest_character(&live_digest);
    assert_eq!(
        mutated_digest.len(),
        live_digest.len(),
        "the digest mutation must change no length"
    );
    assert_eq!(
        mutated_digest
            .chars()
            .zip(live_digest.chars())
            .filter(|(mutated, original)| mutated != original)
            .count(),
        1,
        "exactly one digest character may differ"
    );

    let digest_mutant = ClosedChildBinding::declare(
        SUBJECT_PATH,
        SUBJECT_OWNER_SCOPE,
        bytes.len(),
        &mutated_digest,
    )
    .expect("a one-character digest change is still well formed");
    let outcome = digest_mutant
        .evaluate(&bytes)
        .expect("the mutant evaluates");

    assert!(!outcome.is_bound(), "a mutated digest must not bind");
    assert!(!outcome.digest_matches());
    assert_eq!(outcome.drift(), BindingDrift::ContentOnly);
    // Unchanged-state proof: every other observed field equals the control.
    assert!(
        outcome.length_matches(),
        "the length field must be untouched"
    );
    assert_eq!(
        outcome.declared_byte_length(),
        control_outcome.declared_byte_length()
    );
    assert_eq!(
        outcome.actual_byte_length(),
        control_outcome.actual_byte_length()
    );
    assert_eq!(
        outcome.actual_sha256(),
        control_outcome.actual_sha256(),
        "the computed digest depends on the bytes, never on the declaration"
    );

    // --- Mutation 2: exactly one byte of the recorded length -------------
    let length_mutant = ClosedChildBinding::declare(
        SUBJECT_PATH,
        SUBJECT_OWNER_SCOPE,
        bytes.len() + 1,
        &live_digest,
    )
    .expect("a one-byte length change is still well formed");
    let outcome = length_mutant
        .evaluate(&bytes)
        .expect("the mutant evaluates");

    assert!(!outcome.is_bound(), "a mutated length must not bind");
    assert!(!outcome.length_matches());
    assert_eq!(outcome.drift(), BindingDrift::LengthOnly);
    // Unchanged-state proof: the digest half is untouched.
    assert!(
        outcome.digest_matches(),
        "the digest field must be untouched"
    );
    assert_eq!(
        outcome.actual_byte_length(),
        control_outcome.actual_byte_length()
    );
    assert_eq!(outcome.actual_sha256(), control_outcome.actual_sha256());
    assert_eq!(outcome.declared_byte_length(), bytes.len() + 1);

    // --- Mutation 3: malformed declarations reach the typed refusal ------
    assert_eq!(
        ClosedChildBinding::declare("", SUBJECT_OWNER_SCOPE, bytes.len(), &live_digest)
            .expect_err("an empty path must refuse"),
        BindingDeclarationError::EmptyPath
    );
    assert_eq!(
        ClosedChildBinding::declare(SUBJECT_PATH, "", bytes.len(), &live_digest)
            .expect_err("an empty owner scope must refuse"),
        BindingDeclarationError::EmptyOwnerScope
    );
    assert_eq!(
        ClosedChildBinding::declare(
            SUBJECT_PATH,
            SUBJECT_OWNER_SCOPE,
            bytes.len(),
            &live_digest[..SHA256_HEX_LENGTH - 1],
        )
        .expect_err("a short digest must refuse"),
        BindingDeclarationError::DigestLength
    );
    assert_eq!(
        ClosedChildBinding::declare(
            SUBJECT_PATH,
            SUBJECT_OWNER_SCOPE,
            bytes.len(),
            &live_digest.to_uppercase(),
        )
        .expect_err("an uppercase digest must refuse"),
        BindingDeclarationError::DigestNotLowercaseHex
    );

    // The control is still admissible and still binds: no mutation above
    // disturbed the unmutated declaration.
    let reaccepted =
        ClosedChildBinding::declare(SUBJECT_PATH, SUBJECT_OWNER_SCOPE, bytes.len(), &live_digest)
            .expect("the control remains admissible");
    assert_eq!(reaccepted, control);
    assert_eq!(
        reaccepted.evaluate(&bytes).expect("re-evaluates"),
        control_outcome
    );
}
