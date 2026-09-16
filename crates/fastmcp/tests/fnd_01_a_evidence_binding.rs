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
    BindingDeclarationError, BindingDrift, ClosedChildBinding, DeclaredFact,
    MAX_BOUND_SOURCE_BYTES, SHA256_HEX_LENGTH,
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

    // CONTROL, not a discriminator. `live_sha256_hex` calls the same
    // `sha256_bounded` the module calls, so this can only ever observe
    // `sha256_bounded(x) == sha256_bounded(x)`. It is here to pin the shape of
    // an accepting outcome, and it must not be cited as proof of enforcement.
    // The discriminators in this file are the same-length mutation below and
    // the one-character digest flip in the planted negative.
    assert!(
        outcome.is_bound(),
        "CONTROL: a live-computed binding must hold"
    );
    assert!(outcome.length_matches(), "CONTROL");
    assert!(outcome.digest_matches(), "CONTROL");
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

/// The declared closed-child bindings, parsed from the evidence document.
struct DeclaredRow {
    path: String,
    owner_scope: String,
    byte_length: usize,
    sha256: String,
}

/// Parses every `[[closed_child_binding]]` row exactly as recorded.
///
/// Recorded values are used verbatim. Nothing here recomputes a digest or a
/// length: the recorded pair *is* the subject under test.
fn declared_closed_child_bindings() -> Vec<DeclaredRow> {
    let document =
        fs::read_to_string(workspace_root().join("evidence/fnd-01/dependency-verification.toml"))
            .expect("the FND-01 evidence document is readable");
    let parsed: toml::Value = document
        .parse()
        .expect("the FND-01 evidence document parses as TOML");
    // This `.get` is the ONLY line in the workspace that consumes the
    // `closed_child_binding` key. Every other mention of that string here is a
    // function name, which a grep matches without anything being read. Delete
    // this line and the declared rows silently go back to being unenforced
    // with the whole file still compiling.
    let rows = parsed
        .get("closed_child_binding")
        .and_then(toml::Value::as_array)
        .expect("the evidence document declares a closed_child_binding array");

    rows.iter()
        .map(|row| {
            let field = |name: &str| {
                row.get(name)
                    .and_then(toml::Value::as_str)
                    .unwrap_or_else(|| panic!("closed_child_binding.{name} is a string"))
                    .to_owned()
            };
            let byte_length = row
                .get("byte_length")
                .and_then(toml::Value::as_integer)
                .expect("closed_child_binding.byte_length is an integer");
            DeclaredRow {
                path: field("path"),
                owner_scope: field("owner_scope"),
                byte_length: usize::try_from(byte_length)
                    .expect("closed_child_binding.byte_length is non-negative"),
                sha256: field("sha256"),
            }
        })
        .collect()
}

/// Evaluates the **recorded** bindings against the bytes they claim to bind.
///
/// This is the case the module exists for. Every value compared here is read
/// from the evidence document as written; none is recomputed. A zero-row parse
/// fails rather than passing vacuously, because a check that silently examines
/// nothing is the exact defect this capability was added to remove.
///
/// This test is expected to FAIL while the recorded bindings are drifted. That
/// red is the mechanical proof of the drift, and it is the correct result. It
/// must not be inverted to `!is_bound()`, ignored, feature-gated, or repaired
/// by regenerating the recorded values.
#[test]
fn fnd_01_a_recorded_closed_child_bindings_hold() {
    let declared = declared_closed_child_bindings();
    assert!(
        !declared.is_empty(),
        "the evidence document must declare at least one closed-child binding; \
         an empty parse would let this check pass while examining nothing"
    );

    let mut drifted = Vec::new();
    for row in &declared {
        let binding =
            ClosedChildBinding::declare(&row.path, &row.owner_scope, row.byte_length, &row.sha256)
                .unwrap_or_else(|error| panic!("{}: malformed declaration: {error}", row.path));

        let actual = fs::read(workspace_root().join(&row.path))
            .unwrap_or_else(|error| panic!("{}: bound source unreadable: {error}", row.path));

        let outcome = binding
            .evaluate(&actual)
            .unwrap_or_else(|error| panic!("{}: {error}", row.path));

        if !outcome.is_bound() {
            drifted.push(format!(
                "{} [{}] {:?}: recorded {} bytes / {}, actual {} bytes / {}",
                row.path,
                row.owner_scope,
                outcome.drift(),
                binding.byte_length(),
                binding.sha256(),
                outcome.actual_byte_length(),
                outcome.actual_sha256(),
            ));
        }
    }

    assert!(
        drifted.is_empty(),
        "{} of {} recorded closed-child bindings no longer bind the files they name:\n{}",
        drifted.len(),
        declared.len(),
        drifted.join("\n"),
    );
}

// ---------------------------------------------------------------------------
// Policy versus reality: does the evidence document describe this repository?
// ---------------------------------------------------------------------------

/// Reads one `*_rule` string from its declaring contract table.
///
/// The rules are not at the document root; each lives under the contract that
/// owns it. Looking them up by table makes a relocated rule a loud failure
/// rather than a silently absent declaration.
fn policy_rule(document: &toml::Value, table: &str, key: &str) -> String {
    document
        .get(table)
        .unwrap_or_else(|| panic!("the evidence document declares the {table} table"))
        .get(key)
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("{table} declares {key}"))
        .to_owned()
}

/// Extracts every `nightly-YYYY-MM-DD` channel a rule names.
///
/// Scans for the literal marker rather than parsing prose, so a rule that
/// names no channel yields an empty set and is reported as such instead of
/// silently contributing nothing.
fn declared_channels(rule: &str) -> Vec<String> {
    const MARKER: &str = "nightly-";
    const DATE_LENGTH: usize = 10; // YYYY-MM-DD
    let bytes = rule.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while let Some(offset) = rule[index..].find(MARKER) {
        let start = index + offset;
        let date_start = start + MARKER.len();
        let date_end = date_start + DATE_LENGTH;
        if date_end <= bytes.len() {
            let date = &rule[date_start..date_end];
            let shaped = date.len() == DATE_LENGTH
                && date.as_bytes().iter().enumerate().all(|(position, byte)| {
                    if position == 4 || position == 7 {
                        *byte == b'-'
                    } else {
                        byte.is_ascii_digit()
                    }
                });
            if shaped {
                let channel = format!("{MARKER}{date}");
                if !found.contains(&channel) {
                    found.push(channel);
                }
            }
        }
        index = start + MARKER.len();
    }
    found
}

/// Extracts the `rust-version <major>.<minor>` a rule names, if any.
fn declared_rust_version(rule: &str) -> Option<String> {
    const MARKER: &str = "rust-version ";
    let start = rule.find(MARKER)? + MARKER.len();
    let rest = &rule[start..];
    let end = rest
        .find(|character: char| !(character.is_ascii_digit() || character == '.'))
        .unwrap_or(rest.len());
    let version = &rest[..end];
    if version.is_empty() || !version.contains('.') {
        return None;
    }
    Some(version.to_owned())
}

/// The evidence document must describe *this* repository.
///
/// This is a consistency check, not a literal-value assertion. It does not
/// require any particular toolchain: it requires that the toolchain the
/// evidence document declares is the toolchain the repository actually pins,
/// and that the `rust-version` the document tells the documentation to state
/// is the one the workspace actually declares and the documentation actually
/// states.
///
/// This test is expected to FAIL while the document is behind the project's
/// deliberate toolchain move. The red is the inventory for the re-attest that
/// owns correcting it; it must not be resolved here by editing the policy
/// string, nor by asserting the document's stale literals, which would demand
/// the repository move backwards.
#[test]
fn fnd_01_a_policy_describes_this_repository() {
    let root = workspace_root();
    let evidence: toml::Value =
        fs::read_to_string(root.join("evidence/fnd-01/dependency-verification.toml"))
            .expect("the FND-01 evidence document is readable")
            .parse()
            .expect("the FND-01 evidence document parses as TOML");

    // --- what the repository actually is --------------------------------
    let toolchain: toml::Value = fs::read_to_string(root.join("rust-toolchain.toml"))
        .expect("rust-toolchain.toml is readable")
        .parse()
        .expect("rust-toolchain.toml parses as TOML");
    let actual_channel = toolchain
        .get("toolchain")
        .and_then(|table| table.get("channel"))
        .and_then(toml::Value::as_str)
        .expect("rust-toolchain.toml declares toolchain.channel")
        .to_owned();

    let manifest: toml::Value = fs::read_to_string(root.join("Cargo.toml"))
        .expect("the workspace manifest is readable")
        .parse()
        .expect("the workspace manifest parses as TOML");
    let actual_rust_version = manifest
        .get("workspace")
        .and_then(|table| table.get("package"))
        .and_then(|table| table.get("rust-version"))
        .and_then(toml::Value::as_str)
        .expect("the workspace declares rust-version")
        .to_owned();

    let agents = fs::read_to_string(root.join("AGENTS.md")).expect("AGENTS.md is readable");

    // --- what the evidence document declares ----------------------------
    let rules = [
        (
            "workspace_manifest_integration_contract",
            "toolchain_relationship_rule",
        ),
        ("repository_surface_contract", "toolchain_rule"),
        (
            "repository_surface_contract",
            "documentation_toolchain_rule",
        ),
    ];

    let mut divergences = Vec::new();
    let mut compared = 0_usize;

    for (table, key) in rules {
        let rule = policy_rule(&evidence, table, key);
        let channels = declared_channels(&rule);
        assert!(
            !channels.is_empty(),
            "{key} names no toolchain channel; a rule that declares nothing \
             would let this check pass while comparing nothing"
        );
        for channel in channels {
            let fact = DeclaredFact::declare(&format!("{key} toolchain channel"), &channel)
                .expect("a nonempty declared channel is admissible");
            let outcome = fact.compare(&actual_channel);
            compared += 1;
            if !outcome.describes_repository() {
                divergences.push(outcome.to_string());
            }
        }

        if let Some(version) = declared_rust_version(&rule) {
            let fact = DeclaredFact::declare(&format!("{key} rust-version"), &version)
                .expect("a nonempty declared rust-version is admissible");
            let outcome = fact.compare(&actual_rust_version);
            compared += 1;
            if !outcome.describes_repository() {
                divergences.push(outcome.to_string());
            }
        }
    }

    // The documentation side: AGENTS.md must state the repository's real
    // toolchain and rust-version, so a divergence cannot be blamed on the
    // docs having moved instead of the policy.
    for (subject, expected) in [
        ("AGENTS.md toolchain channel", actual_channel.as_str()),
        ("AGENTS.md rust-version", actual_rust_version.as_str()),
    ] {
        let stated = if agents.contains(expected) {
            expected.to_owned()
        } else {
            "absent".to_owned()
        };
        let fact =
            DeclaredFact::declare(subject, expected).expect("a nonempty expectation is admissible");
        let outcome = fact.compare(&stated);
        compared += 1;
        if !outcome.describes_repository() {
            divergences.push(outcome.to_string());
        }
    }

    assert!(
        compared >= rules.len(),
        "every declared toolchain rule must contribute at least one comparison"
    );
    assert!(
        divergences.is_empty(),
        "the FND-01 evidence document does not describe this repository \
         ({} of {} compared facts diverge):\n{}",
        divergences.len(),
        compared,
        divergences.join("\n"),
    );
}
