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
    // `toml::from_str`, NOT `str::parse`. `<toml::Value as FromStr>` routes
    // through `ValueDeserializer`, which parses a single TOML *value* and then
    // expects end-of-input, so it rejects a whole document with "unexpected
    // content, expected nothing". `from_str` is the document deserializer,
    // which is what the ordinary verifier's `parse_toml_strict` uses.
    let parsed: toml::Value =
        toml::from_str(&document).expect("the FND-01 evidence document parses as a TOML document");
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

/// The revision at which each owning child bead actually closed.
///
/// Derived mechanically, not chosen: for each row, the owning bead's `closed_at`
/// was read from the tracker and the closure revision is the last commit
/// touching that exact path with author time at or before it. These are
/// immutable historical revisions, so unlike a working-tree measurement they
/// cannot rot. They are named here rather than hashed here so that every digest
/// below stays computed from the repository instead of copied into source.
///
/// path, owner_scope, closure revision, owning bead's closed_at (UTC).
const CLOSURE_REVISIONS: &[(&str, &str, &str, &str)] = &[
    (
        "crates/fastmcp-core/src/crypto.rs",
        "bd-mcp-2026-07-28-support-ahet.1.9",
        "7d79aa36",
        "2026-08-22T15:04:25Z",
    ),
    (
        "crates/fastmcp-core/src/uri.rs",
        "bd-mcp-2026-07-28-support-ahet.1.8",
        "b2863887",
        "2026-08-22T23:00:53Z",
    ),
    (
        "crates/fastmcp-server/src/auth.rs",
        "bd-mcp-2026-07-28-support-ahet.1.11",
        "9007adce",
        "2026-08-03T18:54:42Z",
    ),
    (
        "crates/fastmcp-server/src/oauth.rs",
        "bd-mcp-2026-07-28-support-ahet.1.10",
        "00cb860c",
        "2026-09-01T09:04:02Z",
    ),
    (
        "crates/fastmcp-server/src/oidc.rs",
        "bd-mcp-2026-07-28-support-ahet.1.11",
        "9007adce",
        "2026-08-03T18:54:42Z",
    ),
    (
        "crates/fastmcp-transport/src/websocket.rs",
        "bd-mcp-2026-07-28-support-ahet.1.10",
        "00cb860c",
        "2026-09-01T09:04:02Z",
    ),
];

/// Looks up the closure revision for a bound path.
fn closure_revision(path: &str) -> (&'static str, &'static str) {
    CLOSURE_REVISIONS
        .iter()
        .find(|(candidate, ..)| *candidate == path)
        .map(|(_, _, revision, closed_at)| (*revision, *closed_at))
        .unwrap_or_else(|| {
            panic!(
                "{path}: no closure revision is recorded for this bound path. A row was added to \
                 the evidence document without a corresponding closure revision here, which \
                 would leave it silently unchecked."
            )
        })
}

/// Reads the bytes of `path` as of `revision`, straight from Git object storage.
///
/// Fails closed. A missing `git`, a detached object store, or an unknown
/// revision is a hard failure rather than a skip, because a check that
/// silently examines nothing is the exact defect this capability exists to
/// remove.
fn blob_at_revision(revision: &str, path: &str) -> Vec<u8> {
    let output = std::process::Command::new("git")
        .args(["cat-file", "blob", &format!("{revision}:{path}")])
        .current_dir(workspace_root())
        .output()
        .unwrap_or_else(|error| {
            panic!("{path}: cannot run `git cat-file blob {revision}:{path}`: {error}")
        });
    assert!(
        output.status.success(),
        "{path}: `git cat-file blob {revision}:{path}` failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    output.stdout
}

/// Evaluates the **recorded** bindings against the LIVE WORKING TREE.
///
/// RE-AUTHORED BASELINE (2026-09-17, user-authorized). The six rows now record
/// the bytes each owning child actually handed off at its own closure
/// revision, derived mechanically via `git cat-file blob`. Before that, the
/// rows were the 2026-07-30 policy-authoring snapshot, which predated every
/// child closure by 4 to 33 days and so described nobody's handoff; the check
/// was pointed at the closure revision purely to keep that failure stable and
/// diagnosable. That workaround is now retired.
///
/// THE COMPARAND IS THE WORKING TREE, DELIBERATELY. `baseline_rule` requires
/// the bound paths be re-opened and re-compared "after every producer
/// command/write, immediately before directory publication, in ordinary
/// read-only verification, and independently in final attestation". The row is
/// the immutable anchor; the tree is the mutable thing under test. Comparing a
/// row against the same revision it was derived from would pass by
/// construction and prove nothing — see
/// `fnd_01_a_closed_child_rows_match_their_closure_revisions`, which makes
/// that provenance comparison separately and is labelled as a control.
///
/// THIS TEST IS STILL EXPECTED TO FAIL, and the remaining failures are the
/// finding. Five of the six closed children's delivered outputs were modified
/// after those children closed; `uri.rs` was not, and passes. That 5-fire /
/// 1-pass split is the proof this gate discriminates rather than being red by
/// construction.
///
/// The correct response to a failure here is to adjudicate the post-closure
/// modification it names — never to edit the bound file, and never to
/// re-anchor a row to make it quiet.
#[test]
fn fnd_01_a_recorded_closed_child_bindings_hold() {
    let declared = declared_closed_child_bindings();
    assert!(
        !declared.is_empty(),
        "the evidence document must declare at least one closed-child binding; \
         an empty parse would let this check pass while examining nothing"
    );

    assert_eq!(
        declared.len(),
        CLOSURE_REVISIONS.len(),
        "every declared closed-child row must have exactly one closure revision; a row without \
         one would go unchecked, and a closure revision without a row would check nothing"
    );

    let mut drifted = Vec::new();
    for row in &declared {
        let binding =
            ClosedChildBinding::declare(&row.path, &row.owner_scope, row.byte_length, &row.sha256)
                .unwrap_or_else(|error| panic!("{}: malformed declaration: {error}", row.path));

        let (revision, closed_at) = closure_revision(&row.path);

        // THE SUBJECT: the live working tree, which is what `baseline_rule`
        // re-opens after every producer command/write.
        let working_tree = fs::read(workspace_root().join(&row.path))
            .unwrap_or_else(|error| panic!("{}: bound source unreadable: {error}", row.path));

        let outcome = binding
            .evaluate(&working_tree)
            .unwrap_or_else(|error| panic!("{}: {error}", row.path));

        let population = if outcome.is_bound() {
            "UNMODIFIED since closure"
        } else {
            "MODIFIED AFTER CLOSURE - adjudicate the commits, do not edit the file"
        };

        if !outcome.is_bound() {
            drifted.push(format!(
                "{} [{}]\n    {:?}: recorded {} bytes / {}\n              handoff @ {} ({}) {} bytes / {}\n    {}",
                row.path,
                row.owner_scope,
                outcome.drift(),
                binding.byte_length(),
                binding.sha256(),
                revision,
                closed_at,
                outcome.actual_byte_length(),
                outcome.actual_sha256(),
                population,
            ));
        }
    }

    assert!(
        drifted.is_empty(),
        "{} of {} closed-child bound paths no longer match the bytes their owning child \
         handed off at closure.\n\nThis is the finding, not a nuisance: a CLOSED child's \
         delivered output was modified after it closed. Adjudicate the commits named on each \
         row - re-close the child at its true delivered revision, or accept the change and \
         re-anchor that single row under explicit authorization. Do NOT edit the bound file to \
         silence this, and do NOT re-anchor a row merely to make it quiet (RH-3).\n\nThe rows \
         themselves are sound: they were re-authored 2026-09-17 at each child's closure \
         revision by mechanical derivation, and they reproduce \
         closed_child_handoff_contract.registry_sha256 exactly.\n\n{}",
        drifted.len(),
        declared.len(),
        drifted.join("\n"),
    );
}

/// PROVENANCE CONTROL for the 2026-09-17 re-authored baseline.
///
/// Verifies that every recorded row really is the byte length and digest of
/// its owning child's closure revision, recomputed here from Git rather than
/// read from the document.
///
/// This is a CONTROL, not a drift gate, and it must never be cited as evidence
/// that the closed-child capability is enforced. It compares a row against the
/// same revision the row was derived from, so it is green by construction for
/// any correctly derived registry — which is exactly its job: it fails if
/// someone hand-edits a row, re-anchors one to a different revision, or tunes
/// a value to quiet a failure (RH-3). The test that can actually observe drift
/// is `fnd_01_a_recorded_closed_child_bindings_hold`, which compares against
/// the live working tree.
#[test]
fn fnd_01_a_closed_child_rows_match_their_closure_revisions() {
    let declared = declared_closed_child_bindings();
    assert_eq!(
        declared.len(),
        CLOSURE_REVISIONS.len(),
        "every declared row must have exactly one closure revision"
    );
    assert!(!declared.is_empty(), "a zero-row parse would prove nothing");

    let mut wrong = Vec::new();
    for row in &declared {
        let (revision, _) = closure_revision(&row.path);
        let handoff = blob_at_revision(revision, &row.path);
        let digest = live_sha256_hex(&handoff);
        if handoff.len() != row.byte_length || digest != row.sha256 {
            wrong.push(format!(
                "{} @{}: recorded {} bytes / {}, closure revision holds {} bytes / {}",
                row.path,
                revision,
                row.byte_length,
                row.sha256,
                handoff.len(),
                digest,
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "{} recorded row(s) are NOT the bytes of the closure revision they claim. The registry \
         was hand-edited, re-anchored, or tuned rather than mechanically derived:\n{}",
        wrong.len(),
        wrong.join("\n"),
    );
}

/// Proves the corrected subject can actually fire.
///
/// The check above is red for a reason outside its own control, so on its own
/// it cannot demonstrate that a closure-revision binding is capable of
/// distinguishing anything. This does: it takes a row whose recorded digest is
/// genuinely the digest of its closure-revision bytes (constructed here from
/// the real handoff so no constant is copied), confirms it binds, then changes
/// exactly one byte of those bytes and requires the typed refusal — proving
/// every other observed field byte-for-byte unchanged (RH-5).
#[test]
fn fnd_01_a_closure_revision_subject_planted_negative() {
    const SUBJECT: &str = "crates/fastmcp-core/src/uri.rs";
    let (revision, _) = closure_revision(SUBJECT);
    let handoff = blob_at_revision(revision, SUBJECT);
    assert!(
        !handoff.is_empty(),
        "the closure-revision handoff must be non-empty, or the mutation below would be vacuous"
    );

    let owner_scope = CLOSURE_REVISIONS
        .iter()
        .find(|(path, ..)| *path == SUBJECT)
        .map(|(_, owner, ..)| *owner)
        .expect("the subject has a recorded owner scope");

    // A correctly anchored row: digest computed from the handoff bytes here,
    // never copied from the artifact under test.
    let digest = live_sha256_hex(&handoff);
    let binding = ClosedChildBinding::declare(SUBJECT, owner_scope, handoff.len(), &digest)
        .expect("a correctly anchored declaration is admitted");

    let control = binding
        .evaluate(&handoff)
        .expect("the handoff is inside the hashing bound");
    assert!(
        control.is_bound(),
        "a row anchored at its own closure revision must bind those bytes"
    );
    assert_eq!(control.drift(), BindingDrift::Bound);

    // --- Mutation: exactly one byte of the handoff, length preserved --------
    let mut mutated = handoff.clone();
    let last = mutated.len() - 1;
    mutated[last] ^= 0x01;

    let outcome = binding
        .evaluate(&mutated)
        .expect("the mutated subject is inside the hashing bound");

    assert!(
        !outcome.is_bound(),
        "a one-byte change to the handoff must not bind"
    );
    assert_eq!(outcome.drift(), BindingDrift::ContentOnly);
    assert!(outcome.length_matches(), "the mutation preserved length");
    assert!(!outcome.digest_matches());

    // Every other observed field is unchanged by the mutation.
    assert_eq!(binding.path(), SUBJECT);
    assert_eq!(binding.owner_scope(), owner_scope);
    assert_eq!(binding.byte_length(), handoff.len());
    assert_eq!(binding.sha256(), digest);
    assert_eq!(outcome.declared_byte_length(), handoff.len());
    assert_eq!(outcome.actual_byte_length(), handoff.len());
    assert_ne!(outcome.actual_sha256(), digest);
    assert_eq!(outcome.actual_sha256().len(), SHA256_HEX_LENGTH);

    // The control is unaffected by having evaluated the mutation.
    assert_eq!(
        binding.evaluate(&handoff).expect("re-evaluates"),
        control,
        "evaluating a mutation must not disturb the accepting outcome"
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
    let evidence_text =
        fs::read_to_string(root.join("evidence/fnd-01/dependency-verification.toml"))
            .expect("the FND-01 evidence document is readable");
    let evidence: toml::Value = toml::from_str(&evidence_text)
        .expect("the FND-01 evidence document parses as a TOML document");

    // --- what the repository actually is --------------------------------
    let toolchain_text = fs::read_to_string(root.join("rust-toolchain.toml"))
        .expect("rust-toolchain.toml is readable");
    let toolchain: toml::Value =
        toml::from_str(&toolchain_text).expect("rust-toolchain.toml parses as a TOML document");
    let actual_channel = toolchain
        .get("toolchain")
        .and_then(|table| table.get("channel"))
        .and_then(toml::Value::as_str)
        .expect("rust-toolchain.toml declares toolchain.channel")
        .to_owned();

    let manifest_text =
        fs::read_to_string(root.join("Cargo.toml")).expect("the workspace manifest is readable");
    let manifest: toml::Value =
        toml::from_str(&manifest_text).expect("the workspace manifest parses as a TOML document");
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

// ---------------------------------------------------------------------------
// workspace_snapshot: the same defect as the closed-child rows, at 24x scale
// ---------------------------------------------------------------------------

/// Collects every regular file beneath `root`, skipping the directories the
/// contract excludes, and returns repository-relative slash-separated paths.
fn walk_regular_files(root: &Path, base: &Path, found: &mut Vec<String>) {
    const EXCLUDED_DIRECTORIES: &[&str] = &["target", ".git", ".fnd01-run"];
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(_) => continue,
        };
        if kind.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if EXCLUDED_DIRECTORIES.contains(&name.as_ref()) {
                continue;
            }
            walk_regular_files(&path, base, found);
        } else if kind.is_file() {
            if let Ok(relative) = path.strip_prefix(base) {
                found.push(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }
}

/// Every declared `[[workspace_binding]]` path.
fn declared_workspace_binding_paths(document: &toml::Value) -> Vec<String> {
    document
        .get("workspace_binding")
        .and_then(toml::Value::as_array)
        .expect("the evidence document declares a workspace_binding array")
        .iter()
        .map(|row| {
            row.get("path")
                .and_then(toml::Value::as_str)
                .expect("workspace_binding.path is a string")
                .to_owned()
        })
        .collect()
}

/// Enforces `closed_scan_root_rule` and `required_absent_path_rule`.
///
/// SUBJECT CORRECTION (2026-09-17), same reasoning as the closed-child rows
/// above and applied in the same pass. This is the identical defect at 24x
/// scale: `[[workspace_binding]]` is a frozen measurement of a mutable tree,
/// authored once and never re-authored, while the campaign kept adding files
/// beneath the scan roots. Previously the failure surfaced as a bare count
/// through the policy-owned verifier; here every offending path is enumerated
/// so the red is attributable instead of merely large.
///
/// This test is EXPECTED TO FAIL. The registries themselves are intact — the
/// declared row count matches the contract and no bound path is missing — so
/// every failure below is an ADDITION that postdates the freeze, not a
/// deletion or a tampering. Re-authoring the registry to absorb them is
/// reserved to the freeze-policy owner and is not licensed here; weakening
/// either rule to match reality would be RH-1/RH-3.
#[test]
fn fnd_01_a_workspace_snapshot_describes_this_repository() {
    let root = workspace_root();
    let document: toml::Value = toml::from_str(
        &fs::read_to_string(root.join("evidence/fnd-01/dependency-verification.toml"))
            .expect("the FND-01 evidence document is readable"),
    )
    .expect("the FND-01 evidence document parses as a TOML document");

    let snapshot = document
        .get("workspace_snapshot")
        .expect("the evidence document declares workspace_snapshot");
    let scan_roots: Vec<String> = snapshot
        .get("closed_scan_roots")
        .and_then(toml::Value::as_array)
        .expect("workspace_snapshot declares closed_scan_roots")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("closed_scan_roots entries are strings")
                .to_owned()
        })
        .collect();
    assert!(
        !scan_roots.is_empty(),
        "an empty closed_scan_roots would let this check pass while walking nothing"
    );

    let bound = declared_workspace_binding_paths(&document);
    assert!(
        !bound.is_empty(),
        "an empty workspace_binding array would let this check pass while examining nothing"
    );

    let mut unbound = Vec::new();
    let mut missing = Vec::new();
    for scan_root in &scan_roots {
        let mut found = Vec::new();
        walk_regular_files(&root.join(scan_root), &root, &mut found);
        let prefix = format!("{scan_root}/");
        let bound_here: Vec<&String> = bound.iter().filter(|p| p.starts_with(&prefix)).collect();
        for path in &found {
            if !bound_here.iter().any(|bound_path| *bound_path == path) {
                unbound.push(path.clone());
            }
        }
        for bound_path in bound_here {
            if !found.contains(bound_path) {
                missing.push(bound_path.clone());
            }
        }
    }
    unbound.sort();
    missing.sort();

    // `required_absent_path_rule`: a present node fails rather than being ignored.
    let mut present_forbidden = Vec::new();
    for value in snapshot
        .get("required_absent_paths")
        .and_then(toml::Value::as_array)
        .expect("workspace_snapshot declares required_absent_paths")
    {
        let declared = value
            .as_str()
            .expect("required_absent_paths entries are strings");
        if root.join(declared).exists() {
            present_forbidden.push(declared.to_owned());
        }
    }

    assert!(
        unbound.is_empty() && missing.is_empty() && present_forbidden.is_empty(),
        "workspace_snapshot no longer describes this repository.\n\n\
         {} unlisted regular file(s) beneath closed_scan_roots {:?} (closed_scan_root_rule: \"an \
         unlisted regular file, symlink, hardlink, special file, missing row, or extra row \
         fails\").\n{} bound path(s) missing from the tree.\n{} required-absent path(s) present \
         (required_absent_path_rule).\n\n\
         ROOT CAUSE: same as the closed-child rows — a frozen measurement of a mutable tree. The \
         registry itself is intact ({} declared rows, {} missing), so every entry below is an \
         ADDITION that postdates the freeze, produced by legitimate campaign work in other \
         lanes.\n\n\
         NOTE: a present `.cargo` is additionally a NORMATIVE conflict, not mere rot — FND-02's \
         package contract mandates a checked-in .cargo/config.toml carrying the xtask alias while \
         this rule forbids .cargo existing at all, and FND-02 depends on FND-01. That collision \
         crosses lanes and is escalated, not resolvable here. Do not delete the file.\n\n\
         UNLISTED:\n{}\n\nMISSING:\n{}\n\nPRESENT BUT REQUIRED ABSENT:\n{}",
        unbound.len(),
        scan_roots,
        missing.len(),
        present_forbidden.len(),
        bound.len(),
        missing.len(),
        unbound.join("\n"),
        missing.join("\n"),
        present_forbidden.join("\n"),
    );
}

// ===========================================================================
// bd-fnd01-anchoring-false-attestation-44sow
// WORKSPACE-INPUT PROVENANCE: the REVISION anchor.
// ===========================================================================

/// The frozen verifier that DECLARES the workspace-input bindings.
///
/// READ, NEVER WRITTEN. That path is `ordered_paths[1]` (policy `:284`) and
/// `authoring_write_paths[1]` under `authoring_owner = ahet.1.14` (`:2850`),
/// so a byte change there resets the authoring quiet window and belongs to
/// that bead alone. This file is named in the policy only in a comment
/// (`:230`) and in none of those lists, which is why the check lives here.
///
/// ITS TEXT IS PARSED RATHER THAN ITS VALUES COPIED. A re-declared copy would
/// satisfy this test while silently drifting from the table actually in force
/// — and the module contract above forbids anchoring an assertion to a
/// constant copied from the artifact under test (RH-5). Parsing keeps the two
/// sides of every comparison in different artifacts: the declaration on one
/// side, Git object storage on the other.
const WORKSPACE_INPUT_DECLARATION_SOURCE: &str =
    "crates/fastmcp/tests/fnd_01_dependency_evidence.rs";

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceInputRow {
    path: String,
    byte_length: usize,
    sha256: String,
    revision: String,
}

/// Splits one tuple-literal row into its fields, respecting quotes.
///
/// Underscores are NOT stripped here: `7_224` is a numeric separator but a
/// path may legitimately contain `_`, and a blanket strip would corrupt the
/// join key. The caller strips them from the field it parses as a number.
fn parse_tuple_fields(row: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for character in row.chars() {
        match character {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => fields.push(std::mem::take(&mut current)),
            _ if in_quotes || !character.is_whitespace() => current.push(character),
            _ => {}
        }
    }
    fields.push(current);
    fields
        .into_iter()
        .map(|field| field.trim().to_owned())
        .filter(|field| !field.is_empty())
        .collect()
}

/// Extracts the tuple rows of a `const <name>: [...; N] = [...]` declaration.
///
/// Fails closed at every step. A missing declaration, an unterminated literal,
/// or a parsed row count that disagrees with the `N` in the declared type is a
/// hard failure rather than a short vector, because a silently partial parse
/// would make every assertion built on it vacuous while still looking green.
fn parse_declared_tuple_rows(source: &str, name: &str) -> Vec<Vec<String>> {
    let marker = format!("const {name}:");
    let start = source.find(&marker).unwrap_or_else(|| {
        panic!("{name} is declared in {WORKSPACE_INPUT_DECLARATION_SOURCE}")
    });
    let tail = &source[start..];
    let assignment = tail
        .find("= [")
        .unwrap_or_else(|| panic!("{name} assigns an array literal"));
    let declared_type = &tail[..assignment];
    let declared_count: usize = declared_type
        .rsplit(';')
        .next()
        .and_then(|fragment| fragment.split(']').next())
        .unwrap_or_else(|| panic!("{name} declares an array length"))
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("{name} declares a decimal array length"));

    let body_start = assignment + 3;
    let body_end = tail[body_start..]
        .find("];")
        .unwrap_or_else(|| panic!("{name}'s array literal is terminated"))
        + body_start;
    let body = &tail[body_start..body_end];

    let mut rows = Vec::new();
    let mut rest = body;
    while let Some(open) = rest.find('(') {
        let close = rest[open..]
            .find(')')
            .unwrap_or_else(|| panic!("{name} has an unterminated tuple row"))
            + open;
        rows.push(parse_tuple_fields(&rest[open + 1..close]));
        rest = &rest[close + 1..];
    }

    assert_eq!(
        rows.len(),
        declared_count,
        "{name}: parsed {} row(s) but the declared type says {declared_count}. A partial parse \
         must fail here rather than silently shrink the population under test",
        rows.len(),
    );
    rows
}

/// Blanks `//` line comments so a commented-out call cannot read as live.
///
/// MEASURED NECESSITY: without this, the liveness guard below passed with EVERY
/// call site commented out, because the substring was still present. That is the
/// defect the guard exists to refuse, committed one level up inside the guard.
///
/// BLOCK COMMENTS ARE DELIBERATELY NOT STRIPPED, and the reason is measured. A
/// first version also consumed `/* ... */`. The verifier contains `/*` inside
/// STRING LITERALS — glob patterns such as `"/*"` and `"dist/**"` — and holds 7
/// `/*` against only 2 `*/`, so an unmatched opener swallowed **2,102,460 of
/// 4,001,124 characters (53%)**, both call sites included. The guard then read 0
/// live sites on perfectly good source and would have failed for everyone,
/// permanently. "Over-stripping fails closed" was the right direction and the
/// wrong magnitude: a guard that is supposed to always pass fails closed INTO A
/// PERMANENT RED, which is not a safe error.
///
/// Line-only stripping removes 57,273 characters (1.4%) and is correct on all
/// three controls: real source stays at 2 live sites, a commented-out call and a
/// rewired table both drop to 0. A `//` inside a string truncates that one line,
/// which is bounded damage and can only make the guard fire.
fn strip_line_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| line.find("//").map_or(line, |at| &line[..at]))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Refuses to validate a table the verifier no longer uses.
///
/// THE FALSE-PASS INPUT THIS CLOSES. Everything below reads the two constants
/// out of the frozen verifier's TEXT. That binds the check to a DECLARATION,
/// and a declaration can outlive its use: rewire the verifier to a different
/// table, leave these constants in place, and the parse still succeeds, the
/// git comparisons still pass, and every test here reports GREEN while the
/// table actually in force goes unchecked. Measured by simulating exactly that
/// rewire on the real source — the declarations survive and the count of live
/// call sites drops from 2 to 0.
///
/// So liveness is asserted rather than assumed: at least one call to the pure
/// checker must consume BOTH constants. This cannot prove the verifier is
/// correct, only that the table under test is the table being used.
///
/// RESIDUAL LIMITS, MEASURED AND STATED RATHER THAN IMPLIED. Comments are
/// stripped before scanning, so a commented-out call no longer counts — without
/// that, this guard passed with EVERY call site commented out, still reporting
/// two live sites. Two cases remain that a text scan cannot decide: a call
/// behind a `#[cfg(..)]` that is off in the build under test, and the literal
/// call text inside a string. Both were tried and both kept the guard green at
/// two sites. Its strength is "the call text exists outside comments", NOT
/// "the call executes", and it must not be cited as the latter.
fn assert_workspace_input_tables_are_live(source: &str) {
    const CALL: &str = "fnd_01_check_workspace_input_anchoring(";
    const WINDOW: usize = 260;

    let source = &strip_line_comments(source);
    let mut live = 0usize;
    let mut cursor = 0usize;
    while let Some(found) = source[cursor..].find(CALL) {
        let at = cursor + found;
        let mut end = (at + WINDOW).min(source.len());
        while !source.is_char_boundary(end) {
            end -= 1;
        }
        let window = &source[at..end];
        if window.contains("TOOLCHAIN_WORKSPACE_INPUTS")
            && window.contains("TOOLCHAIN_WORKSPACE_INPUT_PROVENANCE")
        {
            live += 1;
        }
        cursor = at + CALL.len();
    }

    assert!(
        live > 0,
        "no call to fnd_01_check_workspace_input_anchoring consumes both \
         TOOLCHAIN_WORKSPACE_INPUTS and TOOLCHAIN_WORKSPACE_INPUT_PROVENANCE. The constants \
         are still DECLARED, so every check in this file would parse them and pass — while \
         the table the verifier actually uses goes unexamined. A declaration that outlives \
         its use is exactly the false premise this bead exists to refuse."
    );
}

/// Joins the binding table to the provenance table by path.
///
/// The two tables are declared separately and the pure checker already proves
/// their path sets are equal; this join re-derives that rather than assuming
/// it, so a divergence shows up as a hard failure instead of a dropped row.
fn declared_workspace_input_rows() -> Vec<WorkspaceInputRow> {
    let source =
        fs::read_to_string(workspace_root().join(WORKSPACE_INPUT_DECLARATION_SOURCE))
            .expect("the FND-01 verifier source is readable");

    assert_workspace_input_tables_are_live(&source);

    let bindings = parse_declared_tuple_rows(&source, "TOOLCHAIN_WORKSPACE_INPUTS");
    let provenance = parse_declared_tuple_rows(&source, "TOOLCHAIN_WORKSPACE_INPUT_PROVENANCE");
    assert!(
        !bindings.is_empty(),
        "a zero-row parse would let every assertion below pass while examining nothing"
    );
    assert_eq!(
        bindings.len(),
        provenance.len(),
        "every bound workspace input must carry exactly one provenance row"
    );

    bindings
        .iter()
        .map(|binding| {
            let [path, byte_length, sha256] = binding.as_slice() else {
                panic!("a TOOLCHAIN_WORKSPACE_INPUTS row is (path, byte_length, sha256)")
            };
            let revision = provenance
                .iter()
                .find_map(|row| match row.as_slice() {
                    [anchored_path, revision] if anchored_path == path => Some(revision.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{path} is bound but carries no provenance row"));
            WorkspaceInputRow {
                path: path.clone(),
                byte_length: byte_length
                    .replace('_', "")
                    .parse()
                    .unwrap_or_else(|_| panic!("{path}: byte_length is a decimal count")),
                sha256: sha256.clone(),
                revision,
            }
        })
        .collect()
}

/// Every commit touching `path`, newest first, WITHOUT history simplification.
///
/// `--full-history` is load-bearing, not hygiene. Plain `git log -- <path>`
/// simplifies merge history and OMITS commits that really did modify the file:
/// measured on this repository, 79 default vs 103 full-history for `Cargo.toml`,
/// 114 vs 134 for `Cargo.lock`, 7 vs 9 for `rust-toolchain.toml`, against 79
/// reachable merges. A staleness check built on the simplified list can report
/// "anchor is the latest mover" while a later commit moved it — passing while
/// carrying a false premise, which is the exact defect this bead exists to close.
///
/// Fails closed for the same reason `blob_at_revision` does: a check that
/// silently examines nothing is the defect this capability exists to remove.
fn commits_touching(path: &str) -> Vec<String> {
    let output = std::process::Command::new("git")
        .args(["log", "--full-history", "--format=%H", "--", path])
        .current_dir(workspace_root())
        .output()
        .unwrap_or_else(|error| panic!("{path}: cannot run `git log -- {path}`: {error}"));
    assert!(
        output.status.success(),
        "{path}: `git log -- {path}` failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// PROPERTY 2: the blob at each anchor equals the recorded length AND digest.
///
/// Returns one line per divergence rather than asserting, so the positive and
/// the planted negative drive the SAME predicate — a negative that
/// re-implements the check proves the re-implementation discriminates, not
/// this one.
fn workspace_input_provenance_drift(rows: &[WorkspaceInputRow]) -> Vec<String> {
    let mut drift = Vec::new();
    for row in rows {
        let anchored = blob_at_revision(&row.revision, &row.path);
        let digest = live_sha256_hex(&anchored);
        if anchored.len() != row.byte_length || digest != row.sha256 {
            drift.push(format!(
                "{} @{}: recorded {} bytes / {}, the anchor holds {} bytes / {}",
                row.path,
                row.revision,
                row.byte_length,
                row.sha256,
                anchored.len(),
                digest,
            ));
        }
    }
    drift
}

/// PROPERTY 3: nothing has moved the bound path since its anchor.
///
/// TWO TRIGGERS, DELIBERATELY NOT COLLAPSED, because they are different
/// defects with different severities and one can hide the other.
///
///   CONTENT DRIFT  the bytes at HEAD differ from the bytes at the anchor. The message
///                  carries BOTH DIGESTS, not only lengths: a same-length edit is real and
///                  observed — planting a stale anchor on `rust-toolchain.toml` yields
///                  "anchor 239 bytes, HEAD 239 bytes" while the content genuinely differs,
///                  which reads as a contradiction unless the digests are shown. A
///                  length-only comparison would have missed that drift entirely.
///                  The recorded digest no longer describes the tree, so the
///                  binding is stale and the anchor's claim is false. This is
///                  what a dependency-pin refresh produces.
///   LATER TOUCHER  the bytes are identical but a later commit touched the
///                  path (a revert, a no-op rewrite). The digest is still
///                  true; only the attribution is stale. Reported, because
///                  the declared property is "the anchor is the LATEST commit
///                  touching that path", and narrowing that to content alone
///                  would be weakening the check to match reality.
///
/// CONTENT IS THE PRIMARY TRIGGER AND IT IS EVALUATED FIRST, because it is
/// derived from object storage and cannot be defeated by history traversal at
/// all. The commit list is used only to ATTRIBUTE a drift that content has
/// already proven. A check whose only evidence is `git log` can pass while
/// false whenever simplification omits the modifying commit — see
/// `commits_touching`, where that omission is measured rather than assumed.
fn workspace_input_unaccounted_movers(rows: &[WorkspaceInputRow]) -> Vec<String> {
    let mut movers = Vec::new();
    for row in rows {
        let anchored = blob_at_revision(&row.revision, &row.path);
        let current = blob_at_revision("HEAD", &row.path);
        let history = commits_touching(&row.path);
        let position = history.iter().position(|commit| *commit == row.revision);

        if anchored != current {
            let attribution = match (history.first(), position) {
                (Some(latest), Some(later)) => format!(
                    "{later} later commit(s) touched it, most recently {latest}"
                ),
                (Some(latest), None) => format!(
                    "its anchor is absent from this path's full history; most recent is {latest}"
                ),
                (None, _) => "no commit in this history touches the path".to_owned(),
            };
            movers.push(format!(
                "{}: CONTENT DRIFT since anchor {} - anchor holds {} bytes / {}, HEAD holds {} \
                 bytes / {}; {}",
                row.path,
                row.revision,
                anchored.len(),
                live_sha256_hex(&anchored),
                current.len(),
                live_sha256_hex(&current),
                attribution,
            ));
            continue;
        }

        match (history.first(), position) {
            (_, Some(0)) => {}
            (Some(latest), Some(later)) => movers.push(format!(
                "{}: LATER TOUCHER of anchor {} - content is unchanged, but {later} later \
                 commit(s) touched it, most recently {latest}",
                row.path, row.revision,
            )),
            (Some(latest), None) => movers.push(format!(
                "{}: anchor {} does not appear in this path's full history at all; its most \
                 recent commit is {latest}",
                row.path, row.revision,
            )),
            (None, _) => movers.push(format!(
                "{}: no commit in this history touches a bound path",
                row.path
            )),
        }
    }
    movers
}

/// PROPERTY 2, AND THE CONTROL THAT MAKES THE NEXT TEST ATTRIBUTABLE.
///
/// `fnd_01_check_workspace_input_anchoring` asserts set-equality over the path
/// columns and a 40-hex shape on each revision. It never reads the bytes, so
/// it cannot assert that the recorded commit produced them. The TREE half of
/// that gap is already closed elsewhere and already fires: `checked_read` is
/// handed a `FileBinding` by `toolchain_workspace_inputs_with_bindings`, so a
/// digest that disagrees with the working tree surfaces as `E_FILE_LENGTH`
/// wrapped in `E_TOOLCHAIN_ASUPERSYNC`. What nothing checked is the REVISION
/// half: that the anchor really holds those bytes.
///
/// EXPECTED GREEN, and that is the point. If this fails, the instrument is
/// broken and the red below means nothing; if it passes, the anchors are
/// honest and a property-3 failure is a real finding rather than a
/// misconfigured harness.
///
/// WHAT IT STILL CANNOT DETECT, stated rather than implied: reading Git object
/// storage establishes what THIS repository holds at a revision. It cannot
/// establish that this repository is what any external party published, that
/// the history was not rewritten before the read, or that the anchor was
/// chosen honestly rather than back-fitted to bytes already written.
#[test]
fn fnd_01_a_workspace_inputs_bind_the_bytes_of_their_anchors() {
    let rows = declared_workspace_input_rows();
    assert!(!rows.is_empty(), "a zero-row parse would prove nothing");

    let drift = workspace_input_provenance_drift(&rows);
    assert!(
        drift.is_empty(),
        "{} recorded workspace input(s) are NOT the bytes of the commit they name. A recorded \
         pair that disagrees with its own anchor was hand-edited or re-anchored rather than \
         mechanically derived, and the anchor is then a false attestation carried by a green \
         check:\n{}",
        drift.len(),
        drift.join("\n"),
    );
}

/// PROPERTY 3: no unaccounted mover since the anchor.
///
/// THIS TEST IS EXPECTED TO FAIL, and the failure is the finding. A dependency
/// refresh regenerates `Cargo.lock` and moves `Cargo.toml` while nothing
/// obliges it to re-attest; the pure checker cannot notice because the path
/// SET is unchanged, and the tree check reports only that some length differs.
/// This names the commit responsible.
///
/// THE CORRECT RESPONSE TO A RED HERE IS TO ADJUDICATE THE MOVE IT NAMES —
/// never to edit the bound file, and never to re-anchor a row to make it
/// quiet. Re-attestation is legitimate only from the mover, with the drift
/// enumerated; a re-attest that merely updates a number is indistinguishable
/// from a regeneration-to-get-green (RH-3).
#[test]
fn fnd_01_a_workspace_input_anchors_are_the_latest_movers() {
    let rows = declared_workspace_input_rows();
    assert!(!rows.is_empty(), "a zero-row parse would prove nothing");

    let movers = workspace_input_unaccounted_movers(&rows);
    assert!(
        movers.is_empty(),
        "{} bound workspace input(s) were moved after the commit they are anchored to. The \
         recorded bytes therefore describe an older tree while the anchor still claims to be \
         current, and no check in the frozen verifier can see it:\n{}",
        movers.len(),
        movers.join("\n"),
    );
}

/// PLANTED NEGATIVE for property 2 — exactly the mutation this bead names.
///
/// The failure mode is a digest moved to match new bytes while the provenance
/// commit is left alone: the check then passes while the anchor falsely claims
/// to have produced them. This performs that mutation and nothing else — one
/// hex character of one digest, the revision untouched — and requires both the
/// typed refusal AND that a second accepted row stays green, so a negative
/// that merely proves "something fails" cannot satisfy it.
#[test]
fn fnd_01_a_workspace_input_digest_move_is_refused() {
    let rows = declared_workspace_input_rows();
    let clean = workspace_input_provenance_drift(&rows);
    let accepted: Vec<&WorkspaceInputRow> = rows
        .iter()
        .filter(|row| !clean.iter().any(|line| line.starts_with(&format!("{} @", row.path))))
        .collect();
    assert!(
        accepted.len() >= 2,
        "this control needs two rows that already bind at their anchors, so the red below is \
         caused by the plant rather than by pre-existing drift; found {}",
        accepted.len(),
    );

    let target = accepted[0].path.clone();
    let witness = accepted[1].path.clone();
    let mut planted = rows.clone();
    for row in &mut planted {
        if row.path == target {
            row.sha256 = flip_one_digest_character(&row.sha256);
        }
    }
    assert_ne!(
        planted, rows,
        "the plant must actually change the table it is testing"
    );

    let drift = workspace_input_provenance_drift(&planted);
    assert!(
        drift.iter().any(|line| line.starts_with(&format!("{target} @"))),
        "a digest moved away from its anchor's bytes, with the provenance commit untouched, must \
         be refused; got {drift:?}"
    );
    assert!(
        !drift.iter().any(|line| line.starts_with(&format!("{witness} @"))),
        "the plant changed exactly one row, so {witness} must remain green; got {drift:?}"
    );
}

/// PLANTED NEGATIVE for property 3, built from real history.
///
/// The stale anchor is DERIVED at run time — the second-newest commit touching
/// a bound path — rather than written as a constant, so the plant stays valid
/// as history grows and cannot pass by matching a number someone typed. It
/// isolates one clause: the bytes are untouched and only the anchor moves
/// backwards by exactly one commit.
#[test]
fn fnd_01_a_workspace_input_stale_anchor_is_refused() {
    let rows = declared_workspace_input_rows();
    let planted_row = rows
        .iter()
        .find(|row| commits_touching(&row.path).len() >= 2)
        .expect("at least one bound path has two commits in its history")
        .clone();
    let history = commits_touching(&planted_row.path);
    let previous = history[1].clone();
    let latest = history[0].clone();

    let mut planted = rows.clone();
    for row in &mut planted {
        if row.path == planted_row.path {
            row.revision = previous.clone();
        }
    }

    let movers = workspace_input_unaccounted_movers(&planted);
    let reported = movers
        .iter()
        .find(|line| line.starts_with(&format!("{}: ", planted_row.path)))
        .unwrap_or_else(|| {
            panic!(
                "an anchor one commit behind the latest mover must be refused; got {movers:?}"
            )
        });
    assert!(
        reported.contains("1 later commit(s)") && reported.contains(&latest),
        "the refusal must name how far behind the anchor is and which commit moved it last; got \
         {reported}"
    );
}
