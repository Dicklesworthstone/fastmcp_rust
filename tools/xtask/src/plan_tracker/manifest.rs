//! Canonical receipts.
//!
//! Receipts are typed structs, not dynamic maps: `serde_json` emits a struct's
//! fields in declaration order and a `Value` map in alphabetical order, and a
//! receipt whose field order depends on how it was built is not canonical.
//!
//! The revision binding is a set of Git blob identities, never a commit SHA.
//! `main` is rebased here; a commit SHA stops resolving while the bytes it
//! described are untouched, so a commit-bound receipt reports drift that did
//! not happen and misses drift that did.

use serde::Serialize;

use super::digest::sha256_hex;

/// Outcome of one ordered subcase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Pass,
    Fail,
}

/// One ordered subcase result.
#[derive(Debug, Clone, Serialize)]
pub struct SubcaseOutcome {
    pub id: String,
    pub name: String,
    pub outcome: Outcome,
    pub diagnostic_count: usize,
}

/// One authoritative source, bound by content.
#[derive(Debug, Clone, Serialize)]
pub struct SourceReceipt {
    pub id: String,
    pub path: String,
    pub blob_sha1: String,
}

/// The `fnd-02-a-manifest-v1` canonical receipt.
#[derive(Debug, Clone, Serialize)]
pub struct AManifest {
    pub schema: String,
    pub canonical_plan_sha256: String,
    pub canonical_trace_table_sha256: String,
    pub evaluator_argv: Vec<String>,
    pub profile: String,
    pub target: String,
    pub features: String,
    pub toolchain: String,
    /// Content-addressed revision binding. Blob identities, not commit SHAs.
    pub source_bindings: Vec<SourceReceipt>,
    /// SHA-256 over the ordered source bindings; the "tree" for this receipt.
    pub source_tree_sha256: String,
    pub trace_row_count: usize,
    pub observed_fields_per_row: usize,
    pub required_item_count: usize,
    pub subcases: Vec<SubcaseOutcome>,
    pub consumer_id: String,
    pub write_counters: [u64; 6],
}

pub const A_MANIFEST_SCHEMA: &str = "fnd-02-a-manifest-v1";

/// Digest over the ordered source bindings.
///
/// Domain-separated and length-prefixed so that concatenating two different
/// binding lists cannot produce one preimage.
pub fn source_tree_digest(sources: &[SourceReceipt]) -> String {
    let mut preimage: Vec<u8> = Vec::new();
    preimage.extend_from_slice(b"FND02SRCTREEv1\0");
    preimage.extend_from_slice(&(sources.len() as u32).to_be_bytes());
    for source in sources {
        for field in [&source.id, &source.path, &source.blob_sha1] {
            preimage.extend_from_slice(&(field.len() as u32).to_be_bytes());
            preimage.extend_from_slice(field.as_bytes());
        }
    }
    sha256_hex(&preimage)
}

impl AManifest {
    /// Canonical JSON rendering. Declaration order, stable across runs.
    pub fn to_canonical_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("manifest serialization is infallible")
    }

    /// Digest of the canonical rendering.
    pub fn digest(&self) -> String {
        sha256_hex(self.to_canonical_json().as_bytes())
    }

    /// True when every declared digest field is 64 lowercase hex characters.
    pub fn digests_are_canonical(&self) -> bool {
        [
            &self.canonical_plan_sha256,
            &self.canonical_trace_table_sha256,
            &self.source_tree_sha256,
        ]
        .into_iter()
        .all(|value| is_lowercase_hex(value, 64))
            && self
                .source_bindings
                .iter()
                .all(|binding| is_lowercase_hex(&binding.blob_sha1, 40))
    }

    pub fn all_subcases_passed(&self) -> bool {
        !self.subcases.is_empty()
            && self
                .subcases
                .iter()
                .all(|subcase| subcase.outcome == Outcome::Pass)
    }
}

/// Exactly `width` characters, each a lowercase hex digit.
pub fn is_lowercase_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> AManifest {
        let bindings = vec![SourceReceipt {
            id: "s".to_owned(),
            path: "p".to_owned(),
            blob_sha1: "a".repeat(40),
        }];
        AManifest {
            schema: A_MANIFEST_SCHEMA.to_owned(),
            canonical_plan_sha256: "b".repeat(64),
            canonical_trace_table_sha256: "c".repeat(64),
            evaluator_argv: vec!["cargo".to_owned(), "xtask".to_owned()],
            profile: "core-candidate".to_owned(),
            target: "x86_64-unknown-linux-gnu".to_owned(),
            features: "fastmcp-xtask default only".to_owned(),
            toolchain: "nightly-2026-08-25".to_owned(),
            source_tree_sha256: source_tree_digest(&bindings),
            source_bindings: bindings,
            trace_row_count: 1,
            observed_fields_per_row: 13,
            required_item_count: 1,
            subcases: vec![SubcaseOutcome {
                id: "FND-02-A-01".to_owned(),
                name: "traceability-completeness".to_owned(),
                outcome: Outcome::Pass,
                diagnostic_count: 0,
            }],
            consumer_id: "bd-mcp-fnd-02-integration-8s4k".to_owned(),
            write_counters: [0; 6],
        }
    }

    #[test]
    fn canonical_json_is_stable_and_declaration_ordered() {
        let first = manifest().to_canonical_json();
        let second = manifest().to_canonical_json();
        assert_eq!(first, second);
        // Declaration order, not alphabetical: `schema` precedes
        // `canonical_plan_sha256` even though `c` sorts before `s`.
        let schema_at = first.find("\"schema\"").expect("schema present");
        let plan_at = first
            .find("\"canonical_plan_sha256\"")
            .expect("plan digest present");
        assert!(schema_at < plan_at);
    }

    #[test]
    fn digest_changes_when_any_field_changes() {
        let baseline = manifest().digest();
        let mut mutated = manifest();
        mutated.trace_row_count = 2;
        assert_ne!(baseline, mutated.digest());
    }

    #[test]
    fn digest_fields_are_validated_for_width_and_case() {
        assert!(manifest().digests_are_canonical());

        let mut uppercase = manifest();
        uppercase.canonical_plan_sha256 = "B".repeat(64);
        assert!(!uppercase.digests_are_canonical());

        let mut truncated = manifest();
        truncated.canonical_trace_table_sha256 = "c".repeat(63);
        assert!(!truncated.digests_are_canonical());
    }

    #[test]
    fn hex_validation_rejects_wrong_width_case_and_prefix() {
        assert!(is_lowercase_hex(&"a".repeat(64), 64));
        assert!(!is_lowercase_hex(&"A".repeat(64), 64));
        assert!(!is_lowercase_hex(&"a".repeat(63), 64));
        assert!(!is_lowercase_hex(&format!("0x{}", "a".repeat(62)), 64));
    }

    #[test]
    fn source_tree_digest_is_order_sensitive_and_unambiguous() {
        let first = SourceReceipt {
            id: "a".to_owned(),
            path: "p1".to_owned(),
            blob_sha1: "1".repeat(40),
        };
        let second = SourceReceipt {
            id: "b".to_owned(),
            path: "p2".to_owned(),
            blob_sha1: "2".repeat(40),
        };
        let forward = source_tree_digest(&[first.clone(), second.clone()]);
        let reversed = source_tree_digest(&[second, first]);
        assert_ne!(forward, reversed);

        // Length prefixing: splitting a field differently must not collide.
        let ab = source_tree_digest(&[SourceReceipt {
            id: "ab".to_owned(),
            path: String::new(),
            blob_sha1: String::new(),
        }]);
        let a_b = source_tree_digest(&[SourceReceipt {
            id: "a".to_owned(),
            path: "b".to_owned(),
            blob_sha1: String::new(),
        }]);
        assert_ne!(ab, a_b);
    }

    #[test]
    fn an_empty_subcase_list_is_not_a_pass() {
        let mut empty = manifest();
        empty.subcases.clear();
        assert!(!empty.all_subcases_passed());
    }

    #[test]
    fn a_failing_subcase_is_not_a_pass() {
        let mut failed = manifest();
        failed.subcases[0].outcome = Outcome::Fail;
        assert!(!failed.all_subcases_passed());
    }
}
