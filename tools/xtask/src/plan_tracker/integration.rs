//! FND-02 integration: join the A and B capability slices through the shipped
//! public entrypoint.
//!
//! The join consumes the two manifests *by their bytes*. It recomputes each
//! manifest's digest from the canonical JSON it was handed and compares that
//! to the digest the caller declared; a copied field or a re-derived value
//! would make the binding untestable, because there would be nothing that
//! could disagree.
//!
//! The join also refuses two manifests that disagree on a fact they must
//! share. Concatenating receipts from different profiles, targets, or
//! toolchains would produce a receipt describing a configuration that was
//! never run.

use serde::Serialize;

use super::b_eval::BManifest;
use super::diagnostics::{Code, Diagnostic, Report};
use super::digest::sha256_hex;
use super::manifest::{AManifest, Outcome, SubcaseOutcome, is_lowercase_hex};

/// The four ordered integration subcases, in their frozen order.
pub const I_SUBCASES: [(&str, &str); 4] = [
    ("FND-02-I-01", "consume-a-manifest"),
    ("FND-02-I-02", "consume-b-manifest"),
    ("FND-02-I-03", "all-mode-joined-projection"),
    ("FND-02-I-04", "exact-receipt-binding"),
];

pub const I_MANIFEST_SCHEMA: &str = "fnd-02-integration-manifest-v1";
/// The verification child this receipt is produced for.
pub const I_CONSUMER: &str = "bd-mcp-fnd-02-verification-mcol";

/// One manifest as it arrives at the join: its bytes and the digest the
/// producer declared for them.
#[derive(Debug, Clone)]
pub struct ManifestInput {
    pub schema: String,
    pub canonical_json: String,
    pub declared_digest: String,
}

impl ManifestInput {
    pub fn from_a(manifest: &AManifest) -> Self {
        Self {
            schema: manifest.schema.clone(),
            canonical_json: manifest.to_canonical_json(),
            declared_digest: manifest.digest(),
        }
    }

    pub fn from_b(manifest: &BManifest) -> Self {
        Self {
            schema: manifest.schema.clone(),
            canonical_json: manifest.to_canonical_json(),
            declared_digest: manifest.digest(),
        }
    }

    /// The digest recomputed from the bytes, never taken on trust.
    pub fn observed_digest(&self) -> String {
        sha256_hex(self.canonical_json.as_bytes())
    }
}

/// The `fnd-02-integration-manifest-v1` canonical receipt.
#[derive(Debug, Clone, Serialize)]
pub struct IntegrationManifest {
    pub schema: String,
    pub a_manifest_sha256: String,
    pub b_manifest_sha256: String,
    pub joined_graph_sha256: String,
    pub joined_corpus_sha256: String,
    pub joined_trace_table_sha256: String,
    pub evaluator_argv: Vec<String>,
    pub profile: String,
    pub target: String,
    pub features: String,
    pub toolchain: String,
    /// Content-addressed revision binding, carried through from A and B.
    pub source_tree_sha256: String,
    pub plan_blob_sha1: String,
    pub input_manifest_count: usize,
    pub subcases: Vec<SubcaseOutcome>,
    pub consumer_id: String,
    pub write_counters: [u64; 5],
}

impl IntegrationManifest {
    pub fn to_canonical_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("manifest serialization is infallible")
    }

    pub fn digest(&self) -> String {
        sha256_hex(self.to_canonical_json().as_bytes())
    }

    pub fn digests_are_canonical(&self) -> bool {
        [
            &self.a_manifest_sha256,
            &self.b_manifest_sha256,
            &self.joined_graph_sha256,
            &self.joined_corpus_sha256,
            &self.joined_trace_table_sha256,
            &self.source_tree_sha256,
        ]
        .into_iter()
        .all(|value| is_lowercase_hex(value, 64))
            && is_lowercase_hex(&self.plan_blob_sha1, 40)
    }

    pub fn all_subcases_passed(&self) -> bool {
        self.subcases.len() == I_SUBCASES.len()
            && self.subcases.iter().all(|s| s.outcome == Outcome::Pass)
    }
}

/// The result of one join.
#[derive(Debug, Clone)]
pub struct IntegrationRun {
    pub manifest: IntegrationManifest,
    pub report: Report,
}

impl IntegrationRun {
    pub fn passed(&self) -> bool {
        self.report.is_clean() && self.manifest.all_subcases_passed()
    }

    pub fn subcase(&self, id: &str) -> Option<&SubcaseOutcome> {
        self.manifest.subcases.iter().find(|s| s.id == id)
    }
}

/// Verify one manifest's binding: declared digest equals observed digest, and
/// the schema tag is the expected one.
fn check_binding(input: &ManifestInput, expected_schema: &str) -> Report {
    let mut report = Report::new();

    if input.schema != expected_schema {
        report.push(Diagnostic::new(
            Code::ManifestBindingMismatch,
            expected_schema,
            "schema",
            format!("expected {expected_schema}, observed {}", input.schema),
        ));
    }

    let observed = input.observed_digest();
    if observed != input.declared_digest {
        report.push(Diagnostic::new(
            Code::ManifestBindingMismatch,
            expected_schema,
            "digest",
            format!(
                "declared {} but the bytes hash to {observed}",
                input.declared_digest
            ),
        ));
    }

    if input.canonical_json.is_empty() {
        report.push(Diagnostic::new(
            Code::ManifestBindingMismatch,
            expected_schema,
            "bytes",
            "an empty manifest cannot be consumed",
        ));
    }

    report
}

/// Join the A and B manifests into one integration receipt.
pub fn join(
    a_input: &ManifestInput,
    b_input: &ManifestInput,
    a: &AManifest,
    b: &BManifest,
) -> IntegrationRun {
    // FND-02-I-01 and FND-02-I-02: consume each manifest by its bytes.
    let first = check_binding(a_input, super::manifest::A_MANIFEST_SCHEMA);
    let second = check_binding(b_input, super::b_eval::B_MANIFEST_SCHEMA);

    // FND-02-I-03: exactly one joined projection, and the two slices must
    // agree on the configuration they were produced under.
    let mut third = Report::new();
    for (field, left, right) in [
        ("profile", &a.profile, &b.profile),
        ("target", &a.target, &b.target),
        ("features", &a.features, &b.features),
        ("toolchain", &a.toolchain, &b.toolchain),
        ("consumer_id", &a.consumer_id, &b.consumer_id),
    ] {
        if left != right {
            third.push(Diagnostic::new(
                Code::ManifestJoinConflict,
                "joined-projection",
                field,
                format!("A declares {left:?} but B declares {right:?}"),
            ));
        }
    }
    // Both slices must themselves have passed; a joined receipt over a failed
    // slice would report a green that no slice earned.
    if !a.all_subcases_passed() {
        third.push(Diagnostic::new(
            Code::ManifestJoinConflict,
            "joined-projection",
            "a_subcases",
            "the A slice did not pass every subcase",
        ));
    }
    if !b.all_subcases_passed() {
        third.push(Diagnostic::new(
            Code::ManifestJoinConflict,
            "joined-projection",
            "b_subcases",
            "the B slice did not pass every subcase",
        ));
    }

    // FND-02-I-04: the receipt binding is exact -- every digest the join
    // carries forward is a canonical rendering, and the input cardinality is
    // exactly two manifests.
    let mut fourth = Report::new();
    for (field, value, width) in [
        ("a_manifest_sha256", &a_input.declared_digest, 64),
        ("b_manifest_sha256", &b_input.declared_digest, 64),
        ("joined_graph_sha256", &b.canonical_graph_sha256, 64),
        ("joined_corpus_sha256", &b.canonical_corpus_sha256, 64),
        ("joined_trace_table_sha256", &a.canonical_trace_table_sha256, 64),
        ("source_tree_sha256", &a.source_tree_sha256, 64),
        ("plan_blob_sha1", &b.plan_blob_sha1, 40),
    ] {
        if !is_lowercase_hex(value, width) {
            fourth.push(Diagnostic::new(
                Code::ManifestBindingMismatch,
                "receipt-binding",
                field,
                format!("{value:?} is not {width} lowercase hexadecimal characters"),
            ));
        }
    }
    if a_input.declared_digest == b_input.declared_digest {
        fourth.push(Diagnostic::new(
            Code::ManifestBindingMismatch,
            "receipt-binding",
            "distinctness",
            "the A and B manifests hash identically",
        ));
    }

    let reports = [first, second, third, fourth];
    let subcases: Vec<SubcaseOutcome> = I_SUBCASES
        .iter()
        .zip(&reports)
        .map(|((id, name), report)| SubcaseOutcome {
            id: (*id).to_owned(),
            name: (*name).to_owned(),
            outcome: if report.is_clean() {
                Outcome::Pass
            } else {
                Outcome::Fail
            },
            diagnostic_count: report.diagnostics().len(),
        })
        .collect();

    let mut report = Report::new();
    for subcase_report in reports {
        report.extend(subcase_report);
    }
    report.canonicalize();

    let manifest = IntegrationManifest {
        schema: I_MANIFEST_SCHEMA.to_owned(),
        a_manifest_sha256: a_input.declared_digest.clone(),
        b_manifest_sha256: b_input.declared_digest.clone(),
        joined_graph_sha256: b.canonical_graph_sha256.clone(),
        joined_corpus_sha256: b.canonical_corpus_sha256.clone(),
        joined_trace_table_sha256: a.canonical_trace_table_sha256.clone(),
        evaluator_argv: vec![
            "cargo".to_owned(),
            "xtask".to_owned(),
            "plan-tracker-check".to_owned(),
            "all".to_owned(),
        ],
        profile: a.profile.clone(),
        target: a.target.clone(),
        features: a.features.clone(),
        toolchain: a.toolchain.clone(),
        source_tree_sha256: a.source_tree_sha256.clone(),
        plan_blob_sha1: b.plan_blob_sha1.clone(),
        input_manifest_count: 2,
        subcases,
        consumer_id: I_CONSUMER.to_owned(),
        // The join reads two in-memory receipts and writes nothing.
        write_counters: [0; 5],
    };

    IntegrationRun { manifest, report }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_four_subcases_are_ordered_and_distinct() {
        let ids: Vec<&str> = I_SUBCASES.iter().map(|(id, _)| *id).collect();
        assert_eq!(
            ids,
            ["FND-02-I-01", "FND-02-I-02", "FND-02-I-03", "FND-02-I-04"]
        );
        let mut sorted = ids;
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4);
    }

    #[test]
    fn a_binding_passes_when_the_declared_digest_matches_the_bytes() {
        let json = "{\"schema\":\"x\"}".to_owned();
        let input = ManifestInput {
            schema: "s".to_owned(),
            declared_digest: sha256_hex(json.as_bytes()),
            canonical_json: json,
        };
        assert!(check_binding(&input, "s").is_clean());
    }

    #[test]
    fn a_binding_fails_when_the_declared_digest_does_not_match() {
        let json = "{\"schema\":\"x\"}".to_owned();
        let input = ManifestInput {
            schema: "s".to_owned(),
            declared_digest: "0".repeat(64),
            canonical_json: json,
        };
        let report = check_binding(&input, "s");
        assert_eq!(report.codes(), vec![Code::ManifestBindingMismatch]);
        assert_eq!(report.diagnostics()[0].field, "digest");
    }

    #[test]
    fn a_binding_fails_on_a_wrong_schema_tag() {
        let json = "{}".to_owned();
        let input = ManifestInput {
            schema: "wrong".to_owned(),
            declared_digest: sha256_hex(json.as_bytes()),
            canonical_json: json,
        };
        assert!(check_binding(&input, "expected").has(Code::ManifestBindingMismatch));
    }

    #[test]
    fn an_empty_manifest_cannot_be_consumed() {
        let input = ManifestInput {
            schema: "s".to_owned(),
            declared_digest: sha256_hex(b""),
            canonical_json: String::new(),
        };
        let report = check_binding(&input, "s");
        assert!(report.diagnostics().iter().any(|d| d.field == "bytes"));
    }
}
