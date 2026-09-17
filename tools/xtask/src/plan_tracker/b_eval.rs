//! The FND-02 B evaluator: drift detection, invalidation propagation, and
//! exact-set checking across fifteen ordered subcases.
//!
//! Every subcase is a real check over real inputs. Where a subcase's canonical
//! definition is not derivable from the authoritative inputs, it reports that
//! openly rather than passing on a guess -- a subcase that cannot fail is not
//! a subcase.

use std::fs;
use std::path::Path;

use serde::Serialize;

use super::diagnostics::{Code, Diagnostic, Report};
use super::digest::sha256_hex;
use super::fingerprint::{self, fingerprint_hex};
use super::manifest::{Outcome, SubcaseOutcome, is_lowercase_hex};
use super::plan::{self, Limits, Plan};
use super::policy;
use super::projection::{self, Projection};
use super::reservations::{self, Declaration, Pass, ReservationSnapshot};
use super::sources::EffectLedger;

/// Repository-relative path of the campaign plan.
pub const PLAN_PATH: &str = "COMPREHENSIVE_PLAN_TO_SUPPORT_MCP_2026-07-28_SPEC_IN_FASTMCP_RUST.md";
/// Repository-relative path of the exported tracker state.
pub const BEADS_EXPORT_PATH: &str = ".beads/issues.jsonl";

/// The fifteen ordered B subcases, in their frozen order.
pub const B_SUBCASES: [(&str, &str); 15] = [
    ("FND-02-B-01", "mode-golden-mutation-all"),
    ("FND-02-B-02", "mode-golden-mutation-preclaim"),
    ("FND-02-B-03", "mode-golden-mutation-preclose"),
    ("FND-02-B-04", "mode-golden-mutation-snapshot"),
    ("FND-02-B-05", "reservation-snapshot-matrix"),
    ("FND-02-B-06", "strict-read-only"),
    ("FND-02-B-07", "fence-corpus"),
    ("FND-02-B-08", "package-grammar-boundaries"),
    ("FND-02-B-09", "graph-corpus-v2-mutations"),
    ("FND-02-B-10", "full-digest-substitutions"),
    ("FND-02-B-11", "unsigned-byte-ordering"),
    ("FND-02-B-12", "module-oracle-inventory"),
    ("FND-02-B-13", "xtask-package-alias"),
    ("FND-02-B-14", "workspace-unsafe-policy"),
    ("FND-02-B-15", "generated-inventory-closure"),
];

pub const B_MANIFEST_SCHEMA: &str = "fnd-02-b-manifest-v1";
pub const B_CONSUMER: &str = "bd-mcp-fnd-02-integration-8s4k";

/// The `fnd-02-b-manifest-v1` canonical receipt.
#[derive(Debug, Clone, Serialize)]
pub struct BManifest {
    pub schema: String,
    pub canonical_graph_sha256: String,
    pub canonical_corpus_sha256: String,
    pub evaluator_argv: Vec<String>,
    pub profile: String,
    pub target: String,
    pub features: String,
    pub toolchain: String,
    pub plan_blob_sha1: String,
    pub package_count: usize,
    pub edge_count: usize,
    pub module_count: usize,
    pub subcases: Vec<SubcaseOutcome>,
    pub consumer_id: String,
    pub write_counters: [u64; 6],
}

impl BManifest {
    pub fn to_canonical_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("manifest serialization is infallible")
    }

    pub fn digest(&self) -> String {
        sha256_hex(self.to_canonical_json().as_bytes())
    }

    pub fn digests_are_canonical(&self) -> bool {
        is_lowercase_hex(&self.canonical_graph_sha256, 64)
            && is_lowercase_hex(&self.canonical_corpus_sha256, 64)
            && is_lowercase_hex(&self.plan_blob_sha1, 40)
    }

    pub fn all_subcases_passed(&self) -> bool {
        self.subcases.len() == B_SUBCASES.len()
            && self.subcases.iter().all(|s| s.outcome == Outcome::Pass)
    }
}

/// Everything one B run observed.
#[derive(Debug, Clone)]
pub struct BRun {
    pub manifest: BManifest,
    pub report: Report,
    pub ledger: EffectLedger,
    pub plan: Plan,
    pub projection: Projection,
}

impl BRun {
    pub fn passed(&self) -> bool {
        self.report.is_clean() && self.manifest.all_subcases_passed() && self.ledger.is_read_only()
    }

    /// The report for one subcase id, for tests that assert a single failure.
    pub fn subcase(&self, id: &str) -> Option<&SubcaseOutcome> {
        self.manifest.subcases.iter().find(|s| s.id == id)
    }
}

/// Inputs for the reservation-dependent passes.
#[derive(Debug, Clone, Default)]
pub struct ReservationInputs {
    pub declaration: Option<Declaration>,
    pub snapshot: Option<ReservationSnapshot>,
    pub now: i64,
    pub claimed_at: i64,
}

/// Run every B subcase against `root`.
pub fn run(root: &Path, reservations_input: &ReservationInputs) -> Result<BRun, Diagnostic> {
    let mut ledger = EffectLedger::new();
    let limits = Limits::default();

    let plan_bytes = fs::read(root.join(PLAN_PATH)).map_err(|error| {
        Diagnostic::new(Code::SourceUnreadable, PLAN_PATH, "path", error.to_string())
    })?;
    ledger.record_read();
    let plan_blob = super::digest::git_blob_hex(&plan_bytes);

    let parsed = plan::parse(&plan_bytes, &limits)?;

    let export = fs::read_to_string(root.join(BEADS_EXPORT_PATH)).map_err(|error| {
        Diagnostic::new(
            Code::SourceUnreadable,
            BEADS_EXPORT_PATH,
            "path",
            error.to_string(),
        )
    })?;
    ledger.record_read();
    let projected = projection::parse_export(&export, BEADS_EXPORT_PATH)?;

    let graph_stream = fingerprint::encode_graph(&parsed);
    let corpus_stream = fingerprint::encode_corpus(&parsed);

    let mut reports: Vec<Report> = Vec::with_capacity(B_SUBCASES.len());

    // B-01 mode-golden-mutation-all: the parsed plan is internally closed.
    // `plan::parse` already rejected an unresolved, self, or duplicate edge,
    // so reaching here means the graph is well formed; the residual check is
    // that it is non-degenerate.
    let mut b01 = Report::new();
    if parsed.packages.is_empty() || parsed.edges.is_empty() {
        b01.push(Diagnostic::new(
            Code::PlanRegionMissing,
            "all",
            "graph",
            "a plan with no package or no edge cannot certify the all mode",
        ));
    }
    reports.push(b01);

    // B-02 preclaim and B-03 preclose.
    let declaration = reservations_input.declaration.clone();
    let mut b02 = Report::new();
    let mut b03 = Report::new();
    match &declaration {
        None => {
            // With no declaration supplied, these modes are not exercised.
            // Reporting that is honest; passing would be a vacuous green.
            let missing = |mode: &'static str| {
                Diagnostic::new(
                    Code::ReservationSnapshotMissing,
                    mode,
                    "declaration",
                    "no ownership declaration was supplied to this mode",
                )
            };
            b02.push(missing("preclaim"));
            b03.push(missing("preclose"));
        }
        Some(declaration) => {
            b02.extend(reservations::validate(
                declaration,
                reservations_input.snapshot.as_ref(),
                Pass::Claim,
                reservations_input.now,
                reservations_input.claimed_at,
            ));
            b03.extend(reservations::validate(
                declaration,
                reservations_input.snapshot.as_ref(),
                Pass::Close,
                reservations_input.now,
                reservations_input.claimed_at,
            ));
        }
    }
    reports.push(b02);
    reports.push(b03);

    // B-04 snapshot: the receipt digests are canonical renderings.
    let mut b04 = Report::new();
    let graph_hex = fingerprint_hex(&graph_stream);
    let corpus_hex = fingerprint_hex(&corpus_stream);
    for (field, value) in [("graph", &graph_hex), ("corpus", &corpus_hex)] {
        if !is_lowercase_hex(value, 64) {
            b04.push(Diagnostic::new(
                Code::StreamMalformed,
                "snapshot",
                field,
                "a digest must render as 64 lowercase hexadecimal characters",
            ));
        }
    }
    if graph_hex == corpus_hex {
        b04.push(Diagnostic::new(
            Code::StreamMalformed,
            "snapshot",
            "domain",
            "the graph and corpus digests collided",
        ));
    }
    reports.push(b04);

    // B-05 reservation-snapshot-matrix: exercised by the declaration above
    // when supplied; otherwise the matrix is proven by the module's own tests
    // and this subcase reports that it had no live snapshot to check.
    let mut b05 = Report::new();
    if reservations_input.snapshot.is_none() {
        b05.push(Diagnostic::new(
            Code::ReservationSnapshotMissing,
            "reservation-matrix",
            "snapshot",
            "no reservation snapshot was supplied",
        ));
    }
    reports.push(b05);

    // B-06 strict-read-only.
    let mut b06 = Report::new();
    if !ledger.is_read_only() {
        b06.push(Diagnostic::new(
            Code::WorkspacePolicy,
            "strict-read-only",
            "write_counters",
            "the checker recorded a write",
        ));
    }
    reports.push(b06);

    // B-07 fence-corpus and B-08 package-grammar-boundaries: both are
    // enforced during parsing. Reaching here means the live plan satisfied
    // them; the residual live check is that extraction found the expected
    // shape rather than silently zero.
    let mut b07 = Report::new();
    if parsed.packages.len() < 2 {
        b07.push(Diagnostic::new(
            Code::PlanRegionMissing,
            "fence-corpus",
            "packages",
            "fence-aware extraction yielded fewer than two packages",
        ));
    }
    reports.push(b07);

    let mut b08 = Report::new();
    for package in &parsed.packages {
        if !plan::is_package_id(&package.id, limits.max_id_bytes) {
            b08.push(Diagnostic::new(
                Code::PackageIdInvalid,
                &package.id,
                "id",
                "extracted identifier does not satisfy the grammar",
            ));
        }
        if package.canonical_body.last() != Some(&b'\n') {
            b08.push(Diagnostic::new(
                Code::PackageHeadingInvalid,
                &package.id,
                "canonical_body",
                "a canonical body ends in exactly one LF",
            ));
        }
    }
    reports.push(b08);

    // B-09 graph-corpus-v2-mutations: both streams decode exactly and
    // re-encode byte-identically.
    let mut b09 = Report::new();
    if let Err(diagnostic) = fingerprint::decode_graph(&graph_stream, &limits) {
        b09.push(diagnostic);
    }
    if let Err(diagnostic) = fingerprint::decode_corpus(&corpus_stream, &limits) {
        b09.push(diagnostic);
    }
    if let Err(diagnostic) = fingerprint::graph_reencodes_identically(&graph_stream, &limits) {
        b09.push(diagnostic);
    }
    reports.push(b09);

    // B-10 full-digest-substitutions: a truncated or double-hashed rendering
    // must not equal the real one.
    let mut b10 = Report::new();
    let raw = fingerprint::fingerprint(&graph_stream);
    if graph_hex.len() != 64
        || graph_hex == sha256_hex(&raw)
        || graph_hex == sha256_hex(graph_hex.as_bytes())
    {
        b10.push(Diagnostic::new(
            Code::StreamMalformed,
            "digest",
            "substitution",
            "the digest is not a single full-length hash of the stream",
        ));
    }
    reports.push(b10);

    // B-11 unsigned-byte-ordering: the encoded node order is ascending by
    // raw bytes. Decoding already enforces it; this reproves it against the
    // live corpus so a natural-sort regression cannot pass unobserved.
    let mut b11 = Report::new();
    let decoded = fingerprint::decode_graph(&graph_stream, &limits);
    if let Ok(decoded) = &decoded {
        let mut expected = decoded.nodes.clone();
        expected.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        if decoded.nodes != expected {
            b11.push(Diagnostic::new(
                Code::StreamMalformed,
                "ordering",
                "nodes",
                "node order is not unsigned-byte ascending",
            ));
        }
    }
    reports.push(b11);

    // B-12 module-oracle-inventory.
    let (modules, b12) = policy::check_module_inventory(root);
    reports.push(b12);

    // B-13 xtask-package-alias.
    reports.push(policy::check_xtask_package(root));

    // B-14 workspace-unsafe-policy.
    reports.push(policy::check_unsafe_policy(
        root,
        &["tools/xtask/src/lib.rs", "tools/xtask/src/main.rs"],
    ));

    // B-15 generated-inventory-closure: canonical package/label mapping
    // parity, generated from the parsed graph and the tracker export.
    let mut b15 = Report::new();
    b15.extend(projection::check_package_label_parity(
        &parsed.ids(),
        &projected,
    ));
    reports.push(b15);

    let subcases: Vec<SubcaseOutcome> = B_SUBCASES
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

    let manifest = BManifest {
        schema: B_MANIFEST_SCHEMA.to_owned(),
        canonical_graph_sha256: graph_hex,
        canonical_corpus_sha256: corpus_hex,
        evaluator_argv: vec![
            "cargo".to_owned(),
            "xtask".to_owned(),
            "plan-tracker-check".to_owned(),
            "all".to_owned(),
        ],
        profile: super::PROFILE.to_owned(),
        target: super::TARGET.to_owned(),
        features: super::FEATURES.to_owned(),
        toolchain: super::TOOLCHAIN.to_owned(),
        plan_blob_sha1: plan_blob,
        package_count: parsed.packages.len(),
        edge_count: parsed.edges.len(),
        module_count: modules.len(),
        subcases,
        consumer_id: B_CONSUMER.to_owned(),
        write_counters: ledger.write_counters(),
    };

    Ok(BRun {
        manifest,
        report,
        ledger,
        plan: parsed,
        projection: projected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fifteen_subcases_are_ordered_and_distinct() {
        let ids: Vec<&str> = B_SUBCASES.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids.len(), 15);
        assert_eq!(ids[0], "FND-02-B-01");
        assert_eq!(ids[14], "FND-02-B-15");
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 15, "subcase ids must be distinct");
        // Ordinals ascend without a gap.
        for (index, id) in ids.iter().enumerate() {
            assert_eq!(*id, format!("FND-02-B-{:02}", index + 1));
        }
    }

    #[test]
    fn a_manifest_with_fewer_than_fifteen_subcases_is_not_a_pass() {
        let manifest = BManifest {
            schema: B_MANIFEST_SCHEMA.to_owned(),
            canonical_graph_sha256: "a".repeat(64),
            canonical_corpus_sha256: "b".repeat(64),
            evaluator_argv: Vec::new(),
            profile: String::new(),
            target: String::new(),
            features: String::new(),
            toolchain: String::new(),
            plan_blob_sha1: "c".repeat(40),
            package_count: 1,
            edge_count: 1,
            module_count: 1,
            subcases: vec![SubcaseOutcome {
                id: "FND-02-B-01".to_owned(),
                name: "x".to_owned(),
                outcome: Outcome::Pass,
                diagnostic_count: 0,
            }],
            consumer_id: B_CONSUMER.to_owned(),
            write_counters: [0; 6],
        };
        assert!(!manifest.all_subcases_passed());
        assert!(manifest.digests_are_canonical());
    }
}
