//! `plan-tracker-check` — FND-02 normative traceability.
//!
//! The checker maps every observable requirement to implementation and tests,
//! and — the part that matters — it *detects* when that map stops being true.
//! Every authoritative input is bound by Git blob identity and re-derived on
//! each run, the required coverage set is parsed out of the authoritative
//! corpus rather than frozen as a count, and coverage is checked as an exact
//! set in both directions so a passing subset is impossible.
//!
//! Validation is strictly read-only. It never edits the plan, the Beads
//! database, Agent Mail reservations, the worktree, or Git state.

pub mod authority;
pub mod b_eval;
pub mod corpus;
pub mod diagnostics;
pub mod digest;
pub mod fingerprint;
pub mod integration;
pub mod manifest;
pub mod plan;
pub mod policy;
pub mod projection;
pub mod reservations;
pub mod sources;
pub mod trace;

use std::fs;
use std::path::{Path, PathBuf};

use authority::{AuthorityRevisions, ConformanceInventory};
use diagnostics::{Code, Diagnostic, Report};
use digest::sha256_hex;
use manifest::{AManifest, Outcome, SourceReceipt, SubcaseOutcome, source_tree_digest};
use sources::{EffectLedger, ResolvedSources};
use trace::{OBSERVED_FIELDS_PER_ROW, TraceTable};

/// Repository-relative path of the authoritative source registry.
pub const SOURCES_PATH: &str = "evidence/fnd-02/authoritative-sources.toml";
/// Repository-relative path of the requirement trace table.
pub const TRACE_TABLE_PATH: &str = "evidence/fnd-02/trace-table.toml";

/// Source ids the A evaluator requires the registry to bind.
pub const SOURCE_ID_PLAN: &str = "campaign-plan";
pub const SOURCE_ID_CHANGELOG: &str = "core-changelog-2026-07-28";
pub const SOURCE_ID_CONFORMANCE: &str = "fnd-01-core-conformance";
pub const SOURCE_ID_AUTH: &str = "fnd-01-auth-standards";

/// Frozen proof configuration for the A slice.
pub const PROFILE: &str = "core-candidate";
pub const TARGET: &str = "x86_64-unknown-linux-gnu";
pub const FEATURES: &str = "fastmcp-xtask default only";
pub const TOOLCHAIN: &str = "nightly-2026-08-25";
pub const A_CONSUMER: &str = "bd-mcp-fnd-02-integration-8s4k";

/// The four ordered A subcases, in their frozen order.
pub const A_SUBCASES: [(&str, &str); 4] = [
    ("FND-02-A-01", "traceability-completeness"),
    ("FND-02-A-02", "duplicate-requirement-key"),
    ("FND-02-A-03", "stale-conformance-check-reference"),
    ("FND-02-A-04", "exact-auth-source-revision"),
];

/// Checker modes.
///
/// `preclaim` and `preclose` carry the issue they are validating; the
/// reservation snapshot itself arrives from the execution layer, because the
/// checker has neither network nor mutation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    All,
    Snapshot,
    Preclaim(String),
    Preclose(String),
}

impl Mode {
    /// Parse a mode word and its optional issue argument.
    pub fn parse(raw: &str, argument: Option<&str>) -> Option<Self> {
        match raw {
            "all" => Some(Self::All),
            "snapshot" => Some(Self::Snapshot),
            "preclaim" => argument.map(|issue| Self::Preclaim(issue.to_owned())),
            "preclose" => argument.map(|issue| Self::Preclose(issue.to_owned())),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Snapshot => "snapshot",
            Self::Preclaim(_) => "preclaim",
            Self::Preclose(_) => "preclose",
        }
    }

    /// The issue this mode validates, when it has one.
    pub fn issue_id(&self) -> Option<&str> {
        match self {
            Self::Preclaim(issue) | Self::Preclose(issue) => Some(issue.as_str()),
            _ => None,
        }
    }
}

/// Everything one `all` run observed.
#[derive(Debug, Clone)]
pub struct CheckRun {
    pub manifest: AManifest,
    pub report: Report,
    pub ledger: EffectLedger,
}

impl CheckRun {
    /// A run passes only when every subcase passed and nothing was written.
    pub fn passed(&self) -> bool {
        self.report.is_clean() && self.manifest.all_subcases_passed() && self.ledger.is_read_only()
    }
}

/// Load the two FND-02 inputs and every authoritative source they bind.
fn load_sources(
    root: &Path,
    ledger: &mut EffectLedger,
) -> Result<(ResolvedSources, Report, String, TraceTable, String), Diagnostic> {
    let registry_path = root.join(SOURCES_PATH);
    let registry_text = fs::read_to_string(&registry_path).map_err(|error| {
        Diagnostic::new(Code::SourceUnreadable, SOURCES_PATH, "path", error.to_string())
    })?;
    ledger.record_read();
    let registry = sources::parse_registry(&registry_text, SOURCES_PATH)?;

    let table_path = root.join(TRACE_TABLE_PATH);
    let table_text = fs::read_to_string(&table_path).map_err(|error| {
        Diagnostic::new(Code::SourceUnreadable, TRACE_TABLE_PATH, "path", error.to_string())
    })?;
    ledger.record_read();
    let table = trace::parse_table(&table_text, TRACE_TABLE_PATH)?;
    let table_digest = sha256_hex(table_text.as_bytes());

    let (resolved, report) = sources::resolve(root, &registry, ledger);

    let receipts: Vec<SourceReceipt> = registry
        .sources
        .iter()
        .map(|binding| SourceReceipt {
            id: binding.id.clone(),
            path: binding.path.clone(),
            blob_sha1: binding.blob_sha1.clone(),
        })
        .collect();
    let tree_digest = source_tree_digest(&receipts);

    Ok((resolved, report, tree_digest, table, table_digest))
}

/// Run `plan-tracker-check all` against `root`.
///
/// This is the shipped evaluator. It is reachable from the binary and from
/// integration tests through the same public entrypoint; there is no
/// test-only path.
pub fn run_all(root: &Path) -> Result<CheckRun, Diagnostic> {
    let mut ledger = EffectLedger::new();
    let (resolved, mut report, tree_digest, table, table_digest) =
        load_sources(root, &mut ledger)?;

    // A binding that failed to resolve has already been reported. Continuing
    // with a partial source set would let a subcase pass by having nothing to
    // check, so the run is cut short with its diagnostics intact.
    let required_ids = [
        SOURCE_ID_PLAN,
        SOURCE_ID_CHANGELOG,
        SOURCE_ID_CONFORMANCE,
        SOURCE_ID_AUTH,
    ];
    for id in required_ids {
        if resolved.get(id).is_none() {
            report.push(Diagnostic::new(
                Code::SourceUnreadable,
                id,
                "id",
                "required authoritative source did not resolve",
            ));
        }
    }

    let receipts: Vec<SourceReceipt> = required_ids
        .iter()
        .filter_map(|id| resolved.get(id))
        .map(|source| SourceReceipt {
            id: source.id.clone(),
            path: source.path.display().to_string(),
            blob_sha1: source.observed_blob_sha1.clone(),
        })
        .collect();

    let plan_digest = resolved
        .get(SOURCE_ID_PLAN)
        .map(|source| sha256_hex(&source.bytes))
        .unwrap_or_else(|| "0".repeat(64));

    if !report.is_clean() {
        let manifest = build_manifest(
            &plan_digest,
            &table_digest,
            receipts,
            &tree_digest,
            table.rows.len(),
            0,
            A_SUBCASES
                .iter()
                .map(|(id, name)| SubcaseOutcome {
                    id: (*id).to_owned(),
                    name: (*name).to_owned(),
                    outcome: Outcome::Fail,
                    diagnostic_count: report.diagnostics().len(),
                })
                .collect(),
            &ledger,
        );
        report.canonicalize();
        return Ok(CheckRun { manifest, report, ledger });
    }

    // The conformance inventory is parsed first: its scenarios are part of
    // the required coverage set, which A-01 checks.
    let inventory = resolved
        .get(SOURCE_ID_CONFORMANCE)
        .and_then(|source| source.text())
        .ok_or_else(|| {
            Diagnostic::new(
                Code::SourceUnreadable,
                SOURCE_ID_CONFORMANCE,
                "bytes",
                "conformance authority is not valid UTF-8",
            )
        })
        .and_then(|text| ConformanceInventory::parse(text, SOURCE_ID_CONFORMANCE));

    // ---- FND-02-A-01 traceability-completeness -------------------------
    let mut first = trace::check_row_completeness(&table);
    // A resolved source is not necessarily a readable one: `resolve` reads
    // bytes and verifies the blob hash but never validates UTF-8, and the
    // required-source gate above only checks that the id resolved at all. So a
    // changelog that exists and matches its recorded blob, yet holds one
    // invalid byte sequence, reaches here with `text()` returning None.
    //
    // This previously ended in `unwrap_or_default()`, which turned that into
    // an EMPTY required coverage set rather than a failure. `check_coverage`
    // refuses a zero-item set, but only when the conformance items are absent
    // too; with those present the set stays non-empty, the guard never fires,
    // and the whole changelog half of A-01 coverage silently disappears from a
    // GREEN run. The conformance path fifteen lines above reports exactly this
    // failure as `SourceUnreadable`; this path now matches it.
    let changelog_text = match resolved.get(SOURCE_ID_CHANGELOG).map(|source| source.text()) {
        Some(Some(text)) => text,
        Some(None) => {
            first.push(Diagnostic::new(
                Code::SourceUnreadable,
                SOURCE_ID_CHANGELOG,
                "bytes",
                "core changelog is not valid UTF-8",
            ));
            ""
        }
        // Unreachable: an unresolved required source is reported by the gate
        // above, which makes the report unclean and returns before this point.
        None => "",
    };
    let mut required_items = corpus::changelog_items(changelog_text);
    if let Ok(inventory) = &inventory {
        required_items.extend(corpus::conformance_items(&inventory.scenario_ids()));
    }
    first.extend(corpus::check_coverage(&required_items, &table));

    // ---- FND-02-A-02 duplicate-requirement-key -------------------------
    let second = trace::check_duplicate_keys(&table);

    // ---- FND-02-A-03 stale-conformance-check-reference -----------------
    let mut third = Report::new();
    match &inventory {
        Ok(inventory) => third.extend(authority::check_conformance_references(inventory, &table)),
        Err(diagnostic) => third.push(diagnostic.clone()),
    }

    // ---- FND-02-A-04 exact-auth-source-revision ------------------------
    let mut fourth = Report::new();
    match resolved
        .get(SOURCE_ID_AUTH)
        .and_then(|source| source.text())
        .ok_or_else(|| {
            Diagnostic::new(
                Code::SourceUnreadable,
                SOURCE_ID_AUTH,
                "bytes",
                "authorization authority is not valid UTF-8",
            )
        })
        .and_then(|text| AuthorityRevisions::parse(text, SOURCE_ID_AUTH))
    {
        Ok(revisions) => fourth.extend(authority::check_auth_revisions(&revisions, &table)),
        Err(diagnostic) => fourth.push(diagnostic),
    }

    let outcomes: Vec<SubcaseOutcome> = A_SUBCASES
        .iter()
        .zip([&first, &second, &third, &fourth])
        .map(|((id, name), subcase_report)| SubcaseOutcome {
            id: (*id).to_owned(),
            name: (*name).to_owned(),
            outcome: if subcase_report.is_clean() {
                Outcome::Pass
            } else {
                Outcome::Fail
            },
            diagnostic_count: subcase_report.diagnostics().len(),
        })
        .collect();

    for subcase_report in [first, second, third, fourth] {
        report.extend(subcase_report);
    }
    report.canonicalize();

    let manifest = build_manifest(
        &plan_digest,
        &table_digest,
        receipts,
        &tree_digest,
        table.rows.len(),
        required_items.len(),
        outcomes,
        &ledger,
    );

    Ok(CheckRun { manifest, report, ledger })
}

#[allow(clippy::too_many_arguments)]
fn build_manifest(
    plan_digest: &str,
    table_digest: &str,
    source_bindings: Vec<SourceReceipt>,
    tree_digest: &str,
    trace_row_count: usize,
    required_item_count: usize,
    subcases: Vec<SubcaseOutcome>,
    ledger: &EffectLedger,
) -> AManifest {
    AManifest {
        schema: manifest::A_MANIFEST_SCHEMA.to_owned(),
        canonical_plan_sha256: plan_digest.to_owned(),
        canonical_trace_table_sha256: table_digest.to_owned(),
        evaluator_argv: vec![
            "cargo".to_owned(),
            "xtask".to_owned(),
            "plan-tracker-check".to_owned(),
            "all".to_owned(),
        ],
        profile: PROFILE.to_owned(),
        target: TARGET.to_owned(),
        features: FEATURES.to_owned(),
        toolchain: TOOLCHAIN.to_owned(),
        source_bindings,
        source_tree_sha256: tree_digest.to_owned(),
        trace_row_count,
        observed_fields_per_row: OBSERVED_FIELDS_PER_ROW,
        required_item_count,
        subcases,
        consumer_id: A_CONSUMER.to_owned(),
        write_counters: ledger.write_counters(),
    }
}

/// Locate the repository root by walking up from `start` until the directory
/// holding the FND-02 evidence is found.
pub fn find_root(start: &Path) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(directory) = current {
        if directory.join(SOURCES_PATH).is_file() {
            return Some(directory.to_path_buf());
        }
        current = directory.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parses_only_declared_modes() {
        assert_eq!(Mode::parse("all", None), Some(Mode::All));
        assert_eq!(Mode::parse("snapshot", None), Some(Mode::Snapshot));
        assert_eq!(Mode::parse("ALL", None), None);
        assert_eq!(Mode::parse("", None), None);
    }

    #[test]
    fn preclaim_and_preclose_require_an_issue_argument() {
        assert_eq!(Mode::parse("preclaim", None), None);
        assert_eq!(Mode::parse("preclose", None), None);
        assert_eq!(
            Mode::parse("preclaim", Some("bd-x")),
            Some(Mode::Preclaim("bd-x".to_owned()))
        );
        assert_eq!(
            Mode::parse("preclose", Some("bd-x")).and_then(|m| m.issue_id().map(str::to_owned)),
            Some("bd-x".to_owned())
        );
    }

    #[test]
    fn mode_names_are_the_documented_words() {
        assert_eq!(Mode::All.name(), "all");
        assert_eq!(Mode::Snapshot.name(), "snapshot");
        assert_eq!(Mode::Preclaim("i".to_owned()).name(), "preclaim");
        assert_eq!(Mode::Preclose("i".to_owned()).name(), "preclose");
        assert_eq!(Mode::All.issue_id(), None);
    }

    #[test]
    fn the_four_subcases_are_ordered_and_distinct() {
        let ids: Vec<&str> = A_SUBCASES.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, ["FND-02-A-01", "FND-02-A-02", "FND-02-A-03", "FND-02-A-04"]);
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4);
    }
}
