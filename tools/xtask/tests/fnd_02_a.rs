//! FND-02 implementation A: authoritative source and requirement trace rows.
//!
//! These tests drive the same public entrypoint the binary drives
//! (`plan_tracker::run_all`). There is no test-only evaluator path and no
//! hard-coded receipt: the positive runs against the real repository tree and
//! the negatives run against a byte-for-byte copy with exactly one field
//! changed.
//!
//! Frozen IDs: `fnd_02_a_positive`, `fnd_02_a_planted_negative`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use fastmcp_xtask::plan_tracker::{
    self, SOURCES_PATH, TRACE_TABLE_PATH,
    diagnostics::Code,
    digest::git_blob_hex,
    manifest::Outcome,
};

/// The authoritative final changelog, whose items A-01 requires trace rows to
/// cover. Its registry role is "final changelog items requiring trace
/// coverage".
const CHANGELOG_PATH: &str = "evidence/fnd-01/vendor/core/mcp-changelog-2026-07-28-5f5440bb.mdx";

/// The repository root, derived from this crate's manifest directory rather
/// than from the process working directory, which a test harness may change.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tools/xtask sits two levels below the repository root")
        .to_path_buf()
}

/// Paths whose bytes must be identical before and after any checker run.
fn immutable_paths(root: &Path) -> Vec<PathBuf> {
    vec![
        root.join("COMPREHENSIVE_PLAN_TO_SUPPORT_MCP_2026-07-28_SPEC_IN_FASTMCP_RUST.md"),
        root.join(SOURCES_PATH),
        root.join(TRACE_TABLE_PATH),
        root.join("evidence/fnd-01/core-conformance.toml"),
        root.join("evidence/fnd-01/auth-standards.toml"),
        root.join(".beads/issues.jsonl"),
        root.join(".git/index"),
    ]
}

/// Snapshot the bytes of every path that exists.
fn snapshot(paths: &[PathBuf]) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    paths
        .iter()
        .map(|path| (path.clone(), fs::read(path).ok()))
        .collect()
}

static SCRATCH_COUNTER: AtomicU32 = AtomicU32::new(0);

/// A disposable copy of every input the checker reads.
///
/// Mutations are planted here, never in the repository: the negatives must
/// prove the real tree is untouched, which they cannot do if they edit it.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let unique = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fnd-02-a-{label}-{}-{unique}",
            std::process::id()
        ));
        let source = repo_root();

        for relative in [
            "COMPREHENSIVE_PLAN_TO_SUPPORT_MCP_2026-07-28_SPEC_IN_FASTMCP_RUST.md",
            "evidence/fnd-01/vendor/core/mcp-changelog-2026-07-28-5f5440bb.mdx",
            "evidence/fnd-01/core-conformance.toml",
            "evidence/fnd-01/auth-standards.toml",
            SOURCES_PATH,
            TRACE_TABLE_PATH,
        ] {
            let target = root.join(relative);
            fs::create_dir_all(target.parent().expect("relative paths have a parent"))
                .expect("scratch directory is creatable");
            fs::copy(source.join(relative), &target).expect("input is copyable");
        }

        Self { root }
    }

    fn read(&self, relative: &str) -> String {
        fs::read_to_string(self.root.join(relative)).expect("scratch input is readable")
    }

    fn write(&self, relative: &str, contents: &str) {
        fs::write(self.root.join(relative), contents).expect("scratch input is writable");
    }

    /// Replace exactly one occurrence of `from` with `to`. Panics unless the
    /// needle occurs exactly once, so a mutation can never silently become a
    /// no-op and leave the test asserting against unmodified input.
    fn mutate_once(&self, relative: &str, from: &str, to: &str) {
        let original = self.read(relative);
        assert_eq!(
            original.matches(from).count(),
            1,
            "planted mutation {from:?} must match exactly once in {relative}"
        );
        self.write(relative, &original.replacen(from, to, 1));
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Only ever removes a directory this test created under the system
        // temporary directory.
        if self.root.starts_with(std::env::temp_dir()) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

// ----------------------------------------------------------------- positive

/// A clean trace set verifies through the shipped public surface.
#[test]
fn fnd_02_a_positive() {
    let root = repo_root();
    let before = snapshot(&immutable_paths(&root));

    let run = plan_tracker::run_all(&root).expect("the checker loads its inputs");

    assert!(
        run.report.is_clean(),
        "expected a clean trace set, got:\n{}",
        run.report.render()
    );
    assert!(run.passed(), "the run must pass");

    // Every named subcase is present, ordered, and passing. A run that
    // reported fewer subcases would be green for the wrong reason.
    let observed: Vec<(&str, &str)> = run
        .manifest
        .subcases
        .iter()
        .map(|s| (s.id.as_str(), s.name.as_str()))
        .collect();
    assert_eq!(observed, plan_tracker::A_SUBCASES.to_vec());
    assert!(
        run.manifest
            .subcases
            .iter()
            .all(|s| s.outcome == Outcome::Pass && s.diagnostic_count == 0)
    );

    // A zero-row green is red: assert the run actually had something to check.
    assert!(
        run.manifest.trace_row_count > 0,
        "a zero-row trace table cannot certify anything"
    );
    assert!(run.manifest.required_item_count > 0);
    assert_eq!(
        run.manifest.trace_row_count,
        run.manifest.required_item_count,
        "exact-set coverage: one row per required corpus item"
    );
    assert!(run.manifest.observed_fields_per_row >= 12);

    // Receipt shape.
    assert_eq!(run.manifest.schema, "fnd-02-a-manifest-v1");
    assert!(run.manifest.digests_are_canonical());
    assert_eq!(run.manifest.source_bindings.len(), 4);
    assert_eq!(run.manifest.consumer_id, plan_tracker::A_CONSUMER);
    assert_eq!(run.manifest.profile, plan_tracker::PROFILE);
    assert_eq!(run.manifest.target, plan_tracker::TARGET);
    assert_eq!(run.manifest.toolchain, plan_tracker::TOOLCHAIN);

    // Strictly read-only.
    assert_eq!(run.manifest.write_counters, [0; 6]);
    assert!(run.ledger.is_read_only());
    assert!(run.ledger.files_read() > 0, "the checker must have read its inputs");

    assert_eq!(before, snapshot(&immutable_paths(&root)), "the checker wrote something");
}

// ---------------------------------------------------------------- negative

/// The one-variable planted negative.
///
/// It differs from the positive in exactly one trace-row field: a single
/// authorization row's exact immutable revision `oauth-2.1-13` becomes the
/// floating `oauth-2.1`. Everything else is byte-identical.
#[test]
fn fnd_02_a_planted_negative() {
    let repo = repo_root();
    let before = snapshot(&immutable_paths(&repo));

    let scratch = Scratch::new("floating-revision");

    // Confirm the unmutated copy is clean, so the rejection below is
    // attributable to the mutation and to nothing else.
    let baseline = plan_tracker::run_all(&scratch.root).expect("scratch loads");
    assert!(
        baseline.passed(),
        "the unmutated copy must pass, got:\n{}",
        baseline.report.render()
    );

    scratch.mutate_once(
        TRACE_TABLE_PATH,
        "source_revision = \"auth:oauth-2.1-13\"",
        "source_revision = \"auth:oauth-2.1\"",
    );

    let run = plan_tracker::run_all(&scratch.root).expect("scratch loads after mutation");

    assert!(!run.passed(), "a floating citation must not pass");
    assert_eq!(
        run.report.codes(),
        vec![Code::AuthRevisionFloating],
        "exactly the typed diagnostic for that field, and nothing else:\n{}",
        run.report.render()
    );
    let diagnostic = &run.report.diagnostics()[0];
    assert_eq!(diagnostic.field, "source_revision");
    assert_eq!(diagnostic.subject, "core/2026-07-28/authorization/credentials-bound-to-issuer");

    // Only subcase A-04 fails; the other three still pass.
    let failed: Vec<&str> = run
        .manifest
        .subcases
        .iter()
        .filter(|s| s.outcome == Outcome::Fail)
        .map(|s| s.id.as_str())
        .collect();
    assert_eq!(failed, vec!["FND-02-A-04"]);

    // The rejection changed no state the acceptance names.
    //
    // The plan digest is the direct evidence for "changes only ONE variable":
    // the mutation was to the trace table, so the plan side must be bit-stable
    // across the two runs. The trace-table digest is deliberately NOT compared
    // here — it MUST move, because that is the variable that changed.
    assert_eq!(
        run.manifest.canonical_plan_sha256, baseline.manifest.canonical_plan_sha256,
        "the plan was not mutated, so its digest must be identical"
    );
    assert_ne!(
        run.manifest.canonical_trace_table_sha256, baseline.manifest.canonical_trace_table_sha256,
        "the trace table WAS mutated; an unchanged digest would mean the \
         mutation never reached the evaluator"
    );
    assert_eq!(run.manifest.trace_row_count, baseline.manifest.trace_row_count);
    assert_eq!(run.manifest.write_counters, [0; 6]);
    assert!(run.ledger.is_read_only());
    assert_eq!(
        before,
        snapshot(&immutable_paths(&repo)),
        "the repository must be byte-for-byte unchanged"
    );
}

// --------------------------------------------------------- ordered subcases

/// FND-02-A-01: coverage is an exact set in both directions.
#[test]
fn fnd_02_a_01_traceability_completeness() {
    // A removed row leaves its corpus item uncovered. A subset must fail.
    let scratch = Scratch::new("missing-row");
    let table = scratch.read(TRACE_TABLE_PATH);
    let marker = "[[row]]\nclause_key = \"core/2026-07-28/schema/json-schema-2020-12\"";
    let start = table.find(marker).expect("target row is present");
    let end = table[start + marker.len()..]
        .find("[[row]]")
        .map(|offset| start + marker.len() + offset)
        .unwrap_or(table.len());
    let mut trimmed = String::with_capacity(table.len());
    trimmed.push_str(&table[..start]);
    trimmed.push_str(&table[end..]);
    scratch.write(TRACE_TABLE_PATH, &trimmed);

    let run = plan_tracker::run_all(&scratch.root).expect("scratch loads");
    assert!(!run.passed());
    assert!(run.report.has(Code::TraceCoverageMissing));
    assert_eq!(run.manifest.subcases[0].outcome, Outcome::Fail);

    // A blank required field is rejected and names that field.
    let blanked = Scratch::new("blank-field");
    blanked.mutate_once(
        TRACE_TABLE_PATH,
        "server_behavior = \"resolves $ref within the declared composition-keyword resource bounds\"",
        "server_behavior = \"\"",
    );
    let run = plan_tracker::run_all(&blanked.root).expect("scratch loads");
    assert!(run.report.has(Code::TraceRowFieldEmpty));
    assert!(
        run.report
            .diagnostics()
            .iter()
            .any(|d| d.field == "server_behavior")
    );
}

/// FND-02-A-02: a duplicated clause key is rejected.
#[test]
fn fnd_02_a_02_duplicate_requirement_key() {
    let scratch = Scratch::new("duplicate-key");
    // Two distinct clauses, one key. Coverage is untouched, so only the
    // duplicate-key rule can catch this.
    scratch.mutate_once(
        TRACE_TABLE_PATH,
        "clause_key = \"core/2026-07-28/errors/allocation-policy-partition\"",
        "clause_key = \"core/2026-07-28/errors/resource-not-found-invalid-params\"",
    );

    let run = plan_tracker::run_all(&scratch.root).expect("scratch loads");
    assert!(!run.passed());
    assert_eq!(run.report.codes(), vec![Code::TraceRowDuplicateKey]);
    assert_eq!(run.manifest.subcases[1].id, "FND-02-A-02");
    assert_eq!(run.manifest.subcases[1].outcome, Outcome::Fail);
}

/// FND-02-A-03: a conformance reference that no longer resolves is rejected.
#[test]
fn fnd_02_a_03_stale_conformance_check_reference() {
    let scratch = Scratch::new("stale-check");
    // The scenario still exists; the check id does not. This is the drift
    // shape that a spelling check cannot see -- the row still looks traceable.
    scratch.mutate_once(
        TRACE_TABLE_PATH,
        "scenario_check_id = \"auth/client-credentials-jwt#client-credentials-jwt-verified\"",
        "scenario_check_id = \"auth/client-credentials-jwt#client-credentials-jwt-renamed\"",
    );

    let run = plan_tracker::run_all(&scratch.root).expect("scratch loads");
    assert!(!run.passed());
    assert_eq!(run.report.codes(), vec![Code::ConformanceReferenceStale]);
    assert_eq!(run.manifest.subcases[2].id, "FND-02-A-03");
    assert_eq!(run.manifest.subcases[2].outcome, Outcome::Fail);
}

/// FND-02-A-04: an exact but wrong revision is rejected.
#[test]
fn fnd_02_a_04_exact_auth_source_revision() {
    let scratch = Scratch::new("wrong-revision");
    // `oauth-2.1-14` is a real authority-declared revision, so membership and
    // spelling both pass. Only the clause-specific rule rejects it here.
    scratch.mutate_once(
        TRACE_TABLE_PATH,
        "source_revision = \"auth:oauth-2.1-13\"",
        "source_revision = \"auth:oauth-2.1-14\"",
    );

    let run = plan_tracker::run_all(&scratch.root).expect("scratch loads");
    assert!(!run.passed());
    assert_eq!(run.report.codes(), vec![Code::AuthRevisionWrong]);
    assert_eq!(run.manifest.subcases[3].id, "FND-02-A-04");
    assert_eq!(run.manifest.subcases[3].outcome, Outcome::Fail);
}

// ------------------------------------------------------------ drift detector

/// An authoritative source whose bytes changed without its binding being
/// updated turns the gate red.
///
/// This is the mechanism FND-01's six silently-stale bindings lacked. The
/// mutation is one byte of prose in a bound file: it changes no trace row, no
/// count, and no schema, and every other check still passes.
#[test]
fn fnd_02_a_detects_authoritative_source_drift() {
    let scratch = Scratch::new("source-drift");
    let baseline = plan_tracker::run_all(&scratch.root).expect("scratch loads");
    assert!(baseline.passed(), "the unmutated copy must pass");

    let conformance = "evidence/fnd-01/core-conformance.toml";
    let original = scratch.read(conformance);
    scratch.write(conformance, &format!("{original}\n# drifted\n"));

    let run = plan_tracker::run_all(&scratch.root).expect("scratch loads after drift");

    assert!(!run.passed(), "drifted authority must not pass");
    assert!(run.report.has(Code::SourceBlobDrift));
    let drift = run
        .report
        .diagnostics()
        .iter()
        .find(|d| d.code == Code::SourceBlobDrift)
        .expect("a drift diagnostic");
    assert_eq!(drift.field, "blob_sha1");
    assert_eq!(drift.subject, "fnd-01-core-conformance");
    assert_eq!(run.manifest.write_counters, [0; 6]);
}

/// The binding is verified against the bytes, not merely re-read from the
/// registry: a registry claiming a wrong hash for an untouched file fails.
/// A changelog that RESOLVES but cannot be decoded must fail, not silently
/// empty the required coverage set.
///
/// `resolve` reads bytes and verifies the blob hash; it never validates UTF-8.
/// The required-source gate only checks that the id resolved. So an
/// undecodable changelog reaches the coverage step with `text()` returning
/// `None`, where `unwrap_or_default()` used to turn it into zero required
/// changelog items. `check_coverage` refuses a zero-item set, but the
/// conformance items keep the set non-empty, so that guard never fired and
/// A-01's changelog half vanished from a green run.
#[test]
fn fnd_02_a_rejects_a_changelog_that_is_not_valid_utf8() {
    let scratch = Scratch::new("changelog-not-utf8");

    // One invalid byte appended to an otherwise intact document, so encoding
    // is the only thing wrong with it.
    let path = scratch.root.join(CHANGELOG_PATH);
    let mut bytes = fs::read(&path).expect("the scratch changelog is readable");
    bytes.push(0xff);
    fs::write(&path, &bytes).expect("the scratch changelog is writable");

    // Rebind the registry to the corrupted bytes. WITHOUT THIS the run stops
    // at SourceBlobDrift and never reaches the decode — which is precisely why
    // blob verification does not cover this case. It catches bytes that
    // CHANGED, not bytes that were never decodable to begin with.
    scratch.mutate_once(
        SOURCES_PATH,
        "blob_sha1 = \"dc5c9a9cf3e6895504534cf3f300514394d8c6ae\"",
        &format!("blob_sha1 = \"{}\"", git_blob_hex(&bytes)),
    );

    let run = plan_tracker::run_all(&scratch.root).expect("scratch loads");

    assert!(!run.passed(), "an undecodable changelog must not pass");
    assert!(
        run.report.has(Code::SourceUnreadable),
        "the failure must be reported, not absorbed into an empty required set"
    );
    // Discriminator: without this the test could pass for the wrong reason,
    // proving blob verification works rather than UTF-8 validation.
    assert!(
        !run.report.has(Code::SourceBlobDrift),
        "the binding was updated to match, so this must not be a drift failure"
    );
}

#[test]
fn fnd_02_a_rejects_a_binding_that_does_not_match_its_file() {
    let scratch = Scratch::new("wrong-binding");
    scratch.mutate_once(
        SOURCES_PATH,
        "blob_sha1 = \"c3ee530e9d0b70fce8ca85393fd72736a559f168\"",
        "blob_sha1 = \"0000000000000000000000000000000000000000\"",
    );

    let run = plan_tracker::run_all(&scratch.root).expect("scratch loads");
    assert!(!run.passed());
    assert!(run.report.has(Code::SourceBlobDrift));
}
