//! FND-02 implementation B: drift detection, invalidation propagation, and
//! exact-set checking.
//!
//! The positive runs the shipped evaluator end to end over a conformant
//! fixture; the negatives plant exactly one field, byte, edge, or label and
//! require the matching typed diagnostic. The checker's own crate files are
//! copied into the fixture unchanged, so the workspace-policy and module
//! inventory subcases observe the real crate rather than a stand-in.
//!
//! Frozen IDs: `fnd_02_b_positive`, `fnd_02_b_planted_negative`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use fastmcp_xtask::plan_tracker::{
    b_eval::{self, BEADS_EXPORT_PATH, B_SUBCASES, PLAN_PATH, ReservationInputs},
    diagnostics::Code,
    digest::git_blob_hex,
    fingerprint,
    manifest::Outcome,
    plan::{self, Limits},
    reservations::{
        DECLARATION_SCHEMA, Declaration, Lease, Renewal, ReservationSnapshot, SNAPSHOT_SCHEMA,
    },
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tools/xtask sits two levels below the repository root")
        .to_path_buf()
}

/// A minimal but fully conformant plan: three packages, two edges, one fenced
/// decoy heading, and one interstitial separator.
const FIXTURE_PLAN: &str = "\
# Intro prose outside the region.

### FND-01 \u{2014} Freeze authoritative inputs

Outcome: freeze the inputs.

```
### DECOY \u{2014} this heading lives inside a fence
Dependencies:

- None.
```

Dependencies:

- None.

---

### FND-02 \u{2014} Build normative traceability

Outcome: map requirements to tests.

Dependencies:

- FND-01.

## 14. Phase 2 \u{2014} An interstitial phase heading

### PRT-01 \u{2014} Introduce strict JSON-RPC envelopes

Outcome: strict envelopes.

Dependencies:

- FND-01.
- FND-02.

## 24. Dependency graph and critical path

Trailing prose outside the region.
";

/// A tracker export whose `wp-parent-` labels exactly match the fixture plan.
const FIXTURE_EXPORT: &str = concat!(
    r#"{"id":"bd-a","status":"open","labels":["wp-parent-fnd-01","profile-core-qualified"]}"#,
    "\n",
    r#"{"id":"bd-b","status":"open","labels":["wp-parent-fnd-02","profile-core-qualified"]}"#,
    "\n",
    r#"{"id":"bd-c","status":"open","labels":["wp-parent-prt-01","profile-core-qualified"]}"#,
    "\n",
);

const NOW: i64 = 1_700_000_000;
const CLAIMED_AT: i64 = NOW - 3_600;

fn declaration() -> Declaration {
    Declaration {
        schema: DECLARATION_SCHEMA.to_owned(),
        project_key: "/repo".to_owned(),
        agent_name: "MagentaOsprey".to_owned(),
        issue_id: "bd-mcp-fnd-02-b-3srw".to_owned(),
        paths: vec!["tools/xtask/**".to_owned()],
    }
}

fn snapshot() -> ReservationSnapshot {
    ReservationSnapshot {
        schema: SNAPSHOT_SCHEMA.to_owned(),
        project_key: "/repo".to_owned(),
        agent_name: "MagentaOsprey".to_owned(),
        generated_at: NOW - 5,
        leases: vec![Lease {
            lease_id: "L1".to_owned(),
            path: "tools/xtask/**".to_owned(),
            exclusive: true,
            issue_id: "bd-mcp-fnd-02-b-3srw".to_owned(),
            expires_at: NOW + 7_200,
            history: vec![Renewal { at: CLAIMED_AT - 60, until: NOW + 7_200 }],
        }],
    }
}

fn inputs() -> ReservationInputs {
    ReservationInputs {
        declaration: Some(declaration()),
        snapshot: Some(snapshot()),
        now: NOW,
        claimed_at: CLAIMED_AT,
    }
}

static SCRATCH_COUNTER: AtomicU32 = AtomicU32::new(0);

/// A conformant fixture repository.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let unique = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fnd-02-b-{label}-{}-{unique}",
            std::process::id()
        ));
        let source = repo_root();

        fs::create_dir_all(root.join(".beads")).expect("scratch is creatable");
        fs::write(root.join(PLAN_PATH), FIXTURE_PLAN).expect("plan is writable");
        fs::write(root.join(BEADS_EXPORT_PATH), FIXTURE_EXPORT).expect("export is writable");

        // The real checker crate, copied verbatim: the policy and inventory
        // subcases must observe the shipped crate, not a stand-in.
        fs::create_dir_all(root.join(".cargo")).expect("scratch is creatable");
        fs::copy(source.join(".cargo/config.toml"), root.join(".cargo/config.toml"))
            .expect(".cargo/config.toml is copyable");
        fs::copy(source.join("Cargo.toml"), root.join("Cargo.toml"))
            .expect("Cargo.toml is copyable");
        fs::create_dir_all(root.join("tools/xtask/src/plan_tracker")).expect("scratch");
        fs::copy(
            source.join("tools/xtask/Cargo.toml"),
            root.join("tools/xtask/Cargo.toml"),
        )
        .expect("crate manifest is copyable");
        for stem in ["lib", "main"] {
            fs::copy(
                source.join(format!("tools/xtask/src/{stem}.rs")),
                root.join(format!("tools/xtask/src/{stem}.rs")),
            )
            .expect("crate root is copyable");
        }
        for entry in fs::read_dir(source.join("tools/xtask/src/plan_tracker"))
            .expect("module directory is readable")
            .flatten()
        {
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "rs") {
                let name = path.file_name().expect("module has a name");
                fs::copy(&path, root.join("tools/xtask/src/plan_tracker").join(name))
                    .expect("module is copyable");
            }
        }


        // Every declared workspace member's manifest, because the unsafe-code
        // policy check reads each one. Only the manifests are needed; the
        // crate sources are irrelevant to the policy subcase.
        for member in fastmcp_xtask::plan_tracker::policy::workspace_members(&source)
            .expect("the live workspace declares members")
        {
            let target = root.join(&member).join("Cargo.toml");
            fs::create_dir_all(target.parent().expect("has a parent"))
                .expect("scratch member directory");
            fs::copy(source.join(&member).join("Cargo.toml"), &target)
                .expect("member manifest is copyable");
        }

        Self { root }
    }

    fn read(&self, relative: &str) -> String {
        fs::read_to_string(self.root.join(relative)).expect("fixture input is readable")
    }

    fn write(&self, relative: &str, contents: &str) {
        fs::write(self.root.join(relative), contents).expect("fixture input is writable");
    }

    /// Replace exactly one occurrence, refusing to become a silent no-op.
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

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.root.starts_with(std::env::temp_dir()) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

// ----------------------------------------------------------------- positive

/// Every one of the fifteen subcases passes over a conformant fixture.
#[test]
fn fnd_02_b_positive() {
    let fixture = Fixture::new("positive");
    let run = b_eval::run(&fixture.root, &inputs()).expect("the evaluator loads its inputs");

    assert!(
        run.report.is_clean(),
        "expected a clean run, got:\n{}",
        run.report.render()
    );
    assert!(run.passed());

    // Exactly the fifteen declared subcases, in order, all passing.
    let observed: Vec<(&str, &str)> = run
        .manifest
        .subcases
        .iter()
        .map(|s| (s.id.as_str(), s.name.as_str()))
        .collect();
    assert_eq!(observed, B_SUBCASES.to_vec());
    assert!(
        run.manifest
            .subcases
            .iter()
            .all(|s| s.outcome == Outcome::Pass && s.diagnostic_count == 0)
    );

    // Non-degenerate: the fixture really had a graph to check.
    assert_eq!(run.manifest.package_count, 3);
    assert_eq!(run.manifest.edge_count, 3);
    assert!(run.manifest.module_count >= 6);
    assert_eq!(run.plan.ids(), ["FND-01", "FND-02", "PRT-01"]);

    // The fenced decoy heading did not become a package.
    assert!(!run.plan.ids().contains(&"DECOY"));

    assert!(run.manifest.digests_are_canonical());
    assert_ne!(
        run.manifest.canonical_graph_sha256,
        run.manifest.canonical_corpus_sha256
    );
    assert_eq!(run.manifest.write_counters, [0; 6]);
    assert!(run.ledger.is_read_only());
}

// ---------------------------------------------------------------- negative

/// The one-variable planted negative: one dependency bullet changes from
/// `FND-01` to an identifier the corpus does not declare.
#[test]
fn fnd_02_b_planted_negative() {
    let repo = repo_root();
    let before = fs::read(repo.join(PLAN_PATH)).expect("plan is readable");

    let fixture = Fixture::new("unresolved-edge");
    let baseline = b_eval::run(&fixture.root, &inputs()).expect("fixture loads");
    assert!(baseline.passed(), "the unmutated fixture must pass");

    fixture.mutate_once(PLAN_PATH, "- FND-01.\n- FND-02.", "- FND-99.\n- FND-02.");

    // Snapshot the fixture's own inputs AFTER the deliberate mutation and
    // BEFORE the run, so the comparison below isolates what the EVALUATOR did
    // from what the test did.
    //
    // `run` returns Result<BRun, Diagnostic>, so a rejection discards the
    // manifest and the ledger with it: write_counters cannot be observed on
    // this path at all, and both existing `write_counters == [0; 6]`
    // assertions are on PASSING runs. Acceptance item 5 is specifically about
    // what a REJECTION leaves behind, so the filesystem is the only witness
    // available here.
    let inputs_before: Vec<(PathBuf, Vec<u8>)> =
        [PLAN_PATH, BEADS_EXPORT_PATH, ".cargo/config.toml"]
            .iter()
            .map(|relative| {
                let path = fixture.root.join(relative);
                let bytes = fs::read(&path).expect("fixture input is readable");
                (path, bytes)
            })
            .collect();

    let error = b_eval::run(&fixture.root, &inputs())
        .expect_err("an unresolved edge must be rejected");
    assert_eq!(error.code, Code::DependencyUnresolved);
    assert_eq!(error.subject, "PRT-01");

    // The rejecting path wrote nothing to what it read.
    for (path, bytes) in inputs_before {
        assert_eq!(
            bytes,
            fs::read(&path).expect("fixture input is readable"),
            "a rejection must not modify its own inputs: {path:?}"
        );
    }

    // The rejection changed nothing.
    assert_eq!(
        before,
        fs::read(repo.join(PLAN_PATH)).expect("plan is readable"),
        "the repository plan must be byte-for-byte unchanged"
    );
}

// ------------------------------------------------------- per-subcase drift

/// B-02 and B-03: a stale snapshot fails preclaim and preclose.
#[test]
fn fnd_02_b_02_03_reservation_modes_reject_a_stale_snapshot() {
    let fixture = Fixture::new("stale-snapshot");
    let mut stale = inputs();
    stale.snapshot.as_mut().expect("snapshot").generated_at = NOW - 61;

    let run = b_eval::run(&fixture.root, &stale).expect("fixture loads");
    assert!(!run.passed());
    assert!(run.report.has(Code::ReservationSnapshotStale));
    assert_eq!(run.subcase("FND-02-B-02").expect("B-02").outcome, Outcome::Fail);
    assert_eq!(run.subcase("FND-02-B-03").expect("B-03").outcome, Outcome::Fail);
}

/// B-03: a renewal gap fails close but not claim.
#[test]
fn fnd_02_b_03_preclose_rejects_a_renewal_gap() {
    let fixture = Fixture::new("renewal-gap");
    let mut gapped = inputs();
    gapped.snapshot.as_mut().expect("snapshot").leases[0].history = vec![
        Renewal { at: CLAIMED_AT - 60, until: CLAIMED_AT + 10 },
        Renewal { at: CLAIMED_AT + 600, until: NOW + 7_200 },
    ];

    let run = b_eval::run(&fixture.root, &gapped).expect("fixture loads");
    assert!(run.report.has(Code::ReservationRenewalGap));
    assert_eq!(run.subcase("FND-02-B-03").expect("B-03").outcome, Outcome::Fail);
    assert_eq!(
        run.subcase("FND-02-B-02").expect("B-02").outcome,
        Outcome::Pass,
        "claim does not impose the close-time history rule"
    );
}

/// B-05: a missing snapshot is reported, never silently passed.
#[test]
fn fnd_02_b_05_a_missing_snapshot_does_not_pass_vacuously() {
    let fixture = Fixture::new("no-snapshot");
    let run = b_eval::run(&fixture.root, &ReservationInputs::default())
        .expect("fixture loads");
    assert!(!run.passed());
    assert!(run.report.has(Code::ReservationSnapshotMissing));
    assert_eq!(run.subcase("FND-02-B-05").expect("B-05").outcome, Outcome::Fail);
}

/// B-07: a package heading hidden inside a fence never becomes a package,
/// and an unclosed fence is rejected outright.
#[test]
fn fnd_02_b_07_fence_corpus() {
    let fixture = Fixture::new("fence");
    let run = b_eval::run(&fixture.root, &inputs()).expect("fixture loads");
    assert_eq!(run.manifest.package_count, 3, "the decoy heading leaked in");

    let unclosed = Fixture::new("unclosed-fence");
    unclosed.mutate_once(PLAN_PATH, "- None.\n```", "- None.");
    let error = b_eval::run(&unclosed.root, &inputs())
        .expect_err("an unclosed fence must be rejected");
    assert_eq!(error.code, Code::PlanFenceUnclosed);
}

/// B-08: the package grammar is exact at its boundaries.
#[test]
fn fnd_02_b_08_package_grammar_boundaries() {
    let cases: [(&str, &str, Code); 4] = [
        ("### PRT-01 \u{2014} Introduce strict JSON-RPC envelopes",
         "### prt-01 \u{2014} Lowercase identifier", Code::PackageIdInvalid),
        ("### PRT-01 \u{2014} Introduce strict JSON-RPC envelopes",
         "### PRT-01 - Hyphen instead of em dash", Code::PackageHeadingInvalid),
        ("- FND-01.\n- FND-02.", "- FND-01\n- FND-02.", Code::DependencyBulletInvalid),
        ("- FND-01.\n- FND-02.", "- None.\n- FND-02.", Code::DependencyMixedSentinel),
    ];
    for (from, to, expected) in cases {
        let fixture = Fixture::new("grammar");
        fixture.mutate_once(PLAN_PATH, from, to);
        let error = b_eval::run(&fixture.root, &inputs())
            .expect_err(&format!("{to:?} must be rejected"));
        assert_eq!(error.code, expected, "for mutation {to:?}");
    }
}

/// B-09/B-10/B-11: a one-byte change anywhere in either stream changes its
/// digest, and a domain-swapped stream is rejected.
#[test]
fn fnd_02_b_09_10_11_stream_mutations() {
    let fixture = Fixture::new("streams");
    let run = b_eval::run(&fixture.root, &inputs()).expect("fixture loads");

    let limits = Limits::default();
    let parsed = plan::parse(&fs::read(fixture.root.join(PLAN_PATH)).unwrap(), &limits)
        .expect("parses");
    let graph = fingerprint::encode_graph(&parsed);
    let corpus = fingerprint::encode_corpus(&parsed);

    assert_eq!(fingerprint::fingerprint_hex(&graph), run.manifest.canonical_graph_sha256);
    assert_eq!(fingerprint::fingerprint_hex(&corpus), run.manifest.canonical_corpus_sha256);

    // Domain separation.
    assert!(fingerprint::decode_corpus(&graph, &limits).is_err());
    assert!(fingerprint::decode_graph(&corpus, &limits).is_err());

    // Every single-byte mutation changes the digest.
    let baseline = fingerprint::fingerprint_hex(&graph);
    for index in 0..graph.len() {
        let mut mutated = graph.clone();
        mutated[index] ^= 0x01;
        assert_ne!(baseline, fingerprint::fingerprint_hex(&mutated), "byte {index}");
    }

    // Every truncation is rejected.
    for cut in 0..graph.len() {
        assert!(fingerprint::decode_graph(&graph[..cut], &limits).is_err(), "cut {cut}");
    }

    // Unsigned byte ordering, not natural sort.
    let decoded = fingerprint::decode_graph(&graph, &limits).expect("decodes");
    let mut expected = decoded.nodes.clone();
    expected.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(decoded.nodes, expected);
}

/// B-13/B-14: removing the alias or the unsafe-code attribute is detected.
#[test]
fn fnd_02_b_13_14_workspace_policy() {
    let alias = Fixture::new("no-alias");
    alias.mutate_once(
        ".cargo/config.toml",
        "xtask = \"run --locked --quiet -p fastmcp-xtask --\"",
        "xtask = \"run -p something-else --\"",
    );
    let run = b_eval::run(&alias.root, &inputs()).expect("fixture loads");
    assert!(run.report.has(Code::WorkspacePolicy));
    assert_eq!(run.subcase("FND-02-B-13").expect("B-13").outcome, Outcome::Fail);

    let unsafe_policy = Fixture::new("no-forbid");
    unsafe_policy.mutate_once(
        "tools/xtask/src/lib.rs",
        "#![forbid(unsafe_code)]",
        "// #![forbid(unsafe_code)]",
    );
    let run = b_eval::run(&unsafe_policy.root, &inputs()).expect("fixture loads");
    assert!(run.report.has(Code::WorkspacePolicy));
    assert_eq!(run.subcase("FND-02-B-14").expect("B-14").outcome, Outcome::Fail);

    let publishable = Fixture::new("publishable");
    publishable.mutate_once("tools/xtask/Cargo.toml", "publish = false", "publish = true");
    let run = b_eval::run(&publishable.root, &inputs()).expect("fixture loads");
    assert_eq!(run.subcase("FND-02-B-13").expect("B-13").outcome, Outcome::Fail);
}

/// B-15: package/label mapping parity is an exact set in both directions.
#[test]
fn fnd_02_b_15_generated_inventory_closure() {
    // A label naming a package the plan does not declare.
    let extra = Fixture::new("label-extra");
    extra.mutate_once(BEADS_EXPORT_PATH, "wp-parent-prt-01", "wp-parent-prt-99");
    let run = b_eval::run(&extra.root, &inputs()).expect("fixture loads");
    assert!(!run.passed());
    assert_eq!(run.report.codes(), vec![Code::PackageLabelMapping]);
    assert_eq!(run.subcase("FND-02-B-15").expect("B-15").outcome, Outcome::Fail);
    // Both directions are reported: PRT-01 untracked, PRT-99 undeclared.
    let subjects: Vec<&str> = run
        .report
        .diagnostics()
        .iter()
        .map(|d| d.subject.as_str())
        .collect();
    assert!(subjects.contains(&"PRT-01"));
    assert!(subjects.contains(&"PRT-99"));
}

/// The evaluator is strictly read-only: the fixture is byte-identical after a
/// run, and every write counter is zero.
#[test]
fn fnd_02_b_06_strict_read_only() {
    let fixture = Fixture::new("read-only");
    let before: Vec<(PathBuf, Vec<u8>)> = [PLAN_PATH, BEADS_EXPORT_PATH, ".cargo/config.toml"]
        .iter()
        .map(|relative| {
            let path = fixture.root.join(relative);
            let bytes = fs::read(&path).expect("input is readable");
            (path, bytes)
        })
        .collect();

    let run = b_eval::run(&fixture.root, &inputs()).expect("fixture loads");

    assert_eq!(run.manifest.write_counters, [0; 6]);
    assert!(run.ledger.is_read_only());
    assert_eq!(run.subcase("FND-02-B-06").expect("B-06").outcome, Outcome::Pass);
    for (path, bytes) in before {
        assert_eq!(bytes, fs::read(&path).expect("input is readable"), "{path:?}");
    }
}

/// The tracker export is BOUND by the receipt, not merely read.
///
/// B reads two inputs. Until the `beads_blob_sha1` field existed it bound only
/// the plan, so two runs could produce byte-identical receipts while having
/// evaluated B-15 generated-inventory-closure against different tracker
/// exports. Neither the graph nor the corpus digest covers the export: both
/// derive from the parsed plan.
#[test]
fn fnd_02_b_binds_the_tracker_export_it_read() {
    let fixture = Fixture::new("beads-binding");
    let run = b_eval::run(&fixture.root, &inputs()).expect("fixture loads");

    let bytes = fs::read(fixture.root.join(BEADS_EXPORT_PATH)).expect("export is readable");
    assert_eq!(
        run.manifest.beads_blob_sha1,
        git_blob_hex(&bytes),
        "the receipt must bind the blob id of the export it read"
    );
    assert_ne!(
        run.manifest.beads_blob_sha1, run.manifest.plan_blob_sha1,
        "the two inputs must not collapse onto one binding"
    );

    // And it TRACKS content. Without this the field could be any fixed string
    // and every assertion above would still hold.
    let mutated = Fixture::new("beads-binding-mutated");
    mutated.mutate_once(BEADS_EXPORT_PATH, r#""id":"bd-a""#, r#""id":"bd-a1""#);
    let after = b_eval::run(&mutated.root, &inputs()).expect("fixture loads");

    assert!(
        after.passed(),
        "the mutation must leave a PASSING run, or the digest difference is \
         confounded by a failure:\n{}",
        after.report.render()
    );
    assert_ne!(
        after.manifest.beads_blob_sha1, run.manifest.beads_blob_sha1,
        "a different export must bind differently"
    );
    assert_eq!(
        after.manifest.plan_blob_sha1, run.manifest.plan_blob_sha1,
        "only the export changed, so the plan binding must be identical -- \
         this is what makes the difference above attributable"
    );
}

/// The live repository parses under the same grammar the fixture uses.
///
/// This is the anti-toy check: a parser that only ever sees its own fixture
/// proves nothing about the document it was written for.
#[test]
fn fnd_02_b_parses_the_live_campaign_plan() {
    let bytes = fs::read(repo_root().join(PLAN_PATH)).expect("the plan is readable");
    let parsed = plan::parse(&bytes, &Limits::default()).expect("the live plan parses");

    assert!(parsed.packages.len() > 100, "observed {}", parsed.packages.len());
    assert!(parsed.edges.len() > parsed.packages.len());
    assert!(parsed.packages.iter().all(|p| plan::is_package_id(&p.id, 64)));
    assert!(parsed.ids().contains(&"FND-01"));
    assert!(parsed.ids().contains(&"FND-02"));

    // Both streams decode and re-encode exactly over the real corpus.
    let limits = Limits::default();
    let graph = fingerprint::encode_graph(&parsed);
    let corpus = fingerprint::encode_corpus(&parsed);
    fingerprint::decode_graph(&graph, &limits).expect("live graph decodes");
    fingerprint::decode_corpus(&corpus, &limits).expect("live corpus decodes");
    fingerprint::graph_reencodes_identically(&graph, &limits).expect("live round trip is exact");
}
