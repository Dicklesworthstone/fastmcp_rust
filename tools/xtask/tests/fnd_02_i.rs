//! FND-02 integration: join capability slices through public entrypoints.
//!
//! The join consumes the A and B manifests produced by the shipped
//! evaluators, by their bytes. Nothing here re-derives a slice's result or
//! substitutes a private evaluator: both inputs come from the same public
//! functions the binary calls.
//!
//! Frozen IDs: `fnd_02_i_positive`, `fnd_02_i_planted_negative`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use fastmcp_xtask::plan_tracker::{
    self,
    b_eval::{self, BEADS_EXPORT_PATH, PLAN_PATH, ReservationInputs},
    diagnostics::Code,
    integration::{self, I_CONSUMER, I_SUBCASES, ManifestInput},
    manifest::Outcome,
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

const FIXTURE_PLAN: &str = "\
### FND-01 \u{2014} Freeze authoritative inputs

Outcome: freeze the inputs.

Dependencies:

- None.

---

### FND-02 \u{2014} Build normative traceability

Outcome: map requirements to tests.

Dependencies:

- FND-01.

## 24. Dependency graph and critical path
";

const FIXTURE_EXPORT: &str = concat!(
    r#"{"id":"bd-a","status":"open","labels":["wp-parent-fnd-01"]}"#,
    "\n",
    r#"{"id":"bd-b","status":"open","labels":["wp-parent-fnd-02"]}"#,
    "\n",
);

const NOW: i64 = 1_700_000_000;
const CLAIMED_AT: i64 = NOW - 3_600;

static SCRATCH_COUNTER: AtomicU32 = AtomicU32::new(0);

/// A fixture carrying everything both evaluators read.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let unique = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fnd-02-i-{label}-{}-{unique}",
            std::process::id()
        ));
        let source = repo_root();

        fs::create_dir_all(root.join(".beads")).expect("scratch is creatable");
        fs::write(root.join(PLAN_PATH), FIXTURE_PLAN).expect("plan is writable");
        fs::write(root.join(BEADS_EXPORT_PATH), FIXTURE_EXPORT).expect("export is writable");

        fs::create_dir_all(root.join(".cargo")).expect("scratch is creatable");
        for relative in [".cargo/config.toml", "Cargo.toml"] {
            fs::copy(source.join(relative), root.join(relative)).expect("file is copyable");
        }
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

        // The A evaluator reads the real FND-02 evidence and the sources it
        // binds, so those are copied verbatim too.
        for relative in [
            plan_tracker::SOURCES_PATH,
            plan_tracker::TRACE_TABLE_PATH,
            "evidence/fnd-01/vendor/core/mcp-changelog-2026-07-28-5f5440bb.mdx",
            "evidence/fnd-01/core-conformance.toml",
            "evidence/fnd-01/auth-standards.toml",
        ] {
            let target = root.join(relative);
            fs::create_dir_all(target.parent().expect("has a parent")).expect("scratch");
            fs::copy(source.join(relative), &target).expect("evidence is copyable");
        }
        // The A registry binds the campaign plan; the fixture substitutes a
        // small one, so the real plan is copied to that bound path instead.
        fs::copy(source.join(PLAN_PATH), root.join("real-plan.md")).expect("plan is copyable");


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
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.root.starts_with(std::env::temp_dir()) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn reservation_inputs() -> ReservationInputs {
    ReservationInputs {
        declaration: Some(Declaration {
            schema: DECLARATION_SCHEMA.to_owned(),
            project_key: "/repo".to_owned(),
            agent_name: "MagentaOsprey".to_owned(),
            issue_id: "bd-mcp-fnd-02-integration-8s4k".to_owned(),
            paths: vec!["tools/xtask/**".to_owned()],
        }),
        snapshot: Some(ReservationSnapshot {
            schema: SNAPSHOT_SCHEMA.to_owned(),
            project_key: "/repo".to_owned(),
            agent_name: "MagentaOsprey".to_owned(),
            generated_at: NOW - 5,
            leases: vec![Lease {
                lease_id: "L1".to_owned(),
                path: "tools/xtask/**".to_owned(),
                exclusive: true,
                issue_id: "bd-mcp-fnd-02-integration-8s4k".to_owned(),
                expires_at: NOW + 7_200,
                history: vec![Renewal { at: CLAIMED_AT - 60, until: NOW + 7_200 }],
            }],
        }),
        now: NOW,
        claimed_at: CLAIMED_AT,
    }
}

/// Produce both slice manifests from the shipped evaluators.
///
/// A runs against the real repository, because its authoritative-source
/// bindings are blob hashes of the real files; B runs against the fixture.
/// Both are the public entrypoints the binary uses.
fn slices(
    fixture: &Fixture,
) -> (
    plan_tracker::manifest::AManifest,
    b_eval::BManifest,
) {
    let a = plan_tracker::run_all(&repo_root()).expect("the A evaluator loads");
    let b = b_eval::run(&fixture.root, &reservation_inputs()).expect("the B evaluator loads");
    (a.manifest, b.manifest)
}

// ----------------------------------------------------------------- positive

#[test]
fn fnd_02_i_positive() {
    let fixture = Fixture::new("positive");
    let (a, b) = slices(&fixture);

    let a_input = ManifestInput::from_a(&a);
    let b_input = ManifestInput::from_b(&b);
    let run = integration::join(&a_input, &b_input, &a, &b);

    assert!(
        run.report.is_clean(),
        "expected a clean join, got:\n{}",
        run.report.render()
    );
    assert!(run.passed());

    // Exactly the four declared subcases, in order, all passing.
    let observed: Vec<(&str, &str)> = run
        .manifest
        .subcases
        .iter()
        .map(|s| (s.id.as_str(), s.name.as_str()))
        .collect();
    assert_eq!(observed, I_SUBCASES.to_vec());
    assert!(
        run.manifest
            .subcases
            .iter()
            .all(|s| s.outcome == Outcome::Pass && s.diagnostic_count == 0)
    );

    // Minimum input cardinality: two manifests and four subcases.
    assert_eq!(run.manifest.input_manifest_count, 2);
    assert_eq!(run.manifest.subcases.len(), 4);

    // The receipt carries both input digests and the joined digests.
    assert_eq!(run.manifest.schema, "fnd-02-integration-manifest-v1");
    assert_eq!(run.manifest.a_manifest_sha256, a.digest());
    assert_eq!(run.manifest.b_manifest_sha256, b.digest());
    assert_eq!(run.manifest.joined_graph_sha256, b.canonical_graph_sha256);
    assert_eq!(run.manifest.joined_corpus_sha256, b.canonical_corpus_sha256);
    assert_eq!(
        run.manifest.joined_trace_table_sha256,
        a.canonical_trace_table_sha256
    );
    assert!(run.manifest.digests_are_canonical());
    assert_eq!(run.manifest.consumer_id, I_CONSUMER);
    assert_eq!(run.manifest.write_counters, [0; 5]);

    // The two inputs are genuinely distinct receipts.
    assert_ne!(run.manifest.a_manifest_sha256, run.manifest.b_manifest_sha256);
}

// ---------------------------------------------------------------- negative

/// The one-variable planted negative: only the B manifest's graph digest
/// changes, which breaks its byte binding.
#[test]
fn fnd_02_i_planted_negative() {
    let fixture = Fixture::new("negative");
    let (a, mut b) = slices(&fixture);

    let a_input = ManifestInput::from_a(&a);
    let honest_b = ManifestInput::from_b(&b);

    // Baseline: the unmutated join passes, so the rejection below is
    // attributable to the mutation alone.
    let baseline = integration::join(&a_input, &honest_b, &a, &b);
    assert!(baseline.passed(), "the unmutated join must pass");

    // Change exactly one field: the B manifest's graph digest. The declared
    // digest still describes the original bytes, so the binding must break.
    let original_graph_digest = b.canonical_graph_sha256.clone();
    b.canonical_graph_sha256 = "f".repeat(64);
    let tampered = ManifestInput {
        schema: honest_b.schema.clone(),
        canonical_json: b.to_canonical_json(),
        declared_digest: honest_b.declared_digest.clone(),
    };

    let run = integration::join(&a_input, &tampered, &a, &b);

    assert!(!run.passed(), "a broken manifest binding must not pass");
    assert_eq!(
        run.report.codes(),
        vec![Code::ManifestBindingMismatch],
        "exactly the manifest-binding diagnostic:\n{}",
        run.report.render()
    );
    assert_eq!(
        run.subcase("FND-02-I-02").expect("I-02").outcome,
        Outcome::Fail
    );
    // Only the B-consuming subcase fails; the A binding is untouched.
    assert_eq!(
        run.subcase("FND-02-I-01").expect("I-01").outcome,
        Outcome::Pass
    );

    // The A manifest and the honest B receipt are unchanged.
    assert_eq!(a_input.declared_digest, a.digest());
    assert_eq!(honest_b.declared_digest, run.manifest.b_manifest_sha256);
    assert_ne!(original_graph_digest, b.canonical_graph_sha256);
    assert_eq!(run.manifest.write_counters, [0; 5]);
}

// --------------------------------------------------------- ordered subcases

/// FND-02-I-01: the A manifest is consumed by its bytes.
#[test]
fn fnd_02_i_01_consume_a_manifest() {
    let fixture = Fixture::new("consume-a");
    let (a, b) = slices(&fixture);

    let honest = ManifestInput::from_a(&a);
    assert_eq!(honest.observed_digest(), honest.declared_digest);
    assert!(integration::join(&honest, &ManifestInput::from_b(&b), &a, &b).passed());

    let tampered = ManifestInput {
        declared_digest: "0".repeat(64),
        ..honest
    };
    let run = integration::join(&tampered, &ManifestInput::from_b(&b), &a, &b);
    assert_eq!(run.subcase("FND-02-I-01").expect("I-01").outcome, Outcome::Fail);
    assert!(run.report.has(Code::ManifestBindingMismatch));
}

/// FND-02-I-02: the B manifest is consumed by its bytes.
#[test]
fn fnd_02_i_02_consume_b_manifest() {
    let fixture = Fixture::new("consume-b");
    let (a, b) = slices(&fixture);

    let honest = ManifestInput::from_b(&b);
    assert_eq!(honest.observed_digest(), honest.declared_digest);

    // A single flipped character in the bytes breaks the binding.
    let flipped = ManifestInput {
        canonical_json: honest.canonical_json.replacen("fnd-02-b", "fnd-02-B", 1),
        ..honest.clone()
    };
    assert_ne!(flipped.observed_digest(), flipped.declared_digest);
    let run = integration::join(&ManifestInput::from_a(&a), &flipped, &a, &b);
    assert_eq!(run.subcase("FND-02-I-02").expect("I-02").outcome, Outcome::Fail);
}

/// FND-02-I-03: the join refuses slices produced under different
/// configurations, and refuses a slice that did not pass.
#[test]
fn fnd_02_i_03_all_mode_joined_projection() {
    let fixture = Fixture::new("joined");
    let (a, mut b) = slices(&fixture);

    // A configuration conflict.
    b.target = "aarch64-apple-darwin".to_owned();
    let run = integration::join(
        &ManifestInput::from_a(&a),
        &ManifestInput::from_b(&b),
        &a,
        &b,
    );
    assert!(run.report.has(Code::ManifestJoinConflict));
    assert_eq!(run.subcase("FND-02-I-03").expect("I-03").outcome, Outcome::Fail);

    // A failed slice cannot be joined into a passing receipt.
    let (a, mut b) = slices(&fixture);
    b.subcases[0].outcome = Outcome::Fail;
    let run = integration::join(
        &ManifestInput::from_a(&a),
        &ManifestInput::from_b(&b),
        &a,
        &b,
    );
    assert!(run.report.has(Code::ManifestJoinConflict));
    assert!(
        run.report
            .diagnostics()
            .iter()
            .any(|d| d.field == "b_subcases")
    );
}

/// FND-02-I-04: every carried digest is an exact canonical rendering.
#[test]
fn fnd_02_i_04_exact_receipt_binding() {
    let fixture = Fixture::new("binding");
    let (a, mut b) = slices(&fixture);
    assert!(
        integration::join(
            &ManifestInput::from_a(&a),
            &ManifestInput::from_b(&b),
            &a,
            &b
        )
        .passed()
    );

    // An uppercase digest is a different rendering and is rejected.
    b.canonical_corpus_sha256 = b.canonical_corpus_sha256.to_uppercase();
    let input = ManifestInput::from_b(&b);
    let run = integration::join(&ManifestInput::from_a(&a), &input, &a, &b);
    assert_eq!(run.subcase("FND-02-I-04").expect("I-04").outcome, Outcome::Fail);
    assert!(
        run.report
            .diagnostics()
            .iter()
            .any(|d| d.field == "joined_corpus_sha256")
    );

    // A truncated digest is rejected too.
    let (a, mut b) = slices(&fixture);
    b.canonical_graph_sha256.truncate(63);
    let input = ManifestInput::from_b(&b);
    let run = integration::join(&ManifestInput::from_a(&a), &input, &a, &b);
    assert_eq!(run.subcase("FND-02-I-04").expect("I-04").outcome, Outcome::Fail);
}
