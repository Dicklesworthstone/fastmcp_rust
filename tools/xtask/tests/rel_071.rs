//! REL-071: the published-release binding relation, positive and planted negative.
//!
//! These tests drive the same public entrypoint any caller drives
//! (`rel_071::evaluate`). There is no test-only evaluator path: the positive
//! runs against the recorded observation fixture as committed, and the negative
//! runs against an in-memory copy of that same fixture with exactly one member
//! changed.
//!
//! SCOPE LIMIT, carried here so no receipt citing these tests overstates them:
//! this pair is a **regression guard on the binding relation**. It proves the
//! members of a recorded observation set agree with one another and that a
//! perturbed or missing observation is refused. It does **not** re-establish
//! the observations, and it cannot detect a registry that served something
//! false. It is not a provider audit.
//!
//! Frozen IDs: `rel_071_positive`, `rel_071_planted_negative`.

use std::fs;
use std::path::{Path, PathBuf};

use fastmcp_xtask::rel_071::{self, Code, Observations};

/// Fixture path, repository-relative.
const OBSERVATIONS_PATH: &str = "evidence/rel-071/observations-0.7.1.json";

/// The repository root, derived from this crate's manifest directory rather
/// than from the process working directory, which a test harness may change.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tools/xtask sits two levels below the repository root")
        .to_path_buf()
}

/// Loads the committed observation fixture.
fn load() -> Observations {
    let path = repo_root().join(OBSERVATIONS_PATH);
    let bytes = fs::read(&path)
        .unwrap_or_else(|error| panic!("fixture {} must be readable: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("fixture {} must parse: {error}", path.display()))
}

/// Flips one hexadecimal character, producing a different well-formed digest.
fn flip_one_hex_char(digest: &str) -> String {
    let mut chars: Vec<char> = digest.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == '0' { '1' } else { '0' };
    chars.into_iter().collect()
}

#[test]
fn rel_071_positive() {
    let observations = load();

    // The record describes the version this pair is frozen against. A fixture
    // swapped for another version would otherwise pass silently.
    assert_eq!(observations.version, "0.7.1");
    assert_eq!(observations.required_file_count, 77);

    // The four lawful categories are BOUND, not merely mentioned. Workflow runs
    // and environments are permanent RULE 0.5 exclusions and are deliberately
    // absent from this record; they are not pending work.
    assert_eq!(
        observations.release.tag, "v0.7.1",
        "category: repository tag"
    );
    assert_eq!(
        observations.release.required_asset_count, 16,
        "category: GitHub release/assets"
    );
    assert_eq!(
        observations.credential_presence.required_entry_count, 4,
        "category: credential-presence metadata"
    );
    // The anchor is what keeps the digest columns from being the release
    // restating its own manifest.
    assert!(
        observations
            .release
            .assets
            .iter()
            .any(|asset| asset.name == observations.release.anchored_asset
                && asset.independently_verified),
        "one asset must be independently recomputed"
    );

    let disposition = rel_071::evaluate(&observations);

    assert!(
        disposition.admitted(),
        "the committed observation record must bind:\n{}",
        disposition.render()
    );

    // required == discovered == inspected == dispositioned, stated as an
    // equality over the numbers rather than asserted in prose.
    let required = observations.required_file_count;
    let discovered = observations.files.len();
    let rel_071::Disposition::Admitted { inspected } = disposition else {
        unreachable!("admitted above");
    };
    assert_eq!(required, discovered, "required == discovered");
    assert_eq!(discovered, inspected, "discovered == inspected");
    assert_eq!(inspected, 77, "inspected == dispositioned == 77");
}

#[test]
fn rel_071_planted_negative() {
    // ARM 0 — the accepted row. Establishes that every refusal below is
    // attributable to the one member each arm changes, and to nothing else.
    // Without this, an evaluator that refused everything would pass this test.
    let accepted = load();
    let accepted_disposition = rel_071::evaluate(&accepted);
    assert!(
        accepted_disposition.admitted(),
        "the unmutated record must be admitted, or the arms below prove nothing:\n{}",
        accepted_disposition.render()
    );

    // ARM A — "changes only one provider object identity/digest/state".
    // One hexadecimal character of the advertised digest, nothing else.
    let mut arm_a = load();
    arm_a.advertised_sha256 = flip_one_hex_char(&arm_a.advertised_sha256);
    assert_ne!(
        arm_a.advertised_sha256, accepted.advertised_sha256,
        "the mutation must actually change the record"
    );
    assert_eq!(
        arm_a.files.len(),
        accepted.files.len(),
        "arm A changes exactly one field and no observations"
    );
    let refused_a = rel_071::evaluate(&arm_a);
    assert!(
        !refused_a.admitted(),
        "a divergent advertised digest must not be admitted"
    );
    assert_eq!(
        refused_a.codes(),
        vec![Code::ArchiveDigestMismatch],
        "exactly the typed diagnostic for that field, and nothing else:\n{}",
        refused_a.render()
    );

    // ARM B — "removes one required observation". One file row, nothing else.
    let mut arm_b = load();
    let dropped = arm_b.files.remove(0);
    assert_eq!(
        arm_b.files.len() + 1,
        accepted.files.len(),
        "arm B removes exactly one observation"
    );
    assert_eq!(
        arm_b.required_file_count, accepted.required_file_count,
        "the declared requirement is untouched; only the observation is gone"
    );
    let refused_b = rel_071::evaluate(&arm_b);
    assert!(
        !refused_b.admitted(),
        "a missing required observation must not be admitted: dropped {}",
        dropped.path
    );
    assert_eq!(
        refused_b.codes(),
        vec![Code::ObservationMissing],
        "exactly the typed diagnostic for a gap, and nothing else:\n{}",
        refused_b.render()
    );

    // ARM C — a divergence between the two sides of one binding. This is the
    // defect the whole record exists to detect: an archive file whose bytes do
    // not match the tree blob it claims to come from.
    let mut arm_c = load();
    arm_c.files[0].tree_sha256 = flip_one_hex_char(&arm_c.files[0].tree_sha256);
    let refused_c = rel_071::evaluate(&arm_c);
    assert!(
        !refused_c.admitted(),
        "a divergent file must not be admitted"
    );
    assert_eq!(
        refused_c.codes(),
        vec![Code::FileDivergence],
        "exactly the typed diagnostic for a divergent file, and nothing else:\n{}",
        refused_c.render()
    );

    // ARM D — one release asset removed. Same "removes one required
    // observation" arm, over the release/assets category.
    let mut arm_d = load();
    let dropped_asset = arm_d.release.assets.remove(0);
    let refused_d = rel_071::evaluate(&arm_d);
    assert_eq!(
        refused_d.codes(),
        vec![Code::ReleaseAssetMissing],
        "dropping asset {} must refuse for exactly that reason:\n{}",
        dropped_asset.name,
        refused_d.render()
    );

    // ARM E — the anchor withdrawn. Without an independently recomputed digest
    // the release's digest columns are only the release restating itself, and
    // the evaluator must say so rather than admitting a self-witnessing record.
    let mut arm_e = load();
    for asset in &mut arm_e.release.assets {
        asset.independently_verified = false;
    }
    let refused_e = rel_071::evaluate(&arm_e);
    assert_eq!(
        refused_e.codes(),
        vec![Code::NoAnchoredAsset],
        "an unanchored record must be refused:\n{}",
        refused_e.render()
    );

    // ARM F — a credential VALUE planted where only presence belongs. The
    // record must refuse to carry it, so that a fixture which starts leaking
    // fails loudly instead of being published.
    let mut arm_f = load();
    arm_f.credential_presence.entries[2].detail =
        Some("gho_EXAMPLENOTAREALTOKENVALUE0000000000".to_owned());
    let refused_f = rel_071::evaluate(&arm_f);
    assert_eq!(
        refused_f.codes(),
        vec![Code::CredentialValueDisclosed],
        "a credential value must be refused, not recorded:\n{}",
        refused_f.render()
    );

    // ARM G — the commit field emptied. Equality alone would admit this: two
    // empty strings compare equal. Only the shape gate catches it.
    let mut arm_g = load();
    arm_g.vcs_sha1 = String::new();
    arm_g.tag_commit = String::new();
    assert_eq!(
        arm_g.vcs_sha1, arm_g.tag_commit,
        "the two fields are still EQUAL; only their shape is wrong"
    );
    let refused_g = rel_071::evaluate(&arm_g);
    assert_eq!(
        refused_g.codes(),
        vec![Code::MalformedCommit],
        "equal-but-malformed commits must be refused:\n{}",
        refused_g.render()
    );

    // The accepted row is re-evaluated last and must still be admitted, and its
    // disposition must be BYTE-FOR-BYTE what arm 0 produced — not merely
    // admitted. A disposition that changed while staying admitted would
    // otherwise pass unnoticed.
    assert_eq!(
        rel_071::evaluate(&accepted),
        accepted_disposition,
        "the accepted disposition must be unchanged after the planted arms"
    );
}
