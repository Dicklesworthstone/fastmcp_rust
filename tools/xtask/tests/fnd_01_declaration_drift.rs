//! Detector for bd-dmnn6: FND-01's frozen policy must not drift from the tree
//! unnoticed.
//!
//! FND-01 has two halves and only one has rotted. Everything that BINDS —
//! 71 `source_input` digests, 163 `workspace_binding` paths, 27 member-scoped
//! dependency rules — is current and demonstrably maintained: 18 bound evidence
//! files changed after the 2026-07-30 freeze and every digest moved with them.
//! Everything that DECLARES the workspace envelope was frozen and never touched
//! again. Ten drifts were measured on 2026-09-19 and every one is a declaration.
//!
//! The two halves now contradict each other inside one file:
//! `probes/toolchain-2026-08-20.json` is bound and current while
//! `RUSTUP_TOOLCHAIN = "nightly-2026-07-11"` stands at 23 sites.
//!
//! WHY A DETECTOR RATHER THAN A FIX. Every drift arrived in an ordinary commit —
//! three release preparations and one feature addition — and no author had any
//! way to know they were invalidating an attestation. Re-attestation repairs the
//! current ten; only a check prevents the eleventh. The two are orthogonal and
//! this file is the second one.
//!
//! WHY IT LIVES IN `tools/xtask/tests/`. FND-01's
//! `closed_scan_roots = ["crates", ".github"]` fails on any unlisted regular file
//! beneath those roots and `exact_root_files` is a closed list, so adding this
//! detector under `crates/` would itself create a new FND-01 drift. `tools/xtask`
//! is a workspace member, so it still runs under `cargo test --workspace`.
//! (Same reasoning, and the same placement, as the bd-0a7ka detector.)
//!
//! NO-CLAIM BOUNDARY: passing means the policy's declarations still describe the
//! tree. It says nothing about whether FND-01's evidence is correct, whether the
//! verifier runs, or whether any capability is satisfied. It earns no credit.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Repository root, from this crate's manifest dir rather than the process CWD,
/// which a harness may change.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tools/xtask sits two levels below the repository root")
        .to_path_buf()
}

fn read(path: &str) -> String {
    let full = repo_root().join(path);
    std::fs::read_to_string(&full)
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", full.display()))
}

fn parse(path: &str) -> toml::Value {
    toml::from_str(&read(path)).unwrap_or_else(|e| panic!("{path} must parse as TOML: {e}"))
}

const POLICY: &str = "evidence/fnd-01/dependency-verification.toml";

/// The ten drifts measured on 2026-09-19, recorded on bd-dmnn6, against these
/// exact inputs:
///
///     Cargo.toml           blob 2cf86cc1e4178ad09c9bd8159942da97cd9e65a0
///     rust-toolchain.toml  blob e36bd453a98fc579be6afd951f5ef5b7cc170469
///
/// Bound by BLOB, not by revision. The measurement sha was 1a18f942, which is
/// already rebase-orphaned (twin aa09a123) barely an hour after it was written;
/// three of this bead's shas died the same way and only the blobs survived. A
/// commit sha is a changing name for fixed content, so a receipt that needs to
/// outlive a rebase names the content. The shas above are a convenience for a
/// reader who wants context, not the anchor.
///
/// Ten drifts render as NINE keys: the license VALUE drift ("MIT" -> gone) and the
/// license KEY drift (`license.workspace` -> `license-file.workspace`) are one
/// observation here, reported as `policy="MIT" tree="(key absent)"`.
///
/// This baseline is itself a frozen constant and will rot — which is the exact
/// defect this file exists to catch. So the test fails in BOTH directions: a new
/// drift is a regression, and a baselined drift that has been REPAIRED means this
/// list is stale and must be updated. A baseline that can only fail one way is
/// how the policy got here.
const KNOWN_DRIFTS: &[&str] = &[
    "workspace.package.version",
    "workspace.package.rust-version",
    "workspace.package.license",
    "toolchain.channel",
    "workspace.members.count",
    "dependency.asupersync",
    "dependency.flate2",
    "dependency.hmac",
    "dependency.sha2",
    "workspace.package.ids",
];

/// Collects every declaration mismatch between the policy and the tree.
/// The evaluator, pure and total: it reads nothing and decides only from the
/// three inputs it is handed.
///
/// RH-5: this was originally written to read the three files itself, which made
/// the two-way baseline claim UNTESTABLE — there was no way to hand it a tree
/// that drifts differently from the real one. A detector whose own failure modes
/// cannot be exercised is the shape this file exists to catch.
fn drifts_between(
    policy_src: &str,
    root: &toml::Value,
    toolchain: &toml::Value,
) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();

    // 1-3. [workspace.package] scalars the policy freezes by name.
    let wp = root
        .get("workspace")
        .and_then(|w| w.get("package"))
        .expect("root Cargo.toml must carry [workspace.package]");
    for (policy_key, tree_key) in [
        ("workspace_package_version", "version"),
        ("workspace_package_edition", "edition"),
        ("workspace_package_rust_version", "rust-version"),
        ("workspace_package_license", "license"),
    ] {
        let declared = scalar(policy_src, policy_key);
        let actual = wp
            .get(tree_key)
            .and_then(toml::Value::as_str)
            .map(str::to_owned);
        if let Some(declared) = declared {
            let actual = actual.unwrap_or_else(|| "(key absent)".to_owned());
            if declared != actual {
                out.insert(format!("workspace.package.{tree_key}"), (declared, actual));
            }
        }
    }

    // 4. The pinned toolchain the environment_profile requires.
    if let Some(declared) = policy_src
        .split("\"RUSTUP_TOOLCHAIN\", \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .map(str::to_owned)
    {
        let actual = toolchain
            .get("toolchain")
            .and_then(|t| t.get("channel"))
            .and_then(toml::Value::as_str)
            .unwrap_or("(absent)")
            .to_owned();
        if declared != actual {
            out.insert("toolchain.channel".to_owned(), (declared, actual));
        }
    }

    // 5. Member count. package_member_paths is the publishable-and-member set as
    //    frozen; [workspace].members is every member. They coincided at the freeze.
    let declared_members = policy_src
        .split("package_member_paths = [")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .map(|body| body.matches('"').count() / 2)
        .unwrap_or(0);
    let actual_members = root
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(toml::Value::as_array)
        .map_or(0, Vec::len);
    if declared_members != actual_members {
        out.insert(
            "workspace.members.count".to_owned(),
            (declared_members.to_string(), actual_members.to_string()),
        );
    }

    // 6. Root-scope dependency pins. `presence = "absent"` rows are prohibitions,
    //    where absence from the tree is compliance rather than drift.
    let deps = root
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(toml::Value::as_table);
    for block in policy_src.split("[[integration_dependency_rule]]").skip(1) {
        let block = block.split("\n[").next().unwrap_or(block);
        let field = |k: &str| scalar(block, k);
        if field("manifest_path").as_deref() != Some("Cargo.toml")
            || field("table_scope").as_deref() != Some("workspace.dependencies")
            || field("presence").as_deref() == Some("absent")
        {
            continue;
        }
        let (Some(name), Some(declared)) = (field("dependency"), field("version")) else {
            continue;
        };
        let actual = deps
            .and_then(|d| d.get(&name))
            .map(|v| match v {
                toml::Value::String(s) => s.clone(),
                other => other
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .unwrap_or("(inherited)")
                    .to_owned(),
            })
            .unwrap_or_else(|| "(absent)".to_owned());
        if declared.trim_start_matches('=') != actual.trim_start_matches('=') {
            out.insert(format!("dependency.{name}"), (declared, actual));
        }
    }

    // 7. workspace_package_ids: the policy's list of package NAMES, which is a
    //    separate key from package_member_paths and drifted the same way. It was
    //    unwatched until bd-a61ej: repairing package_member_paths alone would have
    //    left the policy internally inconsistent with this detector green.
    let declared_ids = policy_src
        .split("workspace_package_ids = [")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .map(|body| body.matches('"').count() / 2)
        .unwrap_or(0);
    let actual_ids = root
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(toml::Value::as_array)
        .map_or(0, Vec::len);
    if declared_ids != actual_ids {
        out.insert(
            "workspace.package.ids".to_owned(),
            (declared_ids.to_string(), actual_ids.to_string()),
        );
    }
    out
}

/// The real tree's drifts: the only place this file touches the filesystem.
fn observed_drifts() -> BTreeMap<String, (String, String)> {
    drifts_between(
        &read(POLICY),
        &parse("Cargo.toml"),
        &parse("rust-toolchain.toml"),
    )
}

/// Every `workspace_package_*` key this detector knows how to check.
///
/// bd-a61ej: the checks above resolve policy keys by LITERAL NAME, and `scalar`
/// returns None for an absent name, which SKIPS the comparison rather than
/// failing it. So a re-attestation that renames or adds a key would silently
/// narrow this file while its positive control kept passing on the other keys.
/// Asserting the key SET makes that fail loudly and separately from a value
/// drift. This does not change what the detector claims about any value; it
/// claims only that it still knows about every value.
const WATCHED_POLICY_KEYS: &[&str] = &[
    "workspace_package_edition",
    "workspace_package_ids",
    "workspace_package_license",
    "workspace_package_rust_version",
    "workspace_package_version",
];

/// Every `workspace_package_*` key the policy actually declares.
fn policy_package_keys() -> std::collections::BTreeSet<String> {
    let src = read(POLICY);
    let mut found = std::collections::BTreeSet::new();
    for line in src.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix("workspace_package_") else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || *c == '_')
            .collect();
        if !name.is_empty() && line[18 + name.len()..].trim_start().starts_with('=') {
            found.insert(format!("workspace_package_{name}"));
        }
    }
    found
}

/// First `key = "value"` in `src`, or None. Deliberately line-anchored: the
/// policy stores several keys whose names are prefixes of others.
fn scalar(src: &str, key: &str) -> Option<String> {
    src.lines()
        .map(str::trim)
        .find(|line| line.starts_with(key) && line[key.len()..].trim_start().starts_with('='))
        .and_then(|line| line.split('"').nth(1))
        .map(str::to_owned)
}

#[test]
fn fnd_01_policy_declarations_have_not_drifted_further() {
    let observed = observed_drifts();

    // POSITIVE CONTROL. The tree carries ten known drifts, so a run finding NONE
    // means this detector is not reading the policy, not that the tree is clean.
    // Without this, a broken parser and a repaired policy are indistinguishable.
    assert!(
        !observed.is_empty(),
        "detector found zero drifts; it should see the {} recorded on bd-dmnn6. \
         Either the policy was fully re-attested (update KNOWN_DRIFTS) or this \
         detector has stopped reading it.",
        KNOWN_DRIFTS.len()
    );

    let known: std::collections::BTreeSet<&str> = KNOWN_DRIFTS.iter().copied().collect();
    let seen: std::collections::BTreeSet<&str> = observed.keys().map(String::as_str).collect();

    let fresh: Vec<_> = seen.difference(&known).copied().collect();
    assert!(
        fresh.is_empty(),
        "NEW FND-01 declaration drift since bd-dmnn6 was measured:\n{}",
        fresh
            .iter()
            .map(|k| {
                let (p, t) = &observed[*k];
                format!("  {k}: policy={p:?} tree={t:?}")
            })
            .collect::<Vec<_>>()
            .join("\n")
    );

    let repaired: Vec<_> = known.difference(&seen).copied().collect();
    assert!(
        repaired.is_empty(),
        "these baselined drifts are REPAIRED, so KNOWN_DRIFTS is now stale and \
         must be shortened — a baseline that only fails one way is how FND-01 \
         reached ten:\n{}",
        repaired
            .iter()
            .map(|k| format!("  {k}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn fnd_01_detector_still_knows_every_policy_declaration_key() {
    let declared = policy_package_keys();
    let watched: std::collections::BTreeSet<String> = WATCHED_POLICY_KEYS
        .iter()
        .map(|k| (*k).to_owned())
        .collect();

    // POSITIVE CONTROL. The policy declares these keys today, so an empty read
    // means this test stopped parsing the policy — not that the policy is empty.
    assert!(
        !declared.is_empty(),
        "no workspace_package_* key found in {POLICY}; this test has stopped reading it"
    );

    let unwatched: Vec<_> = declared.difference(&watched).cloned().collect();
    assert!(
        unwatched.is_empty(),
        "the policy declares workspace_package_* keys this detector does not check, so their \
         values are unwatched and could drift silently — add a comparison for each, then add it \
         to WATCHED_POLICY_KEYS:\n{}",
        unwatched.join("\n  ")
    );

    let vanished: Vec<_> = watched.difference(&declared).cloned().collect();
    assert!(
        vanished.is_empty(),
        "this detector names workspace_package_* keys the policy no longer declares. A RENAME is \
         the likely cause, and a renamed key is skipped rather than failed by `scalar`, which is \
         exactly how this file would go silently narrow (bd-a61ej). Re-point the comparison at \
         the new name; do not simply delete the entry:\n{}",
        vanished.join("\n  ")
    );
}

/// Returns the real inputs with one `[workspace.package]` scalar overridden.
///
/// The mutation is applied to the PARSED tree rather than by string-editing the
/// manifest text, so it cannot accidentally hit a same-named key in another
/// table — `edition` and `version` both appear in more than one place.
fn root_with_package_scalar(key: &str, value: &str) -> toml::Value {
    let mut root = parse("Cargo.toml");
    root.get_mut("workspace")
        .and_then(|w| w.get_mut("package"))
        .and_then(toml::Value::as_table_mut)
        .expect("root Cargo.toml must carry [workspace.package]")
        .insert(key.to_owned(), toml::Value::String(value.to_owned()));
    root
}

#[test]
fn fnd_01_drift_detector_planted_negative() {
    let policy = read(POLICY);
    let toolchain = parse("rust-toolchain.toml");
    let known: std::collections::BTreeSet<&str> = KNOWN_DRIFTS.iter().copied().collect();

    // ARM 0 — the accepted row. Establishes that each arm's effect is
    // attributable to the one field it changes and to nothing else. Without
    // this, an evaluator that reported everything would pass every arm below.
    let accepted = drifts_between(&policy, &parse("Cargo.toml"), &toolchain);
    let accepted_keys: std::collections::BTreeSet<&str> =
        accepted.keys().map(String::as_str).collect();
    assert_eq!(
        accepted_keys, known,
        "the unmutated tree must observe exactly the baseline, or the arms below prove nothing"
    );

    // ARM A — PLANT A FRESH DRIFT. `edition` agrees today (policy and tree both
    // "2024") and is not in KNOWN_DRIFTS, so changing only it must make the
    // `fresh` set non-empty and name exactly that key. This is the direction a
    // one-way baseline would also catch.
    let arm_a = drifts_between(
        &policy,
        &root_with_package_scalar("edition", "2021"),
        &toolchain,
    );
    let fresh_a: Vec<&str> = arm_a
        .keys()
        .map(String::as_str)
        .filter(|k| !known.contains(k))
        .collect();
    assert_eq!(
        fresh_a,
        vec!["workspace.package.edition"],
        "planting one fresh drift must surface exactly that key"
    );
    assert_eq!(
        arm_a.len(),
        accepted.len() + 1,
        "arm A changes exactly one field and must add exactly one observation"
    );

    // ARM B — PLANT A REPAIR. This is the direction a ONE-WAY BASELINE CANNOT
    // SEE, and it is the whole reason the detector asserts `known - seen` is
    // empty. `workspace.package.version` is baselined as drifted (policy 0.3.2,
    // tree 0.10.0); setting the tree to the policy's value repairs it, and the
    // key must LEAVE the observed set so the staleness of KNOWN_DRIFTS is
    // forced into the open instead of passing silently.
    let declared_version =
        scalar(&policy, "workspace_package_version").expect("the policy declares a version");
    let arm_b = drifts_between(
        &policy,
        &root_with_package_scalar("version", &declared_version),
        &toolchain,
    );
    let repaired_b: Vec<&str> = known
        .iter()
        .copied()
        .filter(|k| !arm_b.contains_key(*k))
        .collect();
    assert_eq!(
        repaired_b,
        vec!["workspace.package.version"],
        "repairing one baselined drift must be detected as a stale baseline entry"
    );

    // ARM C — PLANT A TOOLCHAIN REPAIR. Arms A and B both mutate the ROOT
    // MANIFEST, so an evaluator that ignored its `toolchain` argument entirely
    // and read the real file would pass both. Mutation-testing the arms against
    // a deliberately broken evaluator found exactly that hole: `ignore_root`,
    // `stuck_baseline`, `drop_edition` and `drop_version` were each caught, and
    // `ignore_toolchain` was caught by nothing. This arm closes it by making one
    // arm depend on that parameter and nothing else.
    let declared_channel = policy
        .split("\"RUSTUP_TOOLCHAIN\", \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the policy declares a pinned toolchain");
    let repaired_toolchain =
        toml::from_str::<toml::Value>(&format!("[toolchain]\nchannel = \"{declared_channel}\"\n"))
            .expect("synthetic toolchain manifest parses");
    let arm_c = drifts_between(&policy, &parse("Cargo.toml"), &repaired_toolchain);
    let repaired_c: Vec<&str> = known
        .iter()
        .copied()
        .filter(|k| !arm_c.contains_key(*k))
        .collect();
    assert_eq!(
        repaired_c,
        vec!["toolchain.channel"],
        "an evaluator that ignores its toolchain input passes arms A and B; only this arm fails it"
    );

    // ARM 0 AGAIN — byte-for-byte, not merely still-non-empty. The evaluator is
    // pure, so this cannot fail; asserting it is what proves the arms above
    // mutated their inputs rather than any shared state.
    assert_eq!(
        drifts_between(&policy, &parse("Cargo.toml"), &toolchain),
        accepted,
        "the accepted observation must be unchanged after the planted arms"
    );
}
