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
];

/// Collects every declaration mismatch between the policy and the tree.
fn observed_drifts() -> BTreeMap<String, (String, String)> {
    let policy_src = read(POLICY);
    let root = parse("Cargo.toml");
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
        let declared = scalar(&policy_src, policy_key);
        let actual = wp.get(tree_key).and_then(toml::Value::as_str).map(str::to_owned);
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
        let actual = parse("rust-toolchain.toml")
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
    out
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
