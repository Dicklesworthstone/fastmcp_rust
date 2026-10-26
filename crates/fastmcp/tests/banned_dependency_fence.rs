//! bd-rh11-no-live-banned-dep-gate-1eyve: the banned-dependency list, enforced
//! against the LIVE workspace lock from inside the default test gate.
//!
//! AGENTS.md states the architectural invariant in its strongest terms --
//! "Tokio and the entire tokio ecosystem are FORBIDDEN" -- and names the
//! forbidden crates. RH-11 says "verification mechanically enforces the banned
//! dependency and runtime lists". It does, in exactly one place:
//! `fnd_01_dependency_evidence.rs` walks `receipt.target_graphs` and refuses any
//! node whose name is in `banned_package_ids`. That is a better instrument than
//! this one, because it is target- and feature-RESOLVED. But its subject is a
//! receipt the FND-01 harness produced rather than the workspace as it stands;
//! its target is gated behind `required-features = ["testing-lab"]`; the
//! manifest stanza declaring it says in its own words "This binary is not part
//! of the default product test gate"; and the contract it validates is frozen on
//! nightly-2026-07-11 while the workspace pins nightly-2026-08-25. Four
//! default-gate targets read `Cargo.lock` and all four check something else --
//! asupersync's pin, the `test-internals` feature, shipped `block_on` counts, a
//! trybuild fixture. So nothing in the path every batch verification runs would
//! notice `hyper = "1"` appearing in a workspace manifest tomorrow.
//!
//! This file is the live guard beside that frozen attestation. It does not
//! replace it and is strictly weaker than it: **a lockfile is target- and
//! feature-blind.** It cannot tell a dependency that compiles from one that is
//! merely resolvable, which is exactly why the exception register below pins
//! reverse-dependency SHAPE instead of trusting a name.
//!
//! WHY A NAME-ONLY GATE WOULD BE RED ON ARRIVAL, and that matters more than it
//! sounds. `tokio` IS in this workspace's lock today, at 1.53.2, and it is not a
//! violation: its only reverse dependency is `wasm-bindgen-futures`, which
//! `asupersync` declares under `[target.'cfg(target_arch = "wasm32")'
//! .dependencies]`. It is therefore compiled for no target this project builds,
//! and it arrives through the mandated runtime's own wasm dependency rather than
//! through anything this project could remove. A `grep tokio Cargo.lock` gate
//! would be permanently red for a non-defect, which is the condition most likely
//! to get a mandated gate switched off again.
//!
//! So an exception names a package AND the exact chain of reverse-dependency
//! sets that made it admissible. If anything other than `wasm-bindgen-futures`
//! starts depending on `tokio`, or anything other than `asupersync` starts
//! depending on `wasm-bindgen-futures`, the reviewed shape no longer holds and
//! this gate fires -- even though the package name has not changed.
//!
//! THE LIST IS NOT RESTATED HERE. It is read from
//! `evidence/fnd-01/dependency-verification.toml`, so this gate and the policy
//! cannot drift into two authorities, and a missing or unparseable row FAILS
//! CLOSED rather than yielding an empty banned set and a quiet pass. The one
//! thing this file does assert about the policy is that it still covers every
//! crate AGENTS.md itself forbids by name: narrowing the policy row to make
//! something pass is the RH-1 shape pointed at a dependency ban, and it would
//! otherwise be invisible.
//!
//! NO CAPABILITY CREDIT IS CLAIMED. This is proof integrity, not product. Its
//! consumer is the workspace test gate; its enforced property is the
//! banned-dependency list; its observed defect class is the absence of any live
//! check for it; its retirement condition is a re-attested FND-01 receipt
//! validated inside the default gate, at which point the stronger
//! target-resolved check subsumes this one and this file should be deleted.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const POLICY_PATH: &str = "evidence/fnd-01/dependency-verification.toml";
const POLICY_ROW_KEY: &str = "banned_package_ids";
const LOCK_PATH: &str = "Cargo.lock";

/// The crates AGENTS.md forbids by name, under "Forbidden crates". The policy
/// row must cover every one of them; it may ban more.
const AGENTS_MD_FORBIDDEN: [&str; 7] = [
    "tokio",
    "hyper",
    "reqwest",
    "axum",
    "tower",
    "async-std",
    "smol",
];

const NO_EXCEPTION: &str = "present in the workspace lock with no reviewed exception";
const SHAPE_CHANGED: &str =
    "present under a reverse-dependency shape that differs from the reviewed exception";

/// A banned package admitted only while the reviewed chain still holds.
struct Exception {
    package: &'static str,
    /// Ordered rungs upward from the banned package. Each names a package and
    /// the EXACT set of packages permitted to depend on it.
    rungs: &'static [(&'static str, &'static [&'static str])],
    justification: &'static str,
}

/// Reviewed 2026-10-25 against Cargo.lock at HEAD `122a914e`, 417 packages.
///
/// A row is an EXPIRING exception. If the edge disappears -- a wasm-free
/// asupersync, or a `wasm-bindgen-futures` that no longer depends on `tokio` --
/// `the_reviewed_exception_holds_on_the_live_lock` turns red so the row is
/// deleted rather than left as a hole a real arrival could fall into.
const EXCEPTIONS: [Exception; 1] = [Exception {
    package: "tokio",
    rungs: &[
        ("tokio", &["wasm-bindgen-futures"]),
        ("wasm-bindgen-futures", &["asupersync"]),
    ],
    justification: "asupersync 0.5.0 declares [target.'cfg(target_arch = \"wasm32\")'.dependencies.wasm-bindgen-futures], so the edge is compiled only for wasm32, which this project does not build; it arrives through the mandated runtime's own wasm dependency and is not within this project's power to remove",
}];

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Not a package in the lock at all.
    Absent,
    /// Present, and the reviewed reverse-dependency chain still holds exactly.
    AdmittedByException,
    Refused(&'static str),
}

/// Package names present in the lock, and who depends on each name.
///
/// `present` is keyed by NAME, which is what a name-based ban judges, so it is
/// smaller than `rows`: a lock holds one row per name-and-version, and 23 names
/// appear twice in this workspace's lock (417 rows, 392 names, measured
/// 2026-10-25). Both counts are reported because labelling one with the other's
/// figure is how a reader concludes the parser dropped 25 packages.
struct Graph {
    rows: usize,
    present: BTreeSet<String>,
    reverse: BTreeMap<String, BTreeSet<String>>,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root exists above crates/fastmcp")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    let root = workspace_root();
    fs::read_to_string(root.join(relative))
        .unwrap_or_else(|error| panic!("{relative} is readable: {error}"))
}

/// Contents of the first double-quoted run in `text`.
fn quoted(text: &str) -> Option<&str> {
    let start = text.find('"')? + 1;
    let rest = text.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end)
}

/// The banned set, read from the policy rather than restated. `None` is a
/// refusal, never an empty set: a gate that cannot read its list must not pass.
fn banned_ids(policy_text: &str) -> Option<BTreeSet<String>> {
    let row = policy_text.lines().find(|line| {
        line.trim_start()
            .strip_prefix(POLICY_ROW_KEY)
            .is_some_and(|rest| rest.trim_start().starts_with('='))
    })?;
    let open = row.find('[')?;
    let close = row.rfind(']')?;
    if close <= open {
        return None;
    }
    let mut ids = BTreeSet::new();
    for piece in row.get(open + 1..close)?.split(',') {
        if piece.trim().is_empty() {
            continue; // a legal trailing comma, not an unreadable element
        }
        let value = quoted(piece)?;
        if value.is_empty() {
            return None;
        }
        ids.insert(value.to_owned());
    }
    if ids.is_empty() { None } else { Some(ids) }
}

/// `(name, dependency names)` for every `[[package]]` block in a Cargo lock.
/// A dependency entry may be `"name"`, `"name version"` or
/// `"name version (source)"`; only the name is taken.
fn lock_packages(lock_text: &str) -> Vec<(String, Vec<String>)> {
    let mut packages = Vec::new();
    let mut name: Option<String> = None;
    let mut deps: Vec<String> = Vec::new();
    let mut in_deps = false;
    for line in lock_text.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            let collected = std::mem::take(&mut deps);
            if let Some(previous) = name.take() {
                packages.push((previous, collected));
            }
            in_deps = false;
            continue;
        }
        if in_deps {
            if trimmed == "]" {
                in_deps = false;
            } else if let Some(entry) = quoted(trimmed) {
                if let Some(first) = entry.split_whitespace().next() {
                    deps.push(first.to_owned());
                }
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("name = ") {
            if let Some(value) = quoted(rest) {
                name = Some(value.to_owned());
            }
            continue;
        }
        if trimmed == "dependencies = [" {
            in_deps = true;
        }
    }
    if let Some(last) = name {
        packages.push((last, deps));
    }
    packages
}

fn graph(lock_text: &str) -> Graph {
    let mut present = BTreeSet::new();
    let mut reverse: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let parsed = lock_packages(lock_text);
    let rows = parsed.len();
    for (name, deps) in parsed {
        for dep in deps {
            reverse.entry(dep).or_default().insert(name.clone());
        }
        present.insert(name);
    }
    Graph {
        rows,
        present,
        reverse,
    }
}

fn exception_for(package: &str) -> Option<&'static Exception> {
    EXCEPTIONS.iter().find(|entry| entry.package == package)
}

fn judge(package: &str, graph: &Graph) -> Verdict {
    if !graph.present.contains(package) {
        return Verdict::Absent;
    }
    let Some(exception) = exception_for(package) else {
        return Verdict::Refused(NO_EXCEPTION);
    };
    for (child, allowed) in exception.rungs {
        let reviewed: BTreeSet<&str> = allowed.iter().copied().collect();
        let observed: BTreeSet<&str> = graph
            .reverse
            .get(*child)
            .map(|set| set.iter().map(String::as_str).collect())
            .unwrap_or_default();
        if observed != reviewed {
            return Verdict::Refused(SHAPE_CHANGED);
        }
    }
    Verdict::AdmittedByException
}

/// Every refusal the live pair of artifacts produces, sorted so a failure reads
/// the same way twice.
fn refusals(banned: &BTreeSet<String>, graph: &Graph) -> Vec<String> {
    let mut out = Vec::new();
    for package in banned {
        if let Verdict::Refused(clause) = judge(package, graph) {
            let depended_on_by: Vec<&str> = graph
                .reverse
                .get(package)
                .map(|set| set.iter().map(String::as_str).collect())
                .unwrap_or_default();
            out.push(format!(
                "{package} -- {clause}; depended on by {depended_on_by:?}"
            ));
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// The live gate
// ---------------------------------------------------------------------------

#[test]
fn the_workspace_lock_admits_no_banned_package_outside_a_reviewed_exception() {
    let policy_text = read(POLICY_PATH);
    let banned = banned_ids(&policy_text).unwrap_or_else(|| {
        panic!("{POLICY_PATH} must carry a readable `{POLICY_ROW_KEY}` row; a gate that cannot read its list must not pass")
    });
    let lock = graph(&read(LOCK_PATH));
    println!(
        "{} banned ids read from {POLICY_PATH}; {LOCK_PATH} holds {} rows over {} distinct package names",
        banned.len(),
        lock.rows,
        lock.present.len()
    );
    for package in &banned {
        println!("  {package:14} {:?}", judge(package, &lock));
    }
    let refused = refusals(&banned, &lock);
    assert!(
        refused.is_empty(),
        "{} banned package(s) are in the workspace lock without a reviewed exception.\n\
         A dependency on a forbidden runtime is an RH-11 violation; if the arrival is a\n\
         target-gated edge that compiles for no target this project builds, add an EXCEPTIONS\n\
         row pinning its reverse-dependency chain and say in the justification why it is\n\
         inert. Do not widen the policy row.\n{}",
        refused.len(),
        refused.join("\n")
    );
}

/// RH-1 pointed at a dependency ban: the cheapest way to make this gate pass is
/// to delete a name from the policy row, and nothing else would notice.
#[test]
fn the_policy_row_still_covers_every_crate_agents_md_forbids_by_name() {
    let policy_text = read(POLICY_PATH);
    let banned = banned_ids(&policy_text).expect("the policy row is readable");
    let missing: Vec<&str> = AGENTS_MD_FORBIDDEN
        .iter()
        .copied()
        .filter(|name| !banned.contains(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "{POLICY_ROW_KEY} no longer bans {missing:?}, which AGENTS.md forbids by name under \
         \"Forbidden crates\". Narrowing the list is not a way to pass this gate."
    );
}

/// Positive control on the live tree, and the retirement condition for the
/// register: the one reviewed exception must still describe the real lock.
#[test]
fn the_reviewed_exception_holds_on_the_live_lock() {
    let lock = graph(&read(LOCK_PATH));
    for exception in &EXCEPTIONS {
        assert!(
            lock.present.contains(exception.package),
            "{} is no longer in {LOCK_PATH}: DELETE its EXCEPTIONS row rather than leaving an \
             exception a later real arrival could fall into",
            exception.package
        );
        assert_eq!(
            judge(exception.package, &lock),
            Verdict::AdmittedByException,
            "{} is in the lock under a shape the reviewed exception does not describe. Its \
             justification was: {}",
            exception.package,
            exception.justification
        );
        println!(
            "exception holds: {} via {:?}",
            exception.package, exception.rungs
        );
    }
}

// ---------------------------------------------------------------------------
// Instrument: positive and near-identical planted negatives
// ---------------------------------------------------------------------------

/// A minimal lock in Cargo's own emitted shape.
fn synthetic_lock(entries: &[(&str, &[&str])]) -> String {
    let mut text = String::from("version = 4\n");
    for (name, deps) in entries {
        text.push_str("\n[[package]]\n");
        text.push_str(&format!("name = \"{name}\"\nversion = \"1.0.0\"\n"));
        text.push_str("source = \"registry+https://github.com/rust-lang/crates.io-index\"\n");
        if !deps.is_empty() {
            text.push_str("dependencies = [\n");
            for dep in *deps {
                text.push_str(&format!(" \"{dep}\",\n"));
            }
            text.push_str("]\n");
        }
    }
    text
}

#[test]
fn the_lock_parser_reads_names_and_dependency_entry_forms() {
    let text = synthetic_lock(&[
        ("fastmcp-core", &["asupersync"]),
        (
            "asupersync",
            &["wasm-bindgen-futures 0.4.79 (registry+https://x)"],
        ),
        ("wasm-bindgen-futures", &["tokio 1.53.2"]),
        ("tokio", &[]),
    ]);
    let lock = graph(&text);
    assert_eq!(lock.present.len(), 4, "saw {:?}", lock.present);
    assert!(lock.present.contains("tokio"));
    // The version and source suffixes must not become part of the name.
    assert_eq!(
        lock.reverse.get("tokio").map(BTreeSet::len),
        Some(1),
        "reverse: {:?}",
        lock.reverse
    );
    assert!(
        lock.reverse["tokio"].contains("wasm-bindgen-futures"),
        "reverse: {:?}",
        lock.reverse
    );
    assert!(lock.reverse["wasm-bindgen-futures"].contains("asupersync"));
}

/// The reviewed shape, reproduced synthetically: admitted.
#[test]
fn the_reviewed_shape_is_admitted_in_a_synthetic_lock() {
    let lock = graph(&synthetic_lock(&[
        ("asupersync", &["wasm-bindgen-futures"]),
        ("wasm-bindgen-futures", &["tokio"]),
        ("tokio", &[]),
    ]));
    assert_eq!(judge("tokio", &lock), Verdict::AdmittedByException);
}

/// The planted negative for the test above: the SAME banned package, one edge
/// different -- a second crate depends on it -- so the reviewed shape no longer
/// holds and the exception must not carry.
#[test]
fn the_exception_does_not_carry_to_a_different_reverse_dependency_shape() {
    let lock = graph(&synthetic_lock(&[
        ("asupersync", &["wasm-bindgen-futures"]),
        ("wasm-bindgen-futures", &["tokio"]),
        ("fastmcp-server", &["tokio"]),
        ("tokio", &[]),
    ]));
    assert_eq!(judge("tokio", &lock), Verdict::Refused(SHAPE_CHANGED));

    // And one rung up: the intermediary acquiring a second consumer also breaks
    // the chain, because that is how a wasm-only edge stops being wasm-only.
    let moved = graph(&synthetic_lock(&[
        ("asupersync", &["wasm-bindgen-futures"]),
        ("fastmcp-transport", &["wasm-bindgen-futures"]),
        ("wasm-bindgen-futures", &["tokio"]),
        ("tokio", &[]),
    ]));
    assert_eq!(judge("tokio", &moved), Verdict::Refused(SHAPE_CHANGED));
}

#[test]
fn a_banned_package_with_no_reviewed_exception_is_refused() {
    let lock = graph(&synthetic_lock(&[
        ("fastmcp-server", &["hyper"]),
        ("hyper", &[]),
    ]));
    assert_eq!(judge("hyper", &lock), Verdict::Refused(NO_EXCEPTION));
    assert_eq!(judge("axum", &lock), Verdict::Absent);

    let banned: BTreeSet<String> = ["hyper", "axum"].iter().map(|s| (*s).to_owned()).collect();
    let refused = refusals(&banned, &lock);
    assert_eq!(refused.len(), 1, "got {refused:?}");
    assert!(refused[0].starts_with("hyper -- "), "got {refused:?}");
    assert!(
        refused[0].contains("fastmcp-server"),
        "a refusal must name who depends on it, got {refused:?}"
    );
}

#[test]
fn the_fence_fails_closed_on_a_policy_row_it_cannot_read() {
    for text in [
        "",
        "banned_package_ids\n",
        "banned_package_ids = \n",
        "banned_package_ids = []\n",
        "banned_package_ids = [tokio]\n",
        "banned_package_ids = [\"\"]\n",
        "banned_package_idsx = [\"tokio\"]\n",
        "other = [\"tokio\"]\n",
    ] {
        assert_eq!(
            banned_ids(text),
            None,
            "{text:?} must fail closed rather than yield a banned set"
        );
    }
    // The readable forms, including a legal trailing comma.
    let one = banned_ids("banned_package_ids = [\"tokio\"]\n").expect("readable");
    assert_eq!(one.len(), 1);
    let two =
        banned_ids("  banned_package_ids  =  [\"tokio\", \"hyper\",]  # note\n").expect("readable");
    assert_eq!(two.len(), 2);
    assert!(two.contains("hyper"));
}
