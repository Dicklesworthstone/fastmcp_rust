//! Detector for bd-readme-mechanical-claim-gate-cqqbc: the README's
//! *mechanical* claims must not drift from the tree unnoticed.
//!
//! The README's behavioural claims are already gated. `crates/fastmcp/tests/
//! readme_examples.rs` compiles the README's code blocks from its exact text
//! and drives the resulting binaries over stdio, and bd-2kvu6 added a facade
//! test for the Troubleshooting/Limitations behavioural claims. What had no
//! gate is the class of claim that is a plain fact about the workspace: which
//! features gate code, which symbols exist, which test targets are vacuous.
//!
//! That class rots, and it rots silently, because a mechanical claim can be
//! falsified by a commit that never touches the README. Five doc-truth beads
//! have closed on README accuracy (bd-31al7, bd-qlwn3, bd-zb8ol, bd-2kvu6,
//! bd-8yw3e) and on 2026-10-05 three fresh defects were measured anyway:
//!
//!   1. `fastmcp-server/oauth-client-credentials` was listed as gating no
//!      server code. It gates 34 sites, including the `client_credentials` arm
//!      of the token endpoint and the advertised `grant_types_supported` list.
//!   2. The Limitations table named `Server::run_stdio`, which does not exist;
//!      the method is `run_stdio_with_cx`.
//!   3. The nine `oauth_*` targets were called vacuous 35 minutes after
//!      d0993fb0 gave all nine a `required-features` stanza, which is the
//!      opposite condition.
//!
//! WHY A DETECTOR RATHER THAN THREE EDITS. Fixing the prose closes this
//! instance, not the class. Every one of the three arrived in an ordinary
//! commit by an author with no way to know a README sentence had just become
//! false. Same reasoning, and the same placement, as the bd-dmnn6 and bd-0a7ka
//! detectors.
//!
//! WHY IT LIVES IN `tools/xtask/tests/`. FND-01's
//! `closed_scan_roots = ["crates", ".github"]` fails on any unlisted regular
//! file beneath those roots and `exact_root_files` is a closed list, so adding
//! this detector under `crates/` would itself create a new FND-01 drift.
//! `tools/xtask` is a workspace member, so it still runs under
//! `cargo test --workspace`, and unlike `readme_examples` it carries no
//! `required-features`, so it is not itself dark by default — which would
//! defeat the point of a gate against dark targets.
//!
//! NO-CLAIM BOUNDARY: passing means the README's mechanical claims still
//! describe the tree. It says nothing about whether the README's
//! *qualification* language is right, whether any capability works, or whether
//! any conformance claim holds. It earns no capability credit.

use std::collections::{BTreeMap, BTreeSet};
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

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()))
}

/// Every `.rs` file under `dir`, recursively. Returns an empty vector when the
/// directory is absent so a caller can distinguish "no matches" from a panic.
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// Every workspace-member `src/` file as (repository-relative path, contents),
/// read exactly once for the whole test binary.
///
/// This cache is not premature optimisation; it was measured. Without it the
/// five tree-reading checks each re-walked all member sources — 344 files and
/// roughly 25 MB — and because libtest runs them concurrently the target took
/// **128 s** instead of under 2 s. A gate that slow gets skipped or times out,
/// which would defeat its purpose, and the cost grows with the tree.
fn source_corpus() -> &'static [(String, String)] {
    static CORPUS: std::sync::OnceLock<Vec<(String, String)>> = std::sync::OnceLock::new();
    CORPUS.get_or_init(|| {
        let root = repo_root();
        let mut files = Vec::new();
        for member in workspace_members(&root) {
            for path in rust_sources(&root.join(&member).join("src")) {
                let relative = path
                    .strip_prefix(&root)
                    .expect("a member source sits under the repository root")
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push((relative, read(&path)));
            }
        }
        files.sort();
        files
    })
}

// ---------------------------------------------------------------------------
// Claim 1: features the README calls inert really do gate nothing.
// ---------------------------------------------------------------------------

/// Occurrences of `feature = "<feature>"` under one crate's `src/`.
///
/// Counting mentions rather than parsing `cfg` trees is deliberate: it
/// over-counts (a mention inside a doc comment counts) and never under-counts,
/// so a zero is a strong claim and that is the direction this check needs.
fn feature_mentions(krate: &str, feature: &str) -> usize {
    let needle = format!("feature = \"{feature}\"");
    let prefix = format!("crates/{krate}/src/");
    source_corpus()
        .iter()
        .filter(|(path, _)| path.starts_with(prefix.as_str()))
        .map(|(_, text)| text.matches(needle.as_str()).count())
        .sum()
}

/// `(crate, feature)` pairs the README's "Feature flags that gate nothing" row
/// asserts are inert. Measured 2026-10-05 at 99a3b4e8; every one was 0.
/// Re-measured 2026-10-12: all ten still 0, and `fastmcp-console`'s
/// `websocket-experimental` joined them. It was always inert and the README row
/// simply never named it, found by sweeping all 72 declared features across the
/// eight crates that declare any rather than by reading the row.
const README_INERT: &[(&str, &str)] = &[
    ("fastmcp-server", "enterprise-auth"),
    ("fastmcp-server", "websocket-experimental"),
    ("fastmcp-console", "enterprise-auth"),
    ("fastmcp-console", "oauth-client-credentials"),
    ("fastmcp-console", "builtin-auth-server"),
    ("fastmcp-console", "jwt-resource-auth"),
    ("fastmcp-console", "proxy"),
    ("fastmcp-console", "websocket-experimental"),
    ("fastmcp-transport", "websocket-experimental"),
    ("fastmcp-cli", "jwt-resource-auth"),
];

/// `(crate, feature)` pairs the same README row asserts DO gate code. Without
/// this direction the check is satisfiable by making everything inert, and the
/// defect it was written for was a false *inertness* claim.
const README_NOT_INERT: &[(&str, &str)] = &[
    ("fastmcp-server", "oauth-client-credentials"),
    ("fastmcp-server", "websocket"),
    ("fastmcp-server", "jwt-resource-auth"),
];

#[test]
fn readme_inert_feature_claims_hold() {
    let mut wrong = Vec::new();
    for (krate, feature) in README_INERT {
        let seen = feature_mentions(krate, feature);
        if seen != 0 {
            wrong.push(format!(
                "{krate}/{feature}: README says it gates nothing, found {seen} mention(s) in src/"
            ));
        }
    }
    for (krate, feature) in README_NOT_INERT {
        if feature_mentions(krate, feature) == 0 {
            wrong.push(format!(
                "{krate}/{feature}: README says it gates code, found 0 mentions in src/"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "README feature-inertness claims no longer describe the tree. Fix the \
         README row and this list together:\n  {}",
        wrong.join("\n  ")
    );
}

/// The README table row that enumerates features which gate nothing.
///
/// Returned as one string because the row is a single Markdown line.
fn readme_inert_row(readme: &str) -> &str {
    const HEADER: &str = "| **Feature flags that gate nothing** |";
    let row = readme
        .lines()
        .filter(|line| line.starts_with(HEADER))
        .collect::<Vec<_>>();
    assert_eq!(
        row.len(),
        1,
        "the README must carry exactly one \"Feature flags that gate nothing\" \
         row; found {}",
        row.len()
    );
    row[0]
}

/// `README_INERT` and the README row it models still agree.
///
/// Neither inert check above reads the README's prose: both compare the const
/// list against the tree. So the list and the row it claims to mirror could
/// drift apart silently, and the row's own instruction to "fix the README row
/// and this list together" was an unenforced comment. Half of exactly that
/// drift was real on 2026-10-12: `fastmcp-console/websocket-experimental` was
/// missing from BOTH, and fixing only one would have left no test failing.
///
/// NO-CLAIM: this binds feature NAMES, not crate-qualified pairs, because the
/// row names a feature once and then discusses several crates that share the
/// name. It therefore catches a feature dropped from the row, not a
/// mis-attributed crate.
#[test]
fn readme_inert_row_names_every_listed_feature() {
    let readme = read(&repo_root().join("README.md"));
    let row = readme_inert_row(&readme);

    let mut missing = Vec::new();
    for (krate, feature) in README_INERT {
        if !row.contains(&format!("`{feature}`")) {
            missing.push(format!("{krate}/{feature}"));
        }
    }
    assert!(
        missing.is_empty(),
        "README_INERT lists these features but the \"Feature flags that gate \
         nothing\" row does not name them, so the list and the prose have \
         drifted:\n  {}",
        missing.join("\n  ")
    );

    // Control: the needle must be able to fail. A row that matched everything
    // would make the loop above vacuous.
    assert!(
        !row.contains("`definitely-not-a-declared-feature`"),
        "the row matched a feature name that does not exist, so this check \
         cannot distinguish a named feature from an unnamed one"
    );
}

/// Planted negative for the row/list binding above.
///
/// `readme_inert_row_names_every_listed_feature` passing proves nothing unless
/// the same predicate detects an omission, so this runs it against a fabricated
/// row that names one listed feature and drops another.
#[test]
fn planted_inert_row_omission_is_detected() {
    let row = "| **Feature flags that gate nothing** | `fastmcp-console`'s \
               `proxy` is empty |";
    let omitted: Vec<&str> = ["proxy", "websocket-experimental"]
        .into_iter()
        .filter(|feature| !row.contains(&format!("`{feature}`")))
        .collect();
    assert_eq!(
        omitted,
        vec!["websocket-experimental"],
        "the binding must flag exactly the feature the planted row omits, and \
         must not flag the one it names"
    );
}

/// Occurrences of `feature = "<feature>"` under one workspace member's `src/`.
///
/// Keyed on the member PATH rather than a crate name, so a member outside
/// `crates/` (`tools/xtask`) is counted against its own sources instead of a
/// `crates/<name>/src/` prefix that does not exist and would silently return 0.
fn member_feature_mentions(member: &str, feature: &str) -> usize {
    let needle = format!("feature = \"{feature}\"");
    let prefix = format!("{member}/src/");
    source_corpus()
        .iter()
        .filter(|(path, _)| path.starts_with(prefix.as_str()))
        .map(|(_, text)| text.matches(needle.as_str()).count())
        .sum()
}

/// Declared features of one workspace member as `name -> value-count`.
///
/// Parsed with the `toml` crate, which is load-bearing rather than incidental.
/// A hand-rolled line parser for this exact table was written during the
/// 2026-10-12 sweep and was wrong twice: it skipped every multi-line
/// `name = [\n  ...\n]` definition (8 in `fastmcp-cli` alone, including the
/// `jwt-resource-auth` the README describes), and once that was fixed it leaked
/// `required-features` out of the `[[example]]` and `[[test]]` tables that
/// follow `[features]` in `fastmcp-console`. Both bugs silently changed which
/// features the sweep believed existed, and neither was visible in its output.
fn declared_features(root: &Path, member: &str) -> BTreeMap<String, usize> {
    let manifest = root.join(member).join("Cargo.toml");
    if !manifest.exists() {
        return BTreeMap::new();
    }
    let parsed: toml::Value =
        toml::from_str(&read(&manifest)).expect("a member manifest must parse as TOML");
    parsed
        .get("features")
        .and_then(toml::Value::as_table)
        .map(|table| {
            table
                .iter()
                .filter_map(|(name, value)| {
                    value.as_array().map(|values| (name.clone(), values.len()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Every inert feature in the tree is named by the README row that enumerates
/// them.
///
/// This is the OTHER direction from `readme_inert_feature_claims_hold`, and the
/// two catch disjoint defects. That check proves every feature the README calls
/// inert really is inert, which by construction cannot notice a NEW inert
/// feature the row fails to mention. That is precisely the defect found by hand
/// on 2026-10-12: `fastmcp-console/websocket-experimental` had always been `[]`
/// with zero `cfg` sites, and the row had simply never named it. A feature a
/// user can enable for no effect is a footgun, so the enumeration has to stay
/// complete, not merely truthful about its own entries.
///
/// `default` is excluded deliberately: `default = []` says a crate has no
/// default features, which is not a capability claim a user can be misled by.
#[test]
fn every_inert_feature_is_named_in_the_readme_inert_list() {
    let root = repo_root();
    let named: BTreeSet<(String, String)> = README_INERT
        .iter()
        .map(|(krate, feature)| ((*krate).to_owned(), (*feature).to_owned()))
        .collect();

    let mut inert = BTreeSet::new();
    let mut declared = 0usize;
    for member in workspace_members(&root) {
        let krate = member
            .rsplit('/')
            .next()
            .unwrap_or(member.as_str())
            .to_owned();
        for (feature, values) in declared_features(&root, &member) {
            declared += 1;
            if values != 0
                || feature == "default"
                || member_feature_mentions(&member, &feature) != 0
            {
                continue;
            }
            inert.insert((krate.clone(), feature));
        }
    }

    // Two controls, because an empty finding list is only evidence if the
    // instrument can see anything at all. Without the first a manifest-reading
    // break would pass as "no inert features"; without the second a classifier
    // that labelled everything non-inert would pass vacuously.
    assert!(
        declared > 0,
        "no declared features were read from any member manifest, so this check          proved nothing"
    );
    assert!(
        inert.contains(&(
            "fastmcp-transport".to_owned(),
            "websocket-experimental".to_owned()
        )),
        "the classifier no longer recognises fastmcp-transport/\
         websocket-experimental as inert, so its finding list is not evidence"
    );

    let unnamed: Vec<String> = inert
        .difference(&named)
        .map(|(krate, feature)| format!("{krate}/{feature}"))
        .collect();
    assert!(
        unnamed.is_empty(),
        "these features are inert — empty value list AND zero \
         `cfg(feature = ..)` sites in their own crate's `src/` — but the \
         README's \"Feature flags that gate nothing\" row does not name them. \
         Add each to that row AND to README_INERT:\n  {}",
        unnamed.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Claim 2: a feature-gated test target declares `required-features`.
// ---------------------------------------------------------------------------

/// Feature names appearing in a file-scope `#![cfg(..)]` attribute.
///
/// Only inner attributes in the file's leading attribute block count, because
/// those are the ones that empty the whole target. `#![cfg_attr(..)]` is not a
/// gate and is ignored; so is any `#[cfg(..)]` on an item further down.
fn file_scope_cfg_features(source: &str) -> BTreeSet<String> {
    let mut features = BTreeSet::new();
    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("#![cfg(") {
            let mut remainder = rest;
            while let Some(at) = remainder.find("feature = \"") {
                let tail = &remainder[at + "feature = \"".len()..];
                match tail.find('"') {
                    Some(end) => {
                        features.insert(tail[..end].to_owned());
                        remainder = &tail[end + 1..];
                    }
                    None => break,
                }
            }
            continue;
        }
        if line.starts_with("#![") || line.starts_with("#!") {
            continue;
        }
        // First line of real code: the leading attribute block is over.
        break;
    }
    features
}

/// `required-features` for each `[[test]]` target, keyed by its declared path.
fn declared_required_features(manifest: &str) -> BTreeMap<String, BTreeSet<String>> {
    let parsed: toml::Value = toml::from_str(manifest).expect("crate manifest must parse as TOML");
    let mut declared = BTreeMap::new();
    let Some(targets) = parsed.get("test").and_then(toml::Value::as_array) else {
        return declared;
    };
    for target in targets {
        let Some(path) = target.get("path").and_then(toml::Value::as_str) else {
            continue;
        };
        let features = target
            .get("required-features")
            .and_then(toml::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .map(str::to_owned)
                    .collect::<BTreeSet<String>>()
            })
            .unwrap_or_default();
        declared.insert(path.to_owned(), features);
    }
    declared
}

/// Workspace members that own `tests/` directories, read from the root manifest
/// rather than hard-coded, so a new member is covered the day it lands.
fn workspace_members(root: &Path) -> Vec<String> {
    let parsed: toml::Value =
        toml::from_str(&read(&root.join("Cargo.toml"))).expect("root manifest must parse as TOML");
    parsed
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .expect("the root manifest must declare workspace members")
        .iter()
        .filter_map(toml::Value::as_str)
        .map(str::to_owned)
        .collect()
}

#[test]
fn every_feature_gated_test_target_declares_required_features() {
    let root = repo_root();
    let mut wrong = Vec::new();
    for member in workspace_members(&root) {
        let member_dir = root.join(&member);
        let manifest_path = member_dir.join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let declared = declared_required_features(&read(&manifest_path));
        let tests_dir = member_dir.join("tests");
        for source_path in rust_sources(&tests_dir) {
            // Only a target root can be emptied by a file-scope cfg; a module
            // file included by one cannot be named in a `[[test]]` stanza.
            let is_target_root = source_path.parent() == Some(tests_dir.as_path())
                || source_path
                    .file_name()
                    .is_some_and(|name| name == "main.rs");
            if !is_target_root {
                continue;
            }
            let gated = file_scope_cfg_features(&read(&source_path));
            if gated.is_empty() {
                continue;
            }
            let relative = source_path
                .strip_prefix(&member_dir)
                .expect("test source sits under its member directory")
                .to_string_lossy()
                .replace('\\', "/");
            match declared.get(&relative) {
                None => wrong.push(format!(
                    "{member}/{relative}: file-scope cfg gates {gated:?} but no [[test]] \
                     stanza declares required-features, so an unsatisfying run prints \
                     `ok. 0 passed`"
                )),
                Some(stanza) if stanza != &gated => wrong.push(format!(
                    "{member}/{relative}: file-scope cfg gates {gated:?} but the stanza \
                     declares {stanza:?}; they must match exactly"
                )),
                Some(_) => {}
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "feature-gated test targets without a matching required-features stanza \
         compile to an empty binary and report a vacuous pass (bd-ufj6r):\n  {}",
        wrong.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Claim 3: a `Type::method` the README names in prose resolves.
// ---------------------------------------------------------------------------

/// Backticked `Type::method` paths, where `Type` is upper-camel and `method` is
/// snake_case. Associated constants and enum variants are upper-camel after the
/// `::` and are deliberately excluded.
fn readme_method_paths(readme: &str) -> BTreeSet<(String, String)> {
    let mut paths = BTreeSet::new();
    for span in readme.split('`').skip(1).step_by(2) {
        let Some((head, tail)) = span.rsplit_once("::") else {
            continue;
        };
        let ty = head.rsplit("::").next().unwrap_or(head);
        let method = tail.split('(').next().unwrap_or(tail);
        let type_ok = ty.starts_with(|c: char| c.is_ascii_uppercase())
            && ty.chars().all(|c| c.is_ascii_alphanumeric());
        let method_ok = !method.is_empty()
            && method.starts_with(|c: char| c.is_ascii_lowercase())
            && method
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if type_ok && method_ok {
            paths.insert((ty.to_owned(), method.to_owned()));
        }
    }
    paths
}

/// Whether `corpus` declares `<keyword> <name>` as a whole identifier.
///
/// The boundary check is load-bearing: a plain `contains("struct Budget")`
/// matches `struct BudgetProbeTool`, which made a re-exported dependency type
/// (`pub use asupersync::Budget`) look workspace-owned and produced a false
/// positive on `Budget::consume_poll`.
fn declares_item(corpus: &str, keyword: &str, name: &str) -> bool {
    let needle = format!("{keyword} {name}");
    let mut from = 0usize;
    while let Some(at) = corpus[from..].find(needle.as_str()) {
        let start = from + at;
        let after = start + needle.len();
        let boundary = corpus[after..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_');
        if boundary {
            return true;
        }
        from = after;
    }
    false
}

#[test]
fn readme_prose_names_only_methods_that_exist() {
    let root = repo_root();
    let readme = read(&root.join("README.md"));
    // Search the shared corpus file by file and short-circuit, rather than
    // concatenating 25 MB into one string per test run.
    let corpus = source_corpus();

    let mut missing = Vec::new();
    for (ty, method) in readme_method_paths(&readme) {
        // Only types this workspace defines are in scope. A path rooted in a
        // dependency (`Cx::current`, `RuntimeBuilder::current_thread`) is
        // skipped rather than guessed at, which keeps the check self-maintaining
        // as dependencies move.
        let defines_type = ["struct", "enum", "trait", "type"].iter().any(|keyword| {
            corpus
                .iter()
                .any(|(_, text)| declares_item(text, keyword, &ty))
        });
        if !defines_type {
            continue;
        }
        let needles = [format!("fn {method}("), format!("fn {method}<")];
        let defines_method = corpus
            .iter()
            .any(|(_, text)| needles.iter().any(|n| text.contains(n.as_str())));
        if !defines_method {
            missing.push(format!("{ty}::{method}"));
        }
    }
    assert!(
        missing.is_empty(),
        "README prose names these methods on workspace-defined types, and no \
         matching `fn` exists in any member's src/: {missing:?}"
    );
}

// ---------------------------------------------------------------------------
// Claim 4: the README's "ship with tests but no consumer" row stays true.
// ---------------------------------------------------------------------------

/// Whether `text` contains `token` as a whole identifier.
///
/// The boundary check on BOTH sides is load-bearing: a plain
/// `contains("HttpTransport")` also matches `StreamableHttpTransport`, which is
/// a live and unrelated type, and that would have made the consumer census
/// below report three extra files.
fn mentions_token(text: &str, token: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0usize;
    while let Some(at) = text[from..].find(token) {
        let start = from + at;
        let end = start + token.len();
        let before_ok = start == 0 || {
            let c = bytes[start - 1];
            !c.is_ascii_alphanumeric() && c != b'_'
        };
        let after_ok = end >= bytes.len() || {
            let c = bytes[end];
            !c.is_ascii_alphanumeric() && c != b'_'
        };
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// Member-relative paths of files under any member's `src/` that mention
/// `needle` as a whole identifier, excluding `owner`, which is the module's own
/// definition.
fn mentioning_sources(needle: &str, owner: &str) -> BTreeSet<String> {
    source_corpus()
        .iter()
        .filter(|(path, text)| path != owner && mentions_token(text, needle))
        .map(|(path, _)| path.clone())
        .collect()
}

/// `event_store` is documented as unclaimed library surface. Its only
/// references are the declaration and the facade re-export. A third site means
/// somebody started wiring it, and the README row plus the deliberate
/// `Last-Event-ID` refusal (http.rs, pinned by
/// `dual_era_endpoint_ignores_last_event_id_and_starts_a_fresh_legacy_stream`)
/// have to be revisited together with that change — regenerating around the
/// pinned test instead would be RH-3.
#[test]
fn event_store_is_still_unconsumed_as_the_readme_says() {
    let hits = mentioning_sources("event_store", "crates/fastmcp-transport/src/event_store.rs");
    let expected = BTreeSet::from([
        "crates/fastmcp-transport/src/lib.rs".to_owned(),
        "crates/fastmcp/src/lib.rs".to_owned(),
    ]);
    assert_eq!(
        hits, expected,
        "the set of files referencing `event_store` changed. If a real consumer \
         landed, update the README's \"Two modules ship with tests but no \
         consumer\" row and revisit the deliberate Last-Event-ID refusal in the \
         same change; do not just widen this list"
    );
}

/// `HttpTransport` is documented as unclaimed production surface whose only
/// out-of-crate consumer is a `#[cfg(test)]` fixture. If a *non-test* consumer
/// appears, the README row and the type's own doc comment both become wrong, so
/// this pins the consumer set rather than the mere count.
///
/// Unlike `event_store`, this type IS referenced from another crate, so the
/// assertion names the file instead of requiring emptiness. The point is that
/// the set cannot grow unnoticed.
#[test]
fn http_transport_has_no_shipped_consumer_as_the_readme_says() {
    let hits = mentioning_sources("HttpTransport", "crates/fastmcp-transport/src/http.rs");
    // `StreamableHttpTransport` and `ManagedHttpClient*` contain this substring
    // and are unrelated live types, so only exact-token files are expected.
    let expected = BTreeSet::from(["crates/fastmcp-server/src/auth.rs".to_owned()]);
    assert_eq!(
        hits, expected,
        "the set of files referencing `HttpTransport` changed. Its one expected \
         consumer is a #[cfg(test)] fixture in fastmcp-server's auth.rs. If a \
         shipped path now uses it, update the README's \"Two modules ship with \
         tests but no consumer\" row and the type's doc comment in the same \
         change; do not just widen this list"
    );
}

/// `#[test]` attributes in one repository-relative source file.
///
/// Counts attributes rather than running anything, which is the same quantity
/// the README row quotes and is stable without a build.
fn test_attribute_count(path: &str) -> usize {
    source_corpus()
        .iter()
        .find(|(candidate, _)| candidate == path)
        .map_or(0, |(_, text)| text.matches("#[test]").count())
}

/// The unclaimed-surface row's three test counts still match the tree.
///
/// The two checks above deliberately pin the CONSUMER SET "rather than the
/// mere count", so the numbers themselves were ungated — and they had already
/// drifted once: the row said 168 for `http.rs` and 213 for the total when the
/// tree held 167 and 212, which was corrected by hand on 2026-10-12 with
/// nothing to catch it. This pins all three so the next drift fails here.
///
/// The total is checked as a sum rather than independently, because a row that
/// quotes two parts and a whole can be internally inconsistent as well as
/// stale.
#[test]
fn readme_unclaimed_surface_test_counts_match_the_tree() {
    let readme = read(&repo_root().join("README.md"));
    const HEADER: &str = "| **Two modules ship with tests but no consumer** |";
    let row = readme
        .lines()
        .find(|line| line.starts_with(HEADER))
        .expect("the README must carry the unclaimed-surface row");

    let event_store = test_attribute_count("crates/fastmcp-transport/src/event_store.rs");
    let http = test_attribute_count("crates/fastmcp-transport/src/http.rs");

    // Control: a zero would make every claim below vacuously checkable against
    // a row that happens to say zero, and signals the corpus lookup broke.
    assert!(
        event_store > 0 && http > 0,
        "counted {event_store} and {http} tests; a zero means the corpus \
         lookup stopped finding these files, not that the tests vanished"
    );

    let mut wrong = Vec::new();
    for (label, phrase) in [
        ("event_store", format!("{event_store} tests")),
        ("http", format!("{http} tests")),
        ("total", format!("{} green tests", event_store + http)),
    ] {
        if !row.contains(phrase.as_str()) {
            wrong.push(format!("{label}: row does not say {phrase:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "the unclaimed-surface row's test counts no longer match the tree \
         (event_store {event_store}, http {http}, total {}). Fix the row:\n  {}",
        event_store + http,
        wrong.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// RH-5: each check above must actually fire. These feed the same pure
// functions a mutated input and require the defect to be detected, so a
// refactor that silently neuters a check cannot stay green.
// ---------------------------------------------------------------------------

/// Planted negative for the unclaimed-surface count gate.
///
/// Uses the exact drift that really happened: the row said 168 and 213 while
/// the tree held 167 and 212. The predicate must flag the two stale numbers and
/// must NOT flag the one that was correct, so it discriminates rather than
/// failing on everything.
#[test]
fn planted_unclaimed_surface_count_drift_is_detected() {
    let stale_row = "| **Two modules ship with tests but no consumer** | \
                     event_store (45 tests) ... HttpTransport (168 tests) ... \
                     but 213 green tests exercise code |";
    let (event_store, http) = (45usize, 167usize);
    let flagged: Vec<&str> = [
        ("event_store", format!("{event_store} tests")),
        ("http", format!("{http} tests")),
        ("total", format!("{} green tests", event_store + http)),
    ]
    .iter()
    .filter(|(_, phrase)| !stale_row.contains(phrase.as_str()))
    .map(|(label, _)| *label)
    .collect();
    assert_eq!(
        flagged,
        vec!["http", "total"],
        "the count gate must flag exactly the two numbers that drifted and \
         leave the correct one alone"
    );
}

#[test]
fn planted_file_scope_cfg_is_detected_and_an_item_cfg_is_not() {
    let gated = file_scope_cfg_features(
        "//! doc\n#![cfg(all(target_os = \"linux\", feature = \"tasks\"))]\n\nuse std::fs;\n",
    );
    assert_eq!(
        gated,
        BTreeSet::from(["tasks".to_owned()]),
        "the feature half of a mixed file-scope gate must be extracted"
    );

    let two = file_scope_cfg_features(
        "#![cfg(any(feature = \"apps\", feature = \"renderers\"))]\nfn main() {}\n",
    );
    assert_eq!(
        two,
        BTreeSet::from(["apps".to_owned(), "renderers".to_owned()]),
        "every feature in an any(..) gate must be extracted"
    );

    // Near-identical negatives: the same text in positions that do NOT empty a
    // target must not be reported, or the check would demand stanzas for files
    // that need none.
    assert!(
        file_scope_cfg_features("#![cfg_attr(windows, feature(windows_by_handle))]\nfn a() {}\n")
            .is_empty(),
        "cfg_attr is not a gate"
    );
    assert!(
        file_scope_cfg_features("fn a() {}\n#[cfg(feature = \"tasks\")]\nfn b() {}\n").is_empty(),
        "an item-level cfg below the leading attribute block is not a file-scope gate"
    );
    assert!(
        file_scope_cfg_features("#![forbid(unsafe_code)]\nfn a() {}\n").is_empty(),
        "an unrelated inner attribute is not a gate"
    );
}

#[test]
fn planted_missing_stanza_is_detected() {
    let with = declared_required_features(
        "[[test]]\nname = \"t\"\npath = \"tests/t.rs\"\nrequired-features = [\"tasks\"]\n",
    );
    assert_eq!(
        with.get("tests/t.rs"),
        Some(&BTreeSet::from(["tasks".to_owned()]))
    );

    // The planted negative differs only in the stanza's presence.
    let without = declared_required_features("[[test]]\nname = \"t\"\npath = \"tests/t.rs\"\n");
    assert_eq!(
        without.get("tests/t.rs"),
        Some(&BTreeSet::new()),
        "a declared target with no required-features must read as an empty set, \
         which cannot equal a non-empty file-scope gate"
    );
    assert_eq!(
        declared_required_features("[package]\nname = \"x\"\n").get("tests/t.rs"),
        None,
        "an undeclared target must be absent, not an empty set"
    );
}

#[test]
fn planted_readme_method_extraction_is_selective() {
    let found = readme_method_paths(
        "prose `Server::run_stdio` and `ServerBuilder::final_tasks` and \
         `ProtocolPolicy::Auto` and `fastmcp_transport::websocket` and \
         `Client::close()` here",
    );
    assert!(found.contains(&("Server".to_owned(), "run_stdio".to_owned())));
    assert!(found.contains(&("ServerBuilder".to_owned(), "final_tasks".to_owned())));
    assert!(
        found.contains(&("Client".to_owned(), "close".to_owned())),
        "a trailing call suffix must be stripped, not rejected"
    );
    assert!(
        !found.iter().any(|(_, method)| method == "Auto"),
        "an upper-camel associated item is a variant or constant, not a method"
    );
    assert!(
        !found.iter().any(|(ty, _)| ty == "fastmcp_transport"),
        "a module path is not a type path"
    );
    assert!(
        readme_method_paths("unbackticked Server::run_stdio must not be collected").is_empty(),
        "only backticked spans count"
    );
}

#[test]
fn planted_token_match_excludes_a_longer_identifier() {
    // The positive.
    assert!(mentions_token(
        "use crate::http::HttpTransport;",
        "HttpTransport"
    ));
    assert!(mentions_token(
        "let t: HttpTransport<R, W>",
        "HttpTransport"
    ));
    assert!(mentions_token("pub mod event_store;", "event_store"));
    assert!(mentions_token(
        "fastmcp_transport::event_store::EventStore",
        "event_store"
    ));

    // The planted negative, differing only by surrounding identifier chars.
    // This exact case would have added three files to the HttpTransport census.
    assert!(
        !mentions_token(
            "impl Transport for StreamableHttpTransport {",
            "HttpTransport"
        ),
        "a longer identifier ENDING with the token must not match"
    );
    assert!(
        !mentions_token("let x = HttpTransportBuilder::new();", "HttpTransport"),
        "a longer identifier STARTING with the token must not match"
    );
    assert!(
        !mentions_token("my_event_store_helper()", "event_store"),
        "same, for a snake_case token embedded in a longer one"
    );
}

#[test]
fn planted_consumer_census_distinguishes_owner_from_consumer() {
    // The owner file is excluded, so naming a file that does mention the needle
    // as the owner must drop it from the set.
    let with_owner_excluded =
        mentioning_sources("event_store", "crates/fastmcp-transport/src/lib.rs");
    assert!(
        !with_owner_excluded.contains("crates/fastmcp-transport/src/lib.rs"),
        "the owner exclusion must apply to whatever path is passed"
    );
    assert!(
        with_owner_excluded.contains("crates/fastmcp-transport/src/event_store.rs"),
        "a file that was previously the owner must appear once it is not excluded, \
         or the census is measuring the wrong thing"
    );
    // A needle no source mentions must produce an empty set rather than a
    // silently-passing match, which is how a census goes vacuous.
    assert!(
        mentioning_sources("ThisIdentifierAppearsInNoSource", "nowhere.rs").is_empty(),
        "an absent needle must yield no hits"
    );
}

#[test]
fn planted_item_declaration_requires_an_identifier_boundary() {
    // The positive.
    assert!(declares_item(
        "pub struct Budget { poll: u64 }",
        "struct",
        "Budget"
    ));
    assert!(declares_item("enum Selection {", "enum", "Selection"));
    assert!(declares_item("pub struct Tool;", "struct", "Tool"));
    assert!(declares_item("struct Wrapper<T>(T);", "struct", "Wrapper"));

    // The planted negative, differing only in a trailing identifier character.
    // This exact case produced a false positive: `Budget` is
    // `pub use asupersync::Budget`, and the only in-tree match was
    // `struct BudgetProbeTool` in fastmcp-server's router tests.
    assert!(
        !declares_item("struct BudgetProbeTool {", "struct", "Budget"),
        "a longer identifier with the same prefix must not count as a declaration"
    );
    assert!(
        !declares_item("struct Tooling {", "struct", "Tool"),
        "same, for a name that is a prefix of another"
    );
    assert!(
        !declares_item("pub use asupersync::Budget;", "struct", "Budget"),
        "a re-export is not a declaration"
    );
}

// ---------------------------------------------------------------------------
// Claim 6: the README's "DPoP has no consumer" row stays true.
//
// WHY THIS ROW AND NOT ITS NUMBERS. The row quoted "781 lines with 18 public
// items and 9 in-module tests" on 2026-10-12. Two days later the module was 9
// files, 6,699 lines, 61 public items and 84 tests — roughly 8.6x the lines —
// and nothing caught it, because the existing checks gate which features are
// inert and which symbols exist, not the size of a module under construction.
//
// WHAT THE ZERO MEANS, corrected 2026-10-14. This check first existed to
// detect a gap being closed. Reading the module header shows the opposite: it
// is an EXPLICIT, caller-driven API whose documentation promises it "never
// promotes a DPoP token into the existing bearer-only OAuth driver" and "does
// not install automatic OAuth negotiation or HTTP retries". The intended
// consumer is the application, so zero in-workspace callers is the design.
// The check is kept and its meaning inverted: it now fails if the library
// starts driving DPoP itself, which is the promise worth protecting. Either
// way the README row must be rewritten when it fires.
//
// Pinning the size would be the wrong repair. That module is being actively
// built, so an exact-count gate would redden on every ordinary commit to it,
// and a gate that reddens on ordinary growth is a gate somebody switches off.
// What the row actually ASSERTS, and what a reader acts on, is the structural
// claim: this implementation has no caller. That is stable until someone wires
// it, and when they do the row must be rewritten — so the zero is exactly the
// right thing to gate, and this check is designed to fail at that moment.
//
// NO-CLAIM: a passing result means no workspace member source names the module
// outside its own tree. It says nothing about whether the DPoP code is correct,
// whether it would work if wired, or whether wiring it would satisfy RFC 9449.
// ---------------------------------------------------------------------------

/// The two module trees that ARE the DPoP implementation. Mentions inside them
/// are the module talking about itself, not a consumer.
const DPOP_MODULE_PREFIXES: &[&str] = &[
    "crates/fastmcp-client/src/http_auth/dpop",
    "crates/fastmcp-protocol/src/dpop.rs",
];

/// The `pub mod dpop;` lines that put the two modules in the build. A module
/// declaration is not a consumer: it is what makes the code compile at all,
/// and the README row says so in the sentence about `ac00c6ad`.
const DPOP_DECLARATIONS: &[(&str, &str)] = &[
    ("crates/fastmcp-client/src/http_auth.rs", "pub mod dpop;"),
    ("crates/fastmcp-protocol/src/lib.rs", "pub mod dpop;"),
];

/// Does this line reference the DPoP module from outside it?
///
/// The needle is the LOWERCASE `dpop`, case-sensitively, because that is the
/// module path. Rust spells the path `dpop` while every piece of prose and
/// every wire value spells it `DPoP`, so case alone separates a code reference
/// from a doc comment or a string literal — including
/// `("token_type", json!("DPoP"))` in `client_credentials.rs`, which is a test
/// fixture REJECTING a sender-constrained token and must not read as a caller.
/// A case-insensitive needle matched five files; this one matches two, and both
/// are the declarations above.
fn is_dpop_consumer_line(line: &str) -> bool {
    line.contains("dpop")
        && !DPOP_DECLARATIONS
            .iter()
            .any(|(_, decl)| line.trim() == *decl)
}

/// `(path, line number, text)` for every DPoP reference outside the module.
fn dpop_consumer_sites() -> Vec<(String, usize, String)> {
    source_corpus()
        .iter()
        .filter(|(path, _)| {
            !DPOP_MODULE_PREFIXES
                .iter()
                .any(|prefix| path.starts_with(prefix))
        })
        .flat_map(|(path, text)| {
            text.lines()
                .enumerate()
                .filter(|(_, line)| is_dpop_consumer_line(line))
                .map(move |(index, line)| (path.clone(), index + 1, line.trim().to_owned()))
        })
        .collect()
}

#[test]
fn readme_dpop_row_still_has_no_consumer() {
    let readme = read(&repo_root().join("README.md"));
    assert!(
        readme.contains("It has no in-workspace consumer"),
        "this gate pins a README claim; if the row no longer makes it, retire \
         the gate with the row rather than leaving it asserting nothing"
    );

    // Control: the corpus must actually contain the module, or the zero below
    // would be the sound of a broken lookup rather than an absent consumer.
    //
    // This counts FILES and requires only a nonzero mention count, rather than
    // a mention threshold. A threshold would be the very failure this gate's
    // header warns about: the module is 6,699 lines but only 59 of its lines
    // carry the lowercase path spelling, because internally it says `DPoP` in
    // prose and uses bare type names, so any figure near 59 would redden on
    // ordinary refactoring.
    let (files, mentions) = source_corpus()
        .iter()
        .filter(|(path, _)| {
            DPOP_MODULE_PREFIXES
                .iter()
                .any(|prefix| path.starts_with(prefix))
        })
        .fold((0usize, 0usize), |(files, mentions), (_, text)| {
            (files + 1, mentions + text.matches("dpop").count())
        });
    assert!(
        files >= 2 && mentions > 0,
        "the corpus holds {files} DPoP module file(s) with {mentions} \
         lowercase `dpop` mention(s); both modules must be present and \
         self-referencing, or the zero below is a broken lookup"
    );

    // Control: both declarations must still be present and still be the thing
    // the exemption describes. If one is renamed the exemption would start
    // hiding a real reference of the same shape.
    for (path, declaration) in DPOP_DECLARATIONS {
        let (_, text) = source_corpus()
            .iter()
            .find(|(candidate, _)| candidate == path)
            .unwrap_or_else(|| panic!("{path} must be in the member source corpus"));
        assert!(
            text.lines().any(|line| line.trim() == *declaration),
            "{path} no longer carries `{declaration}`, so the declaration \
             exemption no longer describes what it exempts"
        );
    }

    let consumers = dpop_consumer_sites();
    assert!(
        consumers.is_empty(),
        "the README says the DPoP module still has no consumer, but {} \
         reference(s) now exist outside it. If DPoP has been wired, that is \
         good news and this row must be rewritten to describe it:\n{}",
        consumers.len(),
        consumers
            .iter()
            .map(|(path, line, text)| format!("  {path}:{line}  {text}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Planted negative for the DPoP consumer gate.
///
/// Feeds the predicate the four shapes that must NOT count — both module
/// declarations, a doc comment, and the `"DPoP"` string literal from the
/// client-credentials rejection test — beside the two shapes that must, a
/// `use` import and a call. Without this the empty result above would be
/// consistent with a predicate that matches nothing at all.
#[test]
fn planted_dpop_consumer_is_detected_and_a_declaration_is_not() {
    for benign in [
        "pub mod dpop;",
        "    pub mod dpop;",
        "/// Explicit DPoP proof, credential, and nonce handling.",
        "//! pinning, or OIDC identity authentication is installed",
        "            (\"token_type\", json!(\"DPoP\")),",
    ] {
        assert!(
            !is_dpop_consumer_line(benign),
            "must not count as a consumer: {benign:?}"
        );
    }

    for wiring in [
        "use crate::http_auth::dpop::DpopSession;",
        "        let proof = dpop::sign(&credential, &request)?;",
        "use crate::http_auth::dpop;",
        "pub use crate::http_auth::dpop::DpopCredential;",
    ] {
        assert!(
            is_dpop_consumer_line(wiring),
            "must count as a consumer: {wiring:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Claim 7: the README's HTTPS hard-gate census matches the tree.
//
// This row feeds an open owner decision (the client-mode conformance
// loopback question), so a wrong number there is worse than a wrong number
// elsewhere: it prices a decision somebody is being asked to take. The row
// previously read "32 production HTTPS hard-gates across 19 files" and then
// named 18 of them. Running the same instrument at the row's own authoring
// commit and at HEAD returns 22 across 17 BOTH times, so the figure was wrong
// when written rather than stale, and nothing caught it for a day.
//
// WHAT IS COUNTED, and why this is the honest unit. An exemption has to be
// threaded through each INDEPENDENT refusal, and through the two central
// helpers in `discovery.rs` once each -- but not through the thirteen call
// sites that merely invoke those helpers, which inherit the decision. So the
// enforcement-point count is exactly the number of inline
// `scheme() != "https"` / `starts_with("https://")` refusals, which includes
// the two helper bodies and excludes their callers. No classification of
// imports or call sites is needed, which keeps this check mechanical.
//
// NO-CLAIM: this counts refusal SITES in production source. It says nothing
// about whether each one is reachable, whether the set is complete (a refusal
// spelled another way would not be seen), or whether the exemption is a good
// idea.
// ---------------------------------------------------------------------------

/// Blank out every `#[cfg(...test...)]`-attributed item block, preserving byte
/// length so nothing downstream shifts.
///
/// WHAT IT DOES AND DOES NOT CATCH, measured 2026-10-14 rather than assumed.
/// It takes the next `{` within 400 bytes that no `;` precedes, so it handles
/// an attributed `mod`, `fn`, `struct`, `enum`, `impl` or `trait` -- verified
/// on a synthetic `#[cfg(test)] #[derive(Debug)] pub struct Gone { .. }`,
/// which is stripped while its neighbours survive. It does NOT remove doc
/// comments or `impl` bodies that merely NAME a gated type from outside the
/// gate, so a mention count over the stripped text is an upper bound on
/// production use rather than an exact one.
///
/// That imprecision does not reach the census below: the enforcement count is
/// IDENTICAL (22 across 17) under this stripper and under a stricter one that
/// also requires an item keyword, checked over all of
/// `crates/fastmcp-client/src`. Left as is for that reason -- a "more correct"
/// stripper whose own correctness is harder to establish would put a pinned
/// number at risk for no measured gain.
///
/// The predicate is any cfg whose text contains a bare `test` token, not the
/// literal `#[cfg(test)]` alone. The narrow form missed
/// `#[cfg(all(test, feature = "legacy-2024-11-05"))]`, which guards a test
/// module in `http_executor.rs`, so a census using it called that module
/// production code.
fn strip_cfg_test_blocks(text: &str) -> String {
    let bytes: Vec<char> = text.chars().collect();
    let mut out = bytes.clone();
    let mut index = 0usize;
    while let Some(found) = text[index..].find("#[cfg(") {
        let start = index + found;
        let Some(close) = text[start..].find(")]") else {
            break;
        };
        let attribute = &text[start..start + close + 2];
        index = start + close + 2;
        if !attribute
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|token| token == "test")
        {
            continue;
        }
        // Find the item's opening brace, refusing to scan far enough to
        // swallow an unrelated block if this attribute sits on a `use` or a
        // field rather than a module or function.
        let tail = &text[index..];
        let Some(brace) = tail.find('{') else {
            continue;
        };
        if brace > 400 || tail[..brace].contains(';') {
            continue;
        }
        let open = index + brace;
        let mut depth = 0i32;
        let mut cursor = open;
        for (offset, character) in text[open..].char_indices() {
            if character == '{' {
                depth += 1;
            } else if character == '}' {
                depth -= 1;
                if depth == 0 {
                    cursor = open + offset;
                    break;
                }
            }
        }
        let from = text[..start].chars().count();
        let to = text[..=cursor.min(text.len() - 1)].chars().count();
        for slot in out.iter_mut().take(to).skip(from) {
            if *slot != '\n' {
                *slot = ' ';
            }
        }
        index = cursor + 1;
    }
    out.into_iter().collect()
}

/// Inline HTTPS refusals per repository-relative file under
/// `crates/fastmcp-client/src`, production code only.
fn https_enforcement_sites() -> BTreeMap<String, usize> {
    const PREFIX: &str = "crates/fastmcp-client/src/";
    let mut per_file = BTreeMap::new();
    for (path, text) in source_corpus() {
        if !path.starts_with(PREFIX) {
            continue;
        }
        let production = strip_cfg_test_blocks(text);
        let count = production.matches("scheme() != \"https\"").count()
            + production.matches("starts_with(\"https://\")").count();
        if count > 0 {
            per_file.insert(path.clone(), count);
        }
    }
    per_file
}

#[test]
fn readme_https_gate_census_matches_the_tree() {
    let per_file = https_enforcement_sites();
    let sites: usize = per_file.values().sum();
    let files = per_file.len();

    // Control: a zero would satisfy no README text but would also mean the
    // corpus lookup or the stripper ate everything, so say so loudly.
    assert!(
        sites > 0 && files > 0,
        "counted {sites} refusals across {files} files; a zero means the \
         fastmcp-client corpus lookup or the cfg(test) stripper is broken"
    );

    let readme = read(&repo_root().join("README.md"));
    let claim = format!("**{sites} production HTTPS enforcement points");
    let files_claim = format!("across {files} files**");
    assert!(
        readme.contains(claim.as_str()) && readme.contains(files_claim.as_str()),
        "the README's HTTPS census no longer matches the tree: the census \
         finds {sites} enforcement points across {files} files. This row \
         prices an open owner decision, so fix the row rather than this \
         check.\nper file: {per_file:#?}"
    );
}

/// Planted negative for the HTTPS census gate.
///
/// Uses the drift that really happened -- a row claiming 32 across 19 against
/// a tree holding 22 across 17 -- and requires the predicate to reject it
/// while accepting the corrected text. Without this, the green above would be
/// consistent with a check that accepts any README at all.
#[test]
fn planted_https_census_drift_is_detected() {
    let accepts = |row: &str, sites: usize, files: usize| {
        row.contains(format!("**{sites} production HTTPS enforcement points").as_str())
            && row.contains(format!("across {files} files**").as_str())
    };

    let wrong = "finds **32 production HTTPS hard-gates across 19 files** — \
                 `validate_https` and `https_url` in `discovery.rs`";
    let right = "finds **22 production HTTPS enforcement points\n  across 17 files**: 20 \
                 independent `scheme() != \"https\"`";

    assert!(
        !accepts(wrong, 22, 17),
        "the row as it was actually written must be rejected against a 22/17 tree"
    );
    assert!(
        accepts(right, 22, 17),
        "the corrected row must be accepted against a 22/17 tree"
    );
    // And it must discriminate on each number independently, not merely on
    // the whole string differing.
    assert!(
        !accepts(right, 23, 17),
        "a one-off site count must be rejected"
    );
    assert!(
        !accepts(right, 22, 18),
        "a one-off file count must be rejected"
    );
}

#[test]
fn planted_cfg_test_stripper_handles_a_compound_predicate() {
    // The exact shape the narrow `#[cfg(test)]` needle missed.
    let source = "fn keep() { let a = url.scheme() != \"https\"; }\n\
                  #[cfg(all(test, feature = \"legacy-2024-11-05\"))]\n\
                  mod gone {\n    fn inner() { let b = x.scheme() != \"https\"; }\n}\n\
                  fn also_keep() { let c = y.starts_with(\"https://\"); }\n";
    let stripped = strip_cfg_test_blocks(source);
    assert_eq!(
        stripped.matches("scheme() != \"https\"").count(),
        1,
        "the production refusal survives and the cfg(all(test, ..)) one does not: {stripped}"
    );
    assert_eq!(
        stripped.matches("starts_with(\"https://\")").count(),
        1,
        "a refusal after the stripped block must survive: {stripped}"
    );
    assert_eq!(
        stripped.len(),
        source.len(),
        "the stripper preserves length so line numbers stay true"
    );
}
