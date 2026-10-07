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
const README_INERT: &[(&str, &str)] = &[
    ("fastmcp-server", "enterprise-auth"),
    ("fastmcp-server", "jwt-resource-auth"),
    ("fastmcp-server", "websocket-experimental"),
    ("fastmcp-console", "enterprise-auth"),
    ("fastmcp-console", "oauth-client-credentials"),
    ("fastmcp-console", "builtin-auth-server"),
    ("fastmcp-console", "jwt-resource-auth"),
    ("fastmcp-console", "proxy"),
    ("fastmcp-transport", "websocket-experimental"),
    ("fastmcp-cli", "jwt-resource-auth"),
];

/// `(crate, feature)` pairs the same README row asserts DO gate code. Without
/// this direction the check is satisfiable by making everything inert, and the
/// defect it was written for was a false *inertness* claim.
const README_NOT_INERT: &[(&str, &str)] = &[
    ("fastmcp-server", "oauth-client-credentials"),
    ("fastmcp-server", "websocket"),
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

// ---------------------------------------------------------------------------
// RH-5: each check above must actually fire. These feed the same pure
// functions a mutated input and require the defect to be detected, so a
// refactor that silently neuters a check cannot stay green.
// ---------------------------------------------------------------------------

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
