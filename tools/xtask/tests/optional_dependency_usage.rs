//! Mechanical detector for `bd-s888g`: every `optional = true` dependency
//! declared in a workspace member's `[dependencies]` must be referenced by
//! non-test production source in that member (or explicitly baselined as a
//! pure feature-forwarding / test-fixture edge).
//!
//! WHY THIS DETECTOR EXISTS:
//! Before `bd-s888g`, `argon2 = "=0.6.0"` (in `fastmcp-server`) and
//! `html5ever = "=0.40.1"` (in `fastmcp-server` and `fastmcp-client`) compiled
//! into optional feature graphs (`builtin-auth-server`, `apps`) with ZERO call
//! sites anywhere in `src/`, silently creating dead dependency bloat and
//! giving readers a false impression that Argon2id KDF and HTML5 parsing were
//! wired.
//!
//! Lives in `tools/xtask/tests/` (outside FND-01's `closed_scan_roots = ["crates", ".github"]`)
//! so it runs unconditionally under `cargo test --workspace` with zero
//! `required-features`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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

fn workspace_members(root: &Path) -> Vec<String> {
    let parsed: toml::Value =
        toml::from_str(&read(&root.join("Cargo.toml"))).expect("root Cargo.toml must parse");
    parsed
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(toml::Value::as_array)
        .expect("root Cargo.toml must declare workspace.members")
        .iter()
        .filter_map(toml::Value::as_str)
        .map(str::to_owned)
        .collect()
}

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

/// Strip `#[cfg(...test...)]` blocks so a test-only reference cannot mask a
/// dead production optional dependency.
fn strip_cfg_test_blocks(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = chars;
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

/// Optional dependencies declared in a member's `[dependencies]` table,
/// returned as `(manifest_key, rust_crate_ident)`.
fn optional_dependencies(manifest_toml: &str) -> Vec<(String, String)> {
    let parsed: toml::Value = toml::from_str(manifest_toml).expect("member manifest parses");
    let Some(deps) = parsed.get("dependencies").and_then(toml::Value::as_table) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (key, value) in deps {
        let is_optional = value
            .as_table()
            .and_then(|table| table.get("optional"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        if is_optional {
            let ident = key.replace('-', "_");
            out.push((key.clone(), ident));
        }
    }
    out.sort();
    out
}

/// Whether non-test Rust source contains a crate-path reference to `ident`
/// (`ident::`, `use ident`, `extern crate ident`, or `ident!`).
fn source_references_crate(production_source: &str, ident: &str) -> bool {
    let needles = [
        format!("{ident}::"),
        format!("use {ident};"),
        format!("use {ident} as "),
        format!("extern crate {ident}"),
        format!("{ident}!"),
    ];
    for needle in &needles {
        let bytes = production_source.as_bytes();
        let mut from = 0usize;
        while let Some(pos) = production_source[from..].find(needle.as_str()) {
            let start = from + pos;
            let before_ok = start == 0 || {
                let c = bytes[start - 1];
                !c.is_ascii_alphanumeric() && c != b'_'
            };
            if before_ok {
                return true;
            }
            from = start + needle.len();
        }
    }
    false
}

/// Pure evaluator for a single member manifest + production `src/` texts.
fn unused_optional_deps_for_member(manifest_toml: &str, src_files: &[&str]) -> BTreeSet<String> {
    let stripped: Vec<String> = src_files
        .iter()
        .map(|src| strip_cfg_test_blocks(src))
        .collect();
    let mut unused = BTreeSet::new();
    for (dep_key, ident) in optional_dependencies(manifest_toml) {
        let used = stripped
            .iter()
            .any(|src| source_references_crate(src, &ident));
        if !used {
            unused.insert(dep_key);
        }
    }
    unused
}

/// The ONLY optional dependencies allowed to have zero `src/` references:
/// - `crates/fastmcp/fastmcp-console`: facade feature-equation forwarding edge
///   (`fastmcp-console/*` in `crates/fastmcp/Cargo.toml` + `trybuild_tests.rs`).
/// - `crates/fastmcp-cli/fastmcp-rust`: `e2e-fixture` test-target fixture edge.
/// - `crates/fastmcp-cli/fastmcp-server`: documented `jwt-resource-auth`
///   feature-forwarding edge tracked in `README.md`.
///
/// Checked two-way: if an exempted dependency gains a `src/` consumer or is
/// removed from `Cargo.toml`, the test fails loudly so this list cannot rot.
const EXEMPT_OPTIONAL_DEPS: &[(&str, &str)] = &[
    ("crates/fastmcp", "fastmcp-console"),
    ("crates/fastmcp-cli", "fastmcp-rust"),
    ("crates/fastmcp-cli", "fastmcp-server"),
];

#[test]
fn every_optional_dependency_is_consumed_by_production_source_or_explicitly_exempted() {
    let root = repo_root();
    let exempt: BTreeSet<(String, String)> = EXEMPT_OPTIONAL_DEPS
        .iter()
        .map(|(member, dep)| ((*member).to_owned(), (*dep).to_owned()))
        .collect();

    let mut total_optional_seen = 0usize;
    let mut unconsumed = BTreeSet::new();

    for member in workspace_members(&root) {
        let manifest_path = root.join(&member).join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let manifest = read(&manifest_path);
        let declared = optional_dependencies(&manifest);
        total_optional_seen += declared.len();

        let src_texts: Vec<String> = rust_sources(&root.join(&member).join("src"))
            .into_iter()
            .map(|path| read(&path))
            .collect();
        let src_refs: Vec<&str> = src_texts.iter().map(String::as_str).collect();

        for dep in unused_optional_deps_for_member(&manifest, &src_refs) {
            unconsumed.insert((member.clone(), dep));
        }
    }

    // Positive control: the workspace declares optional dependencies (argon2,
    // html5ever, ring, zeroize, etc.), so 0 means the parser broke.
    assert!(
        total_optional_seen >= 8,
        "expected >= 8 workspace optional dependencies, saw only {total_optional_seen}"
    );

    let unexpected: Vec<String> = unconsumed
        .difference(&exempt)
        .map(|(member, dep)| {
            format!("{member}: optional dependency `{dep}` has zero production src/ references")
        })
        .collect();
    assert!(
        unexpected.is_empty(),
        "dead optional dependencies detected (wire them into production src/ or remove them):\n  {}",
        unexpected.join("\n  ")
    );

    let stale_exemptions: Vec<String> = exempt
        .difference(&unconsumed)
        .map(|(member, dep)| format!("{member}/{dep}"))
        .collect();
    assert!(
        stale_exemptions.is_empty(),
        "EXEMPT_OPTIONAL_DEPS is stale (these entries are now used in src/ or removed from Cargo.toml):\n  {}",
        stale_exemptions.join("\n  ")
    );
}

#[test]
fn planted_dead_optional_dependency_is_detected_and_wired_dependency_passes() {
    let manifest = r#"
[package]
name = "synthetic-crate"
version = "0.1.0"

[dependencies]
phantom-crypto = { version = "=1.0.0", optional = true }
wired-parser = { version = "=2.0.0", optional = true }
"#;

    // Planted negative (RH-5): `phantom-crypto` is only referenced inside
    // `#[cfg(test)]` while `wired-parser` is called in production code.
    let src_with_dead_dep = r#"
pub fn parse(input: &str) -> usize {
    wired_parser::count(input)
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_in_tests() {
        let _ = phantom_crypto::hash(b"x");
    }
}
"#;
    assert_eq!(
        unused_optional_deps_for_member(manifest, &[src_with_dead_dep]),
        BTreeSet::from(["phantom-crypto".to_owned()]),
        "a test-only reference must NOT satisfy the production optional-dep gate"
    );

    // Near-identical positive: wiring `phantom_crypto` into production clears it.
    let src_both_wired = "
pub fn parse(input: &str) -> usize {
    let _ = phantom_crypto::hash(input.as_bytes());
    wired_parser::count(input)
}
";
    assert!(
        unused_optional_deps_for_member(manifest, &[src_both_wired]).is_empty(),
        "wiring both optional dependencies in production src/ must clear the finding"
    );
}
