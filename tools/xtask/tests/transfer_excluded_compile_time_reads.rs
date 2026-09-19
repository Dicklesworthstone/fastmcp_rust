//! Detector for bd-0a7ka: nothing that compiles remotely may read, at COMPILE TIME,
//! a path the transfer layer excludes.
//!
//! `include_bytes!`/`include_str!` resolve during compilation, so a file the remote
//! build worker never receives makes the target UNBUILDABLE there. The dangerous part
//! is the symptom: a test target that fails to build can report `0 passed` rather than
//! failing, so the failure mode is a VOID GREEN that reads as success.
//!
//! Observed twice in one crate four days apart — `tests/oauth_core_rpc.rs` (fixed by
//! inlining, 2026-09-16) and `.../drive/tests/live.rs:24` (bd-l3iku, 2026-09-19). The
//! first fix was applied at the site and wrote down the class; the class stayed open.
//!
//! THIS FILE LIVES IN `tools/xtask/tests/` DELIBERATELY. FND-01's
//! `closed_scan_roots = ["crates", ".github"]` fails on any unlisted regular file
//! beneath those roots, and `exact_root_files` is a closed list, so a new file in
//! either place would break the evidence freeze. `tools/xtask` is a workspace member,
//! so this test still runs under `cargo test --workspace`.
//!
//! NO-CLAIM BOUNDARY: this says nothing about whether a target is CORRECT, only that
//! it can be BUILT where the verification lane builds. Passing earns no capability credit.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The committed, reviewable transfer-exclusion set.
///
/// This is the checked artifact. It is committed rather than read from
/// `~/.config/rch/config.toml` because that file lives outside the repository: a check
/// whose correctness depends on an unversioned file on one operator's machine fails
/// silently when that file changes, and fails somewhere nobody looks.
/// `reconcile_committed_exclusions_against_operator_config` makes the live config a
/// subject under test instead of the source of truth.
const COMMITTED_EXCLUSIONS: &[&str] = &[
    // --- from ~/.config/rch/config.toml exclude_patterns ---
    "target/", "*.rlib", "*.rmeta", ".git/", "node_modules/", ".bun/", ".npm/",
    ".pnpm-store/", "dist/", "/build/", ".next/", ".next*", "artifacts/", ".nuxt/",
    ".turbo/", ".parcel-cache/", ".beads/", "/coverage/", ".nyc_output/",
    ".cargo/credentials", ".cargo/credentials.toml", ".env", ".env.*",
    "*.pem", "*.key", "credentials.json", "secrets.json", "secrets.yaml",
    "secrets.yml", "secrets.toml", "secrets.env", "secrets.txt", "secrets.conf",
    "secrets.cfg", "secrets.properties", "secrets.xml",
    // --- from the repository's own .rchignore ---
    "target-*/", ".rch-target-*/", ".beads_polish_tmp/", ".wm-verify/", ".wm-verify2/",
    ".grok/", "crates/fastmcp/test_traces/",
];

/// Compile-time file-reading macros. `include!` is deliberately included: it reads a
/// path at compile time exactly as the other two do.
const COMPILE_TIME_READ_MACROS: &[&str] = &["include_bytes", "include_str", "include"];

fn workspace_root() -> PathBuf {
    // tools/xtask -> tools -> workspace root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("xtask manifest dir has a grandparent")
        .to_path_buf()
}

/// Replaces comment bytes with spaces, preserving every byte offset and line break so
/// reported line numbers stay exact.
///
/// This is the load-bearing step. A word-keyed search re-finds every place someone
/// already fixed, because a fix's rationale comment is textually indistinguishable from
/// the defect it describes — `oauth_core_rpc.rs` says `include_bytes!` and `*.pem` in a
/// comment precisely because it explains why it no longer does either.
fn blank_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = vec![b' '; b.len()];
    let mut i = 0usize;
    while i < b.len() {
        // raw string: r#*"..."#*
        if b[i] == b'r' {
            let mut j = i + 1;
            let mut hashes = 0usize;
            while j < b.len() && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < b.len() && b[j] == b'"' {
                let close = format!("\"{}", "#".repeat(hashes));
                let rest = &src[j + 1..];
                let end = rest.find(&close).map_or(b.len(), |k| j + 1 + k + close.len());
                out[i..end.min(b.len())].copy_from_slice(&b[i..end.min(b.len())]);
                i = end;
                continue;
            }
        }
        match b[i] {
            b'"' => {
                out[i] = b'"';
                i += 1;
                while i < b.len() {
                    out[i] = b[i];
                    if b[i] == b'\\' {
                        if i + 1 < b.len() {
                            out[i + 1] = b[i + 1];
                        }
                        i += 2;
                        continue;
                    }
                    if b[i] == b'"' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            b'\'' if i + 2 < b.len() => {
                // char literal or lifetime; copy through conservatively
                out[i] = b[i];
                i += 1;
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                let mut depth = 1usize;
                i += 2;
                while i < b.len() && depth > 0 {
                    if b[i] == b'\n' {
                        out[i] = b'\n';
                    }
                    if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
                        depth += 1;
                        i += 2;
                        continue;
                    }
                    if i + 1 < b.len() && b[i] == b'*' && b[i + 1] == b'/' {
                        depth -= 1;
                        i += 2;
                        continue;
                    }
                    i += 1;
                }
            }
            c => {
                out[i] = c;
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A compile-time read found by syntax: a macro name, `!`, and a balanced argument list.
#[derive(Debug)]
struct CompileTimeRead {
    line: usize,
    macro_name: String,
    /// String literals appearing in the argument, in order. `concat!`/`env!` wrappers
    /// contribute their literals; `env!("CARGO_MANIFEST_DIR")` is recorded as a marker.
    literals: Vec<String>,
    manifest_dir_rooted: bool,
}

fn find_compile_time_reads(src: &str) -> Vec<CompileTimeRead> {
    let code = blank_comments(src);
    let mut found = Vec::new();
    for name in COMPILE_TIME_READ_MACROS {
        let needle = format!("{name}!");
        let mut from = 0usize;
        while let Some(rel) = code[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            // require an identifier boundary before the name, so `include_bytes` does
            // not also match as `include`
            let prev_ok = at == 0
                || !code.as_bytes()[at - 1].is_ascii_alphanumeric()
                    && code.as_bytes()[at - 1] != b'_';
            if !prev_ok {
                continue;
            }
            let open = match code[from..].find('(') {
                Some(k) => from + k,
                None => continue,
            };
            // only whitespace may sit between `!` and `(`
            if code[from..open].chars().any(|c| !c.is_whitespace()) {
                continue;
            }
            let mut depth = 0i32;
            let mut end = open;
            for (k, ch) in code[open..].char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = open + k;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let arg = &code[open + 1..end];
            let literals = string_literals(arg);
            if literals.is_empty() {
                continue;
            }
            found.push(CompileTimeRead {
                line: code[..at].matches('\n').count() + 1,
                macro_name: (*name).to_string(),
                manifest_dir_rooted: arg.contains("CARGO_MANIFEST_DIR"),
                literals,
            });
        }
    }
    found
}

fn string_literals(arg: &str) -> Vec<String> {
    let b = arg.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'"' {
            let mut s = String::new();
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' && i + 1 < b.len() {
                    i += 2;
                    continue;
                }
                s.push(b[i] as char);
                i += 1;
            }
            i += 1;
            out.push(s);
        } else {
            i += 1;
        }
    }
    out
}

/// Resolves a read to a repository-relative path, or `None` when the argument is not a
/// plain path we can resolve (a `env!` of something else, a computed path).
fn resolve(read: &CompileTimeRead, file: &Path, crate_root: &Path, ws: &Path) -> Option<PathBuf> {
    let joined: String = read
        .literals
        .iter()
        .filter(|s| *s != "CARGO_MANIFEST_DIR")
        .cloned()
        .collect();
    if joined.is_empty() {
        return None;
    }
    let base = if read.manifest_dir_rooted {
        crate_root.to_path_buf()
    } else {
        file.parent()?.to_path_buf()
    };
    let raw = base.join(joined.trim_start_matches('/'));
    // normalise `..` without touching the filesystem
    let mut parts: Vec<std::ffi::OsString> = Vec::new();
    for c in raw.components() {
        match c {
            std::path::Component::ParentDir => {
                parts.pop();
            }
            std::path::Component::CurDir => {}
            other => parts.push(other.as_os_str().to_os_string()),
        }
    }
    let abs: PathBuf = parts.iter().collect();
    Some(abs.strip_prefix(ws).unwrap_or(&abs).to_path_buf())
}

/// Glob semantics sufficient for the committed set: a trailing `/` matches a path
/// COMPONENT; a `*` globs the basename; anything else matches a basename or a path
/// segment exactly.
fn excluded_by(path: &Path, pattern: &str) -> bool {
    let p = pattern.trim_start_matches('/');
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if let Some(dir) = p.strip_suffix('/') {
        // EXACT component equality unless the pattern itself globs. A prefix match here
        // makes `.git/` swallow `.github/` and `/build/` swallow `builder.rs` — the two
        // false positives the manual sweep also produced.
        return path.components().any(|c| {
            c.as_os_str().to_str().is_some_and(|s| match dir.split_once('*') {
                Some((pre, suf)) => {
                    s.starts_with(pre) && s.ends_with(suf) && s.len() >= pre.len() + suf.len()
                }
                None => s == dir,
            })
        });
    }
    if let Some((pre, suf)) = p.split_once('*') {
        return name.starts_with(pre) && name.ends_with(suf) && name.len() >= pre.len() + suf.len();
    }
    name == p || path.to_str().is_some_and(|s| s.contains(p))
}

fn workspace_members(ws: &Path) -> Vec<PathBuf> {
    let manifest = fs::read_to_string(ws.join("Cargo.toml")).expect("workspace manifest");
    let start = manifest.find("members").expect("members key");
    let open = manifest[start..].find('[').expect("members array") + start;
    let close = manifest[open..].find(']').expect("members array end") + open;
    string_literals(&manifest[open..close])
        .into_iter()
        .map(|m| ws.join(m))
        .collect()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn no_compile_time_read_targets_a_transfer_excluded_path() {
    let ws = workspace_root();
    let mut violations: Vec<String> = Vec::new();
    let mut scanned_files = 0usize;
    let mut scanned_reads = 0usize;

    for member in workspace_members(&ws) {
        let mut files = Vec::new();
        rust_sources(&member.join("src"), &mut files);
        rust_sources(&member.join("tests"), &mut files);
        rust_sources(&member.join("examples"), &mut files);
        rust_sources(&member.join("benches"), &mut files);
        for file in files {
            scanned_files += 1;
            let Ok(src) = fs::read_to_string(&file) else { continue };
            for read in find_compile_time_reads(&src) {
                scanned_reads += 1;
                let Some(rel) = resolve(&read, &file, &member, &ws) else { continue };
                for pattern in COMMITTED_EXCLUSIONS {
                    if excluded_by(&rel, pattern) {
                        let shown = file.strip_prefix(&ws).unwrap_or(&file);
                        violations.push(format!(
                            "{}:{} `{}!` reads `{}`, excluded by `{}`",
                            shown.display(),
                            read.line,
                            read.macro_name,
                            rel.display(),
                            pattern
                        ));
                        break;
                    }
                }
            }
        }
    }

    // Denominator control: a silent zero here would be indistinguishable from a broken
    // walk, which is the same void-green shape this detector exists to prevent.
    assert!(
        scanned_files > 100,
        "walked only {scanned_files} source files; the walk is broken, not the tree clean"
    );
    assert!(
        scanned_reads > 0,
        "found zero compile-time reads across {scanned_files} files; the matcher is broken"
    );

    assert!(
        violations.is_empty(),
        "compile-time reads of transfer-excluded paths ({} found; {scanned_reads} reads over \
         {scanned_files} files). Each makes its target unbuildable on a remote worker, and a \
         test target that fails to build can report `0 passed` instead of failing:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}

#[test]
fn reconcile_committed_exclusions_against_operator_config() {
    // The operator config is the SUBJECT here, not the source of truth. It lives outside
    // the repository and is not synced to workers, so absence is expected and is not a
    // failure — but divergence, where it is readable, is.
    let Some(home) = std::env::var_os("HOME") else {
        eprintln!("HOME unset; operator config unreadable, reconciliation skipped");
        return;
    };
    let config = Path::new(&home).join(".config/rch/config.toml");
    let Ok(text) = fs::read_to_string(&config) else {
        eprintln!(
            "{} absent (expected on a remote worker); reconciliation skipped",
            config.display()
        );
        return;
    };
    let Some(start) = text.find("exclude_patterns") else {
        eprintln!("no exclude_patterns key; reconciliation skipped");
        return;
    };
    let open = start + text[start..].find('[').expect("exclude_patterns array");
    let close = open + text[open..].find(']').expect("exclude_patterns array end");
    let live: BTreeSet<String> = string_literals(&text[open..close]).into_iter().collect();

    let rchignore = fs::read_to_string(workspace_root().join(".rchignore")).unwrap_or_default();
    let live_repo: BTreeSet<String> = rchignore
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();

    let committed: BTreeSet<String> =
        COMMITTED_EXCLUSIONS.iter().map(|s| (*s).to_string()).collect();
    let observed: BTreeSet<String> = live.union(&live_repo).cloned().collect();

    let missing: Vec<&String> = observed.difference(&committed).collect();
    let stale: Vec<&String> = committed.difference(&observed).collect();

    assert!(
        missing.is_empty() && stale.is_empty(),
        "COMMITTED_EXCLUSIONS has drifted from the live transfer configuration.\n  \
         present live but not committed (the detector is BLIND to these): {missing:?}\n  \
         committed but no longer live (stale, may over-report): {stale:?}\n  \
         Update COMMITTED_EXCLUSIONS in this file to match, deliberately."
    );
}
