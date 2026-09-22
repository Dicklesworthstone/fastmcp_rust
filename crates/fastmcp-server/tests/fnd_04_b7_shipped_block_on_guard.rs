//! bd-fnd04-b7-shipped-block-on-proxy-4rkp9, R5 and R6.
//!
//! R5 asks for one `#[test]` that asserts the shipped `block_on` call-site count
//! is zero across four files, and — the part this file can discharge today —
//! that the guard FAILS CLOSED when a named source file is absent, renamed or
//! unreadable, with that behaviour itself asserted. R6 asks for a near-identical
//! negative proving the guard can refuse, run against an in-memory copy of a
//! shipped file with exactly one call site reintroduced, naming the file and
//! line it objected to.
//!
//! WHAT IS HERE AND WHAT IS NOT. The removals R1/R2 require are held pending a
//! ruling on ten trait-bound sites, so the zero assertion cannot pass yet and is
//! NOT written here: a knowingly-red test would break the target for every lane.
//! What is here is the guard itself and every property of it that is provable
//! without the removals — fail-closed, refusal naming file and line, cfg(test)
//! exclusion, and a positive control. When R1/R2 land, the zero assertion is two
//! lines against `shipped_block_on_sites` and needs no new machinery.
//!
//! WHY A NEW FILE rather than an addition to an existing one. The only test in
//! this package that reads source text is `fnd_07_a.rs`, which belongs to
//! another bead and is cited by its receipts; adding a FND-04 guard there would
//! disturb a frozen surface and could void evidence this bead has no business
//! touching.
//!
//! The counting rules mirror `tools/shipped_block_on_census.py`, which is the
//! instrument R3/R4 were established with. Both must agree; the census reports
//! 21 / 7 / 3 / 0 shipped sites for the four files at the time of writing.

use std::path::{Path, PathBuf};

/// The four files R1 and R2 name, relative to the repository root.
const GUARDED_FILES: [&str; 4] = [
    "crates/fastmcp-server/src/proxy.rs",
    "crates/fastmcp-server/src/router.rs",
    "crates/fastmcp-server/src/lib.rs",
    "crates/fastmcp-server/src/legacy_2024.rs",
];

/// Why the guard refused. Every variant is a REFUSAL — there is deliberately no
/// variant meaning "could not tell", because a guard that cannot find its
/// subject and reports success is the defect R5 exists to prevent.
#[derive(Debug, PartialEq, Eq)]
enum Objection {
    /// A named file is absent, renamed, or unreadable.
    Unreadable { path: String },
    /// Shipped `block_on` call sites remain, with the 1-based line of each.
    ShippedCallSites { path: String, lines: Vec<usize> },
}

impl std::fmt::Display for Objection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { path } => {
                write!(f, "{path}: absent, renamed or unreadable")
            }
            Self::ShippedCallSites { path, lines } => {
                write!(f, "{path}: shipped block_on call sites at lines {lines:?}")
            }
        }
    }
}

/// Blanks comment, string, raw-string, byte-string and char content, preserving
/// every newline so line numbers survive.
///
/// This step is not optional. A brace matcher that counts braces inside string
/// literals and doc comments loses module boundaries entirely, and a `block_on`
/// named in a doc comment is not a call. The census measured the unmasked form
/// over-counting `#[cfg(test)]` regions on `proxy.rs` by 13 -> 395.
fn mask_non_code(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = vec![b' '; bytes.len()];
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\n' {
            out[i] = b'\n';
            i += 1;
        } else if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            let mut depth = 1usize;
            i += 2;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'\n' {
                    out[i] = b'\n';
                }
                if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        } else if b == b'r' && raw_string_hashes(bytes, i).is_some() {
            let hashes = raw_string_hashes(bytes, i).expect("checked by the guard above");
            i += 1 + hashes + 1;
            loop {
                if i >= bytes.len() {
                    break;
                }
                if bytes[i] == b'\n' {
                    out[i] = b'\n';
                }
                if bytes[i] == b'"' && closing_hashes(bytes, i + 1, hashes) {
                    i += 1 + hashes;
                    break;
                }
                i += 1;
            }
        } else if b == b'"' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\n' {
                    out[i] = b'\n';
                }
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
        } else {
            out[i] = b;
            i += 1;
        }
    }
    String::from_utf8(out).expect("masking replaces bytes with spaces and keeps newlines")
}

/// `Some(n)` when position `i` begins a raw string with `n` hashes.
fn raw_string_hashes(bytes: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    let mut hashes = 0usize;
    while j < bytes.len() && bytes[j] == b'#' {
        hashes += 1;
        j += 1;
    }
    (j < bytes.len() && bytes[j] == b'"').then_some(hashes)
}

fn closing_hashes(bytes: &[u8], from: usize, hashes: usize) -> bool {
    (0..hashes).all(|k| bytes.get(from + k) == Some(&b'#'))
}

/// Byte ranges covered by a `#[cfg(test)]`-enabled item, by brace matching over
/// masked source.
///
/// Resolved to whichever ITEM follows the attribute — `mod`, `fn`, `impl` — not
/// only to `mod`, because a `#[cfg(test)]` on a FUNCTION is invisible to a
/// stripper that only removes `#[cfg(test)] mod X { .. }`. `#[cfg(not(test))]`
/// is the opposite and is deliberately NOT excluded.
fn test_regions(masked: &str) -> Vec<(usize, usize)> {
    let bytes = masked.as_bytes();
    let mut regions = Vec::new();
    let mut search = 0usize;
    while let Some(found) = masked[search..].find("#[cfg(") {
        let at = search + found;
        let head_end = masked[at..]
            .find(']')
            .map_or(bytes.len(), |offset| at + offset);
        let head = &masked[at..head_end];
        search = head_end.max(at + 1);
        let enables_test = head.contains("test") && !head.contains("not(test)");
        if !enables_test {
            continue;
        }
        let Some(open) = masked[head_end..].find('{').map(|o| head_end + o) else {
            continue;
        };
        let mut depth = 0usize;
        let mut k = open;
        while k < bytes.len() {
            match bytes[k] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        regions.push((at, k));
                        search = k;
                        break;
                    }
                }
                _ => {}
            }
            k += 1;
        }
    }
    regions
}

/// 1-based lines holding a SHIPPED `block_on` CALL site.
///
/// A call is `block_on` followed by `(`. A mention inside a `use` statement is an
/// import, not a call. Doc comments never reach this point; masking removed them.
fn shipped_block_on_sites(source: &str) -> Vec<usize> {
    let masked = mask_non_code(source);
    let regions = test_regions(&masked);
    let mut lines = Vec::new();
    let mut search = 0usize;
    while let Some(found) = masked[search..].find("block_on") {
        let at = search + found;
        search = at + "block_on".len();
        let after = masked[search..].trim_start();
        if !after.starts_with('(') {
            continue;
        }
        if regions.iter().any(|&(start, end)| at >= start && at <= end) {
            continue;
        }
        let line_start = masked[..at].rfind('\n').map_or(0, |n| n + 1);
        if masked[line_start..at].trim_start().starts_with("use ") {
            continue;
        }
        lines.push(masked[..at].matches('\n').count() + 1);
    }
    lines
}

/// The guard. Refuses on an unreadable file BEFORE it can report a false clean.
fn guard_file(root: &Path, relative: &str) -> Result<(), Objection> {
    let path = root.join(relative);
    let source = std::fs::read_to_string(&path).map_err(|_| Objection::Unreadable {
        path: relative.to_owned(),
    })?;
    guard_source(relative, &source)
}

/// The same predicate over source TEXT, so R6's negative can run against an
/// in-memory copy without touching the tree.
fn guard_source(relative: &str, source: &str) -> Result<(), Objection> {
    let lines = shipped_block_on_sites(source);
    if lines.is_empty() {
        Ok(())
    } else {
        Err(Objection::ShippedCallSites {
            path: relative.to_owned(),
            lines,
        })
    }
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the server crate sits two levels below the repository root")
        .to_path_buf()
}

/// R5, fail-closed half. A named file that is absent, renamed or unreadable must
/// make the guard REFUSE — not pass, not skip — and the refusal must name it.
#[test]
fn fnd_04_b7_shipped_block_on_guard_fails_closed_positive() {
    let root = repository_root();
    let missing = "crates/fastmcp-server/src/this_file_does_not_exist.rs";

    let objection = guard_file(&root, missing)
        .expect_err("a guard that cannot read its subject must refuse, never report success");

    assert_eq!(
        objection,
        Objection::Unreadable {
            path: missing.to_owned()
        },
        "the refusal must name the file it could not read"
    );
    assert!(
        objection.to_string().contains(missing),
        "the rendered objection must carry the path: {objection}"
    );

    // The four real files must all be READABLE, so the check above is testing
    // fail-closed behaviour rather than a typo in GUARDED_FILES. Without this the
    // test would still pass if every guarded path were wrong.
    for relative in GUARDED_FILES {
        assert!(
            root.join(relative).is_file(),
            "guarded path must exist, else the guard is aimed at nothing: {relative}"
        );
    }
}

/// R6. The same guard, against an in-memory copy of a shipped file with exactly
/// ONE call site reintroduced, must refuse and name the file and the line.
#[test]
fn fnd_04_b7_shipped_block_on_guard_planted_negative() {
    let relative = "crates/fastmcp-server/src/legacy_2024.rs";
    let root = repository_root();
    let pristine = std::fs::read_to_string(root.join(relative))
        .expect("the planted negative needs a readable subject");

    // legacy_2024.rs is the file the census reports at ZERO shipped call sites,
    // so it is the one subject where a clean baseline is available today and the
    // plant is the only variable. R1's removals have not landed, so the other
    // three still hold sites and could not distinguish a plant from a survivor.
    guard_source(relative, &pristine)
        .expect("baseline must be clean, or the plant below proves nothing");

    let mut planted = String::new();
    let mut planted_line = 0usize;
    for (index, line) in pristine.lines().enumerate() {
        planted.push_str(line);
        planted.push('\n');
        if planted_line == 0 && line.starts_with("use ") {
            planted.push_str("fn fnd04_b7_planted() { let _ = block_on(async {}); }\n");
            planted_line = index + 2;
        }
    }
    assert_ne!(planted_line, 0, "the plant must have been inserted");
    assert_eq!(
        planted.matches("block_on(").count(),
        pristine.matches("block_on(").count() + 1,
        "the plant changes exactly one dimension: one added call site"
    );

    let objection = guard_source(relative, &planted)
        .expect_err("one reintroduced shipped call site must be refused");

    assert_eq!(
        objection,
        Objection::ShippedCallSites {
            path: relative.to_owned(),
            lines: vec![planted_line],
        },
        "the refusal must name the file and the exact line it objected to"
    );
}

/// The guard must not count what is not a shipped call. Each case below is a way
/// a naive matcher reports a false positive, and `block_on` appears in all of
/// them.
#[test]
fn fnd_04_b7_shipped_block_on_guard_excludes_non_calls_positive() {
    let cases: [(&str, &str); 5] = [
        ("import", "use futures::executor::block_on;\n"),
        ("line comment", "// block_on(x) is not a call here\n"),
        ("doc comment", "/// See block_on(x) for details.\n"),
        ("string", "const S: &str = \"block_on(x)\";\n"),
        ("raw string", "const R: &str = r#\"block_on(x)\"#;\n"),
    ];
    for (label, source) in cases {
        assert_eq!(
            shipped_block_on_sites(source),
            Vec::<usize>::new(),
            "{label} must not count as a shipped call site"
        );
    }

    // cfg(test) exclusion, on a FUNCTION rather than a mod — the form a
    // mod-only stripper misses.
    let gated = "#[cfg(test)]\nfn t() { block_on(async {}); }\n";
    assert_eq!(
        shipped_block_on_sites(gated),
        Vec::<usize>::new(),
        "a call inside a cfg(test) item is not shipped"
    );

    // CONTROL: the identical body WITHOUT the attribute must be counted, so the
    // exclusion above is doing work rather than the matcher simply never firing.
    let shipped = "fn t() { block_on(async {}); }\n";
    assert_eq!(
        shipped_block_on_sites(shipped),
        vec![1],
        "the same call outside cfg(test) MUST be counted"
    );

    // cfg(not(test)) is the opposite of a test gate and stays shipped.
    let not_test = "#[cfg(not(test))]\nfn t() { block_on(async {}); }\n";
    assert_eq!(
        shipped_block_on_sites(not_test),
        vec![2],
        "cfg(not(test)) is shipped code"
    );
}
