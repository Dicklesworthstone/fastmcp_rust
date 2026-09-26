//! Shipped-source scanners shared by two source-reading test targets.
//!
//! - `fnd_04_b7_shipped_block_on_guard` (bd-fnd04-b7-shipped-block-on-proxy-4rkp9)
//!   asserts that no shipped library code calls `block_on` or builds a runtime.
//! - `crates/fastmcp/tests/fnd_04_public_signature_compile.rs`
//!   (bd-mcp-fnd-04-a-jmi7) reuses the same library-graph walk and masking for
//!   its Cx-first signature scan and its forbidden counts.
//!
//! This file is not a test target: Cargo discovers only `tests/*.rs` and
//! `tests/*/main.rs`. Each target includes it with `#[path]`.
//!
//! The counting rules mirror `tools/shipped_block_on_census.py`, except that cfg
//! predicates are evaluated for satisfiability: `not(feature = "x")` ships when
//! the feature is off.

use std::path::{Path, PathBuf};

/// Why the guard refused. Every variant is a REFUSAL — there is deliberately no
/// variant meaning "could not tell", because a guard that cannot find its
/// subject and reports success is the defect R5 exists to prevent.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Objection {
    /// A named file is absent, renamed, or unreadable.
    Unreadable { path: String },
    /// Shipped `block_on` call sites remain, with the 1-based line of each.
    ShippedCallSites { path: String, lines: Vec<usize> },
    /// Shipped library code builds a runtime, with the 1-based line of each.
    RuntimeConstruction { path: String, lines: Vec<usize> },
    /// An out-of-line `mod name;` names no file, so the walk cannot see what
    /// it compiles.
    UnresolvedModule {
        path: String,
        line: usize,
        name: String,
    },
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
            Self::RuntimeConstruction { path, lines } => {
                write!(f, "{path}: shipped runtime construction at lines {lines:?}")
            }
            Self::UnresolvedModule { path, line, name } => {
                write!(f, "{path}:{line}: `mod {name};` resolves to no file")
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
pub(crate) fn mask_non_code(source: &str) -> String {
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
        } else if b == b'\''
            && let Some(end) = char_literal_end(bytes, i)
        {
            // A char literal can hold a quote or a brace ('"', '{'). Left in,
            // it opens a phantom string or shifts every later brace match.
            i = end;
        } else if b == b'"' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\n' {
                    out[i] = b'\n';
                }
                if bytes[i] == b'\\' {
                    // A `\` line continuation escapes the newline itself. Keep
                    // it, or every later line number drifts by one.
                    if bytes.get(i + 1) == Some(&b'\n') {
                        out[i + 1] = b'\n';
                    }
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

/// `Some(end)` just past a char literal opening at `i`, or `None` for a
/// lifetime or label (`'a`), which has no closing quote.
fn char_literal_end(bytes: &[u8], i: usize) -> Option<usize> {
    let body = *bytes.get(i + 1)?;
    let close = if body == b'\\' {
        // '\n', '\'', '\x7f', '\u{10FFFF}': the closing quote is near.
        (i + 3..(i + 12).min(bytes.len())).find(|&k| bytes[k] == b'\'')?
    } else {
        // One UTF-8 scalar, one to four bytes, then the closing quote.
        let width = match body {
            0x00..=0x7f => 1,
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            _ => 4,
        };
        let k = i + 1 + width;
        (bytes.get(k) == Some(&b'\'')).then_some(k)?
    };
    Some(close + 1)
}

/// Byte ranges covered by an item only `cargo test` compiles, by brace matching
/// over masked source.
///
/// Resolved to whichever ITEM follows the attribute (`mod`, `fn`, `impl`), not
/// only to `mod`, because a `#[cfg(test)]` on a FUNCTION is invisible to a
/// stripper that only removes `#[cfg(test)] mod X { .. }`.
///
/// The predicate is EVALUATED, never substring-matched.
/// `any(feature = "legacy-2024-11-05", test)` mentions `test` but ships whenever
/// that default feature is on; matching the substring treated about 3,300
/// shipped lines of `lib.rs` as test code. `#[cfg(not(test))]` is shipped too.
///
/// An item without a body (`use x;`, `mod tests;`) ends at its semicolon, so it
/// can never swallow the item that follows it.
pub(crate) fn test_regions(masked: &str) -> Vec<(usize, usize)> {
    let bytes = masked.as_bytes();
    let mut regions = Vec::new();
    let mut search = 0usize;
    while let Some(found) = masked[search..].find("#[cfg(") {
        let at = search + found;
        let open = at + "#[cfg".len();
        let Some(close) = balanced_end(bytes, open) else {
            break;
        };
        search = close + 1;
        if !cfg_is_test_only(&masked[open + 1..close]) {
            continue;
        }
        // Step past this attribute's `]` and any further attributes on the item.
        let mut item = masked[close..]
            .find(']')
            .map_or(bytes.len(), |offset| close + offset + 1);
        loop {
            while item < bytes.len() && bytes[item].is_ascii_whitespace() {
                item += 1;
            }
            let next_attribute = (bytes.get(item) == Some(&b'#'))
                .then(|| masked[item..].find('['))
                .flatten()
                .and_then(|offset| balanced_end(bytes, item + offset));
            match next_attribute {
                Some(end) => item = end + 1,
                None => break,
            }
        }
        if let Some(end) = item_end(bytes, item) {
            regions.push((at, end));
            search = search.max(end);
        }
    }
    regions
}

/// Index of the delimiter that closes the one at `open` (`(`, `[` or `{`).
pub(crate) fn balanced_end(bytes: &[u8], open: usize) -> Option<usize> {
    let (opening, closing) = match *bytes.get(open)? {
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        b'{' => (b'{', b'}'),
        _ => return None,
    };
    let mut depth = 0usize;
    for (index, &byte) in bytes.iter().enumerate().skip(open) {
        if byte == opening {
            depth += 1;
        } else if byte == closing {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

/// Index of the last byte of the item starting at `start`: its closing `}`, or
/// its `;`, `,` or enclosing `}` when it has no body of its own.
fn item_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, &byte) in bytes.iter().enumerate().skip(start) {
        match byte {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            b'{' if depth == 0 => return balanced_end(bytes, index),
            b';' | b',' | b'}' if depth == 0 => return Some(index),
            _ => {}
        }
    }
    None
}

/// Whether an item gated by `cfg(<predicate>)` compiles only under `cargo test`:
/// with `test` false and every other predicate free, the predicate never holds.
fn cfg_is_test_only(predicate: &str) -> bool {
    !cfg_can_be(predicate, true)
}

/// Whether `predicate` can evaluate to `value` outside `cargo test`, where
/// `test` is false and every other predicate may take either value.
fn cfg_can_be(predicate: &str, value: bool) -> bool {
    let predicate = predicate.trim();
    for operator in ["all", "any", "not"] {
        let Some(arguments) = predicate
            .strip_prefix(operator)
            .map(str::trim_start)
            .and_then(|rest| rest.strip_prefix('('))
            .and_then(|rest| rest.strip_suffix(')'))
        else {
            continue;
        };
        let arguments = split_cfg_arguments(arguments);
        return match (operator, value) {
            ("all", true) | ("any", false) => {
                arguments.iter().all(|argument| cfg_can_be(argument, value))
            }
            ("all", false) | ("any", true) => {
                arguments.iter().any(|argument| cfg_can_be(argument, value))
            }
            _ => arguments
                .first()
                .is_some_and(|argument| cfg_can_be(argument, !value)),
        };
    }
    predicate != "test" || !value
}

/// The comma-separated arguments of a cfg operator, split at paren depth zero.
fn split_cfg_arguments(arguments: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut from) = (0usize, 0usize);
    for (index, byte) in arguments.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                parts.push(arguments[from..index].trim());
                from = index + 1;
            }
            _ => {}
        }
    }
    parts.push(arguments[from..].trim());
    parts.retain(|part| !part.is_empty());
    parts
}

/// 1-based lines holding a SHIPPED `block_on` CALL site.
///
/// A call is `block_on` followed by `(`. A mention inside a `use` statement is an
/// import, not a call. Doc comments never reach this point; masking removed them.
pub(crate) fn shipped_block_on_sites(source: &str) -> Vec<usize> {
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

/// Each including crate sits two levels below the repository root.
pub(crate) fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the including crate sits two levels below the repository root")
        .to_path_buf()
}

/// The library crates whose shipped graph must hold no `block_on` call and no
/// runtime construction. The CLI is the application boundary: its `main`
/// builds the one top-level runtime, so it is deliberately not listed. Nor are
/// examples or bin targets, which are consumer entry points.
pub(crate) const GUARDED_CRATES: [&str; 8] = [
    "crates/fastmcp-core",
    "crates/fastmcp-protocol",
    "crates/fastmcp-transport",
    "crates/fastmcp-client",
    "crates/fastmcp-server",
    "crates/fastmcp-macros",
    "crates/fastmcp-console",
    "crates/fastmcp",
];

/// `fastmcp_core::block_on` builds and drives a runtime by definition. The body
/// of that one function is the only library-side exemption; the rest of its
/// file is scanned like any other.
pub(crate) const BRIDGE_DEFINITION: (&str, &str) =
    ("crates/fastmcp-core/src/runtime.rs", "pub fn block_on");

/// One file a library target compiles outside `cargo test`.
pub(crate) struct ShippedFile {
    pub(crate) relative: String,
    pub(crate) source: String,
}

/// One out-of-line `mod name;` declaration.
struct ModuleDeclaration {
    name: String,
    line: usize,
    test_only: bool,
    explicit_path: Option<String>,
    /// Enclosing inline modules, outermost first; they nest the file path.
    inline: Vec<String>,
}

pub(crate) fn disk(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn relative_to(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every file the library target of `crate_dir` compiles outside `cargo test`,
/// found by walking out-of-line `mod name;` declarations from `src/lib.rs`.
///
/// A test-only declaration is not followed: nothing it reaches ships, and a
/// file it shares with a shipped declaration is reached through that one. A
/// shipped declaration that names no file is a refusal, never a skip. `read`
/// supplies every source, so a planted negative can substitute one in memory.
pub(crate) fn shipped_crate_files(
    root: &Path,
    crate_dir: &str,
    read: &dyn Fn(&Path) -> Option<String>,
) -> Result<Vec<ShippedFile>, Objection> {
    let lib = root.join(crate_dir).join("src").join("lib.rs");
    let mut files = std::collections::BTreeMap::new();
    let mut queue = vec![(lib.clone(), lib.parent().map(Path::to_path_buf))];
    while let Some((path, module_dir)) = queue.pop() {
        if files.contains_key(&path) {
            continue;
        }
        let source = read(&path).ok_or_else(|| Objection::Unreadable {
            path: relative_to(root, &path),
        })?;
        let module_dir = module_dir.unwrap_or_else(|| root.to_path_buf());
        for declaration in module_declarations(&source) {
            if declaration.test_only {
                continue;
            }
            // Inline blocks nest the module directory. A top-level `#[path]` is
            // relative to the declaring file's own directory instead.
            let nested = declaration
                .inline
                .iter()
                .fold(module_dir.clone(), |dir, name| dir.join(name));
            let candidates = match &declaration.explicit_path {
                Some(explicit) if declaration.inline.is_empty() => {
                    vec![path.parent().unwrap_or(root).join(explicit)]
                }
                Some(explicit) => vec![nested.join(explicit)],
                None => vec![
                    nested.join(format!("{}.rs", declaration.name)),
                    nested.join(&declaration.name).join("mod.rs"),
                ],
            };
            let Some(child) = candidates
                .into_iter()
                .find(|candidate| read(candidate).is_some())
            else {
                return Err(Objection::UnresolvedModule {
                    path: relative_to(root, &path),
                    line: declaration.line,
                    name: declaration.name,
                });
            };
            // A `mod.rs` or `#[path]` file owns its own directory; `x.rs` owns `x/`.
            let owns_parent =
                declaration.explicit_path.is_some() || child.file_name() == Some("mod.rs".as_ref());
            let child_dir = if owns_parent {
                child.parent().map(Path::to_path_buf)
            } else {
                Some(child.with_extension(""))
            };
            queue.push((child, child_dir));
        }
        files.insert(path, source);
    }
    Ok(files
        .into_iter()
        .map(|(path, source)| ShippedFile {
            relative: relative_to(root, &path),
            source,
        })
        .collect())
}

/// The out-of-line module declarations in `source`, each classified by the same
/// evaluated cfg regions the call-site scan uses.
fn module_declarations(source: &str) -> Vec<ModuleDeclaration> {
    let masked = mask_non_code(source);
    let regions = test_regions(&masked);
    let inline_spans = inline_module_spans(&masked);
    let raw_lines: Vec<&str> = source.lines().collect();
    let mut declarations = Vec::new();
    let mut offset = 0usize;
    for (index, line) in masked.split_inclusive('\n').enumerate() {
        let line_start = offset;
        offset += line.len();
        // `#[cfg(feature = "x")] mod y;` may share its line with an attribute.
        let mut trimmed = line.trim_start();
        while trimmed.starts_with("#[")
            && let Some(close) = balanced_end(trimmed.as_bytes(), 1)
        {
            trimmed = trimmed[close + 1..].trim_start();
        }
        let Some(name) = out_of_line_module_name(trimmed) else {
            continue;
        };
        let at = line_start + (line.len() - trimmed.len());
        let explicit_path = raw_lines[..index]
            .iter()
            .rev()
            .map(|raw| raw.trim())
            .take_while(|raw| raw.starts_with('#') || raw.starts_with("//"))
            .find_map(|raw| {
                let value = raw.strip_prefix("#[path")?.split('"').nth(1)?;
                Some(value.to_owned())
            });
        let mut inline: Vec<&(usize, usize, String)> = inline_spans
            .iter()
            .filter(|(open, close, _)| *open < at && at < *close)
            .collect();
        inline.sort_by_key(|(open, _, _)| *open);
        declarations.push(ModuleDeclaration {
            name: name.to_owned(),
            line: index + 1,
            test_only: regions.iter().any(|&(start, end)| at >= start && at <= end),
            explicit_path,
            inline: inline
                .into_iter()
                .map(|(_, _, name)| name.clone())
                .collect(),
        });
    }
    declarations
}

/// `Some(name)` when a masked, left-trimmed line is `[pub[(..)]] mod name;`.
fn out_of_line_module_name(trimmed: &str) -> Option<&str> {
    let rest = strip_visibility(trimmed).strip_prefix("mod")?;
    let rest = rest
        .strip_prefix(|c: char| c.is_ascii_whitespace())?
        .trim_start();
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let (name, tail) = rest.split_at(end);
    (!name.is_empty() && tail.trim_start().starts_with(';')).then_some(name)
}

fn strip_visibility(item: &str) -> &str {
    let Some(rest) = item.strip_prefix("pub") else {
        return item;
    };
    let rest = rest.trim_start();
    match rest.strip_prefix('(') {
        Some(scoped) => scoped
            .find(')')
            .map_or(item, |close| scoped[close + 1..].trim_start()),
        None => rest,
    }
}

/// `(open, close, name)` for every inline `mod name { .. }` in masked source.
fn inline_module_spans(masked: &str) -> Vec<(usize, usize, String)> {
    let bytes = masked.as_bytes();
    let mut spans = Vec::new();
    let mut search = 0usize;
    while let Some(found) = masked[search..].find("mod") {
        let at = search + found;
        search = at + 3;
        let bounded_before =
            at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_');
        let rest = &masked[at + 3..];
        if !bounded_before || !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
            continue;
        }
        let rest = rest.trim_start();
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let (name, tail) = rest.split_at(end);
        let tail_trimmed = tail.trim_start();
        if name.is_empty() || !tail_trimmed.starts_with('{') {
            continue;
        }
        let open = masked.len() - tail_trimmed.len();
        if let Some(close) = balanced_end(bytes, open) {
            spans.push((open, close, name.to_owned()));
        }
    }
    spans
}

/// 1-based lines where shipped code builds a runtime: `RuntimeBuilder::..` or
/// `Runtime::new(..)` outside every test-only region.
pub(crate) fn runtime_construction_sites(source: &str) -> Vec<usize> {
    let masked = mask_non_code(source);
    let regions = test_regions(&masked);
    let bytes = masked.as_bytes();
    let mut lines = Vec::new();
    for needle in ["RuntimeBuilder::", "Runtime::new"] {
        let mut search = 0usize;
        while let Some(found) = masked[search..].find(needle) {
            let at = search + found;
            search = at + needle.len();
            let bounded =
                at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_');
            if !bounded || regions.iter().any(|&(start, end)| at >= start && at <= end) {
                continue;
            }
            lines.push(masked[..at].matches('\n').count() + 1);
        }
    }
    lines.sort_unstable();
    lines
}

/// The guard over one library crate's whole shipped graph. Returns how many
/// shipped files it scanned, so a caller can prove it was aimed at something.
pub(crate) fn guard_library_crate(
    root: &Path,
    crate_dir: &str,
    read: &dyn Fn(&Path) -> Option<String>,
) -> Result<usize, Vec<Objection>> {
    let files = shipped_crate_files(root, crate_dir, read).map_err(|objection| vec![objection])?;
    let mut objections = Vec::new();
    for file in &files {
        let exempt = (file.relative == BRIDGE_DEFINITION.0)
            .then(|| exempt_lines(&file.source, BRIDGE_DEFINITION.1))
            .flatten();
        let outside = |line: &usize| exempt.as_ref().is_none_or(|range| !range.contains(line));
        let calls: Vec<usize> = shipped_block_on_sites(&file.source)
            .into_iter()
            .filter(outside)
            .collect();
        if !calls.is_empty() {
            objections.push(Objection::ShippedCallSites {
                path: file.relative.clone(),
                lines: calls,
            });
        }
        let builds: Vec<usize> = runtime_construction_sites(&file.source)
            .into_iter()
            .filter(outside)
            .collect();
        if !builds.is_empty() {
            objections.push(Objection::RuntimeConstruction {
                path: file.relative.clone(),
                lines: builds,
            });
        }
    }
    if objections.is_empty() {
        Ok(files.len())
    } else {
        Err(objections)
    }
}

/// The 1-based line range of the item whose masked text begins with `item`.
fn exempt_lines(source: &str, item: &str) -> Option<std::ops::RangeInclusive<usize>> {
    let masked = mask_non_code(source);
    let at = masked.find(item)?;
    let open = at + masked[at..].find('{')?;
    let close = balanced_end(masked.as_bytes(), open)?;
    let line_of = |offset: usize| masked[..offset].matches('\n').count() + 1;
    Some(line_of(at)..=line_of(close))
}
