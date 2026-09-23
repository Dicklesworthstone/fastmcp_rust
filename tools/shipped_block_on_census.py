#!/usr/bin/env python3
"""Count SHIPPED `block_on` call sites: cfg(test)-aware, and lexically honest.

Written for bd-fnd04-b7-shipped-block-on-proxy-4rkp9 R3/R4, which require the
count to be established by instrument rather than inherited from prose, and the
instrument to be validated against a known positive and a known negative before
any of its zeros are believed.

Two things this does that a grep or a naive brace matcher cannot:

1. LEXICAL MASKING FIRST. Comment, string, raw-string, byte-string and char
   content is blanked (newlines preserved, so line numbers survive) before any
   brace is counted. A brace matcher that skips this step counts braces inside
   string literals and doc comments and loses module boundaries entirely. R4
   puts the over-count at roughly 3.5x on this codebase; `--naive-control`
   reproduces that figure rather than taking it on faith.

2. TEST REGIONS BY ITEM, NOT BY `mod`. A `#[cfg(test)]` on a FUNCTION is
   invisible to a stripper that only removes `#[cfg(test)] mod X { .. }`. So
   every cfg attribute is resolved to whichever item follows it -- mod, fn,
   impl, block -- and that item's brace span becomes the excluded region.
   Non-literal forms like `#[cfg(all(test, feature = "x"))]` are test-enabling;
   `#[cfg(not(test))]` is its opposite and is deliberately NOT excluded.

Occurrences are classified, because the raw match count is not the call count:
    CALL    `block_on` followed by `(`            <- the thing being counted
    IMPORT  inside a `use` statement              <- not a call
    OTHER   a path mention that is neither        <- reported, never counted
Doc comments never reach classification; masking removes them.

Usage:
  tools/shipped_block_on_census.py <file>...        # census
  tools/shipped_block_on_census.py --validate       # R4: positive + negative
  tools/shipped_block_on_census.py --validate --proxy <file>  # controls on a planted copy
  tools/shipped_block_on_census.py --naive-control <file>
  tools/shipped_block_on_census.py --workspace     # every crate's module tree, `mod x;` cfg resolved
  tools/shipped_block_on_census.py --workspace --crates <dir>  # planted fixture crates
"""

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SYMBOL = "block_on"

PROXY = "crates/fastmcp-server/src/proxy.rs"
LEGACY = "crates/fastmcp-server/src/legacy_2024.rs"
ROUTER = "crates/fastmcp-server/src/router.rs"
LIB = "crates/fastmcp-server/src/lib.rs"
BEAD_FILES = [PROXY, LEGACY, ROUTER, LIB]

# The known-positive and known-negative controls, frozen BY SYMBOL.
#
# The bead's R1 baseline was 18 proxy.rs call sites at 4e48b86a, first frozen
# here as line numbers (:4644 .. :7092). Outside edits moved every one of them
# +216..+229 lines without changing a call, and the line-frozen control went
# RED over an unchanged population (bd-fnd04-b7-shipped-block-on-proxy-4rkp9).
# Each site is now (enclosing item path, ordinal among CALLs in that item),
# derived FROM those 18 baseline lines, so the control still names the same 18
# calls and survives any edit that does not rename or remove one. A renamed or
# removed site fails the control loudly; that is a change to the subject, and
# the control must say so rather than follow it.
PROXY_EXPECTED_CALLS = [
    ("impl ProxyFinalTaskRelay :: fn open_listener", 1),                       # :4644 @4e48b86a
    ("impl ProxyHttpClient :: fn ensure_legacy_initialized", 1),               # :5089
    ("impl ProxyHttpClient :: fn request_legacy_response", 1),                 # :5383
    ("impl ProxyHttpClient :: fn request_result_with_context_and_final_progress", 1),  # :5475
    ("impl ProxyHttpClient :: fn request_legacy_response_unscoped", 1),        # :5550
    ("impl ProxyHttpClient :: fn cancel_legacy_request", 1),                   # :5596
    ("impl ProxyBackend for ProxyHttpClient :: fn start_legacy_request_with_context", 1),  # :5709
    ("impl ProxyBackend for ProxyHttpClient :: fn call_tool_final_outcome", 1),  # :6316
    ("impl ProxyBackend for ProxyHttpClient :: fn get_final_task", 1),         # :6336
    ("impl ProxyBackend for ProxyHttpClient :: fn update_final_task", 1),      # :6359
    ("impl ProxyBackend for ProxyHttpClient :: fn cancel_final_task", 1),      # :6379
    ("impl ProxyBackend for ProxyHttpClient :: fn open_final_task_listener", 1),  # :6459
    ("impl ProxyBackend for ProxyHttpClient :: fn next_incremental_catalog_listener", 1),  # :6554
    ("impl ProxyBackend for ProxyHttpClient :: fn next_incremental_final_task_listener", 1),  # :6693
    ("impl ProxyFinalTaskListener for ProxyHttpFinalTaskListener :: fn next", 1),  # :6830
    ("fn receive_modern_response", 1),                                          # :7069
    ("fn receive_modern_response", 2),                                          # :7075
    ("fn receive_modern_response", 3),                                          # :7092
]
# Known negatives, frozen by CONTENT. The import is the one top-level `use`
# statement naming the symbol (found by its own regex, not by classify());
# the doc comments are matched on their exact trimmed text. Each anchor must
# resolve to EXACTLY one place: a line-frozen negative "passes" on whatever
# empty line it drifts onto, which is how :1346 kept passing after its doc
# comment moved to :1399.
PROXY_IMPORT_STMT = re.compile(r"\buse\b[^;]*\bblock_on\b[^;]*;")
PROXY_EXPECTED_DOCS = [
    "/// not nest `block_on` on a second current-thread runtime. The default",  # :752 @4e48b86a
    "/// gateway serve runtime. Starting the pump inside `block_on` orphans it",  # :1346
]


def mask(src):
    """Blank comment/string/char content, preserving length and newlines.

    Everything downstream (brace matching, symbol search, `use` detection) runs
    on the masked text, so no brace or identifier inside a literal or a comment
    can be mistaken for code.
    """
    out = list(src)
    i, n = 0, len(src)

    def blank(start, end):
        for k in range(start, end):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        # line comment
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            blank(i, j)
            i = j
            continue
        # block comment, which nests in Rust
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
            continue
        # raw string, optionally byte-prefixed: r"..", r#".."#, br#".."#
        m = re.match(r'(?:b?r)(#*)"', src[i : i + 8])
        if m and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            hashes = m.group(1)
            close = '"' + hashes
            j = src.find(close, i + m.end())
            j = n if j == -1 else j + len(close)
            blank(i, j)
            i = j
            continue
        # ordinary or byte string
        if c == '"' or (c == "b" and i + 1 < n and src[i + 1] == '"'):
            j = i + (2 if c == "b" else 1)
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
            continue
        # char literal vs lifetime: 'a' is a char, 'a is a lifetime
        if c == "'":
            if i + 2 < n and src[i + 1] == "\\":
                j = i + 2
                while j < n and src[j] != "'":
                    j += 1
                j = min(j + 1, n)
                blank(i, j)
                i = j
                continue
            if i + 2 < n and src[i + 2] == "'":
                blank(i, i + 3)
                i += 3
                continue
            i += 1  # lifetime; nothing to mask
            continue
        i += 1
    return "".join(out)


def line_index(src):
    """Offset -> 1-based line, via prefix newline counts."""
    starts = [0]
    for m in re.finditer("\n", src):
        starts.append(m.end())
    return starts


def line_of(starts, offset):
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def match_brace(masked, open_idx):
    """Index just past the brace that closes the one at open_idx."""
    depth, i, n = 0, open_idx, len(masked)
    while i < n:
        if masked[i] == "{":
            depth += 1
        elif masked[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


CFG_ATTR = re.compile(r"#\s*\[\s*cfg\s*\(")


def _split_args(body):
    """Split a cfg argument list on top-level commas."""
    parts, depth, cur = [], 0, ""
    for ch in body:
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        cur += ch
    if cur.strip():
        parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def _eval_cfg(expr, test):
    """Evaluate a cfg expression with `test` given and every other predicate TRUE.

    Features, target_os and friends are assumed satisfiable, because the
    question is whether the item can reach a shipped build at all.
    """
    expr = expr.strip()
    for op in ("all", "any", "not"):
        if expr.startswith(op) and expr[len(op) :].lstrip().startswith("("):
            inner = expr[expr.index("(") + 1 : expr.rindex(")")]
            args = _split_args(inner)
            vals = [_eval_cfg(a, test) for a in args]
            if op == "all":
                return all(vals)
            if op == "any":
                return any(vals)
            return not vals[0]
    if re.fullmatch(r"test", expr):
        return test
    return True


def test_only(cfg_body):
    """True iff the item CANNOT be compiled outside `cargo test`.

    The distinction that matters, and the one a substring check gets wrong:
    `any(feature = "legacy-2024-11-05", test)` MENTIONS test but ships whenever
    the feature is on, so it is not test-only. `all(test, ..)` and bare `test`
    are. `not(test)` is shipped. Evaluating the expression at test=false, with
    every other predicate assumed satisfiable, answers this directly; matching
    on the token `test` does not.
    """
    return not _eval_cfg("all(" + cfg_body + ")", test=False)


def test_regions(masked):
    """Brace spans of every item carrying a test-enabling cfg attribute."""
    regions = []
    for m in CFG_ATTR.finditer(masked):
        # balance the cfg(...) parens
        i, depth = m.end() - 1, 0
        while i < len(masked):
            if masked[i] == "(":
                depth += 1
            elif masked[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = masked[m.end() : i]
        close_bracket = masked.find("]", i)
        if close_bracket == -1 or not test_only(body):
            continue
        # The attribute may be followed by more attributes before the item.
        j = close_bracket + 1
        while True:
            while j < len(masked) and masked[j].isspace():
                j += 1
            if masked.startswith("#", j):
                k = masked.find("]", j)
                if k == -1:
                    break
                j = k + 1
                continue
            break
        # An out-of-line `mod x;` has no body here; a braced item does.
        semi = masked.find(";", j)
        brace = masked.find("{", j)
        if brace == -1 or (semi != -1 and semi < brace):
            continue
        regions.append((j, match_brace(masked, brace)))
    return regions


def in_region(regions, offset):
    return any(a <= offset < b for a, b in regions)


def classify(masked, start):
    """CALL, IMPORT or OTHER for one occurrence of the symbol."""
    after = masked[start + len(SYMBOL) :]
    stripped = after.lstrip()
    is_call = stripped.startswith("(")
    # Walk back to the statement boundary and look for `use`.
    # Statement boundary: the previous `;` or the previous CLOSING brace.
    # Deliberately not the previous `{` -- a multi-line `use a::{ .., block_on };`
    # puts an opening brace between the `use` keyword and the symbol, and
    # stopping there classifies the import as a call.
    bound = max(masked.rfind(";", 0, start), masked.rfind("}", 0, start)) + 1
    if re.search(r"\buse\b", masked[bound:start]):
        return "IMPORT"
    return "CALL" if is_call else "OTHER"


# An item header at the start of a line: `fn name`, `impl ..`, `mod name`,
# `trait name`, with the usual qualifiers. Anchoring to line starts keeps
# return-position `impl Trait` and `fn(..)` pointer types out.
ITEM_HEAD = re.compile(
    r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:default[ \t]+)?(?:const[ \t]+)?(?:async[ \t]+)?"
    r"(?:unsafe[ \t]+)?(?:extern[ \t]+(?:\"[^\"]*\"[ \t]+)?)?"
    r"(fn[ \t]+\w+|impl\b|mod[ \t]+\w+|trait[ \t]+\w+)",
    re.M,
)


def item_spans(masked):
    """(body_start, body_end, label) for every braced fn/impl/mod/trait item.

    The label is the item's header up to its body brace, whitespace-collapsed:
    `fn name` for functions, the whole `impl<..> Trait for Type where ..` for
    impls. Declarations ending in `;` before any `{` have no body and no span.
    """
    spans = []
    for m in ITEM_HEAD.finditer(masked):
        kind = m.group(1)
        brace = masked.find("{", m.end())
        semi = masked.find(";", m.end())
        if brace == -1 or (semi != -1 and semi < brace):
            continue
        if kind.startswith("impl"):
            label = " ".join(masked[m.start(1) : brace].split())
        else:
            label = " ".join(kind.split())
        spans.append((brace, match_brace(masked, brace), label))
    return spans


def item_path(spans, offset):
    """Enclosing items of `offset`, outermost first, joined with ` :: `."""
    enclosing = sorted((s for s in spans if s[0] <= offset < s[1]), key=lambda s: s[0])
    return " :: ".join(label for _, _, label in enclosing)


def census(path):
    src = Path(path).read_text(encoding="utf-8", errors="replace")
    masked = mask(src)
    starts = line_index(src)
    regions = test_regions(masked)
    first_cfg = None
    for m in CFG_ATTR.finditer(masked):
        i, depth = m.end() - 1, 0
        while i < len(masked):
            if masked[i] == "(":
                depth += 1
            elif masked[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if test_only(masked[m.end() : i]):
            first_cfg = line_of(starts, m.start())
            break

    spans = item_spans(masked)
    raw = [m.start() for m in re.finditer(re.escape(SYMBOL), src)]
    found = {"CALL": [], "IMPORT": [], "OTHER": []}
    shipped = {"CALL": [], "IMPORT": [], "OTHER": []}
    # Every CALL keyed by (enclosing item path, ordinal among CALLs in that
    # path), which is what the known-positive control is frozen against.
    call_keys, seen = {}, {}
    for off in [m.start() for m in re.finditer(re.escape(SYMBOL), masked)]:
        kind = classify(masked, off)
        ln = line_of(starts, off)
        found[kind].append(ln)
        if not in_region(regions, off):
            shipped[kind].append(ln)
        if kind == "CALL":
            where = item_path(spans, off)
            seen[where] = seen.get(where, 0) + 1
            call_keys[(where, seen[where])] = ln
    return {
        "path": path,
        "lines": src.count("\n") + 1,
        "raw_matches": len(raw),
        "masked_matches": sum(len(v) for v in found.values()),
        "first_test_cfg_line": first_cfg,
        "test_regions": len(regions),
        "all": found,
        "shipped": shipped,
        "call_keys": call_keys,
        "src_lines": src.split("\n"),
        "masked": masked,
        "starts": starts,
        "spans": spans,
    }


MOD_DECL = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?mod[ \t]+([A-Za-z_]\w*)[ \t]*;", re.M)
CFG_BODY = re.compile(r"#\s*\[\s*cfg\s*\((.*)\)\s*\]\s*$")
PATH_ATTR = re.compile(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]')


def _preceding_attrs(src, offset):
    """Raw attribute lines directly above the item at `offset`, nearest last.

    Read from RAW source, not masked text: `#[path = ".."]` keeps its target
    inside a string literal, which masking blanks.
    """
    attrs = []
    for line in reversed(src[:offset].split("\n")[:-1]):
        s = line.strip()
        if s.startswith("#[") or s.startswith("///") or s.startswith("//"):
            if s.startswith("#["):
                attrs.append(s)
            continue
        break
    return list(reversed(attrs))


def module_tree(root, is_mod_rs=True):
    """Every file one crate root reaches through out-of-line `mod x;` items.

    Returns (reached, unresolved): reached maps file -> (test_only, reason);
    unresolved lists declarations whose file does not exist. A file is
    TEST-ONLY when its own declaration carries a test-only cfg, when the
    declaration sits inside a test-only region of its parent, or when its
    parent is itself test-only. The last case is why a per-file census cannot
    see these: `#[cfg(test)] mod resuming;` makes all of resuming.rs test code,
    and nothing inside resuming.rs says so.
    """
    root = Path(root)
    reached, unresolved = {}, []
    queue = [(root, False, "crate root", root.parent if is_mod_rs else root.parent / root.stem)]
    while queue:
        path, inherited, reason, mod_dir = queue.pop()
        key = str(path)
        # A file declared more than once (for example `#[cfg(feature)] pub
        # mod x;` beside `#[cfg(all(not(feature), test))] mod x;`) is shipped
        # if ANY declaration is. Only a shipped reach may revisit a file, and
        # it re-walks the children so they are upgraded too. Keeping the first
        # reach instead made the answer depend on traversal order.
        if key in reached and (inherited or not reached[key][0]):
            continue
        reached[key] = (inherited, reason)
        src = path.read_text(encoding="utf-8", errors="replace")
        masked = mask(src)
        regions = test_regions(masked)
        spans = item_spans(masked)
        for m in MOD_DECL.finditer(masked):
            name = m.group(1)
            attrs = _preceding_attrs(src, m.start())
            gated = any(
                (c := CFG_BODY.match(a)) and test_only(c.group(1)) for a in attrs
            )
            in_test = in_region(regions, m.start())
            inline = [lab[4:] for lab in item_path(spans, m.start()).split(" :: ")
                      if lab.startswith("mod ")]
            explicit = next((p.group(1) for a in attrs if (p := PATH_ATTR.search(a))), None)
            if explicit is not None:
                base = path.parent.joinpath(*inline) if inline else path.parent
                candidates = [base / explicit]
            else:
                base = mod_dir.joinpath(*inline)
                candidates = [base / f"{name}.rs", base / name / "mod.rs"]
            child = next((c for c in candidates if c.is_file()), None)
            line = line_of(line_index(src), m.start())
            if child is None:
                unresolved.append(f"{path}:{line} mod {name}")
                continue
            test = inherited or gated or in_test
            why = ("inherited" if inherited else
                   f"declared at {path.name}:{line} under a test-only cfg" if gated else
                   f"declared at {path.name}:{line} inside a test-only region" if in_test else
                   f"declared at {path.name}:{line}")
            # A `mod.rs` file or a #[path] file is a directory owner, so its
            # children live beside it; `x.rs` owns the directory `x/`.
            child_dir = child.parent if (explicit is not None or child.name == "mod.rs") else child.parent / child.stem
            queue.append((child, test, why, child_dir))
    return reached, unresolved


def crate_roots(crate_dir):
    """(path, label) for the library and every binary target a manifest builds."""
    import tomllib
    crate_dir = Path(crate_dir)
    manifest = tomllib.loads((crate_dir / "Cargo.toml").read_text(encoding="utf-8"))
    roots = []
    lib = manifest.get("lib", {}).get("path", "src/lib.rs")
    if (crate_dir / lib).is_file():
        roots.append((crate_dir / lib, "lib"))
    bins = manifest.get("bin", [])
    explicit = {b.get("path") for b in bins}
    if (crate_dir / "src/main.rs").is_file() and "src/main.rs" not in explicit:
        roots.append((crate_dir / "src/main.rs", "bin (default)"))
    for b in bins:
        p = b.get("path") or f"src/bin/{b.get('name')}.rs"
        feats = b.get("required-features", [])
        label = f"bin {b.get('name')}" + (f" (required-features {feats})" if feats else "")
        if (crate_dir / p).is_file():
            roots.append((crate_dir / p, label))
    return roots


def workspace_census(crates_dir):
    """Production occurrences per crate, over every file its targets compile.

    A file is counted only if some target reaches it and it is not test-only
    by its declaration (see module_tree). Occurrences are CALL + IMPORT +
    OTHER, the population the FND-04 census counts; CALL is listed by site.
    Files under a crate's src/ that no target reaches are listed, never
    silently dropped, because an unreached file is not compiled.
    """
    crates_dir = Path(crates_dir)
    grand = {"CALL": 0, "IMPORT": 0, "OTHER": 0}
    for crate in sorted(p for p in crates_dir.iterdir() if (p / "Cargo.toml").is_file()):
        seen, test_files, unresolved = {}, {}, []
        for root, label in crate_roots(crate):
            reached, missing = module_tree(root)
            unresolved += missing
            for path, (test, why) in reached.items():
                if test:
                    test_files[path] = why
                else:
                    seen.setdefault(path, label)
        test_files = {p: w for p, w in test_files.items() if p not in seen}
        counts = {"CALL": 0, "IMPORT": 0, "OTHER": 0}
        sites = []
        for path in sorted(seen):
            shipped = census(path)["shipped"]
            for kind in counts:
                counts[kind] += len(shipped[kind])
            rel = str(Path(path).relative_to(crates_dir))
            sites += [f"{rel}:{line}" for line in shipped["CALL"]]
        hidden = sum(sum(len(v) for v in census(p)["shipped"].values()) for p in test_files)
        src_files = {str(p) for p in (crate / "src").rglob("*.rs")} if (crate / "src").is_dir() else set()
        orphans = sorted(src_files - set(seen) - set(test_files))
        for kind in grand:
            grand[kind] += counts[kind]
        total = sum(counts.values())
        print(f"{crate.name}: PRODUCTION {total} (CALL {counts['CALL']}, IMPORT {counts['IMPORT']}, "
              f"OTHER {counts['OTHER']}) over {len(seen)} files; test-only files {len(test_files)} "
              f"(per-file census would have counted {hidden} there)")
        for label in sorted({label for _, label in crate_roots(crate)}):
            print(f"  target: {label}")
        for site in sites:
            print(f"    CALL {site}")
        for p in orphans:
            print(f"  UNREACHED (not compiled by any target): {Path(p).relative_to(crates_dir)}")
        for u in unresolved:
            print(f"  UNRESOLVED mod declaration: {u}")
    print(f"\nTOTAL production block_on occurrences: {sum(grand.values())} "
          f"(CALL {grand['CALL']}, IMPORT {grand['IMPORT']}, OTHER {grand['OTHER']})")
    return 0


def run_controls(report):
    """R4's two controls against a proxy.rs census. Returns (ok, output lines).

    Shared by --validate and by the census gate, so the gate cannot pass on a
    weaker check than the one --validate reports.
    """
    out, ok = [], True
    shipped = set(report["shipped"]["CALL"])
    keys = report["call_keys"]

    out.append("R4 CONTROL 1 -- KNOWN POSITIVE: proxy.rs shipped block_on CALL sites, by symbol")
    resolved, missing, unshipped = [], [], []
    for key in PROXY_EXPECTED_CALLS:
        line = keys.get(key)
        if line is None:
            missing.append(key)
        elif line not in shipped:
            unshipped.append((key, line))
        else:
            resolved.append(line)
    out.append(f"  expected {len(PROXY_EXPECTED_CALLS)}, resolved and shipped {len(resolved)}")
    # R4's predicate is that the instrument FINDS the 18 and REJECTS the
    # import and doc comments. It does not say the 18 are the whole
    # population -- the bead itself calls them "the verified-by-position
    # floor". So a miss is a control failure and an extra is a finding.
    for key in missing:
        ok = False
        out.append(f"  FAIL -- MISSING (the control case it should catch): {key[0]} #{key[1]}")
    for key, line in unshipped:
        ok = False
        out.append(f"  FAIL -- FOUND BUT CLASSIFIED TEST-ONLY: {key[0]} #{key[1]} at :{line}")
    if not missing and not unshipped:
        out.append(f"  all {len(PROXY_EXPECTED_CALLS)} baseline sites found: sensitivity established")
        out.append(f"  now at lines {resolved}")
    extra = sorted(shipped - set(resolved))
    if extra:
        out.append(f"\n  BEYOND THE BASELINE -- {len(extra)} further SHIPPED call sites: {extra}")
        out.append(f"  The first test-only cfg is at line {report['first_test_cfg_line']}; sites past it")
        out.append("  are invisible to a positional rule. They are feature-gated, NOT")
        out.append("  test-gated, so they are shipped code. Requires adjudication by the")
        out.append("  criteria author: R1's end state is positional, R5's guard is total.")

    out.append("\nR4 CONTROL 2 -- KNOWN NEGATIVE: the import and the two doc comments, by content")
    masked, starts = report["masked"], report["starts"]
    imports = [m for m in PROXY_IMPORT_STMT.finditer(masked)
               if not item_path(report["spans"], m.start())]
    if len(imports) != 1:
        ok = False
        out.append(f"  FAIL: expected exactly 1 top-level `use` naming {SYMBOL}, found {len(imports)}")
    else:
        stmt = imports[0]
        sym = stmt.start() + re.search(rf"\b{SYMBOL}\b", stmt.group(0)).start()
        line = line_of(starts, sym)
        if line in report["all"]["CALL"]:
            ok = False
            out.append(f"  FAIL: the import at :{line} is counted as a CALL")
        elif line not in report["all"]["IMPORT"]:
            ok = False
            out.append(f"  FAIL: the import at :{line} is not classified IMPORT")
        else:
            out.append(f"  :{line} import  -> classified IMPORT, not a CALL")
    trimmed = [s.strip() for s in report["src_lines"]]
    for doc in PROXY_EXPECTED_DOCS:
        at = [i + 1 for i, s in enumerate(trimmed) if s == doc]
        if len(at) != 1:
            ok = False
            out.append(f"  FAIL: doc anchor resolves to {len(at)} lines, not 1: {doc!r}")
            continue
        if any(at[0] in v for v in report["all"].values()):
            ok = False
            out.append(f"  FAIL: doc comment :{at[0]} survived masking")
        else:
            out.append(f"  :{at[0]} doc comment -> removed by masking, never classified")
    return ok, out


def naive_regions(src):
    """Deliberately wrong control: brace matching with no lexical masking."""
    regions = []
    for m in CFG_ATTR.finditer(src):
        brace = src.find("{", m.end())
        if brace == -1:
            continue
        regions.append((m.start(), match_brace(src, brace)))
    return regions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", help="source files (default: the bead's four)")
    parser.add_argument("--validate", action="store_true", help="R4 positive+negative controls")
    parser.add_argument("--naive-control", metavar="FILE", help="show the unmasked over-count")
    parser.add_argument("--proxy", metavar="FILE",
                        help="run the controls against this proxy.rs (planted-control demonstrations)")
    parser.add_argument("--workspace", action="store_true",
                        help="census every crate's module tree, resolving out-of-line `mod x;` cfg")
    parser.add_argument("--crates", metavar="DIR",
                        help="crates directory for --workspace (default: the repo's; planted fixtures)")
    args = parser.parse_args()

    if args.naive_control:
        src = Path(args.naive_control).read_text(encoding="utf-8", errors="replace")
        good = len(test_regions(mask(src)))
        bad = len(naive_regions(src))
        ratio = (bad / good) if good else float("inf")
        print(f"{args.naive_control}")
        print(f"  masked (correct) test regions : {good}")
        print(f"  unmasked (naive) test regions : {bad}")
        print(f"  over-count factor             : {ratio:.2f}x")
        return 0

    proxy = Path(args.proxy) if args.proxy else REPO / PROXY
    if args.validate:
        report = census(proxy)
        ok, lines = run_controls(report)
        print("\n".join(lines))
        print(f"\n  raw grep matches {report['raw_matches']} = "
              f"CALL {len(report['all']['CALL'])} + IMPORT {len(report['all']['IMPORT'])} "
              f"+ OTHER {len(report['all']['OTHER'])} + "
              f"{report['raw_matches'] - report['masked_matches']} in comments/strings")
        print(f"\nR4 VERDICT: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1

    # A zero from this instrument is the answer most likely to be wrong and
    # least likely to look wrong -- the first version of it reported lib.rs = 0
    # because it treated `any(feature, test)` as test-only. So the census
    # refuses to print ANY count until the known-positive arm has passed in
    # this same invocation. R4 requires the control be run; this makes it
    # impossible to read a number that the control did not stand behind.
    ok, lines = run_controls(census(proxy))
    if not ok:
        print("R4 CONTROL FAILED -- no counts reported.", file=sys.stderr)
        for line in lines:
            if "FAIL" in line:
                print(line, file=sys.stderr)
        print("  Run --validate for the full control output.", file=sys.stderr)
        return 2
    print(f"control: {len(PROXY_EXPECTED_CALLS)}/{len(PROXY_EXPECTED_CALLS)} frozen proxy.rs "
          f"sites found by symbol; the import and both doc comments excluded\n")

    if args.workspace:
        return workspace_census(Path(args.crates) if args.crates else REPO / "crates")

    targets = args.files or [str(REPO / f) for f in BEAD_FILES]
    total = 0
    for path in targets:
        r = census(path)
        rel = str(Path(path)).replace(str(REPO) + "/", "")
        shipped_calls = r["shipped"]["CALL"]
        total += len(shipped_calls)
        print(f"{rel}")
        print(f"  lines {r['lines']}, test regions {r['test_regions']}, "
              f"first test cfg at line {r['first_test_cfg_line']}")
        print(f"  raw matches {r['raw_matches']}  ->  "
              f"CALL {len(r['all']['CALL'])} / IMPORT {len(r['all']['IMPORT'])} "
              f"/ OTHER {len(r['all']['OTHER'])}")
        print(f"  SHIPPED CALL sites: {len(shipped_calls)}")
        if shipped_calls:
            print(f"    {shipped_calls}")
        if r["shipped"]["OTHER"]:
            print(f"  shipped OTHER (not counted): {r['shipped']['OTHER']}")
    print(f"\nTOTAL shipped block_on CALL sites: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
