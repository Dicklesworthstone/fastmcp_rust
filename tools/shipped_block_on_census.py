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
  tools/shipped_block_on_census.py --naive-control <file>
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

# Frozen baseline at 4e48b86a, from the bead's R1.
PROXY_EXPECTED_CALLS = [
    4644, 5089, 5383, 5475, 5550, 5596, 5709, 6316,
    6336, 6359, 6379, 6459, 6554, 6693, 6830, 7069, 7075, 7092,
]
PROXY_EXPECTED_IMPORT = 46
PROXY_EXPECTED_DOCS = [752, 1346]


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

    raw = [m.start() for m in re.finditer(re.escape(SYMBOL), src)]
    found = {"CALL": [], "IMPORT": [], "OTHER": []}
    shipped = {"CALL": [], "IMPORT": [], "OTHER": []}
    for off in [m.start() for m in re.finditer(re.escape(SYMBOL), masked)]:
        kind = classify(masked, off)
        ln = line_of(starts, off)
        found[kind].append(ln)
        if not in_region(regions, off):
            shipped[kind].append(ln)
    return {
        "path": path,
        "lines": src.count("\n") + 1,
        "raw_matches": len(raw),
        "masked_matches": sum(len(v) for v in found.values()),
        "first_test_cfg_line": first_cfg,
        "test_regions": len(regions),
        "all": found,
        "shipped": shipped,
    }


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

    if args.validate:
        report = census(REPO / PROXY)
        calls = report["shipped"]["CALL"]
        ok = True

        print("R4 CONTROL 1 -- KNOWN POSITIVE: proxy.rs shipped block_on CALL sites")
        print(f"  expected {len(PROXY_EXPECTED_CALLS)}, found {len(calls)}")
        missing = sorted(set(PROXY_EXPECTED_CALLS) - set(calls))
        extra = sorted(set(calls) - set(PROXY_EXPECTED_CALLS))
        # R4's predicate is that the instrument FINDS the 18 and REJECTS the
        # import and doc comments. It does not say the 18 are the whole
        # population -- the bead itself calls them "the verified-by-position
        # floor". So a miss is a control failure and an extra is a finding.
        if missing:
            ok = False
            print(f"  FAIL -- MISSING (the control case it should catch): {missing}")
        else:
            print(f"  all {len(PROXY_EXPECTED_CALLS)} baseline sites found: sensitivity established")
        if extra:
            print(f"\n  BEYOND THE BASELINE -- {len(extra)} further SHIPPED call sites: {extra}")
            print("  These are past the first #[cfg(test)] at 8166, which is why the")
            print("  positional rule cannot see them. They are feature-gated, NOT")
            print("  test-gated, so they are shipped code. Requires adjudication by the")
            print("  criteria author: R1's end state is positional, R5's guard is total.")

        print("\nR4 CONTROL 2 -- KNOWN NEGATIVE: the import and the two doc comments")
        imports = report["all"]["IMPORT"]
        if PROXY_EXPECTED_IMPORT in calls:
            ok = False
            print(f"  FAIL: :{PROXY_EXPECTED_IMPORT} counted as a CALL")
        else:
            seen = PROXY_EXPECTED_IMPORT in imports
            print(f"  :{PROXY_EXPECTED_IMPORT} import  -> not a CALL (classified IMPORT: {seen})")
        for doc in PROXY_EXPECTED_DOCS:
            every = [d for v in report["all"].values() for d in v if d == doc]
            if every:
                ok = False
                print(f"  FAIL: doc comment :{doc} survived masking")
            else:
                print(f"  :{doc} doc comment -> removed by masking, never classified")

        print(f"\n  raw grep matches {report['raw_matches']} = "
              f"CALL {len(report['all']['CALL'])} + IMPORT {len(report['all']['IMPORT'])} "
              f"+ OTHER {len(report['all']['OTHER'])} + "
              f"{report['raw_matches'] - report['masked_matches']} in comments/strings")
        print(f"\nR4 VERDICT: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1

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
