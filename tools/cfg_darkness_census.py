#!/usr/bin/env python3
"""Attribute every #[test] site to a feature-darkness class, with inline controls.

Produced for AC-6O8CC-02' axis 2 (bd-6o8cc). Measures CLASS 3 (enclosing-item cfg
naming a feature, at any depth) and CLASS 4 (per-fn cfg naming a feature). It does
NOT measure class 1 (target required-features) or class 2 (file-scope `#![cfg]`) --
those are target- and file-level properties that do not attach to a #[test] site the
way 3 and 4 do.

WHY THIS FILE EXISTS RATHER THAN A PIPELINE. The first version of this measurement
was an ad-hoc heredoc and it reported CLASS 3 = 6423 of 9194 -- 70% of every test in
the workspace. The cause: nearly every unit test lives inside `#[cfg(test)] mod
tests`, which is an enclosing-item cfg but is NOT feature darkness. Restricting the
predicate to enclosures naming `feature =` moves 6423 to 308. A number that wrong,
produced by a script nobody can re-run, is not evidence. This file is the same
measurement made reviewable.

CONTROLS ARE NOT OPTIONAL. Both run in this same invocation before any count is
printed, and a failure exits non-zero with nothing reported:
  POSITIVE  crates/fastmcp-cli/tests/e2e_cli.rs must show >0 enclosing-FEATURE-cfg
            tests (mod authenticated_http, mod task_commands). Proves sensitivity.
  NEGATIVE  a file with zero cfg-gated mods must report zero. Proves it does not
            invent them.
Masking of strings and comments happens before any parsing, so an attribute inside a
literal or doc comment cannot be counted. Omitting that masking gave a sibling census
a 30x over-count.

PRECEDENCE IS A PARAMETER, NOT A FACT. A test carrying BOTH an enclosing feature cfg
and a per-fn feature cfg is attributed to whichever --precedence names. The criterion
requires each occurrence to land in EXACTLY ONE class; the ordering belongs to the
criterion's author, not to this script. Default is `enclosing`.
"""

from __future__ import annotations

import argparse
import glob
import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FEATURE = re.compile(r"feature\s*=")
CFG_ATTR = re.compile(r"#\[\s*cfg")
TEST_ATTR = re.compile(r"#\[\s*test\s*\]")
MOD_OPEN = re.compile(r"(pub(\(.*?\))?\s+)?mod\s+\w+")

POSITIVE_CONTROL = "crates/fastmcp-cli/tests/e2e_cli.rs"


def mask(src: str) -> str:
    """Blank string and line-comment content, preserving length and newlines.

    Everything downstream runs on the masked text, so no attribute inside a
    literal or a comment can be classified.
    """
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == '"':
            out.append('"')
            i += 1
            while i < n:
                if src[i] == "\\":
                    out.append("  ")
                    i += 2
                    continue
                if src[i] == '"':
                    out.append('"')
                    i += 1
                    break
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            continue
        if src.startswith("//", i):
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def analyze(path: Path) -> list[tuple[bool, bool, bool]]:
    """Return (enclosing_feature, enclosing_any_cfg, per_fn_feature) per #[test]."""
    src = mask(path.read_text(encoding="utf-8", errors="replace"))
    stack: list[tuple[int, str | None]] = []
    depth = 0
    pending: str | None = None
    found: list[tuple[bool, bool, bool]] = []
    for line in src.splitlines():
        s = line.strip()
        if CFG_ATTR.match(s):
            pending = s
            continue
        if TEST_ATTR.match(s):
            enc_feat = any(bool(h and FEATURE.search(h)) for _, h in stack)
            enc_any = any(bool(h) for _, h in stack)
            found.append((enc_feat, enc_any, bool(pending and FEATURE.search(pending))))
            pending = None
            continue
        if MOD_OPEN.match(s) and "{" in line:
            stack.append((depth, pending))
            pending = None
        depth += line.count("{") - line.count("}")
        while stack and depth <= stack[-1][0]:
            stack.pop()
        if s and not s.startswith("#["):
            pending = None
    return found


def run_controls() -> None:
    pos = REPO / POSITIVE_CONTROL
    if not pos.exists():
        print(f"CONTROL FAIL -- positive-control file missing: {POSITIVE_CONTROL}", file=sys.stderr)
        sys.exit(2)
    rows = analyze(pos)
    seen = sum(1 for enc_feat, _, _ in rows if enc_feat)
    print(f"CONTROL 1 -- POSITIVE: {POSITIVE_CONTROL}")
    print(f"  #[test] sites {len(rows)}, with an enclosing FEATURE cfg: {seen}")
    if seen == 0:
        print("  FAIL -- blind to enclosing feature cfg; its zeros mean nothing.", file=sys.stderr)
        sys.exit(2)
    print("  sensitivity established")

    neg = None
    for candidate in sorted(glob.glob(str(REPO / "crates/*/tests/*.rs"))):
        text = Path(candidate).read_text(encoding="utf-8", errors="replace")
        if "#[test]" not in text:
            continue
        if re.search(r"#\[\s*cfg[^\]]*\]\s*\n\s*(pub(\(.*?\))?\s+)?mod\b", text):
            continue
        rows = analyze(Path(candidate))
        if rows and not any(enc for enc, _, _ in rows):
            neg = (candidate, len(rows))
            break
    print("CONTROL 2 -- NEGATIVE: a file with no cfg-gated mod")
    if neg is None:
        print("  FAIL -- no negative-control specimen found; cannot show it avoids false positives.", file=sys.stderr)
        sys.exit(2)
    rel = Path(neg[0]).relative_to(REPO)
    print(f"  {rel}: {neg[1]} #[test] sites, 0 enclosing-cfg -- does not invent them")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--precedence",
        choices=("enclosing", "per-fn"),
        default="enclosing",
        help="which class wins when a test carries BOTH an enclosing and a per-fn feature cfg",
    )
    ap.add_argument("--by-file", action="store_true", help="print class-3 concentration by file")
    args = ap.parse_args()

    run_controls()
    print()

    total = c3 = c4 = cfg_no_feature = 0
    by_file: Counter[str] = Counter()
    files = glob.glob(str(REPO / "crates/**/*.rs"), recursive=True)
    files += glob.glob(str(REPO / "tools/**/*.rs"), recursive=True)
    for f in files:
        try:
            rows = analyze(Path(f))
        except OSError:
            continue
        for enc_feat, enc_any, per_fn in rows:
            total += 1
            if enc_feat and per_fn:
                if args.precedence == "enclosing":
                    c3 += 1
                    by_file[f] += 1
                else:
                    c4 += 1
            elif enc_feat:
                c3 += 1
                by_file[f] += 1
            elif per_fn:
                c4 += 1
            elif enc_any:
                cfg_no_feature += 1

    print(f"ATTRIBUTION over {total} #[test] sites   (precedence: {args.precedence})")
    print(f"  CLASS 3  enclosing cfg naming a FEATURE : {c3}")
    print(f"  CLASS 4  per-fn cfg naming a FEATURE    : {c4}")
    print(f"  enclosed by a cfg with NO feature       : {cfg_no_feature}  <- mostly #[cfg(test)] mod tests; NOT feature-dark")
    print(f"  ungated at fn and mod level             : {total - c3 - c4 - cfg_no_feature}")
    print()
    print("NOT MEASURED HERE: class 1 (target required-features) and class 2 (file-scope #![cfg]).")
    print("The denominator above is every statically visible #[test] site in this workspace; it is")
    print("NOT the bead's denominator, which its owner has not yet fixed.")

    if args.by_file:
        print()
        print("class-3 concentration:")
        for f, n in by_file.most_common(10):
            print(f"  {n:>5}  {Path(f).relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
