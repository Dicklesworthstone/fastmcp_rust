#!/usr/bin/env python3
"""Attribute every #[test] site to a CROSS-FILE feature-darkness class.

Produced for AC-6O8CC-02' axis 2 (bd-6o8cc), as the missing half of
`tools/cfg_darkness_census.py`, which measures classes 3 and 4 WITHIN one file
and states:

    "It does NOT measure class 1 (target required-features) or class 2
     (file-scope `#![cfg]`) -- those are target- and file-level properties
     that do not attach to a #[test] site the way 3 and 4 do."

THAT REASON DOES NOT HOLD, and the counterexample is measurable. Rust gates
propagate across files through the module tree, so all three of these attach to
a site in some other file:

    class 1  a target's `required-features` gate every site the target compiles
    class 2  a file-scope `#![cfg]` gates every site in every module that file
             declares, transitively
    class 3  a `#[cfg(feature=..)]` on a `mod x;` DECLARATION gates every site
             in x.rs and below -- 02' says "any cfg on a `mod` or other item
             enclosing the test, at ANY DEPTH", and a declaration in another
             file is exactly that

`cfg_darkness_census.analyze` walks one file's brace stack, so it cannot see any
of the three. This file resolves the module tree first and attributes on it.

  WORKED EXAMPLE, and it is the positive control below.
  crates/fastmcp-client/tests/oauth_interaction.rs holds 14 `#[test]` of its own.
  It reaches 15 files and 223 sites. Of those, 96 sit under six
  `#[cfg(feature = "tasks")]` mod declarations in driver.rs, in files that carry
  no cfg of their own. A file-local reading sees 14 and misses 209.

SEMANTICS THAT ARE NOT OBVIOUS AND ARE LOAD-BEARING:

  A SITE CAN BE REACHED BY SEVERAL TARGETS, and by several paths within one
  target, because `#[path]` lets two parents include one file. Darkness is a
  property of the SITE: it is dark only when EVERY reaching path is gated. One
  ungated path makes the site visible in a default build. Merging is therefore
  AND, never OR, and a revisit can only ever weaken a gate.

  A SITE REACHED BY NO TARGET IS NOT DARK, AND IT IS NOT FINE EITHER. It is
  never compiled, for a reason that is neither feature nor platform. 02' has no
  cell for it, so it is reported separately rather than folded into "not dark",
  which would assert it is built when it is not.

  PRECEDENCE IS THE CRITERION AUTHOR'S, NOT THIS SCRIPT'S. Attribution is
  outermost-wins, 1 > 2 > 3, because that is the blast-radius order. Ties cannot
  arise between these three: each class is only evaluated on sites the previous
  one did not take.

CONTROLS RUN BEFORE ANY COUNT IS PRINTED and a failure exits non-zero with
nothing reported. The class-2/3 positive is tied to runs that actually executed
on the lane, not to source alone, and it recomputes both of its terms rather
than comparing frozen constants -- an earlier hand-derivation of this same
reconciliation balanced exactly while being wrong in BOTH terms, because it
dropped one 12-site module from the total and from the gated subset at once.

Site counting is imported from cfg_darkness_census so the denominator here is
the same site set that tool counts, not a second opinion about it.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cfg_darkness_census import FEATURE, analyze, mask  # noqa: E402

REPO = Path(__file__).resolve().parent.parent

# One `mod x;` declaration with the attributes immediately above it. Anchored to
# a line start so a `mod x;` inside a string literal is not a declaration.
# Run over COMMENT-stripped source, NEVER over cfg_darkness_census.mask(), which
# blanks string CONTENT and would erase every `#[path]` argument -- the first
# version of this file did exactly that, and its own control caught it by
# reporting 14 sites for a target that has 223.
MOD_DECL = re.compile(
    r"^[ \t]*(?P<attrs>(?:#\[[^\n]*\][ \t]*\n[ \t]*)*)"
    r"(?:pub(?:\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_]\w*)\s*;",
    re.M,
)
PATH_ATTR = re.compile(r'#\[\s*path\s*=\s*"([^"]+)"\s*\]')
CFG_ATTR = re.compile(r"#\[\s*cfg\((?P<pred>.*)\)\s*\]")
INNER_CFG = re.compile(r"^\s*#!\[\s*cfg\((?P<pred>.*)\)\s*\]\s*$", re.M)

AUTO_DIRS = (("tests", "test"), ("examples", "example"), ("benches", "bench"))


def strip_comments(src: str) -> str:
    """Blank `//` comments only, preserving length, newlines and string content."""
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        if src.startswith("//", i):
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        out.append(src[i])
        i += 1
    return "".join(out)


def members() -> list[Path]:
    root = tomllib.loads((REPO / "Cargo.toml").read_text())
    return [REPO / m for m in root["workspace"]["members"]]


def default_closure(features: dict) -> set[str]:
    """Features active in a plain `cargo build` of this package."""
    active: set[str] = set()
    queue = list(features.get("default", []))
    while queue:
        name = queue.pop().split("/", 1)[0].removeprefix("dep:").removesuffix("?")
        if not name or name in active:
            continue
        active.add(name)
        queue.extend(features.get(name, []))
    return active


def targets(crate: Path) -> list[dict]:
    """Every compilable target of one package, explicit stanzas and auto-discovered."""
    manifest = tomllib.loads((crate / "Cargo.toml").read_text())
    closure = default_closure(manifest.get("features", {}))
    out: list[dict] = []
    declared: set[Path] = set()

    # A target only makes a #[test] DISCOVERABLE if it carries a libtest harness.
    # Cargo defaults `test` to true for lib/bin/test targets and FALSE for
    # examples and benches. An example that compiles a file does not register its
    # tests, so it cannot clear that file's darkness -- and this repo says so out
    # loud: both `#[path]` includers of fnd_01_dependency_evidence.rs are examples
    # carrying `test = false` with the comment "never execute it as an example
    # test harness". Counting them as reachers made a genuinely class-1 file read
    # as not dark at all.
    HARNESS_BY_DEFAULT = {"lib": True, "bin": True, "test": True, "example": False, "bench": False}

    def add(kind: str, name: str, path: Path, required: list[str], stanza: dict | None = None) -> None:
        if not (stanza or {}).get("test", HARNESS_BY_DEFAULT[kind]):
            return
        if path.is_file():
            # A required feature outside the default closure makes the whole
            # target absent from a default build.
            out.append(
                {
                    "package": manifest["package"]["name"],
                    "kind": kind,
                    "name": name,
                    "root": path,
                    "gated": sorted(set(required) - closure),
                }
            )

    subdir = {"test": "tests", "bin": "src/bin", "example": "examples", "bench": "benches"}
    for key in ("test", "bin", "example", "bench"):
        for stanza in manifest.get(key, []) or []:
            rel = stanza.get("path") or f"{subdir[key]}/{stanza['name']}.rs"
            path = (crate / rel).resolve()
            declared.add(path)
            add(key, stanza["name"], path, stanza.get("required-features", []), stanza)

    lib = manifest.get("lib", {})
    lib_path = (crate / lib.get("path", "src/lib.rs")).resolve()
    if lib_path.is_file() and lib_path not in declared:
        add("lib", manifest["package"]["name"], lib_path, lib.get("required-features", []), lib)
    main = (crate / "src/main.rs").resolve()
    if main.is_file() and main not in declared:
        add("bin", manifest["package"]["name"], main, [])
    # Cargo auto-discovers BOTH `tests/<name>.rs` and `tests/<name>/main.rs`.
    # Globbing only the first shape is the same error as scoping a population to
    # `[[test]]` stanzas: it enumerates one shape of target and calls it the set.
    # crates/fastmcp-console/tests/e2e/main.rs is the specimen -- 48 sites that
    # read as "never compiled" until the second shape is included.
    for sub, kind in AUTO_DIRS:
        for path in sorted((crate / sub).glob("*.rs")):
            if path.resolve() not in declared:
                add(kind, path.stem, path.resolve(), [])
        for path in sorted((crate / sub).glob("*/main.rs")):
            if path.resolve() not in declared:
                add(kind, path.parent.name, path.resolve(), [])
    for path in sorted((crate / "src/bin").glob("*/main.rs")):
        if path.resolve() not in declared:
            add("bin", path.parent.name, path.resolve(), [])
    return out


def walk(root: Path) -> dict[Path, dict]:
    """Every file a target compiles, with the gates inherited from its chain.

    Returns {file: {"decl_cfg": bool, "file_cfg": bool}} where each flag is TRUE
    only when EVERY path reaching the file carries that gate. Merging is AND, so
    a second, ungated path to the same file correctly clears the flag.
    """
    reached: dict[Path, dict] = {}
    stack: list[tuple[Path, bool, bool]] = [(root.resolve(), False, False)]
    while stack:
        cur, decl_gated, file_gated = stack.pop()
        if not cur.is_file():
            continue
        # The two gates are INDEPENDENT. Folding the declaration gate into the
        # file gate makes every site under a cfg'd `mod` look file-scoped, and
        # class 3 then reports zero -- which is how the control caught it.
        own = file_scope_feature(cur) is not None
        state = {"decl_cfg": decl_gated, "file_cfg": own or file_gated}
        prev = reached.get(cur)
        if prev is not None:
            merged = {k: prev[k] and state[k] for k in state}
            if merged == prev:
                continue  # nothing weakened; do not re-expand
            state = merged
        reached[cur] = state
        src = strip_comments(cur.read_text(encoding="utf-8", errors="replace"))
        base = cur.parent / cur.stem
        for m in MOD_DECL.finditer(src):
            attrs, name = m.group("attrs") or "", m.group("name")
            explicit = PATH_ATTR.search(attrs)
            cfg = CFG_ATTR.search(attrs)
            gated = state["decl_cfg"] or bool(cfg and FEATURE.search(cfg.group("pred")))
            if explicit:
                candidates = [cur.parent / explicit.group(1)]
            else:
                candidates = [base / f"{name}.rs", base / name / "mod.rs"]
                if cur.name in ("lib.rs", "main.rs", "mod.rs"):
                    candidates = [cur.parent / f"{name}.rs", cur.parent / name / "mod.rs"] + candidates
            for cand in candidates:
                cand = cand.resolve()
                if cand.is_file():
                    stack.append((cand, gated, state["file_cfg"]))
                    break
    return reached


_FILE_CFG: dict[Path, str | None] = {}


def file_scope_feature(path: Path) -> str | None:
    """The file's own `#![cfg(..)]` when it names a feature."""
    if path not in _FILE_CFG:
        src = mask(path.read_text(encoding="utf-8", errors="replace"))
        hit = next(
            (m.group("pred").strip() for m in INNER_CFG.finditer(src) if FEATURE.search(m.group("pred"))),
            None,
        )
        _FILE_CFG[path] = hit
    return _FILE_CFG[path]


def census() -> dict:
    """Map every site to its classes, AND-merged across every reaching target."""
    per_file: dict[Path, list[dict]] = defaultdict(list)
    owner: dict[Path, dict] = {}
    for crate in members():
        if not (crate / "Cargo.toml").is_file():
            continue
        for tgt in targets(crate):
            for path, state in walk(tgt["root"]).items():
                per_file[path].append({"target": tgt, **state})
                owner.setdefault(path, tgt)

    counts = dict.fromkeys(
        ("class1", "class2", "class3_xfile", "class3_infile", "class4", "not_dark", "unreached"), 0
    )
    detail: dict[str, dict[str, int]] = {k: defaultdict(int) for k in counts}
    inner_decl: dict[str, int] = defaultdict(int)
    instance: dict[str, str] = {}
    by_target: dict[str, int] = defaultdict(int)
    files = sorted({p.resolve() for p in REPO.glob("crates/**/*.rs")} | {p.resolve() for p in REPO.glob("tools/**/*.rs")})
    for path in files:
        sites = len(analyze(path))
        if not sites:
            continue
        reachers = per_file.get(path)
        if not reachers:
            counts["unreached"] += sites
            detail["unreached"][str(path.relative_to(REPO))] += sites
            continue
        t = owner[path]
        tag = f"{t['package']}:{t['kind']}:{t['name']}"
        if all(r["target"]["gated"] for r in reachers):
            key = "class1"
        elif all(r["file_cfg"] for r in reachers if not r["target"]["gated"]):
            key = "class2"
        elif all(r["decl_cfg"] for r in reachers if not r["target"]["gated"]):
            key = "class3_xfile"
        else:
            # Only here can cfg_darkness_census speak: no outer gate took this
            # file, so its sites are governed by in-file enclosing and per-fn
            # cfgs alone. Precedence 3 > 4 within the file, as 02' orders them.
            enc = fn = 0
            for enc_feat, _enc_any, fn_feat in analyze(path):
                bucket = "class3_infile" if enc_feat else "class4" if fn_feat else "not_dark"
                counts[bucket] += 1
                detail[bucket][tag] += 1
                enc += enc_feat
                fn += bool(fn_feat) and not enc_feat
            instance[str(path.relative_to(REPO))] = f"class3_infile={enc}" if enc else f"class4>={fn}"
            if all(r["decl_cfg"] for r in reachers if not r["target"]["gated"]):
                inner_decl[tag] += sites
            by_target[tag] += sites
            continue
        counts[key] += sites
        detail[key][tag] += sites
        instance[str(path.relative_to(REPO))] = key
        # Attribution keeps only the OUTERMOST gate; a run is governed by ALL of
        # them. Tally the inner declaration gate separately so the control can
        # predict a discovered count that attribution alone cannot.
        if all(r["decl_cfg"] for r in reachers if not r["target"]["gated"]):
            inner_decl[tag] += sites
        by_target[tag] += sites
    return {"counts": counts, "detail": detail, "inner_decl": inner_decl,
            "by_target": by_target, "instance": instance}


# The oauth_interaction target, run twice on the lane on 2026-09-21:
#   no features       -> `ok. 0 passed`   (the whole target dark: class 2)
#   native-tls-roots  -> 127 discovered   (the tasks subtree still dark: class 3)
CONTROL_TARGET = "fastmcp-client:test:oauth_interaction"
CONTROL_DISCOVERED = 127
CONTROL_NEGATIVE = "fastmcp-client:test:clt_01_executor"

# Instances that were EXECUTED on the lane earlier in bd-6o8cc, each re-derived
# here rather than carried forward on its label. A taxonomy selects its own
# population, so "class 3 under the old classifier" and "class 3 under this one"
# share a name, not a referent; these rows are what make the transfer provable.
# The class-3 count is anchored to a run (hz4 feature-off vs C2-B feature-on
# moved exactly these 7). The class-4 file's tenth per-fn site is real but was
# correctly absent from BOTH arms of its run -- all(not(legacy), ws) with legacy
# default-on -- which is why that run's differential was 9 and this is `>= 9`.
EXECUTED_INSTANCES = (
    ("crates/fastmcp/tests/fnd_01_dependency_evidence.rs", "class1",
     "class 1 -- hz3, the whole target vanishes without `testing-lab`"),
    ("crates/fastmcp-client/tests/http_03_b_runtime.rs", "class3_infile=7",
     "class 3 -- the 7 `mod authenticated_tls` tests, absent in hz4 and present in C2-B"),
    ("crates/fastmcp/src/lib.rs", "class4>=9",
     "class 4 -- the pre-registered differential of 9 per-fn feature sites"),
)


def run_controls(result: dict) -> None:
    d = result["detail"]
    dark = d["class2"].get(CONTROL_TARGET, 0)
    gated = result["inner_decl"].get(CONTROL_TARGET, 0)
    total = result["by_target"].get(CONTROL_TARGET, 0)
    if not dark:
        sys.exit(f"CONTROL FAILED (class 2 positive): {CONTROL_TARGET} contributed no class-2 sites")
    if not gated:
        sys.exit(f"CONTROL FAILED (inner declaration gate): {CONTROL_TARGET} showed none")
    if dark != total:
        sys.exit(f"CONTROL FAILED (attribution): {dark} of {total} sites took class 2; outermost-wins requires all")
    # Both terms are recomputed; neither is a frozen constant. The executed run
    # is the only fixed number, and it is what the classifier must reproduce.
    if total - gated != CONTROL_DISCOVERED:
        sys.exit(
            f"CONTROL FAILED (reconciliation): {total} sites - {gated} behind a cfg'd mod "
            f"declaration = {total - gated}, but the lane discovered {CONTROL_DISCOVERED}"
        )
    if d["class2"].get(CONTROL_NEGATIVE, 0) or result["inner_decl"].get(CONTROL_NEGATIVE, 0):
        sys.exit(f"CONTROL FAILED (negative): ungated {CONTROL_NEGATIVE} was attributed a gate")

    # 02' requires one EXECUTED instance per class, checked before output is used.
    # Classes 2 and 3-cross-file are covered above. These three re-derive the
    # remaining executed instances from earlier in this bead, so a future edit
    # that silently reclassifies one of them fails here instead of in a receipt.
    for path, want, why in EXECUTED_INSTANCES:
        got = result["instance"].get(path)
        ok = got == want
        if not ok and want.count(">=") == 1 and isinstance(got, str) and got.startswith(want.split(">=")[0]):
            # A floor, not an equality: the run demonstrated at least this many.
            ok = int(got.rsplit(">=", 1)[-1].lstrip("=")) >= int(want.rsplit(">=", 1)[-1])
        if not ok:
            sys.exit(f"CONTROL FAILED (executed instance): {path} was {why}, classifier now says {got}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--detail", type=int, default=0, help="show the N largest contributors per class")
    args = ap.parse_args()

    result = census()
    run_controls(result)
    c = result["counts"]
    total = sum(c.values())

    print("AC-6O8CC-02' axis 2 -- CROSS-FILE classes, attributed per site over the module tree.")
    print(f"  class 1  target required-features outside the package default closure : {c['class1']}")
    print(f"  class 2  file-scope #![cfg(feature=..)] on the site's chain           : {c['class2']}")
    print(f"  class 3  cfg(feature=..) on a `mod` DECLARATION in an ancestor file   : {c['class3_xfile']}")
    print(f"  class 3  cfg(feature=..) on an enclosing item IN THE SAME FILE        : {c['class3_infile']}")
    print(f"  class 4  cfg(feature=..) on the test fn itself                        : {c['class4']}")
    print(f"  NOT feature-dark                                                      : {c['not_dark']}")
    print(f"  reached by NO target -- never compiled; 02' has no cell for this      : {c['unreached']}")
    print(f"  TOTAL sites                                                           : {total}")
    dark = c["class1"] + c["class2"] + c["class3_xfile"] + c["class3_infile"] + c["class4"]
    print()
    print(f"  FEATURE-DARK {dark} of {total}  ({100 * dark / total:.1f}%), class 3 = "
          f"{c['class3_xfile']} cross-file + {c['class3_infile']} in-file = "
          f"{c['class3_xfile'] + c['class3_infile']}")
    print("  The classes sum to the denominator, which is 02's predicate.")
    for key in ("class1", "class2", "class3_xfile", "class3_infile", "class4", "unreached"):
        if args.detail:
            print(f"\n  largest {key} contributors:")
            for k, v in sorted(result["detail"][key].items(), key=lambda kv: -kv[1])[: args.detail]:
                print(f"    {v:6}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
