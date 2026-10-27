#!/usr/bin/env python3
"""Keep every commit revision cited in the tracker readable, and refuse when one is not.

WHY THIS EXISTS, in the terms AGENTS.md requires of anything that is not
product code:

  consumer          `scripts/verify_batch.sh` binds a receipt to `head_sha`
                    (line 153) and re-reads HEAD after the run (line 377), but
                    performs no reachability check on any revision a bead
                    cites. A lane citing a revision has the same exposure.
  enforced gate     exit 1 when any cited commit is reachable from no ref, so a
                    verification cycle cannot bind a receipt to a revision that
                    has been rewritten out of the repository.
  observed defect   measured 2026-10-27: 2076 distinct cited commits resolve,
                    179 were reachable from no ref, and 22 of those were held
                    by nothing at all -- not a ref, not a reflog -- while the
                    repository sat at 8546 loose objects against git's default
                    gc.auto threshold of 6700. A peer lane ran the same census
                    by hand on 2026-10-06, pinned the 42 it found, and left no
                    instrument; the population was 4x larger 21 days later.
                    This file exists so the third agent does not rebuild it.
  retirement        delete this when receipts bind to BLOB hashes rather than
                    commit ids (PL-6), or when the pin runs from the commit
                    path. A blob survives a rebase; a commit id does not.

WHAT THE PIN DOES AND DOES NOT BUY. It creates refs under
refs/evidence/review-cited/<short> so the objects stay gc-safe and readable
from any clone that fetches the namespace. It does NOT make a receipt valid: a
commit outside HEAD history is still outside it, and Code-First 4 ("relevant
source movement invalidates it") is a separate question this script does not
answer. Pinning preserves the ability to read the evidence; it does not
re-validate the claim.

WHY A COMMIT ID ROTS HERE. Many lanes commit into one working tree and
`git pull --rebase` rewrites every unpushed commit, so a commit id written into
a comment has a short and unpredictable life. The 22 commits found with no
cover at all were a single cluster from 2026-08-24/25 whose reflog entries had
long since passed gc.reflogExpireUnreachable.

Creates refs ONLY, with the `create` verb, which refuses to overwrite a ref
that already exists: no commit, no branch, no tag, no history edit, nothing
deleted, nothing overwritten, and `git status` unchanged.
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

NAMESPACE = "refs/evidence/review-cited/"

# A git object id as written in prose. The boundary must be NON-ALPHANUMERIC,
# not merely non-hex: with a non-hex boundary the word "succeeded" yields the
# 7-hex token "cceeded", and the first run of this census reported 94 phantom
# citations of exactly that. A 64-char sha256 digest is a single run and so is
# never split into a token either. Checked by --selftest.
TOKEN = re.compile(r"(?<![0-9A-Za-z])([0-9a-f]{7,40})(?![0-9A-Za-z])")


def repo_root() -> Path:
    out = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True, check=True)
    return Path(out.stdout.strip())


class Git:
    def __init__(self, root: Path) -> None:
        self.root = root

    def __call__(self, *args: str, stdin: str | None = None) -> str:
        done = subprocess.run(["git", *args], cwd=self.root, input=stdin,
                              capture_output=True, text=True, check=False)
        if done.returncode and stdin is None and args[0] != "ls-remote":
            print(f"git {' '.join(args)} -> {done.returncode}: "
                  f"{done.stderr.strip()[:200]}", file=sys.stderr)
        return done.stdout

    def lines(self, *args: str) -> list[str]:
        return [line for line in self(*args).splitlines() if line]


def harvest(issues: Path) -> dict[str, set[str]]:
    """token -> set of bead ids citing it, over every text field in the tracker."""
    cites: dict[str, set[str]] = collections.defaultdict(set)
    with issues.open() as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            texts = [record.get("title") or "", record.get("description") or "",
                     record.get("close_reason") or ""]
            texts += [(c.get("text") or "") for c in (record.get("comments") or [])]
            for text in texts:
                for match in TOKEN.finditer(text):
                    token = match.group(1)
                    if not token.isdigit():   # a 7+ digit number is not an id
                        cites[token].add(record["id"])
    return cites


def audit(git: Git, issues: Path) -> dict[str, Any]:
    cites = harvest(issues)
    tokens = sorted(cites)
    kinds = git("cat-file", "--batch-check",
                stdin="\n".join(tokens) + "\n").splitlines()

    commits: dict[str, set[str]] = collections.defaultdict(set)
    for token, row in zip(tokens, kinds):
        parts = row.split()
        if len(parts) >= 2 and parts[1] == "commit":
            commits[parts[0]].update(cites[token])

    ancestors = set(git("rev-list", "HEAD").split())
    reachable = set(git("rev-list", "--all").split())
    # gc keeps what a reflog mentions, but that cover is local to one .git, is
    # never pushed, and expires. Both tiers are reported because only the
    # second is an immediate loss.
    reflog_kept = set(git("rev-list", "--all", "--reflog").split())

    pinned = {}
    for row in git("for-each-ref", "--format=%(refname:lstrip=3) %(objectname)",
                   NAMESPACE).splitlines():
        name, _, sha = row.partition(" ")
        if sha:
            pinned[sha] = name

    unreachable = sorted(sha for sha in commits if sha not in reachable)
    return {
        "head": git("rev-parse", "HEAD").strip(),
        "cited_commits": len(commits),
        "in_head_history": sum(1 for s in commits if s in ancestors),
        "reachable_off_head": sum(
            1 for s in commits if s in reachable and s not in ancestors),
        "unreachable": unreachable,
        "unreachable_reflog_only": [s for s in unreachable if s in reflog_kept],
        "unreachable_uncovered": [s for s in unreachable if s not in reflog_kept],
        "already_pinned": len(pinned),
        "pinned_shas": pinned,
        "beads": {sha: sorted(commits[sha]) for sha in unreachable},
    }


def selftest(git: Git, issues: Path) -> int:
    """Controls for the two defects this instrument actually had while being built."""
    checks: list[tuple[str, bool]] = [
        ("the word 'succeeded' yields no token",
         not TOKEN.findall("compilation has not succeeded yet")),
        ("a 64-char sha256 is not split into a token",
         not TOKEN.findall("checksum " + "f3" * 32)),
        ("a punctuation-delimited id IS found",
         TOKEN.findall("anchor HEAD `0486ef1e`") == ["0486ef1e"]),
        ("a 7-digit decimal is rejected as an id",
         not [t for t in TOKEN.findall("estimate 1234567 ms") if not t.isdigit()]),
        # A hex run inside a longer word is rejected. A hex run that IS a whole
        # word cannot be rejected by shape -- `deadbeef1` is nine hex
        # characters and reads exactly like a short commit id -- which is why
        # every token is resolved against the object database before it counts.
        # Shape proposes; `git cat-file` decides.
        ("a hex run inside a longer word is not a token",
         not TOKEN.findall("let deadbeefx = 0;")),
        ("a whole-word hex run is a candidate, and resolution is what rejects it",
         TOKEN.findall("value deadbeef1 here") == ["deadbeef1"]),
    ]
    report = audit(git, issues)
    # Live control: a ref exists for every pin, so no pin may read unreachable.
    # If one does, the reachability set is wrong and no count here is usable.
    bad = [s for s in report["pinned_shas"] if s in report["unreachable"]]
    checks.append((f"all {report['already_pinned']} existing pins read as "
                   f"reachable", not bad))
    failed = 0
    for name, ok in checks:
        print(f"  {'ok  ' if ok else 'FAIL'}  {name}")
        failed += 0 if ok else 1
    print(f"\n{len(checks) - failed} of {len(checks)} controls pass")
    return 1 if failed else 0


def describe(git: Git, report: dict[str, Any]) -> None:
    print(f"HEAD {report['head'][:8]}   "
          f"(a parallel lane can move this mid-run; nothing below is bound to it)")
    print(f"cited commits that resolve        {report['cited_commits']}")
    print(f"  in HEAD history                {report['in_head_history']}")
    print(f"  reachable off-HEAD             {report['reachable_off_head']}"
          f"   (includes {report['already_pinned']} existing pins)")
    print(f"  reachable from NO ref          {len(report['unreachable'])}")
    print(f"    held only by a local, expiring, unpushed reflog  "
          f"{len(report['unreachable_reflog_only'])}")
    print(f"    held by nothing at all                           "
          f"{len(report['unreachable_uncovered'])}")
    if report["unreachable_uncovered"]:
        print("\nheld by nothing at all -- prunable at the next `git gc --auto`:")
        for sha in report["unreachable_uncovered"]:
            subject = git("log", "-1", "--format=%cs  %s", sha).strip()
            beads = report["beads"][sha]
            print(f"  {sha[:8]}  {subject[:66]}")
            print(f"      cited by {len(beads)} bead(s): {beads[:3]}")


def pin(git: Git, report: dict[str, Any], push: bool) -> int:
    names = set(report["pinned_shas"].values())
    batch, planned = [], []
    for sha in report["unreachable"]:
        short = git("rev-parse", "--short=8", sha).strip()
        if short in names:          # another ref already owns this name
            continue
        names.add(short)
        batch.append(f"create {NAMESPACE}{short} {sha}\n")
        planned.append(short)
    if not batch:
        print("nothing to pin: every cited commit is reachable from some ref")
        return 0
    out = git("update-ref", "--stdin", stdin="".join(batch))
    if out.strip():
        print(out.strip()[:1000])
    after = len(git.lines("for-each-ref", "--format=%(refname)", NAMESPACE))
    still = [s for s in report["unreachable"]
             if s not in set(git("rev-list", "--all").split())]
    print(f"created {len(planned)} refs; namespace now holds {after}")
    print(f"cited commits still unreachable: {len(still)} (want 0)")
    if still:
        return 1
    if push:
        git("push", "origin", f"{NAMESPACE}*:{NAMESPACE}*")
        remote = len(git.lines("ls-remote", "origin", f"{NAMESPACE}*"))
        print(f"origin now holds {remote} refs in the namespace")
        return 0 if remote >= after else 1
    print("not pushed: the objects are gc-safe on this machine only. Pass "
          "--push to make them readable from every clone.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pin", action="store_true",
                        help="create a ref for each unreachable cited commit")
    parser.add_argument("--push", action="store_true",
                        help="with --pin, push the namespace to origin")
    parser.add_argument("--json", action="store_true", help="machine-readable audit")
    parser.add_argument("--selftest", action="store_true",
                        help="run the instrument's own controls and exit")
    args = parser.parse_args()

    root = repo_root()
    git = Git(root)
    issues = root / ".beads/issues.jsonl"
    if not issues.exists():
        print(f"no tracker export at {issues}", file=sys.stderr)
        return 2

    if args.selftest:
        return selftest(git, issues)

    report = audit(git, issues)
    if args.json:
        payload = {k: v for k, v in report.items() if k != "pinned_shas"}
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        describe(git, report)

    if args.pin:
        return pin(git, report, args.push)
    # gate: a cited revision that no ref reaches cannot anchor a receipt
    return 1 if report["unreachable"] else 0


if __name__ == "__main__":
    sys.exit(main())
