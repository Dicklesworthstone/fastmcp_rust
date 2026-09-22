#!/usr/bin/env python3
"""Find beads that name more frozen test IDs than their own count clause permits.

WHY. MagentaSummit found a template defect: a criteria clause reading "both frozen
IDs ... required count = 2" appears on beads that name three, four or fourteen
IDs. They reported 132 as an UPPER BOUND and said plainly they had not read 132
fields. This turns that bound into a measured set, so the text fix has a
population rather than an estimate.

WHAT THE HIT MEANS, AND WHAT IT DOES NOT. A hit is a bead whose acceptance text
names more distinct `*_positive` / `*_planted_negative` identifiers than its own
"required/passed count = N" clause allows. That is a contradiction INSIDE ONE
FIELD -- no run, no implementation and no reading can reconcile it, because the
clause bounds what the same text enumerates. It does NOT mean the bead's work is
wrong; on the one case verified end to end (bd-mcp-rel-quar-00-integration-qiyn)
every property the bead exists to establish was verified green while the two
count clauses remained unsatisfiable.

WHY RE-IMPLEMENTING CANNOT FIX IT. On qiyn the bar names two ID schemes: one pair
in its behaviour item, a different pair in its pinned-runner items. Enumerate the
configurations and every one fails some item:
    only the behaviour pair   -> the runner items name IDs that do not exist
    only the runner pair      -> the behaviour item names IDs that do not exist
    both pairs (four tests)   -> the count clauses see 4 discovered, or 3 filtered
So the defect is in the text and is independent of any implementation choice.
That is the argument for routing these to spec work rather than to owners.

The detector is deliberately conservative: it fires only when the SAME field both
enumerates and bounds, so a bead whose count clause is absent is never flagged.
Controls run first and it refuses to report without them.
"""
import json
import re
import subprocess
import sys

ID = re.compile(r"\b[a-z][a-z0-9_]*_(?:positive|planted_negative)\b")
COUNT = re.compile(r"(?:required|passed) count\s*=\s*(\d+)")


def distinct_ids(text: str) -> list[str]:
    return sorted(set(ID.findall(text)))


def count_clause(text: str) -> int | None:
    found = COUNT.findall(text)
    return int(found[0]) if found else None


def self_test() -> bool:
    """Positive and negative control, in this invocation, before any verdict."""
    over = "a_positive and a_planted_negative and b_positive and b_planted_negative; required count = 2"
    exact = "a_positive and a_planted_negative; required count = 2"
    none = "a_positive and a_planted_negative and b_positive; no clause here"
    if len(distinct_ids(over)) != 4 or count_clause(over) != 2:
        print("CONTROL FAILED: over-named shape not parsed", file=sys.stderr)
        return False
    if len(distinct_ids(exact)) != 2 or count_clause(exact) != 2:
        print("CONTROL FAILED: exact shape not parsed", file=sys.stderr)
        return False
    if count_clause(none) is not None:
        print("CONTROL FAILED: a missing clause was invented", file=sys.stderr)
        return False
    return True


def main() -> int:
    if not self_test():
        print("REFUSING TO REPORT: controls did not pass.", file=sys.stderr)
        return 2
    print("controls: over-named parsed, exact parsed, absent-clause not invented  OK\n")

    raw = subprocess.run(
        ["br", "list", "--json"], capture_output=True, text=True, check=True
    ).stdout
    doc = json.loads(raw)
    rows = doc if isinstance(doc, list) else doc.get("issues", [])

    hits = []
    scanned = 0
    for issue in rows:
        if issue.get("status") == "closed":
            continue
        text = issue.get("acceptance_criteria") or ""
        if not text.strip():
            continue
        scanned += 1
        ids, bound = distinct_ids(text), count_clause(text)
        if bound is not None and len(ids) > bound:
            hits.append((issue.get("id"), len(ids), bound, issue.get("assignee") or "-", ids))

    print(f"non-closed beads with acceptance text : {scanned}")
    print(f"naming MORE ids than their own clause : {len(hits)}\n")
    for bid, found, bound, owner, ids in sorted(hits, key=lambda row: -row[1]):
        print(f"  {bid:<46} ids={found:<3} count={bound:<3} {owner}")
        print(f"      {', '.join(ids)}")
    print("\n  A hit is a contradiction inside ONE field. No run can resolve it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
