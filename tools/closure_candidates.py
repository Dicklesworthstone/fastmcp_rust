#!/usr/bin/env python3
"""Closure-candidate sweep that cannot mistake an empty gate ledger for a pass.

The obvious sweep -- "acceptance complete, open blockers zero, gate ledger
clean" -- reports beads the tracker would refuse to close. For a `require_all`
gate an EMPTY ledger is the blocked state, not a passing one: `br gate list`
renders a missing gate as `satisfied: false` and prints the transition as
[BLOCKED]. Reading "no gate rows" as "nothing in the way" inverts the sign of
the check, and the bead most likely to look closeable is then exactly the one
that is gate-blocked.

So this sweep never infers gate state. It narrows cheaply against the local
SQLite (one pass, no per-bead `br` calls) and then asks `br gate list` for a
verdict on each survivor, because br owns the policy semantics and re-deriving
them here would just be a second place to get them wrong.

Three outcomes, and the middle one is the point:

  CLOSEABLE     a transition to `closed` exists from the current status and
                its gates are satisfied.
  GATE-BLOCKED  a transition to `closed` exists and its gates are NOT
                satisfied -- typically no batch_verify result recorded.
  NO-PATH       no transition to `closed` from the current status at all
                (`blocked` and `open` both have to move first). These cannot
                be closed today no matter how complete they look.

Acceptance ticks are reported but never treated as proof: a tick carries no
timestamp and no actor, so "all criteria ticked" means they were ticked at some
past instant, not that they hold now. Beads whose criteria span more than one
`##` section are flagged rather than silently totalled, because the sections
can set different bars.

Usage:
  tools/closure_candidates.py            # human-readable
  tools/closure_candidates.py --json     # machine-readable
  tools/closure_candidates.py --all      # include partially-ticked beads
"""

import argparse
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DB = REPO / ".beads" / "beads.db"

TICK = re.compile(r"^\s*[-*]\s*\[([ xX])\]", re.MULTILINE)
SECTION = re.compile(r"^\s*##+\s+\S", re.MULTILINE)


def tick_counts(text):
    """Return (ticked, total, section_count) over checkbox lines."""
    if not text:
        return 0, 0, 0
    marks = TICK.findall(text)
    ticked = sum(1 for m in marks if m in ("x", "X"))
    return ticked, len(marks), len(SECTION.findall(text))


def load_rows(conn, include_partial):
    """One pass over the DB: status, ticks, and live blocking dependencies."""
    rows = conn.execute(
        """
        SELECT i.id, i.status, i.acceptance_criteria,
               (SELECT COUNT(*)
                  FROM dependencies d
                  JOIN issues b ON b.id = d.depends_on_id
                 WHERE d.issue_id = i.id
                   AND d.type = 'blocks'
                   AND b.status != 'closed'
                   AND b.deleted_at IS NULL) AS open_blockers
          FROM issues i
         WHERE i.status != 'closed' AND i.deleted_at IS NULL
        """
    ).fetchall()

    out = []
    for issue_id, status, criteria, open_blockers in rows:
        ticked, total, sections = tick_counts(criteria)
        if total == 0:
            continue
        complete = ticked == total
        if not (complete or include_partial):
            continue
        out.append(
            {
                "id": issue_id,
                "status": status,
                "ticked": ticked,
                "criteria": total,
                "sections": sections,
                "open_blockers": open_blockers,
            }
        )
    return out


def gate_verdict(issue_id):
    """Ask br for the gate verdict. br owns policy semantics; we do not."""
    try:
        proc = subprocess.run(
            ["br", "gate", "list", issue_id, "--json"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=REPO,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"disposition": "UNKNOWN", "detail": f"br gate list failed: {exc}"}

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip().splitlines()
        return {
            "disposition": "UNKNOWN",
            "detail": detail[0] if detail else f"br exited {proc.returncode}",
        }
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"disposition": "UNKNOWN", "detail": "br emitted non-JSON"}

    to_closed = [t for t in data.get("gated_transitions", []) if t.get("to") == "closed"]
    if not to_closed:
        return {
            "disposition": "NO-PATH",
            "detail": f"no transition to closed from {data.get('current_status')}",
        }

    transition = to_closed[0]
    unmet = [g["gate"] for g in transition.get("gates", []) if not g.get("satisfied")]
    if transition.get("satisfied"):
        return {"disposition": "CLOSEABLE", "detail": "gates satisfied"}
    return {
        "disposition": "GATE-BLOCKED",
        "detail": "unsatisfied: " + ", ".join(unmet) if unmet else "gates not satisfied",
    }


ORDER = {"CLOSEABLE": 0, "GATE-BLOCKED": 1, "NO-PATH": 2, "UNKNOWN": 3}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--all", action="store_true", help="include partially-ticked beads"
    )
    args = parser.parse_args()

    if not DB.exists():
        print(f"no beads database at {DB}", file=sys.stderr)
        return 2

    conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try:
        rows = load_rows(conn, args.all)
    finally:
        conn.close()

    for row in rows:
        # Only beads with nothing left in the graph can be closed today, so
        # spend a br call only on those; the rest are blocked regardless.
        if row["open_blockers"]:
            row["disposition"] = "NO-PATH"
            row["detail"] = f"{row['open_blockers']} open blocking dependencies"
        else:
            row.update(gate_verdict(row["id"]))

    rows.sort(key=lambda r: (ORDER.get(r["disposition"], 9), r["id"]))

    if args.json:
        print(json.dumps({"candidates": rows}, indent=2))
        return 0

    closeable = [r for r in rows if r["disposition"] == "CLOSEABLE"]
    # Finished work that reads as backlog: every criterion ticked, held only by
    # graph edges, and still sitting at status `open`. `br ready` is not fooled
    # -- it filters on blockers regardless of status -- but a human scanning raw
    # status sees `open` and reads "not begun". That is a reporting hazard in
    # the direction that makes a campaign look less done than it is, so it gets
    # its own line rather than being inferred from the table.
    hidden = [
        r for r in rows
        if r["ticked"] == r["criteria"]
        and r["open_blockers"]
        and r["status"] == "open"
    ]
    print(f"fully-ticked, non-closed beads examined: {len(rows)}")
    print(f"actually closeable today: {len(closeable)}")
    print(f"COMPLETE BUT READS AS BACKLOG (100% ticked, graph-blocked, status=open): {len(hidden)}")
    for r in hidden:
        print(f"    {r['id']:<48} {r['ticked']}/{r['criteria']}  blockers={r['open_blockers']}")
    print()
    for row in rows:
        flag = " MULTI-SECTION" if row["sections"] > 1 else ""
        print(
            f"  {row['disposition']:<13} {row['id']:<48} "
            f"{row['status']:<12} ticks={row['ticked']}/{row['criteria']}{flag}"
        )
        print(f"                {row['detail']}")
    if not closeable:
        print("\nNothing is closeable today. An empty gate ledger is a BLOCK, not a pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
