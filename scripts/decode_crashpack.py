#!/usr/bin/env python3
"""Decode an asupersync lab crashpack into a readable trace.

WHY THIS EXISTS

A failing `lab_test` writes a crashpack under `target/test-artifacts/` and
prints its path. The file is the most useful artifact the lab produces -- it
carries the canonical event prefix, the oracle violations, and an exact replay
command -- and it is unreadable as shipped: every event is
`{"kind": 17, "primary": 2, "secondary": 0, "tertiary": 0}`, where 17 is a
discriminant defined in asupersync's `trace::canonicalize::kind_discriminant`
and the three integers mean different things for different kinds.

So the information is already being produced and nobody can read it. This
script is the missing half.

WHAT IT REPORTS, AND WHY ABSENCE IS THE INTERESTING PART

The decoded listing is useful, but the summary is what diagnosed the four
`task_03_final_*` non-quiescence rows on 2026-11-08. Those crashpacks contain
RegionCreated, TimerScheduled, Spawn, TaskSpawnEnqueued and TaskAdmitted -- and
NO TimeAdvance, NO TimerFired, NO Complete and NO RegionCloseComplete. Three
timers were armed, virtual time never left 0, so no timer could fire and no
task could finish. A listing of what IS present hides that; the summary
therefore names the diagnostic kinds that are MISSING as well.

"N tasks leaked" also tends to be the FIRST oracle violation while the
non-quiescence panic is the second, so the message the test prints names the
consequence and the crashpack names the cause. The summary prints violations
in file order for that reason.

A NOTE ON THE STEP BUDGET. If a run exhausted `max_steps`, compare two
crashpacks from the same seed at different `ASUPERSYNC_MAX_STEPS` values. Equal
`event_count` at a 10x budget means the extra steps bought no observable
progress -- a spin, which no larger budget, longer timeout or retry will fix.
Different counts mean the budget was genuinely marginal. The script prints
`event_count` and `max_steps` adjacently so the comparison is one glance.

VERSION BINDING. The discriminant table below is transcribed from
asupersync 0.5.0. Discriminants are append-only by documented contract
("never renumber existing discriminants (fingerprint stability)"), so they are
safe across versions; the per-kind meaning of primary/secondary/tertiary comes
from `event_sort_key` and carries no such promise. The script resolves
asupersync's actual version from Cargo.lock and prints a banner when it is not
the version this table was taken from, rather than silently mislabelling.

USAGE
  scripts/decode_crashpack.py <crashpack.json|dir> [...] [--json] [--quiet]

  A directory is walked for `crashpack-*.json`. With no argument, the default
  is `crates/fastmcp-server/target/test-artifacts` -- note that the path the
  test prints is relative to the CRATE directory, not the workspace root.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

TABLE_FROM_VERSION = "0.5.0"

# trace::canonicalize::kind_discriminant (asupersync 0.5.0). Append-only.
KIND_NAMES = {
    0: "Spawn", 1: "Schedule", 2: "Yield", 3: "Wake", 4: "Poll", 5: "Complete",
    6: "CancelRequest", 7: "CancelAck", 8: "RegionCloseBegin",
    9: "RegionCloseComplete", 10: "RegionCreated", 11: "RegionCancelled",
    12: "ObligationReserve", 13: "ObligationCommit", 14: "ObligationAbort",
    15: "ObligationLeak", 16: "TimeAdvance", 17: "TimerScheduled",
    18: "TimerFired", 19: "TimerCancelled", 20: "IoRequested", 21: "IoReady",
    22: "IoResult", 23: "IoError", 24: "RngSeed", 25: "RngValue",
    26: "Checkpoint", 27: "FuturelockDetected", 28: "ChaosInjection",
    29: "UserTrace", 30: "MonitorCreated", 31: "MonitorDropped",
    32: "DownDelivered", 33: "LinkCreated", 34: "LinkDropped",
    35: "ExitDelivered", 36: "WorkerCancelRequested",
    37: "WorkerCancelAcknowledged", 38: "WorkerDrainStarted",
    39: "WorkerDrainCompleted", 40: "WorkerFinalizeCompleted",
    41: "TaskSpawnEnqueued", 42: "TaskAdmitted", 43: "BudgetInstalled",
    44: "BudgetConsumed",
}

# Per-kind meaning of the canonical (primary, secondary, tertiary) triple, from
# trace::canonicalize::event_sort_key. "arena" values are index<<32|generation.
# A kind absent here is printed raw rather than guessed at.
A, N = "arena", "num"
FIELD_LAYOUT = {
    **{k: (("task", A), ("region", A)) for k in
       (0, 1, 2, 3, 4, 5, 6, 7, 41, 42, 43, 44)},
    **{k: (("region", A), ("parent", A)) for k in (8, 9, 10)},
    11: (("region", A),),
    **{k: (("obligation", A), ("task", A), ("region", A)) for k in
       (12, 13, 14, 15)},
    16: (("old_ns", N), ("new_ns", N)),
    **{k: (("timer_id", N),) for k in (17, 18, 19)},
    **{k: (("token", N),) for k in (20, 21)},
    22: (("token", N), ("bytes_key", N)),
    23: (("token", N), ("io_error_kind", N)),
    24: (("seed", N),),
    25: (("value", N),),
    26: (("sequence", N), ("active_tasks", N), ("active_regions", N)),
    27: (("task", A), ("region", A), ("detail_hash", N)),
    28: (("task", A),),
    29: (("message_hash", N),),
    **{k: (("monitor_ref", N), ("watcher", A), ("monitored", A)) for k in (30, 31)},
    32: (("completion_vt_ns", N), ("monitored", A), ("monitor_ref", N)),
}

# Kinds whose absence from a non-quiescent run is diagnostic, with the reason.
DIAGNOSTIC_ABSENCES = (
    (16, "TimeAdvance", "virtual time never advanced, so no timer can fire"),
    (18, "TimerFired", "no armed timer ever fired"),
    (5, "Complete", "no task ever ran to completion"),
    (9, "RegionCloseComplete", "no region ever closed"),
)


def arena(value: int) -> str:
    return f"{value >> 32}.{value & 0xFFFFFFFF}"


def decode_event(event: dict) -> tuple[str, str]:
    kind = event.get("kind")
    name = KIND_NAMES.get(kind, f"Kind{kind}")
    raw = (event.get("primary", 0), event.get("secondary", 0),
           event.get("tertiary", 0))
    layout = FIELD_LAYOUT.get(kind)
    if layout is None:
        return name, f"primary={raw[0]} secondary={raw[1]} tertiary={raw[2]}"
    parts = []
    for (label, shape), value in zip(layout, raw):
        parts.append(f"{label}={arena(value) if shape == A else value}")
    return name, " ".join(parts)


def resolved_asupersync_version(root: Path) -> str | None:
    lock = root / "Cargo.lock"
    try:
        text = lock.read_text()
    except OSError:
        return None
    match = re.search(
        r'\[\[package\]\]\s*\nname = "asupersync"\s*\nversion = "([^"]+)"', text)
    return match.group(1) if match else None


def summarize(pack: dict) -> dict:
    manifest = pack.get("manifest", {})
    config = manifest.get("config", {})
    counts: dict[int, int] = {}
    for layer in pack.get("canonical_prefix", []):
        for event in layer:
            counts[event.get("kind")] = counts.get(event.get("kind"), 0) + 1
    return {
        "test": config.get("test_name"),
        "seed": config.get("seed"),
        "workers": config.get("worker_count"),
        "max_steps": config.get("max_steps"),
        "event_count": manifest.get("event_count"),
        "fingerprint": manifest.get("fingerprint"),
        "layers": len(pack.get("canonical_prefix", [])),
        "virtual_time": pack.get("failure", {}).get("virtual_time"),
        "outcome": pack.get("failure", {}).get("outcome"),
        "kinds_present": {KIND_NAMES.get(k, k): v for k, v in sorted(counts.items())},
        "diagnostic_absences": [
            name for kind, name, _ in DIAGNOSTIC_ABSENCES if kind not in counts
        ],
        "oracle_violations": pack.get("oracle_violations", []),
        "divergent_prefix_layers": len(pack.get("divergent_prefix", [])),
        "replay": pack.get("replay", {}).get("command_line"),
    }


def render(pack: dict, path: Path, quiet: bool) -> None:
    s = summarize(pack)
    print(f"=== {path}")
    print(f"  test          {s['test']}")
    print(f"  seed {s['seed']}  workers {s['workers']}  "
          f"max_steps {s['max_steps']}  event_count {s['event_count']}")
    print(f"  fingerprint   {s['fingerprint']}")
    print(f"  failure       outcome={s['outcome']} virtual_time={s['virtual_time']}")
    print("  oracle violations (file order; the first is usually the cause):")
    for violation in s["oracle_violations"] or ["(none)"]:
        print(f"    - {violation}")
    if not quiet:
        print(f"  canonical prefix ({s['layers']} Foata layers, "
              f"{s['event_count']} events):")
        for index, layer in enumerate(pack.get("canonical_prefix", [])):
            for event in layer:
                name, fields = decode_event(event)
                print(f"    L{index:<3} {name:<22} {fields}")
    print(f"  kinds present: {s['kinds_present']}")
    if s["diagnostic_absences"]:
        print("  DIAGNOSTIC ABSENCES -- these kinds never appear:")
        for kind, name, why in DIAGNOSTIC_ABSENCES:
            if name in s["diagnostic_absences"]:
                print(f"    - {name}: {why}")
    if s["divergent_prefix_layers"] == 0:
        print("  divergent_prefix is EMPTY: no schedule divergence was recorded,")
        print("    so this is not a two-run disagreement -- it is one run stopping.")
    print(f"  replay: {s['replay']}")
    print()


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    as_json = "--json" in argv
    quiet = "--quiet" in argv
    if "--help" in argv or "-h" in argv:
        print(__doc__)
        return 0

    root = Path(__file__).resolve().parent.parent
    targets = [Path(a) for a in args] or [
        root / "crates/fastmcp-server/target/test-artifacts"]

    files: list[Path] = []
    for target in targets:
        if target.is_dir():
            files.extend(sorted(target.rglob("crashpack-*.json")))
        elif target.exists():
            files.append(target)
        else:
            print(f"no such path: {target}", file=sys.stderr)
            return 64
    if not files:
        print(f"no crashpack-*.json under: "
              f"{', '.join(str(t) for t in targets)}", file=sys.stderr)
        return 1

    version = resolved_asupersync_version(root)
    if not as_json and version and version != TABLE_FROM_VERSION:
        print(f"NOTE: this table was transcribed from asupersync "
              f"{TABLE_FROM_VERSION}, but Cargo.lock resolves {version}.")
        print("  Discriminants are append-only by contract and remain safe; the")
        print("  primary/secondary/tertiary labels come from event_sort_key and")
        print("  carry no such promise. Re-check trace/canonicalize.rs.\n")

    packs = []
    for path in files:
        try:
            pack = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"cannot read {path}: {exc}", file=sys.stderr)
            return 1
        if as_json:
            packs.append({"path": str(path), **summarize(pack)})
        else:
            render(pack, path, quiet)

    if as_json:
        print(json.dumps({"table_from_asupersync": TABLE_FROM_VERSION,
                          "resolved_asupersync": version,
                          "packs": packs}, indent=2))
    elif len(files) > 1:
        print(f"{len(files)} crashpacks decoded.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
