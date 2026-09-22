#!/usr/bin/env python3
"""Verify a bead's prose->checkbox transcription, independently of whoever made it.

WHY THIS EXISTS. WildMountain recomputed SilentSquirrel's transcription with his own
script before applying it, and said two independent computations agreeing is worth more
than one trusted one. This makes that second computation cheap and repeatable, so any
lane can audit any other lane's transcription from the before/after field alone -- and
so the author's own script is never the only thing that checked the author's own work.

WHAT IT PROVES, and the proofs are the whole point:
  P1  every top-level bullet in the stored field carries the "- [ ] " prefix, count N
  P2  stored_bytes - preimage_bytes == 4 * N   (exactly the prefixes, nothing else)
  P3  stripping the prefixes reproduces the pre-image BYTE FOR BYTE

WHAT IT CANNOT PROVE, stated because the delta proof is blind to it BY CONSTRUCTION:
that the bullets were ever REQUIREMENTS. P1-P3 prove bytes were preserved, never that
they were criteria. WildMountain's sharpened rule is per-bullet grammatical mood -- is
this line an obligation or a note -- and it must be applied PER BULLET, because the
failure case is one commentary line inside an otherwise-genuine requirements list. So
this tool PRINTS EVERY ITEM for reading and refuses to call that step done for you.

The advisory note-marker scan is ADVISORY ONLY and is never a gate. It carries its own
positive and negative control, because an instrument that looked right and had no
control is the failure three lanes hit in one night.
"""
import json
import re
import subprocess
import sys

PREFIX = "- [ ] "
BULLET = "- "
# Advisory only. Cheap markers for lines that read like commentary rather than
# obligation. Never a gate: it orders attention, it does not replace the read.
NOTE_MARKERS = re.compile(
    r"^\s*(note|n\.b\.|see |e\.g\.|for example|todo|fixme|aside|context:|background:)",
    re.IGNORECASE,
)


def transcribe(preimage: str) -> tuple[str, int]:
    """Prefix each TOP-LEVEL bullet. Continuation lines are indented; leave them."""
    out, n = [], 0
    for line in preimage.split("\n"):
        if line.startswith(BULLET) and not line.startswith(("- [ ] ", "- [x] ")):
            out.append(PREFIX + line[len(BULLET):])
            n += 1
        else:
            out.append(line)
    return "\n".join(out), n


def items_of(stored: str) -> list[str]:
    """Whole items, continuation lines INCLUDED.

    The first version of this printed only the prefixed line and dropped the wrapped
    remainder -- reproducing, inside the tool built to force a full read, the exact
    truncation MagentaSummit found in `br`'s own item view: an item rendered at its
    first newline is a sentence fragment, and a mood judgement made on a fragment is
    a judgement about the wrong text. Four of ahet.3's nine items are multi-line.
    """
    items: list[str] = []
    for line in stored.split("\n"):
        if line.startswith(PREFIX):
            items.append(line[len(PREFIX):])
        elif items:
            items[-1] += "\n" + line
    return items


def strip_back(stored: str) -> str:
    return "\n".join(
        ln.replace(PREFIX, BULLET, 1) if ln.startswith(PREFIX) else ln
        for ln in stored.split("\n")
    )


def check(preimage: str, stored: str) -> tuple[bool, int, list[str]]:
    computed, n = transcribe(preimage)
    pre_b, st_b = len(preimage.encode()), len(stored.encode())
    items = sum(1 for ln in stored.split("\n") if ln.startswith(PREFIX))
    findings = []
    if items != n:
        findings.append(f"P1 FAIL: stored has {items} checkbox items, pre-image has {n} bullets")
    if st_b - pre_b != 4 * n:
        findings.append(f"P2 FAIL: byte delta {st_b - pre_b}, expected {4 * n} (= 4 x {n})")
    if strip_back(stored).encode() != preimage.encode():
        findings.append("P3 FAIL: stripping the prefixes does NOT reproduce the pre-image")
    if stored.encode() != computed.encode():
        findings.append("P4 FAIL: stored text differs from an independent recomputation")
    return (not findings), n, findings


def self_test() -> bool:
    """Positive AND negative control, in this invocation, before any verdict."""
    pre = "- Alpha holds.\n- Beta holds;\n  and it wraps.\n- Gamma holds."
    good, n = transcribe(pre)
    if n != 3 or not check(pre, good)[0]:
        print("CONTROL FAILED: a correct transcription did not verify", file=sys.stderr)
        return False
    if check(pre, good + "x")[0]:
        print("CONTROL FAILED: a corrupted stored field verified anyway", file=sys.stderr)
        return False
    if check(pre.replace("Beta holds;", "Beta changed;"), good)[0]:
        print("CONTROL FAILED: a mutated pre-image verified anyway", file=sys.stderr)
        return False
    # The advisory scan must fire on a note and stay quiet on an obligation.
    if not NOTE_MARKERS.search("Note: this is background."):
        print("CONTROL FAILED: advisory scan missed a note line", file=sys.stderr)
        return False
    if NOTE_MARKERS.search("No Tokio, reqwest, or hyper enters the graph."):
        print("CONTROL FAILED: advisory scan fired on an obligation", file=sys.stderr)
        return False
    # A wrapped item must render WHOLE. The control pre-image has one on purpose.
    rendered = items_of(good)
    if len(rendered) != 3 or "and it wraps." not in rendered[1]:
        print("CONTROL FAILED: a wrapped item rendered truncated", file=sys.stderr)
        return False
    return True


def stored_criteria(bead: str) -> str:
    raw = subprocess.run(
        ["br", "show", bead, "--json"], capture_output=True, text=True, check=True
    ).stdout
    doc = json.loads(raw)
    issue = doc if isinstance(doc, dict) else doc[0]
    return issue.get("acceptance_criteria") or ""


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        print("usage: transcription_verify.py <bead-id> <pre-image-file>", file=sys.stderr)
        return 64
    if not self_test():
        print("REFUSING TO REPORT: controls did not pass in this invocation.", file=sys.stderr)
        return 2
    print("controls: correct-verifies, corrupt-rejects, mutated-preimage-rejects, advisory pos+neg, wrapped-item-whole  OK")

    bead, pre_path = sys.argv[1], sys.argv[2]
    preimage = open(pre_path, encoding="utf-8").read()
    stored = stored_criteria(bead)

    ok, n, findings = check(preimage, stored)
    print(f"\n{bead}")
    print(f"  bullets {n}   bytes {len(preimage.encode())} -> {len(stored.encode())}"
          f"   delta {len(stored.encode()) - len(preimage.encode())}")
    for f in findings:
        print("  " + f)
    print(f"  PROOFS: {'ALL PASS' if ok else 'FAILED'}")

    print("\n  EVERY ITEM, FOR THE PER-BULLET MOOD READ. This tool does NOT judge these;")
    print("  the delta proof is blind to whether a line is an obligation or a note.")
    for i, item in enumerate(items_of(stored), 1):
        flag = "  <-- ADVISORY: reads like commentary" if NOTE_MARKERS.search(item) else ""
        body = item.replace("\n", "\n        ")
        print(f"    {i:2d}. {body}{flag}")
    print("\n  Unread is not verified. P1-P3 prove bytes, never criteria.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
