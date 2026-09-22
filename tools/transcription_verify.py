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
    # The wrapped-clause precondition must reject a nested bullet and accept a clause.
    if wrapped_clause_precondition("- [ ] Alpha.\n  - nested obligation")[0]:
        print("CONTROL FAILED: precondition accepted a nested bullet", file=sys.stderr)
        return False
    if not wrapped_clause_precondition("- [ ] Alpha.\n  wrapped clause")[0]:
        print("CONTROL FAILED: precondition rejected a plain wrapped clause", file=sys.stderr)
        return False
    # The precondition must also pass on the PROSE form, not just the checkbox form.
    if not wrapped_clause_precondition(pre)[0]:
        print("CONTROL FAILED: precondition rejected a prose pre-image", file=sys.stderr)
        return False
    if len(_grouped(pre)) != 3:
        print("CONTROL FAILED: grouper miscounted a prose pre-image", file=sys.stderr)
        return False
    # Re-flow must preserve the author's word sequence exactly.
    if norm(strip_back(reflow(good))) != norm(pre):
        print("CONTROL FAILED: re-flow did not preserve the author's words", file=sys.stderr)
        return False
    return True


def norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _item_start(line: str) -> str | None:
    """Item text if this line starts an item, in EITHER the prose or checkbox form.

    The pre-image is prose (`- `) and the stored field is checkboxes (`- [ ] `).
    A grouper that knows only one form reads every bullet of the other as a
    continuation, which turns a correct bead into a FAIL.
    """
    if line.startswith(PREFIX):
        return line[len(PREFIX):]
    if line.startswith(BULLET) and not line.startswith("- [x] "):
        return line[len(BULLET):]
    return None


def _grouped(stored: str) -> list[list[str]]:
    out: list[list[str]] = []
    for line in stored.split("\n"):
        head = _item_start(line)
        if head is not None:
            out.append([head])
        elif out:
            out[-1].append(line.strip())
    return out


def reflow(stored: str) -> str:
    """Join each item's continuation lines. Only whitespace moves."""
    return "\n".join(PREFIX + " ".join(p for p in parts if p) for parts in _grouped(stored))


def wrapped_clause_precondition(stored: str) -> tuple[bool, str]:
    """Re-flow is mechanical ONLY if every continuation is a wrapped clause.

    A nested bullet, or a blank-line-separated block, joined into its predecessor
    would MERGE TWO REQUIREMENTS -- and no byte proof notices. This is the only
    step that can fail dangerously, so it runs before any re-flow is computed.
    """
    nested = blank = cont = 0
    for line in stored.split("\n"):
        if _item_start(line) is not None:
            continue
        if not line.strip():
            blank += 1
            continue
        cont += 1
        if re.match(r"^\s*[-*+]\s", line) or re.match(r"^\s*\d+[.)]\s", line):
            nested += 1
    return (nested == 0 and blank == 0), f"continuations={cont} nested={nested} blank={blank}"


def parser_truncation(bead: str, stored: str) -> list[str]:
    """LAYER 2: compare what br's parser RETURNS to what the field HOLDS.

    ATTRIBUTION, CORRECTED. The mechanism is MagentaSummit's: br reads each item
    as THE FIRST LINE ONLY, recorded 2026-09-21T17:21Z on bd-reconcile-071-
    release-9t607, from "I finally read the criterion's full text instead of my
    own summary of it." RoseStream independently re-derived it AND measured its
    blast radius across the transcribed beads, which is what made the fleet act;
    that is a distinct contribution, not a restatement.

    I had MagentaSummit's comment in hand and had quoted it earlier the same
    hour. `items_of` above credits it correctly. Then a broadcast arrived framing
    the finding as RoseStream's, and I overwrote my own correct attribution with
    it -- amplifying a trusted lane over a record I had already read. The tool is
    the durable artifact, so the correction belongs here and not only in mail.

    A wrapped bullet's continuation sits in the field and in no item, with the
    field intact the whole time, which is why a byte proof cannot see it. The
    proofs above certify the FIELD; this certifies the READER, one layer past
    where those proofs' authority ends.
    """
    raw = subprocess.run(
        ["br", "show", bead, "--json"], capture_output=True, text=True, check=True
    ).stdout
    doc = json.loads(raw)
    issue = doc if isinstance(doc, dict) else doc[0]
    parsed = issue.get("acceptance_items")
    if not parsed:
        return ["LAYER 2 SKIPPED: this br build exposes no acceptance_items array"]
    field_items = [" ".join(p for p in parts if p) for parts in _grouped(stored)]
    findings = []
    if len(parsed) != len(field_items):
        findings.append(
            f"LAYER 2 FAIL: parser returns {len(parsed)} items, field holds {len(field_items)}"
        )
    for i, (got, want) in enumerate(zip(parsed, field_items), 1):
        text = got.get("text") if isinstance(got, dict) else str(got)
        if norm(text) != norm(want):
            findings.append(
                f"LAYER 2 FAIL item {i}: parser {len(text)} chars, field {len(want)}"
                f" -- ORPHANED: {want[len(text):].strip()[:80]}"
            )
    return findings


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
    print("controls: correct-verifies, corrupt-rejects, mutated-preimage-rejects, advisory pos+neg, wrapped-item-whole, precondition pos+neg, prose-form-grouping, reflow-preserves-words  OK")

    bead, pre_path = sys.argv[1], sys.argv[2]
    preimage = open(pre_path, encoding="utf-8").read()
    stored = stored_criteria(bead)

    ok, n, findings = check(preimage, stored)
    # A re-flowed field fails P2/P3 BY CONSTRUCTION: continuations were joined, so
    # bytes moved beyond the prefixes. That is a fact about those proofs, not about
    # the act -- re-flow chooses nothing, only whitespace moves. Verify with the
    # guards that DO cover it rather than rejecting a repaired bead.
    reflowed = all(l.startswith(PREFIX) for l in stored.split("\n") if l.strip())
    if not ok and reflowed:
        pre_ok, detail = wrapped_clause_precondition(preimage)
        gA = norm(reflow(preimage)) == norm(stored)
        gB = norm(strip_back(stored)) == norm(preimage)
        gC = len(_grouped(stored)) == len(_grouped(preimage))
        gD = "- [x]" not in stored
        findings = [f"RE-FLOWED FORM: P2/P3 do not apply; guards used instead ({detail})"]
        for label, val in (
            ("A only-whitespace-moved", gA),
            ("B re-derives the author's words", gB),
            ("C item count unchanged", gC),
            ("D zero ticked", gD),
            ("precondition wrapped-clauses-only", pre_ok),
        ):
            findings.append(f"  GUARD {label}: {'PASS' if val else 'FAIL'}")
        ok = gA and gB and gC and gD and pre_ok
        n = len(_grouped(stored))
    print(f"\n{bead}")
    print(f"  bullets {n}   bytes {len(preimage.encode())} -> {len(stored.encode())}"
          f"   delta {len(stored.encode()) - len(preimage.encode())}")
    for f in findings:
        print("  " + f)
    print(f"  PROOFS: {'ALL PASS' if ok else 'FAILED'}")

    layer2 = parser_truncation(bead, stored)
    for f in layer2:
        print("  " + f)
    if any(f.startswith("LAYER 2 FAIL") for f in layer2):
        print("  LAYER 2: FAILED -- the field is intact and the READER is lossy")
        ok = False
    elif not layer2:
        print("  LAYER 2: every parsed item equals its field item, no orphaned continuations")

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
