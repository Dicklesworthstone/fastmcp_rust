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

RE-FLOW, AND THE ONE PLACE IT IS NOT MECHANICAL. Joining a wrapped clause moves only
whitespace, EXCEPT where the author broke a token across lines (`parse/` +
`invalid-request`, `no-common-` + `modern`). There the right amount of whitespace is
none, and every whitespace-NORMALISING guard passes on the corruption by construction,
because it collapses the very newline it is replacing. `MID_TOKEN` detects those
boundaries, `reflow` joins them without a space, and the precondition reports the count
as `mid_token=`. The shipped joiner used an unconditional space and corrupted
`pre-classification` and `discovery/connection` on ahet.37; the controls in `self_test`
are substring checks, not `norm()` equalities, so they actually fail against it.

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
# A line ending in a word character followed by `-` or `/` is a token BROKEN
# ACROSS LINES: `parse/` + `invalid-request`, `no-common-` + `modern`. Joining
# those with a space corrupts the word. The leading `\w` is load-bearing: it
# excludes `--` and `//`, where the trailing run is a dash separator or a path
# and a space IS correct. Measured over all 815 beads carrying criteria at
# 114759fd: 40 beads match a naive `[-/]$`, 39 match this, and the one it drops
# (bd-55ola, "NOT A NUMBER --" + "corrected ...") wants the space.
MID_TOKEN = re.compile(r"\w[-/]$")


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
    # THE INVERSION, encoded as a control so it cannot come back silently.
    mt_pre = "- Emits a parse/\n  invalid-request code."
    mt_good = "- [ ] Emits a parse/invalid-request code."
    mt_bad = "- [ ] Emits a parse/ invalid-request code."
    if mid_token_integrity(mt_pre, mt_good):
        print("CONTROL FAILED: guard E rejected a CORRECT mid-token join", file=sys.stderr)
        return False
    if not mid_token_integrity(mt_pre, mt_bad):
        print("CONTROL FAILED: guard E accepted a CORRUPTED token", file=sys.stderr)
        return False
    if norm(strip_back(mt_good)) != norm(strip_back(reflow(mt_pre))):
        print("CONTROL FAILED: like-to-like guard B rejected a correct repair", file=sys.stderr)
        return False
    if norm(strip_back(mt_bad)) == norm(strip_back(reflow(mt_pre))):
        print("CONTROL FAILED: like-to-like guard B accepted a corruption", file=sys.stderr)
        return False
    # Re-flow must preserve the author's word sequence exactly. NOTE: this is a
    # norm() equality, so it is BLIND to a space inserted at a mid-token break --
    # both sides normalise identically. The two controls below cover that, and
    # they are substring checks for exactly that reason.
    if norm(strip_back(reflow(good))) != norm(pre):
        print("CONTROL FAILED: re-flow did not preserve the author's words", file=sys.stderr)
        return False
    # A mid-token break must gain NO space. Fails against a reflow() that joins
    # unconditionally, which is the defect this pair exists to catch: it shipped,
    # and it corrupted `pre-classification` and `discovery/connection` on ahet.37.
    mt = "- [ ] emits a parse/\n  invalid-request response.\n- [ ] a no-common-\n  modern error."
    got = reflow(mt)
    if "parse/invalid-request" not in got or "parse/ invalid-request" in got:
        print("CONTROL FAILED: re-flow put a space at a '/' mid-token break", file=sys.stderr)
        return False
    if "no-common-modern" not in got or "no-common- modern" in got:
        print("CONTROL FAILED: re-flow put a space at a '-' mid-token break", file=sys.stderr)
        return False
    if len(mid_token_breaks(mt)) != 2:
        print("CONTROL FAILED: mid-token detector miscounted", file=sys.stderr)
        return False
    # NEGATIVE HALF: a `--` dash separator is not a broken token and the space
    # there is correct. Without this, the fix above would over-fire and silently
    # weld two clauses together -- a different corruption in the other direction.
    ds = "- [ ] A DERIVATION, NOT A NUMBER --\n  corrected later."
    if "NUMBER -- corrected" not in reflow(ds):
        print("CONTROL FAILED: re-flow welded a '--' dash separator", file=sys.stderr)
        return False
    if mid_token_breaks(ds):
        print("CONTROL FAILED: mid-token detector fired on a '--' separator", file=sys.stderr)
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
    """Join each item's continuation lines.

    Only whitespace moves -- EXCEPT at a mid-token break, where the correct
    amount of whitespace to insert is NONE. An author wrapping
    `parse/invalid-request` or `no-common-modern` leaves the line ending in
    `/` or `-` with the token resuming on the next line; joining there with a
    space silently changes the word.

    A whitespace-NORMALISING comparison cannot catch that, because it collapses
    the newline+indent being replaced, so the corrupted join and the author's
    original normalise to the identical string. That is why the control for
    this lives in `self_test` as a literal substring check and not as another
    `norm()` equality.
    """
    out = []
    for parts in _grouped(stored):
        body = ""
        for part in (p for p in parts if p):
            if not body:
                body = part.rstrip()
            elif MID_TOKEN.search(body):
                body += part
            else:
                body += " " + part
        out.append(PREFIX + body)
    return "\n".join(out)


def mid_token_breaks(stored: str) -> list[tuple[str, str]]:
    """Continuation boundaries where the author broke a token across lines.

    Reported so a human sees them, because joining one is the single place
    re-flow stops being purely mechanical: it has to decide whether a trailing
    hyphen belongs to the word or ends it. `reflow` takes the word-break
    reading, which is right for every instance measured in this tracker, but
    the count belongs in the output rather than buried in the joiner.
    """
    out: list[tuple[str, str]] = []
    lines = stored.split("\n")
    for i in range(len(lines) - 1):
        nxt = lines[i + 1]
        if _item_start(nxt) is not None or not nxt.strip():
            continue
        if MID_TOKEN.search(lines[i].rstrip()):
            out.append((lines[i].rstrip()[-30:], nxt.strip()[:30]))
    return out


def mid_token_integrity(preimage: str, stored: str) -> list[str]:
    """Joiner-INDEPENDENT oracle for the one class re-flow can corrupt.

    For each place the AUTHOR broke a token across lines, the joined form must
    appear in the stored text and the SPACED form must not. It derives the
    expected token from the pre-image alone and never asks the joiner what it
    would have produced, so it remains an oracle even when the joiner is wrong
    -- which is exactly the state this tool shipped in between 175bec41 and
    8b6a92df.

    This is the check guard B cannot be. Guard B is a norm() equality, and
    norm() collapses the newline the corruption replaces: the author's
    "no-common-\nmodern" and the corrupt "no-common- modern" normalise to the
    same string, so guard B PASSED the corruption and, once the joiner was
    fixed, FAILED the repair. A proof that normalises away the thing it is
    testing cannot test it.
    """
    findings: list[str] = []
    lines = preimage.split("\n")
    for i in range(len(lines) - 1):
        left, nxt = lines[i].rstrip(), lines[i + 1]
        right = nxt.strip()
        if not right or _item_start(nxt) is not None or not MID_TOKEN.search(left):
            continue
        tail, head = left.split()[-1], right.split()[0]
        joined, spaced = tail + head, tail + " " + head
        if spaced in stored:
            findings.append(f"GUARD E FAIL: space inserted inside a token -- '{spaced}'")
        elif joined not in stored:
            findings.append(f"GUARD E FAIL: joined token absent -- expected '{joined}'")
    return findings


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
    mid = len(mid_token_breaks(stored))
    return (
        nested == 0 and blank == 0,
        f"continuations={cont} nested={nested} blank={blank} mid_token={mid}",
    )


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
    print("controls: correct-verifies, corrupt-rejects, mutated-preimage-rejects, advisory pos+neg, wrapped-item-whole, precondition pos+neg, prose-form-grouping, reflow-preserves-words, mid-token pos+neg, guardB-inversion pos+neg  OK")

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
        # LIKE TO LIKE. The old form compared against norm() of the RAW
        # pre-image, which re-introduces the space at a mid-token break and so
        # inverted on exactly the beads that matter. It now compares against the
        # pre-image put through the SAME joiner. That makes it joiner-dependent
        # and therefore no longer an oracle for the token class -- guard E is.
        gB = norm(strip_back(stored)) == norm(strip_back(reflow(preimage)))
        gE_findings = mid_token_integrity(preimage, stored)
        gC = len(_grouped(stored)) == len(_grouped(preimage))
        gD = "- [x]" not in stored
        findings = [f"RE-FLOWED FORM: P2/P3 do not apply; guards used instead ({detail})"]
        for label, val in (
            ("A only-whitespace-moved", gA),
            ("B re-derives the author's words", gB),
            ("C item count unchanged", gC),
            ("D zero ticked", gD),
            ("E mid-token integrity (joiner-independent)", not gE_findings),
            ("precondition wrapped-clauses-only", pre_ok),
        ):
            findings.append(f"  GUARD {label}: {'PASS' if val else 'FAIL'}")
        findings.extend("  " + f for f in gE_findings)
        ok = gA and gB and gC and gD and pre_ok and not gE_findings
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
