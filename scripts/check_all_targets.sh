#!/usr/bin/env bash
# check_all_targets.sh -- the compile gate for this workspace.
#
# WHY THIS EXISTS (bd-all-targets-gate-missing-0xgae). AGENTS.md names
# `cargo check --workspace --all-targets` under "Compiler Checks (CRITICAL)",
# but nothing ran it on a schedule, and the same defect class recurred SIX
# times in fifteen days: bd-l7s5f (2026-10-19), bd-7good (2026-10-27),
# bd-htrmq (2026-10-28), bd-client-http-negotiation-path-0h82w (2026-11-02),
# plus two more on 2026-11-02 found by hand -- one of which was the SHIPPED
# `fastmcp` CLI binary, broken for three days.
#
# THREE BLIND SPOTS IT CLOSES, each measured rather than assumed:
#   1. A lib-test target is invisible to every dependent. fastmcp-client's
#      library compiled while its test target was broken, so ordinary work
#      never surfaced it.
#   2. NEITHER FEATURE ARM IS A SUPERSET OF THE OTHER. Measured 2026-11-05:
#      the DEFAULT arm caught an E0433 in the CLI bin that the --all-features
#      arm never reached. Running one arm is structurally blind.
#   3. Cargo stops scheduling new units after a failure, so a red run
#      UNDERSTATES the red set. This script therefore reports how many
#      workspace members were actually reached, not just an exit code.
#
# AND THE THING THAT MAKES A REMOTE GATE TRUSTWORTHY: a VOID IS NOT A RED.
# RCH's own telemetry reports a 43-44% command success rate. A dispatch that
# never produced a verdict (SSH timeout, disk-budget admission refusal, source
# namespace refusal, slot-sizing refusal) must exit distinctly from a dispatch
# that compiled and failed. Conflating them is what makes a lane untrustworthy:
# it manufactures both false reds and -- worse -- false greens.
#
# EXIT CODES
#   0  both arms GREEN
#   1  an arm compiled and FAILED (a real red)
#   2  no verdict could be obtained (void) -- NOT a red, retry later
#   3  preflight refused (dirty tracker / moving checkout)
#
# USAGE
#   scripts/check_all_targets.sh [--retries N] [--json] [--arm default|all-features|both]

set -uo pipefail

RETRIES=3
JSON=0
ARM=both

while [ $# -gt 0 ]; do
  case "$1" in
    --retries) RETRIES="${2:?--retries needs a value}"; shift 2 ;;
    --json)    JSON=1; shift ;;
    --arm)     ARM="${2:?--arm needs a value}"; shift 2 ;;
    -h|--help) sed -n '1,40p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "not a git repository" >&2; exit 64; }
cd "$ROOT" || exit 64
command -v rch >/dev/null 2>&1 || { echo "rch is not on PATH" >&2; exit 64; }

LOGDIR=$(mktemp -d "${TMPDIR:-/tmp}/check_all_targets.XXXXXX")

# PREFLIGHT: refuse a moving checkout.
# .beads/beads.db and .beads/issues.jsonl are TRACKED and large. A concurrent
# tracker-mutation loop keeps the working tree changing under RCH's sync, and
# admission then refuses with RCH_SYNC_LIVE_CHECKOUT_REFUSED /
# RCH_SOURCE_NAMESPACE_INTERRUPTED. Measured 2026-11-05: four workers voided
# during a concurrent rewire, then the same command greened on the first
# attempt once serialized. Refusing up front is cheaper than four voids.
dirty_fingerprint() { git status --porcelain --untracked-files=no | sha256sum | cut -c1-16; }
FP_BEFORE=$(dirty_fingerprint)
if git status --porcelain --untracked-files=no -- .beads | grep -q .; then
  echo "PREFLIGHT REFUSED: .beads has tracked modifications, so the checkout is" >&2
  echo "  probably being mutated. Let the tracker settle, then re-run." >&2
  echo "  (Run 'br sync --flush-only' and commit, or wait for the writer.)" >&2
  exit 3
fi

HEAD_SHA=$(git rev-parse HEAD)
TREE_SHA=$(git rev-parse 'HEAD^{tree}')
DIRTY_RS=$(git status --porcelain --untracked-files=no -- '*.rs' | wc -l | tr -d ' ')

strip_ansi() { sed 's/\x1b\[[0-9;]*m//g'; }

# Runs one arm. Echoes "verdict<TAB>exit<TAB>members<TAB>errors<TAB>cnc<TAB>log".
# verdict is green | red | void.
run_arm() {
  local label="$1"; shift
  local try log remote members errors cnc
  for try in $(seq 1 "$RETRIES"); do
    log="$LOGDIR/${label}.$try.log"
    # Deliberately NOT pinning a worker: RCH sizes some commands at 8 cores and
    # a pinned 3-slot box can never satisfy that (RCH-I003 no_free_slots) even
    # with most of the fleet idle. Let the scheduler pick.
    rch exec -- cargo check --workspace --all-targets "$@" >"$log" 2>&1
    # The wrapper's exit status can mask the remote one; this line is the
    # authoritative remote exit, and its ABSENCE means no verdict at all.
    remote=$(strip_ansi <"$log" | grep -oE 'Remote command finished: exit=[0-9]+' | tail -1 | grep -oE '[0-9]+$')
    if [ -n "${remote:-}" ]; then
      members=$(strip_ansi <"$log" | grep -oE 'Checking fastmcp[a-z-]*' | sort -u | wc -l | tr -d ' ')
      errors=$(strip_ansi <"$log" | grep -cE '^error' || true)
      cnc=$(strip_ansi <"$log" | grep -c 'could not compile' || true)
      if [ "$remote" -eq 0 ] && [ "$errors" -eq 0 ] && [ "$cnc" -eq 0 ]; then
        printf 'green\t%s\t%s\t%s\t%s\t%s\n' "$remote" "$members" "$errors" "$cnc" "$log"
      else
        printf 'red\t%s\t%s\t%s\t%s\t%s\n' "$remote" "$members" "$errors" "$cnc" "$log"
      fi
      return 0
    fi
    echo "  $label: try $try produced no verdict (void), retrying" >&2
  done
  printf 'void\t\t\t\t\t%s\n' "$LOGDIR/${label}.$RETRIES.log"
  return 0
}

declare -a NAMES=() VERDICTS=() EXITS=() MEMBERS=() ERRS=() CNCS=() LOGS=()
record() {
  NAMES+=("$1"); VERDICTS+=("$2"); EXITS+=("$3")
  MEMBERS+=("$4"); ERRS+=("$5"); CNCS+=("$6"); LOGS+=("$7")
}

run_and_record() {
  local name="$1"; shift
  local line
  line=$(run_arm "$name" "$@")
  IFS=$'\t' read -r v e m er c l <<<"$line"
  record "$name" "$v" "$e" "$m" "$er" "$c" "$l"
}

# Explicit ifs: `[ a ] || [ b ] && cmd` parses as `([ a ] || [ b ]) && cmd`,
# which happens to work here but is a precedence trap waiting for an edit.
case "$ARM" in
  both|default|all-features) ;;
  *) echo "--arm must be one of: default, all-features, both" >&2; exit 64 ;;
esac

if [ "$ARM" = both ] || [ "$ARM" = default ]; then
  run_and_record default
fi
if [ "$ARM" = both ] || [ "$ARM" = all-features ]; then
  run_and_record all-features --all-features
fi

# A checkout that moved mid-run invalidates the receipt: the arms would have
# measured different bytes. This repository is multi-lane and HEAD moves often.
FP_AFTER=$(dirty_fingerprint)
HEAD_AFTER=$(git rev-parse HEAD)
MOVED=0
if [ "$FP_BEFORE" != "$FP_AFTER" ] || [ "$HEAD_AFTER" != "$HEAD_SHA" ]; then MOVED=1; fi

status=0
for i in "${!NAMES[@]}"; do
  case "${VERDICTS[$i]}" in
    red)  status=1 ;;
    void) [ "$status" -eq 1 ] || status=2 ;;
  esac
done
[ "$MOVED" -eq 1 ] && [ "$status" -eq 0 ] && status=2

if [ "$JSON" -eq 1 ]; then
  printf '{"head":"%s","tree":"%s","dirty_rs":%s,"checkout_moved":%s,"arms":[' \
    "$HEAD_SHA" "$TREE_SHA" "$DIRTY_RS" "$MOVED"
  for i in "${!NAMES[@]}"; do
    [ "$i" -gt 0 ] && printf ','
    printf '{"arm":"%s","verdict":"%s","remote_exit":"%s","members_reached":"%s","error_lines":"%s","could_not_compile":"%s","log":"%s"}' \
      "${NAMES[$i]}" "${VERDICTS[$i]}" "${EXITS[$i]}" "${MEMBERS[$i]}" "${ERRS[$i]}" "${CNCS[$i]}" "${LOGS[$i]}"
  done
  printf '],"exit":%s}\n' "$status"
else
  echo
  echo "compile gate -- HEAD $HEAD_SHA tree $TREE_SHA dirty_rs=$DIRTY_RS"
  for i in "${!NAMES[@]}"; do
    printf '  %-13s %-5s remote_exit=%-3s members_reached=%-3s error_lines=%-3s could_not_compile=%-3s\n' \
      "${NAMES[$i]}" "${VERDICTS[$i]}" "${EXITS[$i]:--}" "${MEMBERS[$i]:--}" "${ERRS[$i]:--}" "${CNCS[$i]:--}"
    echo "                log: ${LOGS[$i]}"
  done
  [ "$MOVED" -eq 1 ] && echo "  WARNING: the checkout moved during the run; this receipt is not bindable."
  case $status in
    0) echo "  RESULT: green (every requested arm compiled)" ;;
    1) echo "  RESULT: RED -- a real compile failure. Note members_reached: cargo stops"
       echo "          scheduling after a failure, so the red set is a FLOOR, not a count." ;;
    2) echo "  RESULT: NO VERDICT (void or moving checkout). This is NOT a red; retry." ;;
  esac
fi

exit "$status"
