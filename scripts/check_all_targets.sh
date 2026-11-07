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
#   scripts/check_all_targets.sh [--retries N] [--json] [--dry-run]
#       [--arm default|all-features|no-default-features|both|all]
#       [--base <rev>] [--working-tree]
#
#   SOURCE: by default every arm builds the COMMITTED revision (HEAD, or
#   --base <rev>) through `rch exec --base .. --clean-overlay --no-overlay`, so
#   the receipt binds a revision and the live checkout is never read. Pass
#   --working-tree for the old behaviour, which rsyncs the working copy and is
#   therefore void if anything tracked moves during the run -- including the
#   orchestrator's own `br` flush, which writes a TRACKED .beads/issues.jsonl.
#
#   Every arm runs with `--keep-going`, so one error does not hide the rest:
#   cargo fail-fasts by default, which is why a red run understates the red set
#   and why repairing this tree took five sequential rounds on 2026-11-07.
#
#   `both` = default + all-features (the cheap pre-submit pair).
#   `all`  = adds --no-default-features, which bd-yhx86 measured as a THIRD
#            non-comparable projection with lint rows the other two cannot see.

set -uo pipefail

RETRIES=3
JSON=0
ARM=both
DRY=0
# SOURCE MODE. `base` (the default) dispatches
#   rch exec --base <rev> --clean-overlay --no-overlay
# so the worker builds a COMMITTED revision and the working tree is never read.
# `working-tree` is the old behaviour: plain `rch exec`, which rsyncs the live
# checkout.
#
# WHY THE DEFAULT CHANGED. A receipt from working-tree mode is only bindable if
# nothing tracked changes for the whole run, and that is unattainable here. The
# orchestrator's own job is to close beads; `br` auto-flushes
# .beads/issues.jsonl, which is TRACKED; so closing a bead voided the receipt of
# the gate that exists to support closing beads. Other lanes push every few
# minutes too -- five commits landed during one run -- and the guard voids on a
# moved HEAD as well. I voided two consecutive receipts this way.
#
# Binding a revision is also the stronger claim, and it is what
# scripts/verify_batch.sh already does.
SOURCE_MODE=base

# `${2:?msg}` would exit 1 on a missing OR empty value, reporting a usage error
# with a code this script documents as something else. Check explicitly so every
# usage failure is 64.
need_value() {
  if [ "$#" -lt 2 ] || [ -z "$2" ]; then
    echo "$1 needs a non-empty value" >&2
    exit 64
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --retries) need_value "$@"; RETRIES="$2"; shift 2 ;;
    --json)    JSON=1; shift ;;
    --arm)     need_value "$@"; ARM="$2"; shift 2 ;;
    # --dry-run exists because exercising the argument paths of a script that
    # performs real work costs real work: validating these five --arm values
    # by running them dispatched five multi-arm remote builds. Validate the
    # parsing without touching the fleet.
    --dry-run) DRY=1; shift ;;
    --working-tree) SOURCE_MODE=working-tree; shift ;;
    --base)
      need_value --base "${2:-}"
      BASE_OVERRIDE="$2"; shift 2 ;;
    -h|--help) sed -n '1,45p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

# Validate usage BEFORE any side effect. Previously this lived after the
# preflight, so `--arm bogus` on a dirty tracker exited 3 (preflight refused)
# instead of 64 (bad usage) -- a usage error reported as an environment error.
case "$ARM" in
  both|all|default|all-features|no-default-features) ;;
  *) echo "--arm must be one of: default, all-features, no-default-features, both, all" >&2
     exit 64 ;;
esac
case "$RETRIES" in
  ''|*[!0-9]*) echo "--retries must be a positive integer, got '$RETRIES'" >&2; exit 64 ;;
  0)           echo "--retries must be at least 1" >&2; exit 64 ;;
esac

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
# Compare the porcelain output directly rather than hashing it. `sha256sum` is
# NOT on a stock macOS (that is `shasum -a 256`), and if it were missing this
# function would silently return the empty string for both the before and after
# reading, making them compare EQUAL and quietly disabling the moving-checkout
# guard. A safety check that fails silently is worse than one that is absent.
dirty_fingerprint() { git status --porcelain --untracked-files=no; }
FP_BEFORE=$(dirty_fingerprint)
# Only a working-tree dispatch can be disturbed by a live checkout. In base mode
# the worker builds from git objects, which are immutable for a given revision,
# so a concurrent tracker write cannot change what gets compiled.
if [ "$SOURCE_MODE" = working-tree ] &&
   git status --porcelain --untracked-files=no -- .beads | grep -q .; then
  echo "PREFLIGHT REFUSED: .beads has tracked modifications, so the checkout is" >&2
  echo "  probably being mutated, and --working-tree rsyncs it. Let the tracker" >&2
  echo "  settle, re-run, or use the default base mode." >&2
  echo "  (Run 'br sync --flush-only' and commit, or wait for the writer.)" >&2
  exit 3
fi

HEAD_SHA=$(git rev-parse HEAD)
# Captured ONCE. Everything below binds this revision, so a later HEAD move
# cannot retroactively change what any arm compiled.
BASE=$(git rev-parse "${BASE_OVERRIDE:-HEAD}^{commit}" 2>/dev/null) || {
  echo "--base does not resolve to a commit: ${BASE_OVERRIDE:-HEAD}" >&2
  exit 64
}
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
    # Progress to STDERR only. run_arm's STDOUT is the tab-separated verdict
    # line the caller parses, and anything else there corrupts the field split.
    # Without this the script prints nothing until every arm finishes, so a
    # thirty-minute arm is indistinguishable from a hang.
    echo "  $(date -u +%H:%M:%SZ) $label: dispatching try $try/$RETRIES" >&2
    # Deliberately NOT pinning a worker: RCH sizes some commands at 8 cores and
    # a pinned 3-slot box can never satisfy that (RCH-I003 no_free_slots) even
    # with most of the fleet idle. Let the scheduler pick.
    # --keep-going, on bd-zqn34's recommendation and on this session's own
    # evidence. Cargo FAIL-FASTS by default: one error hides the rest, so a red
    # run understates the red set and you learn the next layer only after
    # repairing the current one. Repairing HEAD today took FIVE sequential
    # rounds for exactly that reason, and bd-zqn34 lists five separate
    # occurrences of the same class in one session. --keep-going surfaces them
    # together.
    #
    # It does NOT weaken the verdict: a run that would have exited non-zero
    # still does, it just reports more of why. members_reached also becomes a
    # truer figure, because cargo no longer stops scheduling at the first
    # failure.
    if [ "$SOURCE_MODE" = base ]; then
      rch exec --base "$BASE" --clean-overlay --no-overlay -- \
        cargo check --workspace --all-targets --keep-going "$@" >"$log" 2>&1
    else
      rch exec -- cargo check --workspace --all-targets --keep-going "$@" >"$log" 2>&1
    fi
    # The wrapper's exit status can mask the remote one; this line is the
    # authoritative remote exit, and its ABSENCE means no verdict at all.
    remote=$(strip_ansi <"$log" | grep -oE 'Remote command finished: exit=[0-9]+' | tail -1 | grep -oE '[0-9]+$')
    if [ -n "${remote:-}" ]; then
      members=$(strip_ansi <"$log" | grep -oE 'Checking fastmcp[a-z-]*' | sort -u | wc -l | tr -d ' ')
      errors=$(strip_ansi <"$log" | grep -cE '^error' || true)
      cnc=$(strip_ansi <"$log" | grep -c 'could not compile' || true)
      # Default to 0: `grep -c` prints "0" and exits 1 when it matches nothing
      # (handled by `|| true`), but exits 2 printing NOTHING on a read error,
      # which would leave these empty and make `[ "" -eq 0 ]` a bash syntax
      # error that silently evaluates false -- classifying a green run as red.
      errors=${errors:-0}
      cnc=${cnc:-0}
      members=${members:-0}
      if [ "$remote" -eq 0 ] && [ "$errors" -eq 0 ] && [ "$cnc" -eq 0 ]; then
        printf 'green\t%s\t%s\t%s\t%s\t%s\n' "$remote" "$members" "$errors" "$cnc" "$log"
        return 0
      fi
      # RED REQUIRES COMPILER EVIDENCE, NOT MERELY A NONZERO EXIT.
      #
      # Measured 2026-11-07: the default arm ended
      #   Remote command finished: exit=137 in 1811703ms
      # which is SIGKILL at RCH's thirty-minute external deadline -- the log
      # carries RCH_EXTERNAL_DEADLINE:..._DISK_USAGE with "complete":false, and
      # peak disk growth was 1.0GB against a 10GB budget, so disk was not the
      # constraint. Nothing compiled and failed; the command was STOPPED. The
      # earlier form (`green` iff exit==0 && no errors, everything else `red`)
      # reported that as a real compile failure, and did the same to the
      # --no-default-features arm. Two of three arms misclassified, by the
      # very gate whose header calls a false red the thing that makes a lane
      # untrustworthy.
      #
      # Void detection cannot key on the ABSENCE of the `Remote command
      # finished: exit=N` line, because a kill still prints it. It has to key
      # on whether the compiler said anything.
      if [ "$errors" -gt 0 ] || [ "$cnc" -gt 0 ]; then
        printf 'red\t%s\t%s\t%s\t%s\t%s\n' "$remote" "$members" "$errors" "$cnc" "$log"
        return 0
      fi
      echo "  $label: try $try exited $remote with ZERO compiler diagnostics after reaching $members member(s) -- stopped, not failed (void); retrying on a fresh worker draw" >&2
      continue
    fi
    echo "  $label: try $try produced no verdict at all, no remote exit line (void), retrying" >&2
  done
  # Placeholders, not empty fields: TAB is IFS whitespace, so bash collapses a
  # run of consecutive tabs into ONE delimiter and strips leading/trailing
  # ones. Emitting five empty fields therefore shifted the log path into
  # remote_exit in the JSON. Observed 2026-11-05 on the first live run.
  printf 'void\t-\t-\t-\t-\t%s\n' "$LOGDIR/${label}.$RETRIES.log"
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

if [ "$DRY" -eq 1 ]; then
  echo "dry run: arm selection '$ARM', retries $RETRIES, json $JSON"
  if [ "$SOURCE_MODE" = base ]; then
    echo "would dispatch: rch exec --base $BASE --clean-overlay --no-overlay --"
  else
    echo "would dispatch: rch exec --   (LIVE WORKING TREE; receipt not bindable)"
  fi
  echo "would run:"
  { [ "$ARM" = both ] || [ "$ARM" = all ] || [ "$ARM" = default ]; } &&
    echo "  cargo check --workspace --all-targets --keep-going"
  { [ "$ARM" = both ] || [ "$ARM" = all ] || [ "$ARM" = all-features ]; } &&
    echo "  cargo check --workspace --all-targets --keep-going --all-features"
  { [ "$ARM" = all ] || [ "$ARM" = no-default-features ]; } &&
    echo "  cargo check --workspace --all-targets --keep-going --no-default-features"
  exit 0
fi

if [ "$ARM" = both ] || [ "$ARM" = all ] || [ "$ARM" = default ]; then
  run_and_record default
fi
if [ "$ARM" = both ] || [ "$ARM" = all ] || [ "$ARM" = all-features ]; then
  run_and_record all-features --all-features
fi
# THIRD ARM. bd-yhx86 measured three lint rows that exist ONLY at
# --no-default-features, two of them rustc dead_code: with legacy-2024-11-05
# off, handle_application_tools_call_in_request (router.rs, exactly one caller)
# and LegacyToolResultMode::Application lose their only caller. Its words: "a
# 22-finding projection is not a subset of a 73-finding one". So the three
# feature projections are mutually non-comparable and a two-arm gate is still
# blind. Not in `both` (which stays the cheap pre-submit pair); use `--arm all`.
if [ "$ARM" = all ] || [ "$ARM" = no-default-features ]; then
  run_and_record no-default-features --no-default-features
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
# Explicit if, not `[ a ] && [ b ] && assign`: I flagged that precedence trap
# in this file's own comments and should not then rely on it.
#
# A MOVED CHECKOUT ONLY VOIDS A WORKING-TREE DISPATCH. In base mode every arm
# compiled the committed revision in $BASE, which no later edit or push can
# alter, so the verdict still binds and movement is reported as a note rather
# than discarding a real result. That distinction is the whole point of the
# default source mode: the old behaviour could not tell "a tracked file that is
# not a compile input changed" (the orchestrator flushing the bead tracker) from
# "the source moved", and voided a green for the former.
if [ "$MOVED" -eq 1 ] && [ "$status" -eq 0 ] && [ "$SOURCE_MODE" = working-tree ]; then
  status=2
fi

if [ "$JSON" -eq 1 ]; then
  printf '{"head":"%s","tree":"%s","source_mode":"%s","base":"%s","dirty_rs":%s,"checkout_moved":%s,"arms":[' \
    "$HEAD_SHA" "$TREE_SHA" "$SOURCE_MODE" "$BASE" "$DIRTY_RS" "$MOVED"
  for i in "${!NAMES[@]}"; do
    [ "$i" -gt 0 ] && printf ','
    printf '{"arm":"%s","verdict":"%s","remote_exit":"%s","members_reached":"%s","error_lines":"%s","could_not_compile":"%s","log":"%s"}' \
      "${NAMES[$i]}" "${VERDICTS[$i]}" "${EXITS[$i]}" "${MEMBERS[$i]}" "${ERRS[$i]}" "${CNCS[$i]}" "${LOGS[$i]}"
  done
  printf '],"exit":%s}\n' "$status"
else
  echo
  echo "compile gate -- HEAD $HEAD_SHA tree $TREE_SHA dirty_rs=$DIRTY_RS"
  if [ "$SOURCE_MODE" = base ]; then
    echo "  source: committed revision $BASE (rch --base --clean-overlay --no-overlay);"
    echo "          the working tree was NOT read, so this receipt binds that revision."
  else
    echo "  source: LIVE WORKING TREE (--working-tree); this receipt binds no revision"
    echo "          on its own and is void if anything tracked moved."
  fi
  for i in "${!NAMES[@]}"; do
    printf '  %-13s %-5s remote_exit=%-3s members_reached=%-3s error_lines=%-3s could_not_compile=%-3s\n' \
      "${NAMES[$i]}" "${VERDICTS[$i]}" "${EXITS[$i]:--}" "${MEMBERS[$i]:--}" "${ERRS[$i]:--}" "${CNCS[$i]:--}"
    echo "                log: ${LOGS[$i]}"
  done
  if [ "$MOVED" -eq 1 ]; then
    if [ "$SOURCE_MODE" = base ]; then
      echo "  NOTE: the checkout moved during the run (a tracked file changed or HEAD"
      echo "        advanced). The verdicts above are UNAFFECTED: every arm compiled"
      echo "        $BASE from git objects, which no later edit can alter."
    else
      echo "  WARNING: the checkout moved during the run; this receipt is not bindable."
    fi
  fi
  case $status in
    0) echo "  RESULT: green (every requested arm compiled)" ;;
    1) echo "  RESULT: RED -- at least one arm compiled and FAILED, with compiler"
       echo "          diagnostics to prove it. Note members_reached: cargo stops"
       echo "          scheduling after a failure, so the red set is a FLOOR, not a count." ;;
    2) echo "  RESULT: NO VERDICT (void, or a moving checkout in --working-tree mode)."
       echo "          This is NOT a red; retry." ;;
  esac
fi

exit "$status"
