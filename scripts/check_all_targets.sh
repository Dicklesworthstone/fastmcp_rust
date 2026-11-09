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
# FOUR BLIND SPOTS IT CLOSES, each measured rather than assumed:
#   1. A lib-test target is invisible to every dependent. fastmcp-client's
#      library compiled while its test target was broken, so ordinary work
#      never surfaced it.
#   2. NEITHER FEATURE ARM IS A SUPERSET OF THE OTHER. Measured 2026-11-05:
#      the DEFAULT arm caught an E0433 in the CLI bin that the --all-features
#      arm never reached. Running one arm is structurally blind.
#   3. Cargo stops scheduling new units after a failure, so a red run
#      UNDERSTATES the red set. This script therefore reports how many
#      workspace members were actually reached, not just an exit code.
#   4. `--all-targets` DOES NOT MEAN EVERY TARGET. A target whose
#      `required-features` the arm does not enable is SILENTLY SKIPPED and
#      cargo still exits 0. Measured at 8c5b77d4: 178 targets, 39 with
#      `required-features`, of which the DEFAULT arm skips 34 and
#      `--no-default-features` skips all 39; `--all-features` skips none. The
#      script now reports that per arm, so a green can never be mistaken for
#      full target coverage. See `gated_target_census` below -- it is pure
#      reporting and cannot change a verdict or an exit code.
#
# AND THE THING THAT MAKES A REMOTE GATE TRUSTWORTHY: a VOID IS NOT A RED.
# RCH's own telemetry reports a 43-44% command success rate. A dispatch that
# never produced a verdict (SSH timeout, disk-budget admission refusal, source
# namespace refusal, slot-sizing refusal) must exit distinctly from a dispatch
# that compiled and failed. Conflating them is what makes a lane untrustworthy:
# it manufactures both false reds and -- worse -- false greens.
#
# EXIT CODES
#   0  every REQUESTED arm GREEN (one, two or three, per --arm)
#   1  an arm compiled and FAILED (a real red)
#   2  no verdict could be obtained (void) -- NOT a red, retry later
#   3  preflight refused (dirty tracker / moving checkout)
#
# USAGE
#   scripts/check_all_targets.sh [--retries N] [--json] [--dry-run]
#       [--arm default|all-features|no-default-features|both|all]
#       [--base <rev>] [--working-tree] [--local] [--local-timeout-sec N]
#
#   SOURCE: by default every arm builds the COMMITTED revision (HEAD, or
#   --base <rev>) through `rch exec --base .. --clean-overlay --no-overlay`, so
#   the receipt binds a revision and the live checkout is never read. Pass
#   --working-tree for the old behaviour, which rsyncs the working copy and is
#   therefore void if anything tracked moves during the run -- including the
#   orchestrator's own `br` flush, which writes a TRACKED .beads/issues.jsonl.
#
#   --local RUNS THE ARMS ON THIS MACHINE instead of dispatching them. Both
#   other modes go through `rch exec`, so when RCH cannot resolve a toolchain
#   the gate has no way to run AT ALL -- which is the state bd-09nja measures:
#   a hardcoded 5s version probe against a toolchain on an exFAT/FSKit
#   userspace volume where `cargo --version` has been seen to exceed 90s. A
#   gate that cannot run is indistinguishable from a gate that passes, so
#   --local is the fallback that keeps a verdict obtainable.
#
#   WHAT --local COSTS, stated so nobody reads it as equivalent:
#     - it reads the LIVE WORKING TREE, so like --working-tree it binds no
#       revision and is void if the checkout moves;
#     - it compiles on this machine, which is the thing RCH exists to avoid.
#       Use it to get unblocked, never for the receipt that closes a bead;
#     - it shares ONE build-directory lock with every other local cargo on
#       this CARGO_TARGET_DIR (bd-6allt), so it can spend its entire budget
#       waiting instead of compiling. That is reported as a VOID with the lock
#       named, not as a red.
#   The bound is --local-timeout-sec (default 1800). Exceeding it is a void.
#   Retries still apply, but there is no fresh worker to draw: a local retry
#   only helps if the cause was transient, so --retries 1 is usually right.
#   In --json the `remote_exit` field carries the LOCAL exit status in this
#   mode (there is no remote); the text receipt relabels it `local_exit`.
#
#   PICK THE MODE FOR THE JOB; the difference is a cold cache, not a detail.
#   `--clean-overlay` builds in a per-pairing directory on the worker --
#   observed: /data/tmp/fastmcp_rust/paired-670fdc34../ -- under its own rch
#   project namespace, and the FIRST base-mode run on a given worker is cold.
#
#   IT DOES WARM, though, and an earlier version of this comment overstated the
#   cost. I had inferred from two `rch queue` lines at different bases that the
#   namespace is keyed on the base revision and therefore never warms across
#   commits. A third run refuted the strong form: at base 4d6f32d9 the default
#   arm came back `Finished dev profile in 0.55s` with ZERO members reached --
#   fully cached -- on a worker that had compiled this content before, while the
#   all-features arm on the same worker compiled 8 members in 2m50s. So the
#   earlier cold draws were worker-specific, not proof that each revision gets a
#   fresh namespace.
#
#   What survives, and is what matters: a COLD --workspace --all-targets does
#   NOT fit RCH's ~30-minute check-wrapper deadline on a slow worker (killed at
#   1811s three times on 2026-11-07; 248-330s warm, 0.55s fully cached), and
#   which you draw is luck. Retry-on-void is the mechanism that absorbs it.
#
#     --working-tree   uses the project's long-warm namespace; binds NO
#                      revision. Right for an iterative fix-and-recheck loop.
#     base (default)   cold on a worker's first pairing, warm after; BINDS the
#                      revision and survives tracker writes and foreign pushes.
#                      Right for the receipt that closes a bead.
#
#   Retry-on-void is what makes the cold draw a delay instead of a false red.
#   NOT measured: whether rch shares any compilation cache across namespaces.
#
#   AND DO NOT EDIT THIS FILE WHILE IT IS RUNNING. Bash reads a script
#   incrementally from its open fd; rewriting it mid-run makes bash resume at a
#   shifted offset. Measured 2026-11-07: a run looked healthy for thirty
#   minutes and then died with "line 269: local: can only be used in a
#   function", losing both arms and producing no receipt. Copy it to a
#   scratchpad and run the copy for long jobs.
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
# `local` is the third mode: no dispatch at all, the arms run here. See the
# --local paragraph in the header for why it exists and what it gives up.
SOURCE_MODE=base
# Which source-mode flag was passed, so that giving two DIFFERENT ones is
# refused rather than silently honouring whichever came last. Records the flag
# NAME, not a count: a count cannot tell `--local --local` (harmless) from
# `--local --working-tree` (a contradiction), and would report the first as
# the second.
MODE_FLAG_SEEN=""

# Bound for --local only. A local arm has no remote deadline to stop it, and
# the shared build-directory lock (bd-6allt) can hold it indefinitely WITHOUT
# compiling anything, so an unbounded local run is a hang. Exceeding this is a
# VOID and never a red: `timeout` exits 124 having produced zero compiler
# diagnostics, which is exactly the condition the verdict logic below already
# classifies as stopped-rather-than-failed.
LOCAL_TIMEOUT_SEC=1800
# `timeout` is coreutils and is not guaranteed wherever this runs: on this
# Darwin host it is /opt/homebrew/bin/timeout and /usr/bin/timeout DOES NOT
# EXIST, which silently voided an earlier probe of mine that hardcoded the
# absolute path. Resolve it by name, and run unbounded if it is absent rather
# than refusing to run at all.
TIMEOUT_BIN=$(command -v timeout 2>/dev/null || true)

# Bound for the gated-target census, which execs `cargo metadata`. "Compiles
# nothing" is NOT "returns quickly": exec'ing cargo on the FSKit toolchain
# volume has been measured above 90s (bd-09nja), and the census runs BEFORE any
# arm, so unbounded it can hang the entire gate while producing nothing. It is
# pure reporting and must never be able to do that.
CENSUS_TIMEOUT_SEC=120

# `${2:?msg}` would exit 1 on a missing OR empty value, reporting a usage error
# with a code this script documents as something else. Check explicitly so every
# usage failure is 64.
need_value() {
  if [ "$#" -lt 2 ] || [ -z "$2" ]; then
    echo "$1 needs a non-empty value" >&2
    exit 64
  fi
}

# Selects a source mode, refusing a second DIFFERENT one and naming both flags
# in the message so the error describes what was actually passed.
set_mode() {
  if [ -n "$MODE_FLAG_SEEN" ] && [ "$MODE_FLAG_SEEN" != "$1" ]; then
    echo "--$MODE_FLAG_SEEN and --$1 are mutually exclusive: they are different" >&2
    echo "  answers to the same question (what an arm compiles, and where)." >&2
    exit 64
  fi
  MODE_FLAG_SEEN="$1"
  SOURCE_MODE="$1"
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
    --working-tree) set_mode working-tree; shift ;;
    --local) set_mode local; shift ;;
    --local-timeout-sec) need_value "$@"; LOCAL_TIMEOUT_SEC="$2"; shift 2 ;;
    --base)
      need_value --base "${2:-}"
      BASE_OVERRIDE="$2"; shift 2 ;;
    # Print the whole leading comment block instead of a fixed line count. The
    # previous `sed -n '1,45p'` stopped mid-synopsis, so --arm, --base and
    # --working-tree were invisible on the one surface whose job is to document
    # them. Stopping at the first non-comment line cannot drift as the header
    # grows.
    -h|--help) awk '/^[^#]/{exit} {print}' "$0"; exit 0 ;;
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
case "$LOCAL_TIMEOUT_SEC" in
  ''|*[!0-9]*) echo "--local-timeout-sec must be a positive integer, got '$LOCAL_TIMEOUT_SEC'" >&2
               exit 64 ;;
  0)           echo "--local-timeout-sec must be at least 1" >&2; exit 64 ;;
esac
# --base names a COMMITTED revision for a worker to check out. A local arm
# compiles the checkout in place and cannot honour it, and accepting a flag
# whose meaning is then dropped is worse than refusing it.
if [ "$SOURCE_MODE" = local ] && [ -n "${BASE_OVERRIDE:-}" ]; then
  echo "--base cannot be combined with --local: a local arm compiles the live" >&2
  echo "  checkout, so it cannot build an arbitrary committed revision." >&2
  exit 64
fi

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "not a git repository" >&2; exit 64; }
cd "$ROOT" || exit 64
command -v rch >/dev/null 2>&1 || { echo "rch is not on PATH" >&2; exit 64; }

# LOGS GO SOMEWHERE DURABLE, NOT $TMPDIR. Measured 2026-11-07: ZERO log files
# survived across 27 earlier run directories on this machine, and the directory
# of a run that had finished 39 minutes earlier was gone entirely -- the arm
# logs backing six bead closures among them. $TMPDIR here is reaped
# aggressively (disk-pressure janitor and/or the periodic cleaner), so a gate
# that writes its evidence there produces receipts whose `log` paths are dead
# by the time anyone follows them. AGENTS.md section 4 requires a receipt to
# retain every attempt; a reaped log retains nothing.
#
# Default is outside the repository on purpose: no .gitignore entry to forget,
# no interaction with RCH's working-tree sync, and no chance of a log landing
# in a commit. Named by UTC timestamp and short revision so a receipt's paths
# can be found later.
LOGROOT=${CHECK_ALL_TARGETS_LOGDIR:-${XDG_STATE_HOME:-$HOME/.local/state}/fastmcp-gate}
LOGDIR="(none; dry run creates no directory)"
# A dry run must have NO side effects -- that is the whole point of it, and this
# file already moved usage validation ahead of the preflight for the same
# reason. Creating a dated log directory per dry run would litter the log root
# with empties.
if [ "$DRY" -eq 0 ]; then
  if ! mkdir -p "$LOGROOT" 2>/dev/null; then
    echo "cannot create log root $LOGROOT" >&2
    exit 3
  fi
  LOGDIR=$(mktemp -d "$LOGROOT/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
fi

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
  local try log remote members errors cnc lockwait
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
    if [ "$SOURCE_MODE" = local ]; then
      # RCH_SHIM_LOCAL_IDE=1 is the documented escape for a genuinely local
      # run: `cargo` on PATH may be an RCH shim that would offload, and this
      # mode exists precisely for when offloading cannot work.
      # CARGO_TERM_COLOR=never because this log is PARSED, not just read, and
      # a local run is the one case where we control cargo's environment.
      if [ -n "$TIMEOUT_BIN" ]; then
        RCH_SHIM_LOCAL_IDE=1 CARGO_TERM_COLOR=never "$TIMEOUT_BIN" "$LOCAL_TIMEOUT_SEC" \
          cargo check --workspace --all-targets --keep-going "$@" >"$log" 2>&1
      else
        RCH_SHIM_LOCAL_IDE=1 CARGO_TERM_COLOR=never \
          cargo check --workspace --all-targets --keep-going "$@" >"$log" 2>&1
      fi
      # Captured IMMEDIATELY. There is no wrapper line to parse in this mode,
      # so this status IS the verdict input, and any command placed in between
      # would overwrite it.
      remote=$?
    elif [ "$SOURCE_MODE" = base ]; then
      rch exec --base "$BASE" --clean-overlay --no-overlay -- \
        cargo check --workspace --all-targets --keep-going "$@" >"$log" 2>&1
    else
      rch exec -- cargo check --workspace --all-targets --keep-going "$@" >"$log" 2>&1
    fi
    # The wrapper's exit status can mask the remote one; this line is the
    # authoritative remote exit, and its ABSENCE means no verdict at all. A
    # local arm has no wrapper and so no such line: its status was captured
    # above, and parsing here would overwrite it with an empty string and
    # misreport a real verdict as "no verdict at all".
    if [ "$SOURCE_MODE" != local ]; then
      remote=$(strip_ansi <"$log" | grep -oE 'Remote command finished: exit=[0-9]+' | tail -1 | grep -oE '[0-9]+$')
    fi
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
      # Name the cause when the log states it. Waiting out the shared
      # build-directory lock and being killed at a deadline are both voids,
      # but they are DIFFERENT voids with different remedies, and an
      # else-branch must never name a cause it did not test.
      # Counted through strip_ansi, matching the phrase WITHOUT the status
      # word, and deliberately not `grep -q`:
      #   - cargo STYLES "Blocking" and emits a reset between it and
      #     "waiting", so a grep for the full phrase misses on a colored log,
      #     and every other grep in this function already strips ANSI;
      #   - `grep -q` exits at the first match, which can SIGPIPE the sed
      #     upstream of it, and under `pipefail` the pipeline would then
      #     report 141 ON A SUCCESSFUL MATCH -- inverting the test. `grep -c`
      #     reads to EOF, which is the idiom the lines above already use.
      lockwait=$(strip_ansi <"$log" | grep -c 'waiting for file lock' || true)
      lockwait=${lockwait:-0}
      if [ "$members" -eq 0 ] && [ "$lockwait" -gt 0 ] && [ "$SOURCE_MODE" = local ]; then
        echo "  $label: try $try is a LOCK void -- it compiled NOTHING and waited for the exclusive build-directory lock on ${CARGO_TARGET_DIR:-the default target dir} (bd-6allt). Exit $remote, 0 members reached." >&2
      # A WORKER can block on its own build-directory lock too, and that lock
      # is not this machine's: naming the local CARGO_TARGET_DIR for it, or
      # citing bd-6allt, would attribute a remote contention to a local path.
      elif [ "$members" -eq 0 ] && [ "$lockwait" -gt 0 ]; then
        echo "  $label: try $try is a LOCK void ON THE WORKER -- it compiled NOTHING and waited for a build-directory lock in the remote build dir (NOT this machine's CARGO_TARGET_DIR). Exit $remote, 0 members reached; retrying on a fresh worker draw." >&2
      # The 124 branch is MODE-GUARDED, and guarded on TIMEOUT_BIN too. A
      # REMOTE command can also exit 124 -- from a deadline on the worker that
      # has nothing to do with --local-timeout-sec -- and attributing that to
      # our own bound would name a cause we did not test. With no `timeout`
      # binary there is no local bound at all, so a local 124 is then cargo's
      # own status and falls through to the generic branch.
      elif [ "$SOURCE_MODE" = local ] && [ -n "$TIMEOUT_BIN" ] && [ "$remote" -eq 124 ]; then
        echo "  $label: try $try was KILLED at the ${LOCAL_TIMEOUT_SEC}s --local bound with ZERO compiler diagnostics after reaching $members member(s) -- stopped, not failed (void)." >&2
      elif [ "$SOURCE_MODE" = local ]; then
        # No worker draw to retry into: a local retry only helps if the cause
        # was transient. A contended lock may clear; a slow filesystem will not.
        echo "  $label: try $try exited $remote with ZERO compiler diagnostics after reaching $members member(s) -- stopped, not failed (void). Retrying LOCALLY, which only helps if the cause was transient." >&2
      else
        echo "  $label: try $try exited $remote with ZERO compiler diagnostics after reaching $members member(s) -- stopped, not failed (void); retrying on a fresh worker draw" >&2
      fi
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

# ----------------------------------------------------------------------------
# A FOURTH BLIND SPOT: `--all-targets` DOES NOT MEAN EVERY TARGET.
#
# A target carrying `required-features` that the arm does not enable is not an
# error and not a warning -- cargo SILENTLY SKIPS it and still exits 0. So a
# green arm says nothing about those targets, and this gate could not tell you
# which ones it had not looked at. Measured on this workspace at 8c5b77d4:
# 178 targets, 39 with `required-features`, of which the DEFAULT arm skips 34
# and `--no-default-features` skips all 39. `--all-features` skips none.
#
# That is the same class as bd-tt7d8 (two Tasks test targets that "have never
# run and currently cannot", because without the flag cargo skipped them and
# with it the library did not build) and bd-cwoxa (752 rows that existed only
# behind the `tasks` gate). The information was always in the manifests and
# nothing surfaced it.
#
# THIS IS PURE REPORTING AND MUST STAY THAT WAY. It never changes an arm's
# verdict or this script's exit code: a census failure would otherwise turn a
# working gate into a broken one, which is strictly worse than no census. If
# `cargo metadata` cannot run, the census is reported as unavailable and the
# gate proceeds.
#
# The skip lists are an UPPER BOUND. Cross-member feature unification can
# enable a package's feature because another member asked for it, so a target
# listed here may in fact be built. Overstating what was NOT checked is the
# safe direction for a coverage report.
GATED_CENSUS_FILE=""
GATED_TOTAL_TARGETS="?"
GATED_WITH_REQFEAT="?"
GATED_SKIP_DEFAULT="?"
GATED_SKIP_ALLFEAT="?"
GATED_SKIP_NODEFAULT="?"

gated_target_census() {
  # This runs BEFORE the dry-run block, so the guard is what keeps `--dry-run`
  # output unchanged. Testing for the directory rather than for the dry-run
  # placeholder string deliberately: the placeholder is defined ~150 lines away
  # and a later edit to its wording would silently re-enable the census here.
  [ -d "$LOGDIR" ] || return 0
  local meta="$LOGDIR/cargo-metadata.json"
  local out="$LOGDIR/gated-targets.txt"
  # `cargo metadata` resolves manifests and compiles nothing, but cargo in this
  # repository is RCH-hooked, so the census is pinned local: a remote dispatch
  # for a manifest read would cost a slot and could come back void.
  if ! RCH_SHIM_LOCAL_IDE=1 cargo metadata --no-deps --format-version 1 \
         >"$meta" 2>"$LOGDIR/cargo-metadata.err"; then
    echo "  note: gated-target census unavailable (cargo metadata failed; see" >&2
    echo "        $LOGDIR/cargo-metadata.err). The gate is unaffected." >&2
    return 0
  fi
  local line
  # ONE invocation: it writes the per-target detail file AND prints the five
  # counts on stdout, so the summary never recomputes them from a second copy
  # of this logic.
  line=$(python3 - "$meta" "$out" <<'CENSUS'
import json
import sys

metadata = json.load(open(sys.argv[1]))


def closure(features, seeds):
    """Resolve a feature name set through this package's own feature table.

    Only same-package names are followed: a `dep/feature` entry enables a
    feature on a DEPENDENCY and can never satisfy this package's own
    `required-features`, so including it would understate the skip set.
    """
    seen = set()
    stack = list(seeds)
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        for implied in features.get(name, []):
            if "/" not in implied and implied not in seen:
                stack.append(implied)
    return seen


rows = []
total = 0
for package in metadata["packages"]:
    features = package.get("features") or {}
    default = closure(features, features.get("default", []))
    every = set(features)
    for target in package.get("targets") or []:
        total += 1
        required = set(target.get("required-features") or [])
        if not required:
            continue
        rows.append(
            {
                "package": package["name"],
                "target": target["name"],
                "kind": ",".join(target.get("kind") or []),
                "required": sorted(required),
                "default": not required.issubset(default),
                "all-features": not required.issubset(every),
                "no-default-features": True,
            }
        )

arms = ("default", "all-features", "no-default-features")
with open(sys.argv[2], "w") as handle:
    handle.write(
        f"{total} workspace targets; {len(rows)} carry required-features.\n"
        "S = cargo silently skips this target in that arm and still exits 0.\n"
        "Upper bound: cross-member feature unification may enable more.\n\n"
        f"{'package':18} {'target':34} {'kind':8} def all nod  required-features\n"
    )
    for row in sorted(rows, key=lambda r: (r["package"], r["target"])):
        flags = " ".join(
            " S " if row[arm] else " . " for arm in arms
        )
        handle.write(
            f"{row['package']:18} {row['target'][:34]:34} {row['kind'][:8]:8} "
            f"{flags}  {','.join(row['required'])}\n"
        )

counts = {arm: sum(1 for row in rows if row[arm]) for arm in arms}
print(total, len(rows), counts["default"], counts["all-features"],
      counts["no-default-features"])
CENSUS
) || return 0
  [ -n "${line:-}" ] || return 0
  read -r GATED_TOTAL_TARGETS GATED_WITH_REQFEAT GATED_SKIP_DEFAULT \
          GATED_SKIP_ALLFEAT GATED_SKIP_NODEFAULT <<<"$line"
  GATED_CENSUS_FILE="$out"
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

# Taken before any dispatch so it is reported even when every arm comes back
# void. It reads manifests only and cannot affect a verdict.
gated_target_census

if [ "$DRY" -eq 1 ]; then
  echo "dry run: arm selection '$ARM', retries $RETRIES, json $JSON"
  if [ "$SOURCE_MODE" = base ]; then
    echo "would dispatch: rch exec --base $BASE --clean-overlay --no-overlay --"
  elif [ "$SOURCE_MODE" = local ]; then
    if [ -n "$TIMEOUT_BIN" ]; then
      echo "would run LOCALLY (no dispatch), bounded at ${LOCAL_TIMEOUT_SEC}s by $TIMEOUT_BIN"
    else
      echo "would run LOCALLY (no dispatch), UNBOUNDED -- no 'timeout' binary on PATH"
    fi
    echo "                env RCH_SHIM_LOCAL_IDE=1   (LIVE WORKING TREE; receipt not bindable)"
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

# PREFLIGHT REFUSAL, placed AFTER the dry run on purpose. A dry run must REPORT
# what would happen, not refuse: previously `--working-tree --dry-run` on a
# dirty tracker exited 3 and printed nothing, which answers a different question
# than the one asked. Same principle that moved usage validation ahead of the
# preflight earlier in this file.
#
# WORKING-TREE ONLY, and --local is deliberately exempt.
#
# This refusal exists because --working-tree RSYNCS THE WHOLE CHECKOUT, so a
# tracked file being rewritten mid-transfer can produce an inconsistent remote
# copy no matter what that file is. .beads/issues.jsonl is tracked and the
# orchestrator writes it constantly, which is the signal used here.
#
# Neither other mode can be hurt by that. In base mode the worker builds from
# git objects, immutable for a given revision. And --local compiles the tree IN
# PLACE with no transfer at all, so a .beads write -- which is not a compile
# input -- cannot change a single thing cargo reads.
#
# Extending this test to --local (which I did, and a live run caught) would
# inherit a refusal whose own reason does not apply, and would make the mode
# unusable precisely when it is needed: .beads is dirty here almost always.
# What DOES threaten a local arm is .rs movement during the run, and the
# post-run MOVED check already covers that for every non-base mode.
if [ "$SOURCE_MODE" = working-tree ] &&
   git status --porcelain --untracked-files=no -- .beads | grep -q .; then
  echo "PREFLIGHT REFUSED: .beads has tracked modifications, so the checkout is" >&2
  echo "  probably being mutated, and --working-tree rsyncs it. Let the tracker" >&2
  echo "  settle, re-run, or use the default base mode." >&2
  echo "  (Run 'br sync --flush-only' and commit, or wait for the writer.)" >&2
  exit 3
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
if [ "$MOVED" -eq 1 ] && [ "$status" -eq 0 ] && [ "$SOURCE_MODE" != base ]; then
  status=2
fi

if [ "$JSON" -eq 1 ]; then
  printf '{"head":"%s","tree":"%s","source_mode":"%s","base":"%s","dirty_rs":%s,"checkout_moved":%s,"logdir":"%s","arms":[' \
    "$HEAD_SHA" "$TREE_SHA" "$SOURCE_MODE" "$BASE" "$DIRTY_RS" "$MOVED" "$LOGDIR"
  for i in "${!NAMES[@]}"; do
    [ "$i" -gt 0 ] && printf ','
    printf '{"arm":"%s","verdict":"%s","remote_exit":"%s","members_reached":"%s","error_lines":"%s","could_not_compile":"%s","log":"%s"}' \
      "${NAMES[$i]}" "${VERDICTS[$i]}" "${EXITS[$i]}" "${MEMBERS[$i]}" "${ERRS[$i]}" "${CNCS[$i]}" "${LOGS[$i]}"
  done
  printf '],"gated_targets":{"workspace_targets":"%s","with_required_features":"%s"' \
    "$GATED_TOTAL_TARGETS" "$GATED_WITH_REQFEAT"
  printf ',"skipped_default":"%s","skipped_all_features":"%s"' \
    "$GATED_SKIP_DEFAULT" "$GATED_SKIP_ALLFEAT"
  printf ',"skipped_no_default_features":"%s","detail":"%s"}' \
    "$GATED_SKIP_NODEFAULT" "$GATED_CENSUS_FILE"
  printf ',"exit":%s}\n' "$status"
else
  echo
  echo "compile gate -- HEAD $HEAD_SHA tree $TREE_SHA dirty_rs=$DIRTY_RS"
  echo "  logs:   $LOGDIR"
  echo "          retained outside \$TMPDIR, which is reaped on this machine;"
  echo "          override the root with CHECK_ALL_TARGETS_LOGDIR."
  if [ "$SOURCE_MODE" = base ]; then
    echo "  source: committed revision $BASE (rch --base --clean-overlay --no-overlay);"
    echo "          the working tree was NOT read, so this receipt binds that revision."
  elif [ "$SOURCE_MODE" = local ]; then
    echo "  source: LIVE WORKING TREE, compiled ON THIS MACHINE (--local). This receipt"
    echo "          binds no revision, was not produced on the verification lane, and"
    echo "          must NOT be used to close a bead -- it is an unblocking check only."
  else
    echo "  source: LIVE WORKING TREE (--working-tree); this receipt binds no revision"
    echo "          on its own and is void if anything tracked moved."
  fi
  # There is no remote in --local mode, so the column carrying the
  # authoritative exit status is relabelled rather than claiming an origin it
  # does not have. The JSON key stays `remote_exit` for any consumer; the
  # header records that it holds the local status in this mode.
  if [ "$SOURCE_MODE" = local ]; then
    EXIT_LABEL=local_exit
  else
    EXIT_LABEL=remote_exit
  fi
  for i in "${!NAMES[@]}"; do
    printf '  %-13s %-5s %s=%-3s members_reached=%-3s error_lines=%-3s could_not_compile=%-3s\n' \
      "${NAMES[$i]}" "${VERDICTS[$i]}" "$EXIT_LABEL" "${EXITS[$i]:--}" "${MEMBERS[$i]:--}" "${ERRS[$i]:--}" "${CNCS[$i]:--}"
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
  if [ -n "$GATED_CENSUS_FILE" ]; then
    echo "  gated targets: $GATED_WITH_REQFEAT of $GATED_TOTAL_TARGETS workspace targets carry"
    echo "          required-features, and cargo SKIPS such a target SILENTLY while still"
    echo "          exiting 0. Skipped per arm: default=$GATED_SKIP_DEFAULT"
    echo "          all-features=$GATED_SKIP_ALLFEAT no-default-features=$GATED_SKIP_NODEFAULT"
    echo "          So a green arm is not a statement about those targets. Only the"
    echo "          all-features arm covers them; run it before reading any green here"
    echo "          as full target coverage."
    echo "          per-target detail: $GATED_CENSUS_FILE"
  fi
  case $status in
    0) echo "  RESULT: green (every requested arm compiled)" ;;
    1) echo "  RESULT: RED -- at least one arm compiled and FAILED, with compiler"
       echo "          diagnostics to prove it. Note members_reached: cargo stops"
       echo "          scheduling after a failure, so the red set is a FLOOR, not a count." ;;
    2) echo "  RESULT: NO VERDICT (void: stopped rather than failed, or a checkout that"
       echo "          moved under a live-tree mode). This is NOT a red; retry." ;;
  esac
fi

exit "$status"
