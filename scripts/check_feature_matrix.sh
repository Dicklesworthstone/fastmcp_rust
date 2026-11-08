#!/usr/bin/env bash
# check_feature_matrix.sh -- one compile check per DECLARED FEATURE per crate.
#
# WHY THIS EXISTS, and why it is not covered by check_all_targets.sh.
#
# That script's own header records blind spot #2: "NEITHER FEATURE ARM IS A
# SUPERSET OF THE OTHER", and it acts on that by running workspace-wide arms
# (default / --all-features / --no-default-features). Those three arms are
# necessary and they are still not sufficient, because a break can live in the
# gap BETWEEN them -- at one single feature, enabled alone.
#
# Measured on 2026-11-08, which is why this file exists. 22 probes across
# fastmcp-client (7 features) and fastmcp-server (15) found 2 reds:
#
#   error[E0063]: missing field `task_access` in initializer of
#                 `FinalSubscriptionResourceAdmission`
#     --> crates/fastmcp-server/src/async_stdio.rs:4325
#   could not compile `fastmcp-server` (lib test)
#
# reached via `tasks` and via `proxy-tasks = ["proxy", "tasks"]`. All three
# existing arms were GREEN on those exact bytes:
#
#   default features        `tasks` is not in the server's default set
#                           ["legacy-2024-11-05", "console"], so the gated
#                           field does not exist. Green.
#   --no-default-features   with NO features the field does not exist either,
#                           so the initializer is CORRECT there. Green.
#   --all-features          the field exists, but a single-feature break can
#                           hide inside a wider set that satisfies it from
#                           elsewhere -- this repository already recorded that
#                           shape for a gated `use` satisfying an ungated use
#                           site (fixed in 07f52c64).
#
# Cargo features are meant to be ADDITIVE, so a break that appears when you ADD
# one feature is invisible from both ends of the range. Only one-at-a-time
# lands on it.
#
# AND IT MUST BE --all-targets. In the case above the LIB compiled fine; the
# LIB TEST target was what failed, because the missed initializer was in test
# code. A gate that checks lib targets only reports green. That is the same
# shape that, on the same day, was found to have hidden 752 fastmcp-client test
# rows behind `--features tasks` for 26+ days, because that crate's lib-test
# target had never compiled with the flag.
#
# FEATURES ARE DISCOVERED, NOT LISTED. A hardcoded feature list rots, which is
# the very defect class this gate exists to catch -- the hand-run version of
# this probe omitted fastmcp-console entirely because the list was typed by
# hand. Features come from `cargo metadata`, so a feature added tomorrow is
# probed tomorrow.
#
# ON "UNSUPPORTED" COMBINATIONS. A red here is a real compile failure at a
# configuration Cargo permits. If a crate genuinely cannot build at one feature
# alone, that is a constraint it should DECLARE -- a `compile_error!` on the
# unsupported combination, or a feature that pulls in what it needs -- not
# something this gate should quietly skip. There is deliberately no exemption
# list: as of 2026-11-08 every probe either passed or found a real break.
#
# EXIT CODES
#   0  every probe compiled
#   1  at least one probe produced compiler diagnostics (a real red)
#   2  at least one probe produced NO verdict (timeout, or a nonzero exit with
#      zero diagnostics), and nothing was red or malformed -- retry, do not
#      report a failure
#   3  at least one probe was MALFORMED (a cargo invocation error, e.g. a
#      package name that is not a workspace member) and nothing was red.
#      Nothing was measured; fix the probe, do not retry it unchanged.
#
# USAGE
#   scripts/check_feature_matrix.sh [--crate NAME]... [--json] [--dry-run]
#                                   [--timeout SECONDS] [--jobs N]
#
#   --crate may be repeated; default is every workspace member that declares
#   at least one feature. --dry-run prints the probe list and exits 0.
#
# A NOTE ON COUNTING ERRORS. Real errors are counted on `^error[E####]` only.
# A bare `^error:` also matches cargo's "could not compile" summary and
# libtest's "error: test failed", which is how an earlier hand run reported
# "2 errors" for a single E0063 and, separately, called a complete 2602-row
# test run a compile failure.
set -uo pipefail

CRATES=()
JSON=0
DRY=0
TIMEOUT=900
JOBS=""

die() { printf '%s\n' "$*" >&2; exit 64; }
need_value() { [ -n "${2:-}" ] || die "$1 requires a value"; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --crate)   need_value --crate "${2:-}"; CRATES+=("$2"); shift 2 ;;
    --json)    JSON=1; shift ;;
    --dry-run) DRY=1; shift ;;
    --timeout) need_value --timeout "${2:-}"; TIMEOUT="$2"; shift 2 ;;
    --jobs)    need_value --jobs "${2:-}"; JOBS="$2"; shift 2 ;;
    # Print the whole leading comment block, stopping at the first line of
    # code, so --help cannot truncate the rationale mid-sentence.
    -h|--help) sed -n '1,/^set -uo pipefail/p' "$0" | sed '$d'; exit 0 ;;
    *)         die "unknown argument: $1" ;;
  esac
done

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || die "cannot enter $ROOT"

command -v python3 >/dev/null 2>&1 || die "python3 is required to read cargo metadata"

# Discover (package, feature) pairs. `default` is excluded: it is what the
# existing default arm already covers, and it is not a single feature.
PAIRS=$(
  RCH_SHIM_LOCAL_IDE=1 CARGO_TERM_COLOR=never \
    cargo metadata --no-deps --format-version 1 2>/dev/null |
  python3 -c '
import json, sys
meta = json.load(sys.stdin)
wanted = set(sys.argv[1:])
for package in sorted(meta["packages"], key=lambda p: p["name"]):
    if wanted and package["name"] not in wanted:
        continue
    for feature in sorted(f for f in package.get("features", {}) if f != "default"):
        print(package["name"], feature)
' "${CRATES[@]+"${CRATES[@]}"}"
) || die "cargo metadata failed; is this a workspace root?"

[ -n "$PAIRS" ] || die "no (crate, feature) pairs to probe${CRATES[0]+ for the named crate(s)}"

TOTAL=$(printf '%s\n' "$PAIRS" | wc -l | tr -d ' ')

if [ "$DRY" -eq 1 ]; then
  echo "would run $TOTAL probes:"
  # awk, not two seds: the second `s/ /../` would replace the leading space the
  # first one just inserted, emitting a command nobody can paste.
  printf '%s\n' "$PAIRS" | awk '{
    printf "  cargo check --locked -p %s --all-targets --no-default-features --features %s\n", $1, $2
  }'
  exit 0
fi

LOGROOT=${CHECK_FEATURE_MATRIX_LOGDIR:-${XDG_STATE_HOME:-$HOME/.local/state}/fastmcp-gate}
mkdir -p "$LOGROOT" || die "cannot create log root $LOGROOT"
LOGDIR=$(mktemp -d "$LOGROOT/featmatrix-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX") \
  || die "cannot create a log directory under $LOGROOT"

HEAD=$(git rev-parse HEAD 2>/dev/null || echo "<no git>")
red=0
void=0
green=0
bad=0
rows=""

[ "$JSON" -eq 1 ] || {
  echo "check_feature_matrix.sh  HEAD $HEAD"
  echo "  $TOTAL probes, logs in $LOGDIR"
  echo
}

while read -r crate feature; do
  [ -n "$crate" ] || continue
  log="$LOGDIR/${crate}__${feature}.log"
  set -- cargo check --locked -p "$crate" --all-targets \
    --no-default-features --features "$feature"
  [ -n "$JOBS" ] && set -- "$@" --jobs "$JOBS"
  # RCH_SHIM_LOCAL_IDE is the documented escape for a genuinely local run; it
  # must never be combined with RCH_REQUIRE_REMOTE. These are cheap checks and
  # the remote lane is a single serialized slot per project.
  RCH_SHIM_LOCAL_IDE=1 CARGO_TERM_COLOR=never timeout "$TIMEOUT" "$@" >"$log" 2>&1
  rc=$?
  errors=$(grep -cE '^error\[E[0-9]+\]' "$log")
  codes=$(grep -oE '^error\[E[0-9]+\]' "$log" | sort -u | paste -sd, -)
  # An UNCODED `error:` is still a real compile failure -- a `compile_error!`
  # carries no E-number, and a crate that declares an unsupported feature
  # combination that way would otherwise be scored as "no diagnostics". Two
  # forms are excluded because they are consequences rather than causes:
  # cargo's "could not compile" summary and libtest's "test failed".
  uncoded=$(grep -E '^error: ' "$log" | grep -vcE 'could not compile|test failed' || true)
  # A cargo INVOCATION error is neither: the probe itself was malformed, so
  # nothing was measured. Reporting it as void invites endless retries of a
  # command that can never succeed, and reporting it as red blames the code for
  # the harness. It gets its own state and its own exit code.
  invalid=$(grep -cE '^error: (cannot specify features|no such package|package ID specification|failed to (parse|load|read) manifest|current package believes)' "$log" || true)

  # The displayed cause must be a CAUSE. Taking the first `^error: ` line
  # verbatim can surface cargo's "could not compile" summary instead, which
  # names the crate and tells the reader nothing about why.
  first_cause() {
    grep -E '^error: ' "$log" | grep -vE 'could not compile|test failed' \
      | head -1 | cut -c1-72
  }

  if [ "$invalid" -gt 0 ]; then
    state=invalid; bad=$((bad + 1))
    codes=$(first_cause)
  elif [ "$errors" -gt 0 ] || [ "$uncoded" -gt 0 ]; then
    state=red; red=$((red + 1))
    [ -n "$codes" ] || codes=$(first_cause)
  elif [ "$rc" -eq 124 ]; then
    state=void; void=$((void + 1)); codes=timeout
  elif [ "$rc" -ne 0 ]; then
    # A nonzero exit with zero diagnostics never compiled anything: it is a
    # stop, not a failure, and must not be reported as a red.
    state=void; void=$((void + 1)); codes="rc=$rc, no diagnostics"
  else
    state=green; green=$((green + 1))
  fi

  rows="$rows{\"crate\":\"$crate\",\"feature\":\"$feature\",\"state\":\"$state\",\"errors\":$errors,\"rc\":$rc,\"log\":\"$log\"},"
  [ "$JSON" -eq 1 ] || printf '  %-18s %-28s %-6s %s\n' "$crate" "$feature" "$state" "$codes"
done <<EOF
$PAIRS
EOF

status=0
[ "$void" -gt 0 ] && status=2
[ "$bad" -gt 0 ] && status=3
[ "$red" -gt 0 ] && status=1

if [ "$JSON" -eq 1 ]; then
  printf '{"head":"%s","probes":%s,"green":%s,"red":%s,"void":%s,"invalid":%s,"logdir":"%s","status":%s,"rows":[%s]}\n' \
    "$HEAD" "$TOTAL" "$green" "$red" "$void" "$bad" "$LOGDIR" "$status" "${rows%,}"
else
  echo
  echo "  $TOTAL probes: $green green, $red red, $void void, $bad invalid -> exit $status"
fi
exit "$status"
