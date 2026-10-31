#!/usr/bin/env bash
# THE SINGLE HIGHEST-VALUE MISSING DATUM, plus the measurement that would
# retire bd-55ola. Both are now minutes of fleet time because the build is warm
# on hz3 and `fastmcp-server --lib` runs its 2482 tests in ~20s.
#
# PART 1 -- the error text for bd-rssik's six.
#   probe_out/server_lib_full.txt established WHERE they panic but not WHAT the
#   error is: my extractor grepped `panicked at|assertion|left:|right:`, which
#   caught the location line and dropped the payload on the NEXT line. For the
#   two deterministic live_http failures that payload is the whole diagnosis --
#   lib.rs:26215 is `result.unwrap()`, so the message carries `{result:?}`.
#   This prints full output per test instead of grepping for a guess.
#
# PART 2 -- bd-55ola at its own recorded rate.
#   It claims 1-of-3 nondeterminism and PASSES ALONE. It failed 0/3 earlier,
#   which cannot clear a 1-in-3 flake: three clean runs of one happen ~30% of
#   the time. Ten complete-target runs cost ~3.5 min at 20s each and take the
#   residual from ~30% to ~2%. Default test-threads, because "passes alone" is
#   exactly what makes the solo configuration useless here.
#
# Guards: `ran == DISCOVERED` per run or the run is VOID (PL-1, zero-run green
# is red); each solo name must resolve to exactly one discovered test.
set -u
cd /Users/jemanuel/projects/fastmcp_rust || exit 90

mkdir -p probe_out
exec > >(tee probe_out/server_six_detail.txt) 2>&1

echo "HOST=$(hostname)"
echo "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "NPROC=$(nproc 2>/dev/null)"

SIX=(
  lib_unit_tests::live_http_subscription_acknowledgement_precedes_deferred_progress
  lib_unit_tests::live_http_response_write_timeout_releases_stalled_json_peer
  http_admission::security::endpoint::tests::secured_subscription_cancellation_is_delivered_once_then_finishes
  http_admission::security::endpoint::tests::generic_subscription_controls_cannot_finish_a_secured_response
  lib_unit_tests::live_http_subscription_cancellation_cannot_be_replaced_by_response_middleware
  lib_unit_tests::live_http_shutdown_owns_registered_sse_body_before_flushing_terminal
)
OLA=lib_unit_tests::returning_subscription_quiescence_runs_hook_after_owner_retirement

echo ""
echo "=== BUILD (warm) ==="
BL=/tmp/s6_build.$$
cargo test --locked -p fastmcp-server --lib --no-run > "$BL" 2>&1
echo "BUILD_EXIT=$?"
sed 's/\x1b\[[0-9;]*m//g' "$BL" > "$BL.plain"
tail -2 "$BL.plain"
BIN=$(sed -n 's/.*Executable[[:space:]]*unittests src\/lib\.rs (\(.*\))[[:space:]]*$/\1/p' "$BL.plain" | tail -1)
if [ -z "${BIN:-}" ] || [ ! -x "$BIN" ]; then
  echo "NO TEST BINARY -- no verdict."; cat "$BL.plain"; exit 11
fi
echo "BIN=$BIN"
"$BIN" --list --format terse 2>/dev/null | sed 's/: test$//' > probe_out/server_lib_discovered.txt
TOTAL=$(grep -c . probe_out/server_lib_discovered.txt)
echo "DISCOVERED=$TOTAL   (full name list synced back in probe_out/server_lib_discovered.txt)"

echo ""
echo "############################################################"
echo "### PART 1: full output per failing test, solo, serial"
echo "############################################################"
for t in "${SIX[@]}"; do
  n=$(grep -cxF "$t" probe_out/server_lib_discovered.txt)
  echo ""
  echo "================================================================"
  echo "### $t"
  echo "================================================================"
  if [ "$n" != "1" ]; then echo "VOID: resolves to $n discovered tests, not 1."; continue; fi
  O=/tmp/s6_solo.$$
  timeout --signal=KILL 300 "$BIN" "$t" --exact --test-threads=1 --nocapture > "$O" 2>&1
  rc=$?
  if ! grep -q 'running 1 test' "$O"; then
    echo "VOID: zero tests executed (exit $rc)."; tail -6 "$O"; continue
  fi
  echo "exit=$rc"
  # No grep: the payload is on the line AFTER `panicked at`, and guessing the
  # pattern is what lost it last time. Print the whole thing, bounded.
  sed -n '1,120p' "$O"
done

echo ""
echo "############################################################"
echo "### PART 2: bd-55ola -- 10 complete-target runs, default threads"
echo "############################################################"
G=0; R=0; V=0; OLAF=0
for i in $(seq 1 10); do
  O=/tmp/s6_full_${i}.$$
  timeout --signal=KILL 600 "$BIN" > "$O" 2>&1
  RAN=$(grep -oE '^running [0-9]+ tests?$' "$O" | grep -oE '[0-9]+' | head -1)
  if [ "${RAN:-0}" != "$TOTAL" ]; then
    echo "  run $i: VOID ran=${RAN:-0}/$TOTAL"; V=$((V+1)); continue
  fi
  if grep -q '^test result: ok\.' "$O"; then
    echo "  run $i: GREEN"; G=$((G+1))
  else
    echo "  run $i: RED   $(grep -E '^test result:' "$O" | head -1)"
    R=$((R+1))
  fi
  grep -qE "^test ${OLA} \.\.\. FAILED$" "$O" && OLAF=$((OLAF+1))
done
echo ""
echo "  --> GREEN=$G RED=$R VOID=$V of 10 complete-target runs"
echo "  --> bd-55ola's test failed in $OLAF of 10"
echo ""
echo "  --> failure population across all 10 (times-failed  name):"
cat /tmp/s6_full_*.$$ 2>/dev/null | grep -E '^test .* \.\.\. FAILED$' \
  | sed 's/^test //; s/ \.\.\. FAILED$//' | sort | uniq -c | sort -rn | sed 's/^/        /'
echo ""
echo "READING for bd-55ola: 0 of 10 takes the residual on a 1-in-3 claim from"
echo "~30% to ~2%, which is a clearance rather than a non-reproduction."
