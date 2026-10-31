#!/usr/bin/env bash
# FIRST COMPLETE RUN OF THE LARGEST TARGET IN THE PROJECT.
#
# `fastmcp-server --lib` has never been run to completion in any record I can
# find. Today's runs made it cheap: the client target went 1836 tests in 10-15 s
# at DEFAULT test-threads on hz3 (NPROC=64), and the server build is warm on
# that worker ("Finished test profile in 0.19s" on an earlier job). The reason
# this looked infeasible before was an assumption of a SERIALIZED run; at
# default parallelism on a 64-way host the arithmetic is completely different.
#
# bd-55ola is the named beneficiary: it claims
# `returning_subscription_quiescence_runs_hook_after_owner_retirement` is
# "nondeterministic under default test-threads (failed 1 of 3, PASSES ALONE)".
# A solo serial run is exactly the configuration where it is documented to
# pass, so only this -- the whole target, default threads, repeated -- can
# speak to it. I already ran it solo (it passed) and reported that as a
# non-result for precisely this reason.
#
# Beyond bd-55ola the point is the POPULATION: nobody knows what fraction of
# the server crate's tests pass, and that number gates every batch receipt
# touching the crate (PL-1 requires exact test-set equality).
#
# Guards: discovered count checked against each run's `running N tests` so a
# filtered or aborted run is VOID rather than read as a pass (PL-1: zero-run
# green is red). Detail pass capped at 40 names so a large failing population
# cannot blow the job budget or the log.
set -u
cd /Users/jemanuel/projects/fastmcp_rust || exit 90

mkdir -p probe_out
exec > >(tee probe_out/server_lib_full.txt) 2>&1

N=3
echo "HOST=$(hostname)"
echo "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "NPROC=$(nproc 2>/dev/null)   # the variable under test"
echo "HEAD_CLAIMED=$(git rev-parse HEAD 2>/dev/null || echo '<no repo on worker>')"
echo "REPETITIONS=$N   features=DEFAULT, test-threads=DEFAULT (both flags omitted)"

echo ""
echo "=== BUILD (outside the measurement window) ==="
BL=/tmp/srv_build.$$
cargo test --locked -p fastmcp-server --lib --no-run > "$BL" 2>&1
echo "BUILD_EXIT=$?"
sed 's/\x1b\[[0-9;]*m//g' "$BL" > "$BL.plain"
tail -3 "$BL.plain"
BIN=$(sed -n 's/.*Executable[[:space:]]*unittests src\/lib\.rs (\(.*\))[[:space:]]*$/\1/p' "$BL.plain" | tail -1)
if [ -z "${BIN:-}" ] || [ ! -x "$BIN" ]; then
  echo "NO TEST BINARY -- no verdict."
  grep -E '^error' "$BL.plain" | head -12
  exit 11
fi
echo "BIN=$BIN"
TOTAL=$("$BIN" --list --format terse 2>/dev/null | grep -c ': test$')
echo "DISCOVERED=$TOTAL"

GREEN=0; RED=0; VOID=0
for i in $(seq 1 "$N"); do
  echo ""
  echo "================ RUN $i of $N ================"
  OUT=/tmp/srv_run_${i}.$$
  timeout --signal=KILL 1200 "$BIN" > "$OUT" 2>&1
  RC=$?
  RAN=$(grep -oE '^running [0-9]+ tests?$' "$OUT" | grep -oE '[0-9]+' | head -1)
  echo "exit=$RC  ran=${RAN:-0} of discovered=$TOTAL"
  if [ "${RAN:-0}" != "$TOTAL" ]; then
    echo "VOID: executed ${RAN:-0} of $TOTAL -- not a full-target run."
    tail -8 "$OUT"; VOID=$((VOID+1)); continue
  fi
  grep -E '^test result:' "$OUT"
  if grep -q '^test result: ok\.' "$OUT"; then
    echo "-> RUN $i GREEN"; GREEN=$((GREEN+1))
  else
    echo "-> RUN $i RED ($(grep -cE '^test .* \.\.\. FAILED$' "$OUT") failed)"
    RED=$((RED+1))
  fi
done

echo ""
echo "================ POPULATION ACROSS $N RUNS ================"
cat /tmp/srv_run_*.$$ 2>/dev/null | grep -E '^test .* \.\.\. FAILED$' \
  | sed 's/^test //; s/ \.\.\. FAILED$//' | sort | uniq -c | sort -rn \
  > /tmp/srv_pop.$$
echo "distinct failing names = $(grep -c . /tmp/srv_pop.$$)"
echo ""
echo "--- failed in ALL $N runs (deterministic) ---"
awk -v n="$N" '$1==n {$1=""; print "   " $0}' /tmp/srv_pop.$$
echo ""
echo "--- failed in FEWER than $N runs (intermittent) ---"
awk -v n="$N" '$1<n {print "   " $1 "/" n "  " $2}' /tmp/srv_pop.$$
echo "(both sections empty means the target is GREEN)"

echo ""
echo "================ bd-55ola, SPECIFICALLY ================"
T=returning_subscription_quiescence_runs_hook_after_owner_retirement
C=$(cat /tmp/srv_run_*.$$ 2>/dev/null | grep -cE "^test .*${T} \.\.\. FAILED$")
echo "failed in ${C} of $N full-target runs at default parallelism:  $T"
echo "bd-55ola claims: nondeterministic under default test-threads, failed 1 of 3, PASSES ALONE."
echo "READING: 0 -> did not reproduce (weak for a flake claim, see the rate arithmetic)."
echo "         1..$((N-1)) -> CONFIRMED intermittent at that rate."
echo "         $N -> stronger than the bead says: deterministic, not a flake."

echo ""
echo "================ DETAIL: up to 40 deterministic names, solo-serial ================"
awk -v n="$N" '$1==n {print $2}' /tmp/srv_pop.$$ | head -40 > /tmp/srv_det.$$
echo "detail set = $(grep -c . /tmp/srv_det.$$) names"
SP=0; SF=0; SV=0
while IFS= read -r t; do
  [ -n "$t" ] || continue
  O=/tmp/srv_solo.$$
  timeout --signal=KILL 180 "$BIN" "$t" --exact --test-threads=1 > "$O" 2>&1
  rc=$?
  if ! grep -q '^running 1 test$' "$O"; then
    echo "  VOID (ran 0, exit $rc)  $t"; SV=$((SV+1)); continue
  fi
  if grep -q '^test result: ok\.' "$O"; then
    echo "  PASS-solo (so it is a cross-test interaction)  $t"; SP=$((SP+1))
  else
    echo "  FAIL-solo  $t"
    grep -E "panicked at|assertion|left:|right:" "$O" | head -3 | sed 's/^/          /'
    SF=$((SF+1))
  fi
done < /tmp/srv_det.$$
echo ""
echo "solo-serial on the deterministic set: FAIL=$SF (hard defects)  PASS=$SP (interactions)  VOID=$SV"
