#!/usr/bin/env bash
# bd-native-pipe-backpressure-await-wake-cx678 asks ONE question explicitly:
#
#   "A determinism re-run is dispatched but had not reported when this was
#    filed; treat the 'deterministic vs intermittent' question as OPEN and
#    resolve it before designing a fix."
#
# This resolves it, in the configuration the bead's own observation used:
#
#   command   cargo test --locked -p fastmcp-transport --lib
#   observed  616 passed; 2 failed   (suite ran in 1.96s)
#   failing   async_io::native_pipe::tests::native_pipe_backpressure_yields_and_wakes_without_duplicating_bytes
#             async_io::native_pipe::tests::native_pipe_readiness_updates_waker_and_preserves_data_through_eof
#
# DEFAULT test-threads on purpose -- no --test-threads flag. The bead's failure
# was seen under cargo's default parallelism, and a serial solo run of the named
# test PASSES (I measured that minutes ago), so the serial configuration is
# exactly the one that cannot answer this. Matching the claim's configuration
# is the whole point.
#
# Repeated N times because one run cannot distinguish deterministic from
# intermittent -- which is the question -- and because a rotating failure
# population with a stable COUNT means marginal bounds rather than a single
# broken test. Reports the population per run, not just a pass/fail.
#
# The target is small: 664 tests, ~20s to build, ~2s to run. Five repetitions
# cost seconds, which is why this is worth doing properly instead of inferring
# from one solo run.
set -u
cd /Users/jemanuel/projects/fastmcp_rust || exit 90

mkdir -p probe_out
exec > >(tee probe_out/native_pipe_determinism.txt) 2>&1

N=5
echo "HOST=$(hostname)"
echo "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "REPETITIONS=$N   test-threads=DEFAULT (flag deliberately omitted)"
echo "BLOB: $(git hash-object crates/fastmcp-transport/src/async_io/native_pipe.rs 2>/dev/null)  native_pipe.rs"

echo ""
echo "=== BUILD (outside the measurement window) ==="
BL=/tmp/np_build.$$
cargo test --locked -p fastmcp-transport --lib --no-run > "$BL" 2>&1
echo "BUILD_EXIT=$?"
sed 's/\x1b\[[0-9;]*m//g' "$BL" > "$BL.plain"
tail -3 "$BL.plain"
BIN=$(sed -n 's/.*Executable[[:space:]]*unittests src\/lib\.rs (\(.*\))[[:space:]]*$/\1/p' "$BL.plain" | tail -1)
if [ -z "${BIN:-}" ] || [ ! -x "$BIN" ]; then
  echo "NO TEST BINARY -- no verdict."; cat "$BL.plain"; exit 11
fi
echo "BIN=$BIN"
TOTAL=$("$BIN" --list --format terse 2>/dev/null | grep -c ': test$')
echo "DISCOVERED=$TOTAL"

GREEN=0; RED=0
for i in $(seq 1 "$N"); do
  echo ""
  echo "================ RUN $i of $N ================"
  OUT=/tmp/np_run_${i}.$$
  timeout --signal=KILL 300 "$BIN" > "$OUT" 2>&1
  RC=$?
  # Zero-run green is red (PL-1): a filtered or aborted run exits in ways that
  # look like success unless the discovered count is checked against the run.
  RAN=$(grep -oE '^running [0-9]+ tests?$' "$OUT" | grep -oE '[0-9]+' | head -1)
  echo "exit=$RC  ran=${RAN:-0}  of discovered=$TOTAL"
  if [ "${RAN:-0}" != "$TOTAL" ]; then
    echo "VOID: executed ${RAN:-0} of $TOTAL -- not a full-target run."
    tail -5 "$OUT"; continue
  fi
  grep -E '^test result:' "$OUT"
  if grep -q '^test result: ok\.' "$OUT"; then
    echo "-> RUN $i GREEN"
    GREEN=$((GREEN+1))
  else
    echo "-> RUN $i RED. failing population:"
    grep -E '^test .* \.\.\. FAILED$' "$OUT" | sed 's/^/     /'
    RED=$((RED+1))
  fi
done

echo ""
echo "================ VERDICT ================"
echo "GREEN=$GREEN  RED=$RED  of $N runs, full target, default test-threads"
echo ""
echo "failure population across all runs (name -> times failed):"
cat /tmp/np_run_*.$$ 2>/dev/null | grep -E '^test .* \.\.\. FAILED$' \
  | sed 's/^test //; s/ \.\.\. FAILED$//' | sort | uniq -c | sort -rn | sed 's/^/   /'
echo "(empty above means no test failed in any run)"
