#!/usr/bin/env bash
# The measurement FOUR review beads name, in the configuration they name.
#
# bd-534kp (P1) states it outright under "MEASUREMENT THAT DECIDES IT":
#   "Repeat the default-parallel target several times and record, per run, the
#    exact failing set. If the set rotates within a cluster of 'deferred'
#    tests, look for a single shared bound or fixture; if these same two fail
#    every time, they are two deterministic defects."
#
# Beads this run speaks to, all four of which name default parallelism or the
# parallel suite rather than an isolated test:
#   bd-534kp  P1  deferred_control_maintenance_exhaustion_preserves_sibling_ownership
#                 fails 3/3, plus builder::tests::client_deferred_yielding_legacy_positive
#   bd-1l88q  P2  public_http_modern_subscriptions_listen_rejects_one_field_... intermittent
#   bd-kp4td  P2  public_http_mrtr_callback_caller_runtime_planted_negative    intermittent
#   bd-to4cj  P2  automatic_catalog_lists_expire_while_waiting_for_the_second_page
#                 "wall-clock flaky under the parallel suite"
#
# I ran all four tests SOLO and serially earlier and all four passed. That
# settles nothing: solo-serial is the configuration in which they are already
# documented to pass, and bd-534kp's own failure text is "Request timed out at
# the absolute deadline", which is load-sensitive by construction. Hence this.
#
# DEFAULT test-threads and DEFAULT features -- both flags deliberately omitted
# so the shipped, contended configuration is what runs.
#
# Cost: 1836 tests, ~28s per run per bd-534kp's record, build already warm.
set -u
cd /Users/jemanuel/projects/fastmcp_rust || exit 90

mkdir -p probe_out
exec > >(tee probe_out/client_lib_parallel.txt) 2>&1

N=4
echo "HOST=$(hostname)"
echo "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "REPETITIONS=$N   test-threads=DEFAULT, features=DEFAULT (flags omitted)"
echo "NPROC=$(nproc 2>/dev/null)   # parallelism is the variable under test, so record it"

echo ""
echo "=== BUILD (outside the measurement window) ==="
BL=/tmp/clp_build.$$
cargo test --locked -p fastmcp-client --lib --no-run > "$BL" 2>&1
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

GREEN=0; RED=0; VOID=0
for i in $(seq 1 "$N"); do
  echo ""
  echo "================ RUN $i of $N ================"
  OUT=/tmp/clp_run_${i}.$$
  timeout --signal=KILL 600 "$BIN" > "$OUT" 2>&1
  RC=$?
  RAN=$(grep -oE '^running [0-9]+ tests?$' "$OUT" | grep -oE '[0-9]+' | head -1)
  echo "exit=$RC  ran=${RAN:-0}  of discovered=$TOTAL"
  # A partial run is not a measurement of the target (PL-1). An abort mid-suite
  # (stack overflow, SIGKILL) also lands here rather than being read as a pass.
  if [ "${RAN:-0}" != "$TOTAL" ]; then
    echo "VOID: executed ${RAN:-0} of $TOTAL -- not a full-target run."
    tail -8 "$OUT"; VOID=$((VOID+1)); continue
  fi
  grep -E '^test result:' "$OUT"
  if grep -q '^test result: ok\.' "$OUT"; then
    echo "-> RUN $i GREEN"; GREEN=$((GREEN+1))
  else
    echo "-> RUN $i RED. failing population:"
    grep -E '^test .* \.\.\. FAILED$' "$OUT" | sed 's/^/     /'
    RED=$((RED+1))
  fi
done

echo ""
echo "================ VERDICT ================"
echo "GREEN=$GREEN  RED=$RED  VOID=$VOID  of $N full-target runs at default parallelism"
echo ""
echo "failure population across all runs (times-failed  name):"
cat /tmp/clp_run_*.$$ 2>/dev/null | grep -E '^test .* \.\.\. FAILED$' \
  | sed 's/^test //; s/ \.\.\. FAILED$//' | sort | uniq -c | sort -rn | sed 's/^/   /'
echo "(empty above means no test failed in any run)"
echo ""
echo "the four named tests, specifically:"
for t in deferred_control_maintenance_exhaustion_preserves_sibling_ownership \
         client_deferred_yielding_legacy_positive \
         public_http_modern_subscriptions_listen_rejects_one_field_acknowledgement_id_mismatch \
         public_http_mrtr_callback_caller_runtime_planted_negative \
         automatic_catalog_lists_expire_while_waiting_for_the_second_page; do
  c=$(cat /tmp/clp_run_*.$$ 2>/dev/null | grep -cE "^test .*${t} \.\.\. FAILED$")
  echo "   failed ${c}/${N}   ${t}"
done
