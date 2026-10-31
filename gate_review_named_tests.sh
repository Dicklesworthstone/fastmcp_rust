#!/usr/bin/env bash
# FIRST EXECUTION pass over six review-queue beads whose claim is a NAMED TEST.
#
#   bead        crate              test
#   bd-55ola    fastmcp-server     returning_subscription_quiescence_runs_hook_after_owner_eof
#   bd-native-  fastmcp-transport  native_pipe_backpressure_yields_and_wakes_without_duplication
#   bd-534kp    fastmcp-client     deferred_control_maintenance_exhaustion_preserves_...
#   bd-1l88q    fastmcp-client     public_http_modern_subscriptions_listen_rejects_one_...
#   bd-kp4td    fastmcp-client     public_http_mrtr_callback_caller_runtime_planted_neg...
#   bd-to4cj    fastmcp-client     automatic_catalog_lists_expire_while_waiting_for_the...
#
# All six are lib unit tests under DEFAULT features; none is feature-gated
# (two are #[cfg(unix)], satisfied on the Linux workers), so no --features
# flag is needed and no projection question arises.
#
# ORDERED CHEAPEST FIRST on purpose: fastmcp-server's lib test target is warm
# on the fleet (a previous job reported `Finished test profile in 0.19s`),
# transport is small, and fastmcp-client is the expensive build. If this job
# hits the 1800 s ceiling, the results already tee'd to probe_out are the ones
# that survive, so the cheap certain ones go first.
#
# Guards, all three learned the hard way earlier today when a probe reported
# "NOT a hang" while executing ZERO tests:
#   - resolve each leaf to its FULL module::path::name from --list
#   - refuse to run unless it resolves to EXACTLY ONE test
#   - require `running 1 test` in the output before reading any exit status
set -u
cd /Users/jemanuel/projects/fastmcp_rust || exit 90

mkdir -p probe_out
exec > >(tee probe_out/review_named_tests.txt) 2>&1

echo "HOST=$(hostname)"
echo "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# crate:leaf  -- order is load-bearing, see header
# Leaf names resolved from the source BEFORE dispatch. Three of my first
# guesses were wrong (owner_eof vs owner_retirement; without_duplication vs
# without_duplicating_bytes; single_inflight_admission vs sibling_ownership),
# and bd-1l88q's "..._rejects_one_" prefix has two siblings in the file, so the
# full name is required to disambiguate. The guards below would have caught
# each as VOID, but a wrong name costs a whole fleet job on a degraded fleet.
TESTS=(
  "fastmcp-server:returning_subscription_quiescence_runs_hook_after_owner_retirement"
  "fastmcp-transport:native_pipe_backpressure_yields_and_wakes_without_duplicating_bytes"
  "fastmcp-client:deferred_control_maintenance_exhaustion_preserves_sibling_ownership"
  "fastmcp-client:public_http_modern_subscriptions_listen_rejects_one_field_acknowledgement_id_mismatch"
  "fastmcp-client:public_http_mrtr_callback_caller_runtime_planted_negative"
  "fastmcp-client:automatic_catalog_lists_expire_while_waiting_for_the_second_page"
)

declare -A BIN_FOR
build_crate() {
  local crate="$1"
  [ -n "${BIN_FOR[$crate]:-}" ] && return 0
  echo ""
  echo "######## BUILD $crate --lib ########"
  local bl=/tmp/rnt_build_${crate}.$$
  cargo test --locked -p "$crate" --lib --no-run > "$bl" 2>&1
  local rc=$?
  echo "BUILD_EXIT=$rc"
  sed 's/\x1b\[[0-9;]*m//g' "$bl" > "$bl.plain"
  tail -3 "$bl.plain"
  if [ "$rc" -ne 0 ]; then
    echo "BUILD FAILED for $crate -- no verdict for its tests."
    grep -E "^error" "$bl.plain" | head -12
    return 1
  fi
  local bin
  bin=$(sed -n 's/.*Executable[[:space:]]*unittests src\/lib\.rs (\(.*\))[[:space:]]*$/\1/p' "$bl.plain" | tail -1)
  if [ -z "${bin:-}" ] || [ ! -x "$bin" ]; then
    echo "NO BINARY parsed for $crate"; return 1
  fi
  BIN_FOR[$crate]="$bin"
  echo "BIN=$bin"
  "$bin" --list --format terse 2>/dev/null | sed 's/: test$//' > /tmp/rnt_list_${crate}.$$
  echo "DISCOVERED=$(grep -c . /tmp/rnt_list_${crate}.$$)"
  return 0
}

PASS=0; FAIL=0; VOID=0; SUMMARY=""
for entry in "${TESTS[@]}"; do
  CRATE=${entry%%:*}; LEAF=${entry#*:}
  if ! build_crate "$CRATE"; then
    SUMMARY="${SUMMARY}\n  $CRATE  ${LEAF:0:52}  VOID(build)"
    VOID=$((VOID+1)); continue
  fi
  BIN="${BIN_FOR[$CRATE]}"
  echo ""
  echo "================ $CRATE :: $LEAF ================"
  FULL=$(grep -E "(^|::)${LEAF}$" /tmp/rnt_list_${CRATE}.$$)
  N=$(printf '%s\n' "$FULL" | grep -c .)
  if [ "$N" != "1" ]; then
    echo "VOID: resolves to $N tests, not 1. FULL=${FULL:-<none>}"
    SUMMARY="${SUMMARY}\n  $CRATE  ${LEAF:0:52}  VOID(resolve=$N)"
    VOID=$((VOID+1)); continue
  fi
  echo "FULL=$FULL"
  OUT=/tmp/rnt_run.$$
  timeout --signal=KILL 120 "$BIN" "$FULL" --exact --test-threads=1 --nocapture > "$OUT" 2>&1
  RC=$?
  if ! grep -q 'running 1 test' "$OUT"; then
    echo "VOID: zero tests executed (exit $RC). Not a pass."
    tail -6 "$OUT"
    SUMMARY="${SUMMARY}\n  $CRATE  ${LEAF:0:52}  VOID(ran 0)"
    VOID=$((VOID+1)); continue
  fi
  grep -E '^test |^test result:' "$OUT"
  if grep -q '^test result: ok\.' "$OUT"; then
    echo "-> PASS (exit $RC)"
    SUMMARY="${SUMMARY}\n  $CRATE  ${LEAF:0:52}  PASS"
    PASS=$((PASS+1))
  else
    echo "-> FAIL (exit $RC)"
    sed -n '1,60p' "$OUT"
    SUMMARY="${SUMMARY}\n  $CRATE  ${LEAF:0:52}  FAIL"
    FAIL=$((FAIL+1))
  fi
done

echo ""
echo "================ SUMMARY ================"
printf '%b\n' "$SUMMARY"
echo "PASS=$PASS FAIL=$FAIL VOID=$VOID of ${#TESTS[@]}"
