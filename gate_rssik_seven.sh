#!/usr/bin/env bash
# bd-rssik: FIRST EXECUTION of the seven remaining cluster failures.
#
# Three commits landed 2026-10-29 that between them claim ALL SEVEN, and every
# one of them records that nothing ran:
#
#   5aab6e16  "Addresses bd-lk26c and bd-rssik B/E"
#             "No project tests executed."
#   c11df758  "Addresses bd-rssik C1/C2/C3"
#             "asupersync was killed by memory pressure (SIGKILL) before
#              project tests could run."
#   ae52c578  "Addresses bd-rssik D1"
#             "Tests remain pending execution."
#
# The authoring lane was blocked by local memory pressure compiling asupersync.
# The RCH worker already holds a warm build of this target, so the marginal
# cost here is seconds per test.
#
# Deliberately runs each test INDIVIDUALLY with --exact rather than running the
# target: this is a bounded named-test measurement, not a `-p fastmcp-server
# --lib` run, which belongs to the orchestrator's serialized lane and is what
# closure would require. Individual runs also remove cross-test interference as
# an explanation for any result.
#
# Every guard from gate_lk26c_probe.sh applies, because an earlier version of
# that probe reported "NOT a hang" while executing ZERO tests:
#   - resolve each leaf to its FULL module::path::name from --list
#   - refuse to run unless it resolves to EXACTLY ONE test
#   - require `running 1 test` in the output before reading any exit status
set -u
cd /Users/jemanuel/projects/fastmcp_rust || exit 90

mkdir -p probe_out
exec > >(tee probe_out/rssik_seven.txt) 2>&1

# cluster:leaf-name, as recorded in the bead's attribution table
TESTS=(
  "B1:forced_subscription_ack_order_active_first_keeps_graceful_completion"
  "B2:forced_subscription_ack_order_pump_first_keeps_graceful_completion"
  "C1:live_http_response_write_timeout_releases_stalled_json_peer"
  "C2:live_http_shutdown_owns_registered_sse_body_before_flushing_terminal"
  "C3:live_http_subscription_cancellation_cannot_be_replaced_by_response_middleware"
  "D1:elected_shutdown_revalidates_original_credential_before_any_write"
  "E1:returning_subscription_unrelated_peer_cancel_preserves_owner_until_eof"
)

echo "HOST=$(hostname)"
echo "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "HEAD=$(git rev-parse HEAD)"
echo "DIRTY:"; git status --porcelain -- crates/ | sed 's/^/  /'

echo "=== BUILD (expected cached) ==="
BL=/tmp/rssik_build.$$
cargo test --locked -p fastmcp-server --lib --no-run > "$BL" 2>&1
echo "BUILD_EXIT=$?"
sed 's/\x1b\[[0-9;]*m//g' "$BL" > "$BL.plain"
tail -3 "$BL.plain"
BIN=$(sed -n 's/.*Executable[[:space:]]*unittests src\/lib\.rs (\(.*\))[[:space:]]*$/\1/p' "$BL.plain" | tail -1)
if [ -z "${BIN:-}" ] || [ ! -x "$BIN" ]; then
  echo "NO TEST BINARY -- no verdict."; cat "$BL.plain"; exit 11
fi
echo "BIN=$BIN"

"$BIN" --list --format terse 2>/dev/null | sed 's/: test$//' > /tmp/rssik_all.$$
echo "DISCOVERED=$(grep -c . /tmp/rssik_all.$$)"

PASS=0; FAIL=0; VOID=0
SUMMARY=""
for entry in "${TESTS[@]}"; do
  CL=${entry%%:*}; LEAF=${entry#*:}
  echo ""
  echo "================ $CL  $LEAF ================"
  FULL=$(grep -E "(^|::)${LEAF}$" /tmp/rssik_all.$$)
  N=$(printf '%s\n' "$FULL" | grep -c .)
  if [ "$N" != "1" ]; then
    echo "VOID: resolves to $N tests, not 1. FULL=${FULL:-<none>}"
    SUMMARY="${SUMMARY}\n  $CL  VOID(resolve=$N)  $LEAF"
    VOID=$((VOID+1)); continue
  fi
  echo "FULL=$FULL"
  OUT=/tmp/rssik_${CL}.$$
  timeout --signal=KILL 90 "$BIN" "$FULL" --exact --test-threads=1 --nocapture > "$OUT" 2>&1
  RC=$?
  if ! grep -q 'running 1 test' "$OUT"; then
    echo "VOID: zero tests executed (exit $RC). Not a pass."
    tail -5 "$OUT"
    SUMMARY="${SUMMARY}\n  $CL  VOID(ran 0)  $LEAF"
    VOID=$((VOID+1)); continue
  fi
  grep -E '^test |^test result:' "$OUT"
  if grep -q '^test result: ok\.' "$OUT"; then
    echo "-> $CL PASS (exit $RC)"
    SUMMARY="${SUMMARY}\n  $CL  PASS  $LEAF"
    PASS=$((PASS+1))
  else
    echo "-> $CL FAIL (exit $RC)"
    # Keep the diagnostic: a failure here is the valuable half of the result.
    sed -n '1,60p' "$OUT"
    SUMMARY="${SUMMARY}\n  $CL  FAIL  $LEAF"
    FAIL=$((FAIL+1))
  fi
done

echo ""
echo "================ SUMMARY ================"
printf '%b\n' "$SUMMARY"
echo "PASS=$PASS FAIL=$FAIL VOID=$VOID of ${#TESTS[@]}"
