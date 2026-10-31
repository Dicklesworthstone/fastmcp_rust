#!/usr/bin/env bash
# VERIFY TWO FIXTURE FIXES, and gate them on the whole target rather than on
# the two tests I touched.
#
# FIX 1  http_auth/rpc/subscription/tests.rs
#   The oversized-resource row was "x".repeat(MAX + 1) -- a colon-free string.
#   `resourceSubscriptions` deserializes through AbsoluteUri::parse, which
#   refuses a colon-free value as Invalid("URI scheme"), so the `params`
#   helper's .expect fired and `prepare`'s 16 KiB length check was NEVER
#   REACHED by this test. Now "file:///" + repeat(MAX) -- a valid URI, well
#   under MAX_ABSOLUTE_URI_BYTES (64 KiB), still over the managed 16 KiB bound.
#   The assertion (.is_err()) is unchanged; the row now reaches the refusal it
#   claims to test. Coverage goes UP, not down -- this is not an RH-1
#   relaxation.
#
# FIX 2  .../core/stream/subscription/tests/termination.rs
#   The modern tools/list result fixture was {"resultType":"complete","tools":[]}
#   and decoded as Protocol(InvalidResult), so `admit(..).unwrap()` panicked and
#   the terminal-tail refusal the test asserts was never reached. Modern
#   tools/list is a cache-hinted family: ttlMs and cacheScope are required.
#   Every other modern complete-result fixture in this crate carries both
#   (cache.rs:832/1407, memory.rs:805, execution.rs:8935, mcp_apps.rs:6714).
#
# Both diagnoses came from the error VALUES captured in
# probe_out/client_six_detail.txt, not from guessing.
#
# THE GATE. Two named tests passing is not the claim; the claim is that the
# target's failing population shrank by exactly these two and gained nothing.
# Baseline at HEAD before the fixes, 4 complete runs at default test-threads:
# 17 deterministic + 1 intermittent of 1836. So the expected post-fix
# population is 15 deterministic + the same 1 intermittent, and ANY new name
# is a regression I caused.
set -u
cd /Users/jemanuel/projects/fastmcp_rust || exit 90

mkdir -p probe_out
exec > >(tee probe_out/client_fix_verify.txt) 2>&1

echo "HOST=$(hostname)"
echo "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "NPROC=$(nproc 2>/dev/null)"
echo "BLOBS (bind the claim to the bytes under test):"
echo "  $(git hash-object crates/fastmcp-client/src/http_auth/rpc/subscription/tests.rs 2>/dev/null)  rpc/subscription/tests.rs"
echo "  $(git hash-object crates/fastmcp-client/src/http_auth/dpop/native/core/stream/subscription/tests/termination.rs 2>/dev/null)  .../tests/termination.rs"

FIXED=(
  http_auth::rpc::subscription::tests::preflight_refuses_unnegotiated_filters_duplicate_resources_and_oversized_requests
  http_auth::dpop::native::core::stream::subscription::tests::termination::ordinary_core_rpc_still_rejects_the_subscription_tail_exception
  # Not fixed -- made SELF-DIAGNOSING. Both previously reported only
  # "assertion failed: matches!(..)" because the subject was moved into the
  # macro. They now borrow it and name the observed value, which is the datum
  # needed to tell "the input was ADMITTED" (a real hole) from "refused with a
  # different variant" (a stale expectation). Listed here so the script prints
  # their full solo output.
  http_executor::tests::public_http_subscription_cancellation_requires_matching_request_and_stream_ids
  http_executor::tests::public_http_subscription_rejects_invalid_and_string_lookalike_event_owners
)

echo ""
echo "=== BUILD ==="
BL=/tmp/cfv_build.$$
cargo test --locked -p fastmcp-client --lib --no-run > "$BL" 2>&1
echo "BUILD_EXIT=$?"
sed 's/\x1b\[[0-9;]*m//g' "$BL" > "$BL.plain"
tail -2 "$BL.plain"
# A fixture edit can break compilation; surface that instead of reporting a
# missing binary as some other failure.
grep -E '^error' "$BL.plain" | head -12
BIN=$(sed -n 's/.*Executable[[:space:]]*unittests src\/lib\.rs (\(.*\))[[:space:]]*$/\1/p' "$BL.plain" | tail -1)
if [ -z "${BIN:-}" ] || [ ! -x "$BIN" ]; then
  echo "NO TEST BINARY -- the edits did not compile. No verdict."; exit 11
fi
echo "BIN=$BIN"
"$BIN" --list --format terse 2>/dev/null | sed 's/: test$//' > /tmp/cfv_list.$$
TOTAL=$(grep -c . /tmp/cfv_list.$$)
echo "DISCOVERED=$TOTAL   (baseline was 1836)"

echo ""
echo "############################################################"
echo "### THE TWO FIXED TESTS, solo, serial, full output"
echo "############################################################"
OK=0
for t in "${FIXED[@]}"; do
  n=$(grep -cxF "$t" /tmp/cfv_list.$$)
  echo ""
  echo "---- $t"
  if [ "$n" != "1" ]; then echo "VOID: resolves to $n discovered tests, not 1."; continue; fi
  O=/tmp/cfv_solo.$$
  RUST_BACKTRACE=1 timeout --signal=KILL 300 "$BIN" "$t" --exact --test-threads=1 --nocapture > "$O" 2>&1
  rc=$?
  if ! grep -q 'running 1 test' "$O"; then
    echo "VOID: zero tests executed (exit $rc). Not a pass."; tail -6 "$O"; continue
  fi
  if grep -q '^test result: ok\.' "$O"; then
    echo "   -> PASS (exit $rc)"; OK=$((OK+1))
  else
    echo "   -> STILL FAILING (exit $rc). The diagnosis was wrong; here is why:"
    sed -n '1,40p' "$O"
  fi
done
echo ""
echo "fixed-and-passing: $OK of ${#FIXED[@]}"

echo ""
echo "############################################################"
echo "### THE GATE: full target x3, default test-threads"
echo "############################################################"
for i in 1 2 3; do
  O=/tmp/cfv_full_${i}.$$
  timeout --signal=KILL 900 "$BIN" > "$O" 2>&1
  RAN=$(grep -oE '^running [0-9]+ tests?$' "$O" | grep -oE '[0-9]+' | head -1)
  if [ "${RAN:-0}" != "$TOTAL" ]; then
    echo "  run $i: VOID ran=${RAN:-0}/$TOTAL"; continue
  fi
  echo "  run $i: $(grep -E '^test result:' "$O" | head -1)"
done

echo ""
echo "  failing population across the 3 runs (times-failed  name):"
cat /tmp/cfv_full_*.$$ 2>/dev/null | grep -E '^test .* \.\.\. FAILED$' \
  | sed 's/^test //; s/ \.\.\. FAILED$//' | sort | uniq -c | sort -rn > /tmp/cfv_pop.$$
sed 's/^/     /' /tmp/cfv_pop.$$
echo ""
echo "  distinct failing names = $(grep -c . /tmp/cfv_pop.$$)   (baseline 18: 17 deterministic + 1 intermittent)"
echo ""
echo "  NEITHER FIXED TEST MAY APPEAR BELOW:"
for t in "${FIXED[@]}"; do
  leaf=${t##*::}
  echo "     $(grep -cE "$leaf" /tmp/cfv_pop.$$) occurrence(s)  $leaf"
done
echo ""
echo "  REGRESSION CHECK -- names failing now that were NOT in the baseline 18:"
cat <<'BASE' > /tmp/cfv_base.$$
modern_looking_metadata_cannot_retag_a_legacy_typed_catalog
ordinary_core_rpc_still_rejects_the_subscription_tail_exception
preflight_refuses_unnegotiated_filters_duplicate_resources_and_oversized_requests
public_http_client_auto_falls_back_to_ready_exact_legacy_lifecycle
public_http_subscription_cancellation_requires_matching_request_and_stream_ids
public_http_subscription_rejects_invalid_and_string_lookalike_event_owners
config_client_uses_modern_first_builder_with_identity_cwd_and_environment
memory_client_caller_deadline_interrupts_full_queue_before_publication
async_mrtr_callback_cancellation
async_mrtr_continuation_bounds
async_mrtr_operation_deadline
async_mrtr_public_verbs
async_mrtr_refusal_and_passthrough
public_stdio_installed_mrtr_accepts_exact_cumulative_input_budget
public_stdio_installed_mrtr_refuses_one_extra_input_before_callbacks_or_retry
sync_reverse_handler_is_polled_under_the_caller_cx_without_a_nested_runtime
sync_reverse_handler_nesting_block_on_is_refused_before_any_retry
public_http_modern_subscriptions_listen_rejects_one_field_acknowledgement_id_mismatch
BASE
NEW=0
while read -r _c name; do
  leaf=${name##*::}
  grep -qxF "$leaf" /tmp/cfv_base.$$ || { echo "     NEW FAILURE: $name"; NEW=$((NEW+1)); }
done < /tmp/cfv_pop.$$
echo "     new failures introduced: $NEW   (must be 0)"
