#!/usr/bin/env bash
# WHY: the determinism run on hz3 (2026-10-31T03:44Z, probe_out/parallel_determinism.txt)
# found the fastmcp-client lib target RED in 4 of 4 full runs at DEFAULT
# test-threads, with a STABLE set of 17 tests failing in every run and exactly
# one intermittent (1 of 4). The review queue has beads for the intermittent
# one and for four tests that did NOT fail at all. It has nothing naming these
# 17. "17 failed" is not a diagnosis, so this gets their panic text.
#
# Two configurations, because the pair is what discriminates:
#   PASS A  all 18 names together, --test-threads=1   -> is the failure
#           load-independent? A serial failure is a hard defect, not contention.
#   PASS B  each name ALONE, --exact --test-threads=1 -> does it survive total
#           isolation? Separates a shared-fixture collision from a real defect.
#
# --nocapture so the panic text reaches the log. Guards, learned the hard way:
#   - resolve each leaf to its FULL module path and require EXACTLY ONE match
#   - require `running N test` before reading any exit status (PL-1: a filtered
#     run exits 0 having executed nothing, and that is red, not green)
set -u
cd /Users/jemanuel/projects/fastmcp_rust || exit 90

mkdir -p probe_out
exec > >(tee probe_out/client_17_detail.txt) 2>&1

echo "HOST=$(hostname)"
echo "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "NPROC=$(nproc 2>/dev/null)"

# The stable 17 plus the 1 intermittent, verbatim from the determinism record.
NAMES=(
  http_auth::dpop::native::core::catalog::era_tests::modern_looking_metadata_cannot_retag_a_legacy_typed_catalog
  http_auth::dpop::native::core::stream::subscription::tests::termination::ordinary_core_rpc_still_rejects_the_subscription_tail_exception
  http_auth::rpc::subscription::tests::preflight_refuses_unnegotiated_filters_duplicate_resources_and_oversized_requests
  http_executor::tests::public_http_client_auto_falls_back_to_ready_exact_legacy_lifecycle
  http_executor::tests::public_http_subscription_cancellation_requires_matching_request_and_stream_ids
  http_executor::tests::public_http_subscription_rejects_invalid_and_string_lookalike_event_owners
  mcp_config::tests::config_client_uses_modern_first_builder_with_identity_cwd_and_environment
  memory::tests::memory_client_caller_deadline_interrupts_full_queue_before_publication
  tests::async_mrtr_callback_cancellation
  tests::async_mrtr_continuation_bounds
  tests::async_mrtr_operation_deadline
  tests::async_mrtr_public_verbs
  tests::async_mrtr_refusal_and_passthrough
  tests::public_stdio_installed_mrtr_accepts_exact_cumulative_input_budget
  tests::public_stdio_installed_mrtr_refuses_one_extra_input_before_callbacks_or_retry
  tests::sync_reverse_handler_is_polled_under_the_caller_cx_without_a_nested_runtime
  tests::sync_reverse_handler_nesting_block_on_is_refused_before_any_retry
  http_executor::tests::public_http_modern_subscriptions_listen_rejects_one_field_acknowledgement_id_mismatch
)

echo ""
echo "=== BUILD (warm from the determinism run) ==="
BL=/tmp/c17_build.$$
cargo test --locked -p fastmcp-client --lib --no-run > "$BL" 2>&1
echo "BUILD_EXIT=$?"
sed 's/\x1b\[[0-9;]*m//g' "$BL" > "$BL.plain"
tail -2 "$BL.plain"
BIN=$(sed -n 's/.*Executable[[:space:]]*unittests src\/lib\.rs (\(.*\))[[:space:]]*$/\1/p' "$BL.plain" | tail -1)
if [ -z "${BIN:-}" ] || [ ! -x "$BIN" ]; then
  echo "NO TEST BINARY -- no verdict."; cat "$BL.plain"; exit 11
fi
echo "BIN=$BIN"
"$BIN" --list --format terse 2>/dev/null | sed 's/: test$//' > /tmp/c17_list.$$
echo "DISCOVERED=$(grep -c . /tmp/c17_list.$$)"

# Every name must resolve to exactly one discovered test, or the run is void.
echo ""
echo "=== NAME RESOLUTION ==="
RESOLVE_BAD=0
for n in "${NAMES[@]}"; do
  c=$(grep -cxF "$n" /tmp/c17_list.$$)
  [ "$c" = "1" ] || { echo "  UNRESOLVED($c): $n"; RESOLVE_BAD=$((RESOLVE_BAD+1)); }
done
echo "unresolved=$RESOLVE_BAD of ${#NAMES[@]}"
[ "$RESOLVE_BAD" -eq 0 ] || { echo "ABORT: a name does not name exactly one test."; exit 12; }

echo ""
echo "############################################################"
echo "### PASS A: all 18 together, --test-threads=1 (serial)"
echo "############################################################"
A=/tmp/c17_passA.$$
: > /tmp/c17_filters.$$
for n in "${NAMES[@]}"; do printf '%s\n' "$n" >> /tmp/c17_filters.$$; done
timeout --signal=KILL 900 "$BIN" --test-threads=1 --nocapture --exact "${NAMES[@]}" > "$A" 2>&1
echo "exit=$?"
RAN=$(grep -oE '^running [0-9]+ tests?$' "$A" | grep -oE '[0-9]+' | head -1)
echo "ran=${RAN:-0} of ${#NAMES[@]} requested"
if [ "${RAN:-0}" = "0" ]; then
  echo "VOID: zero tests executed. Not a result."; tail -10 "$A"
else
  grep -E '^test result:' "$A"
  echo "--- per-test outcome ---"
  grep -E '^test .* \.\.\. (ok|FAILED)$' "$A" | sed 's/^/   /'
  echo "--- panic text (first 200 lines of failure detail) ---"
  sed -n '/^failures:$/,$p' "$A" | head -200
fi

echo ""
echo "############################################################"
echo "### PASS B: each name ALONE, --exact --test-threads=1"
echo "############################################################"
SOLO_PASS=0; SOLO_FAIL=0; SOLO_VOID=0
for n in "${NAMES[@]}"; do
  O=/tmp/c17_solo.$$
  timeout --signal=KILL 180 "$BIN" "$n" --exact --test-threads=1 > "$O" 2>&1
  rc=$?
  if ! grep -q '^running 1 test$' "$O"; then
    echo "  VOID  (ran 0, exit $rc)  $n"; SOLO_VOID=$((SOLO_VOID+1)); continue
  fi
  if grep -q '^test result: ok\.' "$O"; then
    echo "  PASS  $n"; SOLO_PASS=$((SOLO_PASS+1))
  else
    echo "  FAIL  $n"
    grep -E "^thread|panicked at|assertion|^Error|left:|right:" "$O" | head -4 | sed 's/^/          /'
    SOLO_FAIL=$((SOLO_FAIL+1))
  fi
done

echo ""
echo "================ VERDICT ================"
echo "PASS B solo-serial:  PASS=$SOLO_PASS  FAIL=$SOLO_FAIL  VOID=$SOLO_VOID  of ${#NAMES[@]}"
echo ""
echo "READING: a name that FAILS solo-serial is a deterministic defect independent"
echo "of load. A name that PASSES solo-serial but failed 4/4 in the full target is"
echo "a cross-test interaction -- shared fixture, shared port, or a global."
