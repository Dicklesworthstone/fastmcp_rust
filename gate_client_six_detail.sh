#!/usr/bin/env bash
# FULL OUTPUT for bd-c8xxl's six, plus the reopened P0's test.
#
# My earlier client detail pass grepped for `panicked at|assertion|left:|right:`
# and so captured each panic's LOCATION but dropped the payload on the next
# line. That worked out for the server only because I re-ran it printing
# everything. Same treatment here: no pattern, bounded full output.
#
# The payload is the whole diagnosis for at least two of these:
#   http_executor.rs:18962:10 is
#     .expect("the public client completes the exact fresh legacy lifecycle")
#   so the line after it carries the Err value from connect_http_client_with_cx.
#   mcp_config.rs:1834:14 is the reopened P0's own assertion.
#
# WHY THESE TWO TOGETHER. bd-c8xxl's Group B and the reopened false close
# bd-config-client-auto-stdio-byl21 both fail on ProtocolPolicy::Auto
# negotiating down to exact-2024 -- one over HTTP, one over stdio. If one
# defect is behind both, their error values should rhyme. That is cheap to
# check and expensive to discover after fixing one of them.
#
# A SPECIFIC HYPOTHESIS WORTH NAMING BEFORE THE RUN, so the output can refute
# it: the Auto test builds its cx with `Cx::for_request()`, and bd-nxjy7
# root-caused `HolderNotLive` as asupersync 0.5.0 refusing a REQUEST-SCOPED cx
# as an obligation holder. If connect_http_client_with_cx must hold an
# obligation (an SSE listener task), a request cx would be refused and the
# connect would fail for reasons that have nothing to do with Auto negotiation.
# If the payload says HolderNotLive, the fix is the harness's cx, not the
# product's fallback -- and three beads change shape.
#
# Also captures the FIXTURE thread's panic. These tests assert inside a
# thread::spawn whose join happens AFTER the client's .expect, so a fixture
# assertion failure is masked by the client error it causes
# ([[a-panic-in-a-task-resurfaces-at-the-join]]). --nocapture lets the
# fixture's panic reach the log even though the test never joins it.
set -u
cd /Users/jemanuel/projects/fastmcp_rust || exit 90

mkdir -p probe_out
exec > >(tee probe_out/client_six_detail.txt) 2>&1

echo "HOST=$(hostname)"
echo "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "NPROC=$(nproc 2>/dev/null)"

NAMES=(
  http_executor::tests::public_http_client_auto_falls_back_to_ready_exact_legacy_lifecycle
  mcp_config::tests::config_client_uses_modern_first_builder_with_identity_cwd_and_environment
  http_executor::tests::public_http_subscription_cancellation_requires_matching_request_and_stream_ids
  http_executor::tests::public_http_subscription_rejects_invalid_and_string_lookalike_event_owners
  http_auth::dpop::native::core::stream::subscription::tests::termination::ordinary_core_rpc_still_rejects_the_subscription_tail_exception
  http_auth::rpc::subscription::tests::preflight_refuses_unnegotiated_filters_duplicate_resources_and_oversized_requests
  memory::tests::memory_client_caller_deadline_interrupts_full_queue_before_publication
)

echo ""
echo "=== BUILD (warm) ==="
BL=/tmp/c6_build.$$
cargo test --locked -p fastmcp-client --lib --no-run > "$BL" 2>&1
echo "BUILD_EXIT=$?"
sed 's/\x1b\[[0-9;]*m//g' "$BL" > "$BL.plain"
tail -2 "$BL.plain"
BIN=$(sed -n 's/.*Executable[[:space:]]*unittests src\/lib\.rs (\(.*\))[[:space:]]*$/\1/p' "$BL.plain" | tail -1)
if [ -z "${BIN:-}" ] || [ ! -x "$BIN" ]; then
  echo "NO TEST BINARY -- no verdict."; cat "$BL.plain"; exit 11
fi
echo "BIN=$BIN"
"$BIN" --list --format terse 2>/dev/null | sed 's/: test$//' > probe_out/client_lib_discovered.txt
echo "DISCOVERED=$(grep -c . probe_out/client_lib_discovered.txt)  (full list synced back)"

for t in "${NAMES[@]}"; do
  n=$(grep -cxF "$t" probe_out/client_lib_discovered.txt)
  echo ""
  echo "================================================================"
  echo "### $t"
  echo "================================================================"
  if [ "$n" != "1" ]; then
    echo "VOID: resolves to $n discovered tests, not 1. Says nothing about this name."
    continue
  fi
  O=/tmp/c6_solo.$$
  # RUST_BACKTRACE=1: for the two .expect()/.unwrap() sites the frame list is
  # what names which await actually failed, and it costs nothing here.
  RUST_BACKTRACE=1 timeout --signal=KILL 300 "$BIN" "$t" --exact --test-threads=1 --nocapture > "$O" 2>&1
  rc=$?
  if ! grep -q 'running 1 test' "$O"; then
    echo "VOID: zero tests executed (exit $rc). Not a result."
    tail -8 "$O"; continue
  fi
  echo "exit=$rc"
  sed -n '1,150p' "$O"
done

echo ""
echo "================ ERROR-VALUE SUMMARY ================"
echo "(the line after each 'panicked at' is the payload; that is the datum)"
grep -A2 'panicked at' probe_out/client_six_detail.txt 2>/dev/null \
  | grep -E "^called|^assertion|Err value|HolderNotLive|^  *[A-Z]" | sort -u | head -20
echo ""
echo "HolderNotLive present anywhere in this run? -> $(grep -c 'HolderNotLive' probe_out/client_six_detail.txt 2>/dev/null)"
