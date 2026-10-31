#!/usr/bin/env bash
# TWO determinism experiments in ONE dispatch, because the fleet is a
# per-dispatch lottery right now (two RCH_EXIT=103 on hz3 today, both
# "namespace initialization refused ... Killed", which is the /tmp-full
# source-authority-registry mechanism) and every success has landed on hz4.
# Merging halves the exposure.
#
# Both run the FULL target at DEFAULT test-threads and DEFAULT features,
# repeated, recording the per-run failing SET. That is the configuration the
# beads name, and it is the one a solo `--exact --test-threads=1` run cannot
# reproduce -- I already ran all the named tests solo and all passed, which
# settles nothing because solo-serial is where they are documented to pass.
#
# A: fastmcp-transport --lib  x5   664 tests, suite ~2s
#    bd-native-pipe-backpressure-await-wake-cx678 asks EXACTLY this:
#    "treat the 'deterministic vs intermittent' question as OPEN and resolve
#     it before designing a fix". Its observation was 616 passed / 2 failed on
#    this target at default parallelism.
#
# B: fastmcp-client --lib     x4  1836 tests, suite ~28s per bd-534kp
#    bd-534kp's own "MEASUREMENT THAT DECIDES IT": "Repeat the default-parallel
#    target several times and record, per run, the exact failing set." Also
#    speaks to bd-1l88q, bd-kp4td, bd-to4cj, all of which name the parallel
#    suite.
set -u
cd /Users/jemanuel/projects/fastmcp_rust || exit 90

mkdir -p probe_out
exec > >(tee probe_out/parallel_determinism.txt) 2>&1

echo "HOST=$(hostname)"
echo "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "NPROC=$(nproc 2>/dev/null)   # parallelism is the variable under test"
echo "BLOBS:"
echo "  $(git hash-object crates/fastmcp-transport/src/async_io/native_pipe.rs 2>/dev/null)  native_pipe.rs"

run_target() {
  local crate="$1" reps="$2" budget="$3"
  echo ""
  echo "############################################################"
  echo "###  $crate --lib   x$reps   default test-threads"
  echo "############################################################"
  local bl=/tmp/pd_build_${crate}.$$
  cargo test --locked -p "$crate" --lib --no-run > "$bl" 2>&1
  echo "BUILD_EXIT=$?"
  sed 's/\x1b\[[0-9;]*m//g' "$bl" > "$bl.plain"
  tail -2 "$bl.plain"
  local bin
  bin=$(sed -n 's/.*Executable[[:space:]]*unittests src\/lib\.rs (\(.*\))[[:space:]]*$/\1/p' "$bl.plain" | tail -1)
  if [ -z "${bin:-}" ] || [ ! -x "$bin" ]; then
    echo "NO TEST BINARY for $crate -- no verdict."; grep -E '^error' "$bl.plain" | head -8; return 1
  fi
  local total
  total=$("$bin" --list --format terse 2>/dev/null | grep -c ': test$')
  echo "DISCOVERED=$total"

  local green=0 red=0 void=0
  for i in $(seq 1 "$reps"); do
    local out=/tmp/pd_${crate}_run_${i}.$$
    timeout --signal=KILL "$budget" "$bin" > "$out" 2>&1
    local rc=$? ran
    ran=$(grep -oE '^running [0-9]+ tests?$' "$out" | grep -oE '[0-9]+' | head -1)
    # A partial run is not a measurement of the target (PL-1); an abort
    # mid-suite lands here instead of being misread as a pass.
    if [ "${ran:-0}" != "$total" ]; then
      echo "  run $i: VOID exit=$rc ran=${ran:-0}/$total"; tail -4 "$out" | sed 's/^/      /'
      void=$((void+1)); continue
    fi
    if grep -q '^test result: ok\.' "$out"; then
      echo "  run $i: GREEN exit=$rc  $(grep -E '^test result:' "$out" | head -1)"
      green=$((green+1))
    else
      echo "  run $i: RED   exit=$rc  $(grep -E '^test result:' "$out" | head -1)"
      grep -E '^test .* \.\.\. FAILED$' "$out" | sed 's/^/        /'
      red=$((red+1))
    fi
  done
  echo "  --> $crate: GREEN=$green RED=$red VOID=$void of $reps"
  echo "  --> failure population (times-failed  name):"
  cat /tmp/pd_${crate}_run_*.$$ 2>/dev/null | grep -E '^test .* \.\.\. FAILED$' \
    | sed 's/^test //; s/ \.\.\. FAILED$//' | sort | uniq -c | sort -rn | sed 's/^/        /'
  echo "  (empty means nothing failed in any run)"
  return 0
}

run_target fastmcp-transport 5 300
run_target fastmcp-client    4 600

echo ""
echo "================ THE NAMED TESTS, SPECIFICALLY ================"
for t in native_pipe_backpressure_yields_and_wakes_without_duplicating_bytes \
         native_pipe_readiness_updates_waker_and_preserves_data_through_eof \
         deferred_control_maintenance_exhaustion_preserves_sibling_ownership \
         client_deferred_yielding_legacy_positive \
         public_http_modern_subscriptions_listen_rejects_one_field_acknowledgement_id_mismatch \
         public_http_mrtr_callback_caller_runtime_planted_negative \
         automatic_catalog_lists_expire_while_waiting_for_the_second_page; do
  c=$(cat /tmp/pd_*_run_*.$$ 2>/dev/null | grep -cE "^test .*${t} \.\.\. FAILED$")
  echo "   failed in ${c} run(s)   ${t}"
done
