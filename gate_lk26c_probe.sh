#!/usr/bin/env bash
# bd-lk26c: localise the hang in
#   lib_unit_tests::subscription_deadline_does_not_wait_for_a_listener_shutdown_election
#
# This script runs ON the RCH worker (invoked as `rch exec --job -- bash
# gate_lk26c_probe.sh`), because the discriminating observations need several
# commands against a LIVE process and rch refuses `sh -c`.
#
# Two prior static passes failed to localise this. Both argued from the waker
# semantics that a single Future::poll never returns, but neither measured the
# one bit that splits the candidate space in half:
#
#   SPIN (livelock): the thread burns CPU inside one poll. utime climbs,
#                    %CPU ~100, wchan is 0/running. Cause is a loop whose
#                    awaits all resolve Ready -- e.g. a timer armed at an
#                    already-past deadline re-armed every iteration.
#   PARK (deadlock): the thread is blocked in the kernel. utime FROZEN,
#                    %CPU ~0, wchan names a futex/park. Cause is a blocking
#                    primitive called from inside a poll -- a std Condvar or
#                    Mutex, or a runtime that needs a driver thread that
#                    `blocking_threads(0, 0)` never created.
#
# These two have disjoint remedies and the bead currently asserts the first
# without evidence. utime sampled twice is the authoritative discriminator:
# it is monotonic CPU time actually consumed, not an instantaneous rate.
#
# Everything here is zero-dependency /proc reading. gdb/eu-stack are ATTEMPTED
# for an exact frame but are not required for the verdict, because they are
# not known to be installed on the fleet.
set -u

TEST=subscription_deadline_does_not_wait_for_a_listener_shutdown_election

# Attempt 3 produced RCH_SCOPED_COMPLETION_UNCONFIRMED: SSH exit 255 after ~42s,
# which is about this script's full runtime -- so the verdict was probably
# COMPUTED and then lost with the connection. stdout alone is therefore not a
# durable place to put it. Persist to the worker's /tmp and surface any prior
# run's verdict first, so a dropped SSH costs a round trip and not the result.
if [ -f /tmp/lk26c_verdict.txt ]; then
  echo "=== PRIOR RUN VERDICT RECOVERED (previous SSH dropped before returning it) ==="
  cat /tmp/lk26c_verdict.txt
  echo "=== END PRIOR RUN ==="
fi
# probe_out/ is repo-relative so it can be retrieved with `rch exec --job
# --sync-back probe_out`, which transfers EVEN ON NONZERO EXIT. That is the
# purpose-built answer to attempt 3, where the work finished and the SSH drop
# took the verdict with it. /tmp is kept as a second copy for the recovery
# branch above. The directory must exist or --sync-back fails with exit 102.
mkdir -p probe_out
exec > >(tee /tmp/lk26c_verdict.txt probe_out/lk26c_verdict.txt) 2>&1

echo "PROBE_HOST=$(hostname)"
echo "PROBE_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "PROBE_PWD=$PWD"

echo "=== BUILD (outside the sampling window on purpose) ==="
BUILD_LOG=/tmp/lk26c_build.$$
cargo test --locked -p fastmcp-server --lib --no-run >"$BUILD_LOG" 2>&1
BUILD_EXIT=$?
echo "BUILD_EXIT=$BUILD_EXIT"
tail -5 "$BUILD_LOG"
if [ "$BUILD_EXIT" -ne 0 ]; then
  echo "BUILD FAILED -- no verdict. Full log:"
  cat "$BUILD_LOG"
  exit 10
fi

# `--no-run` prints: Executable unittests src/lib.rs (<path>)
# Cargo colourises that line, so "Executable" and "unittests" are NOT adjacent
# in the raw bytes -- an ESC[0m reset sits between them. Strip ANSI first.
# The path is also NOT under target/debug/deps here: RCH builds into
# .rch-target with its own layout, so the fallback must search both roots.
sed 's/\x1b\[[0-9;]*m//g' "$BUILD_LOG" > "$BUILD_LOG.plain"
BIN=$(sed -n 's/.*Executable[[:space:]]*unittests src\/lib\.rs (\(.*\))[[:space:]]*$/\1/p' "$BUILD_LOG.plain" | tail -1)
echo "PARSED_BIN=${BIN:-<none>}"
if [ -z "${BIN:-}" ] || [ ! -x "$BIN" ]; then
  echo "path not parsed, falling back to newest fastmcp_server-* executable"
  BIN=$(find target .rch-target -type f -name 'fastmcp_server-*' -perm -u+x 2>/dev/null \
        | xargs -r ls -t 2>/dev/null | head -1)
  echo "FALLBACK_BIN=${BIN:-<none>}"
fi
echo "BIN=$BIN"
if [ -z "${BIN:-}" ] || [ ! -x "$BIN" ]; then
  echo "NO TEST BINARY -- no verdict."
  exit 11
fi

echo "=== CONTROL: resolve the FULL test path, because --exact needs it ==="
# Attempt 4 was VOID for this exact reason: the control grepped `--list` for a
# SUBSTRING and printed 1, while the run passed that same bare leaf name to
# `--exact`, which requires the complete `module::path::name`. All 2482 tests
# were filtered out, the binary exited 0 in 0.00s, and the script reported
# "NOT a hang" -- a false negative. A control must use the EXACT matcher the
# run will use, not an approximation of it.
FULL=$("$BIN" --list --format terse 2>/dev/null | sed 's/: test$//' | grep -E "(^|::)${TEST}$")
MATCHES=$(printf '%s\n' "$FULL" | grep -c . )
echo "FULL_NAME=${FULL:-<none>}"
echo "MATCHES=$MATCHES"
if [ "$MATCHES" != "1" ]; then
  echo "NO VERDICT: the filter resolves to $MATCHES tests, not exactly 1."
  exit 12
fi

echo "=== RUN, bounded, in background ==="
timeout --signal=KILL 40 "$BIN" "$FULL" --exact --test-threads=1 --nocapture \
  >/tmp/lk26c_run.$$ 2>&1 &
WRAPPER=$!

# `timeout` is the parent; the harness is its child. Sample the harness.
sleep 5
PID=$(pgrep -P "$WRAPPER" | head -1)
[ -z "${PID:-}" ] && PID=$WRAPPER
echo "WRAPPER=$WRAPPER HARNESS=$PID"

if [ ! -d "/proc/$PID" ]; then
  wait "$WRAPPER"; RC=$?
  echo "--- output ---"; cat /tmp/lk26c_run.$$
  # A run that executed ZERO tests exits 0 in 0.00s and is indistinguishable
  # from a pass unless this line is checked. Never read "finished fast" as a
  # verdict without it.
  if grep -q 'running 1 test' /tmp/lk26c_run.$$; then
    echo "VERDICT: the test RAN and COMPLETED (exit $RC) -- NO HANG at this revision."
    grep -E '^test |^test result:' /tmp/lk26c_run.$$
  else
    echo "NO VERDICT: zero tests executed (exit $RC). This is a VOID, not a pass."
    exit 13
  fi
  exit 0
fi

sample() {
  echo "--- sample $1 (t+$2 s) ---"
  # fields 14/15 of /proc/PID/stat are utime/stime in clock ticks
  awk '{print "utime="$14" stime="$15" state="$3" threads="$20}' "/proc/$PID/stat" 2>/dev/null
  ps -o pid,tid,pcpu,stat,wchan:24,comm -L -p "$PID" 2>/dev/null
  for t in /proc/$PID/task/*; do
    [ -r "$t/wchan" ] && echo "  tid=$(basename "$t") wchan=$(cat "$t/wchan" 2>/dev/null) comm=$(cat "$t/comm" 2>/dev/null)"
  done
}

sample A 5
sleep 8
sample B 13

echo "=== EXACT FRAME, best effort (absence here does not void the verdict) ==="
for dbg in gdb eu-stack lldb; do
  if command -v "$dbg" >/dev/null 2>&1; then
    echo "found: $dbg"
    case "$dbg" in
      gdb) timeout 60 gdb -batch -p "$PID" -ex "thread apply all bt 25" 2>&1 | head -120 ;;
      eu-stack) timeout 60 eu-stack -p "$PID" 2>&1 | head -80 ;;
      lldb) timeout 60 lldb -b -p "$PID" -o "thread backtrace all" 2>&1 | head -120 ;;
    esac
    break
  else
    echo "absent: $dbg"
  fi
done

echo "=== TEARDOWN ==="
wait "$WRAPPER"
echo "WRAPPER_EXIT=$?   (137 = KILLed by timeout, i.e. it hung for the full 40s)"
echo "--- harness output ---"
cat /tmp/lk26c_run.$$
