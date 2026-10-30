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
exec > >(tee /tmp/lk26c_verdict.txt) 2>&1

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

echo "=== CONTROL: the binary runs and this test is DISCOVERED exactly once ==="
# A zero-match filter would hang on nothing and look identical to a hang.
# Validate the instrument against its own positive before trusting a timeout.
"$BIN" --list 2>/dev/null | grep -c "$TEST"

echo "=== RUN, bounded, in background ==="
timeout --signal=KILL 40 "$BIN" "$TEST" --exact --test-threads=1 --nocapture \
  >/tmp/lk26c_run.$$ 2>&1 &
WRAPPER=$!

# `timeout` is the parent; the harness is its child. Sample the harness.
sleep 5
PID=$(pgrep -P "$WRAPPER" | head -1)
[ -z "${PID:-}" ] && PID=$WRAPPER
echo "WRAPPER=$WRAPPER HARNESS=$PID"

if [ ! -d "/proc/$PID" ]; then
  echo "PROCESS ALREADY GONE AT 5s -- this is NOT a hang on this host."
  wait "$WRAPPER"; echo "EXIT=$?"
  echo "--- output ---"; cat /tmp/lk26c_run.$$
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
