#!/usr/bin/env bash
# bd-tt7d8: FIRST EXECUTION of the two Tasks test targets it reports as
# "have never run and currently cannot".
#
#   crates/fastmcp-client/tests/task_01_b.rs          required-features ["tasks"]   2 tests
#   crates/fastmcp-client/tests/task_resume_store.rs  required-features ["tasks"]  12 tests
#
# I verified earlier today that the "currently cannot" half is retired: an
# --all-features clippy run compiled both with 0 errors. The "never run" half
# is an EXECUTION claim and a clippy run cannot speak to it, so this does.
#
# Both targets are also among bd-hy8mq's 37 required-features targets that
# `cargo check --workspace --all-targets` silently skips, so this is the first
# execution of two members of that dark set.
#
# Narrow on purpose: -p fastmcp-client --features tasks and exactly these two
# --test targets, not the workspace and not --all-features. A bounded
# named-target run, not a suite run.
set -u
cd /Users/jemanuel/projects/fastmcp_rust || exit 90

mkdir -p probe_out
exec > >(tee probe_out/tt7d8_tasks.txt) 2>&1

echo "HOST=$(hostname)"
echo "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# RCH workers carry no git repository, so the revision is bound by the
# locally captured HEAD plus these content hashes.
echo "BLOBS:"
for f in crates/fastmcp-client/tests/task_01_b.rs \
         crates/fastmcp-client/tests/task_resume_store.rs \
         crates/fastmcp-client/Cargo.toml; do
  echo "  $(git hash-object "$f" 2>/dev/null)  $f"
done

echo "=== BUILD (outside the run window) ==="
BL=/tmp/tt7d8_build.$$
cargo test --locked -p fastmcp-client --features tasks \
  --test task_01_b --test task_resume_store --no-run > "$BL" 2>&1
BUILD_EXIT=$?
echo "BUILD_EXIT=$BUILD_EXIT"
sed 's/\x1b\[[0-9;]*m//g' "$BL" > "$BL.plain"
tail -6 "$BL.plain"
if [ "$BUILD_EXIT" -ne 0 ]; then
  echo "BUILD FAILED -- that would REOPEN the compile half of this bead."
  grep -E "^error" "$BL.plain" | head -20
  exit 10
fi

# Collect both executables. Cargo colourises this line, so strip ANSI first.
mapfile -t BINS < <(sed -n 's/.*Executable[[:space:]]*tests\/\(task_01_b\|task_resume_store\)\.rs (\(.*\))[[:space:]]*$/\2/p' "$BL.plain")
echo "BINS=${#BINS[@]}"
printf '  %s\n' "${BINS[@]}"
if [ "${#BINS[@]}" -ne 2 ]; then
  echo "NO VERDICT: expected 2 test executables, parsed ${#BINS[@]}."
  exit 11
fi

PASS=0; FAIL=0; VOID=0; SUMMARY=""
for BIN in "${BINS[@]}"; do
  NAME=$(basename "$BIN" | sed 's/-[0-9a-f]*$//')
  echo ""
  echo "================ $NAME ================"
  if [ ! -x "$BIN" ]; then
    echo "VOID: not executable"; VOID=$((VOID+1)); continue
  fi
  LISTED=$("$BIN" --list --format terse 2>/dev/null | grep -c ': test$')
  echo "DISCOVERED=$LISTED"
  OUT=/tmp/tt7d8_${NAME}.$$
  timeout --signal=KILL 300 "$BIN" --test-threads=1 --nocapture > "$OUT" 2>&1
  RC=$?
  # Zero-run green is red (PL-1): a target that executes nothing exits 0 and
  # is indistinguishable from a pass unless this line is checked.
  if ! grep -qE '^running [1-9][0-9]* tests?$' "$OUT"; then
    echo "VOID: zero tests executed (exit $RC). Not a pass."
    tail -8 "$OUT"
    SUMMARY="${SUMMARY}\n  $NAME  VOID"
    VOID=$((VOID+1)); continue
  fi
  grep -E '^running |^test result:' "$OUT"
  grep -E '^test .* \.\.\. (ok|FAILED|ignored)$' "$OUT" | head -20
  if grep -q '^test result: ok\.' "$OUT"; then
    echo "-> $NAME PASS (exit $RC)"
    SUMMARY="${SUMMARY}\n  $NAME  PASS  ($LISTED discovered)"
    PASS=$((PASS+1))
  else
    echo "-> $NAME FAIL (exit $RC)"
    sed -n '1,80p' "$OUT"
    SUMMARY="${SUMMARY}\n  $NAME  FAIL  ($LISTED discovered)"
    FAIL=$((FAIL+1))
  fi
done

echo ""
echo "================ SUMMARY ================"
printf '%b\n' "$SUMMARY"
echo "targets: PASS=$PASS FAIL=$FAIL VOID=$VOID"
