#!/usr/bin/env bash
# bd-e3en4's PROJECTION, re-measured at HEAD, and the run that kills my one
# remaining confound.
#
# bd-e3en4 measured `cargo test --workspace --lib -- --test-threads 1` at HEAD
# 59788afa (2026-10-14): client 2205/4, transport 717/1, server 2727/0. I
# measured `-p <crate> --lib` at HEAD 6fa8cd6e: client 1836 discovered 17-18
# failing, transport 664/1, server 2482/6. Those are DIFFERENT PROJECTIONS, not
# a contradiction -- `--workspace` unifies each crate's features to the union
# the workspace requests, so its discovered sets are strictly larger (server
# 2727 vs 2482 = ~245 server tests invisible at the crate's own defaults;
# client 2209 vs 1836, including the whole `tasks` module, which the client's
# default features exclude).
#
# TWO THINGS THIS SETTLES.
#
# 1. THE REGRESSION CONFOUND. Two server tests were PRESENT at 59788afa and
#    green in bd-e3en4's run, their test text is unchanged since (`git log -S`
#    returns nothing), and they now fail 10/10 and 6/10:
#      live_http_subscription_acknowledgement_precedes_deferred_progress
#      live_http_shutdown_owns_registered_sse_body_before_flushing_terminal
#    Green-to-red with unchanged tests points at the product -- and 98e9f18e +
#    77f75357 added 1819 lines to the lib.rs path both exercise. BUT two
#    variables separate the readings: projection AND test-threads. If these two
#    ALSO fail under feature unification here, projection is eliminated and the
#    regression attribution stands on the 17 days. If they PASS here, the
#    projection was doing the work and this is a default-projection-only
#    defect -- still real, different class, different fix.
#
# 2. bd-e3en4's OWN NUMBERS, 17 days stale. Its five failures included four
#    client tests under `tasks::`, which my default-projection run cannot see
#    at all. This re-measures its exact projection so that bead has a current
#    subject.
#
# Also syncs back each crate's discovered-name list, which is what makes
# per-bead test verdicts free and auditable afterwards (the universe must be
# the binary's --list, never a `fn name(` grep over src/ -- that was 25%
# non-test functions).
#
# DEFAULT test-threads, deliberately: bd-e3en4 used --test-threads 1, but the
# intermittent rates (8/10, 6/10) only exist under contention, and a serial run
# would reintroduce a second difference. One variable at a time: this run
# changes the PROJECTION versus mine and holds parallelism fixed.
set -u
cd /Users/jemanuel/projects/fastmcp_rust || exit 90

mkdir -p probe_out
exec > >(tee probe_out/workspace_unified.txt) 2>&1

echo "HOST=$(hostname)"
echo "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "NPROC=$(nproc 2>/dev/null)"
echo "PROJECTION=--workspace --lib (feature-unified), DEFAULT test-threads"

echo ""
echo "=== BUILD: cargo test --workspace --lib --no-run ==="
BL=/tmp/wsu_build.$$
cargo test --locked --workspace --lib --no-run > "$BL" 2>&1
echo "BUILD_EXIT=$?"
sed 's/\x1b\[[0-9;]*m//g' "$BL" > "$BL.plain"
tail -4 "$BL.plain"
grep -cE '^error' "$BL.plain" | sed 's/^/compile error lines: /'
grep -E '^error' "$BL.plain" | head -8

# One lib unittest binary per crate; the path encodes the crate name.
sed -n 's/.*Executable[[:space:]]*unittests src\/lib\.rs (\(.*\))[[:space:]]*$/\1/p' "$BL.plain" \
  | sort -u > /tmp/wsu_bins.$$
echo ""
echo "lib test binaries found: $(grep -c . /tmp/wsu_bins.$$)"
cat /tmp/wsu_bins.$$

WATCH1=live_http_subscription_acknowledgement_precedes_deferred_progress
WATCH2=live_http_shutdown_owns_registered_sse_body_before_flushing_terminal

echo ""
echo "############################################################"
echo "### ONE FULL RUN PER CRATE, default test-threads"
echo "############################################################"
TOTD=0; TOTP=0; TOTF=0
while IFS= read -r BIN; do
  [ -x "$BIN" ] || { echo "SKIP (not executable): $BIN"; continue; }
  CR=$(printf '%s' "$BIN" | sed -n 's#.*/build/\([a-z0-9_-]*\)/[^/]*/out/.*#\1#p')
  [ -n "$CR" ] || CR=$(basename "$BIN" | sed 's/-[0-9a-f]*$//')
  echo ""
  echo "======== $CR ========"
  "$BIN" --list --format terse 2>/dev/null | sed 's/: test$//' > "probe_out/unified_discovered_${CR}.txt"
  D=$(grep -c . "probe_out/unified_discovered_${CR}.txt")
  O=/tmp/wsu_run_${CR}.$$
  timeout --signal=KILL 1200 "$BIN" > "$O" 2>&1
  rc=$?
  RAN=$(grep -oE '^running [0-9]+ tests?$' "$O" | grep -oE '[0-9]+' | head -1)
  echo "DISCOVERED=$D  ran=${RAN:-0}  exit=$rc"
  if [ "${RAN:-0}" != "$D" ]; then
    echo "VOID: ran ${RAN:-0} of $D -- not a full-target run."
    tail -6 "$O"; continue
  fi
  grep -E '^test result:' "$O"
  P=$(grep -oE '^test result: [a-zA-Z]+\. [0-9]+ passed' "$O" | grep -oE '[0-9]+' | head -1)
  F=$(grep -cE '^test .* \.\.\. FAILED$' "$O")
  TOTD=$((TOTD+D)); TOTP=$((TOTP+${P:-0})); TOTF=$((TOTF+F))
  if [ "$F" -gt 0 ]; then
    echo "  failing names:"
    grep -E '^test .* \.\.\. FAILED$' "$O" | sed 's/^test //; s/ \.\.\. FAILED$//' | sed 's/^/     /'
  fi
done < /tmp/wsu_bins.$$

echo ""
echo "================ TOTALS (feature-unified, default threads) ================"
echo "DISCOVERED=$TOTD  PASSED=$TOTP  FAILED=$TOTF"

echo ""
echo "================ THE CONFOUND KILLER ================"
for t in "$WATCH1" "$WATCH2"; do
  c=$(cat /tmp/wsu_run_*.$$ 2>/dev/null | grep -cE "^test .*${t} \.\.\. FAILED$")
  d=$(cat probe_out/unified_discovered_*.txt 2>/dev/null | grep -cxF "lib_unit_tests::${t}")
  echo "  discovered=${d}  failed_here=${c}   $t"
done
echo ""
echo "READING: failed_here=1 for BOTH -> projection eliminated; green-to-red since"
echo "         59788afa stands, and 98e9f18e / 77f75357 are the 2-commit window."
echo "         failed_here=0 -> they pass under feature unification, so the failure"
echo "         is specific to the crate's own default projection, not a regression."
echo "         discovered=0 -> VOID for that name; it was not in this projection."
