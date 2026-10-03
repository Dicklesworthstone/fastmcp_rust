#!/usr/bin/env bash
#
# Run the official MCP conformance suite against this workspace's adapter.
#
# WHY THIS EXISTS
#
# Plan section 2.6 admits an MCP 2026-07-28 support claim only once the
# official harness passes in server and client modes. That harness is
# `@modelcontextprotocol/conformance`; it owns no server lifecycle and simply
# connects to a URL as an MCP client. `conformance_server` is the server it
# connects to, and this script is the repeatable way to point one at the other.
# Before it existed the measurement was a hand-assembled one-off, so the
# project's only end-to-end measure of its headline claim was run once.
#
# A pass count from this script is NOT an aggregate conformance claim. It is a
# count of named checks at one revision, under one adapter, on one transport.
#
# THE PIN IS LOAD-BEARING
#
# npm's `latest` tag excludes prereleases, so `@latest` resolves to 0.1.16,
# which rejects `--spec-version 2026-07-28` outright. 0.2.0-alpha.10 is also
# the anchor named by upstream `requirements/2026-07-28.yaml`. Do not float it.
#
# THE SUITE DEFAULT HIDES MOST OF THE WORK
#
# `--suite active` runs ~20 scenarios and omits server-stateless, caching,
# header validation and every input-required scenario. This script passes
# `--suite all` deliberately. Narrow it only with intent.
#
# USAGE
#
#   scripts/run_official_conformance.sh [--bin PATH] [--port N]
#                                       [--suite all|active|core|draft|pending]
#                                       [--baseline PATH] [--scenario NAME]
#                                       [--out DIR]
#
# With no --bin it builds the adapter through cargo (which this repo routes to
# RCH). On a machine whose architecture differs from the build worker's, build
# and run on the worker instead: RCH returns the worker's binary, and running a
# foreign ELF fails with RCH-E327 even though the compile succeeded.
#
# BASELINE GATING
#
# --baseline takes the suite's own `--expected-failures` YAML:
#
#   server:
#     - some-scenario-id
#     - other-scenario:specific-check-id
#
# That gates on the SET of failures rather than a count, so a fixed check and a
# newly broken one cannot cancel out into an unchanged number.

set -u -o pipefail

SUITE_PIN='@modelcontextprotocol/conformance@0.2.0-alpha.10'
SPEC_VERSION='2026-07-28'

BIN=''
PORT=0
SUITE='all'
BASELINE=''
SCENARIO=''
OUT=''

die() { printf '%s\n' "$*" >&2; exit 2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --bin)      BIN="${2:?--bin needs a path}"; shift 2 ;;
        --port)     PORT="${2:?--port needs a number}"; shift 2 ;;
        --suite)    SUITE="${2:?--suite needs a name}"; shift 2 ;;
        --baseline) BASELINE="${2:?--baseline needs a path}"; shift 2 ;;
        --scenario) SCENARIO="${2:?--scenario needs a name}"; shift 2 ;;
        --out)      OUT="${2:?--out needs a directory}"; shift 2 ;;
        -h|--help)  sed -n '2,50p' "$0"; exit 0 ;;
        *)          die "unknown argument: $1" ;;
    esac
done

command -v npx >/dev/null 2>&1 || die 'npx is required to run the official suite'

if [ -z "$OUT" ]; then
    OUT="$(mktemp -d "${TMPDIR:-/tmp}/fastmcp-conformance.XXXXXX")" || die 'cannot create output dir'
fi
mkdir -p "$OUT" || die "cannot create $OUT"

# A port of 0 means "pick one that is free right now". The adapter takes an
# explicit host:port, so resolve it here rather than asking the kernel twice.
if [ "$PORT" = 0 ]; then
    PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')" \
        || die 'cannot pick a free port'
fi

if [ -z "$BIN" ]; then
    printf '== building conformance_server ==\n'
    cargo build --locked -p fastmcp-rust --features tasks --bin conformance_server \
        || die 'adapter build failed'
    BIN="$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
        | python3 -c 'import json,sys;print(json.load(sys.stdin)["target_directory"])')/debug/conformance_server"
fi

[ -x "$BIN" ] || die "adapter binary is not executable: $BIN"

printf '== adapter: %s\n== endpoint: http://127.0.0.1:%s/mcp\n== suite: %s @ %s\n' \
    "$BIN" "$PORT" "$SUITE" "$SPEC_VERSION"

"$BIN" "127.0.0.1:$PORT" > "$OUT/adapter.log" 2>&1 &
ADAPTER=$!
cleanup() {
    if kill -0 "$ADAPTER" 2>/dev/null; then
        kill -TERM "$ADAPTER" 2>/dev/null
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$ADAPTER" 2>/dev/null || break
            sleep 0.2
        done
        kill -KILL "$ADAPTER" 2>/dev/null
    fi
}
trap cleanup EXIT INT TERM

# Wait for the listener, bounded, and treat an early exit as fatal rather than
# letting the suite report every scenario as a connection failure.
bound=0
for _ in $(seq 1 120); do
    if python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(0.4)
sys.exit(0 if s.connect_ex(('127.0.0.1',$PORT))==0 else 1)
" 2>/dev/null; then bound=1; break; fi
    if ! kill -0 "$ADAPTER" 2>/dev/null; then
        printf '!! adapter exited before binding (status %s). Last log lines:\n' "$(wait "$ADAPTER" 2>/dev/null; echo $?)" >&2
        tail -40 "$OUT/adapter.log" >&2
        exit 2
    fi
    sleep 0.25
done
[ "$bound" = 1 ] || { printf '!! adapter never bound port %s\n' "$PORT" >&2; tail -40 "$OUT/adapter.log" >&2; exit 2; }

printf '== adapter listening (pid %s) ==\n' "$ADAPTER"

set -- server --url "http://127.0.0.1:$PORT/mcp" --spec-version "$SPEC_VERSION" --output-dir "$OUT"
if [ -n "$SCENARIO" ]; then
    set -- "$@" --scenario "$SCENARIO"
else
    set -- "$@" --suite "$SUITE"
fi
[ -n "$BASELINE" ] && set -- "$@" --expected-failures "$BASELINE"

npx -y "$SUITE_PIN" "$@" 2>&1 | tee "$OUT/suite.log"
STATUS=${PIPESTATUS[0]}

printf '\n== tally ==\n'
# The suite writes machine-readable results into --output-dir. Prefer those over
# scraping the pretty printer, whose wording is not a contract.
python3 - "$OUT" <<'PY'
import json, pathlib, sys

# The suite writes one `<output-dir>/<scenario>/checks.json` per scenario, each
# a FLAT array of check objects carrying id/name/status/errorMessage. Statuses
# seen in 0.2.0-alpha.10: SUCCESS, FAILURE, WARNING, INFO. WARNING is a SHOULD
# miss and is deliberately counted separately from FAILURE, because a SHOULD
# does not move the pass/fail tally the suite reports.
root = pathlib.Path(sys.argv[1])
tally, scenarios, failures, warnings = {}, 0, [], []
for path in sorted(root.rglob('checks.json')):
    try:
        checks = json.loads(path.read_text())
    except (ValueError, OSError):
        continue
    if not isinstance(checks, list):
        continue
    scenario = path.parent.name
    scenarios += 1
    for check in checks:
        if not isinstance(check, dict):
            continue
        status = str(check.get('status', 'UNKNOWN')).upper()
        tally[status] = tally.get(status, 0) + 1
        label = f"{scenario}:{check.get('id') or check.get('name')}"
        if status == 'FAILURE':
            failures.append((label, check.get('errorMessage') or ''))
        elif status == 'WARNING':
            warnings.append(label)

if not tally:
    print('no checks.json found under the output dir; read suite.log above')
else:
    total = sum(tally.values())
    print(f'scenarios={scenarios} checks={total} '
          + ', '.join(f'{k}={v}' for k, v in sorted(tally.items())))
    if warnings:
        print(f'\nSHOULD misses reported as WARNING ({len(warnings)}):')
        for label in warnings:
            print(f'  {label}')
    if failures:
        print(f'\nfailing checks ({len(failures)}):')
        for label, why in failures:
            first = why.splitlines()[0] if why else ''
            print(f'  {label}' + (f' -- {first[:140]}' if first else ''))
        print('\nTo adopt these as a baseline, put the labels under a `server:` key')
        print('in a YAML file and pass it as --baseline:')
        print('\nserver:')
        for label, _ in failures:
            print(f'  - {label}')
PY

printf '\n== adapter stderr (tail) ==\n'
tail -15 "$OUT/adapter.log"
printf '\n== artifacts: %s ==\n' "$OUT"
printf 'suite exit status: %s\n' "$STATUS"
printf '\nA pass count here is not an aggregate MCP %s conformance claim.\n' "$SPEC_VERSION"
exit "$STATUS"
