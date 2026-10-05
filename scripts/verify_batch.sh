#!/usr/bin/env bash
#
# Batch-verification runner that emits the receipt AGENTS.md requires.
#
# WHY THIS EXISTS (the hard-gate justification AGENTS.md demands of a process
# artifact, since otherwise this would be ceremony):
#
#   concrete consumer     the batch-verification orchestrator, the only role
#                         permitted to close an implementation Bead, which needs
#                         evidence bound to an exact revision in order to do it.
#   enforced gate         batch_verify. This script produces that gate's inputs
#                         and fails closed. It does not record a verdict and has
#                         no authority to.
#   observed defect class three, all observed in this repository.
#                         (1) The RCH lane returning "completion unconfirmed"
#                             while retaining project ownership, which left a P1
#                             measurement ungettable across seven attempts on
#                             three workers, so NO batch verification happened.
#                         (2) Green output accepted as proof when nothing ran:
#                             23 test targets print "ok. 0 passed" when their
#                             cfg is absent.
#                         (3) A stale subject measured as if current: a worker
#                             serving an out-of-date mirror, and a
#                             `cargo ... | tail -N` pipeline whose follow-up
#                             `echo "EXIT=${PIPESTATUS[0]}"` reports the echo's
#                             own status, hiding a failed build.
#   retirement condition  when the RCH lane completes reliably AND emits a
#                         receipt carrying these same fields. Delete this then.
#
# It deliberately does NOT record a gate verdict, close a Bead, or decide
# capability credit. Those are separate revision-bound decisions (RH-7, PL-4).
#
# HOW IT AVOIDS THE THREE DEFECTS ABOVE
#
#   * Bypasses the RCH scheduler entirely: plain ssh to one named worker, so a
#     wedged queue cannot swallow the run.
#   * Enforces PL-1. passed==0 is RED. The discovered set and the executed set
#     are captured separately and compared, never assumed equal. Ignored and
#     filtered-out counts are reported, never silently tolerated.
#   * Binds the subject by BLOB IDENTITY. A manifest digest over the
#     compilation-relevant paths is computed locally and independently
#     recomputed on the worker; a mismatch invalidates the receipt. Each run
#     syncs into a FRESH directory, so stale files from an earlier sync cannot
#     participate and no deletion is ever required.
#   * Captures every exit status with `rc=$?` on its own line.
#
# USAGE
#
#   scripts/verify_batch.sh --scope "-p fastmcp-client --lib" \
#       [--worker ubuntu@HOST] [--features tasks] [--filter NAME ...] \
#       [--test-threads 1] [--beads bd-aaa,bd-bbb] [--out DIR] [--key PATH]
#
# --scope is passed to cargo verbatim so the receipt records exactly what ran.
# Omitting --filter runs the whole target, which is what a real batch wants.
# --test-threads 1 matters: 38 client --lib tests fail at default parallelism
# and 1 fails serialized, on the same worker and revision. Serialize before
# attributing a red to a commit.

set -u -o pipefail

# Byte-deterministic collation: see the manifest note below.
export LC_ALL=C

WORKER='ubuntu@194.140.197.98'            # hz3
REMOTE_BASE='/data/projects/fastmcp_rust_batchverify'
KEY="$HOME/.ssh/contabo_vps_ed25519"
TOOLCHAIN='nightly-2026-08-25'
PROFILE='test'
SCOPE=''
FEATURES=''
BEADS=''
OUT=''
THREADS=''
CHECK_ONLY=0
FILTERS=()

die() { printf 'verify_batch: %s\n' "$*" >&2; exit 2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --worker)       WORKER="${2:?}"; shift 2 ;;
        --remote-base)  REMOTE_BASE="${2:?}"; shift 2 ;;
        --scope)        SCOPE="${2:?}"; shift 2 ;;
        --features)     FEATURES="${2:?}"; shift 2 ;;
        --beads)        BEADS="${2:?}"; shift 2 ;;
        --out)          OUT="${2:?}"; shift 2 ;;
        --key)          KEY="${2:?}"; shift 2 ;;
        --toolchain)    TOOLCHAIN="${2:?}"; shift 2 ;;
        --test-threads) THREADS="${2:?}"; shift 2 ;;
        --check-only)   CHECK_ONLY=1; shift ;;
        --filter)       FILTERS+=("${2:?}"); shift 2 ;;
        -h|--help)      sed -n '2,70p' "$0"; exit 0 ;;
        *)              die "unknown argument: $1" ;;
    esac
done

[ -n "$SCOPE" ] || die 'need --scope (passed to cargo verbatim)'
[ -f "$KEY" ]   || die "ssh key not found: $KEY"
command -v rsync >/dev/null || die 'rsync not found locally'

OUT="${OUT:-$(mktemp -d "${TMPDIR:-/tmp}/fastmcp-verify.XXXXXX")}" || die 'cannot create output dir'
mkdir -p "$OUT" || die "cannot create $OUT"

SSH=(ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=25 "$WORKER")

# ---------------------------------------------------------------------------
# Subject identity, captured BEFORE the run.
#
# The manifest covers the paths that can change what gets COMPILED. Binding
# over the whole repo would make every unrelated edit by a parallel lane
# invalidate the receipt; binding over nothing would let a stale mirror pass.
# The path set is recorded in the receipt so the scope of the claim is explicit.
# ---------------------------------------------------------------------------
MANIFEST_PATHS='Cargo.toml Cargo.lock rust-toolchain.toml crates'

# `.github` and `evidence` are here because test targets read them at COMPILE
# time via include_str!/include_bytes! (fnd_01_dependency_evidence.rs :19048,
# :51973, :51987). Omitting them made cargo report 5 "couldn't read ... No such
# file or directory" errors that looked exactly like project defects and were
# purely this script's doing. Syncing them is READ-ONLY; RULE 0.5 forbids
# modifying anything under .github/workflows, not compiling against it.
SYNC_PATHS=(Cargo.toml Cargo.lock rust-toolchain.toml crates spec scripts tools
            .github evidence README.md)
[ -d .cargo ] && SYNC_PATHS+=(.cargo)

head_sha="$(git rev-parse HEAD)" || die 'not a git repository'
tree_sha="$(git rev-parse 'HEAD^{tree}')"
git status --porcelain --untracked-files=no > "$OUT/dirty-before.txt"
dirty_before="$(shasum -a 256 < "$OUT/dirty-before.txt" | cut -d' ' -f1)"
dirty_count="$(wc -l < "$OUT/dirty-before.txt" | tr -d ' ')"

# Per-file content hashes of the WORKING TREE (what actually gets built), not
# of git objects. Sorted by path so the digest is order-independent.
# shellcheck disable=SC2086
find $MANIFEST_PATHS -type f \
    \( -name '*.rs' -o -name '*.toml' -o -name '*.lock' -o -name '*.json' \
       -o -name '*.yaml' -o -name '*.txt' \) -print0 2>/dev/null \
    | sort -z | xargs -0 shasum -a 256 \
    | awk '{ print $1 " " $2 }' > "$OUT/manifest-local.txt"
if awk 'NF != 2 { exit 1 }' "$OUT/manifest-local.txt"; then :; else
    die 'a manifest path contains whitespace; the two-field digest cannot bind it'
fi
manifest_files="$(wc -l < "$OUT/manifest-local.txt" | tr -d ' ')"
manifest_local="$(shasum -a 256 < "$OUT/manifest-local.txt" | cut -d' ' -f1)"

printf '== subject ==\nHEAD      %s\ntree      %s\ndirty     %s tracked file(s) modified\nmanifest  %s  (%s files over: %s)\n\n' \
    "$head_sha" "$tree_sha" "$dirty_count" "${manifest_local:0:16}" \
    "$manifest_files" "$MANIFEST_PATHS"

[ "$manifest_files" -gt 100 ] || die "manifest only matched $manifest_files files; refusing to bind a subject that thin"

# ---------------------------------------------------------------------------
# Sync into a FRESH remote directory. No --delete, so nothing is ever removed;
# a fresh path means no file from an earlier sync can participate. The cargo
# target dir is a shared pool OUTSIDE the fresh tree so caching still works.
# ---------------------------------------------------------------------------
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
remote_dir="$REMOTE_BASE/run-${head_sha:0:8}-$stamp"
target_dir="$REMOTE_BASE/.target-pool"

# Any include_str!/include_bytes! target that is NOT under a synced path makes
# cargo emit "couldn't read ... No such file or directory", which reads as a
# repository defect and is purely this script's doing. Refuse to run instead.
missing_includes="$(python3 - "${SYNC_PATHS[@]}" <<'SCAN'
import os, re, sys, pathlib
synced = set(sys.argv[1:])
pat = re.compile(r'include_(?:str|bytes)!\s*\(\s*"([^"]+)"')
cwd = pathlib.Path.cwd()
missing = set()
for p in pathlib.Path('crates').rglob('*.rs'):
    try: txt = p.read_text(errors='replace')
    except OSError: continue
    for m in pat.finditer(txt):
        target = (p.parent / m.group(1)).resolve()
        try: rel = target.relative_to(cwd)
        except ValueError: continue
        root = str(rel).split(os.sep)[0]
        if root not in synced:
            missing.add(root)
print(' '.join(sorted(missing)))
SCAN
)"
if [ -n "$missing_includes" ]; then
    die "compile-time include roots are not in SYNC_PATHS: $missing_includes"
fi

printf '== sync ==\nworker    %s\nremote    %s\n' "$WORKER" "$remote_dir"
"${SSH[@]}" "mkdir -p '$remote_dir' '$target_dir'" || die 'cannot create the remote directories'

# Everything a build or a test fixture can read, and nothing else. Anything
# added here must also be considered for MANIFEST_PATHS above.
rsync -az --no-perms --omit-dir-times \
    --exclude 'target/' --exclude '.rch-target-*' --exclude '*.log' \
    -e "ssh -i $KEY -o BatchMode=yes -o ConnectTimeout=25" \
    "${SYNC_PATHS[@]}" "$WORKER:$remote_dir/" > "$OUT/rsync.log" 2>&1
rsync_rc=$?
printf 'rsync     rc=%s\n\n' "$rsync_rc"

feature_args=''
[ -n "$FEATURES" ] && feature_args="--features $FEATURES"
thread_args=''
[ -n "$THREADS" ] && thread_args="--test-threads $THREADS"

# ---------------------------------------------------------------------------
# Remote script. Written locally and copied, never inlined into an ssh
# argument: a single quote inside a single-quoted ssh payload silently
# truncates the script, which is how an earlier run in this repository
# "succeeded" while measuring nothing.
# ---------------------------------------------------------------------------
cat > "$OUT/remote.sh" <<REMOTE
#!/usr/bin/env bash
set -u
cd '$remote_dir' || { echo "RECEIPT_VERDICT=NO_REMOTE_DIR"; exit 9; }
# Per-run scratch. Concurrent runs previously shared /tmp/vb_* and one
# reported the other's diagnostics as its own.
RUNTMP='$remote_dir/.vb-run'
mkdir -p "\$RUNTMP"
export CARGO_TARGET_DIR='$target_dir'
export RCH_CARGO_WRAPPER_BYPASS=1
export CARGO_TERM_COLOR=never
# Must match the local side exactly or the manifest ordering diverges.
export LC_ALL=C

# Independent recomputation of the manifest. Same file set, same algorithm,
# computed from the worker's own filesystem. This is what clears a stale
# mirror: blob identity, not sync byte counts and not an rsync exit status.
find $MANIFEST_PATHS -type f \\
    \\( -name '*.rs' -o -name '*.toml' -o -name '*.lock' -o -name '*.json' \\
       -o -name '*.yaml' -o -name '*.txt' \\) -print0 2>/dev/null \\
    | sort -z | xargs -0 sha256sum \
    | awk '{ print \$1 " " \$2 }' > \$RUNTMP/vb_manifest.txt
echo "RECEIPT_MANIFEST_FILES=\$(wc -l < \$RUNTMP/vb_manifest.txt | tr -d ' ')"
echo "RECEIPT_MANIFEST_DIGEST=\$(sha256sum < \$RUNTMP/vb_manifest.txt | cut -d' ' -f1)"

echo "RECEIPT_HOST=\$(hostname -s)"
echo "RECEIPT_RUSTC=\$(rustc +$TOOLCHAIN -vV 2>/dev/null | sed -n 's/^release: //p')"
echo "RECEIPT_COMMIT_HASH=\$(rustc +$TOOLCHAIN -vV 2>/dev/null | sed -n 's/^commit-hash: //p')"
echo "RECEIPT_TARGET=\$(rustc +$TOOLCHAIN -vV 2>/dev/null | sed -n 's/^host: //p')"

if [ '$CHECK_ONLY' = 1 ]; then
    cargo +$TOOLCHAIN check --locked $SCOPE $feature_args > \$RUNTMP/vb_build.log 2>&1
    check_rc=\$?
    echo "RECEIPT_CHECK_RC=\$check_rc"
    echo "RECEIPT_BUILD_RC=\$check_rc"
    echo "RECEIPT_ERRORS=\$(grep -cE '^error(\[|:)' \$RUNTMP/vb_build.log)"
    echo "RECEIPT_WARNINGS=\$(grep -cE '^warning(\[|:)' \$RUNTMP/vb_build.log)"
    grep -E '^error' -A6 \$RUNTMP/vb_build.log | head -150
    echo "RECEIPT_END"
    exit \$check_rc
fi

# COMPILE IS A HARD GATE WITH ITS OWN CAPTURED STATUS. The assignment is on its
# own line because \${PIPESTATUS[0]} read after an intervening command reports
# that command's status, not the build's.
cargo +$TOOLCHAIN test --locked $SCOPE $feature_args --no-run > \$RUNTMP/vb_build.log 2>&1
build_rc=\$?
echo "RECEIPT_BUILD_RC=\$build_rc"
if [ "\$build_rc" != 0 ]; then
    echo "RECEIPT_VERDICT=BUILD_FAILED"
    grep -E '^error(\[|:)' \$RUNTMP/vb_build.log | head -25
    exit 1
fi

# DISCOVERED set, independent of the run. PL-1 compares this against EXECUTED.
cargo +$TOOLCHAIN test --locked $SCOPE $feature_args -- --list > \$RUNTMP/vb_list.log 2>&1
grep -E ': test\$' \$RUNTMP/vb_list.log | sed 's/: test\$//' | sort -u > \$RUNTMP/vb_discovered.txt
echo "RECEIPT_DISCOVERED=\$(wc -l < \$RUNTMP/vb_discovered.txt | tr -d ' ')"

# Text parsing of libtest progress lines is NOT reliable here: product code
# writes straight to stderr, bypassing libtest's capture, and lands ON the
# progress line --
#   test tests::panicked_progress_callback_... ... fastmcp client callback panicked
# so the `ok` never appears where a line anchor can see it, and four outcomes
# went unmatched that way. libtest's JSON events are one object per line and
# are immune to interleaved output.
cargo +$TOOLCHAIN test --locked $SCOPE $feature_args \
    -- -Z unstable-options --format json $thread_args "\$@" > \$RUNTMP/vb_run.log 2>&1
run_rc=\$?
echo "RECEIPT_RUN_RC=\$run_rc"
echo "RECEIPT_JSON_EVENTS=\$(grep -c '^{"type":"test"' \$RUNTMP/vb_run.log)"
# The whole log is returned and parsed locally, so there is ONE parser and the
# worker needs no python.
echo "RECEIPT_END"
REMOTE

scp -i "$KEY" -o BatchMode=yes -q "$OUT/remote.sh" "$WORKER:$remote_dir/vb_remote.sh" \
    || die 'cannot stage the remote script'

printf '== run ==\ncargo test --locked %s %s -- %s %s\n\n' \
    "$SCOPE" "$feature_args" "$thread_args" "${FILTERS[*]-}"

"${SSH[@]}" "chmod +x '$remote_dir/vb_remote.sh' && '$remote_dir/vb_remote.sh' ${FILTERS[*]-}" \
    > "$OUT/remote.out" 2>&1
remote_rc=$?
"${SSH[@]}" "cat '$remote_dir/.vb-run/vb_discovered.txt'" > "$OUT/discovered.txt" 2>/dev/null || :
"${SSH[@]}" "cat '$remote_dir/.vb-run/vb_run.log'"        > "$OUT/run.log"       2>/dev/null || :

# Subject identity AFTER the run. Movement invalidates the receipt.
git status --porcelain --untracked-files=no > "$OUT/dirty-after.txt"
dirty_after="$(shasum -a 256 < "$OUT/dirty-after.txt" | cut -d' ' -f1)"
head_after="$(git rev-parse HEAD)"

python3 - "$OUT" "$head_sha" "$head_after" "$tree_sha" "$dirty_before" \
    "$dirty_after" "$manifest_local" "$manifest_files" "$MANIFEST_PATHS" \
    "$TOOLCHAIN" "$PROFILE" "$SCOPE" "$FEATURES" "$BEADS" "$remote_rc" \
    "$rsync_rc" "$WORKER" "$remote_dir" "$THREADS" "${FILTERS[*]-}" <<'PY'
import json, re, sys, pathlib

(out, head_before, head_after, tree, dirty_before, dirty_after, manifest_local,
 manifest_files, manifest_paths, toolchain, profile, scope, features, beads,
 remote_rc, rsync_rc, worker, remote_dir, threads, filters) = sys.argv[1:21]
root = pathlib.Path(out)
raw = (root / 'remote.out').read_text(errors='replace')

def field(name):
    m = re.search(rf'^RECEIPT_{name}=(.*)$', raw, re.M)
    return m.group(1).strip() if m else None

# libtest JSON events: one object per line, so interleaved product stderr
# cannot corrupt an outcome the way it corrupted the text progress lines.
# Non-JSON lines are skipped rather than guessed at.
events, suites = [], []
run_log = root / 'run.log'
if run_log.exists():
    for line in run_log.read_text(errors='replace').splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get('type') == 'test' and event.get('event') in ('ok', 'failed', 'ignored'):
            events.append(event)
        elif event.get('type') == 'suite' and event.get('event') in ('ok', 'failed'):
            suites.append(event)

results  = suites
passed   = sum(s.get('passed', 0) for s in suites)
failed   = sum(s.get('failed', 0) for s in suites)
ignored  = sum(s.get('ignored', 0) for s in suites)
filtered = sum(s.get('filtered_out', 0) for s in suites)
executed_ids = sorted({e['name'] for e in events if e['event'] in ('ok', 'failed')})
ignored_ids  = sorted({e['name'] for e in events if e['event'] == 'ignored'})
failed_ids   = sorted({e['name'] for e in events if e['event'] == 'failed'})

def ids(name):
    p = root / name
    return sorted(set(p.read_text(errors='replace').split())) if p.exists() else []

discovered, executed = ids('discovered.txt'), executed_ids
manifest_remote = field('MANIFEST_DIGEST')

# Every condition below has turned a green-looking run into a false claim here
# at least once. They are checked, not assumed.
reasons, warnings = [], []
if rsync_rc != '0':
    reasons.append(f'rsync exited {rsync_rc}: the worker may not hold the subject')
if manifest_remote != manifest_local:
    reasons.append(f'manifest mismatch: local {manifest_local[:16]} vs worker '
                   f'{(manifest_remote or "<none>")[:16]} - a stale or partial mirror was measured')
if field('MANIFEST_FILES') != manifest_files:
    reasons.append(f'manifest file count differs: local {manifest_files} vs worker {field("MANIFEST_FILES")}')
if field('BUILD_RC') is None:
    reasons.append('no build status reported: the remote script did not reach the compile step')
elif field('BUILD_RC') != '0':
    reasons.append('compile FAILED: a test count taken after a failed build measures a stale binary')
if 'RECEIPT_END' not in raw:
    reasons.append('remote script did not reach its end marker: early abort')
# In check-only mode there is no test count to judge, so PL-1's zero-run rule
# does not apply and the compile status is the whole verdict.
check_only = field('CHECK_RC') is not None
if check_only:
    if field('CHECK_RC') != '0':
        reasons.append(f'cargo check FAILED with {field("ERRORS")} error(s)')
    if field('WARNINGS') not in (None, '0'):
        warnings.append(f'{field("WARNINGS")} warning(s); this workspace lints at -D warnings')
else:
    if not suites:
        reasons.append('no libtest suite event: nothing reported a count')
    if events and passed + failed + ignored != len(events):
        reasons.append(f'suite totals ({passed + failed + ignored}) disagree with '
                       f'{len(events)} per-test events: the parse is incomplete')
    if passed == 0:
        reasons.append('passed==0: a zero-run green is RED (PL-1)')
    if failed:
        reasons.append(f'{failed} test(s) FAILED')
# NOT invalidating. The receipt is anchored to the manifest DIGEST, which pins
# the blobs the worker actually compiled; a later local edit cannot retroactively
# change what was measured. In this repository parallel lanes commit several
# times a minute, so treating any local movement as invalidation would make
# every receipt INVALID and the instrument useless. What movement does mean is
# that the receipt no longer describes the CURRENT tree, which is recorded as a
# warning and as subject_still_current so a reader cannot miss it.
still_current = head_before == head_after and dirty_before == dirty_after
if not still_current:
    warnings.append('local source moved after the sync: this receipt describes the '
                    'manifest digest above, NOT the current working tree')
if not check_only and field('RUN_RC') not in (None, '0') and not failed:
    reasons.append(f'runner exited {field("RUN_RC")} without reporting any failure: early abort')
if ignored:
    warnings.append(f'{ignored} test(s) ignored and therefore NOT executed: '
                    f'an #[ignore] body is not evidence. {ignored_ids[:5]}')
if filtered and not filters.strip():
    warnings.append(f'{filtered} test(s) filtered out with no --filter requested')
elif filtered:
    warnings.append(f'{filtered} test(s) filtered out by the requested --filter; '
                    f'this receipt covers the selected subset only, not a full batch')
# PL-1 exact test-set equality, scoped to what was actually REQUESTED. An
# unfiltered run must execute everything it discovered. A --filter run must
# execute every discovered test the filter selects -- comparing against the
# whole discovered set would make every targeted run INVALID and teach the
# reader to ignore the verdict, which is worse than not checking.
if not check_only and discovered and executed:
    wanted = [f for f in filters.split() if f]
    if wanted:
        expected = [d for d in discovered if any(f in d for f in wanted)]
        label = f'selected by {wanted}'
    else:
        expected = discovered
        label = 'discovered'
    missing = sorted(set(expected) - set(executed))
    unexpected = sorted(set(executed) - set(expected))
    if missing:
        reasons.append(f'{len(missing)} test(s) {label} never ran, e.g. {missing[:3]}')
    if unexpected:
        reasons.append(f'{len(unexpected)} test(s) ran that were not {label}, '
                       f'e.g. {unexpected[:3]}')
    if not expected:
        reasons.append(f'no discovered test matched {wanted}: a filter that selects '
                       f'nothing is a zero-run green (PL-1)')

receipt = {
    'subject': {
        'head_before': head_before, 'head_after': head_after, 'tree': tree,
        'dirty_digest_before': dirty_before, 'dirty_digest_after': dirty_after,
        'dirty_inventory': 'dirty-before.txt',
        'manifest_paths': manifest_paths,
        'manifest_files': manifest_files,
        'manifest_digest_local': manifest_local,
        'manifest_digest_worker': manifest_remote,
        'manifest_agrees': manifest_remote == manifest_local,
    },
    'configuration': {
        'worker': worker, 'worker_host': field('HOST'), 'remote_dir': remote_dir,
        'toolchain': toolchain, 'rustc': field('RUSTC'),
        'rustc_commit': field('COMMIT_HASH'), 'host_target': field('TARGET'),
        'profile': profile, 'scope': scope, 'features': features or '(default)',
        'test_threads': threads or '(default)', 'filters': filters or '(none)',
        'scheduler': 'none: direct ssh, bypassing the RCH queue',
    },
    'counts': {
        'discovered_listed': field('DISCOVERED'),
        'executed_named': len(executed), 'json_events': field('JSON_EVENTS'),
        'passed': passed, 'failed': failed, 'ignored': ignored, 'filtered_out': filtered,
    },
    'test_ids': {'discovered': discovered, 'executed': executed,
                 'ignored': ignored_ids, 'failed': failed_ids},
    'beads': [b for b in beads.split(',') if b],
    'mode': 'check-only (compile gate)' if check_only else 'test run',
    'verdict': 'INVALID' if reasons else 'GREEN',
    'invalidating_reasons': reasons,
    'warnings': warnings,
    'subject_still_current': still_current,
    'note': ('Evidence only. This records no batch_verify verdict, closes no Bead and '
             'grants no capability credit: those are separate revision-bound decisions '
             'reserved to the orchestrator (RH-7, PL-4).'),
}
(root / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')

print('== receipt ==')
print(f'verdict             {receipt["verdict"]}')
print(f'manifest agrees     {receipt["subject"]["manifest_agrees"]}')
print(f'discovered/executed {field("DISCOVERED")}/{len(executed)}')
print(f'passed/failed/ignored/filtered  {passed}/{failed}/{ignored}/{filtered}')
for r in reasons:
    print(f'  INVALID: {r}')
for w in warnings:
    print(f'  warn:    {w}')
for name in failed_ids[:15]:
    print(f'  FAILED: {name}')
if check_only and field('CHECK_RC') != '0':
    print('\n-- first diagnostics --')
    for line in [l for l in raw.split('\n') if l.startswith(('error', '  -->'))][:40]:
        print(f'  {line}')
print(f'\nreceipt.json -> {root}/receipt.json')
PY
status=$?
printf '\nartifacts: %s\n' "$OUT"
exit "$status"
