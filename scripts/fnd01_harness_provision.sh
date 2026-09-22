#!/usr/bin/env bash
# bd-35o84 -- build the FND-01 evidence harness and derive the one path its
# consumer will accept.
#
# WHY THIS EXISTS.  crates/fastmcp/tests/fnd_01_dependency_evidence.rs reads
# THREE variables, all required, all cited by symbol because that file moves:
#
#     FASTMCP_FND01_PUBLIC_HARNESS_BIN     the artifact path
#     FASTMCP_FND01_PUBLIC_HARNESS_BYTES   canonical positive decimal, 1..=256 MiB
#     FASTMCP_FND01_PUBLIC_HARNESS_SHA256  64 lowercase hex characters
#
# BYTES and SHA256 are read by `ordinary_public_harness_receipt_binding`; BIN is
# read by the path-equality guard.  For BIN the reader derives the only legal
# value itself, six lines after reading it:
#
#     expected = ${CARGO_TARGET_DIR:-<repo>/target}/debug/examples/fnd_01_evidence_harness
#     must be absolute, and must EQUAL that path
#
# So the variable is a restatement handshake, not an input: exactly one string
# is accepted and the reader already knows it.  What is actually required is
# that the Cargo EXAMPLE has been BUILT and is present there.  Before this
# script the build step existed only in untracked per-agent files, so a fresh
# checkout reported E_ORDINARY_HANDOFF_PENDING on five ordinary_* cases.
#
# THIS SCRIPT DELIBERATELY DOES NOT COPY OR STAGE THE ARTIFACT.  The untracked
# predecessor staged it to a retained target root and exported that, which
# satisfies the equality only if CARGO_TARGET_DIR is pointed at the same root --
# a third variable neither the script nor the reader mentions.  Pointing at the
# canonical Cargo path removes that coupling entirely.
#
# It builds and reads; it writes nothing outside the Cargo target directory and
# never touches the worktree, Git state, or the Beads database.
set -euo pipefail

features=testing-lab
emit_export=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --features) features=${2:-}; shift 2 ;;
    --no-features) features=; shift ;;
    --print-export) emit_export=1; shift ;;
    -h|--help)
      cat <<'USAGE'
usage: scripts/fnd01_harness_provision.sh [--features <list>|--no-features] [--print-export]

Builds the `fnd_01_evidence_harness` Cargo example and prints the artifact's
path, byte length and SHA-256 -- the three values the consumer requires as
FASTMCP_FND01_PUBLIC_HARNESS_BIN / _BYTES / _SHA256.  --print-export emits all
three as eval-ready export lines.

  --features <list>   feature list for the build (default: testing-lab)
  --no-features       build with default features only
  --print-export      emit all THREE export lines, ready to eval

FEATURE DEFAULT IS A HYPOTHESIS, NOT A MEASUREMENT.  The example declares no
`required-features`, while the test target that includes the same source
declares `required-features = ["testing-lab"]`.  The default mirrors the test
target; the first successful build settles it.  If it builds under
--no-features, say so on bd-35o84 and this default should change.
USAGE
      exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

# shellcheck disable=SC1007  # `CDPATH= cd` is a command-scoped env assignment, not a
# mistyped assignment; this is the same idiom scripts/mcp_campaign_canary.sh already uses.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# The reader requires an ABSOLUTE path and derives it from CARGO_TARGET_DIR when
# set.  A relative CARGO_TARGET_DIR would make the reader's own `expected`
# relative and its is_absolute() guard would refuse it, so refuse here, where
# the message can name the cause.
target_dir=${CARGO_TARGET_DIR:-$repo_root/target}
case "$target_dir" in
  /*) ;;
  *) printf 'CARGO_TARGET_DIR must be absolute; got: %s\n' "$target_dir" >&2; exit 2 ;;
esac

harness="$target_dir/debug/examples/fnd_01_evidence_harness"

build_args=(build -p fastmcp-rust --example fnd_01_evidence_harness)
if [ -n "$features" ]; then
  build_args+=(--features "$features")
fi
printf 'building: cargo %s\n' "${build_args[*]}" >&2
cargo "${build_args[@]}"

# Absence here is a build that silently produced nothing at the expected path --
# a different fault from a compile error, and the one that would otherwise reach
# the consumer as "is required" with no explanation.
if [ ! -f "$harness" ]; then
  printf 'harness absent after a successful build: %s\n' "$harness" >&2
  printf 'the consumer accepts only this path; a build that lands elsewhere cannot satisfy it\n' >&2
  printf 'in this repository cargo is RCH-hooked: if the build was offloaded, the artifact is on a\n' >&2
  printf 'remote worker and never existed locally. Re-run with the offload disabled.\n' >&2
  exit 1
fi
[ -x "$harness" ] || { printf 'harness is not executable: %s\n' "$harness" >&2; exit 1; }

if command -v sha256sum >/dev/null 2>&1; then
  harness_sha=$(sha256sum -- "$harness" | cut -d' ' -f1)
else
  harness_sha=$(shasum -a 256 -- "$harness" | cut -d' ' -f1)
fi
harness_bytes=$(wc -c < "$harness" | tr -d ' ')

# The consumer reads THREE variables, not one, and validates each before use
# (`ordinary_public_harness_receipt_binding` for BYTES/SHA256; the path equality
# for BIN). Validate here too, so a refusal names its cause at the point the
# value is produced rather than several layers away as `pending!`.
#
# BYTES must be canonical positive decimal: non-empty, no leading zero, digits
# only. SHA256 must be exactly 64 lowercase hex characters.
case "$harness_bytes" in
  ''|0|0*) printf 'byte length is not canonical positive decimal: %s\n' "$harness_bytes" >&2; exit 1 ;;
  *[!0-9]*) printf 'byte length is not all digits: %s\n' "$harness_bytes" >&2; exit 1 ;;
esac
case "$harness_sha" in
  *[!0-9a-f]*|'') printf 'sha256 is not lowercase hex: %s\n' "$harness_sha" >&2; exit 1 ;;
esac
[ "${#harness_sha}" -eq 64 ] || { printf 'sha256 is %s characters, expected 64\n' "${#harness_sha}" >&2; exit 1; }

# MAX_GATE_EXECUTABLE_BYTES is 256 MiB and the consumer refuses a longer artifact
# BEFORE it looks at any digest. Report it here, by name, because a provisioned
# harness over the bound does not fix the five ordinary_* cases -- it exchanges
# E_ORDINARY_HANDOFF_PENDING for a receipt-length refusal, which is the separate
# blocker bd-fnd-01-harness-exceeds-gate-bound-2ayqy.
max_gate_executable_bytes=268435456
over_bound=0
if [ "$harness_bytes" -gt "$max_gate_executable_bytes" ]; then
  over_bound=1
fi

# With --print-export, stdout must be EVAL-SAFE and nothing else: an adopter runs
# `eval "$(scripts/fnd01_harness_provision.sh --print-export)"`, and a human
# summary on stdout makes that emit `harness: command not found` (measured) while
# `eval` still reports success, because eval returns only its LAST command's
# status. Noise that survives set -e is worse than noise that fails it.
summary_fd=1
if [ "$emit_export" -eq 1 ]; then
  summary_fd=2
fi
printf 'harness   %s\n' "$harness" >&"$summary_fd"
printf 'bytes     %s\n' "$harness_bytes" >&"$summary_fd"
printf 'sha256    %s\n' "$harness_sha" >&"$summary_fd"
if [ "$over_bound" -eq 1 ]; then
  printf 'WARNING: %s bytes exceeds MAX_GATE_EXECUTABLE_BYTES (%s).\n' \
    "$harness_bytes" "$max_gate_executable_bytes" >&2
  printf 'The consumer will refuse this artifact on length before reading its digest, so the\n' >&2
  printf 'ordinary_* cases will report a receipt-length refusal rather than succeeding. That is\n' >&2
  printf 'bd-fnd-01-harness-exceeds-gate-bound-2ayqy, not a fault in this provisioning step.\n' >&2
fi

if [ "$emit_export" -eq 1 ]; then
  # All THREE, eval-ready. %q quotes the path so a directory containing spaces
  # survives the round trip; the other two are constrained above to characters
  # that need no quoting.
  printf 'export FASTMCP_FND01_PUBLIC_HARNESS_BIN=%q\n' "$harness"
  printf 'export FASTMCP_FND01_PUBLIC_HARNESS_BYTES=%s\n' "$harness_bytes"
  printf 'export FASTMCP_FND01_PUBLIC_HARNESS_SHA256=%s\n' "$harness_sha"
fi
