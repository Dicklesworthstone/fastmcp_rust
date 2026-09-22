#!/usr/bin/env bash
# bd-35o84 -- build the FND-01 evidence harness and derive the one path its
# consumer will accept.
#
# WHY THIS EXISTS.  crates/fastmcp/tests/fnd_01_dependency_evidence.rs reads
# FASTMCP_FND01_PUBLIC_HARNESS_BIN (see `ordinary_public_harness_*`; cited by
# symbol because that file moves), and six lines later derives the only legal
# value itself:
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

Builds the `fnd_01_evidence_harness` Cargo example and prints the absolute path
that FASTMCP_FND01_PUBLIC_HARNESS_BIN must be set to, with the artifact's byte
length and SHA-256.

  --features <list>   feature list for the build (default: testing-lab)
  --no-features       build with default features only
  --print-export      emit a ready-to-eval `export FASTMCP_FND01_PUBLIC_HARNESS_BIN=...` line

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

printf 'harness   %s\n' "$harness"
printf 'bytes     %s\n' "$harness_bytes"
printf 'sha256    %s\n' "$harness_sha"
if [ "$emit_export" -eq 1 ]; then
  printf 'export FASTMCP_FND01_PUBLIC_HARNESS_BIN=%s\n' "$harness"
fi
