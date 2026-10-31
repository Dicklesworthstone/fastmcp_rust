#!/usr/bin/env bash
# Verify the two lint edits in the projections where their lints actually fire.
# Both are committed (c88f7b25 client, 0cb67c1d facade) and NEITHER has been
# run, so this is the first execution of either.
#
#   facade  crates/fastmcp/tests/public_reexport_closure.rs
#           default_trait_access  :291  -> rewritten to name the type
#           unused_async_trait_impl / no_effect_underscore_binding
#                                 :357 / :394 -> one documented function-level
#           allow. All three sit under #[cfg(feature = "apps")], which is NOT a
#           facade default, so ONLY --all-features sees them.
#
#   client  crates/fastmcp-client/src/lib.rs:14664
#           infallible_destructuring_match -> documented allow, because the
#           suggested `let`-destructure does not compile when
#           legacy-2024-11-05 is ON. Fires ONLY at --no-default-features.
#
# Two projections, not three. DEFAULT is predicted inert for both (apps off,
# and the client lint does not fire there), and that prediction is stated as a
# no-claim rather than silently assumed -- but compile safety IS covered in
# both runs below, which is where a malformed #[allow] would surface.
#
# Expected, against the 2026-10-30 baselines at HEAD 96263d60:
#   --all-features       0 errors, 294 -> 291 distinct, the 3 facade rows gone
#   --no-default-features 0 errors,  21 ->  20 distinct, the client row gone
set -u
cd /Users/jemanuel/projects/fastmcp_rust || exit 90

SC=/Users/jemanuel/projects/fastmcp_rust
AF=/tmp/lintfix_allfeat.log
ND=/tmp/lintfix_nodefault.log

{
  echo "ANCHOR_HEAD=$(git rev-parse HEAD)"
  echo "ANCHOR_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "HOST=$(hostname)"
  echo "BLOBS:"
  echo "  $(git hash-object crates/fastmcp/tests/public_reexport_closure.rs)  public_reexport_closure.rs"
  echo "  $(git hash-object crates/fastmcp-client/src/lib.rs)  fastmcp-client/src/lib.rs"
  echo "DIRTY:"
  git status --porcelain -- crates/ | sed 's/^/  /'
} | tee /tmp/lintfix_anchor.txt

echo "=== PROJECTION 1: --all-features (the facade rows) ==="
cargo clippy --locked --workspace --all-targets --all-features \
  --profile test --keep-going > "$AF" 2>&1
echo "ALLFEAT_EXIT=$?"

echo "=== PROJECTION 2: --no-default-features (the client row) ==="
cargo clippy --locked --workspace --all-targets --no-default-features \
  --profile test --keep-going > "$ND" 2>&1
echo "NODEFAULT_EXIT=$?"

for pair in "all-features:$AF" "no-default:$ND"; do
  NAME=${pair%%:*}; LOG=${pair#*:}
  echo "----- $NAME -----"
  # Strip ANSI first: cargo colourises, and that defeats naive greps.
  sed 's/\x1b\[[0-9;]*m//g' "$LOG" > "$LOG.plain"
  echo "compile errors: $(grep -c '^error' "$LOG.plain")"
  echo "per-target warning lines (authoritative counts):"
  grep -E '^warning: .*generated [0-9]+ warning' "$LOG.plain" | sed 's/^/    /'
  echo "  -- the specific rows this pass must have REMOVED --"
  echo "  public_reexport_closure hits: $(grep -c 'public_reexport_closure.rs' "$LOG.plain")"
  grep -n 'public_reexport_closure.rs:' "$LOG.plain" | sed 's/^/    /' | head
  echo "  infallible_destructuring_match hits: $(grep -c 'infallible_destructuring_match' "$LOG.plain")"
  grep -n 'infallible_destructuring_match' "$LOG.plain" | sed 's/^/    /' | head
  echo "  unused_async_trait_impl hits: $(grep -c 'unused_async_trait_impl' "$LOG.plain")"
  echo "  no_effect_underscore_binding hits: $(grep -c 'no_effect_underscore_binding' "$LOG.plain")"
  echo "  default_trait_access hits: $(grep -c 'default_trait_access' "$LOG.plain")"
  echo "  unknown_lints (would mean I misspelled an allow): $(grep -c 'unknown_lints' "$LOG.plain")"
done
