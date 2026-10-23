#!/usr/bin/env bash
#
# Assert that the pinned Rust toolchain is actually reachable, then optionally
# run a command under it.
#
# WHY THIS EXISTS (the hard-gate justification AGENTS.md demands of a process
# artifact, since otherwise this would be ceremony):
#
#   concrete consumer     any lane running a LOCAL check -- rustfmt, a
#                         clippy-driver probe, a rustc shape check. These are
#                         the checks that survive a wedged RCH lane, so they are
#                         exactly what lanes fall back to, and they are the ones
#                         with no gate in front of them.
#   enforced gate         the mandated fmt gate, and any local lint/shape check.
#                         This script fails closed BEFORE the check runs, so a
#                         lane cannot report a verdict the toolchain never
#                         produced. It records no verdict itself and has no
#                         authority to.
#   observed defect class one, observed in this repository, twice.
#                         ~/.rustup/toolchains is a SYMLINK to an external
#                         volume (/Volumes/USBNVME16TB/rustup_toolchains). When
#                         that volume is not mounted the symlink dangles,
#                         `rustfmt --check` EXITS 0 HAVING CHECKED NOTHING, and
#                         the lane reads a silent false green on a mandated
#                         gate. Recorded on bd-no-local-toolchain-497fu, which
#                         was filed while the volume was detached and whose
#                         premise is false while it is attached -- the state
#                         flaps, which is precisely why it needs a mechanical
#                         check rather than a remembered fact.
#   retirement condition  when the toolchain no longer lives behind a removable
#                         mount, or when rustfmt/clippy fail closed on a missing
#                         toolchain by themselves. Delete this then.
#
# It deliberately does NOT install, repair, mount, or modify anything. It reads
# and reports. Exit non-zero means DO NOT TRUST a local check right now.
#
# USAGE
#   scripts/toolchain_preflight.sh                 # assert only, print verdict
#   scripts/toolchain_preflight.sh rustfmt --edition 2024 --check path/to/lib.rs
#                                                  # assert, then exec the command
#
# EXIT CODES (distinct, so a caller can branch without parsing prose)
#   0   toolchain is live and matches the pin
#   70  toolchain root is a symlink that does not resolve (the observed defect)
#   71  toolchain root resolves but contains no installed toolchain
#   72  rustc is not resolvable or not executable
#   73  the resolved toolchain does not match rust-toolchain.toml's channel

set -euo pipefail

repo_root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
pin_file="$repo_root/rust-toolchain.toml"

fail() {
	printf 'TOOLCHAIN_PREFLIGHT: refused code=%s reason=%s\n' "$1" "$2" >&2
	exit "$1"
}

[ -r "$pin_file" ] || fail 73 "rust-toolchain.toml is unreadable at $pin_file"

channel="$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$pin_file" | head -n 1)"
[ -n "$channel" ] || fail 73 "rust-toolchain.toml declares no channel"

toolchain_root="${RUSTUP_HOME:-$HOME/.rustup}/toolchains"

# The dangling-symlink case is the whole point, so test it before anything that
# would mask it. -e follows symlinks, so a dangling link is NOT -e while it IS
# -L; that pair is what distinguishes "absent" from "detached".
if [ -L "$toolchain_root" ] && [ ! -e "$toolchain_root" ]; then
	fail 70 "toolchain root is a dangling symlink: $toolchain_root -> $(readlink "$toolchain_root")"
fi
[ -d "$toolchain_root" ] || fail 70 "toolchain root is not a directory: $toolchain_root"

# An empty root is the same operational state as a dangling one: nothing to run.
# A real toolchain is a DIRECTORY, and the exFAT volume this root lives on is
# littered with AppleDouble "._name" sidecar files, so neither a bare
# non-empty test nor a file count would be sound here.
installed=0
for entry in "$toolchain_root"/*; do
	[ -e "$entry" ] || continue # unmatched glob expands to itself
	case "${entry##*/}" in
	._*) continue ;;
	esac
	if [ -d "$entry" ]; then
		installed=1
		break
	fi
done
[ "$installed" -eq 1 ] || fail 71 "toolchain root resolves but holds no installed toolchain: $toolchain_root"

command -v rustup >/dev/null 2>&1 || fail 72 "rustup is not on PATH"

# Resolve through rustup so the answer reflects the pin this repo declares,
# rather than whatever happens to be the user default.
rustc_path=""
if ! rustc_path="$(cd "$repo_root" && rustup which rustc 2>/dev/null)"; then
	fail 72 "rustup cannot resolve rustc for channel $channel"
fi
[ -n "$rustc_path" ] && [ -x "$rustc_path" ] || fail 72 "resolved rustc is not executable: ${rustc_path:-<empty>}"

# Bind the resolved binary to the declared channel. rustup resolving SOMETHING
# is not evidence that it resolved the pinned thing.
case "$rustc_path" in
*"/$channel-"*) ;;
*) fail 73 "resolved rustc does not match pinned channel $channel: $rustc_path" ;;
esac

rustc_version=""
if ! rustc_version="$("$rustc_path" --version 2>/dev/null)"; then
	fail 72 "resolved rustc did not execute: $rustc_path"
fi

printf 'TOOLCHAIN_PREFLIGHT: live channel=%s rustc=%s root=%s\n' \
	"$channel" "${rustc_version// /_}" "$(cd "$toolchain_root" && pwd -P)"

if [ "$#" -gt 0 ]; then
	cd "$repo_root"
	exec "$@"
fi
