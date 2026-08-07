#!/usr/bin/env bash
# MCP-CANARY-01 entry point.  The runner preserves its isolated workspace and
# receipt for the batch verifier; it never writes the live Beads database.
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$script_dir/fixtures/mcp_campaign_canary/runner.py" "$@"
