#!/usr/bin/env bash
# Record benign tool-call traces from a curated set of clean MCP servers.
# Each invocation produces one line of JSONL into data/raw/benign/<server>.jsonl.
#
# This script is a placeholder: filling it in requires deciding (with the
# supervisor) which servers count as 'clean baselines' for FPR measurement.
# Suggested initial set: official @modelcontextprotocol/server-filesystem,
# @modelcontextprotocol/server-postgres, @modelcontextprotocol/server-fetch.
set -euo pipefail

echo "Not yet implemented. See LEFT_FOR_YOU.md > Phase 2 > Benign baselines."
exit 1
