#!/usr/bin/env bash
# Phase 3 — gateway benchmark.
# Brings up each gateway via its scripts/gateways/<name>/up.sh helper, runs
# the benchmark, then tears it down. Add new gateways by extending GATEWAYS.
set -euo pipefail
cd "$(dirname "$0")/.."

GATEWAYS=("none" "mcp-gateway-registry" "mcp-scan")

for gw in "${GATEWAYS[@]}"; do
    echo "==> Benchmark: $gw"
    if [[ -x "scripts/gateways/${gw}/up.sh" ]]; then
        "scripts/gateways/${gw}/up.sh"
    fi
    python -m cym500 benchmark run --gateway "$gw" || true
    if [[ -x "scripts/gateways/${gw}/down.sh" ]]; then
        "scripts/gateways/${gw}/down.sh"
    fi
done

echo "Results in data/results/benchmark/"
