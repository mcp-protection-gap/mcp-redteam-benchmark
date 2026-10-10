#!/usr/bin/env bash
# Phase 1 — measurement.
# Prerequisite: .env populated, supervisor + ethics signoff for the queries below.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Step 1/4: GitHub configs"
python -m cym500 collect github --config config/collectors.yaml

echo "==> Step 2/4: Registries"
python -m cym500 collect registries --config config/collectors.yaml

echo "==> Step 3/4: Sandbox tools/list (Docker required)"
python -c "from cym500.sandbox.runner import run; print(run())"

echo "==> Step 4/4: Auto-label + posture stats"
python -m cym500 classify auto
python -m cym500 classify review-queue
python -c "from cym500.analysis.posture import write_all; write_all()"

echo "Done. See data/results/posture/."
