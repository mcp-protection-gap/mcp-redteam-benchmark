#!/usr/bin/env bash
# Phase 2 — build red-team corpus.
set -euo pipefail
cd "$(dirname "$0")/.."

python -m cym500 redteam build
echo "Corpus written to data/processed/redteam_corpus.jsonl"
