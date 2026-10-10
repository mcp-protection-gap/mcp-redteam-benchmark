"""Benign baseline corpus generator.

Produces ~500 benign tool-call traces by replaying recorded interactions
with a curated set of clean MCP servers. This file is the harness; the
recordings themselves live in data/raw/benign/ and are not committed.

The student records baselines once (see scripts/record_benign.sh); this
module replays them to produce the same shape of trace as the attack cases,
which the benchmark harness uses to measure FPR.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from cym500.common.storage import DATA_ROOT


def benign_traces() -> Iterator[dict]:
    base = Path(DATA_ROOT) / "raw" / "benign"
    if not base.exists():
        return
    for path in sorted(base.glob("*.jsonl")):
        with path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                yield json.loads(line)
