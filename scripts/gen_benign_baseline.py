"""Generate the benign baseline corpus for the Phase 3 gateway benchmark.

Rationale: the benchmark needs a set of *legitimate* tool traces so that
false-positive rate (over-blocking of benign traffic) can be measured. Rather
than hand-record synthetic traces, we ground the baseline in the real tool
descriptions already harvested in Phase 1 (data/processed/tools.jsonl): these
are genuine, in-the-wild tool definitions, and all but a handful were cleared by
the hygiene detectors, so they are a defensible "should not be blocked" set.

Any tool that the hygiene detectors flagged is excluded, so the benign set is
genuinely clean. A deterministic, evenly-spaced sample of TARGET_N tools is
written to data/raw/benign/harvested_tools.jsonl in the shape the benchmark
harness and the mcp-scan comparator consume (a `tool_definitions` dict plus a
parallel `payload`, mirroring the attack cases). Re-running reproduces the same
sample.

Usage:  python scripts/gen_benign_baseline.py [N]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from cym500.classification.rules import evaluate_tool
from cym500.common.schema import ToolDescription
from cym500.common.storage import DATA_ROOT, JsonlStore

TARGET_N = int(sys.argv[1]) if len(sys.argv) > 1 else 500
OUT = Path(DATA_ROOT) / "raw" / "benign" / "harvested_tools.jsonl"


def _clean_tools() -> list[ToolDescription]:
    """All harvested tools that carry a usable definition and trip no detector."""
    tools = JsonlStore("processed/tools.jsonl")
    clean: list[ToolDescription] = []
    for t in tools.read(ToolDescription):
        if not (t.name and t.description):
            continue
        if evaluate_tool(t):  # flagged by a hygiene detector -> not benign
            continue
        clean.append(t)
    # Deterministic order so the sample is reproducible run to run.
    clean.sort(key=lambda t: (t.server_id or "", t.name or ""))
    return clean


def _sample(items: list, n: int) -> list:
    if len(items) <= n:
        return items
    # Evenly spaced pick across the whole corpus (spreads servers/paths).
    step = len(items) / n
    return [items[int(i * step)] for i in range(n)]


def main() -> int:
    clean = _clean_tools()
    chosen = _sample(clean, TARGET_N)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w") as f:
        for i, t in enumerate(chosen):
            tool_def = {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema or {},
            }
            trace = {
                "trace_id": f"benign::{t.server_id}::{t.name}::{i}",
                "target": "tool_description",
                "tool_definitions": tool_def,
                "payload": tool_def,
                "derived_from": t.server_id,
                "source_path": (t.source.kind if t.source else None),
            }
            f.write(json.dumps(trace) + "\n")
    print(f"clean tools available: {len(clean)}; wrote {len(chosen)} benign traces -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
