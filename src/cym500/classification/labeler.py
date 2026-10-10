"""Labelling utility.

Two modes:
  auto: applies rules to every tool in tools.jsonl, writes labels/auto.csv
  review: prints any flagged record for human review and writes labels/human.csv

Inter-coder agreement is computed from two human passes via kappa.py.
"""
from __future__ import annotations

import csv
from pathlib import Path

from cym500.classification.rules import evaluate_tool, infer_scope_from_description
from cym500.common.logging import get_logger
from cym500.common.schema import HygieneFlag, ToolDescription
from cym500.common.storage import JsonlStore, DATA_ROOT

log = get_logger(__name__)


def auto_label(out_path: str = "labels/auto.csv") -> int:
    tools = JsonlStore("processed/tools.jsonl")
    out = Path(DATA_ROOT) / out_path
    out.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "server_id",
                "tool_name",
                "hygiene_flags",
                "inferred_scopes",
                "needs_review",
            ]
        )
        for t in tools.read(ToolDescription):
            flags = evaluate_tool(t)
            scopes = sorted(s.value for s in infer_scope_from_description(t.description))
            needs_review = bool(flags) or "exec" in scopes
            w.writerow(
                [
                    t.server_id,
                    t.name,
                    ";".join(f.value for f in flags),
                    ";".join(scopes),
                    "yes" if needs_review else "no",
                ]
            )
            n += 1
    log.info("auto_label_done", count=n, path=str(out))
    return n


def review_queue(out_path: str = "labels/review_queue.csv") -> int:
    """Subset of auto labels that need human review."""
    tools = JsonlStore("processed/tools.jsonl")
    out = Path(DATA_ROOT) / out_path
    out.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            ["server_id", "tool_name", "auto_flags", "description_excerpt", "human_flags", "human_notes"]
        )
        for t in tools.read(ToolDescription):
            flags = evaluate_tool(t)
            if not flags:
                continue
            excerpt = (t.description or "")[:160].replace("\n", " ")
            w.writerow([t.server_id, t.name, ";".join(f.value for f in flags), excerpt, "", ""])
            n += 1
    log.info("review_queue_built", count=n, path=str(out))
    return n
