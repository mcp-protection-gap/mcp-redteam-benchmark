"""Phase 3 benchmark harness.

Drives a gateway adapter through the red-team corpus and the benign baseline,
collecting verdicts and timing. Writes a JSON report per gateway under
data/results/benchmark/<gateway>.json.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from cym500.benchmark.gateways.base import GatewayAdapter
from cym500.benchmark.metrics import BenchmarkMetrics
from cym500.common.logging import get_logger
from cym500.common.storage import DATA_ROOT
from cym500.redteam.base import AttackCase, ThreatClass, TargetKind

log = get_logger(__name__)

CORPUS = Path(DATA_ROOT) / "processed" / "redteam_corpus.jsonl"
RESULTS = Path(DATA_ROOT) / "results" / "benchmark"


def _iter_corpus() -> Iterable[AttackCase]:
    if not CORPUS.exists():
        return
    with CORPUS.open() as f:
        for line in f:
            rec = json.loads(line)
            yield AttackCase(
                case_id=rec["case_id"],
                threat_class=ThreatClass(rec["threat_class"]),
                variant_id=rec["variant_id"],
                target=TargetKind(rec["target"]),
                payload=rec["payload"],
                description=rec["description"],
                expected_outcome=rec["expected_outcome"],
                derived_from=rec.get("derived_from"),
                metadata=rec.get("metadata") or {},
            )


def _iter_benign() -> Iterable[dict]:
    from cym500.redteam.benign_baseline import benign_traces
    yield from benign_traces()


def run_benchmark(gateway: GatewayAdapter, *, corpus_limit: int | None = None) -> dict:
    RESULTS.mkdir(parents=True, exist_ok=True)
    metrics = BenchmarkMetrics(gateway=gateway.name)

    with gateway:
        for i, case in enumerate(_iter_corpus()):
            if corpus_limit is not None and i >= corpus_limit:
                break
            verdict = gateway.submit_attack(case)
            metrics.n_attack += 1
            metrics.per_class_attack[case.threat_class.value] += 1
            metrics.attack_latencies_ms.append(verdict.latency_ms)
            metrics.verdicts.append({
                "kind": "attack",
                "case_id": case.case_id,
                "threat_class": case.threat_class.value,
                "blocked": not verdict.allowed,
                "evidence": verdict.evidence,
                "latency_ms": verdict.latency_ms,
            })
            if not verdict.allowed:
                metrics.n_attack_blocked += 1
                metrics.per_class_blocked[case.threat_class.value] += 1

        for trace in _iter_benign():
            verdict = gateway.submit_benign(trace)
            metrics.n_benign += 1
            metrics.benign_latencies_ms.append(verdict.latency_ms)
            if not verdict.allowed:
                metrics.n_benign_blocked += 1
            metrics.verdicts.append({
                "kind": "benign",
                "case_id": trace.get("trace_id", ""),
                "derived_from": trace.get("derived_from", ""),
                "tool_definition": trace.get("tool_definitions", ""),
                "blocked": not verdict.allowed,
                "evidence": verdict.evidence,
                "latency_ms": verdict.latency_ms,
            })

    out_path = RESULTS / f"{gateway.name}.json"
    with out_path.open("w") as f:
        json.dump(metrics.to_dict(), f, indent=2)

    verdict_path = RESULTS / f"{gateway.name}-verdicts.jsonl"
    with verdict_path.open("w") as f:
        for rec in metrics.verdicts:
            f.write(json.dumps(rec) + "\n")
    log.info("benchmark_done", gateway=gateway.name, path=str(out_path))
    return metrics.to_dict()
