"""Metrics for the gateway benchmark.

Per-threat-class TPR and FPR, latency percentiles, throughput, optional
memory if measured externally. We intentionally compute these in pure
Python rather than scikit-learn to keep the audit trail simple and
reviewable.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from statistics import median


def percentile(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * q
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    frac = k - lo
    return s[lo] * (1 - frac) + s[hi] * frac


# Operators of the red-team generator; the last ``-`` segment of a case id.
MUTATION_OPERATORS = ("obfuscation", "paraphrase", "slow_drip", "unicode_dressing", "split_payload")


def bypass_rate(verdicts: list[dict]) -> dict:
    """Share of mutated variants that evade a configuration which blocked their base.

    A case id is ``class::variant::seed-operator``, the base case carrying the
    operator ``base``. Only families whose base was blocked count, so the rate
    isolates what the mutation operators alone defeat; a family whose base got
    through says nothing about mutation. Families without a ``base`` case
    (supply-chain techniques, credential-leak channels) never enter.
    """
    blocked: dict[str, bool] = {}
    for v in verdicts:
        if v.get("kind", "attack") == "attack" and "-" in v.get("case_id", ""):
            blocked[v["case_id"]] = bool(v.get("blocked"))
    n_mutants = n_bypassed = 0
    for case_id, was_blocked in blocked.items():
        family, operator = case_id.rsplit("-", 1)
        if operator not in MUTATION_OPERATORS or not blocked.get(f"{family}-base"):
            continue
        n_mutants += 1
        n_bypassed += not was_blocked
    return {
        "n_mutants": n_mutants,
        "n_bypassed": n_bypassed,
        "rate": n_bypassed / n_mutants if n_mutants else float("nan"),
    }


@dataclass
class BenchmarkMetrics:
    gateway: str
    n_attack: int = 0
    n_attack_blocked: int = 0
    n_benign: int = 0
    n_benign_blocked: int = 0  # false positives
    per_class_attack: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    per_class_blocked: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    attack_latencies_ms: list[float] = field(default_factory=list)
    benign_latencies_ms: list[float] = field(default_factory=list)
    # Per-case verdicts, kept so that a reported rate can be traced back to the
    # individual definitions behind it. Written to a sidecar file rather than
    # to_dict(), which stays the stable aggregate report.
    verdicts: list[dict] = field(default_factory=list)

    @property
    def tpr(self) -> float:
        return self.n_attack_blocked / self.n_attack if self.n_attack else float("nan")

    @property
    def fpr(self) -> float:
        return self.n_benign_blocked / self.n_benign if self.n_benign else float("nan")

    def per_class_tpr(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for cls, total in self.per_class_attack.items():
            out[cls] = self.per_class_blocked[cls] / total if total else float("nan")
        return out

    def latency_summary(self) -> dict[str, float]:
        all_lat = self.attack_latencies_ms + self.benign_latencies_ms
        if not all_lat:
            return {"p50": float("nan"), "p95": float("nan"), "p99": float("nan"), "median": float("nan")}
        return {
            "median": median(all_lat),
            "p50": percentile(all_lat, 0.50),
            "p95": percentile(all_lat, 0.95),
            "p99": percentile(all_lat, 0.99),
        }

    def to_dict(self) -> dict:
        return {
            "gateway": self.gateway,
            "n_attack": self.n_attack,
            "n_attack_blocked": self.n_attack_blocked,
            "n_benign": self.n_benign,
            "n_benign_blocked_fp": self.n_benign_blocked,
            "tpr": self.tpr,
            "fpr": self.fpr,
            "per_class_tpr": self.per_class_tpr(),
            "latency_ms": self.latency_summary(),
            "bypass": bypass_rate(self.verdicts),
        }
