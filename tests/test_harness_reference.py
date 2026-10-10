"""Harness scoring checked from both ends.

Two reference configurations whose outcome is known by construction: the
no-gateway control must block nothing, and a deny-all configuration must block
everything. A harness that mis-scored in either direction would corrupt every
rate computed from it.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict

import pytest

from cym500.benchmark import harness
from cym500.benchmark.gateways.base import GatewayAdapter, GatewayVerdict
from cym500.benchmark.gateways.no_gateway import NoGatewayAdapter
from cym500.redteam.attacks import ATTACK_CLASSES

BENIGN = [
    {"trace_id": f"benign::{i}", "tool_definitions": {"name": f"get_item_{i}"}}
    for i in range(5)
]


class DenyAllAdapter(GatewayAdapter):
    name = "deny-all"

    def setup(self, policy_path: str | None = None) -> None:
        return

    def teardown(self) -> None:
        return

    def _deny(self, case_id: str) -> GatewayVerdict:
        t0 = time.perf_counter()
        return GatewayVerdict(case_id, False, "deny-all", (time.perf_counter() - t0) * 1000)

    def submit_attack(self, case):
        return self._deny(case.case_id)

    def submit_benign(self, trace):
        return self._deny(trace["trace_id"])


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    cases = [c for cls in ATTACK_CLASSES for c in cls().cases()]
    path = tmp_path / "redteam_corpus.jsonl"
    with path.open("w") as f:
        for c in cases:
            rec = asdict(c)
            rec["threat_class"] = c.threat_class.value
            rec["target"] = c.target.value
            f.write(json.dumps(rec) + "\n")
    monkeypatch.setattr(harness, "CORPUS", path)
    monkeypatch.setattr(harness, "RESULTS", tmp_path / "results")
    monkeypatch.setattr(harness, "_iter_benign", lambda: iter(BENIGN))
    return cases


def test_no_gateway_blocks_nothing(corpus):
    report = harness.run_benchmark(NoGatewayAdapter())
    assert report["n_attack"] == len(corpus)
    assert report["n_attack_blocked"] == 0
    assert report["n_benign_blocked_fp"] == 0


def test_deny_all_blocks_everything(corpus):
    report = harness.run_benchmark(DenyAllAdapter())
    assert report["n_attack_blocked"] == len(corpus)
    assert report["tpr"] == 1.0 and report["fpr"] == 1.0
    assert report["n_benign_blocked_fp"] == len(BENIGN)
