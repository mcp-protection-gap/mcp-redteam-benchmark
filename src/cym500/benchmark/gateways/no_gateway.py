"""Baseline 'no gateway' adapter: every case passes.

This is the control. The benchmark must always include it; the gap between
'no gateway' and each gateway under test is the value the gateway adds.
"""
from __future__ import annotations

import time

from cym500.benchmark.gateways.base import GatewayAdapter, GatewayVerdict
from cym500.redteam.base import AttackCase


class NoGatewayAdapter(GatewayAdapter):
    name = "none"

    def setup(self, policy_path: str | None = None) -> None:
        return

    def teardown(self) -> None:
        return

    def submit_attack(self, case: AttackCase) -> GatewayVerdict:
        t0 = time.perf_counter()
        return GatewayVerdict(
            case_id=case.case_id,
            allowed=True,
            evidence="no gateway in path",
            latency_ms=(time.perf_counter() - t0) * 1000,
        )

    def submit_benign(self, trace: dict) -> GatewayVerdict:
        t0 = time.perf_counter()
        return GatewayVerdict(
            case_id=trace.get("trace_id", "<benign>"),
            allowed=True,
            evidence="no gateway in path",
            latency_ms=(time.perf_counter() - t0) * 1000,
        )
