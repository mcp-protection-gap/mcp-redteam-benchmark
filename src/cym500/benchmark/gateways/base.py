"""Gateway adapter contract.

Each adapter wraps a gateway under test. The adapter is responsible for:
1. Setup: ensuring the gateway is up and configured with a known policy.
2. Submitting one AttackCase or benign trace.
3. Returning a GatewayVerdict (allow/deny + evidence + timing).

The harness owns metrics; adapters only return raw verdicts.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass

from cym500.redteam.base import AttackCase


@dataclass(slots=True)
class GatewayVerdict:
    case_id: str
    allowed: bool
    evidence: str
    latency_ms: float
    error: str | None = None


class GatewayAdapter(abc.ABC):
    """Wraps one gateway under test."""

    name: str = "base"

    @abc.abstractmethod
    def setup(self, policy_path: str | None = None) -> None:
        """Bring the gateway up with a known policy. Idempotent."""

    @abc.abstractmethod
    def teardown(self) -> None:
        """Stop the gateway and clean up."""

    @abc.abstractmethod
    def submit_attack(self, case: AttackCase) -> GatewayVerdict:
        """Submit one attack case; return verdict."""

    @abc.abstractmethod
    def submit_benign(self, trace: dict) -> GatewayVerdict:
        """Submit one benign trace; return verdict (allow=True is the desired outcome)."""

    def __enter__(self):
        self.setup()
        return self

    def __exit__(self, *exc):
        self.teardown()
