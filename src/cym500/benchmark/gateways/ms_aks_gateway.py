"""Adapter skeleton for Microsoft's OSS AKS MCP gateway.

Find authoritative repo URL during pilot. Fill in setup/teardown/submit_*
once the gateway's HTTP surface is documented.
"""
from __future__ import annotations

import time

from cym500.benchmark.gateways.base import GatewayAdapter, GatewayVerdict
from cym500.redteam.base import AttackCase


class MicrosoftAksGatewayAdapter(GatewayAdapter):
    name = "ms-aks-mcp"

    def setup(self, policy_path: str | None = None) -> None:
        raise NotImplementedError(
            "Microsoft AKS MCP gateway adapter not yet implemented. "
            "Pilot step: locate the OSS repo, document the HTTP surface, "
            "fill in this adapter following mcp_gateway_registry.py as a pattern."
        )

    def teardown(self) -> None:
        return

    def submit_attack(self, case: AttackCase) -> GatewayVerdict:
        raise NotImplementedError

    def submit_benign(self, trace: dict) -> GatewayVerdict:
        raise NotImplementedError
