"""Adapter skeleton for Solo.io's OSS MCP demo (registration workflow).

Solo.io's contribution is signature-based registration. If their reference
implementation is available as a deployable artefact during the pilot, fill
this in similarly to mcp_gateway_registry.py. Otherwise drop from the
shortlist and document the omission in Chapter 7's methodology section.
"""
from __future__ import annotations

import time

from cym500.benchmark.gateways.base import GatewayAdapter, GatewayVerdict
from cym500.redteam.base import AttackCase


class SoloIoAdapter(GatewayAdapter):
    name = "solo-io"

    def setup(self, policy_path: str | None = None) -> None:
        raise NotImplementedError(
            "Solo.io adapter not yet implemented. See class docstring."
        )

    def teardown(self) -> None:
        return

    def submit_attack(self, case: AttackCase) -> GatewayVerdict:
        raise NotImplementedError

    def submit_benign(self, trace: dict) -> GatewayVerdict:
        raise NotImplementedError
