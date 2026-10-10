"""Adapter for agentic-community/mcp-gateway-registry.

The pilot must confirm:
- Install path (Docker compose or k8s manifest).
- HTTP endpoint exposed for tool registration and inference.
- Policy file format the gateway accepts.

Once confirmed, fill in setup()/teardown()/submit_*. Until then this raises
NotImplementedError so the harness cannot accidentally claim 'allowed=True'
when the gateway is not actually running.
"""
from __future__ import annotations

import os
import time

import httpx

from cym500.benchmark.gateways.base import GatewayAdapter, GatewayVerdict
from cym500.common.logging import get_logger
from cym500.redteam.base import AttackCase

log = get_logger(__name__)


class McpGatewayRegistryAdapter(GatewayAdapter):
    name = "mcp-gateway-registry"

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = base_url or os.environ.get("MCP_GATEWAY_REGISTRY_URL", "http://localhost:8080")
        self._http: httpx.Client | None = None

    def setup(self, policy_path: str | None = None) -> None:
        # PILOT: confirm gateway is reachable; load policy.
        self._http = httpx.Client(base_url=self.base_url, timeout=10.0)
        try:
            r = self._http.get("/health")
            r.raise_for_status()
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(
                f"{self.name}: not reachable at {self.base_url}; bring it up first "
                "(scripts/gateways/mcp_gateway_registry/up.sh)."
            ) from e

    def teardown(self) -> None:
        if self._http:
            self._http.close()
            self._http = None

    def submit_attack(self, case: AttackCase) -> GatewayVerdict:
        if self._http is None:
            raise RuntimeError("setup() not called")
        t0 = time.perf_counter()
        # PILOT: depends on the gateway's submission API. Below is the
        # placeholder shape; replace with the real endpoint.
        try:
            r = self._http.post("/v1/policy/evaluate", json={"case": case.payload, "case_id": case.case_id})
            r.raise_for_status()
            data = r.json()
            allowed = bool(data.get("allow", True))
            evidence = data.get("reason", "")
        except Exception as e:  # noqa: BLE001
            return GatewayVerdict(
                case_id=case.case_id, allowed=True, evidence="", latency_ms=0.0, error=str(e)
            )
        return GatewayVerdict(
            case_id=case.case_id,
            allowed=allowed,
            evidence=evidence,
            latency_ms=(time.perf_counter() - t0) * 1000,
        )

    def submit_benign(self, trace: dict) -> GatewayVerdict:
        if self._http is None:
            raise RuntimeError("setup() not called")
        t0 = time.perf_counter()
        try:
            r = self._http.post("/v1/policy/evaluate", json={"trace": trace})
            r.raise_for_status()
            data = r.json()
            allowed = bool(data.get("allow", True))
        except Exception as e:  # noqa: BLE001
            return GatewayVerdict(
                case_id=trace.get("trace_id", "<benign>"),
                allowed=True,
                evidence="",
                latency_ms=0.0,
                error=str(e),
            )
        return GatewayVerdict(
            case_id=trace.get("trace_id", "<benign>"),
            allowed=allowed,
            evidence="",
            latency_ms=(time.perf_counter() - t0) * 1000,
        )
