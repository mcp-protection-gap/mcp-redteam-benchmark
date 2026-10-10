"""Comparator: Cisco AI mcp-scanner, YARA analyzer (offline, key-free).

A second, independent static content scanner to sit alongside Snyk Agent Scan in
the benchmark. Where Agent Scan verifies tool descriptions in Snyk's cloud, this
runs entirely offline against a bundled set of YARA rules (tool_poisoning,
prompt_injection, data_exfiltration, credential_harvesting, command_injection,
code_execution, ...), so it needs no API key and its results are fully
reproducible.

It shares Agent Scan's static nature: it inspects tool definitions, so it can
only score attack cases whose payload is a tool definition (target =
tool_description or input_schema); the remaining classes are outside its surface
and recorded as not blocked. The scanner's ``static --tools <file>`` mode reads a
whole tools/list array in one offline pass, so the entire corpus and benign
baseline are scanned in two invocations and per-item verdicts are cached.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time

from cym500.benchmark.comparators.mcp_scan import (
    SCANNABLE_TARGETS,
    _iter_benign,
    _iter_corpus,
    _payload_to_tool,
)
from cym500.benchmark.gateways.base import GatewayAdapter, GatewayVerdict
from cym500.common.logging import get_logger
from cym500.redteam.base import AttackCase

log = get_logger(__name__)


class CiscoYaraComparator(GatewayAdapter):
    name = "mcp-scanner-yara"
    binary = "mcp-scanner"

    def __init__(self) -> None:
        self._verdicts: dict[str, GatewayVerdict] = {}

    def setup(self, policy_path: str | None = None) -> None:
        if not shutil.which(self.binary):
            raise RuntimeError(f"{self.binary} not on PATH; `pip install cisco-ai-mcp-scanner`")

        attack_items: list[tuple[str, dict]] = []
        for case in _iter_corpus():
            if case.target.value in SCANNABLE_TARGETS:
                attack_items.append((case.case_id, _payload_to_tool(case.case_id, case.payload)))
            else:
                self._verdicts[case.case_id] = GatewayVerdict(
                    case_id=case.case_id, allowed=True,
                    evidence=f"outside static tool-scan surface (target={case.target.value})",
                    latency_ms=0.0,
                )
        benign_items = [
            (t.get("trace_id", "<benign>"),
             _payload_to_tool(t.get("trace_id", "<benign>"), t.get("tool_definitions") or t.get("payload") or {}))
            for t in _iter_benign()
        ]
        self._scan(attack_items)
        self._scan(benign_items)

    def _scan(self, items: list[tuple[str, dict]]) -> None:
        if not items:
            return
        name_to_id = {t["name"]: iid for iid, t in items}
        tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"tools": [t for _, t in items]}, tf)
        tf.close()
        # No key must leak in: the YARA analyzer is purely local.
        env = {k: v for k, v in os.environ.items()
               if k not in ("MCP_SCANNER_LLM_API_KEY", "MCP_SCANNER_API_KEY")}
        t0 = time.perf_counter()
        proc = subprocess.run(
            [self.binary, "--analyzers", "yara", "--format", "raw",
             "static", "--tools", tf.name],
            capture_output=True, timeout=600, check=False, env=env,
        )
        dt = (time.perf_counter() - t0) * 1000 / max(len(items), 1)
        os.unlink(tf.name)
        flagged = _parse_unsafe_tools(proc.stdout.decode(errors="replace"))
        for tool_name, iid in name_to_id.items():
            blocked = tool_name in flagged
            self._verdicts[iid] = GatewayVerdict(
                case_id=iid, allowed=not blocked,
                evidence=";".join(flagged.get(tool_name, [])) if blocked else "",
                latency_ms=dt,
            )

    def teardown(self) -> None:
        return

    def submit_attack(self, case: AttackCase) -> GatewayVerdict:
        return self._verdicts.get(case.case_id) or GatewayVerdict(
            case_id=case.case_id, allowed=True, evidence="not scanned", latency_ms=0.0)

    def submit_benign(self, trace: dict) -> GatewayVerdict:
        tid = trace.get("trace_id", "<benign>")
        return self._verdicts.get(tid) or GatewayVerdict(
            case_id=tid, allowed=True, evidence="not scanned", latency_ms=0.0)


def _parse_unsafe_tools(stdout: str) -> dict[str, list[str]]:
    """Return {tool_name: [threat names]} for tools mcp-scanner marked unsafe.

    ``--format raw`` emits JSON with ``scan_results[]``, one entry per tool
    carrying ``tool_name``, ``is_safe`` and per-analyzer ``findings``. A tool is
    blocked when ``is_safe`` is false.
    """
    i = stdout.find("{")
    if i < 0:
        return {}
    try:
        data = json.loads(stdout[i:])
    except json.JSONDecodeError:
        return {}
    flagged: dict[str, list[str]] = {}
    for r in data.get("scan_results") or []:
        if not isinstance(r, dict) or r.get("is_safe", True):
            continue
        name = r.get("tool_name")
        if not name:
            continue
        threats: list[str] = []
        for a in (r.get("findings") or {}).values():
            if isinstance(a, dict):
                threats.extend(a.get("threat_names") or [])
        flagged[name] = threats or ["unsafe"]
    return flagged
