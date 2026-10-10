"""Comparator: Snyk Agent Scan (formerly Invariant Labs mcp-scan).

Agent Scan is a *static* analyser: it connects to a live MCP server, reads the
tool/prompt/resource definitions it advertises, and verifies them (in Snyk's
cloud, gated by SNYK_TOKEN) for tool poisoning, injection and related issues. It
does not sit in the live request path and never sees tool *outputs*, so it can
only score attack cases whose payload is itself a tool definition
(target = tool_description or input_schema). Cases targeting tool outputs,
sampling responses, package manifests or server registrations fall outside its
scanning surface and are recorded as not-blocked with that reason, which is a
faithful account of the comparator's coverage rather than a failure.

Because it is a batch scanner rather than a gateway, the adapter scans the whole
corpus and benign baseline once during setup() and caches per-item verdicts; the
per-item submit_* calls then return the cached result. Each item under test is
served to the scanner by a throwaway stub MCP server (see stub_server.py); items
are batched so one scan covers many tools, keyed by a unique per-item tool name.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from cym500.benchmark.gateways.base import GatewayAdapter, GatewayVerdict
from cym500.common.logging import get_logger
from cym500.common.storage import DATA_ROOT
from cym500.redteam.base import AttackCase

log = get_logger(__name__)

STUB = Path(__file__).with_name("stub_server.py")
CORPUS = Path(DATA_ROOT) / "processed" / "redteam_corpus.jsonl"
BENIGN_DIR = Path(DATA_ROOT) / "raw" / "benign"
# Targets whose payload is a tool definition the scanner can actually inspect.
SCANNABLE_TARGETS = {"tool_description", "input_schema"}
BATCH = 40  # tools served per stub server / scan


class McpScanComparator(GatewayAdapter):
    name = "mcp-scan"
    # The upstream package was renamed: `mcp-scan` is the deprecated 0.4.x line,
    # `snyk-agent-scan` the maintained one. Prefer the current name and fall back,
    # so the scan is not silently run against the older engine.
    binaries = ("snyk-agent-scan", "mcp-scan")
    binary = "snyk-agent-scan"

    def __init__(self) -> None:
        self._verdicts: dict[str, GatewayVerdict] = {}
        self._tmp: list[str] = []

    # -- setup: batch-scan everything, cache verdicts -----------------------
    def setup(self, policy_path: str | None = None) -> None:
        resolved = next((b for b in self.binaries if shutil.which(b)), None)
        if resolved is None:
            raise RuntimeError(
                f"none of {self.binaries} on PATH; `pip install snyk-agent-scan`"
            )
        self.binary = resolved
        log.info("agent_scan_binary", binary=resolved)
        if not os.environ.get("SNYK_TOKEN"):
            raise RuntimeError("SNYK_TOKEN not set; Agent Scan cloud verification requires it")

        items: list[tuple[str, dict]] = []  # (item_id, tool_def)
        # Attack cases with a scannable (tool-definition) payload.
        for case in _iter_corpus():
            if case.target.value in SCANNABLE_TARGETS:
                items.append((case.case_id, _payload_to_tool(case.case_id, case.payload)))
            else:
                self._verdicts[case.case_id] = GatewayVerdict(
                    case_id=case.case_id, allowed=True,
                    evidence=f"outside static tool-scan surface (target={case.target.value})",
                    latency_ms=0.0,
                )
        # Benign traces (all are tool definitions).
        for trace in _iter_benign():
            tid = trace.get("trace_id", "<benign>")
            items.append((tid, _payload_to_tool(tid, trace.get("tool_definitions") or trace.get("payload") or {})))

        for start in range(0, len(items), BATCH):
            self._scan_batch(items[start:start + BATCH])

    def _scan_batch(self, batch: list[tuple[str, dict]]) -> None:
        name_to_id = {t["name"]: iid for iid, t in batch}
        tools = [t for _, t in batch]
        tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(tools, tf); tf.close(); self._tmp.append(tf.name)
        cf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"mcpServers": {"target": {
            "command": "python", "args": [str(STUB)],
            "env": {"MCPSTUB_TOOLS_FILE": tf.name}}}}, cf)
        cf.close(); self._tmp.append(cf.name)

        t0 = time.perf_counter()
        proc = subprocess.run(
            [self.binary, "scan", "--json", "--dangerously-run-mcp-servers",
             "--server-timeout", "60", cf.name],
            capture_output=True, timeout=600, check=False,
        )
        dt = (time.perf_counter() - t0) * 1000 / max(len(batch), 1)
        stdout = proc.stdout.decode(errors="replace")
        failure = _scan_failure(stdout)
        if proc.returncode != 0 or failure:
            # A refused or failed scan must never be scored as "not flagged":
            # Agent Scan exits 0 on a server-side 429 (daily usage limit), so
            # the error has to be read out of the JSON report itself.
            raise RuntimeError(
                f"Agent Scan failed (exit {proc.returncode}): "
                f"{failure or proc.stderr.decode(errors='replace')[-500:]}"
            )
        flagged = _parse_flagged_tools(stdout, [t["name"] for t in tools])
        for tool_name, iid in name_to_id.items():
            blocked = tool_name in flagged
            self._verdicts[iid] = GatewayVerdict(
                case_id=iid, allowed=not blocked,
                evidence=";".join(flagged.get(tool_name, [])) if blocked else "",
                latency_ms=dt,
            )

    def teardown(self) -> None:
        for p in self._tmp:
            try:
                os.unlink(p)
            except OSError:
                pass

    def submit_attack(self, case: AttackCase) -> GatewayVerdict:
        return self._verdicts.get(case.case_id) or GatewayVerdict(
            case_id=case.case_id, allowed=True, evidence="not scanned", latency_ms=0.0)

    def submit_benign(self, trace: dict) -> GatewayVerdict:
        tid = trace.get("trace_id", "<benign>")
        return self._verdicts.get(tid) or GatewayVerdict(
            case_id=tid, allowed=True, evidence="not scanned", latency_ms=0.0)


def _payload_to_tool(item_id: str, payload: dict) -> dict:
    """Build a unique-named MCP tool object from an attack payload / benign def.

    The name is made unique so scan findings map back to exactly one item; the
    description (where poisoning lives) is preserved verbatim.
    """
    safe = "t" + str(abs(hash(item_id)) % (10**10))
    return {
        "name": safe,
        "description": payload.get("description") or payload.get("tool_name") or "",
        "inputSchema": payload.get("input_schema") or payload.get("inputSchema") or {"type": "object"},
    }


def _scan_failure(stdout: str) -> str | None:
    """Return the scanner's error message if the report records a failed scan.

    Unparseable output counts as a failure, as does a config- or server-level
    ``error`` object. Returns None only for a report that completed analysis.
    """
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return "unparseable Agent Scan output"
    if not isinstance(data, dict):
        return "unexpected Agent Scan output shape"
    for cfg in data.values():
        if not isinstance(cfg, dict):
            continue
        errors = [cfg.get("error")] + [
            (s or {}).get("error") for s in (cfg.get("servers") or [])
        ]
        for err in errors:
            if err:
                return str(err.get("message") if isinstance(err, dict) else err)
    return None


def _parse_flagged_tools(stdout: str, served: list[str] | None = None) -> dict[str, list[str]]:
    """Return {tool_name: [issue codes]} for tools Agent Scan flagged.

    Attribution is server-granular in the raw output (an issue's ``reference`` is
    ``[server_idx, None]``), so the per-tool mapping has to come from the issue
    body. Two schemas are handled, because Agent Scan changed its output between
    the first run and re-execution:

    * ``extra_data.affected_tools`` gives indices into the tools served to the
      scanner, in the order they were served. This is exact, and is preferred.
    * Older builds instead named the offending tool inside
      ``extra_data.evidence``/``example``; since every served tool is given a
      unique name, substring-matching that name attributes the issue with no
      collisions.

    ``served`` is the ordered list of tool names in the batch, needed to resolve
    the index form. Without it only the name form is available.
    """
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {}
    flagged: dict[str, list[str]] = {}
    configs = data.values() if isinstance(data, dict) else []
    for cfg in configs:
        if not isinstance(cfg, dict):
            continue
        tool_names = [
            t["name"]
            for s in (cfg.get("servers") or [])
            for t in (((s or {}).get("signature") or {}).get("tools") or [])
            if isinstance(t, dict) and t.get("name")
        ] or list(served or [])
        for issue in cfg.get("issues") or []:
            ed = issue.get("extra_data") or {}
            code = str(issue.get("code") or issue.get("message") or "issue")
            order = list(served or tool_names)
            idxs = ed.get("affected_tools")
            if isinstance(idxs, list) and idxs:
                for i in idxs:
                    if isinstance(i, int) and 0 <= i < len(order):
                        flagged.setdefault(order[i], []).append(code)
                continue
            blob = " ".join(
                str(x) for x in
                (issue.get("message"), ed.get("evidence"), ed.get("example"), ed.get("title"))
                if x
            )
            for name in tool_names:
                if name in blob:
                    flagged.setdefault(name, []).append(code)
    return flagged


def _iter_corpus():
    from cym500.benchmark.harness import _iter_corpus as it
    yield from it()


def _iter_benign():
    from cym500.benchmark.harness import _iter_benign as it
    yield from it()
