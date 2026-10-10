"""Probe the seven Anthropic reference servers through the Path-2 sandbox.

The enumerated records for the `anthropic-servers` registry carry no install
command, so the Phase-1 sandbox run skipped them. This script supplies the
published launch command for each, probes it with the same hardened sandbox and
`tools/list` handshake, and applies the same Tier-1 hygiene detectors and A3
capability inference as the rest of the tool corpus.

Results go to data/processed/reference_tools.jsonl and
data/results/posture/reference_servers.json. The Phase-1 corpus
(tools.jsonl, 3,887 descriptions) is deliberately left untouched, since these
servers were probed after it was frozen.

Usage: python scripts/probe_reference_servers.py
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from cym500.classification.rules import evaluate_tool, infer_scope
from cym500.common.schema import Provenance, ServerRecord, SourceLocation
from cym500.common.storage import DATA_ROOT, JsonlStore
from cym500.sandbox.installer import SandboxInstaller

# Launch commands as published in the modelcontextprotocol/servers README.
REFERENCE_SERVERS = {
    "everything": "npx -y @modelcontextprotocol/server-everything",
    "fetch": "uvx mcp-server-fetch",
    "filesystem": "npx -y @modelcontextprotocol/server-filesystem /tmp",
    "git": "uvx mcp-server-git",
    "memory": "npx -y @modelcontextprotocol/server-memory",
    "sequentialthinking": "npx -y @modelcontextprotocol/server-sequential-thinking",
    "time": "uvx mcp-server-time",
}

OUT_TOOLS = "processed/reference_tools.jsonl"
OUT_SUMMARY = Path(DATA_ROOT) / "results" / "posture" / "reference_servers.json"


def main() -> None:
    installer = SandboxInstaller()
    store = JsonlStore(OUT_TOOLS)
    Path(DATA_ROOT, OUT_TOOLS).unlink(missing_ok=True)
    summary: dict = {"probed_at": datetime.now(UTC).isoformat(), "servers": {}}

    for name, cmd in REFERENCE_SERVERS.items():
        record = ServerRecord(
            id=f"anthropic-servers:src/{name}",
            name=name,
            install_command=cmd,
            provenance=Provenance.OFFICIAL,
            source=SourceLocation(
                kind="sandbox",
                registry="anthropic-servers",
                url="https://github.com/modelcontextprotocol/servers",
                fetched_at=datetime.now(UTC),
            ),
        )
        result = installer.probe(record, install_timeout=120, probe_timeout=120, require_network=True)
        tools = []
        for t in result.tools:
            flags = [f.value for f in evaluate_tool(t)]
            scopes = sorted(s.value for s in infer_scope(t))
            store.append(t)
            tools.append({"name": t.name, "flags": flags, "capabilities": scopes})
        summary["servers"][name] = {
            "install_command": cmd,
            "success": result.success,
            "error": result.error,
            "n_tools": len(tools),
            "tools": tools,
        }
        print(f"{name}: ok={result.success} tools={len(tools)} err={result.error}")

    all_tools = [t for s in summary["servers"].values() for t in s["tools"]]
    summary["n_tools"] = len(all_tools)
    summary["n_flagged"] = sum(1 for t in all_tools if t["flags"])
    summary["n_any_capability"] = sum(1 for t in all_tools if t["capabilities"])
    OUT_SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    OUT_SUMMARY.write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ("n_tools", "n_flagged", "n_any_capability")}))


if __name__ == "__main__":
    main()
