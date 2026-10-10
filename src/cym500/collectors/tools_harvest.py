"""Flatten registry-served tool descriptions into processed/tools.jsonl.

Path 1 of the Chapter 5 tool-description corpus: some registries (Smithery)
return each server's full `tools` array directly, so we can populate the
hygiene corpus without installing or running anything. This step reads
servers.jsonl and emits one ToolDescription per registry-served tool into the
same tools.jsonl that the sandbox probe (Path 2) writes to, so downstream
hygiene coding consumes a single union.
"""
from __future__ import annotations

from cym500.common.logging import get_logger
from cym500.common.schema import ServerRecord, ToolDescription
from cym500.common.storage import JsonlStore

log = get_logger(__name__)


def harvest_registry_tools() -> dict[str, int]:
    servers = JsonlStore("processed/servers.jsonl")
    tools_store = JsonlStore("processed/tools.jsonl")

    n_servers_with_tools = 0
    n_tools = 0
    seen: set[tuple[str, str]] = set()
    for rec in servers.read(ServerRecord):
        if not rec.tools:
            continue
        n_servers_with_tools += 1
        for tool in rec.tools:
            tool = tool if isinstance(tool, ToolDescription) else ToolDescription(**tool)
            # Dedup by (server_id, tool name): the store hash includes the volatile
            # fetched_at, so identical tools re-seen across records would not be
            # caught otherwise.
            k = (tool.server_id, tool.name)
            if k in seen:
                continue
            seen.add(k)
            # ServerRecord.tools already carry a registry SourceLocation and
            # server_id (set by the adapter), so they are complete records.
            if tools_store.append(tool):
                n_tools += 1

    result = {"servers_with_tools": n_servers_with_tools, "tools": n_tools}
    log.info("registry_tools_harvested", **result)
    return result
