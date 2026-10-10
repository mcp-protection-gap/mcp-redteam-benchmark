"""Driver: read servers.jsonl, probe each in the sandbox, persist tools.jsonl."""
from __future__ import annotations

from cym500.common.logging import get_logger
from cym500.common.schema import ServerRecord, ToolDescription
from cym500.common.storage import JsonlStore
from cym500.sandbox.installer import SandboxInstaller

log = get_logger(__name__)


def run(
    limit: int | None = None,
    install_timeout: int = 60,
    probe_timeout: int = 120,
    require_network: bool = False,
    command_prefix: str | None = None,
) -> dict:
    """Probe the installable servers in servers.jsonl (Path 2).

    limit caps the number of *installable* servers probed (not raw rows).
    require_network runs the container on a bridge network so `npx`/`uvx`
    install commands can fetch their packages. command_prefix (e.g. "npx" or
    "uvx") restricts probing to matching install commands.
    """
    servers = JsonlStore("processed/servers.jsonl")
    tools_store = JsonlStore("processed/tools.jsonl")
    failures_store = JsonlStore("processed/sandbox_failures.jsonl")

    installer = SandboxInstaller()
    n_ok = 0
    n_fail = 0
    n_probed = 0

    for rec in servers.read(ServerRecord):
        if not rec.install_command:
            continue
        if command_prefix and not rec.install_command.startswith(command_prefix):
            continue
        if limit is not None and n_probed >= limit:
            break
        n_probed += 1
        log.info("probe_start", server=rec.id, cmd=rec.install_command)
        result = installer.probe(
            rec,
            install_timeout=install_timeout,
            probe_timeout=probe_timeout,
            require_network=require_network,
        )
        if result.success:
            for t in result.tools:
                tools_store.append(t)
            n_ok += 1
        else:
            detail = result.raw.get("stderr") or result.raw.get("logs") or ""
            failures_store.append(
                _FailureRecord(
                    server_id=rec.id,
                    install_command=rec.install_command,
                    error=result.error or "unknown",
                    detail=detail[-2000:],
                    duration_s=result.duration_s,
                )
            )
            n_fail += 1
        log.info("probe_done", server=rec.id, ok=result.success, n_tools=len(result.tools))

    return {"ok": n_ok, "fail": n_fail, "probed": n_probed}


# Lightweight Pydantic model just for the failures log.
from pydantic import BaseModel


class _FailureRecord(BaseModel):
    server_id: str
    install_command: str | None = None
    error: str
    detail: str = ""
    duration_s: float
