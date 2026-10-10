"""Which configurations route their MCP traffic through a gateway or proxy.

Read off each entry's declared command and args, like axis A10. A gateway is
recognised by its launch shape, never guessed from a server's name. The two
in-path gateways benchmarked in Chapter 7 are matched by package or image;
Docker's MCP gateway by ``docker mcp gateway`` or the ``docker/mcp-gateway``
image; and ``mcp-proxy``, a stdio-to-HTTP bridge with no content inspection,
is counted separately so that it is not mistaken for a security control.
"""
from __future__ import annotations

from collections import Counter
from typing import Iterable

_BENCHMARKED = {
    "lasso": {"mcp-gateway"},  # Lasso Security's PyPI package
    "contextforge": {"mcp-contextforge-gateway", "mcpgateway", "mcp-context-forge"},
}


def _package(word: str) -> str:
    """A launch word reduced to its package name: path, scope and version dropped."""
    word = word.rsplit("/", 1)[-1]
    for sep in ("==", "@", ":"):
        word = word.split(sep, 1)[0] if not word.startswith(sep) else word
    return word


def entry_gateway(entry: dict) -> str | None:
    """The gateway or proxy an entry launches, or None."""
    cmd = str(entry.get("command") or "").lower()
    args = [str(a).lower() for a in entry.get("args") or []]
    if "docker/mcp-gateway" in " ".join(args) or (
        _package(cmd) == "docker" and "mcp" in args and "gateway" in args
    ):
        return "docker-mcp-gateway"
    packages = {_package(w) for w in [cmd, *args]}
    for name, needles in _BENCHMARKED.items():
        if packages & needles:
            return name
    if packages & {"mcp-proxy", "mcp_proxy"}:
        return "mcp-proxy"
    return None


def gateway_routing(configs: Iterable[dict]) -> dict:
    """Configurations (not entries) routing through each gateway or proxy."""
    per: Counter[str] = Counter()
    n = 0
    for cfg in configs:
        n += 1
        found = {g for e in cfg.get("server_entries") or [] if (g := entry_gateway(e))}
        per.update(found)
    return {"n_configs": n, "per_gateway": dict(per)}
