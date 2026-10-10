"""Smithery (smithery.ai) registry adapter.

Verified 2026-07-05: the list endpoint at https://registry.smithery.ai/servers
paginates via a `pagination` object ({currentPage,totalPages,totalCount}); the
detail endpoint https://registry.smithery.ai/servers/{qualifiedName} returns the
server's `connections` and, crucially, its full `tools` array (name, description,
inputSchema). We fetch detail per server so tool descriptions land directly in
ServerRecord.tools — no install or sandbox needed for Smithery-hosted servers.
"""
from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime

from tenacity import retry, stop_after_attempt, wait_exponential

from cym500.collectors.registries.base import RegistryAdapter
from cym500.common.logging import get_logger
from cym500.common.schema import (
    AuthPosture,
    Provenance,
    ServerRecord,
    SourceLocation,
    ToolDescription,
    Transport,
)

log = get_logger(__name__)


class SmitheryAdapter(RegistryAdapter):
    name = "smithery"

    _LIST_URL = "https://registry.smithery.ai/servers"
    _DETAIL_URL = "https://registry.smithery.ai/servers/{id}"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        token = os.environ.get("SMITHERY_API_KEY")
        if token:
            self._http.headers["Authorization"] = f"Bearer {token}"

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=2, min=2, max=30))
    def _list(self, page: int) -> dict:
        r = self._http.get(self._LIST_URL, params={"page": page, "pageSize": 100})
        r.raise_for_status()
        return r.json()

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=2, min=2, max=30))
    def _detail(self, server_id: str) -> dict:
        r = self._http.get(self._DETAIL_URL.format(id=server_id))
        r.raise_for_status()
        return r.json()

    def enumerate(self, limit: int | None = None) -> Iterator[ServerRecord]:
        seen = 0
        page = 1
        seen_ids: set[str] = set()
        while True:
            data = self._list(page)
            items = data.get("servers") or data.get("items") or []
            if not items:
                break
            for item in items:
                # Smithery's paginated listing overlaps across pages; skip
                # servers we have already emitted (also avoids re-fetching the
                # per-server detail endpoint, which is the expensive call).
                sid = item.get("qualifiedName") or item.get("id") or item.get("name")
                if sid in seen_ids:
                    continue
                rec = self._normalise(item)
                if rec is None:
                    continue
                seen_ids.add(sid)
                yield rec
                seen += 1
                if limit and seen >= limit:
                    return
            pagination = data.get("pagination") or {}
            current = pagination.get("currentPage", page)
            total = pagination.get("totalPages")
            if total is not None:
                if current >= total:
                    break
            elif not data.get("hasNextPage", len(items) >= 100):
                break
            page += 1

    def _normalise(self, item: dict) -> ServerRecord | None:
        try:
            now = datetime.now(UTC)
            server_id = item.get("qualifiedName") or item.get("id") or item.get("name")
            if not server_id:
                return None

            # The list item is thin; the detail endpoint carries connections and
            # the tools array. Fetch it, but degrade gracefully if it fails.
            detail: dict = {}
            try:
                detail = self._detail(server_id)
            except Exception as e:  # noqa: BLE001
                log.warning("smithery_detail_failed", server=server_id, error=str(e))

            connections = detail.get("connections") or item.get("connections") or [{}]
            transport_str = connections[0].get("type", "unknown")
            record = ServerRecord(
                id=f"smithery:{server_id}",
                name=detail.get("displayName") or item.get("displayName") or server_id,
                description=detail.get("description") or item.get("description"),
                transport=_map_transport(transport_str),
                auth=_map_auth(detail.get("security") or item.get("auth")),
                install_command=item.get("install", {}).get("command"),
                repository_url=item.get("repository", {}).get("url"),
                homepage=item.get("homepage"),
                maintainer=item.get("owner") or item.get("publisher"),
                last_commit_at=_parse_dt(item.get("updatedAt")),
                provenance=_map_provenance({**item, **detail}),
                tools=_tools(detail, server_id, now),
                source=SourceLocation(
                    kind="registry",
                    registry="smithery",
                    url=f"https://smithery.ai/server/{server_id}",
                    fetched_at=now,
                ),
            )
            return record
        except Exception as e:  # noqa: BLE001
            log.warning("smithery_normalise_failed", error=str(e), item_keys=list(item.keys()))
            return None


def _tools(detail: dict, server_id: str, now: datetime) -> list[ToolDescription]:
    out: list[ToolDescription] = []
    for t in detail.get("tools") or []:
        name = t.get("name")
        if not name:
            continue
        out.append(
            ToolDescription(
                name=name,
                description=t.get("description"),
                input_schema=t.get("inputSchema"),
                output_schema=t.get("outputSchema"),
                annotations=t.get("annotations"),
                raw=t,
                server_id=f"smithery:{server_id}",
                source=SourceLocation(
                    kind="registry",
                    registry="smithery",
                    url=f"https://smithery.ai/server/{server_id}",
                    fetched_at=now,
                ),
            )
        )
    return out


def _map_transport(s: str) -> Transport:
    s = (s or "").lower()
    if s in ("stdio", "subprocess"):
        return Transport.STDIO
    if s in ("sse", "http+sse"):
        return Transport.SSE
    if s in ("http", "streamable-http", "https"):
        return Transport.HTTP
    if s == "websocket":
        return Transport.WEBSOCKET
    return Transport.UNKNOWN


def _map_auth(value) -> AuthPosture:
    if value is None:
        return AuthPosture.UNKNOWN
    if value is False or (isinstance(value, str) and value.lower() in ("none", "false", "")):
        return AuthPosture.NONE
    if isinstance(value, str):
        v = value.lower()
        if "oauth" in v:
            return AuthPosture.OAUTH
        if "bearer" in v:
            return AuthPosture.BEARER
        if "api" in v or "key" in v:
            return AuthPosture.API_KEY
        if "mtls" in v or "mutual" in v:
            return AuthPosture.MTLS
    if isinstance(value, dict):
        if value.get("oauth") or value.get("type") == "oauth":
            return AuthPosture.OAUTH
        if value.get("apiKey") or value.get("type") == "api_key":
            return AuthPosture.API_KEY
    return AuthPosture.UNKNOWN


def _map_provenance(item: dict) -> Provenance:
    if item.get("verified") or item.get("official"):
        return Provenance.OFFICIAL
    if item.get("publisher") in {"anthropic", "modelcontextprotocol"}:
        return Provenance.OFFICIAL
    return Provenance.COMMUNITY


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
