"""pulsemcp.com registry adapter."""
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
    Transport,
)

log = get_logger(__name__)


class PulseMcpAdapter(RegistryAdapter):
    name = "pulsemcp"
    _LIST_URL = "https://api.pulsemcp.com/v0beta/servers"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        token = os.environ.get("PULSEMCP_API_KEY")
        if token:
            self._http.headers["X-API-Key"] = token

    _PAGE_SIZE = 100

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=2, min=2, max=30))
    def _list(self, offset: int) -> dict:
        # The v0beta API paginates by offset/count_per_page (not page/limit).
        r = self._http.get(
            self._LIST_URL, params={"offset": offset, "count_per_page": self._PAGE_SIZE}
        )
        r.raise_for_status()
        return r.json()

    def enumerate(self, limit: int | None = None) -> Iterator[ServerRecord]:
        offset = 0
        seen = 0
        while True:
            data = self._list(offset)
            items = data.get("servers") or data.get("data") or []
            if not items:
                break
            for item in items:
                rec = self._normalise(item)
                if rec:
                    yield rec
                    seen += 1
                    if limit and seen >= limit:
                        return
            if len(items) < self._PAGE_SIZE:
                break
            offset += self._PAGE_SIZE

    def _normalise(self, item: dict) -> ServerRecord | None:
        try:
            now = datetime.now(UTC)
            # v0beta records carry no id/slug; derive a stable slug from the URL tail.
            url = item.get("url") or ""
            slug = url.rstrip("/").rsplit("/", 1)[-1] or item.get("name")
            if not slug:
                return None
            remote = (item.get("remotes") or [{}])[0]
            return ServerRecord(
                id=f"pulsemcp:{slug}",
                name=item.get("name") or slug,
                description=item.get("short_description")
                or item.get("EXPERIMENTAL_ai_generated_description"),
                transport=_map_transport(remote.get("transport")),
                auth=_map_auth(remote.get("authentication_method")),
                install_command=_install_command(item),
                repository_url=item.get("source_code_url") or item.get("github_url"),
                homepage=item.get("external_url") or url or None,
                maintainer=item.get("vendor") or item.get("author"),
                provenance=Provenance.COMMUNITY,
                source=SourceLocation(
                    kind="registry",
                    registry="pulsemcp",
                    url=url or f"https://www.pulsemcp.com/servers/{slug}",
                    fetched_at=now,
                ),
            )
        except Exception as e:  # noqa: BLE001
            log.warning("pulsemcp_normalise_failed", error=str(e))
            return None


def _map_transport(value: str | None) -> Transport:
    v = (value or "").lower()
    if v in ("stdio", "subprocess"):
        return Transport.STDIO
    if v in ("sse", "http+sse"):
        return Transport.SSE
    if v in ("http", "streamable_http", "streamable-http", "https"):
        return Transport.HTTP
    if v == "websocket":
        return Transport.WEBSOCKET
    return Transport.UNKNOWN


def _map_auth(value: str | None) -> AuthPosture:
    v = (value or "").lower()
    if not v or v == "none":
        return AuthPosture.NONE if v == "none" else AuthPosture.UNKNOWN
    if "oauth" in v:
        return AuthPosture.OAUTH
    if "bearer" in v:
        return AuthPosture.BEARER
    if "api" in v or "key" in v:
        return AuthPosture.API_KEY
    if "mtls" in v or "mutual" in v:
        return AuthPosture.MTLS
    return AuthPosture.UNKNOWN


def _install_command(item: dict) -> str | None:
    """Synthesise a stdio launch command from package metadata, when present."""
    pkg = item.get("package_name")
    if not pkg:
        return None
    registry = (item.get("package_registry") or "").lower()
    if registry in ("npm", "node"):
        return f"npx -y {pkg}"
    if registry in ("pypi", "pip", "python"):
        return f"uvx {pkg}"
    return None
