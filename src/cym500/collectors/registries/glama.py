"""glama.ai registry adapter."""
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


class GlamaAdapter(RegistryAdapter):
    name = "glama"
    _LIST_URL = "https://glama.ai/api/mcp/v1/servers"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        token = os.environ.get("GLAMA_API_KEY")
        if token:
            self._http.headers["Authorization"] = f"Bearer {token}"

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=2, min=2, max=30))
    def _list(self, cursor: str | None) -> dict:
        params = {"first": 100}
        if cursor:
            params["after"] = cursor
        r = self._http.get(self._LIST_URL, params=params)
        r.raise_for_status()
        return r.json()

    def enumerate(self, limit: int | None = None) -> Iterator[ServerRecord]:
        cursor = None
        seen = 0
        while True:
            data = self._list(cursor)
            edges = data.get("servers") or data.get("edges") or []
            if not edges:
                break
            for edge in edges:
                node = edge.get("node", edge)
                rec = self._normalise(node)
                if rec:
                    yield rec
                    seen += 1
                    if limit and seen >= limit:
                        return
            page_info = data.get("pageInfo") or {}
            cursor = page_info.get("endCursor")
            if not cursor or not page_info.get("hasNextPage", False):
                break

    def _normalise(self, item: dict) -> ServerRecord | None:
        try:
            now = datetime.now(UTC)
            slug = item.get("slug") or item.get("id")
            if not slug:
                return None
            return ServerRecord(
                id=f"glama:{slug}",
                name=item.get("name") or slug,
                description=item.get("description"),
                transport=Transport.UNKNOWN,
                auth=AuthPosture.UNKNOWN,
                repository_url=item.get("repository", {}).get("url") if isinstance(item.get("repository"), dict) else item.get("repository"),
                homepage=item.get("homepage"),
                # `attributes` is a list of tags (e.g. ["hosting:remote-capable"]),
                # not a dict; the glama listing exposes no reliable maintainer field.
                maintainer=None,
                provenance=Provenance.COMMUNITY,
                source=SourceLocation(
                    kind="registry",
                    registry="glama",
                    url=f"https://glama.ai/mcp/servers/{slug}",
                    fetched_at=now,
                ),
            )
        except Exception as e:  # noqa: BLE001
            log.warning("glama_normalise_failed", error=str(e))
            return None
