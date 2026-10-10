"""Adapter for the Anthropic `modelcontextprotocol/servers` reference repo.

Walks the top-level subdirectories under `src/` and `community/` (if present)
on the default branch and produces one ServerRecord per directory. Treats the
`src/` tree as Provenance.OFFICIAL and `community/` as COMMUNITY_VERIFIED.
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
    Transport,
)

log = get_logger(__name__)

REPO = "modelcontextprotocol/servers"


class AnthropicServersAdapter(RegistryAdapter):
    name = "anthropic-servers"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        token = os.environ.get("GITHUB_TOKEN")
        self._http.headers["Accept"] = "application/vnd.github+json"
        self._http.headers["X-GitHub-Api-Version"] = "2022-11-28"
        if token:
            self._http.headers["Authorization"] = f"Bearer {token}"

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=2, min=2, max=30))
    def _list_dir(self, path: str) -> list[dict]:
        r = self._http.get(f"https://api.github.com/repos/{REPO}/contents/{path}")
        if r.status_code == 404:
            return []
        r.raise_for_status()
        return r.json()

    def enumerate(self, limit: int | None = None) -> Iterator[ServerRecord]:
        seen = 0
        for subdir, provenance in (("src", Provenance.OFFICIAL), ("community", Provenance.COMMUNITY_VERIFIED)):
            for entry in self._list_dir(subdir):
                if entry.get("type") != "dir":
                    continue
                rec = self._normalise(entry, subdir, provenance)
                if rec:
                    yield rec
                    seen += 1
                    if limit and seen >= limit:
                        return

    def _normalise(self, entry: dict, subdir: str, provenance: Provenance) -> ServerRecord | None:
        try:
            now = datetime.now(UTC)
            name = entry["name"]
            return ServerRecord(
                id=f"anthropic-servers:{subdir}/{name}",
                name=name,
                description=None,
                transport=Transport.UNKNOWN,
                auth=AuthPosture.UNKNOWN,
                repository_url=f"https://github.com/{REPO}/tree/main/{subdir}/{name}",
                provenance=provenance,
                source=SourceLocation(
                    kind="registry",
                    registry="anthropic-servers",
                    url=f"https://github.com/{REPO}/tree/main/{subdir}/{name}",
                    repo=REPO,
                    path=f"{subdir}/{name}",
                    fetched_at=now,
                ),
            )
        except Exception as e:  # noqa: BLE001
            log.warning("anthropic_normalise_failed", error=str(e))
            return None
