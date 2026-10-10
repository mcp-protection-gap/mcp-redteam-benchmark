"""Harvest MCP client configs from public GitHub repositories.

Uses the GitHub code-search API. Requires GITHUB_TOKEN with repo:public_repo
scope; without it, the API caps at 10 req/min and the corpus will be too
small to be useful.

Pilot queries are configured in config/collectors.yaml. Each query is run,
results are paginated, contents are fetched, secrets and private endpoints
are detected and redacted, and the redacted artefact is appended to the
JSONL store.

Ethics note: this harvester only stores REDACTED content. Raw secrets are
hashed and previewed (first 4 / last 4 chars) for the disclosure tracker;
the raw value never lands on disk. See docs/methodology/ethics-brief.md.
"""
from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import httpx
import orjson
import yaml
from tenacity import retry, stop_after_attempt, wait_exponential

from cym500.common.logging import get_logger
from cym500.common.redaction import (
    find_private_endpoints,
    hits_to_findings,
    redact_dict,
)
from cym500.common.schema import ConfigArtefact, SourceLocation
from cym500.common.storage import JsonlStore, content_hash

GITHUB_API = "https://api.github.com"
log = get_logger(__name__)


class GitHubCodeSearch:
    """Thin wrapper around the GitHub code-search API."""

    def __init__(self, token: str | None = None) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN")
        if not self.token:
            log.warning("github_token_missing", hint="set GITHUB_TOKEN in .env")
        self._client = httpx.Client(
            base_url=GITHUB_API,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
            },
            timeout=30.0,
        )

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=2, min=2, max=60))
    def _get(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        r = self._client.get(path, params=params)
        if r.status_code == 403 and "rate limit" in r.text.lower():
            reset = int(r.headers.get("X-RateLimit-Reset", "0"))
            log.warning("rate_limited", reset=reset)
            r.raise_for_status()
        r.raise_for_status()
        return r

    def search(self, query: str, per_page: int = 100, max_pages: int = 10):
        for page in range(1, max_pages + 1):
            r = self._get(
                "/search/code",
                params={"q": query, "per_page": per_page, "page": page},
            )
            data = r.json()
            items = data.get("items", [])
            if not items:
                break
            for item in items:
                yield item
            if len(items) < per_page:
                break

    def fetch_blob(self, repo_full_name: str, file_sha: str) -> bytes | None:
        r = self._get(f"/repos/{repo_full_name}/git/blobs/{file_sha}")
        body = r.json()
        if body.get("encoding") != "base64":
            return None
        import base64
        return base64.b64decode(body["content"])

    def close(self) -> None:
        self._client.close()


def _looks_like_mcp_config(parsed: dict) -> bool:
    """Quality filter: is this actually an MCP client config?"""
    if not isinstance(parsed, dict):
        return False
    if "mcpServers" in parsed and isinstance(parsed["mcpServers"], dict):
        return True
    if "servers" in parsed and isinstance(parsed["servers"], dict):
        # Cursor uses "servers" key in some variants
        return any(
            isinstance(v, dict) and ("command" in v or "url" in v) for v in parsed["servers"].values()
        )
    return False


def _server_entries(parsed: dict) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for key in ("mcpServers", "servers"):
        if key in parsed and isinstance(parsed[key], dict):
            for name, conf in parsed[key].items():
                if isinstance(conf, dict):
                    entries.append({"name": name, **conf})
    return entries


def collect(config_path: str = "config/collectors.yaml") -> int:
    """Run all GitHub queries from config, store deduped redacted artefacts.

    Returns count of new (non-duplicate) artefacts added.
    """
    with open(config_path, "rb") as f:
        cfg = yaml.safe_load(f)
    queries = cfg.get("github_configs", {}).get("queries", [])
    per_page = cfg.get("github_configs", {}).get("per_page", 100)
    max_pages = cfg.get("github_configs", {}).get("max_pages", 10)

    store = JsonlStore("processed/configs.jsonl")
    api = GitHubCodeSearch()
    added = 0

    try:
        for q in queries:
            log.info("github_search_start", query=q)
            for item in api.search(q, per_page=per_page, max_pages=max_pages):
                repo = item.get("repository", {}).get("full_name")
                path = item.get("path")
                sha = item.get("sha")
                if not (repo and path and sha):
                    continue
                blob = api.fetch_blob(repo, sha)
                if blob is None:
                    continue
                try:
                    parsed = orjson.loads(blob)
                except orjson.JSONDecodeError:
                    continue
                if not _looks_like_mcp_config(parsed):
                    continue

                redacted, hits = redact_dict(parsed)
                source = SourceLocation(
                    kind="github",
                    url=item.get("html_url"),
                    repo=repo,
                    path=path,
                    fetched_at=datetime.now(UTC),
                )
                artefact = ConfigArtefact(
                    id=content_hash(redacted)[:16],
                    raw_redacted=redacted,
                    server_entries=_server_entries(redacted),
                    secret_findings=hits_to_findings(hits, source),
                    private_endpoints=find_private_endpoints(orjson.dumps(parsed).decode()),
                    source=source,
                )
                if store.append(artefact):
                    added += 1
            log.info("github_search_done", query=q, total=len(store))
    finally:
        api.close()

    log.info("github_collect_complete", added=added, total=len(store))
    return added
