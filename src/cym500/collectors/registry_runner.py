"""Run all registry adapters and persist to data/processed/servers.jsonl."""
from __future__ import annotations

import yaml

from cym500.collectors.registries import ADAPTERS
from cym500.common.logging import get_logger
from cym500.common.schema import ServerRecord
from cym500.common.storage import JsonlStore

log = get_logger(__name__)


def collect_all(config_path: str = "config/collectors.yaml") -> dict[str, int]:
    with open(config_path, "rb") as f:
        cfg = yaml.safe_load(f)
    enabled = cfg.get("registries", {}).get("enabled", [])
    limit = cfg.get("registries", {}).get("per_registry_limit")

    store = JsonlStore("processed/servers.jsonl")
    counts: dict[str, int] = {}

    for name in enabled:
        cls = ADAPTERS.get(name)
        if not cls:
            log.warning("unknown_registry", name=name)
            continue
        log.info("registry_start", name=name)
        added = 0
        seen_ids: set[str] = set()
        try:
            with cls() as adapter:
                for rec in adapter.enumerate(limit=limit):
                    # Dedup by stable id: the store hashes full content (incl. the
                    # per-run fetched_at), so it cannot catch a server re-enumerated
                    # within a run. Guard on id here as a safety net.
                    if rec.id in seen_ids:
                        continue
                    seen_ids.add(rec.id)
                    if store.append(rec):
                        added += 1
        except Exception as e:  # noqa: BLE001
            log.error("registry_failed", name=name, error=str(e))
        counts[name] = added
        log.info("registry_done", name=name, added=added)

    return counts
