"""Base contract for a registry adapter.

Each adapter is responsible for:
1. Enumerating server records from one registry source.
2. Normalising them into ServerRecord (common/schema.py).

Adapters MUST NOT install or run servers. That is the sandbox's job.
"""
from __future__ import annotations

import abc
from collections.abc import Iterator

import httpx

from cym500.common.schema import ServerRecord


class RegistryAdapter(abc.ABC):
    """Pull server records from one registry."""

    name: str = "base"

    def __init__(self, http: httpx.Client | None = None) -> None:
        self._http = http or httpx.Client(timeout=30.0, headers={"User-Agent": "cym500/0.1"})

    @abc.abstractmethod
    def enumerate(self, limit: int | None = None) -> Iterator[ServerRecord]:
        """Yield ServerRecords from this registry. May be paginated internally."""

    def close(self) -> None:
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
