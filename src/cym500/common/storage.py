"""File-based storage for harvested artefacts.

A flat-file JSONL store keyed by content hash. Cheap, reproducible, easy to
diff. SQLite would be faster for analysis but harder for the student to
inspect by hand; switch later if volume justifies it.
"""
from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import TypeVar

import orjson
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)

DATA_ROOT = Path(os.environ.get("DATA_ROOT", "./data")).resolve()


def content_hash(payload: bytes | str | dict) -> str:
    if isinstance(payload, dict):
        payload = orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class JsonlStore:
    """Append-only JSONL store with dedup-by-content-hash."""

    def __init__(self, relpath: str) -> None:
        self.path = DATA_ROOT / relpath
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seen: set[str] = set()
        if self.path.exists():
            with self.path.open("rb") as f:
                for line in f:
                    try:
                        rec = orjson.loads(line)
                    except orjson.JSONDecodeError:
                        continue
                    if "_hash" in rec:
                        self._seen.add(rec["_hash"])

    def append(self, record: BaseModel) -> bool:
        """Append a record. Returns False if duplicate (already present)."""
        payload = record.model_dump(mode="json")
        h = content_hash(payload)
        if h in self._seen:
            return False
        self._seen.add(h)
        payload["_hash"] = h
        with self.path.open("ab") as f:
            f.write(orjson.dumps(payload))
            f.write(b"\n")
        return True

    def extend(self, records: Iterable[BaseModel]) -> int:
        added = 0
        for rec in records:
            if self.append(rec):
                added += 1
        return added

    def read(self, model: type[T]) -> Iterator[T]:
        if not self.path.exists():
            return
        with self.path.open("rb") as f:
            for line in f:
                rec = orjson.loads(line)
                rec.pop("_hash", None)
                yield model.model_validate(rec)

    def __len__(self) -> int:
        return len(self._seen)
