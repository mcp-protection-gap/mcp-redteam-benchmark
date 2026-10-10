"""Slow-drip: split the payload across N tool descriptions/messages so any
single artefact looks benign. Returns a list of fragments to be placed in
multiple targets."""
from __future__ import annotations


def slow_drip(text: str, n: int = 3) -> list[str]:
    if n <= 1:
        return [text]
    chunk = max(1, len(text) // n)
    fragments: list[str] = []
    for i in range(n):
        start = i * chunk
        end = (i + 1) * chunk if i < n - 1 else len(text)
        fragments.append(text[start:end])
    return fragments
