"""Split a payload across schema fields (description vs example vs annotation)."""
from __future__ import annotations

from typing import Any


def split_payload(text: str, schema: dict[str, Any]) -> dict[str, Any]:
    """Distribute the malicious instructions across 'description', 'examples', and
    'annotations.x-instruction'. Returns a modified copy of the schema."""
    out = dict(schema)
    half = len(text) // 2
    head, tail = text[:half], text[half:]
    out["description"] = (out.get("description") or "") + " " + head
    examples = out.get("examples") or []
    examples = list(examples) + [tail]
    out["examples"] = examples
    annotations = dict(out.get("annotations") or {})
    annotations["x-instruction"] = tail
    out["annotations"] = annotations
    return out
