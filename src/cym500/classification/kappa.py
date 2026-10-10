"""Cohen's kappa for inter-coder agreement.

Compares two human-labelled CSVs (e.g. labels/coderA.csv, labels/coderB.csv)
on a chosen multi-label column (default: hygiene_flags). For multi-label
columns we compute kappa per label and report the macro-averaged value as
well as per-label kappa for transparency.
"""
from __future__ import annotations

import csv
from collections.abc import Iterable
from pathlib import Path

from cym500.common.storage import DATA_ROOT


def _read_labels(path: Path, key_cols: Iterable[str], label_col: str) -> dict[tuple, set[str]]:
    out: dict[tuple, set[str]] = {}
    with path.open() as f:
        r = csv.DictReader(f)
        for row in r:
            key = tuple(row[c] for c in key_cols)
            labels = {x for x in row.get(label_col, "").split(";") if x}
            out[key] = labels
    return out


def cohens_kappa_binary(a: list[bool], b: list[bool]) -> float:
    if len(a) != len(b) or not a:
        return float("nan")
    n = len(a)
    a_t = sum(a)
    b_t = sum(b)
    a_f = n - a_t
    b_f = n - b_t
    po = sum(1 for x, y in zip(a, b, strict=True) if x == y) / n
    pe = (a_t * b_t + a_f * b_f) / (n * n)
    if pe == 1:
        return 1.0 if po == 1 else float("nan")
    return (po - pe) / (1 - pe)


def per_label_kappa(
    coder_a: str = "labels/coderA.csv",
    coder_b: str = "labels/coderB.csv",
    key_cols: tuple[str, ...] = ("server_id", "tool_name"),
    label_col: str = "hygiene_flags",
    universe: Iterable[str] | None = None,
) -> dict[str, float]:
    a = _read_labels(Path(DATA_ROOT) / coder_a, key_cols, label_col)
    b = _read_labels(Path(DATA_ROOT) / coder_b, key_cols, label_col)
    keys = sorted(set(a) & set(b))

    if universe is None:
        universe = sorted({l for s in (*a.values(), *b.values()) for l in s})

    out: dict[str, float] = {}
    for label in universe:
        av = [label in a[k] for k in keys]
        bv = [label in b[k] for k in keys]
        out[label] = cohens_kappa_binary(av, bv)
    if out:
        out["__macro__"] = sum(v for v in out.values() if v == v) / max(1, sum(1 for v in out.values() if v == v))
    return out
