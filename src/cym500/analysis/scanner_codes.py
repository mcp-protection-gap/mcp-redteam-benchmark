"""Rater-free check on scanner false positives, from the scanner's own codes.

Agent Scan attaches an issue code to every flag. Codes it raised on at least one
attack case are the ones that carry its detection; a benign flag carrying only
codes it never raised on any attack is, by the scanner's own vocabulary, a
different kind of finding (a capability or exposure warning) rather than a
poisoning verdict. The split needs no human judgement and is re-executable
against a per-case verdict file.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def _codes(evidence: str) -> set[str]:
    return {c for c in (evidence or "").split(";") if c}


def code_split(verdicts_path: str | Path) -> dict:
    """Summarise which issue codes fired on attacks and on benign definitions."""
    records = [json.loads(line) for line in Path(verdicts_path).read_text().splitlines() if line]
    attack_codes: Counter[str] = Counter()
    benign_codes: Counter[str] = Counter()
    benign_flags: list[set[str]] = []
    for r in records:
        if not r.get("blocked"):
            continue
        codes = _codes(r.get("evidence", ""))
        if r.get("kind") == "attack":
            attack_codes.update(codes)
        elif r.get("kind") == "benign":
            benign_codes.update(codes)
            benign_flags.append(codes)
    detecting = set(attack_codes)
    only_non_detecting = sum(1 for c in benign_flags if c and not (c & detecting))
    return {
        "attack_codes": dict(attack_codes),
        "benign_codes": dict(benign_codes),
        "n_benign_flags": len(benign_flags),
        "n_benign_flags_only_codes_never_raised_on_attacks": only_non_detecting,
    }
