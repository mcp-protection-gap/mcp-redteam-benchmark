"""Deterministic case expansion and serialisable oracle descriptors.

This module turns a single base attack payload into a base case plus one
variant per text mutation operator, and attaches a serialisable oracle
descriptor to every case so the corpus JSONL is self-describing.

Why a *descriptor* and not a callable: the Phase 3 harness reconstructs
AttackCase objects from the corpus JSONL, where a Python callable cannot be
serialised. The descriptor records what a successful block looks like
(`expected = "block"`) and the canonical malicious `marker` that a
content-inspecting gateway must remove or refuse. Evaluating a descriptor
against a real gateway response is done in Chapter 7 and is out of scope for
corpus construction; here we only guarantee that every case carries one.

All operators are deterministic (no LLM), so the corpus is reproducible.
"""
from __future__ import annotations

from typing import Any, Callable

from cym500.redteam.base import Attack, AttackCase, TargetKind, ThreatClass
from cym500.redteam.mutations import OPERATORS

# Text operators applied to instruction-bearing payloads. split_payload is a
# schema operator (dict in, dict out) and is applied directly by the schema
# attack rather than through mutate(), so it is not listed here.
TEXT_OPS: tuple[str, ...] = ("obfuscation", "paraphrase", "unicode_dressing", "slow_drip")


def mutate(text: str, op: str) -> str:
    """Apply one text mutation operator, returning a single mutated string."""
    if op == "obfuscation":
        return OPERATORS["obfuscation"](text, mode="base64")
    if op == "slow_drip":
        # Represent the dripped fragments as one visibly fragmented string.
        return " <...> ".join(OPERATORS["slow_drip"](text, n=3))
    if op in ("paraphrase", "unicode_dressing"):
        return OPERATORS[op](text)
    raise ValueError(f"unknown text operator: {op}")


def oracle(marker: str, check: str = "marker_in_forwarded_text") -> dict[str, Any]:
    """Build a serialisable oracle descriptor.

    `expected = "block"`: every attack case must be blocked by a correct
    gateway. `marker`: the canonical malicious token whose survival in the
    forwarded payload signals that the gateway failed to neutralise the case.
    `check`: how a Chapter 7 harness should interpret the marker.
    """
    return {"expected": "block", "check": check, "marker": marker}


def expand_text_cases(
    *,
    threat_class: ThreatClass,
    variant_id: str,
    tag: str,
    malicious_text: str,
    make_payload: Callable[[str], dict[str, Any]],
    target: TargetKind,
    marker: str,
    description: str,
    expected_outcome: str,
    derived_from: str | None = None,
) -> list[AttackCase]:
    """Base case + one variant per text operator.

    `make_payload(text)` is a closure that injects the (base or mutated)
    instruction text into the attack's own payload shape, so each attack keeps
    control of its structure while sharing the expansion and oracle logic.
    """
    cases: list[AttackCase] = []
    for op in ("base",) + TEXT_OPS:
        text = malicious_text if op == "base" else mutate(malicious_text, op)
        cases.append(
            AttackCase(
                case_id=Attack.make_id(threat_class, variant_id, f"{tag}-{op}"),
                threat_class=threat_class,
                variant_id=variant_id,
                target=target,
                payload=make_payload(text),
                description=description if op == "base" else f"{description} (mutated with {op}).",
                expected_outcome=expected_outcome,
                derived_from=derived_from,
                metadata={"mutation": op, "oracle": oracle(marker)},
            )
        )
    return cases
