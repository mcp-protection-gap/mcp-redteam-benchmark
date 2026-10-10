"""Standards mapping table.

Maps observed flag/condition strings to relevant clauses in standards.
This is reference data; the entries should be cross-checked against the
authoritative texts before they appear in the dissertation.
"""
from __future__ import annotations

from cym500.common.schema import HygieneFlag, Scope, SupplyChainSignal

STANDARDS_MAP: dict[str, dict[str, list[str]]] = {
    HygieneFlag.HIDDEN_INSTRUCTION.value: {
        "OWASP LLM Top 10": ["LLM01: Prompt Injection"],
        "NIST AI RMF": ["MEASURE 2.7"],
        "EU AI Act": ["Art. 15 (cybersecurity)"],
        "MCP Spec v1.x": ["Tool definition transparency"],
    },
    HygieneFlag.UNICODE_TRICK.value: {
        "OWASP LLM Top 10": ["LLM01: Prompt Injection"],
        "ISO/IEC 42001": ["8.3.1 Data quality"],
    },
    HygieneFlag.NAME_CAPABILITY_MISMATCH.value: {
        "OWASP LLM Top 10": ["LLM06: Excessive Agency", "LLM01"],
        "NIST AI RMF": ["GOVERN 1.4"],
    },
    Scope.SECRETS_ACCESS.value: {
        "OWASP LLM Top 10": ["LLM06: Excessive Agency"],
        "NIST AI RMF": ["MAP 5.1"],
        "EU AI Act": ["Art. 10 (data governance)"],
        "Cyber Resilience Act": ["Annex I (1)(c) protection from unauthorised access"],
    },
    Scope.EXEC.value: {
        "OWASP LLM Top 10": ["LLM06", "LLM02: Insecure Output Handling"],
        "Cyber Resilience Act": ["Annex I (1)(b)"],
    },
    SupplyChainSignal.RECENT_MAINTAINER_CHANGE.value: {
        "Cyber Resilience Act": ["Annex I (2) supply chain"],
        "OWASP LLM Top 10": ["LLM05: Supply Chain"],
    },
    SupplyChainSignal.TYPO_SQUAT_CANDIDATE.value: {
        "OWASP LLM Top 10": ["LLM05: Supply Chain"],
    },
}


def standards_for(flag: str) -> dict[str, list[str]]:
    return STANDARDS_MAP.get(flag, {})
