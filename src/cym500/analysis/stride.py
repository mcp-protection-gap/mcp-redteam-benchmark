"""STRIDE + LINDDUN mapping for the MCP threat surface.

Map flag sets and observed conditions to threat categories. The mapping is a
data table; the function only joins the table to a labelled corpus.

Source for the mapping rationale: docs/methodology/threat-model.md.
"""
from __future__ import annotations

from cym500.common.schema import HygieneFlag, Scope, SupplyChainSignal

# STRIDE: Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege
STRIDE_MAP: dict[str, list[str]] = {
    HygieneFlag.HIDDEN_INSTRUCTION.value: ["Tampering", "Elevation of privilege"],
    HygieneFlag.UNICODE_TRICK.value: ["Spoofing", "Tampering"],
    HygieneFlag.NAME_CAPABILITY_MISMATCH.value: ["Spoofing", "Elevation of privilege"],
    HygieneFlag.EMBEDDED_PROMPT.value: ["Tampering"],
    HygieneFlag.EXCESSIVE_SCOPE_REQUEST.value: ["Elevation of privilege"],
    HygieneFlag.OBFUSCATED_DESCRIPTION.value: ["Tampering", "Repudiation"],
    Scope.NETWORK_EGRESS.value: ["Information disclosure"],
    Scope.SECRETS_ACCESS.value: ["Information disclosure", "Elevation of privilege"],
    Scope.EXEC.value: ["Elevation of privilege", "Denial of service"],
    SupplyChainSignal.RECENT_MAINTAINER_CHANGE.value: ["Tampering", "Spoofing"],
    SupplyChainSignal.TYPO_SQUAT_CANDIDATE.value: ["Spoofing"],
    SupplyChainSignal.UNPINNED_DEPENDENCY.value: ["Tampering"],
}

# Config-level conditions. Unlike the flag map above these are read directly
# off declared fields of a harvested configuration and need no coder judgement,
# so the join below is a data table applied to a deterministic input. Each
# entry is grounded in the STRIDE x MCP table of docs/methodology/threat-model.md.
CONFIG_STRIDE_MAP: dict[str, list[str]] = {
    # "Credential leakage via tool calls" (I); credential_leakage -> I, E.
    "secret_leak": ["Information disclosure", "Elevation of privilege"],
    # "Private-endpoint exposure in committed configs" (I).
    "private_endpoint": ["Information disclosure"],
    # "Over-permissive scope grants in registration" (E) plus "absence of audit
    # trails on tool calls" (R): autoApprove/alwaysAllow removes the
    # per-invocation human confirmation step.
    "consent_bypass": ["Elevation of privilege", "Repudiation"],
    # Client <-> Server is untrusted in both directions; a remote endpoint with
    # no declared authentication admits impersonation and in-transit tampering.
    "unauthenticated_remote": ["Spoofing", "Tampering"],
    # Credential material named in a plaintext, version-controlled artefact.
    "credential_in_plaintext_env": ["Information disclosure"],
}


def stride_for_config(conditions: list[str]) -> set[str]:
    out: set[str] = set()
    for c in conditions:
        out.update(CONFIG_STRIDE_MAP.get(c, []))
    return out


# LINDDUN: Linkability, Identifiability, Non-repudiation, Detectability,
# Disclosure of information, Unawareness, Non-compliance.
LINDDUN_MAP: dict[str, list[str]] = {
    Scope.SECRETS_ACCESS.value: ["Disclosure of information"],
    Scope.NETWORK_EGRESS.value: ["Disclosure of information", "Linkability"],
    HygieneFlag.HIDDEN_INSTRUCTION.value: ["Unawareness"],
    HygieneFlag.OBFUSCATED_DESCRIPTION.value: ["Detectability", "Unawareness"],
    HygieneFlag.NAME_CAPABILITY_MISMATCH.value: ["Unawareness"],
}


def stride_for(flags: list[str]) -> set[str]:
    out: set[str] = set()
    for f in flags:
        out.update(STRIDE_MAP.get(f, []))
    return out


def linddun_for(flags: list[str]) -> set[str]:
    out: set[str] = set()
    for f in flags:
        out.update(LINDDUN_MAP.get(f, []))
    return out
