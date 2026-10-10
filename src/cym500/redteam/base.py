"""Base contracts for the red-team corpus.

A corpus entry is one AttackCase. Each AttackCase has:
  - threat_class (one of the eight CYM100 categories)
  - variant_id (e.g. obfuscation operator applied)
  - payload (the artefact used to attack: tool description text, server config,
    follow-up tool call, etc.)
  - target (kind of MCP entity the payload targets: tool description,
    server registration, sampling response, ...)
  - oracle (the function that determines whether the attack succeeded against
    a given gateway: bool result + evidence string)

Phase 3 reuses this contract to drive the gateway benchmark: each gateway
under test is given the AttackCase, returns a verdict, and metrics are
computed against the oracle's ground truth.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable


class ThreatClass(StrEnum):
    TOOL_POISONING = "tool_poisoning"
    RUG_PULL = "rug_pull"
    CROSS_SERVER_EXFIL = "cross_server_exfil"
    SAMPLING_INJECTION = "sampling_injection"
    SCHEMA_POISONING = "schema_poisoning"
    SUPPLY_CHAIN = "supply_chain"
    PROMPT_INJECTION_VIA_OUTPUT = "prompt_injection_via_output"
    CREDENTIAL_LEAKAGE = "credential_leakage"


class TargetKind(StrEnum):
    TOOL_DESCRIPTION = "tool_description"
    SERVER_REGISTRATION = "server_registration"
    SAMPLING_RESPONSE = "sampling_response"
    INPUT_SCHEMA = "input_schema"
    PACKAGE_MANIFEST = "package_manifest"
    TOOL_OUTPUT = "tool_output"


@dataclass(slots=True)
class AttackCase:
    """One concrete attack instance, ready for execution."""
    case_id: str
    threat_class: ThreatClass
    variant_id: str
    target: TargetKind
    payload: dict[str, Any]
    description: str
    expected_outcome: str
    derived_from: str | None = None  # Phase 1 artefact id, if grounded in observed data
    oracle: Callable[[Any], "AttackOutcome"] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AttackOutcome:
    success: bool
    evidence: str
    blocked_by: str | None = None  # set by harness when a gateway blocks the case


class Attack(abc.ABC):
    """One PoC. Generates one or more AttackCase instances."""

    threat_class: ThreatClass
    variant_id: str

    @abc.abstractmethod
    def cases(self) -> list[AttackCase]:
        ...

    @staticmethod
    def make_id(threat: ThreatClass, variant: str, suffix: str) -> str:
        return f"{threat.value}::{variant}::{suffix}"
