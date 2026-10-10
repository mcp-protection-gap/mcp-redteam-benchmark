"""Pydantic models shared across collectors, classification, and analysis.

Codebook axes are documented in docs/methodology/codebook.md. The enums here
are the machine-readable counterpart and must stay in sync with that doc.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl


class Transport(StrEnum):
    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"
    WEBSOCKET = "websocket"
    UNKNOWN = "unknown"


class AuthPosture(StrEnum):
    NONE = "none"
    API_KEY = "api_key"
    BEARER = "bearer"
    OAUTH = "oauth"
    MTLS = "mtls"
    UNKNOWN = "unknown"


class Scope(StrEnum):
    FS_READ = "fs_read"
    FS_WRITE = "fs_write"
    NETWORK_EGRESS = "network_egress"
    EXEC = "exec"
    SECRETS_ACCESS = "secrets_access"
    PROCESS_CONTROL = "process_control"
    DATABASE = "database"


class Provenance(StrEnum):
    OFFICIAL = "official"
    COMMUNITY_VERIFIED = "community_verified"
    COMMUNITY = "community"
    ANONYMOUS = "anonymous"
    ABANDONED = "abandoned"


class HygieneFlag(StrEnum):
    HIDDEN_INSTRUCTION = "hidden_instruction"
    UNICODE_TRICK = "unicode_trick"
    NAME_CAPABILITY_MISMATCH = "name_capability_mismatch"
    EMBEDDED_PROMPT = "embedded_prompt"
    EXCESSIVE_SCOPE_REQUEST = "excessive_scope_request"
    OBFUSCATED_DESCRIPTION = "obfuscated_description"


class SupplyChainSignal(StrEnum):
    UNPINNED_DEPENDENCY = "unpinned_dependency"
    RECENT_MAINTAINER_CHANGE = "recent_maintainer_change"
    TYPO_SQUAT_CANDIDATE = "typo_squat_candidate"
    NEW_PUBLISHER = "new_publisher"


class SourceLocation(BaseModel):
    """Where an artefact was harvested from."""
    kind: Literal["github", "registry", "sandbox"] = Field(...)
    url: HttpUrl | None = None
    repo: str | None = None
    path: str | None = None
    registry: str | None = None
    commit_sha: str | None = None
    fetched_at: datetime


class ToolDescription(BaseModel):
    """A single tool exposed by an MCP server, as returned from tools/list."""
    name: str
    description: str | None = None
    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None
    raw: dict[str, Any]
    source: SourceLocation
    server_id: str
    hygiene_flags: list[HygieneFlag] = Field(default_factory=list)


class ServerRecord(BaseModel):
    """Normalised MCP server record from a registry or repo enumeration."""
    id: str
    name: str
    description: str | None = None
    transport: Transport = Transport.UNKNOWN
    auth: AuthPosture = AuthPosture.UNKNOWN
    declared_scopes: list[Scope] = Field(default_factory=list)
    install_command: str | None = None
    repository_url: HttpUrl | None = None
    homepage: HttpUrl | None = None
    maintainer: str | None = None
    last_commit_at: datetime | None = None
    provenance: Provenance = Provenance.COMMUNITY
    supply_chain_signals: list[SupplyChainSignal] = Field(default_factory=list)
    tools: list[ToolDescription] = Field(default_factory=list)
    source: SourceLocation


class SecretFinding(BaseModel):
    """A redacted finding for the disclosure tracker. The raw secret is never stored."""
    kind: str  # e.g. "github_pat", "openai_api_key"
    detector: str  # e.g. "detect-secrets:HighEntropyString"
    redacted_value: str  # only first/last 4 chars retained
    sha256: str
    location: SourceLocation
    # A documentation placeholder with a credential's shape. Redacted, but not
    # counted as a leaked secret. Defaults False for records made before the
    # rule existed; those were verified by inspection instead.
    placeholder: bool = False


class ConfigArtefact(BaseModel):
    """A client-side MCP config (claude_desktop_config.json, mcp.json, etc.)."""
    id: str
    raw_redacted: dict[str, Any]
    server_entries: list[dict[str, Any]] = Field(default_factory=list)
    secret_findings: list[SecretFinding] = Field(default_factory=list)
    private_endpoints: list[str] = Field(default_factory=list)
    source: SourceLocation
