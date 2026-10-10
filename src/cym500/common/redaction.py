"""Secret detection and redaction.

Two-layer detector: a curated regex set for common API-key shapes, and
detect-secrets for entropy-based catch-all. We never persist the raw secret;
only a salted SHA-256 and a four-char prefix/suffix preview.

Why salted: if two repos contain the same leaked token, we still want to
correlate them (so the salt is constant across the corpus, not per-record).
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass

from cym500.common.schema import SecretFinding, SourceLocation

# Salt is constant across the corpus to allow correlation without storing
# raw values. Set CYM500_SECRET_SALT in env; default below is fine for dev.
_SALT = os.environ.get("CYM500_SECRET_SALT", "cym500-2026-salt").encode()

REGEX_PATTERNS: dict[str, re.Pattern[str]] = {
    "github_pat": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "github_pat_fine": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    "github_oauth": re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),
    "openai_api_key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    "anthropic_api_key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{30,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "private_key": re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
}

PRIVATE_HOST_PATTERNS = [
    re.compile(r"\bhttps?://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)"),
    re.compile(r"\bhttps?://[A-Za-z0-9.-]+\.(?:internal|corp|local|lan|intra)\b"),
]

# A loopback URL says only that a server runs on the same machine; it discloses
# nothing about a network, so it is not a private endpoint. Records harvested
# before this rule still carry loopback entries, hence the explicit filter.
_LOOPBACK = re.compile(r"^https?://(?:localhost|127\.\d+\.\d+\.\d+|\[::1\])(?:[:/]|$)", re.I)


def is_loopback(endpoint: str) -> bool:
    return bool(_LOOPBACK.match(endpoint))


def non_loopback(endpoints: list[str]) -> list[str]:
    return [e for e in endpoints if not is_loopback(e)]


# A match can have a credential's shape and still be a placeholder copied from
# documentation ("xoxb-your-bot-token-here", "ghp_XXXX..."). Placeholders are
# still redacted (harmless either way) but are not counted as leaked secrets.
_PLACEHOLDER_WORDS = re.compile(
    r"your|here|token|example|placeholder|optional|changeme|dummy|sample|replace|insert|xxxx",
    re.I,
)
# Real Slack tokens carry numeric workspace/user segments: xoxb-<digits>-<digits>-...
_SLACK_REAL = re.compile(r"^xox[baprs]-\d+-\d+")


def is_placeholder(kind: str, value: str) -> bool:
    """True if a regex hit is a documentation placeholder rather than a credential.

    Deterministic: a body that is one repeated character, or that contains a
    placeholder word, is a placeholder; a Slack token without its numeric
    segments cannot be real. JWTs are left to their own review, since a sample
    JWT is structurally valid.
    """
    body = value.split("_", 1)[-1] if kind.startswith("github") else value
    if len(set(body.replace("-", ""))) <= 2:
        return True
    if kind == "slack_token" and not _SLACK_REAL.match(value):
        return True
    if kind != "jwt" and _PLACEHOLDER_WORDS.search(body):
        return True
    return False


@dataclass(frozen=True, slots=True)
class RawHit:
    kind: str
    value: str
    start: int
    end: int


def _hash_secret(value: str) -> str:
    return hashlib.sha256(_SALT + value.encode("utf-8")).hexdigest()


def _preview(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def scan_text(text: str) -> list[RawHit]:
    hits: list[RawHit] = []
    for kind, pattern in REGEX_PATTERNS.items():
        for m in pattern.finditer(text):
            hits.append(RawHit(kind=kind, value=m.group(0), start=m.start(), end=m.end()))
    return hits


def find_private_endpoints(text: str) -> list[str]:
    found: list[str] = []
    for pat in PRIVATE_HOST_PATTERNS:
        for m in pat.finditer(text):
            found.append(m.group(0))
    return list(dict.fromkeys(found))


def redact_text(text: str, hits: list[RawHit]) -> str:
    if not hits:
        return text
    out = text
    for hit in sorted(hits, key=lambda h: -h.start):
        out = out[: hit.start] + f"<REDACTED:{hit.kind}:{_hash_secret(hit.value)[:12]}>" + out[hit.end:]
    return out


def hits_to_findings(hits: list[RawHit], source: SourceLocation) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for hit in hits:
        findings.append(
            SecretFinding(
                kind=hit.kind,
                detector="regex",
                redacted_value=_preview(hit.value),
                sha256=_hash_secret(hit.value),
                location=source,
                placeholder=is_placeholder(hit.kind, hit.value),
            )
        )
    return findings


def redact_dict(obj: dict) -> tuple[dict, list[RawHit]]:
    """Walk a dict, redact string leaves, return (redacted, hits)."""
    all_hits: list[RawHit] = []

    def _walk(node):
        if isinstance(node, str):
            hits = scan_text(node)
            all_hits.extend(hits)
            return redact_text(node, hits)
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(v) for v in node]
        return node

    return _walk(obj), all_hits
