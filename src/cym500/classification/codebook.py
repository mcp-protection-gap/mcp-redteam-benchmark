"""Machine-readable codebook for inter-coder agreement and labelling.

This file mirrors docs/methodology/codebook.md and MUST be updated in the
same commit as that doc. Bump CODEBOOK_VERSION when an axis changes.
"""
from __future__ import annotations

CODEBOOK_VERSION = "0.2.0"

AXES: dict[str, dict] = {
    "transport": {
        "values": ["stdio", "sse", "http", "websocket", "unknown"],
        "rule": "Lift from registry metadata; verify against repo manifest where available.",
    },
    "auth_posture": {
        "values": ["none", "api_key", "bearer", "oauth", "mtls", "unknown"],
        "rule": "Read from manifest 'auth' field; if absent, infer from required env vars.",
    },
    "scope": {
        "values": [
            "fs_read",
            "fs_write",
            "network_egress",
            "exec",
            "secrets_access",
            "process_control",
            "database",
        ],
        "rule": (
            "Lift from declared capabilities in tool descriptions. Multi-label. "
            "If declared scope < observed scope (e.g. tool body shells out but "
            "declares only fs_read), flag NAME_CAPABILITY_MISMATCH and use union."
        ),
    },
    "provenance": {
        "values": ["official", "community_verified", "community", "anonymous", "abandoned"],
        "rule": (
            "official: published by the protocol/vendor (Anthropic, MCP org). "
            "community_verified: in Anthropic servers repo /community or registry "
            "carries a 'verified' badge. abandoned: no commits in 180 days. "
            "anonymous: no identifiable maintainer."
        ),
    },
    "hygiene": {
        "values": [
            "hidden_instruction",
            "unicode_trick",
            "name_capability_mismatch",
            "embedded_prompt",
            "excessive_scope_request",
            "obfuscated_description",
        ],
        "rule": "Multi-label. Apply automated detectors first; human reviews flagged.",
    },
    "supply_chain": {
        "values": [
            "unpinned_dependency",
            "recent_maintainer_change",
            "typo_squat_candidate",
            "new_publisher",
        ],
        "rule": (
            "Multi-label. unpinned: any range or floating tag in manifest. "
            "typo_squat: Levenshtein <= 2 from a 'official' name."
        ),
    },
    "secret_kinds_present": {
        "values": [
            "github_pat",
            "github_oauth",
            "openai_api_key",
            "anthropic_api_key",
            "aws_access_key",
            "google_api_key",
            "slack_token",
            "private_key",
            "jwt",
            "other_high_entropy",
        ],
        "rule": "Multi-label. Detector union of regex set + detect-secrets entropy.",
    },
}


SCOPE_INFERENCE_HINTS: dict[str, str] = {
    "fs_read": "tool description mentions file/path/read or schema includes path",
    "fs_write": "write/save/append/delete/overwrite verbs in description or input schema",
    "network_egress": "fetch/http/url/request verbs OR uses requests/httpx/fetch in code",
    "exec": "shell/exec/spawn/run verbs OR subprocess imports",
    "secrets_access": "tool reads env vars or credentials files",
    "database": "sql/query/insert/db verbs",
}
