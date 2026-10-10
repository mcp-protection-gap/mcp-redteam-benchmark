"""Aggregate statistics for Chapters 4 and 5.

Reads processed/{servers,tools,configs}.jsonl and produces frequency tables
that the chapter draft can pull directly from data/results/posture/.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

from cym500.analysis.stride import stride_for_config
from cym500.analysis.supplychain import supply_chain_concentration
from cym500.classification.rules import evaluate_tool, infer_scope
from cym500.common.redaction import non_loopback
from cym500.common.schema import ConfigArtefact, ServerRecord, ToolDescription
from cym500.common.storage import JsonlStore, DATA_ROOT

OUT = Path(DATA_ROOT) / "results" / "posture"

# Author verification of the secret findings (hash prefixes and verdicts only;
# no secret values). A finding verified as a documentation placeholder is not a
# leaked credential and is excluded from every secret-derived count.
VERIFICATION = Path(__file__).resolve().parents[3] / "config" / "secret_verification.csv"


def _verified_placeholders(path: Path = VERIFICATION) -> set[str]:
    import csv

    if not path.exists():
        return set()
    with path.open() as f:
        return {r["finding_sha256_prefix"] for r in csv.DictReader(f) if r["verdict"] == "placeholder"}


_PLACEHOLDERS = _verified_placeholders()


def credential_findings(cfg: ConfigArtefact) -> list:
    """Secret findings that are credentials, not placeholders (rule or verification)."""
    return [
        s for s in cfg.secret_findings
        if not s.placeholder and s.sha256[:8] not in _PLACEHOLDERS
    ]


def server_posture() -> dict:
    servers = JsonlStore("processed/servers.jsonl")
    by_transport: Counter[str] = Counter()
    by_auth: Counter[str] = Counter()
    by_provenance: Counter[str] = Counter()
    by_registry: Counter[str] = Counter()
    n = 0
    for s in servers.read(ServerRecord):
        n += 1
        by_transport[s.transport.value] += 1
        by_auth[s.auth.value] += 1
        by_provenance[s.provenance.value] += 1
        if s.source.registry:
            by_registry[s.source.registry] += 1
    return {
        "n_servers": n,
        "transport": dict(by_transport),
        "auth": dict(by_auth),
        "provenance": dict(by_provenance),
        "by_registry": dict(by_registry),
    }


# Scopes whose misuse yields code execution, persistence or credential access,
# as against those that only widen reach. Used for the high-privilege rollup.
_HIGH_PRIVILEGE_SCOPES = {"exec", "fs_write", "secrets_access", "process_control"}


def tool_hygiene() -> dict:
    tools = JsonlStore("processed/tools.jsonl")
    flag_counts: Counter[str] = Counter()
    by_server: dict[str, Counter[str]] = defaultdict(Counter)
    scope_counts: Counter[str] = Counter()
    scopes_per_tool: Counter[int] = Counter()
    n = 0
    n_high_privilege = 0
    for t in tools.read(ToolDescription):
        n += 1
        flags = evaluate_tool(t)
        for f in flags:
            flag_counts[f.value] += 1
            by_server[t.server_id][f.value] += 1
        scopes = {s.value for s in infer_scope(t)}
        for s in scopes:
            scope_counts[s] += 1
        scopes_per_tool[len(scopes)] += 1
        if scopes & _HIGH_PRIVILEGE_SCOPES:
            n_high_privilege += 1
    return {
        "n_tools": n,
        "flag_frequency": dict(flag_counts),
        "servers_with_any_flag": sum(1 for c in by_server.values() if c),
        "scope_frequency": dict(scope_counts.most_common()),
        "scopes_per_tool": {str(k): v for k, v in sorted(scopes_per_tool.items())},
        "n_any_scope": n - scopes_per_tool[0],
        "n_high_privilege_scope": n_high_privilege,
    }


_CRED_KEY_WORDS = ("key", "token", "secret", "password", "passwd", "credential")

# Keys a client uses to pre-approve tool invocation without asking the user.
_CONSENT_BYPASS_KEYS = ("autoApprove", "alwaysAllow")


def _as_str(v: object) -> str:
    return v if isinstance(v, str) else ""


def _as_dict(v: object) -> dict:
    return v if isinstance(v, dict) else {}


def entry_transport(entry: dict) -> str:
    """A1 transport, read off declared fields. No coder judgement.

    An explicitly declared type/transport wins. Otherwise the launch shape is
    decisive: a `command` is a subprocess (stdio), a bare `url` is remote.
    """
    declared = (_as_str(entry.get("type")) or _as_str(entry.get("transport"))).lower()
    if declared:
        if declared in {"stdio", "http", "sse", "websocket"}:
            return declared
        if declared in {"streamablehttp", "streamable-http", "http-stream"}:
            return "http"
        if declared in {"remote", "url"}:
            return "remote_unspecified"
        return "other_declared"
    if entry.get("command"):
        return "stdio"
    if entry.get("url"):
        return "remote_unspecified"
    return "undeterminable"


def entry_auth(entry: dict) -> str:
    """A2 auth posture, read off declared fields. No coder judgement."""
    headers = _as_dict(entry.get("headers"))
    for k, v in headers.items():
        kl = _as_str(k).lower()
        if "authorization" in kl or "auth" in kl or "bearer" in _as_str(v).lower():
            return "header_auth"
        if any(w in kl for w in _CRED_KEY_WORDS):
            return "header_auth"
    env = _as_dict(entry.get("env"))
    if any(any(w in _as_str(k).lower() for w in _CRED_KEY_WORDS) for k in env):
        return "env_credential"
    if env:
        return "env_no_credential"
    return "none_declared"


def entry_consent_bypass(entry: dict) -> bool:
    """Whether the entry pre-approves tool calls, removing the confirmation step."""
    return any(bool(entry.get(k)) for k in _CONSENT_BYPASS_KEYS)


def _config_conditions(cfg: ConfigArtefact) -> set[str]:
    """Deterministic config-level conditions used for the STRIDE join."""
    cond: set[str] = set()
    if credential_findings(cfg):
        cond.add("secret_leak")
    if non_loopback(cfg.private_endpoints):
        cond.add("private_endpoint")
    for e in cfg.server_entries:
        if not isinstance(e, dict):
            continue
        if entry_consent_bypass(e):
            cond.add("consent_bypass")
        auth = entry_auth(e)
        if auth == "env_credential":
            cond.add("credential_in_plaintext_env")
        if entry_transport(e) in {"http", "sse", "websocket", "remote_unspecified"}:
            if auth in {"none_declared", "env_no_credential"}:
                cond.add("unauthenticated_remote")
    return cond


def config_findings() -> dict:
    configs = JsonlStore("processed/configs.jsonl")
    secret_kinds: Counter[str] = Counter()
    by_transport: Counter[str] = Counter()
    by_auth: Counter[str] = Counter()
    by_condition: Counter[str] = Counter()
    by_stride: Counter[str] = Counter()
    by_cond_count: Counter[int] = Counter()
    by_cond_pair: Counter[str] = Counter()
    n = 0
    n_entries = 0
    n_with_secret = 0
    n_with_private_endpoint = 0
    n_private_endpoint_refs = 0
    n_with_consent_bypass = 0
    n_consent_bypass_entries = 0
    distinct_secrets: defaultdict[str, set[str]] = defaultdict(set)
    for c in configs.read(ConfigArtefact):
        n += 1
        creds = credential_findings(c)
        if creds:
            n_with_secret += 1
            for s in creds:
                secret_kinds[s.kind] += 1
                distinct_secrets[s.kind].add(s.sha256)
        endpoints = non_loopback(c.private_endpoints)
        if endpoints:
            n_with_private_endpoint += 1
            n_private_endpoint_refs += len(endpoints)
        seen_bypass = False
        for e in c.server_entries:
            if not isinstance(e, dict):
                continue
            n_entries += 1
            by_transport[entry_transport(e)] += 1
            by_auth[entry_auth(e)] += 1
            if entry_consent_bypass(e):
                n_consent_bypass_entries += 1
                seen_bypass = True
        if seen_bypass:
            n_with_consent_bypass += 1
        conditions = _config_conditions(c)
        for cond in conditions:
            by_condition[cond] += 1
        by_cond_count[len(conditions)] += 1
        for a, b in combinations(sorted(conditions), 2):
            by_cond_pair[f"{a}+{b}"] += 1
        for cat in stride_for_config(sorted(conditions)):
            by_stride[cat] += 1
    return {
        "n_configs": n,
        "n_server_entries": n_entries,
        "n_with_secret": n_with_secret,
        "n_with_private_endpoint": n_with_private_endpoint,
        "n_private_endpoint_refs": n_private_endpoint_refs,
        "n_with_consent_bypass": n_with_consent_bypass,
        "n_consent_bypass_entries": n_consent_bypass_entries,
        "secret_kinds": dict(secret_kinds),
        "distinct_secrets": {k: len(v) for k, v in distinct_secrets.items()},
        "transport": dict(by_transport),
        "auth": dict(by_auth),
        "conditions": dict(by_condition),
        "condition_count": {str(k): v for k, v in sorted(by_cond_count.items())},
        "n_clean": by_cond_count[0],
        "n_multi_condition": sum(v for k, v in by_cond_count.items() if k >= 2),
        "condition_pairs": dict(by_cond_pair.most_common()),
        "stride": dict(by_stride),
    }


def write_all() -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    out = {
        "servers": server_posture(),
        "tools": tool_hygiene(),
        "configs": config_findings(),
        "supplychain": supply_chain_concentration(),
    }
    for name, data in out.items():
        with (OUT / f"{name}.json").open("w") as f:
            json.dump(data, f, indent=2)
    return out
