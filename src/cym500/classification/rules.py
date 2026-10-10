"""Automated heuristics for hygiene and scope flags.

These are first-pass labellers. Hits are reviewed by a human before they
become final labels. Recall over precision: prefer flagging ambiguous cases
for review over silently passing them.
"""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable

from cym500.common.schema import HygieneFlag, Scope, ToolDescription

# Hidden instructions: tags or strings that look like the description is
# trying to instruct an LLM rather than describe the tool.
HIDDEN_INSTRUCTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS?|HIDDEN|SECRET|PROMPT)[^>]*>", re.I),
    re.compile(r"\bignore (?:all )?previous\b", re.I),
    re.compile(r"\bdisregard (?:the |any |all )?(?:above|prior)\b", re.I),
    re.compile(r"\b(?:before|when) (?:using|calling)[^.]{1,80}you must\b", re.I),
    re.compile(r"\bdo not (?:reveal|disclose|mention)\b", re.I),
    re.compile(r"\bchain[- ]of[- ]thought\b", re.I),
    re.compile(r"\bAS AN AI\b", re.I),
    re.compile(r"```\s*system\s*", re.I),
]

# Zero-width and direction-control characters used to hide payloads.
ZERO_WIDTH = {
    "​",  # ZERO WIDTH SPACE
    "‌",
    "‍",
    "‎",  # LEFT-TO-RIGHT MARK
    "‏",  # RIGHT-TO-LEFT MARK
    "‪",  # LRE
    "‫",  # RLE
    "‬",  # PDF
    "‭",  # LRO
    "‮",  # RLO
    "⁦",
    "⁧",
    "⁨",
    "⁩",
    "﻿",  # ZWNBSP / BOM
    "­",  # SOFT HYPHEN
}

# Homoglyph spoofing is detected as *mixed-script tokens*: a single word that
# mixes Latin with Cyrillic or Greek letters (e.g. "pаypal" with a Cyrillic "а").
# We deliberately do NOT flag dashes, curly quotes, or lone non-Latin symbols
# (e.g. a Greek sigma in "z-score σ"): those are legitimate typography/notation
# and dominate the false positives on real descriptions.
_HOMOGLYPH_SCRIPTS = ("CYRILLIC", "GREEK")


def _char_script(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    name = unicodedata.name(ch, "")
    if "LATIN" in name:
        return "LATIN"
    for script in _HOMOGLYPH_SCRIPTS:
        if script in name:
            return script
    return None


def detect_hidden_instructions(text: str | None) -> list[str]:
    if not text:
        return []
    found: list[str] = []
    for pat in HIDDEN_INSTRUCTION_PATTERNS:
        m = pat.search(text)
        if m:
            found.append(m.group(0))
    return found


def detect_unicode_tricks(text: str | None) -> list[str]:
    if not text:
        return []
    findings: list[str] = []
    for ch in text:
        if ch in ZERO_WIDTH:
            findings.append(f"zero_width:U+{ord(ch):04X}")
            break
    # Mixed-script tokens: a single word containing both Latin and Cyrillic/Greek
    # letters is the homoglyph-spoofing signal (e.g. Latin "p" + Cyrillic "а").
    for token in re.findall(r"\w+", text, re.UNICODE):
        scripts = {s for ch in token if (s := _char_script(ch))}
        if "LATIN" in scripts and any(h in scripts for h in _HOMOGLYPH_SCRIPTS):
            findings.append(f"mixed_script:{token}")
            break
    return list(dict.fromkeys(findings))


BENIGN_NAME_VERBS = ("get_", "read_", "list_", "search_", "fetch_", "show_")

# Whole-word / phrase patterns for capabilities that a read-only-sounding tool
# name should not imply. Word boundaries are essential: substring matching gave
# almost entirely false positives on real data ("perform"/"terms" -> "rm ",
# "execution" -> "exec", "skills" -> "kill").
DANGEROUS_CAPABILITY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bexec(?:ute)?\b", re.I),
    re.compile(r"\bshell\b", re.I),
    re.compile(r"\bsubprocess\b", re.I),
    re.compile(r"\bcommands?\b", re.I),
    re.compile(r"\brm\b", re.I),
    re.compile(r"\bdelete\b", re.I),
    re.compile(r"\bdrop\s+table\b", re.I),
    re.compile(r"\bkill\b", re.I),
]


def detect_name_capability_mismatch(tool: ToolDescription) -> bool:
    """True if the tool name suggests a narrow capability but the description
    implies a broader/destructive one.

    Example: name="get_weather" but description mentions "execute" / "shell".
    """
    name = (tool.name or "").lower()
    description = tool.description or ""
    if not description:
        return False
    if not any(name.startswith(v) for v in BENIGN_NAME_VERBS):
        return False
    return any(p.search(description) for p in DANGEROUS_CAPABILITY_PATTERNS)


def detect_excessive_scope(declared: Iterable[Scope], inferred: Iterable[Scope]) -> bool:
    """True if inferred scope exceeds declared. Flag for review."""
    declared_s = set(declared)
    inferred_s = set(inferred)
    return bool(inferred_s - declared_s)


# Axis A3 capability triggers, one whole-word pattern per scope, mirroring the
# rubric of codebook.SCOPE_INFERENCE_HINTS. These are written directly rather than
# tokenised out of the hint prose: the earlier implementation matched substrings
# of the hint text itself, so filler words ("tool", "description", "schema")
# matched almost every description. The filesystem scopes additionally require a
# verb and a filesystem noun to co-occur, which is the same precision-over-recall
# correction applied to the name-capability detector after calibration.
SCOPE_PATTERNS: dict[Scope, re.Pattern[str]] = {
    Scope.FS_READ: re.compile(
        r"\b(?:read|open|load|list)\b.{0,30}?"
        r"\b(?:file|files|path|paths|directory|directories|folder)\b"
        r"|\bfile\s+contents?\b",
        re.I | re.S,
    ),
    Scope.FS_WRITE: re.compile(
        r"\b(?:write|writes|save|saves|append|delete|deletes|overwrite|remove)\b"
        r".{0,30}?\b(?:file|files|path|paths|directory|directories|folder)\b",
        re.I | re.S,
    ),
    Scope.NETWORK_EGRESS: re.compile(
        r"\b(?:fetch|fetches|https?|url|urls|download|downloads|web\s+request"
        r"|http\s+request|api\s+call)\b",
        re.I,
    ),
    Scope.EXEC: re.compile(
        r"\b(?:execute|executes|exec|shell|spawn|subprocess|bash"
        r"|command[-\s]line|run\s+a\s+command)\b",
        re.I,
    ),
    Scope.SECRETS_ACCESS: re.compile(
        r"\b(?:secret|secrets|credential|credentials|api[\s_-]?key|api[\s_-]?keys"
        r"|access[\s_-]?token|password|passwords"
        r"|environment\s+variable|env\s+var)\b",
        re.I,
    ),
    Scope.PROCESS_CONTROL: re.compile(
        r"\b(?:kill|terminate|terminates|sigterm|sigkill|process\s+control)\b",
        re.I,
    ),
    Scope.DATABASE: re.compile(
        r"\b(?:sql|sqlite|postgres(?:ql)?|mysql|mongo(?:db)?|database"
        r"|select\s+from|insert\s+into|query\s+the)\b",
        re.I,
    ),
}

# Input-schema property names that evidence filesystem reach directly, without
# depending on how the description happens to be worded.
_PATH_PROPERTY_NAMES = ("path", "filepath", "file_path", "filename", "file_name",
                        "directory", "dirpath", "dir_path", "folder")


def infer_scope_from_description(text: str | None) -> set[Scope]:
    """A3 capability inference from description prose (Tier 2).

    Interpretive: it reads prose to infer what a tool can reach. Low recall by
    construction, since a terse description evidences nothing, so the result is
    a lower bound on capability rather than a census of it.
    """
    if not text:
        return set()
    return {scope for scope, pattern in SCOPE_PATTERNS.items() if pattern.search(text)}


def infer_scope_from_schema(input_schema: object) -> set[Scope]:
    """A3 filesystem reach evidenced by a declared input-schema property name.

    Deterministic: the property names are read off the declared schema, so this
    part of the axis carries no interpretation.
    """
    if not isinstance(input_schema, dict):
        return set()
    props = input_schema.get("properties")
    if not isinstance(props, dict):
        return set()
    for name in props:
        if not isinstance(name, str):
            continue
        if name.strip().lower().replace("-", "_") in _PATH_PROPERTY_NAMES:
            return {Scope.FS_READ}
    return set()


def infer_scope(tool: ToolDescription) -> set[Scope]:
    """Union of the prose and schema routes for axis A3."""
    return infer_scope_from_description(tool.description) | infer_scope_from_schema(
        tool.input_schema
    )


def evaluate_tool(tool: ToolDescription) -> list[HygieneFlag]:
    """Apply all rules to a tool description; return list of triggered flags."""
    flags: list[HygieneFlag] = []
    if detect_hidden_instructions(tool.description):
        flags.append(HygieneFlag.HIDDEN_INSTRUCTION)
    if detect_unicode_tricks(tool.description):
        flags.append(HygieneFlag.UNICODE_TRICK)
    if detect_name_capability_mismatch(tool):
        flags.append(HygieneFlag.NAME_CAPABILITY_MISMATCH)
    return flags
