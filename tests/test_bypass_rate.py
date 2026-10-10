import json
from pathlib import Path

import pytest

from cym500.benchmark.metrics import bypass_rate

TP = "tool_poisoning::hidden_instruction::calc_sum_v1"
OPS = ("obfuscation", "paraphrase", "slow_drip", "unicode_dressing")


def _family(seed, base_blocked, mutants_blocked):
    rows = [{"kind": "attack", "case_id": f"{seed}-base", "blocked": base_blocked}]
    rows += [{"kind": "attack", "case_id": f"{seed}-{op}", "blocked": b}
             for op, b in zip(OPS, mutants_blocked)]
    return rows


def test_counts_only_families_whose_base_was_blocked():
    rows = _family(TP, True, [False, True, True, False])
    rows += _family("rug_pull::post_approval_swap::x", False, [False] * 4)
    assert bypass_rate(rows) == {"n_mutants": 4, "n_bypassed": 2, "rate": 0.5}


def test_hyphenated_seed_names_resolve_to_their_base():
    seed = "schema_poisoning::x_instruction_field::examples-field"
    rows = _family(seed, True, [True, False, False, False])
    rows.append({"kind": "attack", "case_id": f"{seed}-split_payload", "blocked": False})
    assert bypass_rate(rows)["n_mutants"] == 5
    assert bypass_rate(rows)["n_bypassed"] == 4


def test_families_without_a_base_and_benign_rows_are_ignored():
    rows = [
        {"kind": "attack", "case_id": "supply_chain::dependency_typosquat::m-suffix_addition", "blocked": False},
        {"kind": "benign", "case_id": "benign::smithery:x::tool::1", "blocked": True},
    ]
    assert bypass_rate(rows)["n_mutants"] == 0


def test_agent_scan_reported_run_is_zero_of_eight():
    # The reported Agent Scan run kept aggregates only; its per-class result
    # (tool poisoning 10/10, full-schema 0/12) fixes the per-case verdicts.
    rows = _family(TP, True, [True] * 4)
    rows += _family("tool_poisoning::hidden_instruction::calc_sum_v2", True, [True] * 4)
    rows += _family("schema_poisoning::x_instruction_field::title-field", False, [False] * 4)
    assert bypass_rate(rows) == {"n_mutants": 8, "n_bypassed": 0, "rate": 0.0}


VERDICTS = [
    Path(__file__).resolve().parents[1] / "data/results/benchmark/mcp-scanner-yara-verdicts.jsonl",
    Path(__file__).resolve().parents[1] / "results/benchmark/mcp-scanner-yara-verdicts.jsonl",
]


@pytest.mark.skipif(not any(p.exists() for p in VERDICTS), reason="YARA verdicts not present")
def test_yara_reported_run_is_six_of_nine():
    path = next(p for p in VERDICTS if p.exists())
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert bypass_rate(rows) == {"n_mutants": 9, "n_bypassed": 6, "rate": 6 / 9}
