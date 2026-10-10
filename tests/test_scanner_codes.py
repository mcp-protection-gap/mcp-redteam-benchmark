import json

from cym500.analysis.scanner_codes import code_split


def test_code_split_separates_non_detecting_codes(tmp_path):
    rows = [
        {"kind": "attack", "blocked": True, "evidence": "W015"},
        {"kind": "attack", "blocked": True, "evidence": "W015;W001"},
        {"kind": "attack", "blocked": False, "evidence": ""},
        {"kind": "benign", "blocked": True, "evidence": "W019"},        # never on attacks
        {"kind": "benign", "blocked": True, "evidence": "W016;W017"},   # never on attacks
        {"kind": "benign", "blocked": True, "evidence": "W001"},        # also on attacks
        {"kind": "benign", "blocked": False, "evidence": ""},
    ]
    p = tmp_path / "v.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows))
    out = code_split(p)
    assert out["n_benign_flags"] == 3
    assert out["n_benign_flags_only_codes_never_raised_on_attacks"] == 2
    assert set(out["attack_codes"]) == {"W015", "W001"}
