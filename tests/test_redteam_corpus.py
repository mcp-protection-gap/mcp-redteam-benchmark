from cym500.redteam.attacks import ATTACK_CLASSES
from cym500.redteam.base import ThreatClass


def test_each_threat_class_has_at_least_one_attack():
    classes = {cls().threat_class for cls in ATTACK_CLASSES}
    expected = set(ThreatClass)
    missing = expected - classes
    assert not missing, f"missing PoC coverage for: {missing}"


def test_attacks_emit_cases():
    for cls in ATTACK_CLASSES:
        attack = cls()
        cases = attack.cases()
        assert cases, f"{cls.__name__} returned no cases"
        for c in cases:
            assert c.case_id
            assert c.payload


def test_every_case_carries_an_oracle():
    """Every case must carry a serialisable oracle descriptor with a marker."""
    for cls in ATTACK_CLASSES:
        for c in cls().cases():
            oracle = (c.metadata or {}).get("oracle")
            assert oracle, f"{c.case_id} has no oracle descriptor"
            assert oracle.get("expected") == "block"
            assert oracle.get("marker"), f"{c.case_id} oracle has no marker"


def test_base_case_markers_present_in_payload():
    """A base (un-mutated) case must literally contain its oracle marker."""
    import json

    for cls in ATTACK_CLASSES:
        for c in cls().cases():
            if (c.metadata or {}).get("mutation") != "base":
                continue
            marker = c.metadata["oracle"]["marker"]
            assert marker in json.dumps(c.payload), f"{c.case_id}: marker {marker!r} absent"


def test_benign_baseline_carries_no_attack_marker():
    """Benign-baseline sanity: no attack marker occurs in any benign definition.

    The benign baseline lives under data/raw/ (not committed), so the test skips
    when it is absent rather than passing vacuously.
    """
    import json

    import pytest

    from cym500.redteam.benign_baseline import benign_traces

    traces = [json.dumps(t) for t in benign_traces()]
    if not traces:
        pytest.skip("benign baseline not present (data/raw/benign/)")
    markers = {
        c.metadata["oracle"]["marker"] for cls in ATTACK_CLASSES for c in cls().cases()
    }
    for marker in markers:
        hits = [t for t in traces if marker in t]
        assert not hits, f"marker {marker!r} occurs in {len(hits)} benign definition(s)"
