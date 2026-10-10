"""The secret-in-output probe set is deterministic and self-consistent."""
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "masking_set", Path(__file__).resolve().parents[1] / "scripts" / "inpath" / "masking_set.py")
masking_set = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(masking_set)


def test_six_cases_each_marker_in_its_output():
    cases = masking_set.build()
    assert len(cases) == 6
    kinds = {c["case_id"].split("::")[1] for c in cases}
    assert kinds == {"jwt", "github_pat", "slack_token", "aws_access_key",
                     "gcp_api_key", "private_endpoint"}
    for c in cases:
        marker = c["metadata"]["oracle"]["marker"]
        assert marker and marker in c["payload"]["output"]
        assert c["target"] == "tool_output"


def test_tokens_are_the_documented_synthetic_ones():
    # AWS uses AWS's own documented example key; nothing here is a live secret.
    outs = " ".join(c["payload"]["output"] for c in masking_set.build())
    assert "AKIAIOSFODNN7EXAMPLE" in outs
    assert "ghp_EXAMPLE" in outs
